'use strict';
/**
 * TUN mode (system-wide tunnel) on sing-box.
 *
 * Flow:
 *   1. Xray runs with a local SOCKS inbound (already started by XrayManager).
 *   2. sing-box's `tun` inbound creates the adapter and — with `auto_route` —
 *      lays the v4 AND v6 default routes itself, keeps the proxy server's own
 *      addresses off the tunnel (`route_exclude_address`), binds its own
 *      sockets to the physical NIC (`auto_detect_interface`), and forwards
 *      every packet into that SOCKS. On exit it removes everything it added
 *      (routes, and on Windows the WFP filters `strict_route` installs).
 *   3. We only set the adapter's DNS: the tunnel peer (172.19.0.2), so every
 *      query the OS sends there enters the TUN and reaches Xray's port-53
 *      hijack. No routes are laid by hand.
 *   4. Optional per-app split (`apps`): sing-box's TUN can match traffic by
 *      the packet's OWNING PROCESS on Windows, macOS and Linux — a `direct`
 *      outbound plus a `process_name` route rule sends the chosen apps
 *      around the tunnel (`exclude`) or makes them the only ones inside it
 *      (`only`). Xray cannot do this itself (see procRouter.js's IP
 *      approximation), so this is sing-box-only. A `port: 53` rule is always
 *      inserted ahead of the process rule, unconditionally routed to
 *      socks-out: the adapter's resolver is the tunnel peer, reachable only
 *      through the TUN, so every app must keep resolving through it even
 *      while its other traffic goes the other way — see buildTunConfig.
 *
 * Against tun2socks (tunManager.js) this fixes the two known holes: there is
 * a v6 default route (v6 no longer bypasses the tunnel), and once Xray's
 * direct outbounds are bound to the physical interface (task 2) a `direct`
 * dial no longer re-enters the tunnel through /1 split routes. The proxy core
 * stays Xray: sing-box here is only the TUN → SOCKS forwarder.
 *
 * Requires Administrator (Windows) / root or a one-time password prompt
 * (macOS), sing-box(.exe) in a bin dir, and on Windows wintun.dll next to it.
 *
 * macOS is written blind (no Mac in this round): it mirrors tunManager's
 * startMac step for step — privileged script, pid file, wait for a NEW utun,
 * DNS via networksetup — with sing-box in place of tun2socks and no route or
 * ifconfig lines, because auto_route does those.
 */

const { spawn, execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');
const platform = require('./tunPlatform');
const { sh } = platform;

const TUN_IF = platform.SINGBOX_ADAPTER;                    // 'IRNetFree'
const TUN_ADDR4 = '172.19.0.1/30', TUN_PEER4 = '172.19.0.2';
const TUN_ADDR6 = 'fdfe:dcba:9876::1/126', TUN_PEER6 = 'fdfe:dcba:9876::2';
const FAIL_FAST_MS = 400;      // a process that dies this fast had a bad config / missing dll
const ADAPTER_WAIT_MS = 12000;
const STOP_WAIT_MS = 3000;

/** ip → ip/32 or ip/128; an entry that already carries a prefix is kept. */
function cidrOf(ip) {
  const s = String(ip).trim();
  if (s.includes('/')) return s;
  return s.includes(':') ? `${s}/128` : `${s}/32`;
}

/**
 * `apps.names` normalisation — the builder is the last line of defence, so it
 * does this itself rather than trust callers: trim, drop empties, dedupe
 * keeping the first occurrence and the order.
 *
 * Anything that is not a string is DROPPED, not coerced: '[object Object]' in
 * the rule would be a name nothing on the machine is called, while the log
 * cheerfully reports that per-app routing is on.
 */
function normalizeAppNames(names) {
  const seen = new Set();
  const out = [];
  for (const raw of (Array.isArray(names) ? names : [])) {
    if (typeof raw !== 'string') continue;
    const s = raw.trim();
    if (!s || seen.has(s)) continue;
    seen.add(s);
    out.push(s);
  }
  return out;
}

/**
 * Pure. The shape below passed `sing-box check` on 1.13.14 with and without
 * strict, with and without exclusions.
 *
 * `ipv6:false` does NOT remove the v6 address: the OS then still gets a v6
 * default route through the TUN, which is exactly what stops the physical
 * adapter's v6 from leaking — Xray simply answers no AAAA in that mode, so
 * nothing v6 is ever dialled. The flag is accepted so callers can pass their
 * settings through unchanged; the config is the same either way.
 *
 * `interfaceName: null` omits `interface_name`: on darwin sing-tun only accepts
 * `utun<N>` and picks the next free unit itself when no name is given.
 *
 * `apps`: `null | { mode: 'exclude' | 'only', names: string[] }`. `null`, an
 * unrecognised `mode`, or no name left after normalisation (trim, drop
 * empties, dedupe keeping the first occurrence and order) leaves the output
 * byte-stable with `apps` absent — no `route.rules`, no `direct` outbound,
 * `route.final` stays `'socks-out'`. With a usable name list a `direct`
 * outbound is added and `route.rules` gets exactly two rules, in this order:
 *   1. `{ port: 53, outbound: 'socks-out' }` — ALWAYS first, and always to
 *      socks-out regardless of mode. The adapter's resolver is the tunnel
 *      peer (172.19.0.2, TUN_PEER4), reachable only *through* the TUN. Without
 *      this rule an excluded app's DNS query would be dialled `direct` to an
 *      address nothing answers, and that app would lose name resolution
 *      entirely. With it, every app resolves through the tunnel resolver and
 *      only the excluded app's *traffic* goes around the tunnel (for `only`,
 *      the reverse: only the named apps' traffic goes through the tunnel,
 *      everyone's DNS still does).
 *   2. `{ process_name: names, outbound: mode === 'exclude' ? 'direct' : 'socks-out' }`.
 * `route.final` becomes `mode === 'exclude' ? 'socks-out' : 'direct'` — the
 * unlisted apps get the opposite of what the listed ones get.
 */
function buildTunConfig({ socksPort, excludeIps = [], ipv6 = false, strict = false, stack = 'system', mtu = 1500, interfaceName = TUN_IF, apps = null } = {}) {
  void ipv6;
  const inbound = { type: 'tun', tag: 'tun-in' };
  if (interfaceName) inbound.interface_name = interfaceName;
  inbound.address = [TUN_ADDR4, TUN_ADDR6];          // v6 entry ALWAYS present (see above)
  inbound.mtu = mtu;
  inbound.auto_route = true;
  inbound.strict_route = !!strict;
  inbound.stack = stack;
  inbound.route_exclude_address = excludeIps.filter(Boolean).map(cidrOf);

  const outbounds = [{ type: 'socks', tag: 'socks-out', server: '127.0.0.1', server_port: socksPort, version: '5' }];
  const route = { final: 'socks-out', auto_detect_interface: true };

  const mode = apps && (apps.mode === 'exclude' || apps.mode === 'only') ? apps.mode : null;
  const names = mode ? normalizeAppNames(apps.names) : [];
  if (mode && names.length) {
    outbounds.push({ type: 'direct', tag: 'direct' });
    route.final = mode === 'exclude' ? 'socks-out' : 'direct';
    // DNS ALWAYS through the tunnel resolver first: the adapter's resolver is
    // the tunnel peer (TUN_PEER4), reachable only through the TUN. Without
    // this rule ahead of the process rule, an excluded app's DNS query would
    // be dialled `direct` to an address nothing answers, and that app would
    // lose name resolution entirely — so only its *traffic* goes around the
    // tunnel (the reverse for `only`), never its DNS.
    route.rules = [
      { port: 53, outbound: 'socks-out' },
      { process_name: names, outbound: mode === 'exclude' ? 'direct' : 'socks-out' }
    ];
  }

  return {
    log: { level: 'warn', timestamp: false },
    inbounds: [inbound],
    outbounds,
    route
  };
}

const { buildMacSetupScript, buildMacTeardownScript } = require('./macTunScripts');
// Keep overlapping Connect/Disconnect calls from recovering another live
// instance's session in this process. Crash recovery starts with an empty map.
const macOwners = require('./macSessionLock');

/** Race a promise against a deadline; the timer never outlives the race. */
function withTimeout(promise, ms, fallback) {
  let timer;
  const t = new Promise((resolve) => { timer = setTimeout(() => resolve(fallback), ms); });
  return Promise.race([promise, t]).finally(() => clearTimeout(timer));
}

class TunSingbox {
  constructor(opts = {}) {
    this.binDir = opts.binDir;
    // Writable dirs (e.g. userData/bin) checked first so downloads/updates win.
    this.extraDirs = (opts.extraDirs || []).filter(Boolean);
    this.onLog = opts.onLog || (() => {});
    this.lang = opts.lang || 'fa';   // user-facing error language
    this.platform = opts.platform || os.platform();
    this.backendId = 'sing-box';
    this.interfaceName = TUN_IF;
    this.dnsPeer = TUN_PEER4;
    this.dnsPeer6 = TUN_PEER6;
    this.excludeIps = [];      // the resolved bypass list of the live tunnel (the leak guard's firewall excludes)
    this.proc = null;
    this.active = false;
    this.stopping = false;     // an exit we asked for is not an error
    this.exited = Promise.resolve();
    this.recent = '';          // last output lines, for a crash-on-start message
    this.work = null;          // temp dir holding the config (and, on macOS, log/pid/scripts)
    this.macState = null;      // macOS runtime state (pid, device, saved DNS)
    this.macLogTimer = null;
    this.macHealthTimer = null;
    this.userData = opts.userData || null;
    this.onUnexpectedExit = opts.onUnexpectedExit || (() => {});
    this.macOwnerKey = this.userData ? path.resolve(this.userData) : this;
  }

  /** Pick the message in the user's language (fa default). */
  msg(fa, en) { return this.lang === 'en' ? en : fa; }

  dirs() {
    return [
      ...this.extraDirs,
      this.binDir,
      path.join(process.resourcesPath || '', 'bin')
    ].filter(Boolean);
  }

  singboxPath() {
    const exe = this.platform === 'win32' ? 'sing-box.exe' : 'sing-box';
    return this.dirs().map(d => path.join(d, exe)).find(p => fs.existsSync(p)) || null;
  }

  /**
   * Where a wintun.dll for sing-box can come from: beside the binary first,
   * else any known bin dir — the bundled one ships it beside tun2socks.
   */
  wintunSource() {
    const bin = this.singboxPath();
    if (!bin) return null;
    const beside = path.join(path.dirname(bin), 'wintun.dll');
    if (fs.existsSync(beside)) return beside;
    return this.dirs().map(d => path.join(d, 'wintun.dll')).find(p => fs.existsSync(p)) || null;
  }

  /**
   * sing-box present; on Windows a wintun.dll we can put beside it (see
   * ensureWintun). The old rule — wintun in the SAME dir, or "not installed" —
   * sent every machine whose sing-box came from the downloader (userData/bin)
   * to tun2socks for good: the bundled wintun.dll lives beside tun2socks in
   * resources/bin and nothing ever copied it over. The setting said sing-box,
   * the user had installed sing-box, the log said tun2socks.
   */
  isAvailable() {
    const bin = this.singboxPath();
    if (!bin) return false;
    if (this.platform === 'win32') return !!this.wintunSource();
    return true;
  }

  /**
   * Make sure wintun.dll sits beside sing-box.exe, copying it there from another
   * known dir when it does not. sing-box (wireguard-go's loader) opens
   * wintun.dll with LOAD_LIBRARY_SEARCH_APPLICATION_DIR: only the directory of
   * the executable counts — never the working directory, never another dir on
   * the way. Returns the path beside the binary; null off Windows; throws when
   * there is no wintun.dll anywhere to copy, or the copy itself fails.
   */
  ensureWintun() {
    const bin = this.singboxPath();
    if (!bin || this.platform !== 'win32') return null;
    const beside = path.join(path.dirname(bin), 'wintun.dll');
    if (fs.existsSync(beside)) return beside;
    const src = this.wintunSource();
    if (!src) {
      throw new Error(this.msg(
        'wintun.dll کنار sing-box.exe نیست — حالت TUN بدون آن اجرا نمی‌شود',
        'wintun.dll is not next to sing-box.exe — TUN mode cannot run without it'));
    }
    try {
      fs.copyFileSync(src, beside);
    } catch (e) {
      throw new Error(this.msg(
        `کپی wintun.dll کنار sing-box.exe ناموفق بود (${e.message})`,
        `Could not copy wintun.dll next to sing-box.exe (${e.message})`));
    }
    this.onLog(`wintun.dll copied beside sing-box: ${beside}`, 'info');
    return beside;
  }

  isElevated() { return platform.isElevated(this.platform); }

  /** The interface Xray's direct outbounds bind to — read before start(). */
  physicalInterface() { return platform.physicalInterface(this.platform); }

  /* ----------------------------- shared steps ----------------------------- */

  /**
   * Split the caller's adapter resolvers by family; the tunnel peer fills a gap.
   *
   * The v6 side follows the v4 side rather than the `ipv6` setting. When the v4
   * resolver is our own peer, the core hijacks port 53 on either family (the
   * probe watches it answer `[udp:[::1]:53]` and `[tcp:[::1]:53]`) and the
   * adapter always has a v6 address and default route — see buildTunConfig,
   * which keeps them precisely so v6 cannot bypass the tunnel. Leaving the v6
   * resolver empty there left the machine's ONLY IPv6 resolvers on the physical
   * adapters: the ISP's, and a link-local one is on-link, so it never meets the
   * tunnel's default route. When the v4 side is NOT the peer (an unmanaged list,
   * or a core whose config format carries no hijack) the peer answers nothing,
   * and offering it on v6 would be a black hole — so it is not offered.
   *
   * `opts` is kept for callers; the ipv6 flag no longer decides anything here.
   */
  adapterDns(dnsServers, opts) {
    void opts;
    const list = (Array.isArray(dnsServers) ? dnsServers : [dnsServers])
      .map(s => String(s == null ? '' : s).trim()).filter(Boolean);
    const v4 = list.filter(s => !s.includes(':')).slice(0, 2);
    const v6 = list.filter(s => s.includes(':')).slice(0, 2);
    const peered = !v4.length || v4.includes(TUN_PEER4);
    return {
      v4: v4.length ? v4 : [TUN_PEER4],
      v6: v6.length ? v6 : (peered ? [TUN_PEER6] : [])
    };
  }

  /** The proxy server's own addresses (v4 and v6): they must stay off the tunnel. */
  async bypassIps(bypassAddrs) {
    const ips = await platform.resolveServerIps(bypassAddrs, { ipv6: true });
    if (!ips.length) this.onLog(this.msg(
      `نتوانستم IP سرور (${bypassAddrs}) را resolve کنم — ممکن است حلقه ایجاد شود`,
      `Could not resolve server IP (${bypassAddrs}) — a routing loop may occur`), 'warn');
    return ips;
  }

  writeConfig(socksPort, excludeIps, opts, interfaceName) {
    const base = this.platform === 'darwin' && this.userData ? path.join(this.userData, 'mac-tun-sessions') : os.tmpdir();
    fs.mkdirSync(base, { recursive: true, mode: 0o700 });
    const work = fs.mkdtempSync(path.join(base, 'irnf-sb-'));
    const cfgFile = path.join(work, 'sing-box.json');
    const cfg = buildTunConfig({ socksPort, excludeIps, ipv6: !!opts.ipv6, strict: !!opts.strict, interfaceName, apps: opts.apps || null });
    fs.writeFileSync(cfgFile, JSON.stringify(cfg, null, 2));
    this.work = work;
    return { work, cfgFile };
  }

  removeWork() {
    if (!this.work) return;
    try { fs.rmSync(this.work, { recursive: true, force: true }); } catch {}
    this.work = null;
  }

  /** The last output lines, for an error message. */
  tail(info) {
    const lines = (this.recent || '').split(/\r?\n/).map(l => l.trim()).filter(Boolean).slice(-3);
    if (lines.length) return ' — ' + lines.join(' | ');
    return info && info.error ? ' — ' + info.error : ` (code ${info ? info.code : '?'})`;
  }

  /**
   * Spawn `sing-box run -c <cfg>`, wire its output into the app log and its
   * exit into our state. Resolves with the exit info when it dies inside the
   * fail-fast window, null when it is still running after it.
   */
  launch(bin, cfgFile, spawnOpts) {
    const proc = spawn(bin, ['run', '-c', cfgFile], spawnOpts);
    this.proc = proc;
    this.stopping = false;
    this.recent = '';
    const onData = (buf, level) => {
      const text = buf.toString('utf8');
      this.recent = (this.recent + text).slice(-4000);
      for (const line of text.split(/\r?\n/)) if (line.trim()) this.onLog('[tun] ' + line.trim(), level);
    };
    proc.stdout.on('data', d => onData(d, 'log'));
    proc.stderr.on('data', d => onData(d, 'warn'));
    let gone;
    this.exited = new Promise((resolve) => { gone = resolve; });
    const finish = (info) => {
      if (this.proc === proc) this.proc = null;
      // A dead tunnel is a drop: the recovery path treats it like one.
      this.active = false;
      gone(info);
    };
    proc.on('exit', (code, signal) => {
      this.onLog(`sing-box exited (code=${code} signal=${signal || '-'})`, (this.stopping || code === 0) ? 'info' : 'error');
      finish({ code, signal });
    });
    proc.on('error', (err) => {
      this.onLog('sing-box spawn error: ' + err.message, 'error');
      finish({ code: null, signal: null, error: err.message });
    });
    return withTimeout(this.exited, FAIL_FAST_MS, null);
  }

  /* ----------------------------- Windows ----------------------------- */
  async startWindows(socksPort, bypassAddrs, dnsServers, opts) {
    const bin = this.singboxPath();
    if (!bin) throw new Error(this.msg(
      'sing-box.exe پیدا نشد — آن را در پوشه bin بگذارید (از «فایل‌های موردنیاز» دانلود کن)',
      'sing-box.exe not found — put it in the bin folder (download it from "Required files")'));
    // wintun.dll has to be beside the binary; a downloaded sing-box gets the
    // bundled one copied over here (see ensureWintun).
    this.ensureWintun();
    if (!this.isElevated()) {
      throw new Error(this.msg(
        'حالت TUN نیاز به دسترسی Administrator دارد — برنامه را با «Run as administrator» اجرا کنید',
        'TUN mode needs Administrator rights — relaunch the app as administrator'));
    }
    const dns = this.adapterDns(dnsServers, opts);

    // 1) the server's own addresses stay off the tunnel (route_exclude_address)
    const ips = await this.bypassIps(bypassAddrs);
    this.excludeIps = ips;
    const { cfgFile } = this.writeConfig(socksPort, ips, opts, TUN_IF);

    // 2) launch sing-box: it creates the adapter and lays the routes
    this.onLog('Starting sing-box…', 'info');
    const died = await this.launch(bin, cfgFile, { cwd: path.dirname(bin), windowsHide: true });
    if (died) {
      this.removeWork();
      throw new Error(this.msg(
        'sing-box بلافاصله بسته شد — لاگ‌ها را بررسی کنید',
        'sing-box exited immediately — check the logs') + this.tail(died));
    }

    // 3) wait for the adapter to actually be ready (present AND up) — or for
    //    the process to die trying
    const ready = await Promise.race([platform.waitForAdapter(TUN_IF, ADAPTER_WAIT_MS), this.exited.then(() => false)]);
    if (!ready) {
      const gone = !this.proc;
      await this.stop();
      throw new Error(gone
        ? this.msg('sing-box پیش از آماده شدن آداپتور بسته شد', 'sing-box exited before the TUN adapter came up') + this.tail()
        : this.msg(
          'آداپتور TUN آماده نشد — دسترسی ادمین و wintun.dll را بررسی کنید',
          'TUN adapter did not become ready — check admin rights and wintun.dll'));
    }

    // 4) DNS through the tunnel: the adapter's resolver is the tunnel peer (or
    //    what the caller asked for), so every query the OS sends there enters
    //    the TUN. validate=no: the peer answers only once the tunnel is up.
    await platform.run('netsh', ['interface', 'ip', 'set', 'dnsservers', `name=${TUN_IF}`, 'static', dns.v4[0], 'primary', 'validate=no'])
      .catch(e => this.onLog('set dns: ' + e.message, 'warn'));
    if (dns.v4[1]) {
      await platform.run('netsh', ['interface', 'ip', 'add', 'dnsservers', `name=${TUN_IF}`, dns.v4[1], 'index=2', 'validate=no']).catch(() => {});
    }
    // No v6 resolver of ours (no hijack: managed DNS off, or a sing-box-format
    // core) is not "leave v6 alone": sing-tun has already set the peer there
    // under auto_route, and without the hijack nothing answers it — a dead
    // resolver beside the working v4 ones. It becomes ::1, the leak guard's
    // hold: a query there fails in milliseconds. Not a delete, which Windows
    // may fill with its fec0:0:0:ffff::1-3 placeholders — dead the same way.
    const v6 = dns.v6.length ? dns.v6 : ['::1'];
    await platform.run('netsh', ['interface', 'ipv6', 'set', 'dnsservers', `name=${TUN_IF}`, 'static', v6[0], 'primary', 'validate=no'])
      .catch(e => this.onLog('set dns (v6): ' + e.message, 'warn'));
    if (v6[1]) {
      await platform.run('netsh', ['interface', 'ipv6', 'add', 'dnsservers', `name=${TUN_IF}`, v6[1], 'index=2', 'validate=no']).catch(() => {});
    }
    this.onLog(`TUN adapter ${TUN_IF} up; DNS ${[...dns.v4, ...v6].join(', ')}; routes by sing-box (auto_route)`, 'info');

    this.active = true;
    this.onLog(this.msg('حالت TUN فعال شد (کل سیستم).', 'TUN mode active (whole system).'), 'info');
  }

  /* ----------------------------- macOS (blind) ----------------------------- */
  async startMac(socksPort, bypassAddrs, dnsServers, opts) {
    if (this.macState || this.hasPendingMacRecovery()) await this.recoverMacSessions();
    const bin = this.singboxPath();
    if (!bin) throw new Error(this.msg(
      'sing-box پیدا نشد — آن را در پوشه bin بگذارید (از «فایل‌های موردنیاز» دانلود کن)',
      'sing-box not found — put it in the bin folder (download it from "Required files")'));

    // A previously-downloaded binary may be quarantined/unsigned — on Apple
    // Silicon that means it is SIGKILL'd at exec ("Killed: 9"), which then looks
    // like "sing-box did not create a utun device". Re-sign it (ad-hoc) and
    // strip quarantine here so even old downloads run.
    try { execFileSync('xattr', ['-dr', 'com.apple.quarantine', bin], { stdio: 'ignore' }); } catch {}
    try { execFileSync('codesign', ['--force', '--sign', '-', bin], { stdio: 'ignore' }); } catch {}

    const route = await platform.getDefaultRouteMac();
    if (!route.gateway || !route.device) throw new Error(this.msg(
      'دروازه/اینترفیس پیش‌فرض شبکه پیدا نشد',
      'Default network gateway/interface not found'));
    this.onLog(`Default gateway: ${route.gateway} (dev ${route.device})`, 'info');

    const service = await platform.serviceForDeviceMac(route.device);
    if (!service) throw new Error('No physical macOS network service found; TUN DNS cannot be configured');
    const savedDns = await platform.getServiceDnsMac(service, { strict: true });
    const dns = this.adapterDns(dnsServers, opts);

    const ips = await this.bypassIps(bypassAddrs);
    this.excludeIps = ips;
    // darwin: no interface_name — sing-tun only accepts utun<N> and picks the
    // next free unit itself; the script below detects which one appeared.
    const { work, cfgFile } = this.writeConfig(socksPort, ips, opts, null);
    const logFile = path.join(work, 'sing-box.log');
    const pidFile = path.join(work, 'sing-box.pid');
    const devFile = path.join(work, 'sing-box.dev');
    const setupPath = path.join(work, 'setup.sh');
    const identityFile = path.join(work, 'identity');
    const dnsFile = path.join(work, 'dns-changed');
    const teardownPath = path.join(work, 'teardown.sh');
    // Pre-create root-written output files as the app user so they remain readable.
    for (const file of [logFile, pidFile, devFile, identityFile]) fs.writeFileSync(file, '', { mode: 0o600 });
    this.macState = { work, bin, cfgFile, logFile, pidFile, devFile, identityFile, dnsFile, service, savedDns, macPid: null, dev: '', ownerPid: process.pid };
    this.saveMacSession();
    fs.writeFileSync(teardownPath, buildMacTeardownScript(this.macState), { mode: 0o700 });
    fs.writeFileSync(setupPath, buildMacSetupScript({
      bin, cfgFile, logFile, pidFile, devFile, identityFile, dnsFile, teardownPath, service, dnsServers: [...dns.v4, ...dns.v6]
    }), { mode: 0o700 });

    this.onLog('Starting sing-box (you may be asked for your password)…', 'info');
    try {
      await platform.runScriptPrivileged(setupPath);
    } catch (e) {
      const m = (e.message || '').toString();
      // Make the sing-box output visible in the app log for diagnosis.
      let logTail = '';
      try { logTail = this.readMacLogChunk(logFile).text.trim(); } catch {}
      if (logTail) {
        for (const line of logTail.split(/\r?\n/).slice(-12)) {
          if (line.trim()) this.onLog('[tun] ' + line.trim(), 'error');
        }
      }
      // A cancelled prompt before launch is safe to discard. After any mutation
      // the privileged rollback owns cleanup; keep the journal for verified recovery.
      if (!fs.readFileSync(pidFile, 'utf8').trim() && !fs.existsSync(dnsFile)) {
        this.removeWork(); this.macState = null;
      }
      if (/User canceled|-128/i.test(m)) {
        throw new Error(this.msg(
          'برای حالت TUN باید اجازه دسترسی (رمز عبور) بدهید',
          'TUN mode needs your permission (administrator password)'));
      }
      const detail = (logTail || m).split(/\r?\n/).filter(Boolean).slice(-3).join(' | ');
      throw new Error(this.msg('راه‌اندازی TUN ناموفق بود: ', 'TUN setup failed: ') + detail);
    }

    // Read back the sing-box pid (running as root) and the utun it created.
    let macPid = null;
    try { macPid = parseInt(fs.readFileSync(pidFile, 'utf8').trim(), 10) || null; } catch {}
    let dev = '';
    try { dev = fs.readFileSync(devFile, 'utf8').trim(); } catch {}
    this.onLog(`TUN device: ${dev || 'utun (unit unknown)'}`, 'info');

    Object.assign(this.macState, { macPid, dev });
    if (!macPid || !/^utun\d+$/.test(dev)) throw new Error('TUN setup returned incomplete process/interface state; recovery required');
    this.saveMacSession();
    this.stopping = false;
    this.active = true;

    // Surface sing-box logs into the app log by tailing the (root-owned) file.
    this.startMacLogTail(logFile);
    this.startMacHealthCheck();

    this.onLog(this.msg('حالت TUN فعال شد (کل سیستم).', 'TUN mode active (whole system).'), 'info');
  }

  saveMacSession() {
    const file = path.join(this.macState.work, 'session.json');
    fs.writeFileSync(file + '.tmp', JSON.stringify(this.macState), { mode: 0o600 });
    fs.renameSync(file + '.tmp', file);
  }

  hasPendingMacRecovery() {
    if (this.platform !== 'darwin') return false;
    if (this.macState) return true;
    if (!this.userData) return false;
    const base = path.join(this.userData, 'mac-tun-sessions');
    try { return fs.readdirSync(base).some(n => /^irnf-sb-/.test(n) && fs.existsSync(path.join(base, n, 'session.json'))); }
    catch (e) { if (e.code === 'ENOENT') return false; throw e; }
  }

  async recoverMacSessions() {
    if (this.platform !== 'darwin') return 0;
    const owner = macOwners.get(this.macOwnerKey);
    if (owner && owner !== this) throw new Error('Another tunnel operation is live; disconnect it before recovery');
    if (this.active && !this.stopping) throw new Error('Disconnect the active tunnel before recovery');
    let count = 0;
    if (this.macState) { await this.stopMac(); count++; }
    if (!this.userData) return count;
    const base = path.resolve(this.userData, 'mac-tun-sessions');
    let names;
    try { names = fs.readdirSync(base); } catch (e) { if (e.code === 'ENOENT') return count; throw e; }
    for (const name of names.filter(n => /^irnf-sb-/.test(n))) {
      const work = path.join(base, name);
      if (fs.lstatSync(work).isSymbolicLink()) throw new Error('Invalid tunnel recovery directory');
      const file = path.join(work, 'session.json');
      if (!fs.existsSync(file)) continue;
      if (fs.lstatSync(file).isSymbolicLink()) throw new Error('Invalid tunnel recovery journal');
      const st = JSON.parse(fs.readFileSync(file, 'utf8'));
      if (Number.isInteger(st.ownerPid) && st.ownerPid > 1 && st.ownerPid !== process.pid) {
        try {
          process.kill(st.ownerPid, 0);
          throw new Error('Another application instance may own this tunnel; close it before recovery');
        } catch (e) { if (e.code !== 'ESRCH') throw e; }
      }
      // Reject redirected artifacts before writing or deleting anything.
      if (path.resolve(st.work || '') !== work || !Array.isArray(st.savedDns) || typeof st.bin !== 'string') throw new Error('Invalid tunnel recovery session');
      for (const key of ['cfgFile', 'logFile', 'pidFile', 'devFile', 'identityFile', 'dnsFile']) {
        if (typeof st[key] !== 'string' || path.dirname(path.resolve(st[key])) !== work) throw new Error('Invalid tunnel recovery path');
        if (fs.existsSync(st[key]) && fs.lstatSync(st[key]).isSymbolicLink()) throw new Error('Invalid tunnel recovery artifact');
      }
      this.macState = st; this.work = work;
      await this.stopMac(); count++;
    }
    return count;
  }

  readMacLogChunk(logFile, pos = 0) {
    const size = fs.statSync(logFile).size;
    if (size < pos) pos = 0;
    const start = Math.max(pos, size - 32768);
    const buf = Buffer.alloc(size - start);
    const fd = fs.openSync(logFile, 'r');
    let bytes;
    try { bytes = fs.readSync(fd, buf, 0, buf.length, start); } finally { fs.closeSync(fd); }
    return { text: buf.subarray(0, bytes).toString('utf8'), pos: start + bytes };
  }

  startMacLogTail(logFile) {
    this.stopMacLogTail();
    let pos = 0;
    this.macLogTimer = setInterval(() => {
      try {
        const chunk = this.readMacLogChunk(logFile, pos); pos = chunk.pos;
        for (const line of chunk.text.split(/\r?\n/)) if (line.trim()) this.onLog('[tun] ' + line.trim(), 'warn');
      } catch {}
    }, 1500);
    if (this.macLogTimer.unref) this.macLogTimer.unref();
  }

  stopMacLogTail() {
    if (this.macLogTimer) { clearInterval(this.macLogTimer); this.macLogTimer = null; }
  }

  async checkMacHealth() {
    const st = this.macState;
    if (!st || !this.active || this.stopping || this.macHealthBusy) return;
    this.macHealthBusy = true;
    try {
      const command = await platform.run('ps', ['-ww', '-p', String(st.macPid), '-o', 'command='], { timeout: 3000 });
      const birth = await platform.run('ps', ['-ww', '-p', String(st.macPid), '-o', 'lstart='], { timeout: 3000 });
      if (command.trim() !== `${st.bin} run -c ${st.cfgFile}` || birth.trim() !== fs.readFileSync(st.identityFile, 'utf8').trim()) throw new Error('Tunnel process exited or changed identity');
    } catch (e) {
      if (this.macState !== st || this.stopping || !this.active) return;
      this.active = false;
      this.stopMacHealthCheck(); this.stopMacLogTail();
      this.onLog('TUN process lost; network recovery required: ' + e.message, 'error');
      Promise.resolve().then(() => this.onUnexpectedExit(e)).catch(err => this.onLog('TUN recovery callback: ' + err.message, 'error'));
    } finally { this.macHealthBusy = false; }
  }

  startMacHealthCheck() {
    this.stopMacHealthCheck();
    this.macHealthTimer = setInterval(() => { void this.checkMacHealth(); }, 3000);
    if (this.macHealthTimer.unref) this.macHealthTimer.unref();
  }

  stopMacHealthCheck() {
    if (this.macHealthTimer) clearInterval(this.macHealthTimer);
    this.macHealthTimer = null;
  }

  async stopMac() {
    if (this.macStopPromise) return this.macStopPromise;
    if (!this.macState) return;
    const st = this.macState;
    this.stopping = true;
    this.stopMacLogTail(); this.stopMacHealthCheck();
    this.macStopPromise = (async () => {
      const teardownPath = path.join(st.work, 'teardown.sh');
      try {
        if (fs.existsSync(teardownPath) && fs.lstatSync(teardownPath).isSymbolicLink()) throw new Error('Invalid tunnel teardown path');
        fs.writeFileSync(teardownPath, buildMacTeardownScript({ ...st, pid: st.macPid }), { mode: 0o700 });
        await platform.runScriptPrivileged(teardownPath);
        fs.rmSync(st.work, { recursive: true, force: true });
        this.work = null; this.macState = null; this.active = false; this.excludeIps = [];
        if (!this.macStartPromise && macOwners.get(this.macOwnerKey) === this) macOwners.delete(this.macOwnerKey);
      } catch (e) {
        this.onLog('TUN teardown failed; recovery state retained: ' + e.message, 'error');
        throw e;
      } finally { this.stopping = false; }
    })();
    try { return await this.macStopPromise; } finally { this.macStopPromise = null; }
  }

  /* ----------------------------- Linux (best effort) ----------------------------- */
  async startLinux(socksPort, bypassAddrs, dnsServers, opts) {
    const bin = this.singboxPath();
    if (!bin) throw new Error('sing-box not found in bin/');
    if (process.getuid && process.getuid() !== 0) {
      throw new Error('TUN mode requires root (run with sudo)');
    }
    const ips = await this.bypassIps(bypassAddrs);
    this.excludeIps = ips;
    const { cfgFile } = this.writeConfig(socksPort, ips, opts, TUN_IF);
    const died = await this.launch(bin, cfgFile, { cwd: path.dirname(bin) });
    if (died) {
      this.removeWork();
      throw new Error('sing-box exited immediately' + this.tail(died));
    }
    // auto_route lays the routes; the resolver is left alone (resolv.conf /
    // systemd-resolved differ per distro) — point it at the peer if needed.
    this.onLog(`TUN started on ${TUN_IF} (routes by sing-box; set your resolver to ${TUN_PEER4} if needed).`, 'warn');
    this.active = true;
  }

  /* ----------------------------- public API ----------------------------- */
  /**
   * @param socksPort   Xray's local SOCKS inbound
   * @param bypassAddrs server entry addresses (+ resolver bypass IPs): kept off the tunnel
   * @param dnsServers  what the adapter's resolvers should be (the tunnel peer under managed DNS)
   * @param opts        { ipv6, strict, apps } — `apps` is the per-app split
   *                    (`null | { mode: 'exclude'|'only', names }`), decided by
   *                    tunApps.js and baked into the config (see buildTunConfig)
   */
  async start(socksPort, bypassAddrs, dnsServers, opts = {}) {
    if (this.platform === 'darwin') {
      if (this.macStartPromise) return this.macStartPromise;
      if (this.macStopPromise) await this.macStopPromise;
      if (this.active) return;
      const owner = macOwners.get(this.macOwnerKey);
      if (owner && owner !== this) throw new Error('Another tunnel operation is live; disconnect it first');
      macOwners.set(this.macOwnerKey, this);
      this.macStartPromise = this.startMac(socksPort, bypassAddrs, dnsServers, opts || {});
      try { return await this.macStartPromise; }
      finally {
        this.macStartPromise = null;
        if (!this.macState && !this.active && macOwners.get(this.macOwnerKey) === this) macOwners.delete(this.macOwnerKey);
      }
    }
    if (this.active) return;
    const o = opts || {};
    if (this.platform === 'win32') return this.startWindows(socksPort, bypassAddrs, dnsServers, o);
    if (this.platform === 'darwin') return this.startMac(socksPort, bypassAddrs, dnsServers, o);
    return this.startLinux(socksPort, bypassAddrs, dnsServers, o);
  }

  async stop() {
    // A stop during the administrator prompt must wait until setup has either
    // completed or rolled back, before deleting scripts or recovery files.
    if (this.platform === 'darwin' && this.macStartPromise) {
      try { await this.macStartPromise; } catch {} // still clean a partial setup
    }
    if (!this.active && !this.proc && !this.macState) return;
    if (this.platform === 'darwin') {
      await this.stopMac();
      this.onLog('TUN mode stopped.', 'info');
      return;
    }
    this.active = false;
    this.excludeIps = [];
    const proc = this.proc;
    if (proc) {
      // sing-box removes its routes (and WFP filters) on the way out; nothing
      // else to undo. Wait for the exit, bounded, so a reconnect cannot race it.
      this.stopping = true;
      const exited = this.exited;
      try {
        if (this.platform === 'win32') {
          spawn('taskkill', ['/pid', String(proc.pid), '/t', '/f'], { windowsHide: true });
        } else {
          proc.kill('SIGTERM');
        }
      } catch {}
      await withTimeout(exited, STOP_WAIT_MS, null);
      this.proc = null;
    }
    this.removeWork();
    this.onLog('TUN mode stopped.', 'info');
  }

  /** Synchronous best-effort cleanup for process exit. */
  cleanupSync() {
    const plat = this.platform;
    if (plat === 'win32') {
      if (this.proc && this.proc.pid) {
        try { execFileSync('taskkill', ['/pid', String(this.proc.pid), '/t', '/f'], { stdio: 'ignore', windowsHide: true }); } catch {}
      }
      return;
    }
    if (plat === 'darwin') {
      // Only when already root: we cannot show a password prompt during process
      // exit. Graceful disconnect / quit already ran the async privileged teardown.
      if (!(process.getuid && process.getuid() === 0)) return;
      const st = this.macState;
      if (!st) return;
      try {
        const script = path.join(st.work, 'teardown-sync.sh');
        fs.writeFileSync(script, buildMacTeardownScript({ ...st, pid: st.macPid }), { mode: 0o700 });
        execFileSync('/bin/bash', [script], { stdio: 'ignore', timeout: 12000 });
      } catch {} // The durable journal remains available on the next launch.
      return;
    }
    try { if (this.proc) this.proc.kill('SIGTERM'); } catch {}
  }
}

module.exports = {
  TunSingbox, buildTunConfig, buildMacSetupScript, buildMacTeardownScript, cidrOf,
  TUN_IF, TUN_ADDR4, TUN_PEER4, TUN_ADDR6, TUN_PEER6
};
