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
 */
function buildTunConfig({ socksPort, excludeIps = [], ipv6 = false, strict = false, stack = 'system', mtu = 1500, interfaceName = TUN_IF } = {}) {
  void ipv6;
  const inbound = { type: 'tun', tag: 'tun-in' };
  if (interfaceName) inbound.interface_name = interfaceName;
  inbound.address = [TUN_ADDR4, TUN_ADDR6];          // v6 entry ALWAYS present (see above)
  inbound.mtu = mtu;
  inbound.auto_route = true;
  inbound.strict_route = !!strict;
  inbound.stack = stack;
  inbound.route_exclude_address = excludeIps.filter(Boolean).map(cidrOf);
  return {
    log: { level: 'warn', timestamp: false },
    inbounds: [inbound],
    outbounds: [{ type: 'socks', tag: 'socks-out', server: '127.0.0.1', server_port: socksPort, version: '5' }],
    route: { final: 'socks-out', auto_detect_interface: true }
  };
}

/**
 * The privileged macOS setup script. Pure, so a reviewer can read every line
 * without a Mac. NOTE: no `set -e` — the critical step (a new utun) is checked
 * explicitly so a benign non-zero cannot abort the script, and a failure
 * prints the sing-box log to stderr for diagnosis.
 */
function buildMacSetupScript({ bin, cfgFile, logFile, pidFile, devFile, service, dnsServers = [] }) {
  const dnsLine = (service && dnsServers.length)
    ? `networksetup -setdnsservers ${sh(service)} ${dnsServers.join(' ')} 2>/dev/null || true`
    : 'true';
  return [
    '#!/bin/bash',
    // Ignore hangups so sing-box keeps running after this privileged shell
    // exits. SIG_IGN is inherited by the child, so the daemon survives WITHOUT
    // `nohup` — which fails under `osascript do shell script` with
    // "nohup: can't detach from console: Inappropriate ioctl for device".
    "trap '' HUP",
    `BIN=${sh(bin)}`,
    `CFG=${sh(cfgFile)}`,
    `LOG=${sh(logFile)}`,
    `PIDFILE=${sh(pidFile)}`,
    `DEVFILE=${sh(devFile)}`,
    // snapshot existing utun interfaces (single space-separated line)
    'BEFORE=" $(ifconfig -l 2>/dev/null) "',
    // 1) launch sing-box as root, backgrounded with all FDs redirected so it
    //    keeps running after the privileged shell returns (no controlling tty
    //    under osascript, and HUP is trapped above → no SIGHUP reaches it).
    '"$BIN" run -c "$CFG" >"$LOG" 2>&1 </dev/null &',
    'SBPID=$!',
    'echo "$SBPID" > "$PIDFILE"',
    // 2) wait for a NEW utun device: sing-box names the unit itself (sing-tun
    //    on darwin only accepts utun<N>, so the config carries no name). Stop
    //    waiting early when the process is already gone.
    'ACTUAL=""',
    'i=0',
    'while [ $i -lt 50 ]; do',
    '  for u in $(ifconfig -l 2>/dev/null); do',
    '    case "$u" in',
    '      utun*)',
    '        case "$BEFORE" in',
    '          *" $u "*) ;;',
    '          *) ACTUAL="$u"; break;;',
    '        esac;;',
    '    esac',
    '  done',
    '  if [ -n "$ACTUAL" ]; then break; fi',
    '  if ! kill -0 "$SBPID" 2>/dev/null; then break; fi',
    '  i=$((i+1))',
    '  sleep 0.3',
    'done',
    'if [ -z "$ACTUAL" ]; then',
    '  echo "ERR: sing-box did not create a utun device" >&2',
    '  echo "----- sing-box log -----" >&2',
    '  cat "$LOG" >&2 2>/dev/null',
    '  exit 11',
    'fi',
    'echo "$ACTUAL" > "$DEVFILE"',
    // 3) NO ifconfig / route lines: auto_route set the address and the v4+v6
    //    default routes, and removes them again on SIGTERM.
    // 4) DNS through the tunnel (leak prevention)
    dnsLine,
    'exit 0',
    ''
  ].join('\n');
}

/** The privileged macOS teardown script. Pure. */
function buildMacTeardownScript({ pid, cfgFile, service, savedDns }) {
  const lines = ['#!/bin/bash'];
  const p = parseInt(pid, 10) || 0;
  if (p) {
    // SIGTERM: sing-box removes its routes and the utun on the way out. Wait
    // (bounded, 4 s) so a reconnect cannot race a tunnel that is still going.
    lines.push(`kill ${p} 2>/dev/null || true`);
    lines.push('i=0');
    lines.push(`while [ $i -lt 20 ] && kill -0 ${p} 2>/dev/null; do i=$((i+1)); sleep 0.2; done`);
  }
  // belt-and-braces: any sing-box we launched on this config, by its argv
  if (cfgFile) lines.push(`pkill -f ${sh(`sing-box run -c ${cfgFile}`)} 2>/dev/null || true`);
  if (service) {
    const dns = (savedDns && savedDns.length) ? savedDns.join(' ') : 'Empty';
    lines.push(`networksetup -setdnsservers ${sh(service)} ${dns} 2>/dev/null || true`);
  }
  lines.push('exit 0', '');
  return lines.join('\n');
}

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

  /** sing-box present; on Windows wintun.dll in the SAME dir (sing-box loads it from its own). */
  isAvailable() {
    const bin = this.singboxPath();
    if (!bin) return false;
    if (this.platform === 'win32') return fs.existsSync(path.join(path.dirname(bin), 'wintun.dll'));
    return true;
  }

  isElevated() { return platform.isElevated(this.platform); }

  /** The interface Xray's direct outbounds bind to — read before start(). */
  physicalInterface() { return platform.physicalInterface(this.platform); }

  /* ----------------------------- shared steps ----------------------------- */

  /** Split the caller's adapter resolvers by family; the tunnel peer fills a gap. */
  adapterDns(dnsServers, opts) {
    const list = (Array.isArray(dnsServers) ? dnsServers : [dnsServers])
      .map(s => String(s == null ? '' : s).trim()).filter(Boolean);
    const v4 = list.filter(s => !s.includes(':')).slice(0, 2);
    const v6 = list.filter(s => s.includes(':')).slice(0, 2);
    return {
      v4: v4.length ? v4 : [TUN_PEER4],
      v6: v6.length ? v6 : (opts.ipv6 ? [TUN_PEER6] : [])
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
    const work = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-sb-'));
    const cfgFile = path.join(work, 'sing-box.json');
    const cfg = buildTunConfig({ socksPort, excludeIps, ipv6: !!opts.ipv6, strict: !!opts.strict, interfaceName });
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
    if (!fs.existsSync(path.join(path.dirname(bin), 'wintun.dll'))) {
      throw new Error(this.msg(
        'wintun.dll کنار sing-box.exe نیست — حالت TUN بدون آن اجرا نمی‌شود',
        'wintun.dll is not next to sing-box.exe — TUN mode cannot run without it'));
    }
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
    if (dns.v6[0]) {
      await platform.run('netsh', ['interface', 'ipv6', 'set', 'dnsservers', `name=${TUN_IF}`, 'static', dns.v6[0], 'primary', 'validate=no'])
        .catch(e => this.onLog('set dns (v6): ' + e.message, 'warn'));
    }
    if (dns.v6[1]) {
      await platform.run('netsh', ['interface', 'ipv6', 'add', 'dnsservers', `name=${TUN_IF}`, dns.v6[1], 'index=2', 'validate=no']).catch(() => {});
    }
    this.onLog(`TUN adapter ${TUN_IF} up; DNS ${[...dns.v4, ...dns.v6].join(', ')}; routes by sing-box (auto_route)`, 'info');

    this.active = true;
    this.onLog(this.msg('حالت TUN فعال شد (کل سیستم).', 'TUN mode active (whole system).'), 'info');
  }

  /* ----------------------------- macOS (blind) ----------------------------- */
  async startMac(socksPort, bypassAddrs, dnsServers, opts) {
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
    const savedDns = service ? await platform.getServiceDnsMac(service) : [];
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
    fs.writeFileSync(setupPath, buildMacSetupScript({
      bin, cfgFile, logFile, pidFile, devFile, service, dnsServers: [...dns.v4, ...dns.v6]
    }), { mode: 0o700 });

    this.onLog('Starting sing-box (you may be asked for your password)…', 'info');
    try {
      await platform.runScriptPrivileged(setupPath);
    } catch (e) {
      const m = (e.message || '').toString();
      // Make the sing-box output visible in the app log for diagnosis.
      let logTail = '';
      try { logTail = fs.readFileSync(logFile, 'utf8').trim(); } catch {}
      if (logTail) {
        for (const line of logTail.split(/\r?\n/).slice(-12)) {
          if (line.trim()) this.onLog('[tun] ' + line.trim(), 'error');
        }
      }
      this.removeWork();
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

    this.macState = { work, cfgFile, logFile, pidFile, macPid, service, savedDns, dev };
    this.active = true;

    // Surface sing-box logs into the app log by tailing the (root-owned) file.
    this.startMacLogTail(logFile);

    this.onLog(this.msg('حالت TUN فعال شد (کل سیستم).', 'TUN mode active (whole system).'), 'info');
  }

  /** Periodically tail new lines from the sing-box log file. */
  startMacLogTail(logFile) {
    this.stopMacLogTail();
    let pos = 0;
    this.macLogTimer = setInterval(() => {
      try {
        const stat = fs.statSync(logFile);
        if (stat.size < pos) pos = 0;
        if (stat.size === pos) return;
        const fd = fs.openSync(logFile, 'r');
        const len = stat.size - pos;
        const buf = Buffer.alloc(len);
        fs.readSync(fd, buf, 0, len, pos);
        fs.closeSync(fd);
        pos = stat.size;
        for (const line of buf.toString('utf8').split(/\r?\n/)) {
          if (line.trim()) this.onLog('[tun] ' + line.trim(), 'warn');
        }
      } catch {}
    }, 1500);
    if (this.macLogTimer.unref) this.macLogTimer.unref();
  }

  stopMacLogTail() {
    if (this.macLogTimer) { clearInterval(this.macLogTimer); this.macLogTimer = null; }
  }

  async stopMac() {
    this.stopMacLogTail();
    const st = this.macState || {};
    const work = st.work || fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-sb-'));
    const teardownPath = path.join(work, 'teardown.sh');
    try {
      fs.writeFileSync(teardownPath, buildMacTeardownScript({
        pid: st.macPid, cfgFile: st.cfgFile, service: st.service, savedDns: st.savedDns
      }), { mode: 0o700 });
      await platform.runScriptPrivileged(teardownPath);
    } catch (e) {
      this.onLog('TUN teardown: ' + (e.message || e), 'warn');
    }
    try { fs.rmSync(work, { recursive: true, force: true }); } catch {}
    this.work = null;
    this.macState = null;
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
   * @param opts        { ipv6, strict }
   */
  async start(socksPort, bypassAddrs, dnsServers, opts = {}) {
    if (this.active) return;
    const o = opts || {};
    if (this.platform === 'win32') return this.startWindows(socksPort, bypassAddrs, dnsServers, o);
    if (this.platform === 'darwin') return this.startMac(socksPort, bypassAddrs, dnsServers, o);
    return this.startLinux(socksPort, bypassAddrs, dnsServers, o);
  }

  async stop() {
    if (!this.active && !this.proc && !this.macState) return;
    this.active = false;
    this.excludeIps = [];
    if (this.platform === 'darwin') {
      await this.stopMac().catch((e) => this.onLog('TUN stop: ' + (e.message || e), 'warn'));
      this.onLog('TUN mode stopped.', 'info');
      return;
    }
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
      const st = this.macState || {};
      try { if (st.macPid) execFileSync('kill', [String(st.macPid)], { stdio: 'ignore' }); } catch {}
      if (st.service) {
        const dns = (st.savedDns && st.savedDns.length) ? st.savedDns : ['Empty'];
        try { execFileSync('networksetup', ['-setdnsservers', st.service, ...dns], { stdio: 'ignore' }); } catch {}
      }
      return;
    }
    try { if (this.proc) this.proc.kill('SIGTERM'); } catch {}
  }
}

module.exports = {
  TunSingbox, buildTunConfig, buildMacSetupScript, buildMacTeardownScript, cidrOf,
  TUN_IF, TUN_ADDR4, TUN_PEER4, TUN_ADDR6, TUN_PEER6
};
