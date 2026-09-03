'use strict';
/**
 * TUN mode (system-wide tunnel) using tun2socks + wintun on Windows.
 *
 * Flow:
 *   1. Xray runs with a local SOCKS inbound (already started by XrayManager).
 *   2. tun2socks creates a TUN adapter and forwards all IP packets to that SOCKS.
 *   3. We set the adapter IP, add a default route through it, and add /32 routes
 *      for the *real* server IP(s) via the original gateway so the proxy's own
 *      traffic doesn't loop back into the tunnel.
 *
 * Requires Administrator privileges and:
 *   - bin/tun2socks.exe
 *   - bin/wintun.dll  (next to tun2socks.exe)
 *
 * On stop we tear down every route we added and kill tun2socks.
 *
 * macOS: a full implementation creates a utun device with tun2socks, sets the
 *   point-to-point address, adds split-default + bypass routes and tunnel DNS.
 *   Privileged commands run directly when root, otherwise through a single
 *   `osascript` administrator prompt. Linux is best-effort.
 *
 * This is the legacy backend: tunSingbox.js (sing-box, auto_route, v4+v6) is
 * preferred when installed. The command/route/DNS helpers both share live in
 * tunPlatform.js; the methods below delegate to them so the surface here is
 * unchanged.
 */

const { spawn, execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');
const platform = require('./tunPlatform');
const { run, delay, sh, isOwnTunInterface } = platform;

const ADAPTER = platform.TUN2SOCKS_ADAPTER;   // 'XrayTun'
// macOS: let the kernel assign the next free utun unit. Forcing a specific
// unit (e.g. utun123) fails when it's taken/out of range and tun2socks exits
// before any device appears. We detect the actual device it created instead.
const MAC_TUN_DEV = 'utun';
const TUN_ADDR = '10.255.0.2';
const TUN_MASK = '255.255.255.0';
const TUN_GW = '10.255.0.1';
// Split-default routes (two /1 routes) override the OS default route without
// deleting it, so cleanup is clean and the real gateway stays intact.
const SPLIT_ROUTES = ['0.0.0.0', '128.0.0.0'];

class TunManager {
  constructor(opts = {}) {
    this.binDir = opts.binDir;
    // Writable dirs (e.g. userData/bin) checked first so downloads/updates win.
    this.extraDirs = (opts.extraDirs || []).filter(Boolean);
    this.onLog = opts.onLog || (() => {});
    this.proc = null;
    this.active = false;
    this.savedGateway = null;
    this.bypassIps = [];   // every /32 we added so we can remove them all
    this.tunIfIndex = null;
    this.dnsServers = ['1.1.1.1', '8.8.8.8'];
    this.lang = opts.lang || 'fa';   // user-facing error language
    this.macState = null;            // macOS TUN runtime state (pid, routes, dns)
    this.macLogTimer = null;
  }

  /** Pick the message in the user's language (fa default). */
  msg(fa, en) { return this.lang === 'en' ? en : fa; }

  /**
   * The resolved bypass addresses of the live tunnel, under the name the
   * sing-box backend uses (its `bypassIps` is a METHOD; here it is the array
   * of /32 routes kept for cleanup — callers use this getter, never that).
   */
  get excludeIps() { return this.bypassIps.slice(); }

  /**
   * The physical NIC the machine's default route uses. The connect path binds
   * Xray's own dials to it before the tunnel goes up (see configBuilder's
   * bindDirectDials) — this backend needs it just as much as sing-box does:
   * its /1 split routes are exactly what a `direct` dial would loop back into.
   */
  physicalInterface() { return platform.physicalInterface(); }

  dirs() {
    return [
      ...this.extraDirs,
      this.binDir,
      path.join(process.resourcesPath || '', 'bin')
    ].filter(Boolean);
  }

  tun2socksPath() {
    const exe = os.platform() === 'win32' ? 'tun2socks.exe' : 'tun2socks';
    return this.dirs().map(d => path.join(d, exe)).find(p => fs.existsSync(p)) || null;
  }

  isAvailable() {
    const t = this.tun2socksPath();
    if (!t) return false;
    if (os.platform() === 'win32') {
      // wintun.dll can live next to tun2socks OR in any known dir
      return this.dirs().some(d => fs.existsSync(path.join(d, 'wintun.dll')))
        || fs.existsSync(path.join(path.dirname(t), 'wintun.dll'));
    }
    return true;
  }

  /* --- shared helpers (tunPlatform.js), kept as methods so the surface is unchanged --- */

  /** Whether TUN mode can be activated without a separate "relaunch elevated" step. */
  isElevated() { return platform.isElevated(); }

  /** Resolve one or many hostnames/IPs to all their IPv4 addresses. */
  resolveServerIps(serverAddress) { return platform.resolveServerIps(serverAddress); }

  /** Discover the current default gateway + interface index (Windows). */
  getDefaultGatewayWin() { return platform.getDefaultGatewayWin(); }

  /** Get the interface index of our TUN adapter once it exists. */
  getTunIfIndex() { return platform.getTunIfIndex(ADAPTER); }

  /** Wait until the adapter exists AND its admin/connect state is up. */
  waitForAdapter(name, timeout) { return platform.waitForAdapter(name, timeout); }

  /** Run a privileged shell script: directly if root, else via an osascript prompt. */
  runScriptPrivileged(scriptPath) { return platform.runScriptPrivileged(scriptPath); }

  /** Parse `route -n get default` → { gateway, interface }. */
  getDefaultRouteMac() { return platform.getDefaultRouteMac(); }

  /** Map a BSD device (en0) to its networksetup service name ("Wi-Fi"). */
  serviceForDeviceMac(device) { return platform.serviceForDeviceMac(device); }

  /** Current DNS servers for a service, or [] if set to automatic/DHCP. */
  getServiceDnsMac(service) { return platform.getServiceDnsMac(service); }

  /* ----------------------------- Windows ----------------------------- */
  async startWindows(socksPort, serverAddress, dnsServers) {
    const bin = this.tun2socksPath();
    if (!bin) throw new Error(this.msg(
      'tun2socks.exe پیدا نشد — آن را در پوشه bin بگذارید',
      'tun2socks.exe not found — put it in the bin folder'));
    if (!fs.existsSync(path.join(path.dirname(bin), 'wintun.dll'))) {
      throw new Error(this.msg(
        'wintun.dll کنار tun2socks.exe نیست — حالت TUN بدون آن اجرا نمی‌شود',
        'wintun.dll is not next to tun2socks.exe — TUN mode cannot run without it'));
    }
    if (!this.isElevated()) {
      throw new Error(this.msg(
        'حالت TUN نیاز به دسترسی Administrator دارد — برنامه را با «Run as administrator» اجرا کنید',
        'TUN mode needs Administrator rights — relaunch the app as administrator'));
    }
    if (Array.isArray(dnsServers) && dnsServers.length) this.dnsServers = dnsServers.slice(0, 2);

    // 1) record current default gateway BEFORE we change routes
    const gw = await this.getDefaultGatewayWin();
    this.savedGateway = gw;
    if (!gw.nextHop) throw new Error(this.msg(
      'دروازه پیش‌فرض شبکه پیدا نشد',
      'Default network gateway not found'));
    this.onLog(`Default gateway: ${gw.nextHop} (if ${gw.ifIndex})`, 'info');

    // 2) resolve ALL server IPs and add bypass routes (avoid loopback)
    const ips = await this.resolveServerIps(serverAddress);
    if (!ips.length) this.onLog(this.msg(
      `نتوانستم IP سرور (${serverAddress}) را resolve کنم — ممکن است حلقه ایجاد شود`,
      `Could not resolve server IP (${serverAddress}) — a routing loop may occur`), 'warn');
    const ifArgs = gw.ifIndex ? ['if', String(gw.ifIndex)] : [];
    for (const ip of ips) {
      await run('route', ['add', ip, 'mask', '255.255.255.255', gw.nextHop, 'metric', '1', ...ifArgs])
        .then(() => { this.bypassIps.push(ip); this.onLog(`Bypass route for ${ip} via ${gw.nextHop}`, 'info'); })
        .catch(e => this.onLog('Bypass route failed: ' + e.message, 'warn'));
    }
    // 3) launch tun2socks (let it manage the wintun adapter + DNS hijack)
    this.onLog('Starting tun2socks…', 'info');
    // tun2socks v2.x uses the bare adapter name as the wintun device on Windows
    // (the legacy "wintun://" scheme is no longer a recognized driver).
    this.proc = spawn(bin, [
      '-device', ADAPTER,
      '-proxy', `socks5://127.0.0.1:${socksPort}`,
      '-loglevel', 'warn'
    ], { cwd: path.dirname(bin), windowsHide: true });

    this.proc.stdout.on('data', d => this.onLog('[tun] ' + d.toString().trim(), 'log'));
    this.proc.stderr.on('data', d => this.onLog('[tun] ' + d.toString().trim(), 'warn'));
    this.proc.on('exit', (code) => {
      this.onLog(`tun2socks exited (${code})`, code === 0 ? 'info' : 'error');
      if (this.active) this.cleanupRoutesWindows().catch(() => {});
      this.active = false;
      this.proc = null;
    });

    // give the process a moment to fail fast (missing dll, bad args, etc.)
    await delay(400);
    if (!this.proc) throw new Error(this.msg(
      'tun2socks بلافاصله بسته شد — لاگ‌ها را بررسی کنید',
      'tun2socks exited immediately — check the logs'));

    // 4) wait for the adapter to actually be ready (present AND up)
    const ready = await this.waitForAdapter(ADAPTER, 12000);
    if (!ready) {
      await this.stop();
      throw new Error(this.msg(
        'آداپتور TUN آماده نشد — دسترسی ادمین و wintun.dll را بررسی کنید',
        'TUN adapter did not become ready — check admin rights and wintun.dll'));
    }

    // 5) grab the TUN interface index — every route is pinned to it explicitly
    this.tunIfIndex = await this.getTunIfIndex();
    if (!this.tunIfIndex) {
      await this.stop();
      throw new Error(this.msg(
        'Interface index آداپتور TUN پیدا نشد',
        'TUN adapter interface index not found'));
    }
    this.onLog(`TUN adapter ifIndex=${this.tunIfIndex}`, 'info');

    // 6) assign the adapter IP WITHOUT a gateway (gateway here would create a
    //    competing default route). Point-to-point gateway TUN_GW stays on-link.
    await run('netsh', ['interface', 'ip', 'set', 'address', `name=${ADAPTER}`,
      'static', TUN_ADDR, TUN_MASK])
      .catch(e => this.onLog('set address: ' + e.message, 'warn'));

    // lower the interface metric so TUN routes always win over the physical NIC
    await run('netsh', ['interface', 'ip', 'set', 'interface', `interface=${ADAPTER}`, 'metric=1'])
      .catch(() => {});

    // 7) DNS through the tunnel (leak prevention): force resolvers on the TUN
    await run('netsh', ['interface', 'ip', 'set', 'dnsservers', `name=${ADAPTER}`,
      'static', this.dnsServers[0], 'primary', 'validate=no'])
      .catch(() => {});
    if (this.dnsServers[1]) {
      await run('netsh', ['interface', 'ip', 'add', 'dnsservers', `name=${ADAPTER}`,
        this.dnsServers[1], 'index=2', 'validate=no']).catch(() => {});
    }

    // 8) split-default routes through TUN, pinned to the TUN interface index.
    //    Two /1 routes override the OS default without deleting it.
    let routed = false;
    for (const net of SPLIT_ROUTES) {
      try {
        await run('route', ['add', net, 'mask', '128.0.0.0', TUN_GW,
          'metric', '1', 'if', String(this.tunIfIndex)]);
        routed = true;
      } catch (e) {
        this.onLog(`route ${net}/1: ` + e.message, 'warn');
      }
    }
    if (!routed) {
      await this.stop();
      throw new Error(this.msg(
        'افزودن روت پیش‌فرض به TUN ناموفق بود — اتصال لغو شد',
        'Failed to add the default route to TUN — connection aborted'));
    }
    this.onLog('Default traffic -> TUN (split routes, pinned to ifIndex)', 'info');

    this.active = true;
    this.onLog(this.msg('حالت TUN فعال شد (کل سیستم).', 'TUN mode active (whole system).'), 'info');
  }

  async cleanupRoutesWindows() {
    for (const net of SPLIT_ROUTES) {
      await run('route', ['delete', net, 'mask', '128.0.0.0', TUN_GW]).catch(() => {});
    }
    for (const ip of this.bypassIps) {
      await run('route', ['delete', ip]).catch(() => {});
    }
    this.bypassIps = [];
    this.tunIfIndex = null;
  }

  /* ----------------------------- macOS ----------------------------- */

  async startMac(socksPort, serverAddress, dnsServers) {
    const bin = this.tun2socksPath();
    if (!bin) throw new Error(this.msg(
      'tun2socks پیدا نشد — آن را در پوشه bin بگذارید (از «فایل‌های موردنیاز» دانلود کن)',
      'tun2socks not found — put it in the bin folder (download it from "Required files")'));

    // A previously-downloaded binary may be quarantined/unsigned — on Apple
    // Silicon that means it is SIGKILL'd at exec ("Killed: 9"), which then looks
    // like "tun2socks did not create a utun device". Re-sign it (ad-hoc) and
    // strip quarantine here so even old downloads run.
    try { execFileSync('xattr', ['-dr', 'com.apple.quarantine', bin], { stdio: 'ignore' }); } catch {}
    try { execFileSync('codesign', ['--force', '--sign', '-', bin], { stdio: 'ignore' }); } catch {}

    if (Array.isArray(dnsServers) && dnsServers.length) this.dnsServers = dnsServers.slice(0, 2);

    const route = await this.getDefaultRouteMac();
    if (!route.gateway || !route.device) throw new Error(this.msg(
      'دروازه/اینترفیس پیش‌فرض شبکه پیدا نشد',
      'Default network gateway/interface not found'));
    this.onLog(`Default gateway: ${route.gateway} (dev ${route.device})`, 'info');

    const service = await this.serviceForDeviceMac(route.device);
    const savedDns = service ? await this.getServiceDnsMac(service) : [];

    const ips = await this.resolveServerIps(serverAddress);
    if (!ips.length) this.onLog(this.msg(
      `نتوانستم IP سرور (${serverAddress}) را resolve کنم — ممکن است حلقه ایجاد شود`,
      `Could not resolve server IP (${serverAddress}) — a routing loop may occur`), 'warn');

    const work = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-tun-'));
    const logFile = path.join(work, 'tun2socks.log');
    const pidFile = path.join(work, 'tun2socks.pid');
    const devFile = path.join(work, 'tun2socks.dev');
    const reqDev = MAC_TUN_DEV;
    const dns1 = this.dnsServers[0] || '1.1.1.1';
    const dns2 = this.dnsServers[1] || '';

    const bypassAdd = ips.map(ip => `route -n add -host ${sh(ip)} ${sh(route.gateway)} >/dev/null 2>&1 || true`).join('\n');
    const dnsLine = service
      ? `networksetup -setdnsservers ${sh(service)} ${dns1}${dns2 ? ' ' + dns2 : ''} 2>/dev/null || true`
      : 'true';

    // NOTE: no `set -e` — we validate the critical steps explicitly so a
    // benign non-zero (e.g. grep with no match) can't abort the whole script,
    // and so failures print the tun2socks log to stderr for diagnosis.
    const setup = [
      '#!/bin/bash',
      // Ignore hangups so tun2socks keeps running after this privileged shell
      // exits. SIG_IGN is inherited by the child, so the daemon survives WITHOUT
      // `nohup` — which fails under `osascript do shell script` with
      // "nohup: can't detach from console: Inappropriate ioctl for device".
      "trap '' HUP",
      `BIN=${sh(bin)}`,
      `REQ_DEV=${sh(reqDev)}`,
      `LOG=${sh(logFile)}`,
      `PIDFILE=${sh(pidFile)}`,
      `DEVFILE=${sh(devFile)}`,
      // snapshot existing utun interfaces (single space-separated line)
      'BEFORE=" $(ifconfig -l 2>/dev/null) "',
      // 1) launch tun2socks as root, backgrounded with all FDs redirected so it
      //    keeps running after the privileged shell returns (no controlling tty
      //    under osascript, and HUP is trapped above → no SIGHUP reaches it).
      //    `warn` matches the (working) Windows log level.
      `"$BIN" -device "$REQ_DEV" -proxy ${sh(`socks5://127.0.0.1:${socksPort}`)} -loglevel warn >"$LOG" 2>&1 </dev/null &`,
      'echo $! > "$PIDFILE"',
      // 2) wait for a NEW utun device (tun2socks may pick the next free unit
      //    instead of the exact name we requested).
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
      '  i=$((i+1))',
      '  sleep 0.3',
      'done',
      'if [ -z "$ACTUAL" ]; then',
      '  echo "ERR: tun2socks did not create a utun device" >&2',
      '  echo "----- tun2socks log -----" >&2',
      '  cat "$LOG" >&2 2>/dev/null',
      '  exit 11',
      'fi',
      'echo "$ACTUAL" > "$DEVFILE"',
      // 3) point-to-point address on the tunnel (local 10.255.0.2, peer
      //    10.255.0.1 — cosmetic; routing is pinned to the interface below).
      `ifconfig "$ACTUAL" ${TUN_ADDR} ${TUN_GW} up || { echo "ERR: ifconfig failed" >&2; exit 12; }`,
      `ifconfig "$ACTUAL" mtu 1500 2>/dev/null`,
      // 4) bypass routes for the proxy server itself (avoid loopback)
      bypassAdd || 'true',
      // 5) split-default routes through the tunnel, pinned to the INTERFACE (not
      //    the peer IP). On a macOS utun the peer 10.255.0.1 is not a resolvable
      //    next-hop, so `route add -net 0/1 10.255.0.1` black-holes; `-interface`
      //    is the correct form. Two /1 routes override the default without
      //    deleting it. Delete first so a leftover route can't error out.
      `route -n delete -net 0.0.0.0/1 -interface "$ACTUAL" >/dev/null 2>&1`,
      `route -n delete -net 128.0.0.0/1 -interface "$ACTUAL" >/dev/null 2>&1`,
      `OUT=$(route -n add -net 0.0.0.0/1 -interface "$ACTUAL" 2>&1) || { echo "ERR: route 0/1 failed: $OUT" >&2; exit 13; }`,
      `OUT=$(route -n add -net 128.0.0.0/1 -interface "$ACTUAL" 2>&1) || { echo "ERR: route 128/1 failed: $OUT" >&2; exit 13; }`,
      // 6) DNS through the tunnel (leak prevention)
      dnsLine,
      'exit 0',
      ''
    ].join('\n');

    const setupPath = path.join(work, 'setup.sh');
    fs.writeFileSync(setupPath, setup, { mode: 0o700 });

    this.onLog('Starting tun2socks (you may be asked for your password)…', 'info');
    try {
      await this.runScriptPrivileged(setupPath);
    } catch (e) {
      const m = (e.message || '').toString();
      // Make the tun2socks output visible in the app log for diagnosis.
      let logTail = '';
      try { logTail = fs.readFileSync(logFile, 'utf8').trim(); } catch {}
      if (logTail) {
        for (const line of logTail.split(/\r?\n/).slice(-12)) {
          if (line.trim()) this.onLog('[tun] ' + line.trim(), 'error');
        }
      }
      try { fs.rmSync(work, { recursive: true, force: true }); } catch {}
      if (/User canceled|-128/i.test(m)) {
        throw new Error(this.msg(
          'برای حالت TUN باید اجازه دسترسی (رمز عبور) بدهید',
          'TUN mode needs your permission (administrator password)'));
      }
      const detail = (logTail || m).split(/\r?\n/).filter(Boolean).slice(-3).join(' | ');
      throw new Error(this.msg('راه‌اندازی TUN ناموفق بود: ', 'TUN setup failed: ') + detail);
    }

    // Read back the tun2socks pid (running as root) and the real device name.
    let macPid = null;
    try { macPid = parseInt(fs.readFileSync(pidFile, 'utf8').trim(), 10) || null; } catch {}
    let dev = reqDev;
    try { dev = (fs.readFileSync(devFile, 'utf8').trim()) || reqDev; } catch {}
    this.onLog(`TUN device: ${dev}`, 'info');

    this.macState = { work, logFile, pidFile, macPid, service, savedDns, bypassIps: ips, dev, reqDev };
    this.bypassIps = ips.slice();
    this.active = true;

    // Surface tun2socks logs into the app log by tailing the (root-owned) file.
    this.startMacLogTail(logFile);

    this.onLog(this.msg('حالت TUN فعال شد (کل سیستم).', 'TUN mode active (whole system).'), 'info');
  }

  /** Periodically tail new lines from the tun2socks log file. */
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
    const dns1 = (st.savedDns && st.savedDns.length) ? st.savedDns.join(' ') : 'Empty';
    const dev = st.dev || '';
    const lines = ['#!/bin/bash'];
    if (st.macPid) lines.push(`kill ${st.macPid} 2>/dev/null || true`);
    // belt-and-suspenders: also kill any tun2socks we launched. Match on the
    // device flag we pass at launch (`-device utun`).
    lines.push(`pkill -f ${sh(`-device ${st.reqDev || MAC_TUN_DEV}`)} 2>/dev/null || true`);
    // Delete the split-default routes using the SAME (interface-pinned) form we
    // added them with — otherwise they leak and break all networking after
    // disconnect until reboot.
    if (dev) {
      lines.push(`route -n delete -net 0.0.0.0/1 -interface ${sh(dev)} 2>/dev/null || true`);
      lines.push(`route -n delete -net 128.0.0.0/1 -interface ${sh(dev)} 2>/dev/null || true`);
    }
    // legacy cleanup: also try the old peer-IP form in case a route from a
    // previous app version is still installed.
    lines.push(`route -n delete -net 0.0.0.0/1 ${TUN_GW} 2>/dev/null || true`);
    lines.push(`route -n delete -net 128.0.0.0/1 ${TUN_GW} 2>/dev/null || true`);
    for (const ip of (st.bypassIps || this.bypassIps || [])) {
      lines.push(`route -n delete -host ${sh(ip)} 2>/dev/null || true`);
    }
    if (st.service) lines.push(`networksetup -setdnsservers ${sh(st.service)} ${dns1} 2>/dev/null || true`);
    lines.push('exit 0', '');

    const work = st.work || fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-tun-'));
    const teardownPath = path.join(work, 'teardown.sh');
    try {
      fs.writeFileSync(teardownPath, lines.join('\n'), { mode: 0o700 });
      await this.runScriptPrivileged(teardownPath);
    } catch (e) {
      this.onLog('TUN teardown: ' + (e.message || e), 'warn');
    }
    try { fs.rmSync(work, { recursive: true, force: true }); } catch {}
    this.macState = null;
    this.bypassIps = [];
  }

  /* ----------------------------- Linux (best effort) ----------------------------- */
  async startLinux(socksPort, serverAddress) {
    const bin = this.tun2socksPath();
    if (!bin) throw new Error('tun2socks not found in bin/');
    if (process.getuid && process.getuid() !== 0) {
      throw new Error('TUN mode requires root (run with sudo)');
    }
    const dev = 'tun0';
    this.proc = spawn(bin, [
      '-device', dev,
      '-proxy', `socks5://127.0.0.1:${socksPort}`,
      '-loglevel', 'warn'
    ], { cwd: path.dirname(bin) });
    this.proc.stdout.on('data', d => this.onLog('[tun] ' + d.toString().trim(), 'log'));
    this.proc.stderr.on('data', d => this.onLog('[tun] ' + d.toString().trim(), 'warn'));
    this.proc.on('exit', (c) => { this.active = false; this.proc = null; this.onLog('tun2socks exited ' + c, 'info'); });

    this.onLog('TUN started on ' + dev + ' (configure routes manually if needed).', 'warn');
    this.active = true;
  }

  /* ----------------------------- public API ----------------------------- */
  async start(socksPort, serverAddress, dnsServers) {
    if (this.active) return;
    const plat = os.platform();
    if (plat === 'win32') return this.startWindows(socksPort, serverAddress, dnsServers);
    if (plat === 'darwin') return this.startMac(socksPort, serverAddress, dnsServers);
    return this.startLinux(socksPort, serverAddress);
  }

  async stop() {
    if (!this.active && !this.proc && !this.macState) return;
    this.active = false;
    const plat = os.platform();
    if (plat === 'win32') {
      await this.cleanupRoutesWindows().catch(() => {});
    } else if (plat === 'darwin') {
      await this.stopMac().catch((e) => this.onLog('TUN stop: ' + (e.message || e), 'warn'));
      this.onLog('TUN mode stopped.', 'info');
      return;
    }
    if (this.proc) {
      try {
        if (plat === 'win32') {
          spawn('taskkill', ['/pid', String(this.proc.pid), '/t', '/f'], { windowsHide: true });
        } else {
          this.proc.kill('SIGTERM');
        }
      } catch {}
      this.proc = null;
    }
    this.onLog('TUN mode stopped.', 'info');
  }

  /** Synchronous best-effort cleanup for process exit. */
  cleanupSync() {
    const plat = os.platform();
    if (plat === 'win32') {
      for (const net of SPLIT_ROUTES) {
        try { execFileSync('route', ['delete', net, 'mask', '128.0.0.0', TUN_GW], { windowsHide: true }); } catch {}
      }
      for (const ip of this.bypassIps) {
        try { execFileSync('route', ['delete', ip], { windowsHide: true }); } catch {}
      }
      return;
    }
    // macOS/Linux: only attempt synchronous teardown when already root (we
    // cannot show a password prompt during process exit). Graceful disconnect
    // / quit already runs the async, privileged teardown.
    if (plat === 'darwin' && process.getuid && process.getuid() === 0) {
      const st = this.macState || {};
      try { if (st.macPid) execFileSync('kill', [String(st.macPid)]); } catch {}
      if (st.dev) {
        try { execFileSync('route', ['-n', 'delete', '-net', '0.0.0.0/1', '-interface', st.dev]); } catch {}
        try { execFileSync('route', ['-n', 'delete', '-net', '128.0.0.0/1', '-interface', st.dev]); } catch {}
      }
      // legacy peer-IP form, in case an old route is still present
      try { execFileSync('route', ['-n', 'delete', '-net', '0.0.0.0/1', TUN_GW]); } catch {}
      try { execFileSync('route', ['-n', 'delete', '-net', '128.0.0.0/1', TUN_GW]); } catch {}
      for (const ip of (st.bypassIps || [])) {
        try { execFileSync('route', ['-n', 'delete', '-host', ip]); } catch {}
      }
    }
  }
}

// isOwnTunInterface lives in tunPlatform.js now (it knows both backends'
// adapter names); re-exported so main.js / service.js / the tests keep their
// import.
module.exports = { TunManager, isOwnTunInterface, TUN_GW };
