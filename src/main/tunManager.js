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
const macOwners = require('./macSessionLock');
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
// IPv6 on the same adapter (Windows): an address so the peer is on-link, the
// peer as the adapter's v6 resolver, and the two /1 routes. The addresses are
// the sing-box backend's (TUN_ADDR6 / TUN_PEER6 in tunSingbox.js), so the leak
// guard sees one v6 peer whichever backend is live. Without them a dual-stack
// machine kept its ISP's v6 default route and the router's v6 resolver beside
// the tunnel: every v6 packet, and every query Windows fell back to when the
// tunnel resolver was slow, left the machine outside it. Seen live on the
// owner's laptop (a TXT lookup the hijack refused went to the router over
// fe80::, and on to Google from the ISP's v6 prefix).
const TUN_ADDR6 = 'fdfe:dcba:9876::1';
const TUN_PREFIX6 = 126;
const TUN_GW6 = 'fdfe:dcba:9876::2';
const SPLIT_ROUTES6 = ['::/1', '8000::/1'];

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
    // The adapter's IPv6 resolver once the v6 side is up (Windows) — the peer,
    // and only when the v4 resolver is the peer too. null until then, without
    // the hijack, and if the v6 setup failed.
    this.dnsPeer6 = null;
    this.lang = opts.lang || 'fa';   // user-facing error language
    this.macState = null;            // macOS TUN runtime state (pid, routes, dns)
    this.macLogTimer = null;
    this.userData = opts.userData || null;
    this.macOwnerKey = this.userData ? path.resolve(this.userData) : this;
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
    // (and so Windows asks this adapter's resolver first). Said when it fails:
    // the leak guard holds every physical adapter on loopback, so this
    // adapter's resolvers are the only ones that answer.
    await run('netsh', ['interface', 'ip', 'set', 'interface', `interface=${ADAPTER}`, 'metric=1'])
      .catch(e => this.onLog('TUN adapter metric: ' + e.message, 'warn'));

    // 7) DNS through the tunnel (leak prevention): force resolvers on the TUN
    await run('netsh', ['interface', 'ip', 'set', 'dnsservers', `name=${ADAPTER}`,
      'static', this.dnsServers[0], 'primary', 'validate=no'])
      .catch(e => this.onLog(`TUN adapter resolver ${this.dnsServers[0]}: ` + e.message, 'warn'));
    if (this.dnsServers[1]) {
      await run('netsh', ['interface', 'ip', 'add', 'dnsservers', `name=${ADAPTER}`,
        this.dnsServers[1], 'index=2', 'validate=no'])
        .catch(e => this.onLog(`TUN adapter resolver ${this.dnsServers[1]}: ` + e.message, 'warn'));
    }

    // 7b) IPv6 through the tunnel too — address, resolver, the two /1 routes
    //     (see TUN_ADDR6). Best effort: a failure is logged and dnsPeer6 stays
    //     null (the guard holds the physical adapters' v6 on loopback anyway).
    await this.setupIpv6Windows();

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

  /**
   * The v6 side of the adapter: on-link address, resolver, `::/1` + `8000::/1`
   * pinned to the adapter with the peer as next hop. `store=active` — the
   * adapter is gone with tun2socks, nothing of this belongs in the registry.
   * The /1 prefixes are longer than the ISP's `::/0`, so they win without any
   * metric games; LAN prefixes are longer still and stay on the LAN.
   *
   * The peer is the v6 RESOLVER only when it is the v4 one (tunSingbox's
   * adapterDns rule): with managed DNS off the core hijacks nothing, the peer
   * answers no query, and a dead resolver ahead of the working v4 ones pushed
   * every lookup to Windows' "ask every server" step. The address and the
   * routes are set either way — v6 traffic must not go around the tunnel.
   */
  async setupIpv6Windows() {
    this.dnsPeer6 = null;
    const peered = (this.dnsServers || []).includes(TUN_GW);
    try {
      await run('netsh', ['interface', 'ipv6', 'add', 'address', `interface=${ADAPTER}`,
        `address=${TUN_ADDR6}/${TUN_PREFIX6}`, 'store=active']);
      if (peered) {
        await run('netsh', ['interface', 'ipv6', 'set', 'dnsservers', `name=${ADAPTER}`,
          'static', TUN_GW6, 'primary', 'validate=no']);
      }
      for (const net of SPLIT_ROUTES6) {
        await run('netsh', ['interface', 'ipv6', 'add', 'route', `prefix=${net}`, `interface=${ADAPTER}`,
          `nexthop=${TUN_GW6}`, 'metric=1', 'store=active']);
      }
      this.dnsPeer6 = peered ? TUN_GW6 : null;
      this.onLog(`IPv6 -> TUN too (${TUN_ADDR6}/${TUN_PREFIX6}, resolver ${peered ? TUN_GW6 : 'none (no hijack)'}, ${SPLIT_ROUTES6.join(' + ')})`, 'info');
    } catch (e) {
      this.onLog('IPv6 on the TUN adapter failed — v6 stays outside the tunnel: ' + e.message, 'warn');
      await this.cleanupIpv6Windows();
    }
  }

  async cleanupIpv6Windows() {
    for (const net of SPLIT_ROUTES6) {
      await run('netsh', ['interface', 'ipv6', 'delete', 'route', `prefix=${net}`, `interface=${ADAPTER}`,
        `nexthop=${TUN_GW6}`]).catch(() => {});
    }
    this.dnsPeer6 = null;
  }

  async cleanupRoutesWindows() {
    for (const net of SPLIT_ROUTES) {
      await run('route', ['delete', net, 'mask', '128.0.0.0', TUN_GW]).catch(() => {});
    }
    await this.cleanupIpv6Windows();
    for (const ip of this.bypassIps) {
      await run('route', ['delete', ip]).catch(() => {});
    }
    this.bypassIps = [];
    this.tunIfIndex = null;
  }

  /* ----------------------------- macOS ----------------------------- */

  async startMac(socksPort, serverAddress, dnsServers) {
    if (this.macState || this.hasPendingMacRecovery()) await this.recoverMacSessions();
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

    const base = this.userData ? path.join(this.userData, 'mac-legacy-tun-sessions') : os.tmpdir();
    fs.mkdirSync(base, { recursive: true, mode: 0o700 });
    const work = fs.mkdtempSync(path.join(base, 'irnf-tun-'));
    const logFile = path.join(work, 'tun2socks.log');
    const pidFile = path.join(work, 'tun2socks.pid');
    const devFile = path.join(work, 'tun2socks.dev');
    const identityFile = path.join(work, 'tun2socks.identity');
    const dnsFile = path.join(work, 'dns-changed');
    const routesFile = path.join(work, 'bypass-added');
    const teardownPath = path.join(work, 'teardown.sh');
    const reqDev = MAC_TUN_DEV;
    const dns1 = this.dnsServers[0] || '1.1.1.1';
    const dns2 = this.dnsServers[1] || '';

    for (const file of [logFile, pidFile, devFile, identityFile, routesFile]) fs.writeFileSync(file, '', { mode: 0o600 });
    this.macState = { work, logFile, pidFile, devFile, identityFile, dnsFile, routesFile, service, savedDns, gateway: route.gateway, bypassIps: ips, reqDev, macPid: null, dev: '', identity: '', expectedCommand: `${bin} -device ${reqDev} -proxy socks5://127.0.0.1:${socksPort} -loglevel warn` };
    this.saveMacSession();
    fs.writeFileSync(teardownPath, this.macTeardownScript(), { mode: 0o700 });
    const bypassAdd = ips.map(ip => `if route -n add -host ${sh(ip)} ${sh(route.gateway)} >/dev/null 2>&1; then echo ${sh(ip)} >> ${sh(routesFile)} || exit 13; fi`).join('\n');
    const dnsLine = service
      ? `touch ${sh(dnsFile)} || exit 14\nnetworksetup -setdnsservers ${sh(service)} ${[dns1, dns2].filter(Boolean).map(sh).join(' ')} || exit 14`
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
      `rollback() { code=$?; trap - EXIT; if [ "$code" -ne 0 ]; then /bin/bash ${sh(teardownPath)} || echo 'Tunnel rollback failed; recovery retained' >&2; fi; exit "$code"; }`,
      'trap rollback EXIT',
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
      'echo $! > "$PIDFILE" || exit 10',
      `ps -ww -p "$(cat "$PIDFILE")" -o lstart= > ${sh(identityFile)} || exit 10`,
      // 2) wait for a NEW utun device (tun2socks may pick the next free unit
      //    instead of the exact name we requested).
      'ACTUAL=""',
      'i=0',
      'while [ $i -lt 50 ]; do',
      '  kill -0 "$(cat "$PIDFILE")" 2>/dev/null || break',
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
      'echo "$ACTUAL" > "$DEVFILE" || exit 12',
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
      'kill -0 "$(cat "$PIDFILE")" 2>/dev/null || exit 15',
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
      if (!fs.readFileSync(pidFile, 'utf8').trim() && !fs.existsSync(dnsFile)) {
        fs.rmSync(work, { recursive: true, force: true }); this.macState = null;
      }
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

    let identity = '';
    try { identity = fs.readFileSync(identityFile, 'utf8').trim(); } catch {}
    Object.assign(this.macState, { macPid, identity, dev });
    if (!macPid || !identity || !/^utun\d+$/.test(dev)) throw new Error('Incomplete tunnel setup state; recovery required');
    this.saveMacSession();
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
        const len = Math.min(stat.size - pos, 64 * 1024);
        const buf = Buffer.alloc(len);
        let bytes;
        try { bytes = fs.readSync(fd, buf, 0, len, pos); } finally { fs.closeSync(fd); }
        pos += bytes;
        for (const line of buf.subarray(0, bytes).toString('utf8').split(/\r?\n/)) {
          if (line.trim()) this.onLog('[tun] ' + line.trim(), 'warn');
        }
      } catch {}
    }, 1500);
    if (this.macLogTimer.unref) this.macLogTimer.unref();
  }

  stopMacLogTail() {
    if (this.macLogTimer) { clearInterval(this.macLogTimer); this.macLogTimer = null; }
  }

  saveMacSession() {
    if (!this.macState.ownerPid) this.macState.ownerPid = process.pid;
    const file = path.join(this.macState.work, 'session.json');
    fs.writeFileSync(file + '.tmp', JSON.stringify(this.macState), { mode: 0o600 });
    fs.renameSync(file + '.tmp', file);
  }

  hasPendingMacRecovery() {
    if (os.platform() !== 'darwin') return false;
    if (this.macState) return true;
    if (!this.userData) return false;
    try { return fs.readdirSync(path.join(this.userData, 'mac-legacy-tun-sessions')).some(n => /^irnf-tun-/.test(n)); }
    catch (e) { if (e.code === 'ENOENT') return false; throw e; }
  }

  async recoverMacSessions() {
    if (os.platform() !== 'darwin') return 0;
    const owner = macOwners.get(this.macOwnerKey);
    if (owner && owner !== this) throw new Error('Another tunnel operation is live; disconnect it before recovery');
    if (this.active) throw new Error('Disconnect the active tunnel before recovery');
    let count = 0;
    if (this.macState) { await this.stopMac(); count++; }
    if (!this.userData) return count;
    const base = path.resolve(this.userData, 'mac-legacy-tun-sessions');
    let names;
    try { names = fs.readdirSync(base); } catch (e) { if (e.code === 'ENOENT') return count; throw e; }
    for (const name of names.filter(n => /^irnf-tun-/.test(n))) {
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
      if (path.resolve(st.work || '') !== work || !Array.isArray(st.savedDns) || !Array.isArray(st.bypassIps) || typeof st.gateway !== 'string' || typeof st.expectedCommand !== 'string') throw new Error('Invalid tunnel recovery session');
      for (const key of ['logFile', 'pidFile', 'devFile', 'identityFile', 'dnsFile', 'routesFile']) {
        if (typeof st[key] !== 'string' || path.dirname(path.resolve(st[key])) !== work) throw new Error('Invalid tunnel recovery path');
        if (fs.existsSync(st[key]) && fs.lstatSync(st[key]).isSymbolicLink()) throw new Error('Invalid tunnel recovery artifact');
      }
      this.macState = st;
      await this.stopMac(); count++;
    }
    return count;
  }

  macTeardownScript() {
    const st = this.macState || {};
    const dns1 = (st.savedDns && st.savedDns.length) ? st.savedDns.map(sh).join(' ') : 'Empty';
    const lines = ['#!/bin/bash'];
    if (st.pidFile) {
      lines.push(
        `PID=$(cat ${sh(st.pidFile)} 2>/dev/null)`,
        `EXPECTED=$(cat ${sh(st.identityFile)} 2>/dev/null | sed "s/^[[:space:]]*//;s/[[:space:]]*$//")`,
        `COMMAND=${sh(st.expectedCommand)}`,
        'case "$PID" in ""|*[!0-9]*) PID="";; esac',
        'owned() { [ "$(ps -ww -p "$PID" -o command=)" = "$COMMAND" ] && [ "$(ps -ww -p "$PID" -o lstart= | sed "s/^[[:space:]]*//;s/[[:space:]]*$//")" = "$EXPECTED" ]; }',
        'if [ -n "$PID" ] && [ "$PID" -gt 1 ] && kill -0 "$PID" 2>/dev/null; then',
        '  [ -n "$EXPECTED" ] || { echo "Missing tunnel identity; recovery retained" >&2; exit 21; }',
        '  if owned; then',
        '  kill -TERM "$PID" || exit 22',
        '  i=0; while owned && [ "$i" -lt 30 ]; do sleep 0.1; i=$((i+1)); done',
        '  if owned; then kill -KILL "$PID" || exit 23; fi',
        '  i=0; while owned && [ "$i" -lt 20 ]; do sleep 0.1; i=$((i+1)); done',
        '  if owned; then echo "TUN process is still running" >&2; exit 24; fi',
        '  fi',
        'fi');
    }
    // Delete the split-default routes using the SAME (interface-pinned) form we
    // added them with — otherwise they leak and break all networking after
    // disconnect until reboot.
    // Interface routes disappear with the owned utun. Do not delete by a
    // recycled device name after a crash: another VPN may own it by then.
    for (const ip of (st.bypassIps || [])) {
      lines.push(`if grep -Fxq -- ${sh(ip)} ${sh(st.routesFile)} 2>/dev/null; then route -n delete -host ${sh(ip)} ${sh(st.gateway)} 2>/dev/null || true; fi`);
    }
    if (st.service) lines.push(`if [ -f ${sh(st.dnsFile)} ]; then networksetup -setdnsservers ${sh(st.service)} ${dns1} || exit 25; rm -f ${sh(st.dnsFile)}; fi`);
    lines.push('exit 0', '');
    return lines.join('\n');
  }

  async stopMac() {
    if (this.macStopPromise) return this.macStopPromise;
    if (!this.macState) return;
    this.macStopPromise = this.finishMacStop();
    try { return await this.macStopPromise; } finally { this.macStopPromise = null; }
  }

  async finishMacStop() {
    this.stopMacLogTail();
    const work = this.macState.work;
    const teardownPath = path.join(work, 'teardown.sh');
    try {
      if (fs.existsSync(teardownPath) && fs.lstatSync(teardownPath).isSymbolicLink()) throw new Error('Invalid tunnel teardown path');
      fs.writeFileSync(teardownPath, this.macTeardownScript(), { mode: 0o700 });
      await this.runScriptPrivileged(teardownPath);
    } catch (e) {
      this.onLog('TUN teardown: ' + (e.message || e), 'warn');
      throw e;
    }
    fs.rmSync(work, { recursive: true, force: true });
    this.macState = null;
    this.bypassIps = [];
    this.active = false;
    if (!this.macStartPromise && macOwners.get(this.macOwnerKey) === this) macOwners.delete(this.macOwnerKey);
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
    if (os.platform() === 'darwin') {
      if (this.macStartPromise) return this.macStartPromise;
      const owner = macOwners.get(this.macOwnerKey);
      if (owner && owner !== this) throw new Error('Another tunnel operation is live; disconnect it first');
      macOwners.set(this.macOwnerKey, this);
      this.macStartPromise = (async () => {
        if (this.macStopPromise) await this.macStopPromise;
        if (!this.active) await this.startMac(socksPort, serverAddress, dnsServers);
      })();
      try { return await this.macStartPromise; } finally {
        this.macStartPromise = null;
        if (!this.macState && !this.active && macOwners.get(this.macOwnerKey) === this) macOwners.delete(this.macOwnerKey);
      }
    }
    if (this.active) return;
    const plat = os.platform();
    if (plat === 'win32') return this.startWindows(socksPort, serverAddress, dnsServers);
    if (plat === 'darwin') return this.startMac(socksPort, serverAddress, dnsServers);
    return this.startLinux(socksPort, serverAddress);
  }

  async stop() {
    if (os.platform() === 'darwin' && this.macStartPromise) await this.macStartPromise.catch(() => {});
    if (!this.active && !this.proc && !this.macState) return;
    const plat = os.platform();
    if (plat !== 'darwin') this.active = false;
    if (plat === 'win32') {
      await this.cleanupRoutesWindows().catch(() => {});
    } else if (plat === 'darwin') {
      await this.stopMac();
      this.active = false;
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
      for (const net of SPLIT_ROUTES6) {
        try {
          execFileSync('netsh', ['interface', 'ipv6', 'delete', 'route', `prefix=${net}`, `interface=${ADAPTER}`, `nexthop=${TUN_GW6}`], { windowsHide: true });
        } catch {}
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
      if (!this.macState) return;
      try {
        const script = path.join(this.macState.work, 'teardown-sync.sh');
        if (fs.existsSync(script) && fs.lstatSync(script).isSymbolicLink()) return;
        fs.writeFileSync(script, this.macTeardownScript(), { mode: 0o700 });
        execFileSync('/bin/bash', [script], { stdio: 'ignore', timeout: 12000 });
      } catch {} // Keep the durable journal for verified recovery at next launch.
    }
  }
}

// isOwnTunInterface lives in tunPlatform.js now (it knows both backends'
// adapter names); re-exported so main.js / service.js / the tests keep their
// import.
module.exports = { TunManager, isOwnTunInterface, TUN_GW, TUN_GW6 };
