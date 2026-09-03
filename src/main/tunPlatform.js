'use strict';
/**
 * What both TUN backends share — tun2socks (tunManager.js) and sing-box
 * (tunSingbox.js): command plumbing, the Windows gateway/adapter queries, the
 * macOS route/service/DNS lookups, the privileged-script runner, and the two
 * facts the rest of the app needs about our adapters: which interface names
 * are ours, and which physical interface carries the default route.
 *
 * Every helper here was moved out of tunManager.js unchanged in behaviour
 * (the adapter name became a parameter); the tests pin what they parse.
 */

const { execFile, execFileSync } = require('child_process');
const os = require('os');
const dns = require('dns').promises;

/** The adapter names the backends create. */
const TUN2SOCKS_ADAPTER = 'XrayTun';    // tunManager.js — the wintun adapter it names
const SINGBOX_ADAPTER = 'IRNetFree';    // tunSingbox.js — sing-box's `interface_name`

/**
 * Is this network interface one WE create for TUN mode?
 *
 * The network watcher must not count our own adapter as part of the machine's
 * network: rebuilding the tunnel destroys and recreates it (on Windows with a
 * fresh GUID, on macOS possibly under a different utun unit), so every
 * recovery would otherwise look like the network change that triggers the
 * next one — a single Wi-Fi switch would rebuild forever.
 *
 * Deliberately broad on macOS: the kernel picks the utun unit, so we cannot know
 * in advance which one is ours. The cost is that a change on someone else's utun
 * (another VPN, iCloud Private Relay) does not trigger a recovery on its own —
 * far cheaper than an unbreakable rebuild loop, and a genuine change there almost
 * always moves the physical interface too.
 */
function isOwnTunInterface(name) {
  const n = String(name == null ? '' : name);
  if (!n) return false;
  if (n === TUN2SOCKS_ADAPTER) return true;   // Windows: the wintun adapter tun2socks names
  if (n === SINGBOX_ADAPTER) return true;     // Windows/Linux: sing-box's interface_name
  if (/^utun\d*$/i.test(n)) return true;      // macOS: the unit the kernel picks (either backend)
  return n === 'tun0';                        // Linux: tunManager's startLinux() fixed device
}

function run(cmd, args) {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, { windowsHide: true }, (err, stdout, stderr) => {
      if (err) return reject(new Error((stderr || err.message).toString().trim()));
      resolve((stdout || '').toString());
    });
  });
}

function delay(ms) { return new Promise(r => setTimeout(r, ms)); }

/** Single-quote a value for bash. */
function sh(s) { return `'${String(s).replace(/'/g, `'\\''`)}'`; }

/**
 * Whether TUN mode can be activated without a separate "relaunch elevated"
 * step.
 *  - Windows: true only when the process is already Administrator.
 *  - macOS:   true when root OR when we can escalate per-operation through
 *             `osascript` (a one-time password prompt at connect time).
 *  - Linux:   true only when running as root.
 */
function isElevated(plat = os.platform()) {
  if (plat === 'darwin') {
    try { if (process.getuid && process.getuid() === 0) return true; } catch {}
    // osascript is always present on macOS → we can prompt for privileges.
    return true;
  }
  if (plat !== 'win32') {
    try { return !!(process.getuid && process.getuid() === 0); } catch { return false; }
  }
  try {
    // `net session` only succeeds when elevated.
    execFileSync('net', ['session'], { stdio: 'ignore', windowsHide: true });
    return true;
  } catch {
    return false;
  }
}

/**
 * Resolve one or many hostnames/IPs to all their IPv4 addresses — and, with
 * `opts.ipv6`, their IPv6 addresses too (the sing-box backend routes v6 through
 * the tunnel, so a v6 server address must be on its exclusion list or the
 * proxy's own traffic would loop). Without the flag this is exactly the
 * tun2socks behaviour: A records only.
 */
async function resolveServerIps(serverAddress, opts = {}) {
  const inputs = Array.isArray(serverAddress) ? serverAddress : [serverAddress];
  const all = [];
  for (const addr of inputs) {
    if (!addr) continue;
    if (/^\d+\.\d+\.\d+\.\d+$/.test(addr)) { all.push(addr); continue; }
    if (opts.ipv6 && /^[0-9a-f:]+$/i.test(addr) && addr.includes(':')) { all.push(addr); continue; }
    try {
      const res = await dns.lookup(addr, { family: opts.ipv6 ? 0 : 4, all: true });
      for (const r of res) if (r.address) all.push(r.address);
    } catch { /* unresolved — skip */ }
  }
  return [...new Set(all)];
}

/** Discover the current default gateway + interface index (Windows). */
async function getDefaultGatewayWin() {
  const ps = "$r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Where-Object { $_.NextHop -ne '0.0.0.0' } | Sort-Object RouteMetric | Select-Object -First 1; " +
    "Write-Output ($r.NextHop + '|' + $r.InterfaceIndex)";
  const out = (await run('powershell', ['-NoProfile', '-NonInteractive', '-Command', ps])).trim();
  const [nextHop, ifIndex] = out.split('|');
  return { nextHop: nextHop && nextHop.trim(), ifIndex: ifIndex && ifIndex.trim() };
}

/** Get the interface index of a TUN adapter once it exists (Windows). */
async function getTunIfIndex(name) {
  const ps = `(Get-NetAdapter -Name '${name}' -ErrorAction SilentlyContinue).ifIndex`;
  const out = (await run('powershell', ['-NoProfile', '-NonInteractive', '-Command', ps])).trim();
  return out ? out.split(/\s+/)[0].trim() : null;
}

/** Wait until the adapter exists AND its admin/connect state is up (Windows). */
async function waitForAdapter(name, timeout) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    try {
      const ps = `(Get-NetAdapter -Name '${name}' -ErrorAction SilentlyContinue).Status`;
      const out = (await run('powershell', ['-NoProfile', '-NonInteractive', '-Command', ps])).trim();
      if (out && /Up/i.test(out)) return true;
    } catch {}
    await delay(400);
  }
  return false;
}

/** Run a privileged shell script: directly if root, else via an osascript
 * GUI prompt (`do shell script ... with administrator privileges`). */
async function runScriptPrivileged(scriptPath) {
  const isRoot = !!(process.getuid && process.getuid() === 0);
  if (isRoot) {
    return run('/bin/bash', [scriptPath]);
  }
  // AppleScript string: escape backslashes and double quotes; the path may
  // contain spaces (e.g. ".../Application Support/IRNetFree/...").
  const esc = (s) => String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  const cmd = `do shell script "/bin/bash \\"${esc(scriptPath)}\\"" with administrator privileges`;
  return run('osascript', ['-e', cmd]);
}

/** Parse `route -n get default` → { gateway, device } (macOS). */
async function getDefaultRouteMac() {
  let out = '';
  try { out = await run('route', ['-n', 'get', 'default']); } catch { out = ''; }
  const gw = (out.match(/gateway:\s*([^\s]+)/) || [])[1] || '';
  const dev = (out.match(/interface:\s*([^\s]+)/) || [])[1] || '';
  return { gateway: gw.trim(), device: dev.trim() };
}

/** Map a BSD device (en0) to its networksetup service name ("Wi-Fi"). */
async function serviceForDeviceMac(device) {
  if (!device) return null;
  let out = '';
  try { out = await run('networksetup', ['-listnetworkserviceorder']); } catch { return null; }
  // Blocks look like:
  //   (1) Wi-Fi
  //   (Hardware Port: Wi-Fi, Device: en0)
  const lines = out.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (new RegExp(`Device:\\s*${device}\\)`).test(lines[i])) {
      const name = (lines[i - 1] || '').replace(/^\(\d+\)\s*/, '').trim();
      if (name) return name;
    }
  }
  return null;
}

/** Current DNS servers for a service, or [] if set to automatic/DHCP. */
async function getServiceDnsMac(service) {
  if (!service) return [];
  let out = '';
  try { out = await run('networksetup', ['-getdnsservers', service]); } catch { return []; }
  if (/aren't any|any DNS Servers/i.test(out)) return [];
  return out.split('\n').map(s => s.trim()).filter(s => /^\d+\.\d+\.\d+\.\d+$/.test(s) || s.includes(':'));
}

/**
 * The physical interface that carries the default route, as
 * `{ name, ifIndex, gateway }` — null fields, never a throw, when nothing is
 * found. `name` is what Xray binds a direct outbound to (`sockopt.interface`:
 * the adapter's friendly name on Windows — "Wi-Fi" — the BSD device on macOS
 * — en0 — the `dev` on Linux). Read it BEFORE the tunnel is up: with a TUN
 * default route in place the answer may be the tunnel itself.
 */
async function physicalInterface(plat = os.platform()) {
  const none = { name: null, ifIndex: null, gateway: null };
  try {
    if (plat === 'win32') {
      const gw = await getDefaultGatewayWin();
      const idx = String(gw.ifIndex || '').replace(/\D/g, '');
      if (!idx) return { name: null, ifIndex: null, gateway: gw.nextHop || null };
      const ps = `(Get-NetAdapter -InterfaceIndex ${idx} -ErrorAction SilentlyContinue).Name`;
      const name = (await run('powershell', ['-NoProfile', '-NonInteractive', '-Command', ps])).trim();
      return { name: name || null, ifIndex: idx, gateway: gw.nextHop || null };
    }
    if (plat === 'darwin') {
      const r = await getDefaultRouteMac();
      return { name: r.device || null, ifIndex: null, gateway: r.gateway || null };
    }
    let out = '';
    try { out = await run('ip', ['route', 'show', 'default']); } catch { out = ''; }
    const line = out.split('\n').map(l => l.trim()).find(l => /^default\b/.test(l)) || '';
    const dev = (line.match(/\bdev\s+(\S+)/) || [])[1] || null;
    const via = (line.match(/\bvia\s+(\S+)/) || [])[1] || null;
    return { name: dev, ifIndex: null, gateway: via };
  } catch {
    return none;
  }
}

module.exports = {
  TUN2SOCKS_ADAPTER, SINGBOX_ADAPTER,
  isOwnTunInterface, run, delay, sh, isElevated, resolveServerIps,
  getDefaultGatewayWin, getTunIfIndex, waitForAdapter, runScriptPrivileged,
  getDefaultRouteMac, serviceForDeviceMac, getServiceDnsMac, physicalInterface
};
