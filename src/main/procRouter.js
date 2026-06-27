'use strict';
/**
 * Process-based routing helper.
 *
 * IMPORTANT: xray-core CANNOT match traffic by process — its routing rules only
 * understand domain/ip/port/source/etc, and there is no live routing reload
 * (only StatsService/HandlerService over gRPC). So we approximate process
 * routing the only honest way possible:
 *
 *   1. Resolve a chosen process NAME to the set of remote IPs its TCP
 *      connections currently use.
 *   2. Remember those IPs in a persisted, monotonically-growing per-process
 *      cache (with a TTL) so previously-seen destinations stay routed.
 *   3. Emit that IP set as ordinary xray `ip` routing rules toward the chosen
 *      outbound (done by the caller, before buildConfig).
 *   4. While connected, a watcher periodically re-resolves; when a routed
 *      process's IP set GROWS, it asks the host to rebuild the config (which
 *      briefly restarts xray — there is no hot routing reload).
 *
 * Limitations (surfaced in the UI): matches by destination IP, so other apps
 * hitting the same IPs are affected; short-lived/bursty connections may be
 * missed; visibility is limited to the user's own processes unless elevated.
 */

const { execFile } = require('child_process');
const os = require('os');

function run(cmd, args, timeout = 6000) {
  return new Promise((resolve) => {
    execFile(cmd, args, { windowsHide: true, timeout, maxBuffer: 16 * 1024 * 1024 }, (err, stdout) => {
      resolve(err ? '' : (stdout || '').toString());
    });
  });
}

const isIPv4 = (s) => /^\d{1,3}(\.\d{1,3}){3}$/.test(s);
const isIPv6 = (s) => s.includes(':') && /^[0-9a-fA-F:]+$/.test(s);

/** Skip loopback / link-local / unspecified — never worth a routing rule. */
function isRoutable(ip) {
  if (!ip) return false;
  if (isIPv4(ip)) return ip !== '0.0.0.0' && !ip.startsWith('127.');
  if (isIPv6(ip)) {
    const l = ip.toLowerCase();
    return l !== '::' && l !== '::1' && !l.startsWith('fe80');
  }
  return false;
}

/** Extract the bare IP from an "ip:port" / "[ipv6]:port" endpoint. */
function ipFromEndpoint(s) {
  if (!s) return '';
  s = s.trim();
  if (s[0] === '[') { const i = s.indexOf(']'); return i > 0 ? s.slice(1, i) : ''; }
  const i = s.lastIndexOf(':');
  return i > 0 ? s.slice(0, i) : s;
}

/* ----------------------------- connection enumeration ----------------------------- */
/** [{ name, pid, remote }] of established outbound TCP connections. */
async function connections() {
  if (os.platform() === 'win32') return winConnections();
  return unixConnections();
}

async function winConnections() {
  // Get-NetTCPConnection needs no elevation for the user's own processes; pid→
  // name mapping for SYSTEM/other-user processes may be blank (filtered out).
  const ps =
    "Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | " +
    "ForEach-Object { $p=(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName; " +
    "if ($p) { \"$p|$($_.OwningProcess)|$($_.RemoteAddress)\" } }";
  const out = await run('powershell', ['-NoProfile', '-NonInteractive', '-Command', ps]);
  const conns = [];
  for (const line of out.split(/\r?\n/)) {
    const parts = line.trim().split('|');
    if (parts.length < 3) continue;
    const name = (parts[0] || '').trim();
    if (!name) continue;
    conns.push({ name, pid: parseInt(parts[1], 10) || 0, remote: (parts[2] || '').trim() });
  }
  return conns;
}

async function unixConnections() {
  // Prefer lsof (present on macOS by default). `+c 0` disables the 9-char
  // command-name truncation so we get full process names.
  const lo = await run('lsof', ['-nP', '-iTCP', '-sTCP:ESTABLISHED', '+c', '0']);
  if (lo) {
    const conns = [];
    for (const line of lo.split(/\r?\n/)) {
      if (!line.trim() || /^COMMAND\s/.test(line)) continue;
      const cols = line.trim().split(/\s+/);
      if (cols.length < 9) continue;
      const name = cols[0];
      const pid = parseInt(cols[1], 10) || 0;
      const nameField = cols[cols.length - 1]; // NAME col: local->remote (no spaces)
      const m = nameField.match(/->(\[?[0-9a-fA-F:.]+\]?):\d+$/);
      if (!m) continue;
      const ip = ipFromEndpoint(m[1]);
      conns.push({ name, pid, remote: ip });
    }
    return conns;
  }
  // Linux fallback: ss -tnp (process column needs root for other users).
  const ss = await run('ss', ['-tnp', 'state', 'established']);
  if (!ss) return [];
  const conns = [];
  for (const line of ss.split(/\r?\n/)) {
    if (!line.trim() || /^State|^Recv-Q/.test(line)) continue;
    const cols = line.trim().split(/\s+/);
    // columns: Recv-Q Send-Q Local Peer [Process]  (State filtered out)
    if (cols.length < 4) continue;
    const peer = cols[3];
    const ip = ipFromEndpoint(peer);
    const pm = line.match(/users:\(\("([^"]+)",pid=(\d+)/);
    const name = pm ? pm[1] : '';
    if (!name) continue;
    conns.push({ name, pid: pm ? parseInt(pm[2], 10) : 0, remote: ip });
  }
  return conns;
}

/* ----------------------------- public helpers ----------------------------- */
/** Processes that currently own outbound TCP connections: [{name, pid, count}]. */
async function listProcesses() {
  const conns = await connections();
  const byName = new Map();
  for (const c of conns) {
    if (!c.name) continue;
    const cur = byName.get(c.name) || { name: c.name, pid: c.pid, count: 0 };
    cur.count++;
    byName.set(c.name, cur);
  }
  return [...byName.values()].sort((a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase()));
}

/** Current routable remote IPs for one process name (case-insensitive). */
async function resolveProcessIps(name) {
  if (!name) return [];
  const want = String(name).toLowerCase();
  const conns = await connections();
  const set = new Set();
  for (const c of conns) {
    if (String(c.name).toLowerCase() !== want) continue;
    if (isRoutable(c.remote)) set.add(c.remote);
  }
  return [...set];
}

const MAX_IPS_PER_PROC = 512;

/**
 * Merge live IPs for each name into the cache (monotonic union, TTL-stamped).
 * Mutates `cache`. Returns { ips: {name:[...]}, grew }.
 */
async function collectProcessIps(names, cache) {
  const result = {};
  let grew = false;
  for (const name of names) {
    let live = [];
    try { live = await resolveProcessIps(name); } catch { live = []; }
    const entry = cache[name] || { ips: [], ts: 0 };
    const set = new Set(entry.ips);
    const before = set.size;
    for (const ip of live) set.add(ip);
    let ips = [...set];
    if (ips.length > MAX_IPS_PER_PROC) ips = ips.slice(ips.length - MAX_IPS_PER_PROC); // keep newest
    if (ips.length > before) grew = true;
    entry.ips = ips;
    entry.ts = Date.now();
    cache[name] = entry;
    result[name] = ips;
  }
  return { ips: result, grew };
}

/** Drop cache entries not seen within ttlMs. Mutates `cache`. */
function pruneProcCache(cache, ttlMs = 24 * 3600 * 1000) {
  const now = Date.now();
  for (const name of Object.keys(cache)) {
    const e = cache[name];
    if (!e || !e.ts || (now - e.ts) > ttlMs) delete cache[name];
  }
  return cache;
}

/**
 * Periodically re-resolves routed processes; when the IP set grows, calls
 * onGrow() (debounced via the busy flag) so the host can rebuild + restart xray.
 */
class ProcWatcher {
  constructor(opts = {}) {
    this.getNames = opts.getNames || (() => []);      // () => [process name,...]
    this.loadCache = opts.loadCache || (() => ({}));
    this.saveCache = opts.saveCache || (() => {});
    this.onGrow = opts.onGrow || (async () => {});
    this.onLog = opts.onLog || (() => {});
    this.intervalMs = opts.intervalMs || 20000;
    this.timer = null;
    this.busy = false;
  }

  start() {
    this.stop();
    this.timer = setInterval(() => this.tick().catch(() => {}), this.intervalMs);
    if (this.timer.unref) this.timer.unref();
  }

  stop() {
    if (this.timer) { clearInterval(this.timer); this.timer = null; }
    this.busy = false;
  }

  async tick() {
    if (this.busy) return;
    const names = [...new Set((this.getNames() || []).filter(Boolean))];
    if (!names.length) return;
    const cache = this.loadCache();
    pruneProcCache(cache);
    const { grew } = await collectProcessIps(names, cache);
    this.saveCache(cache);
    if (!grew) return;
    this.busy = true;
    try {
      this.onLog('Process routing: new destinations detected — updating routes', 'info');
      await this.onGrow();
    } catch (e) {
      this.onLog('Process routing rebuild failed: ' + (e.message || e), 'error');
    } finally {
      this.busy = false;
    }
  }
}

module.exports = {
  listProcesses,
  resolveProcessIps,
  collectProcessIps,
  pruneProcCache,
  ProcWatcher
};
