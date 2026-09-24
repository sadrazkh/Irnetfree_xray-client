'use strict';
/**
 * System-wide proxy control.
 *  - Windows: writes "Internet Settings" registry keys + notifies WinINet.
 *  - macOS:   networksetup for each network service.
 *  - Linux:   gsettings (GNOME) best-effort.
 *
 * We set an HTTP/HTTPS system proxy pointing at the local Xray HTTP inbound,
 * with a sensible bypass list for local addresses.
 *
 * The desktop app journals what the proxy was before it set it (useProxyJournal,
 * see "the journal" below) and puts exactly that back. Without a journal — the
 * headless service — enable and disable behave as they always did.
 */

const { execFile, execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { psArgs } = require('./tunPlatform');

function run(cmd, args) {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, { windowsHide: true }, (err, stdout, stderr) => {
      if (err) return reject(new Error((stderr || err.message || '').toString().trim()));
      resolve((stdout || '').toString().trim());
    });
  });
}

const WIN_REG = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings';
const WIN_BYPASS = '<local>;localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.2*;172.30.*;172.31.*;192.168.*';

const regDword = (name, v) => ['add', WIN_REG, '/v', name, '/t', 'REG_DWORD', '/d', String(v), '/f'];
const regSz = (name, v) => ['add', WIN_REG, '/v', name, '/t', 'REG_SZ', '/d', String(v), '/f'];
const regDelete = (name) => ['delete', WIN_REG, '/v', name, '/f'];

async function enableWindows(host, httpPort, exec = run) {
  const proxyServer = `${host}:${httpPort}`;
  await exec('reg', regDword('ProxyEnable', 1));
  await exec('reg', regSz('ProxyServer', proxyServer));
  await exec('reg', regSz('ProxyOverride', WIN_BYPASS));
  await refreshWindows(exec);
}

async function disableWindows(exec = run) {
  await exec('reg', regDword('ProxyEnable', 0));
  await refreshWindows(exec).catch(() => {});
}

// Notify WinINet that settings changed so apps pick it up without restart.
function refreshWindows(exec = run) {
  const ps = [
    '$sig = @"',
    '[System.Runtime.InteropServices.DllImport("wininet.dll", SetLastError=true)]',
    'public static extern bool InternetSetOption(IntPtr h, int o, IntPtr b, int l);',
    '"@',
    'try {',
    '  $t = Add-Type -MemberDefinition $sig -Name N -Namespace W -PassThru -ErrorAction Stop',
    '  [void]$t::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0)', // INTERNET_OPTION_SETTINGS_CHANGED
    '  [void]$t::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0)', // INTERNET_OPTION_REFRESH
    '} catch {}'
  ].join('\n');
  return exec('powershell', psArgs(ps));
}

/**
 * The four values that decide WinINet's proxy, as JSON — read through
 * PowerShell so a bypass list or a PAC URL outside the OEM code page survives
 * (see tunPlatform.psArgs). A value that does not exist comes back null.
 */
const WIN_SNAPSHOT_PS = [
  "$p = Get-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -ErrorAction SilentlyContinue",
  'ConvertTo-Json -Compress -InputObject @{ ProxyEnable = $p.ProxyEnable; ProxyServer = $p.ProxyServer; ProxyOverride = $p.ProxyOverride; AutoConfigURL = $p.AutoConfigURL }'
].join('\n');

/** `{ ProxyEnable, ProxyServer, ProxyOverride, AutoConfigURL }` out of that, or null when unreadable. */
function parseWinProxy(json) {
  let d;
  try { d = JSON.parse(String(json == null ? '' : json).trim()); } catch { return null; }
  if (!d || typeof d !== 'object') return null;
  const str = (v) => (v == null ? null : String(v));
  const n = Number(d.ProxyEnable);
  return {
    ProxyEnable: d.ProxyEnable == null || Number.isNaN(n) ? null : n,
    ProxyServer: str(d.ProxyServer),
    ProxyOverride: str(d.ProxyOverride),
    AutoConfigURL: str(d.AutoConfigURL)
  };
}

/**
 * The reg lines that put `prev` back. Ours goes off FIRST — if anything after
 * it fails (or the machine is shutting down under us) the proxy is at least no
 * longer aimed at a port nothing listens on. A value that did not exist is
 * deleted again; the switch goes back on last, only if it was on. AutoConfigURL
 * is recorded but never written: nothing here ever changes it, so writing it
 * back could only undo someone else's change. With no record at all (the
 * snapshot was unreadable) this is exactly the old disable.
 */
function winRestoreSteps(prev) {
  const steps = [regDword('ProxyEnable', 0)];
  if (!prev) return steps;
  steps.push(prev.ProxyServer == null ? regDelete('ProxyServer') : regSz('ProxyServer', prev.ProxyServer));
  steps.push(prev.ProxyOverride == null ? regDelete('ProxyOverride') : regSz('ProxyOverride', prev.ProxyOverride));
  if (Number(prev.ProxyEnable) === 1) steps.push(regDword('ProxyEnable', 1));
  return steps;
}

/* --------------------------- macOS --------------------------- */

/**
 * Service names out of `networksetup -listallnetworkservices`. The output opens
 * with a legend — "An asterisk (*) denotes that a network service is
 * disabled." — and lists a disabled service with that asterisk in front. The
 * legend goes and the asterisk comes off, so what is left are the names
 * networksetup takes as arguments. Matched by content, not by position: the
 * old `slice(1)` would have eaten the first real service had the legend ever
 * been missing. Pure, so a test pins it — nobody here has a Mac to watch it.
 */
function parseMacServices(out) {
  return String(out == null ? '' : out).split(/\r?\n/)
    .map(s => s.trim())
    .filter(s => s && !/^An asterisk \(\*\) denotes/i.test(s))
    .map(s => s.replace(/^\*\s*/, ''));
}

async function macServices(exec) {
  return parseMacServices(await exec('networksetup', ['-listallnetworkservices']));
}

/**
 * SOCKS, HTTP and HTTPS proxy on every network service. A service that refuses
 * is skipped, but when NONE took the setting the call fails — which is what
 * happens for a user who is not an administrator, since networksetup demands
 * that for writes. Every error used to be swallowed per command, so that case
 * ended in a "System proxy enabled" log line over a machine whose proxy had
 * not changed at all. `exec` is injectable for the tests.
 */
async function enableMac(host, socksPort, httpPort, exec = run) {
  const services = await macServices(exec);
  let applied = 0;
  let lastError = null;
  for (const svc of services) {
    try {
      await exec('networksetup', ['-setsocksfirewallproxy', svc, host, String(socksPort)]);
      await exec('networksetup', ['-setsocksfirewallproxystate', svc, 'on']);
      await exec('networksetup', ['-setwebproxy', svc, host, String(httpPort)]);
      await exec('networksetup', ['-setwebproxystate', svc, 'on']);
      await exec('networksetup', ['-setsecurewebproxy', svc, host, String(httpPort)]);
      await exec('networksetup', ['-setsecurewebproxystate', svc, 'on']);
      applied++;
    } catch (e) {
      lastError = e;
    }
  }
  if (!applied) {
    if (!services.length) throw new Error('networksetup lists no network service to set the proxy on');
    throw new Error('networksetup refused the proxy on every network service'
      + (lastError && lastError.message ? ` (${lastError.message})` : '')
      + ' — on macOS changing the system proxy needs an administrator account');
  }
}

/** Best-effort, as before: a disable must never be the thing that fails a disconnect. */
async function disableMac(exec = run) {
  const services = await macServices(exec);
  for (const svc of services) {
    await exec('networksetup', ['-setsocksfirewallproxystate', svc, 'off']).catch(() => {});
    await exec('networksetup', ['-setwebproxystate', svc, 'off']).catch(() => {});
    await exec('networksetup', ['-setsecurewebproxystate', svc, 'off']).catch(() => {});
  }
}

/** The three proxies networksetup keeps per service, and the verbs for each. */
const MAC_KINDS = [
  { key: 'web', get: '-getwebproxy', set: '-setwebproxy', state: '-setwebproxystate' },
  { key: 'secure', get: '-getsecurewebproxy', set: '-setsecurewebproxy', state: '-setsecurewebproxystate' },
  { key: 'socks', get: '-getsocksfirewallproxy', set: '-setsocksfirewallproxy', state: '-setsocksfirewallproxystate' }
];

/**
 * `networksetup -get…proxy` → `{ enabled, server, port }`. The output reads
 * "Enabled: Yes|No / Server: … / Port: … / Authenticated Proxy Enabled: 0";
 * the first line is anchored so the last one cannot answer for it.
 */
function parseMacProxy(out) {
  const s = String(out == null ? '' : out);
  const server = (s.match(/^Server:[ \t]*(.*)$/m) || [])[1];
  return {
    enabled: /^Enabled:\s*Yes\b/mi.test(s),
    server: server ? server.trim() : '',
    port: Number((s.match(/^Port:\s*(\d+)/m) || [])[1]) || 0
  };
}

/** What each service's three proxies are right now. A read that fails is null (unknown). */
async function macSnapshot(exec) {
  const out = [];
  for (const name of await macServices(exec)) {
    const rec = { name };
    for (const k of MAC_KINDS) {
      try { rec[k.key] = parseMacProxy(await exec('networksetup', [k.get, name])); } catch { rec[k.key] = null; }
    }
    out.push(rec);
  }
  return out;
}

/**
 * The networksetup lines that put each recorded service back. A proxy that was
 * configured gets its server and port again (`-set…proxy` also switches it
 * on), and is switched off again when it was off; one that never was is just
 * switched off — as is anything whose record is unknown, the old disable.
 */
function macRestoreSteps(services) {
  const steps = [];
  for (const svc of services || []) {
    if (!svc || !svc.name) continue;
    for (const k of MAC_KINDS) {
      const r = svc[k.key];
      if (r && r.server && r.port) {
        steps.push(['networksetup', [k.set, svc.name, r.server, String(r.port)]]);
        if (!r.enabled) steps.push(['networksetup', [k.state, svc.name, 'off']]);
      } else {
        steps.push(['networksetup', [k.state, svc.name, 'off']]);
      }
    }
  }
  return steps;
}

/* --------------------------- Linux (GNOME) --------------------------- */
async function enableLinux(host, httpPort) {
  await run('gsettings', ['set', 'org.gnome.system.proxy', 'mode', 'manual']).catch(() => {});
  for (const p of ['http', 'https']) {
    await run('gsettings', ['set', `org.gnome.system.proxy.${p}`, 'host', host]).catch(() => {});
    await run('gsettings', ['set', `org.gnome.system.proxy.${p}`, 'port', String(httpPort)]).catch(() => {});
  }
}
async function disableLinux() {
  await run('gsettings', ['set', 'org.gnome.system.proxy', 'mode', 'none']).catch(() => {});
}

/* --------------------------- the journal --------------------------- */
/*
 * What the system proxy was before WE set it, in a small file in userData.
 *
 * Without it, three things went wrong. A disconnect only switched ProxyEnable
 * off, so a corporate proxy the user had was overwritten on connect and gone
 * for good after. setSystemProxy(false) ran on every disconnect, quit and exit
 * — even in a TUN-only session that never set the proxy — which killed that
 * same corporate proxy. And an app that died connected (a crash, Task Manager,
 * the update installer closing it) left the machine aimed at 127.0.0.1:10809
 * with nothing listening: the UI said disconnected, every browser failed, and
 * nothing repaired it at launch.
 *
 * So: the record is written BEFORE the first change (a crash in between still
 * leaves it), a second enable keeps the first record (our own proxy is never
 * "what was there before"), a disable restores it only when it exists — no
 * record, not ours to touch — and deletes it; the launch restores a record a
 * dead session left (repairSystemProxy), and the exit hook does it
 * synchronously (restoreSystemProxySync). Linux keeps the old behaviour.
 */
let journalFile = null;

/** The desktop app's journal file; null (the headless service) keeps the old blind enable/disable. */
function useProxyJournal(file) { journalFile = file || null; }

function readJournal(file) {
  try {
    const j = JSON.parse(fs.readFileSync(file, 'utf8'));
    return j && typeof j === 'object' ? j : null;
  } catch { return null; }
}

function writeJournal(file, data) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = file + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
  fs.renameSync(tmp, file);
}

function clearJournal(file) {
  try { fs.rmSync(file, { force: true }); } catch { /* nothing to clear */ }
}

const journaled = (platform) => platform === 'win32' || platform === 'darwin';

/**
 * One proxy operation at a time. The launch repair is not awaited by anyone,
 * and an auto-connect a second later must not snapshot the machine halfway
 * through it — nor may the repair undo a proxy that connect has just set.
 */
let queue = Promise.resolve();
function serial(fn) {
  const p = queue.then(fn, fn);
  queue = p.catch(() => {});
  return p;
}

async function enableJournaled(platform, { host, httpPort, socksPort }, { exec, journal }) {
  const ours = platform === 'win32' ? `${host}:${httpPort}` : { host, httpPort, socksPort };
  const existing = readJournal(journal);
  let fresh = false;
  if (!existing) {
    // Before the first change. An unreadable snapshot still journals (null):
    // the disable then does what it always did, instead of nothing.
    const rec = { platform, ours, at: new Date().toISOString() };
    if (platform === 'win32') {
      rec.win = null;
      try { rec.win = parseWinProxy(await exec('powershell', psArgs(WIN_SNAPSHOT_PS))); } catch { /* unknown */ }
    } else {
      rec.mac = null;   // unknown — not "no services": the restore then switches ours off everywhere
      try { rec.mac = await macSnapshot(exec); } catch { /* unknown */ }
    }
    writeJournal(journal, rec);
    fresh = true;
  } else if (JSON.stringify(existing.ours) !== JSON.stringify(ours)) {
    writeJournal(journal, Object.assign({}, existing, { ours }));   // keep the original, name what is ours now
  }
  try {
    if (platform === 'win32') await enableWindows(host, httpPort, exec);
    else await enableMac(host, socksPort, httpPort, exec);
  } catch (e) {
    // networksetup refused every service: nothing was set, so nothing is to be put back
    if (fresh && platform === 'darwin') clearJournal(journal);
    throw e;
  }
}

/** Put the journaled state back and spend the journal. false when there was none (not ours). */
async function restoreJournaled(platform, { exec, journal }) {
  const j = readJournal(journal);
  if (!j) return false;
  if (platform === 'win32') {
    let offFailed = false;
    const steps = winRestoreSteps(j.win);
    for (let i = 0; i < steps.length; i++) {
      try { await exec('reg', steps[i]); } catch { if (i === 0) offFailed = true; }
    }
    await refreshWindows(exec).catch(() => {});
    // ours could not even be switched off: keep the record for the next launch
    if (offFailed) return true;
  } else if (!Array.isArray(j.mac)) {
    await disableMac(exec).catch(() => {});   // nothing known about before: the old disable
  } else {
    for (const [cmd, args] of macRestoreSteps(j.mac)) await exec(cmd, args).catch(() => {});
  }
  clearJournal(journal);
  return true;
}

/* --------------------------- public API --------------------------- */
/**
 * @param {boolean} enabled
 * @param {object} [opts] host, httpPort, socksPort; and for the tests `exec`
 *   (the async runner), `platform`, and `journal` (defaults to useProxyJournal's).
 */
async function setSystemProxy(enabled, opts = {}) {
  const host = opts.host || '127.0.0.1';
  const httpPort = opts.httpPort || 10809;
  const socksPort = opts.socksPort || 10808;
  const platform = opts.platform || os.platform();
  const exec = opts.exec || run;
  const journal = opts.journal !== undefined ? opts.journal : journalFile;

  if (journal && journaled(platform)) {
    return serial(() => (enabled
      ? enableJournaled(platform, { host, httpPort, socksPort }, { exec, journal })
      : restoreJournaled(platform, { exec, journal })));
  }
  if (enabled) {
    if (platform === 'win32') return enableWindows(host, httpPort, exec);
    if (platform === 'darwin') return enableMac(host, socksPort, httpPort, exec);
    return enableLinux(host, httpPort);
  } else {
    if (platform === 'win32') return disableWindows(exec);
    if (platform === 'darwin') return disableMac(exec);
    return disableLinux();
  }
}

/**
 * At launch: a journal left behind means the last session died with the proxy
 * set. Put it back — but only while the proxy is still OURS: one someone set
 * since the crash is theirs, and the stale record just goes. On Windows, with
 * no journal, the proxy a build before the journal left (the one that died
 * connected, or that the update installer closed) is recognised by our own
 * exact bypass list AND `opts.legacyServer` — this app's own 127.0.0.1:port,
 * since a sibling build (the Plus fork) writes the same list for its own port
 * and may be connected right now — and switched off. Resolves 'restored' |
 * 'dropped' | 'legacy' | null; never throws.
 */
function repairSystemProxy(opts = {}) {
  const platform = opts.platform || os.platform();
  const exec = opts.exec || run;
  const journal = opts.journal !== undefined ? opts.journal : journalFile;
  if (!journal || !journaled(platform)) return Promise.resolve(null);
  return serial(async () => {
    const j = readJournal(journal);
    if (platform === 'win32') {
      let cur = null;
      try { cur = parseWinProxy(await exec('powershell', psArgs(WIN_SNAPSHOT_PS))); } catch { /* unknown */ }
      if (j) {
        const ours = !cur || (Number(cur.ProxyEnable) === 1 && cur.ProxyServer === j.ours);
        if (!ours) { clearJournal(journal); return 'dropped'; }
        await restoreJournaled(platform, { exec, journal });
        return 'restored';
      }
      if (opts.legacyServer && cur && Number(cur.ProxyEnable) === 1 && cur.ProxyOverride === WIN_BYPASS && cur.ProxyServer === opts.legacyServer) {
        await disableWindows(exec).catch(() => {});
        return 'legacy';
      }
      return null;
    }
    if (!j) return null;
    let cur = null;
    try { cur = await macSnapshot(exec); } catch { /* unknown */ }
    const o = j.ours || {};
    const ours = !cur || cur.some(s => s.web && s.web.enabled && s.web.server === o.host && s.web.port === Number(o.httpPort));
    if (!ours) { clearJournal(journal); return 'dropped'; }
    await restoreJournaled(platform, { exec, journal });
    return 'restored';
  }).catch(() => null);
}

/**
 * The exit hook's version: synchronous, bounded, never throws. The journal is
 * the only authority — none means we set nothing. No WinINet refresh (a
 * PowerShell start on the way out); browsers watch the registry key anyway.
 */
function restoreSystemProxySync(opts = {}) {
  const platform = opts.platform || os.platform();
  const journal = opts.journal !== undefined ? opts.journal : journalFile;
  const execSync = opts.execSync || ((cmd, args) => execFileSync(cmd, args, { windowsHide: true, stdio: 'ignore', timeout: 3000 }));
  if (!journal || !journaled(platform)) return false;
  const j = readJournal(journal);
  if (!j) return false;
  // macOS with nothing recorded: switching ours off needs the service list,
  // which this path cannot read — the journal stays for the launch repair
  if (platform === 'darwin' && !Array.isArray(j.mac)) return false;
  const steps = platform === 'win32'
    ? winRestoreSteps(j.win).map(args => ['reg', args])
    : macRestoreSteps(j.mac);
  let offFailed = false;
  steps.forEach(([cmd, args], i) => {
    try { execSync(cmd, args); } catch { if (i === 0 && platform === 'win32') offFailed = true; }
  });
  if (!offFailed) clearJournal(journal);
  return true;
}

module.exports = {
  setSystemProxy, useProxyJournal, repairSystemProxy, restoreSystemProxySync,
  parseMacServices, enableMac, disableMac, parseWinProxy, parseMacProxy, WIN_BYPASS
};
