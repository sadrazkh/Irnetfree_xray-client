'use strict';
/**
 * The leak guard — level `standard`.
 *
 * Phase 2 pointed the TUN adapter's own resolver at the tunnel peer, and that is
 * not enough on either desktop platform:
 *
 *  - Windows sends a query to the resolvers of EVERY connected adapter in
 *    parallel ("smart multi-homed name resolution"). The physical adapters still
 *    carry the ISP's, so the ISP still sees every name the machine looks up, and
 *    the first answer back wins.
 *  - macOS resolves per network service; only the service that owns the default
 *    route was ours.
 *
 * So for the length of a session every physical adapter's DNS points at the
 * tunnel peer, and the originals go back afterwards. "Afterwards" includes the
 * ugly cases: a disconnect, a quit, a hard `process.exit`, and — because none of
 * those run when the app is killed or the machine loses power — the next launch,
 * from `userData/tun-state.json`. That file is the whole crash story: it is
 * written BEFORE the first adapter is touched, so a crash in the middle still
 * leaves a complete record of what to put back. Every "my internet broke after
 * the VPN died" report is a guard that had no such file.
 *
 * Nothing here runs a command directly: `run`, `runScriptPrivileged` and
 * `runSync` are injected (tunPlatform.js supplies the real ones), so the tests
 * pin the generated script text — the only review these lines get before they
 * run as Administrator on someone's laptop — without spawning anything.
 *
 * Windows note: one `powershell` spawn per operation, never one per adapter.
 * macOS note: `networksetup` needs root, so apply/restore go through
 * `runScriptPrivileged`. Task 1 left no hook to append lines to the TUN setup
 * script, so this is a SECOND password prompt at connect time on macOS (the
 * design accepts one); the crash repair batches its orphan kill and its DNS
 * restore into a single script, so a launch after a crash prompts only once.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const platform = require('./tunPlatform');

/** Written to userData before the override, removed after a clean restore. */
const STATE_FILE = 'tun-state.json';

/** Adapters we create ourselves — never guarded, whichever backend is live. */
const OWN_ADAPTERS = [platform.SINGBOX_ADAPTER, platform.TUN2SOCKS_ADAPTER];

/** Adapter descriptions that are not a physical NIC (ours included). */
const VIRTUAL_RE = 'Wintun|TAP|Loopback|Hyper-V|VMware|VirtualBox|Bluetooth';

const PS_FLAGS = ['-NoProfile', '-NonInteractive'];

/* ----------------------------- small shared bits ----------------------------- */

/** Single-quote a value for PowerShell (a quote inside doubles itself). */
function psQuote(s) { return `'${String(s == null ? '' : s).replace(/'/g, "''")}'`; }
function psList(arr) { return arr.map(psQuote).join(','); }

/** A list of addresses out of whatever the platform gave us. */
function addrList(v) {
  if (v == null) return [];
  return (Array.isArray(v) ? v : [v]).map(s => String(s == null ? '' : s).trim()).filter(Boolean);
}

const aliasOf = (a) => (a && typeof a === 'object' ? a.alias : a);
const nameOf = (s) => (s && typeof s === 'object' ? s.name : s);

/* ----------------------------- Windows scripts ----------------------------- */

/**
 * Print every physical adapter that is Up, with the resolvers it uses now and
 * whether that list came from DHCP.
 *
 * The DHCP question is what makes the restore honest. `Get-DnsClientServerAddress`
 * reports the EFFECTIVE list, so an adapter on DHCP reports the router's address
 * — and putting that back with `-ServerAddresses` would pin it as a STATIC
 * resolver, which survives the session, the app and the move to another network.
 * The registry `NameServer` value holds the statically configured list and only
 * that, so an empty one means "this family is on DHCP, put it back with
 * -ResetServerAddresses". It is also locale-independent, which `netsh`'s
 * "Statically Configured DNS Servers" heading is not.
 */
function winSnapshotScript(tunAlias) {
  const skip = [...new Set([...OWN_ADAPTERS, ...(tunAlias ? [String(tunAlias)] : [])])];
  const where = [
    "$_.Status -eq 'Up'",
    ...skip.map(a => `$_.InterfaceAlias -ne ${psQuote(a)}`),
    `$_.InterfaceDescription -notmatch ${psQuote(VIRTUAL_RE)}`
  ].join(' -and ');
  const dnsOf = (fam) => `@(Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily ${fam} | Select-Object -ExpandProperty ServerAddresses)`;
  return [
    "$ErrorActionPreference = 'SilentlyContinue'",
    '$out = @()',
    `foreach ($a in @(Get-NetAdapter | Where-Object { ${where} })) {`,
    "$k4 = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\' + $a.InterfaceGuid",
    "$k6 = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\Interfaces\\' + $a.InterfaceGuid",
    '$out += [pscustomobject]@{ alias = $a.InterfaceAlias;'
      + ` v4 = ${dnsOf('IPv4')};`
      + ` v6 = ${dnsOf('IPv6')};`
      + ' dhcp4 = [string]::IsNullOrWhiteSpace((Get-ItemProperty -Path $k4 -Name NameServer).NameServer);'
      + ' dhcp6 = [string]::IsNullOrWhiteSpace((Get-ItemProperty -Path $k6 -Name NameServer).NameServer) }',
    '}',
    'ConvertTo-Json -InputObject @($out) -Depth 3 -Compress'
  ].join('\n');
}

/**
 * `[{ alias, v4, v6, dhcp4, dhcp6 }]` out of that script's stdout. Anything that
 * is not the expected JSON (an error message, an empty run, the single object
 * PowerShell 5.1 unwraps a one-element array into) yields a list, never a throw:
 * a snapshot we cannot read means "guard nothing", not "fail the connect".
 */
function parseWinSnapshot(json) {
  let data;
  try { data = JSON.parse(String(json == null ? '' : json).trim() || 'null'); } catch { return []; }
  if (!data) return [];
  const out = [];
  for (const a of (Array.isArray(data) ? data : [data])) {
    if (!a || typeof a !== 'object') continue;
    const alias = String(a.alias == null ? '' : a.alias).trim();
    if (!alias) continue;
    const rec = { alias, v4: addrList(a.v4), v6: addrList(a.v6) };
    if (typeof a.dhcp4 === 'boolean') rec.dhcp4 = a.dhcp4;
    if (typeof a.dhcp6 === 'boolean') rec.dhcp6 = a.dhcp6;
    out.push(rec);
  }
  return out;
}

/** Every adapter's resolver becomes the tunnel peer; the cache goes with it. */
function winApplyLines(adapters, peer4, peer6) {
  const lines = ["$ErrorActionPreference = 'Stop'"];
  for (const a of adapters || []) {
    const alias = psQuote(aliasOf(a));
    // Set-DnsClientServerAddress has no -AddressFamily: the family of each call
    // is the family of the addresses in it, and a call leaves the other alone.
    if (peer4) lines.push(`Set-DnsClientServerAddress -InterfaceAlias ${alias} -ServerAddresses ${psQuote(peer4)}`);
    if (peer6) lines.push(`Set-DnsClientServerAddress -InterfaceAlias ${alias} -ServerAddresses ${psQuote(peer6)}`);
  }
  lines.push('Clear-DnsClientCache');
  return lines;
}

/**
 * Put the recorded resolvers back.
 *
 * `-ResetServerAddresses` is per adapter, not per family, so it runs first and
 * clears both back to DHCP; then whichever family was STATIC gets its list
 * again. Doing it the other way round would leave our peer as the v6 resolver of
 * a machine with a static v4 and an automatic v6.
 *
 * An adapter that no longer exists (the USB NIC was unplugged) is skipped rather
 * than failing the whole restore — its configuration went with it.
 */
function winRestoreLines(adapters) {
  const lines = ["$ErrorActionPreference = 'Stop'"];
  for (const a of adapters || []) {
    const alias = psQuote(aliasOf(a));
    lines.push(`if (Get-NetAdapter -InterfaceAlias ${alias} -ErrorAction SilentlyContinue) {`);
    lines.push(`Set-DnsClientServerAddress -InterfaceAlias ${alias} -ResetServerAddresses`);
    for (const [fam, dhcp] of [['v4', 'dhcp4'], ['v6', 'dhcp6']]) {
      const orig = addrList(a && a[fam]);
      if (!orig.length) continue;          // nothing was set: the reset IS the restore
      if (a[dhcp] === true) continue;      // it came from DHCP: ditto
      lines.push(`Set-DnsClientServerAddress -InterfaceAlias ${alias} -ServerAddresses ${psList(orig)}`);
    }
    lines.push('}');
  }
  lines.push('Clear-DnsClientCache');
  return lines;
}

/**
 * A hard-killed app leaves the tunnel process running with its routes in place.
 * The state file is how we know a session died, so this only ever runs from
 * repairAtLaunch() — and it matches on the argv of OUR tunnels (sing-box on a
 * config in one of our `irnf-sb-` temp dirs, tun2socks on our adapter), never on
 * a bare process name.
 */
function winOrphanLines() {
  const hunt = (exe, argvLike, label) =>
    `foreach ($p in @(Get-CimInstance Win32_Process -Filter ${psQuote(`Name='${exe}'`)} | Where-Object { $_.CommandLine -like ${psQuote(argvLike)} })) `
    + `{ Write-Output ('killed ${label} (pid ' + $p.ProcessId + ')'); Stop-Process -Id $p.ProcessId -Force }`;
  return [
    "$ErrorActionPreference = 'SilentlyContinue'",
    hunt('sing-box.exe', '*irnf-sb-*', 'sing-box'),
    hunt('tun2socks.exe', `*-device ${platform.TUN2SOCKS_ADAPTER}*`, 'tun2socks')
  ];
}

const winApplyScript = (adapters, peer4, peer6) => winApplyLines(adapters, peer4, peer6).join('\n');
const winRestoreScript = (adapters) => winRestoreLines(adapters).join('\n');
const winOrphanKillScript = () => winOrphanLines().join('\n');
/** Crash repair, one spawn: kill what is left of the old session, then restore. */
const winRepairScript = (adapters) => [...winOrphanLines(), ...winRestoreLines(adapters)].join('\n');

/* ----------------------------- macOS scripts ----------------------------- */

const sh = platform.sh;

function macScript(lines) { return ['#!/bin/bash', 'FAIL=0', ...lines, 'exit $FAIL', ''].join('\n'); }

/**
 * Every enabled network service and its current resolvers, as
 * `name<TAB>a b c` (or `name<TAB>` when it is on DHCP). `-listallnetworkservices`
 * puts a legend on the first line and marks disabled services with a `*`; both
 * are dropped here. Read-only — this one needs no password.
 */
function macSnapshotScript() {
  return macScript([
    'networksetup -listallnetworkservices 2>/dev/null | tail -n +2 | while IFS= read -r svc; do',
    "  case \"$svc\" in ''|\\**) continue;; esac",
    '  dns="$(networksetup -getdnsservers "$svc" 2>/dev/null)"',
    '  case "$dns" in',
    "    *'any DNS Servers'*) printf '%s\\t\\n' \"$svc\";;",
    "    *) printf '%s\\t%s\\n' \"$svc\" \"$(printf '%s' \"$dns\" | tr '\\n' ' ')\";;",
    '  esac',
    'done'
  ]);
}

/** `[{ name, dns }]` out of that script's stdout. */
function parseMacSnapshot(text) {
  const out = [];
  for (const line of String(text == null ? '' : text).split(/\r?\n/)) {
    const tab = line.indexOf('\t');
    if (tab < 0) continue;                       // the legend, a blank line, an error
    const name = line.slice(0, tab).trim();
    if (!name) continue;
    out.push({ name, dns: line.slice(tab + 1).split(/\s+/).map(s => s.trim()).filter(Boolean) });
  }
  return out;
}

/** macOS keeps its own cache in front of the resolvers — flush it both ways. */
const MAC_FLUSH = [
  'dscacheutil -flushcache 2>/dev/null || true',
  'killall -HUP mDNSResponder 2>/dev/null || true'
];

function macApplyLines(services, peer4, peer6) {
  const peers = [peer4, peer6].filter(Boolean).join(' ');
  return [
    ...(services || []).map(s => `networksetup -setdnsservers ${sh(nameOf(s))} ${peers} || FAIL=1`),
    ...MAC_FLUSH
  ];
}

/** `Empty` is how networksetup says "back to whatever DHCP hands you". */
function macRestoreLines(services) {
  return [
    ...(services || []).map(s => {
      const dns = addrList(s && s.dns);
      return `networksetup -setdnsservers ${sh(nameOf(s))} ${dns.length ? dns.join(' ') : 'Empty'} || FAIL=1`;
    }),
    ...MAC_FLUSH
  ];
}

/** The same orphan hunt as on Windows. `[-]device` keeps pgrep off its own argv. */
function macOrphanLines() {
  const hunt = (pattern, label) =>
    `for p in $(pgrep -f ${sh(pattern)} 2>/dev/null); do echo "killed ${label} (pid $p)"; kill -TERM "$p" 2>/dev/null || true; done`;
  return [
    hunt('sing-box run -c .*irnf-sb-', 'sing-box'),
    hunt('[-]device utun', 'tun2socks')
  ];
}

const macApplyScript = (services, peer4, peer6) => macScript(macApplyLines(services, peer4, peer6));
const macRestoreScript = (services) => macScript(macRestoreLines(services));
const macOrphanKillScript = () => macScript(macOrphanLines());
/** Crash repair in ONE privileged script, so the launch asks for one password. */
const macRepairScript = (services) => macScript([...macOrphanLines(), ...macRestoreLines(services)]);

/* ----------------------------- the guard ----------------------------- */

function countTargets(st) {
  if (!st) return 0;
  return ((st.win && st.win.adapters) || []).length + ((st.mac && st.mac.services) || []).length;
}

class LeakGuard {
  /**
   * @param {{ userData: string, onLog?: Function, run?: Function,
   *           runScriptPrivileged?: Function, runSync?: Function, platform?: string }} opts
   */
  constructor(opts = {}) {
    this.userData = opts.userData;
    this.onLog = opts.onLog || (() => {});
    this.run = opts.run || platform.run;
    this.runScriptPrivileged = opts.runScriptPrivileged || platform.runScriptPrivileged;
    this.runSync = opts.runSync || execFileSync;
    this.platform = opts.platform || os.platform();
    // engage / release / repairAtLaunch all read-modify-delete one file. The
    // launch repair is deliberately not awaited (a macOS password prompt must
    // not hold up the window), so it can still be running when the user presses
    // Connect — and its delete would then throw away the LIVE session's
    // originals. One queue, and that whole class of race is gone.
    this._chain = Promise.resolve();
  }

  /** Serialize against every other operation on the state file. */
  _queue(fn) {
    const started = this._chain.then(fn, fn);
    this._chain = started.then(() => {}, () => {});
    return started;
  }

  statePath() { return path.join(this.userData, STATE_FILE); }

  readState() {
    try {
      const raw = fs.readFileSync(this.statePath(), 'utf8');
      const st = JSON.parse(raw);
      return st && typeof st === 'object' ? st : null;
    } catch { return null; }
  }

  /** Write through a temp file: a torn state file is worse than none at all. */
  writeState(st) {
    const p = this.statePath();
    const tmp = p + '.tmp';
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(tmp, JSON.stringify(st, null, 2));
    fs.renameSync(tmp, p);
  }

  clearState() { try { fs.unlinkSync(this.statePath()); } catch {} }

  /** Run a generated script as root (macOS): a temp file, then one prompt. */
  async _privileged(name, text) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-lg-'));
    const file = path.join(dir, `${name}.sh`);
    try {
      fs.writeFileSync(file, text, { mode: 0o700 });
      return await this.runScriptPrivileged(file);
    } finally {
      try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
    }
  }

  _powershell(script) {
    return this.run('powershell', [...PS_FLAGS, '-Command', script]);
  }

  /** One log line per tunnel process the repair killed. */
  _logKills(out) {
    for (const line of String(out || '').split(/\r?\n/)) {
      const t = line.trim();
      if (t.startsWith('killed ')) this.onLog(t, 'warn');
    }
  }

  /**
   * Point every physical adapter at the tunnel peer for this session.
   * `level: 'off'` (and Linux, which has no portable resolver to rewrite) does
   * nothing. Throws when the override itself fails — the caller keeps the
   * tunnel, logs it and carries on.
   */
  engage({ level, peer4, peer6, tunAlias, backend } = {}) {
    return this._queue(async () => {
      if (!level || level === 'off') return { engaged: false, adapters: 0 };
      if (!peer4) {
        this.onLog('Leak guard: no tunnel resolver to point the adapters at — skipped', 'warn');
        return { engaged: false, adapters: 0 };
      }
      if (this.platform !== 'win32' && this.platform !== 'darwin') {
        this.onLog('Leak guard: the adapter DNS override is not supported on Linux — the resolver is yours to point at '
          + peer4, 'warn');
        return { engaged: false, adapters: 0 };
      }

      const state = {
        version: 1,
        at: new Date().toISOString(),
        backend: backend || null,
        peer4,
        peer6: peer6 || null,
        tunAlias: tunAlias || null
      };

      let count = 0;
      let apply = null;
      if (this.platform === 'win32') {
        const adapters = parseWinSnapshot(await this._powershell(winSnapshotScript(tunAlias)));
        count = adapters.length;
        state.win = { adapters };
        apply = () => this._powershell(winApplyScript(adapters, peer4, peer6));
      } else {
        const services = parseMacSnapshot(await this.run('/bin/bash', ['-c', macSnapshotScript()]));
        count = services.length;
        state.mac = { services };
        apply = () => this._privileged('apply', macApplyScript(services, peer4, peer6));
      }
      if (!count) {
        this.onLog('Leak guard: no physical adapter is up — nothing to point at the tunnel', 'warn');
        return { engaged: false, adapters: 0 };
      }

      // The originals go to disk BEFORE the first adapter changes: everything
      // after this line is undoable, by us or by the next launch.
      this.writeState(state);
      await apply();
      this.onLog(`Leak guard: DNS of ${count} adapters → ${[peer4, peer6].filter(Boolean).join(' ')}`, 'info');
      return { engaged: true, adapters: count };
    });
  }

  /**
   * Put the recorded resolvers back and forget the session. Idempotent: with no
   * state file there is nothing to undo. A failed restore KEEPS the file, so the
   * next launch tries again rather than losing the originals.
   */
  release(opts = {}) {
    return this._queue(async () => {
      const st = this.readState();
      if (!st) return { released: false, adapters: 0 };
      const n = countTargets(st);
      const orphans = !!opts.orphans;
      try {
        if (this.platform === 'darwin') {
          const services = (st.mac && st.mac.services) || [];
          this._logKills(await this._privileged('restore',
            orphans ? macRepairScript(services) : macRestoreScript(services)));
        } else {
          const adapters = (st.win && st.win.adapters) || [];
          this._logKills(await this._powershell(
            orphans ? winRepairScript(adapters) : winRestoreScript(adapters)));
        }
      } catch (e) {
        this.onLog(`Leak guard could not put the adapters' DNS back (${(e && e.message) || e}) — `
          + 'it will try again at the next launch', 'error');
        return { released: false, adapters: n, error: (e && e.message) || String(e) };
      }
      this.clearState();
      this.onLog(opts.repair
        ? `Restored DNS of ${n} adapters left from a previous session`
        : `Leak guard released: DNS of ${n} adapters restored`, 'info');
      return { released: true, adapters: n };
    });
  }

  /**
   * `process.on('exit')` cleanup: no promises are left to await there, so this
   * is the synchronous, best-effort, never-throwing version. Windows gets one
   * bounded PowerShell run; macOS only when we are already root, since a
   * password prompt cannot be answered while the process is exiting (the
   * graceful teardown, or the next launch, covers that case).
   */
  releaseSync() {
    try {
      const st = this.readState();
      if (!st) return false;
      if (this.platform === 'win32') {
        const adapters = (st.win && st.win.adapters) || [];
        if (!adapters.length) { this.clearState(); return false; }
        this.runSync('powershell', [...PS_FLAGS, '-Command', winRestoreScript(adapters)],
          { timeout: 5000, stdio: 'ignore', windowsHide: true });
        this.clearState();
        return true;
      }
      if (this.platform === 'darwin') {
        if (!(process.getuid && process.getuid() === 0)) return false;
        const services = (st.mac && st.mac.services) || [];
        if (!services.length) { this.clearState(); return false; }
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-lg-'));
        const file = path.join(dir, 'restore.sh');
        fs.writeFileSync(file, macRestoreScript(services), { mode: 0o700 });
        try {
          this.runSync('/bin/bash', [file], { timeout: 5000, stdio: 'ignore' });
          this.clearState();
          return true;
        } finally {
          try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
        }
      }
      return false;
    } catch {
      // Never throw out of an exit hook, and never clear the file on a failure:
      // the next launch is the last chance to give the machine its DNS back.
      return false;
    }
  }

  /**
   * The crash repair, called once at startup before anything touches the
   * network. A state file here means the last session did not shut down
   * cleanly, so the tunnel process it started may still be running with its
   * routes in place — that goes first, in the same script as the DNS restore.
   */
  async repairAtLaunch() {
    if (!this.readState()) return { repaired: false, adapters: 0 };
    this.onLog('A previous session did not shut down cleanly — putting the network back', 'warn');
    const r = await this.release({ repair: true, orphans: true });
    return { repaired: !!r.released, adapters: r.adapters };
  }
}

module.exports = {
  LeakGuard, STATE_FILE,
  psQuote, parseWinSnapshot, parseMacSnapshot,
  winSnapshotScript, winApplyScript, winRestoreScript, winOrphanKillScript, winRepairScript,
  macSnapshotScript, macApplyScript, macRestoreScript, macOrphanKillScript, macRepairScript
};
