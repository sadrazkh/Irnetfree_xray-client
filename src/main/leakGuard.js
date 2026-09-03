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

/**
 * Every firewall rule we make carries this group, and the group is the only
 * handle we ever remove by — so one `Remove-NetFirewallRule -Group` clears the
 * strict rules and the proxy-mode UDP block together, and cannot touch anything
 * else. In particular it cannot touch main.js's kill switch: that is a `netsh`
 * rule NAMED 'IRNetFree KillSwitch' and netsh rules carry no group, so neither
 * side can remove the other's. The two are independent on purpose — the kill
 * switch is armed on an unexpected drop and stays until the user says otherwise.
 */
const FW_GROUP = 'IRNetFree';

/**
 * What may still leave a physical adapter under the strict guard, on top of the
 * server entry IPs and the resolver bypass addresses the caller passes in: the
 * private ranges (the LAN, the router, the printer), link-local, loopback,
 * CGNAT, multicast, and the tunnel's own subnet. Everything else is blocked, so
 * an app that binds to the physical NIC on purpose — WebRTC/STUN, a client with
 * its own routes, anything dialling while the TUN is down for a moment — has
 * nowhere to go but the tunnel.
 */
const GUARD_EXCLUDES = [
  '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16',
  '127.0.0.0/8', '224.0.0.0/4', '100.64.0.0/10', '172.19.0.0/30',
  // The DHCP limited broadcast. Blocking it takes the machine's lease with it a
  // few hours into a session — long after anyone would connect the two.
  '255.255.255.255/32'
];

/** Every UDP remote port except 53. The address ranges narrow it further. */
const UDP_KEEP_PORTS = ['1-52', '54-65535'];

/* pf, on macOS: our rules live in one anchor, in files only root can write. */
const PF_ANCHOR = 'irnetfree';
const PF_ANCHOR_FILE = '/etc/pf.anchors/irnetfree';
const PF_MAIN_FILE = '/etc/pf.anchors/irnetfree.conf';
const PF_MARK = 'IRNF_PF_WAS';
/** An address or CIDR, either family — never a hostname, never a shell word. */
const PF_ADDR_RE = /^[0-9a-fA-F.:]+(\/\d{1,3})?$/;

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

/* ----------------------------- address maths ----------------------------- */

const IP_MAX = 4294967295;

function ipToInt(s) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(s == null ? '' : s).trim());
  if (!m) return null;
  let n = 0;
  for (let i = 1; i <= 4; i++) {
    const o = Number(m[i]);
    if (o > 255) return null;
    n = n * 256 + o;
  }
  return n;
}

function intToIp(n) {
  return [Math.floor(n / 16777216) % 256, Math.floor(n / 65536) % 256, Math.floor(n / 256) % 256, n % 256].join('.');
}

/**
 * `[first, last]` for `1.2.3.4`, `1.2.3.0/24` or `1.2.3.4-1.2.3.9`; null for
 * anything this layer cannot block — a v6 address (sing-box's `strict_route`
 * blocks v6 off-TUN by itself), a hostname we never resolved, junk out of a
 * hand-edited setting. A host address with a prefix is taken as its network,
 * which is what `192.168.8.63/24` obviously means.
 */
function parseRange(entry) {
  const s = String(entry == null ? '' : entry).trim();
  if (!s || s.includes(':')) return null;
  const dash = s.indexOf('-');
  if (dash > 0) {
    const a = ipToInt(s.slice(0, dash));
    const b = ipToInt(s.slice(dash + 1));
    return (a == null || b == null || b < a) ? null : [a, b];
  }
  const slash = s.indexOf('/');
  if (slash < 0) {
    const a = ipToInt(s);
    return a == null ? null : [a, a];
  }
  const a = ipToInt(s.slice(0, slash));
  const bits = Number(s.slice(slash + 1));
  if (a == null || !/^\d{1,2}$/.test(s.slice(slash + 1)) || bits > 32) return null;
  const size = Math.pow(2, 32 - bits);
  const lo = Math.floor(a / size) * size;
  return [lo, lo + size - 1];
}

/**
 * Everything in 0.0.0.0–255.255.255.255 that `excludes` does NOT cover, as
 * `start-end` strings — the form `New-NetFirewallRule -RemoteAddress` takes.
 *
 * A block rule is written as its own complement because the Windows firewall
 * has no "block everything except", and an ALLOW rule would not do: allow rules
 * do not beat other block rules, and a rule with an empty address list means
 * "any", i.e. the whole machine. Overlapping and adjacent excludes merge on the
 * way through, so the caller can hand over its lists unsorted and unmerged.
 */
function rangeComplement(excludes) {
  const spans = (excludes || []).map(parseRange).filter(Boolean).sort((a, b) => a[0] - b[0] || a[1] - b[1]);
  const out = [];
  let next = 0;
  for (const [lo, hi] of spans) {
    if (lo > next) out.push(`${intToIp(next)}-${intToIp(lo - 1)}`);
    if (hi + 1 > next) next = hi + 1;
  }
  if (next <= IP_MAX) out.push(`${intToIp(next)}-${intToIp(IP_MAX)}`);
  return out;
}

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

/* --------------------- Windows: the strict firewall rules --------------------- */

/** One outbound block rule in our group. `extra` is the part that differs. */
function winBlockRule(display, extra) {
  return `New-NetFirewallRule -Group ${psQuote(FW_GROUP)} -DisplayName ${psQuote(display)}`
    + ' -Direction Outbound -Action Block -Enabled True -Profile Any'
    + ` ${extra} | Out-Null`;
}

/**
 * The whole group, gone. Removing by GROUP is what keeps this from ever
 * touching the kill switch (a netsh rule with a name and no group), and what
 * lets one call clear the strict rules and the UDP block together.
 * `-ErrorAction SilentlyContinue` because "no rules matched" is an error, and
 * removing rules that are not there is the normal case.
 */
function winGroupRemoveScript() {
  return `Remove-NetFirewallRule -Group ${psQuote(FW_GROUP)} -ErrorAction SilentlyContinue`;
}

/**
 * Strict: every physical adapter blocks outbound TCP and UDP to everything
 * except the excludes (see rangeComplement). The tunnel adapter is not named,
 * so the tunnel itself is untouched; the server's entry IP is a hole in the
 * block, so sing-box/Xray can still reach it from the physical NIC.
 *
 * The removal goes first so re-engaging — a server switch under TUN — replaces
 * the rules instead of stacking a second set of them.
 *
 * With no ranges nothing is emitted at all: an empty `-RemoteAddress` means
 * "Any" to New-NetFirewallRule, so the "block nothing" case would silently
 * become "block the whole machine".
 */
function winStrictApplyScript({ adapters, ranges } = {}) {
  const list = (ranges || []).filter(Boolean);
  const lines = ["$ErrorActionPreference = 'Stop'", winGroupRemoveScript()];
  if (list.length) {
    for (const a of adapters || []) {
      const alias = aliasOf(a);
      for (const proto of ['TCP', 'UDP']) {
        lines.push(winBlockRule(`${FW_GROUP} strict ${proto} ${alias}`,
          `-InterfaceAlias ${psQuote(alias)} -Protocol ${proto} -RemoteAddress @(${psList(list)})`));
      }
    }
  }
  return lines.join('\n');
}

/**
 * Proxy mode's UDP block: WebRTC asks a STUN server on the internet for the
 * machine's real address over UDP, and the system proxy does not carry UDP at
 * all — so that question, and the answer, go around the proxy. This blocks it.
 *
 * Port 53 stays open (the resolver), and so does the whole LAN: the ranges are
 * the same public-internet complement the strict level uses, which is what
 * keeps DHCP renewals (unicast to the router on port 67), mDNS, SSDP and a
 * printer working. A rule that blocked every UDP port but 53 everywhere would
 * take the machine's DHCP lease with it a few hours into a session.
 */
function winUdpBlockApplyScript({ adapters, ranges } = {}) {
  const list = (ranges || []).filter(Boolean);
  const lines = ["$ErrorActionPreference = 'Stop'", winGroupRemoveScript()];
  if (list.length) {
    for (const a of adapters || []) {
      const alias = aliasOf(a);
      lines.push(winBlockRule(`${FW_GROUP} udp ${alias}`,
        `-InterfaceAlias ${psQuote(alias)} -Protocol UDP`
        + ` -RemotePort @(${psList(UDP_KEEP_PORTS)}) -RemoteAddress @(${psList(list)})`));
    }
  }
  return lines.join('\n');
}

const winApplyScript = (adapters, peer4, peer6) => winApplyLines(adapters, peer4, peer6).join('\n');
const winRestoreScript = (adapters) => winRestoreLines(adapters).join('\n');
const winOrphanKillScript = () => winOrphanLines().join('\n');

/**
 * Everything a teardown does on Windows, in ONE spawn: the orphan tunnel of a
 * dead session (crash repair only), then our firewall rules, then the
 * resolvers. The firewall comes before the DNS restore so the restore is never
 * the thing left blocked, and the rules go even when the adapters cannot be put
 * back — a block rule that outlives the app is a machine with no internet.
 */
function winReleaseScript(adapters, opts = {}) {
  return [
    ...(opts.orphans ? winOrphanLines() : []),
    ...(opts.firewall ? [winGroupRemoveScript()] : []),
    ...winRestoreLines(adapters)
  ].join('\n');
}

/** Crash repair, one spawn: kill what is left of the old session, then restore. */
const winRepairScript = (adapters) => winReleaseScript(adapters, { orphans: true });

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
      // The addresses are quoted too: they came off the machine, and this
      // script runs as root.
      return `networksetup -setdnsservers ${sh(nameOf(s))} ${dns.length ? dns.map(sh).join(' ') : 'Empty'} || FAIL=1`;
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

/* ----------------------------- macOS: the pf anchor ----------------------------- */

/**
 * The strict guard on macOS, as a pf ruleset for our own anchor.
 *
 * `set skip on lo0` (the obvious first line) is an OPTION, and pf takes options
 * only in the MAIN ruleset — inside an anchor it is a parse error, so loopback
 * gets a pass rule instead, which is the same thing for outbound traffic.
 *
 * Returns null when the tunnel device cannot be named: without
 * `pass out quick on <utunN>` this ruleset is "block everything", i.e. a
 * machine with no network at all. Neither backend hands us the device name on
 * Windows terms, so it is checked against the shape macOS actually creates.
 *
 * UNVERIFIED on a real Mac — the UI labels the level experimental there.
 */
function macPfAnchorText({ tunDevice, excludes } = {}) {
  const dev = String(tunDevice == null ? '' : tunDevice).trim();
  if (!/^utun\d+$/.test(dev)) return null;
  const list = [];
  for (const e of [...(excludes || []), ...GUARD_EXCLUDES]) {
    const s = String(e == null ? '' : e).trim();
    // A hostname would make pfctl resolve it at load time (and a shell word
    // would end up in a file we run as root) — addresses only.
    if (!s || !PF_ADDR_RE.test(s) || list.includes(s)) continue;
    list.push(s);
  }
  return [
    `# IRNetFree strict guard — generated, loaded into anchor "${PF_ANCHOR}"`,
    'pass out quick on lo0 all',
    `pass out quick on ${dev} all`,
    `pass out quick to { ${list.join(', ')} }`,
    'block out quick inet all',
    'block out quick inet6 all',
    ''
  ].join('\n');
}

/**
 * Write the anchor and load it. Two things it deliberately does NOT do:
 *
 *  - edit `/etc/pf.conf`. If the running ruleset has no `anchor "irnetfree"`
 *    line, a COPY of pf.conf plus that one line is loaded instead — and the
 *    copy lives in the root-owned anchors directory, because a file in
 *    world-writable /tmp fed to `pfctl` as root is a local privilege
 *    escalation waiting for someone to notice it.
 *  - enable pf when it is already enabled. `pfctl -E` bumps a reference count
 *    that only a matching `-X <token>` releases; taking one every session and
 *    never giving it back would pin pf on for other software. The marker line
 *    tells the caller which case it was, and release() disables pf only when
 *    this run is what enabled it.
 */
function macPfApplyLines(anchorText) {
  const body = String(anchorText == null ? '' : anchorText).replace(/\n+$/, '').split('\n');
  return [
    'umask 077',
    'mkdir -p /etc/pf.anchors',
    `cat > ${PF_ANCHOR_FILE} <<'IRNF_ANCHOR'`,
    ...body,
    'IRNF_ANCHOR',
    "if pfctl -s info 2>/dev/null | head -n 1 | grep -q 'Status: Enabled'; then",
    `  echo '${PF_MARK}=enabled'`,
    'else',
    `  echo '${PF_MARK}=disabled'`,
    '  pfctl -E >/dev/null 2>&1 || FAIL=1',
    'fi',
    `if ! pfctl -sr 2>/dev/null | grep -q 'anchor "${PF_ANCHOR}"'; then`,
    `  { cat /etc/pf.conf; echo 'anchor "${PF_ANCHOR}"'; } > ${PF_MAIN_FILE} || FAIL=1`,
    `  pfctl -f ${PF_MAIN_FILE} || FAIL=1`,
    'fi',
    `pfctl -a ${PF_ANCHOR} -f ${PF_ANCHOR_FILE} || FAIL=1`
  ];
}

/**
 * Flush our anchor and take its files with it — never `pfctl -F all`, which
 * would flush the whole machine's ruleset. The anchor line may stay in the
 * running ruleset: it then references an anchor with no rules, which filters
 * nothing, and the next engage reuses it.
 */
function macPfRemoveLines(opts = {}) {
  return [
    `pfctl -a ${PF_ANCHOR} -F all 2>/dev/null || true`,
    `rm -f ${PF_ANCHOR_FILE} ${PF_MAIN_FILE}`,
    ...(opts.disable ? ['pfctl -d 2>/dev/null || true'] : [])
  ];
}

const macApplyScript = (services, peer4, peer6) => macScript(macApplyLines(services, peer4, peer6));
const macRestoreScript = (services) => macScript(macRestoreLines(services));
const macOrphanKillScript = () => macScript(macOrphanLines());
const macPfApplyScript = (anchorText) => macScript(macPfApplyLines(anchorText));
const macPfRemoveScript = (opts) => macScript(macPfRemoveLines(opts));

/** The macOS teardown, in ONE privileged script — one password prompt. */
function macReleaseScript(services, opts = {}) {
  return macScript([
    ...(opts.orphans ? macOrphanLines() : []),
    ...(opts.firewall ? macPfRemoveLines({ disable: !!opts.disablePf }) : []),
    ...macRestoreLines(services)
  ]);
}

/** Crash repair in ONE privileged script, so the launch asks for one password. */
const macRepairScript = (services) => macReleaseScript(services, { orphans: true });

/* ----------------------------- the guard ----------------------------- */

/**
 * A snapshot with the tunnel's own resolvers taken out of it.
 *
 * What we are about to write must never come back as what was there before. On
 * macOS the tunnel sets the service's DNS before the guard ever looks; on
 * Windows a second engage — a server switch under TUN — reads back the peer the
 * first one wrote. Restoring THAT would pin every adapter to an address that
 * routes nowhere the moment the tunnel stops, and the state file is deleted on
 * a successful restore, so nothing would be left to undo it with. A family left
 * empty here is read as "it was on DHCP", so the worst this can do is restore
 * too little.
 */
function withoutPeers(list, peers) {
  const drop = new Set((peers || []).filter(Boolean).map(p => String(p).toLowerCase()));
  const keep = (arr) => addrList(arr).filter(a => !drop.has(String(a).toLowerCase()));
  return (list || []).map(e => (e && e.dns !== undefined)
    ? Object.assign({}, e, { dns: keep(e.dns) })
    : Object.assign({}, e, { v4: keep(e.v4), v6: keep(e.v6) }));
}

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
    this._udpNoteLogged = false;
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
   * Point every physical adapter at the tunnel peer for this session, and — at
   * `level: 'strict'` — firewall everything that is not the tunnel off those
   * adapters. `level: 'off'` (and Linux, which has no portable resolver to
   * rewrite) does nothing. Throws when the override itself fails — the caller
   * keeps the tunnel, logs it and carries on.
   *
   * `excludes` are the addresses that must still reach the network directly:
   * the resolved server entry IPs and the resolver bypass addresses of the live
   * tunnel (`tun.excludeIps`). Without the entry IPs among them a strict block
   * would cut the tunnel it exists to protect.
   */
  engage({ level, peer4, peer6, tunAlias, backend, excludes } = {}) {
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

      const strict = level === 'strict';
      const state = {
        version: 1,
        at: new Date().toISOString(),
        backend: backend || null,
        peer4,
        peer6: peer6 || null,
        tunAlias: tunAlias || null,
        strict: false,
        udpBlock: false
      };

      let count = 0;
      let apply = null;
      let block = null;
      // Worked out before the state file is written: on macOS a tunnel device
      // we cannot name means no anchor at all, and the file must not claim one.
      const anchor = (strict && this.platform === 'darwin')
        ? macPfAnchorText({ tunDevice: tunAlias, excludes })
        : null;
      // An override of ours that is already live — a server switch under TUN
      // re-engages without an intervening release — keeps the originals it
      // recorded. They are the machine's own resolvers, and they exist nowhere
      // else; re-reading the adapters now would only find our peer.
      const live = this.readState();
      if (this.platform === 'win32') {
        const adapters = (live && live.win && live.win.adapters && live.win.adapters.length)
          ? live.win.adapters
          : withoutPeers(parseWinSnapshot(await this._powershell(winSnapshotScript(tunAlias))), [peer4, peer6]);
        count = adapters.length;
        state.win = { adapters };
        state.strict = strict;
        apply = () => this._powershell(winApplyScript(adapters, peer4, peer6));
        if (strict) {
          const ranges = rangeComplement([...(excludes || []), ...GUARD_EXCLUDES]);
          block = () => this._powershell(winStrictApplyScript({ adapters, ranges }));
        }
      } else {
        const services = (live && live.mac && live.mac.services && live.mac.services.length)
          ? live.mac.services
          : withoutPeers(parseMacSnapshot(await this.run('/bin/bash', ['-c', macSnapshotScript()])), [peer4, peer6]);
        count = services.length;
        state.mac = { services };
        state.strict = !!anchor;
        apply = () => this._privileged('apply', macApplyScript(services, peer4, peer6));
        if (anchor) {
          state.pfEnabledByUs = false;
          block = async () => {
            const out = await this._privileged('pf', macPfApplyScript(anchor));
            // Only OUR pfctl -E gets a pfctl -d at the end of the session.
            state.pfEnabledByUs = new RegExp(`${PF_MARK}=disabled`).test(String(out == null ? '' : out));
            this.writeState(state);
          };
        }
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
      if (strict) {
        if (block) {
          await block();
          // Not an aside: at this level a bypass rule ("send .ir direct") no
          // longer reaches anything, because direct dials leave through the
          // physical adapter this just blocked.
          this.onLog(`Leak guard (strict): ${count} adapters now block every outbound address but the tunnel's`
            + ' — traffic your rules send direct is blocked too', 'warn');
        } else {
          this.onLog('Leak guard (strict): could not name the tunnel device, so the pf block was skipped'
            + ' — the DNS override is on, the rest of the traffic is not guarded', 'warn');
        }
      }
      return { engaged: true, adapters: count };
    });
  }

  /**
   * Proxy mode only: block outbound UDP to the internet (except DNS) on every
   * physical adapter, so WebRTC cannot ask a STUN server for the real address
   * behind a proxy that carries no UDP at all. TUN mode has no use for it — the
   * tunnel already takes UDP — and the strict guard's rules cover the same
   * ground.
   *
   * The adapters are snapshotted here rather than passed in: the caller has no
   * way to enumerate them (that is a generated script, and it is this module
   * that owns them). They are NOT recorded in the state file — nothing here
   * touches a resolver, and a recorded adapter is one whose DNS release() would
   * reset.
   */
  engageUdpBlock({ excludes } = {}) {
    return this._queue(async () => {
      if (this.platform !== 'win32') {
        if (!this._udpNoteLogged) {
          this._udpNoteLogged = true;
          this.onLog('Blocking UDP in proxy mode is not available on this platform yet'
            + ' — WebRTC can still reveal your address; TUN mode covers it', 'warn');
        }
        return { engaged: false, adapters: 0 };
      }
      const adapters = parseWinSnapshot(await this._powershell(winSnapshotScript(null)));
      if (!adapters.length) {
        this.onLog('Leak guard: no physical adapter is up — no UDP block to apply', 'warn');
        return { engaged: false, adapters: 0 };
      }
      // A state file already here belongs to a session whose DNS override is
      // still live (a repair that could not run, most likely) — its record of
      // the originals is the only copy there is. Add to it, never replace it.
      const prev = this.readState();
      const state = Object.assign({
        version: 1, backend: null, peer4: null, peer6: null, tunAlias: null, strict: false, win: { adapters: [] }
      }, prev || {}, { at: new Date().toISOString(), udpBlock: true });

      this.writeState(state);
      await this._powershell(winUdpBlockApplyScript({
        adapters, ranges: rangeComplement([...(excludes || []), ...GUARD_EXCLUDES])
      }));
      this.onLog(`Blocked outbound UDP to the internet (except DNS) on ${adapters.length} adapters`
        + ' — WebRTC cannot leak your address', 'info');
      return { engaged: true, adapters: adapters.length };
    });
  }

  /** What a release actually undid, for the log. */
  _releasedLine(st, n, repair) {
    const rules = st.strict ? 'firewall rules' : (st.udpBlock ? 'the UDP block' : null);
    if (repair) {
      if (!n) return `Removed ${rules || 'what a previous session left behind'} left from a previous session`;
      const head = `Restored DNS of ${n} adapters left from a previous session`;
      return rules ? `${head}, and removed its ${rules}` : head;
    }
    const parts = [];
    if (n) parts.push(`DNS of ${n} adapters restored`);
    if (rules) parts.push(`${rules} removed`);
    return parts.length ? `Leak guard released: ${parts.join(', ')}` : 'Leak guard released';
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
      // Exactly what this session made: the state file says whether the strict
      // rules or the UDP block are out there. Both live in one firewall group,
      // so one removal clears either.
      const firewall = !!(st.strict || st.udpBlock);
      try {
        if (this.platform === 'darwin') {
          const services = (st.mac && st.mac.services) || [];
          this._logKills(await this._privileged('restore',
            macReleaseScript(services, { orphans, firewall, disablePf: !!st.pfEnabledByUs })));
        } else {
          const adapters = (st.win && st.win.adapters) || [];
          this._logKills(await this._powershell(winReleaseScript(adapters, { orphans, firewall })));
        }
      } catch (e) {
        this.onLog(`Leak guard could not put the adapters' DNS back (${(e && e.message) || e}) — `
          + 'it will try again at the next launch', 'error');
        return { released: false, adapters: n, error: (e && e.message) || String(e) };
      }
      this.clearState();
      this.onLog(this._releasedLine(st, n, !!opts.repair), 'info');
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
      const firewall = !!(st.strict || st.udpBlock);
      if (this.platform === 'win32') {
        const adapters = (st.win && st.win.adapters) || [];
        if (!adapters.length && !firewall) { this.clearState(); return false; }
        this.runSync('powershell', [...PS_FLAGS, '-Command', winReleaseScript(adapters, { firewall })],
          { timeout: 5000, stdio: 'ignore', windowsHide: true });
        this.clearState();
        return true;
      }
      if (this.platform === 'darwin') {
        if (!(process.getuid && process.getuid() === 0)) return false;
        const services = (st.mac && st.mac.services) || [];
        if (!services.length && !firewall) { this.clearState(); return false; }
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-lg-'));
        const file = path.join(dir, 'restore.sh');
        fs.writeFileSync(file, macReleaseScript(services, { firewall, disablePf: !!st.pfEnabledByUs }), { mode: 0o700 });
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
  LeakGuard, STATE_FILE, FW_GROUP, GUARD_EXCLUDES, withoutPeers,
  psQuote, parseWinSnapshot, parseMacSnapshot, rangeComplement,
  winSnapshotScript, winApplyScript, winRestoreScript, winOrphanKillScript, winRepairScript,
  winStrictApplyScript, winGroupRemoveScript, winUdpBlockApplyScript, winReleaseScript,
  macSnapshotScript, macApplyScript, macRestoreScript, macOrphanKillScript, macRepairScript,
  macPfAnchorText, macPfApplyScript, macPfRemoveScript, macReleaseScript
};
