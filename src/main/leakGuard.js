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
 * So for the length of a session every physical adapter's DNS is taken — on
 * macOS pointed at the tunnel peer, on Windows held on loopback (WIN_HOLD4, and
 * why not the peer) — and the originals go back afterwards. "Afterwards" includes the
 * ugly cases: a disconnect, a quit, a hard `process.exit`, and — because none of
 * those run when the app is killed or the machine loses power — the next launch,
 * from `userData/tun-state.json`. That file is the whole crash story: it is
 * written BEFORE the first adapter is touched, so a crash in the middle still
 * leaves a complete record of what to put back. Every "my internet broke after
 * the VPN died" report is a guard that had no such file.
 *
 * "Afterwards" pointedly does NOT include a reconnect. A network change, a
 * server switch and a settings apply all tear the tunnel down and build it
 * again, and releasing the guard for the length of that rebuild would put every
 * adapter back on the ISP's resolver — and take the strict firewall with it —
 * for exactly as long as it takes to protect the machine again. So there is
 * `holdForReconnect()`: the override stays, and only the firewall's holes are
 * widened to admit the server the next tunnel is about to dial. During the gap
 * names simply do not resolve. That is the safe answer, and it is the whole
 * design — and on Windows it holds only because the adapters are on loopback:
 * with the TUN adapter gone, the peer routes out of the physical NIC.
 *
 * The other half of the same problem is ownership. Two connects can overlap,
 * and the one that loses still runs its cleanup: without a way to tell whose
 * override is on the machine, the loser's release undoes the winner's guard on
 * a tunnel that is up and carrying traffic. So `engage()` hands back a receipt
 * and `release({ token })` refuses to act on a stale one. A release with no
 * receipt is the user's own intent — disconnect, quit, exit — and always runs.
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
const net = require('net');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const platform = require('./tunPlatform');

/** Written to userData before the override, removed after a clean restore. */
const STATE_FILE = 'tun-state.json';

/** Adapters we create ourselves — never guarded, whichever backend is live. */
const OWN_ADAPTERS = [platform.SINGBOX_ADAPTER, platform.TUN2SOCKS_ADAPTER];

/**
 * Adapter descriptions the guard leaves alone: another VPN's tunnel (and ours),
 * loopback, and the HOST-ONLY side of a hypervisor. Not "Hyper-V" or
 * "Bluetooth": Windows asks those adapters' resolvers like any other, and they
 * can carry real ones — the only NIC of a Windows VM on Hyper-V ("Microsoft
 * Hyper-V Network Adapter"), the host's vEthernet on an EXTERNAL switch (the
 * machine's real address lives there; netWatcher.js counts it for the same
 * reason), a phone tethered over Bluetooth PAN. Excluding them left each of
 * those machines on its router's resolver for the whole session.
 */
const VIRTUAL_RE = 'Wintun|TAP|Loopback|VMware Virtual Ethernet|VirtualBox Host-Only';

/**
 * What every guarded Windows adapter's resolvers are for the session, on both
 * families: loopback. Never the tunnel peer.
 *
 * The peer (172.19.0.2 / fdfe:dcba:9876::2) is on-link only on the TUN adapter.
 * Whenever that adapter does not exist — every reconnect, where the guard is
 * held while the tunnel is rebuilt; a tunnel that crashed; an app that was
 * killed and not yet relaunched; retries given up on with the guard holding —
 * the only route to the peer is the physical default route, so every name the
 * machine looks up went to the router and the ISP in cleartext, and a network
 * that answers every port-53 packet resolved it for them. And Windows sends an
 * adapter's queries ON that adapter, to every adapter when the preferred one is
 * slow or answers REFUSED (smart multi-homed name resolution), so the peer on a
 * physical adapter was never a way into the tunnel to begin with.
 *
 * Loopback is the one address no packet leaves the host for, tunnel or not. The
 * TUN adapter keeps its own resolver (the backend sets it, not the guard) and is
 * the one that answers; normally nothing listens on 127.0.0.2:53, so a query
 * fanned out to a physical adapter fails at once instead of waiting — which
 * also serves a core with no port-53 hijack, where the peer answered nothing
 * and the guard had to hand the adapters public resolvers (see guardPeers).
 * During a reconnect names do not resolve at all: closed, as the hold intends.
 * 127.0.0.2 rather than .1 so it is never mistaken for a local DNS proxy the
 * user configured (those listen on .1); v6 has only ::1.
 */
const WIN_HOLD4 = '127.0.0.2';
const WIN_HOLD6 = '::1';

/** The marker an apply script prints for an adapter family it could not set. */
const APPLY_FAIL = 'IRNF_FAIL';

/** 127.0.0.0/8 or ::1 — a resolver there is this machine, never the network. */
function isLoopbackIp(ip) {
  const s = String(ip == null ? '' : ip).trim().toLowerCase();
  return /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(s) || s === '::1';
}

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

/**
 * An adapter alias the way `-InterfaceAlias` takes it. That parameter is a
 * WILDCARD — on the DnsClient and NetAdapter cmdlets and on New-NetFirewallRule
 * alike — so "Ethernet [USB]" is a character class that never matches the
 * adapter it names, and the override or the restore fails on it. Brackets and
 * the backtick (the wildcard escape itself) get a backtick; single quotes keep
 * it literal for the wildcard engine. A plain name comes out as psQuote made it.
 * `*` and `?` are left alone: Windows refuses them in a connection name, so one
 * in a record is an alias an older build read garbled (tunPlatform.psArgs) and
 * applied AS a wildcard — and only the same wildcard undoes that.
 */
function psAlias(name) {
  return psQuote(String(name == null ? '' : name).replace(/[`[\]]/g, '`$&'));
}

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
 *
 * `has4` / `has6` say whether the adapter has that IP family at all — a family
 * whose binding is off has no DNS client entry — and an adapter with neither (a
 * NIC bound to a Hyper-V external switch or a bridge: Up, but no IP interface)
 * is not listed: it asks no resolver, and setting one on it can only fail.
 */
function winSnapshotScript(tunAlias) {
  const skip = [...new Set([...OWN_ADAPTERS, ...(tunAlias ? [String(tunAlias)] : [])])];
  const where = [
    "$_.Status -eq 'Up'",
    ...skip.map(a => `$_.InterfaceAlias -ne ${psQuote(a)}`),
    `$_.InterfaceDescription -notmatch ${psQuote(VIRTUAL_RE)}`
  ].join(' -and ');
  const entry = (fam) => `@(Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily ${fam})`;
  const dnsOf = (d) => `@(${d} | Select-Object -ExpandProperty ServerAddresses)`;
  return [
    "$ErrorActionPreference = 'SilentlyContinue'",
    '$out = @()',
    `foreach ($a in @(Get-NetAdapter | Where-Object { ${where} })) {`,
    `$d4 = ${entry('IPv4')}`,
    `$d6 = ${entry('IPv6')}`,
    'if (-not $d4.Count -and -not $d6.Count) { continue }',
    "$k4 = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\' + $a.InterfaceGuid",
    "$k6 = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\Interfaces\\' + $a.InterfaceGuid",
    '$out += [pscustomobject]@{ alias = $a.InterfaceAlias;'
      + ` v4 = ${dnsOf('$d4')};`
      + ` v6 = ${dnsOf('$d6')};`
      + ' has4 = [bool]$d4.Count; has6 = [bool]$d6.Count;'
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
    // absent (an older record): assume the family is there, as before
    if (typeof a.has4 === 'boolean') rec.has4 = a.has4;
    if (typeof a.has6 === 'boolean') rec.has6 = a.has6;
    if (typeof a.dhcp4 === 'boolean') rec.dhcp4 = a.dhcp4;
    if (typeof a.dhcp6 === 'boolean') rec.dhcp6 = a.dhcp6;
    out.push(rec);
  }
  return out;
}

/**
 * `netsh interface ipv4|ipv6 show dnsservers` → Map<alias (lower-case), [addresses]>.
 *
 * The cheap half of a refresh: one native process, tens of milliseconds,
 * against the second or two of CPU every PowerShell start costs — which
 * v1.7.1 paid every 30 s of a session for an answer that was "unchanged"
 * nearly every time. Only the quoted alias of each block and the addresses in
 * it are read; the headings are localized and never matched. IPv6 scope ids
 * (`fe80::1%22`) are dropped so a peer compares equal to what was written.
 */
function parseNetshDnsServers(text) {
  const out = new Map();
  let cur = null;
  for (const raw of String(text == null ? '' : text).split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;
    const head = line.match(/"([^"]*)"/);
    if (head) {
      cur = head[1].trim().toLowerCase();
      if (cur && !out.has(cur)) out.set(cur, []);
      continue;
    }
    if (!cur) continue;
    for (const tok of line.split(/\s+/)) {
      const ip = tok.replace(/%.*$/, '');
      if (net.isIP(ip)) out.get(cur).push(ip.toLowerCase());
    }
  }
  return out;
}

/**
 * Every adapter's resolver becomes `addr4` / `addr6` (the guard passes the
 * loopback hold, WIN_HOLD4/6); the cache goes with it.
 *
 * Each adapter family is its own try: under `$ErrorActionPreference = 'Stop'`
 * the first line that failed used to end the script, so every adapter after it
 * kept its own resolvers and engage() threw — no guard and no drift watch for
 * the session, over one adapter that could not be set. A failure is printed as
 * `IRNF_FAIL <index> <v4|v6> <message>` for winApplyOutcome() to read, and a
 * family the snapshot says the adapter does not have is not attempted. The
 * cache is flushed only when a Set went through: a run that changed nothing
 * has nothing stale to flush, and a refresh that keeps retrying an adapter
 * that refuses would otherwise empty the machine's DNS cache every tick.
 */
function winApplyLines(adapters, addr4, addr6) {
  const lines = ["$ErrorActionPreference = 'Stop'", '$set = 0'];
  (adapters || []).forEach((a, i) => {
    const alias = psAlias(aliasOf(a));
    // Set-DnsClientServerAddress has no -AddressFamily: the family of each call
    // is the family of the addresses in it, and a call leaves the other alone.
    for (const [fam, addr, has] of [['v4', addr4, 'has4'], ['v6', addr6, 'has6']]) {
      if (!addr || (a && a[has] === false)) continue;
      lines.push(`try { Set-DnsClientServerAddress -InterfaceAlias ${alias} -ServerAddresses ${psQuote(addr)}; $set++ }`
        + ` catch { Write-Output ('${APPLY_FAIL} ${i} ${fam} ' + $_.Exception.Message) }`);
    }
  });
  lines.push('if ($set) { Clear-DnsClientCache }');
  return lines;
}

/**
 * What an apply script's output says: how many adapter families it tried, and
 * `[{ alias, family, message }]` for each one it could not set.
 */
function winApplyOutcome(out, adapters, addr4, addr6) {
  const list = adapters || [];
  let attempted = 0;
  for (const a of list) {
    if (addr4 && !(a && a.has4 === false)) attempted++;
    if (addr6 && !(a && a.has6 === false)) attempted++;
  }
  const failed = [];
  const re = new RegExp(`^${APPLY_FAIL} (\\d+) (v4|v6) ?(.*)$`);
  for (const line of String(out == null ? '' : out).split(/\r?\n/)) {
    const m = re.exec(line.trim());
    if (!m || !list[Number(m[1])]) continue;
    failed.push({ alias: aliasOf(list[Number(m[1])]), family: m[2], message: m[3].trim() });
  }
  return { attempted, failed };
}

/**
 * A Windows snapshot with our own hold taken out of it, so it is never recorded
 * as an adapter's original.
 *
 * 127.0.0.2 is stripped ALWAYS, state file or not: it is ours by construction,
 * and it can be on an adapter with no session of ours live — a USB NIC or a
 * tether unplugged before the disconnect is skipped by the restore while the
 * state file goes, and Windows keeps the static hold for when it comes back.
 * Recording it then pinned 127.0.0.2 on that adapter for good at the next
 * release. ::1 goes only from beside it: on its own it is a local DNS proxy's
 * address, the user's (so is 127.0.0.1).
 *
 * The tunnel's own resolvers are NOT stripped: they are never written to an
 * adapter here, and with managed DNS off they are the user's own public ones —
 * a static 1.1.1.1 must come back as a static 1.1.1.1. `legacyPeers` is for a
 * live state file written before the hold existed, which did write them.
 */
function winWithoutHold(list, legacyPeers) {
  const drop = new Set(addrList(legacyPeers).map(a => a.toLowerCase()));
  const keep = (arr, ours) => addrList(arr).filter(a => !drop.has(a.toLowerCase()) && !ours.includes(a.toLowerCase()));
  return (list || []).map(a => {
    const v4 = addrList(a && a.v4);
    const held = v4.length === 1 && v4[0] === WIN_HOLD4;
    return Object.assign({}, a, { v4: keep(v4, [WIN_HOLD4]), v6: keep(a && a.v6, held ? [WIN_HOLD6] : []) });
  });
}

/** The key an adapter family that refused the hold is remembered under. */
function _winRefusedKey(alias, family) { return `${String(alias == null ? '' : alias).toLowerCase()}|${family}`; }

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
    const alias = psAlias(aliasOf(a));
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
          `-InterfaceAlias ${psAlias(alias)} -Protocol ${proto} -RemoteAddress @(${psList(list)})`));
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
        `-InterfaceAlias ${psAlias(alias)} -Protocol UDP`
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

/**
 * The peers come back out of the state file — a file the user owns — for every
 * 30 s refresh, and this script runs as root. So an IP literal or no apply at
 * all, and quoted even then: `'1.1.1.1; id > /tmp/pwn'` was a root command.
 */
function macApplyLines(services, peer4, peer6) {
  const peers = [peer4, peer6].filter(Boolean).map(p => String(p).trim());
  if (!peers.length) throw new Error('Leak guard: no tunnel resolver to point the services at');
  if (peers.some(p => !net.isIP(p))) throw new Error('Leak guard: the tunnel resolver is not an IP address — nothing was applied');
  return [
    ...(services || []).map(s => `networksetup -setdnsservers ${sh(nameOf(s))} ${peers.map(sh).join(' ')} || FAIL=1`),
    ...MAC_FLUSH
  ];
}

/** `Empty` is how networksetup says "back to whatever DHCP hands you". */
function macRestoreLines(services) {
  return [
    ...(services || []).map(s => {
      // Only IP literals: the record is read back from a user-owned file.
      const dns = addrList(s && s.dns).filter(a => net.isIP(a));
      // The addresses are quoted too: they came off the machine, and this
      // script runs as root.
      return `networksetup -setdnsservers ${sh(nameOf(s))} ${dns.length ? dns.map(sh).join(' ') : 'Empty'} || FAIL=1`;
    }),
    ...MAC_FLUSH
  ];
}

/** macOS tunnel recovery belongs to the backend's persisted, verified session.
 * A generic utun/argv match cannot establish ownership (other VPNs use both).
 */
function macOrphanLines() { return []; }

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
function macOriginalSnapshot(fresh, peers, originals) {
  const peerSet = new Set(peers.filter(Boolean));
  const known = new Map((Array.isArray(originals) ? originals : [])
    .filter(s => s && typeof s.name === 'string' && Array.isArray(s.dns))
    .map(s => [s.name, s]));
  return withoutPeers(fresh.map(s => {
    const original = known.get(s.name);
    // Only replace the contaminated snapshot. A later externally changed DNS
    // list is authoritative; persisted prior-session originals win in mergeTargets.
    return original && s.dns.some(d => peerSet.has(d))
      ? { name: s.name, dns: addrList(original.dns) } : s;
  }), peers);
}

function withoutPeers(list, peers) {
  const drop = new Set((peers || []).filter(Boolean).map(p => String(p).toLowerCase()));
  const keep = (arr) => addrList(arr).filter(a => !drop.has(String(a).toLowerCase()));
  return (list || []).map(e => (e && e.dns !== undefined)
    ? Object.assign({}, e, { dns: keep(e.dns) })
    : Object.assign({}, e, { v4: keep(e.v4), v6: keep(e.v6) }));
}

/**
 * The live record, plus whatever has come up since.
 *
 * A re-engage over an override of ours must KEEP the originals it already holds:
 * re-reading an adapter we have already pointed at the tunnel would record our
 * own peer as its "original" (the phase-3 review's C1 — a machine left with no
 * DNS and no record to repair it with).
 *
 * But it must not stop there. An adapter that was down at the first engage, or
 * plugged in since, has never been overridden: it still hands every name to the
 * ISP, and the resolvers it reports right now genuinely ARE its originals. That
 * is not an edge case — plugging the ethernet cable in while connected over
 * Wi-Fi is both "a new adapter" and "a network change", so the two always
 * arrive together. So: keep what we hold, then add what is new.
 *
 * An adapter that has gone away keeps its record. The restore already skips one
 * that no longer exists, and if it comes back before the release it is ours.
 */
function mergeTargets(live, fresh, keyOf) {
  const out = (live || []).slice();
  const known = new Set(out.map(e => String(keyOf(e) == null ? '' : keyOf(e)).toLowerCase()));
  for (const e of fresh || []) {
    const k = String(keyOf(e) == null ? '' : keyOf(e)).toLowerCase();
    if (!k || known.has(k)) continue;
    known.add(k);
    out.push(e);
  }
  return out;
}

function countTargets(st) {
  if (!st) return 0;
  return ((st.win && st.win.adapters) || []).length + ((st.mac && st.mac.services) || []).length;
}

/**
 * THE ORDER A CALLER MUST USE. These primitives cannot make a reconnect
 * leak-free on their own — the sequence lives in the caller (main.js /
 * service.js), and getting it wrong is what the owner reported. It is:
 *
 *   reconnect (network change, settings apply, server switch)
 *     1. guard.holdForReconnect({ excludes: <resolved entry IPs of the server
 *        about to be dialled>, token })   ← NEVER release() here
 *     2. stop the tunnel and the core
 *     3. start the core, start the tunnel
 *     4. guard.engage({ ..., excludes: tun.excludeIps })  ← same call as a
 *        first connect; it keeps the originals and narrows the holes back
 *
 *   a connect that finds itself overtaken
 *     guard.release({ token })   ← with the receipt ITS OWN engage returned, so
 *     it cannot undo the guard of the connect that overtook it
 *
 *   disconnect / quit / exit
 *     guard.release()            ← no receipt: unconditional, that is the point
 *
 * The invariant, in one line: BETWEEN THE FIRST CONNECT AND A DELIBERATE
 * DISCONNECT THE STATE FILE MUST NEVER BE ABSENT. Every moment it is missing is
 * a moment the machine's own resolvers are back and, at the strict level, the
 * firewall is open — with no tunnel, because that is why we are reconnecting.
 *
 * The cost of holding is honest and must be shown, not hidden: while the tunnel
 * is down, name resolution fails and (at strict) so does everything else. If the
 * retries are given up on, the guard is STILL engaged, and the UI owes the user
 * a way out — the same shape as the kill-switch banner.
 */
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
    // Ordering is not ownership. Two overlapping connects both reach a release,
    // in order, and the loser's release still undoes the winner's live override
    // — the phase-3 review's carried "can drop the override on a live tunnel:
    // leak, not breakage". So every engage takes a RECEIPT, and a release that
    // presents an old one is refused. A release with no receipt at all is the
    // user's own intent (disconnect, quit, the exit hook) and always runs.
    this._token = null;
    this._tokenSeq = 0;
    // Set SYNCHRONOUSLY by engage, before anything can be queued behind it:
    // repairAtLaunch reads it to know whether a state file is a previous
    // session's or this one's.
    this._ownSession = false;
  }

  _nextToken() { return `irnf-guard-${++this._tokenSeq}`; }

  /** True when this caller may undo the override that is live now. */
  _owns(token) { return !token || !this._token || token === this._token; }

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
  async _privileged(name, text, options) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-lg-'));
    const file = path.join(dir, `${name}.sh`);
    try {
      fs.writeFileSync(file, text, { mode: 0o700 });
      return await this.runScriptPrivileged(file, options);
    } finally {
      try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
    }
  }

  /** UTF-8 stdout, or an adapter's own name comes back as "?????" (see tunPlatform.psArgs). */
  _powershell(script, options) {
    return this.run('powershell', platform.psArgs(script), options);
  }

  /** One log line per tunnel process the repair killed. */
  _logKills(out) {
    for (const line of String(out || '').split(/\r?\n/)) {
      const t = line.trim();
      if (t.startsWith('killed ')) this.onLog(t, 'warn');
    }
  }

  /**
   * Hold `adapters` on `addr4` / `addr6` (Windows). An adapter family that
   * could not be set is a warning that names it — the others ARE guarded and
   * the session must go on being watched; only when nothing at all could be
   * set is it the guard failing, and that throws like the spawn failing does.
   *
   * A family that refused is remembered (`_winFailed`, see _winRefusedKey):
   * its error is usually the adapter's and does not go away on its own, so the
   * cheap ticks of refresh() neither count it as drift nor try it again — no
   * PowerShell snapshot, warning and cache flush every 30 s for the session.
   * The full ticks (the first and every tenth) and the next engage try it
   * afresh, so a one-off refusal (a race with an unplug) is not for good; the
   * warning is said once per engage (`_winWarned`). `fatal: false` (refresh)
   * never throws: the guard is engaged, one family of one adapter is not.
   * Returns what refused.
   */
  async _winApply(adapters, addr4, addr6, options, { fatal = true } = {}) {
    const out = await this._powershell(winApplyScript(adapters, addr4, addr6), options);
    const { attempted, failed } = winApplyOutcome(out, adapters, addr4, addr6);
    if (!failed.length) return failed;
    this._winFailed = this._winFailed || new Set();
    this._winWarned = this._winWarned || new Set();
    for (const f of failed) this._winFailed.add(_winRefusedKey(f.alias, f.family));
    const what = (list) => list.map(f => `${f.alias} (${f.family === 'v6' ? 'IPv6' : 'IPv4'}): ${f.message}`).join('; ');
    if (fatal && failed.length >= attempted) throw new Error(`no adapter's DNS could be set — ${what(failed)}`);
    const fresh = failed.filter(f => !this._winWarned.has(_winRefusedKey(f.alias, f.family)));
    for (const f of fresh) this._winWarned.add(_winRefusedKey(f.alias, f.family));
    if (fresh.length) {
      this.onLog(`Leak guard: could not set the DNS of ${what(fresh)} — the other adapters are guarded;`
        + ' tried again every few minutes', 'warn');
    }
    return failed;
  }

  /** Did this adapter family refuse the hold since the last engage? */
  _winRefused(alias, family) {
    return !!(this._winFailed && this._winFailed.has(_winRefusedKey(alias, family)));
  }

  /**
   * Take every physical adapter's DNS for this session (macOS: the tunnel peer;
   * Windows: the loopback hold — `peer4`/`peer6` there only say which resolver
   * the TUN adapter answers on), and — at `level: 'strict'` — firewall
   * everything that is not the tunnel off those adapters. `level: 'off'` (and
   * Linux, which has no portable resolver to rewrite) does nothing. Throws when
   * the override itself fails — the caller keeps the tunnel, logs it and
   * carries on; one Windows adapter that cannot be set is only a warning.
   *
   * `excludes` are the addresses that must still reach the network directly:
   * the resolved server entry IPs and the resolver bypass addresses of the live
   * tunnel (`tun.excludeIps`). Without the entry IPs among them a strict block
   * would cut the tunnel it exists to protect.
   */
  engage({ level, peer4, peer6, tunAlias, backend, excludes, originalMacServices } = {}) {
    // Claimed before the call is even queued: repairAtLaunch is fired and not
    // awaited, so it can land after this one and must not read the file we are
    // about to write as "a previous session's".
    if (level && level !== 'off' && (this.platform === 'win32' || this.platform === 'darwin')) {
      this._ownSession = true;
    }
    const token = this._nextToken();
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
        level,
        // What the firewall holes were cut from, so a later holdForReconnect can
        // widen them without the caller having to remember the old server's IPs.
        excludes: addrList(excludes),
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
      // An override of ours that is already live — a server switch under TUN, or
      // a reconnect that deliberately never let go — keeps the originals it
      // recorded. They are the machine's own resolvers, they exist nowhere else,
      // and re-reading those adapters now would only find our own peer.
      const live = this.readState();
      const liveStrict = !!(live && live.strict);
      const liveUdp = !!(live && live.udpBlock);
      if (this.platform === 'win32') {
        // Our hold is never an original (see winWithoutHold), with or without
        // a live session; the peers only for a state file from before the hold.
        const legacy = (live && !live.hold4) ? [live.peer4, live.peer6] : [];
        const adapters = mergeTargets(
          (live && live.win && live.win.adapters) || [],
          winWithoutHold(parseWinSnapshot(await this._powershell(winSnapshotScript(tunAlias))), legacy),
          (a) => a.alias);
        count = adapters.length;
        state.win = { adapters };
        state.strict = strict;
        // What the adapters are held on (see WIN_HOLD4) — refresh() compares
        // against these, not the tunnel's resolver.
        state.hold4 = WIN_HOLD4;
        state.hold6 = WIN_HOLD6;
        // Every adapter there is has just been looked at (see refresh()), and
        // one that refused before gets another try.
        this._winSeen = new Set();
        this._winFailed = new Set();
        this._winWarned = new Set();
        apply = () => this._winApply(adapters, WIN_HOLD4, WIN_HOLD6);
        if (strict) {
          const ranges = rangeComplement([...(excludes || []), ...GUARD_EXCLUDES]);
          block = () => this._powershell(winStrictApplyScript({ adapters, ranges }));
        }
      } else {
        const services = mergeTargets(
          (live && live.mac && live.mac.services) || [],
          macOriginalSnapshot(parseMacSnapshot(await this.run('/bin/bash', ['-c', macSnapshotScript()])),
            [peer4, peer6], originalMacServices),
          (s) => s.name);
        count = services.length;
        state.mac = { services };
        state.strict = !!anchor;
        const applyScript = macApplyScript(services, peer4, peer6);   // a peer that is no IP stops here, before the state file
        apply = () => this._privileged('apply', applyScript);
        if (anchor) {
          // Carried over: if the FIRST engage of this session turned pf on, the
          // second one finds it already on and would record "not ours",
          // leaving pf enabled for other software after we are gone.
          state.pfEnabledByUs = !!(live && live.pfEnabledByUs);
          block = async () => {
            const out = await this._privileged('pf', macPfApplyScript(anchor));
            // Only OUR pfctl -E gets a pfctl -d at the end of the session.
            state.pfEnabledByUs = state.pfEnabledByUs
              || new RegExp(`${PF_MARK}=disabled`).test(String(out == null ? '' : out));
            this.writeState(state);
          };
        }
      }
      if (!count) {
        this.onLog('Leak guard: no physical adapter is up — nothing to point at the tunnel', 'warn');
        return { engaged: false, adapters: 0 };
      }

      // Rules a previous engage left that this level does NOT put back. Strict
      // blocks everything that is not the tunnel, so leaving them is not
      // harmless — it is the strict guard still running under a user who turned
      // it off, and a state file that has stopped mentioning them, so not even
      // the release would clear them. They go here, while the OLD file is still
      // on disk claiming them: a crash in between is still repairable.
      if (liveStrict && !block) {
        if (this.platform === 'win32') await this._powershell(winGroupRemoveScript());
        else await this._privileged('pf', macPfRemoveScript({ disable: !!(live && live.pfEnabledByUs) }));
        this.onLog('Leak guard: the previous session\'s firewall rules removed — this level does not use them', 'info');
      }
      // The proxy-mode UDP block is a different matter: it blocks UDP off the
      // physical adapters, which a tunnel does not care about either way. It is
      // still OUT THERE though, so the file must keep saying so or release()
      // would orphan it. A strict apply removes the whole group and takes it.
      state.udpBlock = liveUdp && !block && !liveStrict;

      // The originals go to disk BEFORE the first adapter changes: everything
      // after this line is undoable, by us or by the next launch.
      this.writeState(state);
      this._token = token;
      await apply();
      this.onLog(this.platform === 'win32'
        ? `Leak guard: DNS of ${count} adapters → ${WIN_HOLD4} ${WIN_HOLD6} (loopback: nothing asked there leaves the machine;`
          + ` the tunnel's resolver ${[peer4, peer6].filter(Boolean).join(' ')} answers)`
        : `Leak guard: DNS of ${count} adapters → ${[peer4, peer6].filter(Boolean).join(' ')}`, 'info');
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
      return { engaged: true, adapters: count, token };
    });
  }

  /**
   * Repair DNS drift without restarting the tunnel. The caller runs this only
   * while its tunnel is active. Newly connected adapters are journaled before
   * changing them; known adapters retain their pre-connect originals. An
   * unchanged snapshot causes no writes, cache flushes, or privileged prompts.
   * Firewall rules are intentionally not reloaded by this DNS-only operation.
   *
   * Windows pays for the snapshot in two halves. `netsh` lists every
   * interface's resolvers in tens of milliseconds; when each adapter this
   * session owns still names the hold, that is the whole tick. Only a
   * drift — or `full`, which the watch sets on its first tick and every Nth
   * after — takes the PowerShell snapshot that can also see an adapter that
   * came up since (netsh cannot tell ours from the machine's).
   */
  refresh({ token, full = false } = {}) {
    return this._queue(async () => {
      // Unlike user Disconnect, a background refresh must have an exact live
      // receipt. An old timer must never reclaim DNS after release/reconnect.
      if (!token || token !== this._token || !this._ownSession) return { refreshed: false, skipped: true };
      const st = this.readState();
      if (!st || !st.peer4 || !st.level || st.level === 'off') return { refreshed: false, skipped: true };
      const options = { timeout: 15000 };
      const peers = [st.peer4, st.peer6].filter(Boolean);
      const same = (a, b) => a.length === b.length && a.every(v => b.includes(v));
      let changed;
      if (this.platform === 'win32' && st.win) {
        // What the adapters are held on (WIN_HOLD4/6); a state file written
        // before the hold existed held them on the peers.
        const want4 = st.hold4 || st.peer4;
        const want6 = st.hold4 ? st.hold6 : st.peer6;
        this._winSeen = this._winSeen || new Set();   // reset by every engage
        if (!full && (st.win.adapters || []).length) {
          const owned = st.win.adapters.map(a => String(a.alias || '').toLowerCase()).filter(Boolean);
          const lists = (map, alias, peer) => (map.get(alias) || []).includes(String(peer).toLowerCase());
          const v4 = parseNetshDnsServers(await this.run('netsh', ['interface', 'ipv4', 'show', 'dnsservers'], options));
          const v6 = want6 ? parseNetshDnsServers(await this.run('netsh', ['interface', 'ipv6', 'show', 'dnsservers'], options)) : null;
          // An alias netsh no longer lists is an adapter that is gone, not a
          // drift; an empty listing is not trusted and falls through. Nor is a
          // family that refused the hold (see _winApply).
          const drifted = owned.some(alias => (v4.has(alias) && !this._winRefused(alias, 'v4') && !lists(v4, alias, want4))
            || (v6 && v6.has(alias) && !this._winRefused(alias, 'v6') && !lists(v6, alias, want6)));
          // An adapter nobody owns that lists a resolver of its own has come up
          // since the last snapshot — a Bluetooth tether, anything with
          // auto-reconnect off: netWatcher rebuilds for neither. The snapshot
          // decides whether it is ours to guard. Each alias is looked at once
          // per resolver list: netsh also lists an adapter that is down, with
          // the resolver it last had, and one judged (and skipped) then must be
          // looked at again when it comes up on a network that hands it another.
          // Coming up on the same one waits for the next full tick (≤ 5 min).
          const known = new Set([...owned, ...[...OWN_ADAPTERS, st.tunAlias].map(a => String(a || '').toLowerCase())]);
          const resolves = (ip) => !isLoopbackIp(ip) && !/^fec0:0:0:ffff::[123]$/i.test(ip);
          const resolversOf = (alias) => [...(v4.get(alias) || []), ...((v6 && v6.get(alias)) || [])].filter(resolves);
          const seenKey = (alias) => `${alias}|${resolversOf(alias).sort().join(',')}`;
          const newcomers = [...new Set([...v4.keys(), ...(v6 ? v6.keys() : [])])].filter(alias => !known.has(alias)
            && resolversOf(alias).length && !this._winSeen.has(seenKey(alias)));
          for (const alias of newcomers) this._winSeen.add(seenKey(alias));
          if (v4.size && !drifted && !newcomers.length) return { refreshed: false, adapters: 0, quick: true };
        }
        // A full tick tries again what refused (see _winApply).
        if (full) this._winFailed = new Set();
        const fresh = parseWinSnapshot(await this._powershell(winSnapshotScript(st.tunAlias), options));
        // A family the adapter does not have lists nothing, and that is not
        // drift; one that refused the hold waits for a full tick. Only the
        // families that drifted are set again.
        const wants = (a, fam) => a[fam === 'v4' ? 'has4' : 'has6'] !== false && !this._winRefused(a.alias, fam);
        const drift4 = (a) => wants(a, 'v4') && !same(a.v4, [want4]);
        const drift6 = (a) => !!want6 && wants(a, 'v6') && !same(a.v6, [want6]);
        changed = fresh.filter(a => drift4(a) || drift6(a))
          .map(a => Object.assign({}, a, { has4: drift4(a), has6: drift6(a) }));
        if (!changed.length) return { refreshed: false, adapters: 0 };
        st.win.adapters = mergeTargets(st.win.adapters, winWithoutHold(fresh, st.hold4 ? [] : peers), a => a.alias);
        this.writeState(st);
        const refused = await this._winApply(changed, want4, want6, options, { fatal: false });
        const held = changed.filter(a => ['v4', 'v6'].some(fam => a[fam === 'v4' ? 'has4' : 'has6']
          && !refused.some(f => f.alias === a.alias && f.family === fam)));
        if (!held.length) return { refreshed: false, adapters: 0, refused: refused.length };
        changed = held;
      } else if (this.platform === 'darwin' && st.mac) {
        const fresh = parseMacSnapshot(await this.run('/bin/bash', ['-c', macSnapshotScript()], options));
        changed = fresh.filter(s => !same(s.dns, peers));
        if (!changed.length) return { refreshed: false, adapters: 0 };
        const script = macApplyScript(changed, st.peer4, st.peer6);   // a tampered peer throws before any write
        st.mac.services = mergeTargets(st.mac.services, withoutPeers(fresh, peers), s => s.name);
        this.writeState(st);
        await this._privileged('refresh', script, options);
      } else return { refreshed: false, skipped: true };
      this.onLog(`Leak guard: repaired DNS drift on ${changed.length} adapters`, 'warn');
      return { refreshed: true, adapters: changed.length };
    });
  }

  // Keep DNS pointed at the tunnel throughout reconnect, and widen only the
  // strict firewall's server exceptions until the next engage narrows them.
  holdForReconnect({ excludes, token } = {}) {
    return this._queue(async () => {
      if (!this._owns(token)) return { held: false, adapters: 0, stale: true };
      const st = this.readState();
      if (!st) return { held: false, adapters: 0 };
      const merged = [...new Set([...addrList(st.excludes), ...addrList(excludes)])];
      st.excludes = merged;
      st.at = new Date().toISOString();
      this.writeState(st);
      const n = countTargets(st);
      if (!st.strict) return { held: true, adapters: n };   // the override is the whole guard here
      if (this.platform === 'win32') {
        await this._powershell(winStrictApplyScript({
          adapters: (st.win && st.win.adapters) || [],
          ranges: rangeComplement([...merged, ...GUARD_EXCLUDES])
        }));
      } else {
        const anchor = macPfAnchorText({ tunDevice: st.tunAlias, excludes: merged });
        // No anchor means the live session never had one (engage says so in its
        // log): there is nothing to widen, and nothing to take away either.
        if (anchor) await this._privileged('pf', macPfApplyScript(anchor));
      }
      return { held: true, adapters: n };
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
    if (this.platform === 'win32') this._ownSession = true;
    const token = this._nextToken();
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
      this._token = token;
      await this._powershell(winUdpBlockApplyScript({
        adapters, ranges: rangeComplement([...(excludes || []), ...GUARD_EXCLUDES])
      }));
      this.onLog(`Blocked outbound UDP to the internet (except DNS) on ${adapters.length} adapters`
        + ' — WebRTC cannot leak your address', 'info');
      return { engaged: true, adapters: adapters.length, token };
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
   *
   * `opts.token` is the receipt engage() handed out. Present it and the release
   * only happens if the override on disk is still the one that receipt names:
   * an overtaken connect cleaning up after itself must not put the adapters of
   * the connect that overtook it back on the ISP's resolver, on a tunnel that
   * is up and carrying traffic, with the UI saying connected. A release with NO
   * receipt is the user's own intent — disconnect, quit, the exit hook — and is
   * always unconditional.
   */
  release(opts = {}) {
    return this._queue(async () => {
      if (!this._owns(opts.token)) return { released: false, adapters: 0, stale: true };
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
      this._token = null;
      this._ownSession = false;
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
        this.runSync('powershell', platform.psArgs(winReleaseScript(adapters, { firewall })),
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
    // A state file belongs to a PREVIOUS session only while this one has
    // engaged nothing. The call is fired and not awaited (a macOS password
    // prompt must not hold up the window), so it can still be pending when the
    // user presses Connect — and "restoring" then would put the adapters of the
    // live tunnel back on the ISP's resolver and delete the only record of what
    // they were. The queue makes the two orderly; this makes them correct.
    if (this._ownSession) return { repaired: false, adapters: 0 };
    if (!this.readState()) return { repaired: false, adapters: 0 };
    this.onLog('A previous session did not shut down cleanly — putting the network back', 'warn');
    const r = await this.release({ repair: true, orphans: true });
    return { repaired: !!r.released, adapters: r.adapters };
  }
}

module.exports = {
  LeakGuard, STATE_FILE, FW_GROUP, GUARD_EXCLUDES, withoutPeers,
  psQuote, parseWinSnapshot, parseMacSnapshot, parseNetshDnsServers, rangeComplement,
  winSnapshotScript, winApplyScript, winRestoreScript, winOrphanKillScript, winRepairScript,
  winStrictApplyScript, winGroupRemoveScript, winUdpBlockApplyScript, winReleaseScript,
  macSnapshotScript, macApplyScript, macRestoreScript, macOrphanKillScript, macRepairScript,
  macPfAnchorText, macPfApplyScript, macPfRemoveScript, macReleaseScript
};
