'use strict';
/**
 * OpenWrt: the LAN behind the router as a list of devices, and the two kernel
 * tables the gateway backend writes around sing-box (see tunOpenwrt.js).
 *
 * How the exclusion works. sing-box's `auto_route` on Linux ends its rule set
 * with `not iif lo → lookup 2022`, so every packet the router FORWARDS from the
 * LAN is routed into the TUN — that is what makes the router the tunnel for
 * every device without touching any of them. A device the user wants direct
 * needs its packets to escape that rule: the nft chain below marks packets by
 * source MAC, and one `ip rule` with a LOWER preference than sing-box's (8999
 * against its 9000+) sends marked packets to the main table, i.e. out the WAN
 * with fw4's normal NAT. Nothing about sing-box's own tables is edited.
 *
 * Everything in this file is pure or takes its I/O as parameters, so the tests
 * run where the owner works (Windows) and the only thing left to prove on a
 * router is that the kernel accepts the text — which the QEMU job does.
 */
const fs = require('fs');

/** Packets from excluded devices carry this mark; matches nothing sing-box uses. */
const BYPASS_MARK = 0x1f1e;
/** Below sing-box's default `iproute2_rule_index` (9000): evaluated before its rules. */
const BYPASS_RULE_PREF = 8999;
/**
 * Before both: whatever the main table can route by a SPECIFIC route stays on
 * the main table. See mainFirstRuleArgs — this is the rule that keeps the
 * router reachable from its own LAN while the tunnel is up.
 */
const MAIN_FIRST_PREF = 8998;
const NFT_TABLE = 'inet irnetfree';

/**
 * Are we on an OpenWrt box? `/etc/openwrt_release` is the distro's own marker.
 * The env override is for the unit tests and for images built from another
 * root (a QEMU test image, a container) — never set it on a desktop.
 */
function isOpenwrt(env = process.env, exists = fs.existsSync) {
  if (env.IRNETFREE_PLATFORM === 'openwrt') return true;
  try { return !!exists('/etc/openwrt_release'); } catch { return false; }
}

const MAC_RE = /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/;

/** `aa:bb:cc:dd:ee:ff` lower-cased, or null. The only shape that ever reaches nft. */
function normalizeMac(s) {
  const m = String(s == null ? '' : s).trim().toLowerCase();
  return MAC_RE.test(m) ? m : null;
}

/** The user's list, cleaned: invalid entries dropped, duplicates dropped, order kept. */
function validMacs(list) {
  const out = [];
  const seen = new Set();
  for (const x of (Array.isArray(list) ? list : [])) {
    const m = normalizeMac(x);
    if (!m || seen.has(m)) continue;
    seen.add(m);
    out.push(m);
  }
  return out;
}

/**
 * dnsmasq's /tmp/dhcp.leases: `<expiry> <mac> <ip> <hostname|*> <client-id|*>`.
 * A line that does not start with a number and a MAC (the `duid` line, blanks)
 * is skipped.
 */
function parseDhcpLeases(text) {
  const out = [];
  for (const raw of String(text || '').split(/\r?\n/)) {
    const f = raw.trim().split(/\s+/);
    if (f.length < 3) continue;
    const mac = normalizeMac(f[1]);
    if (!mac || !/^\d+$/.test(f[0])) continue;
    out.push({ expires: parseInt(f[0], 10), mac, ip: f[2], name: (f[3] && f[3] !== '*') ? f[3] : '' });
  }
  return out;
}

/** Neighbour states that mean "this device answered recently". */
const ONLINE = new Set(['REACHABLE', 'STALE', 'DELAY', 'PROBE', 'PERMANENT']);

/** `ip neigh show dev <lan>`: `<ip> lladdr <mac> [router] <STATE>`; lines with no MAC skipped. */
function parseNeigh(text) {
  const out = [];
  for (const raw of String(text || '').split(/\r?\n/)) {
    const f = raw.trim().split(/\s+/);
    if (f.length < 2) continue;
    const i = f.indexOf('lladdr');
    const mac = i > 0 ? normalizeMac(f[i + 1]) : null;
    if (!mac) continue;
    out.push({ ip: f[0], mac, online: ONLINE.has(f[f.length - 1]) });
  }
  return out;
}

/**
 * One row per MAC. The lease names it and gives its address; the neighbour
 * table says whether it is here now (any online entry wins, so a device seen
 * on v4 and v6 is online once). A device only in the neighbour table (static
 * IP, no lease) is still a device. Online first, named before nameless, then
 * by name, then by MAC — the order the list is shown in: what you can
 * recognise at the top, the bare addresses at the bottom.
 */
function mergeDevices(leases, neigh) {
  const byMac = new Map();
  for (const l of leases || []) byMac.set(l.mac, { mac: l.mac, ip: l.ip || '', name: l.name || '', online: false });
  for (const n of neigh || []) {
    const cur = byMac.get(n.mac) || { mac: n.mac, ip: '', name: '', online: false };
    // prefer a v4 address for display; a v6-only neighbour keeps its v6
    if (!cur.ip || (cur.ip.includes(':') && !n.ip.includes(':'))) cur.ip = n.ip;
    cur.online = cur.online || n.online;
    byMac.set(n.mac, cur);
  }
  return [...byMac.values()].sort((a, b) =>
    (Number(b.online) - Number(a.online)) || (Number(!a.name) - Number(!b.name)) ||
    a.name.localeCompare(b.name) || a.mac.localeCompare(b.mac));
}

/**
 * The text for `nft -f`. The first two lines make the load an atomic replace:
 * `table` creates it if missing (so `delete` cannot fail), `delete` drops the
 * old contents, and the block recreates it — one transaction, no window with
 * no table. An empty exclusion list still declares the set, so a later
 * `add element` has something to add to.
 */
function buildNftRuleset({ lanIf = 'br-lan', macs = [], mark = BYPASS_MARK, blockQuic = false } = {}) {
  const list = validMacs(macs);
  const ifName = String(lanIf == null ? '' : lanIf).replace(/[^A-Za-z0-9_.-]/g, '') || 'br-lan';
  const hex = '0x' + Number(mark).toString(16);
  const elements = list.length ? ` elements = { ${list.join(', ')} };` : '';
  const lines = [
    `table ${NFT_TABLE}`,
    `delete table ${NFT_TABLE}`,
    `table ${NFT_TABLE} {`,
    `  set bypass_macs { type ether_addr;${elements} }`,
    '  chain pre {',
    '    type filter hook prerouting priority mangle; policy accept;',
    `    iifname "${ifName}" ether saddr @bypass_macs meta mark set ${hex} counter`,
    '  }'
  ];
  // QUIC (UDP 443) from the LAN is refused — not dropped — so a browser falls
  // back to TCP at once instead of waiting on a proxy that carries UDP badly
  // or not at all (the AC-1304 log: a stream of `udp:…:443 [socks-in -> proxy]`
  // for every Google and Apple host). Devices that go direct keep their QUIC.
  if (blockQuic) {
    lines.push(
      '  chain quic {',   // not `fwd`: that is nftables' own forward statement, a reserved word
      '    type filter hook forward priority filter - 10; policy accept;',
      `    iifname "${ifName}" meta mark != ${hex} udp dport 443 counter reject`,
      '  }'
    );
  }
  lines.push('}', '');
  return lines.join('\n');
}

/** argv for busybox `ip`, v4 then v6: the one rule that lets marked packets out through main. */
function bypassRuleArgs(verb, mark = BYPASS_MARK, pref = BYPASS_RULE_PREF) {
  if (verb !== 'add' && verb !== 'del') throw new Error('bypassRuleArgs: verb must be add or del');
  if (verb === 'del') return ['-4', '-6'].map(fam => [fam, 'rule', 'del', 'pref', String(pref)]);
  const hex = '0x' + Number(mark).toString(16);
  return ['-4', '-6'].map(fam => [fam, 'rule', 'add', 'pref', String(pref), 'fwmark', hex, 'lookup', 'main']);
}

/**
 * The rule that makes a router of this. sing-box's own rule set starts with
 * `lookup 2022 suppress_prefixlength 0`, which is harmless while its table
 * holds one default route — but with `route_exclude_address` set (the server
 * IPs, always) sing-tun fills the table with the SPLIT ranges around the
 * excluded addresses instead, none of them prefix 0, so nothing is suppressed
 * any more and every packet the ROUTER ITSELF sends to a LAN client — DNS and
 * DHCP replies, LuCI, this very UI — is routed into the tunnel and lost. The
 * house goes dark until the power is pulled (v1.13.2 on the owner's AC-1304).
 *
 * This rule sits before all of sing-box's: anything the main table can route
 * by a specific route (a LAN subnet, a VLAN, the WAN's own net, link-local)
 * stays on main; only a destination main would send to its DEFAULT route falls
 * through to sing-box's rules and the tunnel — which is exactly the split a
 * gateway wants, for forwarded and for its own traffic alike, v4 and v6.
 */
function mainFirstRuleArgs(verb, pref = MAIN_FIRST_PREF) {
  if (verb !== 'add' && verb !== 'del') throw new Error('mainFirstRuleArgs: verb must be add or del');
  // `del` is by preference alone: it then also removes the rule an older
  // version left behind, whatever selectors that one carried.
  if (verb === 'del') return ['-4', '-6'].map(fam => [fam, 'rule', 'del', 'pref', String(pref)]);
  // `not dport 53`: a DNS query is NEVER let out through a specific route. The
  // resolver a router's WAN DHCP hands out is very often the ISP's modem on the
  // WAN's own subnet — a connected route — and without this every query dnsmasq
  // forwards would go straight to it, off the tunnel: the DNS leak. Port 53 falls
  // through to sing-box's rules, enters the tunnel and is answered by the core.
  // sing-tun's own rule set carries the same `not dport 53` for the same reason.
  return ['-4', '-6'].map(fam => [fam, 'rule', 'add', 'not', 'dport', '53', 'pref', String(pref), 'lookup', 'main', 'suppress_prefixlength', '0']);
}

/** `ubus call network.interface.lan status` → { device, address, mask }; pure. */
function parseLanStatus(text) {
  const j = JSON.parse(text);
  const device = (j && typeof j.l3_device === 'string' && j.l3_device) ? j.l3_device : 'br-lan';
  const a = (j && Array.isArray(j['ipv4-address']) && j['ipv4-address'][0]) || {};
  const address = (typeof a.address === 'string' && /^\d+\.\d+\.\d+\.\d+$/.test(a.address)) ? a.address : null;
  const mask = Number.isInteger(a.mask) ? a.mask : null;
  return { device, address, mask };
}

/**
 * The LAN as netifd sees it: its L3 device (`br-lan` on every stock image, but
 * a renamed or VLAN'd LAN says otherwise) and its first IPv4 address. `run` is
 * tunPlatform.run's shape. Never throws: no ubus answer → the defaults.
 */
async function lanStatus(run) {
  try { return parseLanStatus(await run('ubus', ['call', 'network.interface.lan', 'status'])); }
  catch { return { device: 'br-lan', address: null, mask: null }; }
}

/** The LAN's L3 device only — what the device list and the nft rule need. */
async function lanInterface(run) { return (await lanStatus(run)).device; }

/**
 * An address a LAN client could have, for `ip route get`: the router's own
 * address with bit 1 of its last octet flipped (.1 → .3, .254 → .252). Never
 * the router itself; inside the subnet for any mask up to /29; null when the
 * LAN has no usable IPv4 — then there is nothing to probe.
 */
function lanProbeAddress(address, mask) {
  if (!address || !/^\d+\.\d+\.\d+\.\d+$/.test(address) || mask == null || mask > 29) return null;
  const o = address.split('.').map(Number);
  o[3] ^= 2;
  return o.join('.');
}

/**
 * The devices behind the router right now: DHCP leases (names, addresses) and
 * the neighbour table on the LAN device (who is actually here). Either source
 * may be missing — a fresh router has no lease file yet — and contributes
 * nothing then. Never throws.
 */
async function lanDevices({ readFile = (p) => fs.promises.readFile(p, 'utf8'), run, lanIf = 'br-lan' } = {}) {
  let leases = [];
  try { leases = parseDhcpLeases(await readFile('/tmp/dhcp.leases')); } catch { /* no leases yet */ }
  let neigh = [];
  try { if (run) neigh = parseNeigh(await run('ip', ['neigh', 'show', 'dev', lanIf])); } catch { /* no neighbour table */ }
  return mergeDevices(leases, neigh);
}

/** The cores this service runs, by executable name. */
const CORE_NAMES = new Set(['xray', 'xray-pattn', 'sing-box']);

/**
 * The cores a previous run of THIS service left behind: a service that died
 * without its exit hook (OOM killer, procd's SIGKILL after a slow stop) leaves
 * its children running — an xray holding the SOCKS port the next one needs, a
 * sing-box holding the IRNetFree device. Matched by /proc/<pid>/cmdline: the
 * executable is one of ours AND an argument lies inside this service's data
 * dir (xray's config and test configs) or is one of the gateway's own sing-box
 * configs (`<tmp>/irnf-sb-…`). Anything else — another package's xray, a
 * sing-box someone runs by hand — is never touched. Never throws.
 */
function ownOrphanCores({ dataDir, tmpDir = '/tmp', selfPid = process.pid, readdir = fs.readdirSync, readFile = fs.readFileSync } = {}) {
  const dir = String(dataDir || '').replace(/\/+$/, '');
  const inData = dir.startsWith('/') && dir.length > 1 ? dir + '/' : null;
  const sbPrefix = String(tmpDir || '/tmp').replace(/\/+$/, '') + '/irnf-sb-';
  let entries;
  try { entries = readdir('/proc'); } catch { return []; }
  const out = [];
  for (const e of entries) {
    if (!/^\d+$/.test(String(e)) || Number(e) === selfPid) continue;
    let argv;
    try { argv = String(readFile(`/proc/${e}/cmdline`)).split('\0').filter(Boolean); } catch { continue; }   // exited meanwhile
    if (!argv.length || !CORE_NAMES.has(argv[0].slice(argv[0].lastIndexOf('/') + 1))) continue;
    if (!argv.slice(1).some(a => (inData && a.startsWith(inData)) || a.startsWith(sbPrefix))) continue;
    out.push({ pid: Number(e), argv });
  }
  return out;
}

module.exports = {
  BYPASS_MARK, BYPASS_RULE_PREF, MAIN_FIRST_PREF, NFT_TABLE,
  isOpenwrt, normalizeMac, validMacs, parseDhcpLeases, parseNeigh, mergeDevices,
  buildNftRuleset, bypassRuleArgs, mainFirstRuleArgs, parseLanStatus, lanStatus, lanInterface, lanProbeAddress, lanDevices,
  ownOrphanCores
};
