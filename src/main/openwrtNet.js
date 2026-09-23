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
function buildNftRuleset({ lanIf = 'br-lan', macs = [], mark = BYPASS_MARK } = {}) {
  const list = validMacs(macs);
  const ifName = String(lanIf == null ? '' : lanIf).replace(/[^A-Za-z0-9_.-]/g, '') || 'br-lan';
  const hex = '0x' + Number(mark).toString(16);
  const elements = list.length ? ` elements = { ${list.join(', ')} };` : '';
  return [
    `table ${NFT_TABLE}`,
    `delete table ${NFT_TABLE}`,
    `table ${NFT_TABLE} {`,
    `  set bypass_macs { type ether_addr;${elements} }`,
    '  chain pre {',
    '    type filter hook prerouting priority mangle; policy accept;',
    `    iifname "${ifName}" ether saddr @bypass_macs meta mark set ${hex} counter`,
    '  }',
    '}',
    ''
  ].join('\n');
}

/** argv for busybox `ip`, v4 then v6: the one rule that lets marked packets out through main. */
function bypassRuleArgs(verb, mark = BYPASS_MARK, pref = BYPASS_RULE_PREF) {
  if (verb !== 'add' && verb !== 'del') throw new Error('bypassRuleArgs: verb must be add or del');
  const hex = '0x' + Number(mark).toString(16);
  return ['-4', '-6'].map(fam => [fam, 'rule', verb, 'pref', String(pref), 'fwmark', hex, 'lookup', 'main']);
}

/**
 * The LAN's L3 device, as netifd names it (`br-lan` on every stock image, but
 * a renamed or VLAN'd LAN says otherwise). `run` is tunPlatform.run's shape.
 * Never throws: a router with no ubus answer still gets the default.
 */
async function lanInterface(run) {
  try {
    const out = await run('ubus', ['call', 'network.interface.lan', 'status']);
    const j = JSON.parse(out);
    if (j && typeof j.l3_device === 'string' && j.l3_device) return j.l3_device;
  } catch { /* fall through */ }
  return 'br-lan';
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

module.exports = {
  BYPASS_MARK, BYPASS_RULE_PREF, NFT_TABLE,
  isOpenwrt, normalizeMac, validMacs, parseDhcpLeases, parseNeigh, mergeDevices,
  buildNftRuleset, bypassRuleArgs, lanInterface, lanDevices
};
