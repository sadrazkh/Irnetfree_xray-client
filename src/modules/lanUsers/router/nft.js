'use strict';
/**
 * Users on the router, transparent mode: what the gateway's own nft table
 * (openwrtNet.buildNftRuleset, `table inet irnetfree`) gains for them. Pure —
 * the text is built here and tested byte for byte on the owner's Windows; the
 * kernel's word on it comes from the QEMU / CI jobs.
 *
 * Every rule is about packets the router FORWARDS from (or to) its LAN, by
 * the device's MAC — the one thing a device cannot change without the
 * network seeing a new device:
 *
 *   - `lu_blocked`: dropped, whatever else is true (the admin's block, a user
 *     whose config is "block", a user held for its cap outside login mode);
 *   - the pins: an address that belongs to a user's device (`lu_bound4` /
 *     `lu_bound6`) is that device's alone — a packet from it whose source MAC
 *     is not the device's (the pair is not in `lu_ipmac4` / `lu_ipmac6`) is
 *     dropped. sing-box picks a device's config by its source ADDRESS (a
 *     rule-set cannot match a MAC — router/index.js), and the down counters
 *     charge a user by it, so without them any device the rest of this table
 *     lets through by its own MAC could set its address to another's and ride
 *     that user's config and cap. Before the gate and the counters: a borrowed
 *     address gets nothing at all — not the gate's DNS, not a byte on anyone's
 *     counter. An address that is nobody's is in no set: nothing changes for it;
 *   - the gate, when unassigned devices are not simply let through: every MAC
 *     that is neither assigned by the admin (`lu_allowed`), signed in on the
 *     portal (`lu_authorized`, each element with its session's remaining time
 *     — the kernel lets it go by itself) nor sent around the tunnel
 *     (`bypass_macs`) jumps to `lu_gate`: in login mode DNS passes and the rest
 *     is refused (a refusal, not a silent drop, so a phone falls back to its
 *     plain-http captive check at once); in block mode everything is dropped;
 *   - in login mode their tcp/80 to anywhere but the router is redirected
 *     (DNAT) to the portal on the router's LAN address — the request every
 *     phone and laptop sends to find out whether it is behind a sign-in page;
 *   - a byte counter per device, both directions: up by source MAC (a map from
 *     MAC to a named counter: one lookup per packet, not one rule per device),
 *     down by the device's addresses (on the way out to the LAN there is no
 *     source MAC to match yet). `nft -j list table` reads them (parseCounters).
 *
 * Nothing here touches the input path: the router itself — its DHCP and DNS,
 * LuCI, this app's UI — stays reachable from every device, so an admin whose
 * own laptop falls into the gate can still put it right.
 */
const nodeNet = require('net');

const MAC_RE = /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/;
/** The forwarded-traffic chain: after the QUIC refusal (filter - 10), before fw4's own forward (filter). */
const FWD_PRIORITY = 'filter - 5';
/** The portal's DNAT: before fw4's own port forwards (dstnat). */
const DNAT_PRIORITY = 'dstnat - 5';
/** An element's timeout is at least a second (0 is "never" to nft) and at most a year. */
const MAX_TIMEOUT_S = 365 * 24 * 3600;

const macOf = (s) => {
  const m = String(s == null ? '' : s).trim().toLowerCase();
  return MAC_RE.test(m) ? m : null;
};

/** The list cleaned: valid MACs only, each once, order kept. */
function macList(list) {
  const out = [];
  for (const x of Array.isArray(list) ? list : []) {
    const m = macOf(x);
    if (m && !out.includes(m)) out.push(m);
  }
  return out;
}

/** `cu_aabbccddeeff` (up) / `cd_aabbccddeeff` (down): the device's two named counters. */
function counterName(mac, dir) {
  return (dir === 'down' ? 'cd_' : 'cu_') + String(mac).replace(/:/g, '');
}

/** `cu_…` / `cd_…` → { mac, dir }, or null for a counter that is not one of ours. */
function parseCounterName(name) {
  const m = /^c([ud])_([0-9a-f]{12})$/.exec(String(name || ''));
  if (!m) return null;
  return { mac: m[2].match(/../g).join(':'), dir: m[1] === 'u' ? 'up' : 'down' };
}

/** An address a counter can key on: v4, or a v6 that is not link-local (fe80::/10 is never forwarded). */
function countable(ip) {
  const s = String(ip == null ? '' : ip).trim().toLowerCase();
  const fam = nodeNet.isIP(s);
  if (fam === 4) return s;
  if (fam === 6 && !/^fe[89ab]/.test(s)) return s;
  return null;
}

const elements = (items) => (items.length ? ` elements = { ${items.join(', ')} };` : '');

/**
 * The description (router/plan.js decide → nft) cleaned to what may reach the
 * kernel: MACs by their one shape, an address claimed by two devices kept by
 * the first (a map key twice would fail the whole table — and with it the
 * gateway; a pinned address twice would be one address with two MACs, so
 * neither pin would hold), timeouts whole seconds in range, the portal a v4
 * address and a port. The pins come out as one { ip, mac } per address.
 */
function cleanDesc(desc) {
  const d = desc && typeof desc === 'object' ? desc : {};
  const unassigned = d.unassigned === 'block' || d.unassigned === 'allow' ? d.unassigned : 'login';
  const authorized = [];
  for (const a of Array.isArray(d.authorized) ? d.authorized : []) {
    const mac = macOf(a && a.mac);
    if (!mac || authorized.some(x => x.mac === mac)) continue;
    const t = Math.ceil(Number(a.timeoutS));
    if (!Number.isFinite(t) || t < 1) continue;   // a session already over is no element at all
    authorized.push({ mac, timeoutS: Math.min(t, MAX_TIMEOUT_S) });
  }
  const counters = [];
  const seenIp = new Set();
  for (const c of Array.isArray(d.counters) ? d.counters : []) {
    const mac = macOf(c && c.mac);
    if (!mac || counters.some(x => x.mac === mac)) continue;
    const ips = [];
    for (const raw of Array.isArray(c.ips) ? c.ips : []) {
      const ip = countable(raw);
      if (!ip || seenIp.has(ip)) continue;
      seenIp.add(ip);
      ips.push(ip);
    }
    counters.push({ mac, ips });
  }
  const ipmac = [];
  const pinned = new Set();
  for (const p of Array.isArray(d.ipmac) ? d.ipmac : []) {
    const mac = macOf(p && p.mac);
    if (!mac) continue;
    for (const raw of Array.isArray(p.ips) ? p.ips : []) {
      // the same addresses a counter keys on: a link-local v6 is never forwarded, so never borrowed through here
      const ip = countable(raw);
      if (!ip || pinned.has(ip)) continue;
      pinned.add(ip);
      ipmac.push({ ip, mac });
    }
  }
  let portal = null;
  const p = d.portal;
  if (unassigned === 'login' && p && /^\d+\.\d+\.\d+\.\d+$/.test(String(p.ip || '')) && nodeNet.isIP(p.ip) === 4 &&
      Number.isInteger(p.port) && p.port > 0 && p.port < 65536) portal = { ip: p.ip, port: p.port };
  return { unassigned, blocked: macList(d.blocked), allowed: macList(d.allowed), authorized, ipmac, counters, portal };
}

/**
 * The lines for the table body: `sets` go after `bypass_macs` (they must be
 * declared before a rule names them), `chains` after the gateway's own.
 * `ifName` is the LAN device, already reduced to a token by the caller.
 */
function lanUsersNftLines(desc, { ifName = 'br-lan' } = {}) {
  const d = cleanDesc(desc);
  const sets = [
    `  set lu_blocked { type ether_addr;${elements(d.blocked)} }`,
    `  set lu_allowed { type ether_addr;${elements(d.allowed)} }`,
    `  set lu_authorized { type ether_addr; flags timeout;${elements(d.authorized.map(a => `${a.mac} timeout ${a.timeoutS}s`))} }`
  ];
  // the pins, per family: the addresses, and each one with the one MAC that may send from it
  for (const [fam, v6] of [['4', false], ['6', true]]) {
    const pins = d.ipmac.filter(p => p.ip.includes(':') === v6);
    const type = v6 ? 'ipv6_addr' : 'ipv4_addr';
    sets.push(`  set lu_bound${fam} { type ${type};${elements(pins.map(p => p.ip))} }`);
    sets.push(`  set lu_ipmac${fam} { type ${type} . ether_addr;${elements(pins.map(p => `${p.ip} . ${p.mac}`))} }`);
  }
  // the named counters, then the maps that pick one per packet
  for (const c of d.counters) {
    sets.push(`  counter ${counterName(c.mac, 'up')} { packets 0 bytes 0 }`);
    sets.push(`  counter ${counterName(c.mac, 'down')} { packets 0 bytes 0 }`);
  }
  const v4 = [], v6 = [];
  for (const c of d.counters) {
    for (const ip of c.ips) (ip.includes(':') ? v6 : v4).push(`${ip} : "${counterName(c.mac, 'down')}"`);
  }
  sets.push(`  map lu_up { type ether_addr : counter;${elements(d.counters.map(c => `${c.mac} : "${counterName(c.mac, 'up')}"`))} }`);
  sets.push(`  map lu_dn4 { type ipv4_addr : counter;${elements(v4)} }`);
  sets.push(`  map lu_dn6 { type ipv6_addr : counter;${elements(v6)} }`);

  const lan = `iifname "${ifName}"`;
  const notLet = 'ether saddr != @lu_allowed ether saddr != @lu_authorized ether saddr != @bypass_macs';
  const gated = d.unassigned !== 'allow';
  const chains = [];
  // the gate first: a jump names a chain the table already declared
  if (gated) {
    chains.push('  chain lu_gate {');
    if (d.unassigned === 'login') {
      chains.push('    meta l4proto { tcp, udp } th dport 53 accept');
      chains.push('    counter reject');
    } else {
      chains.push('    counter drop');
    }
    chains.push('  }');
  }
  chains.push(
    '  chain lu_fwd {',
    `    type filter hook forward priority ${FWD_PRIORITY}; policy accept;`,
    `    ${lan} ether saddr @lu_blocked counter drop`,
    // a pinned address from any MAC but its own: nothing — before the gate (whose DNS would pass) and the counters
    `    ${lan} ip saddr @lu_bound4 ip saddr . ether saddr != @lu_ipmac4 counter drop`,
    `    ${lan} ip6 saddr @lu_bound6 ip6 saddr . ether saddr != @lu_ipmac6 counter drop`
  );
  if (gated) chains.push(`    ${lan} ${notLet} jump lu_gate`);
  chains.push(
    `    ${lan} counter name ether saddr map @lu_up`,
    `    oifname "${ifName}" counter name ip daddr map @lu_dn4`,
    `    oifname "${ifName}" counter name ip6 daddr map @lu_dn6`,
    '  }'
  );
  if (d.portal) {
    chains.push(
      '  chain lu_portal {',
      `    type nat hook prerouting priority ${DNAT_PRIORITY}; policy accept;`,
      `    ${lan} ${notLet} ether saddr != @lu_blocked ip daddr != ${d.portal.ip} tcp dport 80 counter dnat ip to ${d.portal.ip}:${d.portal.port}`,
      '  }'
    );
  }
  return { sets, chains };
}

/**
 * `nft -j list table inet irnetfree` → { [mac]: { up, down } } (bytes), from
 * the named counters this file declares. Anything else in the listing — the
 * other sets, the rules' own anonymous counters (nested inside a rule, never
 * top level) — is ignored; text that is not JSON is no counters at all.
 */
function parseCounters(text) {
  let j;
  try { j = typeof text === 'string' ? JSON.parse(text) : text; } catch { return {}; }
  const out = {};
  for (const item of (j && Array.isArray(j.nftables)) ? j.nftables : []) {
    const c = item && item.counter;
    if (!c || typeof c !== 'object') continue;
    const who = parseCounterName(c.name);
    if (!who) continue;
    const bytes = Number(c.bytes);
    const row = out[who.mac] || (out[who.mac] = { up: 0, down: 0 });
    row[who.dir] = Number.isFinite(bytes) && bytes > 0 ? bytes : 0;
  }
  return out;
}

module.exports = { lanUsersNftLines, cleanDesc, parseCounters, counterName, parseCounterName, countable, FWD_PRIORITY, DNAT_PRIORITY };
