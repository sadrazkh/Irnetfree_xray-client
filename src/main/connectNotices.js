'use strict';
/**
 * What a connect can see on THIS machine that explains a tunnel that "does not
 * work properly" here while the same configs work on another PC (v1.16.3,
 * windows-android-report §2): said — a line in the log and, where it can be
 * the cause, a toast in the window — and never acted on. Nothing here touches a
 * config, a route or a resolver, and each check returns nothing at all where
 * its condition does not hold.
 *
 * That is not "a healthy PC hears nothing": W1 is a fact about the STORE, so a
 * PC that works but holds a WireGuard identity twice says it too (the window
 * once per run, app.js connectToasts). W4 is a fact about this PC's networks,
 * and only the overlaps that can hit something the plan needs reach the window.
 *
 *   W1  a WireGuard identity stored twice. A WireGuard server keeps one
 *       endpoint per key and routes a tunnel address to one key: the same peer
 *       on two devices (the router kept the desktop's rules; backups copy
 *       records verbatim) — or the twin record tested while connected, from a
 *       throwaway core — moves the session away, and the live tunnel stalls.
 *       Its remedy depends on where the twin lives: one in a live subscription
 *       comes back on the next refresh, so it is the one to keep.
 *   W4  a local network inside a private range advanced routing sends to a
 *       tunnel. The tunnel's routes are 0/0 minus its exclusions, so an on-link
 *       /24 (the Wi-Fi, a VirtualBox host-only net) is more specific and wins:
 *       hosts there never reach the chain however the rule reads. That bites
 *       only where the target has hosts in that /24 — a broad /16 or /8 rule
 *       around a home LAN is almost always fine, so it is a log line; the
 *       window hears it when the LAN holds the target's WireGuard DNS, its
 *       tunnel address or a narrower AllowedIPs entry, or when the rule itself
 *       is as narrow as the LAN.
 *
 * Pure: the store's records, the rules and os.networkInterfaces() come in as
 * arguments (main.js asks, on Windows only). Private keys never leave here —
 * a notice names records, never what is in them.
 */

// Cloudflare WARP's server key: WARP gives every device the same tunnel
// address (172.16.0.2) under its own key, so a shared address means nothing there.
const WARP_PEER = 'bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=';

/** The ranges called private here — what a corporate network lives in. */
const PRIVATE_V4 = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10'];

/* ------------------------------ W1 ------------------------------ */

function isWg(s) {
  return !!s && (s.protocol === 'wireguard' || !!(s.outbound && s.outbound.protocol === 'wireguard'));
}

/** Key, server and tunnel addresses of a WireGuard record (addresses without their prefix). */
function wgFacts(s) {
  const st = (s.outbound && s.outbound.settings) || {};
  const peer = (Array.isArray(st.peers) && st.peers[0]) || {};
  const text = (v) => String(v == null ? '' : v).trim();
  const list = Array.isArray(st.address) ? st.address : (st.address ? [st.address] : []);
  return {
    key: text(st.secretKey),
    server: text(peer.publicKey),
    addrs: list.map(a => text(a).replace(/\/\d+$/, '').toLowerCase()).filter(Boolean)
  };
}

/** The subscription a record came with, while that subscription is still stored (its refresh can bring the record back). */
function liveSubOf(s, subs) {
  if (!s || !s.subId) return null;
  return (Array.isArray(subs) ? subs : []).find(x => x && x.id === s.subId) || null;
}

/**
 * The Servers page's group a record sits in, so twin records with one name can
 * be told apart: its subscription's name, or — for the window to say in the
 * user's language — { t: <i18n key> } for "added by hand" or "deleted
 * subscription" (the page's own two labels).
 */
function groupOf(s, subs) {
  if (!s || !s.subId) return { t: 'srv.manual' };
  const sub = liveSubOf(s, subs);
  return sub && sub.name ? String(sub.name) : { t: 'srv.subGone' };
}

/**
 * Every WireGuard record the plan uses (`usedIds`, its server ids) whose
 * identity another stored record for the SAME server also holds:
 *   { id: 'wgSharedKey', name, other, group, otherInSub, byHand }
 *                                                    the same private key;
 *   { id: 'wgSharedAddress', name, other, group, otherInSub, byHand, address }
 *                                                    the same tunnel address under another key.
 * `other` is the other record's name and `group` its group (groupOf) — two
 * records can have one name. `otherInSub`: the other record belongs to a
 * subscription that is still stored; `byHand`: the one the plan uses (`name`)
 * was added by hand. Both together are the owner's case, and their own ids —
 * 'wgSharedKeySub', 'wgSharedAddressSub' — because "delete the copy you do not
 * use" does not last there: a record deleted from a subscription has no
 * tombstone and the next refresh (hourly by default) brings it back, so the
 * remedy is to keep the subscription's record, rebuild on it and delete the
 * hand-added one. Another server is another session (no clash); WARP's shared
 * address is by design. One entry per pair.
 */
function sharedWgIdentities(usedIds, servers, subs = []) {
  const iterable = usedIds && typeof usedIds !== 'string' && typeof usedIds[Symbol.iterator] === 'function';
  const used = new Set(iterable ? usedIds : []);
  const wg = (Array.isArray(servers) ? servers : []).filter(s => isWg(s) && s.id);
  const out = [];
  const said = new Set();
  for (const a of wg) {
    if (!used.has(a.id)) continue;
    const fa = wgFacts(a);
    if (!fa.server) continue;
    for (const b of wg) {
      if (b.id === a.id) continue;
      const pair = [a.id, b.id].sort().join('\n');
      if (said.has(pair)) continue;
      const fb = wgFacts(b);
      if (fb.server !== fa.server) continue;
      const facts = { name: a.name || a.id, other: b.name || b.id, group: groupOf(b, subs), otherInSub: !!liveSubOf(b, subs), byHand: !a.subId };
      // the twin comes back with its subscription's next refresh: keep it, delete the hand-added one
      const comesBack = facts.otherInSub && facts.byHand;
      if (fa.key && fa.key === fb.key) {
        said.add(pair);
        out.push(comesBack ? Object.assign({ id: 'wgSharedKeySub' }, facts) : Object.assign({ id: 'wgSharedKey' }, facts));
        continue;
      }
      if (fa.server === WARP_PEER || !fa.key || !fb.key) continue;
      const address = fa.addrs.find(x => fb.addrs.includes(x));
      if (address) {
        said.add(pair);
        out.push(Object.assign(comesBack ? { id: 'wgSharedAddressSub' } : { id: 'wgSharedAddress' }, facts, { address }));
      }
    }
  }
  return out;
}

/* ------------------------------ W4 ------------------------------ */

function v4(ip) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(ip == null ? '' : ip).trim());
  if (!m) return null;
  const p = m.slice(1).map(Number);
  if (p.some(n => n > 255)) return null;
  return ((p[0] * 16777216) + (p[1] << 16) + (p[2] << 8) + p[3]) >>> 0;
}
const maskOf = (bits) => (bits === 0 ? 0 : (0xFFFFFFFF << (32 - bits)) >>> 0);
/** '192.168.1.5/24' or a bare address (/32) → { base, bits }; null for anything else. */
function parseCidr(s) {
  const [ip, b, extra] = String(s == null ? '' : s).trim().split('/');
  if (extra !== undefined) return null;
  const n = v4(ip);
  if (n == null) return null;
  const bits = b === undefined ? 32 : (/^\d{1,2}$/.test(b) ? Number(b) : NaN);
  if (!(bits >= 0 && bits <= 32)) return null;
  return { base: (n & maskOf(bits)) >>> 0, bits };
}
function cidrText(c) {
  const n = c.base;
  return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.') + '/' + c.bits;
}
function contains(outer, inner) {
  return outer.bits <= inner.bits && ((inner.base & maskOf(outer.bits)) >>> 0) === outer.base;
}
const PRIVATE = PRIVATE_V4.map(parseCidr);

/** A netmask such as 255.255.255.0 → its prefix length; null when it is not one. */
function maskBits(mask) {
  const n = v4(mask);
  if (n == null) return null;
  let bits = 0;
  while (bits < 32 && (n & (0x80000000 >>> bits))) bits++;
  return maskOf(bits) === n ? bits : null;
}

/**
 * This PC's own connected IPv4 networks, from os.networkInterfaces():
 * [{ cidr, iface }]. Not loopback, not APIPA (169.254/16), not a /31 or /32
 * (a point-to-point address has no on-link subnet to shadow anything), and
 * not what `ignore(name, address)` claims — our own tunnel adapters.
 */
function localSubnets(ifaces, ignore = () => false) {
  const out = [];
  const seen = new Set();
  for (const [name, list] of Object.entries(ifaces && typeof ifaces === 'object' ? ifaces : {})) {
    for (const ni of Array.isArray(list) ? list : []) {
      if (!ni || ni.internal) continue;
      if (ni.family !== 'IPv4' && ni.family !== 4) continue;
      const address = String(ni.address || '');
      if (/^169\.254\./.test(address) || ignore(name, address)) continue;
      let c = ni.cidr ? parseCidr(ni.cidr) : null;
      if (!c && v4(address) != null) {
        const bits = maskBits(ni.netmask);
        if (bits != null) c = parseCidr(address + '/' + bits);
      }
      if (!c || c.bits < 8 || c.bits >= 31) continue;
      const cidr = cidrText(c);
      if (seen.has(cidr)) continue;
      seen.add(cidr);
      out.push({ cidr, iface: name });
    }
  }
  return out;
}

const SEPARATORS = /[|,]/;   // configBuilder's splitList
function ruleTokens(v) {
  const list = Array.isArray(v) ? v : String(v == null ? '' : v).split(SEPARATORS);
  return list.map(x => String(x).trim()).filter(Boolean);
}

/** The private IPv4 ranges of the advanced `ip` rules, in rule order: [{ range, label, target }]. */
function ruleRanges(rules) {
  const out = [];
  for (const r of Array.isArray(rules) ? rules : []) {
    if (!r || r.type !== 'ip') continue;
    for (const tok of ruleTokens(r.value)) {
      if (/^geoip:private$/i.test(tok)) {
        for (const c of PRIVATE) out.push({ range: c, label: cidrText(c) + ' (geoip:private)', target: r.target });
        continue;
      }
      const c = parseCidr(tok);
      if (c && PRIVATE.some(p => contains(p, c))) out.push({ range: c, label: cidrText(c), target: r.target });
    }
  }
  return out;
}

/**
 * What a routing target needs through its tunnel, as far as its WireGuard
 * records say (a chain: every WireGuard hop): [{ address, key }] — the DNS
 * servers, the tunnel address (without its prefix) and the AllowedIPs entries
 * other than a full tunnel, IPv4 only, named by their wg-quick keys (DNS,
 * Address, AllowedIPs), which read the same in every language. Never a key.
 * Nothing for `direct`, `block`, a proxy, or a target that is gone.
 */
function targetNeeds(target, plan) {
  if (!target || target === 'direct' || target === 'block') return [];
  const p = plan || {};
  let list;
  if (target === 'chain') list = p.chain;
  else if (String(target).indexOf('chain:') === 0) list = (p.chainsById || {})[String(target).slice('chain:'.length)];
  else list = [(p.serversById || {})[target]];
  const out = [];
  const seen = new Set();
  const add = (address, key) => {
    if (seen.has(key + ' ' + address)) return;
    seen.add(key + ' ' + address);
    out.push({ address, key });
  };
  const host = (v) => {
    const c = parseCidr(String(v == null ? '' : v).trim().replace(/\/\d+$/, ''));
    return c ? cidrText(c).replace(/\/32$/, '') : null;
  };
  for (const s of Array.isArray(list) ? list : []) {
    if (!isWg(s)) continue;
    for (const d of Array.isArray(s.dns) ? s.dns : []) { const h = host(d); if (h) add(h, 'DNS'); }
    const st = (s.outbound && s.outbound.settings) || {};
    for (const a of Array.isArray(st.address) ? st.address : (st.address ? [st.address] : [])) { const h = host(a); if (h) add(h, 'Address'); }
    const peer = (Array.isArray(st.peers) && st.peers[0]) || {};
    for (const a of Array.isArray(peer.allowedIPs) ? peer.allowedIPs : []) {
      const c = parseCidr(a);
      if (c && c.bits > 0) add(cidrText(c), 'AllowedIPs');
    }
  }
  return out;
}

/**
 * The first of `needs` (targetNeeds) that lies in the LAN `net` and so never
 * reaches a tunnel `range` wider than that LAN: a DNS server or the tunnel
 * address inside it, or an AllowedIPs entry narrower than the rule that
 * overlaps it (one as wide as the rule says nothing the rule did not).
 */
function needInLan(net, range, needs) {
  for (const n of Array.isArray(needs) ? needs : []) {
    const c = n && parseCidr(n.address);
    if (!c) continue;
    const hit = n.key === 'AllowedIPs'
      ? c.bits > range.bits && (contains(net, c) || contains(c, net))
      : c.bits === 32 && contains(net, c);
    if (hit) return { address: n.address, key: n.key };
  }
  return null;
}

/**
 * Each local network (localSubnets) that a private range of the advanced
 * rules, sent to a tunnel, overlaps — one finding per network, unless an
 * earlier rule already keeps that network `direct` or blocks it (the user
 * meant it to stay local). `nameOf(target)` names a server or a chain; null
 * means the target is gone and configBuilder drops the rule. `needsOf(target)`
 * is what that target needs through its tunnel (targetNeeds). Strongest first,
 * the first rule among equals:
 *   { id: 'rangeInLan', lan, iface, range, target }   the range is the LAN or
 *                                                     inside it — the user asked for hosts on the LAN
 *   { id: 'lanInRange', lan, iface, range, target, address, key }
 *                                                     the LAN is inside the range and holds
 *                                                     `address`, the target's `key` (DNS, Address, AllowedIPs)
 *   { id: 'lanInBroadRange', lan, iface, range, target }  the LAN is inside the range and nothing
 *                                                     the target is known to need is in it: a log line only
 */
function lanOverlaps(subnets, rules, nameOf = () => null, needsOf = () => []) {
  const ranges = ruleRanges(rules);
  const out = [];
  for (const lan of Array.isArray(subnets) ? subnets : []) {
    const net = lan && parseCidr(lan.cidr);
    if (!net) continue;
    let needed = null, broad = null, narrow = null;
    for (const e of ranges) {
      const local = !e.target || e.target === 'direct' || e.target === 'block';
      if (local) {
        if (contains(e.range, net)) break;
        continue;
      }
      const within = contains(net, e.range);
      if (!within && !contains(e.range, net)) continue;
      const target = nameOf(e.target);
      if (!target) continue;
      const found = { lan: cidrText(net), iface: lan.iface, range: e.label, target };
      if (within) { narrow = Object.assign({ id: 'rangeInLan' }, found); break; }
      if (!needed) {
        const need = needInLan(net, e.range, needsOf(e.target));
        if (need) needed = Object.assign({ id: 'lanInRange' }, found, need);
      }
      if (!broad) broad = Object.assign({ id: 'lanInBroadRange' }, found);
    }
    const best = narrow || needed || broad;
    if (best) out.push(best);
  }
  return out;
}

/** Notices that stay in the log: never a toast. */
const LOG_ONLY = new Set(['lanInBroadRange']);
/** Does the window hear this notice (a toast), or only the log? */
function forWindow(n) { return !!n && !LOG_ONLY.has(n.id); }
/** The log level of a notice's line. */
function noticeLevel(n) { return forWindow(n) ? 'warn' : 'info'; }

/**
 * A routing target by the name the user gave it: a server, a named chain
 * (`chain:<id>`), the legacy chain ('chain', its hops). null for `direct`,
 * `block`, nothing, or a target that no longer exists.
 */
function routeTargetName(target, plan, chains) {
  if (!target || target === 'direct' || target === 'block') return null;
  const p = plan || {};
  if (target === 'chain') {
    const names = (p.chain || []).map(s => s && s.name).filter(Boolean);
    return names.length ? names.join(' → ') : null;
  }
  if (String(target).indexOf('chain:') === 0) {
    const id = String(target).slice('chain:'.length);
    const c = (Array.isArray(chains) ? chains : []).find(x => x && x.id === id);
    return c ? (c.name || c.id) : null;
  }
  const s = (p.serversById || {})[target];
  return s ? (s.name || s.id) : null;
}

/* ------------------------------ the log line ------------------------------ */

/** The window's two group labels (i18n.js 'srv.manual' / 'srv.subGone'), for the English log line. */
const GROUP_EN = { 'srv.manual': 'Added by hand', 'srv.subGone': 'Deleted subscription' };
const groupText = (g) => (g && typeof g === 'object' ? (GROUP_EN[g.t] || '') : String(g == null ? '' : g));

/** The English log line of a notice (the window says it from i18n.js, in the user's language). */
function noticeLine(n) {
  if (!n) return '';
  const lan = (x) => `${x.lan}${x.iface ? ` (${x.iface})` : ''}`;
  const move = 'Move that LAN, VM or host-only network to another subnet';
  const sharedKey = () => `WireGuard ${n.name}: the same private key is also stored in another record, “${n.other}” in the group “${groupText(n.group)}” — a WireGuard server accepts one device per key, so when both are used (on two devices, or that record tested while you are connected) one of them stalls.`;
  const sharedAddress = () => `WireGuard ${n.name}: its tunnel address ${n.address} is also stored in another record, “${n.other}” in the group “${groupText(n.group)}”, with another key for the same server — the server gives an address to one key only (unless it gives every device the same one), so one of the two may carry nothing.`;
  const comesBack = 'A record in a subscription comes back on the subscription’s next update, so deleting that one does not last:';
  switch (n.id) {
    case 'wgSharedKey':
      return `${sharedKey()} Delete the copy you do not use, do not test it while connected, and get one peer per device from the server’s admin`;
    case 'wgSharedKeySub':
      return `${sharedKey()} ${comesBack} keep it, use it in place of this one (rebuild the chain on it), delete the copy added by hand and do not test it while connected — or remove the subscription if it should not be used`;
    case 'wgSharedAddress':
      return `${sharedAddress()} Keep the record the server’s admin made for this device, delete the other, and do not test it while connected`;
    case 'wgSharedAddressSub':
      return `${sharedAddress()} ${comesBack} if it is the one the server’s admin made for this device, keep it, use it in place of this one (rebuild the chain on it) and delete the copy added by hand; if not, remove the subscription. Do not test it while connected`;
    case 'lanInRange':
      return `Your local network ${lan(n)} overlaps ${n.address} — the ${n.key} of ${n.target}’s WireGuard — inside ${n.range} that advanced routing sends to ${n.target}: addresses in ${n.lan} stay on the LAN and never reach the tunnel. ${move}`;
    case 'rangeInLan':
      return `${n.range} that advanced routing sends to ${n.target} is part of your local network ${lan(n)} — hosts in ${n.range} stay on the LAN, not the tunnel. ${move}`;
    case 'lanInBroadRange':
      return `Your local network ${lan(n)} lies inside ${n.range} that advanced routing sends to ${n.target}; none of the addresses ${n.target} is known to need (a WireGuard DNS, Address or narrower AllowedIPs) is in it, so this matters only if a host you reach through ${n.target} has an address in ${n.lan}`;
    default:
      return '';
  }
}

module.exports = {
  sharedWgIdentities, localSubnets, lanOverlaps, targetNeeds, routeTargetName,
  noticeLine, noticeLevel, forWindow, LOG_ONLY, PRIVATE_V4, WARP_PEER
};
