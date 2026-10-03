'use strict';
/**
 * What a connect can see on THIS machine that explains a tunnel that "does not
 * work properly" here while the same configs work on another PC (v1.16.3,
 * windows-android-report §2): said — a warn line in the log and a toast in the
 * window — and never acted on. Nothing here touches a config, a route or a
 * resolver, and each check returns nothing at all where its condition does not
 * hold, so a healthy machine hears nothing new.
 *
 *   W1  a WireGuard identity stored twice. A WireGuard server keeps one
 *       endpoint per key and routes a tunnel address to one key: the same peer
 *       on two devices (the router kept the desktop's rules; backups copy
 *       records verbatim) — or the twin record tested while connected, from a
 *       throwaway core — moves the session away, and the live tunnel stalls.
 *   W4  a local network inside a private range advanced routing sends to a
 *       tunnel. The tunnel's routes are 0/0 minus its exclusions, so an on-link
 *       /24 (the Wi-Fi, a VirtualBox host-only net) is more specific and wins:
 *       hosts there never reach the chain however the rule reads.
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

/**
 * Every WireGuard record the plan uses (`usedIds`, its server ids) whose
 * identity another stored record for the SAME server also holds:
 *   { id: 'wgSharedKey', name, other }               the same private key;
 *   { id: 'wgSharedAddress', name, other, address }  the same tunnel address
 *                                                    under another key.
 * Another server is another session (no clash); WARP's shared address is by
 * design. One entry per pair.
 */
function sharedWgIdentities(usedIds, servers) {
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
      const name = a.name || a.id, other = b.name || b.id;
      if (fa.key && fa.key === fb.key) {
        said.add(pair);
        out.push({ id: 'wgSharedKey', name, other });
        continue;
      }
      if (fa.server === WARP_PEER || !fa.key || !fb.key) continue;
      const address = fa.addrs.find(x => fb.addrs.includes(x));
      if (address) {
        said.add(pair);
        out.push({ id: 'wgSharedAddress', name, other, address });
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
 * Each local network (localSubnets) that a private range of the advanced
 * rules, sent to a tunnel, overlaps — the first such rule per network, in rule
 * order, unless an earlier rule already keeps that network `direct` or blocks
 * it (the user meant it to stay local). `nameOf(target)` names a server or a
 * chain; null means the target is gone and configBuilder drops the rule.
 *   { id: 'lanInRange', lan, iface, range, target }  the LAN inside the range
 *   { id: 'rangeInLan', lan, iface, range, target }  the range inside the LAN
 */
function lanOverlaps(subnets, rules, nameOf = () => null) {
  const ranges = ruleRanges(rules);
  const out = [];
  for (const lan of Array.isArray(subnets) ? subnets : []) {
    const net = lan && parseCidr(lan.cidr);
    if (!net) continue;
    for (const e of ranges) {
      const local = !e.target || e.target === 'direct' || e.target === 'block';
      if (local) {
        if (contains(e.range, net)) break;
        continue;
      }
      const inside = contains(e.range, net);
      if (!inside && !contains(net, e.range)) continue;
      const target = nameOf(e.target);
      if (!target) continue;
      out.push({ id: inside ? 'lanInRange' : 'rangeInLan', lan: cidrText(net), iface: lan.iface, range: e.label, target });
      break;
    }
  }
  return out;
}

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

/** The English log line of a notice (the window says it from i18n.js, in the user's language). */
function noticeLine(n) {
  if (!n) return '';
  const lan = (x) => `${x.lan}${x.iface ? ` (${x.iface})` : ''}`;
  switch (n.id) {
    case 'wgSharedKey':
      return `WireGuard ${n.name}: this identity is also stored as ${n.other} — a WireGuard server accepts one device per key; used on two devices (or tested while connected) one of them stalls. Ask the server’s admin for one peer per device, and do not copy WireGuard records between devices`;
    case 'wgSharedAddress':
      return `WireGuard ${n.name}: its tunnel address ${n.address} is also stored as ${n.other} with another key for the same server — a WireGuard server routes an address to one key only (unless the provider gives every device the same address), so one of the two may carry nothing`;
    case 'lanInRange':
      return `Your local network ${lan(n)} lies inside ${n.range} that advanced routing sends to ${n.target} — hosts in ${n.lan} stay on the LAN, not the tunnel`;
    case 'rangeInLan':
      return `${n.range} that advanced routing sends to ${n.target} lies inside your local network ${lan(n)} — hosts in ${n.range} stay on the LAN, not the tunnel`;
    default:
      return '';
  }
}

module.exports = { sharedWgIdentities, localSubnets, lanOverlaps, routeTargetName, noticeLine, PRIVATE_V4, WARP_PEER };
