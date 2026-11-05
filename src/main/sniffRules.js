'use strict';
/**
 * What the core may read from a connection, and what a domain rule's text means.
 *
 * Under a TUN the core is handed a bare address. The only name it ever has is
 * the one it reads from the first bytes (sniffing), and with `routeOnly: false`
 * that name replaces the address. So one setting could never suit every host,
 * measured on real cores (scripts/probe-domain-routing.js):
 *
 *                                             sniffing off   sniffing on
 *   corporate address, its own name           the VPN        the VPN
 *   corporate address, a name that resolves
 *     elsewhere or nowhere                    the VPN        the default: lost
 *   a wrong public address, a corporate name  the default    the VPN
 *   a name in a domain rule                   the default    its target
 *
 * The core's `sniffing.ipsExcluded` (Xray 26.4.13 on, an older core ignores it) gives
 * the right answer of every row at once: sniffing stays on, its default, and an
 * address a rule names by itself is left alone. The switch still turns it off. Android's
 * core/SniffRules.kt is this file; tests/sniffRules.test.js and SniffRulesTest.kt
 * hold the same cases.
 */
const net = require('net');
const { domainToASCII } = require('url');

/**
 * Iran's DNS poison answers with these private addresses (10.10.34.34-36). A
 * connection to one holds the only true name it will ever get in its first bytes:
 * it stays sniffed, whatever range around it is left alone.
 */
const POISON_CIDR = '10.10.34.32/29';

const ipv4ToInt = (ip) => ip.split('.').reduce((n, x) => ((n * 256) + Number(x)) >>> 0, 0);
const intToIpv4 = (n) => [24, 16, 8, 0].map((s) => (n >>> s) & 255).join('.');

/** Is this an address or a CIDR the core can read: a geoip: name, a range `a-b` or a typo is not? */
function isIpLiteral(value) {
  const parts = String(value == null ? '' : value).trim().split('/');
  if (parts.length > 2) return false;
  const family = net.isIP(parts[0]);
  if (!family) return false;
  if (parts.length === 1) return true;
  return /^\d{1,3}$/.test(parts[1]) && Number(parts[1]) <= (family === 4 ? 32 : 128);
}

/**
 * Wider than this is the internet, not a host: an IP rule for `0.0.0.0/0` must not
 * stop every name being read, or the domain rules above it never catch. The
 * private ranges' widest are `10.0.0.0/8` and `fc00::/7`.
 */
const WIDEST = { 4: 8, 6: 7 };
const tooWide = (cidr) => {
  const [addr, mask] = cidr.split('/');
  return mask !== undefined && Number(mask) < WIDEST[net.isIP(addr)];
};

/** A v4 CIDR around the poison addresses, as the CIDRs that cover the rest of it. Anything else stays as it is. */
function withoutPoison(cidr) {
  const [addr, mask] = cidr.split('/');
  if (net.isIP(addr) !== 4 || mask === undefined) return [cidr];
  const bits = Number(mask);
  const [poison, poisonMask] = POISON_CIDR.split('/');
  const size = Number(poisonMask);
  if (bits >= size) return [cidr];
  const hostBits = 32 - bits;
  const base = hostBits === 32 ? 0 : ipv4ToInt(addr) >>> hostBits;
  const target = ipv4ToInt(poison);
  if ((hostBits === 32 ? 0 : target >>> hostBits) !== base) return [cidr];
  const out = [];
  for (let b = bits + 1; b <= size; b++) {
    const shift = 32 - b;
    const sibling = (((target >>> shift) ^ 1) << shift) >>> 0;
    out.push(`${intToIpv4(sibling)}/${b}`);
  }
  return out;
}

/**
 * `sniffing.ipsExcluded` for these addresses: the ones a core can read and that
 * are not the whole internet, once each, with the poison addresses cut out of any
 * range around them.
 */
function sniffExcludedIps(values) {
  const out = new Set();
  for (const v of values || []) {
    const s = String(v == null ? '' : v).trim();
    if (!isIpLiteral(s) || tooWide(s)) continue;
    for (const c of withoutPoison(s)) out.add(c);
  }
  return [...out];
}

const CORE_PREFIX = /^(domain|full|keyword|regexp|geosite|ext|dotless):/i;

const escapeRegexp = (s) => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&');

/**
 * One value of a domain rule as the core must read it. To the core a bare string
 * is a substring and a `*` is an ordinary character, so `x.com` caught netflix.com
 * and `*.claude.com` matched nothing at all. A prefix the core knows stays as
 * written. Otherwise: an address pasted whole is its host; `example.com`, `.example.com`
 * and `*.example.com` are that name and everything under it; any other `*` is a
 * wildcard over the whole name; a word with no dot is the core's own substring.
 */
function normalizeDomain(value) {
  const raw = String(value == null ? '' : value).trim();
  if (!raw) return null;
  const prefix = CORE_PREFIX.exec(raw);
  if (prefix) return prefix[1].toLowerCase() + raw.slice(prefix[1].length);
  let v = raw.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').replace(/[/?#].*$/, '').replace(/:\d+$/, '').replace(/\.+$/, '').toLowerCase();
  if (!v) return null;
  if (/^\*\.+[^*]+$/.test(v)) v = v.replace(/^\*\.+/, '');
  else if (v.includes('*')) return 'regexp:^' + v.split('*').map(escapeRegexp).join('.*') + '$';
  v = v.replace(/^\.+/, '');
  if (!v) return null;
  // a name is sniffed in its ASCII form
  if (/[^\x00-\x7f]/.test(v)) v = domainToASCII(v) || v;
  return v.includes('.') ? 'domain:' + v : v;
}

/** A domain rule's values for the core, once each. */
function normalizeDomains(values) {
  const out = new Set();
  for (const v of values || []) {
    const n = normalizeDomain(v);
    if (n) out.add(n);
  }
  return [...out];
}

/**
 * Does a name decide where something goes, away from where it would go anyway?
 * Then a browser's QUIC has to be read too, and the core cannot read every one:
 * a Chrome-shaped Initial (its CRYPTO frames shuffled) is not sniffed, on either
 * core. claude.ai publishes h3, so the same site went one way over TCP and the
 * other over QUIC.
 */
const namesDecide = (rules, defaultTag) => (rules || []).some((r) => r && r.domain && r.outboundTag !== defaultTag);

/**
 * The two rules that settle it, right before the catch-all: a QUIC with a name goes
 * on as usual, and one whose name could not be read is refused. A browser then
 * falls back to TCP, where the name is always read.
 */
const quicFallbackRules = (defaultTag) => [
  { type: 'field', network: 'udp', port: '443', domain: ['regexp:.'], outboundTag: defaultTag },
  { type: 'field', network: 'udp', port: '443', outboundTag: 'block' }
];

module.exports = { POISON_CIDR, isIpLiteral, sniffExcludedIps, normalizeDomain, normalizeDomains, namesDecide, quicFallbackRules };
