'use strict';
/**
 * Resolving a name without believing the network.
 *
 * The machine's own resolver is the one thing this app cannot trust. On the
 * network this was written for, `nslookup` answers EVERY name with an address
 * out of 198.18.0.0/15 and a fc00::/7 companion — a fake-IP gateway — and on a
 * filtered ISP it answers with the block page. An address like that is not a
 * lookup failure the caller can see: it is a plausible-looking IP that connects
 * to the wrong machine.
 *
 * So: ask the OS first (it is instant, and on a sane network it is right), and
 * when every answer it gives falls in a range a public server can never be in,
 * ask a DoH resolver over HTTPS instead. The DoH URL must name a literal IP —
 * otherwise resolving the resolver would need the resolver we do not trust —
 * and its certificate is verified, so the middlebox that rewrites DNS cannot
 * answer for it either: an intercepted connection fails validation and we fall
 * back rather than believe it.
 *
 * Nothing here decides policy. It returns what it found and where it came from;
 * the caller logs it and picks.
 */
const dnsPromises = require('dns').promises;
const https = require('https');
const net = require('net');

/** The DoH servers used when the caller names none. Literal IPs on purpose. */
const DEFAULT_DOH = ['https://1.1.1.1/dns-query', 'https://8.8.8.8/dns-query'];

/**
 * Ranges no public server's A record can legitimately be in. A LAN address is
 * in here too: a corporate endpoint really can be 10.x, so this is only ever a
 * reason to ask a second resolver, never a reason to discard an answer.
 */
const SUSPECT4 = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.2.0', 24], ['192.168.0.0', 16],
  // 198.18.0.0/15 is the benchmarking range every fake-IP gateway hands out.
  ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24],
  ['224.0.0.0', 4], ['240.0.0.0', 4]
];

function v4num(ip) {
  const p = String(ip).split('.');
  if (p.length !== 4) return null;
  let n = 0;
  for (const part of p) {
    const b = Number(part);
    if (!/^\d{1,3}$/.test(part) || b > 255) return null;
    n = (n * 256) + b;
  }
  return n;
}

/** True when an address cannot be a public server — see SUSPECT4. */
function isSuspect(ip) {
  const s = String(ip || '').trim();
  if (net.isIPv4(s)) {
    const n = v4num(s);
    if (n == null) return true;
    return SUSPECT4.some(([base, bits]) => {
      const mask = bits === 0 ? 0 : (-1 << (32 - bits)) >>> 0;
      return (n & mask) === (v4num(base) & mask);
    });
  }
  if (net.isIPv6(s)) {
    const low = s.toLowerCase();
    return low === '::' || low === '::1' || /^f[cd]/.test(low) || /^fe[89ab]/.test(low) || low.startsWith('2001:db8:');
  }
  return true;
}

/** One DoH question over the JSON API (Cloudflare, Google, Quad9, AdGuard). */
function dohQuery(url, host, type, timeoutMs, agent) {
  return new Promise((resolve) => {
    let u;
    try { u = new URL(url); } catch { return resolve([]); }
    // No bootstrap: a DoH server named by hostname would have to be resolved
    // by the resolver we are trying not to trust.
    if (u.protocol !== 'https:' || !net.isIP(u.hostname.replace(/^\[|\]$/g, ''))) return resolve([]);
    u.searchParams.set('name', host);
    u.searchParams.set('type', type);
    const req = https.get(u, { headers: { accept: 'application/dns-json' }, agent }, (res) => {
      if (res.statusCode !== 200) { res.resume(); return resolve([]); }
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (c) => { body += c; if (body.length > 65536) req.destroy(); });
      res.on('end', () => {
        try {
          const j = JSON.parse(body);
          const want = type === 'AAAA' ? 28 : 1;
          resolve((j.Answer || []).filter(a => a && a.type === want && net.isIP(String(a.data)))
            .map(a => String(a.data)));
        } catch { resolve([]); }
      });
      res.on('error', () => resolve([]));
    });
    req.on('error', () => resolve([]));
    req.setTimeout(timeoutMs, () => { req.destroy(); resolve([]); });
  });
}

/** Every DoH server in turn until one answers. */
async function dohLookup(host, { ipv6, doh, timeout, query }) {
  const ask = query || dohQuery;
  const types = ipv6 ? ['A', 'AAAA'] : ['A'];
  for (const url of doh) {
    const out = [];
    for (const type of types) {
      for (const ip of await ask(url, host, type, timeout)) if (!out.includes(ip)) out.push(ip);
    }
    if (out.length) return out;
  }
  return [];
}

/**
 * @param {string} host           a hostname, or a literal address (returned as is)
 * @param {object} [opts]         { ipv6, doh: string[], timeout, lookup, query }
 * @returns {Promise<{ips: string[], source: string, suspect: string[]}>}
 *   source: 'literal' | 'os' | 'doh' (the OS answer was unusable) |
 *           'os-suspect' (no second opinion available) | 'none'
 */
async function resolveHost(host, opts = {}) {
  const h = String(host || '').trim();
  if (!h) return { ips: [], source: 'none', suspect: [] };
  if (net.isIP(h)) return { ips: [h], source: 'literal', suspect: [] };
  const ipv6 = !!opts.ipv6;
  const timeout = opts.timeout || 2500;
  const doh = (Array.isArray(opts.doh) && opts.doh.length ? opts.doh : DEFAULT_DOH)
    .filter(u => /^https:\/\//i.test(String(u || '')));
  const lookup = opts.lookup || (async (name) => {
    const res = await dnsPromises.lookup(name, { family: ipv6 ? 0 : 4, all: true });
    return res.map(r => r.address).filter(Boolean);
  });

  let osIps = [];
  try { osIps = await lookup(h); } catch { osIps = []; }
  const clean = osIps.filter(ip => !isSuspect(ip));
  if (clean.length) return { ips: clean, source: 'os', suspect: [] };

  const fromDoh = await dohLookup(h, { ipv6, doh, timeout, query: opts.query });
  const cleanDoh = fromDoh.filter(ip => !isSuspect(ip));
  if (cleanDoh.length) return { ips: cleanDoh, source: 'doh', suspect: osIps.slice() };
  if (osIps.length) return { ips: osIps.slice(), source: 'os-suspect', suspect: osIps.slice() };
  return { ips: fromDoh, source: fromDoh.length ? 'doh' : 'none', suspect: [] };
}

module.exports = { resolveHost, isSuspect, dohQuery, DEFAULT_DOH, SUSPECT4 };
