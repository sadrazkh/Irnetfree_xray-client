'use strict';
/**
 * One-time settings migration for the resolver rework (phase 2).
 *
 * The old store held a single `dns` list of plain-UDP resolvers. The new model
 * has two lists with different jobs: `dnsRemote` (the world, over DoH through
 * the tunnel) and `dnsDirect` (the in-country resolver for bypass modes). A
 * known public resolver is upgraded to its DoH endpoint — the whole point of
 * the rework is that plain UDP through the proxy is what broke bypass — and a
 * known Iranian resolver goes where it belongs. Anything else is kept as is.
 *
 * Pure and idempotent: returns the SAME object when there is nothing to do.
 */

const DOH_FOR = {
  '1.1.1.1': 'https://1.1.1.1/dns-query', '1.0.0.1': 'https://1.0.0.1/dns-query',
  '8.8.8.8': 'https://8.8.8.8/dns-query', '8.8.4.4': 'https://8.8.4.4/dns-query',
  '9.9.9.9': 'https://9.9.9.9/dns-query', '149.112.112.112': 'https://149.112.112.112/dns-query',
  '94.140.14.14': 'https://94.140.14.14/dns-query', '94.140.15.15': 'https://94.140.15.15/dns-query',
  '208.67.222.222': 'https://208.67.222.222/dns-query', '208.67.220.220': 'https://208.67.220.220/dns-query'
};

/** Resolvers that only make sense as the in-country (direct) server. */
const IRANIAN = new Set([
  '178.22.122.100', '185.51.200.2',      // Shecan
  '78.157.42.100', '78.157.42.101',      // Electro
  '10.202.10.202', '10.202.10.102',      // Begzar
  '10.202.10.10', '10.202.10.11'         // 403.online
]);

const DEFAULT_REMOTE = ['https://1.1.1.1/dns-query', 'https://8.8.8.8/dns-query'];

function migrateSettings(raw) {
  if (!raw || typeof raw !== 'object' || !('dns' in raw)) return { settings: raw, changed: false };

  const next = Object.assign({}, raw);
  // only a string can name a resolver; a number or null in the list is junk
  const old = Array.isArray(raw.dns) ? raw.dns.filter(v => typeof v === 'string').map(v => v.trim()).filter(Boolean) : [];
  delete next.dns;

  if (next.dnsRemote == null) {
    const remote = [], direct = [];
    for (const ip of old) {
      if (IRANIAN.has(ip)) direct.push(ip);
      else remote.push(DOH_FOR[ip] || ip);
    }
    next.dnsRemote = remote.length ? remote : DEFAULT_REMOTE.slice();
    if (direct.length && next.dnsDirect == null) next.dnsDirect = direct;
  }
  return { settings: next, changed: true };
}

module.exports = { migrateSettings };
