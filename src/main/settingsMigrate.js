'use strict';
/**
 * One-time settings migrations: the resolver rework (phase 2) and the local
 * ports' move to the 30000s (migratePorts, below).
 *
 * The resolver rework:
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

function migrateDns(raw) {
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

/**
 * The local ports left 10808/10809/10085 — what v2rayN, v2rayNG, Nekoray and
 * most Xray clients take too, so two of them on one machine fought over the
 * same ports — for 30808/30809/30085. A store from before moves once
 * (`portsMoved` marks it, and the defaults carry it so a new store never
 * runs this): only a port still on its OLD DEFAULT moves, a port the user
 * chose stays. With LAN sharing on (`allowLan`) the SOCKS and HTTP ports are
 * what the other devices on the network were pointed at, so they stay too;
 * the stats port is loopback-only and moves either way.
 */
const OLD_PORTS = { socksPort: 10808, httpPort: 10809, apiPort: 10085 };
const NEW_PORTS = { socksPort: 30808, httpPort: 30809, apiPort: 30085 };
const LAN_FACING = new Set(['socksPort', 'httpPort']);

function migratePorts(raw) {
  if (!raw || typeof raw !== 'object' || raw.portsMoved === true) return { settings: raw, changed: false };
  const next = Object.assign({}, raw, { portsMoved: true });
  for (const k of Object.keys(OLD_PORTS)) {
    if (raw.allowLan && LAN_FACING.has(k)) continue;
    if (Number(raw[k]) === OLD_PORTS[k]) next[k] = NEW_PORTS[k];
  }
  return { settings: next, changed: true };
}

function migrateSettings(raw) {
  const a = migrateDns(raw);
  const b = migratePorts(a.settings);
  return { settings: b.settings, changed: a.changed || b.changed };
}

module.exports = { migrateSettings, migratePorts, OLD_PORTS, NEW_PORTS };
