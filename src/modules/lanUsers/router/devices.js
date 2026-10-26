'use strict';
/**
 * The devices behind the router, for the users module's transparent mode:
 * by MAC, with EVERY address each one uses now — the per-device routes in
 * sing-box match by source address (see index.js for why not by MAC), and a
 * phone speaking v4 and v6 needs both in its user's rule-set.
 *
 * Two sources, as the gateway's own device list (openwrtNet.lanDevices):
 * dnsmasq's /tmp/dhcp.leases (the name, the v4 address it handed out) and the
 * kernel's neighbour table on the LAN device (who is actually here, at which
 * addresses — a static address, a v6 privacy address). openwrtNet parses both;
 * this keeps every address where that list keeps one for display.
 *
 * Pure but for scanDevices, which takes its I/O as parameters.
 */
const fs = require('fs');
const nodeNet = require('net');
const { parseDhcpLeases, parseNeigh, normalizeMac } = require('../../../main/openwrtNet');

/** `::ffff:192.168.1.23` (a dual-stack socket's view of a v4 client) → `192.168.1.23`; anything else as it is. */
function plainIp(ip) {
  const s = String(ip == null ? '' : ip).trim().toLowerCase();
  const m = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(s);
  return m ? m[1] : s;
}

/**
 * An address the device's packets can carry through the router: v4, or a v6
 * that is not link-local — fe80::/10 never leaves the LAN, so it never meets
 * sing-box and only makes the rule-set longer.
 */
function routableIp(ip) {
  const s = plainIp(ip);
  const fam = nodeNet.isIP(s);
  if (fam === 4) return s !== '0.0.0.0' ? s : null;
  if (fam === 6 && !/^fe[89ab]/.test(s) && s !== '::') return s;
  return null;
}

/**
 * One row per MAC: { mac, ip, ips, hostname, online }. `ips`: the lease's
 * address while its lease runs (`expires` 0 is "never") and every address the
 * neighbour table has for the MAC in a live state — v4 first, then v6, each
 * once. `ip`: the one to show (its first v4, else its first). `online`: the
 * neighbour table saw it lately. Sorted as openwrtNet.mergeDevices sorts.
 */
function mergeAll(leases, neigh, { now = Date.now() } = {}) {
  const byMac = new Map();
  const row = (mac) => {
    let r = byMac.get(mac);
    if (!r) { r = { mac, ip: '', ips: [], hostname: '', online: false }; byMac.set(mac, r); }
    return r;
  };
  const add = (r, ip) => { const a = routableIp(ip); if (a && !r.ips.includes(a)) r.ips.push(a); };
  for (const l of leases || []) {
    const mac = normalizeMac(l && l.mac);
    if (!mac) continue;
    const r = row(mac);
    if (l.name && !r.hostname) r.hostname = String(l.name);
    if (!l.expires || l.expires * 1000 > now) add(r, l.ip);
  }
  for (const n of neigh || []) {
    const mac = normalizeMac(n && n.mac);
    if (!mac) continue;
    const r = row(mac);
    if (n.online) { add(r, n.ip); r.online = true; }
  }
  const rows = [...byMac.values()];
  for (const r of rows) {
    r.ips.sort((a, b) => Number(a.includes(':')) - Number(b.includes(':')));
    r.ip = r.ips[0] || '';
  }
  return rows.sort((a, b) =>
    (Number(b.online) - Number(a.online)) || (Number(!a.hostname) - Number(!b.hostname)) ||
    a.hostname.localeCompare(b.hostname) || a.mac.localeCompare(b.mac));
}

/**
 * The LAN now. `run` is tunPlatform.run's shape (`ip neigh show dev <lan>` —
 * both families), `readFile` reads the lease file. Either source may be
 * missing (a fresh router has no leases yet) and contributes nothing; never
 * throws.
 */
async function scanDevices({ readFile = (p) => fs.promises.readFile(p, 'utf8'), run, lanIf = 'br-lan', leaseFile = '/tmp/dhcp.leases', now = Date.now() } = {}) {
  let leases = [];
  try { leases = parseDhcpLeases(await readFile(leaseFile)); } catch { /* no leases yet */ }
  let neigh = [];
  try { if (run) neigh = parseNeigh(await run('ip', ['neigh', 'show', 'dev', String(lanIf || 'br-lan')])); } catch { /* no neighbour table */ }
  return mergeAll(leases, neigh, { now });
}

/** The MAC an address belongs to in a scan, or null. */
function macOfIp(rows, ip) {
  const a = plainIp(ip);
  for (const r of rows || []) if (r && Array.isArray(r.ips) && r.ips.includes(a)) return r.mac;
  return null;
}

module.exports = { plainIp, routableIp, mergeAll, scanDevices, macOfIp };
