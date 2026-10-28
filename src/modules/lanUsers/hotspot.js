'use strict';
/**
 * Users on a Windows PC's Mobile Hotspot: does a device on it ride the tunnel?
 *
 * The question before a transparent mode for the hotspot (as the router has:
 * no proxy to set on the device, a sign-in page, a config per user). That
 * mode would route each device by its source address inside the TUN; it can
 * only work if what the hotspot's devices send reaches sing-box's TUN with
 * THEIR addresses (192.168.137.x) — not sent around it by Windows' Internet
 * Connection Sharing straight out of the Wi-Fi, and not rewritten to the PC's
 * own address before the TUN sees it. Nobody can say which from here; the
 * owner's laptop can. So the Users page shows, while TUN mode runs:
 *
 *   - the devices on the hotspot: the PC's neighbour table on the hotspot's
 *     address (`arp -a -N 192.168.137.1`, read-only — the ICS DHCP keeps no
 *     list a program can read without admin);
 *   - for each, whether the tunnel has seen a connection FROM it: sing-box's
 *     loopback API (`experimental.clash_api`, tunSingbox.js `watch`, on
 *     127.0.0.1 with a secret) lists the open connections with their source
 *     address. A connection is open for seconds, so what was seen is kept for
 *     the life of the process: when last, how many open now, the bytes.
 *
 * Read on each lanusers:get (the page reads every few seconds while open);
 * nothing runs in the background, nothing is changed anywhere.
 */
const http = require('http');
const { execFile } = require('child_process');

const HOTSPOT_IP = '192.168.137.1';
const SUBNET = '192.168.137.';
const API_TIMEOUT_MS = 2500;

const inSubnet = (ip) => typeof ip === 'string' && ip.startsWith(SUBNET) && /^\d+\.\d+\.\d+\.\d+$/.test(ip)
  && ip !== HOTSPOT_IP && !ip.endsWith('.255') && !ip.endsWith('.0');

/**
 * `arp -a -N 192.168.137.1` → [{ ip, mac }]: the hotspot's devices, not its
 * broadcast or the multicast groups. The headings and the type word are in
 * Windows' language; the address lines are not, so only those are read.
 */
function parseArp(text) {
  const out = [];
  for (const line of String(text || '').split(/\r?\n/)) {
    const m = /^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-f]{2}(?:[-:][0-9a-f]{2}){5})\b/i.exec(line);
    if (!m || !inSubnet(m[1])) continue;
    const mac = m[2].toLowerCase().replace(/-/g, ':');
    if (mac === 'ff:ff:ff:ff:ff:ff' || mac.startsWith('01:00:5e') || mac === '00:00:00:00:00:00') continue;
    if (!out.some((d) => d.ip === m[1])) out.push({ ip: m[1], mac });
  }
  return out;
}

function runArp(exec) {
  return new Promise((resolve) => {
    (exec || execFile)('arp', ['-a', '-N', HOTSPOT_IP], { windowsHide: true, timeout: 5000 }, (err, so) => {
      // no entries on that interface (the hotspot off) is an exit code, not an error worth a word
      resolve(err && !so ? '' : String(so || ''));
    });
  });
}

/** GET /connections of sing-box's API → its `connections` list; throws on no answer. */
function fetchConnections(watch, get) {
  return new Promise((resolve, reject) => {
    const req = (get || http.get)({ host: '127.0.0.1', port: watch.port, path: '/connections', headers: { Authorization: 'Bearer ' + watch.secret }, timeout: API_TIMEOUT_MS }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (d) => { body += d; if (body.length > 8 * 1024 * 1024) req.destroy(new Error('too big')); });
      res.on('end', () => {
        if (res.statusCode !== 200) return reject(new Error('HTTP ' + res.statusCode));
        try {
          const j = JSON.parse(body);
          resolve(Array.isArray(j && j.connections) ? j.connections : []);
        } catch (e) { reject(e); }
      });
    });
    req.on('timeout', () => req.destroy(new Error('timed out')));
    req.on('error', reject);
  });
}

/**
 * @param {object} o
 *   watch()        → { port, secret } of the running tunnel's API, or null (no TUN, or not a sing-box one)
 *   lanAddresses() → this PC's LAN addresses (the hotspot is on when 192.168.137.1 is among them)
 *   exec, get      child_process.execFile's and http.get's shapes (a test's fakes)
 *   now()
 * → { read() → Promise<{ on, address, tun, error, devices: [{ ip, mac, seen, lastSeen, open, bytes }] }> }
 */
function createHotspotWatch(o) {
  const opts = o || {};
  const now = typeof opts.now === 'function' ? opts.now : () => Date.now();
  const conns = new Map();    // connection id → { ip, bytes } while open
  const closed = new Map();   // ip → the bytes of its connections that ended
  const last = new Map();     // ip → when the tunnel last had a connection from it
  let secret = '';

  function take(list) {
    const t = now();
    const open = new Set();
    for (const c of list) {
      const ip = c && c.metadata && c.metadata.sourceIP;
      if (!inSubnet(ip) || !c.id) continue;
      open.add(c.id);
      conns.set(c.id, { ip, bytes: (Number(c.upload) || 0) + (Number(c.download) || 0) });
      last.set(ip, t);
    }
    for (const [id, c] of conns) {
      if (open.has(id)) continue;
      closed.set(c.ip, (closed.get(c.ip) || 0) + c.bytes);
      conns.delete(id);
    }
  }

  async function read() {
    const lans = typeof opts.lanAddresses === 'function' ? (opts.lanAddresses() || []) : [];
    const on = lans.includes(HOTSPOT_IP);
    const watch = typeof opts.watch === 'function' ? opts.watch() : null;
    let error = '';
    if (watch) {
      // a new tunnel's API: its connection ids are its own
      if (watch.secret !== secret) { conns.clear(); secret = watch.secret; }
      try { take(await fetchConnections(watch, opts.get)); } catch (e) { error = (e && e.message) || 'no answer'; }
    }
    const arp = on ? parseArp(await runArp(opts.exec)) : [];
    const ips = [...new Set([...arp.map((d) => d.ip), ...last.keys()])];
    const devices = ips.map((ip) => {
      const a = arp.find((d) => d.ip === ip);
      const open = [...conns.values()].filter((c) => c.ip === ip);
      return {
        ip, mac: a ? a.mac : '',
        seen: last.has(ip), lastSeen: last.get(ip) || 0, open: open.length,
        bytes: (closed.get(ip) || 0) + open.reduce((s, c) => s + c.bytes, 0)
      };
    }).sort((x, y) => Number(y.seen) - Number(x.seen) || x.ip.localeCompare(y.ip, 'en', { numeric: true }));
    return { on, address: HOTSPOT_IP, tun: !!watch, error, devices };
  }

  return { read };
}

module.exports = { HOTSPOT_IP, parseArp, fetchConnections, createHotspotWatch };
