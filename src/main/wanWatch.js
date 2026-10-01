'use strict';
/**
 * The router's network watcher (v1.16 S3): WAN facts only, judged — not obeyed.
 *
 * The desktop watcher (netWatcher.js) fingerprints every address of every
 * interface and rebuilds the tunnel once a change has settled. On a router
 * that is wrong three times over: an IPv6 delegated prefix rotates (twice —
 * the new one arrives, the old one leaves), a PPPoE/WAN carrier flaps, br-lan
 * loses all its carriers on a Wi-Fi firmware reset — and each cost 20-40 s
 * with the whole LAN direct, for a tunnel that was fine.
 *
 * Here the fingerprint is netifd's own view (`ubus call network.interface
 * dump`): only the interfaces holding a default route, their up / L3 device /
 * IPv4 addresses / gateway, and for IPv6 up and device alone (an address or
 * prefix rotation is not a new network). The LAN never counts. After a change
 * has held still for `settleMs` the tunnel is asked whether it survived —
 * an HTTP 204 through the local SOCKS inbound, twice, 5 s apart — and only a
 * tunnel that answers neither time is rebuilt. One thing is not asked: the
 * device xray binds its direct dials to (sockopt.interface) having vanished
 * is a rebuild at once, since every dial would fail with the old name.
 *
 * Pure: the dump reader, the probe, the sleep and the clock are injected.
 */

const isV4 = (s) => /^\d{1,3}(\.\d{1,3}){3}$/.test(String(s || ''));
const isV6 = (s) => String(s || '').includes(':');

/**
 * `dump` = the parsed `ubus call network.interface dump`.
 * → { v4: [{ iface, up, dev, addrs: ['a/mask'…], nexthop }], v6: [{ iface, up, dev }] } — only the
 *   interfaces holding a default route (route target 0.0.0.0 / :: with mask 0), sorted by name.
 */
function wanFingerprint(dump) {
  const ifaces = dump && Array.isArray(dump.interface) ? dump.interface : [];
  const v4 = [];
  const v6 = [];
  for (const i of ifaces) {
    if (!i || typeof i !== 'object' || typeof i.interface !== 'string') continue;
    const routes = Array.isArray(i.route) ? i.route : [];
    const def4 = routes.filter(r => r && Number(r.mask) === 0 && isV4(r.target));
    const def6 = routes.filter(r => r && Number(r.mask) === 0 && isV6(r.target));
    const dev = (typeof i.l3_device === 'string' && i.l3_device) || (typeof i.device === 'string' && i.device) || null;
    if (def4.length) {
      const addrs = (Array.isArray(i['ipv4-address']) ? i['ipv4-address'] : []).filter(a => a && a.address).map(a => `${a.address}/${a.mask}`).sort();
      const nexthop = [...new Set(def4.map(r => r.nexthop).filter(Boolean))].sort().join(',') || null;
      v4.push({ iface: i.interface, up: !!i.up, dev, addrs, nexthop });
    }
    if (def6.length) v6.push({ iface: i.interface, up: !!i.up, dev });
  }
  const byName = (a, b) => a.iface.localeCompare(b.iface);
  return { v4: v4.sort(byName), v6: v6.sort(byName) };
}

/** What changed between two fingerprints, for the log — and which devices left. */
function diffFingerprint(prev, next) {
  const a = prev || { v4: [], v6: [] };
  const b = next || { v4: [], v6: [] };
  const lines = [];
  const index = (list) => Object.fromEntries((list || []).map(e => [e.iface, e]));
  for (const fam of ['v4', 'v6']) {
    const was = index(a[fam]);
    const now = index(b[fam]);
    for (const name of [...new Set([...Object.keys(was), ...Object.keys(now)])].sort()) {
      const x = was[name];
      const y = now[name];
      if (!x) {
        lines.push(`${name}: default ${fam} route appeared (${y.dev || '?'}${y.addrs && y.addrs.length ? ' ' + y.addrs.join(' ') : ''})`);
        continue;
      }
      if (!y) { lines.push(`${name}: default ${fam} route gone`); continue; }
      if (x.up !== y.up) lines.push(`${name}: ${y.up ? 'up' : 'down'}`);
      if (x.dev !== y.dev) lines.push(`${name}: device ${x.dev || '-'} → ${y.dev || '-'}`);
      if (fam === 'v4') {
        if ((x.addrs || []).join(' ') !== (y.addrs || []).join(' ')) lines.push(`${name}: ${(x.addrs || []).join(' ') || '-'} → ${(y.addrs || []).join(' ') || '-'}`);
        if (x.nexthop !== y.nexthop) lines.push(`${name}: gateway ${x.nexthop || '-'} → ${y.nexthop || '-'}`);
      }
    }
  }
  const devs = (fp) => new Set([...(fp.v4 || []), ...(fp.v6 || [])].map(e => e.dev).filter(Boolean));
  const after = devs(b);
  const devGone = [...devs(a)].filter(d => !after.has(d));
  return { changed: lines.length > 0, lines, devGone };
}

const defaultSleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * 'rebuild' when the device the tunnel's dials are bound to is among the
 * gone ones; else the tunnel is asked (`probe`: true = it answers), and asked
 * once more `probeGapMs` later when it did not — 'kept' as soon as it answers,
 * 'rebuild' when it answered neither time. A probe that throws did not answer.
 */
async function decide({ diff, boundDev, probe, sleep = defaultSleep, probeGapMs = 5000 }) {
  if (boundDev && diff && Array.isArray(diff.devGone) && diff.devGone.includes(boundDev)) return 'rebuild';
  const ask = async () => { try { return !!(await probe()); } catch { return false; } };
  if (await ask()) return 'kept';
  await sleep(probeGapMs);
  if (await ask()) return 'kept';
  return 'rebuild';
}

/**
 * Polls the dump every `intervalMs`; once the fingerprint has LEFT the
 * baseline and then held still for `settleMs`, `onChange({ diff })` — once.
 * A read that fails is no change. A link that flaps and settles back fires
 * with an empty diff: the tunnel's sockets may have died with it, and the
 * probe is what decides. A change seen while onChange is still running is
 * judged after it (the next settle), never beside it.
 */
function createWanWatcher({ readDump, settleMs = 10000, intervalMs = 5000, onChange = () => {}, setTimer, clearTimer } = {}) {
  if (typeof readDump !== 'function') throw new Error('createWanWatcher: readDump is required');
  const setT = setTimer || ((fn, ms) => setInterval(fn, ms));
  const clearT = clearTimer || ((h) => clearInterval(h));
  const key = (fp) => JSON.stringify(fp);
  const w = {
    timer: null,
    last: null,        // the baseline: the fingerprint the tunnel was (last) judged for
    pending: null,     // what the last read said, while it is still settling
    settledFor: 0,
    moved: false,      // the fingerprint has LEFT the baseline since the last verdict
    busy: false,       // onChange in flight
    ticking: false,
    async read() {
      try { return wanFingerprint(await readDump()); } catch { return null; }
    },
    async tick() {
      if (w.ticking || !w.timer) return;
      w.ticking = true;
      try {
        const fp = await w.read();
        if (!fp || !w.timer) return;
        if (w.last === null) { w.last = fp; return; }
        const k = key(fp);
        if (k !== key(w.last)) w.moved = true;
        if (w.pending === null || k !== key(w.pending)) { w.pending = fp; w.settledFor = 0; return; }
        w.settledFor += intervalMs;
        if (w.settledFor < settleMs) return;
        const settled = w.pending;
        w.pending = null;
        w.settledFor = 0;
        if (!w.moved || w.busy) return;   // nothing moved — or a verdict is still being reached: judged at the next settle
        w.moved = false;
        const diff = diffFingerprint(w.last, settled);
        w.last = settled;
        w.busy = true;
        Promise.resolve().then(() => onChange({ diff })).catch(() => {}).then(() => { w.busy = false; });
      } finally { w.ticking = false; }
    },
    async start() {
      if (w.timer) return;
      w.last = null; w.pending = null; w.settledFor = 0; w.moved = false;
      w.timer = setT(() => { w.tick(); }, intervalMs);
      w.last = await w.read();          // the baseline, before the first interval
    },
    stop() {
      if (w.timer) clearT(w.timer);
      w.timer = null;
      w.pending = null; w.settledFor = 0; w.moved = false;
    }
  };
  return w;
}

module.exports = { wanFingerprint, diffFingerprint, decide, createWanWatcher };
