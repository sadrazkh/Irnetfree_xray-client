'use strict';
/**
 * The router's network watcher (v1.16 S3): WAN facts only, from netifd's
 * `ubus call network.interface dump` — the interfaces holding a default
 * route, their up / device / IPv4 address / gateway, IPv6 by up and device
 * only — and a change that is JUDGED by a probe through the tunnel, not
 * obeyed. The desktop watcher (netWatcher.js) rebuilt on any address blip:
 * an IPv6 prefix rotation, a WAN carrier flap, br-lan losing its carriers —
 * each a 20-40 s outage of the whole LAN.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { wanFingerprint, diffFingerprint, decide, createWanWatcher } = require('../src/main/wanWatch');

/* ----------------------------- recorded dumps (the shapes netifd prints) ----------------------------- */

const lan = (addr = '192.168.1.1') => ({
  interface: 'lan', up: true, pending: false, available: true, autostart: true, dynamic: false, uptime: 500,
  l3_device: 'br-lan', proto: 'static', device: 'br-lan', metric: 0, dns_metric: 0, delegation: true,
  'ipv4-address': [{ address: addr, mask: 24 }], 'ipv6-address': [], 'ipv6-prefix': [],
  'ipv6-prefix-assignment': [{ address: 'fd12:3456:789a::', mask: 60, 'local-address': { address: 'fd12:3456:789a::1', mask: 60 } }],
  route: [], 'dns-server': [], 'dns-search': [], neighbors: [], inactive: { 'ipv4-address': [], 'ipv6-address': [], route: [], 'dns-server': [], 'dns-search': [], neighbors: [] }, data: {}
});
const wan = ({ addr = '192.0.2.10', mask = 24, gw = '192.0.2.1', dev = 'pppoe-wan', up = true } = {}) => (up ? {
  interface: 'wan', up: true, pending: false, available: true, autostart: true, dynamic: false, uptime: 400,
  l3_device: dev, proto: 'pppoe', device: 'eth0', metric: 0, dns_metric: 0, delegation: true,
  'ipv4-address': [{ address: addr, mask, ptpaddress: gw }], 'ipv6-address': [], 'ipv6-prefix': [],
  route: [{ target: '0.0.0.0', mask: 0, nexthop: gw, source: '0.0.0.0/0' }],
  'dns-server': ['10.0.0.1'], 'dns-search': [], neighbors: [], inactive: { route: [] }, data: {}
} : {
  interface: 'wan', up: false, pending: true, available: true, autostart: true, dynamic: false, proto: 'pppoe', device: 'eth0', data: {}
});
const wan6 = ({ prefix = '2001:db8:a1:', addr = '2001:db8:a1::1', dev = 'pppoe-wan', up = true } = {}) => (up ? {
  interface: 'wan6', up: true, pending: false, available: true, autostart: true, dynamic: false, uptime: 400,
  l3_device: dev, proto: 'dhcpv6', device: 'eth0', metric: 0, dns_metric: 0, delegation: false,
  'ipv4-address': [], 'ipv6-address': [{ address: addr, mask: 64, preferred: 3000, valid: 7000 }],
  'ipv6-prefix': [{ address: prefix + ':', mask: 56, preferred: 3000, valid: 7000, class: 'wan6', assigned: { lan: { address: prefix + ':', mask: 60 } } }],
  route: [{ target: '::', mask: 0, nexthop: 'fe80::1', source: '::/0', metric: 384 }],
  'dns-server': ['2001:4860:4860::8888'], 'dns-search': [], neighbors: [], inactive: { route: [] }, data: {}
} : { interface: 'wan6', up: false, pending: true, available: true, autostart: true, dynamic: false, proto: 'dhcpv6', device: 'eth0', data: {} });
const dump = (...ifaces) => ({ interface: ifaces });

test('wanFingerprint: only the interfaces holding a default route, with the facts that are a new network', () => {
  const fp = wanFingerprint(dump(lan(), wan(), wan6()));
  assert.deepEqual(fp, {
    v4: [{ iface: 'wan', up: true, dev: 'pppoe-wan', addrs: ['192.0.2.10/24'], nexthop: '192.0.2.1' }],
    v6: [{ iface: 'wan6', up: true, dev: 'pppoe-wan' }]
  });
  assert.deepEqual(wanFingerprint(dump(lan())), { v4: [], v6: [] }, 'a LAN with no default route is not a WAN');
  assert.deepEqual(wanFingerprint(null), { v4: [], v6: [] });
  assert.deepEqual(wanFingerprint({ interface: 'nonsense' }), { v4: [], v6: [] });
  // a down WAN (netifd prints it without a device or routes) holds nothing
  assert.deepEqual(wanFingerprint(dump(lan(), wan({ up: false }), wan6({ up: false }))), { v4: [], v6: [] });
});

test('diffFingerprint: an IPv6 prefix rotation and a LAN address change are not changes; a WAN address, gateway, device or up change is', () => {
  const base = wanFingerprint(dump(lan(), wan(), wan6()));
  // the ISP rotates the delegated prefix (twice: the new one arrives, then the old one leaves)
  const rotated = wanFingerprint(dump(lan(), wan(), wan6({ prefix: '2001:db8:b7:', addr: '2001:db8:b7::1' })));
  assert.deepEqual(diffFingerprint(base, rotated), { changed: false, lines: [], devGone: [] });
  // br-lan moves — a VLAN re-plan, a renumbering — with no default route on it
  assert.equal(diffFingerprint(base, wanFingerprint(dump(lan('10.9.8.1'), wan(), wan6()))).changed, false);
  // the WAN's IPv4 address moves
  const readdr = diffFingerprint(base, wanFingerprint(dump(lan(), wan({ addr: '192.0.2.77' }), wan6())));
  assert.equal(readdr.changed, true);
  assert.deepEqual(readdr.lines, ['wan: 192.0.2.10/24 → 192.0.2.77/24']);
  assert.deepEqual(readdr.devGone, []);
  // the gateway moves
  assert.deepEqual(diffFingerprint(base, wanFingerprint(dump(lan(), wan({ gw: '192.0.2.254' }), wan6()))).lines, ['wan: gateway 192.0.2.1 → 192.0.2.254']);
  // pppoe-wan disappears (the PPPoE session dropped): both WANs lose their routes, the device is gone
  const down = diffFingerprint(base, wanFingerprint(dump(lan(), wan({ up: false }), wan6({ up: false }))));
  assert.equal(down.changed, true);
  assert.deepEqual(down.lines, ['wan: default v4 route gone', 'wan6: default v6 route gone']);
  assert.deepEqual(down.devGone, ['pppoe-wan']);
  // the WAN comes back on another device (a failover to a second WAN, mwan3)
  const moved = diffFingerprint(base, wanFingerprint(dump(lan(), wan({ dev: 'wwan0', addr: '100.64.3.4', gw: '100.64.3.1' }), wan6({ up: false }))));
  assert.deepEqual(moved.lines, ['wan: device pppoe-wan → wwan0', 'wan: 192.0.2.10/24 → 100.64.3.4/24', 'wan: gateway 192.0.2.1 → 100.64.3.1', 'wan6: default v6 route gone']);
  assert.deepEqual(moved.devGone, ['pppoe-wan']);
  // a route appearing (the WAN coming up) is a change too
  assert.deepEqual(diffFingerprint(wanFingerprint(dump(lan())), base).lines, ['wan: default v4 route appeared (pppoe-wan 192.0.2.10/24)', 'wan6: default v6 route appeared (pppoe-wan)']);
  assert.deepEqual(diffFingerprint(null, base).changed, true);
});

test('decide: the bound device gone is a rebuild without asking; else the tunnel is asked twice, 5 s apart', async () => {
  const sleeps = [];
  const sleep = async (ms) => { sleeps.push(ms); };
  let probes = 0;
  const probeOf = (answers) => async () => answers[probes++];
  const gone = { changed: true, lines: ['wan: default v4 route gone'], devGone: ['pppoe-wan'] };
  assert.equal(await decide({ diff: gone, boundDev: 'pppoe-wan', probe: probeOf([true, true]), sleep }), 'rebuild');
  assert.equal(probes, 0, 'not asked: the device xray binds to is gone');
  const changed = { changed: true, lines: ['wan: 192.0.2.10/24 → 192.0.2.77/24'], devGone: [] };
  probes = 0;
  assert.equal(await decide({ diff: changed, boundDev: 'pppoe-wan', probe: probeOf([false, true]), sleep }), 'kept');
  assert.equal(probes, 2);
  assert.deepEqual(sleeps, [5000], 'the second ask 5 s after the first');
  probes = 0;
  assert.equal(await decide({ diff: changed, boundDev: 'pppoe-wan', probe: probeOf([true]), sleep }), 'kept');
  assert.equal(probes, 1, 'answered at once: no second ask');
  probes = 0;
  assert.equal(await decide({ diff: changed, boundDev: 'pppoe-wan', probe: probeOf([false, false]), sleep }), 'rebuild');
  assert.equal(probes, 2);
  // a probe that throws is a probe that failed; another device gone is not ours
  assert.equal(await decide({ diff: gone, boundDev: 'eth1', probe: async () => { throw new Error('socks timeout'); }, sleep }), 'rebuild');
  assert.equal(await decide({ diff: gone, boundDev: 'eth1', probe: async () => true, sleep }), 'kept');
  assert.equal(await decide({ diff: gone, boundDev: null, probe: async () => true, sleep }), 'kept');
});

/** A watcher whose clock is a tick fired by hand; `dumps` is what each read answers (the last one repeats). */
function harness(dumps, opts = {}) {
  const fired = [];
  let tick = null;
  let i = 0;
  const w = createWanWatcher(Object.assign({
    readDump: async () => { const d = dumps[Math.min(i, dumps.length - 1)]; if (d instanceof Error) throw d; return d; },
    settleMs: 10000,
    intervalMs: 5000,
    onChange: (ev) => fired.push(ev),
    setTimer: (fn) => { tick = fn; return 'timer'; },
    clearTimer: () => { tick = null; }
  }, opts));
  const next = () => new Promise((r) => setImmediate(r));
  return {
    w, fired,
    advance: (n = 1) => { i = Math.min(i + n, dumps.length - 1); },
    tick: async () => { if (tick) await tick(); await next(); await next(); },
    running: () => tick !== null
  };
}

test('createWanWatcher: one change then stable for settleMs fires exactly one onChange, with the diff', async () => {
  const h = harness([dump(lan(), wan(), wan6()), dump(lan(), wan({ addr: '192.0.2.77' }), wan6())]);
  await h.w.start();
  assert.equal(h.running(), true);
  await h.tick();                      // the baseline (and nothing else)
  assert.deepEqual(h.fired, []);
  h.advance();
  await h.tick();                      // the change seen: the settle starts
  assert.deepEqual(h.fired, []);
  await h.tick();                      // 5 s stable
  assert.deepEqual(h.fired, []);
  await h.tick();                      // 10 s stable: settled
  assert.equal(h.fired.length, 1);
  assert.deepEqual(h.fired[0].diff.lines, ['wan: 192.0.2.10/24 → 192.0.2.77/24']);
  await h.tick(); await h.tick(); await h.tick();
  assert.equal(h.fired.length, 1, 'said once');
  h.w.stop();
  assert.equal(h.running(), false);
});

test('createWanWatcher: a prefix rotation never fires; a failed read is no change; a flap that settles back fires once with an empty diff (the probe decides)', async () => {
  const rot = harness([dump(lan(), wan(), wan6()), dump(lan(), wan(), wan6({ prefix: '2001:db8:b7:', addr: '2001:db8:b7::1' })), new Error('ubus timeout'), dump(lan(), wan(), wan6({ prefix: '2001:db8:c9:', addr: '2001:db8:c9::1' }))]);
  await rot.w.start();
  await rot.tick();
  for (let n = 0; n < 3; n++) { rot.advance(); for (let k = 0; k < 3; k++) await rot.tick(); }
  assert.deepEqual(rot.fired, []);

  const flap = harness([dump(lan(), wan(), wan6()), dump(lan(), wan({ up: false }), wan6({ up: false })), dump(lan(), wan(), wan6())]);
  await flap.w.start();
  await flap.tick();
  flap.advance(); await flap.tick();   // the WAN gone
  flap.advance(); await flap.tick();   // …and back before it settled
  await flap.tick(); await flap.tick();
  assert.equal(flap.fired.length, 1, 'the link moved: the tunnel is asked whether it survived');
  assert.deepEqual(flap.fired[0].diff, { changed: false, lines: [], devGone: [] });
});

test('createWanWatcher: a change that lands while onChange runs is judged after it, never beside it', async () => {
  const releases = [];
  const diffs = [];
  const h = harness([dump(lan(), wan(), wan6()), dump(lan(), wan({ addr: '192.0.2.77' }), wan6()), dump(lan(), wan({ addr: '192.0.2.78' }), wan6())],
    { onChange: ({ diff }) => new Promise((r) => { diffs.push(diff.lines); releases.push(r); }) });
  await h.w.start();
  await h.tick();
  h.advance(); await h.tick(); await h.tick(); await h.tick();
  assert.equal(releases.length, 1, 'the first change is being judged');
  h.advance(); await h.tick(); await h.tick(); await h.tick();
  assert.equal(releases.length, 1, 'the second is not judged beside it');
  assert.equal(h.w.busy, true);
  releases[0]();
  await h.tick();
  await h.tick(); await h.tick(); await h.tick();
  assert.equal(releases.length, 2, 'judged once the first verdict is in, against the baseline that verdict left');
  assert.deepEqual(diffs, [['wan: 192.0.2.10/24 → 192.0.2.77/24'], ['wan: 192.0.2.77/24 → 192.0.2.78/24']]);
  releases[1]();
  await h.tick();
  assert.equal(h.w.busy, false);
});
