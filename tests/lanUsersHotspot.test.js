'use strict';
/**
 * The hotspot check (src/modules/lanUsers/hotspot.js): the devices on a
 * Windows PC's Mobile Hotspot from its neighbour table, and whether the
 * tunnel had a connection from each — sing-box's loopback API, read with its
 * secret. Fakes for `arp` and the API; the field names were read from a real
 * sing-box 1.14.4 (metadata.sourceIP, id, upload, download; a wrong secret is
 * a 401).
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { HOTSPOT_IP, parseArp, createHotspotWatch } = require('../src/modules/lanUsers/hotspot');
const { buildTunConfig, watchOf } = require('../src/main/tunSingbox');

const ARP = [
  '',
  'Interface: 192.168.137.1 --- 0x1a',
  '  Internet Address      Physical Address      Type',
  '  192.168.137.45        a2-4b-11-0c-9e-07     dynamic',
  '  192.168.137.88        3C-22-FB-9A-10-7E     dynamic',
  '  192.168.137.255       ff-ff-ff-ff-ff-ff     static',
  '  224.0.0.22            01-00-5e-00-00-16     static',
  '  239.255.255.250       01-00-5e-7f-ff-fa     static',
  ''
].join('\r\n');
// the same table on a Windows in another language: only the address lines are read
const ARP_FA = 'رابط: 192.168.137.1 --- 0x1a\n  آدرس اینترنتی   آدرس فیزیکی   نوع\n  192.168.137.45   a2-4b-11-0c-9e-07   پویا\n';

test('parseArp: the hotspot\'s devices — not its broadcast, the multicast groups, nor another subnet; a localised table too', () => {
  assert.equal(HOTSPOT_IP, '192.168.137.1');
  assert.deepEqual(parseArp(ARP), [{ ip: '192.168.137.45', mac: 'a2:4b:11:0c:9e:07' }, { ip: '192.168.137.88', mac: '3c:22:fb:9a:10:7e' }]);
  assert.deepEqual(parseArp(ARP_FA), [{ ip: '192.168.137.45', mac: 'a2:4b:11:0c:9e:07' }]);
  assert.deepEqual(parseArp('  192.168.1.20   aa-bb-cc-dd-ee-ff   dynamic'), [], 'another LAN is not the hotspot');
  assert.deepEqual(parseArp('No ARP Entries Found.'), []);
  assert.deepEqual(parseArp(''), []);
});

function fakes() {
  const state = { arp: ARP, conns: [], status: 200, asked: [], lans: ['192.168.137.1', '192.168.8.191'], watch: { port: 30860, secret: 'a'.repeat(32) }, t: 1000 };
  const exec = (cmd, args, o, cb) => { state.asked.push([cmd, ...args]); cb(null, state.arp, ''); };
  const get = (o, cb) => {
    state.asked.push(['GET', o.host, o.port, o.path, o.headers.Authorization]);
    const handlers = {};
    const res = { statusCode: state.status, setEncoding() {}, on(ev, fn) { handlers[ev] = fn; } };
    const req = { on() { return req; }, destroy() {} };
    setImmediate(() => {
      cb(res);
      handlers.data && handlers.data(JSON.stringify({ connections: state.conns }));
      handlers.end && handlers.end();
    });
    return req;
  };
  const w = createHotspotWatch({ exec, get, watch: () => state.watch, lanAddresses: () => state.lans, now: () => state.t });
  return { state, w };
}
const conn = (id, ip, up, down) => ({ id, metadata: { sourceIP: ip, destinationIP: '142.250.0.1' }, upload: up, download: down });

test('the watch: a device the tunnel had a connection from is seen — kept after it closes, with its bytes; one it never saw is not', async () => {
  const { state, w } = fakes();
  state.conns = [conn('c1', '192.168.137.45', 500, 2000), conn('c2', '172.19.0.1', 9, 9), conn('c3', '127.0.0.1', 1, 1)];
  let r = await w.read();
  assert.deepEqual(state.asked[0], ['GET', '127.0.0.1', 30860, '/connections', 'Bearer ' + 'a'.repeat(32)], 'loopback, with the secret');
  assert.deepEqual(state.asked[1], ['arp', '-a', '-N', '192.168.137.1'], 'the neighbour table of the hotspot\'s address alone');
  assert.equal(r.on, true);
  assert.equal(r.tun, true);
  assert.equal(r.error, '');
  assert.deepEqual(r.devices, [
    { ip: '192.168.137.45', mac: 'a2:4b:11:0c:9e:07', seen: true, lastSeen: 1000, open: 1, bytes: 2500 },
    { ip: '192.168.137.88', mac: '3c:22:fb:9a:10:7e', seen: false, lastSeen: 0, open: 0, bytes: 0 }
  ], 'the PC\'s own (TUN, loopback) connections are not a hotspot device\'s');
  // c1 grew and closed; a new one opened
  state.t = 5000;
  state.conns = [conn('c1', '192.168.137.45', 800, 4000)];
  await w.read();
  state.conns = [conn('c4', '192.168.137.45', 100, 100)];
  r = await w.read();
  assert.deepEqual(r.devices[0], { ip: '192.168.137.45', mac: 'a2:4b:11:0c:9e:07', seen: true, lastSeen: 5000, open: 1, bytes: 4800 + 200 });
  state.conns = [];
  r = await w.read();
  assert.deepEqual(r.devices[0], { ip: '192.168.137.45', mac: 'a2:4b:11:0c:9e:07', seen: true, lastSeen: 5000, open: 0, bytes: 5000 }, 'seen stays: a connection lives seconds');
});

test('the watch: no tunnel (TUN off) says so and reads only the devices; an API that refuses is said; a hotspot that is off asks nothing', async () => {
  const { state, w } = fakes();
  state.watch = null;
  let r = await w.read();
  assert.equal(r.tun, false);
  assert.deepEqual(r.devices.map((d) => [d.ip, d.seen]), [['192.168.137.45', false], ['192.168.137.88', false]]);
  assert.ok(!state.asked.some((a) => a[0] === 'GET'));
  state.watch = { port: 30860, secret: 'b'.repeat(32) };
  state.status = 401;
  r = await w.read();
  assert.equal(r.tun, true);
  assert.equal(r.error, 'HTTP 401');
  state.lans = ['192.168.8.191'];
  state.asked.length = 0;
  state.status = 200;
  r = await w.read();
  assert.equal(r.on, false);
  assert.deepEqual(r.devices, []);
  assert.ok(!state.asked.some((a) => a[0] === 'arp'), 'the hotspot off: no arp run');
});

test('the tunnel\'s API in its config: on 127.0.0.1 with the secret, and every connection\'s program looked up; absent or malformed — the output of before', () => {
  const base = buildTunConfig({ socksPort: 10808 });
  assert.equal(base.experimental, undefined);
  assert.equal(base.route.find_process, undefined);
  const w = buildTunConfig({ socksPort: 10808, watch: { port: 30860, secret: '0123456789abcdef0123456789abcdef' } });
  assert.deepEqual(w.experimental, { clash_api: { external_controller: '127.0.0.1:30860', secret: '0123456789abcdef0123456789abcdef' } });
  assert.equal(w.route.find_process, true, 'the Connections tab names each connection\'s program');
  assert.deepEqual(Object.assign({}, w, { experimental: undefined, route: Object.assign({}, w.route, { find_process: undefined }) }),
    Object.assign({}, base, { experimental: undefined, route: Object.assign({}, base.route, { find_process: undefined }) }), 'nothing else changes');
  for (const bad of [{ port: 0, secret: 'a'.repeat(32) }, { port: 30860, secret: 'short' }, { port: 30860, secret: 'a'.repeat(31) + '"' }, { port: '30860', secret: 'a'.repeat(32) }, null]) {
    assert.equal(watchOf(bad), null, JSON.stringify(bad));
    assert.equal(buildTunConfig({ socksPort: 10808, watch: bad }).experimental, undefined);
    assert.equal(buildTunConfig({ socksPort: 10808, watch: bad }).route.find_process, undefined);
  }
  // beside the per-app split: its rules and outbounds as before, the lookup added
  const apps = { mode: 'exclude', names: ['steam.exe'] };
  const a = buildTunConfig({ socksPort: 10808, apps, watch: { port: 30860, secret: 'b'.repeat(32) } });
  assert.deepEqual(a.route.rules, buildTunConfig({ socksPort: 10808, apps }).route.rules);
  assert.deepEqual(a.outbounds, buildTunConfig({ socksPort: 10808, apps }).outbounds);
  assert.equal(a.route.find_process, true);
});

test('writeConfig: the API (with find_process) on every desktop sing-box can name a program on — Windows, Linux, a Mac\'s compatibility backend — never on the router; the tunnel says what it runs (tun.watch)', () => {
  const fs = require('node:fs');
  const { TunSingbox, WATCH_PLATFORMS } = require('../src/main/tunSingbox');
  assert.deepEqual(WATCH_PLATFORMS, ['win32', 'linux', 'darwin']);
  const watch = { port: 30860, secret: 'c'.repeat(32) };
  const read = (t) => {
    const { cfgFile } = t.writeConfig(10808, [], { watch }, 'IRNetFree');
    const cfg = JSON.parse(fs.readFileSync(cfgFile, 'utf8'));
    t.removeWork();
    return cfg;
  };
  const API = { clash_api: { external_controller: '127.0.0.1:30860', secret: 'c'.repeat(32) } };
  for (const platform of WATCH_PLATFORMS) {
    const t = new TunSingbox({ platform });
    const cfg = read(t);
    assert.deepEqual(cfg.experimental, API, platform);
    assert.equal(cfg.route.find_process, true, platform);
    assert.deepEqual(t.watch, watch, platform);
  }
  const router = new TunSingbox({ platform: 'linux', composedBy: 'openwrt' });
  const rc = read(router);
  assert.equal(rc.experimental, undefined);
  assert.equal(rc.route.find_process, undefined, 'the router\'s config as before');
  assert.equal(router.watch, null);
  const other = new TunSingbox({ platform: 'freebsd' });
  assert.equal(read(other).experimental, undefined, 'a platform sing-box cannot name programs on');
  // no watch handed in (tun2socks' caller, an older one): the output of before
  const plain = new TunSingbox({ platform: 'win32' });
  const { cfgFile } = plain.writeConfig(10808, [], {}, 'IRNetFree');
  const pc = JSON.parse(fs.readFileSync(cfgFile, 'utf8'));
  plain.removeWork();
  assert.equal(pc.experimental, undefined);
  assert.equal(pc.route.find_process, undefined);
  assert.equal(plain.watch, null);
});
