'use strict';
/**
 * The users module's transparent mode on the router, the rest of it: off is
 * nothing at all; who rides which config (the per-device decisions and the
 * rule-set files); sing-box's per-target routes; the core's loopback inbounds;
 * caps from the table's counters (held, and back at the new period); the
 * devices' usage and rates; and the service wiring on a "router".
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const plan = require('../src/modules/lanUsers/router/plan');
const { applyTransparentTargets } = require('../src/modules/lanUsers/router/xrayTargets');
const { createLanRouter } = require('../src/modules/lanUsers/router');
const { buildTunConfig } = require('../src/main/tunSingbox');
const { buildConfig } = require('../src/main/configBuilder');
const { makeProxyServer } = require('../src/main/parser');
const { memFs, fakeLan, fakeGateway, fakeMeter } = require('./lanUsersRouterFakes');

const A = 'aa:bb:cc:dd:ee:01', B = 'aa:bb:cc:dd:ee:02', C = 'aa:bb:cc:dd:ee:03', D = 'aa:bb:cc:dd:ee:04';
const NOW = Date.UTC(2026, 9, 26, 12, 0, 0);
const SRV1 = Object.assign(makeProxyServer({ type: 'socks', address: '192.0.2.10', port: 1080, name: 'home' }), { id: 'srv-1' });
const SRV2 = Object.assign(makeProxyServer({ type: 'socks', address: '192.0.2.20', port: 1080, name: 'office' }), { id: 'srv-2' });
const SRV3 = Object.assign(makeProxyServer({ type: 'socks', address: '192.0.2.30', port: 1080, name: 'third' }), { id: 'srv-3' });

/* ------------------------------ the decisions ------------------------------ */

test('routedTargets: every config a user has, once, sorted — the current connection, direct and block are the gateway\'s own', () => {
  const lu = plan.readLanUsers({ users: [{ id: 'u1', target: 'srv-2' }, { id: 'u2', target: 'chain:c1' }, { id: 'u3', target: 'srv-2' }, { id: 'u4', target: '' }, { id: 'u5', target: 'direct' }, { id: 'u6', target: 'block' }, { id: 'u7', target: 'grp-x', enabled: false }] });
  assert.deepEqual(plan.routedTargets(lu), ['chain:c1', 'grp-x', 'srv-2'], 'a disabled user\'s too: a sign-in never changes the core\'s shape');
});

test('decide: per device — the admin\'s binding for good, a sign-in for its hours, held users, block / direct / a config\'s rule-set', () => {
  const lu = plan.readLanUsers({
    config: { transparent: { enabled: true, unassigned: 'login' } },
    users: [
      { id: 'u-ali', target: 'srv-2', enabled: true }, { id: 'u-net', target: 'direct', enabled: true },
      { id: 'u-no', target: 'block', enabled: true }, { id: 'u-cap', target: 'srv-2', enabled: true }, { id: 'u-here', target: '', enabled: true }
    ],
    devices: [{ mac: A, userId: 'u-ali' }, { mac: B, userId: 'u-net' }, { mac: C, userId: 'u-cap' }, { mac: 'AA:BB:CC:DD:EE:05', blocked: true }, { mac: D, userId: 'u-gone' }]
  });
  const sessions = { 'aa:bb:cc:dd:ee:06': { userId: 'u-ali', until: NOW + 3600000 }, 'aa:bb:cc:dd:ee:07': { userId: 'u-no', until: NOW + 60000 }, 'aa:bb:cc:dd:ee:08': { userId: 'u-here', until: NOW - 1 } };
  const scan = [{ mac: A, ips: ['192.168.1.23', '2001:db8::23'] }, { mac: 'aa:bb:cc:dd:ee:06', ips: ['192.168.1.66'] }, { mac: C, ips: ['192.168.1.30'] }, { mac: 'aa:bb:cc:dd:ee:09', ips: ['192.168.1.99'] }];
  const d = plan.decide({ lu, sessions, scan, usage: { 'u-cap': { over: true } }, now: NOW, tp: [{ tag: 'lu-tp-1', target: 'srv-2' }], portal: { ip: '192.168.1.1', port: 30822 } });
  assert.deepEqual(d.nft.blocked, ['aa:bb:cc:dd:ee:05', 'aa:bb:cc:dd:ee:07'], 'the admin\'s block; a user whose config is "block"');
  assert.deepEqual(d.nft.allowed, [A, B]);
  assert.deepEqual(d.nft.authorized, [{ mac: 'aa:bb:cc:dd:ee:06', timeoutS: 3600 }], 'a session over is no binding at all');
  assert.deepEqual(d.nft.direct, [B]);
  assert.deepEqual(d.held, { [C]: 'over' }, 'login mode: held devices meet the gate, and the page says why');
  assert.deepEqual(d.ruleSets, { 'lu-tp-1': ['192.168.1.23/32', '2001:db8::23/128', '192.168.1.66/32'] });
  assert.deepEqual(d.nft.counters.map(c => c.mac), [A, B, C, D, 'aa:bb:cc:dd:ee:05', 'aa:bb:cc:dd:ee:06', 'aa:bb:cc:dd:ee:07', 'aa:bb:cc:dd:ee:09'], 'every device the router knows is counted');
  assert.deepEqual(d.nft.portal, { ip: '192.168.1.1', port: 30822 });
  // allow mode: no page to explain — a held device is dropped
  const allow = plan.decide({ lu: Object.assign({}, lu, { transparent: Object.assign({}, lu.transparent, { unassigned: 'allow' }) }), sessions, scan, usage: { 'u-cap': { over: true } }, now: NOW, tp: [], portal: { ip: '192.168.1.1', port: 1 } });
  assert.ok(allow.nft.blocked.includes(C));
  assert.equal(allow.nft.portal, null);
});

test('addressOwners: a running lease\'s address is its holder\'s whoever the neighbour table has at it; an address no lease names, the neighbour table\'s', () => {
  const X = 'aa:bb:cc:dd:ee:0c';
  const owners = plan.addressOwners([
    // X took .23 (A's lease) and answers for it; it comes first in the scan's order (online, A is not)
    { mac: X, ips: ['192.168.1.23', '192.168.1.77'], leased: [] },
    { mac: A, ips: ['192.168.1.23', '2001:db8::23'], leased: ['192.168.1.23'] },
    { mac: B, ips: ['192.168.1.77'], leased: [] },
    null, { ips: ['10.0.0.1'] }
  ]);
  assert.deepEqual([...owners], [['192.168.1.23', A], ['192.168.1.77', X], ['2001:db8::23', A]],
    'the lease wins; two unleased claims: the first in the scan\'s order; a row with no MAC is no claim');
  assert.deepEqual([...plan.addressOwners(undefined)], []);
  assert.deepEqual([...plan.addressOwners([{ mac: A, ips: ['192.168.1.23'] }])], [['192.168.1.23', A]], 'a row with no `leased` (an older scan): its addresses by the neighbour table');
});

test('decide: the pins — every address of every device that belongs to a user, bound to its MAC; a borrowed address in nobody else\'s rule-set or counter', () => {
  const X = 'aa:bb:cc:dd:ee:0c', Y = 'aa:bb:cc:dd:ee:0d', F = 'aa:bb:cc:dd:ee:0f', E = 'aa:bb:cc:dd:ee:0e';
  const lu = plan.readLanUsers({
    config: { transparent: { enabled: true, unassigned: 'login' } },
    users: [
      { id: 'u-ali', target: 'srv-2' }, { id: 'u-bob', target: 'srv-3' }, { id: 'u-net', target: 'direct' },
      { id: 'u-cap', target: 'srv-2' }, { id: 'u-here', target: '' }
    ],
    devices: [
      { mac: A, userId: 'u-ali' }, { mac: X, userId: 'u-bob' }, { mac: B, userId: 'u-net' }, { mac: C, userId: 'u-cap' },
      { mac: D, userId: 'u-here' }, { mac: E, userId: 'u-ali', blocked: true }
    ]
  });
  const sessions = { [F]: { userId: 'u-ali', until: NOW + 3600000 } };
  const scan = [
    // bob's X took alice's A's leased address (A is away) and answers for it
    { mac: X, ips: ['192.168.1.23', '192.168.1.24'], leased: ['192.168.1.24'] },
    { mac: A, ips: ['192.168.1.23', '2001:db8::23', '2001:db8::a:23'], leased: ['192.168.1.23'] },
    { mac: B, ips: ['192.168.1.40'], leased: ['192.168.1.40'] },
    { mac: C, ips: ['192.168.1.30'], leased: [] },
    { mac: D, ips: ['192.168.1.50'], leased: [] },
    { mac: E, ips: ['192.168.1.60'], leased: [] },
    { mac: F, ips: ['192.168.1.66'], leased: [] },
    { mac: Y, ips: ['192.168.1.99'], leased: [] }      // nobody's: pinned to nothing
  ];
  const d = plan.decide({ lu, sessions, scan, usage: { 'u-cap': { over: true } }, now: NOW,
    tp: [{ tag: 'lu-tp-1', target: 'srv-2' }, { tag: 'lu-tp-2', target: 'srv-3' }], portal: { ip: '192.168.1.1', port: 30822 } });
  assert.deepEqual(d.nft.ipmac, [
    { mac: A, ips: ['192.168.1.23', '2001:db8::23', '2001:db8::a:23'] },   // routed: every address, both families
    { mac: B, ips: ['192.168.1.40'] },                                     // direct: around the tunnel, still charged by address
    { mac: C, ips: ['192.168.1.30'] },                                     // held: meets the gate as itself
    { mac: D, ips: ['192.168.1.50'] },                                     // the router's own connection: still someone's cap
    { mac: X, ips: ['192.168.1.24'] },                                     // only its own: .23 is A's lease
    { mac: E, ips: ['192.168.1.60'] },                                     // blocked, but someone's: no one rides its address either
    { mac: F, ips: ['192.168.1.66'] }                                      // signed in
  ]);
  assert.deepEqual(d.ruleSets, { 'lu-tp-1': ['192.168.1.23/32', '2001:db8::23/128', '2001:db8::a:23/128', '192.168.1.66/32'], 'lu-tp-2': ['192.168.1.24/32'] },
    'A\'s address is in alice\'s rule-set only — not in bob\'s for the device that took it');
  const ctr = Object.fromEntries(d.nft.counters.map(c => [c.mac, c.ips]));
  assert.deepEqual([ctr[A], ctr[X], ctr[Y]], [['192.168.1.23', '2001:db8::23', '2001:db8::a:23'], ['192.168.1.24'], ['192.168.1.99']], 'the down counter of an address is its owner\'s');
  // the text that reaches the kernel: X's MAC is not A's, so X sending from .23 is dropped
  const text = require('../src/main/openwrtNet').buildNftRuleset({ lanUsers: d.nft });
  assert.ok(text.includes(`192.168.1.23 . ${A}`) && !text.includes(`192.168.1.23 . ${X}`), text);
  assert.ok(!/192\.168\.1\.99 \./.test(text), 'nobody\'s device: no pin');
});

test('ruleSetText: sing-box\'s source format, version 1 — every sing-box from 1.8 reads it; no device is an empty list, not an invalid rule', () => {
  assert.equal(plan.ruleSetText(['192.168.1.23/32']), '{\n  "version": 1,\n  "rules": [\n    {\n      "source_ip_cidr": [\n        "192.168.1.23/32"\n      ]\n    }\n  ]\n}\n');
  assert.deepEqual(JSON.parse(plan.ruleSetText([])), { version: 1, rules: [] });
});

/* ------------------------------ sing-box: the per-target routes ------------------------------ */

test('buildTunConfig lanRoutes: a socks outbound per config, a rule over its local rule-set file; absent or junk — the config of before', () => {
  const base = JSON.stringify(buildTunConfig({ socksPort: 30808, udpTimeout: 120 }));
  assert.equal(JSON.stringify(buildTunConfig({ socksPort: 30808, udpTimeout: 120, lanRoutes: null })), base);
  assert.equal(JSON.stringify(buildTunConfig({ socksPort: 30808, udpTimeout: 120, lanRoutes: { targets: [] } })), base);
  assert.equal(JSON.stringify(buildTunConfig({ socksPort: 30808, udpTimeout: 120, lanRoutes: { targets: [{ tag: 'x', port: 1, path: '/a' }, { tag: 'lu-tp-1', port: 0, path: '/a' }, { tag: 'lu-tp-2', port: 2, path: 'rel.json' }] } })), base);
  const cfg = buildTunConfig({ socksPort: 30808, lanRoutes: { targets: [
    { tag: 'lu-tp-1', port: 41001, path: '/tmp/irnetfree-lu/lu-tp-1.json' },
    { tag: 'lu-tp-2', port: 41002, path: '/tmp/irnetfree-lu/lu-tp-2.json' },
    { tag: 'lu-tp-1', port: 41003, path: '/tmp/x.json' }
  ] } });
  assert.deepEqual(cfg.outbounds, [
    { type: 'socks', tag: 'socks-out', server: '127.0.0.1', server_port: 30808, version: '5' },
    { type: 'socks', tag: 'lu-tp-1', server: '127.0.0.1', server_port: 41001, version: '5' },
    { type: 'socks', tag: 'lu-tp-2', server: '127.0.0.1', server_port: 41002, version: '5' }
  ]);
  assert.deepEqual(cfg.route, {
    final: 'socks-out', auto_detect_interface: true,
    rules: [{ rule_set: ['lu-tp-1'], outbound: 'lu-tp-1' }, { rule_set: ['lu-tp-2'], outbound: 'lu-tp-2' }],
    rule_set: [
      { type: 'local', tag: 'lu-tp-1', format: 'source', path: '/tmp/irnetfree-lu/lu-tp-1.json' },
      { type: 'local', tag: 'lu-tp-2', format: 'source', path: '/tmp/irnetfree-lu/lu-tp-2.json' }
    ]
  }, 'what no device rule claims stays on the current connection');
});

test('writeConfig hands the routes to buildTunConfig on a router only — a desktop TunSingbox ignores them', () => {
  const { TunSingbox } = require('../src/main/tunSingbox');
  const lanUsers = { singbox: { targets: [{ tag: 'lu-tp-1', port: 41001, path: '/tmp/irnetfree-lu/lu-tp-1.json' }] } };
  for (const composedBy of ['openwrt', null]) {
    const t = new TunSingbox({ binDir: '/nonexistent', composedBy, platform: 'linux' });
    const { cfgFile } = t.writeConfig(30808, [], { lanUsers }, 'IRNetFree');
    const cfg = JSON.parse(require('fs').readFileSync(cfgFile, 'utf8'));
    t.removeWork();
    assert.equal(cfg.outbounds.some(o => o.tag === 'lu-tp-1'), composedBy === 'openwrt', String(composedBy));
  }
});

/* ------------------------------ the core: loopback inbounds ------------------------------ */

test('the core: one loopback SOCKS per config, routed before the catch-all; the selected server reused, another built and bound to the WAN; a config gone rides the default', () => {
  const config = buildConfig({ mode: 'single', server: SRV1 }, { socksPort: 30808, httpPort: 30809, apiPort: 30085, routingMode: 'global', blockAds: false, directInterface: 'eth0' });
  const records = { serversById: { 'srv-1': SRV1, 'srv-2': SRV2, 'srv-3': SRV3 }, chainsById: { c1: [SRV2, SRV3] } };
  const tp = [{ tag: 'lu-tp-1', port: 41001, target: 'chain:c1' }, { tag: 'lu-tp-2', port: 41002, target: 'srv-1' }, { tag: 'lu-tp-3', port: 41003, target: 'srv-2' }, { tag: 'lu-tp-4', port: 41004, target: 'srv-gone' }];
  const r = applyTransparentTargets(config, tp, { serverId: 'srv-1', plan: { mode: 'single', server: SRV1 }, records, directInterface: 'eth0' });
  assert.deepEqual(r.applied.map(a => [a.tag, a.outboundTag, a.gone]), [['lu-tp-1', 'lu-tp-1-out', false], ['lu-tp-2', 'proxy', false], ['lu-tp-3', 'lu-tp-3-out', false], ['lu-tp-4', 'proxy', true]]);
  assert.deepEqual(r.applied[0].entryAddrs, ['192.0.2.20'], 'the chain\'s first hop, kept off the tunnel');
  const inb = config.inbounds.find(i => i.tag === 'lu-tp-3');
  assert.deepEqual(inb, { tag: 'lu-tp-3', port: 41003, listen: '127.0.0.1', protocol: 'socks', settings: { auth: 'noauth', udp: true }, sniffing: config.inbounds[0].sniffing });
  const rules = config.routing.rules;
  const tail = rules.length - 1;
  assert.deepEqual(rules[tail], { type: 'field', port: '0-65535', outboundTag: 'proxy' }, 'the catch-all stays last');
  assert.deepEqual(rules.slice(tail - 4, tail).map(x => x.inboundTag[0]), ['lu-tp-1', 'lu-tp-2', 'lu-tp-3', 'lu-tp-4']);
  const out3 = config.outbounds.find(o => o.tag === 'lu-tp-3-out');
  assert.equal(out3.streamSettings.sockopt.interface, 'eth0', 'bound to the WAN: an unbound dial would re-enter the whole-LAN tunnel');
  const hop = config.outbounds.find(o => o.tag === 'lu-tp-1-out');
  assert.equal(hop.streamSettings.sockopt.dialerProxy, 'lu-tp-1-out-h0', 'the chain\'s exit dials through its hop');
});

/* ------------------------------ the controller ------------------------------ */

function controller({ settings = { modules: { lanUsers: true } }, store, lan = fakeLan(), meter = fakeMeter(), now } = {}) {
  const files = memFs();
  const logs = [];
  let clock = now || NOW;
  const r = createLanRouter({
    openwrt: true, dataDir: '/etc/irnetfree', tmpDir: '/tmp', fs: files, run: lan.run, readFile: lan.readFile,
    getSettings: () => settings, getLanUsers: () => store, records: () => ({ servers: [SRV1, SRV2], groups: [], chains: [] }),
    getFreePorts: async (n) => Array.from({ length: n }, (_, i) => 41001 + i), log: (line, level) => logs.push([level, line]),
    now: () => clock, meter, tickMs: 3600000
  });
  return { r, files, logs, lan, meter, advance: (ms) => { clock += ms; } };
}

test('off — the module not installed, or the mode not on: no ports, nothing in the core\'s config, no gateway option, nothing kept off the tunnel', async () => {
  const store = { config: { transparent: { enabled: true } }, users: [{ id: 'u1', target: 'srv-2' }] };
  for (const settings of [{}, { modules: {} }, { modules: { lanUsers: true } }]) {
    const st = settings.modules && settings.modules.lanUsers ? { config: { transparent: { enabled: false } }, users: store.users } : store;
    const { r, lan } = controller({ settings, store: st });
    const tp = await r.prepare();
    assert.deepEqual(tp, []);
    const config = buildConfig({ mode: 'single', server: SRV1 }, { socksPort: 30808, httpPort: 30809, apiPort: 30085 });
    const before = JSON.stringify(config);
    assert.equal(r.applyXray(config, { settings: { lanUsersTp: tp } }), null);
    assert.equal(JSON.stringify(config), before);
    assert.equal(await r.gatewayOptions(tp), null);
    assert.deepEqual(r.entryAddrs(tp), []);
    await r.gatewayUp(fakeGateway());
    assert.equal(r.portal, null);
    assert.deepEqual(lan.calls, [], 'not even a read of the LAN');
  }
});

test('caps: the table\'s counters feed the meter per user; over the cap its devices are held, the new period lets them through — said in the log', async () => {
  const lan = fakeLan({ neigh: `192.168.1.23 lladdr ${A} REACHABLE\n192.168.1.99 lladdr ${C} REACHABLE\n` });
  const meter = fakeMeter({ 'u-ali': 1000 });
  const store = { config: { transparent: { enabled: true, unassigned: 'allow' } }, users: [{ id: 'u-ali', name: 'Ali', target: 'srv-2', enabled: true, quotaPeriod: 'month' }], devices: [{ mac: A, userId: 'u-ali' }] };
  const c = controller({ store, lan, meter });
  const tp = await c.r.prepare();
  assert.deepEqual(tp.map(e => [e.tag, e.port, e.target]), [['lu-tp-1', 41001, 'srv-2']]);
  const config = buildConfig({ mode: 'single', server: SRV1 }, { socksPort: 30808, httpPort: 30809, apiPort: 30085 });
  c.r.applyXray(config, { serverId: 'srv-1', plan: { mode: 'single', server: SRV1 }, settings: { lanUsersTp: tp } });
  const opts = await c.r.gatewayOptions(tp);
  assert.deepEqual(opts.nft.allowed, [A]);
  assert.deepEqual(opts.singbox.targets, [{ tag: 'lu-tp-1', port: 41001, path: '/tmp/irnetfree-lu/lu-tp-1.json' }]);
  assert.deepEqual(JSON.parse(c.files.get('/tmp/irnetfree-lu/lu-tp-1.json')).rules, [{ source_ip_cidr: ['192.168.1.23/32'] }]);
  assert.deepEqual(c.r.entryAddrs(tp), ['192.0.2.20']);
  const gw = fakeGateway();
  gw.tableGen = 1;               // the start's own load
  await c.r.gatewayUp(gw);
  lan.counters = { [A]: { up: 300, down: 400 }, [C]: { up: 50, down: 50 } };
  await c.r.tick();
  assert.deepEqual(meter.fed, [{ 'u-ali': { up: 300, down: 400, bytes: 700 } }], 'a device with no user is counted, not fed');
  assert.equal(gw.loads.length, 0, 'nothing changed: the table is not reloaded');
  c.advance(10000);
  lan.counters = { [A]: { up: 500, down: 800 }, [C]: { up: 50, down: 50 } };
  await c.r.tick();
  assert.deepEqual(meter.fed[1], { 'u-ali': { up: 200, down: 400, bytes: 600 } }, 'only what is new since the last read');
  const held = gw.loads[gw.loads.length - 1];
  assert.deepEqual(held.blocked, [A], 'over its cap: held (allow mode has no page to explain, so: dropped)');
  assert.deepEqual(held.allowed, []);
  assert.ok(c.logs.some(([lvl, l]) => lvl === 'warn' && /"Ali" reached its data cap/.test(l)), JSON.stringify(c.logs));
  assert.deepEqual(c.r.deviceUsage(), { [A]: 1300, [C]: 100 });
  const on = c.r.online();
  assert.equal(on[A].userId, 'u-ali');
  assert.deepEqual([on[A].up, on[A].down], [20, 40], 'bytes/s over the last read');
  // the reload started its counters from zero: the next read is all new
  lan.counters = { [A]: { up: 0, down: 0 }, [C]: { up: 5, down: 5 } };
  meter.newPeriod();
  c.advance(10000);
  await c.r.tick();
  assert.deepEqual(gw.loads[gw.loads.length - 1].allowed, [A], 'the new period lets it through again');
  assert.ok(c.logs.some(([, l]) => /"Ali" has data again/.test(l)));
  assert.equal(c.r.pendingReconnect(), false);
  store.users = [...store.users, { id: 'u-new', target: 'srv-1' }];
  assert.equal(c.r.pendingReconnect(), true, 'a new config needs its inbound: a reconnect');
  gw.active = false;
  await c.r.tick();
  assert.equal(c.r.pendingReconnect(), false, 'the gateway gone: nothing to reconnect');
  assert.ok(c.files.get('/etc/irnetfree/lan-device-usage.json'), 'the devices\' usage saved when the gateway went');
});

test('the pins follow the devices: a new lease moves the rule-set file and the table\'s pin in the same tick; a device taking an assigned one\'s address moves neither', async () => {
  const X = 'aa:bb:cc:dd:ee:0c';
  const until = NOW / 1000 + 86400;
  const lan = fakeLan({ leases: `${until} ${A} 192.168.1.23 phone *\n`, neigh: `192.168.1.23 lladdr ${A} REACHABLE\n` });
  const store = { config: { transparent: { enabled: true, unassigned: 'allow' } }, users: [{ id: 'u-ali', name: 'Ali', target: 'srv-2', enabled: true }], devices: [{ mac: A, userId: 'u-ali' }] };
  const c = controller({ store, lan });
  const tp = await c.r.prepare();
  const config = buildConfig({ mode: 'single', server: SRV1 }, { socksPort: 30808, httpPort: 30809, apiPort: 30085 });
  c.r.applyXray(config, { serverId: 'srv-1', plan: { mode: 'single', server: SRV1 }, settings: { lanUsersTp: tp } });
  const opts = await c.r.gatewayOptions(tp);
  assert.deepEqual(opts.nft.ipmac, [{ mac: A, ips: ['192.168.1.23'] }], 'the gateway starts with the pin in its first table');
  const file = () => JSON.parse(c.files.get('/tmp/irnetfree-lu/lu-tp-1.json')).rules;
  assert.deepEqual(file(), [{ source_ip_cidr: ['192.168.1.23/32'] }]);
  const gw = fakeGateway();
  await c.r.gatewayUp(gw);
  const table = () => (gw.loads.length ? gw.loads[gw.loads.length - 1] : opts.nft);

  // A away, X (nobody's — allow mode lets it through by its own MAC) took .23 and answers for it
  lan.neigh = `192.168.1.23 lladdr ${X} REACHABLE\n`;
  await c.r.tick();
  assert.deepEqual(table().ipmac, [{ mac: A, ips: ['192.168.1.23'] }], 'the address stays A\'s (its lease): X\'s packets from it are dropped');
  assert.deepEqual(file(), [{ source_ip_cidr: ['192.168.1.23/32'] }]);
  assert.deepEqual(table().counters.find(x => x.mac === X), { mac: X, ips: [] }, 'X is counted, but .23\'s bytes are A\'s');

  // a DHCP renewal hands A another address: the file and the pin move together, in one tick
  lan.leases = `${until} ${A} 192.168.1.50 phone *\n`;
  lan.neigh = `192.168.1.50 lladdr ${A} REACHABLE\n`;
  const loads = gw.loads.length;
  await c.r.tick();
  assert.equal(gw.loads.length, loads + 1, 'one table load');
  assert.deepEqual(table().ipmac, [{ mac: A, ips: ['192.168.1.50'] }]);
  assert.deepEqual(file(), [{ source_ip_cidr: ['192.168.1.50/32'] }]);

  // A unassigned: nobody's device, pinned to nothing — the table as it is for any device of no one
  store.devices = [];
  await c.r.tick();
  assert.deepEqual(table().ipmac, []);
  assert.deepEqual(file(), []);
});

test('the devices list counts each device in its user’s month — a Persian-month user’s under j1405-08, the running month’s count carried', async () => {
  const lan = fakeLan({ neigh: `192.168.1.23 lladdr ${A} REACHABLE\n` });
  const files = memFs();
  // saved before the user's cap followed the Persian month: October's count
  files.writeFileSync('/etc/irnetfree/lan-device-usage.json', JSON.stringify({ [A]: { period: '2026-10', bytes: 1000 }, [C]: { period: '2026-10', bytes: 50 }, [D]: { period: '2026-09', bytes: 70 } }));
  const store = { config: { transparent: { enabled: true, unassigned: 'allow' } }, users: [{ id: 'u-ali', name: 'Ali', target: 'srv-2', enabled: true, quotaPeriod: 'month', quotaCalendar: 'jalali' }], devices: [{ mac: A, userId: 'u-ali' }] };
  const r = createLanRouter({
    openwrt: true, dataDir: '/etc/irnetfree', tmpDir: '/tmp', fs: files, run: lan.run, readFile: lan.readFile,
    getSettings: () => ({ modules: { lanUsers: true } }), getLanUsers: () => store, records: () => ({ servers: [SRV1, SRV2], groups: [], chains: [] }),
    getFreePorts: async (n) => Array.from({ length: n }, (_, i) => 41001 + i), log: () => {}, now: () => NOW, meter: fakeMeter(), tickMs: 3600000
  });
  assert.deepEqual(r.deviceUsage(), { [A]: 1000, [C]: 50 }, 'October overlaps Aban: carried; an unbound device by the Gregorian month; September is over');
  await r.gatewayOptions(await r.prepare());
  const gw = fakeGateway();
  gw.tableGen = 1;
  await r.gatewayUp(gw);
  lan.counters = { [A]: { up: 100, down: 200 } };
  await r.tick();
  assert.deepEqual(r.deviceUsage(), { [A]: 1300, [C]: 50 });
  await r.stop();
  assert.deepEqual(JSON.parse(files.get('/etc/irnetfree/lan-device-usage.json'))[A], { period: 'j1405-08', bytes: 1300 });
});

/* ------------------------------ the service on a "router" ------------------------------ */

test('the service: with the module and the mode on, the core gets the inbound and the gateway the users\' sets; off, neither', async () => {
  process.env.IRNETFREE_PLATFORM = 'openwrt';
  const fs = require('fs'), os = require('os'), path = require('path');
  const { createService } = require('../src/server/service');
  const fakes = require('./gatewayFakes');
  const lan = fakeLan({ neigh: `192.168.1.23 lladdr ${A} REACHABLE\n` });
  const files = memFs();
  const run = async (on) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-svc-lu-'));
    try {
      const settings = Object.assign({ autoUpdateSubs: false, autoUpdateAssets: 'off', autoConnect: false, tunMode: true, lang: 'en', socksPort: 47808, httpPort: 47809, apiPort: 47885 },
        // off = not installed, the extensions' one-time migration already done (else the users in the store install it)
        on ? { modules: { lanUsers: true }, modulesMigrated: true } : { modules: {}, modulesMigrated: true });
      fs.writeFileSync(path.join(dir, 'store.json'), JSON.stringify({ servers: [SRV1, SRV2], routerDefaultsApplied: true, settings,
        lanUsers: { config: { transparent: { enabled: true, unassigned: 'allow' } }, users: [{ id: 'u-ali', username: 'ali', password: 'pw12', target: 'srv-2', enabled: true }], devices: [{ mac: A, userId: 'u-ali' }] } }));
      const state = fakes.makeState();
      const service = createService({ dataDir: dir, deps: fakes.deps(state, {
        lanRouter: (o) => createLanRouter(Object.assign({}, o, { fs: files, tmpDir: '/tmp', run: lan.run, readFile: lan.readFile, tickMs: 3600000 }))
      }) });
      await service.invoke('connect', 'srv-1');
      const cfg = state.xray.starts[state.xray.starts.length - 1].config;
      const gw = state.gateways[state.gateways.length - 1];
      const out = { inbound: cfg.inbounds.find(i => i.tag === 'lu-tp-1') || null, lanUsers: gw.lanUsers, bypass: state.inners[state.inners.length - 1].bypass };
      await service.invoke('disconnect');
      return out;
    } finally { try { fs.rmSync(dir, { recursive: true, force: true }); } catch {} }
  };
  const on = await run(true);
  assert.equal(on.inbound.listen, '127.0.0.1');
  assert.deepEqual(on.lanUsers.allowed, [A]);
  assert.ok(on.bypass.includes('192.0.2.20'), 'the user\'s config is kept off the tunnel: ' + on.bypass.join(', '));
  const off = await run(false);
  assert.equal(off.inbound, null);
  assert.equal(off.lanUsers, null);
  assert.ok(!off.bypass.includes('192.0.2.20'));
});
