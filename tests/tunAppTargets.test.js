'use strict';
/**
 * Per-app configs under the sing-box TUN (src/main/tunAppTargets.js): each
 * listed app rides a config of its own through a loopback Xray SOCKS inbound
 * `pa-<n>` — the users module's transparent-mode machinery
 * (src/main/targetOutbounds.js) chosen by `process_name` instead of a
 * source-address rule-set.
 *
 * Pinned here: how the decision's targets are bound to inbounds and ports
 * (a gone target blocked, never the connection), the Xray side through the
 * app's own builder (inbounds, rules where the users' go, outbounds every pass
 * reaches, one outbound per target shared with the plan and the users), not a
 * byte changed without it, the users' output unchanged beside it, a reload's
 * same ports, and the connect step main.js and the service share.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { buildConfig } = require('../src/main/configBuilder');
const { groupRecord } = require('../src/main/groups');
const PA = require('../src/main/tunAppTargets');
const { recordsForTargets, targetOutbounds } = require('../src/main/targetOutbounds');
const F = require('./fixtures');

const MANAGED = { dnsManaged: true, dnsRemote: ['https://1.1.1.1/dns-query'], dnsDirect: ['178.22.122.100'] };
const GROUP = groupRecord({ id: 'grp-1', name: 'G', strategy: 'roundRobin', members: [{ id: 'sv-trojan' }, { id: 'sv-ss' }] }, { 'sv-trojan': F.TROJAN_TCP_TLS, 'sv-ss': F.SS_TCP });
const single = { mode: 'single', server: F.VLESS_WS_TLS };

/** The build input main.js makes (connectAppRoutes): the inbounds and the records their targets name. */
function routes(inbounds, over) {
  return Object.assign({
    inbounds,
    serversById: { 'sv-trojan': F.TROJAN_TCP_TLS, 'sv-ss': F.SS_TCP, 'sv-vless': F.VLESS_WS_TLS, 'grp-1': GROUP },
    chainsById: { c1: [F.SS_TCP, F.TROJAN_TCP_TLS] }
  }, over);
}
const inbound = (cfg, tag) => cfg.inbounds.find((i) => i.tag === tag);
const ruleOf = (cfg, tag) => cfg.routing.rules.find((r) => Array.isArray(r.inboundTag) && r.inboundTag.length === 1 && r.inboundTag[0] === tag);

/* ------------------------------ binding the decision ------------------------------ */

test('loopbackTargets: the configs the listed apps name, each once, in list order — never "", direct or block', () => {
  const apps = { mode: 'exclude', names: ['a.exe', 'b.exe', 'c.exe', 'd.exe', 'e.exe', 'f.exe'], to: { 'a.exe': 'sv-trojan', 'b.exe': '', 'c.exe': 'block', 'd.exe': 'chain:c1', 'e.exe': 'sv-trojan', 'f.exe': 'direct', 'z.exe': 'grp-1' } };
  assert.deepEqual(PA.loopbackTargets(apps), ['sv-trojan', 'chain:c1']);
  assert.deepEqual(PA.loopbackTargets({ mode: 'exclude', names: ['a.exe'] }), []);
  assert.deepEqual(PA.loopbackTargets(null), []);
});

test('bindAppTargets: without `to` the decision goes to the TUN untouched — the config of before', () => {
  const apps = { mode: 'exclude', names: ['chrome.exe'] };
  const b = PA.bindAppTargets(apps, { ports: [41300] });
  assert.equal(b.apps, apps);
  assert.deepEqual(b.inbounds, []);
  assert.deepEqual(PA.bindAppTargets(null), { apps: null, inbounds: [], gone: [] });
});

test('bindAppTargets: each config a `pa-<n>` on its port; the connection, direct and block as words; a gone or portless one blocked', () => {
  const apps = { mode: 'exclude', names: ['a.exe', 'b.exe', 'c.exe', 'd.exe', 'e.exe', 'f.exe'], to: { 'a.exe': 'sv-trojan', 'b.exe': '', 'c.exe': 'block', 'd.exe': 'srv-gone', 'e.exe': 'chain:c1', 'f.exe': 'sv-trojan' } };
  const b = PA.bindAppTargets(apps, { ports: [41300, 41301, 41302], gone: (t) => t === 'srv-gone' });
  assert.deepEqual(b.inbounds, [{ tag: 'pa-0', port: 41300, target: 'sv-trojan' }, { tag: 'pa-1', port: 41302, target: 'chain:c1' }]);
  assert.deepEqual(b.apps, {
    mode: 'exclude', names: ['a.exe', 'b.exe', 'c.exe', 'd.exe', 'e.exe', 'f.exe'],
    to: { 'a.exe': 'pa-0', 'b.exe': 'tunnel', 'c.exe': 'block', 'd.exe': 'block', 'e.exe': 'pa-1', 'f.exe': 'pa-0' },
    loopbacks: [{ tag: 'pa-0', port: 41300 }, { tag: 'pa-1', port: 41302 }]
  });
  assert.deepEqual(b.gone, [{ name: 'd.exe', target: 'srv-gone' }]);
  // no port for a config: blocked too (and not reported as gone — it is still there)
  const short = PA.bindAppTargets({ mode: 'only', names: ['a.exe'], to: { 'a.exe': 'sv-trojan' } }, { ports: [] });
  assert.deepEqual(short.apps.to, { 'a.exe': 'block' });
  assert.deepEqual(short.gone, []);
});

test('goneLine names the app and what to do; namesFor finds the apps riding a target', () => {
  assert.match(PA.goneLine('Telegram.exe', 'srv-9'), /^Per-app routing: the config of Telegram\.exe \(srv-9\) no longer exists .* Telegram\.exe is blocked until another is picked$/);
  const ar = { inbounds: [{ tag: 'pa-0', port: 41300, target: 'sv-trojan' }, { tag: 'pa-1', port: 41301, target: 'chain:c1' }], names: { 'pa-0': ['a.exe', 'b.exe'], 'pa-1': ['c.exe'] } };
  assert.deepEqual(PA.namesFor(ar, 'sv-trojan'), ['a.exe', 'b.exe']);
  assert.deepEqual(PA.namesFor(ar, 'nope'), []);
  assert.deepEqual(PA.namesFor(null, 'sv-trojan'), []);
});

/* ------------------------------ the Xray side, through the builder ------------------------------ */

test('without appRoutes — absent, null, empty, or nothing writable — the config is byte-identical, every plan, plain and under TUN', () => {
  const plans = {
    single,
    chain: { mode: 'chain', chain: [F.VLESS_WS_TLS, F.TROJAN_TCP_TLS] },
    advanced: { mode: 'advanced', serversById: { 'sv-vless': F.VLESS_WS_TLS, 'sv-trojan': F.TROJAN_TCP_TLS }, chainsById: {}, chain: [], rules: [{ type: 'domain', value: 'a.com', target: 'sv-trojan' }], def: 'sv-vless' },
    pool: { mode: 'pool', entries: [{ id: 'e1', target: 'sv-trojan', socksPort: 60001 }], primary: 'sv-vless', serversById: { 'sv-vless': F.VLESS_WS_TLS, 'sv-trojan': F.TROJAN_TCP_TLS }, chainsById: {}, chain: [] }
  };
  for (const [name, plan] of Object.entries(plans)) {
    for (const base of [{}, MANAGED, Object.assign({ tunMode: true, directInterface: 'Wi-Fi' }, MANAGED)]) {
      const plain = JSON.stringify(buildConfig(plan, F.settings(base)));
      for (const ar of [null, undefined, {}, routes([]), routes([{ tag: 'x-0', port: 41300, target: 'sv-trojan' }, { tag: 'pa-1', port: 0, target: 'sv-trojan' }, { tag: 'pa-2', port: 41302, target: 'direct' }, { tag: 'pa-3', port: 41303, target: '' }])]) {
        assert.equal(JSON.stringify(buildConfig(plan, F.settings(Object.assign({}, base, { appRoutes: ar })))), plain, `${name} / ${JSON.stringify(ar && ar.inbounds)}`);
      }
    }
  }
});

test('on: one loopback SOCKS inbound per config — 127.0.0.1, no account, UDP, the app’s sniffing — beside the app’s own', () => {
  const cfg = buildConfig(single, F.settings({ appRoutes: routes([{ tag: 'pa-0', port: 41300, target: 'sv-trojan' }, { tag: 'pa-1', port: 41301, target: 'chain:c1' }]) }));
  assert.deepEqual(inbound(cfg, 'pa-0'), {
    tag: 'pa-0', port: 41300, listen: '127.0.0.1', protocol: 'socks', settings: { auth: 'noauth', udp: true },
    sniffing: { enabled: true, destOverride: ['http', 'tls', 'quic'], routeOnly: false }
  });
  assert.equal(inbound(cfg, 'pa-1').port, 41301);
  assert.deepEqual(cfg.inbounds.slice(0, 2).map((i) => i.tag), ['socks-in', 'http-in'], 'the app’s own inbounds first, as they were');
});

test('the rules: after the groups’ and the DNS rules, ahead of everything of the plan’s — each inbound → its config alone', () => {
  const cfg = buildConfig(single, F.settings(Object.assign({ routingMode: 'bypass-ir', appRoutes: routes([{ tag: 'pa-0', port: 41300, target: 'sv-trojan' }]) }, MANAGED)));
  const rules = cfg.routing.rules;
  const at = rules.findIndex((r) => (r.inboundTag || []).includes('pa-0'));
  assert.ok(at > 0, 'there are DNS rules before it');
  for (const r of rules.slice(0, at)) assert.ok((r.inboundTag && r.inboundTag.includes('dns-internal')) || r.outboundTag === 'dns-out', JSON.stringify(r));
  assert.deepEqual(rules[at], { type: 'field', inboundTag: ['pa-0'], outboundTag: 'pa-out-sv-trojan' });
  // the plan's bypass and catch-all come after: an app's traffic is its config's alone
  assert.ok(rules.findIndex((r) => r.outboundTag === 'direct' && Array.isArray(r.ip) && !r.inboundTag) > at);
  assert.deepEqual(rules[rules.length - 1], { type: 'field', port: '0-65535', outboundTag: 'proxy' });
});

test('the outbounds: a config of its own `pa-out-<id>`, shared with the plan when it dials that very target, chains and groups too, gone → block', () => {
  const cfg = buildConfig(single, F.settings(Object.assign({ tunMode: true, directInterface: 'Wi-Fi', appRoutes: routes([
    { tag: 'pa-0', port: 41300, target: 'sv-trojan' },
    { tag: 'pa-1', port: 41301, target: 'sv-vless' },        // the selection itself → `proxy`, one session
    { tag: 'pa-2', port: 41302, target: 'chain:c1' },
    { tag: 'pa-3', port: 41303, target: 'grp-1' },
    { tag: 'pa-4', port: 41304, target: 'srv-gone' },
    { tag: 'pa-5', port: 41305, target: 'chain:c-gone' }
  ]) }, MANAGED)));
  assert.equal(ruleOf(cfg, 'pa-0').outboundTag, 'pa-out-sv-trojan');
  assert.equal(ruleOf(cfg, 'pa-1').outboundTag, 'proxy');
  assert.equal(ruleOf(cfg, 'pa-2').outboundTag, 'pa-out-chain-c1');
  assert.equal(ruleOf(cfg, 'pa-4').outboundTag, 'block');
  assert.equal(ruleOf(cfg, 'pa-5').outboundTag, 'block');
  const tags = cfg.outbounds.map((o) => o.tag);
  assert.ok(tags.includes('pa-out-sv-trojan'));
  assert.equal(tags.filter((t) => t === 'proxy').length, 1, 'the selection is not dialled twice');
  // under TUN every dial of its own is bound to the physical NIC, like the plan's (bindDirectDials)
  const own = cfg.outbounds.find((o) => o.tag === 'pa-out-sv-trojan');
  assert.equal(own.streamSettings.sockopt.interface, 'Wi-Fi');
  // a group target is written out by expandGroups: the rule names its balancer
  const grp = ruleOf(cfg, 'pa-3');
  assert.ok(grp.balancerTag || grp.outboundTag, JSON.stringify(grp));
  assert.notEqual(grp.outboundTag, 'block');
});

test('a WireGuard config whose endpoint name nobody resolved is never handed to the core — that app is blocked, the connection untouched', () => {
  const wg = Object.assign({}, F.WG_BAD_MASK, { id: 'sv-wg' });
  const ar = (ips) => routes([{ tag: 'pa-0', port: 41300, target: 'sv-wg' }], { serversById: { 'sv-wg': wg }, wgEndpointIps: ips });
  const blind = buildConfig(single, F.settings({ appRoutes: ar({}) }));
  assert.equal(ruleOf(blind, 'pa-0').outboundTag, 'block');
  assert.ok(!blind.outbounds.some((o) => o.tag === 'pa-out-sv-wg'));
  const known = buildConfig(single, F.settings({ appRoutes: ar({ 'd.example.com': '198.51.100.7' }) }));
  assert.equal(ruleOf(known, 'pa-0').outboundTag, 'pa-out-sv-wg');
  assert.equal(known.outbounds.find((o) => o.tag === 'pa-out-sv-wg').settings.peers[0].endpoint, '198.51.100.7:51820');
});

test('a port the config already holds is left out; the pool builds them too', () => {
  const clash = buildConfig(single, F.settings({ appRoutes: routes([{ tag: 'pa-0', port: 10808, target: 'sv-trojan' }, { tag: 'pa-1', port: 41301, target: 'sv-ss' }]) }));
  assert.equal(clash.inbounds.filter((i) => i.port === 10808).length, 1);
  assert.equal(inbound(clash, 'pa-0'), undefined);
  assert.ok(inbound(clash, 'pa-1'));
  const pool = { mode: 'pool', entries: [{ id: 'e1', target: 'sv-trojan', socksPort: 60001 }], primary: 'sv-vless', serversById: { 'sv-vless': F.VLESS_WS_TLS, 'sv-trojan': F.TROJAN_TCP_TLS }, chainsById: {}, chain: [] };
  const p = buildConfig(pool, F.settings({ appRoutes: routes([{ tag: 'pa-0', port: 41300, target: 'sv-trojan' }, { tag: 'pa-1', port: 41301, target: 'sv-ss' }]) }));
  assert.ok(inbound(p, 'pa-0'));
  // the pool's entry already dials sv-trojan: shared, one outbound
  assert.equal(ruleOf(p, 'pa-0').outboundTag, 'out-sv-trojan');
  assert.equal(ruleOf(p, 'pa-1').outboundTag, 'pa-out-sv-ss');
});

test('beside the users module: the users’ part of the config is unchanged, and a config both ride is ONE outbound', () => {
  const LU = {
    config: { proxy: { enabled: true, port: 30820, httpPort: 30821 } },
    users: [{ id: 'usr-a', username: 'ali', password: 'pw-ali', name: '', target: 'sv-trojan', quotaGb: 0, quotaPeriod: 'month', expiresAt: 0, maxDevices: 0, enabled: true }],
    devices: [], over: [], now: 1_800_000_000_000,
    serversById: { 'sv-trojan': F.TROJAN_TCP_TLS }, chainsById: {}
  };
  const base = F.settings(Object.assign({ modules: { lanUsers: true }, lanUsers: LU }, MANAGED));
  const users = buildConfig(single, base);
  const both = buildConfig(single, Object.assign({}, base, { appRoutes: routes([{ tag: 'pa-0', port: 41300, target: 'sv-trojan' }, { tag: 'pa-1', port: 41301, target: 'sv-ss' }]) }));
  // the users' inbounds and rules, exactly as without the apps
  const luOnly = (cfg) => ({
    inbounds: cfg.inbounds.filter((i) => i.tag.startsWith('lu-')),
    rules: cfg.routing.rules.filter((r) => (r.inboundTag || []).some((t) => t.startsWith('lu-'))),
    outbounds: cfg.outbounds.filter((o) => o.tag.startsWith('lu-'))
  });
  assert.deepEqual(luOnly(both), luOnly(users));
  // sv-trojan: the user's outbound, shared; sv-ss: the app's own
  assert.equal(ruleOf(both, 'pa-0').outboundTag, 'lu-out-sv-trojan');
  assert.ok(!both.outbounds.some((o) => o.tag === 'pa-out-sv-trojan'), 'not dialled a second time');
  assert.equal(ruleOf(both, 'pa-1').outboundTag, 'pa-out-sv-ss');
});

test('targetOutbounds is the users’ old tag logic, by prefix: what lanUsersOutbounds answered, it still answers', () => {
  const X = require('../src/modules/lanUsers/xray');
  const ctx = {
    exitTag: 'proxy', serversById: { 'sv-trojan': F.TROJAN_TCP_TLS }, chainsById: { c1: [F.SS_TCP, F.TROJAN_TCP_TLS], c2: null },
    existingTag: (t) => (t === 'sv-vless' ? 'proxy' : null),
    server: (srv, tag) => [{ tag, protocol: 'x' }], chain: (list, tag) => [{ tag, protocol: 'y' }, { tag: tag + '-hop', protocol: 'z' }]
  };
  // the router's transparent inbounds name targets without any user behind them
  const lu = { config: { proxy: { enabled: false } }, users: [], devices: [], tp: ['', 'direct', 'block', 'sv-vless', 'sv-trojan', 'chain:c1', 'chain:c2', 'nope'].map((target, n) => ({ n, port: 41200 + n, target })) };
  const a = X.lanUsersOutbounds(lu, ctx);
  assert.deepEqual(a.tags, { '': 'proxy', direct: 'direct', block: 'block', 'sv-vless': 'proxy', 'sv-trojan': 'lu-out-sv-trojan', 'chain:c1': 'lu-out-chain-c1', 'chain:c2': 'block', nope: 'block' });
  assert.deepEqual(a.outbounds.map((o) => o.tag), ['lu-out-sv-trojan', 'lu-out-chain-c1', 'lu-out-chain-c1-hop']);
  assert.deepEqual(targetOutbounds(['sv-trojan'], ctx, 'pa-out-').tags, { 'sv-trojan': 'pa-out-sv-trojan' });
});

test('recordsForTargets: groups beside servers, a chain that lost a member is null, a name that is nothing is absent', () => {
  const store = {
    servers: [F.TROJAN_TCP_TLS, F.SS_TCP],
    groups: [{ id: 'grp-1', name: 'G', members: [{ id: 'sv-trojan' }, { id: 'sv-ss' }] }],
    chains: [{ id: 'c1', name: 'C', members: ['sv-ss', 'sv-trojan'] }, { id: 'c2', name: 'Broken', members: ['sv-ss', 'gone'] }]
  };
  const r = recordsForTargets(['sv-trojan', 'grp-1', 'chain:c1', 'chain:c2', 'chain:c3', 'nope', '', 'direct'], store);
  assert.deepEqual(Object.keys(r.serversById).sort(), ['grp-1', 'sv-trojan']);
  assert.deepEqual(r.chainsById.c1.map((s) => s.id), ['sv-ss', 'sv-trojan']);
  assert.equal(r.chainsById.c2, null);
  assert.equal(r.chainsById.c3, null);
});

/* ------------------------------ connect and reload ------------------------------ */

const STORE = {
  servers: [F.TROJAN_TCP_TLS, F.SS_TCP, Object.assign({}, F.WG_BAD_MASK, { id: 'sv-wg' })],
  groups: [],
  chains: [{ id: 'c1', name: 'Corp chain', members: ['sv-ss', 'sv-trojan'] }]
};

test('connectAppRoutes: free ports never one the config holds, the records, the bypass of their entry servers, labels for the log', async () => {
  const asked = [];
  const getFreePorts = async (n) => { asked.push(n); return [10808, 41300, 41301, 41302, 41303].slice(0, n); };
  const apps = { mode: 'exclude', names: ['a.exe', 'b.exe', 'c.exe', 'd.exe'], to: { 'a.exe': 'sv-trojan', 'b.exe': 'chain:c1', 'c.exe': 'srv-gone', 'd.exe': 'sv-wg' } };
  const r = await PA.connectAppRoutes({
    apps, store: STORE, getFreePorts, reserved: PA.reservedPorts({ socksPort: 10808, httpPort: 10809, apiPort: 10085 }),
    resolveWg: async (hosts) => Object.fromEntries(hosts.map((h) => [h, '198.51.100.7']))
  });
  assert.deepEqual(asked, [3 + 3], 'three live targets, room for the three reserved ports');
  assert.deepEqual(r.appRoutes.inbounds, [
    { tag: 'pa-0', port: 41300, target: 'sv-trojan' },
    { tag: 'pa-1', port: 41301, target: 'chain:c1' },
    { tag: 'pa-2', port: 41302, target: 'sv-wg' }
  ]);
  assert.deepEqual(r.apps.to, { 'a.exe': 'pa-0', 'b.exe': 'pa-1', 'c.exe': 'block', 'd.exe': 'pa-2' });
  assert.deepEqual(r.gone, [{ name: 'c.exe', target: 'srv-gone' }]);
  // dialled directly: the server's address, a chain's FIRST hop, the WireGuard endpoint as resolved
  assert.deepEqual(r.bypass, ['b.example.com', 'c.example.com', 'd.example.com', '198.51.100.7']);
  assert.deepEqual(r.appRoutes.wgEndpointIps, { 'd.example.com': '198.51.100.7' });
  assert.deepEqual(r.labels, { 'pa-0': 'Trojan', 'pa-1': 'Corp chain', 'pa-2': 'WireGuard' });
  assert.deepEqual(r.appRoutes.names, { 'pa-0': ['a.exe'], 'pa-1': ['b.exe'], 'pa-2': ['d.exe'] });
});

test('connectAppRoutes: no config to bind asks for no port; all gone is all blocked, and no appRoutes', async () => {
  let called = 0;
  const getFreePorts = async (n) => { called++; return Array.from({ length: n }, (_, i) => 41300 + i); };
  const plain = await PA.connectAppRoutes({ apps: { mode: 'exclude', names: ['a.exe'] }, store: STORE, getFreePorts });
  assert.equal(called, 0);
  assert.deepEqual(plain.apps, { mode: 'exclude', names: ['a.exe'] });
  assert.equal(plain.appRoutes, null);
  const words = await PA.connectAppRoutes({ apps: { mode: 'exclude', names: ['a.exe', 'b.exe'], to: { 'a.exe': 'block', 'b.exe': '' } }, store: STORE, getFreePorts });
  assert.equal(called, 0);
  assert.deepEqual(words.apps.to, { 'a.exe': 'block', 'b.exe': 'tunnel' });
  const gone = await PA.connectAppRoutes({ apps: { mode: 'exclude', names: ['a.exe'], to: { 'a.exe': 'srv-gone' } }, store: STORE, getFreePorts });
  assert.equal(gone.appRoutes, null);
  assert.deepEqual(gone.apps.to, { 'a.exe': 'block' });
  assert.deepEqual(gone.gone, [{ name: 'a.exe', target: 'srv-gone' }]);
});

test('reservedPorts: the config’s own listeners and the users’ proxy', () => {
  const r = PA.reservedPorts({ socksPort: 10808, httpPort: '10809', apiPort: 10085, apiCtlPort: 50000, chainRelayPort: 50001, lanUsers: { config: { proxy: { port: 30820, httpPort: 30821 } }, tp: [{ port: 41200 }] } });
  assert.deepEqual([...r].sort(), [10085, 10808, 10809, 30820, 30821, 41200, 50000, 50001]);
  assert.deepEqual([...PA.reservedPorts(null)], []);
});

test('reloadAppRoutes: the live inbounds on the same ports, records read again — a config deleted since is blocked and said', () => {
  const live = { inbounds: [{ tag: 'pa-0', port: 41300, target: 'sv-trojan' }, { tag: 'pa-1', port: 41301, target: 'sv-vless' }], serversById: {}, chainsById: {}, wgEndpointIps: { 'x': '1.2.3.4' }, names: { 'pa-1': ['b.exe'] } };
  const r = PA.reloadAppRoutes(live, STORE);
  assert.deepEqual(r.appRoutes.inbounds, live.inbounds);
  assert.deepEqual(r.gone, ['sv-vless']);
  assert.deepEqual(Object.keys(r.appRoutes.serversById), ['sv-trojan']);
  assert.deepEqual(r.appRoutes.wgEndpointIps, { x: '1.2.3.4' }, 'the connect’s pinned addresses: the tunnel’s bypass was cut for these');
  // built: the gone one's inbound stays (the tunnel points at it) and goes to block
  const cfg = buildConfig(single, F.settings({ appRoutes: r.appRoutes }));
  assert.equal(ruleOf(cfg, 'pa-1').outboundTag, 'proxy', 'sv-vless is the selection itself here — still the connection’s outbound');
  const other = buildConfig({ mode: 'single', server: F.SS_TCP }, F.settings({ appRoutes: r.appRoutes }));
  assert.equal(ruleOf(other, 'pa-1').outboundTag, 'block');
  assert.equal(inbound(other, 'pa-1').port, 41301);
  assert.deepEqual(PA.reloadAppRoutes(null, STORE), { appRoutes: null, gone: [] });
});

/* ------------------------------ the connect step (createPerApp) ------------------------------ */

function step(over) {
  const logs = [];
  const s = PA.createPerApp(Object.assign({
    storeLists: () => STORE,
    resolveHost: async () => ({ ips: ['198.51.100.7'] }),
    getFreePorts: async (n) => Array.from({ length: n }, (_, i) => 41300 + i),
    log: (l) => logs.push(l)
  }, over));
  return { s, logs };
}
const TUN = (backendId, extra) => Object.assign({ isAvailable: () => true, backendId }, extra);

test('forConnect: nothing without TUN mode or a backend that can run; the decision’s refusals come back to be said at the tunnel', async () => {
  const { s } = step();
  const on = { tunMode: true, tunAppMode: 'exclude', tunApps: ['a.exe'], tunAppTargets: { 'a.exe': 'sv-trojan' }, leakGuard: 'standard' };
  assert.equal(await s.forConnect(Object.assign({}, on, { tunMode: false }), TUN('sing-box')), null);
  assert.equal(await s.forConnect(on, TUN('sing-box', { isAvailable: () => false })), null);
  const t2s = await s.forConnect(on, TUN('tun2socks'));
  assert.deepEqual(t2s, { apps: null, warn: 'Per-app routing needs the sing-box TUN backend — ignored', appRoutes: null, bypass: [], labels: {} });
  const native = await s.forConnect(on, TUN('sing-box', { native: true }));
  assert.match(native.warn, /native macOS service/);
  const ok = await s.forConnect(on, TUN('sing-box'));
  assert.equal(ok.warn, null);
  assert.deepEqual(ok.appRoutes.inbounds, [{ tag: 'pa-0', port: 41300, target: 'sv-trojan' }]);
  assert.deepEqual(ok.apps.to, { 'a.exe': 'pa-0' });
});

test('forConnect under strict: a server config is kept (it stays inside the tunnel), a direct app rides the connection', async () => {
  const { s } = step();
  const r = await s.forConnect({ tunMode: true, leakGuard: 'strict', tunAppMode: 'exclude', tunApps: ['a.exe', 'b.exe'], tunAppTargets: { 'a.exe': 'sv-trojan' } }, TUN('sing-box'));
  assert.deepEqual(r.apps.names, ['a.exe']);
  assert.match(r.warn, /b\.exe ride the connection instead of going around the tunnel/);
  assert.deepEqual(r.bypass, ['b.example.com'], 'the strict firewall gets the config’s hole, like the connection’s');
});

test('forConnect / forReload: a gone config is said once per app and target, never again on a reconnect or a reload', async () => {
  const { s, logs } = step();
  const set = { tunMode: true, tunAppMode: 'exclude', tunApps: ['a.exe'], tunAppTargets: { 'a.exe': 'srv-gone' } };
  await s.forConnect(set, TUN('sing-box'));
  await s.forConnect(set, TUN('sing-box'));
  assert.equal(logs.filter((l) => /no longer exists/.test(l.line)).length, 1);
  const live = { inbounds: [{ tag: 'pa-0', port: 41300, target: 'sv-vless' }], names: { 'pa-0': ['b.exe'] } };
  s.forReload(live);
  s.forReload(live);
  const said = logs.filter((l) => /b\.exe/.test(l.line));
  assert.equal(said.length, 1);
  assert.equal(said[0].level, 'warn');
});

test('forConnect: a WireGuard name that does not resolve is said, left out — and that app is then blocked by the builder', async () => {
  const { s, logs } = step({ resolveHost: async () => ({ ips: [] }) });
  const r = await s.forConnect({ tunMode: true, tunAppMode: 'exclude', tunApps: ['a.exe'], tunAppTargets: { 'a.exe': 'sv-wg' } }, TUN('sing-box'));
  assert.deepEqual(r.appRoutes.wgEndpointIps, {});
  assert.ok(logs.some((l) => /WireGuard endpoint d\.example\.com does not resolve/.test(l.line)));
  const cfg = buildConfig(single, F.settings({ appRoutes: r.appRoutes }));
  assert.equal(ruleOf(cfg, 'pa-0').outboundTag, 'block');
  // the connection's own answer is used first (no second lookup, same address)
  const { s: s2 } = step({ resolveHost: async () => { throw new Error('must not ask'); } });
  const r2 = await s2.forConnect({ tunMode: true, tunAppMode: 'exclude', tunApps: ['a.exe'], tunAppTargets: { 'a.exe': 'sv-wg' }, wgEndpointIps: { 'd.example.com': '203.0.113.9' } }, TUN('sing-box'));
  assert.deepEqual(r2.appRoutes.wgEndpointIps, { 'd.example.com': '203.0.113.9' });
});

test('a TUIC / AnyTLS config cannot ride an app’s inbound (no Xray core has it): said by name, and the builder blocks it', async () => {
  const tuic = { id: 'sv-tuic', name: 'My TUIC', protocol: 'tuic', address: 't.example.com', port: 443, outbound: { protocol: 'tuic', settings: {} } };
  const { s, logs } = step({ storeLists: () => ({ servers: [tuic], groups: [], chains: [] }) });
  const r = await s.forConnect({ tunMode: true, tunAppMode: 'exclude', tunApps: ['a.exe'], tunAppTargets: { 'a.exe': 'sv-tuic' } }, TUN('sing-box'));
  assert.ok(logs.some((l) => l.level === 'warn' && /“My TUIC” is TUIC \/ AnyTLS/.test(l.line)));
  const cfg = buildConfig(single, F.settings({ appRoutes: r.appRoutes }));
  assert.equal(ruleOf(cfg, 'pa-0').outboundTag, 'block');
});

/* ------------------------------ the TUN side helpers ------------------------------ */

test('missingInbounds / blockRoutes: a core without the apps’ inbounds (sing-box’s own format, a raw JSON) blocks those apps', () => {
  const inbounds = [{ tag: 'pa-0', port: 41300, target: 'sv-trojan' }, { tag: 'pa-1', port: 41301, target: 'sv-ss' }];
  assert.deepEqual(PA.missingInbounds({ inbounds: [{ tag: 'socks-in' }, { tag: 'pa-1' }] }, inbounds), [inbounds[0]]);
  assert.deepEqual(PA.missingInbounds({ inbounds: [{ type: 'socks', tag: 'socks-in' }] }, inbounds), inbounds);
  const apps = { mode: 'exclude', names: ['a.exe', 'b.exe', 'c.exe'], to: { 'a.exe': 'pa-0', 'b.exe': 'pa-1', 'c.exe': 'block' }, loopbacks: [{ tag: 'pa-0', port: 41300 }, { tag: 'pa-1', port: 41301 }] };
  const b = PA.blockRoutes(apps, ['pa-0']);
  assert.deepEqual(b.apps.to, { 'a.exe': 'block', 'b.exe': 'pa-1', 'c.exe': 'block' });
  assert.deepEqual(b.apps.loopbacks, [{ tag: 'pa-1', port: 41301 }]);
  assert.deepEqual(b.names, ['a.exe']);
  assert.deepEqual(PA.blockRoutes(apps, []).apps, apps);
});

test('describeApps: the line of before without configs; with them, each app and where it goes', () => {
  assert.equal(PA.describeApps({ mode: 'exclude', names: ['a.exe', 'b.exe'] }), 'Per-app routing: these apps go around the tunnel — a.exe, b.exe');
  assert.equal(PA.describeApps({ mode: 'only', names: ['a.exe'] }), 'Per-app routing: only these apps use the tunnel — a.exe');
  const line = PA.describeApps({ mode: 'exclude', names: ['a.exe', 'b.exe', 'c.exe', 'd.exe'], to: { 'a.exe': 'pa-0', 'b.exe': 'block', 'd.exe': 'tunnel' } }, (tag) => ({ 'pa-0': 'Trojan' })[tag]);
  assert.equal(line, 'Per-app routing: a.exe → Trojan, b.exe → blocked, c.exe → direct, d.exe → the connection; every other app rides the connection');
  assert.equal(PA.describeApps(null), '');
});

test('appRoutesOf writes only what can be written: a pa-<n> tag once, a port, a target that needs an inbound', () => {
  assert.deepEqual(PA.appRoutesOf({ inbounds: [
    { tag: 'pa-0', port: 41300, target: 'sv-trojan' }, { tag: 'pa-0', port: 41301, target: 'sv-ss' },
    { tag: 'pa-1', port: '41302', target: 'sv-ss' }, { tag: 'pa-2', port: 41303, target: 'block' },
    { tag: 'lu-tp-0', port: 41304, target: 'sv-ss' }, { tag: 'pa-3', port: 41305, target: 'chain:c1' }, null, 'pa-4'
  ] }), [{ tag: 'pa-0', port: 41300, target: 'sv-trojan' }, { tag: 'pa-3', port: 41305, target: 'chain:c1' }]);
});
