'use strict';
/*
 * The warning that a connection's way out stopped answering: what it says for which plan, when it says it, and that the
 * router's service wires it to the window. Reached through the connect path, the window's half in renderer.test.js.
 */
process.env.IRNETFREE_PLATFORM = 'openwrt';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createRouteWatch, deadRouteNotice } = require('../src/main/routeWatch');
const { groupRecord } = require('../src/main/groups');
const F = require('./fixtures');
const H = require('./serviceHarness');

process.setMaxListeners(60);
test.after(() => H.cleanupDirs());
const R = (...p) => fs.readFileSync(path.join(__dirname, '..', ...p), 'utf8').replace(/\r\n/g, '\n');

const byId = { 'sv-vless': F.VLESS_WS_TLS, 'sv-wg': F.WG_CORP };
const advanced = (def) => ({ mode: 'advanced', def, rules: [], serversById: byId, chainsById: { c1: [F.VLESS_WS_TLS, F.TROJAN_TCP_TLS], w1: [F.VLESS_WS_TLS, F.WG_CORP] }, chain: [] });

test('an advanced plan: the default by its name; DNS is named only when it leaves that way', () => {
  assert.deepEqual(deadRouteNotice(advanced('sv-vless'), {}), { id: 'routeDeadDns', name: F.VLESS_WS_TLS.name });
  assert.deepEqual(deadRouteNotice(advanced('sv-vless'), { dnsManaged: true }), { id: 'routeDeadDns', name: F.VLESS_WS_TLS.name });
  assert.deepEqual(deadRouteNotice(advanced('sv-vless'), { dnsManaged: false }), { id: 'routeDead', name: F.VLESS_WS_TLS.name });
  assert.deepEqual(deadRouteNotice(advanced('chain:c1'), {}, [{ id: 'c1', name: 'Work chain' }]), { id: 'routeDeadDns', name: 'Work chain' });
  assert.deepEqual(deadRouteNotice(advanced('chain:c1'), {}, []), { id: 'routeDeadDns', name: 'c1' });
});

test('an old store\'s plain "chain" default is named by its last hop, never the word "chain"', () => {
  const plan = Object.assign(advanced('chain'), { chain: [F.VLESS_WS_TLS, F.TROJAN_TCP_TLS] });
  assert.deepEqual(deadRouteNotice(plan, {}), { id: 'routeDeadDns', name: F.TROJAN_TCP_TLS.name });
});

test('nothing to watch: direct, block, a split-tunnel WireGuard, which never answers the test, a pool, no plan', () => {
  assert.equal(deadRouteNotice(advanced('direct')), null);
  assert.equal(deadRouteNotice(advanced('block')), null);
  assert.equal(deadRouteNotice(advanced('sv-wg')), null);
  assert.equal(deadRouteNotice(advanced('chain:w1')), null, 'a chain ending in one');
  assert.equal(deadRouteNotice({ mode: 'single', server: F.WG_CORP }), null);
  assert.equal(deadRouteNotice({ mode: 'chain', chain: [F.VLESS_WS_TLS, F.WG_CORP] }), null);
  assert.equal(deadRouteNotice({ mode: 'pool', entries: [] }), null);
  assert.equal(deadRouteNotice(null), null);
  assert.equal(deadRouteNotice({ mode: 'single', server: F.VLESS_WS_TLS }, { routingMode: 'direct' }), null);
});

test('a single server and a chain: said by name, in plain words', () => {
  assert.deepEqual(deadRouteNotice({ mode: 'single', server: F.VLESS_WS_TLS }), { id: 'serverDead', name: F.VLESS_WS_TLS.name });
  assert.deepEqual(deadRouteNotice({ mode: 'chain', name: 'Acme', chain: [F.VLESS_WS_TLS, F.TROJAN_TCP_TLS] }), { id: 'serverDead', name: 'Acme' });
  const group = groupRecord({ id: 'grp-g', name: 'Europe', strategy: 'leastPing', members: ['sv-vless'] }, byId);
  assert.deepEqual(deadRouteNotice({ mode: 'single', server: group }), { id: 'serverDead', name: 'Europe' });
});

const FAST = { firstMs: 1, everyMs: 5, recheckMs: 2 };
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
function rig(answers, opts = {}) {
  const said = [];
  const asked = [];
  let i = 0;
  const w = createRouteWatch({
    probe: async (port) => { asked.push(port); const a = answers[Math.min(i++, answers.length - 1)]; if (a instanceof Error) throw a; return a; },
    onChange: (n) => said.push(n),
    busy: opts.busy,
    timing: FAST
  });
  return { w, said, asked };
}
const N = { id: 'routeDeadDns', name: 'x' };

test('one miss says nothing: two in a row do, once, and an answer takes it back', async () => {
  const one = rig([false, true]);
  one.w.start(N, 1234);
  await wait(40);
  one.w.stop();
  assert.deepEqual(one.said, [], 'a single miss is a hiccup');
  assert.equal(one.asked[0], 1234);

  const r = rig([false, false, false, false, true, true]);
  r.w.start(N, 1);
  await wait(80);
  assert.equal(r.w.notice(), null, 'answering again');
  r.w.stop();
  assert.deepEqual(r.said, [N, null]);
});

test('while it stands it asks at the short interval, so a false alarm leaves in seconds', async () => {
  const said = [];
  let answer = false;
  const w = createRouteWatch({ probe: async () => answer, onChange: (n) => said.push(n), timing: { firstMs: 1, everyMs: 100000, recheckMs: 2 } });
  w.start(N, 1);
  await wait(30);
  assert.deepEqual(said, [N]);
  answer = true;
  await wait(30);
  assert.deepEqual(said, [N, null], 'not after everyMs');
  w.stop();
});

test('a probe that throws is a miss, and the window opened later still learns it', async () => {
  const r = rig([new Error('refused')]);
  r.w.start(N, 1);
  await wait(30);
  assert.deepEqual(r.said, [N]);
  assert.deepEqual(r.w.notice(), N);
  r.w.stop();
  assert.equal(r.w.notice(), null);
});

test('during a connect or a recovery nothing is asked or counted, and stop() silences an answer on its way', async () => {
  let busy = true;
  const r = rig([false], { busy: () => busy });
  r.w.start(N, 1);
  await wait(25);
  assert.deepEqual(r.asked, []);
  assert.deepEqual(r.said, []);
  busy = false;
  await wait(30);
  assert.deepEqual(r.said, [N]);
  r.w.stop();

  let release;
  const late = createRouteWatch({ probe: () => new Promise((res) => { release = res; }), onChange: () => assert.fail('after stop'), timing: FAST });
  late.start(N, 1);
  await wait(10);
  late.stop();
  release(false);
  await wait(10);
});

test('start(null) watches nothing, and a new connection starts its count afresh', async () => {
  const r = rig([false]);
  r.w.start(null, 1);
  await wait(15);
  assert.deepEqual(r.asked, []);
  r.w.start(N, 1);
  await wait(30);
  assert.deepEqual(r.said, [N]);
  r.w.start(N, 2);
  assert.equal(r.w.notice(), null, 'nothing stands for the new connection yet');
  r.w.stop();
});

test('the router\'s service tells the window, in its snapshot too, and a disconnect ends it', async (t) => {
  let answer = false;
  const s = H.start({ settings: {} }, { probeTunnel: async () => answer, timing: { routeWatchFirstMs: 1, routeWatchEveryMs: 5, routeWatchRecheckMs: 2 } });
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', H.SERVER.id);
  const events = () => s.events.filter(([ch]) => ch === 'route-health').map(([, p]) => p.notice);
  await H.until(() => events().length === 1, 'the warning');
  assert.deepEqual(events()[0], { id: 'serverDead', name: H.SERVER.name });
  assert.deepEqual(s.service.connSnapshot().routeNotice, events()[0]);
  answer = true;
  await H.until(() => events().length === 2, 'taken back');
  assert.equal(events()[1], null);
  assert.equal(s.service.connSnapshot().routeNotice, null);
  answer = false;
  await s.service.invoke('disconnect');
  assert.equal(s.service.connSnapshot().routeNotice, null);
});

test('the desktop: the same watch, started when a connection stands, not for a raw JSON server, stopped with it', () => {
  const MAIN = R('src', 'main', 'main.js');
  assert.match(MAIN, /routeWatch\.start\(rawServerOf\(plan, settings, RAW_OPTS\) \? null : deadRouteNotice\(plan, settings, getChains\(\)\), settings\.socksPort\);\n  updateOverlay\('on'\);/);
  assert.match(MAIN, /stopNetWatcher\(\); +\/\/ nothing live to recover any more\n    routeWatch\.stop\(\);/);
  assert.match(MAIN, /routeNotice: routeWatch\.notice\(\)/);
  assert.match(MAIN, /busy: \(\) => conn\.state !== 'connected'/, 'proxy-only after a failed recovery is still connected');
  assert.match(R('src', 'preload', 'preload.js'), /onRouteHealth: \(cb\) => ipcRenderer\.on\('route-health'/);
  assert.match(R('src', 'server', 'web-api.js'), /onRouteHealth: \(cb\) => on\('route-health', cb\)/);
});

test('both languages say all three', () => {
  const src = R('src', 'renderer', 'i18n.js');
  for (const id of ['routeDeadDns', 'routeDead', 'serverDead']) {
    const lines = src.split('\n').filter((l) => l.includes(`'notice.${id}':`));
    assert.equal(lines.length, 2, id);
    for (const l of lines) assert.match(l, /\{name\}/, id);
  }
});
