'use strict';
/**
 * Mux decided per server (spec 2026-10-05 §4), driven through the headless
 * service's REAL connect and recovery paths on a "router" — the field report's
 * platform — with every seam faked (gatewayFakes.js) and the probe itself
 * handed in (deps.probeMux): no core runs, nothing leaves this machine. The
 * probe's own logic is pinned in mux.test.js; main.js does the same at the
 * same points (connectPath.test.js).
 *
 * What is pinned: `auto` tests each eligible server before its live config
 * is built and remembers the answer in the store (`muxProbes`); the config
 * carries mux exactly when the answer is "works"; an unknown is not
 * remembered; a muxed connection that drops is tested again; `on` and `off`
 * test nothing.
 */
process.env.IRNETFREE_PLATFORM = 'openwrt';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const h = require('./serviceHarness');
const { parseLink } = require('../src/main/parser');
const { MUX, muxFingerprint } = require('../src/main/mux');
const { Store } = require('../src/main/store');

process.setMaxListeners(40);   // every service registers its own exit hook
test.after(() => h.cleanupDirs());

// Every store.set('muxProbes', …) in this process, with the store's file: on a
// router each one rewrites the whole store.json on flash.
const muxWrites = [];
const realSet = Store.prototype.set;
Store.prototype.set = function (key, value) {
  if (key === 'muxProbes') muxWrites.push(this.filePath);
  return realSet.call(this, key, value);
};
const muxWritesOf = (s) => muxWrites.filter((f) => f === path.join(s.dir, 'store.json')).length;
const HOUR = 60 * 60 * 1000;

const UUID = '11111111-2222-3333-4444-555555555555';
// The field report's shape: VLESS over WebSocket + TLS with ECH, by address (no name to resolve here)
const WS = Object.assign(parseLink(`vless://${UUID}@104.21.44.18:2087?encryption=none&type=ws&host=h.example&path=/&security=tls&sni=h.example&ech=cloudflare-ech.com+udp://1.1.1.1#ws-server`), { id: 'srv-ws' });
const FP = muxFingerprint(WS);

/**
 * A router with the ws server; `answers` is what the probe says, in order (the
 * last one repeats); `memory` is the store's muxProbes it starts with.
 */
function router(settings = {}, answers = ['ok'], memory = undefined) {
  const probes = [];
  const probeMux = async (server, deps) => {
    probes.push({ server, deps });
    s.state.events.push('mux:probe ' + server.id);
    return answers[Math.min(probes.length - 1, answers.length - 1)];
  };
  const s = h.start(Object.assign({ servers: [WS, h.SERVER], settings }, memory ? { muxProbes: memory } : {}), { probeMux });
  s.probes = probes;
  return s;
}
const liveProxy = (s) => s.state.xray.starts.at(-1).config.outbounds.find((o) => o.tag === 'proxy');
const saved = (s) => JSON.parse(fs.readFileSync(path.join(s.dir, 'store.json'), 'utf8'));
const lines = (s, re) => s.logs.filter((l) => re.test(l.line));

test('auto (the default): the first connect tests the server before its core starts, muxes it, and remembers the answer', async (t) => {
  const s = router();
  t.after(() => s.service.shutdown());
  const before = Date.now();
  await s.service.invoke('connect', WS.id);
  assert.equal(s.probes.length, 1);
  assert.equal(s.probes[0].server.id, WS.id);
  assert.ok(s.state.events.indexOf('mux:probe srv-ws') < s.state.events.indexOf('xray:start'), 'tested before the live core starts');
  assert.deepEqual(liveProxy(s).mux, MUX);
  const memo = saved(s).muxProbes;
  assert.deepEqual(Object.keys(memo), [FP]);
  assert.equal(memo[FP].verdict, 'ok');
  assert.ok(memo[FP].at >= before && memo[FP].at <= Date.now());
  assert.deepEqual(lines(s, /^Mux /).map((l) => [l.level, l.line]), [['info', 'Mux on for ws-server (tested: works)']]);
});

test('auto: a remembered "works" is not tested again — the next connect is muxed at once', async (t) => {
  const s = router();
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', WS.id);
  await s.service.invoke('disconnect');
  await s.service.invoke('connect', WS.id);
  assert.equal(s.probes.length, 1, 'one test for two connects');
  assert.deepEqual(liveProxy(s).mux, MUX);
  assert.equal(lines(s, /^Mux on for ws-server/).length, 2, 'one line per connect');
});

test('auto: the probe is handed the connect’s own tools — the live core’s engine, a test config without mux', async (t) => {
  const s = router();
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', WS.id);
  const { deps } = s.probes[0];
  for (const k of ['buildTestConfig', 'startTest', 'getFreePort', 'httpThroughProxy']) assert.equal(typeof deps[k], 'function', k);
  const cfg = deps.buildTestConfig(WS, 46200);
  assert.equal(cfg.inbounds[0].port, 46200);
  assert.equal(cfg.outbounds.find((o) => o.tag === 'proxy').mux, undefined, 'the probe adds mux itself, to its first core only');
  const asked = [];
  s.state.xray.startTest = async (config, engine) => { asked.push(engine); return { cleanup() {} }; };
  await deps.startTest(cfg);
  assert.deepEqual(asked, ['xray']);
});

test('auto: a drop marks the live answer for a re-test — the recovery’s connect tests nothing and stays muxed; the user’s next connect tests it again', async (t) => {
  // Final review I1: a re-test inside the recovery ran in the outage (the LAN
  // offline or direct meanwhile), and a slow line turned mux off for good.
  const s = router();
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', WS.id);
  assert.equal(s.probes.length, 1);
  s.state.xray.crash();
  await h.until(() => h.connectedCount(s) === 2, 'the rebuilt connection');
  assert.equal(s.probes.length, 1, 'no test inside the recovery');
  assert.deepEqual(liveProxy(s).mux, MUX, 'the rebuild is muxed as before');
  assert.equal(saved(s).muxProbes[FP].verdict, 'ok', 'still ok');
  assert.equal(saved(s).muxProbes[FP].recheck, true, 'marked for a re-test');
  // the next connect the user makes tests it again, and the answer clears the mark
  await s.service.invoke('disconnect');
  await s.service.invoke('connect', WS.id);
  assert.equal(s.probes.length, 2);
  assert.deepEqual(Object.keys(saved(s).muxProbes[FP]).sort(), ['at', 'verdict']);
  assert.deepEqual(liveProxy(s).mux, MUX);
});

test('auto: a drop then a recovery connect — zero probes, mux still on; a second drop writes nothing more', async (t) => {
  // A core that keeps crashing for a reason that has nothing to do with mux:
  // no test in any of its rebuilds, and one store write (the mark) in all.
  const s = router();
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', WS.id);
  assert.equal(s.probes.length, 1);
  const written = muxWritesOf(s);
  assert.equal(written, 1, 'the probe’s answer, once');
  s.state.xray.crash();
  await h.until(() => h.connectedCount(s) === 2, 'the first rebuild');
  s.state.xray.crash();
  await h.until(() => h.connectedCount(s) === 3, 'the second rebuild');
  assert.equal(s.probes.length, 1, 'zero probes in the recoveries');
  assert.equal(muxWritesOf(s) - written, 1, 'the mark — and nothing for the second drop');
  assert.deepEqual(liveProxy(s).mux, MUX, 'and the rebuilt connections are muxed');
  assert.deepEqual(lines(s, /^Mux /).map((l) => l.line), Array(3).fill('Mux on for ws-server (tested: works)'));
});

test('auto: an inconclusive re-test keeps mux on — the ok from before stands, tested again after an hour', async (t) => {
  const s = router({}, ['ok', 'unknown']);
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', WS.id);
  s.state.xray.crash();
  await h.until(() => h.connectedCount(s) === 2, 'the rebuilt connection');
  await s.service.invoke('disconnect');
  const before = Date.now();
  await s.service.invoke('connect', WS.id);
  assert.equal(s.probes.length, 2, 'the re-test ran');
  assert.deepEqual(liveProxy(s).mux, MUX, 'mux stays on');
  const memo = saved(s).muxProbes[FP];
  assert.equal(memo.verdict, 'ok');
  assert.equal(memo.recheck, true, 'still to be re-tested');
  assert.ok(memo.retryAfter >= before + HOUR && memo.retryAfter <= Date.now() + HOUR, 'but not for an hour');
  assert.equal(lines(s, /^Mux on for ws-server \(tested before: works — this test did not answer\)$/).length, 1);
});

test('auto: "does not accept it" — no mux, remembered; the next connect is not tested', async (t) => {
  const s = router({}, ['unsupported']);
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', WS.id);
  assert.equal(liveProxy(s).mux, undefined);
  assert.equal(JSON.stringify(s.state.xray.starts.at(-1).config).includes('"mux"'), false);
  assert.equal(saved(s).muxProbes[FP].verdict, 'unsupported');
  assert.deepEqual(lines(s, /^Mux /).map((l) => [l.level, l.line]), [['info', 'Mux off for ws-server (this server does not accept it)']]);
  await s.service.invoke('disconnect');
  await s.service.invoke('connect', WS.id);
  assert.equal(s.probes.length, 1);
});

test('auto: no answer either way — connected without mux, remembered for an hour: the next connect does not test it again', async (t) => {
  const s = router({}, ['unknown', 'ok']);
  t.after(() => s.service.shutdown());
  const before = Date.now();
  await s.service.invoke('connect', WS.id);
  assert.equal(liveProxy(s).mux, undefined);
  const memo = saved(s).muxProbes[FP];
  assert.equal(memo.verdict, 'unknown');
  assert.ok(memo.retryAfter >= before + HOUR && memo.retryAfter <= Date.now() + HOUR, 'tested again after an hour');
  assert.deepEqual(lines(s, /^Mux/).map((l) => [l.level, l.line]), [['warn', 'Mux: ws-server did not answer either way — connecting without it']]);
  // a warning: on a router it reaches syslog too
  assert.ok(s.syslog.some(([, text]) => text.includes('Mux: ws-server did not answer either way')));
  await s.service.invoke('disconnect');
  await s.service.invoke('connect', WS.id);
  assert.equal(s.probes.length, 1, 'not tested again within the hour');
  assert.equal(liveProxy(s).mux, undefined);
});

test('the router tests one server at a time — three test cores at once on its CPU miss the 5 s share', async (t) => {
  const wsLike = (id, p) => { const s = JSON.parse(JSON.stringify(WS)); s.id = id; s.name = id; s.outbound.streamSettings.wsSettings.path = p; return s; };
  const two = wsLike('srv-ws2', '/two');
  const three = wsLike('srv-ws3', '/three');
  let inFlight = 0, most = 0;
  const probed = [];
  const probeMux = async (server) => { probed.push(server.id); inFlight++; most = Math.max(most, inFlight); await h.sleep(20); inFlight--; return 'ok'; };
  const s = h.start({
    servers: [WS, two, three],
    settings: { routeDefault: WS.id, routeRules: [{ id: 'r1', type: 'domain', value: 'a.example', target: two.id }, { id: 'r2', type: 'domain', value: 'b.example', target: three.id }] }
  }, { probeMux });
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', '__advanced__');
  assert.deepEqual(probed.sort(), ['srv-ws', 'srv-ws2', 'srv-ws3']);
  assert.equal(most, 1, 'one at a time');
  const muxed = s.state.xray.starts.at(-1).config.outbounds.filter((o) => o.mux).map((o) => o.tag).sort();
  assert.deepEqual(muxed, ['out-srv-ws', 'out-srv-ws2', 'out-srv-ws3']);
});

test('on: every eligible server is muxed untested; off: nothing is tested and no config carries mux', async (t) => {
  const on = router({ mux: 'on' });
  t.after(() => on.service.shutdown());
  await on.service.invoke('connect', WS.id);
  assert.equal(on.probes.length, 0);
  assert.deepEqual(liveProxy(on).mux, MUX);
  assert.deepEqual(lines(on, /^Mux/), []);

  const off = router({ mux: 'off' });
  t.after(() => off.service.shutdown());
  await off.service.invoke('connect', WS.id);
  assert.equal(off.probes.length, 0);
  assert.equal(JSON.stringify(off.state.xray.starts.at(-1).config).includes('"mux"'), false);
  assert.deepEqual(lines(off, /^Mux/), []);
});

test('a server that cannot carry mux is never tested', async (t) => {
  const s = router();
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', h.SERVER.id);   // SOCKS
  assert.equal(s.probes.length, 0);
  assert.equal(JSON.stringify(s.state.xray.starts.at(-1).config).includes('"mux"'), false);
  assert.deepEqual(lines(s, /^Mux/), []);
});
