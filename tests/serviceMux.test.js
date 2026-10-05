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
const MIN = 60 * 1000;

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

test('auto: a muxed connection that drops forgets an answer at least 10 minutes old — the rebuild tests the server again', async (t) => {
  const learnt = Date.now() - 11 * MIN;
  const s = router({}, ['ok'], { [FP]: { verdict: 'ok', at: learnt } });
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', WS.id);
  assert.equal(s.probes.length, 0, 'muxed from memory');
  assert.deepEqual(liveProxy(s).mux, MUX);
  s.state.xray.crash();
  await h.until(() => h.connectedCount(s) === 2, 'the rebuilt connection');
  assert.equal(s.probes.length, 1, 'tested again on the rebuild');
  assert.deepEqual(liveProxy(s).mux, MUX);
  assert.equal(saved(s).muxProbes[FP].verdict, 'ok', 'and remembered again');
  assert.ok(saved(s).muxProbes[FP].at > learnt, 'as of now');
});

test('auto: drops within 10 minutes of the probe forget nothing — no store write for muxProbes, no test again', async (t) => {
  // A core that keeps crashing for a reason that has nothing to do with mux:
  // a forget and a re-learnt answer per crash were two rewrites of store.json
  // on the router's flash, for as long as the crashes went on.
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
  assert.equal(muxWritesOf(s) - written, 0, 'two drops, no store.set(\'muxProbes\', …)');
  assert.equal(s.probes.length, 1, 'the answer from minutes ago stands');
  assert.deepEqual(liveProxy(s).mux, MUX, 'and the rebuilt connections are muxed with it');
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

test('auto: no answer either way — connected without mux, nothing remembered, tested again next time', async (t) => {
  const s = router({}, ['unknown', 'ok']);
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', WS.id);
  assert.equal(liveProxy(s).mux, undefined);
  assert.equal(saved(s).muxProbes, undefined, 'an unknown is never written');
  assert.deepEqual(lines(s, /^Mux/).map((l) => [l.level, l.line]), [['warn', 'Mux: ws-server did not answer either way — connecting without it']]);
  // a warning: on a router it reaches syslog too
  assert.ok(s.syslog.some(([, text]) => text.includes('Mux: ws-server did not answer either way')));
  await s.service.invoke('disconnect');
  await s.service.invoke('connect', WS.id);
  assert.equal(s.probes.length, 2);
  assert.deepEqual(liveProxy(s).mux, MUX);
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
