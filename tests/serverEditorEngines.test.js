'use strict';
/**
 * What the editor's Advanced tab and VLESS Encryption change in the engines:
 * Mux set for one server (on / off / the app's), its own numbers, and the
 * sing-box engine handing a VLESS Encryption server to Xray.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { planMux, decideMux, MUX } = require('../src/main/mux');
const { buildConfig } = require('../src/main/configBuilder');
const { buildSingboxConfig, UnsupportedEngineConfig } = require('../src/main/singboxBuilder');
const { parseLink, applyServerEdits } = require('../src/main/parser');

const UUID = '11111111-2222-3333-4444-555555555555';
const ws = (id, extra) => Object.assign(parseLink(`vless://${UUID}@${id}.example.com:443?encryption=none&type=ws&path=%2F&host=${id}.example.com&security=tls&sni=${id}.example.com#${id}`), { id }, extra);
const ENC = 'mlkem768x25519plus.native.0rtt.p7sTtcQlhzr21By6QMbFOEFjtHJa8dquXhK7pboK9GE';

test('planMux: a server set to Mux on is muxed without a test, even with the app’s Mux off; one set off never is', () => {
  const on = ws('a', { mux: 'on' }), off = ws('b', { mux: 'off' }), plain = ws('c');
  assert.deepEqual(planMux({ mode: 'off', servers: [on, off, plain], cache: {}, now: 1 }), { muxIds: ['a'], toProbe: [] });
  assert.deepEqual(planMux({ mode: 'on', servers: [on, off, plain], cache: {}, now: 1 }), { muxIds: ['a', 'c'], toProbe: [] });
  const auto = planMux({ mode: 'auto', servers: [on, off, plain], cache: {}, now: 1 });
  assert.deepEqual(auto.muxIds, ['a']);
  assert.deepEqual(auto.toProbe.map((s) => s.id), ['c'], 'only the one the app decides is tested');
  // not eligible (VLESS with flow): its own "on" cannot make it
  const vision = Object.assign(parseLink(`vless://${UUID}@v.example.com:443?encryption=none&flow=xtls-rprx-vision&type=tcp&security=tls&sni=v.example.com#v`), { id: 'v', mux: 'on' });
  assert.deepEqual(planMux({ mode: 'off', servers: [vision], cache: {}, now: 1 }).muxIds, []);
});

test('decideMux (auto): the server’s own setting decides it, said in the log, never probed', async () => {
  const lines = [];
  const probed = [];
  const r = await decideMux({
    mode: 'auto', servers: [ws('a', { mux: 'on' }), ws('b', { mux: 'off' })], cache: {}, now: 1,
    probe: async (s) => { probed.push(s.id); return 'ok'; }, log: (l) => lines.push(l)
  });
  assert.deepEqual(r.muxIds, ['a']);
  assert.deepEqual(probed, []);
  assert.ok(lines.some((l) => /Mux on for .*set for this server/.test(l)));
  assert.ok(lines.some((l) => /Mux off for .*set for this server/.test(l)));
});

test('the server’s own Mux numbers replace the defaults in the config; without them MUX as it was', () => {
  const s = ws('a', { muxConcurrency: 4, xudpConcurrency: 32 });
  const cfg = buildConfig({ mode: 'single', server: s }, { muxServerIds: ['a'], socksPort: 1080, httpPort: 1081, apiPort: 1085, geoAssets: false });
  const proxy = cfg.outbounds.find((o) => o.tag === 'proxy');
  assert.deepEqual(proxy.mux, Object.assign({}, MUX, { concurrency: 4, xudpConcurrency: 32 }));
  const plain = buildConfig({ mode: 'single', server: ws('b') }, { muxServerIds: ['b'], socksPort: 1080, httpPort: 1081, apiPort: 1085, geoAssets: false });
  assert.deepEqual(plain.outbounds.find((o) => o.tag === 'proxy').mux, Object.assign({}, MUX));
});

test('the sing-box engine refuses VLESS Encryption (the connect then runs it on Xray); "none" it takes as before', () => {
  const s = applyServerEdits(ws('a'), { encryption: ENC });
  assert.throws(() => buildSingboxConfig(s, {}), (e) => e instanceof UnsupportedEngineConfig && /VLESS Encryption/.test(e.message));
  assert.doesNotThrow(() => buildSingboxConfig(ws('b'), {}));
});
