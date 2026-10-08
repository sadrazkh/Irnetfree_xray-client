'use strict';
/**
 * JSON servers on the connect paths (spec: docs/superpowers/specs/2026-10-08-json-configs-design.md).
 *
 * The router's service is driven for real (its seams faked — gatewayFakes.js):
 * a JSON server set to run raw is started with its own config, one in full
 * mode with its helpers inside the app's config, a refused edit answers with
 * the reason. main.js requires Electron at load, so — like connectPath.test.js
 * — the desktop's copy of the same steps is read as text and held to the
 * service's.
 */
process.env.IRNETFREE_PLATFORM = 'openwrt';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const H = require('./serviceHarness');
const { importJson } = require('../src/main/jsonImport');
const { muxCandidates } = require('../src/main/mux');

process.setMaxListeners(40);   // every service registers its own exit hook
test.after(H.cleanupDirs);

const R = (...p) => fs.readFileSync(path.join(__dirname, '..', ...p), 'utf8').replace(/\r\n/g, '\n');
const MAIN = R('src', 'main', 'main.js');
const SERVICE = R('src', 'server', 'service.js');
const FIX = (f) => fs.readFileSync(path.join(__dirname, 'fixtures/json', f), 'utf8');
const jsonServer = (f, over) => Object.assign(importJson(FIX(f)).servers[0], over);
// names answered without the network (the entry hosts are resolved under TUN)
const DEPS = { resolveHost: async () => ({ ips: ['203.0.113.7'] }) };

/** The source from `start` up to the first `end` after it. */
function slice(source, start, end) {
  const a = source.indexOf(start);
  assert.notEqual(a, -1, `${start} is gone`);
  const b = source.indexOf(end, a + start.length);
  assert.notEqual(b, -1, `nothing ends ${start}`);
  return source.slice(a, b + end.length);
}
const level = (s) => s.split('\n').map((l) => l.trim()).join('\n');

/* ------------------------------ the router, for real ------------------------------ */

test('the router runs a raw JSON server’s own config: its routing, DNS and outbounds as written, the app’s inbounds, said once in the log', async (t) => {
  const raw = jsonServer('xray-fragment.json', { id: 'js-raw', jsonMode: 'raw' });
  const fx = JSON.parse(FIX('xray-fragment.json'));
  const s = H.start({ servers: [raw] }, DEPS);
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', raw.id);
  assert.equal(s.state.xray.starts.length, 1);
  const { config, engine } = s.state.xray.starts[0];
  assert.equal(engine, 'xray');
  assert.deepEqual(config.routing, fx.routing);
  assert.deepEqual(config.dns, fx.dns, 'no DNS plan of the app’s, and not the router’s DNS block either');
  assert.deepEqual(config.inbounds.map((i) => [i.tag, i.port]), [['socks-in', H.PORTS.socksPort], ['http-in', H.PORTS.httpPort]]);
  assert.deepEqual(config.outbounds.map((o) => o.tag), ['proxy', 'fragment', 'direct', 'block']);
  assert.equal(config.outbounds[0].streamSettings.sockopt.dialerProxy, 'fragment');
  assert.equal(config.metrics.listen, `127.0.0.1:${H.PORTS.apiPort}`);
  const said = s.logs.filter((l) => /raw JSON/.test(l.line));
  assert.deepEqual(said.map((l) => l.line), ['Running "🇩🇪 frag" exactly as written (raw JSON) — the app\'s DNS management, leak guard and routing mode do not apply']);
  await s.service.invoke('disconnect');
});

test('the router runs a full-mode JSON server inside its own config: the helpers beside it, the app’s DNS plan around it', async (t) => {
  const full = jsonServer('xray-chain.json', { id: 'js-full' });
  const s = H.start({ servers: [full] }, DEPS);
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', full.id);
  const { config } = s.state.xray.starts[0];
  const tags = config.outbounds.map((o) => o.tag);
  assert.deepEqual(tags.slice(0, 3), ['proxy', 'proxy~hop1', 'proxy~frag']);
  assert.ok(tags.includes('dns-out'), 'the app’s hijack is there');
  assert.deepEqual(config.outbounds[0].streamSettings.sockopt.dialerProxy, 'proxy~hop1', 'its hop as the dialerProxy the cores take');
  assert.equal(config.outbounds[0].proxySettings, undefined);
  assert.equal(s.logs.some((l) => /raw/.test(l.line)), false, 'nothing to say about raw');
  await s.service.invoke('disconnect');
});

test('a raw server in a chain is used in its full form, and the log says so once', async (t) => {
  const raw = jsonServer('xray-fragment.json', { id: 'js-raw', jsonMode: 'raw', name: 'R' });
  const s = H.start({ servers: [H.SERVER, raw], chains: [{ id: 'c1', name: 'C', members: [H.SERVER.id, raw.id] }] }, DEPS);
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', 'c1');
  const { config } = s.state.xray.starts[0];
  assert.deepEqual(config.outbounds.slice(0, 2).map((o) => o.tag), ['proxy-h0', 'proxy']);
  assert.equal(config.outbounds[1].streamSettings.sockopt.dialerProxy, 'proxy-h0');
  assert.deepEqual(s.logs.filter((l) => /set to run raw/.test(l.line)).map((l) => l.line), ['"R" is set to run raw, but a chain/routing target uses its full form']);
  await s.service.invoke('disconnect');
});

test('servers:update answers a refused JSON edit with the reason and keeps the record; servers:link gives the pretty JSON', async (t) => {
  const full = jsonServer('xray-fragment.json', { id: 'js-1' });
  const s = H.start({ servers: [full] }, DEPS);
  t.after(() => s.service.shutdown());
  const bad = await s.service.invoke('servers:update', { id: full.id, fields: { json: '{"outbounds": [' } });
  assert.equal(bad.ok, false);
  assert.match(bad.error, /^invalid JSON/);
  assert.deepEqual(bad.servers.map((x) => x.id), [full.id]);
  const none = await s.service.invoke('servers:update', { id: full.id, fields: { json: { outbounds: [{ tag: 'direct', protocol: 'freedom' }] } } });
  assert.equal(none.ok, false);
  assert.match(none.error, /no proxy outbound/);
  const list = await s.service.invoke('servers:list');
  assert.deepEqual(list[0].json, full.json, 'the stored record is unchanged');
  // a good edit: the mode switch, and the config sent back as the parsed object
  const ok = await s.service.invoke('servers:update', { id: full.id, fields: { name: full.name, jsonMode: 'raw', json: JSON.parse(JSON.stringify(full.json)) } });
  assert.equal(ok.ok, true);
  assert.equal(ok.server.jsonMode, 'raw');
  assert.deepEqual(ok.server._edited, ['jsonMode']);
  assert.equal(await s.service.invoke('servers:link', full.id), JSON.stringify(full.json, null, 2));
});

test('a raw single server is no mux candidate — its config runs as written; in full mode it is one like any server', () => {
  const raw = jsonServer('xray-subscription.json', { id: 'r', jsonMode: 'raw' });
  const full = jsonServer('xray-subscription.json', { id: 'f' });
  assert.deepEqual(muxCandidates({ mode: 'single', server: raw }), []);
  assert.deepEqual(muxCandidates({ mode: 'single', server: full }).map((x) => x.id), ['f']);
  assert.deepEqual(muxCandidates({ mode: 'advanced', serversById: { r: raw }, rules: [], def: 'r' }).map((x) => x.id), ['r'], 'routed to: its full form');
});

/* ------------------------------ the desktop, as text ------------------------------ */

test('the desktop builds a raw JSON server the way the router does: rawServerOf → buildRawConfig on an Xray core', () => {
  for (const [label, src, end] of [['main.js', MAIN, '\n}\n'], ['service.js', SERVICE, '\n  }\n']]) {
    const body = level(slice(src, 'function buildActive(serverId, settings) {', end));
    assert.match(body, /const rawServer = rawServerOf\(plan\);/, label);
    assert.match(body, /if \(rawServer && engineFormat\(engine\) === 'sing-box'\) engine = xray\.resolveEngine\('xray'\)\.id;/, label);
    assert.match(body, /if \(rawServer\) \{\nconfig = buildRawConfig\(rawServer, settings\);\n\} else if \(engineFormat\(engine\) === 'sing-box'\) \{/, label);
    assert.match(body, /if \(!geoAssets && usesGeo && !rawServer\) \{/, `${label}: no geo warning for a config the app did not write`);
  }
  assert.match(SERVICE, /if \(OPENWRT && !rawServer && engineFormat\(engine\) === 'xray' && config\.dns\) config\.dns = routerDnsTuning\(config\.dns\);/);
});

test('both connects say raw mode once, right after the config is built, and hand a raw config’s TUN the plain resolvers', () => {
  for (const [label, src, start, end] of [
    ['main.js', MAIN, 'async function connectOnce(serverId, opts = {}) {', '\n  return { ok: true, tunError };\n}'],
    ['service.js', SERVICE, 'async function connectOnce(serverId, opts = {}) {', '\n    return { ok: true, tunError };\n  }']
  ]) {
    const body = level(slice(src, start, end));
    const built = body.indexOf('buildActive(serverId, settings)');
    const note = body.indexOf('for (const note of rawModeNotes(plan)) send(\'log\', note);');
    assert.ok(built > -1 && note > built, `${label}: the note follows the build`);
    assert.equal(body.split('rawModeNotes(').length, 2, `${label}: once`);
    assert.match(body, /const hijacks = engineFormat\(runEngine\) !== 'sing-box' && !rawServerOf\(plan\);/, label);
  }
});

test('both servers:update handlers answer a refused edit with { ok: false, error, servers }; servers:link is the share link (JSON for a JSON server)', () => {
  const refused = /try \{ servers\[idx\] = applyServerEdits\(before, fields \|\| \{\}\); \} catch \(err\) \{ return \{ ok: false, error: err\.message, servers \}; \}/;
  assert.match(MAIN, refused);
  assert.match(SERVICE, refused);
  assert.match(MAIN, /ipcMain\.handle\('servers:link', \(e, id\) => \{\n {4}const s = store\.get\('servers', \[\]\)\.find\(x => x\.id === id\);\n {4}return s \? buildShareLink\(s\) : '';/);
  assert.match(SERVICE, /'servers:link': \(id\) => \{ const s = store\.get\('servers', \[\]\)\.find\(x => x\.id === id\); return s \? buildShareLink\(s\) : ''; \}/);
});
