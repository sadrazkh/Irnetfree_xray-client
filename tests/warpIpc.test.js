'use strict';
/**
 * servers:addWarp outside warp.js: the router's service (the real service over
 * the gateway fakes, its WARP API a local fake or a SOCKS port that refuses —
 * nothing reaches Cloudflare), main.js (its wiring, read as text: Electron does
 * not load here), the two bridges the one renderer talks through, and every
 * code the window translates, in Persian and English.
 *
 * Until the parser knows `masque` (the MASQUE round's T1), createServer is a
 * stub here; the test with the real one runs as soon as it does.
 */
process.env.IRNETFREE_PLATFORM = 'openwrt';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const H = require('./serviceHarness');
const F = require('./warpFakes');
const W = require('../src/main/warp');
const SF = require('../src/renderer/serverFields');
const { createServer } = require('../src/main/parser');

process.setMaxListeners(60);   // every service registers its own exit hook
test.after(() => H.cleanupDirs());

const R = (...p) => fs.readFileSync(path.join(__dirname, '..', ...p), 'utf8').replace(/\r\n/g, '\n');
const { SERVER, until } = H;

/** usque's config.json for a key made here. */
function usque() {
  const k = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return JSON.stringify({
    private_key: k.privateKey.export({ type: 'sec1', format: 'der' }).toString('base64'),
    endpoint_v4: '162.159.198.1', endpoint_h2_v4: '162.159.198.2',
    endpoint_pub_key: crypto.createPublicKey({ key: Buffer.from(F.EDGE_PUB, 'base64'), format: 'der', type: 'spki' }).export({ type: 'spki', format: 'pem' }),
    ipv4: '172.16.0.2', ipv6: '2606:4700:110:8a36::2', id: 'u1', access_token: 'never-carried'
  });
}
/** The public half of a key the core would read (PEM or base64; PKCS#8, SEC1 or SPKI), as base64 SPKI. */
function spkiOf(v, isPrivate) {
  const s = String(v).trim();
  const der = (type) => ({ key: Buffer.from(s, 'base64'), format: 'der', type });
  let k;
  if (/-----BEGIN/.test(s)) k = isPrivate ? crypto.createPrivateKey(s) : crypto.createPublicKey(s);
  else if (!isPrivate) k = crypto.createPublicKey(der('spki'));
  else { try { k = crypto.createPrivateKey(der('pkcs8')); } catch { k = crypto.createPrivateKey(der('sec1')); } }
  return (k.type === 'public' ? k : crypto.createPublicKey(k)).export({ type: 'spki', format: 'der' }).toString('base64');
}
const stub = () => {
  const made = [];
  return { made, createServer: (f) => { made.push(f); return { id: 'warp-' + made.length, name: f.name, protocol: f.protocol, address: f.address, port: f.port, outbound: {} }; } };
};

test('router: servers:addWarp — a new account through the fake API, both servers saved after the others; the whole list, the new ones and the account back', async (t) => {
  const api = F.fakeApi();
  const parser = stub();
  const s = H.start({}, { warp: { request: api, createServer: parser.createServer, now: () => Date.UTC(2026, 9, 14) } });
  t.after(() => s.service.shutdown());
  const res = await s.service.invoke('servers:addWarp', { mode: 'new', via: 'direct', http: 'both', endpoint: 'auto', antiDpi: true });
  assert.equal(res.ok, true, res.error);
  assert.deepEqual(res.added.map((x) => x.name), ['☁ WARP · H3', '☁ WARP · H2']);
  assert.deepEqual(res.servers.map((x) => x.id), [SERVER.id, 'srv-2', 'warp-1', 'warp-2']);
  assert.deepEqual((await s.service.invoke('servers:list')).map((x) => x.id), [SERVER.id, 'srv-2', 'warp-1', 'warp-2']);
  assert.deepEqual(res.account, { id: F.DEVICE, type: 'free', warpPlus: false });
  assert.equal(api.calls[0].path, '/v0a5641/reg');
  // the steps reach the log, the secrets do not
  const logged = JSON.stringify(s.logs);
  assert.match(logged, /WARP: device .* registered/);
  assert.equal(logged.includes(F.TOKEN), false);
  assert.equal(logged.includes(parser.made[0].warpPrivateKey.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '').slice(0, 40)), false);
});

test('router: an import needs no network; a bad one, a bad cover, a sign-up through a connection that is not up — refused with their codes, nothing saved', async (t) => {
  const api = F.fakeApi();
  const parser = stub();
  const s = H.start({}, { warp: { request: api, createServer: parser.createServer } });
  t.after(() => s.service.shutdown());
  let res = await s.service.invoke('servers:addWarp', { mode: 'import', importText: usque(), http: 'h3', cover: 'www.example.com' });
  assert.equal(res.ok, true, res.error);
  assert.deepEqual(res.added.map((x) => x.name), ['☁ WARP · H3']);
  assert.equal(parser.made[0].vcn, 'www.example.com');
  assert.equal(JSON.stringify(parser.made).includes('never-carried'), false);
  for (const [args, code] of [
    [{ mode: 'import', importText: 'vless://nope' }, 'badImport'],
    [{ mode: 'new', cover: 'not a domain' }, 'badCover'],
    [{ mode: 'new', via: 'proxy' }, 'notConnected']
  ]) {
    res = await s.service.invoke('servers:addWarp', args);
    assert.deepEqual([res.ok, res.code], [false, code], JSON.stringify(args));
    assert.ok(res.error);
  }
  assert.equal(api.calls.length, 0);
  assert.equal((await s.service.invoke('servers:list')).length, 3);
});

test('router: connected, "through the connection" dials the API by name through the gateway’s own SOCKS port — a SOCKS here that refuses, so nothing leaves; said as blocked', async (t) => {
  const socks = await F.socksServer({ refuse: true });
  const s = H.start({ settings: { socksPort: socks.port } }, { warp: { createServer: stub().createServer } });
  t.after(async () => { await s.service.shutdown(); await socks.close(); });
  await s.service.invoke('connect', SERVER.id);
  await until(async () => (await s.service.invoke('app:init')).conn.state === 'connected', 'connected');
  const res = await s.service.invoke('servers:addWarp', { mode: 'new', via: 'proxy' });
  assert.deepEqual([res.ok, res.code], [false, 'blocked'], res.error);
  assert.deepEqual(socks.asked, ['api.cloudflareclient.com:443'], 'the name went to the proxy, the proxy went nowhere');
});

test('the real parser takes warpServers’ fields — once it knows MASQUE (T1)', { skip: !SF.PROTOCOLS.includes('masque') && 'parser.createServer has no masque yet' }, () => {
  const reg = W.importWarp(usque());
  for (const opts of [{}, { cover: 'www.example.com', antiDpi: false }, { endpoint: 'v6' }, { endpoint: 'custom', address: '162.159.198.2:8443', http: 'h2' }]) {
    const fields = W.warpServers(reg, opts);
    for (const f of fields) {
      const s = createServer(f);
      assert.equal(s.protocol, 'masque');
      assert.equal(s.name, f.name);
      assert.equal(s.address, f.address);
      assert.equal(s.port, f.port);
      const ob = s.outbound;
      assert.equal(ob.protocol, 'masque');
      assert.deepEqual(ob.settings && { address: ob.settings.address, port: ob.settings.port }, { address: f.address, port: f.port });
      const st = ob.streamSettings;
      assert.equal(st.security, 'tls');
      const w = st.masqueSettings.warp;
      // the editor may keep a key as PEM or as its base64 body: the same key either way
      assert.equal(spkiOf(w.privateKey, true), spkiOf(reg.privateKey, true));
      assert.equal(spkiOf(w.publicKey, false), spkiOf(reg.publicKey, false));
      assert.deepEqual(w.address, reg.address);
      assert.equal(st.masqueSettings.user, undefined);
      assert.equal(st.tlsSettings.serverName, f.sni);
      assert.equal(st.tlsSettings.verifyPeerCertByName, f.vcn);
      assert.equal(st.tlsSettings.allowInsecure, undefined);
      if (f.masqueHttp === 'h2') assert.deepEqual(st.tlsSettings.alpn, ['h2']);
      else assert.ok(!st.tlsSettings.alpn || !st.tlsSettings.alpn.includes('h2'));
      assert.equal(ob._fragment, f.fragment);
      assert.equal(ob._noise, f.noise);
      assert.ok(s.raw, 'a share JSON');
    }
  }
});

test('servers:addWarp is wired: main.js (the shared handler, the live SOCKS port), the preload bridge, the router’s web bridge', () => {
  const MAIN = R('src', 'main', 'main.js');
  assert.match(MAIN, /const \{ warpHandler \} = require\('\.\/warp'\);/);
  assert.match(MAIN, /const addWarp = warpHandler\(\{\n {4}createServer,\n {4}connected: \(\) => conn\.state === 'connected',\n {4}socksPort: \(\) => \(appliedSettings \|\| getSettings\(\)\)\.socksPort,\n {4}getServers: \(\) => store\.get\('servers', \[\]\),\n {4}setServers,/);
  assert.match(MAIN, /ipcMain\.handle\('servers:addWarp', \(e, args\) => addWarp\(args \|\| \{\}\)\);/);
  assert.match(R('src', 'preload', 'preload.js'), /addWarp: \(args\) => ipcRenderer\.invoke\('servers:addWarp', args\),/);
  assert.match(R('src', 'server', 'web-api.js'), /addWarp: \(args\) => invoke\('servers:addWarp', args\),/);
  assert.match(R('src', 'server', 'service.js'), /'servers:addWarp': \(args\) => addWarp\(args \|\| \{\}\),/);
});

test('every WARP error and warning code reads in Persian and English', () => {
  const ctx = { window: {}, document: { documentElement: {}, querySelectorAll: () => [] } };
  vm.runInNewContext(R('src', 'renderer', 'i18n.js'), ctx);
  const t = (lang, k) => { ctx.window.i18n.applyI18n(lang); return ctx.window.i18n.t(k); };
  const keys = W.ERROR_CODES.map((c) => 'warp.err.' + c).concat(W.WARNING_CODES.map((c) => 'warp.warn.' + c));
  assert.ok(keys.length >= 14);
  const arabicScript = /[\u0600-\u06FF]/;
  for (const k of keys) {
    const fa = t('fa', k);
    const en = t('en', k);
    assert.notEqual(fa, k, `fa has no '${k}'`);
    assert.match(fa, arabicScript, `fa '${k}' is not Persian`);
    assert.notEqual(en, k, `en has no '${k}'`);
    assert.doesNotMatch(en, arabicScript, `en has no '${k}' (the Persian shows through)`);
  }
  // the codes addWarp can answer are exactly these
  assert.deepEqual(W.ERROR_CODES.slice().sort(), ['badAddress', 'badAnswer', 'badCover', 'badImport', 'badLicense', 'blocked', 'busy', 'createFailed', 'failed', 'notConnected', 'rateLimited', 'rejected']);
});
