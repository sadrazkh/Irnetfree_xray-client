'use strict';
/**
 * WARP on WireGuard, many accounts, the account shown (v1.26.0,
 * .superpowers/sdd/warp-wg/design.md): a WireGuard device registered with a
 * FAKE of Cloudflare's API (warpFakes.js — api.cloudflareclient.com is never
 * dialled), what the account says read back, the server the real parser makes
 * of it, a batch of accounts from a list of WARP+ keys, and the chain that
 * carries a WARP over a config the user already has.
 */
process.env.IRNETFREE_PLATFORM = 'openwrt';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const W = require('../src/main/warp');
const F = require('./warpFakes');
const H = require('./serviceHarness');
const { createServer } = require('../src/main/parser');

process.setMaxListeners(60);
test.after(() => H.cleanupDirs());

const NOW = Date.UTC(2026, 9, 19, 8, 0, 0, 0);
const now = () => NOW;
const KEY2 = 'Z9y8X7w6-V5u4T3s2-R1q0P9o8';
const KEY3 = 'M1n2B3v4-C5x6Z7l8-K9j0H1g2';
const PEER = 'bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=';
const path = (c) => c.method + ' ' + c.path.replace('/v0a5641', '').replace(F.DEVICE, '{id}');

/** registerWarpWg over the fake API; `log` lines collected. */
async function register(apiOpts = {}, args = {}) {
  const api = F.fakeApi(apiOpts);
  const lines = [];
  const reg = await W.registerWarpWg(Object.assign({ request: api, now, log: (l, lv) => lines.push([lv, l]) }, args));
  return { reg, api, lines };
}
/** The X25519 public key (raw, base64) of a raw base64 private key. */
function publicOf(rawPrivate) {
  const k = crypto.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), Buffer.from(rawPrivate, 'base64')]), format: 'der', type: 'pkcs8' });
  const der = crypto.createPublicKey(k).export({ type: 'spki', format: 'der' });
  return der.subarray(der.length - 32).toString('base64');
}

/* ------------------------------ the registration ------------------------------ */
test('registerWarpWg: POST /reg carries OUR X25519 key (curve25519, wireguard) — no MASQUE enrollment — then warp_enabled, the account and its devices', async () => {
  const { reg, api } = await register();
  assert.deepEqual(api.calls.map(path), ['POST /reg', 'PATCH /reg/{id}', 'GET /reg/{id}/account', 'GET /reg/{id}/account/devices']);
  const post = api.calls[0];
  assert.equal(post.body.key_type, 'curve25519');
  assert.equal(post.body.tunnel_type, 'wireguard');
  assert.equal(post.body.tos, '2026-10-19T08:00:00.000Z');
  assert.equal('Authorization' in post.headers, false);
  // the key sent is the public half of the private key kept
  assert.equal(post.body.key, publicOf(reg.privateKey));
  assert.match(reg.privateKey, /^[A-Za-z0-9+/]{43}=$/);
  assert.deepEqual(api.calls[1].body, { warp_enabled: true });
  for (const c of api.calls.slice(1)) assert.equal(c.headers.Authorization, 'Bearer ' + F.TOKEN);
  // already on → no PATCH at all
  const again = await register({}, {});
  assert.equal(again.api.calls.filter((c) => c.method === 'PATCH').length, 1);
});

test('registerWarpWg: the record mapped — the peer’s WireGuard key, v4 /32 + v6 /128, the edges without ":0", reserved from config.client_id', async () => {
  const { reg } = await register();
  assert.equal(reg.kind, 'wireguard');
  assert.equal(reg.publicKey, PEER);
  assert.deepEqual(reg.address, ['172.16.0.2/32', '2606:4700:110:8a36:9c1:2b3:4d5:6e7f/128']);
  assert.deepEqual(reg.endpoints, { v4: '162.159.192.1', v6: '2606:4700:d0::a29f:c001' });
  assert.deepEqual(reg.reserved, [0, 0, 0], 'client_id "AAAA" is three zero bytes');
  // another client id; an answer without peers is read back with GET /reg/{id}
  const cfg = (over) => F.device(Object.assign({ token: F.TOKEN, warp_enabled: true }, over));
  const api = F.fakeApi({ fetched: F.device({ config: { client_id: 'qbs5', peers: [{ public_key: PEER, endpoint: { v4: '162.159.192.7:0' } }], interface: { addresses: { v4: '172.16.0.2' } } } }) });
  const bare = async (r) => (r.method === 'POST' ? { status: 200, body: JSON.stringify(cfg({ config: { peers: [], interface: { addresses: {} } } })) } : api(r));
  const r2 = await W.registerWarpWg({ request: bare, now });
  assert.deepEqual(r2.reserved, [169, 187, 57]);
  assert.equal(r2.endpoints.v4, '162.159.192.7');
  assert.equal(r2.endpoints.v6, '2606:4700:d0::a29f:c001', 'none given → Cloudflare’s default');
  assert.deepEqual(api.calls.map(path).slice(0, 1), ['GET /reg/{id}']);
  // a peer key that is not a WireGuard key → badAnswer
  const off = async (r) => (r.method === 'POST' ? { status: 200, body: JSON.stringify(cfg({ config: { peers: [{ public_key: F.EDGE_PUB }], interface: { addresses: { v4: '172.16.0.2' } } } })) } : api(r));
  await assert.rejects(W.registerWarpWg({ request: off, now }), (e) => e.code === 'badAnswer');
});

/* ------------------------------ the account ------------------------------ */
test('the account: a WARP+ key applied — its type, warp_plus, premium_data / quota / usage in bytes, the devices, which key (its last four), when', async () => {
  const account = { id: 'acc-9', account_type: 'limited', warp_plus: true, premium_data: 27670000000000000, quota: '27670000000000000', usage: 0, role: 'child', referral_count: 3, license: F.LICENSE };
  const { reg, api } = await register({ account, devices: [{ id: 'a' }, { id: 'b' }, { id: F.DEVICE }] }, { license: F.LICENSE });
  assert.deepEqual(api.calls.slice(-3).map(path), ['PUT /reg/{id}/account', 'GET /reg/{id}/account', 'GET /reg/{id}/account/devices']);
  assert.deepEqual(api.calls.at(-3).body, { license: F.LICENSE });
  assert.deepEqual(reg.info, {
    kind: 'wireguard', deviceId: F.DEVICE, type: 'limited', warpPlus: true,
    premiumData: 27670000000000000, quota: 27670000000000000, usage: 0, role: 'child', referralCount: 3, devices: 3,
    license: 'applied', licenseTail: F.LICENSE.slice(-4), licenseError: '', checkedAt: '2026-10-19T08:00:00.000Z'
  });
  assert.deepEqual(reg.account, { id: F.DEVICE, type: 'limited', warpPlus: true });
  assert.deepEqual(reg.warnings, []);
  assert.equal(JSON.stringify(reg.info).includes(F.LICENSE), false, 'the key itself is not kept');
});

test('the account: PUT …/account may answer 204 with no body — applied, and the account read back says what it became', async () => {
  const { reg } = await register({ license: 204 }, { license: F.LICENSE });
  assert.equal(reg.info.license, 'applied');
  assert.equal(reg.info.type, 'unlimited');
  assert.equal(reg.info.warpPlus, true);
  assert.deepEqual(reg.warnings, []);
  // MASQUE takes the same step
  const m = await W.registerWarp({ request: F.fakeApi({ license: 204 }), now, license: F.LICENSE });
  assert.equal(m.info.kind, 'masque');
  assert.equal(m.info.license, 'applied');
  assert.equal(m.info.type, 'unlimited');
});

test('the account: a key Cloudflare refuses — refused with its words, a licenseFailed warning, the account still read (free); without a key: none', async () => {
  const { reg } = await register({ status: { 'PUT /reg/{id}/account': 403 }, errorBody: { success: false, errors: [{ code: 1300, message: 'Too many connected devices.' }] } }, { license: F.LICENSE });
  assert.equal(reg.info.license, 'refused');
  assert.match(reg.info.licenseError, /Too many connected devices/);
  assert.equal(reg.info.type, 'free');
  assert.equal(reg.info.warpPlus, false);
  assert.deepEqual(reg.warnings.map((w) => w.code), ['licenseFailed']);
  const none = await register();
  assert.equal(none.reg.info.license, 'none');
  assert.equal(none.reg.info.licenseTail, '');
  assert.equal(none.reg.info.devices, 1);
  assert.equal(none.api.calls.some((c) => c.method === 'PUT'), false);
});

test('the account: unread — GET …/account or …/devices failing is an accountUnread warning, the registration’s own account kept; odd values read as null / ""', async () => {
  const { reg } = await register({ status: { 'GET /reg/{id}/account': 500, 'GET /reg/{id}/account/devices': 429 } });
  assert.deepEqual(reg.warnings.map((w) => w.code), ['accountUnread']);
  assert.equal(reg.info.type, 'free', 'the POST answer’s account');
  assert.equal(reg.info.devices, null);
  assert.ok(reg.address.length, 'the servers can still be made');
  const odd = W.accountInfo('wireguard', 'd', { account_type: 'Platinum', warp_plus: 'yes', premium_data: -5, quota: '12x', usage: 1.5, role: 'admin' }, {}, now);
  assert.equal(odd.type, '');
  assert.equal(odd.warpPlus, false);
  assert.equal(odd.premiumData, null);
  assert.equal(odd.quota, null);
  assert.equal(odd.usage, 1.5);
  assert.equal(odd.role, '');
});

test('the WARP+ key, the token and the private key are never logged, nor in a warning — not even when Cloudflare repeats the key', async () => {
  const { reg, lines } = await register({ status: { 'PUT /reg/{id}/account': 400 }, errorBody: { errors: [{ message: `License ${F.LICENSE} is invalid` }] } }, { license: F.LICENSE });
  const text = JSON.stringify(lines) + JSON.stringify(reg.warnings) + JSON.stringify(reg.info);
  assert.equal(text.includes(F.LICENSE), false);
  assert.equal(text.includes(F.TOKEN), false);
  assert.equal(text.includes(reg.privateKey), false);
  assert.match(reg.info.licenseError, /License … is invalid/);
  assert.match(JSON.stringify(lines), new RegExp('…' + F.LICENSE.slice(-4)));
});

/* ------------------------------ the server ------------------------------ */
test('wgServerFields: chained by default — Cloudflare’s v4 edge on 2408, MTU 1280, reserved, everything through it, no noise; the real parser makes a WireGuard server of it', async () => {
  const { reg } = await register();
  const f = W.wgServerFields(reg, { use: 'chain', antiDpi: true }, '☁ WARP');
  assert.deepEqual(f, {
    protocol: 'wireguard', name: '☁ WARP', address: '162.159.192.1', port: 2408,
    privateKey: reg.privateKey, publicKey: PEER, localAddress: '172.16.0.2/32, 2606:4700:110:8a36:9c1:2b3:4d5:6e7f/128',
    mtu: '1280', allowedIPs: '0.0.0.0/0, ::/0', reserved: '0,0,0'
  });
  const s = createServer(f);
  assert.equal(s.protocol, 'wireguard');
  assert.equal(s.address, '162.159.192.1');
  assert.equal(s.port, 2408);
  const st = s.outbound.settings;
  assert.equal(st.secretKey, reg.privateKey);
  assert.equal(st.mtu, 1280);
  assert.deepEqual(st.reserved, [0, 0, 0]);
  assert.deepEqual(st.address, ['172.16.0.2/32', '2606:4700:110:8a36:9c1:2b3:4d5:6e7f/128']);
  assert.equal(st.peers[0].publicKey, PEER);
  assert.equal(st.peers[0].endpoint, '162.159.192.1:2408');
  assert.deepEqual(st.peers[0].allowedIPs, ['0.0.0.0/0', '::/0']);
  assert.equal(s.outbound._noise, undefined);
});

test('wgServerFields: direct — anti-DPI noise (and none when off), the v6 edge, my own clean IP (2408 unless given); a bad one is badAddress', async () => {
  const { reg } = await register();
  assert.equal(W.wgServerFields(reg, { use: 'direct' }).noise, 'random');
  assert.equal(createServer(W.wgServerFields(reg, { use: 'direct' })).outbound._noise, 'random');
  assert.equal('noise' in W.wgServerFields(reg, { use: 'direct', antiDpi: false }), false);
  const v6 = W.wgServerFields(reg, { use: 'direct', endpoint: 'v6' });
  assert.equal(v6.address, '2606:4700:d0::a29f:c001');
  assert.equal(createServer(v6).outbound.settings.peers[0].endpoint, '[2606:4700:d0::a29f:c001]:2408');
  assert.deepEqual([W.wgServerFields(reg, { use: 'direct', endpoint: 'custom', address: '188.114.97.3' })].map((x) => [x.address, x.port]), [['188.114.97.3', 2408]]);
  assert.deepEqual([W.wgServerFields(reg, { use: 'direct', endpoint: 'custom', address: '[2606:4700::1]:4500' })].map((x) => [x.address, x.port]), [['2606:4700::1', 4500]]);
  assert.throws(() => W.wgOptions({ use: 'direct', endpoint: 'custom', address: 'not an ip/x' }), (e) => e.code === 'badAddress');
  // a chained WARP takes no endpoint choice: the hop's server dials Cloudflare's own edge
  assert.equal(W.wgServerFields(reg, { use: 'chain', endpoint: 'custom', address: '188.114.97.3' }).address, '162.159.192.1');
  assert.throws(() => W.wgServerFields({ privateKey: 'x', publicKey: PEER, address: ['1.2.3.4/32'] }, {}), (e) => e.code === 'badAnswer');
});

/* ------------------------------ names, keys, the hop ------------------------------ */
test('accountLabels: the bare base for one account nobody uses; numbers otherwise — from 2 when the bare base is there, past the ones taken (also by « · H3» names)', () => {
  assert.deepEqual(W.accountLabels(1, '☁ WARP', []), ['☁ WARP']);
  assert.deepEqual(W.accountLabels(3, '☁ WARP', []), ['☁ WARP 1', '☁ WARP 2', '☁ WARP 3']);
  assert.deepEqual(W.accountLabels(1, '☁ WARP', [{ name: '☁ WARP · H3' }]), ['☁ WARP 2']);
  assert.deepEqual(W.accountLabels(2, '☁ WARP', [{ name: '☁ WARP' }, { name: '☁ WARP 3' }, { name: '☁ WARP 10 · H2' }]), ['☁ WARP 2', '☁ WARP 4']);
  assert.deepEqual(W.accountLabels(1, 'Home', [{ name: 'Home office' }]), ['Home'], 'a longer name is not this one');
});

test('licensePlan: one key goes on every account; several one each in order, the rest free; more keys raise the count; at most 10; a bad line named, never shown', () => {
  assert.deepEqual(W.licensePlan({ count: 3, licenses: [F.LICENSE] }), { count: 3, keys: [F.LICENSE, F.LICENSE, F.LICENSE] });
  assert.deepEqual(W.licensePlan({ count: 3, licenses: [F.LICENSE, ' ', KEY2] }), { count: 3, keys: [F.LICENSE, KEY2, ''] });
  assert.deepEqual(W.licensePlan({ count: 1, licenses: [F.LICENSE, KEY2, KEY3] }), { count: 3, keys: [F.LICENSE, KEY2, KEY3] });
  assert.deepEqual(W.licensePlan({ license: F.LICENSE }), { count: 1, keys: [F.LICENSE] }, 'the pre-1.26 single key');
  assert.deepEqual(W.licensePlan({ count: 'x' }), { count: 1, keys: [''] });
  assert.deepEqual(W.licensePlan({ count: 99 }).count, 10);
  assert.throws(() => W.licensePlan({ licenses: Array(11).fill(F.LICENSE) }), (e) => e.code === 'badLicense');
  assert.throws(() => W.licensePlan({ licenses: [F.LICENSE, 'Q1w2E3r4-T5y6U7i8'] }), (e) => {
    assert.equal(e.code, 'badLicense');
    assert.match(e.message, /^Key 2 /);
    assert.equal(e.message.includes('Q1w2E3r4'), false);
    return true;
  });
});

test('resolveHop: a server or a chain’s members — each still there, the last not an HTTP proxy (no UDP; the ones before only carry its stream); otherwise badHop', () => {
  const servers = [{ id: 's1', name: 'UK xhttp', protocol: 'vless' }, { id: 's2', name: 'hy2', protocol: 'hysteria2' }, { id: 'p', name: 'office proxy', protocol: 'http' }];
  const chains = [{ id: 'c1', name: 'Two hops', members: ['s1', 's2'] }, { id: 'c2', name: 'empty', members: [] }, { id: 'c3', name: 'via proxy', members: ['p', 's1'] }, { id: 'c4', name: 'gone', members: ['s1', 'zz'] }, { id: 'c5', name: 'ends on proxy', members: ['s1', 'p'] }];
  assert.deepEqual(W.resolveHop('s1', servers, chains), { members: ['s1'], name: 'UK xhttp' });
  assert.deepEqual(W.resolveHop('chain:c1', servers, chains), { members: ['s1', 's2'], name: 'Two hops' });
  assert.deepEqual(W.resolveHop('chain:c3', servers, chains), { members: ['p', 's1'], name: 'via proxy' }, 'an HTTP proxy first carries the VLESS stream');
  for (const v of ['', 'nope', 'chain:nope', 'chain:c2', 'chain:c4', 'chain:c5', 'p']) {
    assert.throws(() => W.resolveHop(v, servers, chains), (e) => e.code === 'badHop', v);
  }
  assert.throws(() => W.resolveHop('p', servers, chains), /HTTP proxy/);
});

/* ------------------------------ servers:addWarp ------------------------------ */
/** warpHandler over a fake store, the REAL parser, no pause (the pauses recorded). */
function handler(over = {}) {
  const store = {
    servers: [{ id: 'hop', name: 'UK xhttp', protocol: 'vless' }, { id: 'px', name: 'office proxy', protocol: 'http' }],
    chains: [{ id: 'old-chain', name: 'Old', members: ['hop'] }]
  };
  const logs = [];
  const pauses = [];
  const deps = Object.assign({
    createServer,
    getServers: () => store.servers.slice(),
    setServers: (list) => { store.servers = list; },
    getChains: () => store.chains.slice(),
    setChains: (list) => { store.chains = list; },
    connected: () => false,
    socksPort: () => 47808,
    now,
    pause: async (ms) => { pauses.push(ms); },
    log: (line, level) => logs.push([level, line])
  }, over);
  return { add: W.warpHandler(deps), store, logs, pauses };
}

test('servers:addWarp, WireGuard: three accounts from two keys, one after another — numbered, each with its account, each chained over the config I picked; servers and chains saved', async () => {
  const api = F.fakeApi();
  const h = handler({ request: api });
  const res = await h.add({ kind: 'wireguard', mode: 'new', via: 'direct', count: 3, licenses: [F.LICENSE, KEY2], use: 'chain', chainWith: 'hop' });
  assert.equal(res.ok, true, res.error);
  assert.equal(api.calls.filter((c) => c.method === 'POST').length, 3);
  assert.deepEqual(api.calls.filter((c) => c.method === 'PUT').map((c) => c.body.license), [F.LICENSE, KEY2], 'the third account is free');
  assert.deepEqual(h.pauses, [2000, 2000]);
  assert.deepEqual(res.added.map((s) => [s.name, s.protocol, s.address, s.port]), [
    ['☁ WARP 1', 'wireguard', '162.159.192.1', 2408], ['☁ WARP 2', 'wireguard', '162.159.192.1', 2408], ['☁ WARP 3', 'wireguard', '162.159.192.1', 2408]]);
  // each account's own device key
  assert.equal(new Set(res.added.map((s) => s.outbound.settings.secretKey)).size, 3);
  assert.deepEqual(res.added.map((s) => s.warp.license), ['applied', 'applied', 'none']);
  assert.deepEqual(res.added.map((s) => s.warp.type), ['unlimited', 'unlimited', 'free']);
  // the chains: the hop, then the account's WARP
  assert.deepEqual(res.addedChains.map((c) => [c.name, c.members]), res.added.map((s) => [`UK xhttp → ${s.name}`, ['hop', s.id]]));
  for (const c of res.addedChains) assert.match(c.id, /^chain-[0-9a-z]+[0-9a-f]{4}$/);
  assert.deepEqual(res.accounts.map((x) => [x.name, x.serverIds, x.chainId, x.chainName, x.info.license]),
    res.added.map((s, i) => [s.name, [s.id], res.addedChains[i].id, res.addedChains[i].name, s.warp.license]));
  // saved after what was there
  assert.deepEqual(h.store.servers.map((s) => s.id), ['hop', 'px'].concat(res.added.map((s) => s.id)));
  assert.deepEqual(h.store.chains.map((c) => c.id), ['old-chain'].concat(res.addedChains.map((c) => c.id)));
  assert.deepEqual(res.chains, h.store.chains);
  assert.deepEqual(res.warnings, []);
  assert.equal('stopped' in res, false);
  const text = JSON.stringify(h.logs) + JSON.stringify(res.accounts);
  for (const k of [F.LICENSE, KEY2, F.TOKEN]) assert.equal(text.includes(k), false);
});

test('servers:addWarp, WireGuard: a chain as the hop — its members, then WARP; direct — no chain, noise on; a hop gone or an HTTP proxy is refused before any device is made', async () => {
  let api = F.fakeApi();
  let h = handler({ request: api });
  let res = await h.add({ kind: 'wireguard', mode: 'new', use: 'chain', chainWith: 'chain:old-chain' });
  assert.equal(res.ok, true, res.error);
  assert.deepEqual(res.addedChains.map((c) => [c.name, c.members]), [['Old → ☁ WARP', ['hop', res.added[0].id]]]);

  api = F.fakeApi();
  h = handler({ request: api });
  res = await h.add({ kind: 'wireguard', mode: 'new', use: 'direct', antiDpi: true });
  assert.equal(res.ok, true, res.error);
  assert.deepEqual(res.addedChains, []);
  assert.equal('chains' in res, false);
  assert.deepEqual(h.store.chains.map((c) => c.id), ['old-chain']);
  assert.equal(res.added[0].outbound._noise, 'random');
  assert.equal(res.accounts[0].chainId, null);

  for (const chainWith of ['', 'gone', 'px', 'chain:nope']) {
    api = F.fakeApi();
    h = handler({ request: api });
    res = await h.add({ kind: 'wireguard', mode: 'new', use: 'chain', chainWith, licenses: [F.LICENSE] });
    assert.equal(res.ok, false, chainWith);
    assert.equal(res.code, 'badHop');
    assert.equal(api.calls.length, 0, 'no device registered for nothing');
  }
  // a bad key too, before anything
  api = F.fakeApi();
  h = handler({ request: api });
  res = await h.add({ kind: 'wireguard', mode: 'new', use: 'chain', chainWith: 'hop', licenses: [F.LICENSE, 'nope'] });
  assert.equal(res.code, 'badLicense');
  assert.equal(api.calls.length, 0);
});

test('servers:addWarp: a batch stopped by Cloudflare keeps what was made and says why; the first one failing fails the call, nothing saved', async () => {
  const api = F.fakeApi();
  let posts = 0;
  const limited = async (r) => (r.method === 'POST' && ++posts >= 3 ? { status: 429, body: '{}' } : api(r));
  let h = handler({ request: limited });
  let res = await h.add({ kind: 'wireguard', mode: 'new', count: 4, use: 'chain', chainWith: 'hop' });
  assert.equal(res.ok, true, res.error);
  assert.equal(res.added.length, 2);
  assert.equal(res.addedChains.length, 2);
  assert.deepEqual({ code: res.stopped.code, made: res.stopped.made, wanted: res.stopped.wanted }, { code: 'rateLimited', made: 2, wanted: 4 });
  assert.match(res.stopped.detail, /429/);
  assert.equal(h.store.servers.length, 4);

  h = handler({ request: async () => ({ status: 429, body: '{}' }) });
  res = await h.add({ kind: 'wireguard', mode: 'new', count: 3, use: 'chain', chainWith: 'hop' });
  assert.equal(res.ok, false);
  assert.equal(res.code, 'rateLimited');
  assert.equal(h.store.servers.length, 2);
  assert.equal(h.store.chains.length, 1);
});

test('servers:addWarp, MASQUE: two accounts → «☁ WARP 1 · H3/H2», «☁ WARP 2 · H3/H2»; every server keeps its account; warnings carry the account’s name', async () => {
  const api = F.fakeApi({ status: { 'PUT /reg/{id}/account': 403 } });
  const h = handler({ request: api, createServer: (f) => ({ id: 'm' + Math.random().toString(36).slice(2, 8), name: f.name, protocol: f.protocol, outbound: {} }) });
  const res = await h.add({ mode: 'new', count: 2, licenses: [F.LICENSE], http: 'both' });
  assert.equal(res.ok, true, res.error);
  assert.deepEqual(res.added.map((s) => s.name), ['☁ WARP 1 · H3', '☁ WARP 1 · H2', '☁ WARP 2 · H3', '☁ WARP 2 · H2']);
  assert.deepEqual(res.accounts.map((x) => [x.name, x.serverIds.length, x.chainId, x.info.kind, x.info.license]), [['☁ WARP 1', 2, null, 'masque', 'refused'], ['☁ WARP 2', 2, null, 'masque', 'refused']]);
  for (const s of res.added) assert.equal(s.warp.kind, 'masque');
  assert.deepEqual(res.warnings.map((w) => [w.code, w.name]), [['licenseFailed', '☁ WARP 1'], ['licenseFailed', '☁ WARP 2']]);
  assert.deepEqual(res.addedChains, []);
});

test('servers:addWarp, WireGuard import: a .conf or a wireguard:// link — no network, marked imported, chained when asked; anything else is badConf', async () => {
  const conf = '[Interface]\nPrivateKey = ' + crypto.randomBytes(32).toString('base64') + '\nAddress = 172.16.0.2/32, 2606:4700:110:8a36::2/128\nMTU = 1280\n\n[Peer]\nPublicKey = ' + PEER + '\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = engage.cloudflareclient.com:2408\n';
  let h = handler({ request: async () => { throw new Error('no network for an import'); } });
  let res = await h.add({ kind: 'wireguard', mode: 'import', importText: conf, use: 'chain', chainWith: 'hop' });
  assert.equal(res.ok, true, res.error);
  assert.equal(res.added[0].name, '☁ WARP');
  assert.equal(res.added[0].protocol, 'wireguard');
  assert.equal(res.added[0].port, 2408);
  assert.deepEqual(res.added[0].warp, { kind: 'wireguard', imported: true });
  assert.deepEqual(res.addedChains[0].members, ['hop', res.added[0].id]);
  assert.deepEqual(res.accounts[0].info, { kind: 'wireguard', imported: true });

  const link = 'wireguard://' + encodeURIComponent(crypto.randomBytes(32).toString('base64')) + '@162.159.192.1:2408?publickey=' + encodeURIComponent(PEER) + '&address=172.16.0.2%2F32&reserved=1,2,3#w';
  h = handler();
  res = await h.add({ kind: 'wireguard', mode: 'import', importText: link, use: 'direct' });
  assert.equal(res.ok, true, res.error);
  assert.deepEqual(res.added[0].outbound.settings.reserved, [1, 2, 3]);
  assert.equal(res.added[0].name, '☁ WARP');
  assert.equal(res.added[0].outbound._noise, 'random', 'used directly: the noise, as for a new one');
  // my clean IP replaces the config's endpoint; chained, the config's own endpoint stays and no noise
  h = handler();
  res = await h.add({ kind: 'wireguard', mode: 'import', importText: link, use: 'direct', endpoint: 'custom', address: '188.114.97.3:4500', antiDpi: false });
  assert.deepEqual([res.added[0].address, res.added[0].port, res.added[0].outbound.settings.peers[0].endpoint, res.added[0].outbound._noise], ['188.114.97.3', 4500, '188.114.97.3:4500', undefined]);
  assert.equal('_edited' in res.added[0], false);
  h = handler();
  res = await h.add({ kind: 'wireguard', mode: 'import', importText: conf, use: 'chain', chainWith: 'hop', endpoint: 'custom', address: '188.114.97.3', antiDpi: true });
  assert.deepEqual([res.added[0].address, res.added[0].port, res.added[0].outbound._noise], ['engage.cloudflareclient.com', 2408, undefined]);

  for (const bad of ['', '{"private_key":"x"}', 'vless://u@h:1', '[Interface]\nAddress = 10.0.0.2/32\n']) {
    h = handler();
    res = await h.add({ kind: 'wireguard', mode: 'import', importText: bad, use: 'direct' });
    assert.equal(res.ok, false, bad);
    assert.equal(res.code, 'badConf', bad);
  }
});

test('router: servers:addWarp makes a chained WireGuard WARP through the real service — the server and the chain both saved', async (t) => {
  const api = F.fakeApi();
  const s = H.start({}, { warp: { request: api, now, pause: async () => {} } });
  t.after(() => s.service.shutdown());
  const res = await s.service.invoke('servers:addWarp', { kind: 'wireguard', mode: 'new', via: 'direct', use: 'chain', chainWith: H.SERVER.id, licenses: [F.LICENSE] });
  assert.equal(res.ok, true, res.error);
  assert.equal(res.added[0].protocol, 'wireguard');
  assert.equal(res.added[0].warp.license, 'applied');
  const chains = await s.service.invoke('chains:list');
  assert.deepEqual(chains.at(-1).members, [H.SERVER.id, res.added[0].id]);
  assert.equal(chains.at(-1).name, `${H.SERVER.name} → ☁ WARP`);
  assert.equal((await s.service.invoke('servers:list')).at(-1).warp.type, 'unlimited');
  assert.equal(JSON.stringify(s.logs).includes(F.LICENSE), false);
});
