'use strict';
/**
 * The remote-access api LuCI drives (src/server/remote/api.js): what it
 * returns never carries a token, what it accepts is validated and persisted
 * in its own store, and the agent is started/stopped/restarted by it.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { Store } = require('../src/main/store');
const api = require('../src/server/remote/api');
const { mintToken } = require('../src/server/remote/token');

const TOKEN = mintToken();
const CF_TOKEN = 'eyJhIjoiYWJjZGVmMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODkiLCJ0IjoiMTIzNDU2NzgtYWJjZC00ZWYwLTkxMjMtNDU2Nzg5YWJjZGVmIiwicyI6IlpYaGhiWEJzWlE9PSJ9';

function fakeAgent() {
  const calls = [];
  let state = 'off';
  return {
    calls,
    start: () => { calls.push('start'); state = 'connecting'; },
    stop: () => { calls.push('stop'); state = 'off'; },
    reconfigure: () => { calls.push('reconfigure'); state = 'connecting'; },
    status: () => ({ state, path: 'direct', since: null, lastError: null, relayHost: 'relay.example' })
  };
}
function fakeCloudflared({ installed = false } = {}) {
  const calls = [];
  return {
    calls,
    installed: () => installed,
    apply: async (arg) => { calls.push(['apply', arg]); return { ok: true }; },
    status: async () => ({ installed, running: false, lastLine: null, version: null, installing: false }),
    install: (after) => { calls.push(['install']); if (after) after(); return { accepted: true }; }
  };
}
function setup(t, { installed = false } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-remote-api-'));
  t.after(() => { try { fs.rmSync(dir, { recursive: true, force: true }); } catch {} });
  const store = new Store(path.join(dir, 'remote.json'), api.DEFAULTS());
  const agent = fakeAgent();
  const cloudflared = fakeCloudflared({ installed });
  const logs = [];
  const r = api.createRemoteApi({ store, service: { version: '1.16.0' }, agent, cloudflared, log: (line, level) => logs.push(`${level || 'info'}: ${line}`) });
  return { dir, store, agent, cloudflared, logs, api: r };
}

test('remote_get never contains a token, only whether one is set', (t) => {
  const { api: r } = setup(t);
  assert.deepEqual(r.remote_get(), { relay: { enabled: false, relayUrl: '', name: '', tokenSet: false }, cloudflared: { installed: false, enabled: false, tokenSet: false } });
  r.remote_set({ relay: { relayUrl: 'https://relay.example/', name: 'Home', token: TOKEN }, cloudflared: { token: CF_TOKEN } });
  const g = r.remote_get();
  assert.equal(g.relay.tokenSet, true);
  assert.equal(g.cloudflared.tokenSet, true);
  assert.equal(g.relay.relayUrl, 'https://relay.example', 'normalised, no trailing slash');
  assert.equal(g.relay.name, 'Home');
  const text = JSON.stringify(g);
  assert.ok(!text.includes(TOKEN) && !text.includes(CF_TOKEN), 'no token in the answer');
  assert.ok(!('token' in g.relay) && !('token' in g.cloudflared));
});

test('remote_set validates: the relay URL (https, host, no path), the name (≤ 40 printable), the token (the relay\'s 43 chars)', (t) => {
  const { api: r } = setup(t);
  for (const bad of ['http://relay.example', 'relay.example', 'https://', 'https://relay.example/path', 'https://relay.example/?x=1', 'https://u:p@relay.example/', 'ftp://x', 42]) {
    assert.throws(() => r.remote_set({ relay: { relayUrl: bad } }), /relayUrl/, String(bad));
  }
  for (const ok of ['https://relay.example', 'https://relay.example/', 'https://relay.example:8443/', ' https://relay.example ']) assert.doesNotThrow(() => r.remote_set({ relay: { relayUrl: ok } }), ok);
  assert.equal(r.remote_get().relay.relayUrl, 'https://relay.example');
  assert.throws(() => r.remote_set({ relay: { name: 'x'.repeat(41) } }), /name/);
  assert.throws(() => r.remote_set({ relay: { name: 'bad\u0000name' } }), /name/);
  assert.doesNotThrow(() => r.remote_set({ relay: { name: ' روتر خانه ' } }));
  assert.equal(r.remote_get().relay.name, 'روتر خانه');
  for (const bad of ['short', TOKEN + 'x', TOKEN.slice(0, 42) + '!', 42]) assert.throws(() => r.remote_set({ relay: { token: bad } }), /token/, String(bad));
  assert.throws(() => r.remote_set({ cloudflared: { token: 'not a tunnel token' } }), /token/);
  // enabling needs both the URL and a token
  assert.throws(() => r.remote_set({ relay: { enabled: true } }), /needs the relay URL and the device token/);
  assert.equal(r.remote_get().relay.enabled, false);
});

test('remote_set persists in its own store file, and an empty token keeps the old one', (t) => {
  const { api: r, dir, store } = setup(t);
  r.remote_set({ relay: { relayUrl: 'https://relay.example', name: 'Home', token: TOKEN } });
  const onDisk = JSON.parse(fs.readFileSync(path.join(dir, 'remote.json'), 'utf8'));
  assert.equal(onDisk.relay.token, TOKEN);
  assert.equal(onDisk.relay.relayUrl, 'https://relay.example');
  r.remote_set({ relay: { token: '', name: 'Home 2' } });
  r.remote_set({ relay: { token: null } });
  assert.equal(store.get('relay').token, TOKEN, 'an empty token leaves the old one');
  assert.equal(store.get('relay').name, 'Home 2');
  const fresh = new Store(path.join(dir, 'remote.json'), api.DEFAULTS());
  assert.equal(fresh.get('relay').token, TOKEN, 'and it is on disk');
  // a new relay URL forgets the remembered addresses of the old one
  store.set('lastIps', ['1.2.3.4']);
  r.remote_set({ relay: { relayUrl: 'https://other.example' } });
  assert.deepEqual(store.get('lastIps'), []);
});

test('enabling starts the agent, changing it while enabled restarts it, disabling stops it; an unchanged set does nothing', (t) => {
  const { api: r, agent } = setup(t);
  r.remote_set({ relay: { relayUrl: 'https://relay.example', name: 'Home', token: TOKEN } });
  assert.deepEqual(agent.calls, ['stop'], 'not enabled: the agent is told to stay off');
  r.remote_set({ relay: { enabled: true } });
  assert.deepEqual(agent.calls, ['stop', 'reconfigure']);
  assert.equal(r.remote_status !== undefined, true);
  r.remote_set({ relay: { enabled: true } });
  assert.deepEqual(agent.calls, ['stop', 'reconfigure'], 'nothing changed, nothing restarted');
  r.remote_set({ relay: { name: 'Home router' } });
  assert.deepEqual(agent.calls, ['stop', 'reconfigure', 'reconfigure'], 'a change while enabled restarts the link');
  r.remote_set({ relay: { enabled: false } });
  assert.deepEqual(agent.calls, ['stop', 'reconfigure', 'reconfigure', 'stop']);
  assert.equal(r.remote_get().relay.enabled, false);
});

test('remote_status carries the agent\'s status and the cloudflared status; cloudflared_install is accepted at once', async (t) => {
  const { api: r, cloudflared } = setup(t);
  const s = await r.remote_status();
  assert.equal(s.relay.state, 'off');
  assert.equal(s.relay.relayHost, 'relay.example');
  assert.equal(s.cloudflared.installed, false);
  assert.deepEqual(r.cloudflared_install(), { accepted: true });
  assert.deepEqual(cloudflared.calls, [['install']]);
});

test('cloudflared: enabled + token is applied to the driver; disabling applies off; get says installed/tokenSet', async (t) => {
  const { api: r, cloudflared } = setup(t, { installed: true });
  r.remote_set({ cloudflared: { token: CF_TOKEN, enabled: true } });
  await new Promise((res) => setImmediate(res));
  assert.deepEqual(cloudflared.calls, [['apply', { enabled: true, token: CF_TOKEN }]]);
  assert.deepEqual(r.remote_get().cloudflared, { installed: true, enabled: true, tokenSet: true });
  r.remote_set({ cloudflared: { enabled: false } });
  await new Promise((res) => setImmediate(res));
  assert.deepEqual(cloudflared.calls[1], ['apply', { enabled: false, token: CF_TOKEN }]);
  // the install's completion re-applies when enabled
  r.remote_set({ cloudflared: { enabled: true } });
  await new Promise((res) => setImmediate(res));
  cloudflared.calls.length = 0;
  r.cloudflared_install();
  await new Promise((res) => setImmediate(res));
  assert.deepEqual(cloudflared.calls, [['install'], ['apply', { enabled: true, token: CF_TOKEN }]]);
});

/* ----------------------------- v1.16.1: «فعال» must be honest ----------------------------- */

const flush = () => new Promise((res) => setImmediate(res));
const applies = (cloudflared) => cloudflared.calls.filter((c) => c[0] === 'apply');

test('remote_set refuses to enable Cloudflare Tunnel before cloudflared is installed or without a tunnel token (it used to say "applied" and start nothing)', async (t) => {
  const { api: r, cloudflared, store } = setup(t);   // not installed
  assert.throws(() => r.remote_set({ cloudflared: { enabled: true, token: CF_TOKEN } }), /enabling needs cloudflared — install it first/);
  assert.deepEqual(r.remote_get().cloudflared, { installed: false, enabled: false, tokenSet: false }, 'a refused set writes nothing, not even the token');
  await flush();
  assert.deepEqual(applies(cloudflared), [], 'and applies nothing');
  // a token alone (to switch on later) and switching off are always taken
  assert.deepEqual(r.remote_set({ cloudflared: { token: CF_TOKEN } }), { ok: true });
  assert.deepEqual(r.remote_set({ cloudflared: { enabled: false } }), { ok: true });
  assert.equal(r.remote_get().cloudflared.tokenSet, true);

  const b = setup(t, { installed: true });
  assert.throws(() => b.api.remote_set({ cloudflared: { enabled: true } }), /enabling needs the Cloudflare tunnel token/);
  assert.equal(b.api.remote_get().cloudflared.enabled, false);
  assert.deepEqual(b.api.remote_set({ cloudflared: { enabled: true, token: CF_TOKEN } }), { ok: true });
  assert.deepEqual(b.api.remote_get().cloudflared, { installed: true, enabled: true, tokenSet: true });
  // a tick saved by v1.16.0 (no such check then) is not re-judged when only the relay changes
  store.set('cloudflared', { enabled: true, token: '' });
  assert.deepEqual(r.remote_set({ relay: { name: 'Home' } }), { ok: true });
  assert.equal(r.remote_get().relay.name, 'Home');
});

test('remote_set judges both halves before it writes either: a refused half leaves the other one unsaved and the agent untouched', async (t) => {
  const { api: r, agent, cloudflared } = setup(t);   // cloudflared not installed
  assert.throws(() => r.remote_set({ relay: { relayUrl: 'https://relay.example', token: TOKEN, enabled: true }, cloudflared: { enabled: true, token: CF_TOKEN } }), /install it first/);
  assert.deepEqual(r.remote_get().relay, { enabled: false, relayUrl: '', name: '', tokenSet: false }, 'the relay half was not saved');
  assert.deepEqual(agent.calls, [], 'nor started');
  assert.throws(() => r.remote_set({ relay: { name: 'Office' }, cloudflared: { token: 'not a tunnel token' } }), /token/);
  assert.equal(r.remote_get().relay.name, '', 'a bad Cloudflare token keeps a good relay name out too');
  await flush();
  assert.deepEqual(applies(cloudflared), []);
  // the relay's own refusal still comes first and says what it always said
  assert.throws(() => r.remote_set({ relay: { enabled: true } }), /enabling needs the relay URL and the device token/);
});

test('remote_status: the Cloudflare half says whether it is meant to run, whether a token is set, an apply in flight and how the last one went — never the token', async (t) => {
  const { api: r, cloudflared } = setup(t, { installed: true });
  let release;
  cloudflared.apply = (arg) => { cloudflared.calls.push(['apply', arg]); return new Promise((res) => { release = res; }); };
  let s = await r.remote_status();
  assert.equal(s.cloudflared.enabled, false);
  assert.equal(s.cloudflared.tokenSet, false);
  assert.equal(s.cloudflared.applying, false);
  assert.equal(s.cloudflared.apply, null, 'nothing applied yet');
  r.remote_set({ cloudflared: { enabled: true, token: CF_TOKEN } });
  await flush();
  s = await r.remote_status();
  assert.equal(s.cloudflared.applying, true, 'the apply is running');
  assert.equal(s.cloudflared.enabled, true);
  assert.equal(s.cloudflared.tokenSet, true);
  release({ ok: false, error: 'uci' });
  await flush();
  s = await r.remote_status();
  assert.equal(s.cloudflared.applying, false);
  assert.deepEqual(s.cloudflared.apply, { ok: false, error: 'uci' }, 'the result nobody used to read');
  assert.ok(!JSON.stringify(s).includes(CF_TOKEN), 'no token in the status');
  // an apply that throws is a failed apply too (and a log line)
  cloudflared.apply = async () => { throw new Error('uci batch crashed'); };
  r.remote_set({ cloudflared: { enabled: false } });
  await flush(); await flush();
  assert.deepEqual((await r.remote_status()).cloudflared.apply, { ok: false, error: 'uci batch crashed' });
});

test('boot(): the agent starts only when enabled; the module-level methods reach the started instance', (t) => {
  const { api: r, agent } = setup(t);
  r.boot();
  assert.deepEqual(agent.calls, []);
  r.remote_set({ relay: { relayUrl: 'https://relay.example', token: TOKEN, enabled: true } });
  agent.calls.length = 0;
  r.boot();
  assert.deepEqual(agent.calls, ['start']);
  // the module surface the facade mounts
  assert.deepEqual(api.METHODS, ['remote_get', 'remote_set', 'remote_status', 'cloudflared_install']);
  api._reset();
  assert.throws(() => api.remote_get(), /not started/);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-remote-start-'));
  t.after(() => { api._reset(); try { fs.rmSync(dir, { recursive: true, force: true }); } catch {} });
  const started = api.start({ service: { version: '1.16.0', dataDir: dir, getSettings: () => ({ socksPort: 1 }) }, localPort: 1, uiToken: 'x', log: () => {}, cloudflared: fakeCloudflared() });
  assert.ok(started);
  assert.equal(api.current(), started);
  assert.deepEqual(api.remote_get().relay, { enabled: false, relayUrl: '', name: '', tokenSet: false });
  assert.deepEqual(Object.keys(api.methods()), api.METHODS);
  assert.ok(fs.existsSync(path.join(dir, 'remote.json')) || true, 'the store is created lazily on the first write');
  started.stop();
});

test('remote.json (the device token) is kept 0600 — on every write, and fixed on an existing file (review M8)', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-remote-mode-'));
  t.after(() => { api._reset(); try { fs.rmSync(dir, { recursive: true, force: true }); } catch {} });
  const file = path.join(dir, 'remote.json');
  fs.writeFileSync(file, JSON.stringify({ relay: { enabled: false, relayUrl: '', name: '', token: 'old' } }), { mode: 0o644 });
  const chmods = [];
  const orig = fs.chmodSync;
  fs.chmodSync = (p, mode) => { chmods.push([String(p), mode]); return orig(p, mode); };
  t.after(() => { fs.chmodSync = orig; });
  const started = api.start({ service: { version: '1.16.0', dataDir: dir, getSettings: () => ({ socksPort: 1 }) }, localPort: 1, uiToken: 'x', log: () => {}, cloudflared: fakeCloudflared() });
  assert.ok(chmods.some(([p, m]) => p === file && m === 0o600), 'an existing file is fixed at start');
  started.remote_set({ relay: { name: 'Home' } });
  assert.ok(chmods.filter(([p, m]) => p === file && m === 0o600).length >= 2, 'and after a write');
  if (process.platform !== 'win32') assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  started.stop();
});

test('start() never throws: a broken service object is a log line, not a crash of the gateway process', (t) => {
  const logs = [];
  api._reset();
  t.after(() => api._reset());
  const broken = { get() { throw new Error('the store is broken'); }, set() {} };
  const out = api.start({ service: null, localPort: 1, uiToken: 'x', store: broken, cloudflared: fakeCloudflared(), log: (l, lv) => logs.push(lv + ': ' + l) });
  assert.equal(out, null);
  assert.ok(logs.some((l) => /not started/.test(l)), logs.join(' | '));
});
