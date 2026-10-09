'use strict';
/**
 * Routing profiles on the router's service (docs/superpowers/specs/2026-10-09-
 * routing-profiles-design.md §1-2), driven for real over the gateway fakes:
 * the migration at start, the two IPC channels and the mirror both ways, a
 * profile connected by `__advanced__:<id>` and by plain `__advanced__`, a
 * target through a base, a profile or base that is gone, the reconnect state
 * for an edit of the live profile or a chain it uses, the boot intent, the
 * backup. main.js says the same in the same words (connectPath.test.js).
 */
process.env.IRNETFREE_PLATFORM = 'openwrt';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const H = require('./serviceHarness');
const { makeProxyServer } = require('../src/main/parser');

process.setMaxListeners(60);
test.after(() => H.cleanupDirs());
const { SERVER, SERVER_B, start, until, connectedCount } = H;
const SERVER_C = Object.assign(makeProxyServer({ type: 'socks', address: '192.0.2.12', port: 1080, name: 'third' }), { id: 'srv-3' });

const RULES = [{ type: 'domain', value: 'a.example', target: SERVER_B.id }];
const SETTINGS = { advancedRouting: true, routeDefault: SERVER.id, routeRules: RULES };
const profile = (over) => Object.assign({ id: 'rp-work', name: 'Work', rules: [], def: SERVER.id, defVia: 'inherit', useMode: false, base: null }, over);
const configAt = (s, i) => s.state.xray.starts[i].config;
const tags = (cfg) => cfg.outbounds.map((o) => o.tag);
const storeOf = (s) => JSON.parse(fs.readFileSync(path.join(s.dir, 'store.json'), 'utf8'));

test('at start, today’s advanced routing becomes profile rp-default — the rules identical, no via — and routing:profiles answers it', async (t) => {
  const s = start({ settings: SETTINGS });
  t.after(() => s.service.shutdown());
  const want = { id: 'rp-default', name: 'Advanced routing', rules: RULES, def: SERVER.id, defVia: 'inherit', useMode: false, base: null };
  assert.deepEqual(storeOf(s).routingProfiles, [want], 'written once, at start');
  assert.deepEqual(await s.service.invoke('routing:profiles'), { profiles: [want] });
  assert.deepEqual(storeOf(s).settings.routeRules, RULES, 'the settings stay, as rp-default’s mirror');
});

test('plain __advanced__ and __advanced__:rp-default build the very same config as before profiles', async (t) => {
  const a = start({ settings: SETTINGS });
  t.after(() => a.service.shutdown());
  await a.service.invoke('connect', '__advanced__');
  const b = start({ settings: SETTINGS });
  t.after(() => b.service.shutdown());
  await b.service.invoke('connect', '__advanced__:rp-default');
  assert.equal(JSON.stringify(configAt(a, 0)), JSON.stringify(configAt(b, 0)));
  assert.deepEqual(tags(configAt(a, 0)).filter((x) => x.startsWith('out-')), ['out-srv-2', 'out-srv-1']);
  assert.equal(a.statuses.find((x) => x.state === 'connected').serverId, '__advanced__');
  // up on a plain `__advanced__` (an old boot intent), LuCI lists it as `__advanced__:rp-default`:
  // a Connect on that item is the no-op, not a 20-40 s gateway rebuild
  assert.equal((await a.service.invoke('connect', '__advanced__:rp-default')).already, true);
  assert.equal(connectedCount(a), 1);
  assert.equal((await b.service.invoke('connect', '__advanced__')).already, true);
});

test('a profile connected by its id: a target through the base dials it; the gateway’s bypass names the base, never the target behind it', async (t) => {
  const work = profile({ base: SERVER.id, rules: [{ type: 'domain', value: 'b.example', target: SERVER_B.id }], def: SERVER_C.id, defVia: 'none' });
  const s = start({ servers: [SERVER, SERVER_B, SERVER_C], routingProfiles: [work], settings: SETTINGS });
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', '__advanced__:rp-work');
  const cfg = configAt(s, 0);
  assert.deepEqual(tags(cfg).slice(0, 3), ['base-srv-1', 'out-srv-2@srv-1', 'out-srv-3']);
  assert.equal(cfg.outbounds.find((o) => o.tag === 'out-srv-2@srv-1').streamSettings.sockopt.dialerProxy, 'base-srv-1');
  const gw = s.state.inners.find((i) => i.active);
  assert.ok(gw.bypass.includes('192.0.2.10') && gw.bypass.includes('192.0.2.12'), `the base and the direct default: ${gw.bypass}`);
  assert.equal(gw.bypass.includes('192.0.2.11'), false, 'the target behind the base is reached through it');
  const st = s.statuses.find((x) => x.state === 'connected');
  assert.equal(st.serverId, '__advanced__:rp-work');
});

test('a profile that is gone, and a base that is gone, refuse the connect in plain words — nothing is started', async (t) => {
  const s = start({ servers: [SERVER, SERVER_B], routingProfiles: [profile({ base: 'srv-gone', rules: [{ type: 'domain', value: 'b.example', target: SERVER_B.id }] })], settings: SETTINGS });
  t.after(() => s.service.shutdown());
  await assert.rejects(s.service.invoke('connect', '__advanced__:rp-nope'), /routing profile no longer exists/);
  await assert.rejects(s.service.invoke('connect', '__advanced__:rp-work'), /a base that a target goes through no longer exists/);
  // a chain base that lost a member is refused by name, as a chain target is
  const tes = { id: 'tes', name: 'Tes Chain', members: ['srv-gone', SERVER.id] };
  const c = start({ servers: [SERVER, SERVER_B], chains: [tes], routingProfiles: [profile({ base: 'chain:tes', def: SERVER_B.id })], settings: SETTINGS });
  t.after(() => c.service.shutdown());
  await assert.rejects(c.service.invoke('connect', '__advanced__:rp-work'), /The chain “Tes Chain” lost a server/);
  assert.equal(s.state.xray.starts.length + c.state.xray.starts.length, 0);
});

test('routing:setProfiles saves them normalized and mirrors rp-default into the settings; settings:set mirrors the other way', async (t) => {
  const s = start({ settings: SETTINGS });
  t.after(() => s.service.shutdown());
  const { profiles } = await s.service.invoke('routing:profiles');
  const edited = [Object.assign({}, profiles[0], { rules: [{ type: 'ip', value: '10.0.0.0/8', target: SERVER_B.id, via: SERVER.id }], def: 'direct', useMode: true, junk: 1 }), profile({ name: '  Two  ' })];
  const r = await s.service.invoke('routing:setProfiles', edited);
  assert.equal(r.ok, true);
  assert.deepEqual(r.pendingReconnect, []);
  assert.deepEqual(r.profiles.map((p) => p.name), ['Advanced routing', 'Two']);
  assert.equal('junk' in r.profiles[0], false);
  const st = storeOf(s);
  assert.deepEqual(st.routingProfiles, r.profiles);
  assert.deepEqual([st.settings.routeRules, st.settings.routeDefault, st.settings.advancedUseMode], [[{ type: 'ip', value: '10.0.0.0/8', target: SERVER_B.id, via: SERVER.id }], 'direct', true]);
  // the old renderer's path: the settings' three keys → rp-default, its base and name kept
  await s.service.invoke('settings:set', { routeRules: RULES, routeDefault: SERVER.id });
  const after = (await s.service.invoke('routing:profiles')).profiles;
  assert.deepEqual([after[0].rules, after[0].def, after[0].useMode, after[0].name], [RULES, SERVER.id, true, 'Advanced routing']);
  assert.deepEqual(after[1], r.profiles[1], 'another profile untouched');
  assert.equal((await s.service.invoke('routing:setProfiles', 'nope')).ok, false);
});

test('an edit of the live profile, or of a chain it uses, waits for a reconnect; a rename does not', async (t) => {
  const tes = { id: 'tes', name: 'Tes Chain', members: [SERVER.id, SERVER_B.id] };
  const work = profile({ rules: [{ type: 'domain', value: 'b.example', target: 'chain:tes' }] });
  const s = start({ chains: [tes], routingProfiles: [work], settings: SETTINGS });
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', '__advanced__:rp-work');
  assert.deepEqual(await s.service.invoke('settings:pending'), []);
  const renamed = await s.service.invoke('routing:setProfiles', [Object.assign({}, work, { name: 'Office' })]);
  assert.deepEqual(renamed.pendingReconnect, [], 'a name is never in the config');
  const edited = await s.service.invoke('routing:setProfiles', [Object.assign({}, work, { name: 'Office', def: SERVER_B.id })]);
  assert.deepEqual(edited.pendingReconnect, ['routingProfiles']);
  await s.service.invoke('routing:setProfiles', [Object.assign({}, work, { name: 'Office' })]);
  assert.deepEqual(await s.service.invoke('settings:pending'), [], 'put back: nothing to reconnect for');
  await s.service.invoke('chains:set', [Object.assign({}, tes, { members: [SERVER_B.id, SERVER.id] })]);
  assert.deepEqual(await s.service.invoke('settings:pending'), ['chains']);
  // a reconnect takes them in
  await s.service.invoke('settings:apply');
  await until(async () => (await s.service.invoke('settings:pending')).length === 0, 'the reconnect took the edits');
});

test('a chain connected to directly: an edit of its members waits for a reconnect too', async (t) => {
  const tes = { id: 'tes', name: 'Tes Chain', members: [SERVER.id, SERVER_B.id] };
  const s = start({ chains: [tes] });
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', 'tes');
  await s.service.invoke('chains:set', [Object.assign({}, tes, { name: 'renamed' })]);
  assert.deepEqual(await s.service.invoke('settings:pending'), []);
  await s.service.invoke('chains:set', [Object.assign({}, tes, { members: [SERVER_B.id, SERVER.id] })]);
  assert.deepEqual(await s.service.invoke('settings:pending'), ['chains']);
});

test('the router’s boot intent resumes a profile by either selection form', async (t) => {
  const work = profile({ rules: [{ type: 'domain', value: 'b.example', target: SERVER_B.id }] });
  const s = start({ connectIntent: '__advanced__:rp-work', routingProfiles: [work], settings: Object.assign({ autoConnect: true }, SETTINGS) });
  t.after(() => s.service.shutdown());
  await until(() => connectedCount(s) === 1, 'the boot connect of __advanced__:rp-work');
  assert.equal(s.statuses.find((x) => x.state === 'connected').serverId, '__advanced__:rp-work');
  // a profile deleted since: said, and the intent cleared
  const gone = start({ connectIntent: '__advanced__:rp-deleted', routingProfiles: [work], settings: Object.assign({ autoConnect: true }, SETTINGS) });
  t.after(() => gone.service.shutdown());
  await until(() => gone.logs.some((l) => /Auto-connect/.test(l.line)), 'a log line');
  assert.equal(gone.state.xray.starts.length, 0);
});

test('the backup carries the routing profiles, and a restore merges them by id', async (t) => {
  const work = profile({ rules: [{ type: 'domain', value: 'b.example', target: SERVER_B.id }] });
  const s = start({ routingProfiles: [work], settings: SETTINGS });
  t.after(() => s.service.shutdown());
  const bundle = JSON.parse(await s.service.invoke('backup:export'));
  assert.deepEqual(bundle.routingProfiles, [work]);
  const fresh = start({ settings: SETTINGS });
  t.after(() => fresh.service.shutdown());
  const r = await fresh.service.invoke('backup:import', JSON.stringify(bundle));
  assert.equal(r.ok, true);
  assert.equal(r.added.routingProfiles, 1);
  assert.deepEqual((await fresh.service.invoke('routing:profiles')).profiles.map((p) => p.id), ['rp-default', 'rp-work']);
});

test('"exit at the base": the default and a rule leave from the base itself — its own outbound, dialled directly; without a base the default refuses in plain words', async (t) => {
  const work = profile({ base: SERVER.id, def: 'base', rules: [
    { type: 'domain', value: 'b.example', target: SERVER_B.id },
    { type: 'domain', value: 'c.example', target: 'base' }
  ] });
  const s = start({ servers: [SERVER, SERVER_B, SERVER_C], routingProfiles: [work], settings: SETTINGS });
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', '__advanced__:rp-work');
  const cfg = configAt(s, 0);
  assert.deepEqual(tags(cfg).slice(0, 3), ['base-srv-1', 'out-srv-2@srv-1', 'out-srv-1']);
  const out = cfg.outbounds.find((o) => o.tag === 'out-srv-1');
  assert.equal(((out.streamSettings || {}).sockopt || {}).dialerProxy, undefined, 'the base itself dials directly');
  const rule = cfg.routing.rules.find((r) => (r.domain || []).includes('c.example'));
  assert.equal(rule.outboundTag, 'out-srv-1');
  assert.equal(cfg.routing.rules.at(-1).outboundTag, 'out-srv-1', 'everything else leaves from the base');
  const gw = s.state.inners.find((i) => i.active);
  assert.deepEqual([gw.bypass.includes('192.0.2.10'), gw.bypass.includes('192.0.2.11')], [true, false]);
  // the base moves: "exit at the base" follows it
  await s.service.invoke('routing:setProfiles', [Object.assign({}, work, { base: SERVER_C.id })]);
  await s.service.invoke('connect', '__advanced__:rp-work');
  assert.equal(configAt(s, 1).routing.rules.at(-1).outboundTag, 'out-srv-3');
  // no base at all
  const n = start({ servers: [SERVER, SERVER_B], routingProfiles: [profile({ def: 'base' })], settings: SETTINGS });
  t.after(() => n.service.shutdown());
  await assert.rejects(n.service.invoke('connect', '__advanced__:rp-work'), /through its base, but it has no base/);
  assert.equal(n.state.xray.starts.length, 0);
});

test('"exit at the base" from a base that is gone refuses the connect in plain words — a rule there is never quietly left to the default', async (t) => {
  const s = start({ servers: [SERVER, SERVER_B], routingProfiles: [profile({ base: 'srv-gone', def: SERVER_B.id, rules: [{ type: 'domain', value: 'c.example', target: 'base' }] })], settings: SETTINGS });
  t.after(() => s.service.shutdown());
  await assert.rejects(s.service.invoke('connect', '__advanced__:rp-work'), /the base this routing leaves from no longer exists/);
  const d = start({ servers: [SERVER, SERVER_B], chains: [{ id: 'empty', name: 'Empty', members: [] }], routingProfiles: [profile({ base: 'chain:empty', def: 'base' })], settings: SETTINGS });
  t.after(() => d.service.shutdown());
  await assert.rejects(d.service.invoke('connect', '__advanced__:rp-work'), /the base this routing leaves from no longer exists/);
  assert.equal(s.state.xray.starts.length + d.state.xray.starts.length, 0);
});
