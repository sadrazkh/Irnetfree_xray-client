'use strict';
// A group member set aside — or put back — in the running core, without a restart (groupLive.js): the core's
// HandlerService through its own CLI, on the loopback port the config's `api` listens on.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const B = require('../src/main/configBuilder');
const { groupRecord } = require('../src/main/groups');
const { GroupEvictor } = require('../src/main/groupEvict');
const { memberTags, applyLive } = require('../src/main/groupLive');

const srv = (id, address) => ({ id, name: id.toUpperCase(), protocol: 'vless', address, port: 443,
  outbound: { protocol: 'vless', settings: { vnext: [{ address, port: 443, users: [{ id: '7d2f0c3b-1e4a-4b6d-9c8e-0a1b2c3d4e5f', encryption: 'none' }] }] }, streamSettings: { network: 'tcp', security: 'none' } } });
const byId = { a: srv('a', 'a.example.net'), b: srv('b', 'b.example.net'), c: srv('c', 'c.example.net'), w: srv('w', '162.159.192.1') };
const SETTINGS = { socksPort: 41700, httpPort: 41701, apiPort: 41702, routingMode: 'global', geoAssets: false, dnsManaged: false, logLevel: 'warning' };
const key = (id, address) => B.groupMemberKey('grp-x', { id, address, port: 443 });

test('the core’s control API is in the config only when a group runs and the connect gave it a port — on loopback', () => {
  const grp = groupRecord({ id: 'grp-x', name: 'X', members: [{ id: 'a' }, { id: 'b' }] }, byId);
  const cfg = B.buildConfig({ mode: 'single', server: grp }, Object.assign({}, SETTINGS, { apiCtlPort: 41750 }));
  assert.deepEqual(cfg.api, { tag: 'api', listen: '127.0.0.1:41750', services: ['HandlerService'] });
  assert.equal('api' in B.buildConfig({ mode: 'single', server: grp }, SETTINGS), false, 'no port: none');
  assert.equal('api' in B.buildConfig({ mode: 'single', server: byId.a }, Object.assign({}, SETTINGS, { apiCtlPort: 41750 })), false, 'no group: none');
  const pool = B.buildPoolConfig ? B.buildConfig({ mode: 'pool', serversById: Object.assign({}, byId, { 'grp-x': grp }), chainsById: {}, chain: [], primary: 'grp-x',
    entries: [{ id: 'e1', name: 'E', target: 'grp-x', socksPort: 41760 }] }, Object.assign({}, SETTINGS, { apiCtlPort: 41751 })) : null;
  if (pool) assert.equal(pool.api.listen, '127.0.0.1:41751', 'the pool too');
});

test('memberTags: each running member by its key, as T~gm<i>; member 0 is the balancer’s fallback unless the group has one of its own', () => {
  const grp = groupRecord({ id: 'grp-x', name: 'X', members: [{ id: 'a' }, { id: 'b' }] }, byId);
  const tags = memberTags(B.buildConfig({ mode: 'single', server: grp }, SETTINGS).groupTags);
  assert.deepEqual([...tags], [[key('a', 'a.example.net'), { tag: 'proxy~gm0', isFallback: true }], [key('b', 'b.example.net'), { tag: 'proxy~gm1', isFallback: false }]]);
  const withFb = groupRecord({ id: 'grp-x', name: 'X', members: [{ id: 'a' }, { id: 'b' }], fallback: 'w' }, byId);
  assert.equal(memberTags(B.buildConfig({ mode: 'single', server: withFb }, SETTINGS).groupTags).get(key('a', 'a.example.net')).isFallback, false);
});

test('applyLive: rmo for a member set aside, ado of its outbound as built for one back; never the fallback member, never one the running config lacks; a failed call stops it (the caller reloads)', async () => {
  const grp = groupRecord({ id: 'grp-x', name: 'X', members: [{ id: 'a' }, { id: 'b' }, { id: 'c' }] }, byId);
  const cfg = B.buildConfig({ mode: 'single', server: grp }, Object.assign({}, SETTINGS, { apiCtlPort: 41770 }));
  const calls = [];
  const written = {};
  const run = async (bin, args) => { calls.push([bin, ...args]); return { ok: true, out: '' }; };
  const write = (f, s) => { written[f] = JSON.parse(s); };
  const base = { map: cfg.groupTags, outbounds: cfg.outbounds, bin: 'xray', port: 41770, run, write };
  // out
  let r = await applyLive(Object.assign({}, base, { changes: { out: [key('b', 'b.example.net')], back: [] } }));
  assert.deepEqual(r, { ok: true, done: [{ key: key('b', 'b.example.net'), tag: 'proxy~gm1', how: 'out' }] });
  assert.deepEqual(calls[0], ['xray', 'api', 'rmo', '--server=127.0.0.1:41770', 'proxy~gm1']);
  // back: its outbound exactly as the config built it, tag unchanged
  r = await applyLive(Object.assign({}, base, { changes: { out: [], back: [key('c', 'c.example.net')] } }));
  assert.equal(r.ok, true);
  assert.deepEqual(calls[1].slice(0, 4), ['xray', 'api', 'ado', '--server=127.0.0.1:41770']);
  assert.deepEqual(written[calls[1][4]], { outbounds: [cfg.outbounds.find((o) => o.tag === 'proxy~gm2')] });
  // the fallback member: not live (its traffic would go nowhere with the others dead) — nothing called
  calls.length = 0;
  r = await applyLive(Object.assign({}, base, { changes: { out: [key('a', 'a.example.net')], back: [] } }));
  assert.equal(r.ok, false);
  assert.deepEqual(calls, []);
  // one the running config does not have (left out at the connect): back is a reload's
  r = await applyLive(Object.assign({}, base, { changes: { out: [], back: [B.groupMemberKey('grp-x', { id: 'gone', address: 'g', port: 1 })] } }));
  assert.equal(r.ok, false);
  // the core says no
  r = await applyLive(Object.assign({}, base, { run: async () => ({ ok: false, out: 'rpc error' }), changes: { out: [key('b', 'b.example.net')], back: [] } }));
  assert.equal(r.ok, false);
  // already there is where it should be
  r = await applyLive(Object.assign({}, base, { run: async () => ({ ok: false, out: 'failed to add outbound: existing tag found: proxy~gm2' }), changes: { out: [], back: [key('c', 'c.example.net')] } }));
  assert.equal(r.ok, true);
  // no API in the running core: nothing live
  assert.equal((await applyLive(Object.assign({}, base, { port: null, changes: { out: [key('b', 'b.example.net')], back: [] } }))).ok, false);
});

test('the evictor hands over what changed since the last ask; done live, no reload is wanted for it', () => {
  let now = 1000000;
  const e = new GroupEvictor({ now: () => now });
  const grp = groupRecord({ id: 'grp-x', name: 'X', members: [{ id: 'a' }, { id: 'b' }] }, byId);
  e.reset({ mode: 'single', server: grp });
  const map = B.buildConfig({ mode: 'single', server: grp }, SETTINGS).groupTags;
  const payload = (alive) => map.map((g) => Object.assign({}, g, { members: g.members.map((m, i) => Object.assign({}, m, { alive: alive[i] })) }));
  e.update(payload([true, false]));
  now += 91000;
  e.update(payload([true, false]));
  assert.deepEqual(e.takeChanges(), { out: [key('b', 'b.example.net')], back: [] });
  assert.deepEqual(e.takeChanges(), { out: [], back: [] }, 'taken once');
  assert.equal(e.wantsReload(), true);
  e.liveApplied();
  assert.equal(e.wantsReload(), false);
  assert.deepEqual(e.skip(), [key('b', 'b.example.net')], 'still out for the next config built');
  now += 180000; e.tested(key('b', 'b.example.net'), true, 90);
  now += 30000; e.tested(key('b', 'b.example.net'), true, 80);
  assert.deepEqual(e.takeChanges(), { out: [], back: [key('b', 'b.example.net')] });
});

test('main.js and the router: a port for the API at connect, kept by a reload; the live attempt first, the reload for the rest', () => {
  for (const f of ['src/main/main.js', 'src/server/service.js']) {
    const s = fs.readFileSync(path.join(__dirname, '..', f), 'utf8').replace(/\r\n/g, '\n');
    assert.match(s, /groupSkip: groupEvict\.skip\(\), apiCtlPort: await getFreePort\(\) \}\);/, f + ': the connect');
    assert.match(s, /groupSkip: groupEvict\.skip\(\), apiCtlPort: liveApi \? liveApi\.port : await getFreePort\(\) \}\);/, f + ': the reload');
    assert.match(s, /const ch = groupEvict\.takeChanges\(\);\n\s*if \(ch\.out\.length \|\| ch\.back\.length\) \{\n\s*const live = await applyLive\(\{/, f);
    assert.match(s, /if \(live\.ok\) \{\n\s*groupEvict\.liveApplied\(\);/, f);
  }
});
