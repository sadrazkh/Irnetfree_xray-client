'use strict';
// A group's member that stays dead leaves the running config and the app tests it instead (groupEvict.js):
// the core's own check keeps probing a dead member, and each probe whose TLS handshake fails leaves a socket behind.
const test = require('node:test');
const assert = require('node:assert/strict');
const B = require('../src/main/configBuilder');
const { groupRecord } = require('../src/main/groups');
const { GroupEvictor, groupRecordsOf } = require('../src/main/groupEvict');

const srv = (id, address, port) => ({ id, name: id.toUpperCase(), protocol: 'vless', address, port,
  outbound: { protocol: 'vless', settings: { vnext: [{ address, port, users: [{ id: '7d2f0c3b-1e4a-4b6d-9c8e-0a1b2c3d4e5f', encryption: 'none' }] }] }, streamSettings: { network: 'tcp', security: 'none' } } });
const byId = { a: srv('a', 'a.example.net', 443), b: srv('b', 'b.example.net', 443), c: srv('c', 'c.example.net', 443) };
const grp = groupRecord({ id: 'grp-x', name: 'X', members: [{ id: 'a' }, { id: 'b' }, { id: 'c', address: '104.16.1.1', port: 2053 }] }, byId);
const SETTINGS = { socksPort: 41500, httpPort: 41501, apiPort: 41502, routingMode: 'global', geoAssets: false, dnsManaged: false, logLevel: 'warning' };
const key = (id, address, port) => B.groupMemberKey('grp-x', { id, address, port });

/** The live payload the poller sends for the plan's config, with these verdicts. */
function payload(cfg, alive) {
  return cfg.groupTags.map((g) => Object.assign({}, g, { members: g.members.map((m, i) => Object.assign({}, m, { alive: alive[i] })) }));
}

test('the builder leaves a set-aside member out — never the whole group — and the live map says who the app may test', () => {
  const full = B.buildConfig({ mode: 'single', server: grp }, SETTINGS);
  assert.deepEqual(full.groupTags[0].members.map((m) => [m.id, m.direct]), [['a', true], ['b', true], ['c', true]]);
  const less = B.buildConfig({ mode: 'single', server: grp }, Object.assign({}, SETTINGS, { groupSkip: [key('b', 'b.example.net', 443)] }));
  assert.deepEqual(less.groupTags[0].members.map((m) => m.id), ['a', 'c']);
  assert.deepEqual(less.outbounds.filter((o) => /~gm\d$/.test(o.tag)).map((o) => o.settings.vnext[0].address), ['a.example.net', '104.16.1.1']);
  assert.equal(less.routing.balancers[0].fallbackTag, 'proxy~gm0');
  const all = [key('a', 'a.example.net', 443), key('b', 'b.example.net', 443), key('c', '104.16.1.1', 2053)];
  assert.deepEqual(B.buildConfig({ mode: 'single', server: grp }, Object.assign({}, SETTINGS, { groupSkip: all })).groupTags[0].members.map((m) => m.id), ['a', 'b', 'c'], 'all of them: none left out');
  // a group behind a hop: the app cannot test its members as the core dials them
  const behind = B.buildConfig({ mode: 'chain', chain: [byId.a, grp] }, SETTINGS);
  assert.equal(behind.groupTags[0].members.every((m) => m.direct === false), true);
});

test('dead for 90 s while another member answers: set aside, said, a reload wanted; never the last that might answer, never one behind a hop', () => {
  let now = 1000000;
  const e = new GroupEvictor({ now: () => now });
  e.reset({ mode: 'single', server: grp });
  assert.deepEqual(groupRecordsOf({ mode: 'single', server: grp }), [grp]);
  const cfg = B.buildConfig({ mode: 'single', server: grp }, SETTINGS);
  assert.deepEqual(e.update(payload(cfg, [true, false, null])), [], 'first seen dead: a streak starts');
  now += 60000;
  assert.deepEqual(e.update(payload(cfg, [true, false, null])), []);
  assert.equal(e.takeReload(), false);
  now += 31000;
  const lines = e.update(payload(cfg, [true, false, null]));
  assert.equal(lines.length, 1);
  assert.match(lines[0].line, /^Group X: B \(b\.example\.net:443\) has not answered for 90 s — taken out of the running config/);
  assert.equal(lines[0].level, 'warn');
  assert.deepEqual(e.skip(), [key('b', 'b.example.net', 443)]);
  assert.equal(e.takeReload(), true);
  assert.equal(e.takeReload(), false, 'taken once');
  // still dead in the running config until the reload lands: said once, not again every 90 s
  now += 95000;
  assert.deepEqual(e.update(payload(cfg, [true, false, null])), []);
  assert.deepEqual(e.skip(), [key('b', 'b.example.net', 443)]);
  // a member that comes back alive before 90 s: its streak ends
  const f = new GroupEvictor({ now: () => now });
  f.reset({ mode: 'single', server: grp });
  f.update(payload(cfg, [true, false, true]));
  now += 50000; f.update(payload(cfg, [true, true, true]));
  now += 50000; assert.deepEqual(f.update(payload(cfg, [true, false, true])), [], 'a new streak, not 100 s of one');
  // nobody answers: nothing is set aside (the core's fallback stays)
  const g = new GroupEvictor({ now: () => now });
  g.reset({ mode: 'single', server: grp });
  g.update(payload(cfg, [false, false, false]));
  now += 200000;
  assert.deepEqual(g.update(payload(cfg, [false, false, false])), []);
  assert.deepEqual(g.skip(), []);
  // behind a hop: left to the core
  const behind = B.buildConfig({ mode: 'chain', chain: [byId.a, grp] }, SETTINGS);
  const h = new GroupEvictor({ now: () => now });
  h.reset({ mode: 'chain', chain: [byId.a, grp] });
  h.update(payload(behind, [true, false, true]));
  now += 200000;
  assert.deepEqual(h.update(payload(behind, [true, false, true])), []);
});

test('a set-aside member: tested after 3 min, then twice as long after each miss (up to 24 min); back only after two answers in a row; reloads at least 60 s apart, a failed one asked again', () => {
  let now = 5000000;
  const e = new GroupEvictor({ now: () => now });
  e.reset({ mode: 'single', server: grp });
  const cfg = B.buildConfig({ mode: 'single', server: grp }, SETTINGS);
  e.update(payload(cfg, [true, false, false]));
  now += 91000;
  assert.equal(e.update(payload(cfg, [true, false, false])).length, 2);
  assert.match(e.update(payload(cfg, [true, false, false])).concat([{ line: '' }])[0].line, /^$/, 'said once');
  assert.equal(e.takeReload(), true);
  assert.deepEqual(e.due(), [], 'not before 3 min');
  now += 180000;
  const due = e.due();
  assert.deepEqual(due.map((d) => [d.key, d.record.address, d.label]), [
    [key('b', 'b.example.net', 443), 'b.example.net', 'B (b.example.net:443)'],
    [key('c', '104.16.1.1', 2053), '104.16.1.1', 'C (104.16.1.1:2053)']], 'each with the record a test dials — a clean-IP member at its own address');
  // b misses: 6 min to its next test, then 12, 24, 24
  assert.deepEqual(e.tested(due[0].key, false), []);
  // c answers once: not back yet — once more in 30 s
  assert.deepEqual(e.tested(due[1].key, true, 120), []);
  assert.deepEqual(e.skip(), [key('b', 'b.example.net', 443), key('c', '104.16.1.1', 2053)]);
  assert.equal(e.wantsReload(), false);
  now += 30000;
  assert.deepEqual(e.due().map((d) => d.key), [key('c', '104.16.1.1', 2053)]);
  const back = e.tested(key('c', '104.16.1.1', 2053), true, 110);
  assert.deepEqual(back, [{ line: 'Group X: C (104.16.1.1:2053) answers again (110 ms) — back in the running config', level: 'info' }]);
  assert.deepEqual(e.skip(), [key('b', 'b.example.net', 443)]);
  // c answering, then missing, starts its two answers over (here: a member set aside again)
  assert.equal(e.takeReload(), true, 'the last reload was 3.5 min ago');
  // the reload did not happen (a connect came first, or the start failed): asked again, still 60 s apart
  e.reloadFailed();
  assert.equal(e.wantsReload(), true);
  now += 30000;
  assert.equal(e.takeReload(), false, '30 s after the last: not yet');
  now += 31000;
  assert.equal(e.takeReload(), true);
  // b's backoff: 6 min after its miss, not 3
  const bKey = key('b', 'b.example.net', 443);
  const bSince = now;
  assert.deepEqual(e.due(), [], '91 s after its miss: not due');
  now = bSince - 91000 + 360000;
  assert.deepEqual(e.due().map((d) => d.key), [bKey], 'due 6 min after the miss');
  e.tested(bKey, false);
  now += 6 * 60000;
  assert.deepEqual(e.due(), [], '12 min now');
  now += 6 * 60000;
  assert.deepEqual(e.due().map((d) => d.key), [bKey]);
  e.tested(bKey, false);
  e.tested(bKey, false);
  e.tested(bKey, false);
  now += 24 * 60000;
  assert.deepEqual(e.due().map((d) => d.key), [bKey], 'capped at 24 min');
  assert.deepEqual(e.tested('nobody', true), []);
  assert.deepEqual(e.list().map((x) => [x.groupId, x.label]), [['grp-x', 'B (b.example.net:443)']], 'what the window shows');
});

test('the whole group dead at once is the line, not its members: no streak runs, and the first to answer again does not take the others out with it', () => {
  let now = 9000000;
  const e = new GroupEvictor({ now: () => now });
  e.reset({ mode: 'single', server: grp });
  const cfg = B.buildConfig({ mode: 'single', server: grp }, SETTINGS);
  e.update(payload(cfg, [false, false, false]));
  now += 120000;
  e.update(payload(cfg, [false, false, false]));
  now += 5000;
  assert.deepEqual(e.update(payload(cfg, [true, false, false])), [], 'a answers again: b and c start their streaks now, not 2 min ago');
  now += 60000;
  assert.deepEqual(e.update(payload(cfg, [true, true, false])), []);
  now += 31000;
  assert.deepEqual(e.update(payload(cfg, [true, true, false])).map((l) => l.line.split(':')[1].trim()), ['C (104.16.1.1'], 'c, dead 91 s while others answered');
});

test('a reconnect of the same plan keeps what is set aside (30 min since its last test): the connect builds without it; another plan, or a stale one, forgets it', () => {
  let now = 12000000;
  const e = new GroupEvictor({ now: () => now });
  const plan = { mode: 'single', server: grp };
  e.reset(plan);
  const cfg = B.buildConfig(plan, SETTINGS);
  e.update(payload(cfg, [true, false, true]));
  now += 91000;
  e.update(payload(cfg, [true, false, true]));
  assert.deepEqual(e.skip(), [key('b', 'b.example.net', 443)]);
  // a network change: the connect asks skip() before it builds, then resets with its plan
  const again = B.buildConfig(plan, Object.assign({}, SETTINGS, { groupSkip: e.skip() }));
  assert.deepEqual(again.groupTags[0].members.map((m) => m.id), ['a', 'c']);
  e.reset(plan);
  assert.deepEqual(e.skip(), [key('b', 'b.example.net', 443)], 'still out');
  assert.equal(e.takeReload(), false, 'the connect built without it: nothing to reload');
  // another plan without that group: forgotten
  e.reset({ mode: 'single', server: byId.a });
  assert.deepEqual(e.skip(), []);
  // stale (no test for over 30 min): forgotten too
  const f = new GroupEvictor({ now: () => now });
  f.reset(plan);
  f.update(payload(cfg, [true, false, true]));
  now += 91000;
  f.update(payload(cfg, [true, false, true]));
  now += 31 * 60000;
  f.reset(plan);
  assert.deepEqual(f.skip(), []);
});

test('main.js and the router: a stats tick feeds the evictor, the reload keeps the set-aside members out and hands the poller the new map', () => {
  const fs = require('fs');
  for (const f of ['src/main/main.js', 'src/server/service.js']) {
    const s = fs.readFileSync(require('path').join(__dirname, '..', f), 'utf8');
    assert.match(s, /groupEvict\.update\(s\.groups\)/, f);
    assert.match(s, /groupEvict\.reset\(plan\)/, f);
    assert.match(s, /groupSkip: groupEvict\.skip\(\)/, f);
    assert.match(s, /stats\.groupMap = config\.groupTags \|\| null;\s*\n\s*groupHealth\.reset\(\);/, f + ': the reload refreshes the map');
    assert.match(s, /const base = appliedSettings \? Object\.assign\(\{\}, getSettings\(\), appliedSettings\) : getSettings\(\);\s*\n\s*let settings = await effectiveSettings\(serverId, base\);/, f + ': the reload is built from what the connection was built with');
    assert.match(s, /if \(gen !== connGen \|\| userDisconnecting \|\| recovering \|\| !xray\.running\) return false;/, f + ': nothing started past a connect, a disconnect or a recovery');
    assert.match(s, /onGrow: \(\) => queueReload\(\),/, f + ': the process-route watcher queues too');
    assert.match(s, /done = await queueReload\('Groups: the core reloaded with the members that answer'\); \} finally \{ if \(!done\) groupEvict\.reloadFailed\(\); \}/, f);
    assert.match(s, /if \(pendingKeys\(\)\.length\) \{/, f + ': a pending change is not applied by a group reload');
    assert.match(s, /if \(s\.groups\) s\.setAside = groupEvict\.list\(\);/, f);
  }
  const svc = fs.readFileSync(require('path').join(__dirname, '..', 'src/server/service.js'), 'utf8');
  assert.match(svc, /lostCore = !xray\.running;/, 'the router: a reload that left no core');
  assert.match(svc, /setTimeout\(\(\) => recoverFromDrop\('reload-failed'\), 0\);/, '...is rebuilt like a drop');
  assert.match(svc, /const DROP_REASONS = new Set\(\[[^\]]*'reload-failed'/);
});
