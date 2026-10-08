'use strict';
/**
 * Routing profiles (docs/superpowers/specs/2026-10-09-routing-profiles-design.md
 * §1-2): the model, the migration from today's settings, the mirror both ways,
 * the selection ids and the effective "via" of a rule or the default. Pure —
 * src/main/routingProfiles.js has no store, no electron.
 */
const test = require('node:test');
const assert = require('node:assert/strict');

const RP = require('../src/main/routingProfiles');
const {
  VIA_INHERIT, VIA_NONE, DEFAULT_PROFILE_ID, newProfileId, normalizeProfile, migrateProfiles, mirrorToSettings,
  mirrorFromSettings, profileFromSettings, profileIdOf, effectiveVia, advancedTargets, isAdvancedSelection,
  resolveProcessRules, liveRoutingOf, routingPendingKeys
} = RP;

const RULES = [
  { type: 'domain', value: 'geosite:category-ir', target: 'direct' },
  { type: 'ip', value: '10.20.0.0/16', target: 'chain:c1' },
  { type: 'process', value: 'chrome.exe', target: 'sv-a' }
];
const SETTINGS = { lang: 'en', advancedRouting: true, advancedUseMode: true, routeRules: RULES, routeDefault: 'sv-b' };

test('the values the spec names', () => {
  assert.equal(VIA_INHERIT, 'inherit');
  assert.equal(VIA_NONE, 'none');
  assert.equal(DEFAULT_PROFILE_ID, 'rp-default');
  const ids = new Set();
  for (let i = 0; i < 50; i++) {
    const id = newProfileId();
    assert.match(id, /^rp-[a-z0-9]+$/);
    assert.match(id, /^[\w-]+$/);
    ids.add(id);
  }
  assert.equal(ids.size, 50, 'every new id is its own');
});

test('migration: no stored profiles → one rp-default from today’s settings, the rules identical, no via, no base', () => {
  const { profiles, changed } = migrateProfiles({ stored: undefined, settings: SETTINGS });
  assert.equal(changed, true);
  assert.equal(profiles.length, 1);
  const [p] = profiles;
  assert.deepEqual(p, { id: 'rp-default', name: 'Advanced routing', rules: RULES, def: 'sv-b', defVia: 'inherit', useMode: true, base: null });
  assert.notEqual(p.rules, RULES, 'a copy — the settings are not shared');
  assert.ok(p.rules.every((r) => !('via' in r)), 'no via');
  // fa by default, as the spec names it; an empty store gives an empty profile
  const fa = migrateProfiles({ stored: null, settings: {} }).profiles[0];
  assert.deepEqual(fa, { id: 'rp-default', name: 'روتینگ ویژه', rules: [], def: '', defVia: 'inherit', useMode: false, base: null });
  // a stored list is kept (normalized): nothing to migrate, nothing written
  const again = migrateProfiles({ stored: profiles, settings: { routeRules: [] } });
  assert.equal(again.changed, false);
  assert.deepEqual(again.profiles, profiles);
  // an empty list is the user’s own choice: no re-migration
  assert.deepEqual(migrateProfiles({ stored: [], settings: SETTINGS }), { profiles: [], changed: false });
});

test('migration of a stored list: junk dropped, duplicate ids once, a bad id replaced, unknown fields gone', () => {
  const stored = [
    null, 'x',
    { id: 'p1', name: ' Work ', rules: [{ type: 'ip', value: '1.2.3.0/24', target: 'sv-a', via: 'sv-b', extra: 1 }, null], def: 'sv-a', defVia: 'none', useMode: 1, base: 'chain:c1', junk: true },
    { id: 'p1', name: 'dup' },
    { id: 'bad id!', name: 'Bad' }
  ];
  const { profiles, changed } = migrateProfiles({ stored, settings: SETTINGS });
  assert.equal(changed, true);
  assert.deepEqual(profiles.map((p) => p.name), ['Work', 'Bad']);
  assert.deepEqual(profiles[0], { id: 'p1', name: 'Work', rules: [{ type: 'ip', value: '1.2.3.0/24', target: 'sv-a', via: 'sv-b' }], def: 'sv-a', defVia: 'none', useMode: true, base: 'chain:c1' });
  assert.match(profiles[1].id, /^rp-[a-z0-9]+$/);
});

test('normalizeProfile coerces types and keeps only the profile’s fields', () => {
  assert.equal(normalizeProfile(null), null);
  assert.equal(normalizeProfile([1]), null);
  const p = normalizeProfile({ id: 'x', name: 5, rules: [{ id: 'r1', type: 'ip', value: 42, target: 7 }, { type: 'domain', value: 'a.com', target: 'sv-a', via: '' }], def: null, defVia: '', useMode: '', base: '' });
  assert.deepEqual(p, { id: 'x', name: '5', rules: [{ id: 'r1', type: 'ip', value: '42', target: '7' }, { type: 'domain', value: 'a.com', target: 'sv-a' }], def: '', defVia: 'inherit', useMode: false, base: null });
  // direct / block / inherit / none are no base
  for (const base of ['direct', 'block', 'inherit', 'none']) assert.equal(normalizeProfile({ id: 'x', base }).base, null, base);
  assert.equal(normalizeProfile({ id: 'x', base: 'sv-a' }).base, 'sv-a');
});

test('mirror both ways: rp-default → routeRules / routeDefault / advancedUseMode, and an edit of those settings → rp-default', () => {
  const { profiles } = migrateProfiles({ stored: undefined, settings: SETTINGS });
  const edited = profiles.map((p) => Object.assign({}, p, { rules: [{ type: 'domain', value: 'b.com', target: 'sv-a', via: 'sv-b' }], def: 'direct', useMode: false, base: 'sv-b', name: 'Mine' }));
  const other = { id: 'p2', name: 'Other', rules: [{ type: 'ip', value: '1.1.1.1', target: 'sv-x' }], def: 'sv-x', defVia: 'inherit', useMode: true, base: null };
  const s = mirrorToSettings([other, ...edited], SETTINGS);
  assert.deepEqual(s.routeRules, [{ type: 'domain', value: 'b.com', target: 'sv-a', via: 'sv-b' }]);
  assert.equal(s.routeDefault, 'direct');
  assert.equal(s.advancedUseMode, false);
  assert.equal(s.lang, 'en', 'the rest of the settings untouched');
  assert.equal(SETTINGS.routeDefault, 'sv-b', 'the input is not changed');
  // nothing to mirror → the very same settings object
  assert.equal(mirrorToSettings([other], SETTINGS), SETTINGS, 'no rp-default: nothing');
  const same = mirrorToSettings(profiles, SETTINGS);
  assert.equal(same, SETTINGS, 'already equal: the same object (the caller writes nothing)');
  // …and back: the settings' three keys into rp-default, its name, base and default via kept
  const back = mirrorFromSettings([other, ...edited], SETTINGS);
  assert.deepEqual(back[0], other, 'another profile untouched');
  assert.deepEqual(back[1], { id: 'rp-default', name: 'Mine', rules: RULES, def: 'sv-b', defVia: 'inherit', useMode: true, base: 'sv-b' });
  assert.equal(mirrorFromSettings([other], SETTINGS).length, 1, 'no rp-default: nothing created');
  assert.equal(mirrorFromSettings(profiles, SETTINGS), profiles, 'already equal: the same list');
});

test('profileFromSettings is the settings’ advanced routing as a profile', () => {
  assert.deepEqual(profileFromSettings({ routeRules: 'not a list', routeDefault: 5, advancedUseMode: 'yes' }),
    { id: 'rp-default', name: 'روتینگ ویژه', rules: [], def: '5', defVia: 'inherit', useMode: true, base: null });
});

test('selection ids: plain __advanced__ is the first profile; __advanced__:<id> that profile when it exists, else null', () => {
  const list = [{ id: 'a' }, { id: 'b' }];
  assert.equal(profileIdOf('__advanced__', list), 'a');
  assert.equal(profileIdOf('__advanced__:b', list), 'b');
  assert.equal(profileIdOf('__advanced__:x', list), null);
  assert.equal(profileIdOf('__advanced__', []), null);
  assert.equal(profileIdOf('__advanced__:', list), null);
  assert.equal(profileIdOf('sv-a', list), null);
  assert.equal(profileIdOf(null, list), null);
  assert.equal(isAdvancedSelection('__advanced__'), true);
  assert.equal(isAdvancedSelection('__advanced__:rp-x'), true);
  assert.equal(isAdvancedSelection('__advanced__x'), false);
  assert.equal(isAdvancedSelection('__pool__'), false);
  assert.equal(isAdvancedSelection(undefined), false);
});

test('effectiveVia: inherit with a base → the base; inherit without → null; none → null; explicit → it; direct / block never', () => {
  const withBase = { base: 'sv-base', def: 'sv-d', defVia: 'inherit' };
  const noBase = { base: null, def: 'sv-d', defVia: 'inherit' };
  assert.equal(effectiveVia({ target: 'sv-a', via: 'inherit' }, withBase), 'sv-base');
  assert.equal(effectiveVia({ target: 'sv-a' }, withBase), 'sv-base', 'no via is inherit');
  assert.equal(effectiveVia({ target: 'sv-a', via: 'inherit' }, noBase), null);
  assert.equal(effectiveVia({ target: 'sv-a', via: 'none' }, withBase), null);
  assert.equal(effectiveVia({ target: 'sv-a', via: 'chain:c9' }, noBase), 'chain:c9');
  assert.equal(effectiveVia({ target: 'chain:c1', via: 'sv-x' }, withBase), 'sv-x');
  assert.equal(effectiveVia({ target: 'direct', via: 'sv-x' }, withBase), null);
  assert.equal(effectiveVia({ target: 'block' }, withBase), null);
  assert.equal(effectiveVia({ target: '' }, withBase), null, 'a rule not routed anywhere');
  assert.equal(effectiveVia({ target: 'sv-base' }, withBase), null, 'a target is never its own base');
  assert.equal(effectiveVia({ target: 'sv-a', via: 'sv-a' }, noBase), null, 'nor its own explicit via');
  assert.equal(effectiveVia({ target: 'chain:c1', via: 'chain:c1' }, withBase), null, 'a chain neither');
  assert.equal(effectiveVia({ target: 'chain:c1' }, Object.assign({}, withBase, { base: 'chain:c1' })), null, 'nor a chain riding the inherited base it is');
  assert.equal(effectiveVia('def', Object.assign({}, withBase, { def: 'sv-z', defVia: 'sv-z' })), null, 'the default neither');
  assert.equal(effectiveVia('def', withBase), 'sv-base');
  assert.equal(effectiveVia('def', Object.assign({}, withBase, { defVia: 'none' })), null);
  assert.equal(effectiveVia('def', Object.assign({}, withBase, { defVia: 'sv-z' })), 'sv-z');
  assert.equal(effectiveVia('def', Object.assign({}, withBase, { def: 'direct' })), null);
  // today's plans have neither base nor via: never a via
  assert.equal(effectiveVia({ target: 'sv-a' }, { def: 'sv-b' }), null);
  assert.equal(effectiveVia('def', { def: 'sv-b' }), null);
});

test('advancedTargets: the targets, the bases they go through, and what the machine dials itself', () => {
  const plan = {
    base: 'sv-base', def: 'sv-base', defVia: 'none',
    rules: [{ target: 'sv-a' }, { target: 'chain:c1', via: 'none' }, null, { target: 'sv-c', via: 'chain:c2' }, { target: 'direct' }, { target: 'sv-a', via: 'none' }]
  };
  assert.deepEqual(advancedTargets(plan), {
    targets: ['sv-a', 'chain:c1', 'sv-c', 'direct', 'sv-base'],
    vias: ['sv-base', 'chain:c2'],
    entries: ['sv-base', 'chain:c1', 'chain:c2', 'direct', 'sv-a']
  });
  // today's plan: the entries are the targets, in the same order
  const today = advancedTargets({ rules: [{ target: 'sv-a' }, { target: 'sv-b' }, { target: 'sv-a' }], def: 'sv-c' });
  assert.deepEqual(today, { targets: ['sv-a', 'sv-b', 'sv-c'], vias: [], entries: ['sv-a', 'sv-b', 'sv-c'] });
});

test('resolveProcessRules: a process rule becomes the ip rule of its addresses, its via kept; without addresses the rules are as they are', () => {
  const rules = [{ type: 'process', value: 'chrome.exe', target: 'sv-a' }, { type: 'process', value: 'tg.exe', target: 'sv-b', via: 'sv-c' }, { type: 'domain', value: 'a.com', target: 'direct' }];
  assert.equal(resolveProcessRules(rules, undefined), rules);
  assert.deepEqual(resolveProcessRules(rules, { 'chrome.exe': ['1.1.1.1', '2.2.2.2'] }), [
    { type: 'ip', value: '1.1.1.1,2.2.2.2', target: 'sv-a' },
    { type: 'ip', value: '', target: 'sv-b', via: 'sv-c' },
    { type: 'domain', value: 'a.com', target: 'direct' }
  ]);
});

test('reconnect state: an edit of the live profile or of a chain the live connection uses is pending; a rename is not', () => {
  const profile = { id: 'p1', name: 'Work', rules: [{ type: 'ip', value: '1.1.1.1', target: 'chain:c1', via: 'sv-b' }], def: 'sv-a', defVia: 'chain:c2', useMode: false, base: null };
  const chains = [{ id: 'c1', name: 'One', members: ['sv-a', 'sv-b'] }, { id: 'c2', name: 'Two', members: ['sv-c', 'sv-d'] }, { id: 'c3', name: 'Other', members: ['sv-a', 'sv-c'] }];
  const plan = Object.assign({ mode: 'advanced', profileId: 'p1' }, profile);
  const live = liveRoutingOf({ serverId: '__advanced__:p1', plan, profiles: [profile], chains });
  assert.deepEqual(routingPendingKeys(live, [profile], chains), []);
  assert.deepEqual(routingPendingKeys(live, [Object.assign({}, profile, { name: 'Renamed' })], chains), [], 'a rename changes no config');
  assert.deepEqual(routingPendingKeys(live, [Object.assign({}, profile, { def: 'sv-b' })], chains), ['routingProfiles']);
  assert.deepEqual(routingPendingKeys(live, [], chains), ['routingProfiles'], 'deleted');
  const edit = (id, members) => chains.map((c) => (c.id === id ? Object.assign({}, c, { members }) : c));
  assert.deepEqual(routingPendingKeys(live, [profile], edit('c1', ['sv-b', 'sv-a'])), ['chains'], 'a target chain');
  assert.deepEqual(routingPendingKeys(live, [profile], edit('c2', ['sv-c'])), ['chains'], 'a base chain');
  assert.deepEqual(routingPendingKeys(live, [profile], edit('c3', ['sv-c'])), [], 'a chain it does not use');
  assert.deepEqual(routingPendingKeys(live, [profile], chains.map((c) => Object.assign({}, c, { name: 'x' }))), [], 'a chain renamed');
  // a chain connected to directly: its id is the connect's
  const direct = liveRoutingOf({ serverId: 'c3', plan: { mode: 'chain', chain: [] }, profiles: [], chains });
  assert.deepEqual(routingPendingKeys(direct, [], edit('c3', ['sv-d', 'sv-a'])), ['chains']);
  // a single server: nothing of this kind to be out of sync with
  const single = liveRoutingOf({ serverId: 'sv-a', plan: { mode: 'single' }, profiles: [profile], chains });
  assert.deepEqual(routingPendingKeys(single, [], []), []);
  assert.deepEqual(routingPendingKeys(null, [], []), []);
});
