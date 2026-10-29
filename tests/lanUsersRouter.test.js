'use strict';
/**
 * The users module's transparent mode on the router, the rest of it: off is
 * nothing at all; who rides which config (the per-device decisions and the
 * rule-set files); sing-box's per-target routes; the core's loopback inbounds;
 * caps from the table's counters (held, and back at the new period); the
 * devices' usage and rates; and the service wiring on a "router".
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const plan = require('../src/modules/lanUsers/router/plan');
const { applyTransparentTargets } = require('../src/modules/lanUsers/router/xrayTargets');
const { createLanRouter } = require('../src/modules/lanUsers/router');
const { buildTunConfig } = require('../src/main/tunSingbox');
const { buildConfig } = require('../src/main/configBuilder');
const { makeProxyServer } = require('../src/main/parser');
const { memFs, fakeLan, fakeGateway, fakeMeter } = require('./lanUsersRouterFakes');

const A = 'aa:bb:cc:dd:ee:01', B = 'aa:bb:cc:dd:ee:02', C = 'aa:bb:cc:dd:ee:03', D = 'aa:bb:cc:dd:ee:04';
const NOW = Date.UTC(2026, 9, 26, 12, 0, 0);
const SRV1 = Object.assign(makeProxyServer({ type: 'socks', address: '192.0.2.10', port: 1080, name: 'home' }), { id: 'srv-1' });
const SRV2 = Object.assign(makeProxyServer({ type: 'socks', address: '192.0.2.20', port: 1080, name: 'office' }), { id: 'srv-2' });
const SRV3 = Object.assign(makeProxyServer({ type: 'socks', address: '192.0.2.30', port: 1080, name: 'third' }), { id: 'srv-3' });

/* ------------------------------ the decisions ------------------------------ */

test('routedUsers: an inbound per user, by id, sorted — two on one server are two; the current connection and direct have one too; block has none', () => {
  const lu = plan.readLanUsers({ users: [{ id: 'u3', target: 'srv-2' }, { id: 'u2', target: 'chain:c1' }, { id: 'u1', target: 'srv-2' }, { id: 'u4', target: '' }, { id: 'u5', target: 'direct' }, { id: 'u6', target: 'block' }, { id: 'u7', target: 'grp-x', enabled: false }] });
  assert.deepEqual(plan.routedUsers(lu), ['u1', 'u2', 'u3', 'u4', 'u5', 'u7'], 'a disabled user\'s too: a sign-in never changes the core\'s shape');
  assert.deepEqual(plan.routedUsers(null), []);
});

test('decide: per device — the admin\'s binding for good, a sign-in for its hours, held users, block / direct / a config\'s rule-set', () => {
  const lu = plan.readLanUsers({
    config: { transparent: { enabled: true, unassigned: 'login' } },
    users: [
      { id: 'u-ali', target: 'srv-2', enabled: true }, { id: 'u-net', target: 'direct', enabled: true },
      { id: 'u-no', target: 'block', enabled: true }, { id: 'u-cap', target: 'srv-2', enabled: true }, { id: 'u-here', target: '', enabled: true }
    ],
    devices: [{ mac: A, userId: 'u-ali' }, { mac: B, userId: 'u-net' }, { mac: C, userId: 'u-cap' }, { mac: 'AA:BB:CC:DD:EE:05', blocked: true }, { mac: D, userId: 'u-gone' }]
  });
  const sessions = { 'aa:bb:cc:dd:ee:06': { userId: 'u-ali', until: NOW + 3600000 }, 'aa:bb:cc:dd:ee:07': { userId: 'u-no', until: NOW + 60000 }, 'aa:bb:cc:dd:ee:08': { userId: 'u-here', until: NOW - 1 } };
  const scan = [{ mac: A, ips: ['192.168.1.23', '2001:db8::23'] }, { mac: 'aa:bb:cc:dd:ee:06', ips: ['192.168.1.66'] }, { mac: C, ips: ['192.168.1.30'] }, { mac: 'aa:bb:cc:dd:ee:09', ips: ['192.168.1.99'] }];
  const d = plan.decide({ lu, sessions, scan, usage: { 'u-cap': { over: true } }, now: NOW, tp: [{ tag: 'lu-tp-1', userId: 'u-ali', target: 'srv-2' }, { tag: 'lu-tp-2', userId: 'u-cap', target: 'srv-2' }], portal: { ip: '192.168.1.1', port: 30822 } });
  assert.deepEqual(d.nft.blocked, ['aa:bb:cc:dd:ee:05', 'aa:bb:cc:dd:ee:07'], 'the admin\'s block; a user whose config is "block"');
  assert.deepEqual(d.nft.allowed, [A, B]);
  assert.deepEqual(d.nft.authorized, [{ mac: 'aa:bb:cc:dd:ee:06', timeoutS: 3600 }], 'a session over is no binding at all');
  assert.deepEqual(d.nft.direct, [B]);
  assert.deepEqual(d.held, { [C]: 'over' }, 'login mode: held devices meet the gate, and the page says why');
  assert.deepEqual(d.ruleSets, { 'lu-tp-1': ['192.168.1.23/32', '2001:db8::23/128', '192.168.1.66/32'], 'lu-tp-2': [] }, 'a held user\'s file is empty: its device meets the gate');
  assert.deepEqual(d.nft.counters.map(c => c.mac), [A, B, C, D, 'aa:bb:cc:dd:ee:05', 'aa:bb:cc:dd:ee:06', 'aa:bb:cc:dd:ee:07', 'aa:bb:cc:dd:ee:09'], 'every device the router knows is counted');
  assert.deepEqual(d.nft.portal, { ip: '192.168.1.1', port: 30822 });
  // allow mode: no page to explain — a held device is dropped
  const allow = plan.decide({ lu: Object.assign({}, lu, { transparent: Object.assign({}, lu.transparent, { unassigned: 'allow' }) }), sessions, scan, usage: { 'u-cap': { over: true } }, now: NOW, tp: [], portal: { ip: '192.168.1.1', port: 1 } });
  assert.ok(allow.nft.blocked.includes(C));
  assert.equal(allow.nft.portal, null);
});

test('addressOwners: a running lease\'s address is its holder\'s while the holder is online anywhere or nobody answers for it; else whoever answers now (a MAC-NAT repeater, "case C"); an address no lease names, the neighbour table\'s', () => {
  const X = 'aa:bb:cc:dd:ee:0c', R = 'aa:bb:cc:dd:ee:0a', P1 = 'aa:bb:cc:dd:ee:b1', P2 = 'aa:bb:cc:dd:ee:b2';
  // X took .23 (A's lease) and answers for it; A is online by its v6 address: the lease wins
  const online = plan.addressOwners([
    { mac: X, ips: ['192.168.1.23', '192.168.1.77'], leased: [], online: true },
    { mac: A, ips: ['192.168.1.23', '2001:db8::23'], leased: ['192.168.1.23'], online: true },
    { mac: B, ips: ['192.168.1.77'], leased: [], online: true },
    null, { ips: ['10.0.0.1'] }
  ]);
  assert.deepEqual([...online], [['192.168.1.23', A], ['192.168.1.77', X], ['2001:db8::23', A]],
    'the lease wins while its holder is online; two unleased claims: the first in the scan\'s order; a row with no MAC is no claim');
  // A away — no entry of its own anywhere in the neighbour table: .23 is X's own now (decide puts it in X's user's rule-set, never A's user's)
  const away = plan.addressOwners([
    { mac: X, ips: ['192.168.1.23'], leased: [], online: true },
    { mac: A, ips: ['192.168.1.23'], leased: ['192.168.1.23'], online: false }
  ]);
  assert.deepEqual([...away], [['192.168.1.23', X]]);
  // A away and nobody at its address: the lease keeps it A's — back on its address, A rides at once
  assert.deepEqual([...plan.addressOwners([{ mac: A, ips: ['192.168.1.23'], leased: ['192.168.1.23'], online: false }])], [['192.168.1.23', A]]);
  // case C: the repeater R answers for .23 and .24 with its own MAC; the leases name the phones P1 and P2, which the LAN never sees
  const repeater = plan.addressOwners([
    { mac: R, ips: ['192.168.1.23', '192.168.1.24'], leased: [], online: true },
    { mac: P1, ips: ['192.168.1.23'], leased: ['192.168.1.23'], online: false },
    { mac: P2, ips: ['192.168.1.24'], leased: ['192.168.1.24'], online: false }
  ]);
  assert.deepEqual([...repeater], [['192.168.1.23', R], ['192.168.1.24', R]], 'the repeater\'s: its user\'s rule-set, counter, speed and pins');
  assert.deepEqual([...plan.addressOwners(undefined)], []);
  assert.deepEqual([...plan.addressOwners([{ mac: A, ips: ['192.168.1.23'] }])], [['192.168.1.23', A]], 'a row with no `leased` (an older scan): its addresses by the neighbour table');
});

test('decide, case C and a taken address: a repeater\'s addresses are its user\'s in the rule-set, the counter, the speed and the pins; a device taking an OFFLINE device\'s address rides as itself — its own user\'s, or nothing — never the holder\'s user; the holder back online, its lease wins again', () => {
  const R = 'aa:bb:cc:dd:ee:0a', P1 = 'aa:bb:cc:dd:ee:b1', P2 = 'aa:bb:cc:dd:ee:b2', X = 'aa:bb:cc:dd:ee:0c', Y = 'aa:bb:cc:dd:ee:0d';
  const lu = plan.readLanUsers({
    config: { transparent: { enabled: true, unassigned: 'login' } },
    users: [{ id: 'u-ali', target: 'srv-2' }, { id: 'u-bob', target: 'srv-3' }, { id: 'u-net', target: 'srv-2' }],
    devices: [{ mac: A, userId: 'u-ali' }, { mac: X, userId: 'u-bob' }, { mac: R, userId: 'u-net' }]
  });
  const tp = [{ tag: 'lu-tp-1', userId: 'u-ali' }, { tag: 'lu-tp-2', userId: 'u-bob' }, { tag: 'lu-tp-3', userId: 'u-net' }];
  const portal = { ip: '192.168.1.1', port: 30822 };
  const speeds = { 'u-net': { down: 3000, up: 0 } };
  // the repeater R (u-net's) at .21 and .22, leased to the phones P1 and P2; bob's X took alice's A's .23 while A is away; Y is nobody's
  const scan = [
    { mac: R, ips: ['192.168.1.21', '192.168.1.22'], leased: [], online: true },
    { mac: P1, ips: ['192.168.1.21'], leased: ['192.168.1.21'], online: false },
    { mac: P2, ips: ['192.168.1.22'], leased: ['192.168.1.22'], online: false },
    { mac: X, ips: ['192.168.1.23', '192.168.1.24'], leased: ['192.168.1.24'], online: true },
    { mac: A, ips: ['192.168.1.23'], leased: ['192.168.1.23'], online: false },
    { mac: Y, ips: ['192.168.1.25'], leased: [], online: true }
  ];
  const d = plan.decide({ lu, scan, speeds, now: NOW, tp, portal });
  assert.deepEqual(d.ruleSets, { 'lu-tp-1': [], 'lu-tp-2': ['192.168.1.23/32', '192.168.1.24/32'], 'lu-tp-3': ['192.168.1.21/32', '192.168.1.22/32'] },
    'the repeater\'s user routes both addresses behind it; A\'s address rides bob\'s config as X\'s own — alice\'s file has nothing');
  assert.deepEqual(d.nft.ipmac, [{ mac: R, ips: ['192.168.1.21', '192.168.1.22'] }, { mac: X, ips: ['192.168.1.23', '192.168.1.24'] }]);
  assert.deepEqual(d.nft.rates, [{ mac: R, ips: ['192.168.1.21', '192.168.1.22'], down: 3000, up: 0 }], 'the repeater\'s user\'s speed polices both');
  const ctr = (dd) => Object.fromEntries(dd.nft.counters.map(c => [c.mac, c.ips]));
  assert.deepEqual(ctr(d), { [A]: [], [R]: ['192.168.1.21', '192.168.1.22'], [X]: ['192.168.1.23', '192.168.1.24'], [Y]: ['192.168.1.25'], [P1]: [], [P2]: [] },
    'the bytes behind the repeater are its own; .23\'s are X\'s while A is away; the phones\' MACs count nothing');
  // A back online — by any address, its link-local v6 is enough (the row says online): its lease wins again, X's packets from .23 are dropped
  const back = plan.decide({ lu, scan: scan.map(r => (r.mac === A ? Object.assign({}, r, { online: true }) : r)), speeds, now: NOW, tp, portal });
  assert.deepEqual([back.ruleSets['lu-tp-1'], back.ruleSets['lu-tp-2']], [['192.168.1.23/32'], ['192.168.1.24/32']]);
  assert.deepEqual(back.nft.ipmac, [{ mac: A, ips: ['192.168.1.23'] }, { mac: R, ips: ['192.168.1.21', '192.168.1.22'] }, { mac: X, ips: ['192.168.1.24'] }]);
  const text = require('../src/main/openwrtNet').buildNftRuleset({ lanUsers: back.nft });
  assert.ok(text.includes(`192.168.1.23 . ${A}`) && !text.includes(`192.168.1.23 . ${X}`), text);
  // nobody's Y takes A's address while A is away: Y's own — in no rule-set (Y meets the gate by its MAC), no pin, counted on Y
  const nobody = plan.decide({ lu, scan: [{ mac: Y, ips: ['192.168.1.23'], leased: [], online: true }, { mac: A, ips: ['192.168.1.23'], leased: ['192.168.1.23'], online: false }], now: NOW, tp, portal });
  assert.deepEqual(nobody.ruleSets, { 'lu-tp-1': [], 'lu-tp-2': [], 'lu-tp-3': [] });
  assert.deepEqual(nobody.nft.ipmac, []);
  assert.deepEqual(ctr(nobody), { [A]: [], [R]: [], [X]: [], [Y]: ['192.168.1.23'] });
});

test('decide: `shape` for the shaper — the line from config.shaping, a class per device let through with a speed or a priority other than normal; readLanUsers reads portal, shaping and the remembered devices', () => {
  const E = 'aa:bb:cc:dd:ee:05';
  const lu = plan.readLanUsers({
    config: { transparent: { enabled: true, unassigned: 'login' }, portal: { note: ' Pay by the 5th\u0001 ', contact: '0912', requests: false }, shaping: { down: '20000', up: 5000.4, smooth: false } },
    users: [{ id: 'u-ali', target: 'srv-2', priority: 'high' }, { id: 'u-bob', target: 'srv-2', priority: 'low' }, { id: 'u-cy', target: 'direct' }, { id: 'u-dan', target: 'srv-2', priority: 'junk' }, { id: 'u-eve', target: 'srv-2', priority: 'high' }],
    devices: [{ mac: A, userId: 'u-ali', remembered: true, at: NOW - 5 }, { mac: B, userId: 'u-bob' }, { mac: C, userId: 'u-cy' }, { mac: D, userId: 'u-dan' }, { mac: E, userId: 'u-eve' }]
  });
  assert.deepEqual(lu.portal, { note: 'Pay by the 5th', contact: '0912', requests: false });
  assert.deepEqual(lu.shaping, { down: 20000, up: 5000, smooth: false });
  assert.deepEqual(lu.devices[0], { mac: A, name: '', userId: 'u-ali', blocked: false, remembered: true, at: NOW - 5 });
  assert.deepEqual([lu.devices[1].remembered, lu.devices[1].at], [false, 0]);
  assert.deepEqual(plan.readLanUsers({}).portal, { note: '', contact: '', requests: true }, 'a store of before: no note, requests allowed');
  assert.deepEqual(plan.readLanUsers({}).shaping, { down: 0, up: 0, smooth: true }, 'a store of before: no line speed, smooth when the router can');
  assert.deepEqual(plan.bindingsOf(lu, {}, NOW)[A], { userId: 'u-ali', via: 'admin', remembered: true }, 'the admin\'s binding in every way, said how it got there');
  assert.deepEqual(plan.bindingsOf(lu, {}, NOW)[B], { userId: 'u-bob', via: 'admin' });
  const scan = [A, B, C, D, E].map((mac, i) => ({ mac, ips: [`192.168.1.2${i + 1}`], leased: [`192.168.1.2${i + 1}`], online: true }));
  const speeds = { 'u-cy': { down: 1000, up: 0 }, 'u-dan': { down: 500, up: 500 } };
  const d = plan.decide({ lu, scan, speeds, usage: { 'u-eve': { hold: 'all', why: 'total', over: true } }, now: NOW, tp: [], portal: null });
  assert.deepEqual(d.shape, { line: { down: 20000, up: 5000 }, classes: [
    { mac: A, ips: ['192.168.1.21'], down: 0, up: 0, prio: 'high' },        // a priority alone: no speed, a place under the line
    { mac: B, ips: ['192.168.1.22'], down: 0, up: 0, prio: 'low' },
    { mac: C, ips: ['192.168.1.23'], down: 1000, up: 0, prio: 'normal' },   // a speed alone — around the tunnel too
    { mac: D, ips: ['192.168.1.24'], down: 500, up: 500, prio: 'normal' }   // a priority the model never writes reads as normal
  ] }, 'eve, held, is no class');
  assert.deepEqual(d.nft.rates.map(r => r.mac), [C, D], 'the table\'s rates as before: the speeds alone');
  assert.deepEqual(plan.decide({ lu: plan.readLanUsers({ users: [] }), scan: [], now: NOW }).shape, { line: { down: 0, up: 0 }, classes: [] });
});

test('judgeSignIn by code: the card whose code it is, typed as a phone types it; a wrong code is "bad" like a wrong password (the compare runs either way); expired and spent as any user; `activate` for an unused card, `remember` for a user who remembers and is no card', () => {
  const { checkPassword } = require('../src/modules/lanUsers/router/portal');
  const V1 = 'HK7M-29PW', V2 = 'ABCD-EFGH';
  const lu = plan.readLanUsers({ users: [
    { id: 'u-ali', username: 'ali', password: 'pw12', remember: true, enabled: true },
    { id: 'u-v1', username: V1, password: V1, enabled: true, maxDevices: 1, voucher: { batch: 'b1', hours: 2, activatedAt: 0 } },
    { id: 'u-v2', username: V2, password: V2, enabled: true, expiresAt: NOW - 1, voucher: { batch: 'b1', hours: 2, activatedAt: NOW - 3 * 3600000 } },
    { id: 'u-fake', username: 'QRST-UVWX', password: 'QRST-UVWX', enabled: true }   // a user that looks like a card is none by code
  ] });
  let compares = 0;
  const cp = (a, b) => { compares++; return checkPassword(a, b); };
  const at = (o) => plan.judgeSignIn(Object.assign({ lu, now: NOW, mac: A, checkPassword: cp }, o));
  assert.deepEqual(at({ code: V1 }), { ok: true, user: lu.users[1], voucher: true, activate: true, remember: false });
  assert.equal(at({ code: 'hk7m 29pw' }).ok, true, 'lower case, a space for the dash');
  assert.equal(at({ code: 'HK7M-۲۹PW' }).ok, true, 'a Persian keyboard\'s digits');
  assert.equal(at({ code: 'hk7m29pw' }).ok, true, 'no dash');
  compares = 0;
  assert.deepEqual(at({ code: 'ZZZZ-ZZZZ' }), { ok: false, code: 'bad', why: 'code' });
  assert.deepEqual(at({ code: 'nope' }), { ok: false, code: 'bad', why: 'code' });
  assert.deepEqual(at({ code: 'QRST-UVWX' }), { ok: false, code: 'bad', why: 'code' });
  assert.equal(compares, 3, 'the compare ran for each: a wrong code takes as long as a wrong password');
  assert.deepEqual(at({ code: V2 }), { ok: false, code: 'expired' });
  assert.deepEqual(at({ code: V1, usage: { 'u-v1': { hold: 'all', why: 'total', over: true } } }), { ok: false, code: 'total' }, 'spent: the meter holds its one-off limit');
  const active = plan.readLanUsers({ users: [Object.assign({}, lu.users[1], { voucher: { batch: 'b1', hours: 2, activatedAt: NOW - 1000 }, expiresAt: NOW + 3600000 })] });
  assert.equal(plan.judgeSignIn({ lu: active, now: NOW, mac: A, code: V1, checkPassword: cp }).activate, false, 'an active card is not activated again');
  assert.deepEqual(at({ username: V1, password: V1 }), { ok: true, user: lu.users[1], voucher: true, activate: true, remember: false }, 'the username way in activates too');
  assert.deepEqual(at({ username: 'ali', password: 'pw12' }), { ok: true, user: lu.users[0], voucher: false, activate: false, remember: true });
  assert.equal(at({ username: 'ali', password: 'pw12', code: '' }).ok, true, 'an empty code is no code: the username and password decide');
  assert.deepEqual(plan.judgeSignIn({ lu, sessions: { [B]: { userId: 'u-v1', until: NOW + 1000 } }, now: NOW, mac: A, code: V1, checkPassword: cp }), { ok: false, code: 'maxDevices', max: 1 }, 'a card\'s one device');
});

test('decide: the pins — every address of every device that belongs to a user, bound to its MAC; a borrowed address in nobody else\'s rule-set or counter', () => {
  const X = 'aa:bb:cc:dd:ee:0c', Y = 'aa:bb:cc:dd:ee:0d', F = 'aa:bb:cc:dd:ee:0f', E = 'aa:bb:cc:dd:ee:0e';
  const lu = plan.readLanUsers({
    config: { transparent: { enabled: true, unassigned: 'login' } },
    users: [
      { id: 'u-ali', target: 'srv-2' }, { id: 'u-bob', target: 'srv-3' }, { id: 'u-net', target: 'direct' },
      { id: 'u-cap', target: 'srv-2' }, { id: 'u-here', target: '' }
    ],
    devices: [
      { mac: A, userId: 'u-ali' }, { mac: X, userId: 'u-bob' }, { mac: B, userId: 'u-net' }, { mac: C, userId: 'u-cap' },
      { mac: D, userId: 'u-here' }, { mac: E, userId: 'u-ali', blocked: true }
    ]
  });
  const sessions = { [F]: { userId: 'u-ali', until: NOW + 3600000 } };
  const scan = [
    // bob's X took alice's A's leased address and answers for it; A is online by its v6 addresses, so its lease holds
    { mac: X, ips: ['192.168.1.23', '192.168.1.24'], leased: ['192.168.1.24'], online: true },
    { mac: A, ips: ['192.168.1.23', '2001:db8::23', '2001:db8::a:23'], leased: ['192.168.1.23'], online: true },
    { mac: B, ips: ['192.168.1.40'], leased: ['192.168.1.40'] },
    { mac: C, ips: ['192.168.1.30'], leased: [] },
    { mac: D, ips: ['192.168.1.50'], leased: [] },
    { mac: E, ips: ['192.168.1.60'], leased: [] },
    { mac: F, ips: ['192.168.1.66'], leased: [] },
    { mac: Y, ips: ['192.168.1.99'], leased: [] }      // nobody's: pinned to nothing
  ];
  const d = plan.decide({ lu, sessions, scan, usage: { 'u-cap': { over: true } }, now: NOW,
    tp: [{ tag: 'lu-tp-1', userId: 'u-ali', target: 'srv-2' }, { tag: 'lu-tp-2', userId: 'u-bob', target: 'srv-3' }], portal: { ip: '192.168.1.1', port: 30822 } });
  assert.deepEqual(d.nft.ipmac, [
    { mac: A, ips: ['192.168.1.23', '2001:db8::23', '2001:db8::a:23'] },   // routed: every address, both families
    { mac: B, ips: ['192.168.1.40'] },                                     // direct: around the tunnel, still charged by address
    { mac: C, ips: ['192.168.1.30'] },                                     // held: meets the gate as itself
    { mac: D, ips: ['192.168.1.50'] },                                     // the router's own connection: still someone's cap
    { mac: X, ips: ['192.168.1.24'] },                                     // only its own: .23 is A's lease
    { mac: E, ips: ['192.168.1.60'] },                                     // blocked, but someone's: no one rides its address either
    { mac: F, ips: ['192.168.1.66'] }                                      // signed in
  ]);
  assert.deepEqual(d.ruleSets, { 'lu-tp-1': ['192.168.1.23/32', '2001:db8::23/128', '2001:db8::a:23/128', '192.168.1.66/32'], 'lu-tp-2': ['192.168.1.24/32'] },
    'A\'s address is in alice\'s rule-set only — not in bob\'s for the device that took it');
  const ctr = Object.fromEntries(d.nft.counters.map(c => [c.mac, c.ips]));
  assert.deepEqual([ctr[A], ctr[X], ctr[Y]], [['192.168.1.23', '2001:db8::23', '2001:db8::a:23'], ['192.168.1.24'], ['192.168.1.99']], 'the down counter of an address is its owner\'s');
  // the text that reaches the kernel: X's MAC is not A's, so X sending from .23 is dropped
  const text = require('../src/main/openwrtNet').buildNftRuleset({ lanUsers: d.nft });
  assert.ok(text.includes(`192.168.1.23 . ${A}`) && !text.includes(`192.168.1.23 . ${X}`), text);
  assert.ok(!/192\.168\.1\.99 \./.test(text), 'nobody\'s device: no pin');
});

test('ruleSetText: sing-box\'s source format, version 1 — every sing-box from 1.8 reads it; no device is an empty list, not an invalid rule', () => {
  assert.equal(plan.ruleSetText(['192.168.1.23/32']), '{\n  "version": 1,\n  "rules": [\n    {\n      "source_ip_cidr": [\n        "192.168.1.23/32"\n      ]\n    }\n  ]\n}\n');
  assert.deepEqual(JSON.parse(plan.ruleSetText([])), { version: 1, rules: [] });
});

/* ------------------------------ sing-box: the per-target routes ------------------------------ */

test('buildTunConfig lanRoutes: a socks outbound per config, a rule over its local rule-set file; absent or junk — the config of before', () => {
  const base = JSON.stringify(buildTunConfig({ socksPort: 30808, udpTimeout: 120 }));
  assert.equal(JSON.stringify(buildTunConfig({ socksPort: 30808, udpTimeout: 120, lanRoutes: null })), base);
  assert.equal(JSON.stringify(buildTunConfig({ socksPort: 30808, udpTimeout: 120, lanRoutes: { targets: [] } })), base);
  assert.equal(JSON.stringify(buildTunConfig({ socksPort: 30808, udpTimeout: 120, lanRoutes: { targets: [{ tag: 'x', port: 1, path: '/a' }, { tag: 'lu-tp-1', port: 0, path: '/a' }, { tag: 'lu-tp-2', port: 2, path: 'rel.json' }] } })), base);
  const cfg = buildTunConfig({ socksPort: 30808, lanRoutes: { targets: [
    { tag: 'lu-tp-1', port: 41001, path: '/tmp/irnetfree-lu/lu-tp-1.json' },
    { tag: 'lu-tp-2', port: 41002, path: '/tmp/irnetfree-lu/lu-tp-2.json' },
    { tag: 'lu-tp-1', port: 41003, path: '/tmp/x.json' }
  ] } });
  assert.deepEqual(cfg.outbounds, [
    { type: 'socks', tag: 'socks-out', server: '127.0.0.1', server_port: 30808, version: '5' },
    { type: 'socks', tag: 'lu-tp-1', server: '127.0.0.1', server_port: 41001, version: '5' },
    { type: 'socks', tag: 'lu-tp-2', server: '127.0.0.1', server_port: 41002, version: '5' }
  ]);
  assert.deepEqual(cfg.route, {
    final: 'socks-out', auto_detect_interface: true,
    rules: [{ rule_set: ['lu-tp-1'], outbound: 'lu-tp-1' }, { rule_set: ['lu-tp-2'], outbound: 'lu-tp-2' }],
    rule_set: [
      { type: 'local', tag: 'lu-tp-1', format: 'source', path: '/tmp/irnetfree-lu/lu-tp-1.json' },
      { type: 'local', tag: 'lu-tp-2', format: 'source', path: '/tmp/irnetfree-lu/lu-tp-2.json' }
    ]
  }, 'what no device rule claims stays on the current connection');
});

test('writeConfig hands the routes to buildTunConfig on a router only — a desktop TunSingbox ignores them', () => {
  const { TunSingbox } = require('../src/main/tunSingbox');
  const lanUsers = { singbox: { targets: [{ tag: 'lu-tp-1', port: 41001, path: '/tmp/irnetfree-lu/lu-tp-1.json' }] } };
  for (const composedBy of ['openwrt', null]) {
    const t = new TunSingbox({ binDir: '/nonexistent', composedBy, platform: 'linux' });
    const { cfgFile } = t.writeConfig(30808, [], { lanUsers }, 'IRNetFree');
    const cfg = JSON.parse(require('fs').readFileSync(cfgFile, 'utf8'));
    t.removeWork();
    assert.equal(cfg.outbounds.some(o => o.tag === 'lu-tp-1'), composedBy === 'openwrt', String(composedBy));
  }
});

/* ------------------------------ the core: loopback inbounds ------------------------------ */

test('the core: one loopback SOCKS per config, routed before the catch-all; the selected server reused, another built and bound to the WAN; a config gone rides the default', () => {
  const config = buildConfig({ mode: 'single', server: SRV1 }, { socksPort: 30808, httpPort: 30809, apiPort: 30085, routingMode: 'global', blockAds: false, directInterface: 'eth0' });
  const records = { serversById: { 'srv-1': SRV1, 'srv-2': SRV2, 'srv-3': SRV3 }, chainsById: { c1: [SRV2, SRV3] } };
  const tp = [{ tag: 'lu-tp-1', port: 41001, target: 'chain:c1' }, { tag: 'lu-tp-2', port: 41002, target: 'srv-1' }, { tag: 'lu-tp-3', port: 41003, target: 'srv-2' }, { tag: 'lu-tp-4', port: 41004, target: 'srv-gone' }];
  const r = applyTransparentTargets(config, tp, { serverId: 'srv-1', plan: { mode: 'single', server: SRV1 }, records, directInterface: 'eth0' });
  assert.deepEqual(r.applied.map(a => [a.tag, a.outboundTag, a.gone]), [['lu-tp-1', 'lu-tp-1-out', false], ['lu-tp-2', 'proxy', false], ['lu-tp-3', 'lu-tp-3-out', false], ['lu-tp-4', 'proxy', true]]);
  assert.deepEqual(r.applied[0].entryAddrs, ['192.0.2.20'], 'the chain\'s first hop, kept off the tunnel');
  const inb = config.inbounds.find(i => i.tag === 'lu-tp-3');
  assert.deepEqual(inb, { tag: 'lu-tp-3', port: 41003, listen: '127.0.0.1', protocol: 'socks', settings: { auth: 'noauth', udp: true }, sniffing: config.inbounds[0].sniffing });
  const rules = config.routing.rules;
  const tail = rules.length - 1;
  assert.deepEqual(rules[tail], { type: 'field', port: '0-65535', outboundTag: 'proxy' }, 'the catch-all stays last');
  assert.deepEqual(rules.slice(tail - 4, tail).map(x => x.inboundTag[0]), ['lu-tp-1', 'lu-tp-2', 'lu-tp-3', 'lu-tp-4']);
  const out3 = config.outbounds.find(o => o.tag === 'lu-tp-3-out');
  assert.equal(out3.streamSettings.sockopt.interface, 'eth0', 'bound to the WAN: an unbound dial would re-enter the whole-LAN tunnel');
  const hop = config.outbounds.find(o => o.tag === 'lu-tp-1-out');
  assert.equal(hop.streamSettings.sockopt.dialerProxy, 'lu-tp-1-out-h0', 'the chain\'s exit dials through its hop');
});

test('decide v1.39: an inbound per user — two on one server ride two files, the current connection\'s too; a hold of all is held with its reason, of one class rides on; each device\'s speed', () => {
  const E = 'aa:bb:cc:dd:ee:05';
  const lu = plan.readLanUsers({
    config: { transparent: { enabled: true, unassigned: 'login' } },
    users: [{ id: 'u-ali', target: 'srv-2' }, { id: 'u-bob', target: 'srv-2' }, { id: 'u-eve', target: '' }, { id: 'u-net', target: 'direct' }, { id: 'u-late', target: 'srv-2' }],
    devices: [{ mac: A, userId: 'u-ali' }, { mac: B, userId: 'u-bob' }, { mac: C, userId: 'u-eve' }, { mac: D, userId: 'u-net' }, { mac: E, userId: 'u-late' }]
  });
  const scan = [A, B, C, D, E].map((mac, i) => ({ mac, ips: [`192.168.1.2${i + 1}`], leased: [`192.168.1.2${i + 1}`] }));
  const usage = { 'u-bob': { hold: 'vpn', why: 'vpn', over: false }, 'u-late': { hold: 'all', why: 'schedule', holdUntil: NOW + 3600000, over: true } };
  const speeds = { 'u-ali': { down: 2000, up: 500, why: ['base'] }, 'u-net': { down: 1000, up: 0, why: ['hours'] }, 'u-late': { down: 100, up: 100, why: ['base'] } };
  const tp = [['u-ali', 'srv-2'], ['u-bob', 'srv-2'], ['u-eve', ''], ['u-late', 'srv-2'], ['u-net', 'direct']].map(([userId, target], i) => ({ tag: `lu-tp-${i + 1}`, userId, target }));
  const d = plan.decide({ lu, scan, usage, speeds, now: NOW, tp, portal: { ip: '192.168.1.1', port: 30822 } });
  assert.deepEqual(d.ruleSets, { 'lu-tp-1': ['192.168.1.21/32'], 'lu-tp-2': ['192.168.1.22/32'], 'lu-tp-3': ['192.168.1.23/32'], 'lu-tp-4': [], 'lu-tp-5': [] },
    'the same server, two files; a user on the current connection rides their own inbound too (their direct counted); "direct" goes around');
  assert.deepEqual(d.held, { [E]: 'schedule' }, 'outside the allowed hours: held, the page says why');
  assert.deepEqual(d.nft.allowed, [A, B, C, D], 'a hold of the VPN alone: let through — the core blocks the class');
  assert.deepEqual(d.nft.direct, [D]);
  assert.deepEqual(d.nft.rates, [{ mac: A, ips: ['192.168.1.21'], down: 2000, up: 500 }, { mac: D, ips: ['192.168.1.24'], down: 1000, up: 0 }],
    'every device let through whose user has a speed — around the tunnel too; a held one meets the gate instead');
  const slower = plan.decide({ lu, scan, usage, speeds: Object.assign({}, speeds, { 'u-ali': { down: 1000, up: 500 } }), now: NOW, tp, portal: { ip: '192.168.1.1', port: 30822 } });
  assert.notEqual(plan.nftKey(slower.nft), plan.nftKey(d.nft), 'a speed changed: another table');
});

test('inactiveReason: the meter\'s hold "all" with its reason; a hold of one class is none; a meter of before says "over"', () => {
  const u = { id: 'u1', enabled: true };
  for (const why of ['schedule', 'total', 'vpn', 'direct']) assert.equal(plan.inactiveReason(u, { usage: { u1: { hold: 'all', why, over: true } } }), why);
  assert.equal(plan.inactiveReason(u, { usage: { u1: { hold: 'vpn', why: 'vpn', over: false } } }), null);
  assert.equal(plan.inactiveReason(u, { usage: { u1: { hold: 'direct', why: 'direct', over: false } } }), null);
  assert.equal(plan.inactiveReason(u, { usage: { u1: { over: true } } }), 'over');
  assert.equal(plan.inactiveReason(u, { usage: { u1: { hold: 'all', why: '??', over: true } } }), 'over');
  assert.equal(plan.inactiveReason({ id: 'u1', enabled: false }, { usage: {} }), 'disabled');
  assert.equal(plan.inactiveReason({ id: 'u1', expiresAt: NOW - 1 }, { now: NOW }), 'expired');
  // the sign-in: refused with the reason and when it lifts, in the user's calendar
  const lu = plan.readLanUsers({ users: [{ id: 'u1', username: 'ali', password: 'pw12', quotaCalendar: 'jalali' }] });
  const r = plan.judgeSignIn({ lu, usage: { u1: { hold: 'all', why: 'schedule', holdUntil: NOW + 3600000, over: true } }, now: NOW, mac: A, username: 'ali', password: 'pw12', checkPassword: (a, b) => a === b });
  assert.deepEqual(r, { ok: false, code: 'schedule', until: NOW + 3600000, calendar: 'jalali' });
  assert.equal(plan.judgeSignIn({ lu, usage: { u1: { hold: 'vpn', why: 'vpn' } }, now: NOW, mac: A, username: 'ali', password: 'pw12', checkPassword: (a, b) => a === b }).ok, true);
});

test('the core, per user: two on one server — two inbounds, one outbound; a direct of their own (the router\'s, bound); routing "" repeats the router\'s direct rules after the DNS ones and rides its rules; bypass-ir and a profile decide first; the holds', () => {
  const config = buildConfig({ mode: 'single', server: SRV1 }, { socksPort: 30808, httpPort: 30809, apiPort: 30085, routingMode: 'bypass-ir', blockAds: true, directInterface: 'eth0' });
  const own = config.routing.rules.slice();
  const records = { serversById: { 'srv-1': SRV1, 'srv-2': SRV2, 'srv-3': SRV3 }, chainsById: {} };
  const users = [
    { id: 'u-ali', target: 'srv-2', routing: '' },
    { id: 'u-bob', target: 'srv-2', routing: 'bypass-ir' },
    { id: 'u-cy', target: 'srv-2', routing: 'profile:p1' },
    { id: 'u-dan', target: '', routing: '' },
    { id: 'u-eve', target: 'srv-2', routing: 'global' }
  ];
  const profilesById = { p1: { id: 'p1', name: 'Work', rules: [
    { type: 'domain', value: 'corp.example', target: 'srv-3' }, { type: 'ip', value: '203.0.113.0/24', target: 'direct' },
    { type: 'domain', value: 'ads.example', target: 'block' }, { type: 'domain', value: 'gone.example', target: 'srv-gone' }
  ] } };
  const tp = users.map((u, i) => ({ tag: `lu-tp-${i + 1}`, port: 41001 + i, userId: u.id, target: u.target }));
  const r = applyTransparentTargets(config, tp, { serverId: 'srv-1', plan: { mode: 'single', server: SRV1 }, records, directInterface: 'eth0',
    users, holds: { 'u-dan': 'vpn', 'u-eve': 'direct' }, profilesById, geo: true });
  assert.deepEqual(r.applied.map(a => [a.tag, a.userId, a.outboundTag, a.gone]), [
    ['lu-tp-1', 'u-ali', 'lu-tp-1-out', false], ['lu-tp-2', 'u-bob', 'lu-tp-1-out', false], ['lu-tp-3', 'u-cy', 'lu-tp-1-out', false],
    ['lu-tp-4', 'u-dan', 'proxy', false], ['lu-tp-5', 'u-eve', 'lu-tp-1-out', false]
  ], 'the current connection is where the router\'s catch-all goes — not a config gone');
  assert.equal(config.outbounds.filter(o => o.tag === 'lu-tp-1-out').length, 1, 'two users on one server: one outbound (a WireGuard is never two sessions)');
  const direct = config.outbounds.find(o => o.tag === 'direct');
  for (const u of users) assert.deepEqual(config.outbounds.find(o => o.tag === 'lu-d-' + u.id), Object.assign({}, direct, { tag: 'lu-d-' + u.id }));
  assert.equal(config.outbounds.find(o => o.tag === 'lu-d-u-ali').streamSettings.sockopt.interface, 'eth0', 'bound to the WAN like the router\'s direct');
  assert.equal(config.outbounds.find(o => o.tag === 'lu-tp-3-r1-out').streamSettings.sockopt.interface, 'eth0', 'a profile\'s server, built and bound');

  const rules = config.routing.rules;
  const at = rules.findIndex(x => x.outboundTag === 'dns-out') + 1;
  const tail = rules.length - 1;
  assert.deepEqual(rules[tail], { type: 'field', port: '0-65535', outboundTag: 'proxy' }, 'the catch-all stays last');
  const of = (tag) => rules.map((x, i) => [i, x]).filter(([, x]) => x.inboundTag && x.inboundTag[0] === tag);
  const tags = (tag) => of(tag).map(([, x]) => x.outboundTag);
  // the router's own rules are all there, in their own order — the users' copies only sit between them
  assert.deepEqual(rules.filter(x => !(x.inboundTag && /^lu-tp-/.test(x.inboundTag[0]))), own);
  // bypass-ir and a profile: all of it first, right after the DNS ones
  assert.deepEqual(tags('lu-tp-2'), ['lu-d-u-bob', 'lu-d-u-bob', 'lu-d-u-bob', 'lu-tp-1-out']);
  assert.deepEqual(of('lu-tp-3').map(([, x]) => [x.domain || x.ip || null, x.outboundTag]), [
    [['corp.example'], 'lu-tp-3-r1-out'], [['203.0.113.0/24'], 'lu-d-u-cy'], [['ads.example'], 'block'], [null, 'lu-tp-1-out']
  ], 'its default and a target gone are not used: the user\'s config is the default');
  assert.deepEqual([...of('lu-tp-2'), ...of('lu-tp-3')].map(([i]) => i), [0, 1, 2, 3, 4, 5, 6, 7].map(n => at + n));
  // '' (ali; dan held from the VPN; eve held from direct): each router rule keeps its place — right before one that
  // ends direct, a copy for each of them (ali's and dan's to their own direct, eve's blocked); under dan's hold, right
  // before one that ends at a server, his copy to block; before one that blocks (the ads), nothing
  const plain = ['lu-tp-1', 'lu-tp-4', 'lu-tp-5'];
  const strip = (x) => { const c = Object.assign({}, x); delete c.inboundTag; delete c.outboundTag; delete c.balancerTag; return JSON.stringify(c); };
  let directs = 0, servers = 0, blocks = 0;
  for (let i = at + 8; i < tail; i++) {
    const r = rules[i];
    if (r.inboundTag) continue;
    const before = [];
    for (let j = i - 1; j >= 0 && rules[j].inboundTag && plain.includes(rules[j].inboundTag[0]) && strip(rules[j]) === strip(r); j--) before.unshift(rules[j]);
    if (r.outboundTag === 'direct') {
      directs++;
      assert.deepEqual(before.map(x => [x.inboundTag[0], x.outboundTag]), [['lu-tp-1', 'lu-d-u-ali'], ['lu-tp-4', 'lu-d-u-dan'], ['lu-tp-5', 'block']], JSON.stringify(r));
    } else if (r.outboundTag === 'block') {
      blocks++;
      assert.deepEqual(before, [], 'a rule that blocks (the ads) still decides first for every device');
    } else {
      servers++;
      assert.deepEqual(before.map(x => [x.inboundTag[0], x.outboundTag]), [['lu-tp-4', 'block']], JSON.stringify(r));
    }
  }
  assert.ok(directs >= 3 && blocks >= 1, `${directs} direct, ${blocks} block, ${servers} server rules of the router's own`);
  // their configs (dan's blocked) right before the router's catch-all
  assert.deepEqual(rules.slice(tail - 3, tail).map(x => [x.inboundTag[0], x.outboundTag]), [['lu-tp-1', 'lu-tp-1-out'], ['lu-tp-4', 'block'], ['lu-tp-5', 'lu-tp-1-out']]);
});

test('the core, per user: the router\'s connection a group — a user on it ends at its balancer; a user gone keeps one rule; their account\'s direct is not made twice', () => {
  const config = { inbounds: [{ tag: 'socks-in', port: 30808, sniffing: { enabled: true } }], outbounds: [{ tag: 'g1-a', protocol: 'socks' }, { tag: 'direct', protocol: 'freedom' }, { tag: 'block', protocol: 'blackhole' }, { tag: 'lu-d-u-ali', protocol: 'freedom', settings: { mine: true } }],
    routing: { rules: [{ type: 'field', port: '53', network: 'tcp,udp', outboundTag: 'dns-out' }, { type: 'field', ip: ['10.0.0.0/8'], outboundTag: 'direct' }, { type: 'field', port: '0-65535', balancerTag: 'g1' }] } };
  const r = applyTransparentTargets(config, [{ tag: 'lu-tp-1', port: 41001, userId: 'u-ali', target: '' }, { tag: 'lu-tp-2', port: 41002, userId: 'u-gone', target: 'srv-x' }],
    { users: [{ id: 'u-ali', target: '' }], records: { serversById: {}, chainsById: {} } });
  assert.deepEqual(r.applied.map(a => [a.tag, a.outboundTag, a.gone]), [['lu-tp-1', 'g1', false], ['lu-tp-2', 'g1', true]]);
  assert.deepEqual(config.routing.rules, [
    { type: 'field', port: '53', network: 'tcp,udp', outboundTag: 'dns-out' },
    { type: 'field', inboundTag: ['lu-tp-1'], ip: ['10.0.0.0/8'], outboundTag: 'lu-d-u-ali' },
    { type: 'field', ip: ['10.0.0.0/8'], outboundTag: 'direct' },
    { type: 'field', inboundTag: ['lu-tp-1'], balancerTag: 'g1' },
    { type: 'field', inboundTag: ['lu-tp-2'], balancerTag: 'g1' },
    { type: 'field', port: '0-65535', balancerTag: 'g1' }
  ]);
  assert.equal(config.outbounds.filter(o => o.tag === 'lu-d-u-ali').length, 1);
  assert.deepEqual(config.outbounds.find(o => o.tag === 'lu-d-u-ali').settings, { mine: true }, 'the one the build made for their account stays');
});

test('the core, per user (v1.40.0): a user\'s content filter is the first of their rules, ahead of the router\'s own — for the router\'s routing too; safe search dials through their config\'s outbound, or is a copy of their direct; none for the router\'s balancer (a note); sniffing on where it was off', () => {
  const config = buildConfig({ mode: 'single', server: SRV1 }, { socksPort: 30808, httpPort: 30809, apiPort: 30085, routingMode: 'bypass-ir', blockAds: true, directInterface: 'eth0', enableSniffing: false });
  const own = config.routing.rules.slice();
  const records = { serversById: { 'srv-1': SRV1, 'srv-2': SRV2 }, chainsById: {} };
  const FILTER = { block: ['adult', 'ads'], safeSearch: true, domains: ['bad.example'] };
  const users = [
    { id: 'u-ali', target: 'srv-2', routing: '', filter: FILTER },
    { id: 'u-bob', target: 'direct', routing: 'bypass-ir', filter: { safeSearch: true } },
    { id: 'u-cy', target: 'srv-2', routing: '', filter: FILTER },
    { id: 'u-dan', target: 'srv-2', routing: '' }
  ];
  const tp = users.map((u, i) => ({ tag: `lu-tp-${i + 1}`, port: 41001 + i, userId: u.id, target: u.target }));
  const r = applyTransparentTargets(config, tp, { serverId: 'srv-1', plan: { mode: 'single', server: SRV1 }, records, directInterface: 'eth0', users, holds: { 'u-cy': 'vpn' }, profilesById: {}, geo: true });
  assert.deepEqual(r.notes, []);
  const rules = config.routing.rules;
  const at = rules.findIndex(x => x.outboundTag === 'dns-out') + 1;
  const brief = (x) => [x.inboundTag[0], x.domain ? x.domain[0] : (x.ip ? 'ip' : null), x.network || null, x.outboundTag];
  // ali ('' routing — the router's own): her filter right after the DNS rules, ahead of every rule of the router's
  assert.deepEqual(rules.slice(at, at + 7).map(brief), [
    ['lu-tp-1', 'domain:bad.example', null, 'block'], ['lu-tp-1', 'geosite:category-porn', null, 'block'], ['lu-tp-1', 'full:www.google.com', 'udp', 'block'],
    ['lu-tp-1', 'full:www.google.com', 'tcp', 'lu-ss-u-ali-google'], ['lu-tp-1', 'full:www.bing.com', 'tcp', 'lu-ss-u-ali-bing'],
    ['lu-tp-1', 'full:duckduckgo.com', 'tcp', 'lu-ss-u-ali-ddg'], ['lu-tp-1', 'full:www.youtube.com', 'tcp', 'lu-ss-u-ali-youtube']
  ]);
  assert.deepEqual(rules[at + 1].domain, ['geosite:category-porn', 'geosite:category-ads-all']);
  // bob (bypass-ir, direct): his filter, then his routing, then his catch-all — all of it in the head
  assert.deepEqual(rules.slice(at + 7, at + 16).map(x => x.outboundTag), ['block', 'lu-ss-u-bob-google', 'lu-ss-u-bob-bing', 'lu-ss-u-bob-ddg', 'lu-ss-u-bob-youtube', 'lu-d-u-bob', 'lu-d-u-bob', 'lu-d-u-bob', 'lu-d-u-bob']);
  // cy (VPN held): his searches ride the VPN — blocked with it
  assert.deepEqual(rules.slice(at + 16, at + 23).map(x => [x.inboundTag[0], x.outboundTag]), Array(7).fill(['lu-tp-3', 'block']));
  assert.equal(rules[at + 23].inboundTag, undefined, 'then the router\'s own (the ads block first: nothing is mirrored before it)');
  assert.deepEqual(rules.filter(x => !(x.inboundTag && /^lu-tp-/.test(x.inboundTag[0]))), own, 'the router\'s rules are all there, in their order');
  const tail = rules.length - 1;
  assert.deepEqual(rules.slice(tail - 3, tail).map(x => [x.inboundTag[0], x.outboundTag]), [['lu-tp-1', 'lu-tp-1-out'], ['lu-tp-3', 'block'], ['lu-tp-4', 'lu-tp-1-out']], 'the \'\' users\' catch-alls before the router\'s');
  // the outbounds: through the config's outbound (not bound to the WAN themselves — the hop is); bob's a copy of his direct, bound
  const out = (tag) => config.outbounds.find(o => o.tag === tag);
  assert.deepEqual(out('lu-ss-u-ali-google'), { tag: 'lu-ss-u-ali-google', protocol: 'freedom', settings: { redirect: 'forcesafesearch.google.com:443' }, streamSettings: { sockopt: { dialerProxy: 'lu-tp-1-out' } } });
  assert.deepEqual(out('lu-ss-u-bob-ddg'), Object.assign({}, out('lu-d-u-bob'), { tag: 'lu-ss-u-bob-ddg', settings: Object.assign({}, out('lu-d-u-bob').settings, { redirect: 'safe.duckduckgo.com:443' }) }));
  assert.equal(out('lu-ss-u-bob-ddg').streamSettings.sockopt.interface, 'eth0');
  assert.ok(out('lu-ss-u-cy-bing'), 'held: the outbound stands, the rules block');
  assert.equal(config.outbounds.filter(o => /^lu-ss-/.test(o.tag)).length, 12);
  assert.equal(new Set(config.outbounds.map(o => o.tag)).size, config.outbounds.length, 'no tag twice');
  // sniffing: a filtered user's inbound sees names; dan's is the router's socks-in's
  const ib = (tag) => config.inbounds.find(i => i.tag === tag);
  assert.deepEqual(ib('lu-tp-1').sniffing, { enabled: true, destOverride: ['http', 'tls', 'quic'], routeOnly: true });
  assert.deepEqual(ib('lu-tp-4').sniffing, config.inbounds.find(i => i.tag === 'socks-in').sniffing);
  assert.notEqual(ib('lu-tp-4').sniffing.enabled, true);
  // a group as the router's connection: nothing dials through its balancer — the block rules alone, and a note
  const grp = { inbounds: [{ tag: 'socks-in', port: 30808, sniffing: { enabled: true } }], outbounds: [{ tag: 'g1-a', protocol: 'socks' }, { tag: 'direct', protocol: 'freedom' }, { tag: 'block', protocol: 'blackhole' }],
    routing: { rules: [{ type: 'field', port: '53', network: 'tcp,udp', outboundTag: 'dns-out' }, { type: 'field', port: '0-65535', balancerTag: 'g1' }] } };
  const g = applyTransparentTargets(grp, [{ tag: 'lu-tp-1', port: 41001, userId: 'u-eve', target: '' }], { users: [{ id: 'u-eve', name: 'Eve', target: '', filter: { safeSearch: true, domains: ['bad.example'] } }], records, geo: false });
  assert.deepEqual(g.notes, ['Users: "Eve": safe search needs a server, a chain or direct as the config — not a group, nor the router’s balancer — left out']);
  assert.deepEqual(grp.routing.rules.map(x => [(x.inboundTag || [])[0] || null, x.domain || null, x.outboundTag || x.balancerTag]), [
    [null, null, 'dns-out'], ['lu-tp-1', ['domain:bad.example'], 'block'], ['lu-tp-1', null, 'g1'], [null, null, 'g1']
  ]);
  assert.ok(!grp.outbounds.some(o => /^lu-ss-/.test(o.tag)));
  assert.deepEqual(applyTransparentTargets({ inbounds: [], outbounds: [], routing: { rules: [] } }, [], {}), { applied: [], skipped: [], notes: [] });
});

/* ------------------------------ the controller ------------------------------ */

function controller({ settings = { modules: { lanUsers: true } }, store, lan = fakeLan(), meter = fakeMeter(), now } = {}) {
  const files = memFs();
  const logs = [];
  let clock = now || NOW;
  const r = createLanRouter({
    openwrt: true, dataDir: '/etc/irnetfree', tmpDir: '/tmp', fs: files, run: lan.run, readFile: lan.readFile,
    getSettings: () => settings, getLanUsers: () => store, records: () => ({ servers: [SRV1, SRV2], groups: [], chains: [] }),
    getFreePorts: async (n) => Array.from({ length: n }, (_, i) => 41001 + i), log: (line, level) => logs.push([level, line]),
    now: () => clock, meter, tickMs: 3600000
  });
  return { r, files, logs, lan, meter, advance: (ms) => { clock += ms; } };
}

test('off — the module not installed, or the mode not on: no ports, nothing in the core\'s config, no gateway option, nothing kept off the tunnel', async () => {
  const store = { config: { transparent: { enabled: true } }, users: [{ id: 'u1', target: 'srv-2' }] };
  for (const settings of [{}, { modules: {} }, { modules: { lanUsers: true } }]) {
    const st = settings.modules && settings.modules.lanUsers ? { config: { transparent: { enabled: false } }, users: store.users } : store;
    const { r, lan } = controller({ settings, store: st });
    const tp = await r.prepare();
    assert.deepEqual(tp, []);
    const config = buildConfig({ mode: 'single', server: SRV1 }, { socksPort: 30808, httpPort: 30809, apiPort: 30085 });
    const before = JSON.stringify(config);
    assert.equal(r.applyXray(config, { settings: { lanUsersTp: tp } }), null);
    assert.equal(JSON.stringify(config), before);
    assert.equal(await r.gatewayOptions(tp), null);
    assert.deepEqual(r.entryAddrs(tp), []);
    await r.gatewayUp(fakeGateway());
    assert.equal(r.portal, null);
    assert.deepEqual(lan.calls, [], 'not even a read of the LAN');
  }
});

test('caps: the table\'s counters feed the meter per user; over the cap its devices are held, the new period lets them through — said in the log', async () => {
  const lan = fakeLan({ neigh: `192.168.1.23 lladdr ${A} REACHABLE\n192.168.1.99 lladdr ${C} REACHABLE\n` });
  const meter = fakeMeter({ 'u-ali': 1000 });
  const store = { config: { transparent: { enabled: true, unassigned: 'allow' } }, users: [{ id: 'u-ali', name: 'Ali', target: 'srv-2', enabled: true, quotaPeriod: 'month' }], devices: [{ mac: A, userId: 'u-ali' }] };
  const c = controller({ store, lan, meter });
  const tp = await c.r.prepare();
  assert.deepEqual(tp.map(e => [e.tag, e.port, e.target]), [['lu-tp-1', 41001, 'srv-2']]);
  const config = buildConfig({ mode: 'single', server: SRV1 }, { socksPort: 30808, httpPort: 30809, apiPort: 30085 });
  c.r.applyXray(config, { serverId: 'srv-1', plan: { mode: 'single', server: SRV1 }, settings: { lanUsersTp: tp } });
  const opts = await c.r.gatewayOptions(tp);
  assert.deepEqual(opts.nft.allowed, [A]);
  assert.deepEqual(opts.singbox.targets, [{ tag: 'lu-tp-1', port: 41001, path: '/tmp/irnetfree-lu/lu-tp-1.json' }]);
  assert.deepEqual(JSON.parse(c.files.get('/tmp/irnetfree-lu/lu-tp-1.json')).rules, [{ source_ip_cidr: ['192.168.1.23/32'] }]);
  assert.deepEqual(c.r.entryAddrs(tp), ['192.0.2.20']);
  const gw = fakeGateway();
  gw.tableGen = 1;               // the start's own load
  await c.r.gatewayUp(gw);
  lan.counters = { [A]: { up: 300, down: 400 }, [C]: { up: 50, down: 50 } };
  await c.r.tick();
  assert.deepEqual(meter.fed, [{ 'u-ali': { up: 300, down: 400, bytes: 700 } }], 'a device with no user is counted, not fed');
  assert.equal(gw.loads.length, 0, 'nothing changed: the table is not reloaded');
  c.advance(10000);
  lan.counters = { [A]: { up: 500, down: 800 }, [C]: { up: 50, down: 50 } };
  await c.r.tick();
  assert.deepEqual(meter.fed[1], { 'u-ali': { up: 200, down: 400, bytes: 600 } }, 'only what is new since the last read');
  const held = gw.loads[gw.loads.length - 1];
  assert.deepEqual(held.blocked, [A], 'over its cap: held (allow mode has no page to explain, so: dropped)');
  assert.deepEqual(held.allowed, []);
  assert.ok(c.logs.some(([lvl, l]) => lvl === 'warn' && /"Ali" reached its data cap/.test(l)), JSON.stringify(c.logs));
  assert.deepEqual(c.r.deviceUsage(), { [A]: 1300, [C]: 100 });
  const on = c.r.online();
  assert.equal(on[A].userId, 'u-ali');
  assert.deepEqual([on[A].up, on[A].down], [20, 40], 'bytes/s over the last read');
  // the reload started its counters from zero: the next read is all new
  lan.counters = { [A]: { up: 0, down: 0 }, [C]: { up: 5, down: 5 } };
  meter.newPeriod();
  c.advance(10000);
  await c.r.tick();
  assert.deepEqual(gw.loads[gw.loads.length - 1].allowed, [A], 'the new period lets it through again');
  assert.ok(c.logs.some(([, l]) => /"Ali" has data again/.test(l)));
  assert.equal(c.r.pendingReconnect(), false);
  store.users = [...store.users, { id: 'u-new', target: 'srv-1' }];
  assert.equal(c.r.pendingReconnect(), true, 'a new config needs its inbound: a reconnect');
  gw.active = false;
  await c.r.tick();
  assert.equal(c.r.pendingReconnect(), false, 'the gateway gone: nothing to reconnect');
  assert.ok(c.files.get('/etc/irnetfree/lan-device-usage.json'), 'the devices\' usage saved when the gateway went');
});

test('the pins follow the devices: a new lease moves the rule-set file and the table\'s pin in the same tick; a device taking an ONLINE assigned one\'s address moves neither; an away one\'s address is the taker\'s own', async () => {
  const X = 'aa:bb:cc:dd:ee:0c';
  const until = NOW / 1000 + 86400;
  const lan = fakeLan({ leases: `${until} ${A} 192.168.1.23 phone *\n`, neigh: `192.168.1.23 lladdr ${A} REACHABLE\n` });
  const store = { config: { transparent: { enabled: true, unassigned: 'allow' } }, users: [{ id: 'u-ali', name: 'Ali', target: 'srv-2', enabled: true }], devices: [{ mac: A, userId: 'u-ali' }] };
  const c = controller({ store, lan });
  const tp = await c.r.prepare();
  const config = buildConfig({ mode: 'single', server: SRV1 }, { socksPort: 30808, httpPort: 30809, apiPort: 30085 });
  c.r.applyXray(config, { serverId: 'srv-1', plan: { mode: 'single', server: SRV1 }, settings: { lanUsersTp: tp } });
  const opts = await c.r.gatewayOptions(tp);
  assert.deepEqual(opts.nft.ipmac, [{ mac: A, ips: ['192.168.1.23'] }], 'the gateway starts with the pin in its first table');
  const file = () => JSON.parse(c.files.get('/tmp/irnetfree-lu/lu-tp-1.json')).rules;
  assert.deepEqual(file(), [{ source_ip_cidr: ['192.168.1.23/32'] }]);
  const gw = fakeGateway();
  await c.r.gatewayUp(gw);
  const table = () => (gw.loads.length ? gw.loads[gw.loads.length - 1] : opts.nft);

  // A away — nowhere in the neighbour table — and X (nobody's; allow mode lets it through by its own MAC) took .23 and
  // answers for it: the address is X's own now (plan.addressOwners, "case C") — in no rule-set, pinned to nothing, its bytes X's
  lan.neigh = `192.168.1.23 lladdr ${X} REACHABLE\n`;
  await c.r.tick();
  assert.deepEqual(table().ipmac, [], 'A away: X rides as itself from .23 — and itself is nobody');
  assert.deepEqual(file(), []);
  assert.deepEqual(table().counters.find(x => x.mac === X), { mac: X, ips: ['192.168.1.23'] }, '.23\'s bytes are X\'s own now, not A\'s');
  // A online by another address (its link-local v6: the neighbour table has it) while X still answers for .23: A's lease holds
  lan.neigh = `192.168.1.23 lladdr ${X} REACHABLE\nfe80::a8bb:ccff:fedd:ee01 lladdr ${A} STALE\n`;
  await c.r.tick();
  assert.deepEqual(table().ipmac, [{ mac: A, ips: ['192.168.1.23'] }], 'the address stays A\'s (its lease, A online): X\'s packets from it are dropped');
  assert.deepEqual(file(), [{ source_ip_cidr: ['192.168.1.23/32'] }]);
  assert.deepEqual(table().counters.find(x => x.mac === X), { mac: X, ips: [] }, 'X is counted, but .23\'s bytes are A\'s');

  // a DHCP renewal hands A another address: the file and the pin move together, in one tick
  lan.leases = `${until} ${A} 192.168.1.50 phone *\n`;
  lan.neigh = `192.168.1.50 lladdr ${A} REACHABLE\n`;
  const loads = gw.loads.length;
  await c.r.tick();
  assert.equal(gw.loads.length, loads + 1, 'one table load');
  assert.deepEqual(table().ipmac, [{ mac: A, ips: ['192.168.1.50'] }]);
  assert.deepEqual(file(), [{ source_ip_cidr: ['192.168.1.50/32'] }]);

  // A unassigned: nobody's device, pinned to nothing — the table as it is for any device of no one
  store.devices = [];
  await c.r.tick();
  assert.deepEqual(table().ipmac, []);
  assert.deepEqual(file(), []);
});

test('the devices list counts each device in its user’s month — a Persian-month user’s under j1405-08, the running month’s count carried', async () => {
  const lan = fakeLan({ neigh: `192.168.1.23 lladdr ${A} REACHABLE\n` });
  const files = memFs();
  // saved before the user's cap followed the Persian month: October's count
  files.writeFileSync('/etc/irnetfree/lan-device-usage.json', JSON.stringify({ [A]: { period: '2026-10', bytes: 1000 }, [C]: { period: '2026-10', bytes: 50 }, [D]: { period: '2026-09', bytes: 70 } }));
  const store = { config: { transparent: { enabled: true, unassigned: 'allow' } }, users: [{ id: 'u-ali', name: 'Ali', target: 'srv-2', enabled: true, quotaPeriod: 'month', quotaCalendar: 'jalali' }], devices: [{ mac: A, userId: 'u-ali' }] };
  const r = createLanRouter({
    openwrt: true, dataDir: '/etc/irnetfree', tmpDir: '/tmp', fs: files, run: lan.run, readFile: lan.readFile,
    getSettings: () => ({ modules: { lanUsers: true } }), getLanUsers: () => store, records: () => ({ servers: [SRV1, SRV2], groups: [], chains: [] }),
    getFreePorts: async (n) => Array.from({ length: n }, (_, i) => 41001 + i), log: () => {}, now: () => NOW, meter: fakeMeter(), tickMs: 3600000
  });
  assert.deepEqual(r.deviceUsage(), { [A]: 1000, [C]: 50 }, 'October overlaps Aban: carried; an unbound device by the Gregorian month; September is over');
  await r.gatewayOptions(await r.prepare());
  const gw = fakeGateway();
  gw.tableGen = 1;
  await r.gatewayUp(gw);
  lan.counters = { [A]: { up: 100, down: 200 } };
  await r.tick();
  assert.deepEqual(r.deviceUsage(), { [A]: 1300, [C]: 50 });
  await r.stop();
  assert.deepEqual(JSON.parse(files.get('/etc/irnetfree/lan-device-usage.json'))[A], { period: 'j1405-08', bytes: 1300 });
});

test('the controller, per user: an inbound each by id; the build\'s holds reach the core; a reload follows a user\'s new config; a new user is a reconnect', async () => {
  const lan = fakeLan({ neigh: `192.168.1.21 lladdr ${A} REACHABLE\n192.168.1.22 lladdr ${B} REACHABLE\n` });
  const store = { config: { transparent: { enabled: true, unassigned: 'allow' } },
    users: [{ id: 'u-bob', name: 'Bob', target: 'srv-2', enabled: true }, { id: 'u-ali', name: 'Ali', target: 'srv-2', enabled: true }, { id: 'u-no', target: 'block' }],
    devices: [{ mac: A, userId: 'u-ali' }, { mac: B, userId: 'u-bob' }] };
  const c = controller({ store, lan });
  const tp = await c.r.prepare();
  assert.deepEqual(tp, [{ tag: 'lu-tp-1', port: 41001, userId: 'u-ali', target: 'srv-2' }, { tag: 'lu-tp-2', port: 41002, userId: 'u-bob', target: 'srv-2' }]);
  const pl = { mode: 'single', server: SRV1 };
  const build = () => buildConfig(pl, { socksPort: 30808, httpPort: 30809, apiPort: 30085, routingMode: 'global', directInterface: 'eth0' });
  const config = build();
  c.r.applyXray(config, { serverId: 'srv-1', plan: pl, settings: { lanUsersTp: tp, directInterface: 'eth0', lanUsers: { holds: { 'u-bob': 'vpn' } } } });
  const last = (cfg, tag) => cfg.routing.rules.filter(x => x.inboundTag && x.inboundTag[0] === tag).pop();
  assert.equal(last(config, 'lu-tp-1').outboundTag, 'lu-tp-1-out');
  assert.equal(last(config, 'lu-tp-2').outboundTag, 'block', 'Bob\'s VPN held: blocked in the core, his direct still his');
  const opts = await c.r.gatewayOptions(tp);
  assert.deepEqual(opts.singbox.targets.map(t => t.tag), ['lu-tp-1', 'lu-tp-2']);
  assert.deepEqual(opts.nft.allowed, [A, B], 'a hold of one class: let through');
  assert.deepEqual(JSON.parse(c.files.get('/tmp/irnetfree-lu/lu-tp-1.json')).rules, [{ source_ip_cidr: ['192.168.1.21/32'] }]);
  assert.deepEqual(JSON.parse(c.files.get('/tmp/irnetfree-lu/lu-tp-2.json')).rules, [{ source_ip_cidr: ['192.168.1.22/32'] }], 'the same server, each device on its own user\'s inbound');
  await c.r.gatewayUp(fakeGateway());
  // Ali moves to the selected server: the reload (no list of its own) builds his inbound to it
  store.users[1].target = 'srv-1';
  assert.deepEqual(c.r.tpFor({}).map(e => [e.tag, e.target]), [['lu-tp-1', 'srv-1'], ['lu-tp-2', 'srv-2']]);
  const again = build();
  c.r.applyXray(again, { serverId: 'srv-1', plan: pl, settings: { directInterface: 'eth0', lanUsers: {} } });
  assert.equal(last(again, 'lu-tp-1').outboundTag, 'proxy');
  assert.equal(last(again, 'lu-tp-2').outboundTag, 'lu-tp-2-out', 'the hold gone in this build');
  assert.equal(c.r.pendingReconnect(), false, 'a user\'s new config is a reload of the core, not a reconnect');
  store.users.push({ id: 'u-new', target: 'srv-2' });
  assert.equal(c.r.pendingReconnect(), true, 'a new user needs an inbound: a reconnect');
});

test('speeds: the meter\'s speeds() police each device in the table; a change is a table load at the next tick', async () => {
  const lan = fakeLan({ neigh: `192.168.1.21 lladdr ${A} REACHABLE\n` });
  let speeds = { 'u-ali': { down: 2000, up: 800, why: ['base'] } };
  const meter = Object.assign(fakeMeter(), { speeds: () => speeds });
  const store = { config: { transparent: { enabled: true, unassigned: 'allow' } }, users: [{ id: 'u-ali', name: 'Ali', target: 'srv-2', enabled: true }], devices: [{ mac: A, userId: 'u-ali' }] };
  const c = controller({ store, lan, meter });
  const tp = await c.r.prepare();
  c.r.applyXray(buildConfig({ mode: 'single', server: SRV1 }, { socksPort: 30808, httpPort: 30809, apiPort: 30085 }), { serverId: 'srv-1', plan: { mode: 'single', server: SRV1 }, settings: { lanUsersTp: tp } });
  const opts = await c.r.gatewayOptions(tp);
  assert.deepEqual(opts.nft.rates, [{ mac: A, ips: ['192.168.1.21'], down: 2000, up: 800 }]);
  const text = require('../src/main/openwrtNet').buildNftRuleset({ lanUsers: opts.nft });
  assert.ok(text.includes(`    iifname "br-lan" ether saddr ${A} limit rate over 100 kbytes/second burst 100 kbytes counter drop\n`), text);
  assert.ok(text.includes('    oifname "br-lan" ip daddr 192.168.1.21 limit rate over 250 kbytes/second burst 250 kbytes counter drop\n'), text);
  const gw = fakeGateway();
  await c.r.gatewayUp(gw);
  await c.r.tick();
  assert.equal(gw.loads.length, 0, 'the same speed: no load');
  speeds = { 'u-ali': { down: 1000, up: 0, why: ['hours'] } };
  await c.r.tick();
  assert.deepEqual(gw.loads[gw.loads.length - 1].rates, [{ mac: A, ips: ['192.168.1.21'], down: 1000, up: 0 }], 'peak hours began: a table load');
  speeds = {};
  await c.r.tick();
  assert.deepEqual(gw.loads[gw.loads.length - 1].rates, []);
});

test('the meter on the router: over a VPN limit with routing "" is a hold of the VPN only — the router\'s own routing sends some traffic direct; the desktop\'s is all', () => {
  const { createLanUsersMeter } = require('../src/modules/lanUsers/meter');
  const users = { users: [{ id: 'u1', username: 'ali', password: 'pw12', target: 'srv-2', routing: '', limits: [{ kind: 'vpn', period: 'day', gb: 1 }] }] };
  for (const [router, hold] of [[true, 'vpn'], [false, 'all']]) {
    const m = createLanUsersMeter({ users: () => users, now: () => NOW, baseHasDirect: router });
    m.addBytes('u1', 2 * 1024 ** 3);
    assert.deepEqual([m.holdOf('u1').hold, m.holdOf('u1').why], [hold, 'vpn'], router ? 'router' : 'desktop');
    assert.deepEqual(m.overIds(), router ? [] : ['u1']);
  }
});

/* ------------------------------ the service on a "router" ------------------------------ */

test('the service: with the module and the mode on, the core gets the inbound and the gateway the users\' sets; off, neither', async () => {
  process.env.IRNETFREE_PLATFORM = 'openwrt';
  const fs = require('fs'), os = require('os'), path = require('path');
  const { createService } = require('../src/server/service');
  const fakes = require('./gatewayFakes');
  const lan = fakeLan({ neigh: `192.168.1.23 lladdr ${A} REACHABLE\n` });
  const files = memFs();
  const run = async (on) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-svc-lu-'));
    try {
      const settings = Object.assign({ autoUpdateSubs: false, autoUpdateAssets: 'off', autoConnect: false, tunMode: true, lang: 'en', socksPort: 47808, httpPort: 47809, apiPort: 47885 },
        // off = not installed, the extensions' one-time migration already done (else the users in the store install it)
        on ? { modules: { lanUsers: true }, modulesMigrated: true } : { modules: {}, modulesMigrated: true });
      fs.writeFileSync(path.join(dir, 'store.json'), JSON.stringify({ servers: [SRV1, SRV2], routerDefaultsApplied: true, settings,
        lanUsers: { config: { transparent: { enabled: true, unassigned: 'allow' } }, users: [{ id: 'u-ali', username: 'ali', password: 'pw12', target: 'srv-2', enabled: true }], devices: [{ mac: A, userId: 'u-ali' }] } }));
      const state = fakes.makeState();
      const service = createService({ dataDir: dir, deps: fakes.deps(state, {
        lanRouter: (o) => createLanRouter(Object.assign({}, o, { fs: files, tmpDir: '/tmp', run: lan.run, readFile: lan.readFile, tickMs: 3600000 }))
      }) });
      await service.invoke('connect', 'srv-1');
      const cfg = state.xray.starts[state.xray.starts.length - 1].config;
      const gw = state.gateways[state.gateways.length - 1];
      const out = { inbound: cfg.inbounds.find(i => i.tag === 'lu-tp-1') || null, direct: cfg.outbounds.find(o => o.tag === 'lu-d-u-ali') || null, lanUsers: gw.lanUsers, bypass: state.inners[state.inners.length - 1].bypass };
      await service.invoke('disconnect');
      return out;
    } finally { try { fs.rmSync(dir, { recursive: true, force: true }); } catch {} }
  };
  const on = await run(true);
  assert.equal(on.inbound.listen, '127.0.0.1');
  assert.ok(on.direct && on.direct.protocol === 'freedom', 'the user’s own direct outbound: their direct bytes counted as theirs');
  assert.deepEqual(on.lanUsers.allowed, [A]);
  assert.ok(on.bypass.includes('192.0.2.20'), 'the user\'s config is kept off the tunnel: ' + on.bypass.join(', '));
  const off = await run(false);
  assert.equal(off.inbound, null);
  assert.equal(off.lanUsers, null);
  assert.ok(!off.bypass.includes('192.0.2.20'));
});
