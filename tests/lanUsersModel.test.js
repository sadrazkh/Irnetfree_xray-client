'use strict';
/**
 * Users and devices (module lanUsers) — the record (src/modules/lanUsers/model.js):
 * what the store holds after normalizing, what a user may be saved as, and who
 * may use the proxy right now (enabled, not expired, not over the cap).
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const M = require('../src/modules/lanUsers/model');

const user = (over) => Object.assign({ id: 'usr-a', username: 'ali', password: 'pass1234', name: 'Ali', target: '', quotaGb: 0, quotaPeriod: 'month', expiresAt: 0, maxDevices: 0, enabled: true }, over);

test('a fresh store normalizes to the contract’s defaults: proxy off on 30820/30821, transparent off, login page, 24 h, portal 30822', () => {
  assert.deepEqual(M.normalizeLanUsers(undefined), {
    config: { proxy: { enabled: false, port: 30820, httpPort: 30821 }, transparent: { enabled: false, unassigned: 'login', sessionHours: 24, portalPort: 30822 } },
    users: [], devices: []
  });
  assert.deepEqual(M.normalizeLanUsers('junk'), M.normalizeLanUsers(null));
});

test('config: every part of its type — bad ports fall back, httpPort 0 is SOCKS only, unknown unassigned → login, hours 1–720', () => {
  const c = M.normalizeConfig({ proxy: { enabled: true, port: '40000', httpPort: 0 }, transparent: { enabled: 'yes', unassigned: 'open', sessionHours: 9999, portalPort: 70000 } });
  assert.deepEqual(c, { proxy: { enabled: true, port: 40000, httpPort: 0 }, transparent: { enabled: false, unassigned: 'login', sessionHours: 24, portalPort: 30822 } });
  assert.equal(M.normalizeConfig({ proxy: { port: 'x', httpPort: -1 } }).proxy.port, 30820);
  assert.equal(M.normalizeConfig({ proxy: { httpPort: -1 } }).proxy.httpPort, 30821);
  assert.equal(M.normalizeConfig({ transparent: { unassigned: 'block', sessionHours: 720 } }).transparent.sessionHours, 720);
});

test('users: dropped without an id we write or a usable username; a second by the same id or username (case aside) goes; a damaged target becomes block', () => {
  const lu = M.normalizeLanUsers({
    users: [
      user(),
      user({ id: 'usr-b', username: 'ALI' }),            // the same username, case aside
      user({ id: 'usr-a', username: 'other' }),          // the same id
      user({ id: '"><img>', username: 'x1' }),            // an id we never write
      user({ id: 'usr-c', username: 'has space' }),
      user({ id: 'usr-d', username: 'sara', target: 'chain:"><b>', quotaGb: '2.5', maxDevices: '3', expiresAt: '1700000000000', enabled: 'no' })
    ]
  });
  assert.deepEqual(lu.users.map((u) => u.id), ['usr-a', 'usr-d']);
  const sara = lu.users[1];
  assert.equal(sara.target, 'block');
  assert.equal(sara.quotaGb, 2.5);
  assert.equal(sara.maxDevices, 3);
  assert.equal(sara.expiresAt, 1700000000000);
  assert.equal(sara.enabled, true, 'only false turns a user off');
  assert.equal(M.normalizeLanUsers({ users: [user({ enabled: false })] }).users[0].enabled, false);
  // the password stays exactly as given
  assert.equal(M.normalizeLanUsers({ users: [user({ password: ' sp ace ' })] }).users[0].password, ' sp ace ');
});

test('devices: MACs lowercased with colons, one row per MAC, bound only to a user who exists', () => {
  const lu = M.normalizeLanUsers({
    users: [user()],
    devices: [{ mac: 'AA-BB-CC-DD-EE-01', userId: 'usr-a', name: ' Phone ' }, { mac: 'aa:bb:cc:dd:ee:01', name: 'dup' }, { mac: 'nope' }, { mac: 'aa:bb:cc:dd:ee:02', userId: 'usr-gone', blocked: true }]
  });
  assert.deepEqual(lu.devices, [
    { mac: 'aa:bb:cc:dd:ee:01', name: 'Phone', userId: 'usr-a', blocked: false },
    { mac: 'aa:bb:cc:dd:ee:02', name: '', userId: '', blocked: true }
  ]);
  assert.equal(M.normalizeMac('AA:BB:CC:DD:EE:FF'), 'aa:bb:cc:dd:ee:ff');
  assert.equal(M.normalizeMac('aa:bb:cc:dd:ee'), null);
});

test('validateUser: the first thing wrong, as a key — username, usernameTaken (case aside, not against itself), password, name, target, quota, quotaPeriod, expiresAt, maxDevices', () => {
  const others = [user(), user({ id: 'usr-b', username: 'sara' })];
  assert.equal(M.validateUser(user({ id: 'usr-new', username: 'reza' }), others), null);
  assert.equal(M.validateUser(user({ id: 'usr-a' }), others), null, 'a user is not taken by itself');
  assert.equal(M.validateUser(user({ id: 'usr-new', username: 'SARA' }), others), 'usernameTaken');
  for (const bad of ['', 'a b', 'x'.repeat(33), 'ali:1', 'علی']) assert.equal(M.validateUser(user({ username: bad }), []), 'username', JSON.stringify(bad));
  for (const bad of ['', 'abc', 'with space', 'x'.repeat(65), 'رمزعبور', 1234]) assert.equal(M.validateUser(user({ password: bad }), []), 'password', JSON.stringify(bad));
  assert.equal(M.validateUser(user({ password: 'a:b!c#d' }), []), null, 'printable ASCII, a colon included');
  assert.equal(M.validateUser(user({ name: 'x'.repeat(65) }), []), 'name');
  assert.equal(M.validateUser(user({ target: 'chain:' }), []), 'target');
  for (const t of ['', 'direct', 'block', 'chain:chain-1', 'abc123', 'grp-x']) assert.equal(M.validateUser(user({ target: t }), []), null, t);
  assert.equal(M.validateUser(user({ quotaGb: -1 }), []), 'quota');
  assert.equal(M.validateUser(user({ quotaGb: 'lots' }), []), 'quota');
  assert.equal(M.validateUser(user({ quotaPeriod: 'week' }), []), 'quotaPeriod');
  assert.equal(M.validateUser(user({ expiresAt: -5 }), []), 'expiresAt');
  assert.equal(M.validateUser(user({ maxDevices: 1.5 }), []), 'maxDevices');
  assert.equal(M.validateUser(user({ quotaGb: '', expiresAt: '', maxDevices: '' }), []), null, 'blank numbers are "none"');
});

test('a monthly cap’s calendar and renew day: kept when they say something, not written for the Gregorian 1st, junk dropped', () => {
  const lu = M.normalizeLanUsers({ users: [
    user({ id: 'usr-j', username: 'j', quotaCalendar: 'jalali', quotaResetDay: 15 }),
    user({ id: 'usr-g', username: 'g', quotaCalendar: 'gregorian', quotaResetDay: 1 }),
    user({ id: 'usr-x', username: 'x', quotaCalendar: 'lunar', quotaResetDay: 32 }),
    user({ id: 'usr-o', username: 'o' })
  ] });
  assert.equal(lu.users[0].quotaCalendar, 'jalali');
  assert.equal(lu.users[0].quotaResetDay, 15);
  for (const u of lu.users.slice(1)) {
    assert.equal('quotaCalendar' in u, false, u.id);
    assert.equal('quotaResetDay' in u, false, u.id);
  }
  // a user saved before the two fields existed comes out as it went in — with v1.39's fields at their "nothing set"
  assert.deepEqual(M.normalizeUser(user()), Object.assign(user(), { limits: [], routing: '', schedule: null, speed: null, speedHours: [] }));
  assert.deepEqual(M.CALENDARS, ['gregorian', 'jalali']);
});

test('validateUser: a calendar that is not one of the two, or a renew day outside 1–31, is refused', () => {
  assert.equal(M.validateUser(user({ quotaCalendar: 'jalali', quotaResetDay: 31 }), []), null);
  assert.equal(M.validateUser(user({ quotaCalendar: 'gregorian', quotaResetDay: '15' }), []), null, 'a form’s number as text');
  assert.equal(M.validateUser(user({ quotaResetDay: '' }), []), null, 'blank is the 1st');
  for (const bad of ['julian', '', 'Jalali', 1]) assert.equal(M.validateUser(user({ quotaCalendar: bad }), []), 'quotaCalendar', JSON.stringify(bad));
  for (const bad of [0, 32, 1.5, -1, 'x', '3a', true]) assert.equal(M.validateUser(user({ quotaResetDay: bad }), []), 'quotaResetDay', JSON.stringify(bad));
});

test('active: enabled, credentials the core takes, not expired, not over the cap — by the meter’s usage or the build’s over list', () => {
  const now = 1_800_000_000_000;
  const lu = { users: [
    user({ id: 'usr-on', username: 'on' }),
    user({ id: 'usr-off', username: 'off', enabled: false }),
    user({ id: 'usr-exp', username: 'exp', expiresAt: now - 1 }),
    user({ id: 'usr-later', username: 'later', expiresAt: now + 60000 }),
    user({ id: 'usr-cap', username: 'cap', quotaGb: 1 }),
    user({ id: 'usr-weak', username: 'weak', password: 'abc' })
  ] };
  assert.deepEqual(M.activeUsers(lu, { now }).map((u) => u.id), ['usr-on', 'usr-later', 'usr-cap']);
  assert.deepEqual(M.activeUsers(lu, { now, over: ['usr-cap'] }).map((u) => u.id), ['usr-on', 'usr-later']);
  assert.deepEqual(M.activeUsers(lu, { now, usage: { 'usr-cap': { over: true } } }).map((u) => u.id), ['usr-on', 'usr-later']);
  assert.deepEqual(M.activeUsers(lu, { now: now + 120000 }).map((u) => u.id), ['usr-on', 'usr-cap'], 'the later one has expired by then');
  assert.equal(M.isExpired(user({ expiresAt: 0 }), now), false, '0 = never');
});

test('targetsOf: each target once, in order of first use, the current connection included', () => {
  assert.deepEqual(M.targetsOf({ users: [user({ id: 'u1', username: 'a', target: 's1' }), user({ id: 'u2', username: 'b' }), user({ id: 'u3', username: 'c', target: 's1' }), user({ id: 'u4', username: 'd', target: 'chain:c1' })] }), ['s1', '', 'chain:c1']);
});

test('newUserId: usr- and ten hex characters, a new one each time', () => {
  const a = M.newUserId();
  assert.match(a, /^usr-[0-9a-f]{10}$/);
  assert.notEqual(a, M.newUserId());
});

/* ------------------------------ v1.39.0: limits by kind, routing, allowed hours, speed ------------------------------ */

const at = (y, mo, d, h = 12, mi = 0) => new Date(y, mo - 1, d, h, mi, 0).getTime();

test('limits: a record of before (quotaGb, no limits) becomes its one total limit; quotaGb / quotaPeriod stay its mirror; canonical order, one per (kind, period)', () => {
  assert.deepEqual(M.normalizeUser(user({ quotaGb: 5, quotaPeriod: 'day' })).limits, [{ kind: 'total', period: 'day', gb: 5, action: 'cut' }]);
  assert.deepEqual(M.normalizeUser(user({ quotaGb: 7, quotaPeriod: 'none' })).limits, [{ kind: 'total', period: 'none', gb: 7, action: 'cut' }]);
  const u = M.normalizeUser(user({ quotaGb: 99, limits: [
    { kind: 'direct', period: 'month', gb: '3' }, { kind: 'vpn', period: 'day', gb: 1.23456, action: 'slow', down: 2000, up: '500' },
    { kind: 'total', period: 'none', gb: 40 }, { kind: 'total', period: 'month', gb: 20 }, { kind: 'vpn', period: 'day', gb: 9 },
    { kind: 'lunar', period: 'day', gb: 1 }, { kind: 'vpn', period: 'week', gb: 1 }, { kind: 'vpn', period: 'month', gb: 0 },
    { kind: 'direct', period: 'day', gb: 2, action: 'slow' }
  ] }));
  assert.deepEqual(u.limits, [
    { kind: 'total', period: 'month', gb: 20, action: 'cut' },
    { kind: 'total', period: 'none', gb: 40, action: 'cut' },
    { kind: 'vpn', period: 'day', gb: 1.235, action: 'slow', down: 2000, up: 500 },
    { kind: 'direct', period: 'day', gb: 2, action: 'cut' },
    { kind: 'direct', period: 'month', gb: 3, action: 'cut' }
  ], 'the first of a pair wins; junk goes; a slow limit with no rate is a cut one');
  assert.deepEqual([u.quotaGb, u.quotaPeriod], [20, 'month'], 'the mirror: the first total limit, the given quotaGb ignored');
  const vpnOnly = M.normalizeUser(user({ quotaGb: 5, limits: [{ kind: 'vpn', period: 'day', gb: 1 }] }));
  assert.deepEqual([vpnOnly.quotaGb, vpnOnly.quotaPeriod], [0, 'month'], 'no total limit: 0 / month');
  assert.equal(M.normalizeUser(user({ limits: Array.from({ length: 12 }, () => ({ kind: 'total', period: 'day', gb: 1 })) })).limits.length, 1);
});

test('routing, schedule and speed as stored: junk routing is "", a damaged window allows nothing, rates whole kbps', () => {
  for (const r of ['', 'global', 'bypass-ir', 'profile:rp-default', 'profile:rp-x1']) assert.equal(M.normalizeUser(user({ routing: r })).routing, r);
  for (const r of ['bypass-cn', 'profile:', 'profile:"><b>', 7, null]) assert.equal(M.normalizeUser(user({ routing: r })).routing, '', String(r));
  assert.equal(M.profileIdOf('profile:rp-x1'), 'rp-x1');
  assert.equal(M.profileIdOf('bypass-ir'), null);
  assert.deepEqual(M.normalizeUser(user({ schedule: { days: [5, 1, 1, 9, 'x'], from: '8:00', to: '17:30' } })).schedule, { days: [1, 5], from: '08:00', to: '17:30' });
  assert.deepEqual(M.normalizeUser(user({ schedule: { days: [1], from: '25:00', to: '17:30' } })).schedule, { days: [], from: '00:00', to: '00:00' }, 'a time it cannot read: never, not always');
  assert.equal(M.normalizeUser(user({ schedule: null })).schedule, null);
  assert.deepEqual(M.normalizeUser(user({ speed: { down: '2000.4', up: -3 } })).speed, { down: 2000, up: 0 });
  assert.equal(M.normalizeUser(user({ speed: { down: 0, up: 0 } })).speed, null, 'nothing limited: no speed');
  const hours = M.normalizeUser(user({ speedHours: [
    { days: [5], from: '18:00', to: '23:00', down: 1000 }, { days: [1], from: '08:00', to: '09:00' },
    { days: [2], from: '18:00', to: '23:00', up: 100 }, { days: [3], from: '18:00', to: '23:00', up: 100 }, { days: [4], from: '18:00', to: '23:00', up: 100 }, { days: [6], from: '18:00', to: '23:00', up: 100 }
  ] })).speedHours;
  assert.equal(hours.length, 4, 'at most four, the one with no rate left out');
  assert.deepEqual(hours[0], { days: [5], from: '18:00', to: '23:00', down: 1000, up: 0 });
});

test('validateUserDetail: limits, routing, schedule and speed each refused with their code and the part — validateUser says the code alone', () => {
  const ok = (over) => M.validateUserDetail(user(over), []);
  assert.equal(ok({ limits: [{ kind: 'total', period: 'day', gb: 1 }, { kind: 'vpn', period: 'month', gb: '2.5', action: 'slow', down: '1500', up: '' }], routing: 'bypass-ir', schedule: { days: [0, 6], from: '08:00', to: '08:00' }, speed: { down: 1000 }, speedHours: [{ days: [1], from: '22:00', to: '06:00', up: 64 }] }), null);
  const cases = [
    [{ limits: 'x' }, 'limits', 'list'], [{ limits: Array.from({ length: 10 }, (_, i) => ({ kind: 'total', period: 'day', gb: i + 1 })) }, 'limits', 'list'],
    [{ limits: [{ kind: 'all', period: 'day', gb: 1 }] }, 'limits', 'kind'], [{ limits: [{ kind: 'vpn', period: 'week', gb: 1 }] }, 'limits', 'period'],
    [{ limits: [{ kind: 'vpn', period: 'day', gb: 0 }] }, 'limits', 'gb'], [{ limits: [{ kind: 'vpn', period: 'day', gb: '' }] }, 'limits', 'gb'],
    [{ limits: [{ kind: 'vpn', period: 'day', gb: 1000001 }] }, 'limits', 'gb'],
    [{ limits: [{ kind: 'vpn', period: 'day', gb: 1 }, { kind: 'vpn', period: 'day', gb: 2 }] }, 'limits', 'duplicate'],
    [{ limits: [{ kind: 'vpn', period: 'day', gb: 1, action: 'stop' }] }, 'limits', 'action'],
    [{ limits: [{ kind: 'vpn', period: 'day', gb: 1, action: 'slow' }] }, 'speed', 'slow'],
    [{ limits: [{ kind: 'vpn', period: 'day', gb: 1, action: 'slow', down: 1.5 }] }, 'speed', 'slow'],
    [{ routing: 'bypass-cn' }, 'routing', 'mode'], [{ routing: 3 }, 'routing', 'mode'], [{ routing: 'profile:a b' }, 'routing', 'profile'],
    [{ schedule: 'mornings' }, 'schedule', 'shape'], [{ schedule: { days: [], from: '08:00', to: '09:00' } }, 'schedule', 'days'],
    [{ schedule: { days: [7], from: '08:00', to: '09:00' } }, 'schedule', 'days'], [{ schedule: { days: [1], from: '8:00', to: '09:00' } }, 'schedule', 'from'],
    [{ schedule: { days: [1], from: '08:00', to: '24:00' } }, 'schedule', 'to'],
    [{ speed: {} }, 'speed', 'base'], [{ speed: { down: 10000001 } }, 'speed', 'base'], [{ speed: { down: 'fast' } }, 'speed', 'base'],
    [{ speedHours: {} }, 'speed', 'hours'], [{ speedHours: Array.from({ length: 5 }, () => ({ days: [1], from: '08:00', to: '09:00', down: 1 })) }, 'speed', 'hours'],
    [{ speedHours: [{ days: [1], from: 'x', to: '09:00', down: 1 }] }, 'speed', 'window'], [{ speedHours: [{ days: [1], from: '08:00', to: '09:00' }] }, 'speed', 'rate']
  ];
  for (const [over, error, detail] of cases) {
    assert.deepEqual(ok(over), { error, detail }, JSON.stringify(over));
    assert.equal(M.validateUser(user(over), []), error);
  }
  assert.deepEqual(ok({ username: 'a b' }), { error: 'username' }, 'the codes of before carry no detail');
});

test('allowed hours: a day window, all day (from = to), overnight (the part after midnight is the day it began on); the next start', () => {
  const S = (days, from, to) => ({ days, from, to });
  // 2026-10-26 is a Monday (getDay 1)
  const day = S([1, 3], '08:00', '17:30');
  assert.deepEqual(M.windowState(day, at(2026, 10, 26, 7, 59)), { on: false, next: at(2026, 10, 26, 8), end: 0 });
  assert.deepEqual(M.windowState(day, at(2026, 10, 26, 8)), { on: true, next: at(2026, 10, 28, 8), end: at(2026, 10, 26, 17, 30) });
  assert.equal(M.windowState(day, at(2026, 10, 26, 17, 30)).on, false, 'the end is not in it');
  assert.equal(M.windowState(day, at(2026, 10, 27, 12)).next, at(2026, 10, 28, 8), 'Tuesday: Wednesday morning');
  const allDay = S([2], '09:00', '09:00');
  assert.deepEqual(M.windowState(allDay, at(2026, 10, 27, 0, 5)), { on: true, next: at(2026, 11, 3, 0), end: at(2026, 10, 28, 0) });
  assert.equal(M.windowState(allDay, at(2026, 10, 26, 23, 59)).next, at(2026, 10, 27, 0));
  const night = S([1], '22:00', '06:00');
  assert.equal(M.windowState(night, at(2026, 10, 26, 23)).on, true, 'Monday night');
  assert.equal(M.windowState(night, at(2026, 10, 27, 5, 59)).on, true, 'Tuesday 05:59 belongs to Monday');
  assert.equal(M.windowState(night, at(2026, 10, 26, 5)).on, false, 'Monday 05:00 would be Sunday’s, and Sunday is not in it');
  assert.equal(M.windowState(night, at(2026, 10, 27, 6)).next, at(2026, 11, 2, 22), 'next Monday night');
  assert.deepEqual(M.windowState(S([], '08:00', '09:00'), at(2026, 10, 26)), { on: false, next: 0, end: 0 }, 'no day: never');
  assert.deepEqual(M.windowState(null, at(2026, 10, 26)), { on: true, next: 0, end: 0 });
  // and the proxy's say: outside the hours is not active
  const lu = { users: [user({ schedule: day }), user({ id: 'usr-b', username: 'sara' })] };
  assert.deepEqual(M.activeUsers(lu, { now: at(2026, 10, 26, 7) }).map((u) => u.id), ['usr-b']);
  assert.deepEqual(M.activeUsers(lu, { now: at(2026, 10, 26, 9) }).map((u) => u.id), ['usr-a', 'usr-b']);
});
