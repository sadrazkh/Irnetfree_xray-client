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
  // a user saved before the two fields existed comes out exactly as it went in
  assert.deepEqual(M.normalizeUser(user()), user());
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
