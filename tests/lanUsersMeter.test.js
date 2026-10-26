'use strict';
/**
 * Users and devices (module lanUsers) — the meter (src/modules/lanUsers/meter.js):
 * each user's bytes per period from the core's per-user counters, a cap
 * reached → ONE reload and a log line, a new period → back with one more, a
 * fresh core's counters counted from zero, the router's devices by MAC.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { createLanUsersMeter, rollEntry, userPeriod, normalizeUsage, normalizeDeviceUsage } = require('../src/modules/lanUsers/meter');

const GIB = 1024 ** 3;
const at = (y, mo, d, h = 12) => new Date(y, mo - 1, d, h, 0, 0).getTime();
const user = (id, username, over) => Object.assign({ id, username, password: 'pw-' + username, target: '', quotaGb: 0, quotaPeriod: 'month', expiresAt: 0, maxDevices: 0, enabled: true }, over);
const vars = (users, extra) => ({ stats: Object.assign({ user: users, outbound: {} }, extra || {}) });
const flush = () => new Promise((r) => setImmediate(r));

function meter(store, o) {
  const seen = { reloads: [], logs: [], notes: [] };
  let t = (o && o.t) || at(2026, 10, 25);
  const m = createLanUsersMeter(Object.assign({
    usage: {}, users: () => store,
    canReload: () => true, pending: () => [],
    reload: async (why) => { seen.reloads.push(why); return true; },
    log: (l) => seen.logs.push(l.line), notify: (n) => seen.notes.push(n),
    now: () => t
  }, o));
  return { m, seen, set: (v) => { t = v; }, get t() { return t; } };
}

test('periods: by the day, by the month, and "none" with a cap — one amount for good; a day rolls into its month, anything else starts over', () => {
  assert.equal(userPeriod(user('a', 'a', { quotaPeriod: 'day' }), at(2026, 10, 25)), '2026-10-25');
  assert.equal(userPeriod(user('a', 'a'), at(2026, 10, 25)), '2026-10');
  assert.equal(userPeriod(user('a', 'a', { quotaPeriod: 'none', quotaGb: 10 }), at(2026, 10, 25)), 'all');
  assert.equal(userPeriod(user('a', 'a', { quotaPeriod: 'none' }), at(2026, 10, 25)), '2026-10', 'no cap: counted by the month');
  assert.deepEqual(rollEntry({ period: '2026-10-25', bytes: 5 }, '2026-10'), { period: '2026-10', bytes: 5 });
  assert.deepEqual(rollEntry({ period: '2026-10', bytes: 5 }, '2026-11'), { period: '2026-11', bytes: 0 });
  assert.deepEqual(rollEntry({ period: '2026-10', bytes: 5 }, 'all'), { period: 'all', bytes: 5 });
  assert.deepEqual(normalizeUsage({ 'usr-a': { period: '2026-10', bytes: '7' }, 'bad id!': { period: '2026-10', bytes: 1 }, 'usr-b': { period: 'x' } }), { 'usr-a': { period: '2026-10', bytes: 7 } });
});

test('counting: each username’s growth to its user, rates per user, a fresh core (counters below the last) counted from zero', () => {
  const store = { users: [user('usr-a', 'ali'), user('usr-b', 'sara')] };
  const { m, set, t } = meter(store);
  m.built({ active: ['usr-a', 'usr-b'], over: [], byName: { ali: 'usr-a', sara: 'usr-b' } });
  assert.equal(m.tick(vars({ ali: { uplink: 100, downlink: 900 } })).fresh, true, 'the first reading is a new core');
  set(t + 1000);
  m.tick(vars({ ali: { uplink: 200, downlink: 1800 }, sara: { uplink: 10, downlink: 0 }, stranger: { uplink: 5, downlink: 5 } }));
  assert.equal(m.usage()['usr-a'].bytes, 2000);
  assert.equal(m.usage()['usr-b'].bytes, 10);
  assert.deepEqual(m.rates()['usr-a'], { up: 100, down: 900 });
  set(t + 2000);
  assert.equal(m.tick(vars({ ali: { uplink: 50, downlink: 50 } })).fresh, true, 'every counter lower: the core started again');
  assert.equal(m.usage()['usr-a'].bytes, 2100, 'all of the new core’s bytes are new');
  assert.ok(m.dirty);
  assert.equal(m.dueForSave(t + 2000 + 30000), true);
});

test('a cap reached: ONE reload and one line, however many ticks; the next day the user is back with one more reload', async () => {
  const store = { users: [user('usr-a', 'ali', { quotaGb: 1, quotaPeriod: 'day' }), user('usr-b', 'sara')] };
  const h = meter(store, { t: at(2026, 10, 25, 12) });
  h.m.built({ active: ['usr-a', 'usr-b'], over: [], byName: { ali: 'usr-a', sara: 'usr-b' } });
  h.m.tick(vars({ ali: { uplink: 0, downlink: 0 } }));
  h.set(h.t + 1000);
  h.m.tick(vars({ ali: { uplink: 1000, downlink: 2 * GIB } }));
  await flush();
  assert.deepEqual(h.m.overIds(), ['usr-a']);
  assert.equal(h.seen.reloads.length, 1);
  assert.ok(h.seen.logs.some((l) => /“ali” reached their cap \(1 GB today\)/.test(l)), JSON.stringify(h.seen.logs));
  assert.deepEqual(h.seen.notes, [{ name: 'ali', capGb: 1, period: 'day', until: at(2026, 10, 26, 0), calendar: 'gregorian' }]);
  for (let i = 2; i < 6; i++) { h.set(h.t + 1000); h.m.tick(vars({ ali: { uplink: 1000, downlink: 2 * GIB } })); }
  await flush();
  assert.equal(h.seen.reloads.length, 1, 'one reload, not one a tick');
  // the reload: the build without her, a fresh core counting from zero
  h.m.built({ active: ['usr-b'], over: ['usr-a'], byName: { sara: 'usr-b' } });
  h.set(h.t + 1000);
  h.m.tick(vars({}));
  await flush();
  assert.equal(h.seen.reloads.length, 1, 'built without her: nothing to do');
  assert.equal(h.m.usage()['usr-a'].over, true);
  // past midnight: a new day — back, said, one reload
  h.set(at(2026, 10, 26, 0) + 5000);
  h.m.tick(vars({}));
  await flush();
  assert.deepEqual(h.m.overIds(), []);
  assert.equal(h.seen.reloads.length, 2);
  assert.ok(h.seen.logs.some((l) => /“ali” is back/.test(l)));
  assert.equal(h.m.usage()['usr-a'].period, '2026-10-26');
});

test('a cap waits for pending settings (said once), and a reload that did not happen is asked again no sooner than 15 s', async () => {
  const store = { users: [user('usr-a', 'ali', { quotaGb: 1 })] };
  let keys = ['dnsRemote'];
  const h = meter(store, { pending: () => keys, usage: { 'usr-a': { period: '2026-10', bytes: 2 * GIB } } });
  h.m.built({ active: ['usr-a'], over: [], byName: { ali: 'usr-a' } });
  h.m.tick(vars({}));
  h.set(h.t + 1000); h.m.tick(vars({}));
  await flush();
  assert.equal(h.seen.reloads.length, 0);
  assert.equal(h.seen.logs.filter((l) => /waits for your pending settings/.test(l)).length, 1);
  keys = [];
  h.set(h.t + 1000); h.m.tick(vars({}));
  await flush();
  assert.equal(h.seen.reloads.length, 1);
  h.set(h.t + 5000); h.m.tick(vars({}));
  await flush();
  assert.equal(h.seen.reloads.length, 1, 'still running the old build: not again within 15 s');
  h.set(h.t + 16000); h.m.tick(vars({}));
  await flush();
  assert.equal(h.seen.reloads.length, 2);
});

test('an expiry passing while connected turns the user off with one reload; an edit is not the meter’s to apply', async () => {
  const t0 = at(2026, 10, 25, 12);
  const store = { users: [user('usr-a', 'ali', { expiresAt: t0 + 2000 }), user('usr-b', 'sara')] };
  const h = meter(store, { t: t0 });
  h.m.built({ active: ['usr-a', 'usr-b'], over: [], byName: { ali: 'usr-a', sara: 'usr-b' } });
  h.m.tick(vars({}));
  store.users[1] = user('usr-b', 'sara', { enabled: false });   // the admin turns sara off: ipc.js reloads for that
  h.set(t0 + 1000); h.m.tick(vars({}));
  await flush();
  assert.equal(h.seen.reloads.length, 0);
  h.set(t0 + 3000); h.m.tick(vars({}));
  await flush();
  assert.equal(h.seen.reloads.length, 1);
  assert.ok(h.seen.logs.some((l) => /“ali” expired/.test(l)));
});

test('the router’s devices: each MAC’s growth counted for it and its user; a counter made again counts from zero', () => {
  const store = { users: [user('usr-a', 'ali')], devices: [{ mac: 'aa:bb:cc:dd:ee:01', userId: 'usr-a' }] };
  const h = meter(store);
  h.m.tickDevices({ 'AA:BB:CC:DD:EE:01': { up: 100, down: 900 }, 'aa:bb:cc:dd:ee:02': 500 });
  h.set(h.t + 1000);
  h.m.tickDevices({ 'aa:bb:cc:dd:ee:01': { up: 200, down: 1800 }, 'aa:bb:cc:dd:ee:02': 100 });
  assert.deepEqual(h.m.deviceUsage(), { 'aa:bb:cc:dd:ee:01': 2000, 'aa:bb:cc:dd:ee:02': 600 });
  assert.equal(h.m.usage()['usr-a'].bytes, 2000, 'the bound device’s bytes are its user’s');
  assert.deepEqual(h.m.deviceRates()['aa:bb:cc:dd:ee:01'], { up: 100, down: 900 });
  assert.deepEqual(Object.keys(h.m.savedDevices()), ['aa:bb:cc:dd:ee:01', 'aa:bb:cc:dd:ee:02']);
});

/* ------------------------------ a month of the owner's choosing ------------------------------ */

test('a user’s month: the Persian one (j1405-08), a renew day (2026-10@15), both; what was saved under them is read back', () => {
  const t = at(2026, 10, 26);
  assert.equal(userPeriod(user('a', 'a', { quotaCalendar: 'jalali' }), t), 'j1405-08');
  assert.equal(userPeriod(user('a', 'a', { quotaResetDay: 15 }), t), '2026-10@15');
  assert.equal(userPeriod(user('a', 'a', { quotaCalendar: 'jalali', quotaResetDay: 15 }), t), 'j1405-07@15');
  assert.equal(userPeriod(user('a', 'a', { quotaPeriod: 'day', quotaCalendar: 'jalali' }), t), '2026-10-26', 'a daily cap: the day');
  assert.equal(userPeriod(user('a', 'a', { quotaPeriod: 'none', quotaGb: 5, quotaCalendar: 'jalali' }), t), 'all');
  assert.deepEqual(normalizeUsage({
    'usr-a': { period: 'j1405-08', bytes: 1 }, 'usr-b': { period: '2026-10@15', bytes: 2 }, 'usr-c': { period: 'j1405-07@31', bytes: 3 },
    'usr-d': { period: 'all', bytes: 4 }, 'usr-e': { period: '2026-10@1', bytes: 5 }, 'usr-f': { period: 'j1405-08-01', bytes: 6 }
  }), { 'usr-a': { period: 'j1405-08', bytes: 1 }, 'usr-b': { period: '2026-10@15', bytes: 2 }, 'usr-c': { period: 'j1405-07@31', bytes: 3 }, 'usr-d': { period: 'all', bytes: 4 } });
  assert.deepEqual(normalizeDeviceUsage({ 'AA:BB:CC:DD:EE:01': { period: 'j1405-08@20', bytes: 9 }, 'aa:bb:cc:dd:ee:02': { period: 'nope', bytes: 9 } }),
    { 'aa:bb:cc:dd:ee:01': { period: 'j1405-08@20', bytes: 9 } });
});

test('an upgrade counts on: a user with neither field keeps the entry saved under YYYY-MM, bytes and all', () => {
  const store = { users: [user('usr-a', 'ali', { quotaGb: 50 })] };
  const h = meter(store, { usage: { 'usr-a': { period: '2026-10', bytes: 7 * GIB } } });
  const u = h.m.usage()['usr-a'];
  assert.deepEqual([u.period, u.bytes, u.since, u.until], ['2026-10', 7 * GIB, at(2026, 10, 1, 0), at(2026, 11, 1, 0)]);
  assert.equal(h.m.dirty, false, 'nothing moved: nothing to write');
});

test('the calendar or renew day changed while counting: the count goes on (and back); until is the new month’s renew day', () => {
  const store = { users: [user('usr-a', 'ali', { quotaGb: 50 })] };
  const h = meter(store, { usage: { 'usr-a': { period: '2026-10', bytes: 7 * GIB } } });
  store.users[0] = user('usr-a', 'ali', { quotaGb: 50, quotaCalendar: 'jalali' });
  let u = h.m.usage()['usr-a'];
  assert.deepEqual([u.period, u.bytes, u.since, u.until], ['j1405-08', 7 * GIB, at(2026, 10, 23, 0), at(2026, 11, 22, 0)], 'Aban: 23 Oct – 22 Nov');
  store.users[0] = user('usr-a', 'ali', { quotaGb: 50, quotaCalendar: 'jalali', quotaResetDay: 15 });
  u = h.m.usage()['usr-a'];
  assert.deepEqual([u.period, u.bytes, u.until], ['j1405-07@15', 7 * GIB, at(2026, 11, 6, 0)], 'renewing on 15 Aban');
  store.users[0] = user('usr-a', 'ali', { quotaGb: 50 });
  assert.equal(h.m.usage()['usr-a'].bytes, 7 * GIB, 'back to the Gregorian month: nothing lost');
  store.users[0] = user('usr-a', 'ali', { quotaGb: 50, quotaPeriod: 'day' });
  assert.equal(h.m.usage()['usr-a'].bytes, 0, 'a day never takes a month’s bytes');
  assert.ok(h.m.dirty);
});

test('a Persian-month cap reached: off until the 1st of the next Persian month, said with that date; back at its midnight', async () => {
  const store = { users: [user('usr-a', 'ali', { quotaGb: 1, quotaCalendar: 'jalali' }), user('usr-b', 'sara')] };
  const h = meter(store, { t: at(2026, 11, 20, 12) });   // 29 Aban 1405
  h.m.built({ active: ['usr-a', 'usr-b'], over: [], byName: { ali: 'usr-a', sara: 'usr-b' } });
  h.m.tick(vars({ ali: { uplink: 0, downlink: 0 } }));
  h.set(h.t + 1000);
  h.m.tick(vars({ ali: { uplink: 0, downlink: 2 * GIB } }));
  await flush();
  assert.deepEqual(h.m.overIds(), ['usr-a']);
  assert.ok(h.seen.logs.some((l) => l === 'Users: “ali” reached their cap (1 GB this month) — off until 22 November (1 Azar)'), JSON.stringify(h.seen.logs));
  assert.deepEqual(h.seen.notes, [{ name: 'ali', capGb: 1, period: 'month', until: at(2026, 11, 22, 0), calendar: 'jalali' }]);
  assert.equal(h.m.usage()['usr-a'].until, at(2026, 11, 22, 0));
  h.m.built({ active: ['usr-b'], over: ['usr-a'], byName: { sara: 'usr-b' } });
  h.set(at(2026, 11, 21, 23, 59));
  h.m.tick(vars({}));
  assert.deepEqual(h.m.overIds(), ['usr-a'], '30 Aban: still off — a Gregorian month would have let her back on 1 Nov already');
  h.set(at(2026, 11, 22, 0) + 5000);
  h.m.tick(vars({}));
  await flush();
  assert.deepEqual(h.m.overIds(), []);
  assert.equal(h.m.usage()['usr-a'].period, 'j1405-09');
  assert.ok(h.seen.logs.some((l) => /“ali” is back/.test(l)));
});

test('a Gregorian cap renewing on the 31st, reached in November: the line says 30 November', async () => {
  const store = { users: [user('usr-a', 'ali', { quotaGb: 1, quotaResetDay: 31 })] };
  const h = meter(store, { t: at(2026, 11, 10, 12) });
  h.m.built({ active: ['usr-a'], over: [], byName: { ali: 'usr-a' } });
  h.m.tick(vars({ ali: { uplink: 0, downlink: 0 } }));
  h.set(h.t + 1000);
  h.m.tick(vars({ ali: { uplink: 0, downlink: 2 * GIB } }));
  assert.ok(h.seen.logs.some((l) => /— off until 30 November$/.test(l)), JSON.stringify(h.seen.logs));
  assert.equal(h.m.usage()['usr-a'].period, '2026-10@31');
});

test('the router’s devices count in their user’s month too: a device of a Persian-month user is keyed j1405-08', () => {
  const store = { users: [user('usr-a', 'ali', { quotaCalendar: 'jalali' })], devices: [{ mac: 'aa:bb:cc:dd:ee:01', userId: 'usr-a' }] };
  const h = meter(store, { t: at(2026, 10, 26), deviceUsage: { 'aa:bb:cc:dd:ee:01': { period: '2026-10', bytes: 300 } } });
  h.m.tickDevices({ 'aa:bb:cc:dd:ee:01': 100 });
  assert.deepEqual(h.m.savedDevices(), { 'aa:bb:cc:dd:ee:01': { period: 'j1405-08', bytes: 400 } }, 'the month just changed to: its count went on');
  assert.deepEqual(h.m.deviceUsage(), { 'aa:bb:cc:dd:ee:01': 400 });
});
