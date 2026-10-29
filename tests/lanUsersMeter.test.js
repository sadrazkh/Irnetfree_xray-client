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
  // v1.39.0: the notice says which limit and how far (80 % and 100 % crossed in one tick: the 100 % alone)
  assert.deepEqual(h.seen.notes, [{ name: 'ali', kind: 'total', period: 'day', pct: 100, capGb: 1, until: at(2026, 10, 26, 0), calendar: 'gregorian', action: 'cut', leftBytes: 0, hold: 'all' }]);
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
  assert.deepEqual(h.seen.notes, [{ name: 'ali', kind: 'total', period: 'month', pct: 100, capGb: 1, until: at(2026, 11, 22, 0), calendar: 'jalali', action: 'cut', leftBytes: 0, hold: 'all' }]);
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

/* ------------------------------ v1.39.0: by kind, holds, top-ups, warnings, history, speed ------------------------------ */

const { normalizeUsage2 } = require('../src/modules/lanUsers/meter');
const L = (kind, period, gb, more) => Object.assign({ kind, period, gb }, more);
const MON = at(2026, 10, 26, 12);   // a Monday
/** Saved usage (lanUsersUsage2) of one user on a day: every kind's day and month at the bytes given. */
const u2 = (day, month, kinds) => {
  const out = {};
  for (const [k, n] of Object.entries(kinds)) out[k] = { day: { period: day, bytes: n }, month: { period: month, bytes: n } };
  return out;
};
const meterRow = (u, kind, period) => u.meters.find((r) => r.kind === kind && r.period === period);

test('by kind: an account’s bytes are its total, its own direct outbound’s (lu-d-<id>) the direct, the rest VPN; direct counted ahead of the total waits for it; target direct is all direct', () => {
  const store = { users: [user('usr-a', 'ali', { routing: 'bypass-ir' }), user('usr-d', 'dina', { target: 'direct' })] };
  const h = meter(store);
  h.m.built({ active: ['usr-a', 'usr-d'], over: [], byName: { ali: 'usr-a', dina: 'usr-d' } });
  const read = (ali, aliDirect, dina) => vars({ ali: { uplink: 0, downlink: ali }, dina: { uplink: 0, downlink: dina } },
    { outbound: { proxy: { uplink: 0, downlink: 0 }, 'lu-d-usr-a': { uplink: 0, downlink: aliDirect }, 'lu-d-usr-d': { uplink: 0, downlink: dina } } });
  h.m.tick(read(0, 0, 0));
  h.set(h.t + 1000); h.m.tick(read(1000, 300, 500));
  const at1 = h.m.usage();
  for (const p of ['day', 'month']) {
    assert.deepEqual(['total', 'vpn', 'direct'].map((k) => meterRow(at1['usr-a'], k, p).bytes), [1000, 700, 300], p);
    assert.deepEqual(['total', 'vpn', 'direct'].map((k) => meterRow(at1['usr-d'], k, p).bytes), [500, 0, 500], 'target direct: all of it direct');
  }
  h.set(h.t + 1000); h.m.tick(read(1000, 500, 500));
  assert.equal(meterRow(h.m.usage()['usr-a'], 'direct', 'day').bytes, 300, 'direct with no total yet: it waits');
  h.set(h.t + 1000); h.m.tick(read(1300, 500, 500));
  const u = h.m.usage()['usr-a'];
  assert.deepEqual(['total', 'vpn', 'direct'].map((k) => meterRow(u, k, 'day').bytes), [1300, 800, 500], 'the three always add up');
  assert.deepEqual(u.history, [{ day: '2026-10-25', vpn: 800, direct: 500 }]);
  assert.equal(u.bytes, 1300, 'the fields of before: the total of the mirror cap (the month here)');
});

test('the router: the devices’ nft bytes are the total, the router core’s lu-d-<id> the direct — whichever arrives first', () => {
  const store = { users: [user('usr-a', 'ali', { routing: 'bypass-ir' })], devices: [{ mac: 'aa:bb:cc:dd:ee:01', userId: 'usr-a' }] };
  const h = meter(store);
  h.m.tick(vars({}, { outbound: { 'lu-d-usr-a': { uplink: 10, downlink: 390 } } }));
  h.m.tickDevices({ 'aa:bb:cc:dd:ee:01': { up: 100, down: 900 } });
  const u = h.m.usage()['usr-a'];
  assert.deepEqual(['total', 'vpn', 'direct'].map((k) => meterRow(u, k, 'month').bytes), [1000, 600, 400]);
});

test('usage(): six meters always (each kind × day and month), a one-off one per kind that has it; caps, top-ups, pct; the old fields from the mirror', () => {
  const store = { users: [user('usr-a', 'ali', { quotaCalendar: 'jalali', limits: [L('total', 'month', 10), L('vpn', 'none', 4), L('direct', 'day', 1, { action: 'slow', down: 1000, up: 500 })] })] };
  const h = meter(store, { t: MON, usage2: { 'usr-a': Object.assign(u2('2026-10-26', 'j1405-08', { total: 3 * GIB, vpn: 2 * GIB, direct: GIB / 2 }), { vpn: { day: { period: '2026-10-26', bytes: 2 * GIB }, month: { period: 'j1405-08', bytes: 2 * GIB }, all: { period: 'all', bytes: 3 * GIB, since: MON - 86400000 } } }) } });
  const u = h.m.usage()['usr-a'];
  assert.deepEqual(u.meters.map((r) => r.kind + ':' + r.period), ['total:day', 'total:month', 'vpn:day', 'vpn:month', 'vpn:none', 'direct:day', 'direct:month']);
  assert.deepEqual(meterRow(u, 'total', 'month'), { kind: 'total', period: 'month', bytes: 3 * GIB, capBytes: 10 * GIB, extraBytes: 0, since: at(2026, 10, 23, 0), until: at(2026, 11, 22, 0), over: false, pct: 30, action: 'cut' });
  assert.deepEqual(meterRow(u, 'vpn', 'none'), { kind: 'vpn', period: 'none', bytes: 3 * GIB, capBytes: 4 * GIB, extraBytes: 0, since: MON - 86400000, until: 0, over: false, pct: 75, action: 'cut' });
  assert.deepEqual(meterRow(u, 'direct', 'day'), { kind: 'direct', period: 'day', bytes: GIB / 2, capBytes: GIB, extraBytes: 0, since: at(2026, 10, 26, 0), until: at(2026, 10, 27, 0), over: false, pct: 50, action: 'slow', down: 1000, up: 500 });
  assert.deepEqual(meterRow(u, 'vpn', 'day'), { kind: 'vpn', period: 'day', bytes: 2 * GIB, capBytes: 0, extraBytes: 0, since: at(2026, 10, 26, 0), until: at(2026, 10, 27, 0), over: false, pct: 0, action: null }, 'no limit: counted, capBytes 0');
  assert.deepEqual([u.bytes, u.period, u.quotaBytes, u.over, u.hold, u.why, u.holdUntil, u.speed], [3 * GIB, 'j1405-08', 10 * GIB, false, null, null, 0, null]);
});

test('holds: disabled > expired > outside the hours > total > VPN / direct; a VPN limit stops only the VPN unless nothing goes direct; until is when it lifts', () => {
  const t0 = MON;
  const day = '2026-10-26', month = '2026-10';
  const all2 = u2(day, month, { total: 2 * GIB, vpn: 2 * GIB, direct: 2 * GIB });
  const users = [
    user('u-vpn', 'v', { routing: 'bypass-ir', limits: [L('vpn', 'day', 1)] }),
    user('u-vpn0', 'v0', { limits: [L('vpn', 'day', 1)] }),
    user('u-dir', 'd', { routing: 'profile:rp-1', limits: [L('direct', 'month', 1)] }),
    user('u-dirt', 'dt', { target: 'direct', limits: [L('direct', 'day', 1)] }),
    user('u-both', 'b', { routing: 'bypass-ir', limits: [L('vpn', 'month', 1), L('direct', 'day', 1)] }),
    user('u-tot', 't', { routing: 'bypass-ir', limits: [L('total', 'day', 1), L('total', 'month', 1), L('vpn', 'day', 1)] }),
    user('u-none', 'n', { limits: [L('total', 'none', 1)] }),
    user('u-sch', 's', { schedule: { days: [2], from: '08:00', to: '09:00' }, limits: [L('total', 'day', 1)] }),
    user('u-exp', 'e', { expiresAt: t0 - 1, schedule: { days: [2], from: '08:00', to: '09:00' } }),
    user('u-off', 'o', { enabled: false, expiresAt: t0 - 1 }),
    user('u-ok', 'k', { limits: [L('vpn', 'day', 5), L('total', 'day', 2, { action: 'slow', down: 1000 })] })
  ];
  const usage2 = {};
  for (const u of users) usage2[u.id] = JSON.parse(JSON.stringify(all2));
  usage2['u-none'].total.all = { period: 'all', bytes: 2 * GIB, since: t0 - 1000 };
  const h = meter({ users }, { t: t0, usage2 });
  assert.deepEqual(h.m.holds(), {
    'u-vpn': { hold: 'vpn', why: 'vpn', until: at(2026, 10, 27, 0) },
    'u-vpn0': { hold: 'all', why: 'vpn', until: at(2026, 10, 27, 0) },
    'u-dir': { hold: 'direct', why: 'direct', until: at(2026, 11, 1, 0) },
    'u-dirt': { hold: 'all', why: 'direct', until: at(2026, 10, 27, 0) },
    'u-both': { hold: 'all', why: 'vpn', until: at(2026, 10, 27, 0) },
    'u-tot': { hold: 'all', why: 'total', until: at(2026, 11, 1, 0) },
    'u-none': { hold: 'all', why: 'total', until: 0 },
    'u-sch': { hold: 'all', why: 'schedule', until: at(2026, 10, 27, 8) },
    'u-exp': { hold: 'all', why: 'expired', until: 0 },
    'u-off': { hold: 'all', why: 'disabled', until: 0 }
  });
  assert.deepEqual(h.m.overIds(), ['u-vpn0', 'u-dirt', 'u-both', 'u-tot', 'u-none', 'u-sch', 'u-exp', 'u-off'], 'the build leaves out the "all" ones only');
  assert.deepEqual(h.m.holdOf('u-ok'), { hold: null, why: null, until: 0 }, 'a slow limit over is no hold');
  assert.deepEqual(h.m.holdOf(users[0]), h.m.holds()['u-vpn'], 'by record or by id');
  const use = h.m.usage();
  assert.deepEqual([use['u-vpn'].over, use['u-vpn'].hold, use['u-vpn'].holdUntil], [false, 'vpn', at(2026, 10, 27, 0)]);
  assert.equal(use['u-tot'].over, true);
});

test('a VPN limit reached while connected: ONE reload (the user keeps their account, the VPN blocked), said; the next day the VPN is back with one more', async () => {
  const store = { users: [user('usr-a', 'ali', { routing: 'bypass-ir', limits: [L('vpn', 'day', 1)] }), user('usr-b', 'sara')] };
  const h = meter(store, { t: at(2026, 10, 25, 12) });
  const snap = (holds) => ({ active: ['usr-a', 'usr-b'], over: [], byName: { ali: 'usr-a', sara: 'usr-b' }, holds, scope: ['usr-a', 'usr-b'], proxy: true });
  h.m.built(snap({}));
  h.m.tick(vars({ ali: { uplink: 0, downlink: 0 } }));
  h.set(h.t + 1000); h.m.tick(vars({ ali: { uplink: 0, downlink: 2 * GIB } }));
  await flush();
  assert.equal(h.seen.reloads.length, 1);
  assert.deepEqual(h.m.overIds(), [], 'not off: still an account');
  assert.ok(h.seen.logs.includes('Users: “ali” reached their VPN cap (1 GB today) — the VPN is off until tomorrow; direct routes still work'), JSON.stringify(h.seen.logs));
  assert.ok(h.seen.logs.some((l) => /“ali”: the VPN is off until 26 October — direct routes only/.test(l)), JSON.stringify(h.seen.logs));
  for (let i = 0; i < 3; i++) { h.set(h.t + 1000); h.m.tick(vars({ ali: { uplink: 0, downlink: 2 * GIB } })); }
  await flush();
  assert.equal(h.seen.reloads.length, 1, 'once');
  // the reload: built with her VPN held — nothing more to do
  h.m.built(snap({ 'usr-a': h.m.holdOf('usr-a') }));
  h.set(h.t + 1000); h.m.tick(vars({}));
  await flush();
  assert.equal(h.seen.reloads.length, 1);
  h.set(at(2026, 10, 26, 0) + 5000); h.m.tick(vars({}));
  await flush();
  assert.equal(h.seen.reloads.length, 2, 'a new day: the VPN back');
  assert.ok(h.seen.logs.some((l) => /“ali” has the VPN and direct routes again/.test(l)));
});

test('allowed hours: the end of the window is a tick away — ONE reload, said with when they are back; the next window lets them back in', async () => {
  const store = { users: [user('usr-a', 'ali', { schedule: { days: [1], from: '08:00', to: '17:00' } }), user('usr-b', 'sara')] };
  const h = meter(store, { t: at(2026, 10, 26, 16, 59) });
  h.m.built({ active: ['usr-a', 'usr-b'], over: [], byName: { ali: 'usr-a', sara: 'usr-b' }, holds: {}, scope: ['usr-a', 'usr-b'] });
  h.m.tick(vars({}));
  await flush();
  assert.equal(h.seen.reloads.length, 0);
  h.set(at(2026, 10, 26, 17, 0) + 1000); h.m.tick(vars({}));
  await flush();
  assert.equal(h.seen.reloads.length, 1);
  assert.ok(h.seen.logs.includes('Users: “ali” is outside their allowed hours — off until Mon 08:00'), JSON.stringify(h.seen.logs));
  h.m.built({ active: ['usr-b'], over: ['usr-a'], byName: { sara: 'usr-b' }, holds: { 'usr-a': h.m.holdOf('usr-a') }, scope: ['usr-b'] });
  h.set(h.t + 30000); h.m.tick(vars({}));
  await flush();
  assert.equal(h.seen.reloads.length, 1, 'built without her: nothing to do');
  h.set(at(2026, 11, 2, 8, 0) + 1000); h.m.tick(vars({}));
  await flush();
  assert.equal(h.seen.reloads.length, 2);
  assert.ok(h.seen.logs.some((l) => l === 'Users: “ali” is back — inside their allowed hours'));
});

test('topUp: more of one limit for this period only — the hold lifts, the next period has none; resetUsage zeroes the periods and keeps the history', () => {
  const store = { users: [user('usr-a', 'ali', { limits: [L('total', 'day', 1), L('vpn', 'month', 2)] })] };
  const h = meter(store, {
    t: MON,
    usage2: { 'usr-a': u2('2026-10-26', '2026-10', { total: 1.5 * GIB, vpn: 1.5 * GIB }) },
    history: { 'usr-a': [{ day: '2026-10-20', vpn: 5, direct: 6 }, { day: '2026-09-01', vpn: 1, direct: 1 }] }
  });
  assert.equal(h.m.holdOf('usr-a').why, 'total');
  assert.equal(h.m.topUp('usr-a', 'total', 'day', 1), null);
  assert.equal(h.m.holdOf('usr-a').hold, null, 'lifted');
  assert.equal(h.m.topUp('usr-a', 'total', 'day', '0.5'), null, 'another adds to it');
  const row = meterRow(h.m.usage()['usr-a'], 'total', 'day');
  assert.deepEqual([row.capBytes, row.extraBytes, row.pct, row.over], [GIB, 1.5 * GIB, 60, false]);
  assert.ok(h.m.dirty);
  for (const [args, code] of [[['nobody', 'total', 'day', 1], 'notFound'], [['usr-a', 'direct', 'day', 1], 'limit'], [['usr-a', 'total', 'week', 1], 'limit'], [['usr-a', 'total', 'day', 0], 'gb'], [['usr-a', 'total', 'day', 'x'], 'gb'], [['usr-a', 'total', 'day', ''], 'gb'], [['usr-a', 'total', 'day', 2e6], 'gb']]) {
    assert.equal(h.m.topUp(...args), code, JSON.stringify(args));
  }
  assert.deepEqual(h.m.usage()['usr-a'].history, [{ day: '2026-10-20', vpn: 5, direct: 6 }], 'the last 30 days');
  h.set(at(2026, 10, 27, 12));
  assert.equal(meterRow(h.m.usage()['usr-a'], 'total', 'day').extraBytes, 0, 'gone with the day');
  assert.deepEqual(h.m.savedUsage2()['usr-a'].extra, {});
  assert.equal(h.m.resetUsage('usr-a'), null);
  const u = h.m.usage()['usr-a'];
  assert.ok(u.meters.every((r) => r.bytes === 0), JSON.stringify(u.meters));
  assert.deepEqual(u.history, [{ day: '2026-10-20', vpn: 5, direct: 6 }], 'history kept');
  assert.equal(h.m.resetUsage('nobody'), 'notFound');
});

test('warnings: 80 % then 100 % of a limit (and its top-up), each said once per period — with what is left', async () => {
  const store = { users: [user('usr-a', 'ali', { routing: 'bypass-ir', limits: [L('vpn', 'day', 1)] })] };
  const h = meter(store, { t: at(2026, 10, 25, 12) });
  h.m.built({ active: ['usr-a'], over: [], byName: { ali: 'usr-a' } });
  const tick = (bytes) => { h.set(h.t + 1000); h.m.tick(vars({ ali: { uplink: 0, downlink: Math.round(bytes) } })); };
  tick(0); tick(0.85 * GIB); tick(0.9 * GIB);
  assert.deepEqual(h.seen.notes.map((n) => [n.kind, n.period, n.pct, n.capGb, n.leftBytes]), [['vpn', 'day', 80, 1, GIB - Math.round(0.85 * GIB)]], 'once, at 0.85 GB — not again at 0.9');
  assert.ok(h.seen.logs.includes('Users: “ali” has used 80 % of their VPN cap (1 GB today) — 0.15 GB left'), JSON.stringify(h.seen.logs));
  tick(1.1 * GIB); tick(1.2 * GIB);
  assert.deepEqual(h.seen.notes.map((n) => n.pct), [80, 100]);
  assert.equal(h.m.topUp('usr-a', 'vpn', 'day', 1), null);
  tick(1.7 * GIB);
  assert.deepEqual(h.seen.notes.map((n) => [n.pct, n.capGb]), [[80, 1], [100, 1], [80, 2]], 'a new amount: said again');
  await flush();
});

test('the old key is read once into the total kind (a day’s bytes were its month’s too); the new key wins; the old key still written for older apps', () => {
  const store = { users: [user('usr-a', 'ali', { quotaGb: 1, quotaPeriod: 'day' }), user('usr-b', 'sara', { quotaGb: 10, quotaPeriod: 'none' })] };
  const old = { 'usr-a': { period: '2026-10-25', bytes: 5 }, 'usr-b': { period: 'all', bytes: 7 } };
  const h = meter(store, { usage: old });
  const a = h.m.usage()['usr-a'];
  assert.deepEqual([meterRow(a, 'total', 'day').bytes, meterRow(a, 'total', 'month').bytes, a.bytes, a.period], [5, 5, 5, '2026-10-25']);
  const b = h.m.usage()['usr-b'];
  assert.deepEqual([meterRow(b, 'total', 'none').bytes, meterRow(b, 'total', 'none').since, b.bytes, b.period], [7, 0, 7, 'all']);
  assert.deepEqual(h.m.saved(), old, 'the old key: the mirror cap’s total');
  const saved = h.m.savedUsage2();
  assert.deepEqual(normalizeUsage2(saved), saved, 'the new key reads back as written');
  const n = meter(store, { usage: old, usage2: { 'usr-a': { total: { day: { period: '2026-10-25', bytes: 9 } } } } });
  assert.equal(meterRow(n.m.usage()['usr-a'], 'total', 'day').bytes, 9, 'the new key, when there is one');
  assert.equal(meterRow(n.m.usage()['usr-b'], 'total', 'none').bytes, 0);
});

test('speed: the lowest of the base, a speed window on now and a slow limit that is over — never a hold, never a reload', async () => {
  const store = { users: [
    user('usr-a', 'ali', { speed: { down: 8000, up: 2000 }, speedHours: [{ days: [1], from: '18:00', to: '23:00', down: 4000 }], limits: [L('total', 'day', 2, { action: 'slow', down: 1000, up: 500 })] }),
    user('usr-b', 'sara')
  ] };
  const h = meter(store, { t: MON });
  assert.deepEqual(h.m.speedOf('usr-a'), { down: 8000, up: 2000, why: ['base'] });
  h.set(at(2026, 10, 26, 19));
  assert.deepEqual(h.m.speedOf('usr-a'), { down: 4000, up: 2000, why: ['base', 'hours'] });
  assert.equal(h.m.speedOf('usr-b'), null);
  h.m.built({ active: ['usr-a', 'usr-b'], over: [], byName: { ali: 'usr-a', sara: 'usr-b' }, holds: {}, scope: ['usr-a', 'usr-b'] });
  h.m.tick(vars({ ali: { uplink: 0, downlink: 0 } }));
  h.set(h.t + 1000); h.m.tick(vars({ ali: { uplink: 0, downlink: 3 * GIB } }));
  await flush();
  assert.deepEqual(h.m.speedOf('usr-a'), { down: 1000, up: 500, why: ['base', 'hours', 'after:total:day'] });
  assert.deepEqual(h.m.speeds(), { 'usr-a': { down: 1000, up: 500, why: ['base', 'hours', 'after:total:day'] } });
  assert.deepEqual(h.m.usage()['usr-a'].speed, h.m.speedOf('usr-a'));
  assert.deepEqual([h.m.holdOf('usr-a').hold, h.m.overIds(), h.seen.reloads.length], [null, [], 0]);
  assert.ok(h.seen.logs.some((l) => /“ali” used their allowance \(2 GB today\) — slowed to ↓1000 ↑500 kbps until tomorrow/.test(l)), JSON.stringify(h.seen.logs));
  h.set(at(2026, 10, 27, 12));
  assert.deepEqual(h.m.speedOf('usr-a'), { down: 8000, up: 2000, why: ['base'] }, 'a new day: full speed again');
});
