'use strict';
/**
 * The periods a data cap counts in (src/main/capPeriods.js), the internets'
 * and the users' alike: a month in the Gregorian or the Persian calendar,
 * renewing on a day 1–31 (a month without that day: its last), from local
 * midnight to local midnight. The keys — an upgrade keeps 'YYYY-MM' and
 * 'YYYY-MM-DD' exactly; the new ones only for the new choices —, their spans,
 * the roll rule between them, the records' two fields as stored (a link's,
 * normalized by multiWan.js), and settingsMeta: a month's calendar or renew day
 * changed while connected asks for no reconnect.
 *
 * Every clock is the test's own, in local time as the periods are; one test
 * runs the same checks in a child process in a zone whose clocks change at
 * midnight (skipped where the OS ignores TZ).
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const P = require('../src/main/capPeriods');
const { normalizeMultiWan } = require('../src/main/multiWan');
const { pendingReconnectKeys, snapshotApplied } = require('../src/main/settingsMeta');

const at = (y, mo, d, h = 12, mi = 0) => new Date(y, mo - 1, d, h, mi, 0).getTime();   // local time
const mid = (y, mo, d) => new Date(y, mo - 1, d).getTime();                             // local midnight
const J = { quotaCalendar: 'jalali' };
const day = (n, more) => Object.assign({ quotaResetDay: n }, more || {});

/* ------------------------------ upgrade: the keys every cap had ------------------------------ */

test('a record without the two fields keeps exactly the keys and spans it had: YYYY-MM from the 1st, YYYY-MM-DD', () => {
  const t = at(2026, 10, 25, 23);
  for (const rec of [undefined, null, {}, { quotaPeriod: 'month', quotaGb: 5 }, { quotaCalendar: 'gregorian', quotaResetDay: 1 }]) {
    assert.equal(P.periodKey('month', t, rec), '2026-10', JSON.stringify(rec));
    assert.equal(P.periodStart('month', t, rec), mid(2026, 10, 1));
    assert.equal(P.periodEnd('month', t, rec), mid(2026, 11, 1));
  }
  assert.equal(P.periodKey('month', t), '2026-10', 'the old two-argument call');
  assert.equal(P.periodKey('day', t, J), '2026-10-25', 'a day is a day in either calendar');
  assert.equal(P.periodStart('day', t, day(15)), mid(2026, 10, 25));
  assert.equal(P.periodEnd('day', t, day(15)), mid(2026, 10, 26));
  assert.equal(P.periodEnd('month', at(2026, 12, 31)), mid(2027, 1, 1), 'December rolls into the next year');
});

/* ------------------------------ the Gregorian month, another renew day ------------------------------ */

test('a Gregorian month renewing on the 15th: keyed by the month it began in, 15th to 15th', () => {
  assert.equal(P.periodKey('month', at(2026, 10, 26), day(15)), '2026-10@15');
  assert.equal(P.periodStart('month', at(2026, 10, 26), day(15)), mid(2026, 10, 15));
  assert.equal(P.periodEnd('month', at(2026, 10, 26), day(15)), mid(2026, 11, 15));
  assert.equal(P.periodKey('month', at(2026, 10, 14, 23, 59), day(15)), '2026-09@15', 'the day before: still last month’s');
  assert.equal(P.periodKey('month', at(2026, 10, 15, 0, 0), day(15)), '2026-10@15', 'at midnight of the 15th: the new one');
  assert.equal(P.periodKey('month', at(2027, 1, 10), day(15)), '2026-12@15', 'across the new year');
  assert.equal(P.periodEnd('month', at(2026, 12, 20), day(15)), mid(2027, 1, 15));
});

test('renew day 31 (or 29, 30) in a shorter month is that month’s last day — February 28, 29 in a leap year', () => {
  // September has 30 days: the period began on the 30th and runs to 31 October
  assert.equal(P.periodKey('month', at(2026, 10, 26), day(31)), '2026-09@31');
  assert.equal(P.periodStart('month', at(2026, 10, 26), day(31)), mid(2026, 9, 30));
  assert.equal(P.periodEnd('month', at(2026, 10, 26), day(31)), mid(2026, 10, 31));
  assert.equal(P.periodKey('month', at(2026, 10, 31), day(31)), '2026-10@31');
  assert.equal(P.periodEnd('month', at(2026, 10, 31), day(31)), mid(2026, 11, 30), 'November has 30');
  assert.equal(P.periodEnd('month', at(2027, 1, 31), day(31)), mid(2027, 2, 28), 'February 2027 has 28');
  assert.equal(P.periodEnd('month', at(2028, 1, 31), day(31)), mid(2028, 2, 29), 'February 2028 has 29');
  assert.equal(P.periodEnd('month', at(2027, 2, 28), day(30)), mid(2027, 3, 30), 'from February’s last back to the 30th');
  assert.equal(P.periodKey('month', at(2027, 2, 28), day(29)), '2027-02@29', 'the 29th in a 28-day February: the 28th');
  assert.equal(P.periodKey('month', at(2027, 2, 27), day(29)), '2027-01@29');
});

/* ------------------------------ the Persian month ------------------------------ */

test('a Persian month from the 1st: 1 Aban 1405 (23 Oct 2026) to 1 Azar (22 Nov), keyed j1405-08', () => {
  const t = at(2026, 10, 26);
  assert.equal(P.periodKey('month', t, J), 'j1405-08');
  assert.equal(P.periodStart('month', t, J), mid(2026, 10, 23));
  assert.equal(P.periodEnd('month', t, J), mid(2026, 11, 22));
  assert.equal(P.periodKey('month', at(2026, 10, 22, 23, 59), J), 'j1405-07', '30 Mehr');
  assert.equal(P.periodKey('month', at(2026, 10, 23, 0, 0), J), 'j1405-08');
  // Nowruz: 1403 was a leap year — 30 Esfand 1403 = 20 March 2025, 1 Farvardin 1404 = 21 March 2025
  assert.equal(P.periodKey('month', at(2025, 3, 20, 23), J), 'j1403-12');
  assert.equal(P.periodKey('month', at(2025, 3, 21, 0), J), 'j1404-01');
  assert.equal(P.periodStart('month', at(2025, 3, 5), J), mid(2025, 2, 19), '1 Esfand 1403');
  assert.equal(P.periodEnd('month', at(2025, 3, 5), J), mid(2025, 3, 21));
});

test('a Persian month renewing on the 15th, and on the 31st: Mehr has 30, Esfand 29 — or 30 in a leap year', () => {
  assert.equal(P.periodKey('month', at(2026, 10, 26), day(15, J)), 'j1405-07@15', '4 Aban: still the period from 15 Mehr');
  assert.equal(P.periodStart('month', at(2026, 10, 26), day(15, J)), mid(2026, 10, 7), '15 Mehr 1405');
  assert.equal(P.periodEnd('month', at(2026, 10, 26), day(15, J)), mid(2026, 11, 6), '15 Aban 1405');
  // 31: Mehr's last day is its 30th (22 Oct 2026), Aban's its 30th (21 Nov)
  assert.equal(P.periodKey('month', at(2026, 10, 26), day(31, J)), 'j1405-07@31');
  assert.equal(P.periodStart('month', at(2026, 10, 26), day(31, J)), mid(2026, 10, 22));
  assert.equal(P.periodEnd('month', at(2026, 10, 26), day(31, J)), mid(2026, 11, 21));
  // Esfand: 30 days in 1403 (its 30th 20 March 2025), 29 in 1404 (its 29th 20 March 2026)
  assert.equal(P.periodStart('month', at(2025, 4, 1), day(30, J)), mid(2025, 3, 20), '30 Esfand 1403');
  assert.equal(P.periodStart('month', at(2026, 4, 1), day(30, J)), mid(2026, 3, 20), '29 Esfand 1404: no 30th');
  assert.equal(P.periodKey('month', at(2026, 4, 1), day(30, J)), 'j1404-12@30');
  assert.equal(P.periodEnd('month', at(2026, 4, 1), day(30, J)), mid(2026, 4, 19), '30 Farvardin 1405');
  // 31 in Farvardin (31 days) is the 31st: 31 Farvardin 1405 = 20 April 2026
  assert.equal(P.periodEnd('month', at(2026, 3, 25), day(31, J)), mid(2026, 4, 20));
});

/* ------------------------------ every period, end to end ------------------------------ */

/**
 * For every day from `from` (three times a day): the period holds the moment,
 * starts at the first instant of a local day, and the next period starts
 * exactly where this one ends; a month is 28–31 days (an hour either way for a
 * clock change), and its key names it.
 */
function tiles(rec, from, days) {
  const firstOfDay = (ms) => { const d = new Date(ms); return new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime() === ms; };
  let last = null;
  for (let i = 0; i < days * 3; i++) {
    const t = from + i * 8 * 3600000;
    const s = P.periodStart('month', t, rec);
    const e = P.periodEnd('month', t, rec);
    const k = P.periodKey('month', t, rec);
    assert.ok(s <= t && t < e, `${new Date(t)}: ${new Date(s)} – ${new Date(e)}`);
    assert.ok(firstOfDay(s) && firstOfDay(e), `${k}: local midnight`);
    const len = (e - s) / 86400000;
    assert.ok(len > 27.9 && len < 31.1, `${k}: ${len} days`);
    assert.deepEqual(P.periodRange(k), { start: s, end: e, day: false }, `${k} spans its own period`);
    if (last && last.k !== k) assert.equal(s, last.e, `${last.k} → ${k}: no gap, no overlap`);
    last = { k, e };
  }
}

test('every cycle tiles time: each period starts at local midnight where the last one ended (2020 – 2027)', () => {
  const from = mid(2020, 1, 1);
  for (const rec of [null, day(15), day(29), day(31), J, day(15, J), day(30, J), day(31, J)]) tiles(rec, from, 365 * 7 + 2);
});

test('a zone whose clocks change at midnight (America/Santiago; Asia/Tehran until 2022): the same periods, in a child process', (t) => {
  const code = `
    const assert = require('node:assert/strict');
    const zone = Intl.DateTimeFormat().resolvedOptions().timeZone;
    if (zone !== process.env.TZ) { console.log('SKIP ' + zone); process.exit(0); }
    const P = require(${JSON.stringify(path.join(__dirname, '..', 'src', 'main', 'capPeriods.js'))});
    // the 1st of a month whose midnight does not exist: September 2024 in Chile began its summer time at 00:00 on the 8th
    const s = P.periodStart('month', new Date(2024, 8, 20).getTime(), { quotaResetDay: 8 });
    assert.equal(s, new Date(2024, 8, 8).getTime(), 'the first instant of the 8th');
    assert.equal(new Date(s).getDate(), 8);
    for (const rec of [null, { quotaResetDay: 8 }, { quotaCalendar: 'jalali' }, { quotaCalendar: 'jalali', quotaResetDay: 18 }]) {
      let lastEnd = null, lastKey = null;
      for (let t = new Date(2021, 0, 1).getTime(); t < new Date(2025, 0, 1).getTime(); t += 6 * 3600000) {
        const a = P.periodStart('month', t, rec), b = P.periodEnd('month', t, rec), k = P.periodKey('month', t, rec);
        assert.ok(a <= t && t < b, k);
        if (lastKey && lastKey !== k) assert.equal(a, lastEnd, k);
        lastEnd = b; lastKey = k;
      }
    }
    // daily periods across the change: 7 Sept 2024 ends where 8 Sept begins
    assert.equal(P.periodEnd('day', new Date(2024, 8, 7, 12).getTime()), P.periodStart('day', new Date(2024, 8, 8, 12).getTime()));
    console.log('OK ' + zone);`;
  let ran = 0;
  for (const tz of ['America/Santiago', 'Asia/Tehran']) {
    const out = execFileSync(process.execPath, ['-e', code], { env: Object.assign({}, process.env, { TZ: tz }), encoding: 'utf8' }).trim();
    if (out.startsWith('OK')) ran++;
    else assert.match(out, /^SKIP/, out);
  }
  if (!ran) t.skip('this OS ignores TZ for a child process');
});

/* ------------------------------ keys and spans ------------------------------ */

test('the keys a saved entry may carry: a day, a month, j for the Persian one, @2–31 for its renew day — nothing else', () => {
  for (const ok of ['2026-10-25', '2026-10', '2026-10@15', '2026-10@31', 'j1405-08', 'j1405-08@2', 'j1405-12@30']) assert.ok(P.PERIOD_KEY.test(ok), ok);
  for (const bad of ['all', '2026-10@1', '2026-10@0', '2026-10@32', 'j1405-08-04', 'j1405', 'October', '2026-1', ' 2026-10', 'x2026-10', '']) assert.ok(!P.PERIOD_KEY.test(bad), bad);
});

test('a key’s span: a day, a month in either calendar from its renew day; null for all, junk and a year past the table', () => {
  assert.deepEqual(P.periodRange('2026-10-25'), { start: mid(2026, 10, 25), end: mid(2026, 10, 26), day: true });
  assert.deepEqual(P.periodRange('2026-10'), { start: mid(2026, 10, 1), end: mid(2026, 11, 1), day: false });
  assert.deepEqual(P.periodRange('2026-09@31'), { start: mid(2026, 9, 30), end: mid(2026, 10, 31), day: false });
  assert.deepEqual(P.periodRange('j1405-08'), { start: mid(2026, 10, 23), end: mid(2026, 11, 22), day: false });
  assert.deepEqual(P.periodRange('j1404-12@30'), { start: mid(2026, 3, 20), end: mid(2026, 4, 19), day: false });
  for (const none of ['all', 'junk', '2026-13', 'j1405-00', 'j9999-01', null, undefined]) assert.equal(P.periodRange(none), null, String(none));
});

/* ------------------------------ the roll rule ------------------------------ */

test('roll: with the old keys, the old rule exactly — a day into its month, a new day or month from nothing', () => {
  const e = { period: '2026-10-25', bytes: 500 };
  assert.equal(P.rollEntry(e, '2026-10-25'), e, 'the same period: the same entry');
  assert.deepEqual(P.rollEntry(e, '2026-10'), { period: '2026-10', bytes: 500 });
  assert.deepEqual(P.rollEntry({ period: '2026-10', bytes: 900 }, '2026-10-25'), { period: '2026-10-25', bytes: 0 }, 'a month says nothing of today');
  assert.deepEqual(P.rollEntry({ period: '2026-09-30', bytes: 900 }, '2026-10'), { period: '2026-10', bytes: 0 });
  assert.deepEqual(P.rollEntry({ period: '2026-10', bytes: 900 }, '2026-11'), { period: '2026-11', bytes: 0 });
  assert.deepEqual(P.rollEntry({ period: '2026-10', bytes: 900 }, 'all'), { period: 'all', bytes: 900 }, 'a cap made one for good keeps its count');
  assert.deepEqual(P.rollEntry({ period: 'all', bytes: 900 }, '2026-10'), { period: '2026-10', bytes: 0 }, 'one that renews again starts fresh');
  assert.deepEqual(P.rollEntry(null, '2026-10'), { period: '2026-10', bytes: 0 });
});

test('roll: a day into the month it falls in, whichever calendar and renew day; a day outside it starts from nothing', () => {
  assert.deepEqual(P.rollEntry({ period: '2026-10-25', bytes: 5 }, '2026-10@15'), { period: '2026-10@15', bytes: 5 });
  assert.deepEqual(P.rollEntry({ period: '2026-10-10', bytes: 5 }, '2026-10@15'), { period: '2026-10@15', bytes: 0 }, '10 Oct was the period before');
  assert.deepEqual(P.rollEntry({ period: '2026-10-25', bytes: 5 }, 'j1405-08'), { period: 'j1405-08', bytes: 5 }, '3 Aban');
  assert.deepEqual(P.rollEntry({ period: '2026-10-22', bytes: 5 }, 'j1405-08'), { period: 'j1405-08', bytes: 0 }, '30 Mehr is Mehr’s');
  assert.deepEqual(P.rollEntry({ period: 'j1405-08', bytes: 5 }, '2026-10-26'), { period: '2026-10-26', bytes: 0 }, 'a month into a day: nothing');
});

test('roll: the calendar or the renew day changed — the running month’s count goes on in the new one, and back again', () => {
  const oct = { period: '2026-10', bytes: 12 };
  const aban = P.rollEntry(oct, 'j1405-08');
  assert.deepEqual(aban, { period: 'j1405-08', bytes: 12 }, 'Gregorian → Persian on 26 Oct: Oct overlaps Aban');
  assert.deepEqual(P.rollEntry(aban, '2026-10'), { period: '2026-10', bytes: 12 }, 'and back: nothing lost, nothing handed out');
  assert.deepEqual(P.rollEntry(oct, '2026-10@15'), { period: '2026-10@15', bytes: 12 }, 'the 1st → the 15th');
  assert.deepEqual(P.rollEntry({ period: 'j1405-07@15', bytes: 7 }, 'j1405-08'), { period: 'j1405-08', bytes: 7 }, '15 Mehr–15 Aban overlaps Aban');
  // a period over before the new one began is over
  assert.deepEqual(P.rollEntry({ period: '2026-09', bytes: 12 }, 'j1405-08'), { period: 'j1405-08', bytes: 0 });
  assert.deepEqual(P.rollEntry({ period: 'j1405-08', bytes: 12 }, 'j1405-09'), { period: 'j1405-09', bytes: 0 }, 'Aban → Azar: a new month');
  assert.deepEqual(P.rollEntry({ period: '2026-10@15', bytes: 12 }, '2026-11@15'), { period: '2026-11@15', bytes: 0 });
  assert.deepEqual(P.rollEntry({ period: 'junk', bytes: 12 }, 'j1405-08'), { period: 'j1405-08', bytes: 0 });
});

/* ------------------------------ the records' fields ------------------------------ */

test('a record’s month: Gregorian from the 1st unless it says otherwise; stored only when it does', () => {
  assert.deepEqual(P.cycleOf(null), { calendar: 'gregorian', day: 1 });
  assert.deepEqual(P.cycleOf({ quotaCalendar: 'jalali', quotaResetDay: '15' }), { calendar: 'jalali', day: 15 });
  for (const junk of [0, 32, 1.5, -3, 'x', '', null, true]) assert.equal(P.cycleOf({ quotaResetDay: junk }).day, 1, JSON.stringify(junk));
  assert.equal(P.cycleOf({ quotaCalendar: 'julian' }).calendar, 'gregorian');
  assert.deepEqual(P.cycleFields({ quotaCalendar: 'gregorian', quotaResetDay: 1 }), {}, 'the defaults are not written');
  assert.deepEqual(P.cycleFields({}), {});
  assert.deepEqual(P.cycleFields({ quotaCalendar: 'jalali', quotaResetDay: 31 }), { quotaCalendar: 'jalali', quotaResetDay: 31 });
  assert.deepEqual(P.cycleFields({ quotaResetDay: 9 }), { quotaResetDay: 9 });
  assert.equal(P.resetDayOf(' 12 '), 12);
  assert.equal(P.resetDayOf('12a'), null);
});

test('a link as saved (multiWan.js): the calendar and renew day it names, nothing for the Gregorian 1st — a link saved before is unchanged', () => {
  const n = normalizeMultiWan({ links: [
    { id: 'wan', iface: 'eth1', quotaGb: 50, quotaPeriod: 'month', quotaCalendar: 'jalali', quotaResetDay: 15 },
    { id: 'lte', iface: 'wwan0', quotaGb: 5, quotaPeriod: 'month', quotaCalendar: 'gregorian', quotaResetDay: 1 },
    { id: 'usb', iface: 'usb0', quotaCalendar: 'lunar', quotaResetDay: 40 }
  ] });
  assert.deepEqual(n.links[0], { id: 'wan', iface: 'eth1', name: 'eth1', role: 'use', weight: 2, quotaGb: 50, quotaPeriod: 'month', quotaCalendar: 'jalali', quotaResetDay: 15 });
  assert.deepEqual(n.links[1], { id: 'lte', iface: 'wwan0', name: 'wwan0', role: 'use', weight: 2, quotaGb: 5, quotaPeriod: 'month' });
  assert.deepEqual(n.links[2], { id: 'usb', iface: 'usb0', name: 'usb0', role: 'use', weight: 2, quotaGb: 0, quotaPeriod: 'none' });
});

test('settingsMeta: a month’s calendar or renew day changed while connected asks for no reconnect (the quota reads it live)', () => {
  const mw = (link) => ({ enabled: true, mode: 'balance', links: [{ id: 'wan', iface: 'eth1', name: 'Cable', quotaGb: 50, quotaPeriod: 'month' }, Object.assign({ id: 'lte', iface: 'wwan0', name: 'LTE' }, link)] });
  const applied = snapshotApplied({ multiWan: mw({}) });
  assert.deepEqual(pendingReconnectKeys(applied, { multiWan: mw({ quotaGb: 9, quotaPeriod: 'month', quotaCalendar: 'jalali', quotaResetDay: 20 }) }), []);
  assert.deepEqual(pendingReconnectKeys(applied, { multiWan: mw({ quotaResetDay: 3, role: 'backup' }) }), ['multiWan'], 'anything else still does');
});
