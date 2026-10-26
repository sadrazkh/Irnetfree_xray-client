'use strict';
/**
 * The Persian calendar (src/main/jalali.js): the anchors everyone knows (the
 * Nowruz of 1402, 1403, 1404; 1403 a leap year, its Esfand 30 days), the month
 * lengths, a round trip over thousands of days both ways, the same days as the
 * window's Intl Persian calendar (the page formats what the service computes),
 * and the words a notice and a log line say a date in.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const J = require('../src/main/jalali');

const DAY = 86400000;

test('the anchors: 1 Farvardin 1402 / 1403 / 1404 = 2023-03-21 / 2024-03-20 / 2025-03-21, and back', () => {
  for (const [jy, g] of [[1402, [2023, 3, 21]], [1403, [2024, 3, 20]], [1404, [2025, 3, 21]], [1405, [2026, 3, 21]], [1400, [2021, 3, 21]]]) {
    assert.deepEqual(J.toGregorian(jy, 1, 1), { gy: g[0], gm: g[1], gd: g[2] }, `Nowruz ${jy}`);
    assert.deepEqual(J.toJalali(...g), { jy, jm: 1, jd: 1 });
  }
  assert.deepEqual(J.toJalali(2026, 10, 26), { jy: 1405, jm: 8, jd: 4 }, '4 Aban 1405');
  assert.deepEqual(J.toJalali(2026, 11, 22), { jy: 1405, jm: 9, jd: 1 }, '1 Azar 1405');
  assert.deepEqual(J.toJalali(1979, 2, 11), { jy: 1357, jm: 11, jd: 22 }, '22 Bahman 1357');
});

test('leap years: 1403 is one (Esfand 30 = 2025-03-20), 1402 and 1404 are not; 1399 and 1408 are', () => {
  assert.equal(J.isLeapJalaliYear(1403), true);
  assert.equal(J.jalaliMonthLength(1403, 12), 30);
  assert.deepEqual(J.toGregorian(1403, 12, 30), { gy: 2025, gm: 3, gd: 20 });
  assert.deepEqual(J.toJalali(2025, 3, 20), { jy: 1403, jm: 12, jd: 30 });
  for (const y of [1402, 1404, 1405, 1406, 1407]) {
    assert.equal(J.isLeapJalaliYear(y), false, String(y));
    assert.equal(J.jalaliMonthLength(y, 12), 29, String(y));
  }
  for (const y of [1395, 1399, 1408, 1412]) assert.equal(J.isLeapJalaliYear(y), true, String(y));
  // the day after 29 Esfand of a common year is Nowruz
  const g = J.toGregorian(1404, 12, 29);
  const next = new Date(Date.UTC(g.gy, g.gm - 1, g.gd) + DAY);
  assert.deepEqual(J.toJalali(next.getUTCFullYear(), next.getUTCMonth() + 1, next.getUTCDate()), { jy: 1405, jm: 1, jd: 1 });
});

test('month lengths: six of 31, five of 30, Esfand 29 or 30 — a year is 365 or 366 days', () => {
  for (let m = 1; m <= 6; m++) assert.equal(J.jalaliMonthLength(1405, m), 31);
  for (let m = 7; m <= 11; m++) assert.equal(J.jalaliMonthLength(1405, m), 30);
  for (let jy = 1380; jy <= 1430; jy++) {
    const len = J.j2d(jy + 1, 1, 1) - J.j2d(jy, 1, 1);
    assert.equal(len, J.isLeapJalaliYear(jy) ? 366 : 365, String(jy));
    let sum = 0;
    for (let m = 1; m <= 12; m++) sum += J.jalaliMonthLength(jy, m);
    assert.equal(sum, len, `${jy}: the months add up to the year`);
  }
});

test('round trips over 20 000 days (1970 – 2024): Gregorian → Jalali → Gregorian, each day one more than the last', () => {
  let prev = null;
  for (let i = 0; i < 20000; i++) {
    const d = new Date(Date.UTC(1970, 0, 1) + i * DAY);
    const g = { gy: d.getUTCFullYear(), gm: d.getUTCMonth() + 1, gd: d.getUTCDate() };
    const j = J.toJalali(g.gy, g.gm, g.gd);
    assert.deepEqual(J.toGregorian(j.jy, j.jm, j.jd), g, JSON.stringify(g));
    assert.ok(j.jm >= 1 && j.jm <= 12 && j.jd >= 1 && j.jd <= J.jalaliMonthLength(j.jy, j.jm), JSON.stringify(j));
    if (prev) {
      // the next day: the next day of the month, or the 1st of the next month (or year)
      const sameMonth = j.jy === prev.jy && j.jm === prev.jm && j.jd === prev.jd + 1;
      const nextMonth = j.jd === 1 && prev.jd === J.jalaliMonthLength(prev.jy, prev.jm) && (j.jy * 12 + j.jm) === (prev.jy * 12 + prev.jm + 1);
      assert.ok(sameMonth || nextMonth, `${JSON.stringify(prev)} → ${JSON.stringify(j)}`);
    }
    prev = j;
  }
});

test('round trips the other way: every Jalali day 1380 – 1430 → Gregorian → back; the Julian Day Number agrees', () => {
  let n = 0;
  for (let jy = 1380; jy <= 1430; jy++) {
    for (let jm = 1; jm <= 12; jm++) {
      for (let jd = 1; jd <= J.jalaliMonthLength(jy, jm); jd++) {
        const g = J.toGregorian(jy, jm, jd);
        assert.deepEqual(J.toJalali(g.gy, g.gm, g.gd), { jy, jm, jd });
        assert.equal(J.g2d(g.gy, g.gm, g.gd), J.j2d(jy, jm, jd));
        n++;
      }
    }
  }
  assert.ok(n > 18000, `${n} days`);
});

test('the same days as Intl’s Persian calendar (what the window formats) for every day 1990 – 2080', (t) => {
  let f;
  try { f = new Intl.DateTimeFormat('en-u-ca-persian-nu-latn', { year: 'numeric', month: 'numeric', day: 'numeric', timeZone: 'UTC' }); } catch { f = null; }
  if (!f || f.resolvedOptions().calendar !== 'persian') { t.skip('this Node has no Persian calendar in Intl'); return; }
  const bad = [];
  for (let ms = Date.UTC(1990, 0, 1); ms < Date.UTC(2080, 0, 1); ms += DAY) {
    const d = new Date(ms);
    const p = Object.fromEntries(f.formatToParts(d).map((x) => [x.type, x.value]));
    const j = J.toJalali(d.getUTCFullYear(), d.getUTCMonth() + 1, d.getUTCDate());
    if (Number(p.year) !== j.jy || Number(p.month) !== j.jm || Number(p.day) !== j.jd) bad.push(d.toISOString().slice(0, 10));
  }
  assert.deepEqual(bad.slice(0, 10), [], `${bad.length} days differ`);
});

test('outside the table (Jalali years -61 … 3177) is a RangeError, never a wrong date', () => {
  assert.throws(() => J.toGregorian(3178, 1, 1), RangeError);
  assert.throws(() => J.toGregorian(-62, 1, 1), RangeError);
  assert.throws(() => J.isLeapJalaliYear(1403.5), RangeError);
});

test('a date in words: Persian always the Persian calendar; English the Gregorian date, the Persian one beside it for a Persian-month cap', () => {
  const nov22 = new Date(2026, 10, 22).getTime();
  assert.equal(J.dayText(nov22, 'fa'), '1 آذر');
  assert.equal(J.dayText(nov22, 'fa', 'gregorian'), '1 آذر', 'the Persian window writes every date in its calendar');
  assert.equal(J.dayText(nov22, 'en'), '22 November');
  assert.equal(J.dayText(nov22, 'en', 'jalali'), '22 November (1 Azar)');
  assert.equal(J.dayText(new Date(2025, 2, 20, 23, 59).getTime(), 'fa'), '30 اسفند', 'the local day, late at night too');
  assert.equal(J.dayText(new Date(2026, 10, 1).getTime(), 'fa'), '10 آبان');
  assert.equal(J.dayText(0, 'en'), '');
  assert.equal(J.dayText(NaN, 'fa'), '');
  assert.deepEqual(J.jalaliOf(new Date(2026, 9, 26, 23, 30).getTime()), { jy: 1405, jm: 8, jd: 4 });
  assert.equal(J.MONTHS_FA.length, 12);
  assert.equal(J.MONTHS_EN[7], 'Aban');
});
