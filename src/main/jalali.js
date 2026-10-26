'use strict';
/**
 * The Persian calendar («تقویم شمسی», Jalali / Solar Hijri) — for the data caps
 * that renew with the Persian month (capPeriods.js) and the words that say
 * when they do.
 *
 * Pure arithmetic, no Intl: the router's Node may be built with small ICU
 * (English only), where `fa-IR` formats a Gregorian date, so the service never
 * asks Intl for a Persian date. The window formats its own (a browser's ICU
 * has the Persian calendar); tests/jalali.test.js holds the two to the same
 * days.
 *
 * The algorithm is the standard one — Borkowski's, as jalaali-js has it
 * (jalCal / j2d / d2j over the Julian Day Number): a year is leap by where its
 * Nowruz falls against the March equinox, through the break years of BREAKS,
 * for Jalali years -61 … 3177. Months 1–6 have 31 days, 7–11 have 30, Esfand
 * 29 — 30 in a leap year (1403 was one, its last day 2025-03-20).
 */

/** The years the 33-year cycle breaks at (jalaali-js `breaks`). */
const BREAKS = [-61, 9, 38, 199, 426, 686, 756, 818, 1111, 1181, 1210, 1635, 2060, 2097, 2192, 2262, 2324, 2394, 2456, 3178];

const MONTHS_FA = ['فروردین', 'اردیبهشت', 'خرداد', 'تیر', 'مرداد', 'شهریور', 'مهر', 'آبان', 'آذر', 'دی', 'بهمن', 'اسفند'];
const MONTHS_EN = ['Farvardin', 'Ordibehesht', 'Khordad', 'Tir', 'Mordad', 'Shahrivar', 'Mehr', 'Aban', 'Azar', 'Dey', 'Bahman', 'Esfand'];
const GREGORIAN_EN = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];

// the algorithm's own integer division and remainder: both truncate toward zero
const div = (a, b) => ~~(a / b);
const mod = (a, b) => a - ~~(a / b) * b;

/**
 * Jalali year `jy` → { leap, gy, march }: `leap` 0 for a leap year (years since
 * the last one otherwise), `gy` the Gregorian year it begins in, `march` the
 * day of March its 1 Farvardin falls on. `withoutLeap` skips the leap count.
 */
function jalCal(jy, withoutLeap) {
  const gy = jy + 621;
  let leapJ = -14;
  let jp = BREAKS[0];
  let jump = 0;
  if (!Number.isInteger(jy) || jy < jp || jy >= BREAKS[BREAKS.length - 1]) throw new RangeError('Jalali year out of range: ' + jy);
  // the leap years up to the break before jy
  for (let i = 1; i < BREAKS.length; i += 1) {
    const jm = BREAKS[i];
    jump = jm - jp;
    if (jy < jm) break;
    leapJ = leapJ + div(jump, 33) * 8 + div(mod(jump, 33), 4);
    jp = jm;
  }
  let n = jy - jp;
  // …and from that break to jy itself
  leapJ = leapJ + div(n, 33) * 8 + div(mod(n, 33) + 3, 4);
  if (mod(jump, 33) === 4 && jump - n === 4) leapJ += 1;
  // the Gregorian leap days until gy, and so the day of March Nowruz falls on
  const leapG = div(gy, 4) - div((div(gy, 100) + 1) * 3, 4) - 150;
  const march = 20 + leapJ - leapG;
  if (withoutLeap) return { gy, march };
  if (jump - n < 6) n = n - jump + div(jump + 4, 33) * 33;
  let leap = mod(mod(n + 1, 33) - 1, 4);
  if (leap === -1) leap = 4;
  return { leap, gy, march };
}

/** A Gregorian date → its Julian Day Number. */
function g2d(gy, gm, gd) {
  const d = div((gy + div(gm - 8, 6) + 100100) * 1461, 4) + div(153 * mod(gm + 9, 12) + 2, 5) + gd - 34840408;
  return d - div(div(gy + 100100 + div(gm - 8, 6), 100) * 3, 4) + 752;
}

/** A Julian Day Number → its Gregorian date { gy, gm, gd }. */
function d2g(jdn) {
  let j = 4 * jdn + 139361631;
  j = j + div(div(4 * jdn + 183187720, 146097) * 3, 4) * 4 - 3908;
  const i = div(mod(j, 1461), 4) * 5 + 308;
  const gd = div(mod(i, 153), 5) + 1;
  const gm = mod(div(i, 153), 12) + 1;
  const gy = div(j, 1461) - 100100 + div(8 - gm, 6);
  return { gy, gm, gd };
}

/** A Jalali date → its Julian Day Number. */
function j2d(jy, jm, jd) {
  const r = jalCal(jy, true);
  return g2d(r.gy, 3, r.march) + (jm - 1) * 31 - div(jm, 7) * (jm - 7) + jd - 1;
}

/** A Julian Day Number → its Jalali date { jy, jm, jd }. */
function d2j(jdn) {
  const gy = d2g(jdn).gy;
  let jy = gy - 621;
  const r = jalCal(jy, false);
  // the days since 1 Farvardin of the year that began in gy
  let k = jdn - g2d(gy, 3, r.march);
  if (k >= 0) {
    if (k <= 185) return { jy, jm: 1 + div(k, 31), jd: mod(k, 31) + 1 };   // the six months of 31 days
    k -= 186;
  } else {
    // before this year's Nowruz: the end of the last one
    jy -= 1;
    k += 179;
    if (r.leap === 1) k += 1;
  }
  return { jy, jm: 7 + div(k, 30), jd: mod(k, 30) + 1 };
}

/** A Gregorian date (month 1–12) → the Jalali one: { jy, jm, jd }. */
function toJalali(gy, gm, gd) { return d2j(g2d(gy, gm, gd)); }

/** A Jalali date (month 1–12) → the Gregorian one: { gy, gm, gd }. */
function toGregorian(jy, jm, jd) { return d2g(j2d(jy, jm, jd)); }

/** Esfand has 30 days this year. */
function isLeapJalaliYear(jy) { return jalCal(jy, false).leap === 0; }

/** The days in Jalali month `jm` (1–12) of year `jy`. */
function jalaliMonthLength(jy, jm) {
  if (jm <= 6) return 31;
  if (jm <= 11) return 30;
  return isLeapJalaliYear(jy) ? 30 : 29;
}

/** The local day of `ms` in the Persian calendar: { jy, jm, jd }. */
function jalaliOf(ms) {
  const d = new Date(ms);
  return toJalali(d.getFullYear(), d.getMonth() + 1, d.getDate());
}

/**
 * The local day of `ms` in words, the year left out (the day a cap renews is
 * at most a month away): '22 November' in English — '22 November (1 Azar)'
 * for a cap that follows the Persian month, so the date it was set by is there
 * too — and '1 آذر' in Persian, always the Persian calendar, as the rest of the
 * Persian window writes a date (Latin digits, as every number in it). '' for
 * no date.
 */
function dayText(ms, lang, calendar) {
  const d = new Date(Number(ms));
  if (!(Number(ms) > 0) || !Number.isFinite(d.getTime())) return '';
  const j = toJalali(d.getFullYear(), d.getMonth() + 1, d.getDate());
  if (lang === 'fa') return `${j.jd} ${MONTHS_FA[j.jm - 1]}`;
  const g = `${d.getDate()} ${GREGORIAN_EN[d.getMonth()]}`;
  return calendar === 'jalali' ? `${g} (${j.jd} ${MONTHS_EN[j.jm - 1]})` : g;
}

module.exports = {
  MONTHS_FA, MONTHS_EN, GREGORIAN_EN,
  toJalali, toGregorian, isLeapJalaliYear, jalaliMonthLength, jalaliOf, dayText,
  // the algorithm's own steps, for the tests
  jalCal, j2d, d2j, g2d, d2g
};
