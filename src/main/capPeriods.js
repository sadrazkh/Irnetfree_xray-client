'use strict';
/**
 * The periods a data cap counts in — one set of rules for the internets'
 * caps (multiWanMeter.js) and the users' (src/modules/lanUsers/meter.js), on
 * the desktop and on the router alike.
 *
 * A daily cap counts by the local day. A monthly one by a month that renews
 * on a day of the owner's choosing, in the calendar of his choosing: the
 * Gregorian month (every cap saved before there was a choice) or the Persian
 * one (jalali.js) — an Iranian ISP's package, or what he charges people,
 * follows the Persian month as often as not. A record says it with two fields
 * beside its
 * quotaPeriod:
 *   quotaCalendar  'gregorian' | 'jalali'   (absent: 'gregorian')
 *   quotaResetDay  1 … 31                   (absent: 1)
 * A month that has no such day (31 in a 30-day month, 30 in Esfand of a
 * common year) renews on its last day. A period begins at local midnight of
 * its renew day and ends at the next one's: the day is found by its date, not
 * by adding hours, so a clock change at midnight moves nothing.
 *
 * The key an entry's bytes are kept under (`{ period, bytes }`, local time):
 *   'YYYY-MM-DD'    a day
 *   'YYYY-MM'       a Gregorian month from the 1st — the key every cap had
 *                   before, so an upgrade counts on in the same entry
 *   'YYYY-MM@D'     a Gregorian month renewing on day D (2–31), keyed by the
 *                   month it began in: '2026-10@15' runs 15 Oct – 15 Nov
 *   'jYYYY-MM'      a Persian month from the 1st: 'j1405-08' is Aban 1405
 *   'jYYYY-MM@D'    a Persian month renewing on day D
 * (and the users' 'all', a cap that never renews — meter.js's own).
 */
const { toJalali, toGregorian, jalaliMonthLength } = require('./jalali');

const CALENDARS = ['gregorian', 'jalali'];
const RESET_DAY_MAX = 31;

/** A key as periodKey writes one (see above); 'all' is the users' meter's to add. */
const PERIOD_KEY = /^(?:\d{4}-\d{2}-\d{2}|j?\d{4}-\d{2}(?:@(?:[2-9]|[12]\d|3[01]))?)$/;

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const pad = (n) => String(n).padStart(2, '0');

/** A renew day as a whole number 1–31, else null ('' and junk included). */
function resetDayOf(v) {
  if (typeof v !== 'number' && !(typeof v === 'string' && /^\s*\d+\s*$/.test(v))) return null;
  const n = Number(v);
  return Number.isInteger(n) && n >= 1 && n <= RESET_DAY_MAX ? n : null;
}

/** A record's month — { calendar, day } — the defaults (Gregorian, the 1st) for what it does not say. */
function cycleOf(rec) {
  const r = isObj(rec) ? rec : {};
  return { calendar: r.quotaCalendar === 'jalali' ? 'jalali' : 'gregorian', day: resetDayOf(r.quotaResetDay) || 1 };
}

/**
 * A record's two month fields as they are stored: each only when it is not
 * the default — a cap saved before they existed is the default, and stays
 * written exactly as it was (no field the store never had, no "change" for a
 * settings comparison).
 */
function cycleFields(rec) {
  const c = cycleOf(rec);
  const out = {};
  if (c.calendar !== 'gregorian') out.quotaCalendar = c.calendar;
  if (c.day !== 1) out.quotaResetDay = c.day;
  return out;
}

/* ------------------------------ months ------------------------------ */

/** Month `m` (1–12) of year `y` moved by `n` months: [y, m]. Both calendars have twelve. */
function stepMonth(y, m, n) {
  const i = y * 12 + (m - 1) + n;
  const ny = Math.floor(i / 12);
  return [ny, i - ny * 12 + 1];
}

const monthLength = (c, y, m) => (c.calendar === 'jalali' ? jalaliMonthLength(y, m) : new Date(y, m, 0).getDate());

/** Local midnight of the day a period of `c` begins in month y/m of its calendar — its renew day, or the month's last. */
function startOf(c, y, m) {
  const day = Math.min(c.day, monthLength(c, y, m));
  if (c.calendar !== 'jalali') return new Date(y, m - 1, day).getTime();
  const g = toGregorian(y, m, day);
  return new Date(g.gy, g.gm - 1, g.gd).getTime();
}

/** The monthly period of `c` that `now` falls in: { y, m } — the month of its calendar it began in — and its start and end. */
function monthPeriod(c, now) {
  const d = new Date(now);
  let y = d.getFullYear();
  let m = d.getMonth() + 1;
  let day = d.getDate();
  if (c.calendar === 'jalali') ({ jy: y, jm: m, jd: day } = toJalali(y, m, day));
  // before this month's renew day: still in the period the last month began
  if (day < Math.min(c.day, monthLength(c, y, m))) [y, m] = stepMonth(y, m, -1);
  const [ny, nm] = stepMonth(y, m, 1);
  return { y, m, start: startOf(c, y, m), end: startOf(c, ny, nm) };
}

const monthKey = (c, y, m) => `${c.calendar === 'jalali' ? 'j' : ''}${y}-${pad(m)}${c.day > 1 ? '@' + c.day : ''}`;

/* ------------------------------ periods ------------------------------ */

/**
 * The key a cap's bytes count under at `now`: the day's for a daily cap, the
 * month's — as `rec` (quotaCalendar, quotaResetDay) says — otherwise. A record
 * with neither field gets 'YYYY-MM', the key it always had.
 */
function periodKey(period, now, rec) {
  const d = new Date(now);
  if (period === 'day') return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
  const c = cycleOf(rec);
  const p = monthPeriod(c, now);
  return monthKey(c, p.y, p.m);
}

/** When that period began, ms epoch (local midnight). */
function periodStart(period, now, rec) {
  const d = new Date(now);
  if (period === 'day') return new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime();
  return monthPeriod(cycleOf(rec), now).start;
}

/** When it ends — the next one's start, the day the cap renews: ms epoch (local midnight). */
function periodEnd(period, now, rec) {
  const d = new Date(now);
  if (period === 'day') return new Date(d.getFullYear(), d.getMonth(), d.getDate() + 1).getTime();
  return monthPeriod(cycleOf(rec), now).end;
}

/** A key's span — { start, end, day } in ms, local time — or null: 'all', or anything periodKey never writes. */
function periodRange(key) {
  const s = String(key == null ? '' : key);
  if (!PERIOD_KEY.test(s)) return null;
  const day = /^(\d{4})-(\d{2})-(\d{2})$/.exec(s);
  if (day) {
    const [y, m, dd] = [Number(day[1]), Number(day[2]), Number(day[3])];
    return { start: new Date(y, m - 1, dd).getTime(), end: new Date(y, m - 1, dd + 1).getTime(), day: true };
  }
  const k = /^(j?)(\d{4})-(\d{2})(?:@(\d+))?$/.exec(s);
  const c = { calendar: k[1] ? 'jalali' : 'gregorian', day: k[4] ? Number(k[4]) : 1 };
  const y = Number(k[2]);
  const m = Number(k[3]);
  if (m < 1 || m > 12) return null;
  try {
    const [ny, nm] = stepMonth(y, m, 1);
    return { start: startOf(c, y, m), end: startOf(c, ny, nm), day: false };
  } catch { return null; }   // a Jalali year the calendar has no table for (jalali.js): no span
}

/**
 * An entry moved to the period `key`. The rule, one for every cap:
 *   - the same period: the same entry;
 *   - a cap made one for good ('all', the users'): it keeps what was counted;
 *   - a MONTH (any calendar, any renew day) keeps the bytes of an entry whose
 *     period overlaps it — a day of that month (they were the month's too), or
 *     the running month of a calendar or a renew day just changed: the count
 *     goes on in the new month instead of starting again, so a change (or a
 *     change and back) never hands anyone a fresh cap, and what was counted
 *     before the new month began is at worst counted in it too;
 *   - anything else starts from nothing: a day never takes a month's bytes as
 *     its own, and a period that ended before this one began is over.
 * With the keys every cap had before (a day, 'YYYY-MM'), this is exactly the
 * old rule: a day kept into its month, a new day or month from nothing.
 */
function rollEntry(entry, key) {
  if (!entry) return { period: key, bytes: 0 };
  if (entry.period === key) return entry;
  if (key === 'all') return { period: key, bytes: entry.bytes };
  const next = periodRange(key);
  const was = periodRange(entry.period);
  if (next && was && !next.day && was.start < next.end && next.start < was.end) return { period: key, bytes: entry.bytes };
  return { period: key, bytes: 0 };
}

module.exports = {
  CALENDARS, RESET_DAY_MAX, PERIOD_KEY,
  resetDayOf, cycleOf, cycleFields, periodKey, periodStart, periodEnd, periodRange, rollEntry
};
