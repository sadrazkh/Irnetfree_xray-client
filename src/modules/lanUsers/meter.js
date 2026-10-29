'use strict';
/**
 * Users and devices (module `lanUsers`): what each user carried — through a
 * config (VPN) and directly — today, this month and since a one-off limit was
 * set; their limits, what holds them off, their speed, and how fast they are
 * moving right now. Modelled on the multi-internet quota
 * (src/main/multiWanMeter.js), whose periods it shares.
 *
 * Fed from the stats poller's tick — the same /debug/vars read the live meter
 * and the usage totals come from — by the core's own counters:
 *  - everything a proxy account carried: `stats.user[<username>] = { uplink,
 *    downlink }` (xray.js says where the core keeps them). A username is
 *    mapped to its user by the build the running core was made from
 *    (built()), then by the users as they are now — a user renamed while
 *    connected is still counted until the reload;
 *  - what went direct: `stats.outbound['lu-d-<userId>']`, the user's own
 *    direct outbound (xray.js) — on the desktop and on the router alike.
 * The router's transparent mode adds what each device carried (nft counters,
 * by MAC) to its user: addBytes() / tickDevices().
 * So a user's total is the account's (or the devices') count, their direct
 * the outbound's, and their VPN the rest. The two arrive apart (the router's
 * nft read is not the stats tick), so the direct bytes the core counted wait
 * (`owed`) until a total carries them: the three always add up, and VPN never
 * goes below nothing. A user whose target is 'direct' carries everything
 * direct.
 *
 * Kept per user per kind (total, vpn, direct) per period — the day
 * ('YYYY-MM-DD'), the user's month (the key capPeriods.js writes for its
 * calendar and renew day) and, only while a 'none' limit of that kind exists,
 * 'all' since it was set — whether or not a limit exists: the page shows them
 * all. Saved by the caller in the usage file beside the per-config totals,
 * lazily (ipc.js): `lanUsersUsage2` (these), `lanUsersHistory` (the last
 * HISTORY_DAYS local days, VPN and direct, per user) and, still, the old
 * `lanUsersUsage` — the total of the user's mirror cap (model.js), so an older
 * app reading the same file counts on. The old key is read once, into the
 * total kind, when there is no new one yet.
 *
 * A top-up (topUp) adds to one limit for its current period only, and is gone
 * with it; resetUsage zeroes a user's every current period (the top-ups too)
 * and keeps the history.
 *
 * Holds, judged at a moment (holdAt), in this order: disabled > expired >
 * outside the allowed hours > over a total limit > over a VPN or a direct one.
 * 'all' — off entirely: the build leaves them out of the accounts (overIds),
 * the router holds their devices. 'vpn' — only the VPN stops, the user's
 * direct routes keep working (the owner's choice); 'direct' the other way.
 * Over a VPN limit with nothing that goes direct (routing ''/'global' to a
 * config — on the desktop; the router's own routing has direct routes, so
 * there it is 'vpn': `baseHasDirect`), or over a direct limit with everything
 * direct (target 'direct'), is 'all'. A 'slow' limit is never a hold: over it, its rates are the user's
 * speed (speedOf) until the period renews.
 *
 * When what the running core does is no longer what it should — the users in
 * the accounts, or a user's hold between none, 'vpn', 'direct' and 'all' — for
 * a reason of the meter's own (a limit reached, a period begun, an expiry or
 * an allowed-hours boundary passed), the meter says why in the log, once per
 * user and core, and asks the caller's reload once, retrying no sooner than
 * RETRY_MS if it did not happen. (Every other difference — an edit — is the
 * caller's to apply: ipc.js asks the same reload.) A speed change is never a
 * reload: the router applies it in nft.
 *
 * A limit crossing 80 % and then 100 % (of its amount and any top-up) is said
 * once per limit per period — in the log, and to notify().
 *
 * v1.40.0:
 *  - months: per user, VPN and direct per month of THEIR month (the key
 *    capPeriods writes for their calendar and renew day), the last
 *    MONTHS_KEPT — saved as `lanUsersMonths`; usage()[id].months, oldest
 *    first, the running month always there. A calendar or renew day changed
 *    mid-month carries the running month's row on under its new key, as the
 *    limits' month bucket does (rollEntry). A file of before (no months yet)
 *    starts from the running month's buckets: the chart has this month at once;
 *  - requests: a signed-in user asking for more from the router's status page
 *    (request()) — one pending per user, until the admin dismisses it, tops
 *    them up or resets their usage; saved as `lanUsersRequests`;
 *  - first use: `onFirstUse(userId)` once, when a voucher never used
 *    (voucher.activatedAt 0) carries its first bytes — ipc.js activates it;
 *  - exportState() / importState(): the Users module's own backup.
 *
 * Desktop (main.js) and router (service.js) alike: no store, no timers, no
 * Electron — the caller hands in its own.
 */
const { GIB } = require('../../main/multiWanMeter');
const { PERIOD_KEY, cycleOf, periodKey, periodStart, periodEnd, periodRange, rollEntry } = require('../../main/capPeriods');
const { dayText } = require('../../main/jalali');
const { normalizeLanUsers, normalizeUser, isActive, isExpired, normalizeMac, windowState, KINDS, PERIODS, QUOTA_MAX_GB } = require('./model');

const SAVE_EVERY_MS = 30000;
const RETRY_MS = 15000;
/** A tick this long after the last one is a new core: the old one's last reading says nothing about it. */
const GAP_MS = 20000;
/** How many local days of VPN / direct the history keeps. */
const HISTORY_DAYS = 30;
/** How many of a user's months the month history keeps: the running one and the twelve before it. */
const MONTHS_KEPT = 13;
/** The user's own direct outbound (xray.js): what its counter carried went direct. */
const DIRECT_PREFIX = 'lu-d-';
/** The reasons a hold comes and goes by itself — the meter's to apply. 'disabled' (an edit) is ipc.js's. */
const OWN_WHY = new Set(['expired', 'schedule', 'total', 'vpn', 'direct']);
const NO_HOLD = Object.freeze({ hold: null, why: null, until: 0 });

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const num = (v) => (typeof v === 'number' && Number.isFinite(v) && v > 0 ? v : 0);
const whole = (v) => { const n = Number(v); return Number.isFinite(n) && n > 0 ? Math.round(n) : 0; };
/** A saved period: a key capPeriods writes, or 'all'. */
const periodOk = (p) => typeof p === 'string' && (p === 'all' || PERIOD_KEY.test(p));
const DAY_KEY = /^\d{4}-\d{2}-\d{2}$/;
/** Where a limit's bytes are kept: 'day', 'month', or 'all' for a limit that never renews. */
const bucketOf = (period) => (period === 'none' ? 'all' : period);
const dayKey = (t) => periodKey('day', t);
const gbText = (bytes) => String(Math.round((bytes / GIB) * 100) / 100);
const round3 = (n) => Math.round(n * 1000) / 1000;

/**
 * The period a user's bytes count in at `now` for their mirror cap (quotaGb /
 * quotaPeriod, model.js): by the day, by the month — the user's own
 * (capPeriods.js: its calendar and renew day) — or, a cap that never renews,
 * 'all'. What the old `lanUsersUsage` key and the router's devices count by.
 */
function userPeriod(u, now) {
  if (u && u.quotaPeriod === 'none' && u.quotaGb > 0) return 'all';
  return periodKey(u && u.quotaPeriod === 'day' ? 'day' : 'month', now, u);
}

/** A user's mirror cap in bytes; 0 = none. A cap with no period ('none') is one amount for good. */
function capBytes(u) {
  const gb = Number(u && u.quotaGb);
  return Number.isFinite(gb) && gb > 0 ? Math.round(gb * GIB) : 0;
}

// rollEntry is capPeriods.js's, the internets' rule too: the same period keeps
// its entry; a month keeps the bytes of a period that overlaps it (a day of
// it, or the running month of a calendar or renew day just changed); anything
// else starts from nothing — a day never takes a month's bytes as its own.

/**
 * A saved bag's entries without the keys that are an object's own machinery:
 * `out['__proto__'] = …` from a usage file or a backup would set a prototype,
 * not add an entry (model.js ID refuses them as ids too).
 */
const UNSAFE_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const safeEntries = (o) => Object.entries(o).filter(([k]) => !UNSAFE_KEYS.has(k));

/** What was saved under the old key, each entry of its type; junk dropped. */
function normalizeUsage(raw) {
  const out = {};
  if (!isObj(raw)) return out;
  for (const [id, e] of safeEntries(raw)) {
    if (!/^[\w-]+$/.test(id) || !isObj(e) || !periodOk(e.period)) continue;
    const bytes = Number(e.bytes);
    out[id] = { period: e.period, bytes: Number.isFinite(bytes) && bytes > 0 ? Math.round(bytes) : 0 };
  }
  return out;
}

/** The router's devices' saved bytes, by MAC; junk dropped. */
function normalizeDeviceUsage(raw) {
  const out = {};
  if (!isObj(raw)) return out;
  for (const [k, e] of safeEntries(raw)) {
    const mac = normalizeMac(k);
    if (!mac || !isObj(e) || !periodOk(e.period)) continue;
    const bytes = Number(e.bytes);
    out[mac] = { period: e.period, bytes: Number.isFinite(bytes) && bytes > 0 ? Math.round(bytes) : 0 };
  }
  return out;
}

const blankEntry = () => ({ total: {}, vpn: {}, direct: {}, extra: {}, warned: {} });
/** A limit's key in a user's `extra` / `warned`: 'vpn:day'. */
const LIMIT_KEY = /^(total|vpn|direct):(day|month|none)$/;

/**
 * What was saved under `lanUsersUsage2`, each part of its type; junk dropped:
 *   { [userId]: { total|vpn|direct: { day: { period, bytes }, month: { period, bytes }, all?: { period: 'all', bytes, since } },
 *                 extra: { 'kind:period': { period, bytes } },          a top-up, for that period id
 *                 warned: { 'kind:period': { period, cap, pct } } } }   the warning said, for that period id and amount
 */
function normalizeUsage2(raw) {
  const out = {};
  if (!isObj(raw)) return out;
  for (const [id, e] of safeEntries(raw)) {
    if (!/^[\w-]+$/.test(id) || !isObj(e)) continue;
    const r = blankEntry();
    for (const k of KINDS) {
      const b = isObj(e[k]) ? e[k] : {};
      if (isObj(b.day) && typeof b.day.period === 'string' && DAY_KEY.test(b.day.period)) r[k].day = { period: b.day.period, bytes: whole(b.day.bytes) };
      if (isObj(b.month) && typeof b.month.period === 'string' && PERIOD_KEY.test(b.month.period)) r[k].month = { period: b.month.period, bytes: whole(b.month.bytes) };
      if (isObj(b.all)) r[k].all = { period: 'all', bytes: whole(b.all.bytes), since: whole(b.all.since) };
    }
    for (const bag of ['extra', 'warned']) {
      for (const [key, x] of safeEntries(isObj(e[bag]) ? e[bag] : {})) {
        if (!LIMIT_KEY.test(key) || !isObj(x) || typeof x.period !== 'string' || !x.period) continue;
        r[bag][key] = bag === 'extra' ? { period: x.period, bytes: whole(x.bytes) } : { period: x.period, cap: whole(x.cap), pct: x.pct === 100 ? 100 : 80 };
      }
    }
    out[id] = r;
  }
  return out;
}

/** Of two buckets of one kind (a day's, a month's): the same period → the larger count; else the period that began later. */
function laterBucket(a, b) {
  if (!a || !b) return a || b ? Object.assign({}, a || b) : null;
  if (a.period === b.period) return { period: a.period, bytes: Math.max(a.bytes, b.bytes) };
  const x = periodRange(a.period);
  const y = periodRange(b.period);
  return Object.assign({}, y && (!x || y.start > x.start) ? b : a);
}

/** Two usage entries of one user as one (a backup merged in): per bucket laterBucket's, the top-ups alike, the warnings said here kept. */
function mergeEntry(a, b) {
  const out = blankEntry();
  for (const k of KINDS) {
    for (const which of ['day', 'month']) { const v = laterBucket(a[k][which], b[k][which]); if (v) out[k][which] = v; }
    const x = a[k].all;
    const y = b[k].all;
    if (x || y) out[k].all = x && y ? { period: 'all', bytes: Math.max(x.bytes, y.bytes), since: x.since } : Object.assign({}, x || y);
  }
  for (const key of new Set(Object.keys(a.extra).concat(Object.keys(b.extra)))) {
    const x = a.extra[key];
    const y = b.extra[key];
    out.extra[key] = x && y && x.period === y.period ? { period: x.period, bytes: Math.max(x.bytes, y.bytes) } : Object.assign({}, x || y);
  }
  for (const key of new Set(Object.keys(a.warned).concat(Object.keys(b.warned)))) out.warned[key] = Object.assign({}, a.warned[key] || b.warned[key]);
  return out;
}

/** Two lists of { [key], vpn, direct } rows as one: each key once, the larger VPN and the larger direct. */
function mergeRows(ours, theirs, key) {
  const m = new Map();
  for (const r of ours || []) m.set(r[key], Object.assign({}, r));
  for (const r of theirs || []) {
    const have = m.get(r[key]);
    m.set(r[key], have ? Object.assign(have, { vpn: Math.max(have.vpn, r.vpn), direct: Math.max(have.direct, r.direct) }) : Object.assign({}, r));
  }
  return [...m.values()];
}

/** The old key's entries as the total kind (read once, when there is no new key yet). */
function migrateUsage(old) {
  const out = {};
  for (const [id, e] of safeEntries(old)) {
    const r = blankEntry();
    if (e.period === 'all') r.total.all = { period: 'all', bytes: e.bytes, since: 0 };
    else if (DAY_KEY.test(e.period)) { r.total.day = { period: e.period, bytes: e.bytes }; r.total.month = { period: e.period, bytes: e.bytes }; }
    else r.total.month = { period: e.period, bytes: e.bytes };
    out[id] = r;
  }
  return out;
}

/** What was saved under `lanUsersHistory`: { [userId]: [{ day, vpn, direct }] }, oldest first, a day once. */
function normalizeHistory(raw) {
  const out = {};
  if (!isObj(raw)) return out;
  for (const [id, rows] of safeEntries(raw)) {
    if (!/^[\w-]+$/.test(id) || !Array.isArray(rows)) continue;
    const byDay = new Map();
    for (const r of rows) if (isObj(r) && typeof r.day === 'string' && DAY_KEY.test(r.day)) byDay.set(r.day, { day: r.day, vpn: whole(r.vpn), direct: whole(r.direct) });
    out[id] = [...byDay.values()].sort((a, b) => (a.day < b.day ? -1 : 1)).slice(-HISTORY_DAYS);
  }
  return out;
}

/** A month key (any calendar, any renew day) — never a day's, never 'all'. */
const monthKeyOk = (k) => typeof k === 'string' && PERIOD_KEY.test(k) && !DAY_KEY.test(k);
/** Where a month key's span begins (ms), for the order; 0 for one the calendar has no table for. */
const monthStart = (k) => { const r = periodRange(k); return r ? r.start : 0; };
/** Two month keys whose spans overlap: the same running month under a calendar or renew day just changed. */
function monthsOverlap(a, b) {
  const x = periodRange(a);
  const y = periodRange(b);
  return !!(x && y && x.start < y.end && y.start < x.end);
}

/** What was saved under `lanUsersMonths`: { [userId]: [{ key, vpn, direct }] }, oldest first, a month once, the last MONTHS_KEPT. */
function normalizeMonths(raw) {
  const out = {};
  if (!isObj(raw)) return out;
  for (const [id, rows] of safeEntries(raw)) {
    if (!/^[\w-]+$/.test(id) || !Array.isArray(rows)) continue;
    const byKey = new Map();
    for (const r of rows) if (isObj(r) && monthKeyOk(r.key)) byKey.set(r.key, { key: r.key, vpn: whole(r.vpn), direct: whole(r.direct) });
    const list = [...byKey.values()].sort((a, b) => monthStart(a.key) - monthStart(b.key)).slice(-MONTHS_KEPT);
    if (list.length) out[id] = list;
  }
  return out;
}

/**
 * The month history of a usage file of before (no `lanUsersMonths` yet): each
 * user's running month as their buckets have it, VPN and direct — the chart
 * shows this month from the first day. The months before it were never kept.
 */
function seedMonths(usage2) {
  const out = {};
  for (const [id, e] of safeEntries(isObj(usage2) ? usage2 : {})) {
    const v = e && e.vpn && e.vpn.month;
    const d = e && e.direct && e.direct.month;
    const key = (v && monthKeyOk(v.period) && v.period) || (d && monthKeyOk(d.period) && d.period) || '';
    if (!key) continue;
    const row = { key, vpn: v && v.period === key ? v.bytes : 0, direct: d && d.period === key ? d.bytes : 0 };
    if (row.vpn || row.direct) out[id] = [row];
  }
  return out;
}

/** What was saved under `lanUsersRequests`: { [userId]: { at, mac } } — a top-up asked for and not yet answered. */
function normalizeRequests(raw) {
  const out = {};
  if (!isObj(raw)) return out;
  for (const [id, r] of safeEntries(raw)) {
    if (!/^[\w-]+$/.test(id) || !isObj(r) || !(whole(r.at) > 0)) continue;
    out[id] = { at: whole(r.at), mac: normalizeMac(r.mac) || '' };
  }
  return out;
}

/** The first day the history keeps at `t`: HISTORY_DAYS local days, today the last. */
function historyFrom(t) {
  const d = new Date(t);
  return dayKey(new Date(d.getFullYear(), d.getMonth(), d.getDate() - (HISTORY_DAYS - 1)).getTime());
}

/** Each username's bytes as the running core counts them (totals since it started): { [username]: { up, down } }. */
function userTotals(vars) {
  const raw = vars && vars.stats && vars.stats.user;
  const out = {};
  if (!isObj(raw)) return out;
  for (const [name, c] of safeEntries(raw)) if (name && isObj(c)) out[name] = { up: num(c.uplink), down: num(c.downlink) };
  return out;
}

/** Each user's own direct outbound's bytes, as the running core counts them: { [userId]: bytes }. */
function directTotals(vars) {
  const raw = vars && vars.stats && vars.stats.outbound;
  const out = {};
  if (!isObj(raw)) return out;
  for (const [tag, c] of safeEntries(raw)) {
    if (tag.indexOf(DIRECT_PREFIX) !== 0 || !isObj(c)) continue;
    const id = tag.slice(DIRECT_PREFIX.length);
    if (/^[\w-]+$/.test(id)) out[id] = num(c.uplink) + num(c.downlink);
  }
  return out;
}

/** Every counter the core reports, summed: a reading below the last one is a core that started again. */
function counterSum(vars) {
  const st = vars && vars.stats;
  let sum = 0;
  if (!isObj(st)) return sum;
  for (const group of Object.values(st)) {
    if (!isObj(group)) continue;
    for (const c of Object.values(group)) if (isObj(c)) sum += num(c.uplink) + num(c.downlink);
  }
  return sum;
}

const sameSet = (a, b) => a.length === b.length && a.every((x) => b.includes(x));
/** When a hold that lifts at `a` or at `b` lifts first (0: never). */
const earlier = (a, b) => (!a ? b : (!b ? a : Math.min(a, b)));
const WEEKDAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
/** A moment as the log says it: 'Mon 08:00'. */
const whenText = (ms) => { const d = new Date(ms); return `${WEEKDAYS[d.getDay()]} ${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`; };

/**
 * @param {object} o
 *   usage        what the usage file held under `lanUsersUsage` (read when `usage2` is not there)
 *   usage2       …under `lanUsersUsage2`
 *   history      …under `lanUsersHistory`
 *   months       …under `lanUsersMonths` (absent: a file of before — started from the month buckets)
 *   requests     …under `lanUsersRequests`
 *   deviceUsage  …and under `lanDeviceUsage` (the router's devices, by MAC)
 *   onFirstUse(userId)  a voucher never used carried its first bytes (once per user until its
 *                activatedAt is written; called from inside a tick — the caller defers its write)
 *   users()      the store's lanUsers as they are now (raw or normalized) —
 *                limits and periods are read live, so a limit changed while
 *                connected counts at once
 *   canReload()  connected and quiet: no connect, recovery or disconnect in flight
 *   pending()    the keys waiting for Apply (a reload would take some of them
 *                live behind the user's back — the hold waits, as multiWan's does)
 *   reload(why)  → Promise: the caller's reload (one queue)
 *   log({ line, level }), notify({ name, kind, period, pct, capGb, until, calendar, action, leftBytes, hold, down?, up? })
 *                (optional; `pct` 80 or 100, `capGb` the limit with any top-up, `until` the day it
 *                renews, ms — 0 for one that never does)
 *   now()        ms epoch (a test hands in its own clock)
 *   baseHasDirect  true on the router: there routing '' / 'global' is the router's own
 *                routing, which sends some traffic direct (private ranges at least, Iranian
 *                sites under bypass-ir) — so over a VPN limit there is 'vpn', never 'all';
 *                on the desktop such a user sends nothing direct (false, the default)
 */
function createLanUsersMeter(o) {
  const now = typeof o.now === 'function' ? o.now : () => Date.now();
  const log = typeof o.log === 'function' ? o.log : () => {};
  const baseHasDirect = o.baseHasDirect === true;
  let store = isObj(o.usage2) ? normalizeUsage2(o.usage2) : migrateUsage(normalizeUsage(o.usage));
  let hist = normalizeHistory(o.history);
  let months = isObj(o.months) ? normalizeMonths(o.months) : seedMonths(store);
  let requests = normalizeRequests(o.requests);
  const firstUse = new Set();   // vouchers whose first bytes were said to onFirstUse, until their activatedAt shows
  let dirty = !isObj(o.months) && Object.keys(months).length > 0;
  let savedAt = now();
  let prev = null;          // the running core's last reading per username
  let prevOut = null;       // …and per user's direct outbound
  let prevAt = 0;
  let prevSum = 0;
  let rates = {};           // bytes/s per user id
  let live = null;          // what the running core was built with (built()); null: no users in it
  let pendingBuild = null;  // what the build that is starting was made with
  let lastTry = -Infinity;
  let reloading = false;
  let waitSaid = false;
  const said = new Set();
  const owed = new Map();   // userId → direct bytes the core counted that no total has carried yet
  const devPrev = new Map();   // mac → the device counters' last totals { up, down } (tickDevices)
  let devPrevAt = 0;
  let devUsage = normalizeDeviceUsage(o.deviceUsage);   // mac → { period, bytes }
  let devRates = {};           // mac → bytes/s

  const current = () => normalizeLanUsers(typeof o.users === 'function' ? o.users() : null);
  const label = (u) => u.name || u.username;
  const sayOnce = (key, line, level) => { if (said.has(key)) return; said.add(key); log({ line, level }); };

  /** The period a device counts in: its user's, or by the month. */
  const devicePeriod = (lu, mac, t) => {
    const d = lu.devices.find((x) => x.mac === mac);
    const u = d && d.userId ? lu.users.find((x) => x.id === d.userId) : null;
    return userPeriod(u, t);
  };

  /** A user's limit of (kind, period), or undefined. */
  const limitOf = (u, kind, period) => u.limits.find((l) => l.kind === kind && l.period === period);

  /** The id of a limit's current period: the day's key, the month's, or 'all@<since>' for one that never renews. */
  function periodId(u, l, e, t) {
    if (l.period === 'day') return dayKey(t);
    if (l.period === 'month') return periodKey('month', t, u);
    const all = e && e[l.kind] && e[l.kind].all;
    return 'all@' + ((all && all.since) || 0);
  }

  /** A user's buckets moved to the periods they count in at `t`; top-ups and warnings of a period that ended go. */
  function rollUser(u, t) {
    const e = store[u.id] || (store[u.id] = blankEntry());
    const keys = { day: dayKey(t), month: periodKey('month', t, u) };
    for (const k of KINDS) {
      const b = e[k];
      for (const which of ['day', 'month']) {
        const was = b[which] || null;
        const next = rollEntry(was, keys[which]);
        if (next === was) continue;
        b[which] = next;
        if (was) dirty = true;   // a period that ended is worth a write; a new empty bucket is not
      }
      const wantsAll = !!limitOf(u, k, 'none');
      if (wantsAll && !b.all) { b.all = { period: 'all', bytes: 0, since: t }; dirty = true; }
      else if (!wantsAll && b.all) { delete b.all; dirty = true; }
    }
    for (const bag of [e.extra, e.warned]) {
      for (const key of Object.keys(bag)) {
        const [kind, period] = key.split(':');
        const l = limitOf(u, kind, period);
        if (l && bag[key].period === periodId(u, l, e, t)) continue;
        delete bag[key];
        dirty = true;
      }
    }
    return e;
  }

  /** Every user moved to the period they count in at `t`. */
  function roll(lu, t) { for (const u of lu.users) rollUser(u, t); }

  /**
   * The running month's row of a user's month history at `t`, made when it is
   * not there; the newest row, when its month overlaps this one (their
   * calendar or renew day just changed), goes on under the new key.
   */
  function monthRow(u, t) {
    const key = periodKey('month', t, u);
    const rows = months[u.id] || (months[u.id] = []);
    let row = rows.find((r) => r.key === key);
    if (row) return row;
    const last = rows[rows.length - 1];
    if (last && monthsOverlap(last.key, key)) row = Object.assign(last, { key });
    else { row = { key, vpn: 0, direct: 0 }; rows.push(row); }
    rows.sort((a, b) => monthStart(a.key) - monthStart(b.key));
    if (rows.length > MONTHS_KEPT) rows.splice(0, rows.length - MONTHS_KEPT);
    return row;
  }

  /** A user's month history as the window shows it at `t`: [{ key, from, to, vpn, direct }], oldest first, the running month always there. */
  function monthsOf(u, t) {
    const key = periodKey('month', t, u);
    const rows = (months[u.id] || []).map((r) => ({ key: r.key, vpn: r.vpn, direct: r.direct }));
    if (!rows.some((r) => r.key === key)) {
      const last = rows[rows.length - 1];
      if (last && monthsOverlap(last.key, key)) last.key = key;
      else rows.push({ key, vpn: 0, direct: 0 });
    }
    return rows.sort((a, b) => monthStart(a.key) - monthStart(b.key)).slice(-MONTHS_KEPT).map((r) => {
      const span = periodRange(r.key);
      return { key: r.key, from: span ? span.start : 0, to: span ? span.end : 0, vpn: r.vpn, direct: r.direct };
    });
  }

  /** A voucher never used carried bytes: said once to onFirstUse (ipc.js writes its activatedAt — until that shows, never again). */
  function firstBytes(u) {
    if (!u.voucher || u.voucher.activatedAt > 0) { firstUse.delete(u.id); return; }
    if (firstUse.has(u.id) || typeof o.onFirstUse !== 'function') return;
    firstUse.add(u.id);
    try { o.onFirstUse(u.id); } catch (e) { log({ line: 'Users: a voucher’s first use could not be written — ' + ((e && e.message) || e), level: 'warn' }); }
  }

  /** A limit at `t`: { bytes, cap, extra, full, over, pct, since, renews, pid } — `full` the amount with any top-up. */
  function limitState(u, l, e, t) {
    const b = e[l.kind][bucketOf(l.period)];
    const bytes = b ? b.bytes : 0;
    const cap = Math.round(l.gb * GIB);
    const pid = periodId(u, l, e, t);
    const x = e.extra[l.kind + ':' + l.period];
    const extra = x && x.period === pid ? x.bytes : 0;
    const full = cap + extra;
    const over = bytes >= full;
    return {
      bytes, cap, extra, full, over, pid,
      pct: over ? 100 : Math.min(99, Math.floor((bytes / full) * 100)),
      since: l.period === 'none' ? ((b && b.since) || 0) : periodStart(l.period, t, u),
      renews: l.period === 'none' ? 0 : periodEnd(l.period, t, u)
    };
  }

  /**
   * What holds a user off at `t` (see the header): { hold, why, until } —
   * `until` when it lifts (ms), 0 for "until the admin changes something".
   */
  function holdAt(u, t) {
    if (!u) return NO_HOLD;
    if (u.enabled === false) return { hold: 'all', why: 'disabled', until: 0 };
    if (isExpired(u, t)) return { hold: 'all', why: 'expired', until: 0 };
    const w = windowState(u.schedule, t);
    if (!w.on) return { hold: 'all', why: 'schedule', until: w.next };
    const e = rollUser(u, t);
    // over every 'cut' limit of a kind: when the last of them renews (0: one never does)
    const lift = (kind) => {
      let any = false, never = false, at = 0;
      for (const l of u.limits) {
        if (l.kind !== kind || l.action !== 'cut') continue;
        const s = limitState(u, l, e, t);
        if (!s.over) continue;
        any = true;
        if (!s.renews) never = true; else at = Math.max(at, s.renews);
      }
      return any ? (never ? 0 : at) : null;
    };
    const total = lift('total');
    if (total !== null) return { hold: 'all', why: 'total', until: total };
    const vpn = lift('vpn');
    const direct = lift('direct');
    if (vpn !== null && direct !== null) return { hold: 'all', why: 'vpn', until: earlier(vpn, direct) };
    if (vpn !== null) {
      // on the router, routing '' / 'global' is its own routing, which sends something direct (private ranges at least)
      const nothingDirect = !baseHasDirect && u.target !== 'direct' && (u.routing === '' || u.routing === 'global');
      return { hold: nothingDirect ? 'all' : 'vpn', why: 'vpn', until: vpn };
    }
    if (direct !== null) return { hold: u.target === 'direct' ? 'all' : 'direct', why: 'direct', until: direct };
    return NO_HOLD;
  }

  /**
   * A user's speed at `t`: per direction the lowest of the base, every speed
   * window on now and every 'slow' limit that is over — { down, up, why } in
   * kbps (0 = unlimited that way), `why` what is in force ('base', 'hours',
   * 'after:<kind>:<period>') — or null.
   */
  function speedAt(u, t) {
    if (!u) return null;
    const parts = [];
    if (u.speed) parts.push({ down: u.speed.down, up: u.speed.up, why: 'base' });
    for (const w of u.speedHours || []) if (windowState(w, t).on) parts.push({ down: w.down, up: w.up, why: 'hours' });
    const slow = u.limits.filter((l) => l.action === 'slow');
    if (slow.length) {
      const e = rollUser(u, t);
      for (const l of slow) if (limitState(u, l, e, t).over) parts.push({ down: l.down, up: l.up, why: `after:${l.kind}:${l.period}` });
    }
    const low = (k) => parts.reduce((m, p) => (p[k] > 0 && (!m || p[k] < m) ? p[k] : m), 0);
    const down = low('down');
    const up = low('up');
    if (!down && !up) return null;
    return { down, up, why: [...new Set(parts.map((p) => p.why))] };
  }

  /** `x` a user record or id → the user as stored now (or the record itself, normalized, when it is not stored). */
  function userOf(lu, x) {
    const id = typeof x === 'string' ? x : (isObj(x) ? x.id : null);
    return lu.users.find((u) => u.id === id) || (isObj(x) ? normalizeUser(x) : null);
  }

  /** Bytes a user carried: { total, vpn, direct } into every bucket of theirs, and the day's history. */
  function add(u, d, t) {
    const e = rollUser(u, t);
    for (const k of KINDS) {
      const n = d[k];
      if (!(n > 0)) continue;
      const b = e[k];
      b.day = { period: b.day.period, bytes: b.day.bytes + n };
      b.month = { period: b.month.period, bytes: b.month.bytes + n };
      if (b.all) b.all = { period: 'all', bytes: b.all.bytes + n, since: b.all.since };
    }
    if (d.vpn > 0 || d.direct > 0) {
      const day = dayKey(t);
      const rows = (hist[u.id] || []).filter((r) => r.day >= historyFrom(t));
      const row = rows.find((r) => r.day === day);
      if (row) { row.vpn += d.vpn; row.direct += d.direct; } else rows.push({ day, vpn: d.vpn, direct: d.direct });
      hist[u.id] = rows.slice(-HISTORY_DAYS);
      const month = monthRow(u, t);
      month.vpn += d.vpn;
      month.direct += d.direct;
    }
    firstBytes(u);
    dirty = true;
  }

  /** `total` bytes a user carried, split: what their direct outbound counted (owed) is direct, the rest VPN. */
  function carried(u, total, t) {
    if (!u || !(total > 0)) return;
    if (u.target === 'direct') { owed.delete(u.id); add(u, { total, vpn: 0, direct: total }, t); return; }
    const was = owed.get(u.id) || 0;
    const direct = Math.min(was, total);
    if (was) owed.set(u.id, was - direct);
    add(u, { total, vpn: total - direct, direct }, t);
  }

  /** A limit past 80 % or 100 % of its amount (and top-up) this period: said once each, in the log and to notify(). */
  function warn(lu, t) {
    for (const u of lu.users) {
      if (!u.limits.length) continue;
      const e = rollUser(u, t);   // never yesterday's bytes judged against today's period
      for (const l of u.limits) {
        const s = limitState(u, l, e, t);
        const reached = s.bytes >= s.full ? 100 : (s.bytes >= s.full * 0.8 ? 80 : 0);
        if (!reached) continue;
        const key = l.kind + ':' + l.period;
        const w = e.warned[key];
        if (w && w.period === s.pid && w.cap === s.full && w.pct >= reached) continue;
        e.warned[key] = { period: s.pid, cap: s.full, pct: reached };
        dirty = true;
        tell(u, l, s, reached, t);
      }
    }
  }

  function tell(u, l, s, pct, t) {
    const capGb = round3(s.full / GIB);
    const calendar = cycleOf(u).calendar;
    const when = l.period === 'day' ? 'today' : (l.period === 'none' ? 'in all' : 'this month');
    // the day it comes back: tomorrow, never, or the day their month renews — in its calendar too
    const until = l.period === 'day' ? 'until tomorrow' : (l.period === 'none' ? 'until the cap is raised' : 'until ' + dayText(s.renews, 'en', calendar));
    const word = l.kind === 'total' ? '' : (l.kind === 'vpn' ? 'VPN ' : 'direct ');
    let line;
    if (pct < 100) line = `Users: “${label(u)}” has used 80 % of their ${word}cap (${capGb} GB ${when}) — ${gbText(s.full - s.bytes)} GB left`;
    else if (l.action === 'slow') line = `Users: “${label(u)}” used their ${word}allowance (${capGb} GB ${when}) — slowed to ${l.down ? '↓' + l.down : ''}${l.down && l.up ? ' ' : ''}${l.up ? '↑' + l.up : ''} kbps ${until}`;
    else if (l.kind === 'total' || holdAt(u, t).hold === 'all') line = `Users: “${label(u)}” reached their ${word}cap (${capGb} GB ${when}) — off ${until}`;
    else if (l.kind === 'vpn') line = `Users: “${label(u)}” reached their VPN cap (${capGb} GB ${when}) — the VPN is off ${until}; direct routes still work`;
    else line = `Users: “${label(u)}” reached their direct cap (${capGb} GB ${when}) — direct routes are off ${until}; the VPN still works`;
    log({ line, level: pct < 100 ? 'info' : 'warn' });
    if (typeof o.notify !== 'function') return;
    // `hold`: what the user is held to now — a VPN limit with nothing going direct is off entirely ('all')
    const n = { name: label(u), kind: l.kind, period: l.period, pct, capGb, until: s.renews, calendar, action: l.action, leftBytes: Math.max(0, s.full - s.bytes), hold: holdAt(u, t).hold };
    if (l.action === 'slow') Object.assign(n, { down: l.down, up: l.up });
    try { o.notify(n); } catch { /* a notification is never worth an error */ }
  }

  /** A user's partial hold as one line for the log. */
  function partialLine(u, h) {
    const until = h.until ? ' until ' + dayText(h.until, 'en', cycleOf(u).calendar) : '';
    if (h.hold === 'vpn') return `Users: “${label(u)}”: the VPN is off${until} — direct routes only`;
    if (h.hold === 'direct') return `Users: “${label(u)}”: direct routes are off${until} — the VPN only`;
    return `Users: “${label(u)}” has the VPN and direct routes again`;
  }

  /**
   * The running core lets in, or routes, other than it should, for a reason
   * of the meter's own: say why, and reload — once. The build's snapshot
   * (built()): `active` the accounts, `holds` each user's hold then, `scope`
   * the users whose rules are in it (the accounts and the router's
   * transparent inbounds), `proxy` false when it had no accounts at all.
   */
  function settle(lu, t) {
    if (!live) return;
    const byId = new Map(lu.users.map((u) => [u.id, u]));
    const hold = new Map(lu.users.map((u) => [u.id, holdAt(u, t)]));
    const held = lu.users.filter((u) => hold.get(u.id).hold === 'all').map((u) => u.id);
    const want = live.proxy === false ? [] : lu.users.filter((u) => isActive(u, { now: t, over: held })).map((u) => u.id);
    const was = (id) => (isObj(live.holds) && isObj(live.holds[id]) ? live.holds[id] : (live.over.includes(id) ? { hold: 'all', why: 'total', until: 0 } : NO_HOLD));
    let ours = false;   // a difference the meter is here for (an edit is ipc.js's to apply)
    for (const id of live.active) {
      const u = byId.get(id);
      const h = hold.get(id);
      if (!u || want.includes(id) || !OWN_WHY.has(h.why)) continue;
      ours = true;
      // a limit's line is the warning's (warn)
      if (h.why === 'expired') sayOnce('exp:' + id, `Users: “${label(u)}” expired — off until the expiry is moved`, 'warn');
      else if (h.why === 'schedule') sayOnce('sch:' + id + ':' + h.until, `Users: “${label(u)}” is outside their allowed hours — off ${h.until ? 'until ' + whenText(h.until) : 'until the hours are changed'}`, 'info');
    }
    for (const id of want) {
      if (live.active.includes(id)) continue;
      const u = byId.get(id);
      const w = was(id);
      if (!u || w.hold !== 'all' || !OWN_WHY.has(w.why) || w.why === 'expired') continue;
      ours = true;
      sayOnce('back:' + id, w.why === 'schedule'
        ? `Users: “${label(u)}” is back — inside their allowed hours`
        : `Users: “${label(u)}” is back — a new period began (or their cap was raised)`, 'info');
    }
    for (const id of Array.isArray(live.scope) ? live.scope : live.active) {
      const u = byId.get(id);
      const h = hold.get(id);
      if (!u || !h || h.hold === 'all') continue;   // off entirely: the accounts (or the router's nft) say it
      const w = was(id);
      const before = w.hold === 'vpn' || w.hold === 'direct' ? w.hold : null;
      if (before === h.hold) continue;
      ours = true;
      sayOnce('part:' + id + ':' + h.hold, partialLine(u, h), 'info');
    }
    if (!ours) { waitSaid = false; return; }
    if (reloading || t - lastTry < RETRY_MS) return;
    if (o.canReload && !o.canReload()) return;
    if (o.pending && o.pending().length) {
      if (!waitSaid) { waitSaid = true; log({ line: 'Users: a user to turn off for their cap (or back on) waits for your pending settings — apply them (or reconnect) and the core reloads', level: 'info' }); }
      return;
    }
    waitSaid = false;
    reloading = true;
    lastTry = t;
    Promise.resolve()
      .then(() => o.reload('Users: the core reloaded with the users who may use it now'))
      .catch((e) => log({ line: 'Users: the reload failed — ' + ((e && e.message) || e), level: 'warn' }))
      .finally(() => { reloading = false; });
  }

  /** A core has started from the build made last: its counters are new, and its users are the ones to hold to. */
  function fresh() {
    prev = null;
    prevOut = null;
    rates = {};
    live = pendingBuild;
    said.clear();
    waitSaid = false;
  }

  /** The history to save: the days before the last HISTORY_DAYS left out. */
  function savedHistory() {
    const from = historyFrom(now());
    const out = {};
    for (const [id, rows] of Object.entries(hist)) { const r = rows.filter((x) => x.day >= from); if (r.length) out[id] = JSON.parse(JSON.stringify(r)); }
    return out;
  }

  /** The month history to save: each user's rows that are there. */
  function savedMonths() {
    const out = {};
    for (const [id, rows] of Object.entries(months)) if (rows.length) out[id] = rows.map((r) => ({ key: r.key, vpn: r.vpn, direct: r.direct }));
    return out;
  }

  /** What to save under the old `lanUsersUsage`: each user's total for their mirror cap's period. */
  function savedOld() {
    const out = {};
    const lu = current();
    for (const [id, e] of Object.entries(store)) {
      const u = lu.users.find((x) => x.id === id);
      const m = u ? u.limits.find((l) => l.kind === 'total') : null;
      const b = e.total[bucketOf(m ? m.period : 'month')] || (u ? null : e.total.month);
      if (b) out[id] = { period: b.period, bytes: b.bytes };
    }
    return out;
  }

  return {
    /**
     * One stats poll: the core's raw counters (`vars`, the parsed /debug/vars).
     * → { fresh }: whether this reading is the first of a core that started again.
     */
    tick(vars) {
      const t = now();
      const lu = current();
      roll(lu, t);
      const sum = counterSum(vars);
      const isFresh = !prevAt || t - prevAt > GAP_MS || sum < prevSum;
      if (isFresh) fresh();
      const byName = new Map(lu.users.map((u) => [u.username, u]));
      const byId = new Map(lu.users.map((u) => [u.id, u]));
      // what went direct first: the totals below carry it
      const outs = directTotals(vars);
      for (const [id, c] of Object.entries(outs)) {
        if (!byId.has(id)) continue;
        const p = (prevOut && prevOut[id]) || 0;
        const d = c >= p ? c - p : c;
        if (d > 0) owed.set(id, (owed.get(id) || 0) + d);
      }
      prevOut = outs;
      const cur = userTotals(vars);
      const dt = prev ? (t - prevAt) / 1000 : 0;
      const nextRates = {};
      for (const [name, c] of Object.entries(cur)) {
        const id = (live && live.byName && live.byName[name]) || (byName.get(name) || {}).id;
        const u = id && byId.get(id);
        if (!u) continue;
        const p = (prev && prev[name]) || { up: 0, down: 0 };
        // a counter below the last is a fresh core counting from zero: all of it is new
        const dUp = c.up >= p.up ? c.up - p.up : c.up;
        const dDown = c.down >= p.down ? c.down - p.down : c.down;
        const r = nextRates[u.id] || { up: 0, down: 0 };
        nextRates[u.id] = dt > 0 ? { up: r.up + dUp / dt, down: r.down + dDown / dt } : r;
        carried(u, dUp + dDown, t);
      }
      prev = cur;
      prevAt = t;
      prevSum = sum;
      rates = nextRates;
      warn(lu, t);
      settle(lu, t);
      return { fresh: isFresh };
    },

    /** Bytes a user carried some other way (the router's transparent devices). */
    addBytes(userId, bytes) {
      const t = now();
      const lu = current();
      carried(lu.users.find((u) => u.id === userId), num(bytes), t);
      warn(lu, t);
    },

    /**
     * The router's per-device counters (nft, by MAC — total bytes since they
     * were made: a number, or { up, down }), each device's growth counted for
     * the device and added to the user it is bound to. A total below the last
     * is a counter made again: all of it is new.
     */
    tickDevices(totals) {
      if (!isObj(totals)) return;
      const t = now();
      const lu = current();
      const owner = new Map(lu.devices.map((d) => [d.mac, d.userId]));
      const dt = devPrevAt ? (t - devPrevAt) / 1000 : 0;
      const nextRates = {};
      for (const [raw, total] of Object.entries(totals)) {
        const mac = normalizeMac(raw);
        if (!mac) continue;
        const v = isObj(total) ? { up: num(total.up), down: num(total.down) } : { up: 0, down: num(total) };
        const was = devPrev.get(mac) || { up: 0, down: 0 };
        devPrev.set(mac, v);
        const dUp = v.up >= was.up ? v.up - was.up : v.up;
        const dDown = v.down >= was.down ? v.down - was.down : v.down;
        nextRates[mac] = dt > 0 && dt * 1000 <= GAP_MS ? { up: dUp / dt, down: dDown / dt } : { up: 0, down: 0 };
        if (dUp + dDown <= 0) continue;
        const e = rollEntry(devUsage[mac], devicePeriod(lu, mac, t));
        devUsage[mac] = { period: e.period, bytes: e.bytes + dUp + dDown };
        dirty = true;
        const id = owner.get(mac);
        if (id) carried(lu.users.find((u) => u.id === id), dUp + dDown, t);
      }
      devPrevAt = t;
      devRates = nextRates;
      warn(lu, t);
      settle(lu, t);
    },

    /** Each device's bytes this period (its user's period, else the month): { [mac]: bytes }. */
    deviceUsage() {
      const t = now();
      const lu = current();
      const out = {};
      for (const [mac, e] of Object.entries(devUsage)) {
        const r = rollEntry(e, devicePeriod(lu, mac, t));
        out[mac] = r.bytes;
      }
      return out;
    },

    /** bytes/s per device from the last device tick: { [mac]: { up, down } }. */
    deviceRates() { return Object.assign({}, devRates); },

    /**
     * What the build that is starting lets in (ipc.js forBuild, right before
     * each build): { active: [id], over: [id], byName: { username: id },
     * holds?: { [id]: { hold, why, until } }, scope?: [id], proxy? } (see
     * settle), or null — no users in it. Held to from the first reading of
     * the core it starts.
     */
    built(snapshot) { pendingBuild = snapshot && Array.isArray(snapshot.active) ? Object.assign({ over: [] }, snapshot, { over: Array.isArray(snapshot.over) ? snapshot.over : [] }) : null; },

    /** The users held off entirely now ('all') — what the build leaves out of the accounts. */
    overIds() { const t = now(); return current().users.filter((u) => holdAt(u, t).hold === 'all').map((u) => u.id); },

    /** What holds a user (a record or an id) off now: { hold: null|'all'|'vpn'|'direct', why, until }. */
    holdOf(user) { const t = now(); return holdAt(userOf(current(), user), t); },

    /** Every user with a hold now: { [userId]: { hold, why, until } }. */
    holds() {
      const t = now();
      const out = {};
      for (const u of current().users) { const h = holdAt(u, t); if (h.hold) out[u.id] = h; }
      return out;
    },

    /** A user's speed now (speedAt): { down, up, why } kbps, or null. */
    speedOf(user) { const t = now(); return speedAt(userOf(current(), user), t); },

    /** Every user with a speed now: { [userId]: { down, up, why } }. Never a reload: the router applies it in nft. */
    speeds() {
      const t = now();
      const out = {};
      for (const u of current().users) { const s = speedAt(u, t); if (s) out[u.id] = s; }
      return out;
    },

    /**
     * More of one limit for its current period only — gone with it (a
     * one-off limit's: until it is set again or the usage is reset). → null,
     * or what is wrong: 'notFound' (no such user), 'limit' (they have no such
     * limit), 'gb' (not an amount: > 0, at most QUOTA_MAX_GB).
     */
    topUp(userId, kind, period, gb) {
      const t = now();
      const u = current().users.find((x) => x.id === userId);
      if (!u) return 'notFound';
      const l = KINDS.includes(kind) && PERIODS.includes(period) ? limitOf(u, kind, period) : null;
      if (!l) return 'limit';
      const n = typeof gb === 'string' && !gb.trim() ? NaN : Number(gb);
      if (!Number.isFinite(n) || n <= 0 || n > QUOTA_MAX_GB) return 'gb';
      const e = rollUser(u, t);
      const key = kind + ':' + period;
      const pid = periodId(u, l, e, t);
      const x = e.extra[key];
      e.extra[key] = { period: pid, bytes: (x && x.period === pid ? x.bytes : 0) + Math.round(n * GIB) };
      // their request, if any, is answered
      delete requests[userId];
      dirty = true;
      return null;
    },

    /** A user's every current period back to nothing, the top-ups and warnings gone, a request answered; the history kept. → null or 'notFound'. */
    resetUsage(userId) {
      const t = now();
      const u = current().users.find((x) => x.id === userId);
      if (!u) return 'notFound';
      const e = rollUser(u, t);
      for (const k of KINDS) {
        const b = e[k];
        b.day = { period: b.day.period, bytes: 0 };
        b.month = { period: b.month.period, bytes: 0 };
        if (b.all) b.all = { period: 'all', bytes: 0, since: t };
      }
      e.extra = {};
      e.warned = {};
      owed.delete(u.id);
      delete requests[userId];
      dirty = true;
      return null;
    },

    /**
     * A signed-in user asks for more (the router's status page): `{ mac, at }`
     * (at: ms, default now). → true when it is a new request, false when one
     * of theirs is pending already (or there is no such user). Said in the log.
     */
    request(userId, r) {
      const u = current().users.find((x) => x.id === userId);
      if (!u || requests[userId]) return false;
      const a = isObj(r) ? r : {};
      requests[userId] = { at: whole(a.at) || now(), mac: normalizeMac(a.mac) || '' };
      dirty = true;
      log({ line: `Users: “${label(u)}” asks for a top-up (from the sign-in page)`, level: 'info' });
      return true;
    },

    /** The admin has seen a user's request and lets it go. → whether there was one. */
    dismissRequest(userId) {
      if (!requests[userId]) return false;
      delete requests[userId];
      dirty = true;
      return true;
    },

    /** The requests pending: { [userId]: { at, mac } }. */
    requests() { return JSON.parse(JSON.stringify(requests)); },

    /** No core any more: nothing is moving, nothing to hold to. */
    stop() { prev = null; prevOut = null; prevAt = 0; prevSum = 0; rates = {}; devRates = {}; devPrevAt = 0; live = null; owed.clear(); said.clear(); waitSaid = false; },

    /** bytes/s per user from the last tick: { [userId]: { up, down } }. */
    rates() { return Object.assign({}, rates); },

    /**
     * Each user as the window shows it: { [userId]: {
     *   bytes, period, since, until, quotaBytes, over,   the mirror cap's (model.js), as before — `over`:
     *                                                     held off entirely ('all')
     *   meters: [{ kind, period, bytes, capBytes, extraBytes, since, until, over, pct, action, down?, up? }],
     *           the six of each kind × day and month, and a 'none' one for each kind with such a limit;
     *           capBytes 0 / action null: no limit there
     *   hold, why, holdUntil,                             holdAt's
     *   history: [{ day, vpn, direct }],                  oldest first, the last HISTORY_DAYS days
     *   speed,                                            speedAt's, or null
     *   months: [{ key, from, to, vpn, direct }],         v1.40: oldest first, the last MONTHS_KEPT of
     *                                                     their months, the running one always there
     *                                                     (from / to: its span, ms; 0 when unknown)
     *   request }}                                        v1.40: { at } — a top-up asked for — or null
     * `until` the day the period renews (local midnight; 0 for one that never does).
     */
    usage() {
      const t = now();
      const lu = current();
      const from = historyFrom(t);
      const out = {};
      for (const u of lu.users) {
        const e = rollUser(u, t);
        const h = holdAt(u, t);
        const mirror = u.limits.find((l) => l.kind === 'total');
        const mp = mirror ? mirror.period : 'month';
        const mb = e.total[bucketOf(mp)];
        const meters = [];
        for (const k of KINDS) {
          for (const p of PERIODS) {
            const l = limitOf(u, k, p);
            if (p === 'none' && !l) continue;
            if (l) {
              const s = limitState(u, l, e, t);
              const row = { kind: k, period: p, bytes: s.bytes, capBytes: s.cap, extraBytes: s.extra, since: s.since, until: s.renews, over: s.over, pct: s.pct, action: l.action };
              if (l.action === 'slow') Object.assign(row, { down: l.down, up: l.up });
              meters.push(row);
            } else {
              const b = e[k][p];
              meters.push({ kind: k, period: p, bytes: b ? b.bytes : 0, capBytes: 0, extraBytes: 0, since: periodStart(p, t, u), until: periodEnd(p, t, u), over: false, pct: 0, action: null });
            }
          }
        }
        out[u.id] = {
          bytes: mb ? mb.bytes : 0,
          period: mp === 'none' ? 'all' : (mb ? mb.period : periodKey(mp, t, u)),
          since: mp === 'none' ? 0 : periodStart(mp, t, u),
          until: mp === 'none' ? 0 : periodEnd(mp, t, u),
          quotaBytes: mirror ? Math.round(mirror.gb * GIB) : 0,
          over: h.hold === 'all',
          meters,
          hold: h.hold, why: h.why, holdUntil: h.until,
          history: (hist[u.id] || []).filter((r) => r.day >= from).map((r) => ({ day: r.day, vpn: r.vpn, direct: r.direct })),
          speed: speedAt(u, t),
          months: monthsOf(u, t),
          request: requests[u.id] ? { at: requests[u.id].at } : null
        };
      }
      return out;
    },

    /** Forget a user's bytes (a user deleted): their buckets, days, months and request. */
    forget(userId) {
      if (store[userId] || hist[userId] || months[userId] || requests[userId]) dirty = true;
      delete store[userId];
      delete hist[userId];
      delete months[userId];
      delete requests[userId];
      owed.delete(userId);
      firstUse.delete(userId);
    },

    /** What to save under `lanUsersUsage` (the mirror cap's total, as older apps read it). */
    saved() { return savedOld(); },
    /** …under `lanUsersUsage2`. */
    savedUsage2() { return JSON.parse(JSON.stringify(store)); },
    /** …under `lanUsersHistory`, the days before the last HISTORY_DAYS left out. */
    savedHistory() { return savedHistory(); },
    /** …under `lanUsersMonths`. */
    savedMonths() { return savedMonths(); },
    /** …under `lanUsersRequests`. */
    savedRequests() { return JSON.parse(JSON.stringify(requests)); },
    /** What to save under `lanDeviceUsage` (the router's devices). */
    savedDevices() { return JSON.parse(JSON.stringify(devUsage)); },

    /**
     * The Users module's own backup (ipc.js lanusers:backup): every user's
     * buckets, days, months and pending request, as plain JSON —
     * { usage2, history, months, requests }. The devices' counts and the
     * moment's rates stay behind: they mean nothing on another router.
     */
    exportState() {
      return { usage2: JSON.parse(JSON.stringify(store)), history: savedHistory(), months: savedMonths(), requests: JSON.parse(JSON.stringify(requests)) };
    },

    /**
     * A backup's state taken in (ipc.js lanusers:restore), each part read as
     * the usage file is (junk dropped), for the users `o.ids` names (default:
     * every user in it). `o.mode`:
     *   'merge'   (default) per bucket the larger count of the same period —
     *             else the period that began later — and so for the top-ups;
     *             per day and per month the larger VPN and direct; a request
     *             pending here stays, else theirs. Restoring twice is
     *             restoring once.
     *   'replace' those users' state is the backup's (none there: none here).
     * → how many users it went through. The caller saves (flush).
     */
    importState(state, opts) {
      const s = isObj(state) ? state : {};
      const op = isObj(opts) ? opts : {};
      const replace = op.mode === 'replace';
      const theirs = { usage2: normalizeUsage2(s.usage2), history: normalizeHistory(s.history), months: normalizeMonths(s.months), requests: normalizeRequests(s.requests) };
      const ids = Array.isArray(op.ids)
        ? [...new Set(op.ids.filter((id) => typeof id === 'string' && /^[\w-]+$/.test(id)))]
        : [...new Set([].concat(...Object.values(theirs).map((bag) => Object.keys(bag))))];
      for (const id of ids) {
        if (replace) {
          for (const [bag, v] of [[store, theirs.usage2[id]], [hist, theirs.history[id]], [months, theirs.months[id]], [requests, theirs.requests[id]]]) {
            if (v === undefined) delete bag[id]; else bag[id] = v;
          }
          owed.delete(id);
        } else {
          if (theirs.usage2[id]) store[id] = store[id] ? mergeEntry(store[id], theirs.usage2[id]) : theirs.usage2[id];
          if (theirs.history[id]) hist[id] = mergeRows(hist[id], theirs.history[id], 'day').sort((a, b) => (a.day < b.day ? -1 : 1)).slice(-HISTORY_DAYS);
          if (theirs.months[id]) months[id] = mergeRows(months[id], theirs.months[id], 'key').sort((a, b) => monthStart(a.key) - monthStart(b.key)).slice(-MONTHS_KEPT);
          if (theirs.requests[id] && !requests[id]) requests[id] = theirs.requests[id];
        }
        firstUse.delete(id);
      }
      dirty = true;
      return ids.length;
    },
    get dirty() { return dirty; },
    dueForSave(at) { return dirty && ((at == null ? now() : at) - savedAt) >= SAVE_EVERY_MS; },
    markSaved(at) { dirty = false; savedAt = at == null ? now() : at; }
  };
}

module.exports = {
  SAVE_EVERY_MS, RETRY_MS, GAP_MS, HISTORY_DAYS, MONTHS_KEPT, DIRECT_PREFIX,
  userPeriod, capBytes, rollEntry, normalizeUsage, normalizeUsage2, normalizeHistory, normalizeMonths, normalizeRequests, normalizeDeviceUsage,
  userTotals, directTotals, counterSum,
  createLanUsersMeter
};
