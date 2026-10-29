'use strict';
/**
 * Users and devices («کاربران», module `lanUsers`): the owner's own home or
 * office — people on his router, or on his PC's Windows hotspot, sign in with a
 * username and password, each with data limits and a config of their own.
 *
 * This file is the record and what it means, nothing else: the store's
 * `lanUsers` key (NOT a setting — it is data, like the servers), normalized;
 * one user checked before it is saved; which users may use the proxy right now.
 * The config the core runs is xray.js's, the counting meter.js's, the channels
 * ipc.js's.
 *
 *   { config: { proxy: { enabled, port, httpPort },
 *               transparent: { enabled, unassigned, sessionHours, portalPort } },   // router only
 *     users: [{ id, username, password, name, target, quotaGb, quotaPeriod, quotaCalendar?, quotaResetDay?,
 *               limits, routing, schedule, speed, speedHours,
 *               expiresAt, maxDevices, enabled }],
 *     devices: [{ mac, name, userId, blocked }] }                                    // router only
 *
 * `password` is stored as given: the core's SOCKS/HTTP accounts need it in its
 * config (as LAN sharing's ports are there), and the admin can see and copy it.
 * It is never logged. `target`: '' = whatever this machine is connected through
 * now; a server or group id; `chain:<id>`; 'direct'; 'block'. `expiresAt` ms,
 * 0 = never; `maxDevices` 0 = any.
 *
 * Data limits (v1.39.0) — `limits`: [{ kind, period, gb, action, down?, up? }]
 *   kind    'total' (everything), 'vpn' (what rides a config), 'direct' (what
 *           leaves this machine or the router as it is — the user's own direct
 *           routes, or everything for a user whose target is 'direct');
 *   period  'day', 'month' (the user's month: the Gregorian one from the 1st
 *           unless `quotaCalendar` 'jalali' (the Persian month) or
 *           `quotaResetDay` 2–31 (the day it renews on) says otherwise — one
 *           cycle per user, src/main/capPeriods.js), 'none' (one amount that
 *           never renews: "10 GB, then stop", counted from when it was set);
 *   gb      > 0, at most QUOTA_MAX_GB;
 *   action  'cut' — over it, that kind stops (meter.js holds: a VPN limit stops
 *           only the VPN, direct routes keep working, the owner's choice); or
 *           'slow' — over it, the user's speed drops to `down` / `up` kbps until
 *           the period renews ("the first 2 GB at full speed, then slower").
 * At most one limit per (kind, period), kept in the canonical order (total,
 * vpn, direct × day, month, none). `quotaGb` / `quotaPeriod` stay written as
 * a MIRROR of the first 'total' limit (0 / 'month' when there is none): an
 * older app or router reading the same store still enforces something sane;
 * a record of before (quotaGb and no `limits`) becomes that one limit.
 *
 * `routing`: '' (as before — everything to the user's target), 'global' (the
 * same, said out loud), 'bypass-ir' (private ranges and Iranian sites direct,
 * the rest to the target), 'profile:<id>' (one of the app's routing profiles:
 * src/main/routingProfiles.js, its rules over the user's target — xray.js
 * userRouteRules says how).
 *
 * `schedule`: null (always allowed) or { days: [0..6] (0 = Sunday, as JS
 * getDay), from: 'HH:MM', to: 'HH:MM' } — the allowed hours, local time.
 * from === to is all day on those days; to < from runs overnight, and the part
 * after midnight belongs to the day it started on.
 *
 * Speed (the router only — Xray has no per-user rate): `speed` null or
 * { down, up } kbps (0 in a direction = unlimited), the user's base cap;
 * `speedHours`: up to SPEED_HOURS_MAX windows { days, from, to, down, up } (the
 * schedule's shape) whose rates apply while they are on. meter.js speedOf()
 * takes the lowest of everything in force.
 */
const crypto = require('crypto');
const { CALENDARS, cycleFields, resetDayOf } = require('../../main/capPeriods');

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);

/** The ids the app writes (backup.js holds every imported id to the same shape). */
const ID = /^[\w-]+$/;
/** What a SOCKS5 / HTTP client can send as a username, and what is easy to read out over the phone. */
const USERNAME = /^[A-Za-z0-9._-]{1,32}$/;
/**
 * 4–64 printable ASCII characters, no spaces. SOCKS5 sends bytes and HTTP
 * Basic a base64 of them, and clients disagree on how a non-ASCII password is
 * encoded — a Persian one typed on a phone would pass in one app and fail in
 * the next. A colon is fine: Basic auth splits at the first one, and the
 * username can never hold one.
 */
const PASSWORD = /^[\x21-\x7e]{4,64}$/;
const MAC = /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/;
const PERIODS = ['day', 'month', 'none'];
const KINDS = ['total', 'vpn', 'direct'];
const ACTIONS = ['cut', 'slow'];
const UNASSIGNED = ['login', 'allow', 'block'];
const ROUTING_MODES = ['', 'global', 'bypass-ir'];
const PROFILE_PREFIX = 'profile:';
const NAME_MAX = 64;
const QUOTA_MAX_GB = 1000000;
const DEVICES_MAX = 1000;
const LIMITS_MAX = KINDS.length * PERIODS.length;
/** A rate is whole kbps, 1 kbps to 10 Gbps. */
const KBPS_MAX = 10000000;
const SPEED_HOURS_MAX = 4;
const HHMM = /^([01]\d|2[0-3]):([0-5]\d)$/;

const DEFAULT_CONFIG = Object.freeze({
  proxy: Object.freeze({ enabled: false, port: 30820, httpPort: 30821 }),
  transparent: Object.freeze({ enabled: false, unassigned: 'login', sessionHours: 24, portalPort: 30822 })
});

/** A TCP port 1–65535 as a number, or null. */
function portOf(v) {
  if (typeof v !== 'number' && typeof v !== 'string') return null;
  if (typeof v === 'string' && !/^\d+$/.test(v.trim())) return null;
  const n = Number(v);
  return Number.isInteger(n) && n >= 1 && n <= 65535 ? n : null;
}

/** A display name: a string, no control characters, at most NAME_MAX. */
function cleanName(v) {
  return typeof v === 'string' ? v.replace(/[\x00-\x1f\x7f]/g, '').trim().slice(0, NAME_MAX) : '';
}

/** A routing target in a shape the app writes, else null. */
function targetOk(t) {
  if (t === '' || t === 'direct' || t === 'block') return true;
  if (typeof t !== 'string') return false;
  return t.indexOf('chain:') === 0 ? ID.test(t.slice('chain:'.length)) : ID.test(t);
}

/** aa:bb:cc:dd:ee:ff, lowercase, from `aa-bb-…` or `AA:BB:…`; null for anything else. */
function normalizeMac(v) {
  if (typeof v !== 'string') return null;
  const m = v.trim().toLowerCase().replace(/-/g, ':');
  return MAC.test(m) ? m : null;
}

function normalizeConfig(raw) {
  const c = isObj(raw) ? raw : {};
  const p = isObj(c.proxy) ? c.proxy : {};
  const t = isObj(c.transparent) ? c.transparent : {};
  const hours = Number(t.sessionHours);
  return {
    proxy: {
      enabled: p.enabled === true,
      port: portOf(p.port) || DEFAULT_CONFIG.proxy.port,
      // 0: no HTTP proxy, SOCKS5 only
      httpPort: p.httpPort === 0 || p.httpPort === '0' ? 0 : (portOf(p.httpPort) || DEFAULT_CONFIG.proxy.httpPort)
    },
    transparent: {
      enabled: t.enabled === true,
      unassigned: UNASSIGNED.includes(t.unassigned) ? t.unassigned : DEFAULT_CONFIG.transparent.unassigned,
      sessionHours: Number.isInteger(hours) && hours >= 1 && hours <= 720 ? hours : DEFAULT_CONFIG.transparent.sessionHours,
      portalPort: portOf(t.portalPort) || DEFAULT_CONFIG.transparent.portalPort
    }
  };
}

/** A whole number in [0, max], else `def`. */
function count(v, max, def) {
  const n = Number(v);
  return Number.isInteger(n) && n >= 0 && n <= max ? n : def;
}

/* ------------------------------ limits, routing, hours, speed ------------------------------ */

/** A GB amount as stored: > 0, three decimals, at most QUOTA_MAX_GB; 0 for anything else. */
function gbOf(v) {
  const gb = Number(v);
  return Number.isFinite(gb) && gb > 0 ? Math.min(Math.round(gb * 1000) / 1000, QUOTA_MAX_GB) || 0 : 0;
}

/** A rate as stored: whole kbps, at most KBPS_MAX; 0 (unlimited) for anything else. */
function kbpsOf(v) {
  const n = Number(v);
  return Number.isFinite(n) && n >= 1 ? Math.min(Math.round(n), KBPS_MAX) : 0;
}

/** { down, up } kbps as stored, or null when neither direction is limited. */
function ratesOf(v) {
  if (!isObj(v)) return null;
  const down = kbpsOf(v.down);
  const up = kbpsOf(v.up);
  return down || up ? { down, up } : null;
}

/** A limit's place in the canonical order (kind, then period). */
const limitRank = (l) => KINDS.indexOf(l.kind) * PERIODS.length + PERIODS.indexOf(l.period);

/**
 * One limit as stored, or null. A 'slow' limit without a rate is a 'cut' one:
 * a damaged record never lets anyone past a limit at full speed.
 */
function normalizeLimit(l) {
  if (!isObj(l) || !KINDS.includes(l.kind) || !PERIODS.includes(l.period)) return null;
  const gb = gbOf(l.gb);
  if (!gb) return null;
  const rates = l.action === 'slow' ? ratesOf(l) : null;
  return rates ? { kind: l.kind, period: l.period, gb, action: 'slow', down: rates.down, up: rates.up } : { kind: l.kind, period: l.period, gb, action: 'cut' };
}

/** A list of limits as stored: each of its type, one per (kind, period) — the first — in the canonical order. */
function normalizeLimits(list) {
  const out = [];
  const seen = new Set();
  for (const x of Array.isArray(list) ? list : []) {
    const l = normalizeLimit(x);
    if (!l || seen.has(l.kind + ':' + l.period)) continue;
    seen.add(l.kind + ':' + l.period);
    out.push(l);
  }
  return out.sort((a, b) => limitRank(a) - limitRank(b));
}

/**
 * The user's first 'total' limit as the two fields of before — { quotaGb,
 * quotaPeriod } — or 0 / 'month' when there is none.
 */
function mirrorOf(limits) {
  const t = (Array.isArray(limits) ? limits : []).find((l) => l && l.kind === 'total');
  return t ? { quotaGb: t.gb, quotaPeriod: t.period } : { quotaGb: 0, quotaPeriod: 'month' };
}

/** 'HH:MM' from 'H:MM' or 'HH:MM' (00:00–23:59), else null. */
function timeOf(v) {
  const m = typeof v === 'string' ? /^\s*(\d{1,2}):(\d{2})\s*$/.exec(v) : null;
  if (!m) return null;
  const s = m[1].padStart(2, '0') + ':' + m[2];
  return HHMM.test(s) ? s : null;
}

/**
 * A window ({ days, from, to }) as stored, or null when it is not an object.
 * Days are the distinct 0–6 given, in order; a time that cannot be read leaves
 * no day at all — a damaged window never allows more than it said.
 */
function normalizeWindow(w) {
  if (!isObj(w)) return null;
  const days = [...new Set((Array.isArray(w.days) ? w.days : []).map(Number).filter((d) => Number.isInteger(d) && d >= 0 && d <= 6))].sort((a, b) => a - b);
  const from = timeOf(w.from);
  const to = timeOf(w.to);
  if (!from || !to) return { days: [], from: '00:00', to: '00:00' };
  return { days, from, to };
}

/** `routing` as stored: one of the modes, or 'profile:<id>'; '' for anything else. */
function routingOf(v) {
  if (typeof v !== 'string') return '';
  if (ROUTING_MODES.includes(v)) return v;
  return v.indexOf(PROFILE_PREFIX) === 0 && ID.test(v.slice(PROFILE_PREFIX.length)) ? v : '';
}

/** The profile id a `routing` names, or null. */
function profileIdOf(routing) {
  return typeof routing === 'string' && routing.indexOf(PROFILE_PREFIX) === 0 && ID.test(routing.slice(PROFILE_PREFIX.length)) ? routing.slice(PROFILE_PREFIX.length) : null;
}

/** The speed windows as stored: at most SPEED_HOURS_MAX, each a window with a rate. */
function normalizeSpeedHours(list) {
  const out = [];
  for (const x of Array.isArray(list) ? list : []) {
    const w = normalizeWindow(x);
    const r = ratesOf(x);
    if (!w || !r) continue;
    out.push(Object.assign(w, r));
    if (out.length >= SPEED_HOURS_MAX) break;
  }
  return out;
}

const minutesOf = (hhmm) => Number(hhmm.slice(0, 2)) * 60 + Number(hhmm.slice(3, 5));

/**
 * A window at `now` (ms, local time): { on, next, end } — whether it is on,
 * when it next begins (ms; 0 never), and when the one on now ends (0 when
 * off). null is always on. A window begins on each of its days at `from` and
 * ends at `to` — the next day's when it runs overnight, the day's end (the
 * next midnight) when from === to.
 */
function windowState(w, now) {
  if (!w) return { on: true, next: 0, end: 0 };
  if (!Array.isArray(w.days) || !w.days.length || !HHMM.test(w.from) || !HHMM.test(w.to)) return { on: false, next: 0, end: 0 };
  const d = new Date(now);
  const [y, m, date, dow] = [d.getFullYear(), d.getMonth(), d.getDate(), d.getDay()];
  const f = minutesOf(w.from);
  const t = minutesOf(w.to);
  // by the calendar, never by adding hours: a clock change moves nothing
  const at = (k, min) => new Date(y, m, date + k, Math.floor(min / 60), min % 60).getTime();
  let on = false, end = 0, next = 0;
  // a window that began yesterday may still be on (overnight); one a week ahead is the furthest the next can be
  for (let k = -1; k <= 7; k++) {
    if (!w.days.includes(((dow + k) % 7 + 7) % 7)) continue;
    const start = f === t ? at(k, 0) : at(k, f);
    const stop = f === t ? at(k + 1, 0) : (t > f ? at(k, t) : at(k + 1, t));
    if (start <= now && now < stop) { on = true; end = Math.max(end, stop); }
    if (start > now && (!next || start < next)) next = start;
  }
  return { on, next, end: on ? end : 0 };
}

/**
 * One user as stored: every field of its type — the month's calendar and
 * renew day only when they are not the Gregorian 1st. A record with no id we
 * would write is not a user (null). A target in a shape the app never writes
 * is `block` — a damaged record never widens anyone's way out.
 */
function normalizeUser(u) {
  if (!isObj(u) || typeof u.id !== 'string' || !ID.test(u.id)) return null;
  const expires = Number(u.expiresAt);
  // a record of before: its one cap is its one limit
  const limits = Array.isArray(u.limits) ? normalizeLimits(u.limits)
    : (gbOf(u.quotaGb) ? [{ kind: 'total', period: PERIODS.includes(u.quotaPeriod) ? u.quotaPeriod : 'month', gb: gbOf(u.quotaGb), action: 'cut' }] : []);
  const mirror = mirrorOf(limits);
  return {
    id: u.id,
    username: typeof u.username === 'string' ? u.username.trim() : '',
    password: typeof u.password === 'string' ? u.password : '',
    name: cleanName(u.name),
    target: targetOk(u.target == null ? '' : u.target) ? (u.target == null ? '' : u.target) : 'block',
    quotaGb: mirror.quotaGb,
    quotaPeriod: mirror.quotaPeriod,
    ...cycleFields(u),
    limits,
    routing: routingOf(u.routing),
    schedule: u.schedule == null ? null : normalizeWindow(u.schedule),
    speed: ratesOf(u.speed),
    speedHours: normalizeSpeedHours(u.speedHours),
    expiresAt: Number.isFinite(expires) && expires > 0 ? Math.round(expires) : 0,
    maxDevices: count(u.maxDevices, DEVICES_MAX, 0),
    enabled: u.enabled !== false
  };
}

function normalizeDevice(d) {
  if (!isObj(d)) return null;
  const mac = normalizeMac(d.mac);
  if (!mac) return null;
  return {
    mac,
    name: cleanName(d.name),
    userId: typeof d.userId === 'string' && ID.test(d.userId) ? d.userId : '',
    blocked: d.blocked === true
  };
}

/**
 * The store's `lanUsers`, every part of its type. Users without a usable
 * username are dropped, and a second user by the same id or the same username
 * (case aside — "Ali" and "ali" are one person on the phone) goes: only a
 * hand-edited store has either, and the core would let only one of them in. A
 * device bound to a user who is gone is unbound.
 */
function normalizeLanUsers(raw) {
  const r = isObj(raw) ? raw : {};
  const users = [];
  const ids = new Set();
  const names = new Set();
  for (const x of Array.isArray(r.users) ? r.users : []) {
    const u = normalizeUser(x);
    if (!u || !USERNAME.test(u.username) || ids.has(u.id) || names.has(u.username.toLowerCase())) continue;
    ids.add(u.id);
    names.add(u.username.toLowerCase());
    users.push(u);
  }
  const devices = [];
  const macs = new Set();
  for (const x of Array.isArray(r.devices) ? r.devices : []) {
    const d = normalizeDevice(x);
    if (!d || macs.has(d.mac)) continue;
    macs.add(d.mac);
    if (d.userId && !ids.has(d.userId)) d.userId = '';
    devices.push(d);
  }
  return { config: normalizeConfig(r.config), users, devices };
}

/** A fresh user id: `usr-` and ten hex characters. */
function newUserId() {
  return 'usr-' + crypto.randomBytes(5).toString('hex');
}

/* ------------------------------ checking a user before it is saved ------------------------------ */

const blank = (v) => v == null || v === '' || v === 0 || v === '0';
/** A rate as the window sends it: blank (unlimited) or whole kbps 1–KBPS_MAX. */
const rateOk = (v) => blank(v) || ((typeof v === 'number' || (typeof v === 'string' && /^\s*\d+\s*$/.test(v))) && Number.isInteger(Number(v)) && Number(v) >= 1 && Number(v) <= KBPS_MAX);
/** { down, up }: each blank or a rate, and at least one of them a rate. */
const ratesOk = (v) => isObj(v) && rateOk(v.down) && rateOk(v.up) && !(blank(v.down) && blank(v.up));

/** A window as the window sends it → the part that is wrong ('shape' | 'days' | 'from' | 'to'), or null. */
function windowError(w) {
  if (!isObj(w)) return 'shape';
  if (!Array.isArray(w.days) || !w.days.length || w.days.some((d) => !Number.isInteger(d) || d < 0 || d > 6)) return 'days';
  if (typeof w.from !== 'string' || !HHMM.test(w.from)) return 'from';
  if (typeof w.to !== 'string' || !HHMM.test(w.to)) return 'to';
  return null;
}

/**
 * One user as it is about to be saved (the raw input, before normalizing),
 * against the others → the first thing wrong with it, or null:
 * { error, detail? } — `error` a key the window words in its own language:
 *   username | usernameTaken | password | name | target | quota | quotaPeriod | quotaCalendar |
 *   quotaResetDay | limits | routing | schedule | speed | expiresAt | maxDevices
 * and `detail` which part, for the new ones:
 *   limits   list (not a list, or more than nine) | kind | period | gb | duplicate | action
 *   routing  mode | profile
 *   schedule shape | days | from | to
 *   speed    base (`speed`'s rates) | hours (not a list, more than four, an entry that is no object) |
 *            window (an entry's days / from / to) | rate (an entry's rates) | slow (a 'slow' limit's rates)
 * A rate is whole kbps 1–10,000,000, blank or 0 for "unlimited that way", and
 * every rate entry limits at least one direction.
 */
function validateUserDetail(user, others) {
  const u = isObj(user) ? user : {};
  const err = (error, detail) => (detail ? { error, detail } : { error });
  const username = typeof u.username === 'string' ? u.username.trim() : '';
  if (!USERNAME.test(username)) return err('username');
  const lower = username.toLowerCase();
  if ((Array.isArray(others) ? others : []).some((o) => o && o.id !== u.id && typeof o.username === 'string' && o.username.trim().toLowerCase() === lower)) return err('usernameTaken');
  if (typeof u.password !== 'string' || !PASSWORD.test(u.password)) return err('password');
  if (u.name != null && (typeof u.name !== 'string' || u.name.trim().length > NAME_MAX)) return err('name');
  if (u.target != null && !targetOk(u.target)) return err('target');
  if (u.quotaGb != null && u.quotaGb !== '') {
    const gb = Number(u.quotaGb);
    if (!Number.isFinite(gb) || gb < 0 || gb > QUOTA_MAX_GB) return err('quota');
  }
  if (u.quotaPeriod != null && !PERIODS.includes(u.quotaPeriod)) return err('quotaPeriod');
  if (u.quotaCalendar != null && !CALENDARS.includes(u.quotaCalendar)) return err('quotaCalendar');
  if (u.quotaResetDay != null && u.quotaResetDay !== '' && resetDayOf(u.quotaResetDay) === null) return err('quotaResetDay');
  if (u.limits != null) {
    if (!Array.isArray(u.limits) || u.limits.length > LIMITS_MAX) return err('limits', 'list');
    const seen = new Set();
    for (const l of u.limits) {
      if (!isObj(l) || !KINDS.includes(l.kind)) return err('limits', 'kind');
      if (!PERIODS.includes(l.period)) return err('limits', 'period');
      const gb = typeof l.gb === 'string' && !l.gb.trim() ? NaN : Number(l.gb);
      if (!Number.isFinite(gb) || gb <= 0 || gb > QUOTA_MAX_GB) return err('limits', 'gb');
      if (seen.has(l.kind + ':' + l.period)) return err('limits', 'duplicate');
      seen.add(l.kind + ':' + l.period);
      if (l.action != null && !ACTIONS.includes(l.action)) return err('limits', 'action');
      if (l.action === 'slow' && !ratesOk(l)) return err('speed', 'slow');
    }
  }
  if (u.routing != null) {
    if (typeof u.routing !== 'string') return err('routing', 'mode');
    if (!ROUTING_MODES.includes(u.routing)) {
      if (u.routing.indexOf(PROFILE_PREFIX) !== 0) return err('routing', 'mode');
      if (!profileIdOf(u.routing)) return err('routing', 'profile');
    }
  }
  if (u.schedule != null) {
    const w = windowError(u.schedule);
    if (w) return err('schedule', w);
  }
  if (u.speed != null && !ratesOk(u.speed)) return err('speed', 'base');
  if (u.speedHours != null) {
    if (!Array.isArray(u.speedHours) || u.speedHours.length > SPEED_HOURS_MAX) return err('speed', 'hours');
    for (const h of u.speedHours) {
      if (!isObj(h)) return err('speed', 'hours');
      if (windowError(h)) return err('speed', 'window');
      if (!ratesOk(h)) return err('speed', 'rate');
    }
  }
  if (u.expiresAt != null && u.expiresAt !== '') {
    const e = Number(u.expiresAt);
    if (!Number.isInteger(e) || e < 0) return err('expiresAt');
  }
  if (u.maxDevices != null && u.maxDevices !== '' && count(u.maxDevices, DEVICES_MAX, -1) < 0) return err('maxDevices');
  return null;
}

/** validateUserDetail's error alone (the key of before), or null. */
function validateUser(user, others) {
  const r = validateUserDetail(user, others);
  return r ? r.error : null;
}

/* ------------------------------ who may use it now ------------------------------ */

/** Credentials the core can take, as validateUser holds them (a damaged store may carry others). */
function credentialsOk(u) {
  return !!u && USERNAME.test(u.username) && typeof u.password === 'string' && PASSWORD.test(u.password);
}

/** Expired at `now`: an expiry set, and reached. */
function isExpired(u, now) {
  return !!u && u.expiresAt > 0 && u.expiresAt <= now;
}

/** Inside the allowed hours at `now` (no schedule: always). */
function inSchedule(u, now) {
  return !u || !u.schedule || windowState(u.schedule, now).on;
}

/**
 * Held off entirely this period. `usage`: meter.js's usage() — { [userId]:
 * { over } } — or `over`: the ids held (what the meter hands the build).
 */
function isOver(u, usage, over) {
  if (!u) return false;
  if (Array.isArray(over) && over.includes(u.id)) return true;
  const e = isObj(usage) ? usage[u.id] : null;
  return !!(e && e.over === true);
}

/** May use the proxy right now: enabled, not expired, inside its hours, not held, with credentials the core can take. */
function isActive(u, o) {
  const opts = o || {};
  const now = typeof opts.now === 'number' ? opts.now : Date.now();
  return !!u && u.enabled !== false && credentialsOk(u) && !isExpired(u, now) && inSchedule(u, now) && !isOver(u, opts.usage, opts.over);
}

/** The users of `lu` (raw or normalized) who may use the proxy right now, in stored order. */
function activeUsers(lu, o) {
  const n = normalizeLanUsers(lu);
  return n.users.filter((u) => isActive(u, o));
}

/** Every distinct target the users of `lu` name, in order of first use ('' — the current connection — included). */
function targetsOf(lu) {
  const out = [];
  for (const u of normalizeLanUsers(lu).users) if (!out.includes(u.target)) out.push(u.target);
  return out;
}

module.exports = {
  DEFAULT_CONFIG, USERNAME, PASSWORD, PERIODS, KINDS, ACTIONS, CALENDARS, UNASSIGNED, ID,
  ROUTING_MODES, PROFILE_PREFIX, QUOTA_MAX_GB, KBPS_MAX, LIMITS_MAX, SPEED_HOURS_MAX,
  normalizeLanUsers, normalizeConfig, normalizeUser, normalizeDevice, normalizeMac, portOf, targetOk,
  normalizeLimit, normalizeLimits, mirrorOf, normalizeWindow, normalizeSpeedHours, ratesOf, routingOf, profileIdOf, windowState,
  newUserId, validateUser, validateUserDetail, credentialsOk, isExpired, inSchedule, isOver, isActive, activeUsers, targetsOf
};
