'use strict';
/**
 * Users and devices («کاربران», module `lanUsers`): the owner's own home or
 * office — people on his router, or on his PC's Windows hotspot, sign in with a
 * username and password, each with a data cap and a config of their own.
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
 *               expiresAt, maxDevices, enabled }],
 *     devices: [{ mac, name, userId, blocked }] }                                    // router only
 *
 * `password` is stored as given: the core's SOCKS/HTTP accounts need it in its
 * config (as LAN sharing's ports are there), and the admin can see and copy it.
 * It is never logged. `target`: '' = whatever this machine is connected through
 * now; a server or group id; `chain:<id>`; 'direct'; 'block'. `quotaGb` 0 = no
 * cap; `quotaPeriod` 'day' | 'month' | 'none' — 'none' with a cap is one amount
 * that never renews ("10 GB, then stop"); a month is the Gregorian one from the
 * 1st unless `quotaCalendar` 'jalali' (the Persian month) or `quotaResetDay`
 * 2–31 (the day it renews on) says otherwise — each written only when it does
 * (src/main/capPeriods.js); `expiresAt` ms, 0 = never; `maxDevices` 0 = any.
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
const UNASSIGNED = ['login', 'allow', 'block'];
const NAME_MAX = 64;
const QUOTA_MAX_GB = 1000000;
const DEVICES_MAX = 1000;

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

/**
 * One user as stored: every field of its type — the month's calendar and
 * renew day only when they are not the Gregorian 1st, so a user saved before
 * they existed is stored exactly as it was. A record with no id we would
 * write is not a user (null). A target in a shape the app never writes is
 * `block` — a damaged record never widens anyone's way out.
 */
function normalizeUser(u) {
  if (!isObj(u) || typeof u.id !== 'string' || !ID.test(u.id)) return null;
  const gb = Number(u.quotaGb);
  const expires = Number(u.expiresAt);
  return {
    id: u.id,
    username: typeof u.username === 'string' ? u.username.trim() : '',
    password: typeof u.password === 'string' ? u.password : '',
    name: cleanName(u.name),
    target: targetOk(u.target == null ? '' : u.target) ? (u.target == null ? '' : u.target) : 'block',
    quotaGb: Number.isFinite(gb) && gb > 0 ? Math.min(Math.round(gb * 1000) / 1000, QUOTA_MAX_GB) : 0,
    quotaPeriod: PERIODS.includes(u.quotaPeriod) ? u.quotaPeriod : 'month',
    ...cycleFields(u),
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

/**
 * One user as it is about to be saved (the raw input, before normalizing),
 * against the others → the first thing wrong with it as a key the window words
 * in its own language, or null:
 *   username | usernameTaken | password | name | target | quota | quotaPeriod | quotaCalendar |
 *   quotaResetDay | expiresAt | maxDevices
 */
function validateUser(user, others) {
  const u = isObj(user) ? user : {};
  const username = typeof u.username === 'string' ? u.username.trim() : '';
  if (!USERNAME.test(username)) return 'username';
  const lower = username.toLowerCase();
  if ((Array.isArray(others) ? others : []).some((o) => o && o.id !== u.id && typeof o.username === 'string' && o.username.trim().toLowerCase() === lower)) return 'usernameTaken';
  if (typeof u.password !== 'string' || !PASSWORD.test(u.password)) return 'password';
  if (u.name != null && (typeof u.name !== 'string' || u.name.trim().length > NAME_MAX)) return 'name';
  if (u.target != null && !targetOk(u.target)) return 'target';
  if (u.quotaGb != null && u.quotaGb !== '') {
    const gb = Number(u.quotaGb);
    if (!Number.isFinite(gb) || gb < 0 || gb > QUOTA_MAX_GB) return 'quota';
  }
  if (u.quotaPeriod != null && !PERIODS.includes(u.quotaPeriod)) return 'quotaPeriod';
  if (u.quotaCalendar != null && !CALENDARS.includes(u.quotaCalendar)) return 'quotaCalendar';
  if (u.quotaResetDay != null && u.quotaResetDay !== '' && resetDayOf(u.quotaResetDay) === null) return 'quotaResetDay';
  if (u.expiresAt != null && u.expiresAt !== '') {
    const e = Number(u.expiresAt);
    if (!Number.isInteger(e) || e < 0) return 'expiresAt';
  }
  if (u.maxDevices != null && u.maxDevices !== '' && count(u.maxDevices, DEVICES_MAX, -1) < 0) return 'maxDevices';
  return null;
}

/** Credentials the core can take, as validateUser holds them (a damaged store may carry others). */
function credentialsOk(u) {
  return !!u && USERNAME.test(u.username) && typeof u.password === 'string' && PASSWORD.test(u.password);
}

/** Expired at `now`: an expiry set, and reached. */
function isExpired(u, now) {
  return !!u && u.expiresAt > 0 && u.expiresAt <= now;
}

/**
 * Over its cap this period. `usage`: meter.js's usage() — { [userId]: { over } }
 * — or `over`: the ids over theirs (what the meter hands the build).
 */
function isOver(u, usage, over) {
  if (!u) return false;
  if (Array.isArray(over) && over.includes(u.id)) return true;
  const e = isObj(usage) ? usage[u.id] : null;
  return !!(e && e.over === true);
}

/** May use the proxy right now: enabled, not expired, not over its cap, with credentials the core can take. */
function isActive(u, o) {
  const opts = o || {};
  const now = typeof opts.now === 'number' ? opts.now : Date.now();
  return !!u && u.enabled !== false && credentialsOk(u) && !isExpired(u, now) && !isOver(u, opts.usage, opts.over);
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
  DEFAULT_CONFIG, USERNAME, PASSWORD, PERIODS, CALENDARS, UNASSIGNED, ID,
  normalizeLanUsers, normalizeConfig, normalizeUser, normalizeDevice, normalizeMac, portOf, targetOk,
  newUserId, validateUser, credentialsOk, isExpired, isOver, isActive, activeUsers, targetsOf
};
