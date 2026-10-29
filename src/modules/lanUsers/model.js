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
 *               transparent: { enabled, unassigned, sessionHours, portalPort },     // router only
 *               portal: { note, contact, requests },                                // router only (v1.40)
 *               shaping: { down, up, smooth } },                                    // router only (v1.40)
 *     users: [{ id, username, password, name, target, quotaGb, quotaPeriod, quotaCalendar?, quotaResetDay?,
 *               limits, routing, schedule, speed, speedHours,
 *               expiresAt, maxDevices, enabled,
 *               remember, priority, filter, voucher }],                             // v1.40
 *     devices: [{ mac, name, userId, blocked, remembered, at }] }                    // router only
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
 *
 * v1.40.0 — every new field optional on read: a record of before reads as the
 * defaults, nothing is migrated.
 *   remember  (default false) a device that signs in on the router's page as
 *             this user becomes theirs for good — a devices[] entry with
 *             `remembered: true` and `at` (when), as if the admin had picked
 *             it. Never for a voucher. An admin's own pick (or unpick) of the
 *             device replaces it.
 *   priority  'high' | 'normal' (default) | 'low' — the router's shaper, under
 *             the line speed of `config.shaping` (0 there: it cannot apply).
 *   filter    null, or { block, safeSearch, domains } — what this user may not
 *             reach: `block` some of FILTER_CATEGORIES (in that order), safe
 *             search on the engines that have it, and up to FILTER_DOMAINS_MAX
 *             names — 'example.com' (it and every name under it),
 *             'full:www.example.com' (that one name), 'keyword:casino' (any
 *             name holding it). null when it says nothing.
 *   voucher   null, or { batch, hours, activatedAt, madeAt? } — a one-time
 *             card. A voucher IS a user: its username and its password are the
 *             code ('XXXX-XXXX', VOUCHER_ALPHABET), its data amount (if any) a
 *             one-off total limit, maxDevices 1 unless the batch said more. It
 *             is unused until its first sign-in on the router or its first
 *             bytes anywhere; that moment is `activatedAt`, and `hours` > 0
 *             sets expiresAt then (ipc.js activateVoucher) — from there the
 *             expiry, the limits and the holds are every user's. `madeAt`: when
 *             its batch was made (the Vouchers tab's "made on").
 *   config.portal   what the router's status page shows the signed-in user:
 *             the admin's `note` (one line), how to reach him (`contact`), and
 *             whether they may ask for a top-up there (`requests`, default on).
 *   config.shaping  the router's line speed (`down` / `up` kbps, 0 = not
 *             said: priorities cannot apply) and `smooth` (default on: shape
 *             with tc when the router has it, else police as v1.39 did).
 */
const crypto = require('crypto');
const { domainToASCII } = require('url');
const { CALENDARS, cycleFields, resetDayOf } = require('../../main/capPeriods');

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);

/**
 * The ids the app writes (backup.js holds every imported id to the same shape)
 * — never an object's own machinery: the meter keys its bags by id, and
 * `bag['__proto__'] = …` sets a prototype (a restored backup could carry one).
 */
const ID = /^(?!(?:__proto__|constructor|prototype)$)[\w-]+$/;
/** What a SOCKS5 / HTTP client can send as a username, and what is easy to read out over the phone (the meter keys the core's counters by it: the same three names refused). */
const USERNAME = /^(?!(?:__proto__|constructor|prototype)$)[A-Za-z0-9._-]{1,32}$/;
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
/**
 * What a user's filter can block by category — each a geosite list the app's
 * geosite.dat has (xray.js maps them). No gambling: v2fly's lists have no
 * such category, and a key with no list behind it would promise a block that
 * never happens — a stored 'gambling' is dropped on read like any unknown key.
 */
const FILTER_CATEGORIES = ['adult', 'social', 'games', 'ads'];
const FILTER_DOMAINS_MAX = 200;
const DOMAIN_MAX = 253;
const PRIORITIES = ['high', 'normal', 'low'];
/**
 * A voucher's letters: no 0/O, 1/I/L — a card is read off paper and typed on
 * a phone. 31 of them, 8 to a code: about 8.5 × 10¹¹ codes (40 bits), and the
 * sign-in page limits the tries per device.
 */
const VOUCHER_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
const VOUCHER_HOURS_MAX = 8760;
const PORTAL_NOTE_MAX = 300;
const PORTAL_CONTACT_MAX = 64;

const DEFAULT_CONFIG = Object.freeze({
  proxy: Object.freeze({ enabled: false, port: 30820, httpPort: 30821 }),
  transparent: Object.freeze({ enabled: false, unassigned: 'login', sessionHours: 24, portalPort: 30822 }),
  portal: Object.freeze({ note: '', contact: '', requests: true }),
  shaping: Object.freeze({ down: 0, up: 0, smooth: true })
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

/** A line of text as stored (the portal's note and contact): a line break is a space, no other control character, at most `max`. */
function oneLine(v, max) {
  return typeof v === 'string' ? v.replace(/[\r\n\t\u2028\u2029]+/g, ' ').replace(/[\x00-\x1f\x7f]/g, '').trim().slice(0, max) : '';
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
  const po = isObj(c.portal) ? c.portal : {};
  const sh = isObj(c.shaping) ? c.shaping : {};
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
    },
    portal: {
      note: oneLine(po.note, PORTAL_NOTE_MAX),
      contact: oneLine(po.contact, PORTAL_CONTACT_MAX),
      requests: po.requests !== false
    },
    // a line speed that cannot be read is "not said" (0): priorities then stand aside, caps still apply
    shaping: { down: kbpsOf(sh.down), up: kbpsOf(sh.up), smooth: sh.smooth !== false }
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

/* ------------------------------ v1.40: the filter, the voucher ------------------------------ */

/**
 * One blocked name as stored, or null: lowercased and trimmed, one of
 *   'example.com'          it and every name under it ('domain:example.com' is read as this)
 *   'full:www.example.com' that one name
 *   'keyword:casino'       any name holding it
 * with letters, digits, '.', '-' and '_' after the prefix, 1–253 of them. A
 * pasted address gives its name ('https://www.example.com/a' → 'www.example.com',
 * '*.example.com' → 'example.com'), and a name in another script its punycode —
 * what the core matches against.
 */
function filterDomainOf(v) {
  if (typeof v !== 'string') return null;
  let s = v.trim().toLowerCase();
  let prefix = '';
  const m = /^(full|keyword|domain):\s*/.exec(s);
  if (m) { prefix = m[1] === 'domain' ? '' : m[1] + ':'; s = s.slice(m[0].length); }
  if (prefix !== 'keyword:') {
    s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, '').replace(/[/?#].*$/, '').replace(/:\d+$/, '').replace(/^\*?\./, '').replace(/\.$/, '');
    if (/[^\x00-\x7f]/.test(s)) s = domainToASCII(s) || '';
  }
  if (!s || s.length > DOMAIN_MAX || !/^[a-z0-9._-]+$/.test(s) || !/[a-z0-9]/.test(s)) return null;
  return prefix + s;
}

/** The blocked names as the window may send them: a list, or the text box's lines (and commas). null: neither. */
function domainLines(v) {
  if (Array.isArray(v)) return v;
  if (typeof v === 'string') return v.split(/[\r\n,]+/);
  return null;
}

/**
 * A user's filter as stored: { block, safeSearch, domains } — the categories
 * in FILTER_CATEGORIES' order, each once; names each once, in the order given,
 * at most FILTER_DOMAINS_MAX, a name that cannot be read left out — or null
 * when it blocks nothing.
 */
function normalizeFilter(f) {
  if (!isObj(f)) return null;
  const want = new Set(Array.isArray(f.block) ? f.block : []);
  const block = FILTER_CATEGORIES.filter((c) => want.has(c));
  const domains = [];
  const seen = new Set();
  for (const x of domainLines(f.domains) || []) {
    const d = filterDomainOf(x);
    if (!d || seen.has(d)) continue;
    seen.add(d);
    domains.push(d);
    if (domains.length >= FILTER_DOMAINS_MAX) break;
  }
  const safeSearch = f.safeSearch === true;
  return block.length || safeSearch || domains.length ? { block, safeSearch, domains } : null;
}

/** A user's voucher as stored, or null: its batch (an id; '' when a hand-edited store lost it), hours 0–8760, activatedAt ms (0 = unused), madeAt when known. */
function normalizeVoucher(v) {
  if (!isObj(v)) return null;
  const hours = Number(v.hours);
  const at = Number(v.activatedAt);
  const made = Number(v.madeAt);
  return Object.assign({
    batch: typeof v.batch === 'string' && ID.test(v.batch) ? v.batch : '',
    hours: Number.isFinite(hours) && hours > 0 ? Math.min(Math.round(hours), VOUCHER_HOURS_MAX) : 0,
    activatedAt: Number.isFinite(at) && at > 0 ? Math.round(at) : 0
  }, Number.isFinite(made) && made > 0 ? { madeAt: Math.round(made) } : {});
}

/**
 * One voucher code: 8 of VOUCHER_ALPHABET as 'XXXX-XXXX', each letter as
 * likely as the next (a byte at or above 248 — 8 × 31 — is thrown away, never
 * folded in). `randomBytesFn(n)` → a Buffer (crypto.randomBytes; a test's own).
 */
function voucherCode(randomBytesFn) {
  const rnd = typeof randomBytesFn === 'function' ? randomBytesFn : crypto.randomBytes;
  const n = VOUCHER_ALPHABET.length;
  const limit = 256 - (256 % n);
  let out = '';
  for (let round = 0; out.length < 8 && round < 64; round++) {
    for (const b of rnd(16)) if (b < limit && out.length < 8) out += VOUCHER_ALPHABET[b % n];
  }
  if (out.length < 8) throw new Error('voucher code: the random source gave nothing usable');
  return out.slice(0, 4) + '-' + out.slice(4);
}

/**
 * A code as someone typed it → 'XXXX-XXXX', or null when it cannot be one:
 * upper-cased, Persian / Arabic digits read as ASCII, spaces (and the
 * invisible marks a Persian keyboard adds) dropped, with or without the dash
 * (or a dash a phone made typographic). Only VOUCHER_ALPHABET's letters — a
 * code with an O or a 1 was never made.
 */
function normalizeCode(s) {
  if (typeof s !== 'string') return null;
  const c = s
    .replace(/[\u06f0-\u06f9]/g, (d) => String(d.charCodeAt(0) - 0x06f0))
    .replace(/[\u0660-\u0669]/g, (d) => String(d.charCodeAt(0) - 0x0660))
    .replace(/[\u2010-\u2015\u2212]/g, '-')
    .replace(/[\s\u00ad\u200b-\u200f\u202a-\u202e\u2066-\u2069]+/g, '')
    .toUpperCase();
  const m = /^([A-Z0-9]{4})-?([A-Z0-9]{4})$/.exec(c);
  if (!m) return null;
  for (const ch of m[1] + m[2]) if (!VOUCHER_ALPHABET.includes(ch)) return null;
  return m[1] + '-' + m[2];
}

/** A voucher batch's id: `vb-` and ten hex characters. */
function newBatchId() {
  return 'vb-' + crypto.randomBytes(5).toString('hex');
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
  const voucher = normalizeVoucher(u.voucher);
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
    enabled: u.enabled !== false,
    // v1.40 — a voucher never remembers a device: the card is for one sitting, not for good
    remember: u.remember === true && !voucher,
    priority: PRIORITIES.includes(u.priority) ? u.priority : 'normal',
    filter: normalizeFilter(u.filter),
    voucher
  };
}

/**
 * One device as stored. `remembered` (v1.40): it became its user's by a
 * sign-in of theirs (`remember`), at `at` — only while it is bound to someone.
 */
function normalizeDevice(d) {
  if (!isObj(d)) return null;
  const mac = normalizeMac(d.mac);
  if (!mac) return null;
  const userId = typeof d.userId === 'string' && ID.test(d.userId) ? d.userId : '';
  const remembered = d.remembered === true && !!userId;
  const at = Number(d.at);
  return {
    mac,
    name: cleanName(d.name),
    userId,
    blocked: d.blocked === true,
    remembered,
    at: remembered && Number.isFinite(at) && at > 0 ? Math.round(at) : 0
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
    if (d.userId && !ids.has(d.userId)) Object.assign(d, { userId: '', remembered: false, at: 0 });
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
 * and v1.40's:
 *   filter   (no detail: not an object, or safeSearch not true/false) | category (`block` not a list, or
 *            a category FILTER_CATEGORIES does not have) | domain (a name filterDomainOf cannot read) |
 *            domains (not a list nor text, or more than FILTER_DOMAINS_MAX names)
 *   priority (not one of PRIORITIES)
 *   voucher  shape | batch | hours | activatedAt | remember (a voucher never remembers a device)
 * A rate is whole kbps 1–10,000,000, blank or 0 for "unlimited that way", and
 * every rate entry limits at least one direction. A blank line among the
 * names is no name.
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
  if (u.filter != null) {
    const f = u.filter;
    if (!isObj(f) || (f.safeSearch != null && typeof f.safeSearch !== 'boolean')) return err('filter');
    if (f.block != null && (!Array.isArray(f.block) || f.block.some((c) => !FILTER_CATEGORIES.includes(c)))) return err('filter', 'category');
    if (f.domains != null) {
      const lines = domainLines(f.domains);
      if (!lines) return err('filter', 'domains');
      const names = lines.filter((x) => !(typeof x === 'string' && !x.trim()));
      if (names.some((x) => !filterDomainOf(x))) return err('filter', 'domain');
      if (new Set(names.map(filterDomainOf)).size > FILTER_DOMAINS_MAX) return err('filter', 'domains');
    }
  }
  if (u.priority != null && !PRIORITIES.includes(u.priority)) return err('priority');
  if (u.voucher != null) {
    const v = u.voucher;
    if (!isObj(v)) return err('voucher', 'shape');
    // '' is what normalizeVoucher keeps of a batch a hand-edited store lost: the user stays editable
    if (typeof v.batch !== 'string' || (v.batch !== '' && !ID.test(v.batch))) return err('voucher', 'batch');
    if (v.hours != null && v.hours !== '' && count(v.hours, VOUCHER_HOURS_MAX, -1) < 0) return err('voucher', 'hours');
    if (v.activatedAt != null && !(Number.isInteger(Number(v.activatedAt)) && Number(v.activatedAt) >= 0)) return err('voucher', 'activatedAt');
    if (u.remember === true) return err('voucher', 'remember');
  }
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

/* ------------------------------ vouchers: what a card is now ------------------------------ */

/** A voucher (a one-time card) rather than a person's account. */
function isVoucher(u) {
  return !!u && isObj(u.voucher);
}

/**
 * Where a voucher stands at `now` → 'unused' (never signed in, no bytes) |
 * 'active' | 'expired' (its time is up — or the admin's expiry, used or not)
 * | 'used' (its one-off total limit is spent); null for a user who is no
 * voucher. "Spent" is the meter's word, so this takes what activeUsers takes:
 * `o.usage` (meter.js usage(): its one-off total meter `over`) — exact — or
 * `o.over` (the ids held off entirely), which says spent for a voucher with
 * such a limit that is held for any reason but a switch the admin turned off.
 * `now` may be that options object itself ({ now, usage, over }).
 */
function voucherState(u, now, o) {
  let t = now;
  let opts = isObj(o) ? o : {};
  if (isObj(now)) { opts = now; t = now.now; }
  if (typeof t !== 'number' || !Number.isFinite(t)) t = Date.now();
  const n = isObj(u) && Array.isArray(u.limits) && isObj(u.voucher) && 'activatedAt' in u.voucher ? u : normalizeUser(u);
  if (!n || !isVoucher(n)) return null;
  if (isExpired(n, t)) return 'expired';
  if (!(n.voucher.activatedAt > 0)) return 'unused';
  if (!n.limits.some((l) => l && l.kind === 'total' && l.period === 'none')) return 'active';
  const e = isObj(opts.usage) ? opts.usage[n.id] : null;
  if (isObj(e) && Array.isArray(e.meters)) return e.meters.some((m) => isObj(m) && m.kind === 'total' && m.period === 'none' && m.over === true) ? 'used' : 'active';
  if (Array.isArray(opts.over)) return opts.over.includes(n.id) && n.enabled !== false ? 'used' : 'active';
  return isObj(e) && e.over === true && e.why === 'total' ? 'used' : 'active';
}

module.exports = {
  DEFAULT_CONFIG, USERNAME, PASSWORD, PERIODS, KINDS, ACTIONS, CALENDARS, UNASSIGNED, ID,
  ROUTING_MODES, PROFILE_PREFIX, QUOTA_MAX_GB, KBPS_MAX, LIMITS_MAX, SPEED_HOURS_MAX, NAME_MAX,
  FILTER_CATEGORIES, FILTER_DOMAINS_MAX, PRIORITIES, VOUCHER_ALPHABET, VOUCHER_HOURS_MAX, PORTAL_NOTE_MAX, PORTAL_CONTACT_MAX,
  normalizeLanUsers, normalizeConfig, normalizeUser, normalizeDevice, normalizeMac, portOf, targetOk, cleanName,
  normalizeLimit, normalizeLimits, mirrorOf, normalizeWindow, normalizeSpeedHours, ratesOf, routingOf, profileIdOf, windowState,
  normalizeFilter, filterDomainOf, normalizeVoucher, voucherCode, normalizeCode, isVoucher, voucherState, newBatchId,
  newUserId, validateUser, validateUserDetail, credentialsOk, isExpired, inSchedule, isOver, isActive, activeUsers, targetsOf
};
