'use strict';
/**
 * Users on the router, transparent mode: the decisions, pure. From the
 * module's store (`store.lanUsers`: config, users, devices — contract §B), the
 * portal's sign-ins, the devices on the LAN now and each user's usage this
 * period, decide for every MAC:
 *
 *   - whom it belongs to — the admin's choice in the devices list (for good),
 *     else a sign-in on the portal (for its session's hours);
 *   - what the gateway does with it — dropped, let through (assigned or
 *     signed in), sent around the tunnel (a user whose config is "direct"),
 *     or left to the unassigned-device policy (the gate: the sign-in page, or
 *     nothing);
 *   - which user's inbound its packets ride (the rule-set of that user's
 *     loopback inbound, by the device's addresses — each one pinned to the
 *     device's MAC in the gateway's table, so no other device can borrow it);
 *   - how fast it may go (its user's speed now, policed in the table).
 *
 * One inbound per USER, not per config (v1.39): what a user sends direct is
 * counted on their own direct outbound, their routing and their holds are
 * theirs — so two users on one server still ride two inbounds.
 *
 * A user is ACTIVE when enabled, not expired, inside their allowed hours and
 * not held off entirely by a limit — the meter's hold 'all' (meter.js
 * holdAt), with its reason. A device whose user is not active is HELD: in
 * login mode it simply is not let through, so it meets the gate and the
 * portal tells it why ("outside your allowed hours — back at 08:00", "this
 * account's data is used up") — and when the hold lifts it is let through
 * again without a new sign-in; with no portal to explain, it is dropped. A
 * hold of one class only ('vpn' or 'direct') is the core's to apply: the
 * device stays let through.
 */
const nodeNet = require('net');

const MAC_RE = /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/;
const DEFAULT_TRANSPARENT = { enabled: false, unassigned: 'login', sessionHours: 24, portalPort: 30822 };
/** Why a user is held off entirely (the meter's hold 'all'): what the portal can say. */
const HOLD_WHY = new Set(['disabled', 'expired', 'schedule', 'total', 'vpn', 'direct']);
/** A speed in kbps the table can police: a whole number, at most this (model.js KBPS_MAX). */
const KBPS_MAX = 10000000;

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const str = (v) => (v == null ? '' : String(v).trim());
const macOf = (s) => { const m = str(s).toLowerCase(); return MAC_RE.test(m) ? m : null; };

/**
 * What the router reads of `store.lanUsers`, defensively — the model's own
 * normalizer (model.js) owns the shape; a field missing or wrong here falls
 * back to the contract's default rather than failing the gateway.
 */
function readLanUsers(raw) {
  const r = isObj(raw) ? raw : {};
  const cfg = isObj(r.config) ? r.config : {};
  const t = isObj(cfg.transparent) ? cfg.transparent : {};
  const hours = Number(t.sessionHours);
  const port = Number(t.portalPort);
  const transparent = {
    enabled: t.enabled === true,
    unassigned: ['login', 'allow', 'block'].includes(t.unassigned) ? t.unassigned : DEFAULT_TRANSPARENT.unassigned,
    sessionHours: Number.isFinite(hours) && hours > 0 ? Math.min(hours, 24 * 365) : DEFAULT_TRANSPARENT.sessionHours,
    portalPort: Number.isInteger(port) && port > 0 && port < 65536 ? port : DEFAULT_TRANSPARENT.portalPort
  };
  const users = (Array.isArray(r.users) ? r.users : []).filter(u => isObj(u) && typeof u.id === 'string' && u.id);
  const devices = [];
  for (const d of Array.isArray(r.devices) ? r.devices : []) {
    const mac = isObj(d) ? macOf(d.mac) : null;
    if (!mac || devices.some(x => x.mac === mac)) continue;
    devices.push({ mac, name: str(d.name), userId: str(d.userId), blocked: d.blocked === true });
  }
  return { transparent, users, devices };
}

/** Is transparent mode wanted: the module installed (settings.modules.lanUsers) and the mode on. */
function transparentWanted(settings, lu) {
  const mods = settings && isObj(settings.modules) ? settings.modules : {};
  return !!mods.lanUsers && !!(lu && lu.transparent && lu.transparent.enabled);
}

/**
 * Why a user is held off entirely right now — 'disabled' | 'expired' |
 * 'schedule' (outside their allowed hours) | 'total' | 'vpn' | 'direct' (a
 * limit, meter.js holdAt: 'vpn' when nothing of theirs goes direct, 'direct'
 * when everything does) — or null when they are not. `usage` is the meter's
 * usage(): `{ [userId]: { hold, why, over } }`; a hold of one class ('vpn' /
 * 'direct') is not one here — the core blocks that class, the device stays
 * let through. A meter of before (one cap, `over` alone): 'over'.
 */
function inactiveReason(user, { now = Date.now(), usage = {} } = {}) {
  if (!user || user.enabled === false) return 'disabled';
  const exp = Number(user.expiresAt);
  if (Number.isFinite(exp) && exp > 0 && exp <= now) return 'expired';
  const u = isObj(usage) ? usage[user.id] : null;
  if (u && u.hold === 'all') return HOLD_WHY.has(u.why) ? u.why : 'over';
  if (u && u.over && !u.hold) return 'over';
  return null;
}

/** A user's config, as the router reads it. */
const targetOf = (user) => str(user && user.target);

/**
 * The users the gateway gives a loopback inbound of their own: every one
 * whose config is not "block", whether or not a device of theirs is here now
 * — a sign-in must never change the shape of the running core or tunnel —
 * by id, sorted, so the same users give the same `lu-tp-<n>` numbering every
 * time. A user whose config is "direct" has one too (their devices go around
 * the tunnel by the table's `direct` set; the inbound waits for a config).
 */
function routedUsers(lu) {
  const out = [];
  for (const u of (lu && lu.users) || []) {
    if (targetOf(u) !== 'block' && !out.includes(u.id)) out.push(u.id);
  }
  return out.sort();
}

/** A user's speed as the table polices it: { down, up } kbps, each a whole number 0..KBPS_MAX (0: not limited that way), or null. */
function rateOf(speed) {
  if (!isObj(speed)) return null;
  const k = (v) => { const n = Math.round(Number(v)); return Number.isFinite(n) && n > 0 ? Math.min(n, KBPS_MAX) : 0; };
  const down = k(speed.down), up = k(speed.up);
  return down || up ? { down, up } : null;
}

/** `192.168.1.23` → `192.168.1.23/32`, a v6 → `/128`; junk → null. */
function hostCidr(ip) {
  const s = str(ip).toLowerCase();
  const fam = nodeNet.isIP(s);
  return fam === 4 ? `${s}/32` : fam === 6 ? `${s}/128` : null;
}

/**
 * Whose each address is, from a scan (devices.js rows): Map ip → mac. An
 * address a running lease names is the lease's device's — the router handed
 * it out, and dnsmasq hands no address to two devices at once — however the
 * neighbour table reads now: that table says only who answered for the
 * address last, and a device that takes another's address answers for it. An
 * address no lease names (a static one, a v6) is the device's the neighbour
 * table has at it — it keeps one entry per address. Two rows claiming one
 * address the same way: the first in the scan's order.
 *
 * One owner per address, read by everything that goes by address: the
 * rule-sets (which config), the down counters (whose bytes) and the pins in
 * the gateway's table (router/nft.js: whose MAC may send from it).
 */
function addressOwners(scan) {
  const out = new Map();
  const rows = Array.isArray(scan) ? scan.filter(r => r && r.mac) : [];
  for (const r of rows) for (const ip of Array.isArray(r.leased) ? r.leased : []) if (!out.has(ip)) out.set(ip, r.mac);
  for (const r of rows) for (const ip of Array.isArray(r.ips) ? r.ips : []) if (!out.has(ip)) out.set(ip, r.mac);
  return out;
}

/**
 * Whom each MAC belongs to: { [mac]: { userId, via: 'admin' | 'login', until? } }.
 * The admin's choice wins over a sign-in; a sign-in counts while its session
 * runs and its user still exists.
 */
function bindingsOf(lu, sessions, now) {
  const ids = new Set(((lu && lu.users) || []).map(u => u.id));
  const out = {};
  for (const d of (lu && lu.devices) || []) if (d.userId && ids.has(d.userId)) out[d.mac] = { userId: d.userId, via: 'admin' };
  for (const [mac, s] of Object.entries(isObj(sessions) ? sessions : {})) {
    if (out[mac] || !isObj(s) || !ids.has(s.userId) || !(Number(s.until) > now)) continue;
    out[mac] = { userId: s.userId, via: 'login', until: Number(s.until) };
  }
  return out;
}

/**
 * Everything the gateway needs for this moment:
 *   nft      — router/nft.js's description (blocked, allowed, authorized with
 *              its remaining seconds, direct, the pinned addresses, the
 *              speeds, counters, the portal);
 *   ruleSets — { [tag]: [cidr…] } for every entry of `tp` (the inbounds the
 *              running gateway has: [{ tag, userId }], one per user), empty
 *              lists included, so a file that had devices is emptied when
 *              they go;
 *   bound    — bindingsOf;
 *   held     — { [mac]: reason } for devices whose user is held off entirely.
 * `scan`: devices.js rows; `usage`: the meter's usage() (each user's hold);
 * `speeds`: the meter's speeds() — { [userId]: { down, up } } kbps; `portal`:
 * the LAN address and port the sign-in page listens on, or null. (The
 * gateway's own exclusions need nothing here: the gate lets `bypass_macs`
 * through in the table itself.)
 *
 * The speeds (`nft.rates`: [{ mac, ips, down, up }]): every device let
 * through whose user has a speed now, with the addresses its download is
 * policed by — its own, as the pins have them.
 *
 * The pins (`nft.ipmac`: [{ mac, ips }]): every address of every device that
 * belongs to a user — whatever the table then does with it (let through,
 * around the tunnel, held, blocked) — bound to that device's MAC. The
 * rule-sets pick a device's config by its source address and the down
 * counters charge its user by its address, so without them a device the gate
 * lets through by its own MAC could take another's address and ride that
 * user's config and cap. From the same addresses as the rule-sets, in the
 * same decision: a new lease moves both at once. A device that is nobody's is
 * pinned to nothing — nothing changes for it.
 */
function decide({ lu, sessions = {}, scan = [], usage = {}, speeds = {}, now = Date.now(), tp = [], portal = null } = {}) {
  const users = new Map(((lu && lu.users) || []).map(u => [u.id, u]));
  const recs = new Map(((lu && lu.devices) || []).map(d => [d.mac, d]));
  const bound = bindingsOf(lu, sessions, now);
  const unassigned = (lu && lu.transparent && lu.transparent.unassigned) || 'login';
  const login = unassigned === 'login';
  const tagOf = new Map();                  // userId → the tag of their inbound
  const ruleSets = {};
  for (const t of Array.isArray(tp) ? tp : []) {
    if (!t || typeof t.tag !== 'string') continue;
    ruleSets[t.tag] = [];
    if (typeof t.userId === 'string' && t.userId && !tagOf.has(t.userId)) tagOf.set(t.userId, t.tag);
  }
  // a device's addresses: those it uses that are its own (an address another device holds the lease of is not)
  const owner = addressOwners(scan);
  const ipsOf = new Map((scan || []).map(r => [r.mac, (Array.isArray(r.ips) ? r.ips : []).filter(ip => owner.get(ip) === r.mac)]));
  const blocked = [], allowed = [], authorized = [], direct = [], rates = [];
  const held = {};
  const macs = [...new Set([...recs.keys(), ...Object.keys(bound)])].sort();
  for (const mac of macs) {
    const rec = recs.get(mac);
    if (rec && rec.blocked) { blocked.push(mac); continue; }
    const b = bound[mac];
    if (!b) continue;                       // unassigned: the policy decides (the gate)
    const user = users.get(b.userId);
    const why = inactiveReason(user, { now, usage });
    if (why) { held[mac] = why; if (!login) blocked.push(mac); continue; }
    const target = targetOf(user);
    if (target === 'block') { blocked.push(mac); continue; }
    if (b.via === 'admin') allowed.push(mac);
    else authorized.push({ mac, timeoutS: Math.ceil((b.until - now) / 1000) });
    // its user's speed, both ways — around the tunnel too: the table polices what it forwards
    const rate = rateOf(isObj(speeds) ? speeds[user.id] : null);
    if (rate) rates.push(Object.assign({ mac, ips: (ipsOf.get(mac) || []).slice() }, rate));
    if (target === 'direct') { direct.push(mac); continue; }
    const tag = tagOf.get(user.id);
    if (!tag) continue;                     // no inbound of theirs in the running gateway (a user made since, a raw JSON config): the current connection
    for (const ip of ipsOf.get(mac) || []) {
      const c = hostCidr(ip);
      if (c && !ruleSets[tag].includes(c)) ruleSets[tag].push(c);
    }
  }
  // every address of a user's device pinned to its MAC (`macs` is sorted, and every bound MAC is in it)
  const ipmac = macs.filter(mac => bound[mac] && (ipsOf.get(mac) || []).length).map(mac => ({ mac, ips: ipsOf.get(mac).slice() }));
  // a counter for every device the router knows: assigned, signed in, or just here
  const known = [...new Set([...macs, ...(scan || []).map(r => r.mac).filter(Boolean)])].sort();
  const counters = known.map(mac => ({ mac, ips: (ipsOf.get(mac) || []).slice() }));
  const nft = { unassigned, blocked, allowed, authorized, direct, ipmac, rates, counters, portal: login && portal ? portal : null };
  return { nft, ruleSets, bound, held };
}

/**
 * A stable key for the nft description: the same devices in the same sets is
 * the same table, though the sessions' remaining seconds count down — so a
 * tick reloads the table only when something changed (`untilOf`: mac → the
 * session's end, which does not move).
 */
function nftKey(nft, untilOf = {}) {
  return JSON.stringify(Object.assign({}, nft, { authorized: (nft.authorized || []).map(a => [a.mac, untilOf[a.mac] || 0]) }));
}

/** sing-box's source format for one inbound's devices; version 1, which every sing-box from 1.8 reads. */
function ruleSetText(cidrs) {
  const list = (Array.isArray(cidrs) ? cidrs : []).filter(c => typeof c === 'string' && c);
  return JSON.stringify({ version: 1, rules: list.length ? [{ source_ip_cidr: list }] : [] }, null, 2) + '\n';
}

/**
 * The portal's verdict on a sign-in, pure: { ok: true, user } or
 * { ok: false, code, max?, until?, calendar? }. `checkPassword(given, stored)`
 * is the constant-time compare (portal.js). Codes: 'bad' (no such user or
 * wrong password — one answer for both), a hold's reason (inactiveReason —
 * with `until`, when it lifts by itself), 'assigned' (the admin gave this
 * device to another user), 'maxDevices'.
 */
/**
 * What a phone types, as the stored account reads it. A sign-in on the
 * router's page is typed on a phone (the owner's was refused with the
 * username and password he had set): a keyboard capitalises the first letter (the
 * page asks it not to — not every keyboard or captive-portal browser
 * listens), a Persian keyboard's number row types ۰–۹ (some Arabic-Indic
 * ٠–٩), and one may slip in a zero-width joiner or a direction mark. None is
 * what the admin meant, and in a password box none of them shows. Both sides
 * go through the same fold (NFKC, those digits as 0–9, the invisible marks
 * gone), so a password typed exactly as stored still matches; a username is
 * matched with its case aside too — model.js already keeps «Ali» and «ali»
 * from being two users.
 */
const INVISIBLE = /[​-‏‪-‮⁦-⁩﻿]/g;
function typed(s) {
  return String(s == null ? '' : s).normalize('NFKC')
    .replace(/[۰-۹]/g, d => String(d.charCodeAt(0) - 0x06f0))
    .replace(/[٠-٩]/g, d => String(d.charCodeAt(0) - 0x0660))
    .replace(INVISIBLE, '');
}
const nameKey = (s) => typed(s).trim().toLowerCase();

/**
 * A sign-in on the portal: { ok: true, user } or { ok: false, code } — the
 * page's message. A refusal for the name or the password carries `why`
 * ('user' | 'password') for the router's own log alone: the page says the
 * same for both.
 */
function judgeSignIn({ lu, sessions = {}, usage = {}, now = Date.now(), mac, username, password, checkPassword }) {
  const name = nameKey(username);
  const users = (lu && lu.users) || [];
  const user = users.find(u => name && nameKey(u.username) === name) || null;
  // the compare runs whether or not the name exists: its time says nothing about which it was
  const match = checkPassword(typed(password), user ? typed(user.password) : '\0no-such-user\0');
  if (!user) return { ok: false, code: 'bad', why: 'user' };
  if (!match) return { ok: false, code: 'bad', why: 'password' };
  const why = inactiveReason(user, { now, usage });
  if (why) {
    // when the hold lifts (the page says "back at 08:00"), in the user's own calendar
    const u = isObj(usage) ? usage[user.id] : null;
    const until = u && u.hold === 'all' && Number(u.holdUntil) > now ? Number(u.holdUntil) : 0;
    return Object.assign({ ok: false, code: why }, until ? { until, calendar: str(user.quotaCalendar) } : {});
  }
  const bound = bindingsOf(lu, sessions, now);
  const mine = bound[mac];
  if (mine && mine.via === 'admin' && mine.userId !== user.id) return { ok: false, code: 'assigned' };
  const max = Number(user.maxDevices);
  if (Number.isInteger(max) && max > 0) {
    const others = Object.entries(bound).filter(([m, b]) => m !== mac && b.userId === user.id).length;
    if (others >= max) return { ok: false, code: 'maxDevices', max };
  }
  return { ok: true, user };
}

module.exports = {
  DEFAULT_TRANSPARENT, HOLD_WHY,
  readLanUsers, transparentWanted, inactiveReason, targetOf, routedUsers, rateOf, addressOwners, bindingsOf, decide, nftKey, ruleSetText, hostCidr, typed, judgeSignIn
};
