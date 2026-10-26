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
 *   - which per-user config its packets ride (the rule-set of that config's
 *     loopback inbound, by the device's addresses — each one pinned to the
 *     device's MAC in the gateway's table, so no other device can borrow it).
 *
 * A user is ACTIVE when enabled, not expired and not over its cap this period
 * — the contract's definition (model.js activeUsers), restated here because
 * the router decides per device and needs the reason too. A device whose user
 * is not active is HELD: in login mode it simply is not let through, so it
 * meets the gate and the portal tells it why ("this account's data is used up
 * this period") — and at the new period it is let through again without a
 * new sign-in; with no portal to explain, it is dropped.
 */
const nodeNet = require('net');

const MAC_RE = /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/;
const DEFAULT_TRANSPARENT = { enabled: false, unassigned: 'login', sessionHours: 24, portalPort: 30822 };
/** Targets the gateway carries out itself, with no inbound of their own: the current connection, around the tunnel, nothing. */
const OWN_TARGETS = new Set(['', 'direct', 'block']);

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
 * Why a user is not active right now — 'disabled' | 'expired' | 'over' — or
 * null when it is. `usage` is the meter's `{ [userId]: { over } }`.
 */
function inactiveReason(user, { now = Date.now(), usage = {} } = {}) {
  if (!user || user.enabled === false) return 'disabled';
  const exp = Number(user.expiresAt);
  if (Number.isFinite(exp) && exp > 0 && exp <= now) return 'expired';
  const u = isObj(usage) ? usage[user.id] : null;
  if (u && u.over) return 'over';
  return null;
}

/** A user's config, as the router reads it. */
const targetOf = (user) => str(user && user.target);

/**
 * The configs the gateway gives an inbound of their own: every distinct one
 * a user has, whether or not a device rides it now — a sign-in must never
 * change the shape of the running core or tunnel — sorted, so the same users
 * give the same list (and the same `lu-tp-<n>` numbering) every time.
 */
function routedTargets(lu) {
  const out = new Set();
  for (const u of (lu && lu.users) || []) {
    const t = targetOf(u);
    if (!OWN_TARGETS.has(t)) out.add(t);
  }
  return [...out].sort();
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
 *              its remaining seconds, direct, the pinned addresses, counters,
 *              the portal);
 *   ruleSets — { [tag]: [cidr…] } for every entry of `tp` (the inbounds the
 *              running gateway has: [{ tag, target }]), empty lists included,
 *              so a file that had devices is emptied when they go;
 *   bound    — bindingsOf;
 *   held     — { [mac]: reason } for devices whose user is not active.
 * `scan`: devices.js rows; `portal`: the LAN address and port the sign-in
 * page listens on, or null. (The gateway's own exclusions need nothing here:
 * the gate lets `bypass_macs` through in the table itself.)
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
function decide({ lu, sessions = {}, scan = [], usage = {}, now = Date.now(), tp = [], portal = null } = {}) {
  const users = new Map(((lu && lu.users) || []).map(u => [u.id, u]));
  const recs = new Map(((lu && lu.devices) || []).map(d => [d.mac, d]));
  const bound = bindingsOf(lu, sessions, now);
  const unassigned = (lu && lu.transparent && lu.transparent.unassigned) || 'login';
  const login = unassigned === 'login';
  const tagOf = new Map();
  const ruleSets = {};
  for (const t of Array.isArray(tp) ? tp : []) {
    if (!t || typeof t.tag !== 'string') continue;
    ruleSets[t.tag] = [];
    if (!tagOf.has(t.target)) tagOf.set(t.target, t.tag);
  }
  // a device's addresses: those it uses that are its own (an address another device holds the lease of is not)
  const owner = addressOwners(scan);
  const ipsOf = new Map((scan || []).map(r => [r.mac, (Array.isArray(r.ips) ? r.ips : []).filter(ip => owner.get(ip) === r.mac)]));
  const blocked = [], allowed = [], authorized = [], direct = [];
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
    if (target === 'direct') { direct.push(mac); continue; }
    const tag = tagOf.get(target);
    if (!tag) continue;                     // the current connection — or a config the running gateway has no inbound for yet
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
  const nft = { unassigned, blocked, allowed, authorized, direct, ipmac, counters, portal: login && portal ? portal : null };
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
 * { ok: false, code, max? }. `checkPassword(given, stored)` is the
 * constant-time compare (portal.js). Codes: 'bad' (no such user or wrong
 * password — one answer for both), 'disabled' | 'expired' | 'over',
 * 'assigned' (the admin gave this device to another user), 'maxDevices'.
 */
function judgeSignIn({ lu, sessions = {}, usage = {}, now = Date.now(), mac, username, password, checkPassword }) {
  const name = str(username);
  const users = (lu && lu.users) || [];
  const user = users.find(u => str(u.username) === name && name) || null;
  // the compare runs whether or not the name exists: its time says nothing about which it was
  const match = checkPassword(String(password == null ? '' : password), user ? String(user.password == null ? '' : user.password) : '\0no-such-user\0');
  if (!user || !match) return { ok: false, code: 'bad' };
  const why = inactiveReason(user, { now, usage });
  if (why) return { ok: false, code: why };
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
  DEFAULT_TRANSPARENT, OWN_TARGETS,
  readLanUsers, transparentWanted, inactiveReason, routedTargets, addressOwners, bindingsOf, decide, nftKey, ruleSetText, hostCidr, judgeSignIn
};
