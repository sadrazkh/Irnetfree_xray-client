'use strict';
/**
 * Users and devices (module `lanUsers`): what each user carried this period,
 * their data cap, how fast they are moving right now — modelled on the
 * multi-internet quota (src/main/multiWanMeter.js), whose periods it shares.
 *
 * Fed from the stats poller's tick — the same /debug/vars read the live meter
 * and the usage totals come from — by the core's per-user counters:
 * `stats.user[<username>] = { uplink, downlink }` (xray.js says where the core
 * keeps them). A username is mapped to its user by the build the running core
 * was made from (built()), then by the users as they are now — a user renamed
 * while connected is still counted until the reload. The router's transparent
 * mode adds what each device carried (nft counters, by MAC) to its user:
 * addBytes() / tickDevices().
 *
 * Bytes are kept per user per period — `{ [userId]: { period, bytes } }`, the
 * period 'YYYY-MM' for a month, 'YYYY-MM-DD' for a day, local time, and 'all'
 * for a cap that never renews (quotaPeriod 'none') — saved by the caller in the
 * usage file beside the per-config totals, lazily (ipc.js).
 *
 * A user over their cap is in overIds(): the build leaves them out of the
 * accounts (and the router's transparent mode blocks their devices). When the
 * users the running core lets in are no longer the ones it should — a cap
 * reached, an expiry passed, a new period begun — the meter says why in the
 * log, once per user and core, and asks the caller's reload once, retrying no
 * sooner than RETRY_MS if it did not happen. (Every other difference — an
 * edit — is the caller's to apply: ipc.js asks the same reload.)
 *
 * Desktop (main.js) and router (service.js) alike: no store, no timers, no
 * Electron — the caller hands in its own.
 */
const { GIB, periodKey, periodStart, periodEnd } = require('../../main/multiWanMeter');
const { normalizeLanUsers, isActive, isExpired, normalizeMac } = require('./model');

const SAVE_EVERY_MS = 30000;
const RETRY_MS = 15000;
/** A tick this long after the last one is a new core: the old one's last reading says nothing about it. */
const GAP_MS = 20000;

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const num = (v) => (typeof v === 'number' && Number.isFinite(v) && v > 0 ? v : 0);

/** The period a user's bytes count in at `now`: by the day, by the month, or — a cap that never renews — 'all'. */
function userPeriod(u, now) {
  if (u && u.quotaPeriod === 'none' && u.quotaGb > 0) return 'all';
  return periodKey(u && u.quotaPeriod === 'day' ? 'day' : 'month', now);
}

/** A user's cap in bytes; 0 = none. A cap with no period ('none') is one amount for good. */
function capBytes(u) {
  const gb = Number(u && u.quotaGb);
  return Number.isFinite(gb) && gb > 0 ? Math.round(gb * GIB) : 0;
}

/**
 * An entry moved to the period `key`: the same one as it was; a day of the
 * month it now counts by keeps its bytes (they were this month's too); a cap
 * made one for good keeps what was counted so far; anything else starts from
 * nothing.
 */
function rollEntry(entry, key) {
  if (!entry) return { period: key, bytes: 0 };
  if (entry.period === key) return entry;
  if (key === 'all' || String(entry.period).startsWith(key + '-')) return { period: key, bytes: entry.bytes };
  return { period: key, bytes: 0 };
}

/** What was saved, each entry of its type; junk dropped. */
function normalizeUsage(raw) {
  const out = {};
  if (!isObj(raw)) return out;
  for (const [id, e] of Object.entries(raw)) {
    if (!/^[\w-]+$/.test(id) || !isObj(e) || typeof e.period !== 'string' || !/^(\d{4}-\d{2}(-\d{2})?|all)$/.test(e.period)) continue;
    const bytes = Number(e.bytes);
    out[id] = { period: e.period, bytes: Number.isFinite(bytes) && bytes > 0 ? Math.round(bytes) : 0 };
  }
  return out;
}

/** The router's devices' saved bytes, by MAC; junk dropped. */
function normalizeDeviceUsage(raw) {
  const out = {};
  if (!isObj(raw)) return out;
  for (const [k, e] of Object.entries(raw)) {
    const mac = normalizeMac(k);
    if (!mac || !isObj(e) || typeof e.period !== 'string' || !/^(\d{4}-\d{2}(-\d{2})?|all)$/.test(e.period)) continue;
    const bytes = Number(e.bytes);
    out[mac] = { period: e.period, bytes: Number.isFinite(bytes) && bytes > 0 ? Math.round(bytes) : 0 };
  }
  return out;
}

/** Each username's bytes as the running core counts them (totals since it started): { [username]: { up, down } }. */
function userTotals(vars) {
  const raw = vars && vars.stats && vars.stats.user;
  const out = {};
  if (!isObj(raw)) return out;
  for (const [name, c] of Object.entries(raw)) if (name && isObj(c)) out[name] = { up: num(c.uplink), down: num(c.downlink) };
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

/**
 * @param {object} o
 *   usage        what the usage file held under `lanUsersUsage`
 *   deviceUsage  …and under `lanDeviceUsage` (the router's devices, by MAC)
 *   users()    the store's lanUsers as they are now (raw or normalized) —
 *                caps and periods are read live, so a cap changed while
 *                connected counts at once
 *   canReload()  connected and quiet: no connect, recovery or disconnect in flight
 *   pending()    the keys waiting for Apply (a reload would take some of them
 *                live behind the user's back — the cap waits, as multiWan's does)
 *   reload(why)  → Promise: the caller's reload (one queue)
 *   log({ line, level }), notify({ name, capGb, period }) (optional)
 *   now()        ms epoch (a test hands in its own clock)
 */
function createLanUsersMeter(o) {
  const now = typeof o.now === 'function' ? o.now : () => Date.now();
  const log = typeof o.log === 'function' ? o.log : () => {};
  let usage = normalizeUsage(o.usage);
  let dirty = false;
  let savedAt = now();
  let prev = null;          // the running core's last reading per username
  let prevAt = 0;
  let prevSum = 0;
  let rates = {};           // bytes/s per user id
  let live = null;          // what the running core was built with (built()); null: no users in it
  let pendingBuild = null;  // what the build that is starting was made with
  let lastTry = -Infinity;
  let reloading = false;
  let waitSaid = false;
  const said = new Set();
  const devPrev = new Map();   // mac → the device counters' last totals { up, down } (tickDevices)
  let devPrevAt = 0;
  let devUsage = normalizeDeviceUsage(o.deviceUsage);   // mac → { period, bytes }
  let devRates = {};           // mac → bytes/s

  const current = () => normalizeLanUsers(typeof o.users === 'function' ? o.users() : null);

  /** The period a device counts in: its user's, or by the month. */
  const devicePeriod = (lu, mac, t) => {
    const d = lu.devices.find((x) => x.mac === mac);
    const u = d && d.userId ? lu.users.find((x) => x.id === d.userId) : null;
    return userPeriod(u, t);
  };

  /** Every user moved to the period they count in at `t`. */
  function roll(lu, t) {
    for (const u of lu.users) {
      const was = usage[u.id];
      const next = rollEntry(was, userPeriod(u, t));
      if (next === was) continue;
      usage[u.id] = next;
      if (was) dirty = true;   // a period that ended is worth a write; a new empty entry is not
    }
  }

  /** The users over their cap at `t`, in stored order. */
  function overOf(lu, t) {
    roll(lu, t);
    return lu.users.filter((u) => { const cap = capBytes(u); return cap > 0 && usage[u.id] && usage[u.id].bytes >= cap; }).map((u) => u.id);
  }

  function add(u, bytes, t) {
    if (!u || !(bytes > 0)) return;
    const e = rollEntry(usage[u.id], userPeriod(u, t));
    usage[u.id] = { period: e.period, bytes: e.bytes + bytes };
    dirty = true;
  }

  /** The running core lets in other users than it should, for a cap, an expiry or a new period: say why, and reload — once. */
  function settle(lu, t) {
    if (!live) return;
    const over = overOf(lu, t);
    const want = lu.users.filter((u) => isActive(u, { now: t, over })).map((u) => u.id);
    if (sameSet(want, live.active)) { waitSaid = false; return; }
    const byId = new Map(lu.users.map((u) => [u.id, u]));
    const label = (u) => u.name || u.username;
    let ours = false;   // a difference the meter is here for (an edit is ipc.js's to apply)
    for (const id of live.active) {
      const u = byId.get(id);
      if (!u || want.includes(id)) continue;
      if (over.includes(id)) {
        ours = true;
        if (said.has('cap:' + id)) continue;
        said.add('cap:' + id);
        const when = u.quotaPeriod === 'day' ? 'today' : (u.quotaPeriod === 'none' ? 'in all' : 'this month');
        const until = u.quotaPeriod === 'day' ? 'until tomorrow' : (u.quotaPeriod === 'none' ? 'until the cap is raised' : 'until the 1st of next month');
        log({ line: `Users: “${label(u)}” reached their cap (${u.quotaGb} GB ${when}) — off ${until}`, level: 'warn' });
        if (typeof o.notify === 'function') { try { o.notify({ name: label(u), capGb: u.quotaGb, period: u.quotaPeriod }); } catch { /* a notification is never worth an error */ } }
      } else if (isExpired(u, t)) {
        ours = true;
        if (said.has('exp:' + id)) continue;
        said.add('exp:' + id);
        log({ line: `Users: “${label(u)}” expired — off until the expiry is moved`, level: 'warn' });
      }
    }
    for (const id of want) {
      if (live.active.includes(id)) continue;
      const u = byId.get(id);
      if (!u || !live.over.includes(id)) continue;
      ours = true;
      if (said.has('back:' + id)) continue;
      said.add('back:' + id);
      log({ line: `Users: “${label(u)}” is back — a new period began (or their cap was raised)`, level: 'info' });
    }
    if (!ours || reloading || t - lastTry < RETRY_MS) return;
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
    rates = {};
    live = pendingBuild;
    said.clear();
    waitSaid = false;
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
      const cur = userTotals(vars);
      const byName = new Map(lu.users.map((u) => [u.username, u]));
      const byId = new Map(lu.users.map((u) => [u.id, u]));
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
        add(u, dUp + dDown, t);
      }
      prev = cur;
      prevAt = t;
      prevSum = sum;
      rates = nextRates;
      settle(lu, t);
      return { fresh: isFresh };
    },

    /** Bytes a user carried some other way (the router's transparent devices). */
    addBytes(userId, bytes) {
      const t = now();
      const lu = current();
      add(lu.users.find((u) => u.id === userId), num(bytes), t);
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
        if (id) add(lu.users.find((u) => u.id === id), dUp + dDown, t);
      }
      devPrevAt = t;
      devRates = nextRates;
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
     * each build): { active: [id], over: [id], byName: { username: id } }, or
     * null — no users in it. Held to from the first reading of the core it
     * starts.
     */
    built(snapshot) { pendingBuild = snapshot && Array.isArray(snapshot.active) ? snapshot : null; },

    /** The users over their cap now — what the build leaves out. */
    overIds() { const t = now(); return overOf(current(), t); },

    /** No core any more: nothing is moving, nothing to hold to. */
    stop() { prev = null; prevAt = 0; prevSum = 0; rates = {}; devRates = {}; devPrevAt = 0; live = null; said.clear(); waitSaid = false; },

    /** bytes/s per user from the last tick: { [userId]: { up, down } }. */
    rates() { return Object.assign({}, rates); },

    /** Each user's period as the window shows it: { [userId]: { bytes, period, since, until, quotaBytes, over } }. */
    usage() {
      const t = now();
      const lu = current();
      roll(lu, t);
      const out = {};
      for (const u of lu.users) {
        const e = usage[u.id];
        const period = userPeriod(u, t);
        const quotaBytes = capBytes(u);
        const unit = u.quotaPeriod === 'day' ? 'day' : 'month';
        out[u.id] = {
          bytes: e ? e.bytes : 0,
          period: e ? e.period : period,
          since: period === 'all' ? 0 : periodStart(unit, t),
          until: period === 'all' ? 0 : periodEnd(unit, t),
          quotaBytes,
          over: quotaBytes > 0 && !!e && e.bytes >= quotaBytes
        };
      }
      return out;
    },

    /** Forget a user's bytes (a user deleted). */
    forget(userId) { if (usage[userId]) { delete usage[userId]; dirty = true; } },

    /** What to save under `lanUsersUsage`. */
    saved() { return JSON.parse(JSON.stringify(usage)); },
    /** What to save under `lanDeviceUsage` (the router's devices). */
    savedDevices() { return JSON.parse(JSON.stringify(devUsage)); },
    get dirty() { return dirty; },
    dueForSave(at) { return dirty && ((at == null ? now() : at) - savedAt) >= SAVE_EVERY_MS; },
    markSaved(at) { dirty = false; savedAt = at == null ? now() : at; }
  };
}

module.exports = {
  SAVE_EVERY_MS, RETRY_MS, GAP_MS,
  userPeriod, capBytes, rollEntry, normalizeUsage, normalizeDeviceUsage, userTotals, counterSum, createLanUsersMeter
};
