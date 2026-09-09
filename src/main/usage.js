'use strict';
/**
 * How much has gone through each config — for good, not just this session.
 *
 * The traffic meter (stats.js) reads counters the CORE keeps, and the core
 * keeps them only while it is alive: every reconnect, every settings apply,
 * every crash-and-recover starts them again at zero. So the app could answer
 * "how much since you pressed connect" and nothing else, while the question the
 * owner actually asks is "how much has this server carried, ever".
 *
 * Turning a counter that resets into a running total is a two-line idea with
 * two ways to get it silently wrong, and neither is visible by looking at the
 * number afterwards:
 *
 *  - lose bytes at the reset. Subtracting the previous sample from a counter
 *    that just restarted gives a negative, and clamping that to zero throws
 *    away everything the new core had already carried by the time of the first
 *    poll.
 *  - count bytes twice. Taking the raw counter as the delta whenever it looks
 *    unfamiliar re-adds the whole session on any hiccup — a tag missing from
 *    one poll, a plan that changed under us.
 *
 * The rule that avoids both is small: a value that went DOWN means the core
 * restarted, and then the new value IS the delta; otherwise the delta is the
 * difference. Everything else here exists to feed that rule honestly — which
 * outbound tag belongs to which config, and a previous sample that is never
 * quietly forgotten.
 *
 * Deliberately pure: no timers, no disk, no electron. The clock is an argument
 * so a test can pin `lastUsed`, and persisting the totals is the caller's job
 * (see UsageMeter#dueForSave for the cadence question). This module is required
 * by both main.js and the headless service.js, which is the other reason it
 * knows nothing about either.
 */

/**
 * The id traffic that did NOT go through a proxy is filed under. It is not a
 * config, but a split-routing user's "how much bypassed the tunnel" is a real
 * question and the counter is already there — see byOutbound(), which reports
 * `direct` for exactly the same reason.
 */
const DIRECT_ID = 'direct';

/** Bytes as reported: garbage, negatives and NaN all read as nothing. */
function num(v) {
  return typeof v === 'number' && Number.isFinite(v) && v > 0 ? v : 0;
}

/**
 * An inner hop of a chain. buildChainOutbounds names them `<exit>-h<i>` and
 * they carry the SAME traffic as the exit, wrapped in one more layer — the exit
 * tag is the one that counts the payload, so a hop must never be counted.
 */
const isHopTag = (tag) => /-h\d+$/.test(tag);

/**
 * The config id an outbound tag counts for, for the tags whose name says so.
 * The inverse of the renderer's outboundTagFor(), and the id vocabulary is the
 * routing-target vocabulary the whole app already speaks: a server id,
 * 'chain:<id>', the legacy 'chain', or DIRECT_ID.
 *
 * `proxy` is deliberately NOT resolvable here: a single server and a chain both
 * exit through it, so only the plan knows which. Ask tagMapFor.
 */
function idForTag(tag) {
  if (typeof tag !== 'string' || !tag) return null;
  if (tag === DIRECT_ID) return DIRECT_ID;
  if (isHopTag(tag)) return null;
  if (tag === 'out-chain') return 'chain';
  if (tag.startsWith('out-chain-')) return 'chain:' + tag.slice('out-chain-'.length);
  if (tag.startsWith('out-')) return tag.slice('out-'.length);
  return null;   // block, dns-out, dpi-*, metrics, anything unknown
}

/** buildConfig's own view of a plan, so this module and the config agree. */
function normalizePlan(plan) {
  if (Array.isArray(plan)) return { mode: 'chain', chain: plan };
  if (plan && plan.mode) return plan;
  if (plan && plan.outbound) return { mode: 'single', server: plan };
  return (plan && typeof plan === 'object') ? plan : {};
}

/**
 * The outbound tag a routing target gets, mirroring makeRegistry().tagFor().
 * The fallbacks matter as much as the successes: a target naming a server that
 * has since been deleted, or a chain with nothing usable left in it, gets
 * `direct` in the config — so its bytes are direct traffic here too, not usage
 * invented for a config that is not carrying anything.
 */
function tagForTarget(target, plan) {
  const p = plan || {};
  if (!target || target === DIRECT_ID) return DIRECT_ID;
  if (target === 'block') return 'block';
  const usable = (list) => (Array.isArray(list) ? list : []).filter(s => s && s.outbound).length > 0;
  if (target === 'chain') return usable(p.chain) ? 'out-chain' : DIRECT_ID;
  if (typeof target === 'string' && target.indexOf('chain:') === 0) {
    const cid = target.slice('chain:'.length);
    return usable((p.chainsById || {})[cid]) ? 'out-chain-' + cid : DIRECT_ID;
  }
  const s = (p.serversById || {})[target];
  return s && s.outbound ? 'out-' + target : DIRECT_ID;
}

/**
 * `outboundTag → the config id whose lifetime total it feeds`, for one plan.
 *
 * @param {object|Array} plan  what buildPlan() produced
 * @param {string} [selectedId] the id the user connected to — the ONLY place a
 *   named chain's id can come from, because a chain plan carries its members
 *   and its name but not its id (see buildPlan).
 *
 * Tags absent from the running config do no harm: the core never reports them,
 * so accumulate never sees them. Tags present but unmapped (hops, block, the
 * DPI dialers) are the point — they are what must NOT be counted.
 */
function tagMapFor(plan, selectedId) {
  const p = normalizePlan(plan);
  // Always countable: `direct` exists in every config this app builds, and with
  // a bypass routing mode it carries a real share of the traffic.
  const map = { direct: DIRECT_ID };

  // The id is the routing target itself — the same vocabulary the rules, the
  // pool and the renderer already use. Deliberately NOT idForTag(tag): the
  // target is the id, and reading it back out of the tag would make a config
  // whose id happened to look like a hop ('…-h0') silently uncountable.
  const put = (target) => {
    const tag = tagForTarget(target, p);
    if (tag === 'block') return;                 // a blackholed request used nobody's bandwidth
    map[tag] = tag === DIRECT_ID ? DIRECT_ID : String(target);
  };

  if (p.mode === 'advanced') {
    for (const r of p.rules || []) if (r) put(r.target);
    put(p.def);
  } else if (p.mode === 'pool') {
    for (const e of p.entries || []) if (e) put(e.target);
    put(p.primary);
  } else if (p.mode === 'chain') {
    // A chain exits through `proxy`, and it counts as the chain — its last hop
    // is a server the user may also run on its own, and the two must not share
    // a total.
    const cid = p.chainId || p.id || (selectedId && selectedId !== '__chain__' ? selectedId : null);
    map.proxy = cid ? 'chain:' + cid : 'chain';
  } else if (p.mode === 'single') {
    const id = (p.server && p.server.id) || selectedId || null;
    if (id) map.proxy = id;
  }
  return map;
}

/* ------------------------------- the accumulator ------------------------------- */

/**
 * How many bytes are new, given the previous reading and this one.
 *
 * The one rule this whole module exists for: a counter that went DOWN can only
 * mean the process behind it started again, and then the new reading IS the
 * delta. Subtracting and clamping the negative to zero is the obvious version
 * and it loses, at every reconnect, everything the fresh core had already
 * carried before the first poll reached it.
 *
 * `prev` missing reads as zero, which gives the same answer for the same
 * reason: a core that has just started has carried all of it since.
 */
function deltaOf(prev, cur) {
  const p = num(prev), c = num(cur);
  return c < p ? c : c - p;
}

/**
 * The lifetime totals, advanced by one poll.
 *
 * @param {object} prevPerTag  the previous reading, `{ tag: { up, down } }`
 * @param {object} curPerTag   this reading (StatsPoller's `per` fits as-is)
 * @param {object} tagMap      from tagMapFor(): only mapped tags are counted
 * @param {object} totals      `{ id: { up, down, lastUsed } }`
 * @param {object} [opts]      `{ now }` — injected so a test can pin lastUsed
 * @returns {object} the new totals — or THE SAME OBJECT when nothing moved,
 *   which is how the caller knows there is nothing worth writing to disk. The
 *   input is never mutated: the renderer may still be holding it.
 */
function accumulate(prevPerTag, curPerTag, tagMap, totals, opts) {
  const map = tagMap || {};
  const prev = prevPerTag || {};
  const cur = curPerTag || {};
  const now = (opts && opts.now != null) ? opts.now : Date.now();
  let out = (totals && typeof totals === 'object' && !Array.isArray(totals)) ? totals : {};
  let copied = false;

  for (const tag of Object.keys(cur)) {
    const id = map[tag];
    if (!id) continue;                        // hops, block, tags this plan does not own
    const c = cur[tag] || {};
    const p = prev[tag] || {};
    const up = deltaOf(p.up, c.up);
    const down = deltaOf(p.down, c.down);
    // An idle tick must not touch lastUsed — "last used" is a fact about
    // traffic, and a connection left open all night would otherwise claim the
    // config was in use the whole time.
    if (!up && !down) continue;
    if (!copied) { out = Object.assign({}, out); copied = true; }
    const rec = out[id];
    out[id] = { up: num(rec && rec.up) + up, down: num(rec && rec.down) + down, lastUsed: now };
  }
  return out;
}

/**
 * The reading to compare the next one against.
 *
 * Tags absent from `cur` are CARRIED FORWARD rather than dropped. /debug/vars
 * lists what the core has counters for, and an outbound that has not moved can
 * simply not be there; forgetting it would make its whole counter look new the
 * moment it came back — the double-count failure. A stale entry costs nothing:
 * if the tag returns lower (a restart) the rule above already handles it, and
 * if it never returns nobody asks.
 *
 * Only up/down are kept — the poller also puts upSpeed/downSpeed in there, and
 * a delta has no use for them.
 */
function nextSample(prevPerTag, curPerTag) {
  const out = {};
  for (const [tag, v] of Object.entries(prevPerTag || {})) out[tag] = { up: num(v && v.up), down: num(v && v.down) };
  for (const [tag, v] of Object.entries(curPerTag || {})) out[tag] = { up: num(v && v.up), down: num(v && v.down) };
  return out;
}

/* ------------------------------- what gets stored ------------------------------- */

/** A usable totals object out of whatever the store handed back. */
function normalizeTotals(raw) {
  const out = {};
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return out;
  for (const [id, v] of Object.entries(raw)) {
    if (!id || !v || typeof v !== 'object') continue;
    const up = num(v.up), down = num(v.down);
    // Nothing writes a record until bytes have moved (see accumulate), so an
    // all-zero — or unreadable — one in the file is damage or a hand edit.
    // Dropping it keeps the file small and loses no fact: usageOf() answers the
    // same for a missing record as for an empty one.
    if (!up && !down) continue;
    out[id] = { up, down, lastUsed: num(v.lastUsed) };
  }
  return out;
}

/** The record for one config id — zeros for one that has never carried anything. */
function usageOf(totals, id) {
  const rec = totals && typeof totals === 'object' ? totals[id] : null;
  return { up: num(rec && rec.up), down: num(rec && rec.down), lastUsed: num(rec && rec.lastUsed) };
}

/**
 * Everything added up. `direct` is left out by default: it is real traffic but
 * it is not a config's, and a bypass-heavy user would otherwise see a lifetime
 * "VPN usage" figure made mostly of traffic that never entered a tunnel.
 */
function grandTotal(totals, opts) {
  const includeDirect = !!(opts && opts.includeDirect);
  let up = 0, down = 0;
  for (const [id, v] of Object.entries(totals || {})) {
    if (!includeDirect && id === DIRECT_ID) continue;
    up += num(v && v.up); down += num(v && v.down);
  }
  return { up, down };
}

/**
 * Drop the records of configs that no longer exist, so a store the user has
 * churned through for a year does not carry a total per deleted server for
 * ever. Returns the same object when there is nothing to drop — again, the
 * "no need to write" signal.
 *
 * `keepIds` missing means the caller has no list to judge by, which is never a
 * reason to delete a user's history. DIRECT_ID always survives: it belongs to
 * no config, so no list of configs can vouch for it.
 */
function pruneTotals(totals, keepIds) {
  if (!totals || typeof totals !== 'object' || !keepIds) return totals;
  const keep = keepIds instanceof Set ? keepIds : new Set(keepIds);
  const doomed = Object.keys(totals).filter(id => id !== DIRECT_ID && !keep.has(id));
  if (!doomed.length) return totals;
  const out = Object.assign({}, totals);
  for (const id of doomed) delete out[id];
  return out;
}

/* ------------------------------ the meter itself ------------------------------ */

/** How long to leave new bytes unwritten. See dueForSave. */
const SAVE_EVERY_MS = 30000;

/**
 * The three pieces above, kept together across a session: the totals, the
 * previous reading, and the map saying which tag feeds which config.
 *
 * Still no timers and no disk — the caller ticks it from the stats poller it
 * already has and writes the totals with the store it already has. What the
 * meter adds is the one piece of knowledge the pure functions cannot have: WHEN
 * the core restarted. A restart is usually visible (the counter falls), but not
 * always — a fresh core can be past the old figure by the time the first poll
 * lands, and then the drop is invisible and the difference is lost. Only the
 * caller knows, so reset() belongs next to every stats.stop().
 */
class UsageMeter {
  /** @param {object} [opts] `{ totals: what the store held, now }` */
  constructor(opts) {
    const o = opts || {};
    this.totals = normalizeTotals(o.totals);
    this.tagMap = {};
    /** The last reading, or null when the next one comes from a fresh core. */
    this.prev = null;
    /** Bytes counted that are not on disk yet. */
    this.dirty = false;
    this.savedAt = o.now == null ? Date.now() : o.now;
  }

  /**
   * Which config each outbound counts for, from here on. Called on every
   * connect and every rebuild — the plan is the only thing that knows, and it
   * changes under a live meter whenever settings are applied.
   */
  setPlan(plan, selectedId) {
    this.tagMap = tagMapFor(plan, selectedId);
    return this.tagMap;
  }

  /**
   * One poll of the core's counters — StatsPoller's `per` goes in unchanged.
   * @returns {boolean} whether anything was added (i.e. whether the totals now
   *   differ from what is on disk).
   */
  tick(perTag, now) {
    if (!perTag || typeof perTag !== 'object') return false;   // a poll that failed says nothing
    const next = accumulate(this.prev, perTag, this.tagMap, this.totals, { now });
    this.prev = nextSample(this.prev, perTag);
    if (next === this.totals) return false;
    this.totals = next;
    this.dirty = true;
    return true;
  }

  /**
   * The core is gone; its counters mean nothing now. The next reading is a
   * fresh start and every byte in it is new.
   */
  reset() { this.prev = null; }

  /** Drop the records of configs that no longer exist. @returns {boolean} changed */
  prune(keepIds) {
    const next = pruneTotals(this.totals, keepIds);
    if (next === this.totals) return false;
    this.totals = next;
    this.dirty = true;
    return true;
  }

  /**
   * Forget the running total of one config, or of every config — the user's
   * own "start over" for a subscription that changed hands or a server that
   * was only ever a test. `dirty` so the next flush writes the absence too:
   * a total that is only gone in memory comes back at the next launch.
   * @returns {boolean} whether anything was forgotten
   */
  clear(id) {
    if (id == null) {
      if (!Object.keys(this.totals).length) return false;
      this.totals = {};
    } else {
      if (!Object.prototype.hasOwnProperty.call(this.totals, id)) return false;
      const next = Object.assign({}, this.totals);
      delete next[id];
      this.totals = next;
    }
    this.dirty = true;
    return true;
  }

  /** The totals have been persisted as they stand. */
  markSaved(now) {
    this.dirty = false;
    this.savedAt = now == null ? Date.now() : now;
  }

  /**
   * Is it time to write? The totals must survive a power cut, but a poll a
   * second means writing the whole store a second — an fsync and a rename each
   * time (see store.js), for a number nobody is watching that closely. Half a
   * minute of unwritten traffic is the trade: at most one interval is lost to a
   * hard kill, and the ordinary exits (disconnect, quit) flush regardless.
   */
  dueForSave(now, everyMs) {
    if (!this.dirty) return false;
    const t = now == null ? Date.now() : now;
    return (t - this.savedAt) >= (everyMs == null ? SAVE_EVERY_MS : everyMs);
  }
}

module.exports = {
  DIRECT_ID, SAVE_EVERY_MS, idForTag, tagMapFor, tagForTarget,
  accumulate, nextSample, normalizeTotals, usageOf, grandTotal, pruneTotals, UsageMeter
};
