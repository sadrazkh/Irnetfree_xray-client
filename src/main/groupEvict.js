'use strict';
/**
 * A group's member that stays dead is taken out of the running config and the
 * app tests it instead (v1.28.2; hardened in v1.28.3).
 *
 * The core's own health check (the observatory) keeps probing a dead member
 * every 10 s for as long as the core runs, and on both suggested cores a probe
 * whose TLS handshake fails leaves its socket and goroutines behind: against a
 * member that accepts and never answers, one established connection more per
 * probe, forever (measured: 3 → 33 in four minutes at a 2 s probe). On a router
 * that is the "fine for hours, then trouble" the owner reported. So after
 * EVICT_AFTER_MS of "dead" — while another member of its group answers — the
 * member is set aside: the core is reloaded without it, and the app asks it
 * itself through a throwaway core (which exits, and its sockets with it):
 * after RETEST_MS, then twice as long after each miss (up to RETEST_MAX_MS), so
 * a member that stays dead costs ever less. It is put back only after TWO
 * answers in a row (PASS_AGAIN_MS apart): one lucky answer from a member that
 * is filtered on and off would otherwise cost a reload — every connection,
 * the corporate WireGuard on the base included — every few minutes.
 * Reloads are at least RELOAD_GAP_MS apart, and a reload that did not happen
 * is asked for again (reloadFailed).
 *
 * A whole group dead at once (the line itself down) is no member's fault: no
 * dead streak runs while no member of the group answers, so the members do not
 * all go the moment the first one answers again.
 *
 * What is set aside outlives a reconnect of the same plan (a network change, a
 * wake from sleep) for KEEP_MS: the connect builds without it (skip()) instead
 * of probing it for 90 s more and reloading once again.
 *
 * Only members the app can test as the core dials them: not a group dialled
 * through a hop, not a chain variant (`direct: false` in the live payload).
 *
 *   reset(plan)        at connect: the plan's group members, by key; what is set
 *                      aside and still in this plan, kept (KEEP_MS); the rest forgotten
 *   update(groups)     each stats tick → log lines; marks a reload when one goes
 *   due()              the set-aside members whose test is due → [{ key, record, label }]
 *   tested(key, ok, ms) → log lines; a member that answered twice is back (a reload)
 *   wantsReload()      is a reload asked for?
 *   takeReload()       a reload wanted and allowed now? (then it is taken)
 *   reloadFailed()     the reload taken did not happen: ask for it again
 *   skip()             the keys the next config leaves out (settings.groupSkip)
 *   takeChanges()      the members set aside / put back since the last ask → { out, back }
 *                      (groupLive.applyLive does them in the running core)
 *   liveApplied()      they were done there: no reload is needed for them
 *   list()             what is set aside, for the window: [{ key, groupId, group, label, since, nextTest }]
 */
const { groupMemberKey } = require('./configBuilder');
const { isGroupRecord } = require('./groups');

const EVICT_AFTER_MS = 90 * 1000;
const RETEST_MS = 3 * 60 * 1000;
const RETEST_MAX_MS = 24 * 60 * 1000;
const PASS_AGAIN_MS = 30 * 1000;
const RELOAD_GAP_MS = 60 * 1000;
const KEEP_MS = 30 * 60 * 1000;

/** Every group record a plan can dial: a single selection, a chain's hops, the targets of advanced routing and the pool. */
function groupRecordsOf(plan) {
  if (!plan) return [];
  const out = [];
  const add = (r) => { if (isGroupRecord(r) && !out.includes(r)) out.push(r); };
  add(plan.server);
  for (const r of plan.chain || []) add(r);
  for (const r of Object.values(plan.serversById || {})) add(r);
  for (const list of Object.values(plan.chainsById || {})) for (const r of list || []) add(r);
  return out;
}

const who = (m) => (m.name || m.id || 'a member') + (m.address ? ` (${m.address}${m.port ? ':' + m.port : ''})` : '');
const mins = (ms) => (ms % 60000 === 0 ? `${ms / 60000} min` : `${Math.round(ms / 1000)} s`);

class GroupEvictor {
  constructor(opts = {}) {
    this.now = opts.now || Date.now;
    this.evictAfter = opts.evictAfterMs || EVICT_AFTER_MS;
    this.retest = opts.retestMs || RETEST_MS;
    this.retestMax = opts.retestMaxMs || RETEST_MAX_MS;
    this.passAgain = opts.passAgainMs || PASS_AGAIN_MS;
    this.reloadGap = opts.reloadGapMs || RELOAD_GAP_MS;
    this.keep = opts.keepMs || KEEP_MS;
    this.out = new Map();        // key → { groupId, group, label, since, nextTest, misses, passes, touched }
    this.reset(null);
  }

  reset(plan) {
    const now = this.now();
    this.records = new Map();   // key → the member's record (what a test dials)
    for (const g of groupRecordsOf(plan)) {
      const grp = g.outbound && g.outbound._group;
      for (const m of (grp && grp.members) || []) if (m && m.outbound) this.records.set(groupMemberKey(grp.id, m), m);
    }
    // set aside lately, and a member of this plan still: it stays out (the connect built without it)
    for (const [key, e] of [...this.out]) if (!this.records.has(key) || now - e.touched > this.keep) this.out.delete(key);
    this.deadSince = new Map();
    this.wantReload = false;
    this.lastReload = 0;
    this.changes = { out: [], back: [] };
  }

  skip() { return [...this.out.keys()]; }

  list() {
    return [...this.out].map(([key, e]) => ({ key, groupId: e.groupId, group: e.group, label: e.label, since: e.since, nextTest: e.nextTest }));
  }

  update(groups) {
    const now = this.now();
    const lines = [];
    const seen = new Set();
    for (const g of Array.isArray(groups) ? groups : []) {
      if (!g || !Array.isArray(g.members) || g.direct === false) continue;
      const alive = g.members.filter((m) => m && m.alive === true).length;
      for (const m of g.members) {
        if (!m || m.direct === false) continue;
        const key = groupMemberKey(g.groupId, m);
        seen.add(key);
        // already set aside, still in the running config until the reload: once is enough;
        // and nobody in the group answering is the line, not this member: no streak runs
        if (m.alive !== false || this.out.has(key) || alive === 0) { this.deadSince.delete(key); continue; }
        if (!this.deadSince.has(key)) this.deadSince.set(key, now);
        // only one the app can test
        if (!this.records.has(key) || now - this.deadSince.get(key) < this.evictAfter) continue;
        this.deadSince.delete(key);
        this.out.set(key, { groupId: g.groupId, group: g.name || g.groupId, label: who(m), since: now, nextTest: now + this.retest, misses: 0, passes: 0, touched: now });
        this.wantReload = true;
        this.changes.out.push(key);
        lines.push({ line: `Group ${g.name || g.groupId}: ${who(m)} has not answered for ${mins(this.evictAfter)} — taken out of the running config (the core's own check would keep knocking on it); tested again in ${mins(this.retest)}`, level: 'warn' });
      }
    }
    // a member no longer in any running group (a reload left it out, the plan changed) has no dead streak
    for (const k of [...this.deadSince.keys()]) if (!seen.has(k)) this.deadSince.delete(k);
    return lines;
  }

  due() {
    const now = this.now();
    const out = [];
    for (const [key, e] of this.out) if (e.nextTest <= now && this.records.has(key)) out.push({ key, record: this.records.get(key), label: e.label, group: e.group });
    return out;
  }

  tested(key, ok, ms) {
    const e = this.out.get(key);
    if (!e) return [];
    const now = this.now();
    e.touched = now;
    if (!ok) {
      // each miss doubles the wait, up to the cap
      e.misses += 1;
      e.passes = 0;
      e.nextTest = now + Math.min(this.retestMax, this.retest * Math.pow(2, e.misses));
      return [];
    }
    if (e.passes < 1) {
      // one answer is not yet a member back: once more, shortly
      e.passes = 1;
      e.nextTest = now + this.passAgain;
      return [];
    }
    this.out.delete(key);
    this.wantReload = true;
    this.changes.back.push(key);
    return [{ line: `Group ${e.group}: ${e.label} answers again${ms != null ? ` (${ms} ms)` : ''} — back in the running config`, level: 'info' }];
  }

  wantsReload() { return this.wantReload; }

  takeChanges() {
    const c = this.changes;
    this.changes = { out: [], back: [] };
    return c;
  }

  liveApplied() { this.wantReload = false; }

  takeReload() {
    const now = this.now();
    if (!this.wantReload || (this.lastReload && now - this.lastReload < this.reloadGap)) return false;
    this.wantReload = false;
    this.lastReload = now;
    return true;
  }

  reloadFailed() { this.wantReload = true; }
}

module.exports = { GroupEvictor, groupRecordsOf, EVICT_AFTER_MS, RETEST_MS, RETEST_MAX_MS, PASS_AGAIN_MS, RELOAD_GAP_MS, KEEP_MS };
