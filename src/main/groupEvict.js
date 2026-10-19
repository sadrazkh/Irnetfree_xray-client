'use strict';
/**
 * A group's member that stays dead is taken out of the running config and the
 * app tests it instead (v1.28.2).
 *
 * The core's own health check (the observatory) keeps probing a dead member
 * every 10 s for as long as the core runs, and on both suggested cores a probe
 * whose TLS handshake fails leaves its socket and goroutines behind: against a
 * member that accepts and never answers, one established connection more per
 * probe, forever (measured: 3 → 33 in four minutes at a 2 s probe). On a router
 * that is the "fine for hours, then trouble" the owner reported. So after
 * EVICT_AFTER_MS of "dead" — while another member of its group still answers —
 * the member is set aside: the core is reloaded without it, and every
 * RETEST_MS the app asks it once through a throwaway core (which exits, and its
 * sockets with it). When it answers it is put back, by another reload. Reloads
 * are at least RELOAD_GAP_MS apart.
 *
 * Only members the app can test as the core dials them: not a group dialled
 * through a hop, not a chain variant (`direct: false` in the live payload).
 *
 *   reset(plan)        at connect: the plan's group members, by key; nothing set aside
 *   update(groups)     each stats tick → log lines; marks a reload when one goes
 *   due()              the set-aside members whose test is due → [{ key, record, label }]
 *   tested(key, ok, ms) → log lines; a member that answered is back (a reload)
 *   takeReload()       a reload wanted and allowed now? (then it is taken)
 *   skip()             the keys the next config leaves out (settings.groupSkip)
 */
const { groupMemberKey } = require('./configBuilder');
const { isGroupRecord } = require('./groups');

const EVICT_AFTER_MS = 90 * 1000;
const RETEST_MS = 3 * 60 * 1000;
const RELOAD_GAP_MS = 60 * 1000;

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
    this.reloadGap = opts.reloadGapMs || RELOAD_GAP_MS;
    this.reset(null);
  }

  reset(plan) {
    this.records = new Map();   // key → the member's record (what a test dials)
    for (const g of groupRecordsOf(plan)) {
      const grp = g.outbound && g.outbound._group;
      for (const m of (grp && grp.members) || []) if (m && m.outbound) this.records.set(groupMemberKey(grp.id, m), m);
    }
    this.deadSince = new Map();
    this.out = new Map();        // key → { group, label, nextTest }
    this.wantReload = false;
    this.lastReload = 0;
  }

  skip() { return [...this.out.keys()]; }

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
        if (m.alive !== false) { this.deadSince.delete(key); continue; }
        if (!this.deadSince.has(key)) this.deadSince.set(key, now);
        // never the last one that might answer, and only one the app can test
        if (alive === 0 || !this.records.has(key) || now - this.deadSince.get(key) < this.evictAfter) continue;
        this.deadSince.delete(key);
        this.out.set(key, { group: g.name || g.groupId, label: who(m), nextTest: now + this.retest });
        this.wantReload = true;
        lines.push({ line: `Group ${g.name || g.groupId}: ${who(m)} has not answered for ${mins(this.evictAfter)} — taken out of the running config (the core's own check would keep knocking on it); tested again every ${mins(this.retest)}`, level: 'warn' });
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
    if (!ok) { e.nextTest = this.now() + this.retest; return []; }
    this.out.delete(key);
    this.wantReload = true;
    return [{ line: `Group ${e.group}: ${e.label} answers again${ms != null ? ` (${ms} ms)` : ''} — back in the running config`, level: 'info' }];
  }

  takeReload() {
    const now = this.now();
    if (!this.wantReload || (this.lastReload && now - this.lastReload < this.reloadGap)) return false;
    this.wantReload = false;
    this.lastReload = now;
    return true;
  }
}

module.exports = { GroupEvictor, groupRecordsOf, EVICT_AFTER_MS, RETEST_MS, RELOAD_GAP_MS };
