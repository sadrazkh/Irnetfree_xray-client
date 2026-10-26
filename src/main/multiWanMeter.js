'use strict';
/**
 * Multi-internet ("ترکیب اینترنت‌ها", multiWan.js): what each internet carried
 * this period, its data cap, how fast it is moving right now, and which ones
 * are set aside for having reached their cap.
 *
 * Fed from the stats poller's tick — the same /debug/vars read the live meter
 * and the usage totals come from (stats.js) — with what the running config was
 * built with: its group map (`config.groupTags`; every member multiWan.js made
 * carries `#<linkId>` in its id) and its split list (`config.multiWanSplit`:
 * an XHTTP outbound whose upload and download leave by two internets is no
 * group, so the builder names its two links). multiWan.linkUsage reads both
 * and says which internet each byte left by.
 *
 * The bytes are kept per link per period — `{ [linkId]: { period, bytes } }`,
 * the period being '2026-10' for a month and '2026-10-25' for a day, local
 * time (a month that follows the Persian calendar, or renews on another day
 * than the 1st, has a key of its own: capPeriods.js) — and saved by the caller
 * in the usage file beside the per-config totals: a save rewrites its whole
 * file, and the main store holds every server (main.js, the `usage`
 * declaration says why that matters).
 *
 * A link over its cap this period is in skip(): the connect and every rebuild
 * put that list into `settings.multiWanSkip`, and the builder leaves the link
 * out. When the list a running core was built with is no longer the list it
 * should be — a cap reached, a new period begun — the quota asks the caller's
 * reload (queueReload) once, retrying no sooner than RETRY_MS if it did not
 * happen, and says in the log which internet reached its cap.
 *
 * Desktop (main.js) and router (service.js) alike: no store, no timers, no
 * Electron — the caller hands in its own.
 */
const { linkUsage } = require('./multiWan');
const { PERIOD_KEY, cycleOf, periodKey, periodStart, periodEnd, rollEntry } = require('./capPeriods');
const { dayText } = require('./jalali');

/** The app writes GB as fmtBytes does — binary — so a cap in GB means the same everywhere on screen. */
const GIB = 1024 * 1024 * 1024;
/** Bytes counted are written at most this often (and on disconnect and quit). */
const SAVE_EVERY_MS = 30000;
/** A reload that did not happen is asked again no sooner than this. */
const RETRY_MS = 15000;

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : 0);

/* ------------------------------ periods ------------------------------ */

// periodKey / periodStart / periodEnd / rollEntry are capPeriods.js's — the
// users' meter counts by the same ones. A link is counted by its day for a
// daily cap and by its month otherwise (as the link says: the Gregorian month
// from the 1st unless it names a calendar or a renew day); a link with no cap
// is counted by the month too, so a monthly cap set later starts from what
// this month already carried.

/** A link's cap in bytes; 0 = none (no GB, or no period to count it in). */
function capBytes(link) {
  if (!link || (link.quotaPeriod !== 'day' && link.quotaPeriod !== 'month')) return 0;
  const gb = Number(link.quotaGb);
  return Number.isFinite(gb) && gb > 0 ? Math.round(gb * GIB) : 0;
}

/** What was saved, each entry of its type; junk dropped. */
function normalizeUsage(raw) {
  const out = {};
  if (!isObj(raw)) return out;
  for (const [id, e] of Object.entries(raw)) {
    if (!id || !isObj(e) || typeof e.period !== 'string' || !PERIOD_KEY.test(e.period)) continue;
    const bytes = Number(e.bytes);
    out[id] = { period: e.period, bytes: Number.isFinite(bytes) && bytes > 0 ? Math.round(bytes) : 0 };
  }
  return out;
}

/* ------------------------------ counting ------------------------------ */

/**
 * Each link's bytes as the running core counts them (totals since it
 * started), from its raw counters (before the groups are folded), its group
 * map and its split list — multiWan.linkUsage, made safe: nothing to read
 * gives nothing, never NaN. → { [linkId]: { up, down } }
 */
function linkTotals(raw, groupMap, split) {
  const hasMap = Array.isArray(groupMap) && groupMap.length > 0;
  const hasSplit = Array.isArray(split) && split.length > 0;
  if (!isObj(raw) || (!hasMap && !hasSplit)) return {};
  const out = {};
  for (const [id, c] of Object.entries(linkUsage(raw, hasMap ? groupMap : null, hasSplit ? split : null) || {})) {
    if (!id || !c) continue;
    out[id] = { up: num(c.up), down: num(c.down) };
  }
  return out;
}

const sameSet = (a, b) => a.length === b.length && a.every((x) => b.includes(x));

/* ------------------------------ the quota ------------------------------ */

/**
 * @param {object} o
 *   usage       what the usage file held under `multiWanUsage`
 *   settings()  the multiWan settings as they are now, normalized — caps and
 *               periods are read live, so a cap changed while connected
 *               counts at once (settingsMeta: no reconnect for a cap)
 *   live()      the multiWan settings the RUNNING core was built from, or
 *               null when nothing is connected
 *   canReload() connected and quiet: no connect, recovery or disconnect in flight
 *   pending()   the keys waiting for Apply — a reload would take some of them
 *               live behind the user's back, so the set-aside waits for them
 *               (the group set-aside does the same)
 *   reload(why) → Promise<boolean>: the caller's queueReload
 *   log({ line, level }), notify({ name, capGb, period, until, calendar }) (optional;
 *               `until` the day the cap renews, ms; `calendar` the month's)
 *   now()       ms epoch (a test hands in its own clock)
 */
function createMultiWanQuota(o) {
  const now = typeof o.now === 'function' ? o.now : () => Date.now();
  const log = typeof o.log === 'function' ? o.log : () => {};
  let usage = normalizeUsage(o.usage);
  let dirty = false;
  let savedAt = now();
  let prev = null;        // the running core's last reading per link, null: the next one is from a fresh core
  let prevAt = 0;
  let rates = {};         // bytes/s per link, from the last two readings
  let built = null;       // the links the running core was built without (null: no core)
  let lastTry = -Infinity;
  let reloading = false;
  let waitSaid = false;
  const said = new Set(); // 'out:<id>' / 'back:<id>' already said for the running core

  const current = () => { const m = o.settings(); return m && Array.isArray(m.links) ? m : { enabled: false, mode: 'balance', links: [], split: { up: '', down: '' } }; };

  /** Every configured link moved to the period it counts in at `t`. */
  function roll(m, t) {
    for (const l of m.links) {
      const was = usage[l.id];
      const next = rollEntry(was, periodKey(l.quotaPeriod, t, l));
      if (next === was) continue;
      usage[l.id] = next;
      if (was) dirty = true;   // a period that ended is worth a write; a new empty entry is not
    }
  }

  /** The configured links over their cap at `t`, in configured order. */
  function overCap(m, t) {
    roll(m, t);
    return m.links.filter((l) => { const cap = capBytes(l); return cap > 0 && usage[l.id] && usage[l.id].bytes >= cap; }).map((l) => l.id);
  }

  /** The running core was built without other links than it should be: say why, and reload — once. */
  function settle(m, want, t) {
    const liveMw = o.live && o.live();
    if (built == null || !liveMw || !liveMw.enabled) return;
    if (sameSet(want, built)) { waitSaid = false; return; }
    const name = (id) => { const l = m.links.find((x) => x.id === id); return (l && l.name) || id; };
    for (const id of want) {
      if (built.includes(id) || said.has('out:' + id)) continue;
      said.add('out:' + id);
      const l = m.links.find((x) => x.id === id) || {};
      const day = l.quotaPeriod === 'day';
      // the day it renews, in words: the 1st of next month, or the day and calendar the link names
      const renews = periodEnd(l.quotaPeriod, t, l);
      const calendar = cycleOf(l).calendar;
      const until = day ? 'tomorrow' : dayText(renews, 'en', calendar);
      log({ line: `Multi-internet: “${name(id)}” reached its cap (${l.quotaGb} GB ${day ? 'today' : 'this month'}) — set aside until ${until}; the connection goes on the other internets`, level: 'warn' });
      if (typeof o.notify === 'function') { try { o.notify({ name: name(id), capGb: l.quotaGb, period: l.quotaPeriod, until: renews, calendar }); } catch { /* a notification is never worth an error */ } }
    }
    for (const id of built) {
      if (want.includes(id) || said.has('back:' + id)) continue;
      said.add('back:' + id);
      log({ line: `Multi-internet: “${name(id)}” is back in use — a new period began (or its cap was raised)`, level: 'info' });
    }
    // the builder balances over whatever is left — one internet will do; none left is said
    const usable = m.links.filter((l) => l.role !== 'off' && !want.includes(l.id));
    if (want.length && !usable.length && !said.has('none:' + want.join(','))) {
      said.add('none:' + want.join(','));
      log({ line: 'Multi-internet: every internet is over its cap — the connection goes the way the system routes it until a new period begins', level: 'warn' });
    }
    if (reloading || t - lastTry < RETRY_MS) return;
    if (o.canReload && !o.canReload()) return;
    if (o.pending && o.pending().length) {
      if (!waitSaid) { waitSaid = true; log({ line: 'Multi-internet: an internet to set aside for its cap (or bring back) waits for your pending settings — apply them (or reconnect) and the core reloads', level: 'info' }); }
      return;
    }
    waitSaid = false;
    reloading = true;
    lastTry = t;
    Promise.resolve()
      .then(() => o.reload(want.length ? 'Multi-internet: the core reloaded without the internets over their cap' : 'Multi-internet: the core reloaded with every internet back'))
      .catch((e) => log({ line: 'Multi-internet: the reload failed — ' + ((e && e.message) || e), level: 'warn' }))
      .finally(() => { reloading = false; });
  }

  return {
    /**
     * One stats poll: the core's raw counters (`vars`, the parsed /debug/vars)
     * and what the running config was built with — its group map
     * (config.groupTags) and its split list (config.multiWanSplit).
     */
    tick(vars, groupMap, split) {
      const t = now();
      const m = current();
      roll(m, t);
      const raw = vars && vars.stats && vars.stats.outbound;
      const cur = linkTotals(raw, groupMap, split);
      const dt = prev ? (t - prevAt) / 1000 : 0;
      const nextRates = {};
      for (const [id, c] of Object.entries(cur)) {
        const p = (prev && prev[id]) || { up: 0, down: 0 };
        // a reading below the last is a fresh core counting from zero: all of it is new
        const dUp = c.up >= p.up ? c.up - p.up : c.up;
        const dDown = c.down >= p.down ? c.down - p.down : c.down;
        nextRates[id] = dt > 0 ? { up: dUp / dt, down: dDown / dt } : { up: 0, down: 0 };
        if (dUp + dDown <= 0) continue;
        const l = m.links.find((x) => x.id === id);
        const e = rollEntry(usage[id], periodKey(l ? l.quotaPeriod : 'month', t, l));
        usage[id] = { period: e.period, bytes: e.bytes + dUp + dDown };
        dirty = true;
      }
      prev = cur;
      prevAt = t;
      rates = nextRates;
      settle(m, overCap(m, t), t);
    },

    /**
     * The links to leave out of a build now (`settings.multiWanSkip`) — the
     * periods rolled first, so a new day clears yesterday's at the connect.
     */
    skip() { const t = now(); return overCap(current(), t); },

    /**
     * A fresh core, built without `skipBuiltWith` — the connect and every
     * rebuild, once it runs. Its counters start at zero, so the next reading
     * is all new; and what it was built with is what the caps are held to.
     */
    reset(skipBuiltWith) {
      prev = null;
      rates = {};
      built = Array.isArray(skipBuiltWith) ? skipBuiltWith.slice() : null;
      said.clear();
      waitSaid = false;
    },

    /** No core any more (a disconnect): nothing is moving, nothing to hold to. */
    stop() { prev = null; rates = {}; built = null; said.clear(); waitSaid = false; },

    /** bytes/s per link from the last tick: { [linkId]: { up, down } } ({} with no core). */
    rates() { return Object.assign({}, rates); },

    /**
     * Each configured link's period as the window shows it:
     * { [linkId]: { bytes, period, since, until, quotaBytes, over } } —
     * `until` the day the cap renews (local midnight).
     */
    usage() {
      const t = now();
      const m = current();
      roll(m, t);
      const out = {};
      for (const l of m.links) {
        const e = usage[l.id];
        const quotaBytes = capBytes(l);
        out[l.id] = {
          bytes: e ? e.bytes : 0,
          period: e ? e.period : periodKey(l.quotaPeriod, t, l),
          since: periodStart(l.quotaPeriod, t, l),
          until: periodEnd(l.quotaPeriod, t, l),
          quotaBytes,
          over: quotaBytes > 0 && !!e && e.bytes >= quotaBytes
        };
      }
      return out;
    },

    /** What to save under `multiWanUsage`. */
    saved() { return JSON.parse(JSON.stringify(usage)); },
    get dirty() { return dirty; },
    /** Time to write? Half a minute of counted bytes is the most a hard kill loses (usage.js weighs the same trade). */
    dueForSave(at) { return dirty && ((at == null ? now() : at) - savedAt) >= SAVE_EVERY_MS; },
    markSaved(at) { dirty = false; savedAt = at == null ? now() : at; }
  };
}

/**
 * The window's list of internets: what is connected now (netLinks.listLinks)
 * merged with what the user configured — a configured link that is not
 * connected now stays, `present: false`. Configured ones first, in their own
 * order, then the newly found; each with the configured name when there is
 * one (`sysName`: what the OS calls it), and its last speed test.
 */
function mergeLinks(listed, mw, tests) {
  const found = (Array.isArray(listed) ? listed : []).filter((l) => l && (l.id || l.iface));
  const byId = new Map(found.map((l) => [String(l.id || l.iface), l]));
  const res = [];
  const testOf = (id) => (isObj(tests) && isObj(tests[id]) ? tests[id] : null);
  for (const c of (mw && Array.isArray(mw.links)) ? mw.links : []) {
    const f = byId.get(c.id) || found.find((l) => l.iface === c.iface);
    if (f) byId.delete(String(f.id || f.iface));
    res.push({
      id: c.id, iface: c.iface, name: c.name || (f && f.name) || c.id, sysName: f ? f.name || '' : '',
      kind: (f && f.kind) || 'other', address: (f && f.address) || '', gateway: (f && f.gateway) || '',
      metric: f && f.metric != null ? f.metric : null,
      present: !!f, configured: true, test: testOf(c.id)
    });
  }
  for (const [id, f] of byId) {
    res.push({
      id, iface: f.iface || id, name: f.name || id, sysName: f.name || '',
      kind: f.kind || 'other', address: f.address || '', gateway: f.gateway || '',
      metric: f.metric != null ? f.metric : null,
      present: true, configured: false, test: testOf(id)
    });
  }
  return res;
}

module.exports = {
  GIB, SAVE_EVERY_MS, RETRY_MS,
  periodKey, periodStart, periodEnd, capBytes, rollEntry, normalizeUsage,
  linkTotals, createMultiWanQuota, mergeLinks
};
