'use strict';
/**
 * Live traffic stats from Xray's `metrics` service: one HTTP GET of
 * /debug/vars per tick, no child process.
 *
 * Counters live under stats.outbound[<tag>].uplink/downlink. We sum every tag
 * EXCEPT the ones that are not proxied traffic (direct, block, dns-out and the
 * dpi-* dialers), because a config's exit tag depends on the plan: 'proxy' for a
 * single server or a chain, 'out-<serverId>' / 'out-chain-<id>' for the pool and
 * advanced routing. The previous implementation asked for the fixed name
 * 'outbound>>>proxy>>>traffic>>>uplink' and therefore always read 0 in those two
 * modes.
 *
 * We compute per-second deltas to show live speed.
 */
const http = require('http');

/** Outbound tags that exist but never carry user traffic through the proxy. */
const NOT_PROXY = new Set(['direct', 'block', 'dns-out']);
/**
 * A JSON server's helper outbounds (`<tag>~<helper>`, configBuilder.helpersFor:
 * its fragment dialer, the hops of its own chain) carry the bytes its main
 * outbound already counted — like the dpi-* dialers, never counted again.
 */
const isHelperTag = (tag) => tag.includes('~');
const isProxyTag = (tag) => !NOT_PROXY.has(tag) && !tag.startsWith('dpi-') && !isHelperTag(tag);

const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : 0);

/**
 * A group's members (`T~gm<i>`, configBuilder.expandGroups) carry its bytes —
 * the core counts nothing on the group's loopback T itself. The counters as
 * read, with each member's added into its group's T and the member gone: a
 * group is one config to the meter, to usage and to the silence watch, as a
 * server is. Anything else is passed through as it was.
 */
const GROUP_MEMBER = /^(.+)~gm\d+$/;
function foldGroups(out) {
  const res = {};
  const add = (tag, c) => {
    const r = res[tag] || (res[tag] = { uplink: 0, downlink: 0 });
    r.uplink += num(c && c.uplink);
    r.downlink += num(c && c.downlink);
  };
  for (const [tag, c] of Object.entries(out)) {
    const m = GROUP_MEMBER.exec(tag);
    if (m) add(m[1], c);
    else if (!res[tag]) res[tag] = { uplink: num(c && c.uplink), downlink: num(c && c.downlink) };
    else add(tag, c);
  }
  return res;
}

/**
 * { up, down } summed from a parsed /debug/vars body. Never throws, never NaN.
 * `skip`: tags to leave out besides the usual — a raw config's dialers
 * (configBuilder.dialerTagsOf), whose bytes the outbound dialling through them
 * already counted.
 */
function sumOutbounds(vars, skip) {
  const raw = vars && vars.stats && vars.stats.outbound;
  if (!raw || typeof raw !== 'object') return { up: 0, down: 0 };
  const out = foldGroups(raw);
  let up = 0, down = 0;
  for (const tag of Object.keys(out)) {
    if (!isProxyTag(tag) || (skip && skip.has(tag))) continue;
    const c = out[tag] || {};
    up += num(c.uplink);
    down += num(c.downlink);
  }
  return { up, down };
}

/** Each group member's own counters (`T~gm<i>`), as read — what foldGroups adds into its group. */
function memberCounters(vars) {
  const out = vars && vars.stats && vars.stats.outbound;
  const res = {};
  if (!out || typeof out !== 'object') return res;
  for (const [tag, c] of Object.entries(out)) {
    if (GROUP_MEMBER.test(tag)) res[tag] = { up: num(c && c.uplink), down: num(c && c.downlink) };
  }
  return res;
}

/**
 * What the core's health check (the observatory a group runs) says of each
 * member it probed: { tag: { alive, delay } } — a delay only for a live one
 * (a dead one reads 99999999).
 */
function healthOf(vars) {
  const obs = vars && vars.observatory;
  const res = {};
  if (!obs || typeof obs !== 'object') return res;
  for (const [tag, o] of Object.entries(obs)) {
    if (!o || typeof o !== 'object') continue;
    const alive = o.alive === true;
    res[tag] = { alive, delay: alive && Number.isFinite(o.delay) ? o.delay : null };
  }
  return res;
}

class StatsPoller {
  /**
   * @param {object} opts { binPath, apiPort, onStats(stats) }
   */
  constructor(opts) {
    this.binPath = opts.binPath;
    this.apiPort = opts.apiPort || 10085;
    // a raw JSON config's dialers (configBuilder.dialerTagsOf), set per connect; null: none
    this.skipTags = null;
    // the running config's groups (configBuilder's groupTags), set per connect; null: none
    this.groupMap = null;
    this.lastMembers = {};
    this.onStats = opts.onStats || (() => {});
    // the whole parsed body, for callers that need per-outbound counters and
    // not just the sum (see SilenceWatch)
    this.onRaw = opts.onRaw || (() => {});
    this.timer = null;
    this.intervalMs = 1000;
    this.last = { up: 0, down: 0, t: 0 };
    this.lastPer = {};          // tag -> previous totals, for per-outbound speed
    this.totals = { up: 0, down: 0 };
    this.generation = 0;
    this.inFlight = null;
    this.cancelQuery = null;
  }

  /**
   * No-op: the metrics endpoint needs no binary. Kept because main.js and
   * service.js mirror each other's call sites and both call it — removing it
   * would break them, and that is out of this change's scope.
   */
  setBin(p) { this.binPath = p; }

  query() {
    const generation = this.generation;
    return new Promise((resolve) => {
      let settled = false;
      let deadline;
      const finish = (value) => {
        if (settled) return;
        settled = true;
        clearTimeout(deadline);
        if (this.cancelQuery === cancel) this.cancelQuery = null;
        resolve(value);
      };
      const cancel = () => { finish(null); req.destroy(); };
      const req = http.get({ host: '127.0.0.1', port: this.apiPort, path: '/debug/vars', agent: false }, (res) => {
        if (res.statusCode !== 200) return cancel();
        let body = '';
        let bytes = 0;
        res.setEncoding('utf8');
        res.on('error', cancel);
        res.on('aborted', cancel);
        res.on('data', (c) => {
          bytes += Buffer.byteLength(c);
          // Metrics include runtime counters; allow ample room without letting
          // an unexpected endpoint stream an unlimited body into the UI process.
          if (bytes > 8 * 1024 * 1024) return cancel();
          body += c;
        });
        res.on('end', () => {
          if (settled || generation !== this.generation) return finish(null);
          let parsed;
          try { parsed = JSON.parse(body); } catch { return finish(null); }
          try { this.onRaw(parsed); } catch { /* a watcher must never stop the meter */ }
          const sample = Object.assign(sumOutbounds(parsed, this.skipTags), { per: byOutbound(parsed, this.skipTags) });
          if (this.groupMap) Object.assign(sample, { members: memberCounters(parsed), health: healthOf(parsed) });
          finish(sample);
        });
      });
      this.cancelQuery = cancel;
      req.on('error', cancel);
      // A wall-clock deadline also bounds a peer that keeps dripping bytes;
      // socket inactivity timeouts alone never expire in that case.
      deadline = setTimeout(cancel, 3000);
    });
  }

  start(intervalMs = 1000) {
    this.stop();
    this.intervalMs = intervalMs;
    this.last = { up: 0, down: 0, t: Date.now() };
    this.lastPer = {};
    this.arm();
  }

  arm() {
    this.timer = setInterval(() => this.tick(), this.intervalMs);
    if (this.timer.unref) this.timer.unref();
  }

  /**
   * Change the cadence without losing the baseline. Speeds divide by the
   * MEASURED gap, so a slower tick reads the same bytes over a longer dt — not
   * a burst — and the usage meter works on deltas, so nothing is lost or
   * counted twice. Used to poll less while the window is hidden: a poll a
   * second is 3,600 requests and JSON parses an hour for numbers nobody sees.
   */
  retime(intervalMs) {
    if (!intervalMs || intervalMs === this.intervalMs) return;
    this.intervalMs = intervalMs;
    if (!this.timer) return;
    clearInterval(this.timer);
    this.arm();
  }

  async tick() {
    if (this.inFlight) return;
    const generation = this.generation;
    const pending = this.query();
    this.inFlight = pending;
    let cur;
    try { cur = await pending; }
    finally { if (this.inFlight === pending) this.inFlight = null; }
    if (!cur || generation !== this.generation) return;
    const now = Date.now();
    const dt = (now - this.last.t) / 1000 || 1;

    const upSpeed = Math.max(0, (cur.up - this.last.up) / dt);
    const downSpeed = Math.max(0, (cur.down - this.last.down) / dt);

    // per-outbound totals and their own per-second deltas, so the home path
    // can say how much went through EACH config rather than one grand total
    const per = {};
    for (const [tag, v] of Object.entries(cur.per || {})) {
      const prev = this.lastPer[tag] || { up: 0, down: 0 };
      per[tag] = {
        up: v.up, down: v.down,
        upSpeed: Math.max(0, (v.up - prev.up) / dt),
        downSpeed: Math.max(0, (v.down - prev.down) / dt)
      };
    }
    this.lastPer = cur.per || {};
    const groups = this.groupMap ? groupsLive(this.groupMap, cur.members || {}, this.lastMembers, cur.health || {}, dt) : null;
    this.lastMembers = cur.members || {};

    this.totals = { up: cur.up, down: cur.down };
    this.last = { up: cur.up, down: cur.down, t: now };

    this.onStats(Object.assign({
      upSpeed, downSpeed,
      totalUp: cur.up, totalDown: cur.down,
      per
    }, groups ? { groups } : {}));
  }

  stop() {
    this.generation++;
    if (this.cancelQuery) this.cancelQuery();
    this.inFlight = null;
    if (this.timer) { clearInterval(this.timer); this.timer = null; }
    this.last = { up: 0, down: 0, t: 0 };
    this.lastPer = {};
    this.lastMembers = {};
  }
}

/**
 * What the log says of a group's members as the core's health check moves
 * them: one line when a member stops answering (it is out of the rotation
 * until it answers again), one when it is back, and a warning when no member
 * of a group answers at all (its traffic then waits on the first). Nothing
 * for the first verdict of a connection — only changes. reset() at connect.
 *   update(groups) → [{ line, level }]
 */
class GroupHealthWatch {
  constructor() { this.seen = new Map(); this.allDown = new Set(); }
  reset() { this.seen.clear(); this.allDown.clear(); }
  update(groups) {
    const out = [];
    for (const g of Array.isArray(groups) ? groups : []) {
      if (!g || !Array.isArray(g.members)) continue;
      const label = g.name || g.groupId || g.tag;
      g.members.forEach((m, i) => {
        if (!m || (m.alive !== true && m.alive !== false)) return;
        const key = `${g.tag}~${i}`;
        const was = this.seen.get(key);
        this.seen.set(key, m.alive);
        if (was === undefined || was === m.alive) return;
        const who = (m.name || m.id || '#' + (i + 1)) + (m.address ? ` (${m.address}${m.port ? ':' + m.port : ''})` : '');
        out.push(m.alive
          ? { line: `Group ${label}: ${who} answers again — back in the rotation`, level: 'info' }
          : { line: `Group ${label}: ${who} stopped answering — left out until it answers again`, level: 'warn' });
      });
      const checked = g.members.filter((m) => m && (m.alive === true || m.alive === false));
      const none = checked.length > 0 && checked.length === g.members.length && checked.every((m) => m.alive === false);
      if (none && !this.allDown.has(g.tag)) { this.allDown.add(g.tag); out.push({ line: `Group ${label}: no member answers — its traffic waits on the first until one does`, level: 'warn' }); }
      if (!none) this.allDown.delete(g.tag);
    }
    return out;
  }
}

/**
 * Every WireGuard of a plan that goes through another config, by name:
 * [{ wg, hop }] — a rule's or the default's target through its via ('inherit'
 * or none given: the base), a chain's WireGuard through the member before it.
 * One dialled straight (via 'none', no base, a chain's first) is not here.
 */
function wgRides(plan) {
  const out = [];
  if (!plan) return out;
  const recs = plan.serversById || {};
  const chainOf = (ref) => (plan.chainsById || {})[String(ref).slice('chain:'.length)] || [];
  const nameOf = (ref) => {
    if (!ref || ref === 'direct' || ref === 'block') return '';
    if (String(ref).startsWith('chain:')) return chainOf(ref).map((s) => s && s.name).filter(Boolean).join(' → ');
    return recs[ref] ? recs[ref].name || ref : '';
  };
  const isWg = (s) => !!s && s.protocol === 'wireguard';
  const add = (wg, hop) => { if (wg && hop && !out.some((x) => x.wg === wg && x.hop === hop)) out.push({ wg, hop }); };
  const walk = (target, via) => {
    const front = via === 'none' ? '' : (via == null || via === 'inherit' ? plan.base || '' : via);
    if (String(target).startsWith('chain:')) {
      const m = chainOf(target);
      m.forEach((s, i) => { if (isWg(s)) add(s.name, i ? m[i - 1] && m[i - 1].name : nameOf(front)); });
    } else if (isWg(recs[target])) add(recs[target].name, nameOf(front));
  };
  if (plan.mode === 'chain') (plan.chain || []).forEach((s, i) => { if (i && isWg(s)) add(s.name, plan.chain[i - 1] && plan.chain[i - 1].name); });
  if (plan.mode === 'advanced') {
    for (const r of plan.rules || []) if (r) walk(r.target, r.via);
    walk(plan.def, plan.defVia);
  }
  return out;
}

/**
 * The core's own word when the config a WireGuard goes through drops it —
 * `proxy/wireguard: unexpected closed > io: read/write on closed pipe`, with
 * no name — said once a connection with the WireGuard and the config named:
 * that config is what is not working, not the WireGuard. reset(plan) at connect.
 *   onLine(line, lang) → { line, level } | null
 */
class WgHopWatch {
  constructor() { this.rides = []; this.said = false; }
  reset(plan) { this.rides = wgRides(plan); this.said = false; }
  onLine(line, lang) {
    if (this.said || !this.rides.length || !/proxy\/wireguard: unexpected closed|proxy\/wireguard:.*closed pipe/.test(String(line))) return null;
    this.said = true;
    const fa = lang !== 'en';
    const pairs = this.rides.map((r) => (fa ? `«${r.wg}» از «${r.hop}»` : `“${r.wg}” through “${r.hop}”`)).join(fa ? '، ' : ', ');
    return {
      line: this.rides.length === 1
        ? (fa
          ? `وایرگارد «${this.rides[0].wg}»: کانفیگی که از آن رد می‌شود («${this.rides[0].hop}») اتصالش را بست — آن کانفیگ الان ترافیک را عبور نمی‌دهد (خطای خودش معمولاً همین بالاست). در صفحهٔ اصلی تستش کن، یا برای این وایرگارد کانفیگ دیگری انتخاب کن.`
          : `WireGuard “${this.rides[0].wg}”: the config it goes through (“${this.rides[0].hop}”) closed on it — that config is not carrying traffic right now (its own error is usually just above). Test it on Home, or choose another config for this WireGuard.`)
        : (fa
          ? `یک وایرگارد کانفیگی را که از آن رد می‌شود از دست داد (${pairs}) — یکی از این کانفیگ‌ها الان ترافیک را عبور نمی‌دهد (خطای خودش معمولاً همین بالاست). در صفحهٔ اصلی تستشان کن، یا برای وایرگارد کانفیگ دیگری انتخاب کن.`
          : `A WireGuard lost the config it goes through (${pairs}) — one of those configs is not carrying traffic right now (its own error is usually just above). Test them on Home, or choose another config for the WireGuard.`),
      level: 'warn'
    };
  }
}

/**
 * The running groups as the window shows them, one tick: each group of the
 * map with its members' bytes, bytes per second and health — member i is
 * `<tag>~gm<i>`. (groups-ui/design.md §3)
 */
function groupsLive(map, members, lastMembers, health, dt) {
  return map.map((g) => ({
    tag: g.tag, groupId: g.groupId, name: g.name, strategy: g.strategy,
    members: (g.members || []).map((m, i) => {
      const tag = `${g.tag}~gm${i}`;
      const c = members[tag] || { up: 0, down: 0 };
      const p = lastMembers[tag] || { up: c.up, down: c.down };
      const h = health[tag];
      return Object.assign({}, m, {
        up: c.up, down: c.down,
        upSpeed: Math.max(0, (c.up - p.up) / dt),
        downSpeed: Math.max(0, (c.down - p.down) / dt),
        alive: h ? h.alive : null,
        delay: h ? h.delay : null
      });
    })
  }));
}

/**
 * The same counters, kept apart per outbound instead of summed.
 *
 * The home screen draws the path traffic actually takes — with advanced routing
 * that is several outbounds at once — and "how much went through THIS config"
 * is the question it exists to answer. `direct` is included (traffic that went
 * past the tunnel is exactly what a split-routing user wants to see) even
 * though sumOutbounds leaves it out of the proxy total; `block`, `dns-out` and
 * the anti-DPI dialers are not traffic anybody chose and stay out.
 */
function byOutbound(vars, skip) {
  const raw = vars && vars.stats && vars.stats.outbound;
  if (!raw || typeof raw !== 'object') return {};
  const out = foldGroups(raw);
  const res = {};
  for (const tag of Object.keys(out)) {
    if (tag === 'block' || tag === 'dns-out' || tag.startsWith('dpi-') || isHelperTag(tag) || (skip && skip.has(tag))) continue;
    const c = out[tag] || {};
    res[tag] = { up: num(c.uplink), down: num(c.downlink) };
  }
  return res;
}

/**
 * Watches named outbounds for the one failure the core will not report at the
 * default log level: bytes go out and nothing ever comes back.
 *
 * A WireGuard whose handshake never completes looks exactly like that — the
 * core writes a handshake initiation every five seconds and the downlink stays
 * at zero — and the only line it prints about it is [Debug]. To the user the
 * tunnel is simply "not working" while every other route is fine, which is
 * indistinguishable from a routing mistake and gets reported as one.
 *
 * Deliberately conservative: a tag must have sent a real amount and received
 * NOTHING AT ALL, for several consecutive ticks, and it is named once — a
 * tunnel that answers even one byte is working as far as this is concerned.
 */
class SilenceWatch {
  /**
   * @param {string[]} tags        outbound tags to watch
   * @param {object} [opts]        { minUp: bytes before judging, ticks: consecutive observations }
   */
  constructor(tags, opts = {}) {
    this.tags = new Set(tags || []);
    this.minUp = opts.minUp == null ? 4096 : opts.minUp;
    this.ticks = opts.ticks == null ? 3 : opts.ticks;
    this.runs = new Map();      // tag → consecutive silent observations
    this.reported = new Set();
  }

  /** Tags that have just crossed the threshold. Each is returned at most once. */
  check(vars) {
    const out = (vars && vars.stats && vars.stats.outbound) || {};
    const hit = [];
    for (const tag of this.tags) {
      const c = out[tag];
      if (!c) continue;
      if (num(c.downlink) > 0 || num(c.uplink) < this.minUp) { this.runs.set(tag, 0); continue; }
      const n = (this.runs.get(tag) || 0) + 1;
      this.runs.set(tag, n);
      if (n >= this.ticks && !this.reported.has(tag)) { this.reported.add(tag); hit.push(tag); }
    }
    return hit;
  }
}

module.exports = { StatsPoller, sumOutbounds, byOutbound, foldGroups, memberCounters, healthOf, groupsLive, GroupHealthWatch, wgRides, WgHopWatch, SilenceWatch };
