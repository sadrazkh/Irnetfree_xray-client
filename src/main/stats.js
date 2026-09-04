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
const isProxyTag = (tag) => !NOT_PROXY.has(tag) && !tag.startsWith('dpi-');

const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : 0);

/** { up, down } summed from a parsed /debug/vars body. Never throws, never NaN. */
function sumOutbounds(vars) {
  const out = vars && vars.stats && vars.stats.outbound;
  if (!out || typeof out !== 'object') return { up: 0, down: 0 };
  let up = 0, down = 0;
  for (const tag of Object.keys(out)) {
    if (!isProxyTag(tag)) continue;
    const c = out[tag] || {};
    up += num(c.uplink);
    down += num(c.downlink);
  }
  return { up, down };
}

class StatsPoller {
  /**
   * @param {object} opts { binPath, apiPort, onStats(stats) }
   */
  constructor(opts) {
    this.binPath = opts.binPath;
    this.apiPort = opts.apiPort || 10085;
    this.onStats = opts.onStats || (() => {});
    // the whole parsed body, for callers that need per-outbound counters and
    // not just the sum (see SilenceWatch)
    this.onRaw = opts.onRaw || (() => {});
    this.timer = null;
    this.last = { up: 0, down: 0, t: 0 };
    this.totals = { up: 0, down: 0 };
  }

  /**
   * No-op: the metrics endpoint needs no binary. Kept because main.js and
   * service.js mirror each other's call sites and both call it — removing it
   * would break them, and that is out of this change's scope.
   */
  setBin(p) { this.binPath = p; }

  query() {
    return new Promise((resolve) => {
      const req = http.get({ host: '127.0.0.1', port: this.apiPort, path: '/debug/vars', timeout: 3000 }, (res) => {
        if (res.statusCode !== 200) { res.resume(); return resolve(null); }
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (c) => { body += c; });
        res.on('end', () => {
          let parsed;
          try { parsed = JSON.parse(body); } catch { return resolve(null); }
          try { this.onRaw(parsed); } catch { /* a watcher must never stop the meter */ }
          resolve(sumOutbounds(parsed));
        });
      });
      req.on('error', () => resolve(null));
      req.on('timeout', () => { req.destroy(); resolve(null); });
    });
  }

  start(intervalMs = 1000) {
    this.stop();
    this.last = { up: 0, down: 0, t: Date.now() };
    this.timer = setInterval(async () => {
      const cur = await this.query();
      if (!cur) return;
      const now = Date.now();
      const dt = (now - this.last.t) / 1000 || 1;

      const upSpeed = Math.max(0, (cur.up - this.last.up) / dt);
      const downSpeed = Math.max(0, (cur.down - this.last.down) / dt);

      this.totals = { up: cur.up, down: cur.down };
      this.last = { up: cur.up, down: cur.down, t: now };

      this.onStats({
        upSpeed, downSpeed,
        totalUp: cur.up, totalDown: cur.down
      });
    }, intervalMs);
    if (this.timer.unref) this.timer.unref();
  }

  stop() {
    if (this.timer) { clearInterval(this.timer); this.timer = null; }
    this.last = { up: 0, down: 0, t: 0 };
  }
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

module.exports = { StatsPoller, sumOutbounds, SilenceWatch };
