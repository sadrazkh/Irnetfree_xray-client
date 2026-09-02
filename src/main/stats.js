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
          try { resolve(sumOutbounds(JSON.parse(body))); } catch { resolve(null); }
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

module.exports = { StatsPoller, sumOutbounds };
