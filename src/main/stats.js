'use strict';
/**
 * Live traffic stats via Xray's gRPC StatsService — but to avoid pulling a gRPC
 * dependency, we query the same counters through the HTTP-less approach: Xray's
 * `api` inbound (dokodemo-door) exposes StatsService over gRPC only, so instead
 * we shell out to the bundled `xray api statsquery` command which talks to the
 * local API port and prints JSON.
 *
 * Counters we read (set up in configBuilder):
 *   outbound>>>proxy>>>traffic>>>uplink
 *   outbound>>>proxy>>>traffic>>>downlink
 *
 * We compute per-second deltas to show live speed.
 */

const { execFile } = require('child_process');

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

  setBin(p) { this.binPath = p; }

  query() {
    return new Promise((resolve) => {
      if (!this.binPath) return resolve(null);
      execFile(this.binPath, ['api', 'statsquery', `--server=127.0.0.1:${this.apiPort}`],
        { windowsHide: true, timeout: 4000 }, (err, stdout) => {
          if (err) return resolve(null);
          try {
            const data = JSON.parse(stdout);
            const stat = data.stat || [];
            let up = 0, down = 0;
            for (const s of stat) {
              if (s.name === 'outbound>>>proxy>>>traffic>>>uplink') up = Number(s.value || 0);
              if (s.name === 'outbound>>>proxy>>>traffic>>>downlink') down = Number(s.value || 0);
            }
            resolve({ up, down });
          } catch {
            resolve(null);
          }
        });
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

module.exports = { StatsPoller };
