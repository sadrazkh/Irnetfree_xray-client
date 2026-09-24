'use strict';
/**
 * How many times a live connection may drop on its own — the core exiting, the
 * TUN backend dying, a reload leaving no core — before the app stops rebuilding
 * it by itself.
 *
 * The recovery after a drop is bounded per episode (main.js runRecovery: the
 * backoff, then 'reconnect-failed'), but only for an attempt that FAILS. A core
 * that comes up, survives the start-up grace and dies a few seconds later is a
 * successful rebuild every time, so each death would open a fresh episode: the
 * tunnel torn down and rebuilt in a loop, for as long as the app runs. This
 * counts the drops in a sliding window and says when enough is enough; the
 * user's own connect or disconnect starts it over.
 */
class DropBudget {
  /**
   * @param {object} [opts]
   *   limit    — drops allowed inside the window (the next one is refused)
   *   windowMs — how far back a drop still counts
   *   now      — injectable clock
   */
  constructor({ limit = 3, windowMs = 5 * 60 * 1000, now = Date.now } = {}) {
    this.limit = limit;
    this.windowMs = windowMs;
    this.now = now;
    this.times = [];
  }

  /** Record a drop. true while the drops inside the window are within the limit. */
  take() {
    const t = this.now();
    this.times = this.times.filter((x) => t - x < this.windowMs);
    this.times.push(t);
    return this.times.length <= this.limit;
  }

  reset() { this.times = []; }
}

module.exports = { DropBudget };
