'use strict';

// Recheck DNS ownership without rebuilding a healthy tunnel. A receipt binds
// every refresh to the guard session that started this watch.
class DnsGuardWatch {
  /**
   * `fullEvery`: the first tick of a session and every Nth after it ask the
   * guard for a FULL refresh (on Windows the PowerShell snapshot that can find
   * an adapter that came up since); the ticks between are the cheap check
   * only. See LeakGuard.refresh.
   */
  constructor({ guard, isActive, onError = () => {}, interval = 30000, fullEvery = 10 }) {
    this.guard = guard;
    this.isActive = isActive;
    this.onError = onError;
    this.interval = interval;
    this.fullEvery = Math.max(1, Math.floor(Number(fullEvery) || 1));
    this.token = null;
    this.timer = null;
    this.inFlight = false;
    this.warned = false;
    this.ticks = 0;
  }
  start(token) {
    this.stop();
    if (!token) return;
    this.token = token;
    this.ticks = 0;
    this.timer = setInterval(() => { void this.tick(); }, this.interval);
    this.timer.unref?.();
  }
  stop() {
    clearInterval(this.timer);
    this.timer = null;
    this.token = null;
    this.warned = false;
  }
  async tick() {
    if (!this.token || this.inFlight || !this.isActive()) return;
    const token = this.token;
    const full = this.ticks % this.fullEvery === 0;
    this.ticks++;
    this.inFlight = true;
    try {
      await this.guard.refresh({ token, full });
      if (this.token === token) this.warned = false;
    } catch (error) {
      if (this.token === token && !this.warned) {
        this.warned = true;
        this.onError(error);
      }
    } finally { this.inFlight = false; }
  }
}

module.exports = { DnsGuardWatch };
