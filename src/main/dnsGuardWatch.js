'use strict';

// Recheck DNS ownership without rebuilding a healthy tunnel. A receipt binds
// every refresh to the guard session that started this watch.
class DnsGuardWatch {
  constructor({ guard, isActive, onError = () => {}, interval = 30000 }) {
    this.guard = guard;
    this.isActive = isActive;
    this.onError = onError;
    this.interval = interval;
    this.token = null;
    this.timer = null;
    this.inFlight = false;
    this.warned = false;
  }
  start(token) {
    this.stop();
    if (!token) return;
    this.token = token;
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
    this.inFlight = true;
    try {
      await this.guard.refresh({ token });
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
