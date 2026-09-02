'use strict';
/**
 * Watches for the machine's network changing underneath a live tunnel.
 *
 * Why this exists: a Wi-Fi ↔ ethernet switch, a new DHCP lease or a wake from
 * sleep does NOT kill xray-core — it only breaks its sockets. So the app's
 * 'stopped' path never fires, the TUN bypass routes still point at the old
 * gateway, and the UI keeps saying "connected" while nothing passes. Other
 * clients recover in seconds; this is how we do.
 *
 * The module is pure enough to test: the interface reader and the clock are
 * injected, so no test needs a real NIC or a real timer.
 */

/**
 * A stable signature of the machine's routable addresses. Interface order and
 * internal (loopback) addresses are ignored, so a re-enumeration that returns
 * the same network in a different order is NOT a change.
 */
function fingerprint(interfaces) {
  const parts = [];
  for (const name of Object.keys(interfaces || {})) {
    for (const ni of (interfaces[name] || [])) {
      if (!ni || ni.internal) continue;
      parts.push(`${name}|${ni.family}|${ni.address}`);
    }
  }
  return parts.sort().join(',');
}

class NetWatcher {
  /**
   * @param {object} opts
   *   read()            -> os.networkInterfaces()-shaped object
   *   onChange(reason)  -> 'interfaces' | 'resume' | 'online'; may return a promise
   *   debounceMs        -> how long the network must hold still before we act
   *   intervalMs        -> poll period
   *   setTimer/clearTimer -> injectable setInterval/clearInterval
   */
  constructor(opts = {}) {
    this.read = opts.read || (() => ({}));
    this.onChange = opts.onChange || (() => {});
    this.debounceMs = opts.debounceMs == null ? 2500 : opts.debounceMs;
    this.intervalMs = opts.intervalMs || 3000;
    this.setTimer = opts.setTimer || ((fn, ms) => setInterval(fn, ms));
    this.clearTimer = opts.clearTimer || ((h) => clearInterval(h));
    this.timer = null;
    this.last = null;         // fingerprint of the last settled network
    this.pending = null;      // fingerprint seen while the network is still moving
    this.settledFor = 0;      // ms the pending fingerprint has held
    this.busy = false;        // a recovery is in flight
  }

  start() {
    if (this.timer) return;
    this.last = fingerprint(this.read());
    this.pending = null;
    this.settledFor = 0;
    this.timer = this.setTimer(() => this.tick(), this.intervalMs);
  }

  stop() {
    if (!this.timer) return;
    this.clearTimer(this.timer);
    this.timer = null;
    this.pending = null;
    this.settledFor = 0;
  }

  /** One poll. Fires onChange only once the new fingerprint has held still. */
  tick() {
    const fp = fingerprint(this.read());
    if (fp === this.last) { this.pending = null; this.settledFor = 0; return; }
    if (fp !== this.pending) { this.pending = fp; this.settledFor = 0; return; }  // still moving
    this.settledFor += this.intervalMs;
    if (this.settledFor < this.debounceMs) return;
    this.last = fp;
    this.pending = null;
    this.settledFor = 0;
    this.fire('interfaces');
  }

  /** An out-of-band signal (power resume, browser 'online'). */
  poke(reason) {
    if (!this.timer) return;                 // not watching: nothing to recover
    this.last = fingerprint(this.read());    // adopt the current network as the baseline
    this.fire(reason || 'poke');
  }

  /** Run onChange, ignoring further triggers until it settles. */
  fire(reason) {
    if (this.busy) return;
    this.busy = true;
    let r;
    try { r = this.onChange(reason); } catch { this.busy = false; return; }
    if (r && typeof r.then === 'function') r.then(() => { this.busy = false; }, () => { this.busy = false; });
    else this.busy = false;
  }
}

module.exports = { NetWatcher, fingerprint };
