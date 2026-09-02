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
    this.queued = null;       // reason of a trigger that arrived during that recovery
    this.gen = 0;             // bumped by stop(); an older run's result is ignored
  }

  start() {
    if (this.timer) return;
    this.last = fingerprint(this.read());
    this.pending = null;
    this.settledFor = 0;
    this.timer = this.setTimer(() => this.tick(), this.intervalMs);
  }

  /**
   * Also the reset for a recovery that never finished: without releasing `busy`
   * here, a hung onChange would leave the watcher permanently deaf and not even
   * stop()/start() could revive it.
   */
  stop() {
    this.pending = null;
    this.settledFor = 0;
    this.busy = false;
    this.queued = null;
    this.gen++;               // whatever was in flight no longer speaks for us
    if (!this.timer) return;
    this.clearTimer(this.timer);
    this.timer = null;
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

  /**
   * Run onChange, holding off further triggers until it settles.
   *
   * A trigger that arrives DURING a recovery is remembered, not dropped: the
   * rebuild in flight was made for the network we have already left, so throwing
   * the newer trigger away would leave the tunnel dead with nothing left to fire
   * again (tick() has already adopted the new fingerprint as its baseline).
   */
  fire(reason) {
    if (this.busy) { this.queued = reason; return; }
    this.busy = true;
    const gen = this.gen;
    let r;
    try { r = this.onChange(reason); } catch { this.settle(gen); return; }
    if (r && typeof r.then === 'function') r.then(() => this.settle(gen), () => this.settle(gen));
    else this.settle(gen);
  }

  /** A recovery finished: release the lock and run whatever arrived meanwhile. */
  settle(gen) {
    if (gen !== this.gen) return;    // a stop() happened while this run was in flight
    this.busy = false;
    const queued = this.queued;
    if (queued == null) return;
    this.queued = null;
    this.fire(queued);
  }
}

module.exports = { NetWatcher, fingerprint };
