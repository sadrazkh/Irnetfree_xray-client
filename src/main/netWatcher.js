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

/** fe80::/10 — regenerated on every adapter recreation, never a routing fact. */
function isLinkLocalV6(address) {
  return /^fe[89ab]/i.test(String(address || ''));
}

/**
 * A stable signature of the machine's routable addresses. Interface order and
 * internal (loopback) addresses are ignored, so a re-enumeration that returns
 * the same network in a different order is NOT a change.
 *
 * Two more things are deliberately outside the signature:
 *
 *  - Any interface `ignoreInterface(name)` claims. The app creates its OWN
 *    adapter in TUN mode, and rebuilding the tunnel destroys and recreates it —
 *    so counting it would make every recovery produce the change that triggers
 *    the next one, forever. The predicate is a parameter rather than baked in
 *    because this function stays pure and directly testable; the watcher passes
 *    the one its owner injected (see NetWatcher#fp).
 *  - IPv6 link-local addresses. Windows hands a recreated adapter a fresh GUID
 *    and therefore a fresh fe80:: address, which says nothing about routing.
 *
 * @param {object} interfaces os.networkInterfaces()-shaped object
 * @param {(name: string) => boolean} [ignoreInterface] defaults to ignoring nothing
 */
function fingerprint(interfaces, ignoreInterface) {
  const skip = typeof ignoreInterface === 'function' ? ignoreInterface : () => false;
  const parts = [];
  for (const name of Object.keys(interfaces || {})) {
    if (skip(name)) continue;
    for (const ni of (interfaces[name] || [])) {
      if (!ni || ni.internal) continue;
      if (isLinkLocalV6(ni.address)) continue;
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
   *   ignoreInterface(name) -> true for interfaces that are none of our business
   *                            (the owner passes the adapters IT creates)
   *   debounceMs        -> how long the network must hold still before we act
   *   intervalMs        -> poll period
   *   setTimer/clearTimer -> injectable setInterval/clearInterval
   */
  constructor(opts = {}) {
    this.read = opts.read || (() => ({}));
    this.onChange = opts.onChange || (() => {});
    this.ignoreInterface = opts.ignoreInterface || (() => false);
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

  /** The current network, as this watcher chooses to see it. */
  fp() {
    return fingerprint(this.read(), this.ignoreInterface);
  }

  start() {
    if (this.timer) return;
    this.last = this.fp();
    this.pending = null;
    this.settledFor = 0;
    this.timer = this.setTimer(() => this.tick(), this.intervalMs);
  }

  /**
   * Adopt the network as it is right now as the baseline, and forget a change
   * that was only half-observed.
   *
   * The owner calls this when a recovery finishes: the tunnel it just rebuilt was
   * built for THIS network, so nothing about it is news. Without it, everything
   * seen during the teardown — an adapter down, a route gone — is still sitting
   * in `pending` and settles into a trigger for a rebuild that already happened.
   *
   * `queued` and `busy` are deliberately untouched: a trigger that arrived during
   * the recovery is a real change the rebuild in flight did NOT cover, and
   * dropping it here would leave the tunnel dead with nothing left to fire again.
   */
  rebaseline() {
    this.last = this.fp();
    this.pending = null;
    this.settledFor = 0;
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
    const fp = this.fp();
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
    this.last = this.fp();                   // adopt the current network as the baseline
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
