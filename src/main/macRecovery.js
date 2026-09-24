'use strict';
/**
 * macOS network recovery — at launch and from "Recover network" (main.js and
 * its mirror service.js).
 *
 * Three backends can leave something behind: the native daemon's session, a
 * sing-box journal, a tun2socks journal; and the leak guard can leave every
 * network service on the tunnel peer. That used to be a row of awaits, so the
 * first step to throw ended it: a native service that was enabled but not
 * answering threw before anything else ran, the guard never gave the services
 * their DNS back, and every Connect was refused until a reboot.
 *
 * Now each step runs whatever the one before it did, a failure is logged, and
 * the guard's step (when given) always runs. The native daemon still goes
 * first — it can be holding the system's DNS right now, and the root daemon
 * outlives the app — but its failure gates nothing: a Connect on sing-box or
 * tun2socks never talks to the daemon, and the native backend's own start()
 * stops a session the daemon still holds before starting another.
 */

const { NativeMacTun } = require('./nativeMacTun');
const { TunSingbox } = require('./tunSingbox');
const { TunManager } = require('./tunManager');

/**
 * @param {{ userData: string, guard?: Function, onLog?: Function, backends?: object }} opts
 *   `guard` is the leak guard's step (repairAtLaunch at launch); `backends` is
 *   for tests.
 * @returns {Promise<Error|null>} what must gate Connect — never rejects.
 */
async function recoverMacNetwork({ userData, guard, onLog = () => {}, backends = {} } = {}) {
  const Native = backends.NativeMacTun || NativeMacTun;
  const Singbox = backends.TunSingbox || TunSingbox;
  const Legacy = backends.TunManager || TunManager;
  const steps = [
    ['the native macOS service', false, () => new Native({ userData }).recoverMacSessions()],
    ['the sing-box tunnel', true, () => new Singbox({ userData }).recoverMacSessions()],
    ['the tun2socks tunnel', true, () => new Legacy({ userData }).recoverMacSessions()]
  ];
  if (guard) steps.push(['the saved DNS', true, guard]);
  const failed = [];
  for (const [name, gates, run] of steps) {
    try { await run(); } catch (e) {
      const message = (e && e.message) || String(e);
      try { onLog(`Network recovery: ${name} failed — ${message}`, gates ? 'error' : 'warn'); } catch {}
      if (gates) failed.push(`${name}: ${message}`);
    }
  }
  return failed.length ? new Error('Network recovery incomplete — ' + failed.join('; ')) : null;
}

module.exports = { recoverMacNetwork };
