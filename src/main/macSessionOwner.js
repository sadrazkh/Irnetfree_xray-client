'use strict';
/**
 * Who wrote a macOS tunnel journal — shared by both backends (tunSingbox.js,
 * tunManager.js).
 *
 * Every journal names the app process that started its tunnel (`ownerPid`), so
 * a second instance never tears down a tunnel a live one is using. A pid alone
 * is not an identity: after a reboot — and "Start at login" makes that the
 * usual launch — the number belongs to some other process. `process.kill(pid,
 * 0)` then succeeded (or failed with EPERM, for a root process), recovery threw
 * "Another application instance may own this tunnel", and because that throw
 * came first, the DNS repair after it never ran: every network service stayed
 * on the tunnel peer and every Connect was refused.
 *
 * So the journal also carries the owner's start time (`ownerStart`: `ps -o
 * lstart=`, the same identity the scripts already use for sing-box itself), and
 * the owner counts as alive only when the pid AND that start time match. A pid
 * we may not signal (EPERM) is another user's — root's — and the app never runs
 * as root, so it is never an instance of this app. A journal written before
 * the start time was recorded counts as live only while its pid runs this very
 * executable.
 *
 * The probe is injected in tests; nothing here changes anything.
 */

const platform = require('./tunPlatform');

/** `process.kill(pid, 0)` in words: 'ours' (we may signal it), 'other' (EPERM), 'gone'. */
function signalState(pid) {
  try { process.kill(pid, 0); return 'ours'; }
  catch (e) { return e && e.code === 'EPERM' ? 'other' : 'gone'; }
}

/** `{ start, command }` of a running pid, or null when `ps` has nothing to say. */
async function processIdentity(pid) {
  try {
    const opts = { timeout: 3000 };
    const start = (await platform.run('ps', ['-ww', '-p', String(pid), '-o', 'lstart='], opts)).trim();
    const command = (await platform.run('ps', ['-ww', '-p', String(pid), '-o', 'command='], opts)).trim();
    return start ? { start, command } : null;
  } catch { return null; }
}

const defaultProbe = { signal: signalState, identity: processIdentity };

async function identityOf(probe, pid) {
  try { return (await probe.identity(pid)) || null; } catch { return null; }
}

/** The journal fields that name THIS process as the owner. */
async function ownerRecord(probe = defaultProbe) {
  const id = await identityOf(probe, process.pid);
  return { ownerPid: process.pid, ownerStart: (id && id.start) || null };
}

/** Whether the app process that wrote `st` is still running (see above). */
async function ownerAlive(st, probe = defaultProbe, execPath = process.execPath) {
  const pid = st && st.ownerPid;
  if (!Number.isInteger(pid) || pid <= 1 || pid === process.pid) return false;
  if (probe.signal(pid) !== 'ours') return false;
  const id = await identityOf(probe, pid);
  if (!id) return false;
  if (typeof st.ownerStart === 'string' && st.ownerStart) return id.start === st.ownerStart;
  const command = String(id.command || '');
  return !!execPath && (command === execPath || command.startsWith(execPath + ' '));
}

/** A root tunnel process (sing-box / tun2socks): EPERM means it runs, only ESRCH means it is gone. */
function pidAlive(pid, probe = defaultProbe) {
  return Number.isInteger(pid) && pid > 1 && probe.signal(pid) !== 'gone';
}

module.exports = { signalState, processIdentity, defaultProbe, ownerRecord, ownerAlive, pidAlive };
