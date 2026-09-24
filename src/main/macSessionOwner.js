'use strict';
/**
 * Who wrote a macOS tunnel journal, and what a reconnect hands to the next one
 * (at the end) — shared by both backends (tunSingbox.js, tunManager.js).
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

/**
 * `{ start }` of a running pid — plus `command` when asked for (a second `ps`,
 * needed only for a journal without a start time) — or null when `ps` has
 * nothing to say.
 */
async function processIdentity(pid, { command = false } = {}) {
  try {
    const opts = { timeout: 3000 };
    const start = (await platform.run('ps', ['-ww', '-p', String(pid), '-o', 'lstart='], opts)).trim();
    if (!start) return null;
    if (!command) return { start };
    return { start, command: (await platform.run('ps', ['-ww', '-p', String(pid), '-o', 'command='], opts)).trim() };
  } catch { return null; }
}

const defaultProbe = { signal: signalState, identity: processIdentity };

async function identityOf(probe, pid, opts) {
  try { return (await probe.identity(pid, opts)) || null; } catch { return null; }
}

/** The journal fields that name THIS process as the owner (one `ps` per connect). */
async function ownerRecord(probe = defaultProbe) {
  const id = await identityOf(probe, process.pid);
  return { ownerPid: process.pid, ownerStart: (id && id.start) || null };
}

/** Whether the app process that wrote `st` is still running (see above). */
async function ownerAlive(st, probe = defaultProbe, execPath = process.execPath) {
  const pid = st && st.ownerPid;
  if (!Number.isInteger(pid) || pid <= 1 || pid === process.pid) return false;
  if (probe.signal(pid) !== 'ours') return false;
  const hasStart = typeof st.ownerStart === 'string' && !!st.ownerStart;
  const id = await identityOf(probe, pid, { command: !hasStart });
  if (!id) return false;
  if (hasStart) return id.start === st.ownerStart;
  const command = String(id.command || '');
  return !!execPath && (command === execPath || command.startsWith(execPath + ' '));
}

/**
 * The code on every recovery refusal that means "a LIVE tunnel owns this" —
 * another instance, an operation in flight, this very tunnel still up.
 * macRecovery.js then leaves the guard's DNS alone: restoring it would put the
 * live tunnel's services back on the ISP's resolver under it.
 */
const LIVE_TUNNEL = 'IRNF_TUNNEL_LIVE';
function liveTunnelError(message) { return Object.assign(new Error(message), { code: LIVE_TUNNEL }); }

/** A root tunnel process (sing-box / tun2socks): EPERM means it runs, only ESRCH means it is gone. */
function pidAlive(pid, probe = defaultProbe) {
  return Number.isInteger(pid) && pid > 1 && probe.signal(pid) !== 'gone';
}

/*
 * What a reconnect hands over. Its stop keeps the service on the tunnel's
 * resolver (`keepDns`: the leak guard is holding it there), so the next start
 * of this app would read THAT back as the service's original DNS and journal
 * it — and a disconnect, or a crash recovery, would then "restore" a resolver
 * that routes nowhere. The stopping session leaves its originals here, keyed
 * like the session lock; the next start uses them while the service still
 * lists only what a tunnel set. Anything else is a change made in between, and
 * the fresh reading wins.
 *
 * Read with peek, and dropped only once a start has SUCCEEDED — its journal
 * holds them from then on. Consuming them on read lost them to any rebuild
 * that failed after it (a cancelled prompt, a sing-box that died and rolled
 * back), and the retry then journalled the tunnel peer as the original.
 */
const dnsHandover = new Map();

function handOverDns(key, st) {
  if (!st || !st.service || !Array.isArray(st.savedDns) || !Array.isArray(st.tunDns)) return;
  dnsHandover.set(key, { service: st.service, savedDns: st.savedDns.slice(), tunDns: st.tunDns.slice() });
}

function peekHandedOverDns(key, service, current) {
  const h = dnsHandover.get(key);
  if (!h || h.service !== service) return null;
  const set = new Set(h.tunDns.map(s => String(s).toLowerCase()));
  const now = (current || []).map(s => String(s).toLowerCase());
  return now.length && now.every(s => set.has(s)) ? h.savedDns.slice() : null;
}

function dropHandedOverDns(key) { dnsHandover.delete(key); }

module.exports = {
  signalState, processIdentity, defaultProbe, ownerRecord, ownerAlive, pidAlive, LIVE_TUNNEL, liveTunnelError,
  handOverDns, peekHandedOverDns, dropHandedOverDns
};
