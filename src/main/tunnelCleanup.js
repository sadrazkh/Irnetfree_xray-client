'use strict';

// Failed macOS teardown must remain retryable. Other platforms retain their
// existing best-effort behavior; this does not change their networking policy.
// `stopOpts` go to every tunnel's stop() — `{ keepDns: true }` for a reconnect.
async function stopTrackedTunnels(started, current, platform = process.platform, stopOpts) {
  const all = new Set(started);
  if (current) all.add(current);
  if (platform !== 'darwin') {
    started.clear();
    for (const tunnel of all) { try { await tunnel.stop(stopOpts); } catch {} }
    return;
  }
  const failures = [];
  for (const tunnel of all) {
    try { await tunnel.stop(stopOpts); started.delete(tunnel); }
    catch (error) {
      if (platform === 'darwin') { started.add(tunnel); failures.push(error); }
      else started.delete(tunnel);
    }
  }
  if (failures.length) throw new Error('Tunnel cleanup incomplete; retry network recovery. ' + failures.map(e => e.message || String(e)).join('; '));
}

async function releaseGuardChecked(guard, platform = process.platform) {
  if (!guard) return;
  const result = await guard.release();
  if (platform === 'darwin' && result && result.error) throw new Error('DNS recovery incomplete: ' + result.error);
  return result;
}

// A guard held for a tunnel that is not coming back — a settings apply that
// turned TUN off (the reapply holds it across the rebuild), a connect after a
// recovery was given up on — keeps every adapter on a resolver that answers
// nothing, and a connect without a tunnel never engages or releases one: the
// whole proxy session would run with no DNS at all. That connect gives it back
// itself. Only a DNS override counts (engage always records its peer): proxy
// mode's own UDP block names no resolver, and the connect renews it — lifting
// it here would open the WebRTC leak for the switch. Never throws; resolves the
// release's answer, or null when nothing was held.
async function releaseStrandedGuard(guard) {
  if (!guard) return null;
  let st = null;
  try { st = guard.readState(); } catch { /* unreadable: nothing we can give back */ }
  if (!st || !st.peer4) return null;
  try { return await guard.release(); }
  catch (e) { return { released: false, error: (e && e.message) || String(e) }; }
}

module.exports = { stopTrackedTunnels, releaseGuardChecked, releaseStrandedGuard };
