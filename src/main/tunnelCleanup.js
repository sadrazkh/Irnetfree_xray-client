'use strict';

// Failed macOS teardown must remain retryable. Other platforms retain their
// existing best-effort behavior; this does not change their networking policy.
async function stopTrackedTunnels(started, current, platform = process.platform) {
  const all = new Set(started);
  if (current) all.add(current);
  if (platform !== 'darwin') {
    started.clear();
    for (const tunnel of all) { try { await tunnel.stop(); } catch {} }
    return;
  }
  const failures = [];
  for (const tunnel of all) {
    try { await tunnel.stop(); started.delete(tunnel); }
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

module.exports = { stopTrackedTunnels, releaseGuardChecked };
