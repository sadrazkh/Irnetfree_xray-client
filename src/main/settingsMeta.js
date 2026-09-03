'use strict';
/**
 * Which settings are BAKED INTO a running connection.
 *
 * Everything in `RECONNECT_KEYS` is consumed either by buildConfig() (so it ends
 * up inside the xray config.json that was written at connect time) or by a
 * connect-time side effect (system proxy, TUN device, LAN firewall rule).
 * xray-core has no hot reload for any of it, so changing one of these while
 * connected does NOTHING until the tunnel is torn down and rebuilt.
 *
 * Persisting such a change silently is what made the app lie to the user: the
 * settings page showed "bypass Iran", the tunnel was still routing everything
 * global — or worse, the user switched *to* global expecting their traffic to be
 * tunnelled while it kept going direct. The UI now asks, and main.js keeps a
 * snapshot of the settings the live connection was actually built from
 * (see `pendingReconnectKeys`).
 *
 * Deliberately NOT in this list:
 *   killSwitch          — read live from the store when a drop is detected
 *   autoUpdateSubs/Interval — the subscription timer is re-armed in settings:set
 *   lang, theme         — renderer only
 */

/** Settings the running tunnel was built from; changing one needs a reconnect. */
const RECONNECT_KEYS = [
  // local inbounds / core config
  'socksPort', 'httpPort', 'apiPort', 'allowLan',
  'dnsManaged', 'dnsRemote', 'dnsDirect', 'ipv6', 'logLevel', 'enableSniffing',
  // routing
  'routingMode', 'blockAds', 'customRules',
  'advancedRouting', 'routeRules', 'routeDefault', 'procRouteWatch',
  // connect-time side effects
  'systemProxy', 'tunMode',
  // which core the config is validated on and started with
  'defaultEngine'
];

/**
 * Every key above has a human-readable name in the renderer under the i18n key
 * `set.<key>` (both languages), which is what the apply dialog lists so the user
 * sees *what* changed instead of a bare "some settings changed". Adding a key
 * here means adding those two strings to src/renderer/i18n.js.
 */

/**
 * Order-insensitive deep equality, enough for the shapes settings actually hold
 * (primitives, arrays of primitives, arrays of plain rule objects). Arrays ARE
 * order-sensitive here on purpose: routing rules are evaluated top-down, so
 * reordering them genuinely changes behaviour.
 */
function sameValue(a, b) {
  if (a === b) return true;
  if (a == null || b == null) return a == null && b == null;
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
    return a.every((v, i) => sameValue(v, b[i]));
  }
  if (typeof a === 'object' && typeof b === 'object') {
    const ka = Object.keys(a), kb = Object.keys(b);
    if (ka.length !== kb.length) return false;
    return ka.every(k => Object.prototype.hasOwnProperty.call(b, k) && sameValue(a[k], b[k]));
  }
  return false;
}

/**
 * Keys in `RECONNECT_KEYS` whose value differs between the settings the live
 * connection was built from (`applied`) and the current ones (`current`).
 *
 * `applied` is null when nothing is connected — then there is nothing to be out
 * of sync with and the result is always empty.
 */
function pendingReconnectKeys(applied, current) {
  if (!applied || !current) return [];
  return RECONNECT_KEYS.filter(k => !sameValue(applied[k], current[k]));
}

/** Snapshot the reconnect-relevant slice of a settings object (deep-copied). */
function snapshotApplied(settings) {
  const out = {};
  for (const k of RECONNECT_KEYS) {
    const v = settings ? settings[k] : undefined;
    out[k] = (v && typeof v === 'object') ? JSON.parse(JSON.stringify(v)) : v;
  }
  return out;
}

module.exports = { RECONNECT_KEYS, pendingReconnectKeys, snapshotApplied, sameValue };
