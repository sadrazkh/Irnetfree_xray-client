'use strict';
/**
 * Per-app routing under the TUN: whether this connection gets a process rule.
 *
 * sing-box can route a packet by the name of the process that owns it
 * (`process_name`), so the tunnel can carry everything EXCEPT a few apps
 * ('exclude') or nothing except a few apps ('only'). Xray cannot do this at
 * all, and neither can tun2socks — the rule only exists inside the sing-box TUN
 * config, which is why the answer is decided here, at connect time, and baked
 * in (both keys are in RECONNECT_KEYS).
 *
 * Every "no" below is a promise being kept, so each one carries the reason as a
 * log line instead of silently dropping the user's rule:
 *
 *   1. the mode is off (or unrecognised)  — silent: nothing was asked for
 *   2. the mode is on but no app is named — the rule would mean nothing
 *   3. the backend is not sing-box        — tun2socks cannot route by process
 *   4. the leak guard is at 'strict'      — the guard promises that NOTHING
 *      leaves outside the tunnel. `exclude` walks the listed apps around it and
 *      `only` walks the whole rest of the system around it, so BOTH modes break
 *      that promise, not just `exclude`. The guard wins; it is the stronger
 *      claim, and a user who set it is entitled to it.
 *
 * The order matters: the first refusal is the one the user is told about, and
 * it has to be the setting they should go fix first.
 *
 * Node core only (no electron): src/server/service.js runs this headless too.
 */

/**
 * Process names as the OS shows them ('chrome.exe'), cleaned up for use.
 *
 * Trims, drops empties, drops anything that is not a string, and dedupes on the
 * first occurrence so the user's own order survives — the settings page shows
 * this list straight back to them. Anything that is not an array (an old store,
 * a hand-edited settings.json) is no list at all: [].
 *
 * Always a fresh array, so nothing downstream can write back into the store.
 *
 * @param {unknown} list
 * @returns {string[]}
 */
function normalizeAppNames(list) {
  if (!Array.isArray(list)) return [];
  const out = [];
  const seen = new Set();
  for (const entry of list) {
    if (typeof entry !== 'string') continue;
    const name = entry.trim();
    if (!name || seen.has(name)) continue;
    seen.add(name);
    out.push(name);
  }
  return out;
}

// "already carries an extension" is a SHORT alphanumeric tail: 'foo.scr' has
// one, 'OneDrive.Sync.Service' (whose image really is …Service.exe) does not.
const HAS_EXT = /\.[A-Za-z0-9]{1,4}$/;

/**
 * The Windows safety net for a hand-typed name: 'chrome' → 'chrome.exe'.
 *
 * Task Manager's Processes tab hides the extension, so 'chrome' is exactly what
 * a user reads off the screen and types in — while sing-box matches the image
 * file's leaf name (`filepath.Base(ProcessPath)`), so that rule would never
 * fire. Only on Windows: a mac/linux binary has no extension. The picker does
 * not need this — it already offers the exact name (procRouter's `exeNameOf`) —
 * but the box next to it takes free text.
 *
 * Deduped again afterwards, so 'chrome' + 'chrome.exe' is one name, not two.
 */
function withExeSuffix(names, platform) {
  if (platform !== 'win32') return names;
  const seen = new Set();
  const out = [];
  for (const name of names) {
    const full = HAS_EXT.test(name) ? name : name + '.exe';
    if (seen.has(full)) continue;
    seen.add(full);
    out.push(full);
  }
  return out;
}

/**
 * The per-app rule for this connection, or null with the reason it was refused.
 *
 * Never throws: `settings` may be missing, half-migrated or hold junk in either
 * key, and a bad store must not be able to break a connect.
 *
 * @param {object|null|undefined} settings  the live settings object
 * @param {string|null|undefined} backendId the TUN backend about to run ('sing-box' | …)
 * @param {string} platform  where the tunnel is about to run; passed in so it is testable
 * @returns {{ apps: { mode: 'exclude'|'only', names: string[] }|null, warn: string|null }}
 */
function appsForTun(settings, backendId, platform = process.platform) {
  const s = (settings && typeof settings === 'object') ? settings : {};

  const mode = s.tunAppMode;
  if (mode !== 'exclude' && mode !== 'only') return { apps: null, warn: null };

  const names = normalizeAppNames(s.tunApps);
  if (!names.length) {
    return { apps: null, warn: 'Per-app routing is on but no app is listed — ignored' };
  }
  if (backendId !== 'sing-box') {
    return { apps: null, warn: 'Per-app routing needs the sing-box TUN backend — ignored' };
  }
  if (s.leakGuard === 'strict') {
    return {
      apps: null,
      warn: 'Per-app routing is off under the strict guard: the guard promises nothing leaves outside the tunnel, and either mode would send some app around it'
    };
  }
  return { apps: { mode, names: withExeSuffix(names, platform) }, warn: null };
}

module.exports = { normalizeAppNames, appsForTun };
