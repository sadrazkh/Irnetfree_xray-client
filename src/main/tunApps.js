'use strict';
/**
 * Per-app routing under the TUN: whether this connection gets a process rule.
 *
 * sing-box can route a packet by the name of the process that owns it
 * (`process_name`), so the tunnel can carry everything EXCEPT a few apps
 * ('exclude') or nothing except a few apps ('only'). Xray cannot do this at
 * all, and neither can tun2socks — the rule only exists inside the sing-box TUN
 * config, which is why the answer is decided here, at connect time, and baked
 * in (all three keys are in RECONNECT_KEYS).
 *
 * Every "no" below is a promise being kept, so each one carries the reason as a
 * log line instead of silently dropping the user's rule:
 *
 *   1. the mode is off (or unrecognised)  — silent: nothing was asked for
 *   2. the mode is on but no app is named — the rule would mean nothing
 *   3. the backend is 'native-macos'      — the macOS service runs a sing-box
 *      TUN, but the app does not write that config: it hands the daemon a fixed
 *      set of fields with no room for a process rule, so the rule would be
 *      accepted here and dropped there. Its own reason, because the fix is a
 *      different one (switch to the compatibility backend).
 *   4. the backend is not sing-box        — tun2socks cannot route by process
 *   5. the leak guard is at 'strict'      — the guard promises that NOTHING
 *      leaves outside the tunnel. `exclude` walks the listed apps around it and
 *      `only` walks the whole rest of the system around it, so BOTH modes break
 *      that promise, not just `exclude`. The guard wins; it is the stronger
 *      claim, and a user who set it is entitled to it. (Since per-app configs
 *      an `exclude` app whose target stays inside the tunnel is kept — below.)
 *
 * The order matters: the first refusal is the one the user is told about, and
 * it has to be the setting they should go fix first.
 *
 * Per-app configs (`tunAppTargets`, tunAppTargets.js): every listed app can name the
 * config it rides — { [appName]: target }, a target as the pickers store it:
 * '' (the connection itself), 'direct', 'block', a server's or a group's id,
 * 'chain:<id>'. An app the map does not name takes its mode's default, which
 * is exactly what it did before the map existed: `exclude` → 'direct' (around
 * the tunnel), `only` → '' (through it). So the mode now says what the apps
 * NOT on the list do (`exclude`: they ride the connection; `only`: they go
 * direct), and each listed app's picker says where it goes. A store without
 * the map behaves as it always did, byte for byte.
 *
 * The strict guard, thought through again for targets: what it forbids is
 * traffic leaving OUTSIDE the tunnel. A config of an app's own is not that —
 * the app's packets still enter the TUN, and Xray carries them to that
 * config's server exactly as it carries the connection's (its entry addresses
 * get the same firewall holes the connection's do: main.js). 'block' leaves
 * nothing at all. Only 'direct' leaves outside it. So under strict:
 *   - `only` is refused whole, as before: the rest of the system goes direct;
 *   - `exclude` keeps every app whose route stays inside — a config, the
 *     connection, block — and drops each app that would go direct, by name in
 *     the log (it then rides the connection like any unlisted app). When no
 *     app is left, it is the old refusal word for word.
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

/** A target as the pickers store it — the users module's rule (lanUsers/model.js targetOk), one id shape for both. */
const TARGET_ID = /^[\w-]+$/;
function targetOk(t) {
  if (t === '' || t === 'direct' || t === 'block') return true;
  if (typeof t !== 'string') return false;
  return t.indexOf('chain:') === 0 ? TARGET_ID.test(t.slice('chain:'.length)) : TARGET_ID.test(t);
}

/**
 * `tunAppTargets` cleaned: { [name]: target } with the name trimmed and the
 * target one a picker could have stored. Anything else is dropped — an entry
 * the builder cannot read takes its mode's default, never a guess. Anything
 * that is not a plain object (an old store, a hand-edited settings.json) is
 * no map at all: {}. Always a fresh object.
 *
 * @param {unknown} map
 * @returns {Object<string, string>}
 */
function normalizeAppTargets(map) {
  const out = {};
  if (!map || typeof map !== 'object' || Array.isArray(map)) return out;
  for (const [key, target] of Object.entries(map)) {
    const name = key.trim();
    if (!name || !targetOk(target) || Object.prototype.hasOwnProperty.call(out, name)) continue;
    out[name] = target;
  }
  return out;
}

/** What a listed app does when the map does not name it: what the mode always did. */
const defaultTarget = (mode) => (mode === 'exclude' ? 'direct' : '');

/**
 * The per-app rule for this connection, or null with the reason it was refused.
 *
 * Never throws: `settings` may be missing, half-migrated or hold junk in any
 * key, and a bad store must not be able to break a connect.
 *
 * `apps.to` (only when some app's target differs from its mode's default):
 * { [name]: target } for those apps alone, keyed by the name handed over
 * (after the Windows suffix). Without it the answer is the one before
 * `tunAppTargets` existed, field for field.
 *
 * @param {object|null|undefined} settings  the live settings object
 * @param {string|null|undefined} backendId the TUN backend about to run, as the
 *   connect path names it ('sing-box' | 'tun2socks' | 'native-macos' | …). NOT
 *   `tun.backendId`: the native macOS service reports 'sing-box' there, because
 *   a sing-box is what it runs — the caller passes 'native-macos' for it.
 * @param {string} platform  where the tunnel is about to run; passed in so it is testable
 * @returns {{ apps: { mode: 'exclude'|'only', names: string[], to?: Object<string,string> }|null, warn: string|null }}
 */
function appsForTun(settings, backendId, platform = process.platform) {
  const s = (settings && typeof settings === 'object') ? settings : {};

  const mode = s.tunAppMode;
  if (mode !== 'exclude' && mode !== 'only') return { apps: null, warn: null };

  const names = normalizeAppNames(s.tunApps);
  if (!names.length) {
    return { apps: null, warn: 'Per-app routing is on but no app is listed — ignored' };
  }
  if (backendId === 'native-macos') {
    return {
      apps: null,
      warn: 'Per-app routing is not available on the native macOS service yet — choose the sing-box (compatibility) backend'
    };
  }
  if (backendId !== 'sing-box') {
    return { apps: null, warn: 'Per-app routing needs the sing-box TUN backend — ignored' };
  }
  const strictOff = 'Per-app routing is off under the strict guard: the guard promises nothing leaves outside the tunnel, and either mode would send some app around it';
  if (s.leakGuard === 'strict' && mode === 'only') return { apps: null, warn: strictOff };

  // Each listed name with its target, the Windows suffix applied after the
  // lookup (the map is keyed by the name as listed), deduped on the result.
  const map = normalizeAppTargets(s.tunAppTargets);
  const def = defaultTarget(mode);
  const seen = new Set();
  const listed = [];
  for (const name of names) {
    const full = withExeSuffix([name], platform)[0];
    if (seen.has(full)) continue;
    seen.add(full);
    const own = Object.prototype.hasOwnProperty.call(map, name) ? map[name]
      : (Object.prototype.hasOwnProperty.call(map, full) ? map[full] : def);
    listed.push({ name: full, target: own });
  }

  // strict + exclude: whatever would go direct rides the connection instead (see the header)
  let warn = null;
  let kept = listed;
  if (s.leakGuard === 'strict') {
    kept = listed.filter((a) => a.target !== 'direct');
    if (!kept.length) return { apps: null, warn: strictOff };
    const dropped = listed.filter((a) => a.target === 'direct').map((a) => a.name);
    if (dropped.length) warn = `Per-app routing under the strict guard: ${dropped.join(', ')} ride the connection instead of going around the tunnel — the guard promises nothing leaves outside it`;
  }

  const apps = { mode, names: kept.map((a) => a.name) };
  const to = {};
  for (const a of kept) if (a.target !== def) to[a.name] = a.target;
  if (Object.keys(to).length) apps.to = to;
  return { apps, warn };
}

module.exports = { normalizeAppNames, normalizeAppTargets, appsForTun, targetOk };
