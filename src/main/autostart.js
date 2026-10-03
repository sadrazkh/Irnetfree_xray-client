'use strict';
/**
 * Start with the OS, hidden in the tray.
 *
 * Windows: the app is built with requestedExecutionLevel=requireAdministrator
 * (package.json → build.win), and a Run-key or Startup-folder entry for a
 * program that requires elevation is SILENTLY skipped by UAC — so
 * `app.setLoginItemSettings` can never work for this app there. A scheduled
 * task at logon with "run with highest privileges" is the supported way, and
 * what every elevated tray application does. macOS and Linux use the login
 * item Electron provides.
 *
 * Pure: these build the arguments, main.js runs `schtasks`. Nothing here
 * touches the machine, so the shape is pinned by a test.
 */

const TASK = 'IRNetFree';

/**
 * Create (or replace: /F) the logon task. /RL HIGHEST is the elevation, /IT
 * runs it in the interactive session so the tray icon has a desktop to be on,
 * and --hidden tells the app to start in the tray. The exe path is quoted
 * because Program Files has a space in it.
 */
function schtasksCreateArgs(exePath, taskName = TASK) {
  return ['/Create', '/TN', taskName, '/SC', 'ONLOGON', '/RL', 'HIGHEST', '/IT', '/F', '/TR', `"${exePath}" --hidden`];
}

function schtasksDeleteArgs(taskName = TASK) { return ['/Delete', '/TN', taskName, '/F']; }

function schtasksQueryArgs(taskName = TASK) { return ['/Query', '/TN', taskName]; }

/** The same read, as the task's XML — which names the file it runs (taskExeFromXml). */
function schtasksQueryXmlArgs(taskName = TASK) { return ['/Query', '/TN', taskName, '/XML']; }

/**
 * The file a task runs, out of `schtasks /Query /XML`: the first Exec's
 * <Command>, unquoted ('' when there is none). A command line kept in one
 * piece gives its quoted program.
 */
function taskExeFromXml(xml) {
  const m = /<Exec>[\s\S]*?<Command>([\s\S]*?)<\/Command>/i.exec(String(xml == null ? '' : xml));
  if (!m) return '';
  const cmd = m[1]
    .replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&')
    .trim();
  if (cmd.startsWith('"')) {
    const end = cmd.indexOf('"', 1);
    return (end > 0 ? cmd.slice(1, end) : cmd.slice(1)).trim();
  }
  return cmd;
}

/**
 * Does the logon task certainly start ANOTHER file than `currentExe`? The
 * task runs exactly the file it was registered with, and is rewritten only
 * when the setting is toggled — so a PC can keep starting an old build (one
 * from before the v1.14 Windows DNS fix) at every logon while a newer one sits
 * beside it (windows-android-report L1).
 *
 * Any doubt is "no": schtasks prints the XML in the console's code page, so a
 * path with a non-ASCII letter arrives mangled and is never compared; an
 * environment variable that does not expand, or nothing read at all, is not a
 * mismatch either. `same(a, b)` is the caller's own file check (an 8.3 name, a
 * junction), asked before saying yes.
 */
function autostartStale(taskExe, currentExe, { env = process.env, same = null } = {}) {
  const expand = (p) => {
    let ok = true;
    const out = String(p == null ? '' : p).replace(/%([^%]+)%/g, (m, name) => {
      const key = Object.keys(env || {}).find(k => k.toUpperCase() === name.toUpperCase());
      if (key === undefined) { ok = false; return m; }
      return String(env[key]);
    });
    return ok ? out : null;
  };
  const norm = (p) => p.trim().replace(/\//g, '\\').replace(/\\{2,}/g, '\\').toLowerCase();
  const task = expand(taskExe), cur = expand(currentExe);
  if (!task || !cur || !task.trim() || !cur.trim()) return false;
  // printable ASCII only: anything else may be the code page's damage, not the path
  if (!/^[\x20-\x7e]+$/.test(task) || !/^[\x20-\x7e]+$/.test(cur) || task.includes('?')) return false;
  if (norm(task) === norm(cur)) return false;
  if (typeof same === 'function') {
    try { if (same(task.trim(), cur.trim())) return false; } catch { return false; }
  }
  return true;
}

/**
 * The file the task must run. The portable build extracts itself into a temp
 * directory and runs from there — process.execPath would name a file that is
 * gone by the next logon — and names its real file in this variable.
 */
function autostartExe(env = process.env, execPath = process.execPath) {
  return env.PORTABLE_EXECUTABLE_FILE || execPath;
}

/**
 * What `app.setLoginItemSettings` gets off Windows. Its `args` is Windows-only:
 * a macOS login item never passes it, so `--hidden` never reached the app there
 * and every login opened the window. macOS has its own word for it,
 * `openAsHidden` (honoured before macOS 13), and startsHidden() below also asks
 * how the app was launched, which covers the newer systems.
 */
function loginItemSettings(enabled, platform = process.platform) {
  if (platform === 'darwin') return { openAtLogin: !!enabled, openAsHidden: true };
  return { openAtLogin: !!enabled, args: ['--hidden'] };
}

/**
 * Whether this launch stays in the tray: `--hidden` (the Windows logon task),
 * or on macOS a launch BY the login item — `wasOpenedAtLogin` /
 * `wasOpenedAsHidden` from `app.getLoginItemSettings()`, passed as a function
 * so a platform that has no such thing is never asked.
 */
function startsHidden({ argv = process.argv, platform = process.platform, loginItem = null } = {}) {
  if ((argv || []).includes('--hidden')) return true;
  if (platform !== 'darwin' || typeof loginItem !== 'function') return false;
  try {
    const s = loginItem() || {};
    return !!(s.wasOpenedAtLogin || s.wasOpenedAsHidden);
  } catch { return false; }
}

module.exports = { TASK, schtasksCreateArgs, schtasksDeleteArgs, schtasksQueryArgs, schtasksQueryXmlArgs, taskExeFromXml, autostartStale, autostartExe, loginItemSettings, startsHidden };
