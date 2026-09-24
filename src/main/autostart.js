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

module.exports = { TASK, schtasksCreateArgs, schtasksDeleteArgs, schtasksQueryArgs, autostartExe, loginItemSettings, startsHidden };
