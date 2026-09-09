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

module.exports = { TASK, schtasksCreateArgs, schtasksDeleteArgs, schtasksQueryArgs, autostartExe };
