'use strict';
/**
 * Start with the OS. On Windows this is a scheduled task, because the app
 * requires elevation and UAC silently skips Run-key entries for such programs.
 * The arguments are what the OS gets; they are pinned here because nothing
 * else can run schtasks safely in a test.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { schtasksCreateArgs, schtasksDeleteArgs, schtasksQueryArgs, autostartExe, TASK, loginItemSettings, startsHidden } = require('../src/main/autostart');

const INSTALLED = 'C:\\Program Files\\IRNetFree\\IRNetFree.exe';

test('the logon task runs the exe hidden with highest privileges, replacing any older task', () => {
  assert.deepEqual(schtasksCreateArgs(INSTALLED), [
    '/Create', '/TN', 'IRNetFree', '/SC', 'ONLOGON', '/RL', 'HIGHEST', '/IT', '/F',
    '/TR', '"' + INSTALLED + '" --hidden'
  ]);
  assert.deepEqual(schtasksDeleteArgs(), ['/Delete', '/TN', 'IRNetFree', '/F']);
  assert.deepEqual(schtasksQueryArgs(), ['/Query', '/TN', 'IRNetFree']);
  assert.equal(TASK, 'IRNetFree', 'a fixed name: a reinstall replaces the task instead of adding one');
});

test('the portable build names its real file; the installed build is its own exe', () => {
  const portable = 'D:\\apps\\IRNetFree-Portable.exe';
  assert.equal(autostartExe({ PORTABLE_EXECUTABLE_FILE: portable }, 'C:\\Temp\\extracted\\IRNetFree.exe'), portable);
  assert.equal(autostartExe({}, INSTALLED), INSTALLED);
});

// Audit 2026-09-24, M9: `args` is Windows-only in Electron's login item, so on
// macOS `--hidden` never reached the app and a login always opened the window.
test('macOS: the login item asks to open hidden; elsewhere the --hidden argument stays', () => {
  assert.deepEqual(loginItemSettings(true, 'darwin'), { openAtLogin: true, openAsHidden: true });
  assert.deepEqual(loginItemSettings(false, 'darwin'), { openAtLogin: false, openAsHidden: true });
  assert.deepEqual(loginItemSettings(true, 'linux'), { openAtLogin: true, args: ['--hidden'] });
  assert.equal('args' in loginItemSettings(true, 'darwin'), false);
});

test('a launch by the macOS login item starts in the tray; a launch by the user does not', () => {
  const loginItem = (s) => () => s;
  assert.equal(startsHidden({ argv: ['/x/IRNetFree', '--hidden'], platform: 'win32' }), true, 'the Windows logon task');
  assert.equal(startsHidden({ argv: ['/x/IRNetFree'], platform: 'win32' }), false);
  assert.equal(startsHidden({ argv: ['/x/IRNetFree'], platform: 'darwin', loginItem: loginItem({ wasOpenedAtLogin: true }) }), true);
  assert.equal(startsHidden({ argv: ['/x/IRNetFree'], platform: 'darwin', loginItem: loginItem({ wasOpenedAsHidden: true }) }), true);
  assert.equal(startsHidden({ argv: ['/x/IRNetFree'], platform: 'darwin', loginItem: loginItem({ openAtLogin: true, wasOpenedAtLogin: false }) }), false,
    'enabled but opened by hand: show the window');
  assert.equal(startsHidden({ argv: ['/x/IRNetFree'], platform: 'darwin', loginItem: () => { throw new Error('no'); } }), false);
  assert.equal(startsHidden({ argv: ['/x/IRNetFree'], platform: 'linux', loginItem: loginItem({ wasOpenedAtLogin: true }) }), false,
    'the macOS-only fields mean nothing elsewhere');
});

test('main.js registers the login item and decides the first show through these two', () => {
  const main = fs.readFileSync(path.join(__dirname, '..', 'src', 'main', 'main.js'), 'utf8');
  assert.match(main, /app\.setLoginItemSettings\(loginItemSettings\(enabled, process\.platform\)\)/);
  assert.match(main, /const startHidden = startsHidden\(\{ argv: process\.argv, platform: process\.platform, loginItem: \(\) => app\.getLoginItemSettings\(\) \}\);/);
  assert.doesNotMatch(main, /args: \['--hidden'\]/);
});
