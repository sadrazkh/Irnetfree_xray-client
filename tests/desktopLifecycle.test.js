'use strict';
/**
 * The desktop main process's lifecycle wiring: single instance, what runs at
 * launch, what runs on the way out, and how a dropped connection is handled.
 *
 * main.js requires Electron at load, so — like serviceOpenwrt.test.js and
 * networkRepair.test.js — these read it as text. Every behaviour that CAN run
 * without Electron lives in a module of its own with a behavioural test; what
 * is pinned here is only the order and the wiring, which is exactly the part
 * that silently rots.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

// CRLF on a Windows checkout (core.autocrlf): the patterns below are written with \n.
const MAIN = fs.readFileSync(path.join(__dirname, '..', 'src', 'main', 'main.js'), 'utf8').replace(/\r\n/g, '\n');

/** The source from `start` up to the first `end` after it. */
function slice(start, end) {
  const a = MAIN.indexOf(start);
  assert.notEqual(a, -1, `main.js: ${start} is gone`);
  const b = MAIN.indexOf(end, a + start.length);
  assert.notEqual(b, -1, `main.js: nothing ends ${start}`);
  return MAIN.slice(a, b + end.length);
}

const WHEN_READY = slice('app.whenReady().then(() => {', '\n});');

/* ------------------------------ W1: one instance ------------------------------ */

test('the single-instance lock is taken at load, before anything launch-time can run', () => {
  const lock = MAIN.indexOf('app.requestSingleInstanceLock()');
  assert.notEqual(lock, -1, 'nothing asks for the single-instance lock');
  assert.equal(MAIN.indexOf('app.requestSingleInstanceLock()', lock + 1), -1, 'asked for once');
  assert.ok(lock < MAIN.indexOf('app.whenReady()'), 'the lock must be requested before the ready handler is even registered');
  // top level, not inside a function: the line starts at column 0
  assert.match(MAIN, /^const primaryInstance = app\.requestSingleInstanceLock\(\);$/m);
  assert.match(MAIN, /^if \(!primaryInstance\) app\.quit\(\);$/m, 'a second instance leaves at once');
});

test('a second instance runs no launch repair and writes no store', () => {
  // The very first statement of the ready handler is the refusal.
  assert.match(WHEN_READY, /^app\.whenReady\(\)\.then\(\(\) => \{\n {2}\/\/[^\n]*\n(?: {2}\/\/[^\n]*\n)* {2}if \(!primaryInstance\) return;\n/,
    'the ready handler must bail out before anything else when this is not the primary instance');
  const refusal = WHEN_READY.indexOf('if (!primaryInstance) return;');
  for (const after of ['new Store(', 'disarmKillSwitch()', 'repairAtLaunch()', 'createWindow()']) {
    const at = WHEN_READY.indexOf(after);
    assert.notEqual(at, -1, `ready handler: ${after} is gone`);
    assert.ok(refusal < at, `${after} runs before the single-instance refusal`);
  }
});

test('the ways out of a second instance touch nothing of the first one’s session', () => {
  // before-quit would run teardownForQuit (proxy, guard, kill switch, core);
  // the exit hook the synchronous half of it. Both belong to the lock holder.
  const beforeQuit = slice("app.on('before-quit', (e) => {", '\n});');
  assert.match(beforeQuit, /^app\.on\('before-quit', \(e\) => \{\n {2}if \(!primaryInstance\) return;/,
    'before-quit must return first thing in a second instance');
  const sync = slice('function teardownSync(', '\n}');
  assert.match(sync, /if \(!primaryInstance\b[^)]*\) return;/, 'the synchronous teardown belongs to the lock holder only');
  assert.match(MAIN, /process\.on\('exit', \(\) => teardownSync\([^)]*\)\);/);
});

test('a second launch brings the running window forward instead', () => {
  const handler = slice("app.on('second-instance'", '\n});');
  assert.match(handler, /mainWindow\.show\(\)/);
  assert.match(handler, /mainWindow\.focus\(\)/);
  assert.match(handler, /isMinimized\(\)\) mainWindow\.restore\(\)/);
  // the logon task starts us with --hidden: a running app stays in the tray
  assert.match(handler, /argv[^\n]*includes\('--hidden'\)[^\n]*return/);
});

test('the elevated relaunch hands the lock over before the new instance can ask for it', () => {
  const relaunch = slice("ipcMain.handle('app:relaunchAdmin'", '\n  });');
  const release = relaunch.indexOf('app.releaseSingleInstanceLock()');
  assert.notEqual(release, -1, 'the elevated copy would find the lock held and quit — no app at all');
  assert.ok(release < relaunch.indexOf("spawn('powershell'"), 'released before the elevated copy is started');
});
