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

/* ------------------------- W5: a connection that drops ------------------------- */

/** The drop handler's source — read per test, so a missing one fails that test, not the file. */
const dropSrc = () => slice('async function onConnectionDrop(reason) {', '\n}');

test('an unexpected core exit is a drop: the kill switch, then the recovery — not just an overlay', () => {
  const DROP = dropSrc();
  const onStatus = slice('onStatus: (state, info) => {', "send('xray-status', { state, info });");
  assert.match(onStatus, /if \(xrayReloading && state === 'stopped'\) return;/, 'a reload still swallows its own stop');
  assert.match(onStatus, /state === 'stopped' && !userDisconnecting && store\.get\('activeServerId', null\)[^\n]*\n\s*onConnectionDrop\('core-exited'\)/,
    'an exit nobody asked for must start the drop handling');
  assert.doesNotMatch(onStatus, /armKillSwitch/, 'the kill switch is armed by the drop handler, in order, before the recovery');
  const arm = DROP.indexOf('await armKillSwitch()');
  const recover = DROP.indexOf('await recoverFromNetworkChange(reason)');
  assert.ok(arm !== -1 && recover !== -1 && arm < recover, 'the block goes in (awaited) before the rebuild reads killEngaged');
  assert.match(DROP, /if \(s\.killSwitch\) \{/);
});

test('a connection that keeps dropping is given up on through the same reconnect-failed the recovery uses', () => {
  const DROP = dropSrc();
  const budget = DROP.indexOf('drops.take()');
  assert.notEqual(budget, -1, 'nothing bounds a core that starts, survives the grace and dies again');
  assert.ok(budget < DROP.indexOf('await recoverFromNetworkChange(reason)'));
  assert.match(DROP, /if \(!drops\.take\(\)\) \{[\s\S]*?reportReconnectFailed\(reason,/);
  const give = slice('function reportReconnectFailed(reason, res) {', '\n}');
  assert.match(give, /state: 'reconnect-failed'/);
  assert.match(slice('async function runRecovery(reason, attempt) {', '\n}'), /reportReconnectFailed\(reason, res\);/,
    'the network-change recovery gives up through the same function');
  // the user's own connect / disconnect starts the count over
  assert.match(slice('async function doDisconnect() {', '\n}'), /drops\.reset\(\);/);
  assert.match(MAIN, /ipcMain\.handle\('connect', \(e, id\) => \{ drops\.reset\(\); return doConnect\(id\); \}\);/);
});

test('giving up on a connection that keeps dropping leaves no tunnel or proxy aimed at the dead core', () => {
  const DROP = dropSrc();
  const give = DROP.slice(DROP.indexOf('if (!drops.take()) {'));
  assert.match(give, /if \(!\(xray && xray\.running\)\) \{\n\s*try \{ await stopAllTuns\(\); \}[^\n]*\n\s*try \{ await setSystemProxy\(false, \{\}\); \}/);
  assert.ok(give.indexOf('stopAllTuns') < give.indexOf('reportReconnectFailed'), 'torn down before the UI is told');
  assert.doesNotMatch(give.slice(0, give.indexOf('reportReconnectFailed')), /leakGuard\.release|disarmKillSwitch/,
    'the guard stays held and the kill switch stays as it is — the banners offer both back');
});

test('with automatic reconnect off, a dead core is torn down instead of left under the TUN, DNS and proxy', () => {
  const DROP = dropSrc();
  const at = DROP.indexOf('if (!s.autoReconnectOnNetworkChange)');
  assert.notEqual(at, -1);
  assert.match(DROP.slice(at), /reason !== 'tunnel-exited' && !s\.killSwitch[\s\S]*?await doDisconnect\(\)/,
    'nothing will rebuild it: make the "Disconnected" the UI shows true');
  // a drop the user already answered is not handled twice
  assert.match(DROP, /^async function onConnectionDrop\(reason\) \{\n {2}if \(userDisconnecting \|\| isQuitting \|\| !store\.get\('activeServerId', null\)\) return;/);
});

test('a tunnel backend dying and a reload that leaves no core take the same path', () => {
  const mk = slice('function makeTun(settings', '\n}');
  assert.match(mk, /onConnectionDrop\('tunnel-exited'\)/);
  const reload = slice('async function rebuildActiveConfig() {', '\n}');
  assert.match(reload, /catch \(e\) \{[\s\S]*?lostCore = !xray\.running;[\s\S]*?throw e;/, 'a failed start() leaves no core — say so');
  assert.match(reload, /finally \{\n\s*xrayReloading = prevReloading;\n\s*if \(lostCore\) onConnectionDrop\('reload-failed'\)/,
    'and only after the reload flag is down, so the drop is not swallowed like the stop was');
});

test('the DNS guard watch re-applies the override only while the core is actually running', () => {
  const watch = slice('dnsGuardWatch = new DnsGuardWatch({', '\n  });');
  assert.match(watch, /isActive: \(\) => [^\n]*!!xray\?\.running/);
});

test('Retry after a give-up rebuilds a core that is gone instead of answering "not connected"', () => {
  const retry = slice("ipcMain.handle('vpn:reconnect'", '\n  });');
  assert.match(retry, /if \(xray && xray\.running\) return await reapplyConnection\(\);/);
  assert.match(retry, /doConnect\(id, \{ holdKillSwitch: held \}\)/);
});
