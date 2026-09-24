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
  // the copy is started by the elevated helper only once this process has
  // exited (relaunch.js), so releasing just before the quit is in time
  assert.ok(release < relaunch.indexOf('app.quit()'), 'released before this instance quits');
});

/* --------------------- W2 / W11 / M2: the system proxy journal --------------------- */

test('the proxy journal is configured and a dead session’s proxy repaired at launch, before any connect', () => {
  const use = WHEN_READY.indexOf("useProxyJournal(path.join(dir, 'proxy-journal.json'))");
  const repair = WHEN_READY.indexOf('repairSystemProxy({ legacyServer: `127.0.0.1:${getSettings().httpPort}` })');
  assert.notEqual(use, -1, 'the desktop app must journal the proxy it sets (sysproxy.useProxyJournal)');
  assert.notEqual(repair, -1, 'nothing repairs a proxy left aimed at 127.0.0.1 after a crash or the update installer — and only OUR port counts as ours');
  assert.ok(WHEN_READY.indexOf('if (!primaryInstance) return;') < use, 'never in a second instance — it would undo the first one’s proxy');
  assert.ok(WHEN_READY.indexOf('new Store(') < repair, 'the settings (our HTTP port) are read from the store');
  assert.ok(use < repair && repair < WHEN_READY.indexOf('createWindow()'), 'before the window, so before any connect');
});

test('the exit hook restores the journal instead of blindly switching the proxy off', () => {
  const sync = slice('function teardownSync(', '\n}');
  assert.match(sync, /restoreSystemProxySync\(\)/);
  assert.ok(sync.indexOf('restoreSystemProxySync()') < sync.indexOf('leakGuard.releaseSync()'),
    'the proxy first: the fastest step and the one every browser depends on');
  assert.doesNotMatch(MAIN, /'ProxyEnable'/, 'no raw ProxyEnable=0 left anywhere in main.js — that killed corporate proxies');
});

test('quitting restores the proxy (and on macOS stops the core) before the steps that need a password', () => {
  const quit = slice('async function teardownForQuit() {', '\n}');
  const proxy = quit.indexOf('await setSystemProxy(false, {})');
  const mac = quit.indexOf("if (process.platform === 'darwin') {\n    try { await stopAllTuns();");
  assert.ok(proxy !== -1 && mac !== -1, quit);
  assert.ok(proxy < mac, 'a 20 s cap on an unanswered password prompt must not leave the proxy aimed at a dead port');
  const macCore = quit.indexOf("if (process.platform === 'darwin') { try { if (xray) await xray.stop(); } catch {} }");
  assert.ok(macCore !== -1 && macCore < mac, 'macOS: the core stops before the privileged steps too');
});

/* ------------------ W7: shutdown, restart or log-off while connected ------------------ */

test('a Windows session end and a macOS/Linux shutdown run the synchronous teardown', () => {
  // Electron emits no before-quit for a Windows shutdown / restart / log-off:
  // the static DNS on the tunnel peer, the strict firewall group and the proxy
  // all survived the reboot.
  const win = slice('function createWindow() {', '\n}');
  assert.match(win, /mainWindow\.on\('session-end', \(\) => teardownSync\('session-end'\)\);/);
  assert.match(WHEN_READY, /powerMonitor\.on\('shutdown', \(\) => \{\n\s*teardownSync\('session-end'\);/);
});

test('the synchronous teardown runs once, says it is quitting first, and covers the tunnel and the kill switch', () => {
  const sync = slice('function teardownSync(reason) {', '\n}');
  assert.match(sync, /if \(!primaryInstance \|\| syncTeardownDone\) return;\n\s*syncTeardownDone = true;/, 'session-end and then exit: once');
  const quitting = sync.indexOf('isQuitting = true;');
  const disc = sync.indexOf('userDisconnecting = true;');
  assert.ok(quitting !== -1 && disc !== -1, 'a tunnel killed on the way out must not be reported as a drop to recover');
  for (const step of ['restoreSystemProxySync()', 'leakGuard.releaseSync()', 'cleanupAllTunsSync()', 'name=${KILL_RULE}']) {
    const at = sync.indexOf(step);
    assert.notEqual(at, -1, `teardownSync: ${step} is gone`);
    assert.ok(quitting < at && disc < at, `${step} runs before the quitting flags are up`);
  }
  // the exit hook keeps its old platform gate for the tunnels; a session end sweeps them everywhere
  assert.match(sync, /if \(process\.platform !== 'win32' && reason === 'exit'\) return;\n\s*cleanupAllTunsSync\(\);/);
  assert.match(MAIN, /process\.on\('exit', \(\) => teardownSync\('exit'\)\);/);
});

/* ------------------------- stale activeServerId at launch ------------------------- */

test('a launch clears the activeServerId a crash or a kill left, and connect-on-launch still has lastServerId', () => {
  const clear = WHEN_READY.indexOf("store.set('activeServerId', null)");
  assert.notEqual(clear, -1, 'a new process has no live connection; the tray marked it and a network change "recovered" it');
  assert.ok(WHEN_READY.indexOf('new Store(') < clear);
  for (const later of ['registerIpc()', 'createTray()', 'createWindow()']) {
    assert.ok(clear < WHEN_READY.indexOf(later), `${later} must already see it cleared`);
  }
  assert.match(WHEN_READY, /const lastId = store\.get\('lastServerId', null\);/, 'connect-on-launch reads lastServerId');
});

/* ----------------------------- S5: navigation guards ----------------------------- */

test('the window navigates only to its own page and opens nothing itself; open:external takes web links only', () => {
  const win = slice('function createWindow() {', '\n}');
  assert.match(win, /webContents\.on\('will-navigate', \(e, url\) => \{\n\s*if \(!isAppPage\(url, APP_PAGE\)\) e\.preventDefault\(\);/);
  assert.match(win, /webContents\.setWindowOpenHandler\(\(\{ url \}\) => \{\n\s*if \(isWebUrl\(url\)\) shell\.openExternal\(url\);\n\s*return \{ action: 'deny' \};/);
  assert.match(win, /mainWindow\.loadFile\(APP_PAGE\);/, 'the page the guard allows is the page that is loaded');
  assert.match(MAIN, /ipcMain\.on\('open:external', \(e, url\) => \{\n\s*if \(isWebUrl\(url\)\) shell\.openExternal\(url\);/);
  assert.doesNotMatch(MAIN, /ipcMain\.on\('open:external', \(e, url\) => shell\.openExternal\(url\)\);/);
});

/* --------------------------- W12: Allow LAN firewall scope --------------------------- */

test('the Allow LAN rules open the no-auth proxy to the local subnet on private networks only', () => {
  const add = slice('async function addLanFirewall(socksPort, httpPort) {', '\n}');
  const rules = add.match(/netsh\(\['advfirewall', 'firewall', 'add', 'rule'[^\]]*\]\)/g) || [];
  assert.equal(rules.length, 2, add);
  for (const r of rules) {
    assert.match(r, /'profile=private,domain'/, 'never on a public network (café, airport)');
    assert.match(r, /'remoteip=localsubnet'/, 'never from beyond the LAN');
  }
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
  assert.ok(budget < DROP.lastIndexOf('await recoverFromNetworkChange(reason)'), 'the budget is spent before a rebuild of its own starts');
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
  assert.match(give, /if \(!\(xray && xray\.running\)\) \{\n(?:\s*if \(gen !== connGen\) return;\n)?\s*try \{ await stopAllTuns\(\); \}[^\n]*\n(?:\s*if \(gen !== connGen\) return;\n)?\s*try \{ await setSystemProxy\(false, \{\}\); \}/);
  assert.ok(give.indexOf('stopAllTuns') < give.indexOf('reportReconnectFailed'), 'torn down before the UI is told');
  assert.doesNotMatch(give.slice(0, give.indexOf('reportReconnectFailed')), /leakGuard\.release|disarmKillSwitch/,
    'the guard stays held and the kill switch stays as it is — the banners offer both back');
});

test('a recovery that cannot resolve the WireGuard endpoint uses the address of the last connect', () => {
  // The owner's corporate chain: cobra.tes.ca is a NAME. A recovery rebuilds
  // under the armed kill switch and the held guard, where nothing resolves, and
  // a name left to the official core has taken the whole core down before.
  const wg = slice('async function withWgEndpointIps(serverId, settings) {', '\n}');
  assert.match(wg, /const last = lastWgEndpointIps\.get\(h\);\n\s*if \(last\) \{\n\s*map\[h\] = last;/);
  assert.match(wg, /map\[h\] = r\.ips\[0\];\n\s*lastWgEndpointIps\.set\(h, r\.ips\[0\]\);/, 'every fresh answer is remembered');
  assert.match(MAIN, /^const lastWgEndpointIps = new Map\(\);/m);
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

test('a connect whose core died while the tunnel was being built fails instead of reporting "connected"', () => {
  // The core only has to survive start()'s 1.2 s grace; the TUN and the guard
  // take seconds more. Reporting connected over a dead core told a recovery it
  // was done — and it lifted the kill switch over nothing.
  const body = slice('async function connectOnce(serverId, opts = {}) {', "send('status', {\n    state: 'connected'");
  const gate = body.lastIndexOf('if (stale()) return abandoned;');
  const dead = body.indexOf('if (!xray.running) throw new Error(');
  assert.ok(dead !== -1 && gate < dead, 'the dead-core check is the last gate before the watchers and the status');
  const rec = slice('async function runRecovery(reason, attempt) {', '\n}');
  assert.match(rec, /if \(held && !\(res && res\.stale\) && xray && xray\.running\) \{/, 'the block is lifted only over a running core');
});

test('a drop waits for a connect in flight, joins a recovery in flight, and only then spends the budget', () => {
  assert.match(MAIN, /^const connectsInFlight = new Set\(\);$/m);
  assert.match(slice('function doConnect(serverId, opts) {', '\n}'), /connectOnce\(serverId, opts\)[\s\S]*connectsInFlight\.add\(p\)/);
  const DROP = dropSrc();
  const wait = DROP.indexOf('await Promise.allSettled([...connectsInFlight])');
  const join = DROP.indexOf('if (recovering) {');
  const budget = DROP.indexOf('drops.take()');
  assert.ok(wait !== -1 && join !== -1 && wait < join && join < budget, DROP);
  // a user connect that settled with a running core healed the drop: no budget, no rebuild
  const healedCheck = DROP.indexOf('if (healed()) return liftOwnBlock();');
  assert.ok(healedCheck !== -1 && wait < healedCheck && healedCheck < budget, 'healed() is asked right after the connects in flight settle');
});

test('giving up cancels the pending retry and says nothing when the user acted meanwhile; proxyUp is false under the kill switch', () => {
  const DROP = dropSrc();
  const give = DROP.slice(DROP.indexOf('if (!drops.take()) {'));
  assert.match(give, /clearTimeout\(recoverTimer\);\s*recoverTimer = null;\s*recoverQueued = null;/);
  assert.match(give, /const gen = connGen;[\s\S]*if \(gen !== connGen\) return;[\s\S]*reportReconnectFailed/);
  assert.match(DROP, /const proxyUp = \(\) => !!\(xray && xray\.running\) && !killEngaged;/);
  assert.doesNotMatch(DROP, /\{ ok: !!\(xray && xray\.running\) \}/);
});

test('with automatic reconnect off, a drop that is not torn down still tells the UI the truth', () => {
  const DROP = dropSrc();
  const off = DROP.slice(DROP.indexOf('if (!s.autoReconnectOnNetworkChange)'), DROP.indexOf('if (recovering)'));
  assert.match(off, /reportReconnectFailed\(reason, \{ ok: proxyUp\(\)/, 'a reload that left no core, or a dead TUN, must not stay "connected"');
});

test('the kill switch is not re-armed over itself (a delete-then-add left a gap with the tunnel down)', () => {
  const arm = slice('async function armKillSwitch() {', '\n}');
  assert.match(arm, /if \(process\.platform !== 'win32'\) return \{ ok: false, error: 'windows only' \};\n(?:\s*\/\/[^\n]*\n)*\s*if \(killEngaged && await killRulePresent\(\)\) return \{ ok: true \};/);
});

test('a Retry that fails says so, instead of leaving the window on "Connecting"', () => {
  const retry = slice("ipcMain.handle('vpn:reconnect'", '\n  });');
  assert.match(retry, /catch \(e\) \{[\s\S]*send\('status', \{ state: 'error', message: e\.message \}\)/);
  assert.match(retry, /if \(held && r && r\.ok && xray && xray\.running\)/);
});

test('the elevated relaunch tears this instance down BEFORE it hands over the lock and quits', () => {
  const relaunch = slice("ipcMain.handle('app:relaunchAdmin'", '\n  });');
  const down = relaunch.indexOf('await Promise.race([teardownForQuit()');
  const release = relaunch.indexOf('app.releaseSingleInstanceLock()');
  const quit = relaunch.indexOf('app.quit()');
  assert.ok(down !== -1 && down < release && release < quit,
    'the copy repairs the same userData files and binds the same ports the moment it starts');
  assert.match(relaunch, /quitTeardown = 'done';/, 'and the quit that follows does not tear down a second time');
});

/* ------------------------------- second review ------------------------------- */

test('the give-up teardown checks, before EACH step, that no connect or disconnect took over', () => {
  const DROP = dropSrc();
  const give = DROP.slice(DROP.indexOf('if (!drops.take()) {'));
  assert.match(give, /if \(gen !== connGen\) return;\n\s*try \{ await stopAllTuns\(\); \}[^\n]*\n\s*if \(gen !== connGen\) return;\n\s*try \{ await setSystemProxy\(false, \{\}\); \}/, give);
});

test('a drop that lands during a recovery waits for it and rebuilds only if that recovery left it unhealed', () => {
  const DROP = dropSrc();
  assert.doesNotMatch(DROP, /if \(recovering\) \{ await recoverFromNetworkChange\(reason\); return; \}/, 'joining queued a second full rebuild');
  assert.match(DROP, /if \(recovering\) \{\n[\s\S]*?await \(recoveryRun \|\| Promise\.resolve\(\)\)\.catch\(\(\) => \{\}\);[\s\S]*?if \(recoverTimer \|\| recovering\) return;[\s\S]*?if \(healed\(\)\) return liftOwnBlock\(\);/);
  assert.match(DROP, /const healed = \(\) => \(reason === 'tunnel-exited' \? !!\(tun && tun\.active\) : !!\(xray && xray\.running\)\);/);
  assert.match(slice('async function recoverFromNetworkChange(reason, attempt = 0) {', '\n}'), /recoveryRun = runRecovery\(reason, attempt\);\n\s*await recoveryRun;/);
});

test('the kill switch trusts killEngaged only when the rule is really there; a drop’s arm is undone if the user disconnected meanwhile', () => {
  const arm = slice('async function armKillSwitch() {', '\n}');
  assert.match(arm, /if \(killEngaged && await killRulePresent\(\)\) return \{ ok: true \};/);
  assert.match(slice('function killRulePresent() {', '\n}'), /netsh\(\['advfirewall', 'firewall', 'show', 'rule', `name=\$\{KILL_RULE\}`\]\)\.then\(\(\) => true, \(\) => false\)/);
  const DROP = dropSrc();
  assert.match(DROP, /const wasEngaged = killEngaged;/);
  assert.match(DROP, /if \(r && r\.ok && !wasEngaged\) \{\n\s*send\('log', \{ line: 'Kill switch engaged/, 'said once, not on every drop');
  assert.match(DROP, /if \(r && r\.ok && !wasEngaged && \(userDisconnecting \|\| isQuitting \|\| !store\.get\('activeServerId', null\)\)\) \{\n\s*await disarmKillSwitch\(\);/);
});

test('a macOS/Linux shutdown that gets cancelled does not leave the app deaf for good', () => {
  assert.match(WHEN_READY, /powerMonitor\.on\('shutdown', \(\) => \{\n\s*teardownSync\('session-end'\);\n\s*scheduleShutdownCancelCheck\(\);/);
  const check = slice('function scheduleShutdownCancelCheck() {', '\n}');
  assert.match(check, /isQuitting = false;/);
  assert.match(check, /userDisconnecting = false;/);
  assert.match(check, /syncTeardownDone = false;/);
  // no automatic rebuild: on a macOS TUN that is a password prompt in the middle of a slow logout
  assert.doesNotMatch(check, /recoverFromNetworkChange/);
  assert.match(check, /reportReconnectFailed\('shutdown-cancelled', \{ ok: false \}\)/, 'the user (or the network watcher) rebuilds');
  assert.match(check, /\.unref\(\)/, 'never what keeps a quitting process alive');
});

test('the elevated relaunch tears nothing down until the UAC prompt was accepted', () => {
  const relaunch = slice("ipcMain.handle('app:relaunchAdmin'", '\n  });');
  const ask = relaunch.indexOf('await runElevatedRelaunch(');
  const down = relaunch.indexOf('await Promise.race([teardownForQuit()');
  assert.ok(ask !== -1 && down !== -1 && ask < down, relaunch);
  assert.match(relaunch, /catch \(e\) \{[\s\S]*return \{ ok: false, error: /, 'a cancelled prompt leaves this instance running, connected, and says so');
  assert.doesNotMatch(relaunch, /spawn\('powershell'/, 'the copy is started by the elevated helper once this instance is gone');
  // in this instance’s working directory — which only the dev relaunch (`electron .`) needs;
  // an installed build passes none (a mapped drive is invisible to the elevated token)
  assert.match(relaunch, /runElevatedRelaunch\(\{[^}]*cwd: app\.isPackaged \? null : process\.cwd\(\) \}\)/);
});

test('the window says a DROP when it was one, and says the kill switch closed the internet once', () => {
  const R = (f) => fs.readFileSync(path.join(__dirname, '..', 'src', 'renderer', f), 'utf8').replace(/\r\n/g, '\n');
  const APP = R('app.js');
  const I18N = R('i18n.js');
  // the reasons main.js calls a drop (DROP_REASONS) are the ones the window knows
  const mainReasons = /const DROP_REASONS = new Set\(\[([^\]]*)\]\)/.exec(MAIN)[1];
  assert.match(APP, new RegExp(`const DROP_REASONS = \\[${mainReasons.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\];`));
  assert.match(APP, /toast\(t\(failedKey\(d\.reason\)\), 'err', 8000\);/);
  assert.match(APP, /function failedKey\(reason\) \{\n\s*if \(reason === 'shutdown-cancelled'\) return 'net\.shutdownCancelled';\n\s*return DROP_REASONS\.includes\(reason\) \? 'net\.dropFailed' : 'net\.failed';/);
  assert.match(APP, /DROP_REASONS\.includes\(state\.reconnectReason\) \? 'state\.reconnectingDrop' : 'state\.reconnecting'/);
  for (const key of ['net.dropFailed', 'state.reconnectingDrop', 'net.shutdownCancelled']) {
    assert.equal((I18N.match(new RegExp(`'${key.replace('.', '\\.')}':`, 'g')) || []).length, 2, `${key}: one fa and one en string`);
  }
  // the kill-switch toast on the way IN only — a second drop under an engaged switch is not news
  assert.match(APP, /const wasEngaged = state\.killEngaged;[\s\S]*?if \(state\.killEngaged && !wasEngaged\) toast\(t\('kill\.blocked'\), 'err'\);/);
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

/* ------------------------------- post-merge ------------------------------- */

/**
 * onConnectionDrop() itself, run against fakes: main.js needs Electron, so the
 * function's own source is compiled with everything it reaches passed in. The
 * kill switch is a flag the fakes flip — no netsh, no firewall.
 */
function dropHarness({ settings = {}, xrayRunning = false, killEngaged = false } = {}) {
  const sent = [];
  const calls = [];
  const env = {
    store: { get: (k, d) => (k === 'activeServerId' ? 'srv1' : d) },
    xray: { running: xrayRunning },
    tun: { active: false },
    send: (channel, payload) => sent.push([channel, payload]),
    notify: () => {},
    isEn: () => true,
    updateOverlay: () => {},
    getSettings: () => Object.assign({ killSwitch: true, autoReconnectOnNetworkChange: true }, settings),
    connectsInFlight: new Set(),
    drops: { take: () => true },
    doDisconnect: async () => { calls.push('doDisconnect'); },
    reportReconnectFailed: () => { calls.push('reportReconnectFailed'); },
    recoverFromNetworkChange: async (reason) => { calls.push('recover:' + reason); },
    stopAllTuns: async () => {},
    setSystemProxy: async () => {},
    killEngaged
  };
  const make = new Function('env', `
    let userDisconnecting = false, isQuitting = false, recovering = false, recoveryRun = null,
        recoverTimer = null, recoverQueued = null, connGen = 0;
    let killEngaged = env.killEngaged;
    const { store, xray, tun, send, notify, isEn, updateOverlay, getSettings, connectsInFlight, drops,
            doDisconnect, reportReconnectFailed, recoverFromNetworkChange, stopAllTuns, setSystemProxy } = env;
    async function armKillSwitch() { env.calls.push('arm'); killEngaged = true; return { ok: true }; }
    async function disarmKillSwitch() { env.calls.push('disarm'); killEngaged = false; }
    ${dropSrc()}
    // a recovery in flight: the drop waits on recoveryRun; finish() is its end
    function startRecovery() {
      let done;
      recovering = true;
      recoveryRun = new Promise((r) => { done = r; });
      return (healedIt) => { if (healedIt) xray.running = true; recovering = false; done(); };
    }
    return { onConnectionDrop, startRecovery, killEngaged: () => killEngaged };
  `);
  env.calls = calls;
  return Object.assign(make(env), { env, sent, calls });
}

test('killSwitch ON: a drop that lands inside the user’s connect lifts ITS block when that connect comes up', async () => {
  // The core died while the user's connect was still building the tunnel. The
  // drop arms the switch, waits for the connect — which settles with a running
  // core — and returns at healed(). Its block stayed: "connected" with the
  // internet blocked.
  const h = dropHarness();
  let settle;
  const connect = new Promise((resolve) => { settle = resolve; });
  h.env.connectsInFlight.add(connect);
  const drop = h.onConnectionDrop('core-exited');
  await new Promise((r) => setImmediate(r));
  assert.equal(h.killEngaged(), true, 'the gap is closed while the connect is still building');
  h.env.xray.running = true;   // the user's connect came up
  settle({ ok: true });
  await drop;
  assert.equal(h.killEngaged(), false, 'connected, and the block this drop put in is gone');
  assert.deepEqual(h.calls, ['arm', 'disarm'], 'no rebuild, no budget, no give-up');
  const ks = h.sent.filter(([c]) => c === 'killswitch').map(([, p]) => p.engaged);
  assert.deepEqual(ks, [true, false], 'and the window is told it was lifted');
});

test('killSwitch ON: a drop that found the block already in place leaves it to whoever armed it', async () => {
  // A settings reapply (or a recovery holding a block from an earlier drop)
  // armed it and lifts it itself once its tunnel is up — not this drop.
  const h = dropHarness({ killEngaged: true });
  const connect = Promise.resolve({ ok: true });
  h.env.connectsInFlight.add(connect);
  h.env.xray.running = true;
  await h.onConnectionDrop('core-exited');
  assert.equal(h.killEngaged(), true);
  assert.deepEqual(h.calls, ['arm']);
});

test('killSwitch ON: a drop that no connect healed keeps its block for the rebuild', async () => {
  const h = dropHarness();
  await h.onConnectionDrop('core-exited');
  assert.equal(h.killEngaged(), true, 'the recovery rebuilds under the block');
  assert.deepEqual(h.calls, ['arm', 'recover:core-exited']);
});

test('killSwitch ON: a drop that joins a recovery which brings the core back lifts its own block too', async () => {
  // runRecovery's doConnect captured "not held" before this drop's rule went in,
  // so it lifts nothing itself once its tunnel is up.
  const h = dropHarness();
  const finish = h.startRecovery();
  const drop = h.onConnectionDrop('core-exited');
  await new Promise((r) => setImmediate(r));
  assert.equal(h.killEngaged(), true);
  finish(true);
  await drop;
  assert.equal(h.killEngaged(), false);
  assert.deepEqual(h.calls, ['arm', 'disarm'], 'joined, not a second rebuild');
});

test('killSwitch ON: a drop that joins a recovery which did NOT bring it back keeps its block', async () => {
  const h = dropHarness();
  const finish = h.startRecovery();
  const drop = h.onConnectionDrop('core-exited');
  await new Promise((r) => setImmediate(r));
  finish(false);
  await drop;
  assert.equal(h.killEngaged(), true, 'the rebuild this drop starts runs under it');
  assert.deepEqual(h.calls, ['arm', 'recover:core-exited']);
});
