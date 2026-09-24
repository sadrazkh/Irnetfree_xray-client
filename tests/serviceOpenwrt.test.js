'use strict';
/**
 * The headless service on a router. The env override stands in for
 * /etc/openwrt_release (no router here), so this pins the wiring: which
 * backend makeTun() picks, what app:init tells the renderer, the validated
 * exclusion list, and that the device RPC is harmless where there is no LAN
 * to read. The service's timers are unref'd, so shutdown() is enough to let
 * the runner exit.
 */
process.env.IRNETFREE_PLATFORM = 'openwrt';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
// shutdown() below turns the system proxy off the headless way (no journal):
// on a Windows dev machine that was a real `reg add … ProxyEnable 0` and a
// WinINet refresh on every `npm test`, on a Mac networksetup. Nothing in here
// may change the network of the machine running it.
const cp = require('node:child_process');
const NETWORK = new Set(['reg', 'netsh', 'route', 'powershell', 'networksetup', 'gsettings', 'osascript', 'taskkill', 'ip', 'nft']);
for (const fn of ['execFile', 'execFileSync', 'spawn']) {
  const real = cp[fn];
  cp[fn] = function (cmd, ...rest) {
    if (NETWORK.has(String(cmd))) throw new Error(`the test reached the real ${cmd}`);
    return real.call(this, cmd, ...rest);
  };
}
const { createService, DEFAULT_SETTINGS } = require('../src/server/service');
// main.js requires Electron at load, so its defaults are read as text
const MAIN_SRC = fs.readFileSync(path.join(__dirname, '..', 'src', 'main', 'main.js'), 'utf8');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-svc-openwrt-'));
// no subscription timer, no asset updater: nothing to keep the process alive
fs.writeFileSync(path.join(dir, 'store.json'), JSON.stringify({ settings: { autoUpdateSubs: false, autoUpdateAssets: 'off' } }));
const service = createService({ dataDir: dir });
test.after(async () => { await service.shutdown(); try { fs.rmSync(dir, { recursive: true, force: true }); } catch {} });

test('both DEFAULT_SETTINGS carry lanBypassMacs = []', () => {
  assert.deepEqual(DEFAULT_SETTINGS.lanBypassMacs, []);
  const block = MAIN_SRC.slice(MAIN_SRC.indexOf('const DEFAULT_SETTINGS = {'));
  assert.match(block.slice(0, block.indexOf('\n};')), /^  lanBypassMacs: \[\],$/m, 'main.js DEFAULT_SETTINGS has the same default');
});

test('app:init says flavor openwrt and that the gateway backend is the one that will run', async () => {
  const init = await service.invoke('app:init');
  assert.equal(init.flavor, 'openwrt');
  assert.equal(init.tunBackendId, 'openwrt');
  assert.equal(init.platform, process.platform, 'platform stays what Node says; flavor is the router');
  assert.deepEqual(init.settings.lanBypassMacs, []);
});

test('settings:set validates the exclusion list and keeps it out of the reconnect keys', async () => {
  const res = await service.invoke('settings:set', { lanBypassMacs: ['AA:BB:CC:DD:EE:FF', 'not a mac', 'aa:bb:cc:dd:ee:ff'] });
  assert.deepEqual(res.settings.lanBypassMacs, ['aa:bb:cc:dd:ee:ff']);
  assert.deepEqual(res.pendingReconnect, [], 'applied live, never a "reconnect to apply"');
  assert.deepEqual((await service.invoke('settings:get')).lanBypassMacs, ['aa:bb:cc:dd:ee:ff']);
});

test('a router connects at start by default, and a stored "off" still wins', async () => {
  assert.equal(DEFAULT_SETTINGS.autoConnect, false, 'the shared default is the desktop one');
  assert.equal((await service.invoke('settings:get')).autoConnect, true, 'the router overlay');
  await service.invoke('settings:set', { autoConnect: false });
  assert.equal((await service.invoke('settings:get')).autoConnect, false);
  await service.invoke('settings:set', { autoConnect: true });
});

test('a router refuses QUIC from the LAN by default; the desktop default is off; the switch still works', async () => {
  assert.equal(DEFAULT_SETTINGS.lanBlockQuic, false);
  assert.equal((await service.invoke('settings:get')).lanBlockQuic, true, 'the router default');
  await service.invoke('settings:set', { lanBlockQuic: false });
  assert.equal((await service.invoke('settings:get')).lanBlockQuic, false);
  await service.invoke('settings:set', { lanBlockQuic: true });
});

test('the router defaults are written into the store once, with a marker, so a fresh store cannot hide them', () => {
  // A fresh Store answers `settings` with the whole desktop DEFAULT_SETTINGS
  // object (autoConnect:false, lanBlockQuic:false); an overlay underneath it
  // would never win. The service writes the router defaults in, once.
  const saved = JSON.parse(fs.readFileSync(path.join(dir, 'store.json'), 'utf8'));
  assert.equal(saved.routerDefaultsApplied, true);
  assert.equal(saved.settings.autoConnect, true);
  assert.equal(saved.settings.lanBlockQuic, true);
  assert.equal(saved.settings.autoUpdateSubs, false, 'what the store already had is kept');
  assert.match(fs.readFileSync(path.join(__dirname, '..', 'src', 'server', 'service.js'), 'utf8'),
    /if \(OPENWRT && !store\.get\('routerDefaultsApplied', false\)\)/, 'guarded by the marker: a second start leaves the user’s choices alone');
});

test('on a router the managed DNS plan is forced on — a stored "off" is overridden, not honoured', async () => {
  assert.equal(DEFAULT_SETTINGS.dnsManaged, true);
  const res = await service.invoke('settings:set', { dnsManaged: false });
  assert.equal(res.settings.dnsManaged, true, 'the answer already says the switch has no effect here');
  assert.equal((await service.invoke('settings:get')).dnsManaged, true);
  assert.equal((await service.invoke('app:init')).settings.dnsManaged, true);
});

test('the boot-time retry is a router thing: the source pins 20 tries 15s apart there, one try elsewhere', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'src', 'server', 'service.js'), 'utf8');
  assert.match(src, /const AUTO_RETRY = OPENWRT \? \{ tries: 20, everyMs: 15000 \} : \{ tries: 1, everyMs: 0 \};/);
  assert.match(src, /if \(store\.get\('activeServerId', null\) \|\| isQuitting\) return;/, 'a connect made by hand ends the retries');
  assert.match(src, /attempt < AUTO_RETRY\.tries && !userDisconnecting/, 'so does a disconnect');
});

test('net:lanDevices answers a list even where there are no leases and no LAN', async () => {
  const devices = await service.invoke('net:lanDevices');
  assert.ok(Array.isArray(devices));
  for (const d of devices) assert.match(d.mac, /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/);
});
