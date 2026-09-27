'use strict';
/**
 * The selected config survives a restart (v1.15 D3).
 *
 * v1.14.0 clears `activeServerId` at every launch — a new process has no live
 * connection — and the picker took its selection from exactly that, so every
 * restart landed on the first server. The selection is now kept on its own
 * (`selectedServerId`, written by `selection:set` whenever the picker's choice
 * moves) and handed back by app:init with `lastServerId` beside it; the renderer
 * resolves it against what can still be selected (desktopUx.test.js).
 *
 * Driven through the headless service (the router's web UI), with the cores
 * faked; main.js is pinned to the same function as text.
 */
process.env.IRNETFREE_PLATFORM = 'openwrt';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createService } = require('../src/server/service');
const { makeProxyServer } = require('../src/main/parser');
const fakes = require('./gatewayFakes');

process.setMaxListeners(40);   // every service registers its own exit hook

const A = Object.assign(makeProxyServer({ type: 'socks', address: '192.0.2.10', port: 1080, name: 'A' }), { id: 'srv-a' });
const B = Object.assign(makeProxyServer({ type: 'socks', address: '192.0.2.11', port: 1080, name: 'B' }), { id: 'srv-b' });
const BASE = { autoUpdateSubs: false, autoUpdateAssets: 'off', autoConnect: false, tunMode: false, lang: 'en',
  routingMode: 'global', blockAds: false, socksPort: 47828, httpPort: 47829, apiPort: 47905 };

const dirs = [];
test.after(() => { for (const d of dirs) { try { fs.rmSync(d, { recursive: true, force: true }); } catch {} } });

function freshDir() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-sel-'));
  dirs.push(dir);
  fs.writeFileSync(path.join(dir, 'store.json'), JSON.stringify({ servers: [A, B], routerDefaultsApplied: true, settings: BASE }));
  return dir;
}
function startIn(dir) {
  const state = fakes.makeState();
  return createService({ dataDir: dir, deps: fakes.deps(state) });
}
const onDisk = (dir) => JSON.parse(fs.readFileSync(path.join(dir, 'store.json'), 'utf8'));

test('the selection is kept across a restart, beside the last connection made', async () => {
  const dir = freshDir();
  const first = startIn(dir);
  let init = await first.invoke('app:init');
  assert.equal(init.selectedServerId, null, 'nothing chosen yet');
  assert.equal(init.lastServerId, null);
  await first.invoke('connect', A.id);
  assert.equal(await first.invoke('selection:set', B.id), B.id);   // connected to A, B picked since
  init = await first.invoke('app:init');
  assert.equal(init.selectedServerId, B.id);
  assert.equal(init.lastServerId, A.id);
  await first.shutdown();

  const again = startIn(dir);
  init = await again.invoke('app:init');
  assert.equal(init.activeServerId, null, 'a new process has no live connection (v1.14.0)');
  assert.equal(init.selectedServerId, B.id, 'but the picker’s choice is still there');
  assert.equal(init.lastServerId, A.id);
  await again.shutdown();
});

test('any target is a selection — a chain, advanced routing, the pool — and anything else clears it', async () => {
  const dir = freshDir();
  const s = startIn(dir);
  for (const id of ['chain-1', '__advanced__', '__pool__', A.id]) {
    assert.equal(await s.invoke('selection:set', id), id);
    assert.equal((await s.invoke('app:init')).selectedServerId, id);
  }
  for (const bad of [null, undefined, '', 42, { id: A.id }]) {
    assert.equal(await s.invoke('selection:set', bad), null, JSON.stringify(bad));
  }
  assert.equal((await s.invoke('app:init')).selectedServerId, null);
  await s.shutdown();
});

test('a choice is coalesced, not a store write per click — and a shutdown still writes it', async () => {
  const dir = freshDir();
  const s = startIn(dir);
  const before = fs.readFileSync(path.join(dir, 'store.json'), 'utf8');
  await s.invoke('selection:set', A.id);
  await s.invoke('selection:set', B.id);
  assert.equal(fs.readFileSync(path.join(dir, 'store.json'), 'utf8'), before, 'nothing on disk yet: clicking down a list is not a write per click');
  await s.shutdown();
  assert.equal(onDisk(dir).selectedServerId, B.id, 'the last choice reached the disk');
});

/* ------------------------------ main.js, as text ------------------------------ */

// CRLF on a Windows checkout (core.autocrlf): the patterns below are written with \n.
const R = (...p) => fs.readFileSync(path.join(__dirname, '..', ...p), 'utf8').replace(/\r\n/g, '\n');
const MAIN = R('src', 'main', 'main.js');
const SERVICE = R('src', 'server', 'service.js');
function slice(source, label, start, end) {
  const a = source.indexOf(start);
  assert.notEqual(a, -1, `${label}: ${start} is gone`);
  const b = source.indexOf(end, a + start.length);
  assert.notEqual(b, -1, `${label}: nothing ends ${start}`);
  return source.slice(a, b + end.length);
}
const level = (s) => s.split('\n').map((l) => l.trim()).join('\n');

test('main.js keeps the selection exactly as the service does, and hands it back at launch', () => {
  const main = level(slice(MAIN, 'main.js', 'function setSelection(id) {', '\n}\n'));
  const service = level(slice(SERVICE, 'service.js', 'function setSelection(id) {', '\n  }\n'));
  assert.equal(main, service);
  assert.match(main, /store\.setLazy\('selectedServerId', v\)/, 'coalesced');
  assert.match(MAIN, /ipcMain\.handle\('selection:set', \(e, id\) => setSelection\(id\)\);/);
  assert.match(SERVICE, /'selection:set': \(id\) => setSelection\(id\),/);
  for (const [label, src] of [['main.js', MAIN], ['service.js', SERVICE]]) {
    const init = slice(src, label, label === 'main.js' ? "ipcMain.handle('app:init', () => ({" : "'app:init': () => ({", '})');
    assert.match(init, /selectedServerId: store\.get\('selectedServerId', null\),/, label);
    assert.match(init, /lastServerId: store\.get\('lastServerId', null\),/, label);
  }
  // a coalesced write must reach the disk on the way out
  assert.match(slice(MAIN, 'main.js', 'async function teardownForQuit() {', '\n}'), /store\.flush\(\)/);
  assert.match(slice(SERVICE, 'service.js', 'async function shutdown() {', '\n  }'), /store\.flush\(\)/);
  // both bridges carry it
  assert.match(R('src', 'preload', 'preload.js'), /setSelection: \(id\) => ipcRenderer\.invoke\('selection:set', id\),/);
  assert.match(R('src', 'server', 'web-api.js'), /setSelection: \(id\) => invoke\('selection:set', id\),/);
});
