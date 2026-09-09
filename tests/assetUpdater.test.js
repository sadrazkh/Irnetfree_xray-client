'use strict';
/**
 * The weekly asset update. What must hold: nothing happens while a tunnel is
 * up; the geo files are refreshed by default and cores only when asked; a core
 * is downloaded only when the release is genuinely newer than the installed
 * one; a failed download is a log line and the week still counts.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { AssetUpdater, cmpVersion, versionNumber, WEEK_MS } = require('../src/main/assetUpdater');

function make(over) {
  const log = [], dl = [];
  let checkedAt = 0, now = 10 * WEEK_MS;
  const u = new AssetUpdater(Object.assign({
    getSettings: () => ({ autoUpdateAssets: 'all' }),
    getCheckedAt: () => checkedAt,
    setCheckedAt: (t) => { checkedAt = t; },
    download: async (c) => { dl.push(c); },
    installed: (id) => id !== 'sing-box',
    currentVersion: async (id) => (id === 'xray' ? 'Xray 26.3.27 (Xray, Penetrates Everything.)' : '26.9.1'),
    latestVersion: async (id) => (id === 'xray' ? '26.4.1' : 'v26.9.1'),
    busy: () => false,
    onLog: (l) => log.push(l),
    now: () => now
  }, over || {}));
  return { u, dl, log, set: (t) => { now = t; }, checked: () => checkedAt };
}

test('cmpVersion and versionNumber', () => {
  assert.ok(cmpVersion('26.4.1', '26.3.27') > 0);
  assert.equal(cmpVersion('1.6.0', '1.6.0'), 0);
  assert.ok(cmpVersion('v1.6', '1.10') < 0);
  assert.equal(versionNumber('Xray 26.9.1 (Xray, Penetrates Everything.)'), '26.9.1');
  assert.equal(versionNumber('sing-box version 1.13.14\n\nEnvironment: go1.24'), '1.13.14');
  assert.equal(versionNumber(''), '');
  assert.equal(versionNumber('no number here'), '');
});

test('all: geo every week, a core only when newer, installed cores only', async () => {
  const h = make();
  assert.deepEqual(await h.u.tick(), { ran: true, done: ['geo', 'xray'] });
  assert.deepEqual(h.dl, ['geo', 'xray'], 'PattN is current and sing-box is not installed');
  assert.equal(h.checked(), 10 * WEEK_MS);
  assert.deepEqual(await h.u.tick(), { ran: false }, 'not due again');
  h.set(11 * WEEK_MS + 1);
  assert.equal((await h.u.tick()).ran, true);
});

test('geo (the default): only the geo files, never a core', async () => {
  const h = make({ getSettings: () => ({ autoUpdateAssets: 'geo' }) });
  assert.deepEqual(await h.u.tick(), { ran: true, done: ['geo'] });
  assert.deepEqual(h.dl, ['geo']);
  const unknown = make({ getSettings: () => ({}) });
  assert.deepEqual(await unknown.u.tick(), { ran: false }, 'an unset or unknown value is off');
});

test('off: never; busy (a tunnel is up): deferred without moving the stamp', async () => {
  assert.deepEqual(await make({ getSettings: () => ({ autoUpdateAssets: 'off' }) }).u.tick(), { ran: false });
  const b = make({ busy: () => true });
  assert.deepEqual(await b.u.tick(), { ran: false, deferred: true });
  assert.equal(b.checked(), 0, 'the next tick tries again');
  assert.deepEqual(b.dl, []);
});

test('a failing download or an unreadable version is a log line, not a stuck week', async () => {
  const f = make({ download: async (c) => { if (c === 'geo') throw new Error('net'); } });
  assert.deepEqual(await f.u.tick(), { ran: true, done: ['xray'] });
  assert.ok(f.log.some(l => /Geo update failed: net/.test(l)));
  assert.equal(f.checked(), 10 * WEEK_MS, 'the week still counts');
  const v = make({ currentVersion: async () => 'garbage' });
  assert.deepEqual(await v.u.tick(), { ran: true, done: ['geo'] }, 'no version, no download');
});

test('start() arms an interval and a first run; stop() clears both; neither holds the process', async () => {
  const h = make({ getSettings: () => ({ autoUpdateAssets: 'geo' }) });
  h.u.start(60000, 10);
  assert.ok(h.u.timer && h.u.firstTimer);
  await new Promise(r => setTimeout(r, 40));
  assert.deepEqual(h.dl, ['geo'], 'the first run happened');
  h.u.stop();
  assert.equal(h.u.timer, null);
  assert.equal(h.u.firstTimer, null);
});
