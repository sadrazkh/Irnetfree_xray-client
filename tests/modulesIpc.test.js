'use strict';
/**
 * The extensions on the router's service (the real service over the gateway
 * fakes, tests/serviceHarness.js): the one-time migration of a store from
 * before (what it uses on, once), modules:get / modules:set — install with
 * what it needs, the refusal while another needs it, persisted — and
 * multiWan built as disabled while its extension is not installed.
 */
process.env.IRNETFREE_PLATFORM = 'openwrt';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const H = require('./serviceHarness');

process.setMaxListeners(60);
test.after(() => H.cleanupDirs());
const disk = (s) => JSON.parse(fs.readFileSync(path.join(s.dir, 'store.json'), 'utf8'));

test('router: a store from before gets the extensions it uses, once; modules:get answers them, the counts and the platform', async (t) => {
  const s = H.start({ chains: [{ id: 'c1', name: 'C', members: ['srv-1', 'srv-2'] }], settings: { allowLan: true } });
  t.after(() => s.service.shutdown());
  const saved = disk(s).settings;
  assert.deepEqual(saved.modules, { chains: true, lanShare: true });
  assert.equal(saved.modulesMigrated, true);
  const res = await s.service.invoke('modules:get');
  assert.deepEqual(Object.keys(res).sort(), ['inUse', 'modules', 'platform']);
  assert.deepEqual(res.modules, { chains: true, lanShare: true });
  assert.equal(res.platform, 'router');
  assert.equal(res.inUse.chains, 1);
  assert.equal(res.inUse.groups, 0);
  // removed by hand, it stays removed at the next start: the migration ran once
  await s.service.invoke('modules:set', { id: 'chains', on: false });
  await s.service.shutdown();
  const again = H.startIn(s.dir);
  t.after(() => again.service.shutdown());
  assert.deepEqual((await again.service.invoke('modules:get')).modules, { lanShare: true });
});

test('router: modules:set installs with what it needs, refuses to remove one another needs, refuses what the router has not', async (t) => {
  const s = H.start({ settings: { modules: {}, modulesMigrated: true } });
  t.after(() => s.service.shutdown());
  const r1 = await s.service.invoke('modules:set', { id: 'warp', on: true });
  assert.deepEqual(r1.modules, { warp: true, chains: true });
  assert.deepEqual(r1.pendingReconnect, []);
  assert.equal('blockedBy' in r1, false);
  const r2 = await s.service.invoke('modules:set', { id: 'chains', on: false });
  assert.deepEqual(r2.blockedBy, ['warp']);
  assert.deepEqual(r2.modules, { warp: true, chains: true });
  const r3 = await s.service.invoke('modules:set', { id: 'lanShare', on: true });
  assert.equal(r3.error, 'unavailable');
  assert.deepEqual(disk(s).settings.modules, { warp: true, chains: true }, 'persisted, and only what was allowed');
  assert.deepEqual((await s.service.invoke('settings:get')).modules, { warp: true, chains: true });
});

test('router: multiWan not installed connects as one internet; installed, over each — and toggling it while connected waits for a reconnect', async (t) => {
  const multiWan = { enabled: true, links: [{ id: 'wan', iface: 'eth1', name: 'Cable' }, { id: 'usb0', iface: 'usb0', name: 'Phone' }] };
  const off = H.start({ settings: { multiWan, modules: {}, modulesMigrated: true } });
  t.after(() => off.service.shutdown());
  await off.service.invoke('connect', H.SERVER.id);
  assert.ok(!JSON.stringify(off.state.xray.starts[0].config).includes('"interface":"usb0"'), 'one internet');
  const res = await off.service.invoke('modules:set', { id: 'multiWan', on: true });
  assert.deepEqual(res.pendingReconnect, ['modules']);
  const on = H.start({ settings: { multiWan, modules: { multiWan: true }, modulesMigrated: true } });
  t.after(() => on.service.shutdown());
  await on.service.invoke('connect', H.SERVER.id);
  assert.ok(JSON.stringify(on.state.xray.starts[0].config).includes('"interface":"usb0"'), 'over each internet');
});
