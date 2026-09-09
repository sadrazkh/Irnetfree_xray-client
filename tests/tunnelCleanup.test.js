'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { stopTrackedTunnels, releaseGuardChecked } = require('../src/main/tunnelCleanup');

test('mac cleanup attempts every tunnel and keeps only failures for retry', async () => {
  let fail = true;
  const calls = [];
  const first = { stop: async () => { calls.push('first'); if (fail) throw new Error('permission cancelled'); } };
  const second = { stop: async () => { calls.push('second'); } };
  const started = new Set([first, second]);
  await assert.rejects(stopTrackedTunnels(started, first, 'darwin'), /cleanup incomplete/);
  assert.deepEqual(calls, ['first', 'second']);
  assert.deepEqual([...started], [first]);
  fail = false;
  await stopTrackedTunnels(started, first, 'darwin');
  assert.equal(started.size, 0);
});
test('Windows keeps best-effort cleanup semantics', async () => {
  const started = new Set([{ stop: async () => { throw new Error('old behavior'); } }]);
  await stopTrackedTunnels(started, null, 'win32');
  assert.equal(started.size, 0);
});
test('mac guard failures cannot become successful disconnects', async () => {
  const guard = { release: async () => ({ released: false, error: 'cancelled' }) };
  await assert.rejects(releaseGuardChecked(guard, 'darwin'), /DNS recovery incomplete/);
  assert.equal((await releaseGuardChecked(guard, 'win32')).released, false);
});
