'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { DnsGuardWatch } = require('../src/main/dnsGuardWatch');

test('DNS watch is single flight and carries its original receipt across stop', async () => {
  const calls = []; let finish;
  const watch = new DnsGuardWatch({ isActive: () => true, guard: { refresh: ({ token }) => {
    calls.push(token); return new Promise(resolve => { finish = resolve; });
  } } });
  watch.start('old');
  const pending = watch.tick(); await watch.tick();
  watch.stop(); await watch.tick();
  assert.deepEqual(calls, ['old']);
  finish(); await pending;
  watch.start('new'); const next = watch.tick();
  assert.deepEqual(calls, ['old', 'new']);
  finish(); await next; watch.stop();
});

test('DNS watch skips inactive sessions and suppresses stale or repeated warnings', async () => {
  let active = false, calls = 0, errors = 0;
  const watch = new DnsGuardWatch({ isActive: () => active, onError: () => errors++,
    guard: { refresh: async () => { calls++; throw Error('denied'); } } });
  watch.start('session'); await watch.tick(); assert.equal(calls, 0);
  active = true; await watch.tick(); await watch.tick(); assert.equal(errors, 1);
  const stale = watch.tick(); watch.stop(); await stale; assert.equal(errors, 1);
});
