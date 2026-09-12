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

test('DNS watch asks for a FULL refresh on the first tick of a session and every Nth after, cheap ticks between', async () => {
  const seen = [];
  const watch = new DnsGuardWatch({ isActive: () => true, fullEvery: 3, guard: { refresh: async ({ token, full }) => { seen.push([token, full]); } } });
  watch.start('s1');
  for (let i = 0; i < 7; i++) await watch.tick();
  assert.deepEqual(seen.map(([, full]) => full), [true, false, false, true, false, false, true]);
  assert.ok(seen.every(([token]) => token === 's1'));
  // a new session starts the cycle again
  watch.stop(); watch.start('s2'); await watch.tick(); await watch.tick();
  assert.deepEqual(seen.slice(-2), [['s2', true], ['s2', false]]);
  watch.stop();
  // the default keeps one PowerShell snapshot in ten ticks (five minutes at 30 s)
  assert.equal(new DnsGuardWatch({ isActive: () => true, guard: {} }).fullEvery, 10);
  assert.equal(new DnsGuardWatch({ isActive: () => true, guard: {}, fullEvery: 0 }).fullEvery, 1, 'never less than every tick');
});

test('DNS watch skips inactive sessions and suppresses stale or repeated warnings', async () => {
  let active = false, calls = 0, errors = 0;
  const watch = new DnsGuardWatch({ isActive: () => active, onError: () => errors++,
    guard: { refresh: async () => { calls++; throw Error('denied'); } } });
  watch.start('session'); await watch.tick(); assert.equal(calls, 0);
  active = true; await watch.tick(); await watch.tick(); assert.equal(errors, 1);
  const stale = watch.tick(); watch.stop(); await stale; assert.equal(errors, 1);
});
