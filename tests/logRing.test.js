'use strict';
/** The service's in-memory log ring (v1.16 S7): the newest `max` lines, in order. */
const test = require('node:test');
const assert = require('node:assert/strict');
const { createLogRing } = require('../src/server/logRing');

test('keeps the newest max lines and hands back the last n in order', () => {
  const ring = createLogRing(5);
  assert.deepEqual(ring.tail(3), []);
  for (let i = 1; i <= 7; i++) ring.push('line ' + i);
  assert.equal(ring.length, 5);
  assert.deepEqual(ring.tail(3), ['line 5', 'line 6', 'line 7']);
  assert.deepEqual(ring.tail(5), ['line 3', 'line 4', 'line 5', 'line 6', 'line 7']);
  assert.deepEqual(ring.tail(50), ['line 3', 'line 4', 'line 5', 'line 6', 'line 7'], 'more than it holds is all of it');
  assert.deepEqual(ring.tail(0), []);
  assert.deepEqual(ring.tail(-1), []);
});

test('the default is 500 lines; a non-string is kept as text; the ring never grows past max', () => {
  const ring = createLogRing();
  assert.equal(ring.max, 500);
  for (let i = 0; i < 1200; i++) ring.push(i);
  assert.equal(ring.length, 500);
  assert.deepEqual(ring.tail(2), ['1198', '1199']);
  assert.equal(createLogRing('nonsense').max, 500);
  assert.equal(createLogRing(0).max, 500, 'nothing or less is the default, never a ring that holds nothing');
  assert.equal(createLogRing(2.7).max, 2);
});
