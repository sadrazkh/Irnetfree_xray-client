'use strict';
/**
 * A connection that drops on its own is rebuilt — but not for ever.
 *
 * The recovery after a drop is bounded per episode (runRecovery's backoff, then
 * reconnect-failed), and only for an attempt that FAILS. A core that comes up,
 * survives the start-up grace and dies seconds later is a successful rebuild
 * every time, so each death would start a fresh episode: the tunnel torn down
 * and rebuilt in a loop, the kill switch flapping, for as long as the app runs.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { DropBudget } = require('../src/main/dropBudget');

function clock(start = 1000) {
  let t = start;
  return { now: () => t, advance: (ms) => { t += ms; } };
}

test('a few drops in the window are rebuilt; the next one is not', () => {
  const c = clock();
  const b = new DropBudget({ limit: 3, windowMs: 60000, now: c.now });
  assert.equal(b.take(), true);
  c.advance(5000); assert.equal(b.take(), true);
  c.advance(5000); assert.equal(b.take(), true);
  c.advance(5000); assert.equal(b.take(), false, 'the fourth drop in a minute is a loop, not bad luck');
  c.advance(1000); assert.equal(b.take(), false, 'and it stays refused while the drops keep coming');
});

test('drops far apart never run the budget out', () => {
  const c = clock();
  const b = new DropBudget({ limit: 3, windowMs: 60000, now: c.now });
  for (let i = 0; i < 20; i++) {
    assert.equal(b.take(), true, `drop ${i + 1}, a minute and a bit after the last`);
    c.advance(61000);
  }
});

test('the window slides: old drops stop counting', () => {
  const c = clock();
  const b = new DropBudget({ limit: 2, windowMs: 10000, now: c.now });
  assert.equal(b.take(), true);
  c.advance(6000); assert.equal(b.take(), true);
  c.advance(3000); assert.equal(b.take(), false);
  c.advance(8000);                     // the first two have aged out; the refused one has not
  assert.equal(b.take(), true);
});

test('reset() — a connect or a disconnect the user made — starts from nothing', () => {
  const c = clock();
  const b = new DropBudget({ limit: 1, windowMs: 60000, now: c.now });
  assert.equal(b.take(), true);
  assert.equal(b.take(), false);
  b.reset();
  assert.equal(b.take(), true);
});

test('the defaults: three drops within five minutes', () => {
  const c = clock();
  const b = new DropBudget({ now: c.now });
  assert.equal(b.limit, 3);
  assert.equal(b.windowMs, 5 * 60 * 1000);
  assert.deepEqual([b.take(), b.take(), b.take(), b.take()], [true, true, true, false]);
});
