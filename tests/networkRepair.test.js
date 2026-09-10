'use strict';
/**
 * "Recover network" (the diagnostics dialog's fourth button) must never take a
 * live VPN down.
 *
 * It was reviewed as a read-only action, sitting beside three read-only buttons,
 * and its own failure text said "Disconnect first, then retry" — while the
 * handler called doDisconnect() unconditionally, on every platform. On Windows
 * and Linux, where the darwin block is skipped entirely, that made the whole
 * action "drop the connection and release an already-released guard".
 *
 * repairNetwork() lives inside main.js / service.js, which cannot be required
 * here (electron; and requiring service.js would build a live headless service).
 * So this reads the two sources: the same test that proves the refusal also
 * proves the two mirrors still say it identically, which is the thing that
 * silently rots.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const R = (...p) => fs.readFileSync(path.join(__dirname, '..', ...p), 'utf8');
const MAIN = R('src', 'main', 'main.js');
const SERVICE = R('src', 'server', 'service.js');

const TAIL = 'finally { networkRepairing = false; }';

/** The body of repairNetwork(), with the one Electron-vs-server word levelled. */
function repairNetwork(source, label) {
  const start = source.indexOf('async function repairNetwork()');
  assert.notEqual(start, -1, `${label}: repairNetwork() is gone`);
  const end = source.indexOf(TAIL, start);
  assert.notEqual(end, -1, `${label}: repairNetwork() no longer clears its busy flag`);
  return source.slice(start, end + TAIL.length).replace(/app\.getPath\('userData'\)/g, 'dataDir');
}

const MAIN_REPAIR = repairNetwork(MAIN, 'main.js');
const SERVICE_REPAIR = repairNetwork(SERVICE, 'service.js');

test('network recovery refuses while the core is running instead of disconnecting', () => {
  for (const [label, body] of [['main.js', MAIN_REPAIR], ['service.js', SERVICE_REPAIR]]) {
    assert.match(body, /if \(xray && xray\.running\) return \{ ok: false, error: 'connected' \};/,
      `${label}: nothing stops recovery from running against a live connection`);
    assert.doesNotMatch(body, /doDisconnect/,
      `${label}: recovery must not take the connection down — the user was never asked`);
  }
});

test('the refusal is decided before anything is torn down', () => {
  for (const [label, body] of [['main.js', MAIN_REPAIR], ['service.js', SERVICE_REPAIR]]) {
    const refusal = body.indexOf("error: 'connected'");
    assert.notEqual(refusal, -1, `${label}: there is no connected check to order`);
    for (const after of ['recoverMacSessions', 'releaseGuardChecked']) {
      assert.ok(refusal < body.indexOf(after),
        `${label}: ${after} runs before the connected check`);
    }
  }
});

test('both mirrors carry the same recovery, line for line', () => {
  // Only `app.getPath('userData')` vs `dataDir` may differ; the indentation of
  // the two enclosing scopes may not count against them.
  const level = (s) => s.split('\n').map((l) => l.trim()).join('\n');
  assert.equal(level(MAIN_REPAIR), level(SERVICE_REPAIR));
});
