'use strict';
/**
 * Store durability tests.
 *
 * This one file holds every server, subscription, chain and setting, so the
 * properties that matter are: a failed write never destroys what was already
 * saved, and an unreadable file is never silently swallowed into an empty store.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { Store } = require('../src/main/store');

const DEFAULTS = { servers: [], settings: { socksPort: 10808 }, activeServerId: null };

/** Run a case in its own temp directory, always cleaned up. */
function withDir(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-store-'));
  const file = path.join(dir, 'store.json');
  try { return fn({ dir, file }); } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

const read = (f) => JSON.parse(fs.readFileSync(f, 'utf8'));

/* ----------------------------- basics ----------------------------- */

test('defaults are used when nothing is saved yet', () => {
  withDir(({ file }) => {
    const s = new Store(file, DEFAULTS);
    assert.deepEqual(s.get('servers'), []);
    assert.equal(s.get('missing', 'fallback'), 'fallback');
    assert.equal(s.loadError, null);
    assert.equal(fs.existsSync(file), false, 'construction must not write');
  });
});

test('values round-trip through a new instance', () => {
  withDir(({ file }) => {
    const a = new Store(file, DEFAULTS);
    a.set('servers', [{ id: 's1', name: 'A' }]);
    a.assign({ activeServerId: 's1' });

    const b = new Store(file, DEFAULTS);
    assert.deepEqual(b.get('servers'), [{ id: 's1', name: 'A' }]);
    assert.equal(b.get('activeServerId'), 's1');
    // keys absent from the file still come from the defaults
    assert.deepEqual(b.get('settings'), { socksPort: 10808 });
  });
});

test('a save leaves no temp file behind', () => {
  withDir(({ dir, file }) => {
    const s = new Store(file, DEFAULTS);
    s.set('servers', [{ id: 's1' }]);
    assert.deepEqual(fs.readdirSync(dir), ['store.json']);
  });
});

test('creates the data directory if it does not exist', () => {
  withDir(({ dir }) => {
    const file = path.join(dir, 'nested', 'deeper', 'store.json');
    new Store(file, DEFAULTS).set('servers', [1]);
    assert.deepEqual(read(file).servers, [1]);
  });
});

/* --------------------------- corrupt files --------------------------- */

test('a corrupt file is quarantined and reported, never silently dropped', () => {
  withDir(({ file }) => {
    // what a torn in-place write used to leave behind
    fs.writeFileSync(file, '{"servers":[{"id":"s1","na', 'utf8');

    const errors = [];
    const s = new Store(file, DEFAULTS, { onError: (kind, info) => errors.push([kind, info]) });

    assert.deepEqual(s.get('servers'), [], 'falls back to defaults');
    assert.ok(s.loadError, 'loadError must be set');
    assert.match(s.loadError.reason, /invalid JSON/);
    assert.equal(s.loadError.recovered, false);

    // the bad file is kept so the user can still get their servers back
    assert.ok(s.loadError.backup && fs.existsSync(s.loadError.backup), 'no backup kept');
    assert.match(path.basename(s.loadError.backup), /^store\.json\.corrupt-\d+$/);
    assert.equal(fs.readFileSync(s.loadError.backup, 'utf8'), '{"servers":[{"id":"s1","na');

    assert.equal(errors.length, 1);
    assert.equal(errors[0][0], 'load');
  });
});

test('JSON that is not an object counts as corrupt', () => {
  for (const body of ['null', '"a string"', '[1,2,3]', '42']) {
    withDir(({ file }) => {
      fs.writeFileSync(file, body, 'utf8');
      const s = new Store(file, DEFAULTS);
      assert.ok(s.loadError, `${body} should be rejected`);
      assert.match(s.loadError.reason, /not a JSON object/);
      assert.deepEqual(s.get('servers'), []);
    });
  }
});

test('a corrupt file falls back to a leftover temp file', () => {
  withDir(({ file }) => {
    fs.writeFileSync(file, 'garbage', 'utf8');
    fs.writeFileSync(file + '.tmp', JSON.stringify({ servers: [{ id: 'rescued' }] }), 'utf8');

    const s = new Store(file, DEFAULTS);
    assert.deepEqual(s.get('servers'), [{ id: 'rescued' }]);
    assert.equal(s.loadError.recovered, true);
  });
});

test('a first-run crash between write and rename is recovered from the temp file', () => {
  withDir(({ file }) => {
    fs.writeFileSync(file + '.tmp', JSON.stringify({ servers: [{ id: 'first' }] }), 'utf8');
    const s = new Store(file, DEFAULTS);
    assert.deepEqual(s.get('servers'), [{ id: 'first' }]);
    assert.equal(s.loadError, null, 'nothing was lost, so nothing to report');
  });
});

test('a stale temp file never overrides a readable store', () => {
  withDir(({ file }) => {
    // the real file is the last COMPLETE write; .tmp may be newer but unswapped
    fs.writeFileSync(file, JSON.stringify({ servers: [{ id: 'real' }] }), 'utf8');
    fs.writeFileSync(file + '.tmp', JSON.stringify({ servers: [{ id: 'stale' }] }), 'utf8');

    const s = new Store(file, DEFAULTS);
    assert.deepEqual(s.get('servers'), [{ id: 'real' }]);
  });
});

/* --------------------------- failed writes --------------------------- */

test('a failed save leaves the previously saved data intact', () => {
  withDir(({ file }) => {
    const s = new Store(file, DEFAULTS);
    s.set('servers', [{ id: 'keep-me' }]);

    // block the temp path so the write cannot succeed
    fs.mkdirSync(s.tmpPath);
    const errors = [];
    s.onError = (kind, info) => errors.push([kind, info]);

    assert.equal(s.set('servers', []), false, 'save must report failure');
    assert.ok(s.saveError, 'saveError must be set');
    assert.equal(errors[0][0], 'save');

    // this is the whole point: the good file on disk is untouched
    assert.deepEqual(read(file).servers, [{ id: 'keep-me' }]);
    assert.deepEqual(new Store(file, DEFAULTS).get('servers'), [{ id: 'keep-me' }]);

    fs.rmdirSync(s.tmpPath);
  });
});

test('saveError clears once a save succeeds again', () => {
  withDir(({ file }) => {
    const s = new Store(file, DEFAULTS);
    fs.mkdirSync(s.tmpPath);
    assert.equal(s.set('servers', [1]), false);
    assert.ok(s.saveError);

    fs.rmdirSync(s.tmpPath);
    assert.equal(s.set('servers', [2]), true);
    assert.equal(s.saveError, null);
    assert.deepEqual(read(file).servers, [2]);
  });
});

/* --------------------------- the actual regression --------------------------- */

test('an interrupted write cannot corrupt the saved store', () => {
  withDir(({ file }) => {
    const s = new Store(file, DEFAULTS);
    const servers = Array.from({ length: 200 }, (_, i) => ({ id: 's' + i, name: 'server ' + i }));
    s.set('servers', servers);

    // Simulate the crash the old code could not survive: a partial write landing
    // in the temp file, with the process dying before the rename.
    fs.writeFileSync(s.tmpPath, JSON.stringify({ servers }).slice(0, 137), 'utf8');

    const next = new Store(file, DEFAULTS);
    assert.equal(next.loadError, null, 'the real file was never touched');
    assert.equal(next.get('servers').length, 200);
    assert.deepEqual(next.get('servers'), servers);
  });
});
