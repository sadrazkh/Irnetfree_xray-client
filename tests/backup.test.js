'use strict';
/**
 * Backup and restore. The properties that matter: nothing already on the
 * machine is lost by a restore, restoring twice equals restoring once, and a
 * foreign file is refused before anything is read from it.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { exportBundle, importBundle } = require('../src/main/backup');

const current = {
  servers: [{ id: 's1', outbound: {} }],
  subscriptions: [{ id: 'A', url: 'https://a' }],
  chains: [], pool: [],
  settings: { lang: 'fa', socksPort: 10808 },
  usage: { s1: { down: 1, up: 1 } }
};

test('export carries everything and says what it is', () => {
  const b = exportBundle({ version: '1.6.0', store: current, usage: current.usage });
  assert.equal(b.app, 'IRNetFree');
  assert.equal(b.format, 1);
  assert.equal(b.version, '1.6.0');
  assert.deepEqual(b.servers, current.servers);
  assert.deepEqual(b.usage, current.usage);
  assert.match(b.exportedAt, /^\d{4}-\d{2}-\d{2}T/);
  assert.deepEqual(exportBundle({ store: null }).servers, [], 'an empty store exports empty lists');
});

test('import merges by id, keeps what is there, overlays settings and usage', () => {
  const b = exportBundle({
    version: '1.6.0',
    store: {
      servers: [{ id: 's1', outbound: { changed: true } }, { id: 's2', outbound: {} }, { id: 'bad' }],
      subscriptions: [{ id: 'B', url: 'https://b' }, { id: 'nourl' }],
      chains: [{ id: 'c1' }], pool: [{ id: 'p1' }],
      settings: { socksPort: 20808, theme: 'light' }
    },
    usage: { s2: { down: 5, up: 5 } }
  });
  const r = importBundle(b, current);
  assert.deepEqual(r.added, { servers: 1, subscriptions: 1, chains: 1, pool: 1 });
  assert.deepEqual(r.next.servers, [{ id: 's1', outbound: {} }, { id: 's2', outbound: {} }], 'the existing s1 is kept as it was; a record without an outbound is not a server');
  assert.deepEqual(r.next.subscriptions.map(s => s.id), ['A', 'B']);
  assert.deepEqual(r.next.settings, { lang: 'fa', socksPort: 20808, theme: 'light' });
  assert.deepEqual(r.next.usage, { s1: { down: 1, up: 1 }, s2: { down: 5, up: 5 } });
});

test('restoring twice is restoring once', () => {
  const b = exportBundle({ store: { servers: [{ id: 's9', outbound: {} }] } });
  const once = importBundle(b, current);
  const twice = importBundle(b, once.next);
  assert.deepEqual(twice.added, { servers: 0, subscriptions: 0, chains: 0, pool: 0 });
  assert.deepEqual(twice.next.servers, once.next.servers);
});

test('a foreign or malformed file is refused', () => {
  assert.throws(() => importBundle({ app: 'other', format: 1 }, current), /not an IRNetFree backup/);
  assert.throws(() => importBundle({ app: 'IRNetFree', format: 2 }, current), /not an IRNetFree backup/);
  assert.throws(() => importBundle(null, current), /not an IRNetFree backup/);
  assert.throws(() => importBundle([], current), /not an IRNetFree backup/);
});
