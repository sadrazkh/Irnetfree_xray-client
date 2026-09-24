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
      servers: [{ id: 's1', protocol: 'vless', port: 443, outbound: { changed: true } }, { id: 's2', protocol: 'vless', port: 443, outbound: {} }, { id: 'bad' }],
      subscriptions: [{ id: 'B', url: 'https://b' }, { id: 'nourl' }],
      chains: [{ id: 'c1' }], pool: [{ id: 'p1' }],
      settings: { socksPort: 20808, theme: 'light' }
    },
    usage: { s2: { down: 5, up: 5 } }
  });
  const r = importBundle(b, current);
  assert.deepEqual(r.added, { servers: 1, subscriptions: 1, chains: 1, pool: 1 });
  assert.deepEqual(r.next.servers, [{ id: 's1', outbound: {} }, { id: 's2', protocol: 'vless', port: 443, outbound: {} }], 'the existing s1 is kept as it was; a record without an outbound is not a server');
  assert.deepEqual(r.next.subscriptions.map(s => s.id), ['A', 'B']);
  assert.deepEqual(r.next.settings, { lang: 'fa', socksPort: 20808, theme: 'light' });
  assert.deepEqual(r.next.usage, { s1: { down: 1, up: 1 }, s2: { down: 5, up: 5 } });
});

test('restoring twice is restoring once', () => {
  const b = exportBundle({ store: { servers: [{ id: 's9', protocol: 'trojan', port: 443, outbound: {} }] } });
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

// A backup is a file someone can hand you. Its ids, protocols and ports end up
// inside the renderer's markup (and its CSS selectors): what a record of ours
// never contains must not come in from one.
test('an imported record with an id we never write is dropped, and so is every reference to it', () => {
  const XSS = '"><img src=x onerror=alert(1)>';
  const b = exportBundle({
    store: {
      servers: [
        { id: 'good1', protocol: 'vless', port: 443, outbound: {} },
        { id: XSS, protocol: 'vless', port: 443, outbound: {} },
        { id: 'a b', protocol: 'vless', port: 443, outbound: {} },
        { id: 7, protocol: 'vless', port: 443, outbound: {} }
      ],
      subscriptions: [{ id: 'sub-ok', url: 'https://a' }, { id: XSS, url: 'https://b' }],
      chains: [{ id: 'chain-ok', name: 'C', members: ['good1', XSS, 'gone', 5] }, { id: XSS, members: [] }],
      pool: [
        { id: 'px-ok', target: 'good1', socksPort: 60001 },
        { id: 'px-chain', target: 'chain:chain-ok', socksPort: 60002 },
        { id: 'px-bad-target', target: XSS, socksPort: 60003 },
        { id: XSS, target: 'good1', socksPort: 60004 }
      ]
    }
  });
  const r = importBundle(b, { servers: [], subscriptions: [], chains: [], pool: [] });
  assert.deepEqual(r.next.servers.map(s => s.id), ['good1']);
  assert.deepEqual(r.next.subscriptions.map(s => s.id), ['sub-ok']);
  assert.deepEqual(r.next.chains, [{ id: 'chain-ok', name: 'C', members: ['good1', 'gone'] }]);
  assert.deepEqual(r.next.pool.map(p => [p.id, p.target]), [['px-ok', 'good1'], ['px-chain', 'chain:chain-ok'], ['px-bad-target', '']]);
  assert.deepEqual(r.added, { servers: 1, subscriptions: 1, chains: 1, pool: 3 });
});

test('an imported server must be a protocol we build, with a real port', () => {
  const b = exportBundle({
    store: {
      servers: [
        { id: 's-a', protocol: 'vless', port: '8443', outbound: {} },
        { id: 's-b', protocol: '<b>x</b>', port: 443, outbound: {} },
        { id: 's-c', protocol: 'trojan', port: '443"><svg onload=alert(1)>', outbound: {} },
        { id: 's-d', protocol: 'wireguard', port: 70000, outbound: {} },
        { id: 's-e', protocol: 'shadowsocks', port: 8388, outbound: {} }
      ]
    }
  });
  const r = importBundle(b, { servers: [] });
  assert.deepEqual(r.next.servers.map(s => [s.id, s.protocol, s.port]), [['s-a', 'vless', 8443], ['s-e', 'shadowsocks', 8388]]);
});

test('imported ports and counts are integers: pool ports, the subscription’s server count, the settings’ ports', () => {
  const b = exportBundle({
    store: {
      subscriptions: [{ id: 'S1', url: 'https://a', serverCount: '<img src=x onerror=alert(1)>' }, { id: 'S2', url: 'https://b', serverCount: '12' }],
      pool: [{ id: 'px-1', target: 't1', socksPort: '60001', httpPort: '<svg onload=alert(1)>' }],
      settings: { socksPort: '20808', httpPort: '"><img src=x>', apiPort: 10085.5, theme: 'dark' }
    }
  });
  const r = importBundle(b, { settings: { httpPort: 10809, apiPort: 10085 } });
  assert.deepEqual(r.next.subscriptions.map(s => s.serverCount), [0, 12]);
  assert.deepEqual(r.next.pool.map(p => [p.socksPort, p.httpPort]), [[60001, 0]]);
  assert.deepEqual(r.next.settings, { socksPort: 20808, httpPort: 10809, apiPort: 10085, theme: 'dark' }, 'a bad port leaves the current one in place');
});
