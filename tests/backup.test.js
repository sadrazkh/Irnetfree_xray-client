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
  assert.deepEqual(r.added, { servers: 1, subscriptions: 1, chains: 1, pool: 1, routingProfiles: 0 });
  assert.deepEqual(r.next.servers, [{ id: 's1', outbound: {} }, { id: 's2', protocol: 'vless', port: 443, outbound: {} }], 'the existing s1 is kept as it was; a record without an outbound is not a server');
  assert.deepEqual(r.next.subscriptions.map(s => s.id), ['A', 'B']);
  assert.deepEqual(r.next.settings, { lang: 'fa', socksPort: 20808, theme: 'light' });
  assert.deepEqual(r.next.usage, { s1: { down: 1, up: 1 }, s2: { down: 5, up: 5 } });
});

test('restoring twice is restoring once', () => {
  const b = exportBundle({ store: { servers: [{ id: 's9', protocol: 'trojan', port: 443, outbound: {} }] } });
  const once = importBundle(b, current);
  const twice = importBundle(b, once.next);
  assert.deepEqual(twice.added, { servers: 0, subscriptions: 0, chains: 0, pool: 0, routingProfiles: 0 });
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
  assert.deepEqual(r.added, { servers: 1, subscriptions: 1, chains: 1, pool: 3, routingProfiles: 0 });
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

test('a server refused for its protocol, port or outbound takes its chain memberships and pool targets with it', () => {
  const b = exportBundle({
    store: {
      servers: [
        { id: 'ok', protocol: 'vless', port: 443, outbound: {} },
        { id: 'badproto', protocol: 'nope', port: 443, outbound: {} },
        { id: 'badport', protocol: 'vless', port: 'x', outbound: {} },
        { id: 'noout', protocol: 'vless', port: 443 }
      ],
      chains: [{ id: 'c1', members: ['ok', 'badproto', 'badport', 'noout', 'here'] }],
      pool: [
        { id: 'p1', target: 'badproto', socksPort: 60001 },
        { id: 'p2', target: 'badport', socksPort: 60002 },
        { id: 'p3', target: 'ok', socksPort: 60003 },
        { id: 'p4', target: 'here', socksPort: 60004 }
      ]
    }
  });
  // `here` is refused from the file too, but a server by that id is already on
  // this machine — references to it stay good
  b.servers.push({ id: 'here', protocol: 'nope', outbound: {} });
  const r = importBundle(b, { servers: [{ id: 'here', protocol: 'trojan', port: 443, outbound: {} }] });
  assert.deepEqual(r.next.servers.map(s => s.id), ['here', 'ok']);
  assert.deepEqual(r.next.chains[0].members, ['ok', 'here']);
  assert.deepEqual(r.next.pool.map(p => [p.id, p.target]), [['p1', ''], ['p2', ''], ['p3', 'ok'], ['p4', 'here']]);
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

test('keep: the keys a machine needs as they are stay as they are — and the answer names those the backup wanted changed', () => {
  // A desktop backup restored on a router carried tunMode:false, the system
  // proxy, autoConnect:false, lanBlockQuic:false… (field report D5 / fix 9):
  // the router keeps its own values for exactly the keys it is handed.
  const here = Object.assign({}, current, { settings: { lang: 'fa', autoConnect: true, lanBlockQuic: true, killSwitch: false, tunMode: true } });
  const b = exportBundle({ store: { settings: { lang: 'en', routingMode: 'bypass-ir', autoConnect: false, lanBlockQuic: false, killSwitch: true, tunMode: true, systemProxy: true } } });
  const keep = ['tunMode', 'autoConnect', 'lanBlockQuic', 'killSwitch', 'systemProxy', 'leakGuard'];
  const r = importBundle(b, here, { keep });
  assert.equal(r.next.settings.lang, 'en', 'everything else is restored');
  assert.equal(r.next.settings.routingMode, 'bypass-ir');
  assert.equal(r.next.settings.autoConnect, true);
  assert.equal(r.next.settings.lanBlockQuic, true);
  assert.equal(r.next.settings.killSwitch, false);
  assert.equal(r.next.settings.tunMode, true);
  assert.equal('systemProxy' in r.next.settings, false, 'a kept key this machine never had is not invented either');
  assert.deepEqual(r.kept, ['autoConnect', 'lanBlockQuic', 'killSwitch', 'systemProxy'], 'only those the backup carried with another value — tunMode was the same');
  // without `keep`, the old overlay — the desktop restores everything
  const all = importBundle(b, here);
  assert.equal(all.next.settings.autoConnect, false);
  assert.deepEqual(all.kept, []);
});

test('flavor: a backup says where it was made when asked to (the router), and only then', () => {
  // The router's restore keeps its own settings only from a backup made
  // elsewhere — its own backup, restored after a reset, must bring them back.
  assert.equal(exportBundle({ store: current, flavor: 'openwrt' }).flavor, 'openwrt');
  assert.equal('flavor' in exportBundle({ store: current }), false, 'a desktop backup is as it always was');
  assert.equal('flavor' in exportBundle({ store: current, flavor: null }), false);
});

/* ---------------- routing profiles (docs/superpowers/specs/2026-10-09-routing-profiles-design.md) ---------------- */

const RP_DEFAULT = { id: 'rp-default', name: 'Advanced routing', rules: [{ type: 'domain', value: 'a.com', target: 's1' }], def: 's1', defVia: 'inherit', useMode: false, base: null };
const RP_WORK = { id: 'rp-work', name: 'Work', rules: [{ type: 'ip', value: '10.0.0.0/8', target: 'chain:c1', via: 's1' }], def: 'direct', defVia: 'inherit', useMode: true, base: 's1' };

test('routing profiles travel in the backup and merge by id: what is here is kept, the new are added, the settings mirror rp-default as kept', () => {
  const here = Object.assign({}, current, {
    routingProfiles: [RP_DEFAULT],
    settings: { lang: 'fa', routeRules: RP_DEFAULT.rules, routeDefault: 's1', advancedUseMode: false }
  });
  const b = exportBundle({ store: here });
  assert.deepEqual(b.routingProfiles, [RP_DEFAULT], 'exported');
  assert.equal('routingProfiles' in exportBundle({ store: current }), false, 'a store without them exports as before');
  const theirs = exportBundle({ store: {
    routingProfiles: [Object.assign({}, RP_DEFAULT, { def: 'direct', rules: [] }), RP_WORK],
    settings: { routeRules: [], routeDefault: 'direct', theme: 'light' }
  } });
  const r = importBundle(theirs, here);
  assert.deepEqual(r.next.routingProfiles, [RP_DEFAULT, RP_WORK], 'rp-default here kept, Work added');
  assert.equal(r.added.routingProfiles, 1);
  assert.deepEqual([r.next.settings.routeRules, r.next.settings.routeDefault], [RP_DEFAULT.rules, 's1'], 'the settings follow the kept rp-default');
  assert.equal(r.next.settings.theme, 'light', 'the rest of the settings restored');
  assert.deepEqual(importBundle(theirs, r.next).next.routingProfiles, r.next.routingProfiles, 'restoring twice is restoring once');
});

test('a backup made before routing profiles: its advanced routing (the settings) becomes rp-default’s, as a restore always did', () => {
  const here = Object.assign({}, current, { routingProfiles: [RP_DEFAULT, RP_WORK], settings: { routeRules: RP_DEFAULT.rules, routeDefault: 's1' } });
  const old = exportBundle({ store: { settings: { routeRules: [{ type: 'ip', value: '1.1.1.1', target: 'direct' }], routeDefault: 'direct', advancedUseMode: true } } });
  const r = importBundle(old, here);
  assert.deepEqual(r.next.routingProfiles[0], Object.assign({}, RP_DEFAULT, { rules: [{ type: 'ip', value: '1.1.1.1', target: 'direct' }], def: 'direct', useMode: true }));
  assert.deepEqual(r.next.routingProfiles[1], RP_WORK, 'another profile untouched');
  // a machine that never had profiles, a backup without them: nothing to write
  assert.equal('routingProfiles' in importBundle(old, current).next, false);
});

test('an imported routing profile holds only shapes the app writes: a bad id is dropped, bad targets / vias / bases cleaned', () => {
  const XSS = '"><img src=x onerror=alert(1)>';
  const b = exportBundle({ store: { routingProfiles: [
    { id: XSS, name: 'bad' },
    { id: 'rp-x', name: '<b>name</b>', rules: [{ type: 'ip', value: '1.1.1.1', target: XSS }, { type: 'ip', value: '2.2.2.2', target: 'chain:' + XSS }, { type: 'ip', value: '3.3.3.3', target: 's1', via: XSS }, { type: 'ip', value: '4.4.4.4', target: 'chain:c1', via: 'none' }],
      def: XSS, defVia: 'chain:' + XSS, base: XSS, junk: 1 }
  ] } });
  const r = importBundle(b, { routingProfiles: [] });
  assert.deepEqual(r.next.routingProfiles, [{
    id: 'rp-x', name: '<b>name</b>',
    rules: [{ type: 'ip', value: '3.3.3.3', target: 's1' }, { type: 'ip', value: '4.4.4.4', target: 'chain:c1', via: 'none' }],
    def: '', defVia: 'inherit', useMode: false, base: null
  }]);
});
