'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { migrateSettings } = require('../src/main/settingsMigrate');

test('a stored `dns` list becomes dnsRemote, public IPs upgraded to DoH', () => {
  const { settings, changed } = migrateSettings({ dns: ['1.1.1.1', '8.8.8.8'], socksPort: 1080 });
  assert.equal(changed, true);
  assert.equal('dns' in settings, false);
  assert.deepEqual(settings.dnsRemote, ['https://1.1.1.1/dns-query', 'https://8.8.8.8/dns-query']);
  assert.equal(settings.socksPort, 1080, 'other keys untouched');
});

test('an unknown resolver stays as plain UDP', () => {
  const { settings } = migrateSettings({ dns: ['10.0.0.53', '9.9.9.9'] });
  assert.deepEqual(settings.dnsRemote, ['10.0.0.53', 'https://9.9.9.9/dns-query']);
});

test('a stored Iranian preset moves to dnsDirect, and the remote list gets the default', () => {
  const { settings } = migrateSettings({ dns: ['178.22.122.100', '185.51.200.2'] });
  assert.deepEqual(settings.dnsDirect, ['178.22.122.100', '185.51.200.2']);
  assert.deepEqual(settings.dnsRemote, ['https://1.1.1.1/dns-query', 'https://8.8.8.8/dns-query']);
});

test('a mixed list splits by role', () => {
  const { settings } = migrateSettings({ dns: ['78.157.42.100', '8.8.8.8'] });
  assert.deepEqual(settings.dnsDirect, ['78.157.42.100']);
  assert.deepEqual(settings.dnsRemote, ['https://8.8.8.8/dns-query']);
});

test('already migrated: nothing changes, same object back', () => {
  const input = { dnsRemote: ['https://1.1.1.1/dns-query'], dnsDirect: [], portsMoved: true };
  const r = migrateSettings(input);
  assert.equal(r.changed, false);
  assert.equal(r.settings, input);
});

test('dns present alongside dnsRemote: dns is dropped, dnsRemote wins', () => {
  const { settings, changed } = migrateSettings({ dns: ['8.8.8.8'], dnsRemote: ['https://9.9.9.9/dns-query'] });
  assert.equal(changed, true);
  assert.deepEqual(settings.dnsRemote, ['https://9.9.9.9/dns-query']);
  assert.equal('dns' in settings, false);
});

test('odd shapes never throw', () => {
  for (const raw of [null, undefined, {}, { dns: null }, { dns: 'x' }, { dns: [null, 3, ''] }]) {
    assert.doesNotThrow(() => migrateSettings(raw), JSON.stringify(raw));
  }
  assert.deepEqual(migrateSettings({ dns: [null, 3, ''] }).settings.dnsRemote, ['https://1.1.1.1/dns-query', 'https://8.8.8.8/dns-query']);
});

/* ------------- the local ports' move to the 30000s (migratePorts) ------------- */

test('ports: a store on the old defaults moves to 30808/30809/30085, once', () => {
  const { settings, changed } = migrateSettings({ socksPort: 10808, httpPort: 10809, apiPort: 10085, routingMode: 'bypass-ir' });
  assert.equal(changed, true);
  assert.equal(settings.socksPort, 30808);
  assert.equal(settings.httpPort, 30809);
  assert.equal(settings.apiPort, 30085);
  assert.equal(settings.portsMoved, true);
  assert.equal(settings.routingMode, 'bypass-ir', 'other keys untouched');
  // the second launch: nothing to do, the same object back
  const again = migrateSettings(settings);
  assert.equal(again.changed, false);
  assert.equal(again.settings, settings);
});

test('ports: a port the user chose stays; each port on its own', () => {
  const { settings } = migrateSettings({ socksPort: 1080, httpPort: 10809, apiPort: 12345 });
  assert.equal(settings.socksPort, 1080);
  assert.equal(settings.httpPort, 30809);
  assert.equal(settings.apiPort, 12345);
});

test('ports: after the move, a user who picks 10808 again keeps it', () => {
  const { settings, changed } = migrateSettings({ socksPort: 10808, httpPort: 10809, apiPort: 10085, portsMoved: true });
  assert.equal(changed, false);
  assert.equal(settings.socksPort, 10808);
});

test('ports: with LAN sharing on, SOCKS and HTTP stay (other devices point at them), the stats port moves', () => {
  const { settings } = migrateSettings({ allowLan: true, socksPort: 10808, httpPort: 10809, apiPort: 10085 });
  assert.equal(settings.socksPort, 10808);
  assert.equal(settings.httpPort, 10809);
  assert.equal(settings.apiPort, 30085);
  assert.equal(settings.portsMoved, true);
});

test('ports: a store without ports only gets the mark; the old dns list and the ports move together', () => {
  assert.deepEqual(migrateSettings({ blockAds: false }).settings, { blockAds: false, portsMoved: true });
  const { settings } = migrateSettings({ dns: ['1.1.1.1'], socksPort: 10808 });
  assert.deepEqual(settings.dnsRemote, ['https://1.1.1.1/dns-query']);
  assert.equal(settings.socksPort, 30808);
});

test('ports: the defaults are the new ports and carry the mark, desktop and router alike', () => {
  const fs = require('fs');
  const path = require('path');
  const { NEW_PORTS } = require('../src/main/settingsMigrate');
  const blockOf = (f, head) => {
    const src = fs.readFileSync(path.join(__dirname, '..', f), 'utf8');
    const at = src.indexOf(head);
    assert.ok(at >= 0, f + ': ' + head);
    return src.slice(at, at + src.slice(at).search(/\r?\n\};/));
  };
  for (const [f, head, mark] of [['src/main/main.js', 'const DEFAULT_SETTINGS = {', true], ['src/server/service.js', 'const DEFAULT_SETTINGS = {', true], ['src/main/configBuilder.js', 'const SETTINGS_DEFAULTS = {', false]]) {
    const block = blockOf(f, head);
    for (const k of Object.keys(NEW_PORTS)) assert.match(block, new RegExp(k + ': ' + NEW_PORTS[k] + ','), f + ' ' + k);
    if (mark) assert.match(block, /portsMoved: true,/, f);
  }
});
