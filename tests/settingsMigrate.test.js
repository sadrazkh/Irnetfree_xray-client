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
  const input = { dnsRemote: ['https://1.1.1.1/dns-query'], dnsDirect: [] };
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
