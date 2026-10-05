'use strict';
/**
 * Tests for the "these settings need a reconnect" classification.
 *
 * The whole point of this module is that a setting the running tunnel is NOT
 * using must be reported as pending — under-reporting is what silently leaks
 * traffic under rules the user thinks they replaced.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const {
  RECONNECT_KEYS, pendingReconnectKeys, snapshotApplied, sameValue
} = require('../src/main/settingsMeta');

/** A full settings object, matching DEFAULT_SETTINGS in main.js. */
function baseSettings(over) {
  return Object.assign({
    socksPort: 10808,
    httpPort: 10809,
    allowLan: false,
    routingMode: 'global',
    blockAds: true,
    enableSniffing: true,
    dnsManaged: true,
    dnsRemote: ['https://1.1.1.1/dns-query', 'https://8.8.8.8/dns-query'],
    dnsDirect: ['178.22.122.100', '185.51.200.2'],
    ipv6: false,
    logLevel: 'warning',
    apiPort: 10085,
    systemProxy: true,
    tunMode: false,
    tunBackend: 'sing-box',
    leakGuard: 'standard',
    blockUdpInProxyMode: false,
    tunAppMode: 'off',
    tunApps: [],
    autoUpdateSubs: true,
    autoUpdateInterval: 60,
    customRules: [],
    advancedRouting: false,
    advancedUseMode: false,
    routeRules: [],
    routeDefault: '',
    procRouteWatch: false,
    killSwitch: false,
    theme: 'dark',
    defaultEngine: 'xray',
    mux: 'auto',
    lang: 'fa'
  }, over || {});
}

const applied = () => snapshotApplied(baseSettings());

/* ----------------------------- sameValue ----------------------------- */

test('sameValue: primitives and null/undefined', () => {
  assert.equal(sameValue(1, 1), true);
  assert.equal(sameValue('a', 'a'), true);
  assert.equal(sameValue(false, false), true);
  assert.equal(sameValue(null, undefined), true);   // "unset" either way
  assert.equal(sameValue(0, false), false);
  assert.equal(sameValue('', null), false);
});

test('sameValue: arrays are compared element-wise and order matters', () => {
  assert.equal(sameValue(['a', 'b'], ['a', 'b']), true);
  // routing rules are evaluated top-down, so a reorder IS a behaviour change
  assert.equal(sameValue(['a', 'b'], ['b', 'a']), false);
  assert.equal(sameValue(['a'], ['a', 'b']), false);
  assert.equal(sameValue([], []), true);
});

test('sameValue: nested rule objects', () => {
  const a = [{ type: 'ip', value: '1.1.1.1', target: 'x' }];
  assert.equal(sameValue(a, [{ type: 'ip', value: '1.1.1.1', target: 'x' }]), true);
  assert.equal(sameValue(a, [{ type: 'ip', value: '1.1.1.1', target: 'y' }]), false);
  assert.equal(sameValue(a, [{ type: 'ip', value: '1.1.1.1' }]), false);   // missing key
});

/* ------------------------- pendingReconnectKeys ------------------------- */

test('nothing connected means nothing can be pending', () => {
  assert.deepEqual(pendingReconnectKeys(null, baseSettings({ routingMode: 'direct' })), []);
});

test('unchanged settings report nothing pending', () => {
  assert.deepEqual(pendingReconnectKeys(applied(), baseSettings()), []);
});

test('every reconnect-relevant key is detected when it changes', () => {
  const changes = {
    socksPort: 1080, httpPort: 1081, apiPort: 1085, allowLan: true,
    dnsManaged: false, dnsRemote: ['https://9.9.9.9/dns-query'], dnsDirect: ['78.157.42.100'], ipv6: true, logLevel: 'debug', enableSniffing: false,
    routingMode: 'bypass-ir', blockAds: false,
    customRules: [{ outboundTag: 'direct', domain: ['x.com'] }],
    advancedRouting: true, advancedUseMode: true,
    routeRules: [{ type: 'ip', value: '10.0.0.0/8', target: 'srv' }],
    routeDefault: 'direct', procRouteWatch: true,
    systemProxy: false, tunMode: true,
    tunBackend: 'tun2socks', leakGuard: 'strict', blockUdpInProxyMode: true,
    tunAppMode: 'exclude', tunApps: ['chrome.exe'],
    defaultEngine: 'xray-pattn',
    mux: 'off'
  };
  // the fixture must cover the whole list, or this test silently stops guarding
  assert.deepEqual(Object.keys(changes).sort(), [...RECONNECT_KEYS].sort());

  for (const [key, value] of Object.entries(changes)) {
    const pending = pendingReconnectKeys(applied(), baseSettings({ [key]: value }));
    assert.deepEqual(pending, [key], `changing ${key} should be pending`);
  }
});

test('settings applied live never ask for a reconnect', () => {
  // killSwitch is read from the store when a drop is detected; the subscription
  // timer is re-armed in settings:set; lang/theme are renderer-only.
  for (const [key, value] of Object.entries({
    killSwitch: true, autoUpdateSubs: false, autoUpdateInterval: 5,
    lang: 'en', theme: 'light'
  })) {
    assert.deepEqual(
      pendingReconnectKeys(applied(), baseSettings({ [key]: value })), [],
      `${key} must not require a reconnect`
    );
  }
});

test('several changes at once are all reported, in RECONNECT_KEYS order', () => {
  const pending = pendingReconnectKeys(applied(), baseSettings({
    tunMode: true, routingMode: 'direct', socksPort: 9999
  }));
  assert.deepEqual(pending, ['socksPort', 'routingMode', 'tunMode']);
});

test('a deep change inside routeRules is detected', () => {
  const rules = [{ type: 'ip', value: '10.0.0.0/8', target: 'srv-a' }];
  const start = snapshotApplied(baseSettings({ routeRules: rules }));

  const sameShape = baseSettings({ routeRules: [{ type: 'ip', value: '10.0.0.0/8', target: 'srv-a' }] });
  assert.deepEqual(pendingReconnectKeys(start, sameShape), []);

  const retargeted = baseSettings({ routeRules: [{ type: 'ip', value: '10.0.0.0/8', target: 'srv-b' }] });
  assert.deepEqual(pendingReconnectKeys(start, retargeted), ['routeRules']);
});

test('changing a value back to what is running clears the pending flag', () => {
  const start = applied();
  assert.deepEqual(pendingReconnectKeys(start, baseSettings({ routingMode: 'direct' })), ['routingMode']);
  assert.deepEqual(pendingReconnectKeys(start, baseSettings({ routingMode: 'global' })), []);
});

/* --------------------------- snapshotApplied --------------------------- */

test('snapshotApplied keeps only the reconnect-relevant keys', () => {
  assert.deepEqual(Object.keys(snapshotApplied(baseSettings())).sort(), [...RECONNECT_KEYS].sort());
});

test('snapshotApplied deep-copies, so later mutation cannot hide a change', () => {
  const live = baseSettings({ routeRules: [{ type: 'ip', value: '1.1.1.1', target: 'a' }] });
  const snap = snapshotApplied(live);

  // main.js hands getSettings() straight to the snapshot; the store hands out the
  // same array reference elsewhere, so an in-place edit must not touch the snapshot
  live.routeRules[0].target = 'b';
  live.dnsRemote.push('https://8.8.4.4/dns-query');

  assert.deepEqual(pendingReconnectKeys(snap, live), ['dnsRemote', 'routeRules']);
});

/* ------------------------- mux (v1.18, spec §4) ------------------------- */

test('mux defaults to auto in both processes, and changing it waits for a reconnect like every config-shaping key', () => {
  // the service's table is exported; main.js requires Electron at load, so it is read as text
  const { DEFAULT_SETTINGS } = require('../src/server/service');
  assert.equal(DEFAULT_SETTINGS.mux, 'auto');
  const main = fs.readFileSync(path.join(__dirname, '..', 'src', 'main', 'main.js'), 'utf8').replace(/\r\n/g, '\n');
  const block = main.slice(main.indexOf('const DEFAULT_SETTINGS = {'));
  assert.match(block.slice(0, block.indexOf('\n};')), /^ {2}mux: 'auto'$/m, 'main.js DEFAULT_SETTINGS has the same default');
  assert.ok(RECONNECT_KEYS.includes('mux'));
  for (const to of ['on', 'off']) assert.deepEqual(pendingReconnectKeys(applied(), baseSettings({ mux: to })), ['mux'], `auto → ${to}`);
});

/* ------------------------------ i18n drift ------------------------------ */

test('every reconnect key has a human-readable name in both languages', () => {
  // The apply dialog looks up `set.<key>`; a missing string would show the raw
  // key ("procRouteWatch") to the user.
  const i18n = fs.readFileSync(path.join(__dirname, '..', 'src', 'renderer', 'i18n.js'), 'utf8');
  for (const key of RECONNECT_KEYS) {
    const hits = i18n.split(`'set.${key}':`).length - 1;
    assert.equal(hits, 2, `set.${key} must be defined in both fa and en (found ${hits})`);
  }
});

test('every key pendingKeys() can add beyond the settings has a name in both languages too', () => {
  // 'servers' (an edit of a server the live connection dials, v1.16.1 fix 18)
  // is no setting, so the loop above never saw it — and the apply banner and
  // dialog showed the raw "set.servers" in both languages.
  const i18n = fs.readFileSync(path.join(__dirname, '..', 'src', 'renderer', 'i18n.js'), 'utf8');
  for (const file of ['src/server/service.js', 'src/main/main.js']) {
    const src = fs.readFileSync(path.join(__dirname, '..', file), 'utf8');
    const body = src.slice(src.indexOf('function pendingKeys() {'), src.indexOf('function planServerIds(plan) {'));
    const extra = [...body.matchAll(/keys\.push\('([A-Za-z]+)'\)/g)].map(m => m[1]);
    assert.deepEqual(extra, ['servers'], `${file}: the extra keys pendingKeys() reports`);
    for (const key of extra) {
      const hits = i18n.split(`'set.${key}':`).length - 1;
      assert.equal(hits, 2, `set.${key} must be defined in both fa and en (found ${hits})`);
    }
  }
});
