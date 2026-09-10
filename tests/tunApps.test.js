'use strict';
/**
 * Tests for the per-app split decision (src/main/tunApps.js).
 *
 * This module is the whole of the policy: the connect path only asks it once and
 * either hands `apps` to the TUN or logs the refusal. Every "no" it can give is
 * a promise being kept — the strict guard's above all — so each one is pinned
 * here, in the order they are checked. Getting the order wrong would report the
 * wrong reason to the user (or, worse, let a refusal through).
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { normalizeAppNames, appsForTun } = require('../src/main/tunApps');

/** A settings object with the per-app keys set; everything else is irrelevant here. */
function S(over) {
  return Object.assign({
    tunAppMode: 'off',
    tunApps: [],
    leakGuard: 'standard'
  }, over || {});
}

const NO_APPS = 'Per-app routing is on but no app is listed — ignored';
const NO_SINGBOX = 'Per-app routing needs the sing-box TUN backend — ignored';
const STRICT = 'Per-app routing is off under the strict guard: the guard promises nothing leaves outside the tunnel, and either mode would send some app around it';

/* --------------------------- normalizeAppNames --------------------------- */

test('normalizeAppNames trims, drops empties and keeps the first of each duplicate', () => {
  assert.deepEqual(
    normalizeAppNames([' chrome.exe ', 'firefox.exe', '', '   ', 'chrome.exe']),
    ['chrome.exe', 'firefox.exe']
  );
});

test('normalizeAppNames keeps the order the user listed', () => {
  // sing-box evaluates process_name as a set, but the settings page shows this
  // list back to the user — reordering it would look like the app ate an entry.
  assert.deepEqual(
    normalizeAppNames(['zoom.exe', 'aria2c.exe', 'brave.exe']),
    ['zoom.exe', 'aria2c.exe', 'brave.exe']
  );
});

test('normalizeAppNames drops entries that are not strings', () => {
  assert.deepEqual(
    normalizeAppNames(['ok.exe', null, undefined, 42, {}, [], true, 'two.exe']),
    ['ok.exe', 'two.exe']
  );
});

test('normalizeAppNames answers [] for anything that is not an array', () => {
  // an old store, a hand-edited settings.json, a half-migrated value
  for (const junk of [undefined, null, '', 'chrome.exe', 7, true, {}, { 0: 'a' }]) {
    assert.deepEqual(normalizeAppNames(junk), [], `${JSON.stringify(junk)} is not a list`);
  }
});

test('normalizeAppNames returns a fresh array, never the caller’s', () => {
  const live = ['chrome.exe'];
  const out = normalizeAppNames(live);
  assert.notEqual(out, live);
  out.push('firefox.exe');
  assert.deepEqual(live, ['chrome.exe']);
});

/* -------------------------- appsForTun: mode off -------------------------- */

test('an unrecognised mode is off, and off is silent', () => {
  // Nothing was asked for, so there is nothing to warn about — a log line here
  // would fire on every single connect of every user who never touched this.
  for (const mode of ['off', undefined, null, '', 'Exclude', 'exclude ', 'all', true, 0, {}]) {
    assert.deepEqual(
      appsForTun(S({ tunAppMode: mode, tunApps: ['chrome.exe'] }), 'sing-box'),
      { apps: null, warn: null },
      `mode ${JSON.stringify(mode)} must be treated as off`
    );
  }
});

test('settings that never heard of these keys are simply off', () => {
  // upgrading from a build before this feature: the store has neither key
  assert.deepEqual(appsForTun({ leakGuard: 'standard' }, 'sing-box'), { apps: null, warn: null });
  assert.deepEqual(appsForTun({}, 'sing-box'), { apps: null, warn: null });
  assert.deepEqual(appsForTun(null, 'sing-box'), { apps: null, warn: null });
  assert.deepEqual(appsForTun(undefined, undefined), { apps: null, warn: null });
});

/* ------------------------ appsForTun: the refusals ------------------------ */

test('a mode with no usable app names is refused, and says so', () => {
  for (const mode of ['exclude', 'only']) {
    for (const list of [[], ['', '  '], [null, 7], 'chrome.exe', undefined]) {
      assert.deepEqual(
        appsForTun(S({ tunAppMode: mode, tunApps: list }), 'sing-box'),
        { apps: null, warn: NO_APPS },
        `${mode} + ${JSON.stringify(list)}`
      );
    }
  }
});

test('any backend that is not sing-box is refused — tun2socks cannot route by process', () => {
  for (const backend of ['tun2socks', undefined, null, '', 'sing-box ', 'singbox']) {
    assert.deepEqual(
      appsForTun(S({ tunAppMode: 'only', tunApps: ['chrome.exe'] }), backend),
      { apps: null, warn: NO_SINGBOX },
      `backend ${JSON.stringify(backend)}`
    );
  }
});

test('the strict guard refuses BOTH modes, not just exclude', () => {
  // `exclude` sends the listed apps around the tunnel; `only` sends everything
  // else around it. Either way traffic leaves outside the tunnel, which is the
  // one thing the strict guard promises never happens.
  for (const mode of ['exclude', 'only']) {
    assert.deepEqual(
      appsForTun(S({ tunAppMode: mode, tunApps: ['chrome.exe'], leakGuard: 'strict' }), 'sing-box'),
      { apps: null, warn: STRICT },
      mode
    );
  }
});

/* ------------------------- appsForTun: the order ------------------------- */

test('an empty list is reported before the backend and before the guard', () => {
  // The first thing to fix is the empty list; naming the backend or the guard
  // instead would send the user to change the wrong setting.
  assert.deepEqual(
    appsForTun(S({ tunAppMode: 'exclude', tunApps: [], leakGuard: 'strict' }), 'tun2socks'),
    { apps: null, warn: NO_APPS }
  );
});

test('the backend is reported before the guard', () => {
  assert.deepEqual(
    appsForTun(S({ tunAppMode: 'exclude', tunApps: ['chrome.exe'], leakGuard: 'strict' }), 'tun2socks'),
    { apps: null, warn: NO_SINGBOX }
  );
});

/* ------------------------- appsForTun: the yes ------------------------- */

test('sing-box, a non-strict guard and real names: the rule is handed over', () => {
  for (const guard of ['standard', 'off', undefined, null, 'Strict']) {
    assert.deepEqual(
      appsForTun(S({ tunAppMode: 'exclude', tunApps: [' chrome.exe ', 'chrome.exe', ''], leakGuard: guard }), 'sing-box'),
      { apps: { mode: 'exclude', names: ['chrome.exe'] }, warn: null },
      `guard ${JSON.stringify(guard)}`
    );
  }
  assert.deepEqual(
    appsForTun(S({ tunAppMode: 'only', tunApps: ['zoom.exe', 'teams.exe'] }), 'sing-box'),
    { apps: { mode: 'only', names: ['zoom.exe', 'teams.exe'] }, warn: null }
  );
});

test('the names handed over are a copy, so the store cannot be mutated through them', () => {
  const settings = S({ tunAppMode: 'only', tunApps: ['zoom.exe'] });
  const { apps } = appsForTun(settings, 'sing-box');
  assert.notEqual(apps.names, settings.tunApps);
  apps.names.push('evil.exe');
  assert.deepEqual(settings.tunApps, ['zoom.exe']);
});

/* ------------------------------ never throws ------------------------------ */

test('garbage in never throws — a bad store must not break the connect', () => {
  const junk = [
    [7, 'sing-box'], ['nonsense', 'sing-box'], [true, 'sing-box'],
    [{ tunAppMode: 'only', tunApps: { length: 2 } }, 'sing-box'],
    [{ tunAppMode: 'exclude', tunApps: ['a.exe'], leakGuard: {} }, 'sing-box'],
    [{ tunAppMode: 'exclude', tunApps: ['a.exe'] }, { id: 'sing-box' }]
  ];
  for (const [settings, backend] of junk) {
    const res = appsForTun(settings, backend);
    assert.equal(typeof res, 'object');
    assert.ok('apps' in res && 'warn' in res, JSON.stringify(settings));
  }
});
