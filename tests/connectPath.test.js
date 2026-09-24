'use strict';
/**
 * The connect path's wiring in the desktop app, and that the headless service
 * says the same thing.
 *
 * main.js requires Electron at load, so — like desktopLifecycle.test.js — it is
 * read as text. The behaviour itself is driven for real through the service in
 * serviceGateway.test.js (pinned entry names, a chain that lost a member, the
 * NIC read again over a live tunnel) and in configBuilder.test.js (the config
 * shape); what is pinned here is that main.js does it at the same points, and
 * that the two mirrors of the shared helpers still say it identically.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

// CRLF on a Windows checkout (core.autocrlf): the patterns below are written with \n.
const R = (...p) => fs.readFileSync(path.join(__dirname, '..', ...p), 'utf8').replace(/\r\n/g, '\n');
const MAIN = R('src', 'main', 'main.js');
const SERVICE = R('src', 'server', 'service.js');

/** The source from `start` up to the first `end` after it. */
function slice(source, label, start, end) {
  const a = source.indexOf(start);
  assert.notEqual(a, -1, `${label}: ${start} is gone`);
  const b = source.indexOf(end, a + start.length);
  assert.notEqual(b, -1, `${label}: nothing ends ${start}`);
  return source.slice(a, b + end.length);
}
/**
 * Both mirrors of one piece, with the indentation of their scopes levelled.
 * `end` defaults to the close of a function: column 0 in main.js, inside
 * createService (two spaces) in service.js.
 */
function both(start, end) {
  const level = (s) => s.split('\n').map((l) => l.trim()).join('\n');
  return [
    ['main.js', level(slice(MAIN, 'main.js', start, end || '\n}\n'))],
    ['service.js', level(slice(SERVICE, 'service.js', start, end || '\n  }\n'))]
  ];
}
// The service answers names through a test seam; main.js through trustedDns itself.
const seam = (s) => s.replace(/\bresolveName\(/g, 'resolveHost(');

const CONNECT = {
  'main.js': slice(MAIN, 'main.js', 'async function connectOnce(serverId, opts = {}) {', '\n  return { ok: true, tunError };\n}'),
  'service.js': slice(SERVICE, 'service.js', 'async function connectOnce(serverId) {', '\n    return { ok: true, tunError };\n  }')
};

/* ---------------------------- A1: pinned entry names ---------------------------- */

test('both mirrors resolve the entry names the same way, line for line', () => {
  const [[, main], [, service]] = both('async function withEntryHostIps(serverId, settings) {');
  assert.equal(main, seam(service));
  assert.match(main, /if \(!settings\.tunMode\) return settings;/, 'only under TUN: without a tunnel nothing loops');
  assert.match(main, /hosts = entryHosts\(buildPlan\(serverId, settings\)\.plan\);/);
  assert.match(main, /const last = lastEntryHostIps\.get\(h\);\nif \(last\) \{\nmap\[h\] = last;/, 'a recovery where nothing resolves keeps the last answer');
  assert.match(main, /map\[h\] = r\.ips\.slice\(\);\nlastEntryHostIps\.set\(h, r\.ips\.slice\(\)\);/, 'every fresh answer is remembered');
  assert.match(main, /return Object\.assign\(\{\}, settings, \{ entryHostIps: map \}\);/);
  assert.match(MAIN, /^const lastEntryHostIps = new Map\(\);/m);
  assert.match(SERVICE, /^ {2}const lastEntryHostIps = new Map\(\);/m);
});

test('the router remembers the WireGuard endpoint of the last connect too, as the desktop does (8e03e89)', () => {
  const [[, main], [, service]] = both('async function withWgEndpointIps(serverId, settings) {');
  assert.equal(main, seam(service));
  assert.match(SERVICE, /^ {2}const lastWgEndpointIps = new Map\(\);/m);
});

test('the connect resolves both kinds of name BEFORE the tunnel and the guard, and hands every pinned address to the bypass', () => {
  for (const [label, body] of Object.entries(CONNECT)) {
    const resolve = body.indexOf('await Promise.all([withWgEndpointIps(serverId, settings), withEntryHostIps(serverId, settings)]);');
    assert.notEqual(resolve, -1, `${label}: the two lookups are not made side by side any more`);
    for (const later of ['tun = makeTun(settings)', 'buildActive(serverId, settings)', 'myTun.start(', 'leakGuard.engage(']) {
      const at = body.indexOf(later);
      assert.notEqual(at, -1, `${label}: ${later} is gone`);
      assert.ok(resolve < at, `${label}: ${later} comes before the names are resolved`);
    }
    assert.match(body, /settings = Object\.assign\(\{\}, settings, \{ wgEndpointIps: wgSet\.wgEndpointIps, entryHostIps: entrySet\.entryHostIps \}\);/);
    assert.match(body, /const pinnedIps = \[\.\.\.Object\.values\(settings\.wgEndpointIps \|\| \{\}\), \.\.\.Object\.values\(settings\.entryHostIps \|\| \{\}\)\.flat\(\)\];/);
    assert.match(body, /await myTun\.start\(settings\.socksPort, \[\.\.\.entryAddrs, \.\.\.resolverBypassIpsOf\(config\), \.\.\.pinnedIps\],/,
      `${label}: the tunnel must keep every pinned address off itself`);
    assert.match(body, /excludes: await tunPlatform\.resolveServerIps\(\[\.\.\.entryAddrs, \.\.\.pinnedIps\], \{ ipv6: true \}\)/,
      `${label}: a held rebuild's firewall holes must cover the addresses the new core will dial`);
    assert.doesNotMatch(body, /wgEndpoints/, `${label}: the WireGuard endpoints travel inside pinnedIps now`);
  }
});

test('a process-route reload keeps the addresses the live tunnel was built for', () => {
  for (const [label, source] of [['main.js', MAIN], ['service.js', SERVICE]]) {
    const body = slice(source, label, 'async function rebuildActiveConfig() {', 'buildActive(serverId, settings);');
    assert.match(body, /if \(livePins\) settings = Object\.assign\(\{\}, settings, livePins\);/, label);
    assert.match(CONNECT[label], /livePins = \{ wgEndpointIps: settings\.wgEndpointIps, entryHostIps: settings\.entryHostIps \};/, label);
  }
  assert.match(MAIN, /^let livePins = null;$/m);
  assert.match(SERVICE, /^ {2}let livePins = null;$/m);
});

/* ------------------------ A2: a chain that lost a member ------------------------ */

test('both mirrors refuse a chain that lost a member, with the same words, wherever the plan uses it', () => {
  const [[, main], [, service]] = both('const legacyIds = store.get(\'chain\', []) || [];', 'let plan, label;');
  assert.equal(main, service);
  assert.match(main, /The chain “\$\{name\}” lost a server/);
  assert.match(main, /زنجیرهٔ «\$\{name\}» یکی از سرورهایش را از دست داده/, 'bilingual, like every connect error');
  for (const [label, source] of [['main.js', MAIN], ['service.js', SERVICE]]) {
    const plan = slice(source, label, 'function buildPlan(serverId, settings) {', 'return { plan, label, entryAddrs };');
    for (const call of [
      'for (const e of enabled) refuseBroken(e.target);',                   // a pool entry
      'for (const tg of targets) { refuseBroken(tg); addEntryForTarget(tg); }', // every advanced rule and the default
      "refuseBroken('chain:' + serverId);",                                  // a chain connected to directly
      "refuseBroken('chain');"                                               // the legacy chain
    ]) assert.ok(plan.includes(call), `${label}: buildPlan no longer calls ${call}`);
    // the refusal comes before the "at least 2 servers" check, which it would otherwise hide
    assert.ok(plan.indexOf("refuseBroken('chain:' + serverId);") < plan.indexOf('needs at least 2 servers'), label);
  }
});

/* -------------------- F1: a held guard does not outlive the tunnel -------------------- */

test('a connect that builds no tunnel gives back a guard held for the last one — before the lookups and the core', () => {
  // TUN → proxy through a settings apply (reapplyConnection holds the guard
  // across the rebuild), or a connect after the "reconnect given up" banner
  // with TUN off: nothing in a proxy connect engaged or released the guard, so
  // the whole proxy session ran with every adapter on a resolver that answers
  // nothing. A tunnel still up (a server switch keeps it) keeps its guard.
  for (const [label, body] of Object.entries(CONNECT)) {
    const release = body.indexOf('if (!settings.tunMode && !(tun && tun.active)) {\n');
    assert.notEqual(release, -1, `${label}: a connect without a tunnel no longer looks for a held guard`);
    assert.match(body.slice(release), /^if \(!settings\.tunMode && !\(tun && tun\.active\)\) \{\n\s*const released = await releaseStrandedGuard\(leakGuard\);\n\s*if \(stale\(\)\) return abandoned;/,
      `${label}: given back — and a disconnect that landed meanwhile still wins`);
    assert.ok(body.indexOf('let settings = await effectiveSettings();') < release, `${label}: decided on the settings of THIS connect`);
    for (const later of ['await ensureCertPins(serverId, settings);', 'withEntryHostIps(serverId, settings)', 'await xray.start(config, runEngine);']) {
      const at = body.indexOf(later);
      assert.notEqual(at, -1, `${label}: ${later} is gone`);
      assert.ok(release < at, `${label}: ${later} runs before the resolvers are given back`);
    }
  }
  assert.match(MAIN, /^const \{ stopTrackedTunnels, releaseGuardChecked, releaseStrandedGuard \} = require\('\.\/tunnelCleanup'\);$/m);
  assert.match(SERVICE, /^const \{ stopTrackedTunnels, releaseGuardChecked, releaseStrandedGuard \} = require\('\.\.\/main\/tunnelCleanup'\);$/m);
});

test('a TUN connect whose tunnel is not up at its end gives back the guard its rebuild held — it reports "proxy only", no banner', () => {
  // A server switch (or a rebuild) under a live tunnel holds the guard and
  // stops the tunnel; a start that then fails (or a backend that is missing)
  // skips the engage and reports connected with a tunError: the adapters sat
  // on 127.0.0.2/::1 with nothing behind them, and no banner offered them back.
  for (const [label, body] of Object.entries(CONNECT)) {
    const engage = body.indexOf('leakGuard.engage(');
    const release = body.indexOf('if (!myTun.active && !stale()) {\n');
    const gate = body.indexOf('if (stale()) {\n', engage);
    assert.notEqual(release, -1, `${label}: a tunnel that did not come up keeps the guard its rebuild held`);
    assert.ok(engage < release && release < gate, `${label}: after the engage it did not reach, before the overtaken-connect gate`);
    assert.match(body.slice(release), /^if \(!myTun\.active && !stale\(\)\) \{\n\s*const released = await releaseStrandedGuard\(leakGuard\);/, label);
    // inside the TUN branch: proxy mode's own UDP block is the else of that branch and stays
    assert.ok(release < body.indexOf('} else if (settings.blockUdpInProxyMode) {'), label);
  }
});

/* ------------------------------ A3: the live NIC ------------------------------ */

test('every connect reads the NIC again — a live tunnel keeps its old name only when the read names nothing usable', () => {
  for (const [label, body] of Object.entries(CONNECT)) {
    assert.doesNotMatch(body, /let name = \(tun\.active && liveDirectInterface\) \|\| null;/, `${label}: a live tunnel skips the read again`);
    assert.match(body, /if \(settings\.tunMode\) \{\n\s*const phys = await tun\.physicalInterface\(\)\.catch\(\(\) => null\);\n\s*if \(stale\(\)\) return abandoned;\n\s*const name = \(phys && phys\.name && !isOwnTunInterface\(phys\.name\)\) \? phys\.name : \(\(tun\.active && liveDirectInterface\) \|\| null\);/,
      `${label}: the read is unconditional, the live name only its fallback`);
  }
});
