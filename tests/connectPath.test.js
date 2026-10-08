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
  'service.js': slice(SERVICE, 'service.js', 'async function connectOnce(serverId, opts = {}) {', '\n    return { ok: true, tunError };\n  }')
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
    // the router keeps the in-country resolvers IN its whole-LAN tunnel (field
    // report D3, driven in routerFieldFixes.test.js); everywhere else they are a hole
    if (label === 'main.js') {
      // (and, under the strict guard only, the resolver an ECH config is fetched from)
      assert.match(body, /const echHoles = settings\.leakGuard === 'strict' \? echResolverIpsOf\(config\) : \[\];\n\s*await myTun\.start\(settings\.socksPort, \[\.\.\.entryAddrs, \.\.\.resolverBypassIpsOf\(config\), \.\.\.echHoles, \.\.\.pinnedIps\],/,
        `${label}: the tunnel must keep every pinned address off itself`);
    } else {
      assert.match(body, /const resolverHoles = OPENWRT \? \[\] : \[\.\.\.resolverBypassIpsOf\(config\), \.\.\.\(settings\.leakGuard === 'strict' \? echResolverIpsOf\(config\) : \[\]\)\];\n\s*await myTun\.start\(settings\.socksPort, \[\.\.\.entryAddrs, \.\.\.resolverHoles, \.\.\.pinnedIps\],/,
        `${label}: the tunnel must keep every pinned address off itself — and, off a router, the direct resolvers`);
    }
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
      'for (const tg of [...targets, ...vias]) refuseBroken(tg);',           // every advanced rule, the default, every base (routing profiles)
      'for (const tg of entries) addEntryForTarget(tg);',                    // …the bypass cut for a base, never a target behind it
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
    for (const later of ['await ensureCertPins(serverId, settings);', 'withEntryHostIps(serverId, settings)', 'await xray.start(config, runEngine)']) {
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
  // …but not inside a recovery that will retry that tunnel: there the hold
  // stays until it comes back or the give-up, whose banner offers the resolvers
  // back (guardHeld). A retry is for a tunnel that could have worked — the same
  // question runRecovery's tunRetryable asks.
  const IF = 'if (!myTun.active && !stale() && !(opts.recovery && myTun.isAvailable() && myTun.isElevated())) {\n';
  for (const [label, body] of Object.entries(CONNECT)) {
    const engage = body.indexOf('leakGuard.engage(');
    const release = body.indexOf(IF);
    const gate = body.indexOf('if (stale()) {\n', engage);
    assert.notEqual(release, -1, `${label}: a tunnel that did not come up keeps the guard its rebuild held — or a retrying recovery gives it up`);
    assert.ok(engage < release && release < gate, `${label}: after the engage it did not reach, before the overtaken-connect gate`);
    assert.match(body.slice(release + IF.length), /^\s*const released = await releaseStrandedGuard\(leakGuard\);/, label);
    // inside the TUN branch: proxy mode's own UDP block is the else of that branch and stays
    assert.ok(release < body.indexOf('} else if (settings.blockUdpInProxyMode) {'), label);
  }
  // the recovery says so, on both of its paths, in both mirrors; a reapply passes it on
  const rec = (src, label, end) => slice(src, label, 'async function runRecovery(reason, attempt) {', end);
  const main = rec(MAIN, 'main.js', '\n}\n');
  assert.match(main, /res = await reapplyConnection\(\{ recovery: true \}\);/);
  assert.match(main, /res = await doConnect\(serverId, \{ holdKillSwitch: held, recovery: true \}\);/);
  assert.match(rec(SERVICE, 'service.js', '\n  }\n'), /res = \(xray && xray\.running\) \? await reapplyConnection\(\{ recovery: true \}\) : await doConnect\(serverId, \{ recovery: true \}\);/);
  assert.match(slice(SERVICE, 'service.js', 'async function reapplyConnection(opts = {}) {', '\n  }\n'), /r = await doConnect\(serverId, \{ recovery: !!opts\.recovery \}\);/);
  assert.match(slice(SERVICE, 'service.js', 'function doConnect(serverId, opts) {', '\n  }\n'), /const p = connectOnce\(serverId, opts\);/);
});

test('an overtaken connect with no receipt releases nothing — without one the release is unconditional and undid the newer connect’s live guard', () => {
  for (const [label, body] of Object.entries(CONNECT)) {
    assert.match(body, /if \(guardToken\) await leakGuard\.release\(\{ token: guardToken \}\)\.catch\(\(\) => \{\}\);/, label);
    assert.doesNotMatch(body, /\n\s*await leakGuard\.release\(\{ token: guardToken \}\)/, `${label}: an unguarded release is left`);
    // an engage that failed after it wrote its state hands its receipt over on the error, so that one is still ours to undo
    assert.match(body, /guardToken = \(e && e\.token\) \|\| guardToken;/, label);
  }
});

test('both mirrors re-apply the DNS guard only over a core that is actually running', () => {
  // re-applying the override every 30 s for a core that died only kept the machine pointed at nothing
  const isActive = (source, label) => {
    const m = /isActive: \(\) => ([^\n]*),\n/.exec(slice(source, label, 'new DnsGuardWatch({', '});'));
    assert.ok(m, `${label}: DnsGuardWatch has no isActive`);
    return m[1];
  };
  assert.equal(isActive(SERVICE, 'service.js'), isActive(MAIN, 'main.js'));
  assert.match(isActive(SERVICE, 'service.js'), /&& !!xray\?\.running$/);
});

/* ------------------- fix 18: a server edit waits for a reconnect ------------------- */

test('both mirrors count an edit of a server the live connection dials as a pending change (the renderer is shared)', () => {
  // driven for real on the router in routerFieldFixes.test.js; the desktop must answer servers:update the same way
  const [[, mainIds], [, serviceIds]] = both('function planServerIds(plan) {');
  assert.equal(mainIds, serviceIds);
  const [[, mainKeys], [, serviceKeys]] = both('function pendingKeys() {');
  assert.equal(mainKeys, serviceKeys);
  // a rename or a Save with nothing changed is no pending edit, in either (review of v1.16.1)
  const [[, mainDial], [, serviceDial]] = both('function dialChanged(a, b) {');
  assert.equal(mainDial, serviceDial);
  assert.match(mainDial, /Object\.assign\(\{\}, s, \{ name: null, _edited: null \}\)/);
  assert.match(mainKeys, /if \(appliedSettings && serverEditPending\) keys\.push\('servers'\);/);
  for (const [label, src] of [['main.js', MAIN], ['service.js', SERVICE]]) {
    assert.match(src, /appliedSettings = snapshotApplied\(getSettings\(\)\);\n\s*liveServerIds = planServerIds\(plan\);\n\s*serverEditPending = false;/, `${label}: the connect records what it dials`);
    const upd = slice(src, label, "'servers:update'", 'return { ok: true, server: servers[idx], servers, live, pendingReconnect: pendingKeys() };');
    assert.match(upd, /const live = !!appliedSettings && liveServerIds\.has\(id\) && dialChanged\(before, servers\[idx\]\);\n\s*if \(live\) serverEditPending = true;/, label);
  }
});

/* --------------- v1.18: ECH asked of an official Xray too old to know it --------------- */

test('ECH on an official Xray older than 25.8.3, no Xray-PattN: both mirrors refuse the connect in the same plain words — the router as a refusal', () => {
  // xrayManager.validateWithFallback answers { echUnsupported, coreVersion }:
  // the old core would pass the config and connect WITHOUT the ECH it asks for
  const EN = '`This server uses ECH, which Xray ${check.coreVersion} does not know (it would connect without it) — update Xray under Settings → Required files`';
  const FA = '`این سرور از ECH استفاده می‌کند و Xray ${check.coreVersion} آن را نمی‌شناسد (بدون ECH وصل می‌شد) — از تنظیمات ← فایل‌های موردنیاز، Xray را به‌روز کن`';
  const LOGGED = "send('log', { line: 'Config rejected by xray: ' + check.error, level: 'error' });";
  for (const [label, body] of Object.entries(CONNECT)) {
    const at = body.indexOf('if (check.echUnsupported) {');
    assert.notEqual(at, -1, `${label}: an official core too old for ECH is not refused`);
    const branch = body.slice(at, body.indexOf('\n', body.indexOf(FA, at)));
    assert.ok(branch.includes(EN), `${label}: the English words`);
    assert.ok(branch.includes(FA), `${label}: the Persian words`);
    assert.match(branch, /settings\.lang === 'en'\s*\n\s*\? `This server uses ECH/, `${label}: in the user’s language`);
    // inside the refused check, after its log line: the core’s error is still in the log
    assert.ok(body.indexOf('if (!check.ok) {') < body.indexOf(LOGGED) && body.indexOf(LOGGED) < at, `${label}: after the log line of a refused check`);
  }
  assert.match(CONNECT['main.js'], /if \(check\.echUnsupported\) \{\n\s*throw new Error\(settings\.lang === 'en'/);
  // the router: a refusal (the boot loop and the recovery do not hammer a core that cannot learn ECH by retrying), before the Xray-PattN one
  const service = CONNECT['service.js'];
  assert.match(service, /if \(check\.echUnsupported\) \{\n\s*throw refusal\(settings\.lang === 'en'/);
  assert.ok(service.indexOf('if (check.echUnsupported) {') < service.indexOf('if (check.pattnNeeded) {'));
});

/* ---------------- v1.18: mux, decided per server by a test (spec §4) ---------------- */
// Driven for real through the service in serviceMux.test.js (the probe before
// the core, the store's memory, the drop that marks for a re-test, the
// recovery that never tests); the decision itself in mux.test.js. Pinned here:
// main.js does it at the same points, in the same words.

test('both mirrors decide mux after the names are resolved and before the config is built — a recovery’s rebuild never tests; the ids go to buildConfig, the live connection keeps them', () => {
  const DECIDE = 'const mux = await muxFor(serverId, settings, !!opts.recovery);';
  for (const [label, body] of Object.entries(CONNECT)) {
    const decide = body.indexOf(DECIDE);
    assert.notEqual(decide, -1, `${label}: the connect no longer decides mux, or no longer tells it a recovery's rebuild`);
    assert.ok(body.indexOf('await Promise.all([withWgEndpointIps(serverId, settings), withEntryHostIps(serverId, settings)]);') < decide, `${label}: the probe dials the names this connect resolved`);
    assert.ok(decide < body.indexOf('buildActive(serverId, settings)'), `${label}: before the live config is built`);
    assert.ok(decide < body.indexOf('await xray.start(config, runEngine)'), `${label}: before the live core starts`);
    assert.match(body.slice(decide), /^const mux = await muxFor\(serverId, settings, !!opts\.recovery\);\n\s*if \(stale\(\)\) return abandoned;\n\s*if \(mux\.ids\.length\) settings = Object\.assign\(\{\}, settings, \{ muxServerIds: mux\.ids \}\);/,
      `${label}: a Cancel during the probe still wins, and an empty decision changes no setting (the configs stay byte-identical)`);
    assert.match(body, /serverEditPending = false;\n\s*liveMux = mux\.ids\.length \? mux : null;/, `${label}: the connect records what it muxed`);
  }
  // `opts.recovery` is what every recovery's rebuild passes, in both mirrors (runRecovery → doConnect / reapplyConnection)
  assert.match(MAIN, /res = await doConnect\(serverId, \{ holdKillSwitch: held, recovery: true \}\);/);
  assert.match(MAIN, /r = await doConnect\(serverId, \{ holdKillSwitch: armed, recovery: !!opts\.recovery \}\);/);
  assert.match(SERVICE, /res = \(xray && xray\.running\) \? await reapplyConnection\(\{ recovery: true \}\) : await doConnect\(serverId, \{ recovery: true \}\);/);
  assert.match(MAIN, /^let liveMux = null;$/m);
  assert.match(SERVICE, /^ {2}let liveMux = null;$/m);
});

test('both mirrors: muxFor is one function — but for the router, which runs a sing-box config on Xray and tests one server at a time, and its test seam', () => {
  const [[, main], [, service]] = both('async function muxFor(serverId, settings, recovery) {');
  const routerOnly = "if (OPENWRT && engineFormat(engine) === 'sing-box') engine = xray.resolveEngine('xray', { quiet: true }).id;   // as buildActive runs it\n";
  const oneAtATime = 'parallel: MUX_PARALLEL,\n';
  assert.ok(service.includes(routerOnly), 'the router muxes what buildActive moves to Xray');
  assert.ok(service.includes(oneAtATime), 'the router hands its own number of probes at once');
  assert.equal(main, service.replace(routerOnly, '').replace(oneAtATime, '').replace(/\bmuxProbe\(/g, 'probeMux('));
  assert.match(SERVICE, /^ {2}const MUX_PARALLEL = OPENWRT \? 1 : PROBE_PARALLEL;$/m);
  assert.match(main, /now: Date\.now\(\), recovery: !!recovery,/, 'a recovery’s rebuild is said to decideMux');
  assert.match(main, /const mode = muxMode\(settings\.mux\);\nif \(mode === 'off'\) return none;/, 'off: not a probe, not a store read');
  assert.match(main, /if \(engineFormat\(engine\) === 'sing-box'\) return none;/, 'the sing-box engine never gets mux');
  assert.match(main, /const servers = muxCandidates\(plan, rawServerOf\(plan, settings, RAW_OPTS\)\);/, 'a chain’s hops are never asked about, nor a JSON server that runs raw');
  assert.match(main, /buildTestConfig: \(target, port\) => buildTestConfig\(target, port, \{ entryHostIps: settings\.entryHostIps, ipv6: settings\.ipv6 \}\),/);
  assert.match(main, /startTest: \(config\) => xray\.startTest\(config, testEngineFor\(engine\)\),/, 'on the core the connect runs');
  assert.match(main, /if \(learnt\.length\) store\.set\('muxProbes', rememberVerdicts\(store\.get\('muxProbes', \{\}\), learnt, Date\.now\(\)\)\);/);
  assert.match(main, /log: \(line, level\) => send\('log', \{ line, level \}\)/, 'one line per decision, into the log');
  assert.match(SERVICE, /^ {2}const muxProbe = deps\.probeMux \|\| probeMux;$/m);
});

test('both mirrors: a drop marks what the live connection muxed for a re-test; a reload keeps it; a disconnect lets it go', () => {
  const [[, mainMark], [, serviceMark]] = both('function recheckLiveMux() {');
  assert.equal(mainMark, serviceMark);
  // kept as ok, and no write when everything is marked already (mux.test.js, serviceMux.test.js)
  assert.match(mainMark, /const next = markRecheck\(cache, liveMux\.fps\);\nliveMux = null;\nif \(next !== cache\) store\.set\('muxProbes', next\);/);
  // the drop: main.js's onConnectionDrop, the service's recoverFromDrop — past the "not a drop" gates, before any rebuild is decided
  const mainDrop = slice(MAIN, 'main.js', 'async function onConnectionDrop(reason) {', 'updateOverlay(\'off\');');
  assert.match(mainDrop, /return;\n\s*\/\/ what the dropped connection muxed: kept for the rebuild, re-tested by the next connect the user or the boot makes\n\s*recheckLiveMux\(\);\n\s*updateOverlay\('off'\);$/);
  const serviceDrop = slice(SERVICE, 'service.js', 'function recoverFromDrop(reason, seq = null) {', 'if (recoverTimer) return;');
  assert.ok(serviceDrop.indexOf('if (reported()) return;') < serviceDrop.indexOf('recheckLiveMux();'), 'a death its own connect reported is no drop of a live connection');
  assert.ok(serviceDrop.indexOf("if (!store.get('activeServerId', null)) return;") < serviceDrop.indexOf('recheckLiveMux();'));
  assert.ok(serviceDrop.indexOf('recheckLiveMux();') < serviceDrop.indexOf('autoReconnectOnNetworkChange'), 'marked whether or not anything rebuilds it');
  for (const [label, source] of [['main.js', MAIN], ['service.js', SERVICE]]) {
    const reload = slice(source, label, 'async function rebuildActiveConfig() {', 'buildActive(serverId, settings);');
    assert.match(reload, /if \(liveMux\) settings = Object\.assign\(\{\}, settings, \{ muxServerIds: liveMux\.ids \}\);/, `${label}: a process-route reload keeps the live connection's mux`);
    const off = slice(source, label, 'async function doDisconnect() {', 'cleanupFailed = false;');
    assert.match(off, /liveDirectInterface = null;\n\s*liveMux = null;/, label);
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

/* ------------------- routing profiles (docs/superpowers/specs/2026-10-09-routing-profiles-design.md) ------------------- */
// Driven for real on the router in routingProfilesService.test.js; main.js
// must plan, migrate, answer and mirror the same way.

test('both mirrors plan a routing profile the same way, line for line: either selection form, its own rules / default / via / base / useMode, every base refused when broken, the bypass cut for a base', () => {
  const [[, main], [, service]] = both('} else if (isAdvancedSelection(serverId)) {', '} else if (chainById[serverId]) {');
  assert.equal(main, service);
  assert.match(main, /const pid = profileIdOf\(serverId, profiles\);/);
  assert.match(main, /This routing profile no longer exists/);
  assert.match(main, /این پروفایلِ روتینگ دیگر وجود ندارد/, 'bilingual, like every connect error');
  assert.match(main, /const rules = resolveProcessRules\(Array\.isArray\(profile\.rules\) \? profile\.rules : \[\], settings\.procIps\);/);
  assert.match(main, /plan = \{ mode: 'advanced', profileId: profile\.id, serversById, chainsById, chain: legacyChain, rules, def, defVia: profile\.defVia, base: profile\.base, useMode: profile\.useMode \};/);
  for (const name of ['getRoutingProfiles() {', 'setRoutingProfiles(list) {', 'procRules(settings, serverId) {', 'activeProcNames(settings, serverId) {']) {
    const [[, m], [, s]] = both('function ' + name);
    assert.equal(m, s, name);
  }
  for (const [label, source] of [['main.js', MAIN], ['service.js', SERVICE]]) {
    // the migration at start, beside the other store migrations
    assert.match(source, /migrateSettingsStore\(\);\n[\s\S]{0,1200}getRoutingProfiles\(\);   \/\/ today's advanced routing becomes profile rp-default, once/, label);
    // process rules: the connect's own profile's, resolved per connect and per reload
    assert.equal((source.match(/let settings = await effectiveSettings\(serverId\);/g) || []).length, 2, `${label}: the connect and the process-route reload`);
    assert.match(source, /for \(const n of names\) procIps\[n\] = ipsByName\[n\] \|\| \(cache\[n\] && cache\[n\]\.ips\) \|\| \[\];\n\s*return Object\.assign\(\{\}, s, \{ procIps \}\);/, label);
    // the geo warning reads the plan's rules, not the settings'
    assert.match(source, /plan\.mode === 'advanced' &&\s*\(\(plan\.rules \|\| \[\]\)\.some\(r => r && \/\^\(geoip\|geosite\):\/i/, label);
    // the reconnect state: the profile and the chains the live connection was built from
    assert.match(source, /liveMux = mux\.ids\.length \? mux : null;\n\s*liveRouting = liveRoutingOf\(\{ serverId, plan, profiles: getRoutingProfiles\(\), chains: getChains\(\) \}\);/, label);
    // the old settings path mirrors into rp-default
    assert.match(source, /if \(\['routeRules', 'routeDefault', 'advancedUseMode'\]\.some\(k => k in partial\)\) \{\n\s*const profiles = getRoutingProfiles\(\);\n\s*const synced = mirrorFromSettings\(profiles, next\);\n\s*if \(synced !== profiles\) store\.set\('routingProfiles', synced\);/, label);
    // the backup carries and restores them
    assert.equal((source.match(/routingProfiles: getRoutingProfiles\(\), settings: getSettings\(\)/g) || []).length, 2, `${label}: export and import`);
    assert.match(source, /pool: r\.next\.pool, routingProfiles: r\.next\.routingProfiles, settings: r\.next\.settings \}\);/, label);
  }
  assert.match(MAIN, /ipcMain\.handle\('routing:profiles', \(\) => \(\{ profiles: getRoutingProfiles\(\) \}\)\);/);
  assert.match(MAIN, /ipcMain\.handle\('routing:setProfiles', \(e, profiles\) => setRoutingProfiles\(profiles\)\);/);
  assert.match(SERVICE, /'routing:profiles': \(\) => \(\{ profiles: getRoutingProfiles\(\) \}\),/);
  assert.match(SERVICE, /'routing:setProfiles': \(profiles\) => setRoutingProfiles\(profiles\),/);
  assert.match(MAIN, /^let liveRouting = null;$/m);
  assert.match(SERVICE, /^ {2}let liveRouting = null;$/m);
  // Windows' W4 hint reads the live profile's stored rules
  assert.match(MAIN, /const profile = getRoutingProfiles\(\)\.find\(p => p\.id === plan\.profileId\);\n\s*found\.push\(\.\.\.lanOverlaps\(lans, profile \? profile\.rules : getSettings\(\)\.routeRules,/);
});
