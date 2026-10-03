'use strict';
/**
 * v1.16.3 — Windows visibility (windows-android-report §1 L1/L2, §2 W1/W3/W4).
 *
 * One Windows PC leaks DNS and its advanced-routing chain to a corporate
 * WireGuard "does not work properly"; another PC with the same configs is fine.
 * Nothing in this round changes what the app DOES — no generated config, no
 * route, no resolver, no guard action, no step of the connect: it only makes
 * the app SAY, on the PC where it happens, which of the known causes applies.
 * Each message fires only on the condition it names (tests/desktopPin.test.js
 * still pins every generated config). That is NOT "a healthy PC sees nothing
 * new": a WireGuard identity stored twice is in the store, so a PC that works
 * says it too — which is why it is said once per run, with what to do.
 *
 *   L2(c)  the leak guard failed           → a toast and a line under the state
 *   L2     TUN on, the tunnel did not come up (proxy only) → a persistent line + the reason
 *   W1     a WireGuard identity stored twice → warn line every connect + one toast per run
 *   W4     a LAN holding what a routed tunnel needs (its WireGuard DNS, Address,
 *          a narrower AllowedIPs), or a rule as narrow as the LAN → warn line + one
 *          toast per connection; a LAN merely inside a broad /16 or /8 → an info line only
 *   W3     managed DNS off with a corporate resolver → the existing warning, also a toast
 *   L1     the logon task starts another copy → a banner whose button re-registers it,
 *          on screen (a fixed stack over the window's foot — the render check proves it)
 *
 * main.js needs Electron, so — like desktopUx.test.js — its new functions are
 * compiled on their own in a vm against fakes, and the wiring is read as text.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const notices = require('../src/main/connectNotices');
const autostart = require('../src/main/autostart');
const { makeWireguardServer } = require('../src/main/parser');

// CRLF on a Windows checkout (core.autocrlf): the patterns below are written with \n.
const R = (...p) => fs.readFileSync(path.join(__dirname, '..', ...p), 'utf8').replace(/\r\n/g, '\n');
const MAIN = R('src', 'main', 'main.js');
const PRELOAD = R('src', 'preload', 'preload.js');

/** A top-level (async) function of a source file, as source. */
function fnOf(src, name) {
  let start = src.indexOf(`\nfunction ${name}(`);
  if (start === -1) start = src.indexOf(`\nasync function ${name}(`);
  assert.ok(start > -1, `no function ${name}`);
  let depth = 0, j = src.indexOf('{', src.indexOf(')', start));
  for (; j < src.length; j++) {
    if (src[j] === '{') depth++;
    else if (src[j] === '}' && --depth === 0) break;
  }
  return src.slice(start, j + 1);
}
/** The source from `start` up to the first `end` after it. */
function slice(src, start, end) {
  const a = src.indexOf(start);
  assert.notEqual(a, -1, `${start} is gone`);
  const b = src.indexOf(end, a + start.length);
  assert.notEqual(b, -1, `nothing ends ${start}`);
  return src.slice(a, b + end.length);
}
/** A value made in the vm, as a plain value of this realm (deepStrictEqual compares prototypes). */
const plain = (v) => JSON.parse(JSON.stringify(v));
const CONNECT = slice(MAIN, 'async function connectOnce(serverId, opts = {}) {', '\n  return { ok: true, tunError };\n}');

/* ------------------------------ main: the connect's notices (W1 / W4 / W3) ------------------------------ */

const PUB = 'Q29ycG9yYXRlU2VydmVyUHVibGljS2V5MDAwMDAwMDA=';
const KEY = 'cHJpdmF0ZS1rZXktQS1BQUFBQUFBQUFBQUFBQUFBQUE=';
const KEY_B = 'cHJpdmF0ZS1rZXktQi1CQkJCQkJCQkJCQkJCQkJCQkI=';
// the owner's corporate WireGuard: its DNS, its tunnel address, AllowedIPs as wide as the advanced rule
const wg = (id, name, f = {}) => Object.assign(makeWireguardServer(Object.assign({
  name, endpoint: 'vpn.corp.example:51820', publicKey: PUB, privateKey: KEY, address: '10.10.10.42/32',
  dns: '192.168.60.1, tes.systems', allowedIPs: '192.168.0.0/16, 10.0.0.0/8'
}, f)), { id });
const SUBS = [{ id: 'sub0554', name: 'tes-vpn-service.platform.irnetfree.info' }];

function hintsHarness({ servers, subs = SUBS, rules = [], ifaces = {}, platform = 'win32', throwOn = null } = {}) {
  const logs = [];
  const ctx = vm.createContext({
    process: { platform },
    store: { get: (k, d) => {
      if (throwOn === 'store') throw new Error('store gone');
      return k === 'servers' ? servers : (k === 'subscriptions' ? subs : d);
    } },
    os: { networkInterfaces: () => { logs.reads = (logs.reads || 0) + 1; return ifaces; } },
    send: (ch, p) => { if (ch === 'log') logs.push(p); },
    getSettings: () => ({ routeRules: rules }),
    getChains: () => [{ id: 'tes', name: 'Tes Chain', members: ['hop', 'b47f'] }],
    isOwnTunInterface: (n) => n === 'IRNetFree' || n === 'XrayTun',
    TUN_LOCAL_IP: '10.255.0.2',
    TUN_ADDR4: '172.19.0.1/30',
    ...notices
  });
  vm.runInContext([fnOf(MAIN, 'planServerIds'), fnOf(MAIN, 'connectHints')].join('\n'), ctx);
  return { ctx, logs };
}

// The owner's laptop as its store reads (records b47f / fa69 / f132, the rule, the Wi-Fi):
// the chain's cobra.tes.ca added by hand, its twin from a subscription, reza-wire on the
// same tunnel address under another key — and a home LAN inside the broad corporate rule.
const HOP = { id: 'hop', name: '🇬🇧-2', protocol: 'vless', outbound: { protocol: 'vless' } };
const OWNER_RULES = [{ type: 'ip', value: '192.168.0.0/16, 10.0.0.0/8', target: 'chain:tes' }];
const WIFI = { 'Wi-Fi': [{ address: '192.168.1.5', netmask: '255.255.255.0', family: 'IPv4', internal: false, cidr: '192.168.1.5/24' }] };
const OUR_TUN = { IRNetFree: [{ address: '172.19.0.1', netmask: '255.255.255.252', family: 'IPv4', internal: false, cidr: '172.19.0.1/30' }] };
function ownerLaptop() {
  const chainWg = wg('b47f', 'cobra.tes.ca');
  const twin = Object.assign(wg('fa69', 'cobra.tes.ca'), { subId: 'sub0554' });
  const reza = wg('f132', 'reza-wire', { privateKey: KEY_B });
  const plan = { mode: 'advanced', serversById: { hop: HOP, b47f: chainWg }, chainsById: { tes: [HOP, chainWg] }, chain: [], rules: OWNER_RULES, def: 'hop' };
  return { plan, servers: [HOP, chainWg, twin, reza] };
}

test('W1/W4 at connect on the owner’s laptop: the twins are told apart by group, the home LAN in the broad corporate rule is an info line only', () => {
  const { plan, servers } = ownerLaptop();
  const h = hintsHarness({ servers, rules: OWNER_RULES, ifaces: Object.assign({}, WIFI, OUR_TUN) });
  const out = h.ctx.connectHints(plan, { tun: true });
  assert.deepEqual(plain(out), [
    // the twin is in a live subscription and the chain's copy was added by hand: deleting the twin would not last
    { id: 'wgSharedKeySub', name: 'cobra.tes.ca', other: 'cobra.tes.ca', group: 'tes-vpn-service.platform.irnetfree.info', otherInSub: true, byHand: true },
    { id: 'wgSharedAddress', name: 'cobra.tes.ca', other: 'reza-wire', group: { t: 'srv.manual' }, otherInSub: false, byHand: true, address: '10.10.10.42' }
  ], 'no lanInRange for 192.168.1.0/24: nothing Tes Chain needs is in it');
  assert.deepEqual(h.logs.map((l) => l.level), ['warn', 'warn', 'info']);
  assert.match(h.logs[0].line, /^WireGuard cobra\.tes\.ca: the same private key is also stored in another record, “cobra\.tes\.ca” in the group “tes-vpn-service\.platform\.irnetfree\.info” — /);
  assert.match(h.logs[0].line, /keep it, use it in place of this one \(rebuild the chain on it\), delete the copy added by hand/);
  assert.match(h.logs[1].line, /^WireGuard cobra\.tes\.ca: its tunnel address 10\.10\.10\.42 is also stored in another record, “reza-wire” in the group “Added by hand”/);
  assert.match(h.logs[2].line, /^Your local network 192\.168\.1\.0\/24 \(Wi-Fi\) lies inside 192\.168\.0\.0\/16 that advanced routing sends to Tes Chain; none of the addresses Tes Chain is known to need/);
  assert.ok(!JSON.stringify(h.logs).includes(KEY) && !JSON.stringify(out).includes(KEY), 'the private key is never said');
  assert.ok(!JSON.stringify(h.logs).includes(KEY_B) && !JSON.stringify(out).includes(KEY_B));
});

test('W4 at connect: a LAN that holds the corporate WireGuard’s DNS is a warn line AND a notice for the window', () => {
  const chainWg = wg('b47f', 'cobra.tes.ca');
  const plan = { mode: 'advanced', serversById: { hop: HOP, b47f: chainWg }, chainsById: { tes: [HOP, chainWg] }, chain: [], rules: OWNER_RULES, def: 'hop' };
  const h = hintsHarness({
    servers: [HOP, chainWg], rules: OWNER_RULES,
    ifaces: { Ethernet: [{ address: '192.168.60.23', netmask: '255.255.255.0', family: 'IPv4', internal: false, cidr: '192.168.60.23/24' }] }
  });
  assert.deepEqual(plain(h.ctx.connectHints(plan, { tun: true })), [
    { id: 'lanInRange', lan: '192.168.60.0/24', iface: 'Ethernet', range: '192.168.0.0/16', target: 'Tes Chain', address: '192.168.60.1', key: 'DNS' }
  ]);
  assert.deepEqual(h.logs.map((l) => l.level), ['warn']);
  assert.match(h.logs[0].line, /^Your local network 192\.168\.60\.0\/24 \(Ethernet\) overlaps 192\.168\.60\.1 — the DNS of Tes Chain’s WireGuard — .* Move that LAN, VM or host-only network to another subnet$/);
});

test('W1/W4 at connect: a store with one record per identity says nothing to the window; W4 is asked only of advanced routing; nothing in here can fail a connect', () => {
  const chainWg = wg('b47f', 'tes-wg');
  const lanIfaces = WIFI;
  // one record per identity, corporate ranges that do not touch this LAN
  const healthy = hintsHarness({ servers: [chainWg], rules: [{ type: 'ip', value: '192.168.60.0/24', target: 'b47f' }], ifaces: lanIfaces });
  assert.deepEqual(plain(healthy.ctx.connectHints({ mode: 'advanced', serversById: { b47f: chainWg }, rules: [{ type: 'ip', value: '192.168.60.0/24', target: 'b47f' }], def: 'b47f' }, { tun: true })), []);
  assert.equal(healthy.logs.length, 0);
  // the owner's broad rule around this LAN, one record per identity: nothing for the window, one info line
  const broad = hintsHarness({ servers: [HOP, chainWg], rules: OWNER_RULES, ifaces: lanIfaces });
  assert.deepEqual(plain(broad.ctx.connectHints({ mode: 'advanced', serversById: { hop: HOP, b47f: chainWg }, chainsById: { tes: [HOP, chainWg] }, chain: [], rules: OWNER_RULES, def: 'hop' }, { tun: true })), []);
  assert.deepEqual(broad.logs.map((l) => l.level), ['info']);
  // a single config: its stored rules are not in this plan
  const single = hintsHarness({ servers: [chainWg], rules: [{ type: 'ip', value: '192.168.0.0/16', target: 'b47f' }], ifaces: lanIfaces });
  assert.deepEqual(plain(single.ctx.connectHints({ mode: 'single', server: chainWg }, { tun: true })), []);
  // a throw anywhere is swallowed: the connect goes on exactly as before
  const broken = hintsHarness({ servers: [], throwOn: 'store' });
  assert.deepEqual(plain(broken.ctx.connectHints({ mode: 'single', server: chainWg }, { tun: true })), []);
  assert.deepEqual(plain(broken.ctx.connectHints(null)), []);
});

test('W4 is a fact about the tunnel’s routes: with TUN off (the system proxy bypasses private ranges anyway) it is not asked — W1 still is', () => {
  const { plan, servers } = ownerLaptop();
  const lan60 = { Ethernet: [{ address: '192.168.60.23', netmask: '255.255.255.0', family: 'IPv4', internal: false, cidr: '192.168.60.23/24' }] };
  const off = hintsHarness({ servers, rules: OWNER_RULES, ifaces: lan60 });
  assert.deepEqual(plain(off.ctx.connectHints(plan, { tun: false })).map((n) => n.id), ['wgSharedKeySub', 'wgSharedAddress']);
  assert.deepEqual(off.logs.map((l) => l.level), ['warn', 'warn'], 'no W4 line either');
  assert.equal(off.logs.reads || 0, 0, 'this PC’s networks are not even read');
  assert.deepEqual(plain(off.ctx.connectHints(plan)).map((n) => n.id), ['wgSharedKeySub', 'wgSharedAddress'], 'no TUN said: none');
  const on = hintsHarness({ servers, rules: OWNER_RULES, ifaces: lan60 });
  assert.deepEqual(plain(on.ctx.connectHints(plan, { tun: true })).map((n) => n.id), ['wgSharedKeySub', 'wgSharedAddress', 'lanInRange']);
  // which notices need the tunnel: W4's three, nothing else
  assert.deepEqual(['wgSharedKey', 'wgSharedKeySub', 'wgSharedAddress', 'wgSharedAddressSub', 'lanInRange', 'rangeInLan', 'lanInBroadRange', 'corpDnsOff']
    .filter((id) => notices.needsTun({ id })), ['lanInRange', 'rangeInLan', 'lanInBroadRange']);
  assert.equal(notices.needsTun(null), false);
});

test('W3: managed DNS off is said for a WireGuard resolver the plan routes to — not for every record an advanced or pool plan carries', () => {
  const { wgResolverAddresses } = require('../src/main/configBuilder');
  const ctx = vm.createContext({ wgResolverAddresses });
  vm.runInContext([fnOf(MAIN, 'planServerIds'), fnOf(MAIN, 'routedWgResolvers')].join('\n'), ctx);
  const corp = wg('b47f', 'cobra.tes.ca');
  const DNS = wgResolverAddresses({ mode: 'single', server: corp });
  assert.ok(DNS.includes('192.168.60.1'));
  const byId = { hop: HOP, b47f: corp };
  const chains = { tes: [HOP, corp] };
  const routed = (plan) => plain(ctx.routedWgResolvers(plan));
  // advanced: buildPlan hands it EVERY stored server; only the rules' targets and the default count
  assert.deepEqual(routed({ mode: 'advanced', serversById: byId, chainsById: chains, chain: [], rules: [{ type: 'domain', value: 'x.ir', target: 'hop' }], def: 'hop' }), [],
    'a corporate WireGuard no rule routes to: nothing missing from this config');
  assert.deepEqual(routed({ mode: 'advanced', serversById: byId, chainsById: chains, chain: [], rules: OWNER_RULES, def: 'hop' }), DNS, 'a rule to the chain it ends');
  assert.deepEqual(routed({ mode: 'advanced', serversById: byId, chainsById: chains, chain: [], rules: [], def: 'b47f' }), DNS, 'the default');
  // pool: only the enabled entries' targets
  assert.deepEqual(routed({ mode: 'pool', entries: [{ target: 'hop' }], serversById: byId, chainsById: chains, chain: [] }), []);
  assert.deepEqual(routed({ mode: 'pool', entries: [{ target: 'hop' }, { target: 'chain:tes' }], serversById: byId, chainsById: chains, chain: [] }), DNS);
  // a single server and a chain, as before
  assert.deepEqual(routed({ mode: 'single', server: corp }), DNS);
  assert.deepEqual(routed({ mode: 'chain', chain: [HOP, corp] }), DNS);
  assert.deepEqual(routed(null), []);
  // the connect asks it, for the log line and the notice alike
  assert.match(CONNECT, /if \(settings\.dnsManaged === false\) \{\n\s*const corp = routedWgResolvers\(plan\);/);
});

test('the connect asks for the notices on Windows only, after the plan is built and before anything is started, and the connected status carries them', () => {
  // W3: the existing managed-DNS line stays exactly as it was, and on Windows becomes a notice too
  assert.match(CONNECT, /line: `Managed DNS is off, so the resolver of your WireGuard \(\$\{corp\.join\(', '\)\}\) is not in this config and names inside that network will not resolve — turn Settings → DNS → "DNS managed by the app" back on`,\n\s*level: 'warn'\n\s*\}\);\n\s*if \(process\.platform === 'win32'\) notices\.push\(\{ id: 'corpDnsOff', servers: corp\.join\(', '\) \}\);/);
  // W4 only for a connect that asks for the tunnel
  assert.match(CONNECT, /\n {2}if \(process\.platform === 'win32'\) notices\.push\(\.\.\.connectHints\(plan, \{ tun: !!settings\.tunMode \}\)\);\n/);
  const built = CONNECT.indexOf('= buildActive(serverId, settings);');
  const declared = CONNECT.indexOf('const notices = [];');
  const asked = CONNECT.indexOf('notices.push(...connectHints(plan, { tun: !!settings.tunMode }))');
  assert.ok(built > -1 && built < declared && declared < asked, 'after the plan is built');
  for (const later of ["send('status', { state: 'connecting', serverId });", 'xray.validateWithFallback(', 'xray.start(', 'myTun.start(', 'leakGuard.engage(']) {
    const at = CONNECT.indexOf(later);
    assert.ok(at > asked, `${later} must come after the notices are gathered`);
  }
  // …and only while that tunnel is up: a TUN that did not start (proxy only) drops W4 from the status
  assert.match(CONNECT, /tun: tun\.active, tunError, guardError, geoWarn, lan, pendingReconnect: pendingKeys\(\),\n\s*notices: tun\.active \? notices : notices\.filter\(\(n\) => !needsTun\(n\)\)\n\s*\}\);/);
  assert.match(MAIN, /^const \{ [^}]*\bneedsTun\b[^}]* \} = require\('\.\/connectNotices'\);$/m);
  // gathered once, said once: nothing else in the connect reads or changes them
  assert.equal(CONNECT.split('notices').length - 1, 6, 'declared, W3, W1/W4, the status (three times in its one line) — and nowhere else');
});

/* ------------------------------ main: "give my internet back" (guard:release) ------------------------------ */

function guardReleaseHarness({ running = false, active = false, inFlight = 0, lang = 'en', guard = 'ok' } = {}) {
  const calls = [];
  const logs = [];
  const ctx = vm.createContext({
    xray: { running }, tun: { active },
    connectsInFlight: new Set(Array.from({ length: inFlight }, (_, i) => Promise.resolve(i))),
    leakGuard: guard === null ? null : {
      release: async (...args) => { calls.push(['release', ...args]); if (guard === 'throws') throw new Error('Access is denied.'); return { released: true }; }
    },
    send: (ch, p) => { if (ch === 'log') logs.push(p); },
    isEn: () => lang === 'en'
  });
  vm.runInContext([fnOf(MAIN, 'guardInUse'), fnOf(MAIN, 'releaseGuardOnRequest')].join('\n'), ctx);
  return { ctx, calls, logs };
}

test('guard:release gives the adapters their resolvers back after a give-up — and refuses while a tunnel is up or a connect is being built (no leak under a live tunnel)', async () => {
  // the give-up it is for: no core, no tunnel — or the proxy back and only TUN missing
  for (const [running, active] of [[false, false], [true, false], [false, true]]) {
    const h = guardReleaseHarness({ running, active });
    assert.deepEqual(plain(await h.ctx.releaseGuardOnRequest()), { ok: true }, `running ${running}, tun ${active}`);
    assert.deepEqual(h.calls, [['release']], 'the release without a receipt, as before');
  }
  // the core running over a live TUN: the guard is that tunnel's — a release now is every
  // physical adapter back on the ISP's resolvers while the tunnel carries the traffic
  const live = guardReleaseHarness({ running: true, active: true });
  const r = plain(await live.ctx.releaseGuardOnRequest());
  assert.equal(r.ok, false);
  assert.equal(r.refused, 'connected');
  assert.match(r.error, /disconnect/i);
  assert.deepEqual(live.calls, [], 'nothing released');
  assert.deepEqual(live.logs.map((l) => l.level), ['warn']);
  assert.equal(guardReleaseHarness({ running: true, active: true, lang: 'fa' }).ctx.guardInUse(), true);
  const faR = plain(await guardReleaseHarness({ running: true, active: true, lang: 'fa' }).ctx.releaseGuardOnRequest());
  assert.match(faR.error, /قطع/);
  // a connect in flight holds (or is about to take) its guard receipt: not from under it
  const building = guardReleaseHarness({ inFlight: 1 });
  assert.equal(plain(await building.ctx.releaseGuardOnRequest()).refused, 'connected');
  assert.deepEqual(building.calls, []);
  // no guard, or one that fails: said, not thrown
  assert.deepEqual(plain(await guardReleaseHarness({ guard: null }).ctx.releaseGuardOnRequest()), { ok: true });
  assert.deepEqual(plain(await guardReleaseHarness({ guard: 'throws' }).ctx.releaseGuardOnRequest()), { ok: false, error: 'Access is denied.' });
  // the IPC goes through it
  assert.match(MAIN, /ipcMain\.handle\('guard:release', \(\) => releaseGuardOnRequest\(\)\);/);
  assert.doesNotMatch(MAIN, /ipcMain\.handle\('guard:release', async/);
});

/* ------------------------------ main: the logon task (L1) ------------------------------ */

const TASK_XML = (cmd) => `<?xml version="1.0" encoding="UTF-16"?>\r\r\n<Task><Actions Context="Author"><Exec><Command>${cmd}</Command><Arguments>--hidden</Arguments></Exec></Actions></Task>`;
const HERE = 'C:\\Program Files\\IRNetFree\\IRNetFree.exe';

function autostartHarness({ platform = 'win32', packaged = true, xml = null, err = null, setAutostart = null } = {}) {
  const calls = [];
  const logs = [];
  const ctx = vm.createContext({
    process: { platform, env: {} },
    app: { isPackaged: packaged },
    execFile: (cmd, args, opts, cb) => { calls.push([cmd, ...args]); setImmediate(() => cb(err, xml == null ? '' : xml, '')); },
    send: (ch, p) => { if (ch === 'log') logs.push(p); },
    fs: { realpathSync: { native: (p) => { throw new Error('ENOENT ' + p); } } },
    autostartExe: () => HERE,
    setAutostart: setAutostart || (async (on) => { calls.push(['setAutostart', on]); return { ok: true, error: null }; }),
    schtasksQueryXmlArgs: autostart.schtasksQueryXmlArgs,
    taskExeFromXml: autostart.taskExeFromXml,
    autostartStale: autostart.autostartStale,
    Promise, setImmediate
  });
  vm.runInContext(['var autostartChecked = null;', fnOf(MAIN, 'sameFile'), fnOf(MAIN, 'autostartCheck'), fnOf(MAIN, 'autostartRepoint')].join('\n'), ctx);
  return { ctx, calls, logs };
}

test('L1: on a packaged Windows build the logon task is only READ, and a task naming another copy is reported once', async () => {
  const old = 'C:\\Users\\me\\Desktop\\IRNetFree-Portable-1.13.0.exe';
  const h = autostartHarness({ xml: TASK_XML(`"${old}"`) });
  const r = await h.ctx.autostartCheck();
  assert.deepEqual(plain(r), { stale: true, taskExe: old, currentExe: HERE });
  assert.deepEqual(h.calls, [['schtasks', '/Query', '/TN', 'IRNetFree', '/XML']], 'one read, nothing written');
  assert.equal(h.logs.length, 1);
  assert.equal(h.logs[0].level, 'warn');
  assert.match(h.logs[0].line, /The logon task IRNetFree starts C:\\Users\\me\\Desktop\\IRNetFree-Portable-1\.13\.0\.exe, not this copy \(C:\\Program Files\\IRNetFree\\IRNetFree\.exe\)/);
  // a renderer reload asks again: the same answer, no second schtasks, no second line
  await h.ctx.autostartCheck();
  assert.equal(h.calls.length, 1);
  assert.equal(h.logs.length, 1);
});

test('L1: silent where the task is this copy, absent or unreadable — and never asked off Windows or from a dev run', async () => {
  const same = autostartHarness({ xml: TASK_XML(`"${HERE}"`) });
  assert.deepEqual(plain(await same.ctx.autostartCheck()), { stale: false });
  assert.deepEqual(same.logs, []);
  const none = autostartHarness({ err: new Error('ERROR: The system cannot find the file specified.') });
  assert.deepEqual(plain(await none.ctx.autostartCheck()), { stale: false });
  assert.deepEqual(none.logs, []);
  for (const h of [autostartHarness({ platform: 'darwin', xml: TASK_XML('"C:\\old\\IRNetFree.exe"') }),
    autostartHarness({ platform: 'linux', xml: TASK_XML('"C:\\old\\IRNetFree.exe"') }),
    autostartHarness({ packaged: false, xml: TASK_XML('"C:\\old\\IRNetFree.exe"') })]) {
    assert.deepEqual(plain(await h.ctx.autostartCheck()), { stale: false });
    assert.deepEqual(h.calls, [], 'schtasks is not even run');
  }
});

test('L1: the only write is the owner’s click — the existing helper registers THIS copy, and the next check reads again', async () => {
  const old = 'C:\\old\\IRNetFree.exe';
  const h = autostartHarness({ xml: TASK_XML(`"${old}"`) });
  await h.ctx.autostartCheck();
  const r = await h.ctx.autostartRepoint();
  assert.deepEqual(plain(r), { ok: true, error: null });
  assert.deepEqual(h.calls.slice(1), [['setAutostart', true]]);
  assert.match(h.logs.at(-1).line, /^The logon task now starts this copy \(C:\\Program Files\\IRNetFree\\IRNetFree\.exe\)$/);
  await h.ctx.autostartCheck();
  assert.equal(h.calls.filter((c) => c[0] === 'schtasks').length, 2, 'asked again after the change');
  // a refusal from schtasks is said, not thrown
  const refused = autostartHarness({ setAutostart: async () => ({ ok: false, error: 'Access is denied.' }) });
  assert.deepEqual(plain(await refused.ctx.autostartRepoint()), { ok: false, error: 'Access is denied.' });
  assert.match(refused.logs.at(-1).line, /Could not point the logon task at this copy: Access is denied\./);
  // off Windows there is nothing to point
  const mac = autostartHarness({ platform: 'darwin' });
  assert.equal((await mac.ctx.autostartRepoint()).ok, false);
  assert.deepEqual(mac.calls, []);
});

test('L1: two IPC calls and two bridge methods, nothing else', () => {
  assert.match(MAIN, /ipcMain\.handle\('autostart:check', \(\) => autostartCheck\(\)\);/);
  assert.match(MAIN, /ipcMain\.handle\('autostart:repoint', \(\) => autostartRepoint\(\)\);/);
  assert.match(PRELOAD, /autostartCheck: \(\) => ipcRenderer\.invoke\('autostart:check'\),/);
  assert.match(PRELOAD, /autostartRepoint: \(\) => ipcRenderer\.invoke\('autostart:repoint'\),/);
  // the launch path itself is untouched: no check runs in the ready handler, only when the window asks
  const ready = slice(MAIN, 'app.whenReady().then(() => {', '\n});');
  assert.doesNotMatch(ready, /autostartCheck|autostartRepoint|setAutostart/);
});

/* ------------------------------ the window: what it shows ------------------------------ */

const APP = R('src', 'renderer', 'app.js');
const HTML = R('src', 'renderer', 'index.html');
const I18N_SRC = R('src', 'renderer', 'i18n.js');
const CSS = ['styles.css', 'home.css'].map((f) => R('src', 'renderer', f)).join('\n');

/** The renderer's real t(), in one language. */
function i18nT(lang) {
  const ctx = vm.createContext({ window: {}, document: { documentElement: {}, querySelectorAll: () => [] } });
  vm.runInContext(I18N_SRC, ctx);
  ctx.window.i18n.applyI18n(lang);
  return ctx.window.i18n.t;
}
/** The body of a `window.api.onX((d) => { … });` handler, as a named function. */
function handlerSource(name) {
  const head = `window.api.${name}((d) => {`;
  const start = APP.indexOf(head);
  assert.ok(start > -1, `app.js has no ${name} handler`);
  const end = APP.indexOf('\n});', start);
  return `var ${name} = (d) => {${APP.slice(start + head.length, end)}\n};`;
}
/** A DOM node that keeps its children and its text. */
class El {
  constructor(id) { this.id = id; this.own = ''; this.children = []; this.hidden = true; this.className = ''; this.title = ''; this.classList = { add() {}, remove() {}, toggle() {} }; }
  get textContent() { return [this.own, ...this.children.map((c) => c.textContent)].filter(Boolean).join('\n'); }
  set textContent(v) { this.own = String(v); this.children = []; }
  appendChild(c) { this.children.push(c); return c; }
  setAttribute() {}
}

function windowHarness({ lang = 'en', platform = 'win32', flavor = null, api = {}, timers = null, clear = null } = {}) {
  const calls = [];
  const els = new Map();
  const el = (id) => { if (!els.has(id)) els.set(id, new El(id)); return els.get(id); };
  const ctx = vm.createContext({
    state: { connected: false, connecting: false, activeServerId: null, activeEngine: '', settings: { tunMode: true }, flavor, platform,
      servers: [], pendingReconnect: [], wasReconnecting: false, lan: null, connIssues: [], noticesToasted: new Set(), noticesOnce: new Set(), autostartStale: null },
    $: (sel) => el(String(sel).replace(/^#/, '')),
    t: i18nT(lang),
    document: { createElement: () => new El('') },
    toast: (msg, kind, ms) => calls.push(['toast', kind || '', msg, ms]),
    setConnUI: (s) => { calls.push(['ui', s]); ctx.renderConnIssues(s); },
    appendLog: (line) => calls.push(['log', line]),
    renderServers: () => {}, renderPicker: () => {}, renderPendingBanner: () => {}, setPending: () => {}, setModeWidget: () => {},
    updateLanInfo: () => {}, hideGeo: () => {}, resetTraffic: () => {}, checkIp: () => {}, quickPing: () => {},
    updateAdminBtn: (on) => calls.push(['admin', on]),
    reconnectingKey: () => 'state.reconnecting', failedKey: () => 'net.failed',
    attemptText: (kind, n) => `${kind} ${n}`, showErrorReason: (m) => calls.push(['error', m]),
    setTimeout: timers || ((fn) => { fn(); return 1; }), clearTimeout: clear || (() => {}),
    window: { api }
  });
  vm.runInContext(['connIssuesFrom', 'noticeText', 'renderConnIssues', 'connectToasts', 'toastSeries', 'cancelToastSeries',
    'checkAutostart', 'renderAutostartBanner', 'repointAutostart', 'giveInternetBack'].map((n) => fnOf(APP, n)).join('\n') + '\n' + handlerSource('onStatus'), ctx);
  const toasts = () => calls.filter((c) => c[0] === 'toast');
  return { ctx, calls, el, toasts };
}
const UP = { state: 'connected', serverId: 's1', engine: 'xray', tun: true, tunError: null, guardError: null, geoWarn: null, lan: null, pendingReconnect: [] };

test('a connect with nothing to say (no failure, no notice) shows nothing new — no toast, no line — on the desktop and on the router', () => {
  for (const flavor of [null, 'openwrt']) {
    const h = windowHarness({ flavor });
    h.ctx.onStatus(Object.assign({}, UP, { notices: [] }));
    h.ctx.onStatus(Object.assign({}, UP));            // a service that sends no notices at all
    assert.deepEqual(h.toasts(), [], String(flavor));
    assert.equal(h.el('connIssues').hidden, true);
    assert.equal(h.el('connIssues').children.length, 0);
  }
});

test('L2: TUN on and no tunnel — the toast says "proxy only" with the reason, and a line stays on Home until the connection goes', () => {
  const reason = 'sing-box exited before the TUN adapter came up — FATAL[0000] start inbound/tun[tun-in]: configure tun interface: set ipv6 address: Element not found.';
  const h = windowHarness();
  h.ctx.onStatus(Object.assign({}, UP, { tun: false, tunError: reason }));
  assert.deepEqual(h.toasts().map((c) => [c[1], c[2]]), [['err', 'Proxy only — the tunnel did not start: ' + reason]]);
  assert.ok(h.calls.some((c) => c[0] === 'admin' && c[1] === true), 'the admin button still shows, as before');
  const box = h.el('connIssues');
  assert.equal(box.hidden, false);
  assert.deepEqual(box.children.map((c) => [c.className, c.textContent]), [['conn-issue', 'Proxy only — the tunnel did not start: ' + reason]]);
  // a language switch repaints the line in the other language (setConnUI → renderConnIssues)
  h.ctx.t = i18nT('fa');
  h.ctx.renderConnIssues('connected');
  assert.equal(box.children[0].textContent, 'فقط پراکسی — تونل بالا نیامد: ' + reason);
  // gone with the connection
  h.ctx.onStatus({ state: 'disconnected' });
  assert.equal(box.hidden, true);
  assert.equal(box.children.length, 0);
  assert.deepEqual(plain(h.ctx.state.connIssues), []);
  // and the next healthy connect does not bring it back
  h.ctx.onStatus(Object.assign({}, UP));
  assert.equal(box.hidden, true);
});

test('L2: a recovery that gave up on TUN with the proxy still up keeps the "proxy only" line too', () => {
  const h = windowHarness();
  h.ctx.state.connected = true;
  h.ctx.onStatus({ state: 'reconnect-failed', reason: 'interfaces', proxyUp: true, guardHeld: false, tunError: 'TUN adapter did not become ready — check admin rights and wintun.dll' });
  assert.equal(h.el('connIssues').hidden, false);
  assert.equal(h.el('connIssues').children[0].textContent, 'Proxy only — the tunnel did not start: TUN adapter did not become ready — check admin rights and wintun.dll');
  // the toast it always gave is unchanged
  assert.deepEqual(h.toasts().map((c) => c[1]), ['warn']);
});

test('L2(c): the leak guard failed under a live tunnel — a toast and a line; the proxy mode’s UDP block is not the guard and says nothing new', () => {
  const h = windowHarness();
  h.ctx.onStatus(Object.assign({}, UP, { guardError: 'no physical adapter is up' }));
  const said = 'Leak guard failed — DNS may leave outside the tunnel: no physical adapter is up';
  assert.deepEqual(h.toasts().map((c) => [c[1], c[2]]), [['err', said]]);
  assert.deepEqual(h.el('connIssues').children.map((c) => c.textContent), [said]);
  const fa = windowHarness({ lang: 'fa' });
  fa.ctx.onStatus(Object.assign({}, UP, { guardError: 'x' }));
  assert.equal(fa.toasts()[0][2], 'محافظ نشت DNS فعال نشد — ممکن است DNS بیرون از تونل برود: x');
  const proxyMode = windowHarness();
  proxyMode.ctx.state.settings.tunMode = false;
  proxyMode.ctx.onStatus(Object.assign({}, UP, { tun: false, guardError: 'UDP block failed' }));
  assert.deepEqual(proxyMode.toasts(), []);
  assert.equal(proxyMode.el('connIssues').hidden, true);
});

const NOTES = [
  { id: 'corpDnsOff', servers: '192.168.60.1' },
  { id: 'wgSharedKeySub', name: 'cobra.tes.ca', other: 'cobra.tes.ca', group: 'tes-vpn-service.platform.irnetfree.info', otherInSub: true, byHand: true },
  { id: 'wgSharedAddress', name: 'cobra.tes.ca', other: 'reza-wire', group: { t: 'srv.manual' }, otherInSub: false, byHand: true, address: '10.10.10.42' },
  { id: 'lanInRange', lan: '192.168.60.0/24', iface: 'Ethernet', range: '192.168.0.0/16', target: 'Tes Chain', address: '192.168.60.1', key: 'DNS' },
  { id: 'rangeInLan', lan: '192.168.1.0/24', iface: 'Wi-Fi', range: '192.168.1.20/32', target: 'tes-wg' }
];

test('W1/W3/W4: each notice is a toast, one after another — what to do in it; a recovery never repeats one, a new connection repeats the PC’s, the store’s twins are said once per run', () => {
  const notes = NOTES;
  const h = windowHarness();
  h.ctx.onStatus(Object.assign({}, UP, { geoWarn: 'Geo files are missing', notices: notes }));
  const t = h.toasts();
  assert.deepEqual(t.map((c) => c[1]), ['warn', 'warn', 'warn', 'warn', 'warn', 'warn']);
  assert.equal(t[0][2], 'Geo files are missing', 'the geo toast is as it was, and first');
  assert.equal(t[0][3], 2600);
  assert.equal(t[1][2], 'Managed DNS is off, so your WireGuard’s resolver (192.168.60.1) is not used and names inside that network will not resolve — turn Settings → DNS → “DNS managed by the app” back on');
  // the window's English says what main's log line says, word for word — the remedy included
  for (let i = 1; i < notes.length; i++) assert.equal(t[i + 1][2], notices.noticeLine(notes[i]), notes[i].id);
  assert.equal(t[2][2], 'WireGuard cobra.tes.ca: the same private key is also stored in another record, “cobra.tes.ca” in the group “tes-vpn-service.platform.irnetfree.info” — a WireGuard server accepts one device per key, so when both are used (on two devices, or that record tested while you are connected) one of them stalls. A record in a subscription comes back on the subscription’s next update, so deleting that one does not last: keep it, use it in place of this one (rebuild the chain on it), delete the copy added by hand and do not test it while connected — or remove the subscription if it should not be used');
  assert.match(t[3][2], /^WireGuard cobra\.tes\.ca: its tunnel address 10\.10\.10\.42 is also stored in another record, “reza-wire” in the group “Added by hand”, with another key/);
  assert.match(t[4][2], /^Your local network 192\.168\.60\.0\/24 \(Ethernet\) overlaps 192\.168\.60\.1 — the DNS of Tes Chain’s WireGuard — /);
  assert.ok(t.slice(1).every((c) => c[3] >= 12000), 'long enough to read a sentence and its remedy');
  assert.equal(h.el('connIssues').hidden, true, 'advice, not a failure of this connection: no line under the state');
  // the network moved and the connection was rebuilt: the same findings are not said again
  // (only the "reconnected" toast it always gave)
  const warns = () => h.toasts().filter((c) => c[1] === 'warn').map((c) => c[2]);
  h.ctx.onStatus({ state: 'reconnecting', reason: 'interfaces' });
  h.ctx.onStatus(Object.assign({}, UP, { notices: notes }));
  assert.equal(warns().length, 6);
  assert.equal(h.toasts().at(-1)[1], 'ok');
  // a disconnect and a new connect: this PC's findings again (its network may have changed) —
  // the store's twin records not: they are said once per run
  h.ctx.onStatus({ state: 'disconnected' });
  h.ctx.onStatus(Object.assign({}, UP, { notices: notes }));
  assert.deepEqual(warns().slice(6), [t[1][2], t[4][2], t[5][2]]);
  // a twin that was not there before is new: said
  h.ctx.onStatus({ state: 'disconnected' });
  const other = { id: 'wgSharedKey', name: 'cobra.tes.ca', other: 'cobra (old)', group: { t: 'srv.manual' } };
  h.ctx.onStatus(Object.assign({}, UP, { notices: [other] }));
  assert.match(warns().at(-1), /“cobra \(old\)” in the group “Added by hand”/);
  // Persian
  const fa = windowHarness({ lang: 'fa' });
  fa.ctx.onStatus(Object.assign({}, UP, { notices: notes }));
  assert.ok(fa.toasts().every((c) => !/\{\w+\}/.test(c[2])), 'every placeholder filled');
  assert.match(fa.toasts()[1][2], /^وایرگارد cobra\.tes\.ca: /);
  assert.match(fa.toasts()[1][2], /«tes-vpn-service\.platform\.irnetfree\.info»/);
  assert.match(fa.toasts()[2][2], /«کانفیگ‌های دستی»/, 'the group label in the user’s language');
});

test('the remedy is in both languages: delete the twin, do not test it while connected, one peer per device; move the clashing network', () => {
  const fa = i18nT('fa'), en = i18nT('en');
  assert.match(en('notice.wgSharedKey'), /Delete the copy you do not use, do not test it while connected, and get one peer per device from the server’s admin$/);
  assert.match(fa('notice.wgSharedKey'), /نسخه‌ای را که استفاده نمی‌کنی پاک کن، وقتی وصلی تستش نکن و برای هر دستگاه یک peer جدا از ادمین سرور بگیر$/);
  assert.match(en('notice.wgSharedAddress'), /Keep the record the server’s admin made for this device, delete the other, and do not test it while connected$/);
  assert.match(fa('notice.wgSharedAddress'), /دیگری را پاک کن و وقتی وصلی تستش نکن$/);
  for (const id of ['lanInRange', 'rangeInLan']) {
    assert.match(en('notice.' + id), /Move that LAN, VM or host-only network to another subnet$/, id);
    assert.match(fa('notice.' + id), /آن شبکهٔ محلی، ماشین مجازی یا شبکهٔ host-only را به زیرشبکهٔ دیگری ببر$/, id);
  }
  // twin records are told apart: "another record" and its group, in both languages
  assert.match(en('notice.wgSharedKey'), /another record, “\{other\}” in the group “\{group\}”/);
  assert.match(fa('notice.wgSharedKey'), /رکورد دیگری .*«\{other\}» در گروه «\{group\}»/);
  // the twin in a live subscription (the owner's case): deleting it does not last — keep that one,
  // rebuild the chain on it, delete the hand-added copy, or remove the subscription
  for (const id of ['wgSharedKeySub', 'wgSharedAddressSub']) {
    assert.match(en('notice.' + id), /A record in a subscription comes back on the subscription’s next update, so deleting that one does not last: /, id);
    assert.match(en('notice.' + id), /use it in place of this one \(rebuild the chain on it\)/, id);
    assert.match(en('notice.' + id), /delete the copy added by hand/, id);
    assert.match(en('notice.' + id), /remove the subscription/, id);
    assert.doesNotMatch(en('notice.' + id), /Delete the copy you do not use|delete the other/, id);
    assert.match(fa('notice.' + id), /با به‌روزرسانی بعدیِ آن ساب برمی‌گردد/, id);
    assert.match(fa('notice.' + id), /زنجیره را روی آن دوباره بساز/, id);
    assert.match(fa('notice.' + id), /نسخهٔ دستی را پاک کن/, id);
    assert.match(fa('notice.' + id), /ساب را حذف کن/, id);
    // the window's English is main's log line, word for word
    const n = { id, name: 'cobra.tes.ca', other: 'cobra.tes.ca', group: 'tes-vpn-service.platform.irnetfree.info', otherInSub: true, byHand: true, address: '10.10.10.42' };
    assert.equal(windowHarness().ctx.noticeText(n), notices.noticeLine(n), id);
  }
});

test('the toasts of one connect come one after another, not over each other', () => {
  const pending = [];
  const h = windowHarness({ timers: (fn, ms) => { pending.push([fn, ms]); return pending.length; } });
  h.ctx.onStatus(Object.assign({}, UP, { guardError: 'g', geoWarn: 'geo', notices: [{ id: 'corpDnsOff', servers: '10.0.0.1' }] }));
  // checkIp / quickPing are deferred too; only the series' own steps are counted here
  const series = () => h.toasts().map((c) => c[1] + ':' + c[2].slice(0, 12));
  assert.deepEqual(series(), ['err:Leak guard f']);
  const step = pending.find(([, ms]) => ms === 9000 + 300);
  assert.ok(step, 'the next toast waits for this one: ' + pending.map((p) => p[1]).join(','));
  step[0]();
  assert.deepEqual(series(), ['err:Leak guard f', 'warn:geo']);
  pending.find(([, ms]) => ms === 2600 + 300)[0]();
  assert.deepEqual(series(), ['err:Leak guard f', 'warn:geo', 'warn:Managed DNS ']);
});

test('a series still running when its connection goes (a disconnect, a switch, a rebuild) stops there — and a notice it never showed is said by the next connection', () => {
  const twin = NOTES[1];   // the store's: once per run
  for (const gone of [{ state: 'disconnected' }, { state: 'connecting', serverId: 's2' }, { state: 'reconnecting', reason: 'interfaces' }]) {
    const pending = new Map();
    let n = 0;
    const h = windowHarness({ timers: (fn, ms) => { pending.set(++n, [fn, ms]); return n; }, clear: (id) => pending.delete(id) });
    const runPending = () => { const list = [...pending.values()]; pending.clear(); for (const [fn] of list) fn(); };
    h.ctx.onStatus(Object.assign({}, UP, { guardError: 'g', notices: [twin, NOTES[3]] }));
    assert.deepEqual(h.toasts().map((c) => c[1]), ['err'], 'the first one shows, the rest wait their turn');
    h.ctx.onStatus(gone);
    runPending();
    assert.deepEqual(h.toasts().map((c) => c[1]), ['err'], `nothing more after '${gone.state}'`);
    // the next connection says what was never shown — the twin too, though it is once per run
    const warns = () => h.toasts().filter((c) => c[1] === 'warn').map((c) => c[2]);
    h.ctx.onStatus(Object.assign({}, UP, { notices: [twin, NOTES[3]] }));
    runPending();
    runPending();
    assert.deepEqual(warns(), [notices.noticeLine(twin), notices.noticeLine(NOTES[3])], gone.state);
    // shown now: the twin is not said again this run, the PC's finding is (a new connection)
    h.ctx.onStatus({ state: 'disconnected' });
    h.ctx.onStatus(Object.assign({}, UP, { notices: [twin, NOTES[3]] }));
    runPending();
    assert.deepEqual(warns().slice(2), [notices.noticeLine(NOTES[3])]);
  }
  // a core that stopped with nothing to rebuild it is a disconnect too
  const xrayStopped = slice(APP, 'window.api.onXrayStatus((d) => {', '\n});');
  assert.match(xrayStopped, /state\.connected = false;\n\s*cancelToastSeries\(\);/);
});

test('a notice’s text: every {field} filled from the notice, literally — a { t } field is the window’s own string, in the user’s language', () => {
  const h = windowHarness();
  assert.equal(h.ctx.noticeText({ id: 'proxyOnly', reason: 'a $& b $1' }), 'Proxy only — the tunnel did not start: a $& b $1');
  assert.equal(h.ctx.noticeText({ id: 'proxyOnly' }), 'Proxy only — the tunnel did not start: {reason}');
  assert.equal(h.ctx.noticeText({ id: 'proxyOnly', reason: { t: 'srv.manual' } }), 'Proxy only — the tunnel did not start: Added by hand');
  assert.equal(h.ctx.noticeText({ id: 'proxyOnly', reason: { t: 'srv.subGone' } }), 'Proxy only — the tunnel did not start: Deleted subscription');
  // an object that is not a string reference is not printed as [object Object]
  assert.equal(h.ctx.noticeText({ id: 'proxyOnly', reason: { x: 1 } }), 'Proxy only — the tunnel did not start: {reason}');
  assert.equal(h.ctx.noticeText(null), '');
  const fa = windowHarness({ lang: 'fa' });
  assert.equal(fa.ctx.noticeText({ id: 'proxyOnly', reason: { t: 'srv.manual' } }), 'فقط پراکسی — تونل بالا نیامد: کانفیگ‌های دستی');
});

/* ------------------------------ the window: the "give my internet back" banner ------------------------------ */

test('the guard banner belongs to a give-up with the guard held: any later state takes it away, so its button is never offered under a live tunnel', () => {
  const GAVE_UP = { state: 'reconnect-failed', reason: 'interfaces', proxyUp: false, guardHeld: true, tunError: null };
  const later = [
    Object.assign({}, UP),                                   // a reconnect (the banner's Retry, the tray, a new network) came back
    { state: 'connecting', serverId: 's1' },
    { state: 'reconnecting', reason: 'interfaces' },
    { state: 'disconnected' },
    { state: 'waiting', attempt: 2 },
    { state: 'error', message: 'x' }
  ];
  for (const d of later) {
    const h = windowHarness();
    h.ctx.onStatus(GAVE_UP);
    assert.equal(h.el('guardBanner').hidden, false, 'shown by the give-up');
    h.ctx.onStatus(d);
    assert.equal(h.el('guardBanner').hidden, true, `still on screen after '${d.state}'`);
  }
  // a give-up with nothing held: no banner; one with the proxy still up and the guard held: the banner
  const none = windowHarness();
  none.ctx.onStatus(Object.assign({}, GAVE_UP, { guardHeld: false }));
  assert.equal(none.el('guardBanner').hidden, true);
  const proxy = windowHarness();
  proxy.ctx.onStatus(Object.assign({}, GAVE_UP, { proxyUp: true, tunError: 'TUN adapter did not become ready' }));
  assert.equal(proxy.el('guardBanner').hidden, false);
  // a disconnect whose teardown failed is no new state: the banner stays as it was
  const cleanup = windowHarness();
  cleanup.ctx.onStatus(GAVE_UP);
  cleanup.ctx.onStatus({ state: 'cleanup-failed', error: 'cleanup-failed' });
  assert.equal(cleanup.el('guardBanner').hidden, false);
});

test('the banner’s "give my internet back": main’s refusal under a live tunnel is said in the user’s language, a release as before', async () => {
  for (const lang of ['en', 'fa']) {
    const t = i18nT(lang);
    const refused = windowHarness({ lang, api: { releaseGuard: async () => ({ ok: false, refused: 'connected', error: 'main’s English' }) } });
    refused.el('guardBanner').hidden = false;
    await refused.ctx.giveInternetBack();
    assert.deepEqual(refused.toasts().map((c) => [c[1], c[2]]), [['err', t('guard.releaseRefused')]]);
    assert.equal(refused.el('guardBanner').hidden, true);
    const done = windowHarness({ lang, api: { releaseGuard: async () => ({ ok: true }) } });
    await done.ctx.giveInternetBack();
    assert.deepEqual(done.toasts().map((c) => [c[1], c[2]]), [['ok', t('t.guardReleased')]]);
    const failed = windowHarness({ lang, api: { releaseGuard: async () => ({ ok: false, error: 'Access is denied.' }) } });
    await failed.ctx.giveInternetBack();
    assert.deepEqual(failed.toasts().map((c) => [c[1], c[2]]), [['err', 'Access is denied.']]);
  }
  assert.notEqual(i18nT('fa')('guard.releaseRefused'), i18nT('en')('guard.releaseRefused'));
  assert.equal(I18N_SRC.split("'guard.releaseRefused':").length - 1, 2, 'once in each language');
  assert.match(APP, /\$\('#guardRelease'\)\.onclick = giveInternetBack;/);
});

/* ------------------------------ the window: the logon task banner (L1) ------------------------------ */

test('L1: on Windows the window asks once it has loaded; a task that starts another copy is a banner with the paths', async () => {
  const h = windowHarness({ api: { autostartCheck: async () => ({ stale: true, taskExe: 'C:\\old\\IRNetFree.exe', currentExe: 'C:\\Program Files\\IRNetFree\\IRNetFree.exe' }) } });
  await h.ctx.checkAutostart();
  assert.equal(h.el('autostartBanner').hidden, false);
  assert.equal(h.el('autostartBannerText').textContent,
    'At logon Windows starts another copy of IRNetFree — C:\\old\\IRNetFree.exe — not this one (C:\\Program Files\\IRNetFree\\IRNetFree.exe). That copy keeps its own, possibly older, network code.');
  assert.deepEqual(h.toasts(), []);
});

test('L1: silent where the task is this copy, off Windows, on the router’s page, or when the read fails', async () => {
  const asked = [];
  const ask = (r) => async () => { asked.push(r); if (r instanceof Error) throw r; return r; };
  for (const [platform, api] of [
    ['win32', { autostartCheck: ask({ stale: false }) }],
    ['win32', { autostartCheck: ask(new Error('no')) }],
    ['win32', {}],                                           // the router's web api has no such call
    ['darwin', { autostartCheck: ask({ stale: true, taskExe: 'a', currentExe: 'b' }) }],
    ['linux', { autostartCheck: ask({ stale: true, taskExe: 'a', currentExe: 'b' }) }]
  ]) {
    const h = windowHarness({ platform, api });
    await h.ctx.checkAutostart();
    assert.equal(h.el('autostartBanner').hidden, true, platform);
    assert.deepEqual(h.toasts(), []);
  }
  assert.equal(asked.length, 2, 'asked on Windows only');
});

test('L1: the button points the task at this copy; a refusal is said and the banner stays', async () => {
  let n = 0;
  const h = windowHarness({ api: {
    autostartCheck: async () => ({ stale: true, taskExe: 'C:\\old\\IRNetFree.exe', currentExe: 'C:\\new\\IRNetFree.exe' }),
    autostartRepoint: async () => (++n === 1 ? { ok: false, error: 'Access is denied.' } : { ok: true })
  } });
  await h.ctx.checkAutostart();
  await h.ctx.repointAutostart();
  assert.deepEqual(h.toasts().map((c) => [c[1], c[2]]), [['err', 'Could not update the logon task: Access is denied.']]);
  assert.equal(h.el('autostartBanner').hidden, false);
  await h.ctx.repointAutostart();
  assert.deepEqual(h.toasts().at(-1).slice(1, 3), ['ok', 'At logon Windows now starts this version']);
  assert.equal(h.el('autostartBanner').hidden, true);
});

/* ------------------------------ the window: markup, strings, wiring ------------------------------ */

test('the markup: the issue lines sit under the connection state, the banner beside the others — both hidden until needed', () => {
  const panel = slice(HTML, '<div class="connect-panel">', '\n            </div>');
  assert.ok(panel.indexOf('id="connMeta"') > -1 && panel.indexOf('id="connMeta"') < panel.indexOf('id="connIssues"'), 'under the state and its meta line');
  assert.match(panel, /<div class="conn-issues" id="connIssues" role="status" hidden><\/div>/);
  assert.match(HTML, /<div class="pending-banner" id="autostartBanner" hidden>/);
  const banner = slice(HTML, 'id="autostartBanner"', '\n  </div>');
  assert.match(banner, /id="autostartBannerText"/);
  assert.match(banner, /<button class="btn" id="autostartFix" data-i18n="notice\.autostartFix">/);
  assert.match(banner, /<button class="btn ghost" id="autostartDismiss" data-i18n="apply\.dismiss">/);
  for (const cls of ['.conn-issues', '.conn-issue']) assert.ok(CSS.includes(cls + ' {'), `${cls} has no style`);
});

test('every notice main can send, and every line the window shows, is a string in both languages with the same fields', () => {
  // what connectNotices makes, minus what stays in the log (a broad range around a LAN), plus main's own W3
  const made = [...R('src', 'main', 'connectNotices.js').matchAll(/\bid: '(\w+)'/g)].map((m) => m[1]);
  assert.ok(made.includes('lanInBroadRange'));
  const fromMain = new Set(made.filter((id) => !notices.LOG_ONLY.has(id)));
  fromMain.add('corpDnsOff');
  assert.deepEqual([...fromMain].sort(), ['corpDnsOff', 'lanInRange', 'rangeInLan', 'wgSharedAddress', 'wgSharedAddressSub', 'wgSharedKey', 'wgSharedKeySub']);
  const ids = [...fromMain, 'proxyOnly', 'guardFailed', 'autostartStale', 'autostartFix', 'autostartFixed', 'autostartFixFailed'];
  const fa = i18nT('fa'), en = i18nT('en');
  const fields = (s) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort().join(',');
  for (const id of ids) {
    const k = 'notice.' + id;
    assert.equal(I18N_SRC.split(`'${k}':`).length - 1, 2, `${k} is not defined exactly once in each of fa and en`);
    assert.notEqual(fa(k), en(k), `${k} is not translated`);
    assert.equal(fields(fa(k)), fields(en(k)), `${k}: the two languages fill different fields`);
  }
  // the two lines the owner asked for, word for word
  assert.equal(en('notice.guardFailed'), 'Leak guard failed — DNS may leave outside the tunnel: {reason}');
  assert.equal(fa('notice.guardFailed'), 'محافظ نشت DNS فعال نشد — ممکن است DNS بیرون از تونل برود: {reason}');
  assert.equal(en('notice.proxyOnly'), 'Proxy only — the tunnel did not start: {reason}');
  assert.equal(fa('notice.proxyOnly'), 'فقط پراکسی — تونل بالا نیامد: {reason}');
});

test('the wiring: setConnUI repaints the lines, a language switch the banner, and init asks about the task without waiting on it', () => {
  assert.match(fnOf(APP, 'setConnUI'), /renderConnIssues\(stateStr\);\n\s*refreshConnectControls\(\);\n\}$/);
  const init = fnOf(APP, 'init');
  assert.match(init, /\n {2}checkAutostart\(\);\n/);
  assert.doesNotMatch(init, /await checkAutostart/);
  assert.ok(init.indexOf('applyConnSnapshot(data.conn)') < init.indexOf('checkAutostart()'));
  assert.match(APP, /\$\('#autostartFix'\)\.onclick = \(\) => repointAutostart\(\);/);
  assert.match(APP, /\$\('#autostartDismiss'\)\.onclick = \(\) => \{ state\.autostartStale = null; renderAutostartBanner\(\); \};/);
  // the language switch: refreshConnLabels() (→ setConnUI → the lines) and the banner
  const switchAt = APP.indexOf('refreshConnLabels();\n  renderAutostartBanner();\n  renderSettingCards();');
  assert.ok(switchAt > -1 && switchAt < APP.indexOf('saveSettings({ lang });'), 'the language switch repaints the banner');
  // the state starts empty
  assert.match(APP, /connIssues: \[\],/);
  assert.match(APP, /noticesToasted: new Set\(\),/);
  assert.match(APP, /noticesOnce: new Set\(\),/);
  assert.match(APP, /autostartStale: null,/);
  // a disconnect forgets this connection's notices, never the run's
  const down = slice(APP, "} else if (d.state === 'disconnected') {", 'setPending([]);');
  assert.match(down, /state\.noticesToasted = new Set\(\);/);
  assert.doesNotMatch(down, /noticesOnce/);
});

/* --------- a connect that fails before a tunnel: a guard stranded by a give-up is given back --------- */

function failedConnectHarness({ active = false, running = false, others = 0 } = {}) {
  const released = [];
  const logs = [];
  const ctx = vm.createContext({
    xray: { running }, tun: { active },
    connectsInFlight: new Set(Array.from({ length: others }, () => new Promise(() => {}))),
    leakGuard: {},
    releaseStrandedGuard: async (g) => { released.push(g); return { released: true }; },
    connectOnce: async () => { throw new Error('Config rejected by xray'); },
    send: (ch, p) => { if (ch === 'log') logs.push(p); }
  });
  vm.runInContext([fnOf(MAIN, 'guardInUse'), fnOf(MAIN, 'releaseGuardAfterFailedConnect'), fnOf(MAIN, 'doConnect')].join('\n'), ctx);
  return { ctx, released, logs };
}
const settle = () => new Promise((r) => setTimeout(r, 20));

test('a connect that fails before any tunnel gives a guard held by a given-up reconnect back — the window\'s banner was hidden by its "connecting" (review of v1.16.3)', async () => {
  const h = failedConnectHarness();
  await assert.rejects(h.ctx.doConnect('srv'), /Config rejected/);
  await settle();
  assert.equal(h.released.length, 1, 'the adapters get their resolvers back');
  assert.equal(h.logs.at(-1).level, 'info');
  // a recovery keeps its hold (runRecovery retries the tunnel), a live tunnel or another connect owns the guard
  for (const [opts, shape] of [[{ recovery: true }, {}], [undefined, { active: true, running: true }], [undefined, { others: 1 }]]) {
    const k = failedConnectHarness(shape);
    await assert.rejects(k.ctx.doConnect('srv', opts));
    await settle();
    assert.equal(k.released.length, 0, JSON.stringify({ opts, shape }));
  }
});
