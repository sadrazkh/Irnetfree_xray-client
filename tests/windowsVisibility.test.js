'use strict';
/**
 * v1.16.3 — Windows visibility (windows-android-report §1 L1/L2, §2 W1/W3/W4).
 *
 * One Windows PC leaks DNS and its advanced-routing chain to a corporate
 * WireGuard "does not work properly"; another PC with the same configs is fine.
 * Nothing in this round changes what the app DOES — no generated config, no
 * route, no resolver, no guard action, no step of the connect: it only makes
 * the app SAY, on the PC where it happens, which of the known causes applies.
 * Each message fires only on the condition it names, so a healthy PC sees
 * nothing new (tests/desktopPin.test.js still pins every generated config).
 *
 *   L2(c)  the leak guard failed           → a toast and a line under the state
 *   L2     TUN on, the tunnel did not come up (proxy only) → a persistent line + the reason
 *   W1     a WireGuard identity stored twice → warn line + one toast per connect
 *   W4     a LAN inside a routed private range → warn line + one toast per connect
 *   W3     managed DNS off with a corporate resolver → the existing warning, also a toast
 *   L1     the logon task starts another copy → a banner whose button re-registers it
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
const wg = (id, name) => Object.assign(makeWireguardServer({ name, endpoint: 'vpn.corp.example:51820', publicKey: PUB, privateKey: KEY, address: '10.10.10.42/32' }), { id });

function hintsHarness({ servers, rules = [], ifaces = {}, platform = 'win32', throwOn = null } = {}) {
  const logs = [];
  const ctx = vm.createContext({
    process: { platform },
    store: { get: (k, d) => { if (throwOn === 'store') throw new Error('store gone'); return k === 'servers' ? servers : d; } },
    os: { networkInterfaces: () => ifaces },
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

test('W1/W4 at connect: a warn line each, and the notices handed back for the window — never a key', () => {
  const chainWg = wg('b47f', 'tes-wg');
  const twin = wg('fa69', 'tes-wg (copy)');
  const hop = { id: 'hop', name: '🇬🇧-2', protocol: 'vless', outbound: { protocol: 'vless' } };
  const plan = { mode: 'advanced', serversById: { hop, b47f: chainWg, fa69: twin }, chainsById: { tes: [hop, chainWg] }, chain: [],
    rules: [{ type: 'ip', value: '192.168.0.0/16', target: 'chain:tes' }], def: 'hop' };
  const h = hintsHarness({
    servers: [hop, chainWg, twin],
    rules: plan.rules,
    ifaces: {
      'Wi-Fi': [{ address: '192.168.1.5', netmask: '255.255.255.0', family: 'IPv4', internal: false, cidr: '192.168.1.5/24' }],
      IRNetFree: [{ address: '172.19.0.1', netmask: '255.255.255.252', family: 'IPv4', internal: false, cidr: '172.19.0.1/30' }]
    }
  });
  const out = h.ctx.connectHints(plan);
  assert.deepEqual(plain(out), [
    { id: 'wgSharedKey', name: 'tes-wg', other: 'tes-wg (copy)' },
    { id: 'lanInRange', lan: '192.168.1.0/24', iface: 'Wi-Fi', range: '192.168.0.0/16', target: 'Tes Chain' }
  ]);
  assert.deepEqual(h.logs.map((l) => l.level), ['warn', 'warn']);
  assert.match(h.logs[0].line, /^WireGuard tes-wg: this identity is also stored as tes-wg \(copy\)/);
  assert.match(h.logs[1].line, /^Your local network 192\.168\.1\.0\/24 \(Wi-Fi\) lies inside 192\.168\.0\.0\/16 that advanced routing sends to Tes Chain/);
  assert.ok(!JSON.stringify(h.logs).includes(KEY) && !JSON.stringify(out).includes(KEY), 'the private key is never said');
});

test('W1/W4 at connect: a healthy plan says nothing; W4 is asked only of advanced routing; nothing in here can fail a connect', () => {
  const chainWg = wg('b47f', 'tes-wg');
  const lanIfaces = { 'Wi-Fi': [{ address: '192.168.1.5', netmask: '255.255.255.0', family: 'IPv4', internal: false, cidr: '192.168.1.5/24' }] };
  // one record per identity, corporate ranges that do not touch this LAN
  const healthy = hintsHarness({ servers: [chainWg], rules: [{ type: 'ip', value: '192.168.60.0/24', target: 'b47f' }], ifaces: lanIfaces });
  assert.deepEqual(plain(healthy.ctx.connectHints({ mode: 'advanced', serversById: { b47f: chainWg }, rules: [{ type: 'ip', value: '192.168.60.0/24', target: 'b47f' }], def: 'b47f' })), []);
  assert.equal(healthy.logs.length, 0);
  // a single config: its stored rules are not in this plan
  const single = hintsHarness({ servers: [chainWg], rules: [{ type: 'ip', value: '192.168.0.0/16', target: 'b47f' }], ifaces: lanIfaces });
  assert.deepEqual(plain(single.ctx.connectHints({ mode: 'single', server: chainWg })), []);
  // a throw anywhere is swallowed: the connect goes on exactly as before
  const broken = hintsHarness({ servers: [], throwOn: 'store' });
  assert.deepEqual(plain(broken.ctx.connectHints({ mode: 'single', server: chainWg })), []);
  assert.deepEqual(plain(broken.ctx.connectHints(null)), []);
});

test('the connect asks for the notices on Windows only, after the plan is built and before anything is started, and the connected status carries them', () => {
  // W3: the existing managed-DNS line stays exactly as it was, and on Windows becomes a notice too
  assert.match(CONNECT, /line: `Managed DNS is off, so the resolver of your WireGuard \(\$\{corp\.join\(', '\)\}\) is not in this config and names inside that network will not resolve — turn Settings → DNS → "DNS managed by the app" back on`,\n\s*level: 'warn'\n\s*\}\);\n\s*if \(process\.platform === 'win32'\) notices\.push\(\{ id: 'corpDnsOff', servers: corp\.join\(', '\) \}\);/);
  assert.match(CONNECT, /\n {2}if \(process\.platform === 'win32'\) notices\.push\(\.\.\.connectHints\(plan\)\);\n/);
  const built = CONNECT.indexOf('= buildActive(serverId, settings);');
  const declared = CONNECT.indexOf('const notices = [];');
  const asked = CONNECT.indexOf('notices.push(...connectHints(plan))');
  assert.ok(built > -1 && built < declared && declared < asked, 'after the plan is built');
  for (const later of ["send('status', { state: 'connecting', serverId });", 'xray.validateWithFallback(', 'xray.start(', 'myTun.start(', 'leakGuard.engage(']) {
    const at = CONNECT.indexOf(later);
    assert.ok(at > asked, `${later} must come after the notices are gathered`);
  }
  assert.match(CONNECT, /tun: tun\.active, tunError, guardError, geoWarn, lan, pendingReconnect: pendingKeys\(\), notices\n\s*\}\);/);
  // gathered once, said once: nothing else in the connect reads or changes them
  assert.equal(CONNECT.split('notices').length - 1, 4, 'declared, W3, W1/W4, the status — and nowhere else');
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

function windowHarness({ lang = 'en', platform = 'win32', flavor = null, api = {}, timers = null } = {}) {
  const calls = [];
  const els = new Map();
  const el = (id) => { if (!els.has(id)) els.set(id, new El(id)); return els.get(id); };
  const ctx = vm.createContext({
    state: { connected: false, connecting: false, activeServerId: null, activeEngine: '', settings: { tunMode: true }, flavor, platform,
      servers: [], pendingReconnect: [], wasReconnecting: false, lan: null, connIssues: [], noticesToasted: new Set(), autostartStale: null },
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
    setTimeout: timers || ((fn) => { fn(); return 1; }), clearTimeout: () => {},
    window: { api }
  });
  vm.runInContext(['connIssuesFrom', 'noticeText', 'renderConnIssues', 'connectToasts', 'toastSeries',
    'checkAutostart', 'renderAutostartBanner', 'repointAutostart'].map((n) => fnOf(APP, n)).join('\n') + '\n' + handlerSource('onStatus'), ctx);
  const toasts = () => calls.filter((c) => c[0] === 'toast');
  return { ctx, calls, el, toasts };
}
const UP = { state: 'connected', serverId: 's1', engine: 'xray', tun: true, tunError: null, guardError: null, geoWarn: null, lan: null, pendingReconnect: [] };

test('a healthy connect shows nothing new — no toast, no line — on the desktop and on the router', () => {
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

test('W1/W3/W4: each notice is a toast, one after another, once per connection — a recovery does not repeat it, the next connect does', () => {
  const notes = [
    { id: 'corpDnsOff', servers: '192.168.60.1' },
    { id: 'wgSharedKey', name: 'tes-wg', other: 'tes-wg (copy)' },
    { id: 'wgSharedAddress', name: 'tes-wg', other: 'reza-wire', address: '10.10.10.42' },
    { id: 'lanInRange', lan: '192.168.1.0/24', iface: 'Wi-Fi', range: '192.168.0.0/16', target: 'Tes Chain' },
    { id: 'rangeInLan', lan: '192.168.1.0/24', iface: 'Wi-Fi', range: '192.168.1.20/32', target: 'tes-wg' }
  ];
  const h = windowHarness();
  h.ctx.onStatus(Object.assign({}, UP, { geoWarn: 'Geo files are missing', notices: notes }));
  const t = h.toasts();
  assert.deepEqual(t.map((c) => c[1]), ['warn', 'warn', 'warn', 'warn', 'warn', 'warn']);
  assert.equal(t[0][2], 'Geo files are missing', 'the geo toast is as it was, and first');
  assert.equal(t[0][3], 2600);
  assert.equal(t[1][2], 'Managed DNS is off, so your WireGuard’s resolver (192.168.60.1) is not used and names inside that network will not resolve — turn Settings → DNS → “DNS managed by the app” back on');
  assert.equal(t[2][2], 'WireGuard tes-wg: this identity is also stored as tes-wg (copy) — a WireGuard server accepts one device per key; used on two devices (or tested while connected) one of them stalls');
  assert.match(t[3][2], /^WireGuard tes-wg: its tunnel address 10\.10\.10\.42 is also stored as reza-wire with another key/);
  assert.equal(t[4][2], 'Your local network 192.168.1.0/24 lies inside 192.168.0.0/16 that advanced routing sends to Tes Chain — hosts in 192.168.1.0/24 stay on the LAN, not the tunnel');
  assert.equal(t[5][2], '192.168.1.20/32 that advanced routing sends to tes-wg lies inside your local network 192.168.1.0/24 — hosts in 192.168.1.20/32 stay on the LAN, not the tunnel');
  assert.ok(t.slice(1).every((c) => c[3] >= 8000), 'long enough to read');
  assert.equal(h.el('connIssues').hidden, true, 'advice, not a failure of this connection: no line under the state');
  // the network moved and the connection was rebuilt: the same findings are not said again
  // (only the "reconnected" toast it always gave)
  const warns = () => h.toasts().filter((c) => c[1] === 'warn').length;
  h.ctx.onStatus({ state: 'reconnecting', reason: 'interfaces' });
  h.ctx.onStatus(Object.assign({}, UP, { notices: notes }));
  assert.equal(warns(), 6);
  assert.equal(h.toasts().at(-1)[1], 'ok');
  // a disconnect and a new connect: said again
  h.ctx.onStatus({ state: 'disconnected' });
  h.ctx.onStatus(Object.assign({}, UP, { notices: notes.slice(1, 2) }));
  assert.equal(warns(), 7);
  // Persian
  const fa = windowHarness({ lang: 'fa' });
  fa.ctx.onStatus(Object.assign({}, UP, { notices: notes }));
  assert.ok(fa.toasts().every((c) => !/\{\w+\}/.test(c[2])), 'every placeholder filled');
  assert.match(fa.toasts()[1][2], /^وایرگارد tes-wg: /);
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

test('a notice’s text: every {field} filled from the notice, literally', () => {
  const h = windowHarness();
  assert.equal(h.ctx.noticeText({ id: 'proxyOnly', reason: 'a $& b $1' }), 'Proxy only — the tunnel did not start: a $& b $1');
  assert.equal(h.ctx.noticeText({ id: 'proxyOnly' }), 'Proxy only — the tunnel did not start: {reason}');
  assert.equal(h.ctx.noticeText(null), '');
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
  const fromMain = new Set([...R('src', 'main', 'connectNotices.js').matchAll(/\bid: '(\w+)'/g)].map((m) => m[1]));
  fromMain.add('corpDnsOff');
  assert.deepEqual([...fromMain].sort(), ['corpDnsOff', 'lanInRange', 'rangeInLan', 'wgSharedAddress', 'wgSharedKey']);
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
  assert.match(APP, /autostartStale: null,/);
});
