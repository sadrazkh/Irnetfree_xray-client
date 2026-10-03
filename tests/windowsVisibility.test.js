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
