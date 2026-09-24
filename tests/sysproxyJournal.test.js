'use strict';
/**
 * The system proxy is put back exactly as we found it — and only when we set it.
 *
 * Three ways it went wrong before:
 *  - A disconnect only wrote ProxyEnable=0. A corporate proxy the user had
 *    (ProxyEnable=1, ProxyServer=corp:8080) was overwritten on connect and
 *    switched off on disconnect: gone for good.
 *  - setSystemProxy(false) ran on every disconnect, quit and exit, even when
 *    the app never set the proxy (systemProxy off, TUN only) — the same kill.
 *  - After a crash, a Task Manager kill or the update installer closing a
 *    connected app, ProxyEnable=1 → 127.0.0.1:10809 stayed: the UI said
 *    disconnected and every browser failed. Nothing repaired it at launch.
 *
 * So the previous state is journaled in userData BEFORE the first write, a
 * disable restores it (only when a journal exists) and deletes it, the launch
 * restores a journal a dead session left, and the exit hook does the same
 * synchronously. Everything runs through an injected exec: nothing here
 * touches this machine's registry or networksetup.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

// Belt and braces: nothing in this file may reach the real registry or
// networksetup of the machine running it. A code path that ignores the
// injected exec lands here and fails, instead of rewriting the proxy of
// whoever runs `npm test`. Installed before the module destructures them.
const cp = require('node:child_process');
cp.execFile = (cmd) => { throw new Error(`the test reached the real ${cmd}`); };
cp.execFileSync = (cmd) => { throw new Error(`the test reached the real ${cmd}`); };
cp.spawn = (cmd) => { throw new Error(`the test reached the real ${cmd}`); };

const {
  setSystemProxy, repairSystemProxy, restoreSystemProxySync, useProxyJournal, WIN_BYPASS
} = require('../src/main/sysproxy');

const WIN_REG = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings';

function tmpJournal(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-proxy-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return path.join(dir, 'proxy-journal.json');
}

/**
 * A fake Windows: the registry values as PowerShell's snapshot reports them,
 * reg add / delete applied to them, every call recorded — and whether the
 * journal existed at the moment of each call.
 */
function fakeWin(journal, values = {}) {
  const reg = Object.assign({}, values);
  const calls = [];
  const apply = (cmd, args) => {
    if (cmd !== 'reg') return;
    const name = args[args.indexOf('/v') + 1];
    if (args[0] === 'delete') {
      if (!(name in reg)) throw new Error('ERROR: The system was unable to find the specified registry key or value.');
      delete reg[name];
    } else {
      const type = args[args.indexOf('/t') + 1];
      const data = args[args.indexOf('/d') + 1];
      reg[name] = type === 'REG_DWORD' ? Number(data) : data;
    }
  };
  const snapshot = () => JSON.stringify({
    ProxyEnable: 'ProxyEnable' in reg ? reg.ProxyEnable : null,
    ProxyServer: 'ProxyServer' in reg ? reg.ProxyServer : null,
    ProxyOverride: 'ProxyOverride' in reg ? reg.ProxyOverride : null,
    AutoConfigURL: 'AutoConfigURL' in reg ? reg.AutoConfigURL : null
  }) + '\r\n';
  const exec = async (cmd, args) => {
    calls.push({ cmd, args, journal: fs.existsSync(journal) });
    if (cmd === 'powershell') return /Get-ItemProperty/.test(args[args.length - 1]) ? snapshot() : '';
    apply(cmd, args);
    return '';
  };
  const execSync = (cmd, args) => { calls.push({ cmd, args, journal: fs.existsSync(journal), sync: true }); apply(cmd, args); return ''; };
  return { reg, calls, exec, execSync, regCalls: () => calls.filter(c => c.cmd === 'reg').map(c => c.args) };
}

const ON = { host: '127.0.0.1', httpPort: 10809, socksPort: 10808 };
const regAdd = (name, type, data) => ['add', WIN_REG, '/v', name, '/t', type, '/d', String(data), '/f'];
const regDel = (name) => ['delete', WIN_REG, '/v', name, '/f'];

/* ------------------------------- Windows ------------------------------- */

test('win: the previous state is journaled before the first registry write, then ours is set', async (t) => {
  const journal = tmpJournal(t);
  const w = fakeWin(journal, { ProxyEnable: 0, AutoConfigURL: 'http://wpad.corp/proxy.pac' });
  await setSystemProxy(true, Object.assign({ journal, exec: w.exec, platform: 'win32' }, ON));
  const firstReg = w.calls.find(c => c.cmd === 'reg');
  assert.equal(firstReg.journal, true, 'the journal must exist before anything is overwritten — a crash in between still has a record');
  assert.deepEqual(w.regCalls(), [
    regAdd('ProxyEnable', 'REG_DWORD', 1),
    regAdd('ProxyServer', 'REG_SZ', '127.0.0.1:10809'),
    regAdd('ProxyOverride', 'REG_SZ', WIN_BYPASS)
  ], 'what is written is what it always was');
  const j = JSON.parse(fs.readFileSync(journal, 'utf8'));
  assert.deepEqual(j.win, { ProxyEnable: 0, ProxyServer: null, ProxyOverride: null, AutoConfigURL: 'http://wpad.corp/proxy.pac' });
  assert.equal(j.ours, '127.0.0.1:10809');
  // the snapshot and the WinINet refresh both read UTF-8 (see tunPlatform.psArgs)
  for (const c of w.calls.filter(x => x.cmd === 'powershell')) assert.match(c.args[3], /OutputEncoding/);
});

test('win: a corporate proxy comes back exactly — server, bypass list and the switch', async (t) => {
  const journal = tmpJournal(t);
  const corp = { ProxyEnable: 1, ProxyServer: 'proxy.corp:8080', ProxyOverride: '*.corp;<local>', AutoConfigURL: 'http://wpad.corp/p.pac' };
  const w = fakeWin(journal, corp);
  await setSystemProxy(true, Object.assign({ journal, exec: w.exec, platform: 'win32' }, ON));
  assert.equal(w.reg.ProxyServer, '127.0.0.1:10809');
  w.calls.length = 0;
  await setSystemProxy(false, { journal, exec: w.exec, platform: 'win32' });
  assert.deepEqual(w.reg, corp, 'the machine is exactly as it was before the connect');
  assert.deepEqual(w.regCalls()[0], regAdd('ProxyEnable', 'REG_DWORD', 0), 'ours goes off first — the step that matters if the rest fails');
  assert.ok(!w.regCalls().some(a => a.includes('AutoConfigURL')), 'AutoConfigURL is recorded, never written: we never changed it');
  assert.equal(fs.existsSync(journal), false, 'the journal is spent');
  assert.ok(w.calls.some(c => c.cmd === 'powershell'), 'WinINet is told');
});

test('win: a machine that had no proxy values gets none back', async (t) => {
  const journal = tmpJournal(t);
  const w = fakeWin(journal, {});
  await setSystemProxy(true, Object.assign({ journal, exec: w.exec, platform: 'win32' }, ON));
  await setSystemProxy(false, { journal, exec: w.exec, platform: 'win32' });
  assert.deepEqual(w.reg, { ProxyEnable: 0 }, 'ProxyServer and ProxyOverride deleted again; the switch off');
});

test('win: a disable with no journal touches nothing — we never set it', async (t) => {
  const journal = tmpJournal(t);
  const corp = { ProxyEnable: 1, ProxyServer: 'proxy.corp:8080', ProxyOverride: '<local>' };
  const w = fakeWin(journal, corp);
  await setSystemProxy(false, { journal, exec: w.exec, platform: 'win32' });
  assert.deepEqual(w.calls, [], 'a TUN-only session, a quit, an exit: the corporate proxy is not ours to switch off');
  assert.deepEqual(w.reg, corp);
});

test('win: a second enable (a server switch) keeps the ORIGINAL record, never our own proxy as "previous"', async (t) => {
  const journal = tmpJournal(t);
  const w = fakeWin(journal, { ProxyEnable: 1, ProxyServer: 'proxy.corp:8080' });
  await setSystemProxy(true, Object.assign({ journal, exec: w.exec, platform: 'win32' }, ON));
  await setSystemProxy(true, Object.assign({ journal, exec: w.exec, platform: 'win32' }, ON, { httpPort: 20809 }));
  const j = JSON.parse(fs.readFileSync(journal, 'utf8'));
  assert.equal(j.win.ProxyServer, 'proxy.corp:8080');
  assert.equal(j.ours, '127.0.0.1:20809', 'but it knows which proxy is ours now');
  await setSystemProxy(false, { journal, exec: w.exec, platform: 'win32' });
  assert.equal(w.reg.ProxyServer, 'proxy.corp:8080');
  assert.equal(w.reg.ProxyEnable, 1);
});

test('win: an unreadable snapshot still journals — the disable then does what it always did', async (t) => {
  const journal = tmpJournal(t);
  const w = fakeWin(journal, { ProxyEnable: 0 });
  const exec = async (cmd, args) => {
    if (cmd === 'powershell' && /Get-ItemProperty/.test(args[args.length - 1])) throw new Error('powershell is not recognized');
    return w.exec(cmd, args);
  };
  await setSystemProxy(true, Object.assign({ journal, exec, platform: 'win32' }, ON));
  assert.equal(JSON.parse(fs.readFileSync(journal, 'utf8')).win, null);
  w.calls.length = 0;
  await setSystemProxy(false, { journal, exec, platform: 'win32' });
  assert.deepEqual(w.regCalls(), [regAdd('ProxyEnable', 'REG_DWORD', 0)]);
  assert.equal(fs.existsSync(journal), false);
});

test('win: when even switching ours off fails, the journal is kept for the next launch', async (t) => {
  const journal = tmpJournal(t);
  const w = fakeWin(journal, { ProxyEnable: 0 });
  await setSystemProxy(true, Object.assign({ journal, exec: w.exec, platform: 'win32' }, ON));
  const failing = async (cmd, args) => { if (cmd === 'reg') throw new Error('Access is denied.'); return w.exec(cmd, args); };
  await setSystemProxy(false, { journal, exec: failing, platform: 'win32' });
  assert.equal(fs.existsSync(journal), true);
});

test('win launch: a journal a dead session left is restored while the proxy is still ours', async (t) => {
  const journal = tmpJournal(t);
  const w = fakeWin(journal, { ProxyEnable: 1, ProxyServer: 'proxy.corp:8080', ProxyOverride: '<local>' });
  await setSystemProxy(true, Object.assign({ journal, exec: w.exec, platform: 'win32' }, ON));
  // …and the app is killed here. Next launch:
  assert.equal(await repairSystemProxy({ journal, exec: w.exec, platform: 'win32' }), 'restored');
  assert.deepEqual(w.reg, { ProxyEnable: 1, ProxyServer: 'proxy.corp:8080', ProxyOverride: '<local>' });
  assert.equal(fs.existsSync(journal), false);
});

test('win launch: a proxy someone set since the crash is theirs — the stale journal goes, nothing is written', async (t) => {
  const journal = tmpJournal(t);
  const w = fakeWin(journal, { ProxyEnable: 0 });
  await setSystemProxy(true, Object.assign({ journal, exec: w.exec, platform: 'win32' }, ON));
  w.reg.ProxyServer = 'fiddler.local:8888';           // the user fixed it by hand, their way
  w.calls.length = 0;
  assert.equal(await repairSystemProxy({ journal, exec: w.exec, platform: 'win32' }), 'dropped');
  assert.deepEqual(w.regCalls(), []);
  assert.equal(w.reg.ProxyServer, 'fiddler.local:8888');
  assert.equal(fs.existsSync(journal), false);
});

test('win launch: our own proxy left by a build that kept no journal is switched off; anyone else’s is not', async (t) => {
  const journal = tmpJournal(t);
  const legacyServer = '127.0.0.1:10809';   // this app's own HTTP port, from its settings
  // what every build before this one wrote, and left behind after a crash or the update installer
  const w = fakeWin(journal, { ProxyEnable: 1, ProxyServer: '127.0.0.1:10809', ProxyOverride: WIN_BYPASS });
  assert.equal(await repairSystemProxy({ journal, exec: w.exec, platform: 'win32', legacyServer }), 'legacy');
  assert.deepEqual(w.regCalls(), [regAdd('ProxyEnable', 'REG_DWORD', 0)]);
  for (const other of [
    { ProxyEnable: 1, ProxyServer: '127.0.0.1:10809', ProxyOverride: 'localhost;127.*' },   // another client on the same port
    // a sibling build (the Plus fork writes the same bypass list) connected on ITS port right now
    { ProxyEnable: 1, ProxyServer: '127.0.0.1:30819', ProxyOverride: WIN_BYPASS },
    { ProxyEnable: 1, ProxyServer: 'proxy.corp:8080', ProxyOverride: WIN_BYPASS },
    { ProxyEnable: 0, ProxyServer: '127.0.0.1:10809', ProxyOverride: WIN_BYPASS }
  ]) {
    const o = fakeWin(journal, other);
    assert.equal(await repairSystemProxy({ journal, exec: o.exec, platform: 'win32', legacyServer }), null);
    assert.deepEqual(o.regCalls(), [], JSON.stringify(other));
  }
  // not told which port is ours: no guessing
  const n = fakeWin(journal, { ProxyEnable: 1, ProxyServer: '127.0.0.1:10809', ProxyOverride: WIN_BYPASS });
  assert.equal(await repairSystemProxy({ journal, exec: n.exec, platform: 'win32' }), null);
  assert.deepEqual(n.regCalls(), []);
});

test('win exit hook: the journal is restored synchronously, and only when there is one', async (t) => {
  const journal = tmpJournal(t);
  const w = fakeWin(journal, { ProxyEnable: 1, ProxyServer: 'proxy.corp:8080', ProxyOverride: '<local>' });
  assert.equal(restoreSystemProxySync({ journal, execSync: w.execSync, platform: 'win32' }), false);
  assert.deepEqual(w.calls, [], 'no journal, no writes');
  await setSystemProxy(true, Object.assign({ journal, exec: w.exec, platform: 'win32' }, ON));
  w.calls.length = 0;
  assert.equal(restoreSystemProxySync({ journal, execSync: w.execSync, platform: 'win32' }), true);
  assert.ok(w.calls.every(c => c.sync && c.cmd === 'reg'), 'reg only: nothing slow on the way out');
  assert.deepEqual(w.reg, { ProxyEnable: 1, ProxyServer: 'proxy.corp:8080', ProxyOverride: '<local>' });
  assert.equal(fs.existsSync(journal), false);
});

test('the launch repair and a connect cannot interleave: the repair finishes before the connect snapshots', async (t) => {
  const journal = tmpJournal(t);
  const w = fakeWin(journal, { ProxyEnable: 0 });
  await setSystemProxy(true, Object.assign({ journal, exec: w.exec, platform: 'win32' }, ON));   // the dead session
  let release;
  const gate = new Promise((r) => { release = r; });
  const slow = async (cmd, args) => { if (cmd === 'powershell') await gate; return w.exec(cmd, args); };
  const repair = repairSystemProxy({ journal, exec: slow, platform: 'win32' });
  const connect = setSystemProxy(true, Object.assign({ journal, exec: w.exec, platform: 'win32' }, ON));
  await new Promise((r) => setImmediate(r));
  assert.equal(w.reg.ProxyServer, '127.0.0.1:10809');
  release();
  await Promise.all([repair, connect]);
  assert.equal(w.reg.ProxyEnable, 1, 'the connect that came second is the state that stays');
  assert.equal(JSON.parse(fs.readFileSync(journal, 'utf8')).win.ProxyEnable, 0, 'and its journal holds the true original');
});

test('without a journal configured (the headless service) the old behaviour stands', async () => {
  const calls = [];
  const exec = async (cmd, args) => { calls.push([cmd, ...args]); return ''; };
  useProxyJournal(null);
  await setSystemProxy(false, { exec, platform: 'win32' });
  assert.deepEqual(calls[0], ['reg', ...regAdd('ProxyEnable', 'REG_DWORD', 0)]);
});

/* ------------------------------- macOS (blind) ------------------------------- */

const LISTING = 'An asterisk (*) denotes that a network service is disabled.\nWi-Fi\nUSB LAN\n';
const PROXY = (enabled, server, port) => `Enabled: ${enabled ? 'Yes' : 'No'}\nServer: ${server}\nPort: ${port}\nAuthenticated Proxy Enabled: 0\n`;

function fakeMac(state) {
  const calls = [];
  const exec = async (cmd, args) => {
    calls.push([cmd, ...args]);
    if (args[0] === '-listallnetworkservices') return LISTING;
    const get = { '-getwebproxy': 'web', '-getsecurewebproxy': 'secure', '-getsocksfirewallproxy': 'socks' }[args[0]];
    if (get) { const s = (state[args[1]] || {})[get] || { enabled: false, server: '', port: 0 }; return PROXY(s.enabled, s.server, s.port); }
    return '';
  };
  return { calls, exec, sets: () => calls.filter(c => /^-set/.test(c[1])) };
}

test('mac: each service’s three proxies are journaled, then ours set; the disable puts each back as it was', async (t) => {
  const journal = tmpJournal(t);
  const m = fakeMac({ 'Wi-Fi': { web: { enabled: true, server: 'proxy.corp', port: 3128 }, secure: { enabled: false, server: 'proxy.corp', port: 3128 } } });
  await setSystemProxy(true, Object.assign({ journal, exec: m.exec, platform: 'darwin' }, ON));
  const j = JSON.parse(fs.readFileSync(journal, 'utf8'));
  assert.deepEqual(j.mac.map(s => s.name), ['Wi-Fi', 'USB LAN']);
  assert.deepEqual(j.mac[0].web, { enabled: true, server: 'proxy.corp', port: 3128 });
  assert.ok(m.sets().some(c => c.join(' ') === 'networksetup -setwebproxy Wi-Fi 127.0.0.1 10809'), 'ours set as before');
  m.calls.length = 0;
  await setSystemProxy(false, { journal, exec: m.exec, platform: 'darwin' });
  const lines = m.sets().map(c => c.slice(1).join(' '));
  assert.deepEqual(lines.filter(l => / Wi-Fi/.test(l)), [
    '-setwebproxy Wi-Fi proxy.corp 3128',                 // was on: server back, and -setwebproxy turns it on
    '-setsecurewebproxy Wi-Fi proxy.corp 3128', '-setsecurewebproxystate Wi-Fi off',   // configured but off
    '-setsocksfirewallproxystate Wi-Fi off'               // never configured
  ]);
  assert.ok(lines.includes('-setwebproxystate USB LAN off'));
  assert.equal(fs.existsSync(journal), false);
});

test('mac: a snapshot that could not be read still gets ours switched off on every service', async (t) => {
  const journal = tmpJournal(t);
  const m = fakeMac({});
  let listing = 0;
  const flaky = async (cmd, args) => {
    // the snapshot's listing fails; enable's own listing, later, works
    if (args[0] === '-listallnetworkservices' && listing++ === 0) throw new Error('networksetup: timed out');
    return m.exec(cmd, args);
  };
  await setSystemProxy(true, Object.assign({ journal, exec: flaky, platform: 'darwin' }, ON));
  assert.equal(JSON.parse(fs.readFileSync(journal, 'utf8')).mac, null, 'unknown, not "no services"');
  m.calls.length = 0;
  await setSystemProxy(false, { journal, exec: m.exec, platform: 'darwin' });
  const offs = m.sets().map(c => c.slice(1).join(' '));
  for (const svc of ['Wi-Fi', 'USB LAN']) {
    for (const verb of ['-setwebproxystate', '-setsecurewebproxystate', '-setsocksfirewallproxystate']) {
      assert.ok(offs.includes(`${verb} ${svc} off`), `${verb} ${svc} off — the old disable, not nothing`);
    }
  }
  assert.equal(fs.existsSync(journal), false);
});

test('mac: no journal, no writes; a refused enable leaves no journal behind', async (t) => {
  const journal = tmpJournal(t);
  const m = fakeMac({});
  await setSystemProxy(false, { journal, exec: m.exec, platform: 'darwin' });
  assert.deepEqual(m.sets(), []);
  const refusing = async (cmd, args) => { if (/^-set/.test(args[0])) throw new Error('You must be an administrator'); return m.exec(cmd, args); };
  await assert.rejects(setSystemProxy(true, Object.assign({ journal, exec: refusing, platform: 'darwin' }, ON)), /administrator/);
  assert.equal(fs.existsSync(journal), false, 'nothing was set, so there is nothing to put back');
});
