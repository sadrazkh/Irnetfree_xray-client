'use strict';
/**
 * The headless server must answer a malformed request, never die of it.
 *
 * On a router this process IS the gateway: when it exits, the exit hook tears
 * the tunnel down and the whole LAN goes direct (and procd stops respawning
 * after five crashes an hour). `new URL(req.url, …)` throws for a request
 * target such as `//x:99999/` — and inside the async request handler that
 * throw was an unhandled rejection, which ends Node ≥ 15. No token needed:
 * the URL is parsed before the token is checked, so any host on the LAN could
 * stop the service with one line.
 *
 * The real server.js runs here as a child on an ephemeral loopback port, in a
 * temp data dir, with no router env and nothing to connect — it binds nothing
 * else and is killed (SIGKILL: no shutdown path runs) when the test ends.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn, spawnSync } = require('node:child_process');
const net = require('node:net');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const SERVER = path.join(__dirname, '..', 'src', 'server', 'server.js');

function startServer(dir, extra = []) {
  return new Promise((resolve, reject) => {
    const env = Object.assign({}, process.env);
    delete env.IRNETFREE_PLATFORM;
    // A Ctrl+C on `npm test` reaches this child too, and its shutdown turns the
    // system proxy off — on Windows a registry write on whoever ran the suite.
    env.IRNETFREE_NO_SYSTEM_PROXY = '1';
    const child = spawn(process.execPath, [SERVER, '--port', '0', '--host', '127.0.0.1', '--data-dir', dir, ...extra],
      { env, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    let out = '';
    let done = false;
    const timer = setTimeout(() => { if (!done) { done = true; child.kill('SIGKILL'); reject(new Error('the server did not start:\n' + out)); } }, 30000);
    const onData = (d) => {
      out += d;
      // the whole banner: its last line on a loopback bind (it can arrive in several chunks)
      const m = /Listening: http:\/\/127\.0\.0\.1:(\d+)\/[\s\S]*in your browser\./.exec(out);
      if (m && !done) { done = true; clearTimeout(timer); resolve({ child, port: Number(m[1]), out: () => out }); }
    };
    child.stdout.on('data', onData);
    child.stderr.on('data', onData);
    child.on('exit', (code) => {
      if (done) return;
      done = true; clearTimeout(timer);
      reject(new Error(`the server exited (${code}) before it listened:\n${out}`));
    });
  });
}

/** One raw request over TCP; resolves with whatever came back before the socket closed. */
function raw(port, text) {
  return new Promise((resolve) => {
    let buf = '';
    const s = net.connect({ host: '127.0.0.1', port }, () => s.write(text));
    s.setEncoding('utf8');
    s.on('data', (d) => { buf += d; });
    s.on('close', () => resolve(buf));
    s.on('error', () => { /* a reset reads as whatever arrived before it */ });
    s.setTimeout(10000, () => s.destroy());
  });
}

const request = (target) => `GET ${target} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n`;

function tempDir() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-server-'));
  // no subscription timer, no asset updater, no connect at start
  fs.writeFileSync(path.join(dir, 'store.json'), JSON.stringify({ settings: { autoUpdateSubs: false, autoUpdateAssets: 'off', autoConnect: false } }));
  return dir;
}

test('a request target URL cannot parse is a 400, and the server keeps answering', async (t) => {
  const dir = tempDir();
  const srv = await startServer(dir);
  t.after(() => { try { srv.child.kill('SIGKILL'); } catch {} try { fs.rmSync(dir, { recursive: true, force: true }); } catch {} });

  for (const target of ['//x:99999/', '//[', 'http://[']) {
    const res = await raw(srv.port, request(target));
    assert.match(res, /^HTTP\/1\.1 400 /, `${target}: ${JSON.stringify(res.slice(0, 80))}\n${srv.out()}`);
  }
  const ok = await raw(srv.port, request('/web-api.js'));
  assert.match(ok, /^HTTP\/1\.1 200 /, 'still serving after the bad requests');
  assert.equal(srv.child.exitCode, null, 'the process is still alive');
});

test('IRNETFREE_NO_SYSTEM_PROXY=1: the service never touches the system proxy, not even on shutdown — and says so at start', () => {
  // Run in a child with every proxy function that reaches the machine replaced
  // by a spy BEFORE the service loads the module — so even a failing check can
  // only ever call a spy (this child runs without the suite's no-network guard).
  const dir = tempDir();
  const script = `
    const sysproxy = require(${JSON.stringify(path.join(__dirname, '..', 'src', 'main', 'sysproxy.js'))});
    const calls = { set: 0, repair: 0, journal: 0 };
    sysproxy.setSystemProxy = async () => { calls.set++; };
    sysproxy.repairSystemProxy = async () => { calls.repair++; return null; };
    sysproxy.useProxyJournal = () => { calls.journal++; };
    sysproxy.restoreSystemProxySync = () => false;
    const { createService } = require(${JSON.stringify(path.join(__dirname, '..', 'src', 'server', 'service.js'))});
    const svc = createService({ dataDir: ${JSON.stringify(dir)} });
    svc.shutdown().then(() => { console.log('CALLS ' + calls.set + ' REPAIR ' + calls.repair + ' JOURNAL ' + calls.journal); process.exit(0); });
  `;
  const run = (env) => spawnSync(process.execPath, ['-e', script], { env: Object.assign({}, process.env, env, { IRNETFREE_PLATFORM: '' }), encoding: 'utf8', timeout: 30000, windowsHide: true });
  try {
    const off = run({ IRNETFREE_NO_SYSTEM_PROXY: '1' });
    assert.match(off.stdout, /^CALLS 0 REPAIR 0 JOURNAL 0$/m, off.stdout + off.stderr);
    assert.match(off.stdout + off.stderr, /IRNETFREE_NO_SYSTEM_PROXY=1 .*test-only/, 'one line at start says the switch is on');
    const on = run({ IRNETFREE_NO_SYSTEM_PROXY: '' });   // the spies show the switch is what made the difference
    // …and without it the service journals the proxy like the desktop does, and repairs a dead session's at start
    assert.match(on.stdout, /^CALLS 1 REPAIR 1 JOURNAL 1$/m, on.stdout + on.stderr);
    assert.doesNotMatch(on.stdout + on.stderr, /IRNETFREE_NO_SYSTEM_PROXY/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('the entry logs a stray rejection instead of dying of it; the handler cannot reject', () => {
  const src = fs.readFileSync(SERVER, 'utf8');
  assert.match(src, /process\.on\('unhandledRejection'/);
  assert.match(src, /handle\(req, res\)\.catch\(/, 'every request goes through one catch');
  assert.match(src, /if \(!res\.headersSent\) res\.writeHead\(500/, 'a failure after the headers only ends the response');
});

test('--token-file: the token is read from (or made in) the file, and never printed', async (t) => {
  const dir = tempDir();
  const file = path.join(dir, 'token');
  fs.writeFileSync(file, 'c0ffee00c0ffee00c0ffee00c0ffee00\n');
  const srv = await startServer(dir, ['--token-file', file]);
  t.after(() => { try { srv.child.kill('SIGKILL'); } catch {} try { fs.rmSync(dir, { recursive: true, force: true }); } catch {} });
  assert.doesNotMatch(srv.out(), /c0ffee00c0ffee00/, 'the banner (syslog on a router) does not carry the token');
  assert.match(srv.out(), new RegExp('Token\\s*: ' + file.replace(/[\\^$.*+?()[\]{}|]/g, '\\$&')), 'it says where the token lives');
  // the token from the file is the one that is enforced (a loopback bind with a token still checks it)
  assert.match(await raw(srv.port, request('/')), /^HTTP\/1\.1 401 /);
  assert.match(await raw(srv.port, request('/?token=c0ffee00c0ffee00c0ffee00c0ffee00')), /^HTTP\/1\.1 200 /);

  // a missing file is created, root-readable only, and used
  const dir2 = tempDir();
  const file2 = path.join(dir2, 'sub', 'token');
  const srv2 = await startServer(dir2, ['--token-file', file2]);
  t.after(() => { try { srv2.child.kill('SIGKILL'); } catch {} try { fs.rmSync(dir2, { recursive: true, force: true }); } catch {} });
  const made = fs.readFileSync(file2, 'utf8').trim();
  assert.match(made, /^[0-9a-f]{32}$/);
  if (process.platform !== 'win32') assert.equal(fs.statSync(file2).mode & 0o077, 0, 'no group/other access');
  assert.doesNotMatch(srv2.out(), new RegExp(made));
  assert.match(await raw(srv2.port, request('/?token=' + made)), /^HTTP\/1\.1 200 /);
});

/* ------------------------- S5 (v1.16): the service never stays dead ------------------------- */

const child = require('./serverChild');

test('S5: an uncaught exception ends in an orderly exit (code 1) that procd restarts, said with the irnetfree prefix', async (t) => {
  const dir = child.tempDir();
  const srv = await child.startServer(dir, [], { IRNETFREE_TEST_THROW_MS: '300' });
  t.after(() => child.stop(srv, dir));
  const exit = await Promise.race([srv.exit, new Promise((_, rej) => setTimeout(() => rej(new Error('the process did not exit:\n' + srv.out())), 20000))]);
  assert.equal(exit.code, 1, srv.out());
  assert.match(srv.out(), /^irnetfree: \[fatal\] Error: IRNETFREE_TEST_THROW_MS/m, srv.out());
  assert.match(srv.out(), /shutting down for procd to restart/);
});

test('S5: every line the server writes starts with irnetfree: (the banner too) — and the token is never among them', async (t) => {
  const dir = child.tempDir();
  const file = path.join(dir, 'token');
  fs.writeFileSync(file, 'deadbeefdeadbeefdeadbeefdeadbeef\n');
  const srv = await child.startServer(dir, ['--token-file', file]);
  t.after(() => child.stop(srv, dir));
  await raw(srv.port, request('//['));   // a 400 the server logs nothing for; the banner is what we read
  const lines = srv.out().split(/\r?\n/).filter((l) => l.length);
  assert.ok(lines.length >= 4, srv.out());
  for (const l of lines) assert.match(l, /^irnetfree: /, `unprefixed line: ${JSON.stringify(l)}`);
  assert.ok(!lines.some((l) => l.trim() === 'irnetfree:'), 'no empty prefixed lines');
  assert.doesNotMatch(srv.out(), /deadbeefdeadbeef/);
  assert.match(srv.out(), /irnetfree: {3}Listening: http:\/\/127\.0\.0\.1:\d+\//);
});

test('S5: the token is compared in constant time — by behaviour: the right one 200, a wrong one of the same length 401, a wrong length 401', async (t) => {
  const dir = child.tempDir();
  const TOKEN = '0123456789abcdef0123456789abcdef';
  const srv = await child.startServer(dir, ['--token', TOKEN]);
  t.after(() => child.stop(srv, dir));
  assert.match(await raw(srv.port, request('/?token=' + TOKEN)), /^HTTP\/1\.1 200 /);
  assert.match(await raw(srv.port, request('/?token=' + TOKEN.slice(0, -1) + '0')), /^HTTP\/1\.1 401 /, 'same length, last character off');
  assert.match(await raw(srv.port, request('/?token=' + TOKEN.slice(0, 8))), /^HTTP\/1\.1 401 /, 'a prefix of it');
  assert.match(await raw(srv.port, request('/?token=' + TOKEN + '0')), /^HTTP\/1\.1 401 /, 'one character more');
  assert.match(await raw(srv.port, request('/')), /^HTTP\/1\.1 401 /);
  const src = fs.readFileSync(SERVER, 'utf8');
  assert.match(src, /function safeEqual\(a, b\)[\s\S]*crypto\.timingSafeEqual\(x, y\)/);
  assert.match(src, /return safeEqual\(q, TOKEN\) \|\| safeEqual\(h, TOKEN\);/);
});

test('S5: app:quit on the headless service answers, then the process exits (procd restarts it) — never "quitting but alive"', async (t) => {
  const dir = child.tempDir();
  const srv = await child.startServer(dir);
  t.after(() => child.stop(srv, dir));
  const r = await child.request(srv.port, { method: 'POST', path: '/rpc', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ channel: 'app:quit' }) });
  assert.equal(r.status, 200, r.body);
  assert.deepEqual(r.json, { result: { ok: true, exiting: true } });
  const exit = await Promise.race([srv.exit, new Promise((_, rej) => setTimeout(() => rej(new Error('still alive after app:quit:\n' + srv.out())), 15000))]);
  assert.equal(exit.code, 0, srv.out());
});
