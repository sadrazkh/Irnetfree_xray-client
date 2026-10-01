'use strict';
/**
 * The rpcd plugin behind LuCI's IRNetFree pages (openwrt/files/rpcd/luci.irnetfree,
 * shipped as /usr/libexec/rpcd/luci.irnetfree). rpcd runs it as
 * `luci.irnetfree list` once at start (the methods it declares become the ubus
 * object luci.irnetfree) and `luci.irnetfree call <method>` with the ubus
 * arguments as JSON on stdin; whatever JSON object it prints is the reply.
 *
 * Checked here: what it declares, that it is POSIX sh, that the UI token never
 * reaches a command line — and, run for real by this machine's sh against fake
 * uci / uclient-fetch / jsonfilter and a stub of the service's local API
 * (POST /luci/<method>, the A9 facade), that every call arrives with the token
 * and the argument and every way the service can fail comes back as a JSON
 * object (rpcd turns anything else, a bare array included, into an error).
 * busybox ash under rpcd is what the QEMU job runs it with.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { spawn, spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const PLUGIN = path.join(ROOT, 'openwrt', 'files', 'rpcd', 'luci.irnetfree');

/** The facade's methods (spec §3.4, the A9 contract) — and `service`, the plugin's own. */
const FACADE = ['status', 'configs', 'connect', 'select', 'disconnect', 'reconnect', 'test', 'subs_update',
  'settings_get', 'settings_set', 'devices', 'log', 'diagnostics', 'remote_get', 'remote_set', 'remote_status',
  'cloudflared_install'];

const src = () => fs.readFileSync(PLUGIN, 'utf8');
/** The `list` reply, read from the file's heredoc. */
function declared() {
  const m = /^list\)\n\tcat <<'EOF'\n([\s\S]*?)\nEOF$/m.exec(src());
  assert.ok(m, 'list prints a quoted heredoc');
  return JSON.parse(m[1]);
}

/** ash is not bash: the same list openwrtPackage.test.js holds every router script to. */
const BASHISMS = [
  [/\[\[/, '[[ ]]'],
  [/^\s*function\s+\w+\s*\(?/m, 'function keyword'],
  [/\$\{\w+\[[@*0-9]/, 'arrays'],
  [/\$'/, "$'…' quoting"],
  [/\[ [^\]\n]*[^=!]==[^=]/, '== inside [ ]'],
  [/\bdeclare\b|\btypeset\b/, 'declare'],
  [/^\s*source\s/m, 'source (use .)'],
  [/&>/, '&> redirection'],
  [/\bpushd\b|\bpopd\b/, 'pushd/popd'],
  [/<<<\s/, 'here-string'],
  [/^\s*local\s+\w+=\$\(/m, 'local x=$(…) hides the exit code'],
  [/\becho -e\b/, 'echo -e']
];

test('the plugin is a POSIX sh script, LF only, with no bashisms', () => {
  const s = src();
  assert.match(s, /^#!\/bin\/sh\n/, 'a /bin/sh shebang (rpcd execs the file itself)');
  assert.ok(!s.includes('\r'), 'LF only');
  for (const [re, what] of BASHISMS) assert.doesNotMatch(s, re, what);
});

test('list: one JSON object, every facade method plus service, with argument types rpcd understands', () => {
  const list = declared();
  assert.deepEqual(Object.keys(list).sort(), [...FACADE, 'service'].sort());
  for (const [m, sig] of Object.entries(list)) assert.ok(sig && typeof sig === 'object' && !Array.isArray(sig), `${m}: a signature object`);
  // rpcd reads the JSON type of each sample value: string, number (int32), boolean, array, object
  assert.deepEqual(list.connect, { id: 'str' });
  assert.deepEqual(list.select, { id: 'str' });
  assert.deepEqual(list.settings_set, { autoConnect: true, killSwitch: true, lanBlockQuic: true, lanBypassMacs: [] });
  assert.deepEqual(list.log, { lines: 300 });
  assert.deepEqual(list.remote_set, { relay: {}, cloudflared: {} });
  assert.deepEqual(list.service, { action: 'str' });
  for (const m of ['status', 'configs', 'disconnect', 'reconnect', 'test', 'subs_update', 'settings_get', 'devices',
    'diagnostics', 'remote_get', 'remote_status', 'cloudflared_install']) assert.deepEqual(list[m], {}, m);
  // the forwarding whitelist and the declared methods are the same set
  const methods = /^METHODS='([^']*)'$/m.exec(src());
  assert.ok(methods, 'a METHODS whitelist');
  assert.deepEqual(methods[1].split(' ').sort(), [...FACADE].sort());
});

test('the token never reaches a command line or a shell variable — the file goes straight into the request body', () => {
  const s = src();
  assert.doesNotMatch(s, /\$\{?token\b/, 'no $token expansion anywhere (an argument shows in ps)');
  assert.doesNotMatch(s, /token=/, 'no token= in a URL or an assignment');
  assert.doesNotMatch(s, /--post-data/, 'the body travels as a file, never in argv');
  assert.match(s, /--post-file="\$tmp"/);
  assert.match(s, /tr -d '\\r\\n' < "\$data_dir\/token"/, 'the token file is redirected into the body, not read into a variable');
  assert.match(s, /mktemp \/tmp\/irnf-luci\.XXXXXX/, 'a private (0600) temp file');
  assert.match(s, /trap 'rm -f "\$tmp"[^']*' EXIT/, 'removed on every way out');
  assert.match(s, /http:\/\/127\.0\.0\.1:\$port\/luci\/\$method/, 'loopback only');
});

/* ------------------------------ run it for real ------------------------------ */

function findSh() {
  if (process.platform !== 'win32') return '/bin/sh';
  for (const p of ['C:/Program Files/Git/usr/bin/sh.exe', 'C:/Program Files/Git/bin/sh.exe']) if (fs.existsSync(p)) return p;
  return null;
}
const SH = findSh();

test('sh -n: the shell itself parses the plugin', (t) => {
  if (!SH) return t.skip('no POSIX sh here');
  const r = spawnSync(SH, ['-n', PLUGIN], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
});

const FAKE_UCI = `#!/usr/bin/env node
// uci -q get <key>, answered from the JSON object in FAKE_UCI_JSON
const a = process.argv.slice(2).filter((x) => x !== '-q');
if (a[0] !== 'get') process.exit(2);
const v = JSON.parse(process.env.FAKE_UCI_JSON || '{}')[a[1]];
if (v == null) process.exit(1);
console.log(v);
`;
// uclient-fetch, the part the plugin uses (-T <s> -O - --post-file=<f> <url>). Like
// the real one: the body on stdout only for 200/204; any other status prints
// "HTTP error <code>" on stderr and exits 8 (the body is dropped); no
// connection exits 4. Its argv and what it posted are kept for the test.
const FAKE_FETCH = `#!/usr/bin/env node
const fs = require('fs');
const http = require('http');
const argv = process.argv.slice(2);
let url = null, postFile = null, out = null, timeout = 10;
for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (a === '-T') timeout = Number(argv[++i]);
  else if (a === '-O') out = argv[++i];
  else if (a.startsWith('--post-file=')) postFile = a.slice('--post-file='.length);
  else if (a.startsWith('-')) { console.error('unexpected option ' + a); process.exit(2); }
  else url = a;
}
const body = postFile ? fs.readFileSync(postFile) : null;
fs.appendFileSync(process.env.FAKE_FETCH_LOG, JSON.stringify({ argv, postFile, out, body: body && body.toString('utf8') }) + '\\n');
// the default port may be a real IRNetFree on the machine running the tests: never touch it
if (/^http:\\/\\/127\\.0\\.0\\.1:6969\\//.test(url)) { process.stderr.write('Connection failed\\n'); process.exit(4); }
const req = http.request(url, { method: body ? 'POST' : 'GET', timeout: timeout * 1000,
  headers: body ? { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': body.length } : {} }, (res) => {
  const chunks = [];
  res.on('data', (c) => chunks.push(c));
  res.on('end', () => {
    if (res.statusCode === 200 || res.statusCode === 204) { process.stdout.write(Buffer.concat(chunks)); process.exit(0); }
    process.stderr.write('HTTP error ' + res.statusCode + '\\n');
    process.exit(8);
  });
});
req.on('timeout', () => { process.stderr.write('Connection timed out\\n'); process.exit(4); });
req.on('error', () => { process.stderr.write('Connection failed\\n'); process.exit(4); });
if (body) req.write(body);
req.end();
`;
// jsonfilter -e '@.<key>' over stdin, the one form the plugin uses
const FAKE_JSONFILTER = `#!/usr/bin/env node
const fs = require('fs');
const expr = process.argv[process.argv.indexOf('-e') + 1] || '';
const m = /^@\\.(\\w+)$/.exec(expr);
if (!m) process.exit(2);
let v;
try { v = JSON.parse(fs.readFileSync(0, 'utf8'))[m[1]]; } catch (e) { process.exit(1); }
if (v == null || typeof v === 'object') process.exit(1);
console.log(String(v));
`;

/** A stub of the service's /luci/<method> API on an ephemeral loopback port. */
function stubFacade() {
  const seen = [];
  const stub = { seen, reply: () => [200, { ok: true }] };
  stub.server = http.createServer((req, res) => {
    let body = '';
    req.setEncoding('utf8');
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      seen.push({ method: req.method, url: req.url, body });
      const [code, json] = stub.reply(req.url.replace(/^\/luci\//, ''), body);
      const text = json === undefined ? '' : JSON.stringify(json);   // undefined: an empty body
      res.writeHead(code, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(text) });
      res.end(text);
    });
  });
  return new Promise((resolve) => stub.server.listen(0, '127.0.0.1', () => { stub.port = stub.server.address().port; resolve(stub); }));
}

const TOKEN = 'a1b2c3d4e5f60718293a4b5c6d7e8f90';

function setup(t) {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-luciplug-'));
  t.after(() => { try { fs.rmSync(work, { recursive: true, force: true }); } catch {} });
  const bin = path.join(work, 'bin');
  const data = path.join(work, 'data');
  fs.mkdirSync(bin);
  fs.mkdirSync(data);
  fs.writeFileSync(path.join(bin, 'uci'), FAKE_UCI, { mode: 0o755 });
  fs.writeFileSync(path.join(bin, 'uclient-fetch'), FAKE_FETCH, { mode: 0o755 });
  fs.writeFileSync(path.join(bin, 'jsonfilter'), FAKE_JSONFILTER, { mode: 0o755 });
  fs.writeFileSync(path.join(data, 'token'), TOKEN + '\n', { mode: 0o600 });
  const log = path.join(work, 'fetch.log');
  fs.writeFileSync(log, '');
  // forward slashes: the shell gets this path through `uci get`, and an MSYS sh on Windows takes C:/… but not C:\…
  const dataDir = data.split(path.sep).join('/');
  return { work, bin, data, dataDir, log };
}

/** Run `luci.irnetfree <args>` with `input` on stdin; resolve with { code, out, json }. */
function plugin(env, args, input) {
  return new Promise((resolve, reject) => {
    const child = spawn(SH, [PLUGIN, ...args], { env, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
    let out = '', err = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { err += d; });
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('the plugin hung: ' + err)); }, 30000);
    child.on('error', reject);
    child.on('close', (code) => {
      clearTimeout(timer);
      let json = null;
      try { json = JSON.parse(out); } catch { /* asserted by the caller */ }
      resolve({ code, out, err, json });
    });
    if (input != null) child.stdin.end(input); else child.stdin.end();
  });
}

function envFor(box, uci) {
  return Object.assign({}, process.env, {
    PATH: box.bin + path.delimiter + path.dirname(process.execPath) + path.delimiter + process.env.PATH,
    FAKE_UCI_JSON: JSON.stringify(uci),
    FAKE_FETCH_LOG: box.log
  });
}
const fetches = (box) => fs.readFileSync(box.log, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));

test('list, run by the shell, prints exactly the declared object', async (t) => {
  if (!SH) return t.skip('no POSIX sh here');
  const box = setup(t);
  const r = await plugin(envFor(box, {}), ['list'], '');
  assert.equal(r.code, 0, r.err);
  assert.deepEqual(r.json, declared());
});

test('call: each method is POSTed to 127.0.0.1:<uci port>/luci/<method> with the token file and the ubus arguments', async (t) => {
  if (!SH) return t.skip('no POSIX sh here');
  const box = setup(t);
  const stub = await stubFacade();
  t.after(() => stub.server.close());
  const env = envFor(box, { 'irnetfree.main.port': String(stub.port), 'irnetfree.main.data_dir': box.dataDir });

  stub.reply = (m) => [200, { state: 'connected', method: m }];
  // rpcd hands an argument-less call `{ }` on stdin
  let r = await plugin(env, ['call', 'status'], '{ }');
  assert.equal(r.code, 0, r.err);
  assert.deepEqual(r.json, { state: 'connected', method: 'status' }, r.out);
  assert.equal(stub.seen.length, 1);
  assert.equal(stub.seen[0].method, 'POST');
  assert.equal(stub.seen[0].url, '/luci/status');
  assert.deepEqual(JSON.parse(stub.seen[0].body), { token: TOKEN, arg: {} }, 'the token from the file, CR/LF trimmed, and the argument');

  r = await plugin(env, ['call', 'connect'], '{ "id": "srv-1" }');
  assert.deepEqual(JSON.parse(stub.seen[1].body), { token: TOKEN, arg: { id: 'srv-1' } });
  assert.equal(stub.seen[1].url, '/luci/connect');
  r = await plugin(env, ['call', 'settings_set'], '{ "killSwitch": true, "lanBypassMacs": [ "aa:bb:cc:dd:ee:ff" ] }');
  assert.deepEqual(JSON.parse(stub.seen[2].body).arg, { killSwitch: true, lanBypassMacs: ['aa:bb:cc:dd:ee:ff'] });
  // nothing at all on stdin still makes a valid body
  r = await plugin(env, ['call', 'disconnect'], '');
  assert.deepEqual(JSON.parse(stub.seen[3].body), { token: TOKEN, arg: {} });

  // the token was never on a command line, and the body file is gone
  for (const f of fetches(box)) {
    assert.ok(!f.argv.join(' ').includes(TOKEN), 'the token is not in uclient-fetch argv');
    assert.deepEqual(f.argv.slice(0, 3), ['-T', '30', '-O']);
    assert.equal(f.out, '-');
    assert.ok(f.postFile && /irnf-luci\./.test(f.postFile), f.postFile);
    assert.equal(fs.existsSync(f.postFile), false, `the temp body ${f.postFile} was left behind`);
    assert.match(f.argv[f.argv.length - 1], new RegExp(`^http://127\\.0\\.0\\.1:${stub.port}/luci/[a-z_]+$`));
  }
});

test('call: a bare array reply (devices) is wrapped as {"result": […]} — rpcd only carries objects', async (t) => {
  if (!SH) return t.skip('no POSIX sh here');
  const box = setup(t);
  const stub = await stubFacade();
  t.after(() => stub.server.close());
  const env = envFor(box, { 'irnetfree.main.port': String(stub.port), 'irnetfree.main.data_dir': box.dataDir });
  const devs = [{ mac: 'aa:bb:cc:dd:ee:ff', ip: '192.168.1.20', name: 'laptop', bypass: false }];
  stub.reply = () => [200, devs];
  const r = await plugin(env, ['call', 'devices'], '{ }');
  assert.deepEqual(r.json, { result: devs }, r.out);
});

test('call: every way the service can fail is a JSON object with an error the pages understand', async (t) => {
  if (!SH) return t.skip('no POSIX sh here');
  const box = setup(t);
  const stub = await stubFacade();
  t.after(() => stub.server.close());
  const env = envFor(box, { 'irnetfree.main.port': String(stub.port), 'irnetfree.main.data_dir': box.dataDir });

  stub.reply = () => [401, { error: 'unauthorized' }];
  assert.deepEqual((await plugin(env, ['call', 'status'], '{ }')).json, { error: 'unauthorized' });
  // uclient-fetch drops the body of any non-2xx reply: the status code is all that is left
  stub.reply = () => [400, { error: 'bad MAC' }];
  assert.deepEqual((await plugin(env, ['call', 'settings_set'], '{ }')).json, { error: 'http 400' });
  stub.reply = () => [500, { error: 'boom' }];
  assert.deepEqual((await plugin(env, ['call', 'status'], '{ }')).json, { error: 'http 500' });
  // a service from before the facade answers POST /luci/* with 405
  stub.reply = () => [405, { error: 'method not allowed' }];
  assert.deepEqual((await plugin(env, ['call', 'status'], '{ }')).json, { error: 'http 405' });
  // an empty 200 is not a reply, and neither is JSON that is not an object or an array
  stub.reply = () => [200, undefined];
  assert.deepEqual((await plugin(env, ['call', 'status'], '{ }')).json, { error: 'empty reply' });
  stub.reply = () => [200, 'just a string'];
  assert.deepEqual((await plugin(env, ['call', 'status'], '{ }')).json, { error: 'bad reply' });

  // nothing listening on the port: the service is not running
  const closed = await new Promise((resolve) => stub.server.close(() => resolve(stub.port)));
  const r = await plugin(envFor(box, { 'irnetfree.main.port': String(closed), 'irnetfree.main.data_dir': box.dataDir }), ['call', 'status'], '{ }');
  assert.deepEqual(r.json, { error: 'not-running' }, r.out + r.err);
});

test('call: an unknown method never leaves the plugin; uci gives the port, 6969 when unset', async (t) => {
  if (!SH) return t.skip('no POSIX sh here');
  const box = setup(t);
  const stub = await stubFacade();
  t.after(() => stub.server.close());
  let r = await plugin(envFor(box, { 'irnetfree.main.port': String(stub.port), 'irnetfree.main.data_dir': box.dataDir }), ['call', 'nope'], '{ }');
  assert.deepEqual(r.json, { error: 'unknown method' });
  r = await plugin(envFor(box, { 'irnetfree.main.port': String(stub.port) }), ['call', '../../x'], '{ }');
  assert.deepEqual(r.json, { error: 'unknown method' });
  assert.equal(stub.seen.length, 0, 'nothing was forwarded');
  assert.equal(fetches(box).length, 0, 'uclient-fetch never ran');
  // no port in uci (or garbage): the default
  await plugin(envFor(box, { 'irnetfree.main.data_dir': box.dataDir }), ['call', 'status'], '{ }');
  await plugin(envFor(box, { 'irnetfree.main.port': '80 http://evil', 'irnetfree.main.data_dir': box.dataDir }), ['call', 'status'], '{ }');
  const urls = fetches(box).map((f) => f.argv[f.argv.length - 1]);
  assert.deepEqual(urls, ['http://127.0.0.1:6969/luci/status', 'http://127.0.0.1:6969/luci/status']);
});

test('call service: only start and restart, answered by the plugin itself', async (t) => {
  if (!SH) return t.skip('no POSIX sh here');
  const box = setup(t);
  const env = envFor(box, {});
  assert.deepEqual((await plugin(env, ['call', 'service'], '{ "action": "stop" }')).json, { error: 'bad action' });
  assert.deepEqual((await plugin(env, ['call', 'service'], '{ }')).json, { error: 'bad action' });
  assert.deepEqual((await plugin(env, ['call', 'service'], '{ "action": "start; reboot" }')).json, { error: 'bad action' });
  // start where there is no init script (this machine): an error, not a fake success
  const r = await plugin(env, ['call', 'service'], '{ "action": "start" }');
  assert.ok(r.json && typeof r.json.error === 'string', r.out);
  assert.equal(fetches(box).length, 0, 'service never talks to the API');
});
