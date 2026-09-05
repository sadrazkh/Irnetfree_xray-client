'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { EventEmitter } = require('node:events');

// The manager destructures `spawn` at require time, so the stub has to be
// installed BEFORE it is loaded. Tests that need a child process set
// `fakeSpawn`; everything else falls through to the real spawn.
const cp = require('node:child_process');
const realSpawn = cp.spawn;
let fakeSpawn = null;
const spawns = [];
cp.spawn = (...args) => { spawns.push(args); return fakeSpawn ? fakeSpawn(...args) : realSpawn(...args); };

const { XrayManager, PLAINTEXT_REJECT } = require('../src/main/xrayManager');
const { ENGINES } = require('../src/main/engines');

/** Stand-in for a spawned core, so no real binary has to exist / run. */
function stubChild() {
  const p = new EventEmitter();
  p.stdout = new EventEmitter();
  p.stderr = new EventEmitter();
  p.pid = 12345;
  p.kill = () => {};
  return p;
}

function withBin(files, fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-xm-'));
  for (const f of files) fs.writeFileSync(path.join(dir, f), '');
  const logs = [];
  const xm = new XrayManager({ dataDir: dir, extraBinDirs: [dir], onLog: (l) => logs.push(l) });
  // never let the real bundled bin/ or XRAY_PATH leak into the test
  xm.binDirs = () => [dir];
  delete process.env.XRAY_PATH;
  const clean = () => fs.rmSync(dir, { recursive: true, force: true });
  let out;
  try { out = fn(xm, dir, logs); } catch (e) { clean(); throw e; }
  // An async body must FINISH before the fake bin/ is removed — otherwise the
  // dir is gone by the first await and resolveBin() stops seeing the cores.
  if (out && typeof out.then === 'function') return out.then(
    (v) => { clean(); return v; },
    (e) => { clean(); throw e; }
  );
  clean();
  return out;
}
const exe = (n) => process.platform === 'win32' ? n + '.exe' : n;

test('resolveEngine returns the requested core when installed', () => {
  withBin([exe('xray'), exe('xray-pattn')], (xm) => {
    assert.equal(xm.resolveEngine('xray-pattn').id, 'xray-pattn');
    assert.equal(xm.resolveEngine('xray').id, 'xray');
    assert.equal(xm.resolveEngine(undefined).id, 'xray');
  });
});

test('resolveEngine falls back across Xray-format cores in both directions', () => {
  withBin([exe('xray-pattn')], (xm, dir, logs) => {
    const r = xm.resolveEngine('xray');
    assert.equal(r.id, 'xray-pattn');
    assert.equal(r.bin, path.join(dir, exe('xray-pattn')));
    assert.match(logs.at(-1), /not found.*using xray-pattn/);
  });
  withBin([exe('xray')], (xm) => {
    assert.equal(xm.resolveEngine('xray-pattn').id, 'xray');
    assert.equal(xm.resolveEngine('sing-box').id, 'xray', 'sing-box missing → default core');
  });
  withBin([], (xm) => assert.deepEqual(xm.resolveEngine('xray'), { id: 'xray', bin: null }));
});

test('resolveEngine can fall back silently, and anyBin() always does', () => {
  withBin([exe('xray-pattn')], (xm, dir, logs) => {
    const r = xm.resolveEngine('xray', { quiet: true });
    assert.deepEqual(r, { id: 'xray-pattn', bin: path.join(dir, exe('xray-pattn')) });
    assert.deepEqual(logs, [], 'a quiet lookup must not warn');

    // internal stats-binary lookup: runs on start, every connect, every config
    // rebuild and after each asset op — a fork-only user must not be spammed
    assert.equal(xm.anyBin(), path.join(dir, exe('xray-pattn')));
    assert.deepEqual(logs, [], 'anyBin() must not warn');

    // the connect path still says which core actually ran
    assert.equal(xm.resolveEngine('xray').id, 'xray-pattn');
    assert.match(logs.at(-1), /not found.*using xray-pattn/);
    assert.equal(logs.length, 1);
  });
  withBin([], (xm, dir, logs) => {
    assert.equal(xm.anyBin(), null);
    assert.deepEqual(logs, []);
  });
});

test('binExists: any Xray core, or a specific one', () => {
  withBin([exe('xray-pattn')], (xm) => {
    assert.equal(xm.binExists(), true);
    assert.equal(xm.binExists('xray'), false);
    assert.equal(xm.binExists('xray-pattn'), true);
  });
});

test('validateWithFallback retries a plaintext-rejected config on the fork', async () => {
  const rejectMsg = 'vless without TLS or other encryption is prohibited unless the server address is a private IP or domain';
  assert.match(rejectMsg, PLAINTEXT_REJECT);
  await withBin([exe('xray'), exe('xray-pattn')], async (xm, dir, logs) => {
    const calls = [];
    xm.validate = async (cfg, id) => { calls.push(id); return id === 'xray' ? { ok: false, error: rejectMsg } : { ok: true }; };
    const r = await xm.validateWithFallback({}, 'xray');
    assert.deepEqual(r, { ok: true, engine: 'xray-pattn', fellBack: true });
    assert.deepEqual(calls, ['xray', 'xray-pattn']);
    assert.match(logs.at(-1), /Xray-PattN/);
  });
});

test('validateWithFallback reports a plaintext rejection when the fork is not installed', async () => {
  await withBin([exe('xray')], async (xm) => {
    xm.validate = async () => ({ ok: false, error: 'trojan without TLS is prohibited unless the server address is a private IP or domain' });
    const r = await xm.validateWithFallback({}, 'xray');
    assert.equal(r.ok, false);
    assert.equal(r.engine, 'xray');
    assert.equal(r.plaintextRejected, true);
  });
});

test('validateWithFallback passes other errors through untouched', async () => {
  await withBin([exe('xray'), exe('xray-pattn')], async (xm) => {
    xm.validate = async () => ({ ok: false, error: 'infra/conf: unknown transport' });
    const r = await xm.validateWithFallback({}, 'xray');
    assert.deepEqual(r, { ok: false, engine: 'xray', error: 'infra/conf: unknown transport', plaintextRejected: false });
  });
});

test('startTest spawns the RESOLVED engine with that engine\'s own argv', async () => {
  // A temporary core with a DIFFERENT argv shape: the three real Xray-format
  // entries happen to share `run -c <cfg>`, so only this can tell a registry
  // lookup apart from a hardcoded argv.
  ENGINES['xray-argvprobe'] = {
    id: 'xray-argvprobe', label: 'argv probe', format: 'xray',
    exe: { win32: 'xray-argvprobe.exe', default: 'xray-argvprobe' },
    runArgs: (cfg) => ['serve', '--conf', cfg],
    testArgs: (cfg) => ['check', '--conf', cfg]
  };
  try {
    await withBin([exe('xray-argvprobe')], async (xm, dir) => {
      spawns.length = 0;
      fakeSpawn = () => stubChild();
      // 'xray' is not installed, so this resolves to the probe core
      const handle = await xm.startTest({ inbounds: [] }, 'xray');
      const [bin, args] = spawns[0];
      assert.equal(bin, path.join(dir, exe('xray-argvprobe')));
      assert.deepEqual(args.slice(0, 2), ['serve', '--conf']);
      assert.equal(path.dirname(args[2]), dir);
      assert.equal(fs.existsSync(args[2]), true, 'the temp config is written before the spawn');
      handle.cleanup();
      assert.equal(fs.existsSync(args[2]), false, 'cleanup removes the temp config');
    });
  } finally {
    delete ENGINES['xray-argvprobe'];
    fakeSpawn = null;
  }
});

test('startTest resolves quietly — a batch ping must not repeat the fallback warning', async () => {
  // Only the fork is installed, so every latency test on a default-'xray' setup
  // falls back. "Ping all" over 40 servers used to log 40 identical warnings.
  await withBin([exe('xray-pattn')], async (xm, dir, logs) => {
    fakeSpawn = () => stubChild();
    try {
      const a = await xm.startTest({ inbounds: [] }, 'xray');
      const b = await xm.startTest({ inbounds: [] }, 'xray');
      a.cleanup(); b.cleanup();
      assert.deepEqual(logs, [], 'the latency-test path must not warn, once per server or at all');

      // the connect path still tells the user which core actually ran
      assert.equal(xm.resolveEngine('xray').id, 'xray-pattn');
      assert.equal(logs.length, 1);
      assert.match(logs.at(-1), /not found.*using xray-pattn/);
    } finally {
      fakeSpawn = null;
    }
  });
});

test('version(): a spawn error is final — the timeout can not overwrite it', async (t) => {
  await withBin([exe('xray')], async (xm) => {
    const child = stubChild();
    fakeSpawn = () => child;
    try {
      const p = xm.version('xray');
      child.emit('error', new Error('spawn ENOENT'));
      assert.equal(await p, '');
      // 'exit' and the 4s timeout call the SAME guarded finish(), so proving the
      // guard against 'exit' proves it for the timeout too — no fake clock needed
      // (t.mock.timers is experimental and prints a warning into the test output).
      child.emit('exit', 1);
      assert.deepEqual(xm._versions, {}, 'nothing may be cached after an error');
    } finally {
      fakeSpawn = null;
    }
  });
});

/* --------------- a core that cannot be spawned must not kill us --------------- */

test('startTest rejects when the core cannot be spawned instead of crashing the app', async () => {
  // Reproduces the real failure: spawn() succeeds as a call, then the child
  // emits 'error' because the binary is missing or not executable. With no
  // listener Node re-throws that as an uncaught exception, which took the whole
  // process down — a latency test against a half-installed core was enough.
  await withBin([exe('xray')], async (xm) => {
    const child = stubChild();
    fakeSpawn = () => child;
    try {
      const p = xm.startTest({ inbounds: [], outbounds: [] }, 'xray');
      const err = Object.assign(new Error('spawn xray ENOENT'), { code: 'ENOENT' });
      setTimeout(() => child.emit('error', err), 10);
      await assert.rejects(() => p, /ENOENT/);
    } finally {
      fakeSpawn = null;
    }
  });
});
