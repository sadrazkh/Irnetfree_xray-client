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

const { XrayManager, getFreePorts, PLAINTEXT_REJECT, usesEch, ECH_SINCE } = require('../src/main/xrayManager');
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

// A patterniha subscription server: its ClientHello fragmenter lives in the
// fork's `finalmask`, which the official 26.3.27 refuses — measured on all 44
// of the owner's finalmask servers (field report S1, fix 20).
const FINALMASK_CFG = {
  inbounds: [],
  outbounds: [{ tag: 'proxy', protocol: 'vless', streamSettings: { network: 'tcp', finalmask: { tcp: [{ type: 'fragment', settings: { packets: 'tlshello', length: '0-0' } }] } } }, { tag: 'direct', protocol: 'freedom' }]
};
const LENGTH_MIN = 'infra/conf: LengthMin can\'t be 0';

test('validateWithFallback: a finalmask config goes to the fork FIRST when it is installed — the official core is not asked', async () => {
  // Asked first, an official core older than 26.3.27 (the 23.05 feed's
  // 24.12.31) passes it — Xray ignores keys it does not know — and runs the
  // server with its mask silently dropped; a 26.3.27 refuses it, and that
  // failing -test (geo files loaded, on a Cortex-A7) was paid on every connect
  // (review of v1.16.1). README: such a config must run on PattN.
  await withBin([exe('xray'), exe('xray-pattn')], async (xm, dir, logs) => {
    const calls = [];
    xm.validate = async (cfg, id) => { calls.push(id); return { ok: true }; };   // an official core that would have passed it too
    const r = await xm.validateWithFallback(FINALMASK_CFG, 'xray');
    assert.deepEqual(r, { ok: true, engine: 'xray-pattn', fellBack: true });
    assert.deepEqual(calls, ['xray-pattn']);
    assert.match(logs.at(-1), /finalmask.*Xray-PattN/);
  });
});

test('validateWithFallback: …and what the fork refuses is the fork’s error (the official core knows even less)', async () => {
  await withBin([exe('xray'), exe('xray-pattn')], async (xm) => {
    const calls = [];
    xm.validate = async (cfg, id) => { calls.push(id); return { ok: false, error: 'infra/conf: bad finalmask' }; };
    assert.deepEqual(await xm.validateWithFallback(FINALMASK_CFG, 'xray'), { ok: false, engine: 'xray-pattn', error: 'infra/conf: bad finalmask', plaintextRejected: false });
    assert.deepEqual(calls, ['xray-pattn']);
  });
});

/**
 * A fake official core behind spawn(): `version` names `ver`, and `run -test`
 * says "Configuration OK." to ANY config — what a real Xray older than 26.3.27
 * does with a finalmask, a key it does not know (checked by the reviewer with
 * an unknown streamSettings key on 26.3.27 itself).
 */
function acceptingCore(ver, spawned) {
  return (bin, args) => {
    spawned.push([path.basename(bin), args.join(' ')]);
    const child = stubChild();
    const out = args.includes('version')
      ? `Xray ${ver} (Xray, Penetrates Everything.) Custom (go1.23.4 linux/arm)\nA unified platform for anti-censorship.\n`
      : `Xray ${ver} (Xray, Penetrates Everything.)\nConfiguration OK.\n`;
    setImmediate(() => { child.stdout.emit('data', Buffer.from(out)); child.emit('exit', 0); });
    return child;
  };
}

test('validateWithFallback, with a real -test and version run: an official 24.12.31 that says "Configuration OK." to a finalmask config is not trusted with it — the fork is asked for', async () => {
  await withBin([exe('xray')], async (xm) => {
    const spawned = [];
    fakeSpawn = acceptingCore('24.12.31', spawned);
    try {
      const r = await xm.validateWithFallback(FINALMASK_CFG, 'xray');
      assert.equal(r.ok, false, 'never run a finalmask server with its mask silently dropped');
      assert.equal(r.pattnNeeded, true, 'the "needs Xray-PattN" message and the download prompt');
      assert.equal(r.finalmaskIgnored, true);
      assert.equal(r.coreVersion, '24.12.31');
      assert.deepEqual(spawned.map(([b, a]) => [b, /-test/.test(a) ? 'test' : a]), [[exe('xray'), 'test'], [exe('xray'), 'version']]);
      // the same core with a plain config is fine: the version is not the question then
      spawned.length = 0;
      const plain = { inbounds: [], outbounds: [{ tag: 'proxy', protocol: 'vless', streamSettings: { network: 'tcp' } }] };
      assert.deepEqual(await xm.validateWithFallback(plain, 'xray'), { ok: true, engine: 'xray' });
    } finally { fakeSpawn = null; }
  });
  // …and with the fork installed the official core is not even spawned for it
  await withBin([exe('xray'), exe('xray-pattn')], async (xm) => {
    const spawned = [];
    fakeSpawn = acceptingCore('24.12.31', spawned);
    try {
      assert.deepEqual(await xm.validateWithFallback(FINALMASK_CFG, 'xray'), { ok: true, engine: 'xray-pattn', fellBack: true });
      assert.deepEqual(spawned.map(([b]) => b), [exe('xray-pattn')]);
    } finally { fakeSpawn = null; }
  });
});

test('validateWithFallback: …and says the fork is needed when it is not', async () => {
  await withBin([exe('xray')], async (xm) => {
    xm.validate = async () => ({ ok: false, error: LENGTH_MIN });
    xm.version = async () => '26.3.27';
    const r = await xm.validateWithFallback(FINALMASK_CFG, 'xray');
    assert.deepEqual(r, { ok: false, engine: 'xray', error: LENGTH_MIN, plaintextRejected: false, pattnNeeded: true });
  });
});

test('validateWithFallback: with no fork, an official core older than 26.3.27 that PASSES a finalmask config still needs the fork — it would drop the mask', async () => {
  await withBin([exe('xray')], async (xm) => {
    const calls = [];
    xm.validate = async (cfg, id) => { calls.push(id); return { ok: true }; };   // unknown keys are ignored: "Configuration OK."
    xm.version = async () => '24.12.31';
    const r = await xm.validateWithFallback(FINALMASK_CFG, 'xray');
    assert.equal(r.ok, false);
    assert.equal(r.engine, 'xray');
    assert.equal(r.pattnNeeded, true);
    assert.equal(r.finalmaskIgnored, true);
    assert.equal(r.coreVersion, '24.12.31');
    assert.match(r.error, /xray 24\.12\.31 does not know finalmask \(26\.3\.27 and newer do\)/);
  });
});

test('validateWithFallback: with no fork, an official core from 26.3.27 that accepts the finalmask runs it — and a config with none never asks the version', async () => {
  await withBin([exe('xray')], async (xm) => {
    let asked = 0;
    xm.validate = async () => ({ ok: true });
    xm.version = async () => { asked++; return '26.3.27'; };
    assert.deepEqual(await xm.validateWithFallback(FINALMASK_CFG, 'xray'), { ok: true, engine: 'xray' });
    assert.equal(asked, 1);
    const plain = { inbounds: [], outbounds: [{ tag: 'proxy', protocol: 'vless', streamSettings: { network: 'tcp' } }] };
    assert.deepEqual(await xm.validateWithFallback(plain, 'xray'), { ok: true, engine: 'xray' });
    assert.equal(asked, 1);
  });
});

test('validateWithFallback: the same words from a config with no finalmask are its own error (a freedom fragment), not a fork question', async () => {
  await withBin([exe('xray'), exe('xray-pattn')], async (xm) => {
    const calls = [];
    xm.validate = async (cfg, id) => { calls.push(id); return { ok: false, error: LENGTH_MIN }; };
    const plain = { inbounds: [], outbounds: [{ tag: 'proxy', protocol: 'vless', streamSettings: { network: 'tcp' } }] };
    assert.deepEqual(await xm.validateWithFallback(plain, 'xray'), { ok: false, engine: 'xray', error: LENGTH_MIN, plaintextRejected: false });
    assert.deepEqual(calls, ['xray']);
  });
});

test('validateWithFallback passes other errors through untouched', async () => {
  await withBin([exe('xray'), exe('xray-pattn')], async (xm) => {
    xm.validate = async () => ({ ok: false, error: 'infra/conf: unknown transport' });
    const r = await xm.validateWithFallback({}, 'xray');
    assert.deepEqual(r, { ok: false, engine: 'xray', error: 'infra/conf: unknown transport', plaintextRejected: false });
  });
});

test('validateWithFallback: a check that was killed stays flagged on every path — the caller must not take it for a verdict', async () => {
  const KILLED = { ok: false, killed: true, error: 'xray -test was killed (SIGKILL) — the config was not checked' };
  const PLAINTEXT = 'vless without TLS or other encryption is prohibited unless the server address is a private IP or domain';
  await withBin([exe('xray')], async (xm) => {
    xm.validate = async () => KILLED;
    assert.deepEqual(await xm.validateWithFallback({}, 'xray'), { ok: false, engine: 'xray', error: KILLED.error, plaintextRejected: false, killed: true });
    // a finalmask config on the official core, no fork: no "install Xray-PattN" either
    assert.deepEqual(await xm.validateWithFallback(FINALMASK_CFG, 'xray'), { ok: false, engine: 'xray', error: KILLED.error, plaintextRejected: false, killed: true });
  });
  await withBin([exe('xray'), exe('xray-pattn')], async (xm) => {
    xm.validate = async () => KILLED;
    assert.deepEqual(await xm.validateWithFallback(FINALMASK_CFG, 'xray'), { ok: false, engine: 'xray-pattn', error: KILLED.error, plaintextRejected: false, killed: true });
    // the official core refuses the plaintext, the fork's check is killed
    xm.validate = async (cfg, id) => (id === 'xray' ? { ok: false, error: PLAINTEXT } : KILLED);
    assert.deepEqual(await xm.validateWithFallback({}, 'xray'), { ok: false, engine: 'xray-pattn', error: KILLED.error, plaintextRejected: false, killed: true });
  });
});

/* -------------- v1.18: ECH asked of an official core too old to know it -------------- */

/**
 * A manager whose cores are stand-ins: `bins` are installed, `versions[id]` is
 * what `<core> version` says, and `-test` passes on the cores in `validOn`.
 * `calls` lists the cores each -test ran on; `logs` the log lines.
 */
function managerWith({ versions = {}, bins = [], validOn = [] } = {}) {
  const m = new XrayManager({ dataDir: os.tmpdir(), onLog: (line) => m.logs.push(line) });
  m.logs = [];
  m.calls = [];
  m.resolveBin = (id = 'xray') => (bins.includes(id) ? path.join(os.tmpdir(), exe(id)) : null);
  m.version = async (id = 'xray') => (versions[id] == null ? '' : versions[id]);
  m.validate = async (cfg, id) => { m.calls.push(id); return validOn.includes(id) ? { ok: true } : { ok: false, error: `infra/conf: refused by ${id}` }; };
  return m;
}

const ECH_CONFIG = { outbounds: [{ protocol: 'vless', streamSettings: { network: 'ws', security: 'tls',
  tlsSettings: { serverName: 'a.example', echConfigList: 'cloudflare-ech.com+udp://1.1.1.1' } } }] };

test('ECH on an official core older than 25.8.3 runs on Xray-PattN when it is installed', async () => {
  const m = managerWith({ versions: { xray: '25.1.30', 'xray-pattn': '26.9.22' }, bins: ['xray', 'xray-pattn'], validOn: ['xray', 'xray-pattn'] });
  const r = await m.validateWithFallback(ECH_CONFIG, 'xray');
  assert.deepEqual([r.ok, r.engine, r.fellBack], [true, 'xray-pattn', true]);
  assert.deepEqual(m.calls, ['xray-pattn'], 'the official core is not asked: it would pass the config and drop the ECH');
  assert.match(m.logs.at(-1), /uses ECH, which xray 25\.1\.30 does not know — running it on Xray-PattN/);
  // what the fork refuses is the fork's own error
  const n = managerWith({ versions: { xray: '25.1.30' }, bins: ['xray', 'xray-pattn'], validOn: [] });
  assert.deepEqual(await n.validateWithFallback(ECH_CONFIG, 'xray'), { ok: false, engine: 'xray-pattn', error: 'infra/conf: refused by xray-pattn', plaintextRejected: false });
});

test('ECH on an old official core with no fork is refused with the version in the answer', async () => {
  const m = managerWith({ versions: { xray: '25.1.30' }, bins: ['xray'], validOn: ['xray'] });
  const r = await m.validateWithFallback(ECH_CONFIG, 'xray');
  assert.equal(r.ok, false);
  assert.equal(r.echUnsupported, true);
  assert.equal(r.coreVersion, '25.1.30');
  assert.equal(r.engine, 'xray');
  assert.equal(r.plaintextRejected, false);
  assert.equal(r.error, 'xray 25.1.30 does not know ECH (25.8.3 and newer do) — it would connect without it');
  assert.deepEqual(m.calls, [], 'not even -test: that would say "Configuration OK."');
  // the router's opkg feed (24.12.31), and the release right before echSockopt
  for (const v of ['24.12.31', '25.8.2']) {
    const old = managerWith({ versions: { xray: v }, bins: ['xray'], validOn: ['xray'] });
    assert.equal((await old.validateWithFallback(ECH_CONFIG, 'xray')).echUnsupported, true, v);
  }
});

test('ECH on 26.9.30, or on a core whose version cannot be read, takes the ordinary path', async () => {
  for (const v of ['26.9.30', '']) {
    const m = managerWith({ versions: { xray: v }, bins: ['xray'], validOn: ['xray'] });
    const r = await m.validateWithFallback(ECH_CONFIG, 'xray');
    assert.deepEqual([r.ok, r.engine], [true, 'xray']);
  }
  // 25.8.3 itself knows it
  const edge = managerWith({ versions: { xray: '25.8.3' }, bins: ['xray', 'xray-pattn'], validOn: ['xray', 'xray-pattn'] });
  assert.deepEqual(await edge.validateWithFallback(ECH_CONFIG, 'xray'), { ok: true, engine: 'xray' });
  assert.deepEqual(edge.calls, ['xray']);
  assert.equal(ECH_SINCE, '25.8.3');
});

test('ECH: a config without it is never asked the core’s version, and a config sent to Xray-PattN is the fork’s alone', async () => {
  const m = managerWith({ versions: { xray: '25.1.30', 'xray-pattn': '26.9.22' }, bins: ['xray', 'xray-pattn'], validOn: ['xray', 'xray-pattn'] });
  let asked = 0;
  m.version = async () => { asked++; return '25.1.30'; };
  const plain = { outbounds: [{ protocol: 'vless', streamSettings: { network: 'ws', security: 'tls', tlsSettings: { serverName: 'a.example' } } }] };
  assert.deepEqual(await m.validateWithFallback(plain, 'xray'), { ok: true, engine: 'xray' });
  assert.equal(asked, 0);
  assert.deepEqual(await m.validateWithFallback(ECH_CONFIG, 'xray-pattn'), { ok: true, engine: 'xray-pattn' });
  assert.equal(asked, 0);
});

test('usesEch: only a non-empty echConfigList counts', () => {
  assert.equal(usesEch(ECH_CONFIG), true);
  assert.equal(usesEch({ outbounds: [{ streamSettings: { tlsSettings: { echConfigList: '  ' } } }] }), false);
  assert.equal(usesEch({ outbounds: [{ streamSettings: { tlsSettings: {} } }] }), false);
  // the second hop of a chain carries it as much as the first; nothing at all is no ECH
  assert.equal(usesEch({ outbounds: [{ protocol: 'freedom' }, null, ECH_CONFIG.outbounds[0]] }), true);
  for (const none of [null, undefined, {}, { outbounds: null }, { outbounds: [{ streamSettings: { realitySettings: { serverName: 'r' } } }] }]) {
    assert.equal(usesEch(none), false, JSON.stringify(none));
  }
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

/* --------------------------- the validation cache --------------------------- */

const exit0 = () => { const p = stubChild(); setImmediate(() => p.emit('exit', 0)); return p; };

test('validate: an identical config on the same core is not spawned twice; forgetVersions() clears it', async () => {
  // A reconnect after a network change rebuilds the identical config, and
  // `-test` costs 1-6 s of the connect each time.
  await withBin([exe('xray')], async (xm) => {
    const before = spawns.length;
    fakeSpawn = exit0;
    try {
      const cfg = { log: { loglevel: 'none' }, inbounds: [], outbounds: [] };
      assert.deepEqual(await xm.validate(cfg, 'xray'), { ok: true });
      assert.deepEqual(await xm.validate(cfg, 'xray'), { ok: true, cached: true });
      assert.equal(spawns.length - before, 1, 'one -test run for two identical validations');
      // a different config is a different fact
      await xm.validate(Object.assign({}, cfg, { log: { loglevel: 'warning' } }), 'xray');
      assert.equal(spawns.length - before, 2);
      xm.forgetVersions();
      assert.deepEqual(await xm.validate(cfg, 'xray'), { ok: true });
      assert.equal(spawns.length - before, 3, 'a re-downloaded core forgets every pass');
    } finally { fakeSpawn = null; }
  });
});

test('validate: a rejected config is never cached', async () => {
  await withBin([exe('xray')], async (xm) => {
    const before = spawns.length;
    fakeSpawn = () => { const p = stubChild(); setImmediate(() => { p.stderr.emit('data', Buffer.from('Failed to start: bad thing')); p.emit('exit', 1); }); return p; };
    try {
      const cfg = { log: { loglevel: 'none' }, inbounds: [], outbounds: [] };
      assert.equal((await xm.validate(cfg, 'xray')).ok, false);
      assert.equal((await xm.validate(cfg, 'xray')).ok, false);
      assert.equal(spawns.length - before, 2);
    } finally { fakeSpawn = null; }
  });
});

test('validate: an old core that does not know -test passes UNVERIFIED and is not cached', async () => {
  await withBin([exe('xray')], async (xm) => {
    const before = spawns.length;
    fakeSpawn = () => { const p = stubChild(); setImmediate(() => { p.stderr.emit('data', Buffer.from('flag provided but not defined: -test')); p.emit('exit', 2); }); return p; };
    try {
      const cfg = { log: { loglevel: 'none' }, inbounds: [], outbounds: [] };
      assert.deepEqual(await xm.validate(cfg, 'xray'), { ok: true, unverified: true });
      assert.deepEqual(await xm.validate(cfg, 'xray'), { ok: true, unverified: true });
      assert.equal(spawns.length - before, 2);
    } finally { fakeSpawn = null; }
  });
});

test('validate: the -test deadline is the caller’s (6 s by default) — a run past it passes UNVERIFIED and says so at warn', async () => {
  // The router asks for ~30 s: on a Cortex-A7 a -test past 6 s counted as a
  // pass, and a config the core refuses then reached start() — whose 1.2 s
  // grace hides a slow refusal (field report S2, fix 20).
  assert.equal(new XrayManager({ dataDir: os.tmpdir() }).testTimeoutMs, 6000);
  assert.equal(new XrayManager({ dataDir: os.tmpdir(), testTimeoutMs: 30000 }).testTimeoutMs, 30000);
  await withBin([exe('xray')], async (xm) => {
    const logs = [];
    xm.onLog = (line, level) => logs.push([level, line]);
    xm.testTimeoutMs = 40;
    let killed = 0;
    fakeSpawn = () => { const p = stubChild(); p.kill = () => { killed++; }; return p; };   // never exits by itself
    try {
      const cfg = { log: { loglevel: 'none' }, inbounds: [], outbounds: [] };
      const t0 = Date.now();
      assert.deepEqual(await xm.validate(cfg, 'xray'), { ok: true, unverified: true });
      assert.ok(Date.now() - t0 < 3000, 'the deadline given, not the default');
      assert.equal(killed, 1, 'the run is ended');
      assert.ok(logs.some(([lvl, l]) => lvl === 'warn' && /did not finish its config check within 0\.04 s — the config was not verified/.test(l)), JSON.stringify(logs));
    } finally { fakeSpawn = null; }
  });
});

test('validate: an old core that does not know -test passes UNVERIFIED with a warn line too', async () => {
  await withBin([exe('xray')], async (xm) => {
    const logs = [];
    xm.onLog = (line, level) => logs.push([level, line]);
    fakeSpawn = () => { const p = stubChild(); setImmediate(() => { p.stderr.emit('data', Buffer.from('flag provided but not defined: -test')); p.emit('exit', 2); }); return p; };
    try {
      assert.deepEqual(await xm.validate({ inbounds: [] }, 'xray'), { ok: true, unverified: true });
      assert.ok(logs.some(([lvl, l]) => lvl === 'warn' && /does not know -test — the config was not verified/.test(l)), JSON.stringify(logs));
    } finally { fakeSpawn = null; }
  });
});

test('validate: the key follows the core file — a replaced binary is checked again', async () => {
  await withBin([exe('xray')], async (xm, dir) => {
    const before = spawns.length;
    fakeSpawn = exit0;
    try {
      const cfg = { log: { loglevel: 'none' }, inbounds: [], outbounds: [] };
      await xm.validate(cfg, 'xray');
      const bin = path.join(dir, exe('xray'));
      const t = new Date(Date.now() + 5000);
      fs.utimesSync(bin, t, t);                       // "re-downloaded": a new mtime
      assert.deepEqual(await xm.validate(cfg, 'xray'), { ok: true });
      assert.equal(spawns.length - before, 2);
    } finally { fakeSpawn = null; }
  });
});

// What `xray run -test` prints before it loads the geo files (checked on a local
// xray 26.3.27 by the v1.16.1 re-review). A check killed after it leaves only
// this, and its last line — the one extractXrayError picks — is no verdict.
const TEST_BANNER = 'Xray 26.3.27 (Xray, Penetrates Everything.) Custom (go1.26.1 linux/arm)\n'
  + 'A unified platform for anti-censorship.\n'
  + '[Info] infra/conf/serial: Reading config: &{Name:/etc/irnetfree/test-cfg-1.json Format:json}\n';
/** A -test that prints `out` (on stdout, or the stream named) and then ends with (code, signal). */
const endsWith = (out, code, signal, stream = 'stdout') => () => {
  const p = stubChild();
  setImmediate(() => { p[stream].emit('data', Buffer.from(out)); p.emit('exit', code, signal); });
  return p;
};
const TEST_CFG = { log: { loglevel: 'none' }, inbounds: [], outbounds: [] };

test('validate: a -test killed by a signal after its banner (the kernel\'s OOM killer on a 512 MB router) is no verdict — it says it was killed, is flagged, and is not cached', async () => {
  // was: { ok:false, error:'[Info] infra/conf/serial: Reading config: …' }, which the
  // router's service took for the core refusing the config and waited 10 minutes on
  await withBin([exe('xray')], async (xm) => {
    const before = spawns.length;
    fakeSpawn = endsWith(TEST_BANNER, null, 'SIGKILL');
    try {
      const r = await xm.validate(TEST_CFG, 'xray');
      assert.equal(r.ok, false);
      assert.equal(r.killed, true);
      assert.match(r.error, /^xray(\.exe)? -test was killed \(SIGKILL\) — the config was not checked$/);
      assert.equal((await xm.validate(TEST_CFG, 'xray')).killed, true);
      assert.equal(spawns.length - before, 2, 'never cached');
    } finally { fakeSpawn = null; }
  });
});

test('validate: …and so is a -test that Go\'s own runtime ended out of memory (exit 2) — either form the runtime prints', async () => {
  const heap = 'fatal error: runtime: out of memory\n\nruntime stack:\nruntime.throw({0x1c2d4f3, 0x16})\n\t/usr/local/go/src/runtime/panic.go:1023 +0x4c\n\ngoroutine 1 [running]:\nmain.main()\n';
  const block = 'runtime: out of memory: cannot allocate 4194304-byte block (3866624 in use)\nfatal error: out of memory\n\ngoroutine 1 [running]:\nruntime.throw({0x1c2d4f3, 0xd})\n\t/usr/local/go/src/runtime/panic.go:1023 +0x4c\n';
  await withBin([exe('xray')], async (xm) => {
    try {
      for (const tail of [heap, block]) {
        fakeSpawn = endsWith(TEST_BANNER + tail, 2, null, 'stderr');
        const r = await xm.validate(TEST_CFG, 'xray');
        assert.equal(r.ok, false);
        assert.equal(r.killed, true, tail);
        assert.match(r.error, /^xray(\.exe)? -test ran out of memory \(.*out of memory.*\) — the config was not checked$/);
      }
      // the core's own verdict after the same banner stays one: "Failed to start", exit 23
      fakeSpawn = endsWith(TEST_BANNER + 'Failed to start: main: failed to load config files: [/etc/irnetfree/test-cfg-1.json] > infra/conf: unknown transport protocol: foo\n', 23, null);
      const refused = await xm.validate(TEST_CFG, 'xray');
      assert.deepEqual(refused, { ok: false, error: 'infra/conf: unknown transport protocol: foo' });
    } finally { fakeSpawn = null; }
  });
});

test('getFreePorts hands out n distinct loopback ports', async () => {
  const ports = await getFreePorts(5);
  assert.equal(ports.length, 5);
  assert.equal(new Set(ports).size, 5, 'distinct: ' + ports.join(','));
  for (const p of ports) assert.ok(p > 0 && p < 65536);
  assert.deepEqual(await getFreePorts(0), []);
});

test('binDirs never yields a relative directory outside Electron', () => {
  // process.resourcesPath is undefined in plain Node; the old
  // path.join(undefined || '', 'bin') was the relative `bin`, which resolved
  // against the spawned child's cwd and made every headless latency test ENOENT.
  const saved = process.resourcesPath;
  delete process.resourcesPath;
  try {
    const xm = new XrayManager({ dataDir: os.tmpdir() });
    for (const d of xm.binDirs()) assert.ok(path.isAbsolute(d), 'relative bin dir: ' + d);
    assert.ok(xm.binDirs().some(d => d === path.join(__dirname, '..', 'bin')), 'the bundled bin/ is still there');
  } finally {
    if (saved !== undefined) process.resourcesPath = saved;
  }
});

test('a late exit or error from an old core cannot stop its replacement', async () => {
  await withBin([exe('xray')], async xm => {
    const old = stubChild();
    const current = stubChild();
    const statuses = [];
    xm.onStatus = status => statuses.push(status);
    fakeSpawn = () => old;
    try {
      const starting = xm.start({ inbounds: [], outbounds: [] }, 'xray');
      // Reproduce the state after bounded stop and replacement, without
      // waiting for a real process to ignore a termination request.
      xm.proc = current;
      old.emit('exit', 0);
      await assert.rejects(starting, /startup/);
      old.emit('error', new Error('late old error'));
      assert.equal(xm.proc, current);
      assert.equal(xm.running, true);
      assert.deepEqual(statuses, [], 'the replacement must not be reported stopped');
    } finally { fakeSpawn = null; }
  });
});

test('recentLines: the last lines the core that was started last printed — for a core that dies after its grace period', async () => {
  // The router's connect waits ~9 s for the SOCKS port after start() returned;
  // a core that dies in that window must be reported with its own words
  // (field report fix 20), not as "has not opened … starting the gateway anyway".
  await withBin([exe('xray')], async (xm) => {
    const first = stubChild();
    const second = stubChild();
    let n = 0;
    fakeSpawn = () => (n++ === 0 ? first : second);
    try {
      assert.deepEqual(xm.recentLines(), [], 'nothing started yet');
      const a = xm.start({ inbounds: [] }, 'xray');
      first.stdout.emit('data', Buffer.from('Xray 26.3.27 started\n'));
      await a;
      first.stderr.emit('data', Buffer.from('\n  line one  \r\nline two\nline three\n'));
      assert.deepEqual(xm.recentLines(2), ['line two', 'line three']);
      first.emit('exit', 2, null);
      assert.deepEqual(xm.recentLines(), ['Xray 26.3.27 started', 'line one', 'line two', 'line three'], 'still there once it has exited');
      const b = xm.start({ inbounds: [] }, 'xray');
      first.stdout.emit('data', Buffer.from('a late line from the old core\n'));
      await b;
      assert.deepEqual(xm.recentLines(), [], 'a new start begins empty, and the old core’s late output is not mixed in');
    } finally { fakeSpawn = null; }
  });
});

test('start rejects a spawn failure promptly and does not keep the failed child', async () => {
  await withBin([exe('xray')], async xm => {
    const child = stubChild();
    fakeSpawn = () => child;
    try {
      const starting = xm.start({ inbounds: [], outbounds: [] }, 'xray');
      child.emit('error', new Error('spawn ENOENT'));
      await assert.rejects(starting, /ENOENT/);
      assert.equal(xm.proc, null);
      assert.equal(xm.running, false);
    } finally { fakeSpawn = null; }
  });
});
