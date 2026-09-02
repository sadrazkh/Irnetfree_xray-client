'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { XrayManager, PLAINTEXT_REJECT } = require('../src/main/xrayManager');

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
