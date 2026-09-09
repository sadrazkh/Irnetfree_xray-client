'use strict';
/**
 * In-app update: the right installer for this machine, and a checksum that
 * has to match before anything is opened.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { pickUpdateAsset, parseSha256Sums, sha256File } = require('../src/main/appUpdate');

const assets = [
  { name: 'IRNetFree-Setup-1.6.0.exe', browser_download_url: 'u1', size: 1 },
  { name: 'IRNetFree-Portable-1.6.0.exe', browser_download_url: 'u2', size: 2 },
  { name: 'IRNetFree-1.6.0-arm64.dmg', browser_download_url: 'u3', size: 3 },
  { name: 'IRNetFree-1.6.0-x64.dmg', browser_download_url: 'u4', size: 4 },
  { name: 'IRNetFree-1.6.0.AppImage', browser_download_url: 'u5', size: 5 },
  { name: 'IRNetFree-1.6.0.apk', browser_download_url: 'u6', size: 6 },
  { name: 'SHA256SUMS-windows-latest.txt', browser_download_url: 'u7', size: 7 }
];

test('pickUpdateAsset: the installer for this platform and arch, never the portable or the APK', () => {
  assert.equal(pickUpdateAsset(assets, 'win32', 'x64').name, 'IRNetFree-Setup-1.6.0.exe');
  assert.equal(pickUpdateAsset(assets, 'darwin', 'arm64').name, 'IRNetFree-1.6.0-arm64.dmg');
  assert.equal(pickUpdateAsset(assets, 'darwin', 'x64').name, 'IRNetFree-1.6.0-x64.dmg');
  assert.equal(pickUpdateAsset(assets, 'linux', 'x64').name, 'IRNetFree-1.6.0.AppImage');
  assert.equal(pickUpdateAsset([], 'win32', 'x64'), null);
  assert.equal(pickUpdateAsset(null, 'win32', 'x64'), null);
});

test('parseSha256Sums and sha256File agree; malformed lines are ignored; names keep their case', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-upd-'));
  try {
    const f = path.join(dir, 'IRNetFree-Setup-1.6.0.exe');
    fs.writeFileSync(f, 'hello');
    const sums = parseSha256Sums([
      '2CF24DBA5FB0A30E26E83B2AC5B9E29E1B161E5C1FA7425E73043362938B9824 *IRNetFree-Setup-1.6.0.exe',
      'abc  b.bin',
      '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824  IRNetFree-1.6.0-x64.dmg',
      ''
    ].join('\n'));
    assert.equal(await sha256File(f), sums['IRNetFree-Setup-1.6.0.exe']);
    assert.equal(sums['IRNetFree-1.6.0-x64.dmg'], '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');
    assert.equal(sums['b.bin'], undefined, 'not a sha256');
    assert.deepEqual(parseSha256Sums(''), {});
    await assert.rejects(sha256File(path.join(dir, 'missing')), /ENOENT/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
