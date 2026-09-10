'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const afterPack = require('../scripts/build-mac-native');
const { verify } = require('../scripts/verify-mac-native');

test('native packaging leaves non-Mac builders alone', async () => {
  await afterPack({ electronPlatformName: 'win32' });
  await afterPack({ electronPlatformName: 'linux' });
});

test('app signing preserves the pinned native binaries and signs the containing app', () => {
  const app = path.resolve('IRNetFree.app');
  const options = afterPack.signingOptions({ app, ignore: (file) => file.endsWith('.kext'), optionsForFile: () => ({ entitlements: 'test.plist' }) });
  assert.equal(options.identity, '-');
  assert.equal(options.ignore(path.join(app, 'Contents/MacOS/IRNetFreeNative')), true);
  assert.equal(options.ignore(path.join(app, 'Contents/MacOS/IRNetFreeTunnelService')), true);
  assert.equal(options.ignore(path.join(app, 'Contents/Resources/native/sing-box')), true);
  assert.equal(options.ignore(path.join(app, 'Contents/MacOS/IRNetFreeNative-other')), false);
  assert.equal(options.ignore(app), false);
  assert.equal(options.ignore(path.join(app, 'Contents/Frameworks/Electron Framework.framework')), false);
  assert.equal(options.optionsForFile(app).entitlements, 'test.plist');
  assert.equal(options.optionsForFile(app).hardenedRuntime, false);
});

test('native packaging rejects unsupported build hosts', { skip: process.platform === 'darwin' }, async () => {
  await assert.rejects(afterPack.buildNative('unused.app', 'arm64'), /requires a Mac/);
});

test('package verification rejects core or bridge changed after hash pinning', { skip: process.platform === 'darwin' }, () => {
  // Pure verification on non-Mac hosts; Mac CI verifies actual Mach-O signatures.
  const app = fs.mkdtempSync(path.join(os.tmpdir(), 'irnetfree-package-test-'));
  const contents = path.join(app, 'Contents');
  try {
    const manifest = { architecture: 'arm64' };
    for (const [relative, key] of [
      ['MacOS/IRNetFreeNative', 'bridgeSHA256'],
      ['MacOS/IRNetFreeTunnelService', 'daemonSHA256'],
      ['Resources/native/sing-box', 'singBoxSHA256'],
    ]) {
      const file = path.join(contents, relative);
      fs.mkdirSync(path.dirname(file), { recursive: true });
      fs.writeFileSync(file, relative);
      manifest[key] = crypto.createHash('sha256').update(relative).digest('hex');
    }
    const plist = path.join(contents, 'Library/LaunchDaemons/com.irnetfree.client.tunnel.plist');
    fs.mkdirSync(path.dirname(plist), { recursive: true });
    fs.copyFileSync(path.join(__dirname, '../native/macos/com.irnetfree.client.tunnel.plist'), plist);
    fs.writeFileSync(path.join(contents, 'Resources/native/build-manifest.json'), JSON.stringify(manifest));
    assert.equal(verify(app, 'arm64').architecture, 'arm64');
    assert.throws(() => verify(app, 'x64'), /architecture/);
    fs.appendFileSync(path.join(contents, 'Resources/native/sing-box'), 'modified');
    assert.throws(() => verify(app), /changed after pinning.*sing-box/);
    fs.writeFileSync(path.join(contents, 'Resources/native/sing-box'), 'Resources/native/sing-box');
    fs.appendFileSync(path.join(contents, 'MacOS/IRNetFreeNative'), 'modified');
    assert.throws(() => verify(app), /changed after pinning.*IRNetFreeNative/);
  } finally { fs.rmSync(app, { recursive: true, force: true }); }
});
