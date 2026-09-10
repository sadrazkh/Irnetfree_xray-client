'use strict';

// electron-builder afterPack: native components are mandatory for every Mac build.
// The beta is ad-hoc signed, not Developer ID signed or notarized.
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');

const VERSION = '1.13.14';
// Official SagerNet release API asset digests, pinned so a replaced download fails.
// https://api.github.com/repos/SagerNet/sing-box/releases/tags/v1.13.14
const ARCHIVES = Object.freeze({
  x64: { target: 'x86_64', upstream: 'amd64', sha256: '5245d645e847f90bb708da74bc020ae078c28489690756419685c04f56b4e3bb' },
  arm64: { target: 'arm64', upstream: 'arm64', sha256: '73e8967b0fc08e17bce4263ca56ebc394822401a16497a1c4e02316c888202ab' },
});
const sha256 = (file) => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
function run(command, args) { return execFileSync(command, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }); }
function sign(file, identifier) { run('/usr/bin/codesign', ['--force', '--sign', '-', '--identifier', identifier, file]); }
function cdhash(file) {
  // codesign writes its display output to stderr, including on success.
  const { spawnSync } = require('node:child_process');
  const result = spawnSync('/usr/bin/codesign', ['--display', '--verbose=4', file], { encoding: 'utf8' });
  if (result.status !== 0) throw new Error(`Cannot inspect native signature: ${result.stderr}`);
  const match = (result.stdout + result.stderr).match(/^CDHash=([a-f0-9]+)$/mi);
  if (!match) throw new Error('Missing native bridge CDHash');
  return match[1];
}

async function buildNative(appPath, arch, projectDir = path.resolve(__dirname, '..')) {
  if (process.platform !== 'darwin') throw new Error('Native macOS packaging requires a Mac with Xcode command line tools');
  const config = ARCHIVES[arch];
  if (!config) throw new Error(`Unsupported native architecture: ${arch}; build x64 and arm64 separately`);
  const source = path.join(projectDir, 'native', 'macos');
  const contents = path.join(appPath, 'Contents');
  const executables = path.join(contents, 'MacOS');
  const resources = path.join(contents, 'Resources', 'native');
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'irnetfree-native-build-'));
  fs.mkdirSync(executables, { recursive: true });
  fs.mkdirSync(resources, { recursive: true });
  try {
    const archiveName = `sing-box-${VERSION}-darwin-${config.upstream}.tar.gz`;
    const archive = path.join(work, archiveName);
    run('/usr/bin/curl', ['--fail', '--location', '--proto', '=https', '--proto-redir', '=https', '--retry', '3', '--max-time', '180', '--output', archive,
      `https://github.com/SagerNet/sing-box/releases/download/v${VERSION}/${archiveName}`]);
    if (sha256(archive) !== config.sha256) throw new Error('Pinned sing-box release checksum mismatch');
    // Extract only the known executable and license from the verified archive.
    const root = `sing-box-${VERSION}-darwin-${config.upstream}`;
    run('/usr/bin/tar', ['-xzf', archive, '-C', work, `${root}/sing-box`, `${root}/LICENSE`]);
    const core = path.join(resources, 'sing-box');
    fs.copyFileSync(path.join(work, root, 'sing-box'), core);
    fs.copyFileSync(path.join(work, root, 'LICENSE'), path.join(resources, 'SING-BOX-LICENSE'));
    fs.chmodSync(core, 0o755);
    sign(core, 'com.irnetfree.client.native.sing-box');
    const bridge = path.join(executables, 'IRNetFreeNative');
    const daemon = path.join(executables, 'IRNetFreeTunnelService');
    const compilerArgs = ['swiftc', '-O', '-parse-as-library', '-target', `${config.target}-apple-macos13.0`, '-framework', 'Foundation', '-framework', 'ServiceManagement', '-framework', 'Security', '-framework', 'SystemConfiguration'];
    run('/usr/bin/xcrun', [...compilerArgs, path.join(source, 'Shared.swift'), path.join(source, 'Bridge.swift'), '-o', bridge]);
    sign(bridge, 'com.irnetfree.client.native');
    const generated = path.join(work, 'NativeBuild.swift');
    fs.writeFileSync(generated, `// Generated from the signed, bundled binaries. Do not edit.\nenum NativeBuild {\n    static let clientRequirement = "cdhash H\\\"${cdhash(bridge)}\\\""\n    static let bridgeSHA256 = "${sha256(bridge)}"\n    static let singboxSHA256 = "${sha256(core)}"\n}\n`);
    run('/usr/bin/xcrun', [...compilerArgs, path.join(source, 'Shared.swift'), path.join(source, 'TunnelService.swift'), generated, '-o', daemon]);
    sign(daemon, 'com.irnetfree.client.tunnel');
    const launchDaemons = path.join(contents, 'Library', 'LaunchDaemons');
    fs.mkdirSync(launchDaemons, { recursive: true });
    fs.copyFileSync(path.join(source, 'com.irnetfree.client.tunnel.plist'), path.join(launchDaemons, 'com.irnetfree.client.tunnel.plist'));
    fs.writeFileSync(path.join(resources, 'build-manifest.json'), JSON.stringify({
      architecture: arch, minimumMacOS: '13.0', signing: 'ad-hoc-beta', singBoxVersion: VERSION,
      archiveSHA256: config.sha256, bridgeSHA256: sha256(bridge), daemonSHA256: sha256(daemon), singBoxSHA256: sha256(core),
    }, null, 2) + '\n');
    console.log(`Native macOS ${arch} components compiled and pinned (${VERSION}, ad-hoc beta)`);
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
}

async function afterPack(context) {
  if (context.electronPlatformName !== 'darwin') return;
  const arch = typeof context.arch === 'string' ? context.arch : ({ 1: 'x64', 3: 'arm64' })[context.arch];
  await buildNative(path.join(context.appOutDir, `${context.packager.appInfo.productFilename}.app`), arch, context.packager.projectDir);
}
module.exports = afterPack;
module.exports.buildNative = buildNative;
module.exports.ARCHIVES = ARCHIVES;
// electron-builder 24 does not ad-hoc sign when identity is null. Use its
// custom signer so the containing app is signed too, while preserving the
// already pinned bridge/core bytes (re-signing those invalidates daemon pins).
function signingOptions(options) {
  const pinned = new Set(['MacOS/IRNetFreeNative', 'MacOS/IRNetFreeTunnelService', 'Resources/native/sing-box']);
  return {
    ...options,
    identity: '-',
    identityValidation: false,
    gatekeeperAssess: false,
    preAutoEntitlements: false,
    ignore: (file) => pinned.has(path.relative(path.join(options.app, 'Contents'), file).split(path.sep).join('/')) || Boolean(options.ignore?.(file)),
    optionsForFile: (file) => ({ ...options.optionsForFile?.(file), hardenedRuntime: false, timestamp: 'none' }),
  };
}
module.exports.signingOptions = signingOptions;
module.exports.sign = async (options) => {
  const { signAsync } = require('@electron/osx-sign');
  await signAsync(signingOptions(options));
};
if (require.main === module) {
  const [appPath, arch] = process.argv.slice(2);
  if (!appPath || !arch) throw new Error('Usage: node scripts/build-mac-native.js /path/IRNetFree.app x64|arm64');
  buildNative(path.resolve(appPath), arch).catch((error) => { console.error(error); process.exitCode = 1; });
}
