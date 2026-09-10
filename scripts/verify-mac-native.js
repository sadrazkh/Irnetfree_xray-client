'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');

function verify(appPath, expectedArch) {
  const contents = path.join(appPath, 'Contents');
  const manifest = JSON.parse(fs.readFileSync(path.join(contents, 'Resources/native/build-manifest.json'), 'utf8'));
  if (expectedArch && manifest.architecture !== expectedArch) throw new Error('Native architecture does not match package');
  const components = [
    ['MacOS/IRNetFreeNative', manifest.bridgeSHA256],
    ['MacOS/IRNetFreeTunnelService', manifest.daemonSHA256],
    ['Resources/native/sing-box', manifest.singBoxSHA256],
  ];
  for (const [relative, expected] of components) {
    const file = path.join(contents, relative);
    const actual = crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
    if (!expected || actual !== expected) throw new Error(`Native binary changed after pinning: ${relative}`);
    if (process.platform === 'darwin') {
      execFileSync('/usr/bin/codesign', ['--verify', '--strict', file], { stdio: 'pipe' });
      const output = execFileSync('/usr/bin/lipo', ['-archs', file], { encoding: 'utf8' }).trim();
      const want = manifest.architecture === 'x64' ? 'x86_64' : 'arm64';
      if (output !== want) throw new Error(`Wrong architecture for ${relative}: ${output}`);
    }
  }
  const plist = path.join(contents, 'Library/LaunchDaemons/com.irnetfree.client.tunnel.plist');
  const xml = fs.readFileSync(plist, 'utf8');
  if (!xml.includes('<key>BundleProgram</key><string>Contents/MacOS/IRNetFreeTunnelService</string>')) throw new Error('Invalid launch daemon BundleProgram');
  if (process.platform === 'darwin') {
    execFileSync('/usr/bin/plutil', ['-lint', plist], { stdio: 'pipe' });
    execFileSync('/usr/bin/codesign', ['--verify', '--deep', '--strict', appPath], { stdio: 'pipe' });
  }
  console.log(`Verified native macOS ${manifest.architecture} package: ${appPath}`);
  return manifest;
}
module.exports = async (context) => {
  if (context.electronPlatformName === 'darwin') verify(path.join(context.appOutDir, `${context.packager.appInfo.productFilename}.app`));
};
module.exports.verify = verify;
if (require.main === module) {
  if (!process.argv[2]) throw new Error('Usage: node scripts/verify-mac-native.js /path/IRNetFree.app [x64|arm64]');
  verify(path.resolve(process.argv[2]), process.argv[3]);
}
