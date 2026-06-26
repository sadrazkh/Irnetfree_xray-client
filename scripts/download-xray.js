'use strict';
/**
 * Downloads the latest Xray-core release binary into ./bin for the current OS/arch.
 * Run with: npm run get-xray
 *
 * No external deps — uses Node's https + the built-in zip extraction via PowerShell
 * (Windows) or `unzip` (mac/linux).
 */

const https = require('https');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { execFileSync } = require('child_process');

const BIN_DIR = path.join(__dirname, '..', 'bin');
const API = 'https://api.github.com/repos/XTLS/Xray-core/releases/latest';

function getJSON(url) {
  return new Promise((resolve, reject) => {
    https.get(url, { headers: { 'User-Agent': 'xray-client-downloader' } }, (res) => {
      if (res.statusCode >= 300 && res.headers.location) {
        return resolve(getJSON(res.headers.location));
      }
      let body = '';
      res.on('data', (c) => (body += c));
      res.on('end', () => { try { resolve(JSON.parse(body)); } catch (e) { reject(e); } });
    }).on('error', reject);
  });
}

function download(url, dest) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(dest);
    const req = (u) => https.get(u, { headers: { 'User-Agent': 'xray-client-downloader' } }, (res) => {
      if (res.statusCode >= 300 && res.headers.location) { req(res.headers.location); return; }
      if (res.statusCode !== 200) { reject(new Error('HTTP ' + res.statusCode)); return; }
      res.pipe(file);
      file.on('finish', () => file.close(() => resolve(dest)));
    }).on('error', reject);
    req(url);
  });
}

function assetName() {
  const plat = os.platform();
  const arch = os.arch();
  if (plat === 'win32') return arch === 'arm64' ? 'Xray-windows-arm64-v8a.zip' : 'Xray-windows-64.zip';
  if (plat === 'darwin') return arch === 'arm64' ? 'Xray-macos-arm64-v8a.zip' : 'Xray-macos-64.zip';
  // linux
  return arch === 'arm64' ? 'Xray-linux-arm64-v8a.zip' : 'Xray-linux-64.zip';
}

function unzip(zipPath, destDir) {
  if (os.platform() === 'win32') {
    execFileSync('powershell', ['-NoProfile', '-Command',
      `Expand-Archive -Path '${zipPath}' -DestinationPath '${destDir}' -Force`], { stdio: 'inherit' });
  } else {
    execFileSync('unzip', ['-o', zipPath, '-d', destDir], { stdio: 'inherit' });
    const exe = path.join(destDir, 'xray');
    if (fs.existsSync(exe)) fs.chmodSync(exe, 0o755);
  }
}

(async () => {
  try {
    fs.mkdirSync(BIN_DIR, { recursive: true });
    console.log('Fetching latest Xray-core release info…');
    const rel = await getJSON(API);
    const want = assetName();
    const asset = (rel.assets || []).find(a => a.name === want);
    if (!asset) {
      console.error('Could not find asset', want, 'in release', rel.tag_name);
      console.error('Available:', (rel.assets || []).map(a => a.name).join(', '));
      process.exit(1);
    }
    console.log(`Downloading ${asset.name} (${rel.tag_name})…`);
    const zipPath = path.join(BIN_DIR, asset.name);
    await download(asset.browser_download_url, zipPath);
    console.log('Extracting…');
    unzip(zipPath, BIN_DIR);
    fs.unlinkSync(zipPath);
    const exe = path.join(BIN_DIR, os.platform() === 'win32' ? 'xray.exe' : 'xray');
    console.log(fs.existsSync(exe) ? '✓ Xray ready: ' + exe : '⚠ Extracted but xray binary not found in ' + BIN_DIR);

    console.log('\nFor TUN mode (system-wide tunnel) you also need, in the bin/ folder:');
    console.log('  • tun2socks(.exe)  https://github.com/xjasonlyu/tun2socks/releases');
    console.log('  • wintun.dll (Windows only)  https://www.wintun.net/  (place next to tun2socks.exe)');
  } catch (e) {
    console.error('Failed:', e.message);
    console.error('You can manually download from https://github.com/XTLS/Xray-core/releases and place xray(.exe) in', BIN_DIR);
    process.exit(1);
  }
})();
