'use strict';
/**
 * Downloads / integrates / updates the runtime binaries the app needs, WITHOUT
 * rebuilding the installer. Everything lands in a writable directory
 * (userData/bin) which the managers check before the bundled bin/.
 *
 * Components:
 *   - xray      : XTLS/Xray-core (zip → xray.exe + geoip.dat + geosite.dat)
 *   - geo       : geoip.dat + geosite.dat only (Loyalsoldier rules, direct .dat)
 *   - tun2socks : xjasonlyu/tun2socks (zip → tun2socks.exe)
 *   - wintun    : wintun.dll (wintun.net zip, Windows only)
 *
 * No external deps: Node https + PowerShell/unzip for extraction.
 */

const https = require('https');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { execFileSync } = require('child_process');

const GEO_BASE = 'https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download';
const WINTUN_URL = 'https://www.wintun.net/builds/wintun-0.14.1.zip';

function getJSON(url) {
  return new Promise((resolve, reject) => {
    https.get(url, { headers: { 'User-Agent': 'IRNetFree' } }, (res) => {
      if (res.statusCode >= 300 && res.headers.location) return resolve(getJSON(res.headers.location));
      let body = '';
      res.on('data', (c) => (body += c));
      res.on('end', () => { try { resolve(JSON.parse(body)); } catch (e) { reject(e); } });
    }).on('error', reject);
  });
}

function downloadFile(url, dest, onProgress) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(dest);
    const req = (u, depth) => {
      if (depth > 6) return reject(new Error('too many redirects'));
      https.get(u, { headers: { 'User-Agent': 'IRNetFree' } }, (res) => {
        if (res.statusCode >= 300 && res.headers.location) { req(res.headers.location, depth + 1); return; }
        if (res.statusCode !== 200) { reject(new Error('HTTP ' + res.statusCode)); return; }
        const total = parseInt(res.headers['content-length'] || '0', 10);
        let got = 0;
        res.on('data', (c) => {
          got += c.length;
          if (onProgress && total) onProgress(Math.min(100, Math.round((got / total) * 100)));
        });
        res.pipe(file);
        file.on('finish', () => file.close(() => resolve(dest)));
      }).on('error', (e) => { try { fs.unlinkSync(dest); } catch {} reject(e); });
    };
    req(url, 0);
  });
}

function tmpDir(tag) {
  const d = path.join(os.tmpdir(), `irnf-${tag}-${Date.now()}`);
  fs.mkdirSync(d, { recursive: true });
  return d;
}

function unzip(zipPath, destDir) {
  if (os.platform() === 'win32') {
    execFileSync('powershell', ['-NoProfile', '-NonInteractive', '-Command',
      `Expand-Archive -LiteralPath '${zipPath}' -DestinationPath '${destDir}' -Force`],
      { windowsHide: true });
  } else {
    execFileSync('unzip', ['-o', zipPath, '-d', destDir], { stdio: 'ignore' });
  }
}

/** Recursively find the first file whose basename matches (case-insensitive). */
function findFile(dir, name) {
  const want = name.toLowerCase();
  const stack = [dir];
  while (stack.length) {
    const cur = stack.pop();
    let entries;
    try { entries = fs.readdirSync(cur, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      const full = path.join(cur, e.name);
      if (e.isDirectory()) stack.push(full);
      else if (e.name.toLowerCase() === want) return full;
    }
  }
  return null;
}

class Downloader {
  /** @param {object} opts { destDir, onLog, onProgress(component, pct) } */
  constructor(opts = {}) {
    this.destDir = opts.destDir;
    this.onLog = opts.onLog || (() => {});
    this.onProgress = opts.onProgress || (() => {});
    fs.mkdirSync(this.destDir, { recursive: true });
  }

  log(msg, level = 'info') { this.onLog('[download] ' + msg, level); }

  xrayAssetName() {
    const arch = os.arch();
    if (os.platform() === 'win32') return arch === 'arm64' ? 'Xray-windows-arm64-v8a.zip' : 'Xray-windows-64.zip';
    if (os.platform() === 'darwin') return arch === 'arm64' ? 'Xray-macos-arm64-v8a.zip' : 'Xray-macos-64.zip';
    return arch === 'arm64' ? 'Xray-linux-arm64-v8a.zip' : 'Xray-linux-64.zip';
  }

  tun2socksAssetName() {
    const arch = os.arch() === 'arm64' ? 'arm64' : 'amd64';
    if (os.platform() === 'win32') return `tun2socks-windows-${arch}.zip`;
    if (os.platform() === 'darwin') return `tun2socks-darwin-${arch}.zip`;
    return `tun2socks-linux-${arch}.zip`;
  }

  /** Download + integrate one component. Returns { ok, files } or throws. */
  async download(component) {
    switch (component) {
      case 'xray': return this.getXray();
      case 'geo': return this.getGeo();
      case 'tun2socks': return this.getTun2socks();
      case 'wintun': return this.getWintun();
      default: throw new Error('unknown component: ' + component);
    }
  }

  async getXray() {
    this.log('Fetching latest Xray-core release info…');
    const rel = await getJSON('https://api.github.com/repos/XTLS/Xray-core/releases/latest');
    const want = this.xrayAssetName();
    const asset = (rel.assets || []).find(a => a.name === want);
    if (!asset) throw new Error('asset not found: ' + want);
    const work = tmpDir('xray');
    const zip = path.join(work, want);
    this.log(`Downloading ${want} (${rel.tag_name})…`);
    await downloadFile(asset.browser_download_url, zip, (p) => this.onProgress('xray', p));
    this.log('Extracting xray…');
    unzip(zip, work);
    const exeName = os.platform() === 'win32' ? 'xray.exe' : 'xray';
    const exe = findFile(work, exeName);
    if (!exe) throw new Error('xray binary not found in archive');
    const out = [];
    out.push(this.place(exe, exeName, true));
    for (const dat of ['geoip.dat', 'geosite.dat']) {
      const f = findFile(work, dat);
      if (f) out.push(this.place(f, dat));
    }
    this.cleanup(work);
    this.log('✓ Xray integrated: ' + out.join(', '));
    return { ok: true, files: out };
  }

  async getGeo() {
    const out = [];
    for (const dat of ['geoip.dat', 'geosite.dat']) {
      const dest = path.join(this.destDir, dat);
      this.log(`Downloading ${dat}…`);
      await downloadFile(`${GEO_BASE}/${dat}`, dest + '.tmp', (p) => this.onProgress('geo', p));
      fs.renameSync(dest + '.tmp', dest);
      out.push(dest);
    }
    this.log('✓ Geo files integrated.');
    return { ok: true, files: out };
  }

  async getTun2socks() {
    this.log('Fetching latest tun2socks release info…');
    const rel = await getJSON('https://api.github.com/repos/xjasonlyu/tun2socks/releases/latest');
    const want = this.tun2socksAssetName();
    const asset = (rel.assets || []).find(a => a.name === want);
    if (!asset) throw new Error('asset not found: ' + want);
    const work = tmpDir('t2s');
    const zip = path.join(work, want);
    this.log(`Downloading ${want} (${rel.tag_name})…`);
    await downloadFile(asset.browser_download_url, zip, (p) => this.onProgress('tun2socks', p));
    this.log('Extracting tun2socks…');
    unzip(zip, work);
    const exeName = os.platform() === 'win32' ? '.exe' : '';
    // archive names the binary like tun2socks-windows-amd64.exe
    let exe = findFile(work, this.tun2socksAssetName().replace('.zip', exeName));
    if (!exe) exe = findFile(work, os.platform() === 'win32' ? 'tun2socks.exe' : 'tun2socks');
    if (!exe) throw new Error('tun2socks binary not found in archive');
    const placed = this.place(exe, os.platform() === 'win32' ? 'tun2socks.exe' : 'tun2socks', true);
    this.cleanup(work);
    this.log('✓ tun2socks integrated: ' + placed);
    return { ok: true, files: [placed] };
  }

  async getWintun() {
    if (os.platform() !== 'win32') return { ok: true, files: [] };
    const work = tmpDir('wintun');
    const zip = path.join(work, 'wintun.zip');
    this.log('Downloading wintun.dll…');
    await downloadFile(WINTUN_URL, zip, (p) => this.onProgress('wintun', p));
    unzip(zip, work);
    const archDir = os.arch() === 'arm64' ? 'arm64' : 'amd64';
    let dll = findFile(path.join(work, 'wintun', 'bin', archDir), 'wintun.dll');
    if (!dll) dll = findFile(work, 'wintun.dll');
    if (!dll) throw new Error('wintun.dll not found in archive');
    const placed = this.place(dll, 'wintun.dll');
    this.cleanup(work);
    this.log('✓ wintun integrated: ' + placed);
    return { ok: true, files: [placed] };
  }

  /** Copy a file into destDir; mark executable on unix. */
  place(src, name, exec = false) {
    const dest = path.join(this.destDir, name);
    fs.copyFileSync(src, dest);
    if (os.platform() !== 'win32') {
      if (exec) { try { fs.chmodSync(dest, 0o755); } catch {} }
      if (os.platform() === 'darwin') this.macPrepareBinary(dest, exec);
    }
    return dest;
  }

  /**
   * Make a downloaded file usable on macOS:
   *  - strip the quarantine attribute (harmless if absent)
   *  - ad-hoc codesign executables so Gatekeeper (esp. Apple Silicon, which
   *    refuses to run unsigned binaries) lets them launch.
   */
  macPrepareBinary(dest, exec) {
    try { execFileSync('xattr', ['-dr', 'com.apple.quarantine', dest]); } catch {}
    if (exec) {
      // Apple Silicon REFUSES to exec an unsigned binary (SIGKILL "Killed: 9")
      // with no useful error — which later masquerades as "tun2socks did not
      // create a utun device". An ad-hoc signature is enough to run a CLI
      // binary, so a codesign failure here must be fatal, not a warning.
      try { execFileSync('codesign', ['--force', '--sign', '-', dest]); }
      catch (e) {
        const isArm = os.arch() === 'arm64';
        const msg = 'codesign failed for ' + path.basename(dest) + ': ' + (e.message || e) +
          (isArm ? ' — on Apple Silicon the binary cannot run unsigned. Install Xcode Command Line Tools (xcode-select --install) and retry.' : '');
        if (isArm) { this.log(msg, 'error'); throw new Error(msg); }
        this.log(msg, 'warn');
      }
    }
  }

  cleanup(dir) { try { fs.rmSync(dir, { recursive: true, force: true }); } catch {} }
}

module.exports = { Downloader };
