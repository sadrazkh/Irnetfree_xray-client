'use strict';
/**
 * Updating the app from inside the app: which release asset installs here,
 * and whether the bytes that arrived are the bytes that were published.
 *
 * The release workflow attaches SHA256SUMS-<os>.txt next to the installers.
 * A download is compared against them before it is handed to the OS; on a
 * mismatch the file is deleted and nothing is opened. Pure helpers, tested;
 * main.js does the downloading and the opening.
 */
const fs = require('fs');
const crypto = require('crypto');

/** The installer for this platform and arch, by electron-builder's artifact names (package.json → build). */
function pickUpdateAsset(assets, platform = process.platform, arch = process.arch) {
  const list = Array.isArray(assets) ? assets : [];
  const find = (re) => list.find(a => a && re.test(String(a.name || ''))) || null;
  if (platform === 'win32') return find(/^IRNetFree-Setup-.*\.exe$/i);
  if (platform === 'darwin') return find(new RegExp(`^IRNetFree-.*-${arch === 'arm64' ? 'arm64' : 'x64'}\\.dmg$`, 'i'));
  return find(/^IRNetFree-.*\.AppImage$/i);
}

/** `sha256sum` output → { fileName: hex }. A line that is not "64 hex, whitespace, [*]name" is ignored. */
function parseSha256Sums(text) {
  const out = {};
  for (const m of String(text || '').matchAll(/^([0-9a-f]{64})\s+\*?(\S.*?)\s*$/gim)) out[m[2]] = m[1].toLowerCase();
  return out;
}

function sha256File(file) {
  return new Promise((resolve, reject) => {
    const h = crypto.createHash('sha256');
    fs.createReadStream(file)
      .on('data', (c) => h.update(c))
      .on('end', () => resolve(h.digest('hex')))
      .on('error', reject);
  });
}

module.exports = { pickUpdateAsset, parseSha256Sums, sha256File };
