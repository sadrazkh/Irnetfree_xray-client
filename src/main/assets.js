'use strict';
/**
 * Presence of each runtime component. Shared by the desktop main process and
 * the headless service so the two can never disagree about what is installed
 * (the headless copy used to omit sing-box, so the UI showed it "missing" for
 * ever after a successful download).
 */
const fs = require('fs');
const path = require('path');
const { ENGINES, engineExe } = require('./engines');

/**
 * @param {string[]} dirs  bin directories to search, writable first, bundled last
 * @param {string} [platform] process.platform value (injectable for tests)
 */
function assetStatus(dirs, platform = process.platform) {
  const has = (name) => dirs.some(d => d && fs.existsSync(path.join(d, name)));
  const win = platform === 'win32';
  const out = { platform };
  for (const id of Object.keys(ENGINES)) out[id] = has(engineExe(id, platform));
  out.tun2socks = has(win ? 'tun2socks.exe' : 'tun2socks');
  out.wintun = win ? has('wintun.dll') : true;
  out.geoip = has('geoip.dat');
  out.geosite = has('geosite.dat');
  return out;
}

module.exports = { assetStatus };
