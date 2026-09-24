'use strict';
/**
 * Where the window may go and what may be handed to the OS to open.
 *
 * The window shows one page of our own, with the preload bridge attached, so a
 * navigation anywhere else — a link in a log line, a server name, a
 * subscription's text — would hand that bridge to whatever page it reached.
 * And shell.openExternal passes a URL to whichever program owns its scheme:
 * file:, smb:, ms-settings: and custom protocol handlers are not links a user
 * clicked in a browser. So the window navigates only to its own page, opens no
 * window of its own, and the OS is given web links and nothing else.
 */
const { pathToFileURL } = require('url');

/** http: or https: — the only schemes the app ever hands to the OS. */
function isWebUrl(url) {
  if (typeof url !== 'string' || !url) return false;
  try {
    const u = new URL(url);
    return u.protocol === 'https:' || u.protocol === 'http:';
  } catch { return false; }
}

/**
 * The app's own page (`pagePath`, a file path), with any hash or query. Paths
 * compare case-insensitively where the file system does (Windows, macOS).
 */
function isAppPage(url, pagePath, platform = process.platform) {
  if (typeof url !== 'string' || !pagePath) return false;
  try {
    const u = new URL(url);
    if (u.protocol !== 'file:') return false;
    const norm = (p) => {
      const s = decodeURIComponent(p);
      return platform === 'win32' || platform === 'darwin' ? s.toLowerCase() : s;
    };
    return norm(u.pathname) === norm(pathToFileURL(pagePath).pathname);
  } catch { return false; }
}

module.exports = { isWebUrl, isAppPage };
