'use strict';
/**
 * A link handed to the app from outside: a browser, a panel's "add to IRNetFree"
 * button, the OS. It may be one of these and nothing else:
 *
 *   irnetfree://routing/<rest>             a routing or chain share link (routeShare.js)
 *   irnetfree://import/<percent-encoded>   one subscription URL or one config link
 *   irnetfree://import?url=<…>&name=<…>    the same, with a name for the subscription
 *
 * In the first form everything after import/ is the text, so a query the sender
 * left unencoded stays the link's own.
 *
 * Any web page can make a browser open one of these, so nothing here acts on it:
 * this only says what it is. The window asks before anything is written, and
 * nothing ever connects. Android's core/DeepLink.kt has the same rules and cases.
 */
const { isHttpProxyLink } = require('./parser');

const PROTOCOL = 'irnetfree';
const MAX_TEXT = 8192;
const MAX_NAME = 60;
/** A routing share link carries its servers and profile in the one line. */
const MAX_ROUTING = 65536;
const CONFIG_SCHEMES = new Set(['vless', 'vmess', 'trojan', 'ss', 'socks', 'socks5', 'wireguard', 'wg', 'tuic', 'anytls', 'hysteria2', 'hy2']);

function decode(s) {
  try { return decodeURIComponent(s); } catch { return null; }
}

/**
 * A name a link brought, as the window's question may show it: one line, with no
 * bidi control. Otherwise a page could write lines of its own under the app's
 * question, or turn the rest of the line around.
 */
function cleanName(name) {
  return String(name == null ? '' : name).replace(/[\u0000-\u001f\u007f\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, ' ')
    .replace(/\s+/g, ' ').trim().slice(0, MAX_NAME);
}

/** The name in a link's #fragment. Never its credentials. */
function remarkOf(text) {
  const i = text.indexOf('#');
  return i === -1 ? '' : cleanName(decode(text.slice(i + 1)));
}

/**
 * What one piece of text is: { kind: 'sub', text, host, name } for a subscription
 * URL, { kind: 'config', text, scheme, name } for a config link, null for anything
 * else (file:, javascript:, several lines, too long, control characters, an HTTP
 * proxy link, a backslash in a URL, which the parsers read differently, a scheme
 * with nothing after it).
 */
function classify(raw, name) {
  const text = String(raw == null ? '' : raw).trim();
  if (!text || text.length > MAX_TEXT || /[\u0000-\u001f\u007f]/.test(text)) return null;
  const m = /^([a-z][a-z0-9+.-]*):\/\/\S/i.exec(text);
  if (!m) return null;
  const scheme = m[1].toLowerCase();
  const given = cleanName(name);
  if (scheme === 'http' || scheme === 'https') {
    if (isHttpProxyLink(text) || text.includes('\\')) return null;
    let host = '';
    try { host = new URL(text).hostname; } catch { return null; }
    return host ? { kind: 'sub', text, host, name: given } : null;
  }
  if (!CONFIG_SCHEMES.has(scheme)) return null;
  return { kind: 'config', text, scheme, name: given || remarkOf(text) };
}

/** What a link handed to the app is ({ kind: 'routing', text } or classify's), or null when it is none of the above. */
function parseDeepLink(url) {
  const s = String(url == null ? '' : url).trim();
  if (!s || s.length > MAX_ROUTING || /[\u0000- \u007f]/.test(s)) return null;
  const routing = /^irnetfree:\/\/routing\/(.+)$/i.exec(s);
  if (routing) return { kind: 'routing', text: 'irnetfree://routing/' + routing[1] };
  const query = /^irnetfree:\/\/import\/?\?(.+)$/i.exec(s);
  if (query) {
    const params = {};
    for (const pair of query[1].split('#')[0].split('&')) {
      const eq = pair.indexOf('=');
      if (eq > 0) params[pair.slice(0, eq).toLowerCase()] = decode(pair.slice(eq + 1));
    }
    return params.url ? classify(params.url, params.name) : null;
  }
  const path = /^irnetfree:\/\/import\/(.+)$/i.exec(s);
  if (!path) return null;
  const body = decode(path[1]);
  return body == null ? null : classify(body);
}

/** The link among a launch's arguments: Windows and Linux hand it to a new process that way. */
function linkFromArgv(argv) {
  if (!Array.isArray(argv)) return null;
  return argv.find((a) => typeof a === 'string' && /^irnetfree:\/\//i.test(a)) || null;
}

module.exports = { PROTOCOL, parseDeepLink, linkFromArgv, classify };
