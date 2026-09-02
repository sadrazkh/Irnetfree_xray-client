'use strict';
/**
 * Request guards for the headless server — pure functions so they are testable
 * without binding a port.
 *
 * Two attacks these stop, both possible in the recommended setup (bound to
 * 127.0.0.1 with no token):
 *  - cross-site requests: any web page can POST to http://127.0.0.1:6969/rpc
 *    with a CORS-simple body (text/plain, no preflight) and drive the panel.
 *    Browser requests carry Origin (fetch/XHR) or Referer (EventSource); either
 *    must be the panel's own origin.
 *  - DNS rebinding: a page on attacker.example that resolves to 127.0.0.1 makes
 *    the browser send `Host: attacker.example`, which would also let it READ
 *    responses. Without a token we only accept loopback Host values.
 */
const LOOPBACK = new Set(['127.0.0.1', 'localhost', '::1', '[::1]']);

/** "host:port" → "host" (lower-case). IPv6 keeps its brackets: "[::1]:1" → "[::1]". */
function hostnameOf(hostHeader) {
  if (!hostHeader) return '';
  const h = String(hostHeader).trim();
  if (h.startsWith('[')) return h.slice(0, h.indexOf(']') + 1).toLowerCase();
  const i = h.lastIndexOf(':');
  return (i === -1 ? h : h.slice(0, i)).toLowerCase();
}

/**
 * A token is the authentication when one is set (public bind); --no-auth is the
 * user's explicit choice to run open. Otherwise only loopback hosts are valid —
 * the port is deliberately ignored so an `ssh -L 8080:127.0.0.1:6969` forward
 * still works.
 */
function hostAllowed(hostHeader, { token, noAuth } = {}) {
  if (token || noAuth) return true;
  return LOOPBACK.has(hostnameOf(hostHeader));
}

/** Origin (or Referer) must match the Host the request arrived on. */
function originAllowed(headers) {
  const raw = headers.origin || headers.referer;
  if (!raw) return true;                       // curl / scripts: token or loopback protects them
  let origin;
  try { origin = new URL(raw); } catch { return false; }
  return origin.host.toLowerCase() === String(headers.host || '').toLowerCase();
}

module.exports = { hostAllowed, originAllowed, hostnameOf };
