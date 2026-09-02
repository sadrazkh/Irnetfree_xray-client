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
 *    responses. Without a token we only accept loopback Host values — and on a
 *    loopback bind that holds even under `--no-auth`, which is about tokens, not
 *    about trusting whatever Host a browser was told to send.
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
 * A token is real authentication, so it lifts the Host restriction on any bind.
 *
 * `--no-auth` only lifts it when the bind is genuinely non-loopback. On a
 * loopback bind the server never required a token in the first place (it only
 * auto-generates one for a public bind, and the token check passes whenever no
 * token is set), so there `--no-auth` turns off nothing but this rebinding
 * guard — which is exactly what it must not do.
 *
 * Otherwise only loopback hosts are valid — the port is deliberately ignored so
 * an `ssh -L 8080:127.0.0.1:6969` forward still works. `loopbackBind` is passed
 * in by the caller (this stays a pure function) and defaults to the safe
 * assumption that we are on loopback.
 */
function hostAllowed(hostHeader, { token, noAuth, loopbackBind = true } = {}) {
  if (token) return true;
  if (noAuth && !loopbackBind) return true;
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
