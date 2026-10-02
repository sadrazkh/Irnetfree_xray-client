'use strict';
/**
 * Who may use the relay: one owner, one password (the env secret
 * RELAY_PASSWORD, 12 characters at least — the relay refuses to start
 * otherwise), compared in constant time; sessions of 30 days in the store,
 * named in an HMAC-signed cookie; failed logins limited per IP (5 in 15 min)
 * and, past ten in a row from anywhere, with a growing wait.
 */
const crypto = require('crypto');

const sha256 = (s) => crypto.createHash('sha256').update(s).digest();
function safeEqual(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

const DAY = 24 * 3600 * 1000;

function createAuth({ password, secret, store, now = Date.now, windowMs = 15 * 60 * 1000, maxFailures = 5, sessionMs = 30 * DAY }) {
  if (typeof password !== 'string' || password.length < 12) throw new Error('RELAY_PASSWORD must be at least 12 characters');
  const pwHash = sha256(password);
  const perIp = new Map();      // ip → the times of its recent failures
  let globalFails = 0;          // in a row, from anywhere
  let globalLastFail = 0;

  const checkPassword = (input) => safeEqual(sha256(String(input == null ? '' : input)), pwHash);

  function recent(ip) {
    const t = now();
    const list = (perIp.get(ip) || []).filter((x) => t - x < windowMs);
    if (list.length) perIp.set(ip, list); else perIp.delete(ip);
    return list;
  }

  /** null when a login may be tried now, else the milliseconds to wait. */
  function loginWait(ip) {
    const t = now();
    const list = recent(ip);
    if (list.length >= maxFailures) return Math.max(1000, list[0] + windowMs - t);
    if (globalFails >= 10) {
      const delay = Math.min(60 * 1000, 1000 * 2 ** (globalFails - 10));
      const wait = globalLastFail + delay - t;
      if (wait > 0) return wait;
    }
    return null;
  }

  function loginFailed(ip) {
    const list = recent(ip);
    list.push(now());
    perIp.set(ip, list);
    globalFails++;
    globalLastFail = now();
    if (perIp.size > 10000) perIp.clear();   // a flood is not allowed to grow the map forever
  }

  function loginSucceeded(ip) {
    perIp.delete(ip);
    globalFails = 0;
  }

  // the signing key binds the sessions to the CURRENT password: rotating RELAY_PASSWORD (the natural "log everyone
  // out" after a lost phone) invalidates every cookie at once; the same password across a restart keeps them (review M2)
  const signingKey = crypto.createHmac('sha256', secret).update(pwHash).digest();
  const sign = (id) => crypto.createHmac('sha256', signingKey).update(id).digest('base64url');

  /** A new session; the cookie value is `<id>.<signature>`. Expired sessions are swept here. */
  function createSession(ip) {
    const id = crypto.randomBytes(16).toString('base64url');
    const t = now();
    store.update((d) => {
      for (const [k, s] of Object.entries(d.sessions)) if (!s || !(s.exp > t)) delete d.sessions[k];
      d.sessions[id] = { exp: t + sessionMs, createdAt: t, ip: String(ip || '') };
    });
    return id + '.' + sign(id);
  }

  function verifySession(cookie) {
    if (typeof cookie !== 'string') return null;
    const i = cookie.indexOf('.');
    if (i <= 0) return null;
    const id = cookie.slice(0, i);
    const sig = cookie.slice(i + 1);
    if (!/^[A-Za-z0-9_-]{22}$/.test(id) || !safeEqual(sig, sign(id))) return null;
    const s = store.get().sessions[id];
    if (!s || !(s.exp > now())) return null;
    return { id, exp: s.exp };
  }

  function destroySession(id) {
    store.update((d) => { delete d.sessions[id]; });
  }

  return { checkPassword, loginWait, loginFailed, loginSucceeded, createSession, verifySession, destroySession };
}

module.exports = { createAuth, safeEqual, sha256 };
