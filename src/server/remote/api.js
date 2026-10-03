'use strict';
/**
 * Remote access settings and status for LuCI (spec §3.5 R7, mounted by
 * src/server/luciApi.js when present) and the start of the agent from
 * server.js.
 *
 *   remote_get()        → { relay: {enabled, relayUrl, name, tokenSet}, cloudflared: {installed, enabled, tokenSet} }
 *   remote_set(arg)     → { ok: true }    arg = { relay?: {enabled?, relayUrl?, name?, token?}, cloudflared?: {enabled?, token?} }
 *                         (throws an Error with the reason on a refusal; then nothing of either half is saved)
 *   remote_status()     → { relay: agent.status(), cloudflared: {installed, running, lastLine, …, enabled, tokenSet, applying, apply} }
 *   cloudflared_install() → { accepted: true }     (opkg in the background; progress in the log)
 *
 * The settings live in <dataDir>/remote.json — a store of their own, not
 * store.json: the device token must never travel with a backup export or
 * app:init, and no other branch's file has to change. A token is written only
 * when non-empty and is never returned or logged: "set" is all anyone sees.
 *
 * Two ways in for the facade: `start()` (server.js, once the port is known)
 * builds the real thing and keeps it as `current()`; the four methods are also
 * exported at module level, bound to whatever `current()` is at call time.
 */
const path = require('path');
const fs = require('fs');
const { Store } = require('../../main/store');

/**
 * The store for remote.json: the device token lives in it, so the file is
 * kept 0600 — after every write (the Store writes a fresh tmp file and renames
 * it, so the mode is set again each time) and on an existing file at start.
 * On the router only root runs the service, but a privilege-dropped daemon
 * must not be able to read a relay credential (review M8).
 */
class SecretStore extends Store {
  constructor(file, defaults) {
    super(file, defaults);
    if (fs.existsSync(file)) this._private();
  }
  _private() { try { fs.chmodSync(this.filePath, 0o600); } catch { /* best effort (Windows: the read-only bit only) */ } }
  save() {
    const ok = super.save();
    if (ok) this._private();
    return ok;
  }
}
const { createRemoteAgent } = require('./agent');
const { createCloudflared, isTunnelToken } = require('./cloudflared');
const { isToken } = require('./token');

const DEFAULTS = () => ({ relay: { enabled: false, relayUrl: '', name: '', token: '' }, cloudflared: { enabled: false, token: '' }, lastIps: [] });

/** `https://host[:port]` or `https://host[:port]/` — nothing else; returned normalised (no trailing slash). */
function validRelayUrl(s) {
  if (typeof s !== 'string' || s.length > 200) return null;
  let u;
  try { u = new URL(s.trim()); } catch { return null; }
  if (u.protocol !== 'https:' || !u.hostname || u.username || u.password || u.search || u.hash) return null;
  if (u.pathname !== '/' && u.pathname !== '') return null;
  return 'https://' + u.host;
}

const validName = (s) => {
  if (typeof s !== 'string') return null;
  const v = s.trim();
  if (v.length > 40 || /[\x00-\x1f\x7f]/.test(v)) return null;
  return v;
};

function createRemoteApi({ store, service, agent, cloudflared, log = () => {} }) {
  const read = (key) => Object.assign({}, DEFAULTS()[key], store.get(key, {}) || {});
  const relay = () => read('relay');
  const cf = () => read('cloudflared');
  // cloudflared.apply runs in the background and answers {ok, error}: kept
  // for remote_status, so "enabled" that does not run can say why (v1.16.1)
  let applying = 0;
  let lastApply = null;       // { ok, error? } of the last apply that finished

  function remote_get() {
    const r = relay();
    const c = cf();
    return {
      relay: { enabled: !!r.enabled, relayUrl: r.relayUrl || '', name: r.name || '', tokenSet: !!r.token },
      cloudflared: { installed: cloudflared.installed(), enabled: !!c.enabled, tokenSet: !!c.token }
    };
  }

  /** The relay half of a remote_set, validated: the settings it would store (throws on a refusal). */
  function nextRelay(a, cur) {
    const next = Object.assign({}, cur);
    if ('relayUrl' in a) {
      const v = a.relayUrl === '' ? '' : validRelayUrl(a.relayUrl);
      if (v === null) throw new Error('relayUrl must be https://<host>[:port]/ with no path');
      next.relayUrl = v;
    }
    if ('name' in a) {
      const v = validName(a.name);
      if (v === null) throw new Error('name must be at most 40 printable characters');
      next.name = v;
    }
    if ('token' in a && a.token !== '' && a.token != null) {
      if (!isToken(a.token)) throw new Error('token must be the 43-character device token the relay showed');
      next.token = a.token;
    }
    if ('enabled' in a) next.enabled = !!a.enabled;
    if (next.enabled && (!next.relayUrl || !next.token)) throw new Error('enabling needs the relay URL and the device token');
    return next;
  }

  /**
   * The Cloudflare half, validated the same way: "enabled" is refused while
   * cloudflared is not installed or no tunnel token is set — v1.16.0 took it,
   * said "applied" and started nothing (field report L2). Judged only when
   * the call carries this half, so a tick v1.16.0 saved does not block a
   * relay change.
   */
  function nextCloudflared(a, cur) {
    const next = Object.assign({}, cur);
    if ('token' in a && a.token !== '' && a.token != null) {
      if (!isTunnelToken(a.token)) throw new Error('the Cloudflare tunnel token does not look right');
      next.token = String(a.token).trim();
    }
    if ('enabled' in a) next.enabled = !!a.enabled;
    if (next.enabled && !cloudflared.installed()) throw new Error('enabling needs cloudflared — install it first');
    if (next.enabled && !next.token) throw new Error('enabling needs the Cloudflare tunnel token');
    return next;
  }

  /** Apply the tunnel's settings in the background; its result is what remote_status reports. */
  function applyCloudflared(c) {
    applying++;
    return Promise.resolve()
      .then(() => cloudflared.apply({ enabled: c.enabled, token: c.token }))
      .then((r) => { lastApply = r && r.ok === false ? { ok: false, error: String(r.error || 'failed') } : { ok: true }; },
        (e) => { lastApply = { ok: false, error: (e && e.message) || String(e) }; log('cloudflared: ' + lastApply.error, 'error'); })
      .then(() => { applying--; });
  }

  function remote_set(arg) {
    const a = arg && typeof arg === 'object' ? arg : {};
    // both halves are judged before either is written: a refusal leaves nothing half-saved
    const relayCur = relay();
    const relayNext = a.relay && typeof a.relay === 'object' ? nextRelay(a.relay, relayCur) : relayCur;
    const cfCur = cf();
    const cfNext = a.cloudflared && typeof a.cloudflared === 'object' ? nextCloudflared(a.cloudflared, cfCur) : cfCur;
    const relayChanged = JSON.stringify(relayNext) !== JSON.stringify(relayCur);
    const cfChanged = JSON.stringify(cfNext) !== JSON.stringify(cfCur);
    if (relayChanged) { store.set('relay', relayNext); if (relayNext.relayUrl !== relayCur.relayUrl) store.set('lastIps', []); }
    if (cfChanged) store.set('cloudflared', cfNext);
    if (relayChanged) {
      const r = relay();
      if (r.enabled) { agent.reconfigure(); log(`remote: relay link ${r.relayUrl} (${r.name || 'router'}) — (re)started`); }
      else { agent.stop(); log('remote: relay link off'); }
    }
    if (cfChanged) applyCloudflared(cf());
    return { ok: true };
  }

  /** The relay agent's status; cloudflared's, with whether it is meant to run, a token is set, an apply is running and how the last one went. */
  async function remote_status() {
    const st = await cloudflared.status();
    const c = cf();
    return {
      relay: agent.status(),
      cloudflared: Object.assign({}, st, { enabled: !!c.enabled, tokenSet: !!c.token, applying: applying > 0, apply: lastApply })
    };
  }

  function cloudflared_install() {
    return cloudflared.install(() => { const c = cf(); if (c.enabled && c.token) return applyCloudflared({ enabled: true, token: c.token }); });
  }

  /** At service start: the link if enabled, the tunnel's drop-in and bypass if enabled (they live in /tmp and the live rules). */
  function boot() {
    const r = relay();
    if (r.enabled) agent.start();
    const c = cf();
    if (c.enabled && c.token && cloudflared.installed()) applyCloudflared({ enabled: true, token: c.token });
  }

  function stop() { agent.stop(); }

  return { remote_get, remote_set, remote_status, cloudflared_install, boot, stop, agent, cloudflared, store };
}

let current = null;

/** The default log: the service's own when it has one, else stdout/stderr with the router's prefix (procd → syslog). */
function defaultLog(service) {
  return (line, level) => {
    if (typeof service.log === 'function') { try { service.log(line, level); return; } catch { /* fall through */ } }
    const out = level === 'warn' || level === 'error' ? process.stderr : process.stdout;
    try { out.write('irnetfree: ' + (level === 'warn' || level === 'error' ? '[' + level + '] ' : '') + line + '\n'); } catch { /* broken pipe */ }
  };
}

/**
 * The one call server.js makes once it listens: builds the store, the agent,
 * the cloudflared driver and the api; starts what the settings say.
 * Never throws — a failure here must not take the gateway's process down.
 */
function start({ service, localPort, uiToken, log, store, agent, cloudflared, dataDir } = {}) {
  try {
    const l = log || defaultLog(service || {});
    const dir = dataDir || (service && service.dataDir) || process.cwd();
    const st = store || new SecretStore(path.join(dir, 'remote.json'), DEFAULTS());
    const cf = cloudflared || createCloudflared({ service, log: l });
    const ag = agent || createRemoteAgent({
      getSettings: () => Object.assign({}, DEFAULTS().relay, st.get('relay', {}) || {}, { lastIps: st.get('lastIps', []) || [] }),
      saveLastIps: (ips) => { try { st.set('lastIps', ips); } catch { /* best effort */ } },
      service, localPort, uiToken, log: l
    });
    const api = createRemoteApi({ store: st, service, agent: ag, cloudflared: cf, log: l });
    current = api;
    api.boot();
    return api;
  } catch (e) {
    try { (log || console.error)('remote: not started: ' + ((e && e.message) || e), 'error'); } catch { /* nothing */ }
    return null;
  }
}

const notStarted = () => { throw new Error('remote access is not started'); };
const bound = {
  remote_get: (...a) => (current || notStarted()).remote_get(...a),
  remote_set: (...a) => (current || notStarted()).remote_set(...a),
  remote_status: (...a) => (current || notStarted()).remote_status(...a),
  cloudflared_install: (...a) => (current || notStarted()).cloudflared_install(...a)
};
const METHODS = Object.freeze(Object.keys(bound));

module.exports = Object.assign({
  createRemoteApi, start, DEFAULTS, validRelayUrl, validName, METHODS,
  current: () => current,
  methods: () => Object.assign({}, bound),
  _reset: () => { current = null; }
}, bound);
