'use strict';
/**
 * Remote access settings and status for LuCI (spec §3.5 R7, mounted by
 * src/server/luciApi.js when present) and the start of the agent from
 * server.js.
 *
 *   remote_get()        → { relay: {enabled, relayUrl, name, tokenSet}, cloudflared: {installed, enabled, tokenSet} }
 *   remote_set(arg)     → { ok: true }    arg = { relay?: {enabled?, relayUrl?, name?, token?}, cloudflared?: {enabled?, token?} }
 *   remote_status()     → { relay: agent.status(), cloudflared: {installed, running, lastLine, …} }
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

  function remote_get() {
    const r = relay();
    const c = cf();
    return {
      relay: { enabled: !!r.enabled, relayUrl: r.relayUrl || '', name: r.name || '', tokenSet: !!r.token },
      cloudflared: { installed: cloudflared.installed(), enabled: !!c.enabled, tokenSet: !!c.token }
    };
  }

  function remote_set(arg) {
    const a = arg && typeof arg === 'object' ? arg : {};
    let relayChanged = false;
    let cfChanged = false;
    if (a.relay && typeof a.relay === 'object') {
      const cur = relay();
      const next = Object.assign({}, cur);
      if ('relayUrl' in a.relay) {
        const v = a.relay.relayUrl === '' ? '' : validRelayUrl(a.relay.relayUrl);
        if (v === null) throw new Error('relayUrl must be https://<host>[:port]/ with no path');
        next.relayUrl = v;
      }
      if ('name' in a.relay) {
        const v = validName(a.relay.name);
        if (v === null) throw new Error('name must be at most 40 printable characters');
        next.name = v;
      }
      if ('token' in a.relay && a.relay.token !== '' && a.relay.token != null) {
        if (!isToken(a.relay.token)) throw new Error('token must be the 43-character device token the relay showed');
        next.token = a.relay.token;
      }
      if ('enabled' in a.relay) next.enabled = !!a.relay.enabled;
      if (next.enabled && (!next.relayUrl || !next.token)) throw new Error('enabling needs the relay URL and the device token');
      relayChanged = JSON.stringify(next) !== JSON.stringify(cur);
      if (relayChanged) { store.set('relay', next); if (next.relayUrl !== cur.relayUrl) store.set('lastIps', []); }
    }
    if (a.cloudflared && typeof a.cloudflared === 'object') {
      const cur = cf();
      const next = Object.assign({}, cur);
      if ('token' in a.cloudflared && a.cloudflared.token !== '' && a.cloudflared.token != null) {
        if (!isTunnelToken(a.cloudflared.token)) throw new Error('the Cloudflare tunnel token does not look right');
        next.token = String(a.cloudflared.token).trim();
      }
      if ('enabled' in a.cloudflared) next.enabled = !!a.cloudflared.enabled;
      cfChanged = JSON.stringify(next) !== JSON.stringify(cur);
      if (cfChanged) store.set('cloudflared', next);
    }
    if (relayChanged) {
      const r = relay();
      if (r.enabled) { agent.reconfigure(); log(`remote: relay link ${r.relayUrl} (${r.name || 'router'}) — (re)started`); }
      else { agent.stop(); log('remote: relay link off'); }
    }
    if (cfChanged) {
      const c = cf();
      Promise.resolve().then(() => cloudflared.apply({ enabled: c.enabled, token: c.token })).catch((e) => log('cloudflared: ' + e.message, 'error'));
    }
    return { ok: true };
  }

  async function remote_status() {
    return { relay: agent.status(), cloudflared: await cloudflared.status() };
  }

  function cloudflared_install() {
    return cloudflared.install(() => { const c = cf(); if (c.enabled && c.token) return cloudflared.apply({ enabled: true, token: c.token }); });
  }

  /** At service start: the link if enabled, the tunnel's drop-in and bypass if enabled (they live in /tmp and the live rules). */
  function boot() {
    const r = relay();
    if (r.enabled) agent.start();
    const c = cf();
    if (c.enabled && c.token && cloudflared.installed()) {
      Promise.resolve().then(() => cloudflared.apply({ enabled: true, token: c.token })).catch((e) => log('cloudflared: ' + e.message, 'error'));
    }
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
