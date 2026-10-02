'use strict';
/**
 * The small local API LuCI's pages call — `POST /luci/<method>` on the
 * headless server (server.js mounts it: loopback peers only, body
 * `{ token, arg }`, the token compared in constant time, any Content-Type).
 * The rpcd plugin `/usr/libexec/rpcd/luci.irnetfree` forwards each ubus
 * call here with the token from <data_dir>/token, so the token never travels
 * in argv or to the browser.
 *
 * The methods and their shapes are the contract of the v1.16 spec (§3.4):
 * do not rename. Actions (connect / disconnect / reconnect / subs_update)
 * start the work and answer { accepted: true } at once — the page follows
 * the status; a connect to the config that is already up answers
 * { accepted: true, already: true } (v1.16.1). settings_set takes only the four router keys, validated the
 * way settings:set validates them, and applies them live. A method that
 * refuses its argument throws { code: 400 }; server.js answers that — and
 * anything else a method throws — as HTTP 200 { error }, because
 * uclient-fetch drops the body of a non-2xx reply (only an unknown method
 * is a 404 there).
 *
 * remote_get / remote_set / remote_status / cloudflared_install belong to
 * feat/remote's api (src/server/remote/api.js); they are delegated when that
 * api is mounted (`remoteApi`: the object, or a getter for it — it may be
 * mounted after this facade is built) and answer { error: 'remote not
 * available' } otherwise.
 */

const { validMacs } = require('../main/openwrtNet');

/** The peer address of a request is this machine's own loopback. */
function isLoopbackPeer(addr) {
  const a = String(addr == null ? '' : addr).toLowerCase();
  if (a === '::1') return true;
  const v4 = a.startsWith('::ffff:') ? a.slice(7) : a;
  return /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(v4);
}

const err = (code, message) => Object.assign(new Error(message), { code });

/** true / false / 1 / 0 / '1' / '0' / 'true' / 'false' → boolean; anything else → undefined (ignored). */
function asBool(v) {
  if (typeof v === 'boolean') return v;
  if (v === 1 || v === '1' || v === 'true' || v === 'on') return true;
  if (v === 0 || v === '0' || v === 'false' || v === 'off' || v === '') return false;
  return undefined;
}

/** A MAC list as an array, or as text separated by commas / whitespace / newlines. */
function macList(v) {
  const raw = Array.isArray(v) ? v : String(v == null ? '' : v).split(/[\s,;]+/);
  return validMacs(raw.map((x) => String(x == null ? '' : x).trim()).filter(Boolean));
}

const REMOTE_METHODS = ['remote_get', 'remote_set', 'remote_status', 'cloudflared_install'];

function createLuciApi({ service, remoteApi = null } = {}) {
  if (!service) throw new Error('createLuciApi: a service is required');
  const remote = () => {
    const r = typeof remoteApi === 'function' ? remoteApi() : remoteApi;
    return r && typeof r === 'object' ? r : null;
  };
  /** An action that runs in the background; a failure is a log line, never an unhandled rejection. */
  const background = (what, p) => {
    Promise.resolve(p).catch((e) => service.log(`LuCI: ${what} failed: ${(e && e.message) || e}`, 'error'));
    return { accepted: true };
  };
  const arg = (a) => (a && typeof a === 'object' && !Array.isArray(a) ? a : {});

  const methods = {
    async status() {
      const mem = service.memInfo();
      const out = Object.assign({}, service.connSnapshot(), {
        version: service.version,
        traffic: service.traffic(),
        memAvailableKb: mem.memAvailableKb == null ? null : mem.memAvailableKb
      });
      // feat/remote's remote_status() (async): { relay: {state, path, since,
      // lastError, relayHost}, cloudflared: {installed, running, lastLine} } —
      // absent or not started → no `remote` key; one that throws → {error}
      const r = remote();
      if (r && typeof r.remote_status === 'function') {
        try { out.remote = await r.remote_status(); }
        catch (e) { out.remote = { error: (e && e.message) || String(e) }; }
      }
      return out;
    },
    configs: () => service.configsForLuci(),
    async connect(a) {
      const id = a.id;
      if (typeof id !== 'string' || !id) throw err(400, 'connect: an id is required');
      const p = Promise.resolve(service.actions.connect(id));
      // On a router a Connect on the config that is already up answers
      // { ok, already } without an await on anything (service.js, S2) — so it
      // is known before the next turn of the event loop. Said to the page,
      // which tells the user to press Reconnect for an edit (field report L4);
      // a real connect takes 20-40 s and stays in the background.
      const early = await Promise.race([p.then((r) => r, () => null), new Promise((resolve) => setImmediate(resolve, null))]);
      if (early && early.already) return { accepted: true, already: true };
      return background('connect', p);
    },
    select(a) {
      const id = a.id;
      if (typeof id !== 'string' || !id) throw err(400, 'select: an id is required');
      service.actions.select(id);
      return { ok: true };
    },
    disconnect: () => background('disconnect', service.actions.disconnect()),
    reconnect: () => background('reconnect', service.actions.reconnect()),
    test: () => service.testThroughTunnel(),
    subs_update: () => background('subscription update', service.actions.subsUpdate()),
    settings_get: () => service.settingsForLuci(),
    async settings_set(a, raw) {
      if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw err(400, 'settings_set: an object is required');
      const partial = {};
      for (const k of ['autoConnect', 'killSwitch', 'lanBlockQuic']) {
        if (!(k in a)) continue;
        const b = asBool(a[k]);
        if (b === undefined) throw err(400, `settings_set: ${k} must be a boolean`);
        partial[k] = b;
      }
      if ('lanBypassMacs' in a) partial.lanBypassMacs = macList(a.lanBypassMacs);
      await service.setSettingsForLuci(partial);
      return { ok: true, settings: service.settingsForLuci() };
    },
    devices: () => service.devices(),
    log(a) {
      const n = Math.max(1, Math.min(500, parseInt(a.lines, 10) || 300));
      return { lines: service.logTail(n) };
    },
    diagnostics: () => service.diagnostics()
  };
  // feat/remote's api: remote_get / remote_set / cloudflared_install are
  // synchronous, remote_status is async, and remote_set throws an Error on
  // invalid input — awaited either way, and a thrown Error is the reply's
  // {error} (a refused setting is not a server failure) — and a warn line:
  // syslog keeps warn, so the refusal is on the router, not only on a page
  // that may have been closed (field report L1).
  for (const m of REMOTE_METHODS) {
    methods[m] = async (a) => {
      const r = remote();
      if (!r || typeof r[m] !== 'function') return { error: 'remote not available' };
      try { return await r[m](a); }
      catch (e) {
        const msg = (e && e.message) || String(e);
        if (typeof service.log === 'function') service.log(`LuCI: ${m} refused: ${msg}`, 'warn');
        return { error: msg };
      }
    };
  }

  return {
    /** The method's result; an unknown method throws { code: 404 }, a refused argument { code: 400 }. */
    async handle(method, a) {
      const fn = Object.prototype.hasOwnProperty.call(methods, method) ? methods[method] : null;
      if (!fn) throw err(404, 'unknown method');
      return fn(arg(a), a);
    }
  };
}

module.exports = { createLuciApi, isLoopbackPeer, asBool, macList, REMOTE_METHODS };
