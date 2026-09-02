'use strict';
/**
 * Headless core service — the same functionality as the Electron app's main
 * process, but with NO Electron dependency, so it runs on a GUI-less Linux
 * server. It reuses every backend manager from ../main/* verbatim and exposes a
 * single `invoke(channel, arg)` dispatcher that mirrors the Electron IPC handlers
 * (see main.js). Events are pushed through `onEvent`.
 *
 * The desktop-only bits (tray, taskbar overlay, dialog, "relaunch as admin",
 * Windows LAN firewall / kill switch) are intentionally omitted or no-oped.
 */

const path = require('path');
const fs = require('fs');
const os = require('os');

const { parseMany, parseLink, makeWireguardServer, makeProxyServer, applyServerEdits, buildShareLink, migrateStoredServer, parseWireguardConf } = require('../main/parser');
const { buildConfig, buildTestConfig } = require('../main/configBuilder');
const { buildSingboxConfig } = require('../main/singboxBuilder');
const { engineFormat } = require('../main/engines');
const { chooseEngine, testEngineFor } = require('../main/engineChoice');
const { assetStatus: scanAssets } = require('../main/assets');
const { XrayManager, getFreePort } = require('../main/xrayManager');
const { setSystemProxy } = require('../main/sysproxy');
const { tcpPing, httpThroughProxy, uploadThroughProxy, ipInfo } = require('../main/netutils');
const { Store } = require('../main/store');
const { SubscriptionManager } = require('../main/subscription');
const { TunManager } = require('../main/tunManager');
const { StatsPoller } = require('../main/stats');
const { Downloader } = require('../main/downloader');
const { listProcesses, collectProcessIps, pruneProcCache, ProcWatcher } = require('../main/procRouter');
const { pendingReconnectKeys, snapshotApplied } = require('../main/settingsMeta');
const { NetWatcher } = require('../main/netWatcher');

const DEFAULT_SETTINGS = {
  socksPort: 10808,
  httpPort: 10809,
  allowLan: false,           // loopback only, like the desktop. `ssh -L` reaches a loopback
                             // bind fine; 0.0.0.0 would make the auth-less SOCKS port an
                             // open relay on a VPS. The user opts in under Settings → LAN.
  routingMode: 'global',
  blockAds: true,
  enableSniffing: true,
  dns: ['1.1.1.1', '8.8.8.8'],
  logLevel: 'warning',
  apiPort: 10085,
  systemProxy: false,        // headless: no desktop session to set a system proxy for
  tunMode: false,
  autoUpdateSubs: true,
  autoUpdateInterval: 60,
  customRules: [],
  advancedRouting: false,
  routeRules: [],
  routeDefault: '',
  procRouteWatch: false,
  killSwitch: false,
  // recover automatically when the machine's network changes (read live, so it
  // needs no reconnect to take effect)
  autoReconnectOnNetworkChange: true,
  theme: 'dark',
  defaultEngine: 'xray',
  lang: 'fa'
};

function defaultDataDir() {
  const base = process.env.IRNETFREE_DATA
    || (process.platform === 'win32'
      ? path.join(process.env.APPDATA || os.homedir(), 'IRNetFree')
      : path.join(process.env.XDG_DATA_HOME || path.join(os.homedir(), '.local', 'share'), 'irnetfree'));
  fs.mkdirSync(base, { recursive: true });
  return base;
}

function createService(opts = {}) {
  const dataDir = opts.dataDir || defaultDataDir();
  fs.mkdirSync(dataDir, { recursive: true });
  const userBinDir = path.join(dataDir, 'bin');
  fs.mkdirSync(userBinDir, { recursive: true });

  // bin/ that ships with the source checkout (xray + geo may be downloaded here)
  const bundledBinDir = path.join(__dirname, '..', '..', 'bin');

  const listeners = new Set();
  const send = (channel, payload) => { for (const cb of listeners) { try { cb(channel, payload); } catch {} } };

  const appVersion = (() => {
    try { return require(path.join(__dirname, '..', '..', 'package.json')).version || '0.0.0'; } catch { return '0.0.0'; }
  })();

  let isQuitting = false;
  let xrayReloading = false;
  let userDisconnecting = false;
  let procWatcher = null;
  let netWatcher = null;
  let recoverTimer = null;
  let recovering = false;        // a network-change recovery is in flight
  let recoverQueued = null;      // reason of a trigger that arrived during that recovery
  const RECOVER_BACKOFF_MS = [2000, 5000, 15000];
  // Settings the LIVE tunnel was built from (null when disconnected) — see
  // ../main/settingsMeta.js.
  let appliedSettings = null;

  const store = new Store(path.join(dataDir, 'store.json'), {
    servers: [], subscriptions: [], settings: DEFAULT_SETTINGS, activeServerId: null, xrayPath: null
  }, {
    // Losing the store means losing every saved server — never let that pass
    // unnoticed. A load error also travels through app:init, since no browser is
    // listening yet at this point.
    onError: (kind, info) => {
      const line = kind === 'load'
        ? `Saved data could not be read: ${info.reason}` +
          (info.recovered ? ' — recovered from the unsaved copy' : '') +
          (info.backup ? ` (the unreadable file was kept at ${info.backup})` : '')
        : `Could not write saved data to disk: ${info.reason}`;
      console.error('  ! ' + line);
      send('log', { line, level: 'error' });
      send('store-error', Object.assign({ kind }, info));
    }
  });

  migrateServers();

  function binDirs() { return [userBinDir, bundledBinDir]; }
  function assetStatus() {
    const st = scanAssets(binDirs());
    if (xray) st.xray = st.xray || xray.binExists('xray');
    return st;
  }

  const xray = new XrayManager({
    binPath: store.get('xrayPath', null),
    dataDir,
    extraBinDirs: [userBinDir],
    onLog: (line, level) => send('log', { line, level }),
    onStatus: (state, info) => {
      if (xrayReloading && state === 'stopped') return;
      if (state === 'stopped' && !userDisconnecting && store.get('activeServerId', null)) {
        // headless: no Windows kill switch; just report the drop
      }
      send('xray-status', { state, info });
    }
  });

  const subs = new SubscriptionManager({
    getSubs: () => store.get('subscriptions', []),
    setSubs: (arr) => store.set('subscriptions', arr),
    getServers: () => store.get('servers', []),
    setServers: (arr) => store.set('servers', arr),
    onUpdate: (sub, info) => send('subs-updated', { sub, info, servers: store.get('servers', []), subs: store.get('subscriptions', []) })
  });

  const tun = new TunManager({
    binDir: bundledBinDir,
    extraDirs: [userBinDir],
    onLog: (line, level) => send('log', { line, level })
  });

  const stats = new StatsPoller({
    binPath: xray.anyBin(),
    apiPort: getSettings().apiPort,
    onStats: (s) => send('stats', s)
  });

  const downloader = new Downloader({
    destDir: userBinDir,
    onLog: (line, level) => send('log', { line, level }),
    onProgress: (component, pct) => send('asset-progress', { component, pct })
  });

  /* ----------------------------- settings / data ----------------------------- */
  function getSettings() { return Object.assign({}, DEFAULT_SETTINGS, store.get('settings', {})); }

  /**
   * One-time upgrade of the saved servers to the shape the current parser and
   * config builder expect (see migrateStoredServer). Runs at startup and writes
   * back, so it costs one pass over the list per launch at most — every later read
   * of `servers` sees the migrated records without repeating the work.
   *
   * Silent on purpose: it has to run before anything reads `servers`, and at that
   * point createService() has not returned, so no onEvent listener exists yet.
   */
  function migrateServers() {
    const servers = store.get('servers', []);
    if (!Array.isArray(servers) || !servers.length) return;
    const migrated = servers.map(migrateStoredServer);
    // migrateStoredServer returns the very same object when there is nothing to
    // do, so this is false on every launch after the first.
    if (!migrated.some((s, i) => s !== servers[i])) return;
    store.set('servers', migrated);
  }

  function getChains() {
    const chains = store.get('chains', null);
    if (Array.isArray(chains)) return chains;
    const legacy = store.get('chain', []) || [];
    const seed = legacy.length >= 2 ? [{ id: 'chain-' + Date.now().toString(36), name: 'زنجیره ۱', members: legacy.slice() }] : [];
    store.set('chains', seed);
    return seed;
  }

  function getPool() {
    const raw = store.get('pool', []);
    if (!Array.isArray(raw)) return [];
    return raw.filter(e => e && e.id).map(e => ({
      id: String(e.id),
      name: String(e.name || 'Proxy').trim() || 'Proxy',
      target: String(e.target || ''),
      socksPort: parseInt(e.socksPort, 10) || 0,
      httpPort: parseInt(e.httpPort, 10) || 0,
      enabled: e.enabled !== false
    }));
  }

  /* ----------------------------- process routing ----------------------------- */
  function activeProcNames(settings) {
    if (!settings || !settings.advancedRouting) return [];
    return [...new Set((settings.routeRules || []).filter(r => r && r.type === 'process' && r.value).map(r => String(r.value)))];
  }
  const loadProcCache = () => store.get('procIpCache', {}) || {};
  const saveProcCache = (c) => store.set('procIpCache', c);

  async function effectiveSettings() {
    const s = getSettings();
    const names = activeProcNames(s);
    if (!names.length) return s;
    const cache = loadProcCache();
    pruneProcCache(cache);
    let ipsByName = {};
    try { const r = await collectProcessIps(names, cache); ipsByName = r.ips; saveProcCache(cache); }
    catch (e) { send('log', { line: 'Process routing resolve failed: ' + e.message, level: 'warn' }); }
    const rules = (s.routeRules || []).map(r => {
      if (r && r.type === 'process' && r.value) {
        const list = ipsByName[r.value] || (cache[r.value] && cache[r.value].ips) || [];
        return { type: 'ip', value: list.join(','), target: r.target };
      }
      return r;
    });
    return Object.assign({}, s, { routeRules: rules });
  }

  /* ----------------------------- plan / config ----------------------------- */
  // Mirrors main.js buildActive(). Kept in sync deliberately (duplicated so the
  // desktop app stays untouched).
  function buildActive(serverId, settings) {
    const servers = store.get('servers', []);
    const byId = (id) => servers.find(s => s.id === id);
    const serversById = {};
    for (const s of servers) serversById[s.id] = s;

    const chains = getChains();
    const chainById = {};
    for (const c of chains) chainById[c.id] = c;
    const membersOf = (c) => (c && Array.isArray(c.members) ? c.members.map(id => serversById[id]).filter(Boolean) : []);
    const chainsById = {};
    for (const c of chains) chainsById[c.id] = membersOf(c);
    const legacyChain = (store.get('chain', []) || []).map(byId).filter(Boolean);

    let plan, label;
    let entryAddrs = [];
    const addEntryForTarget = (tg) => {
      if (!tg || tg === 'direct' || tg === 'block') return;
      if (tg === 'chain') { if (legacyChain[0]) entryAddrs.push(legacyChain[0].address); return; }
      if (String(tg).indexOf('chain:') === 0) {
        const m = chainsById[String(tg).slice('chain:'.length)];
        if (m && m[0]) entryAddrs.push(m[0].address);
        return;
      }
      if (serversById[tg]) entryAddrs.push(serversById[tg].address);
    };

    if (serverId === '__pool__') {
      const targetExists = (tg) => {
        if (String(tg).indexOf('chain:') === 0) { const m = chainsById[String(tg).slice('chain:'.length)]; return !!(m && m.length >= 2); }
        return !!serversById[tg];
      };
      const entries = getPool().filter(e => e.enabled && e.socksPort && targetExists(e.target))
        .map(e => ({ id: e.id, name: e.name, target: e.target, socksPort: e.socksPort, httpPort: e.httpPort }));
      if (!entries.length) throw new Error(settings.lang === 'en'
        ? 'Enable at least one valid proxy in the pool (with a port and an existing target).'
        : 'حداقل یک پروکسیِ معتبر در استخر را فعال کن (با پورت و یک مقصدِ موجود).');
      plan = { mode: 'pool', entries, primary: entries[0].target, serversById, chainsById, chain: legacyChain };
      label = (settings.lang === 'en' ? '🧩 Proxy Pool' : '🧩 استخر پروکسی') + ` (${entries.length})`;
      for (const e of entries) addEntryForTarget(e.target);
    } else if (serverId === '__advanced__') {
      const rules = Array.isArray(settings.routeRules) ? settings.routeRules : [];
      const def = settings.routeDefault || (servers[0] && servers[0].id) || 'direct';
      plan = { mode: 'advanced', serversById, chainsById, chain: legacyChain, rules, def };
      label = '🧭 ' + (settings.lang === 'en' ? 'Advanced routing' : 'روتینگ ویژه');
      const targets = new Set(rules.map(r => r && r.target));
      targets.add(def);
      for (const tg of targets) addEntryForTarget(tg);
    } else if (chainById[serverId]) {
      const members = membersOf(chainById[serverId]);
      if (members.length < 2) throw new Error(settings.lang === 'en' ? 'This chain needs at least 2 servers' : 'این زنجیره حداقل به ۲ سرور نیاز دارد');
      plan = { mode: 'chain', chain: members, name: chainById[serverId].name };
      label = chainById[serverId].name;
      entryAddrs = [members[0].address];
    } else if (serverId === '__chain__') {
      if (legacyChain.length < 2) throw new Error(settings.lang === 'en' ? 'The chain needs at least 2 servers' : 'زنجیره حداقل به ۲ سرور نیاز دارد');
      plan = { mode: 'chain', chain: legacyChain };
      label = legacyChain.map(s => s.name).join(' → ');
      entryAddrs = [legacyChain[0].address];
    } else {
      const server = byId(serverId);
      if (!server) throw new Error(settings.lang === 'en' ? 'Server not found' : 'سرور پیدا نشد');
      plan = { mode: 'single', server };
      label = server.name;
      entryAddrs = [server.address];
    }
    entryAddrs = [...new Set(entryAddrs.filter(Boolean))];

    const geoSt = assetStatus();
    const geoAssets = !!(geoSt.geoip && geoSt.geosite);
    let geoWarn = null;
    const usesGeo = plan.mode === 'pool' ? false : (
      (plan.mode === 'advanced' && ((settings.routeRules || []).some(r => r && /^(geoip|geosite):/i.test(String(r.value || ''))))) ||
      (plan.mode !== 'advanced' && (settings.routingMode === 'bypass-ir' || settings.routingMode === 'bypass-cn' || (settings.blockAds && plan.mode !== 'advanced'))));
    if (!geoAssets && usesGeo) {
      geoWarn = settings.lang === 'en'
        ? 'Geo files (geoip/geosite) are missing — geo-based rules were skipped. Download them under Settings → Required files.'
        : 'فایل‌های geo (geoip/geosite) موجود نیست — قوانین مبتنی بر geo نادیده گرفته شد. از تنظیمات → فایل‌های موردنیاز دانلودشان کن.';
    }

    // Per-config core selection (see engineChoice.js): a single server's own
    // choice, else the default engine; multi-server plans run on PattN when any
    // member needs it. The EFFECTIVE engine (after fallback when the binary is
    // missing) decides the config format.
    let engine = xray.resolveEngine(chooseEngine(plan, settings.defaultEngine)).id;
    let config;
    if (engineFormat(engine) === 'sing-box') {
      try {
        config = buildSingboxConfig(plan.server, settings);
      } catch (e) {
        send('log', { line: `sing-box: ${e.message} — using Xray`, level: 'warn' });
        engine = 'xray';
      }
    }
    if (!config) {
      config = buildConfig(Object.assign({}, plan), Object.assign({}, settings, { geoAssets }));
    }
    return { plan, label, entryAddrs, config, geoWarn, engine };
  }

  /* ----------------------------- connect / disconnect ----------------------------- */
  async function doConnect(serverId) {
    const settings = await effectiveSettings();
    const byId = (id) => store.get('servers', []).find(s => s.id === id);
    const { label, entryAddrs, config, geoWarn, engine } = buildActive(serverId, settings);

    send('status', { state: 'connecting', serverId });

    const check = await xray.validateWithFallback(config, engine);
    if (!check.ok) {
      send('log', { line: 'Config rejected by xray: ' + check.error, level: 'error' });
      // The official core refuses plaintext VLESS/Trojan to public addresses and the
      // fork that accepts them is not installed — say so, the renderer offers the download.
      const hint = check.plaintextRejected
        ? (settings.lang === 'en'
          ? ' — this config has no TLS; the official core refuses it. Install Xray-PattN under Settings → Required files.'
          : ' — این کانفیگ TLS ندارد و هستهٔ رسمی آن را رد می‌کند. Xray-PattN را از تنظیمات → فایل‌های موردنیاز نصب کن.')
        : '';
      // Only Error.message survives the bridge (web-api.js rebuilds it with
      // new Error(data.error)), so the hint IS the signal: the renderer keys off
      // the (untranslated) product name in it. A property set here would be
      // dropped in transit — don't add one.
      throw new Error((settings.lang === 'en' ? 'Config error: ' : 'خطای کانفیگ: ') + check.error + hint);
    }
    const runEngine = check.engine;

    // save/restore rather than clear — reapplyConnection() wraps the whole
    // teardown+reconnect in the same flag
    const prevReloading = xrayReloading;
    xrayReloading = true;
    try { await xray.start(config, runEngine); } finally { xrayReloading = prevReloading; }
    store.set('activeServerId', serverId);
    appliedSettings = snapshotApplied(getSettings());

    if (settings.systemProxy) {
      try {
        await setSystemProxy(true, { host: '127.0.0.1', httpPort: settings.httpPort, socksPort: settings.socksPort });
        send('log', { line: 'System proxy enabled', level: 'info' });
      } catch (e) { send('log', { line: 'System proxy failed: ' + e.message, level: 'error' }); }
    }

    let tunError = null;
    if (settings.tunMode) {
      if (!tun.isAvailable()) {
        tunError = settings.lang === 'en' ? 'TUN needs tun2socks in the bin folder.' : 'حالت TUN به فایل tun2socks در پوشه bin نیاز دارد.';
        send('log', { line: 'TUN requested but tun2socks not found — connected proxy-only', level: 'error' });
      } else {
        try { tun.lang = settings.lang || 'fa'; await tun.start(settings.socksPort, entryAddrs, settings.dns); send('log', { line: 'TUN mode active (whole system)', level: 'info' }); }
        catch (e) { tunError = e.message; send('log', { line: 'TUN start failed: ' + e.message, level: 'error' }); }
      }
    }

    // headless LAN info: which address forwarded clients point at
    let lan = null;
    if (settings.allowLan) lan = { ip: lanIp(), socksPort: settings.socksPort, httpPort: settings.httpPort };

    stats.setBin(xray.anyBin());
    stats.apiPort = settings.apiPort;
    stats.start(1000);

    startProcWatcher();
    // Watch for the machine's network moving under the live tunnel. Every reconnect
    // comes through here too (a settings apply, or our own recovery), so keep a
    // watcher that is already running: its baseline is the network the tunnel was
    // built for, and a change it noticed mid-rebuild is still queued on it —
    // replacing it here would adopt the NEW network as normal and leave a tunnel
    // built for the old one with nothing left to notice.
    if (!netWatcher) startNetWatcher();
    send('status', {
      state: 'connected', serverId, server: byId(serverId) || null, label, engine: runEngine,
      tun: tun.active, tunError, geoWarn, lan, pendingReconnect: pendingKeys()
    });
    // `tunError` is the one failure this function does NOT throw for: TUN is a
    // best-effort upgrade and we stay connected proxy-only without it. Callers
    // that must know whether the WHOLE system is tunnelled (the network-change
    // recovery) can only find out from here — the status event above is fire and
    // forget. The clients ignore this value; they only await the call.
    return { ok: true, tunError };
  }

  /** Reconnect-relevant settings changed since the live tunnel was built. */
  function pendingKeys() {
    return pendingReconnectKeys(appliedSettings, getSettings());
  }

  /**
   * Rebuild the connection so settings baked into it take effect (xray-core has
   * no hot reload). The headless build has no Windows firewall kill switch, so
   * this is a plain teardown + reconnect.
   */
  async function reapplyConnection() {
    const serverId = store.get('activeServerId', null);
    if (!serverId || !xray || !xray.running) return { ok: false, error: 'not connected' };

    send('status', { state: 'connecting', serverId });

    const prevReloading = xrayReloading;
    xrayReloading = true;              // intentional restart, not a drop
    try {
      stopProcWatcher();
      if (stats) stats.stop();
      try { await tun.stop(); } catch {}
      try { await setSystemProxy(false, {}); } catch {}
      if (xray) await xray.stop();
    } finally {
      xrayReloading = prevReloading;
    }

    let r;
    try {
      r = await doConnect(serverId);
    } catch (e) {
      appliedSettings = null;
      send('status', { state: 'error', message: e.message });
      return { ok: false, error: e.message };
    }
    // Pass doConnect()'s one non-throwing failure through: the tunnel is up but
    // TUN is not, so this is not a complete reconnect for whoever asked for one.
    return { ok: true, tunError: (r && r.tunError) || null };
  }

  async function rebuildActiveConfig() {
    const serverId = store.get('activeServerId', null);
    if (!serverId || !xray.running) return;
    const settings = await effectiveSettings();
    const { config, engine } = buildActive(serverId, settings);
    const prevReloading = xrayReloading;
    xrayReloading = true;
    try {
      const check = await xray.validateWithFallback(config, engine);
      if (!check.ok) throw new Error(check.error);
      await xray.start(config, check.engine);   // start() stops the old instance first
    } finally { xrayReloading = prevReloading; }
    stats.setBin(xray.anyBin());
    send('log', { line: 'Process routes applied (xray reloaded)', level: 'info' });
  }

  function startProcWatcher() {
    stopProcWatcher();
    const s = getSettings();
    if (!s.advancedRouting || !s.procRouteWatch || !activeProcNames(s).length) return;
    procWatcher = new ProcWatcher({
      getNames: () => activeProcNames(getSettings()),
      loadCache: loadProcCache, saveCache: saveProcCache,
      onGrow: () => rebuildActiveConfig(),
      onLog: (line, level) => send('log', { line, level }),
      intervalMs: 20000
    });
    procWatcher.start();
  }
  function stopProcWatcher() { if (procWatcher) { procWatcher.stop(); procWatcher = null; } }

  /**
   * The machine's network changed under a live tunnel. xray does not die when that
   * happens — it just stops passing traffic, and under TUN the bypass routes still
   * point at the old gateway — so nothing else would notice. Rebuild the connection
   * from current settings. (Mirrors main.js; the headless build has no kill switch,
   * so reapplyConnection() here is a plain teardown + rebuild.)
   *
   * Only one recovery runs at a time (see `recovering`): a watcher trigger and an
   * already-scheduled backoff retry would otherwise have two reapplyConnection()
   * calls tearing down and starting the same core against each other. A trigger
   * that arrives during a recovery is remembered rather than dropped — the rebuild
   * in flight was made for the network we have already left, and the watcher has
   * long since adopted the new one as its baseline, so nothing would fire again.
   */
  async function recoverFromNetworkChange(reason, attempt = 0) {
    // The INTENT to be connected is the saved active server, not xray.running: an
    // attempt that failed leaves the core stopped, and that is exactly the state
    // the next retry exists for. doDisconnect() clears the id, so a deliberate
    // disconnect still ends the retries.
    if (!store.get('activeServerId', null)) return;
    if (!getSettings().autoReconnectOnNetworkChange) return;
    if (recovering) { recoverQueued = reason; return; }

    recovering = true;
    try {
      await runRecovery(reason, attempt);
    } finally {
      recovering = false;
    }

    // A newer network arrived while we were rebuilding for the old one: start over
    // for it, from the first backoff step.
    const queued = recoverQueued;
    if (queued == null) return;
    recoverQueued = null;
    await recoverFromNetworkChange(queued, 0);
  }

  /** One recovery attempt. Only ever called through recoverFromNetworkChange(). */
  async function runRecovery(reason, attempt) {
    const serverId = store.get('activeServerId', null);
    // Whatever backoff step was waiting belongs to a rebuild this attempt is about
    // to redo. Leaving it armed would start a second, competing chain.
    clearTimeout(recoverTimer);
    recoverTimer = null;

    send('log', { line: `Network changed (${reason}) — rebuilding the connection`, level: 'warn' });
    send('status', { state: 'reconnecting', reason, attempt: attempt + 1 });

    // Pick the rebuild path by what the core is ACTUALLY doing. Both paths answer
    // in the same { ok, tunError, error } shape. (No kill switch here, so the
    // direct path needs none of main.js's hold/release around it.)
    let res;
    try {
      // A previous attempt already stopped the core, so there is nothing to tear
      // down and reapplyConnection() would refuse — connect straight away.
      res = (xray && xray.running) ? await reapplyConnection() : await doConnect(serverId);
    } catch (e) {
      // doConnect() throws where reapplyConnection() returns { ok: false }.
      res = { ok: false, error: (e && e.message) || String(e) };
    }

    if (res && res.ok && !res.tunError) {
      send('log', { line: 'Connection restored after the network change', level: 'info' });
      return;
    }
    // doConnect() does not throw when TUN was asked for and did not come up: it
    // reports tunError and carries on proxy-only. Calling that a restored
    // connection would tell the user the whole system is tunnelled when it is not —
    // so it counts as a failed attempt and the backoff retries it.
    if (res && res.tunError) {
      send('log', { line: 'Reconnected without the system-wide tunnel: ' + res.tunError, level: 'error' });
    }
    const delay = RECOVER_BACKOFF_MS[attempt];
    if (delay == null) {
      send('log', { line: 'Could not reconnect after the network change — giving up', level: 'error' });
      send('status', { state: 'reconnect-failed', reason });
      return;
    }
    send('log', { line: `Reconnect failed — retrying in ${delay / 1000}s`, level: 'warn' });
    recoverTimer = setTimeout(() => recoverFromNetworkChange(reason, attempt + 1), delay);
    if (recoverTimer.unref) recoverTimer.unref();
  }

  function startNetWatcher() {
    stopNetWatcher();
    netWatcher = new NetWatcher({
      read: () => os.networkInterfaces(),
      // The watcher cannot report a failure of its own (it only awaits the promise
      // to know when it may fire again), so the handler logs its own errors —
      // otherwise a throw in here would vanish without a trace.
      onChange: (why) => recoverFromNetworkChange(why).catch((e) => {
        send('log', { line: 'Network recovery failed: ' + ((e && e.message) || e), level: 'error' });
      })
    });
    netWatcher.start();
  }

  function stopNetWatcher() {
    clearTimeout(recoverTimer);
    recoverTimer = null;
    // A trigger parked behind a recovery in flight has nothing left to recover.
    // `recovering` itself is deliberately NOT cleared: the run that owns it
    // releases it in its own finally, and forcing it false here would let a second
    // recovery start alongside the one still going.
    recoverQueued = null;
    if (netWatcher) { netWatcher.stop(); netWatcher = null; }
  }

  async function doDisconnect() {
    userDisconnecting = true;
    stopProcWatcher();
    stopNetWatcher();                // nothing live to recover any more
    if (stats) stats.stop();
    try { await tun.stop(); } catch {}
    try { await setSystemProxy(false, {}); } catch {}
    if (xray) await xray.stop();
    store.set('activeServerId', null);
    appliedSettings = null;          // nothing live to be out of sync with
    send('status', { state: 'disconnected' });
    userDisconnecting = false;
  }

  /* ----------------------------- LAN address ----------------------------- */
  function lanCandidates() {
    const ifs = os.networkInterfaces();
    const out = [];
    for (const name of Object.keys(ifs)) {
      for (const ni of ifs[name] || []) {
        if (ni.family !== 'IPv4' || ni.internal) continue;
        if (ni.address === '10.255.0.2') continue;
        if (ni.address.startsWith('169.254.')) continue;
        out.push(ni.address);
      }
    }
    return out;
  }
  function lanIp() {
    const c = lanCandidates();
    const score = (a) => a.startsWith('192.168.') ? 3 : /^172\.(1[6-9]|2\d|3[01])\./.test(a) ? 2 : a.startsWith('10.') ? 1 : 0;
    c.sort((x, y) => score(y) - score(x));
    return c[0] || null;
  }

  function resolveTarget(id) {
    const servers = store.get('servers', []);
    const server = servers.find(s => s.id === id);
    if (server) return { server, chain: null };
    const chain = getChains().find(c => c.id === id);
    if (chain) {
      const byId = {}; for (const s of servers) byId[s.id] = s;
      const members = (chain.members || []).map(m => byId[m]).filter(Boolean);
      if (members.length) return { server: members[0], chain: members };
    }
    return { server: null, chain: null };
  }

  /* ----------------------------- IPC-equivalent dispatcher ----------------------------- */
  const handlers = {
    'app:init': () => ({
      servers: store.get('servers', []),
      subscriptions: store.get('subscriptions', []),
      settings: getSettings(),
      activeServerId: store.get('activeServerId', null),
      chain: store.get('chain', []),
      chains: getChains(),
      pool: getPool(),
      xrayReady: xray.binExists(),
      tunAvailable: tun.isAvailable(),
      elevated: tun.isElevated(),
      assets: assetStatus(),
      platform: process.platform,
      version: appVersion,
      pendingReconnect: pendingKeys(),
      storeError: store.loadError
    }),

    'servers:import': (text) => {
      const { servers: parsed, errors } = parseMany(text);
      const merged = store.get('servers', []).concat(parsed);
      store.set('servers', merged);
      return { added: parsed.length, errors, servers: merged };
    },
    'servers:add': (link) => { const server = parseLink(link); const e = store.get('servers', []); e.push(server); store.set('servers', e); return server; },
    'servers:addWireguard': (fields) => { const server = makeWireguardServer(fields || {}); const e = store.get('servers', []); e.push(server); store.set('servers', e); return { server, servers: e }; },
    'servers:addProxy': (fields) => { const server = makeProxyServer(fields || {}); const e = store.get('servers', []); e.push(server); store.set('servers', e); return { server, servers: e }; },
    // headless: no native dialog; the browser picks the file itself
    'wg:pickConf': () => ({ ok: false, error: 'not available in server mode' }),
    'wg:parseConf': (text) => {
      try { return { ok: true, fields: parseWireguardConf(text) }; }
      catch (err) { return { ok: false, error: err.message }; }
    },
    'servers:update': ({ id, fields }) => {
      const servers = store.get('servers', []);
      const idx = servers.findIndex(s => s.id === id);
      if (idx === -1) return { ok: false, error: 'not found', servers };
      servers[idx] = applyServerEdits(servers[idx], fields || {});
      store.set('servers', servers);
      return { ok: true, server: servers[idx], servers };
    },
    'servers:delete': (id) => { const servers = store.get('servers', []).filter(s => s.id !== id); store.set('servers', servers); return servers; },
    'servers:clear': () => { store.set('servers', []); return []; },
    'servers:list': () => store.get('servers', []),
    'servers:link': (id) => { const s = store.get('servers', []).find(x => x.id === id); return s ? buildShareLink(s) : ''; },

    'chain:get': () => store.get('chain', []),
    'chain:set': (ids) => { const v = Array.isArray(ids) ? ids : []; store.set('chain', v); return v; },
    'chains:list': () => getChains(),
    'chains:set': (chains) => {
      const v = Array.isArray(chains) ? chains.filter(c => c && c.id).map(c => ({ id: c.id, name: String(c.name || 'Chain').trim() || 'Chain', members: Array.isArray(c.members) ? c.members.filter(Boolean) : [] })) : [];
      store.set('chains', v); return v;
    },
    'pool:list': () => getPool(),
    'pool:set': (entries) => {
      const v = Array.isArray(entries) ? entries.filter(c => c && c.id).map(c => ({
        id: String(c.id), name: String(c.name || 'Proxy').trim() || 'Proxy', target: String(c.target || ''),
        socksPort: parseInt(c.socksPort, 10) || 0, httpPort: parseInt(c.httpPort, 10) || 0, enabled: c.enabled !== false
      })) : [];
      store.set('pool', v); return v;
    },

    'subs:list': () => subs.list(),
    'subs:add': async ({ url, name }) => { const res = await subs.add(url, name); return { sub: res.sub, added: res.added, servers: store.get('servers', []) }; },
    'subs:refresh': async (id) => { const res = await subs.refresh(id); return { added: res.added, servers: store.get('servers', []), subs: subs.list() }; },
    'subs:refreshAll': async () => { const results = await subs.refreshAll(); return { results, servers: store.get('servers', []), subs: subs.list() }; },
    'subs:remove': (id) => { subs.remove(id); return { subs: subs.list(), servers: store.get('servers', []) }; },
    'subs:autoUpdate': ({ id, enabled }) => { subs.setAutoUpdate(id, enabled); return subs.list(); },

    'connect': (id) => doConnect(id),
    'disconnect': () => doDisconnect(),

    'settings:get': () => getSettings(),
    // returns { settings, pendingReconnect } — see main.js / settingsMeta.js
    'settings:set': (partial) => {
      const next = Object.assign(getSettings(), partial);
      store.set('settings', next);
      if ('autoUpdateSubs' in partial || 'autoUpdateInterval' in partial) {
        if (next.autoUpdateSubs) subs.startAuto(next.autoUpdateInterval); else subs.stopAuto();
      }
      return { settings: next, pendingReconnect: pendingKeys() };
    },
    'settings:pending': () => pendingKeys(),
    'settings:apply': () => reapplyConnection(),

    'ping:tcp': async (id) => { const { server } = resolveTarget(id); if (!server) return { ok: false, error: 'not found' }; return tcpPing(server.address, server.port); },
    'ping:real': async (id) => {
      const { server, chain } = resolveTarget(id);
      if (!server) return { ok: false, error: 'not found' };
      if (!xray.binExists()) return { ok: false, error: 'xray binary missing' };
      let test;
      try {
        const port = await getFreePort();
        const cfg = buildTestConfig(chain && chain.length >= 2 ? chain : server, port);
        const plan = chain && chain.length >= 2 ? { mode: 'chain', chain } : { mode: 'single', server };
        test = await xray.startTest(cfg, testEngineFor(chooseEngine(plan, getSettings().defaultEngine)));
        return await httpThroughProxy(port, { host: 'cp.cloudflare.com', port: 80, path: '/' });
      } catch (err) { return { ok: false, error: err.message }; }
      finally { if (test) test.cleanup(); }
    },
    'ping:upload': async (id) => {
      const { server, chain } = resolveTarget(id);
      if (!server) return { ok: false, error: 'not found' };
      if (!xray.binExists()) return { ok: false, error: 'xray binary missing' };
      let test;
      try {
        const port = await getFreePort();
        const cfg = buildTestConfig(chain && chain.length >= 2 ? chain : server, port);
        const plan = chain && chain.length >= 2 ? { mode: 'chain', chain } : { mode: 'single', server };
        test = await xray.startTest(cfg, testEngineFor(chooseEngine(plan, getSettings().defaultEngine)));
        return await uploadThroughProxy(port, {});
      } catch (err) { return { ok: false, error: err.message }; }
      finally { if (test) test.cleanup(); }
    },
    'ip:check': async (viaProxy) => { if (viaProxy) { const s = getSettings(); return ipInfo(s.socksPort); } return ipInfo(null); },

    'assets:status': () => assetStatus(),
    'assets:download': async (component) => {
      try {
        const res = await downloader.download(component);
        // binPath caches ONLY the official core (and holds a user-located path),
        // so downloading the fork must not clear it.
        if (component === 'xray' || component === 'xray-pattn') { if (component === 'xray') xray.binPath = null; xray.forgetVersions(); stats.setBin(xray.anyBin()); }
        return { ok: true, files: res.files, assets: assetStatus(), tunAvailable: tun.isAvailable(), xrayReady: xray.binExists() };
      } catch (err) { send('log', { line: 'Download failed (' + component + '): ' + err.message, level: 'error' }); return { ok: false, error: err.message, assets: assetStatus() }; }
    },
    'assets:remove': async () => {
      if (xray.running || tun.active) return { ok: false, error: 'disconnect first', assets: assetStatus() };
      const names = ['xray', 'xray.exe', 'xray-pattn', 'xray-pattn.exe', 'tun2socks', 'tun2socks.exe', 'wintun.dll', 'geoip.dat', 'geosite.dat'];
      const removed = [];
      for (const n of names) { const p = path.join(userBinDir, n); try { if (fs.existsSync(p)) { fs.rmSync(p, { force: true }); removed.push(n); } } catch {} }
      xray.binPath = store.get('xrayPath', null); xray.forgetVersions(); stats.setBin(xray.anyBin());
      return { ok: true, removed, assets: assetStatus(), xrayReady: xray.binExists(), tunAvailable: tun.isAvailable() };
    },

    'xray:version': async (engineId) => { try { return { ok: true, version: await xray.version(engineId || 'xray') }; } catch (e) { return { ok: false, error: e.message }; } },
    'xray:locate': () => ({ ok: false, error: 'not available in server mode' }),
    'app:checkUpdate': () => ({ ok: false, current: appVersion, error: 'update check is desktop-only' }),

    'proc:list': async () => { try { return { ok: true, processes: await listProcesses() }; } catch (e) { return { ok: false, error: e.message, processes: [] }; } },
    'proc:clearCache': () => { store.set('procIpCache', {}); return { ok: true }; },

    'net:lanInfo': () => { const s = getSettings(); return { ip: lanIp(), all: lanCandidates(), socksPort: s.socksPort, httpPort: s.httpPort }; },
    // The browser saw the OS come back online — the fast path into the watcher
    // (polling alone would take a couple of ticks plus the debounce to notice).
    'net:online': () => { if (netWatcher) netWatcher.poke('online'); },
    'killswitch:disarm': () => ({ ok: true }),
    'killswitch:status': () => ({ engaged: false }),

    // desktop-only / no-op in server mode
    'app:relaunchAdmin': () => ({ ok: false, error: 'not applicable on a server' }),
    'open:dataDir': () => dataDir,
    'open:external': () => {},
    'win:minimize': () => {}, 'win:maximize': () => {}, 'win:hide': () => {}, 'win:close': () => {},
    'app:quit': () => { shutdown(); }
  };

  async function invoke(channel, arg) {
    const h = handlers[channel];
    if (!h) throw new Error('unknown channel: ' + channel);
    return await h(arg);
  }

  function onEvent(cb) { listeners.add(cb); return () => listeners.delete(cb); }

  async function shutdown() {
    if (isQuitting) return; isQuitting = true;
    userDisconnecting = true;
    try { stopNetWatcher(); } catch {}
    try { if (stats) stats.stop(); } catch {}
    try { if (tun) await tun.stop(); } catch {}
    try { await setSystemProxy(false, {}); } catch {}
    try { if (xray) await xray.stop(); } catch {}
  }

  // kick off auto-update if enabled
  const st = getSettings();
  if (st.autoUpdateSubs) subs.startAuto(st.autoUpdateInterval);

  return { invoke, onEvent, shutdown, dataDir, getSettings, assetStatus, version: appVersion };
}

module.exports = { createService, DEFAULT_SETTINGS };
