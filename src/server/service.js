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

const { parseMany, parseLink, makeWireguardServer, makeProxyServer, applyServerEdits, buildShareLink } = require('../main/parser');
const { buildConfig, buildTestConfig } = require('../main/configBuilder');
const { buildSingboxConfig } = require('../main/singboxBuilder');
const { engineFormat } = require('../main/engines');
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
  theme: 'dark',
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
    binPath: xray.resolveEngine().bin,
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

    const wantEngine = (plan.mode === 'single' && plan.server && plan.server.engine) || undefined;
    let engine = xray.resolveEngine(wantEngine).id;
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

    const check = await xray.validate(config, engine);
    if (!check.ok) {
      send('log', { line: 'Config rejected by xray: ' + check.error, level: 'error' });
      throw new Error((settings.lang === 'en' ? 'Config error: ' : 'خطای کانفیگ: ') + check.error);
    }

    // save/restore rather than clear — reapplyConnection() wraps the whole
    // teardown+reconnect in the same flag
    const prevReloading = xrayReloading;
    xrayReloading = true;
    try { await xray.start(config, engine); } finally { xrayReloading = prevReloading; }
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

    stats.setBin(xray.resolveEngine().bin);
    stats.apiPort = settings.apiPort;
    stats.start(1000);

    startProcWatcher();
    send('status', {
      state: 'connected', serverId, server: byId(serverId) || null, label,
      tun: tun.active, tunError, geoWarn, lan, pendingReconnect: pendingKeys()
    });
    return true;
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

    try {
      await doConnect(serverId);
    } catch (e) {
      appliedSettings = null;
      send('status', { state: 'error', message: e.message });
      return { ok: false, error: e.message };
    }
    return { ok: true };
  }

  async function rebuildActiveConfig() {
    const serverId = store.get('activeServerId', null);
    if (!serverId || !xray.running) return;
    const settings = await effectiveSettings();
    const { config, engine } = buildActive(serverId, settings);
    const prevReloading = xrayReloading;
    xrayReloading = true;
    try { await xray.start(config, engine); } finally { xrayReloading = prevReloading; }
    stats.setBin(xray.resolveEngine().bin);
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

  async function doDisconnect() {
    userDisconnecting = true;
    stopProcWatcher();
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
        test = await xray.startTest(cfg);
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
        test = await xray.startTest(cfg);
        return await uploadThroughProxy(port, {});
      } catch (err) { return { ok: false, error: err.message }; }
      finally { if (test) test.cleanup(); }
    },
    'ip:check': async (viaProxy) => { if (viaProxy) { const s = getSettings(); return ipInfo(s.socksPort); } return ipInfo(null); },

    'assets:status': () => assetStatus(),
    'assets:download': async (component) => {
      try {
        const res = await downloader.download(component);
        if (component === 'xray' || component === 'xray-pattn') { xray.binPath = null; xray.forgetVersions(); stats.setBin(xray.resolveEngine().bin); }
        return { ok: true, files: res.files, assets: assetStatus(), tunAvailable: tun.isAvailable(), xrayReady: xray.binExists() };
      } catch (err) { send('log', { line: 'Download failed (' + component + '): ' + err.message, level: 'error' }); return { ok: false, error: err.message, assets: assetStatus() }; }
    },
    'assets:remove': async () => {
      if (xray.running || tun.active) return { ok: false, error: 'disconnect first', assets: assetStatus() };
      const names = ['xray', 'xray.exe', 'xray-pattn', 'xray-pattn.exe', 'tun2socks', 'tun2socks.exe', 'wintun.dll', 'geoip.dat', 'geosite.dat'];
      const removed = [];
      for (const n of names) { const p = path.join(userBinDir, n); try { if (fs.existsSync(p)) { fs.rmSync(p, { force: true }); removed.push(n); } } catch {} }
      xray.binPath = store.get('xrayPath', null); xray.forgetVersions(); stats.setBin(xray.resolveEngine().bin);
      return { ok: true, removed, assets: assetStatus(), xrayReady: xray.binExists(), tunAvailable: tun.isAvailable() };
    },

    'xray:version': async () => { try { return { ok: true, version: await xray.version() }; } catch (e) { return { ok: false, error: e.message }; } },
    'xray:locate': () => ({ ok: false, error: 'not available in server mode' }),
    'app:checkUpdate': () => ({ ok: false, current: appVersion, error: 'update check is desktop-only' }),

    'proc:list': async () => { try { return { ok: true, processes: await listProcesses() }; } catch (e) { return { ok: false, error: e.message, processes: [] }; } },
    'proc:clearCache': () => { store.set('procIpCache', {}); return { ok: true }; },

    'net:lanInfo': () => { const s = getSettings(); return { ip: lanIp(), all: lanCandidates(), socksPort: s.socksPort, httpPort: s.httpPort }; },
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
