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
const { buildConfig, buildTestConfig, resolverBypassIps } = require('../main/configBuilder');
const { adapterDnsServers } = require('../main/dnsBuilder');
const { buildSingboxConfig } = require('../main/singboxBuilder');
const { engineFormat } = require('../main/engines');
const { chooseEngine, testEngineFor } = require('../main/engineChoice');
const { fetchLeafPin, pinTargets, directServers, PinWatch } = require('../main/certPin');
const { assetStatus: scanAssets } = require('../main/assets');
const { XrayManager, getFreePort } = require('../main/xrayManager');
const { setSystemProxy } = require('../main/sysproxy');
const { tcpPing, httpThroughProxy, uploadThroughProxy, ipInfo } = require('../main/netutils');
const { Store } = require('../main/store');
const { SubscriptionManager } = require('../main/subscription');
const { TunManager, isOwnTunInterface, TUN_GW } = require('../main/tunManager');
const { TunSingbox } = require('../main/tunSingbox');
const tunPlatform = require('../main/tunPlatform');
const { LeakGuard } = require('../main/leakGuard');
const { StatsPoller } = require('../main/stats');
const { Downloader } = require('../main/downloader');
const { listProcesses, collectProcessIps, pruneProcCache, ProcWatcher } = require('../main/procRouter');
const { pendingReconnectKeys, snapshotApplied } = require('../main/settingsMeta');
const { migrateSettings } = require('../main/settingsMigrate');
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
  // name resolution (see dnsBuilder.js): remote over DoH through the tunnel,
  // an in-country resolver for bypass modes, every port-53 packet answered by
  // the core. `dnsManaged:false` restores the old "use these servers" behaviour.
  dnsManaged: true,
  dnsRemote: ['https://1.1.1.1/dns-query', 'https://8.8.8.8/dns-query'],
  dnsDirect: ['178.22.122.100', '185.51.200.2'],
  ipv6: false,
  logLevel: 'warning',
  apiPort: 10085,
  systemProxy: false,        // headless: no desktop session to set a system proxy for
  tunMode: false,
  // TUN backend: sing-box (auto_route, v4+v6) when installed, else tun2socks
  tunBackend: 'sing-box',
  // leak guard under TUN: 'off' | 'standard' (adapter DNS override) | 'strict'
  // (+ strict_route and a firewall for everything off the tunnel)
  leakGuard: 'standard',
  // proxy mode only: block outbound UDP except :53 on physical adapters (WebRTC)
  blockUdpInProxyMode: false,
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
  const pinWatch = new PinWatch();   // the live plan's pinned servers, for the core's mismatch line
  let recoverTimer = null;
  let recovering = false;        // a network-change recovery is in flight
  let recoverQueued = null;      // reason of a trigger that arrived during that recovery
  let recoverGen = 0;            // bumped by doDisconnect(); an older recovery no longer owns `recovering`
  const RECOVER_BACKOFF_MS = [2000, 5000, 15000];
  // Bumped by doDisconnect() and by every doConnect(). doConnect awaits several
  // times and the operator can hit disconnect in any of those gaps: from that
  // moment the older call no longer speaks for the service, so it must not emit a
  // status or start a watcher. Comparing the token captured at entry against this
  // is how it finds out (see doConnect).
  let connGen = 0;
  // Settings the LIVE tunnel was built from (null when disconnected) — see
  // ../main/settingsMeta.js.
  let appliedSettings = null;
  // The physical interface the LIVE connection's direct dials are bound to (see
  // doConnect); null when not under TUN. rebuildActiveConfig() reuses it rather
  // than asking the OS again — with the tunnel up, the default route IS the tunnel.
  let liveDirectInterface = null;

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
  migrateSettingsStore();

  function binDirs() { return [userBinDir, bundledBinDir]; }
  function assetStatus() {
    const st = scanAssets(binDirs());
    if (xray) st.xray = st.xray || xray.binExists('xray');
    return st;
  }

  /**
   * The TUN layer for a connect: sing-box unless the user chose tun2socks or
   * sing-box (with wintun next to it, on Windows) is not installed — then
   * tun2socks, and the log says why. Built per connect (`tunBackend` is
   * reconnect-relevant) and kept on `tun` for stop / recovery / shutdown. The
   * status paths that only ask isAvailable() / isElevated() build a throwaway
   * one with `quiet`, so the fallback line is logged once per connect, not per poll.
   */
  function makeTun(settings, { quiet = false } = {}) {
    const opts = { binDir: bundledBinDir, extraDirs: [userBinDir], onLog: (line, level) => send('log', { line, level }), lang: settings.lang };
    const sb = new TunSingbox(opts);
    const legacy = new TunManager(opts);
    if (settings.tunBackend === 'tun2socks') return legacy;
    if (sb.isAvailable()) return sb;
    if (legacy.isAvailable()) {
      if (!quiet) send('log', { line: 'sing-box not installed — TUN falls back to tun2socks', level: 'warn' });
      return legacy;
    }
    return sb;   // neither: the sing-box error message names what to install
  }

  const xray = new XrayManager({
    binPath: store.get('xrayPath', null),
    dataDir,
    extraBinDirs: [userBinDir],
    onLog: (line, level) => { send('log', { line, level }); healCertPin(line); },
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

  // A placeholder until the first connect picks the backend for real (see
  // makeTun / doConnect) — so shutdown always has an instance.
  let tun = makeTun(getSettings(), { quiet: true });

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

  // The leak guard and its crash repair. A `tun-state.json` left in the data dir
  // means the last session died with every physical adapter still pointing at a
  // tunnel that is gone — the machine has no working DNS until the originals go
  // back — and the tunnel process it started may still be running with its
  // routes in place. Deliberately NOT awaited: createService() is synchronous
  // and the restore is a shell round trip. Every operation on the state file is
  // serialized inside the guard, so a connect that starts while the repair is
  // still running cannot lose its own record.
  const leakGuard = new LeakGuard({
    userData: dataDir,
    onLog: (line, level) => send('log', { line, level }),
    run: tunPlatform.run,
    runScriptPrivileged: tunPlatform.runScriptPrivileged,
    platform: process.platform
  });
  leakGuard.repairAtLaunch().catch((e) => send('log', { line: 'Leak guard repair failed: ' + e.message, level: 'error' }));

  // A hard `kill -9` of the headless server runs no shutdown path at all, so the
  // override would outlive it. This is the same sync, best-effort cleanup the
  // desktop app does on exit (macOS only when already root — nothing can answer
  // a password prompt here); anything it cannot do is repaired at the next launch.
  process.on('exit', () => { try { leakGuard.releaseSync(); } catch {} });

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

  /**
   * Convert a pre-phase-2 `dns` setting into `dnsRemote` / `dnsDirect`. Runs
   * before anything reads settings, writes only when something changed.
   */
  function migrateSettingsStore() {
    const raw = store.get('settings', null);
    const { settings, changed } = migrateSettings(raw);
    if (changed) store.set('settings', settings);
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
  // Mirrors main.js buildPlan() / buildActive(). Kept in sync deliberately
  // (duplicated so the desktop app stays untouched).
  function buildPlan(serverId, settings) {
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
    return { plan, label, entryAddrs };
  }

  function buildActive(serverId, settings) {
    const { plan, label, entryAddrs } = buildPlan(serverId, settings);

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

  /**
   * allowInsecure is gone from the core (see certPin.js): before the plan is
   * built, read and store the certificate of every server the plan dials
   * directly that asked for it and has no pin yet — one dial each, in parallel,
   * 5 s at most. A failed probe is logged and the core then verifies the
   * certificate itself; its own error is the user's signal. A server behind
   * another hop cannot be probed from here.
   */
  async function ensureCertPins(serverId, settings) {
    let plan;
    try { plan = buildPlan(serverId, settings).plan; } catch { return; }   // buildActive reports it
    const { probe, behind } = pinTargets(plan);
    for (const s of behind) {
      send('log', { line: `${s.name} sits behind a proxy; its certificate cannot be pinned automatically — connect to it directly once to pin it`, level: 'warn' });
    }
    if (!probe.length) return;
    const learned = {};
    await Promise.all(probe.map(async (s) => {
      const tlsSettings = s.outbound.streamSettings.tlsSettings;
      try {
        const pin = await fetchLeafPin({ host: s.address, port: s.port, servername: tlsSettings.serverName || s.address });
        learned[s.id] = pin;
        send('log', { line: `Certificate pinned on first use for ${s.name}: ${pin}`, level: 'info' });
      } catch (e) {
        send('log', { line: `Could not read the certificate of ${s.name} to pin it (${e.message}) — the core will verify it itself`, level: 'warn' });
      }
    }));
    if (!Object.keys(learned).length) return;
    const certPinAt = new Date().toISOString();
    store.set('servers', store.get('servers', []).map(s => learned[s.id] ? Object.assign({}, s, { certPin: learned[s.id], certPinAt }) : s));
  }

  /**
   * The core reports a pinned certificate that no longer matches at log level
   * info only, once the dial's retries are spent (certPin.js). Clear the stale
   * pin so the next connect pins the new one — and only that: a changed
   * certificate deserves a look before it is trusted again, so no reconnect.
   */
  function healCertPin(line) {
    const hit = pinWatch.onLine(line);
    if (!hit) return;
    const ids = new Set(hit.map(s => s.id));
    store.set('servers', store.get('servers', []).map(s => {
      if (!ids.has(s.id)) return s;
      const out = Object.assign({}, s);
      delete out.certPin; delete out.certPinAt;
      return out;
    }));
    for (const s of hit) send('log', { line: `Certificate changed for ${s.name} — pin cleared, reconnect to pin the new one`, level: 'warn' });
  }

  /* ----------------------------- connect / disconnect ----------------------------- */
  /**
   * @returns {Promise<{ ok: boolean, tunError?: string|null, stale?: boolean }>}
   *   `stale: true` means a disconnect (or a newer connect) overtook this call
   *   before it finished: nothing was emitted and nothing was started, and the
   *   caller must not treat it as either a success or a failure worth retrying.
   */
  async function doConnect(serverId) {
    // Every await below is a window in which the operator can hit disconnect.
    // doDisconnect() then stops the core and clears activeServerId, but THIS call
    // would carry on to start both watchers again and emit 'connected' — leaving
    // the panel claiming a tunnel that no longer exists, with two leaked watchers
    // behind it and a recovery retry that the activeServerId guard silently
    // drops, so nothing ever corrects the display. The token says whose turn it is.
    const gen = ++connGen;
    const stale = () => gen !== connGen;
    const abandoned = { ok: false, stale: true };

    let settings = await effectiveSettings();
    if (stale()) return abandoned;
    const byId = (id) => store.get('servers', []).find(s => s.id === id);

    // allowInsecure is gone from the core: pin the certificate on first use instead.
    await ensureCertPins(serverId, settings);
    if (stale()) return abandoned;

    // The TUN layer for this connect — the backend setting plus what is
    // installed. A LIVE instance is never replaced: switching servers keeps the
    // running tunnel (tun.start() is a no-op while active); a new choice takes
    // effect through reapplyConnection() / doDisconnect(), which stop it first.
    if (!tun || !tun.active) tun = makeTun(settings);

    // Under TUN the OS default route is the tunnel, so every dial Xray makes
    // itself (direct, the anti-DPI dialers, the first hop of a chain) must be
    // bound to the physical NIC or it re-enters the TUN and loops. Read BEFORE
    // tun.start() — with the tunnel up the default route is the tunnel itself,
    // which is also why a live tunnel keeps the name it was built with. Re-derived
    // on every (re)connect, so a network change picks up the new NIC. Never
    // persisted: effectiveSettings() is the source, the store never sees it.
    if (settings.tunMode) {
      let name = (tun.active && liveDirectInterface) || null;
      if (!name) {
        const phys = await tun.physicalInterface().catch(() => null);
        if (stale()) return abandoned;
        name = (phys && phys.name && !isOwnTunInterface(phys.name)) ? phys.name : null;
      }
      if (name) settings = Object.assign({}, settings, { directInterface: name });
      else send('log', { line: 'Could not find the physical network interface — direct traffic under TUN may loop', level: 'warn' });
      liveDirectInterface = name;
    } else {
      liveDirectInterface = null;
    }

    const { plan, label, entryAddrs, config, geoWarn, engine } = buildActive(serverId, settings);

    send('status', { state: 'connecting', serverId });

    const check = await xray.validateWithFallback(config, engine);
    if (stale()) return abandoned;
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
    try {
      await xray.start(config, runEngine);
    } catch (e) {
      // start() watches for 1.2 s to catch a config that crashes the core on
      // startup. A disconnect landing inside that grace KILLS the process, so
      // the watcher reports "xray exited on startup" — a failure the operator
      // caused on purpose, dressed as a config error. Propagating it surfaces an
      // error to the client for something it asked for itself, and makes
      // runRecovery() log a retry for a tunnel nobody wants. Abandonment, not an
      // error: answer like every other gate below.
      if (stale()) return abandoned;
      throw e;
    } finally { xrayReloading = prevReloading; }
    // The critical one. doDisconnect() has already stopped the core this just
    // started, so writing activeServerId back here would resurrect the very
    // intent that was cancelled — and every side effect below would follow it.
    if (stale()) return abandoned;
    store.set('activeServerId', serverId);
    pinWatch.setLive(directServers(plan));
    appliedSettings = snapshotApplied(getSettings());

    if (settings.systemProxy) {
      try {
        await setSystemProxy(true, { host: '127.0.0.1', httpPort: settings.httpPort, socksPort: settings.socksPort });
        send('log', { line: 'System proxy enabled', level: 'info' });
      } catch (e) { send('log', { line: 'System proxy failed: ' + e.message, level: 'error' }); }
    }
    if (stale()) return abandoned;

    // TUN mode (system-wide tunnel via sing-box, or tun2socks as the fallback —
    // see makeTun). Requires root/admin + the backend's files.
    let tunError = null;
    let guardError = null;
    let guardEngaged = false;
    if (settings.tunMode) {
      if (!tun.isAvailable()) {
        tunError = settings.lang === 'en'
          ? 'TUN needs sing-box (or tun2socks) and wintun in the bin folder.'
          : 'حالت TUN به sing-box (یا tun2socks) و wintun در پوشه bin نیاز دارد.';
        send('log', { line: 'TUN requested but sing-box/tun2socks (with wintun) not found — connected proxy-only', level: 'error' });
      } else {
        // Managed DNS: the adapter's resolver is the tunnel's own peer, so every
        // query the OS sends there enters the TUN and is answered by dns-out.
        // The peer is the backend's: 172.19.0.2 for sing-box, 10.255.0.1 for
        // tun2socks. (The physical adapters keep their own resolvers until the
        // phase-3 guard overrides them.) A sing-box-format config carries no
        // hijack, so the adapter gets a resolver the proxy can reach instead.
        // The in-country resolver is dialled `direct` — under TUN that would
        // re-enter the tunnel, so it needs a bypass route exactly like the
        // server addresses (the direct outbound is also bound to the NIC).
        const hijacks = engineFormat(runEngine) !== 'sing-box';
        const dnsPeer = tun.dnsPeer || TUN_GW;
        try {
          tun.lang = settings.lang || 'fa';
          await tun.start(settings.socksPort, [...entryAddrs, ...resolverBypassIps(plan, settings)],
            adapterDnsServers(settings, hijacks ? dnsPeer : null),
            { ipv6: !!settings.ipv6, strict: settings.leakGuard === 'strict' });   // tun2socks ignores the 4th
          send('log', { line: 'TUN mode active (whole system)', level: 'info' });
        } catch (e) { tunError = e.message; send('log', { line: 'TUN start failed: ' + e.message, level: 'error' }); }
      }
      // The leak guard (standard): the TUN adapter's own resolver is ours, but
      // Windows asks the resolvers of EVERY connected adapter in parallel and
      // macOS resolves per network service — so until we take them, the physical
      // adapters still hand every name to the ISP. Only for a tunnel that
      // actually came up: with no tunnel there is nothing to point them at, and
      // doing it anyway would leave the machine unable to resolve at all.
      if (tun.active && settings.leakGuard !== 'off') {
        try {
          await leakGuard.engage({
            level: settings.leakGuard,
            peer4: tun.dnsPeer || TUN_GW,
            peer6: settings.ipv6 ? tun.dnsPeer6 : null,
            // macOS: the strict level's pf anchor has to name the REAL tunnel
            // device (the utun the backend was given at start), not the Windows
            // adapter name — a ruleset that cannot name the tunnel would block
            // the machine's whole network.
            tunAlias: (process.platform === 'darwin' && tun.macState && tun.macState.dev) || tun.interfaceName || 'XrayTun',
            backend: tun.backendId || null,
            // What may still leave through the physical adapters at the strict
            // level: the tunnel's own bypass list (the resolved server entry IPs
            // and the direct resolvers). Read AFTER start — that is when the
            // backend has resolved them.
            excludes: tun.excludeIps || []
          });
          guardEngaged = true;
        } catch (e) {
          // Not fatal — the tunnel is up and carrying traffic, the adapters just
          // kept their own resolvers. Deliberately NOT tunError: that one means
          // "no tunnel", and the network-change recovery retries the whole
          // connection on it.
          guardError = e.message;
          send('log', { line: 'Leak guard failed: ' + e.message + ' — the tunnel is up, but the physical adapters keep their own DNS', level: 'error' });
        }
      }
    } else if (settings.blockUdpInProxyMode) {
      // Proxy mode carries no UDP at all, so WebRTC's question to a STUN server
      // goes around the proxy and comes back with the real address. This is the
      // only thing we can do about it without a tunnel. Windows only; a failure
      // is logged and nothing more — the proxy itself is up and working.
      try {
        // entryAddrs are what the user typed — a hostname there would be no
      // exclusion at all, and a UDP-transport server addressed by name would be
      // the first thing this block cut off. Resolve them the way the TUN layer
      // does before they become firewall holes.
      const udpExcludes = await tunPlatform.resolveServerIps(entryAddrs, { ipv6: true }).catch(() => []);
      await leakGuard.engageUdpBlock({ excludes: udpExcludes });
        guardEngaged = true;
      } catch (e) {
        guardError = e.message;
        send('log', { line: 'UDP block failed: ' + e.message + ' — WebRTC can still reveal your address in proxy mode', level: 'error' });
      }
    }
    // tun.start() is the longest await here (a privileged shell round trip) — the
    // likeliest place for a disconnect to land. Past this line nothing awaits, so
    // this is the last gate before the watchers and the 'connected' status.
    if (stale()) {
      // doDisconnect() ran its release() before this call wrote the state file,
      // so the override it just applied would outlive the tunnel it points at —
      // the machine would be left unable to resolve anything. Undo it here.
      if (guardEngaged) await leakGuard.release().catch(() => {});
      return abandoned;
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
      tun: tun.active, tunError, guardError, geoWarn, lan, pendingReconnect: pendingKeys()
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

    // The teardown below is several awaits long and doConnect()'s own token
    // cannot cover it — that token is taken AFTER the teardown, so it would be
    // the newest generation and see nothing. A `disconnect` RPC landing in this
    // window (it is accepted at any time) bumps connGen, clears activeServerId
    // and emits 'disconnected', and the rebuild would then quietly write the
    // serverId captured above back, bring TUN up and report connected: the
    // operator's disconnect undone.
    const gen = connGen;

    send('status', { state: 'connecting', serverId });

    const prevReloading = xrayReloading;
    xrayReloading = true;              // intentional restart, not a drop
    try {
      stopProcWatcher();
      if (stats) stats.stop();
      // Give the adapters their own resolvers back BEFORE the tunnel goes, and
      // let doConnect() engage the guard again on the new one. Holding the
      // override across the gap would point every adapter at a peer that stops
      // routing the moment tun.stop() runs.
      try { if (leakGuard) await leakGuard.release(); } catch {}
      try { await tun.stop(); } catch {}
      try { await setSystemProxy(false, {}); } catch {}
      if (xray) await xray.stop();
    } finally {
      xrayReloading = prevReloading;
    }

    // A disconnect (or a newer connect) overtook the teardown. Everything this
    // function would rebuild belongs to an intent that no longer exists, so stop
    // here — before doConnect() takes a token that could not detect it.
    if (gen !== connGen) return { ok: false, stale: true };

    let r;
    try {
      r = await doConnect(serverId);
    } catch (e) {
      appliedSettings = null;
      send('status', { state: 'error', message: e.message });
      return { ok: false, error: e.message };
    }
    // A disconnect overtook the connect: it emitted nothing and started nothing,
    // so neither may we.
    if (r && r.stale) return { ok: false, stale: true };
    // Pass doConnect()'s one non-throwing failure through: the tunnel is up but
    // TUN is not, so this is not a complete reconnect for whoever asked for one.
    return { ok: true, tunError: (r && r.tunError) || null };
  }

  async function rebuildActiveConfig() {
    const serverId = store.get('activeServerId', null);
    if (!serverId || !xray.running) return;
    let settings = await effectiveSettings();
    // Keep the binding the live connection was built with (see doConnect): the
    // tunnel stays up across this reload, and asking the OS now would name it.
    if (liveDirectInterface) settings = Object.assign({}, settings, { directInterface: liveDirectInterface });
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

    // `recovering` is a lock with no timeout behind it: tunManager.run() waits on
    // a privileged shell that can hang. A run that never returns would park every
    // future trigger for the life of the process, so the lock is stamped with a
    // generation that doDisconnect() bumps — that is the reset, and it is why the
    // release below is conditional.
    const gen = recoverGen;
    recovering = true;
    try {
      await runRecovery(reason, attempt);
    } finally {
      // Release the lock and nothing else. The watcher's own baseline is not
      // ours to move: its ignoreInterface predicate already keeps the
      // fingerprint stable across the rebuild, so there is nothing half-seen
      // left to forgive — while a GENUINE change landing in the tail of this
      // recovery is still only pending, and adopting it here would leave the
      // tunnel built for a gateway that is gone with nothing left to notice.
      if (gen === recoverGen) recovering = false;
    }
    // The lock was reset under us (a disconnect): whatever comes next is not ours
    // to start, and the activeServerId guard would refuse it anyway.
    if (gen !== recoverGen) return;

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

    // The operator disconnected (or connected somewhere else) while we were
    // rebuilding. The rebuild abandoned itself without emitting anything; a log
    // line or a retry here would be about a tunnel nobody asked for any more.
    if (res && res.stale) return;

    // doConnect() does not throw when TUN was asked for and did not come up: it
    // reports tunError and carries on proxy-only. Calling that a restored
    // connection would tell the user the whole system is tunnelled when it is not —
    // so it counts as a failed attempt and the backoff retries it. But only a TUN
    // that COULD have worked is worth retrying: with tun2socks/wintun simply not
    // installed the failure is a configuration problem no rebuild can fix, and
    // retrying it would spend the whole backoff — four complete teardown+rebuild
    // cycles — on every single network change. The proxy is up either way, so that
    // case is accepted here (doConnect() already logged the missing files, and its
    // 'connected' status carried the tunError to the UI).
    //
    // Missing privileges are permanent in exactly the same way: a service running
    // unprivileged fails with "TUN mode requires root" on every attempt, and no
    // rebuild can grant it — retrying just costs ~25 s of torn-down proxy on every
    // network change. isElevated() is the question "could this ever have worked",
    // so it belongs in the same judgement.
    const tunRetryable = !!(res && res.tunError) && tun.isAvailable() && tun.isElevated();

    if (res && res.ok && !tunRetryable) {
      send('log', {
        line: res.tunError
          ? 'Connection restored after the network change — proxy only, TUN is unavailable: ' + res.tunError
          : 'Connection restored after the network change',
        level: res.tunError ? 'warn' : 'info'
      });
      return;
    }
    if (res && res.tunError) {
      send('log', { line: 'Reconnected without the system-wide tunnel: ' + res.tunError, level: 'error' });
    }
    const delay = RECOVER_BACKOFF_MS[attempt];
    if (delay == null) {
      // "Nothing came back" and "everything came back except TUN" are different
      // failures: on the second, xray is running and the proxy ports carry traffic,
      // so painting the UI red would be a lie. `proxyUp` is what tells them apart.
      const proxyUp = !!(res && res.ok);
      send('log', {
        line: proxyUp
          ? 'Could not bring the system-wide tunnel back after the network change — giving up (the proxy is still up)'
          : 'Could not reconnect after the network change — giving up',
        level: 'error'
      });
      send('status', { state: 'reconnect-failed', reason, proxyUp, tunError: (res && res.tunError) || null });
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
      // Our own TUN adapter is not part of "the machine's network": a rebuild
      // destroys and recreates it, so counting it would make every recovery
      // manufacture the change that triggers the next one.
      ignoreInterface: isOwnTunInterface,
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
    // `recovering` itself is deliberately NOT cleared HERE: startNetWatcher()
    // calls this first, and a recovery's own reconnect can reach it — releasing
    // the lock there would let a second recovery start alongside the one still
    // going. doDisconnect() is where the reset belongs, and it does it explicitly.
    recoverQueued = null;
    if (netWatcher) { netWatcher.stop(); netWatcher = null; }
  }

  async function doDisconnect() {
    userDisconnecting = true;
    // Anything already in flight stops speaking for the service from this line
    // on: a doConnect() past xray.start() must not emit 'connected' or restart
    // the watchers, and a recovery that hung (a stuck privileged shell) must not
    // keep its lock and park every future trigger.
    connGen++;
    recoverGen++;
    recovering = false;
    stopProcWatcher();
    stopNetWatcher();                // nothing live to recover any more
    if (stats) stats.stop();
    // The adapters point at real resolvers again BEFORE the tunnel goes: in
    // between they would be pointing at an address that no longer routes anywhere.
    try { if (leakGuard) await leakGuard.release(); } catch {}
    // `tun` is the instance doConnect() started (makeTun), whichever backend
    // it chose — the same one shutdown() tears down.
    try { if (tun) await tun.stop(); } catch {}
    try { await setSystemProxy(false, {}); } catch {}
    if (xray) await xray.stop();
    store.set('activeServerId', null);
    pinWatch.clear();
    appliedSettings = null;          // nothing live to be out of sync with
    liveDirectInterface = null;
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
      tunAvailable: makeTun(getSettings(), { quiet: true }).isAvailable(),
      elevated: makeTun(getSettings(), { quiet: true }).isElevated(),
      assets: assetStatus(),
      platform: process.platform,
      version: appVersion,
      // a headless server has no desktop theme, so theme: 'system' behaves as
      // dark here unless the user picks light explicitly
      systemDark: true,
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
        return { ok: true, files: res.files, assets: assetStatus(), tunAvailable: makeTun(getSettings(), { quiet: true }).isAvailable(), xrayReady: xray.binExists() };
      } catch (err) { send('log', { line: 'Download failed (' + component + '): ' + err.message, level: 'error' }); return { ok: false, error: err.message, assets: assetStatus() }; }
    },
    'assets:remove': async () => {
      if (xray.running || (tun && tun.active)) return { ok: false, error: 'disconnect first', assets: assetStatus() };
      const names = ['xray', 'xray.exe', 'xray-pattn', 'xray-pattn.exe', 'tun2socks', 'tun2socks.exe', 'wintun.dll', 'geoip.dat', 'geosite.dat'];
      const removed = [];
      for (const n of names) { const p = path.join(userBinDir, n); try { if (fs.existsSync(p)) { fs.rmSync(p, { force: true }); removed.push(n); } } catch {} }
      xray.binPath = store.get('xrayPath', null); xray.forgetVersions(); stats.setBin(xray.anyBin());
      return { ok: true, removed, assets: assetStatus(), xrayReady: xray.binExists(), tunAvailable: makeTun(getSettings(), { quiet: true }).isAvailable() };
    },

    'xray:version': async (engineId) => { try { return { ok: true, version: await xray.version(engineId || 'xray') }; } catch (e) { return { ok: false, error: e.message }; } },
    'xray:locate': () => ({ ok: false, error: 'not available in server mode' }),
    'app:checkUpdate': () => ({ ok: false, current: appVersion, error: 'update check is desktop-only' }),

    'proc:list': async () => { try { return { ok: true, processes: await listProcesses() }; } catch (e) { return { ok: false, error: e.message, processes: [] }; } },
    'proc:clearCache': () => { store.set('procIpCache', {}); return { ok: true }; },

    'net:lanInfo': () => { const s = getSettings(); return { ip: lanIp(), all: lanCandidates(), socksPort: s.socksPort, httpPort: s.httpPort }; },
    // Deliberately a no-op — do NOT mirror main.js's netWatcher.poke() here.
    //
    // On the desktop the renderer runs on the same machine as the tunnel, so the
    // browser's 'online' event genuinely means "this machine's network came
    // back". Headless, the renderer runs in the OPERATOR'S browser and the tunnel
    // runs on the VPS: the event says the operator's laptop woke up, switched
    // Wi-Fi or had its lid closed — nothing whatsoever about the server's
    // network. Poking the watcher would tear the VPS tunnel down and rebuild it
    // every time the operator opens their laptop.
    //
    // The server's own network changes are still caught: netWatcher polls
    // os.networkInterfaces() on the VPS, which is the only trustworthy source
    // here. The handler is kept (rather than deleted) so web-api.js can go on
    // mirroring the preload API one-to-one and the shared renderer needs no
    // feature detection.
    'net:online': () => {},
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
    try { if (leakGuard) await leakGuard.release(); } catch {}   // adapters first, then the tunnel
    try { if (tun) await tun.stop(); } catch {}   // the instance doConnect() started
    try { await setSystemProxy(false, {}); } catch {}
    try { if (xray) await xray.stop(); } catch {}
  }

  // kick off auto-update if enabled
  const st = getSettings();
  if (st.autoUpdateSubs) subs.startAuto(st.autoUpdateInterval);

  return { invoke, onEvent, shutdown, dataDir, getSettings, assetStatus, version: appVersion };
}

module.exports = { createService, DEFAULT_SETTINGS };
