'use strict';
const { app, BrowserWindow, ipcMain, Tray, Menu, nativeImage, shell, dialog, nativeTheme } = require('electron');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { spawn, execFile } = require('child_process');

const { parseMany, parseLink, makeWireguardServer, makeProxyServer, applyServerEdits, buildShareLink, migrateStoredServer, parseWireguardConf } = require('./parser');
const { buildConfig, buildTestConfig, resolverBypassIps, wgEndpointHosts } = require('./configBuilder');
const { adapterDnsServers } = require('./dnsBuilder');
const { buildSingboxConfig } = require('./singboxBuilder');
const { engineFormat } = require('./engines');
const { chooseEngine, testEngineFor, needsWgEndpointIp } = require('./engineChoice');
const { fetchLeafPin, pinTargets, directServers, staleCertPins, PinWatch } = require('./certPin');
const { assetStatus: scanAssets } = require('./assets');
const { geoTokensOf, checkGeoTokens, geoCodeHint } = require('./geoCheck');
const { XrayManager, getFreePort } = require('./xrayManager');
const { setSystemProxy } = require('./sysproxy');
const { tcpPing, httpThroughProxy, uploadThroughProxy, ipInfo } = require('./netutils');
const { Store } = require('./store');
const { SubscriptionManager } = require('./subscription');
const { TunManager, isOwnTunInterface, TUN_GW } = require('./tunManager');
const { TunSingbox } = require('./tunSingbox');
const tunPlatform = require('./tunPlatform');
const { LeakGuard } = require('./leakGuard');
const { StatsPoller, SilenceWatch } = require('./stats');
const { Downloader } = require('./downloader');
const { listProcesses, collectProcessIps, pruneProcCache, ProcWatcher } = require('./procRouter');
const { pendingReconnectKeys, snapshotApplied } = require('./settingsMeta');
const { migrateSettings } = require('./settingsMigrate');
const { NetWatcher } = require('./netWatcher');
const https = require('https');

let mainWindow = null;
let tray = null;
let xray = null;
let store = null;
let subs = null;
let tun = null;
/**
 * Every TUN backend a connect has started. `tun` alone is not enough: a second
 * connect can replace it while the first is still inside start(), and the
 * tunnel that first call brings up would then hold the machine's default routes
 * with nothing left pointing at it. Disconnect, quit and the exit hook sweep
 * this set, so no tunnel can outlive the app.
 */
const startedTuns = new Set();
let leakGuard = null;
let stats = null;
let downloader = null;
let procWatcher = null;
let netWatcher = null;
const pinWatch = new PinWatch();   // the live plan's pinned servers, for the core's mismatch line
let recoverTimer = null;
let recovering = false;        // a network-change recovery is in flight
let recoverQueued = null;      // reason of a trigger that arrived during that recovery
let recoverGen = 0;            // bumped by doDisconnect(); an older recovery no longer owns `recovering`
const RECOVER_BACKOFF_MS = [2000, 5000, 15000];
// Bumped by doDisconnect() and by every doConnect(). doConnect awaits half a
// dozen times and the user can press the power button in any of those gaps: from
// that moment the older call no longer speaks for the app, so it must not emit a
// status or start a watcher. Comparing the token captured at entry against this
// is how it finds out (see doConnect).
let connGen = 0;
let userBinDir = null;
let isQuitting = false;
let xrayReloading = false;   // true while the proc-routing watcher restarts xray
let userDisconnecting = false; // true during an intentional disconnect (kill switch ignores it)
// Snapshot of the settings the LIVE tunnel was actually built from (null when
// disconnected). Diffing it against the current settings is what tells the user
// "you changed this, but it won't take effect until you reconnect".
let appliedSettings = null;
// The physical interface the LIVE connection's direct dials are bound to (see
// doConnect); null when not under TUN. rebuildActiveConfig() reuses it rather
// than asking the OS again — with the tunnel up, the default route IS the tunnel.
let liveDirectInterface = null;

// GitHub repo used for the in-app update check (see app:checkUpdate).
const GITHUB_REPO = 'sadrazkh/Irnetfree_xray-client';

const DEFAULT_SETTINGS = {
  socksPort: 10808,
  httpPort: 10809,
  allowLan: false,
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
  systemProxy: true,
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
  // advanced (graphical) routing — per-rule outbound selection
  advancedRouting: false,
  // apply routingMode (bypass Iran/China…) UNDER the advanced rules as well —
  // off keeps the old behaviour, where advanced routing ignored the mode
  advancedUseMode: false,
  routeRules: [],      // [{ id, type:'ip'|'domain'|'port'|'process', value, target }]
  routeDefault: '',    // fallback target (server id | 'chain' | 'direct' | 'block')
  // process routing: keep routes updated while connected (briefly reloads xray)
  procRouteWatch: false,
  // kill switch: block all internet if the VPN drops unexpectedly (Windows)
  killSwitch: false,
  // recover automatically when the machine's network changes (read live, so it
  // needs no reconnect to take effect)
  autoReconnectOnNetworkChange: true,
  // which surfaces the window shows: 'simple' hides chains, the pool, the log
  // page and the custom-rule editor. A view preference only — renderer-owned,
  // never baked into a config, so it needs no reconnect.
  uiMode: '',
  // which of the three looks the window wears (renderer-only, like theme)
  skin: 'cockpit',
  theme: 'dark',
  defaultEngine: 'xray'
};

function dataDir() {
  const dir = path.join(app.getPath('userData'));
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

/** Writable dir for downloaded/updated binaries (overrides bundled bin/). */
function userBin() {
  if (!userBinDir) {
    userBinDir = path.join(app.getPath('userData'), 'bin');
    fs.mkdirSync(userBinDir, { recursive: true });
  }
  return userBinDir;
}

function bundledBinDir() {
  const packaged = path.join(process.resourcesPath || '', 'bin');
  if (process.resourcesPath && fs.existsSync(packaged)) return packaged;
  return path.join(__dirname, '..', '..', 'bin');
}

/** Presence of each runtime component (checks writable + bundled dirs). */
function assetStatus() {
  const st = scanAssets([userBin(), bundledBinDir()]);
  // a user-located xray (store.xrayPath / XRAY_PATH) counts too
  if (xray) st.xray = st.xray || xray.binExists('xray');
  return st;
}

/**
 * The TUN layer for a connect: sing-box unless the user chose tun2socks or
 * sing-box (with wintun next to it, on Windows) is not installed — then
 * tun2socks, and the log says why. Built per connect (`tunBackend` is
 * reconnect-relevant) and kept on `tun` for stop / recovery / quit. The status
 * paths that only ask isAvailable() / isElevated() build a throwaway one with
 * `quiet`, so the fallback line is logged once per connect, not per poll.
 */
function makeTun(settings, { quiet = false } = {}) {
  const opts = { binDir: bundledBinDir(), extraDirs: [userBin()], onLog: (line, level) => send('log', { line, level }), lang: settings.lang };
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

function send(channel, payload) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send(channel, payload);
  }
}

/* ----------------------------- LAN sharing ----------------------------- */
// When "Allow LAN" is on, the SOCKS/HTTP inbounds already listen on 0.0.0.0
// (see configBuilder). But on Windows the firewall still blocks inbound on
// those ports, so other devices can't connect — we add allow rules here.
const LAN_RULES = { socks: 'IRNetFree LAN SOCKS', http: 'IRNetFree LAN HTTP' };

function netsh(args) {
  return new Promise((resolve, reject) => {
    execFile('netsh', args, { windowsHide: true }, (err, so, se) => {
      if (err) return reject(new Error((se || err.message || '').toString().trim()));
      resolve((so || '').toString());
    });
  });
}

async function removeLanFirewall() {
  if (process.platform !== 'win32') return;
  for (const name of Object.values(LAN_RULES)) {
    try { await netsh(['advfirewall', 'firewall', 'delete', 'rule', `name=${name}`]); } catch {}
  }
}

/** Open inbound TCP for the proxy ports. Needs admin; returns {ok,error}. */
async function addLanFirewall(socksPort, httpPort) {
  if (process.platform !== 'win32') return { ok: true };
  await removeLanFirewall();
  try {
    await netsh(['advfirewall', 'firewall', 'add', 'rule', `name=${LAN_RULES.socks}`,
      'dir=in', 'action=allow', 'protocol=TCP', `localport=${socksPort}`]);
    await netsh(['advfirewall', 'firewall', 'add', 'rule', `name=${LAN_RULES.http}`,
      'dir=in', 'action=allow', 'protocol=TCP', `localport=${httpPort}`]);
    return { ok: true };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

const TUN_LOCAL_IP = '10.255.0.2';   // our own TUN adapter address — never a LAN IP

/** Candidate LAN IPv4 addresses (skips loopback, our TUN adapter, APIPA). */
function lanCandidates() {
  const ifs = os.networkInterfaces();
  const out = [];
  for (const name of Object.keys(ifs)) {
    for (const ni of ifs[name] || []) {
      if (ni.family !== 'IPv4' || ni.internal) continue;
      if (ni.address === TUN_LOCAL_IP) continue;
      if (ni.address.startsWith('169.254.')) continue;   // APIPA / link-local
      out.push(ni.address);
    }
  }
  return out;
}

/** Best LAN IPv4 (the address other devices point their proxy at). */
function lanIp() {
  const c = lanCandidates();
  // prefer common home/office private ranges over odd virtual adapters
  const score = (a) => a.startsWith('192.168.') ? 3
    : /^172\.(1[6-9]|2\d|3[01])\./.test(a) ? 2
    : a.startsWith('10.') ? 1 : 0;
  c.sort((x, y) => score(y) - score(x));
  return c[0] || null;
}

/* ----------------------------- kill switch ----------------------------- */
// Blocks ALL outbound traffic (Windows firewall) if the VPN drops unexpectedly,
// so nothing leaks. The user must disarm (or reconnect) to restore internet.
const KILL_RULE = 'IRNetFree KillSwitch';
let killEngaged = false;

async function armKillSwitch() {
  if (process.platform !== 'win32') return { ok: false, error: 'windows only' };
  try {
    await netsh(['advfirewall', 'firewall', 'delete', 'rule', `name=${KILL_RULE}`]).catch(() => {});
    await netsh(['advfirewall', 'firewall', 'add', 'rule', `name=${KILL_RULE}`,
      'dir=out', 'action=block', 'protocol=any', 'remoteip=any']);
    killEngaged = true;
    return { ok: true };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

async function disarmKillSwitch() {
  killEngaged = false;
  if (process.platform !== 'win32') return;
  try { await netsh(['advfirewall', 'firewall', 'delete', 'rule', `name=${KILL_RULE}`]); } catch {}
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1080,
    height: 720,
    minWidth: 900,
    minHeight: 600,
    backgroundColor: '#0d1117',
    title: 'IRNetFree',
    icon: path.join(__dirname, '..', '..', 'assets', 'icon.png'),
    frame: false,
    webPreferences: {
      preload: path.join(__dirname, '..', 'preload', 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false
    }
  });

  mainWindow.loadFile(path.join(__dirname, '..', 'renderer', 'index.html'));

  mainWindow.on('close', (e) => {
    if (!isQuitting) {
      e.preventDefault();
      mainWindow.hide();
    }
  });

  // mainWindow.webContents.openDevTools({ mode: 'detach' });
}

function createTray() {
  const iconPath = path.join(__dirname, '..', '..', 'assets', 'tray.png');
  let icon = nativeImage.createFromPath(iconPath);
  if (icon.isEmpty()) icon = nativeImage.createEmpty();
  // macOS menu-bar icons look best resized to ~18px.
  if (process.platform === 'darwin' && !icon.isEmpty()) {
    icon = icon.resize({ width: 18, height: 18 });
  }
  tray = new Tray(icon);
  tray.setToolTip('IRNetFree');
  const menu = Menu.buildFromTemplate([
    { label: 'نمایش / Show', click: () => { mainWindow.show(); } },
    { type: 'separator' },
    { label: 'قطع اتصال / Disconnect', click: () => doDisconnect() },
    { type: 'separator' },
    { label: 'خروج / Quit', click: () => { isQuitting = true; app.quit(); } }
  ]);
  tray.setContextMenu(menu);
  tray.on('double-click', () => mainWindow.show());
}

/* ----------------------------- core actions ----------------------------- */

/** Process names referenced by advanced routing 'process' rules. */
function activeProcNames(settings) {
  if (!settings || !settings.advancedRouting) return [];
  return [...new Set((settings.routeRules || [])
    .filter(r => r && r.type === 'process' && r.value)
    .map(r => String(r.value)))];
}

function loadProcCache() { return store.get('procIpCache', {}) || {}; }
function saveProcCache(c) { store.set('procIpCache', c); }

/**
 * Return a settings copy in which every 'process' route rule is rewritten into
 * a concrete 'ip' rule (live connections of that process unioned with the
 * persisted per-process cache). The stored rules keep type:'process'.
 */
async function effectiveSettings() {
  const s = getSettings();
  const names = activeProcNames(s);
  if (!names.length) return s;
  const cache = loadProcCache();
  pruneProcCache(cache);
  let ipsByName = {};
  try {
    const r = await collectProcessIps(names, cache);
    ipsByName = r.ips;
    saveProcCache(cache);
  } catch (e) {
    send('log', { line: 'Process routing resolve failed: ' + e.message, level: 'warn' });
  }
  const rules = (s.routeRules || []).map(r => {
    if (r && r.type === 'process' && r.value) {
      const list = ipsByName[r.value] || (cache[r.value] && cache[r.value].ips) || [];
      return { type: 'ip', value: list.join(','), target: r.target };
    }
    return r;
  });
  return Object.assign({}, s, { routeRules: rules });
}

/**
 * The connection plan for a target id: { plan, label, entryAddrs }.
 * `entryAddrs` are the addresses the machine dials *directly* (must be bypassed
 * under TUN so the tunnel doesn't loop on itself). No side effects.
 */
function buildPlan(serverId, settings) {
  const servers = store.get('servers', []);
  const byId = (id) => servers.find(s => s.id === id);
  const serversById = {};
  for (const s of servers) serversById[s.id] = s;

  // Named chains (first-class "configs"). Legacy single global chain (store.chain)
  // is kept only as a fallback for old routing rules that target 'chain'.
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
      if (String(tg).indexOf('chain:') === 0) {
        const m = chainsById[String(tg).slice('chain:'.length)];
        return !!(m && m.length >= 2);
      }
      return !!serversById[tg];
    };
    const entries = getPool()
      .filter(e => e.enabled && e.socksPort && targetExists(e.target))
      .map(e => ({ id: e.id, name: e.name, target: e.target, socksPort: e.socksPort, httpPort: e.httpPort }));
    if (!entries.length) throw new Error(settings.lang === 'en'
      ? 'Enable at least one valid proxy in the pool (with a port and an existing target).'
      : 'حداقل یک پروکسیِ معتبر در استخر را فعال کن (با پورت و یک مقصدِ موجود).');
    const primary = entries[0].target;
    plan = { mode: 'pool', entries, primary, serversById, chainsById, chain: legacyChain };
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
    if (members.length < 2) throw new Error(settings.lang === 'en'
      ? 'This chain needs at least 2 servers'
      : 'این زنجیره حداقل به ۲ سرور نیاز دارد');
    plan = { mode: 'chain', chain: members, name: chainById[serverId].name };
    label = chainById[serverId].name;
    entryAddrs = [members[0].address];
  } else if (serverId === '__chain__') {
    if (legacyChain.length < 2) throw new Error(settings.lang === 'en'
      ? 'The chain needs at least 2 servers'
      : 'زنجیره حداقل به ۲ سرور نیاز دارد');
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

/**
 * Build the connection plan + xray config for a target id, using already
 * process-resolved settings. Returns { plan, label, entryAddrs, config, geoWarn,
 * engine }. No side effects.
 */
function buildActive(serverId, settings) {
  const { plan, label, entryAddrs } = buildPlan(serverId, settings);

  // Are the geo databases installed? If not, geosite:/geoip: rules would make
  // xray refuse to start — buildConfig drops them and we warn the user.
  const geoSt = assetStatus();
  const geoAssets = !!(geoSt.geoip && geoSt.geosite);
  let geoWarn = null;
  const usesGeo = plan.mode === 'pool' ? false : (
    (plan.mode === 'advanced' &&
      ((settings.routeRules || []).some(r => r && /^(geoip|geosite):/i.test(String(r.value || ''))))) ||
    (plan.mode !== 'advanced' &&
      (settings.routingMode === 'bypass-ir' || settings.routingMode === 'bypass-cn' ||
        (settings.blockAds && plan.mode !== 'advanced'))));
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
  // A certificate that rotated since it was pinned makes the core refuse every
  // dial to that server, and it says so only at log level `info` — which the
  // app does not run at, so healCertPin() below never hears it and the server
  // is dead for good. Asking the servers ourselves works at any log level: a
  // pin that no longer matches is dropped here, and the probe below (which
  // picks up every directly-dialled server without a pin) learns the new one on
  // this same connect.
  const stale = await staleCertPins(directServers(plan), fetchLeafPin).catch(() => []);
  if (stale.length) {
    const ids = new Set(stale.map(s => s.id));
    store.set('servers', store.get('servers', []).map(s => {
      if (!ids.has(s.id)) return s;
      const out = Object.assign({}, s);
      delete out.certPin; delete out.certPinAt;
      return out;
    }));
    for (const s of stale) {
      send('log', { line: `Certificate changed for ${s.name} — the old pin is gone; the one it presents now will be pinned instead`, level: 'warn' });
      delete s.certPin; delete s.certPinAt;   // the plan holds the same objects
    }
  }
  if (!probe.length && !stale.length) return;
  for (const s of stale) if (!probe.includes(s)) probe.push(s);
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

/**
 * The settings for this connect, with every WireGuard peer endpoint that is a
 * NAME resolved to an address (see configBuilder.wgEndpointHosts for why).
 * A name we cannot resolve is left as it is — the core's own error is clearer
 * than anything invented here.
 *
 * Only for the core that needs it (see engineChoice.needsWgEndpointIp): this
 * resolves through the MACHINE's resolver, which on a filtered connection is
 * the answer the app exists to avoid trusting. The official core does its own
 * lookup over DoH and must keep doing it.
 */
async function withWgEndpointIps(serverId, settings) {
  let hosts = [];
  try {
    const { plan } = buildPlan(serverId, settings);
    if (!needsWgEndpointIp(xray.resolveEngine(chooseEngine(plan, settings.defaultEngine), { quiet: true }).id)) return settings;
    hosts = wgEndpointHosts(plan);
  } catch { return settings; }
  if (!hosts.length) return settings;
  const map = {};
  await Promise.all(hosts.map(async (h) => {
    const ips = await tunPlatform.resolveServerIps(h).catch(() => []);
    if (ips.length) map[h] = ips[0];
    else send('log', { line: `Could not resolve the WireGuard endpoint ${h} — leaving it to the core`, level: 'warn' });
  }));
  const named = Object.keys(map);
  if (!named.length) return settings;
  send('log', { line: 'WireGuard endpoint: ' + named.map(h => `${h} → ${map[h]}`).join(', '), level: 'info' });
  return Object.assign({}, settings, { wgEndpointIps: map });
}

/**
 * Arm the "this tunnel is talking to nobody" watch for the WireGuard outbounds
 * of the config we are about to run, and forget the previous connection's.
 */
let wgSilence = null;
function watchWgSilence(config) {
  const wg = (config && config.outbounds || []).filter(o => o && o.protocol === 'wireguard');
  wgSilence = wg.length
    ? { watch: new SilenceWatch(wg.map(o => o.tag)), by: new Map(wg.map(o => [o.tag, wgEndpointOf(o)])) }
    : null;
}

/** The peer address a WireGuard outbound dials, for the message below. */
function wgEndpointOf(o) {
  const peer = o.settings && o.settings.peers && o.settings.peers[0];
  return (peer && peer.endpoint) || '';
}

/**
 * A WireGuard that has sent and never been answered, said out loud once.
 *
 * Without this the user sees only that "the company sites do not open" while
 * every other route works — the core reports the failed handshake at [Debug],
 * which nobody runs — and the obvious conclusion is that routing is broken.
 */
function reportSilentTunnels(vars) {
  if (!wgSilence) return;
  for (const tag of wgSilence.watch.check(vars)) {
    const ep = wgSilence.by.get(tag);
    send('log', {
      line: getSettings().lang === 'en'
        ? `WireGuard ${ep || tag}: traffic is being routed into this tunnel and nothing is coming back — the peer is not completing the handshake. Check the endpoint, its port, and whether the hop in front of it carries UDP.`
        : `وایرگارد ${ep || tag}: ترافیک به این تونل فرستاده می‌شود ولی هیچ پاسخی برنمی‌گردد — یعنی handshake با peer کامل نمی‌شود. endpoint و پورتش را چک کن و این‌که هاپِ قبل از آن UDP را عبور می‌دهد یا نه.`,
      level: 'warn'
    });
  }
}

/**
 * @param {string} serverId
 * @param {{ holdKillSwitch?: boolean }} [opts] `holdKillSwitch` keeps an already
 *   armed kill-switch block in place instead of clearing it up front — used by
 *   reapplyConnection() so the gap between the old and the new tunnel can't leak.
 * @returns {Promise<{ ok: boolean, tunError?: string|null, stale?: boolean }>}
 *   `stale: true` means a disconnect (or a newer connect) overtook this call
 *   before it finished: nothing was emitted and nothing was started, and the
 *   caller must not treat it as either a success or a failure worth retrying.
 */
async function doConnect(serverId, opts = {}) {
  // Every await below is a window in which the user can hit the power button.
  // doDisconnect() then stops the core and clears activeServerId, but THIS call
  // would carry on to start both watchers again and emit 'connected' — leaving
  // the UI claiming a tunnel that no longer exists, with two leaked watchers
  // behind it and a recovery retry that the activeServerId guard silently drops,
  // so nothing ever corrects the display. The token says whose turn it is.
  const gen = ++connGen;
  const stale = () => gen !== connGen;
  const abandoned = { ok: false, stale: true };

  // clear any kill-switch block from a previous unexpected drop
  if (!opts.holdKillSwitch) {
    await disarmKillSwitch();
    if (stale()) return abandoned;
    send('killswitch', { engaged: false });
  }
  let settings = await effectiveSettings();
  if (stale()) return abandoned;
  const byId = (id) => store.get('servers', []).find(s => s.id === id);

  // allowInsecure is gone from the core: pin the certificate on first use instead.
  await ensureCertPins(serverId, settings);
  if (stale()) return abandoned;

  // A WireGuard peer's endpoint is a NAME in every .conf a company hands out,
  // and the two cores disagree about who resolves it: the official one asks its
  // own DNS, the patterniha fork asks the OS resolver ("Unable to update bind:
  // lookup <host>: no such host") or hands the bare name to the next hop of the
  // chain. On that core the tunnel then never comes up — everything else still
  // works, which is what makes it so hard to see. Resolve it here, once, and
  // give the core an address: same behaviour on both, and the tunnel no longer
  // bootstraps through the DNS it is itself supposed to carry.
  settings = await withWgEndpointIps(serverId, settings);
  if (stale()) return abandoned;

  // The TUN layer for this connect — the backend setting plus what is
  // installed. A LIVE instance is never replaced: switching servers keeps the
  // running tunnel (tun.start() is a no-op while active); a new choice takes
  // effect through reapplyConnection() / doDisconnect(), which stop it first.
  if (!tun || !tun.active) tun = makeTun(settings);
  // The instance THIS call works with. `tun` is module-level and a second
  // connect can replace it while this one is still inside tun.start(); the
  // tunnel we started would then be unreachable by every teardown path.
  // Ours stays in hand, and startedTuns is what disconnect/quit/exit sweep.
  const myTun = tun;
  startedTuns.add(myTun);

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

  // Validate first so chain / advanced-routing mistakes surface as a clear
  // message instead of a config that crashes xray right after "connected".
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
      : ''
      // A geo code the data files do not carry refuses the whole config, and
      // the core's own line reads like the files are missing (see geoCheck.js).
      + geoCodeHint(check.error, settings.lang === 'en' ? 'en' : 'fa');
    // Only Error.message survives the IPC boundary, so the hint IS the signal:
    // the renderer keys off the (untranslated) product name in it. A property
    // set here would be dropped in transit — don't add one.
    throw new Error((settings.lang === 'en' ? 'Config error: ' : 'خطای کانفیگ: ') + check.error + hint);
  }
  const runEngine = check.engine;

  // Suppress the old instance's 'stopped' while switching servers so it isn't
  // mistaken for an unexpected drop (which would trip the kill switch) or flash
  // "disconnected" in the UI. Save/restore rather than clear: reapplyConnection()
  // wraps the whole teardown+reconnect in the same flag.
  const prevReloading = xrayReloading;
  xrayReloading = true;
  try {
    await xray.start(config, runEngine);
  } catch (e) {
    // start() watches for 1.2 s to catch a config that crashes the core on
    // startup. A disconnect landing inside that grace KILLS the process, so the
    // watcher reports "xray exited on startup" — a failure the user caused on
    // purpose, dressed as a config error. Propagating it paints an error toast
    // through the IPC handler, and through reapplyConnection() it emits
    // killswitch { engaged: true } AFTER doDisconnect() already disarmed the
    // block, so the banner claims the internet is blocked while the firewall is
    // open. Abandonment, not an error: answer like every other gate below.
    if (stale()) return abandoned;
    throw e;
  } finally {
    xrayReloading = prevReloading;
  }
  // The critical one. doDisconnect() has already stopped the core it just
  // started, so writing activeServerId back here would resurrect the very intent
  // the user cancelled — and every side effect below would follow it.
  if (stale()) return abandoned;

  store.set('activeServerId', serverId);
  pinWatch.setLive(directServers(plan));
  // Everything below is a connect-time side effect, so from here on the live
  // tunnel matches these settings exactly — record what it was built from.
  appliedSettings = snapshotApplied(getSettings());

  if (settings.systemProxy) {
    try {
      await setSystemProxy(true, { host: '127.0.0.1', httpPort: settings.httpPort, socksPort: settings.socksPort });
      send('log', { line: 'System proxy enabled', level: 'info' });
    } catch (e) {
      send('log', { line: 'System proxy failed: ' + e.message, level: 'error' });
    }
  }
  if (stale()) return abandoned;

  updateTray(true, label);

  // TUN mode (system-wide tunnel via sing-box, or tun2socks as the fallback —
  // see makeTun). Requires admin + the backend's files.
  let tunError = null;
  let guardError = null;
  let guardEngaged = false;
  if (settings.tunMode) {
    if (!myTun.isAvailable()) {
      tunError = settings.lang === 'en'
        ? 'TUN needs sing-box (or tun2socks) and wintun in the bin folder.'
        : 'حالت TUN به sing-box (یا tun2socks) و wintun در پوشه bin نیاز دارد.';
      send('log', { line: 'TUN requested but sing-box/tun2socks (with wintun) not found — connected proxy-only', level: 'error' });
    } else {
      try {
        myTun.lang = settings.lang || 'fa';
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
        const dnsPeer = myTun.dnsPeer || TUN_GW;
        // A tunnel that is already up was built for the PREVIOUS server: its
        // route exclusions — and, at the strict level, the firewall holes cut
        // from them — still name that server's address, so the new one would
        // be blocked by our own guard. Tear it down and build it for this
        // connect; the kill switch (when armed) seals the gap.
        if (myTun.active) {
          try { await leakGuard.release(); } catch {}
          try { await myTun.stop(); } catch {}
        }
        await myTun.start(settings.socksPort, [...entryAddrs, ...resolverBypassIps(plan, settings)],
          adapterDnsServers(settings, hijacks ? dnsPeer : null),
          { ipv6: !!settings.ipv6, strict: settings.leakGuard === 'strict' });   // tun2socks ignores the 4th
        send('log', { line: 'TUN mode active (whole system)', level: 'info' });
        if (settings.leakGuard === 'strict' && myTun.backendId !== 'sing-box') {
          send('log', { line: 'Strict guard on the tun2socks backend: no strict_route and no IPv6 route — install sing-box for the guard the setting promises', level: 'warn' });
        }
      } catch (e) {
        tunError = e.message;
        send('log', { line: 'TUN start failed: ' + e.message, level: 'error' });
      }
    }
    // The leak guard (standard): the TUN adapter's own resolver is ours, but
    // Windows asks the resolvers of EVERY connected adapter in parallel and
    // macOS resolves per network service — so until we take them, the physical
    // adapters still hand every name to the ISP. Only for a tunnel that
    // actually came up: with no tunnel there is nothing to point them at, and
    // doing it anyway would leave the machine unable to resolve at all.
    if (myTun.active && settings.leakGuard !== 'off') {
      try {
        await leakGuard.engage({
          level: settings.leakGuard,
          peer4: myTun.dnsPeer || TUN_GW,
          peer6: settings.ipv6 ? myTun.dnsPeer6 : null,
          // macOS: the strict level's pf anchor has to name the REAL tunnel
          // device (the utun the backend was given at start), not the Windows
          // adapter name — a ruleset that cannot name the tunnel would block
          // the machine's whole network.
          tunAlias: (process.platform === 'darwin' && myTun.macState && myTun.macState.dev) || myTun.interfaceName || 'XrayTun',
          backend: myTun.backendId || null,
          // What may still leave through the physical adapters at the strict
          // level: the tunnel's own bypass list (the resolved server entry IPs
          // and the direct resolvers). Read AFTER start — that is when the
          // backend has resolved them.
          excludes: myTun.excludeIps || []
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
  // tun.start() is the longest await here (a PowerShell round trip on Windows, a
  // password prompt on macOS) — the likeliest place for a disconnect to land.
  if (stale()) {
    // Everything this call started belongs to an intent that no longer
    // exists. The release is unconditional: engage() can also throw AFTER
    // writing the state file, and a release with nothing to undo is a no-op.
    // The tunnel goes too — doDisconnect()'s own tun.stop() may well have run
    // BEFORE this call's start() finished, which would leave the backend
    // holding the machine's default routes while the UI says 'disconnected'.
    await leakGuard.release().catch(() => {});
    if (myTun && myTun.active) { try { await myTun.stop(); } catch {} }
    return abandoned;
  }

  // LAN sharing: open the firewall on Windows + report the address other
  // devices should point their proxy at.
  let lan = null;
  if (settings.allowLan) {
    lan = { ip: lanIp(), socksPort: settings.socksPort, httpPort: settings.httpPort };
    const fw = await addLanFirewall(settings.socksPort, settings.httpPort);
    if (process.platform === 'win32') {
      if (fw.ok) send('log', { line: `LAN sharing on — firewall opened for ports ${settings.socksPort}/${settings.httpPort}`, level: 'info' });
      else send('log', { line: 'LAN firewall rule failed (run as admin to allow it): ' + fw.error, level: 'warn' });
    }
  } else {
    await removeLanFirewall();
  }
  // Last gate before the irreversible half: the watchers and the 'connected'
  // status. Past this line nothing awaits, so nothing can overtake us.
  if (stale()) return abandoned;

  // Start live traffic stats
  stats.setBin(xray.anyBin());
  stats.apiPort = settings.apiPort;
  watchWgSilence(config);
  stats.start(1000);

  // Keep process routes fresh while connected (opt-in; briefly reloads xray).
  startProcWatcher();
  // Watch for the machine's network moving under the live tunnel. Every reconnect
  // comes through here too (a settings apply, or our own recovery), so keep a
  // watcher that is already running: its baseline is the network the tunnel was
  // built for, and a change it noticed mid-rebuild is still queued on it —
  // replacing it here would adopt the NEW network as normal and leave a tunnel
  // built for the old one with nothing left to notice.
  if (!netWatcher) startNetWatcher();

  updateOverlay('on');
  send('status', {
    state: 'connected', serverId, server: byId(serverId) || null, label, engine: runEngine,
    tun: tun.active, tunError, guardError, geoWarn, lan, pendingReconnect: pendingKeys()
  });
  // `tunError` is the one failure this function does NOT throw for: TUN is a
  // best-effort upgrade and we stay connected proxy-only without it. Callers
  // that must know whether the WHOLE system is tunnelled (the network-change
  // recovery) can only find out from here — the status event above is fire and
  // forget. The renderer ignores this value; it only awaits the call.
  return { ok: true, tunError };
}

/** Reconnect-relevant settings the user changed since the live tunnel was built. */
function pendingKeys() {
  return pendingReconnectKeys(appliedSettings, getSettings());
}

/**
 * Apply settings that are baked into the running tunnel, by tearing the
 * connection down and building it again from the current settings. xray-core has
 * no hot reload, so this is the only honest way to apply them.
 *
 * When the kill switch is on, the firewall block is armed BEFORE the teardown and
 * lifted only once the new tunnel is up: the gap between the two is exactly when
 * traffic would otherwise escape unproxied, which is what the kill switch exists
 * to prevent. If the reconnect fails the block deliberately STAYS engaged — the
 * UI shows the disarm banner, so restoring the internet is the user's call.
 */
async function reapplyConnection() {
  const serverId = store.get('activeServerId', null);
  if (!serverId || !xray || !xray.running) return { ok: false, error: 'not connected' };

  // The teardown below is several awaits long and doConnect()'s own token cannot
  // cover it — that token is taken AFTER the teardown, so it is the newest
  // generation by definition and sees nothing. A disconnect landing in this
  // window bumps connGen, clears activeServerId and emits 'disconnected', and
  // the rebuild would then quietly write the serverId captured above back, bring
  // TUN up and report connected: the user's disconnect undone. It is also the
  // likeliest window there is — the tray's Disconnect item is live throughout,
  // and with the kill switch on, the banner this function arms below offers
  // "Unblock internet", whose button calls exactly that.
  const gen = connGen;

  const lang = getSettings().lang === 'en' ? 'en' : 'fa';
  let armed = false;
  if (getSettings().killSwitch) {
    const r = await armKillSwitch();
    armed = !!(r && r.ok);
    send('killswitch', { engaged: armed, error: r && r.error });
    if (armed) send('log', { line: 'Kill switch engaged for a settings reconnect — internet blocked until the tunnel is back', level: 'warn' });
    else if (process.platform === 'win32') send('log', { line: 'Kill switch could not be armed for the reconnect (run as admin): ' + (r && r.error), level: 'warn' });
  }

  send('status', { state: 'connecting', serverId });

  // The restart is intentional — don't let it look like an unexpected drop (which
  // would arm the kill switch a second time and log a scary line).
  const prevReloading = xrayReloading;
  xrayReloading = true;
  try {
    stopProcWatcher();
    if (stats) stats.stop();
    // Give the adapters their own resolvers back BEFORE the tunnel goes, and let
    // doConnect() engage the guard again on the new one. Holding the override
    // across the gap would point every adapter at a peer that stops routing the
    // moment tun.stop() runs; the kill switch armed above is what seals the gap.
    try { if (leakGuard) await leakGuard.release(); } catch {}
    await stopAllTuns();
    try { await setSystemProxy(false, {}); } catch {}
    try { await removeLanFirewall(); } catch {}
    if (xray) await xray.stop();
  } finally {
    xrayReloading = prevReloading;
  }

  // A disconnect (or a newer connect) overtook the teardown. Everything this
  // function would rebuild belongs to an intent that no longer exists, so stop
  // here — before doConnect() takes a token that could not detect it. The kill
  // switch is the newer operation's too: doDisconnect() disarms it itself, and
  // releasing it here could unblock a machine that operation chose to keep shut.
  if (gen !== connGen) return { ok: false, stale: true };

  let r;
  try {
    r = await doConnect(serverId, { holdKillSwitch: armed });
  } catch (e) {
    appliedSettings = null;
    if (armed) {
      send('log', { line: 'Reconnect failed — the internet stays blocked by the kill switch: ' + e.message, level: 'error' });
      send('killswitch', { engaged: true });
    }
    send('status', { state: 'error', message: e.message });
    return {
      ok: false,
      killSwitchEngaged: armed,
      error: (lang === 'en' ? 'Reconnect failed: ' : 'اتصال مجدد ناموفق بود: ') + e.message
    };
  }

  // A disconnect overtook the connect: it emitted nothing and started nothing, so
  // neither may we. The newer operation owns the kill switch as well —
  // doDisconnect() disarms it itself, and releasing it here could unblock the
  // machine at a moment that operation chose to keep blocked.
  if (r && r.stale) return { ok: false, stale: true };

  if (armed) {
    await disarmKillSwitch();
    send('killswitch', { engaged: false });
    send('log', { line: 'Kill switch released — tunnel is back up', level: 'info' });
  }
  // Pass doConnect()'s one non-throwing failure through: the tunnel is up but
  // TUN is not, so this is not a complete reconnect for whoever asked for one.
  return { ok: true, tunError: (r && r.tunError) || null };
}

/**
 * Rebuild + restart ONLY xray for the currently active target. Used by the
 * process-routing watcher when a routed app reaches new destinations. Leaves
 * TUN / system proxy / stats in place — xray-core has no hot routing reload, so
 * a brief xray restart is the only way to apply changed routing rules.
 */
async function rebuildActiveConfig() {
  const serverId = store.get('activeServerId', null);
  if (!serverId || !xray.running) return;
  let settings = await effectiveSettings();
  // Keep the binding the live connection was built with (see doConnect): the
  // tunnel stays up across this reload, and asking the OS now would name it.
  if (liveDirectInterface) settings = Object.assign({}, settings, { directInterface: liveDirectInterface });
  const { config, engine } = buildActive(serverId, settings);
  // Suppress the transient 'stopped' status from the old instance so the UI
  // doesn't flash "disconnected" during the reload.
  const prevReloading = xrayReloading;
  xrayReloading = true;
  try {
    const check = await xray.validateWithFallback(config, engine);
    if (!check.ok) throw new Error(check.error);
    await xray.start(config, check.engine);   // start() stops the old instance first
    watchWgSilence(config);   // the plan may have changed under the live tunnel
  } finally {
    xrayReloading = prevReloading;
  }
  // NOTE: appliedSettings is deliberately left alone. This path rebuilds only the
  // xray config; the connect-time side effects (system proxy, TUN, LAN firewall)
  // are untouched, so a pending change to those is still genuinely pending.
  stats.setBin(xray.anyBin());
  send('log', { line: 'Process routes applied (xray reloaded)', level: 'info' });
}

function startProcWatcher() {
  stopProcWatcher();
  const s = getSettings();
  if (!s.advancedRouting || !s.procRouteWatch || !activeProcNames(s).length) return;
  procWatcher = new ProcWatcher({
    getNames: () => activeProcNames(getSettings()),
    loadCache: loadProcCache,
    saveCache: saveProcCache,
    onGrow: () => rebuildActiveConfig(),
    onLog: (line, level) => send('log', { line, level }),
    intervalMs: 20000
  });
  procWatcher.start();
}

function stopProcWatcher() {
  if (procWatcher) { procWatcher.stop(); procWatcher = null; }
}

/**
 * The machine's network changed under a live tunnel. xray does not die when that
 * happens — it just stops passing traffic, and under TUN the bypass routes still
 * point at the old gateway — so nothing else would notice. Rebuild the connection
 * from current settings; reapplyConnection() already holds the kill-switch block
 * across the gap, so this cannot leak.
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
  // PowerShell, and macOS waits on a password prompt the user may simply ignore.
  // A run that never returns would park every future trigger for the life of the
  // process, so the lock is stamped with a generation that doDisconnect() bumps —
  // that is the reset, and it is why the release below is conditional.
  const gen = recoverGen;
  recovering = true;
  try {
    await runRecovery(reason, attempt);
  } finally {
    // Release the lock and nothing else. The watcher's own baseline is not ours
    // to move: its ignoreInterface predicate already keeps the fingerprint stable
    // across the rebuild, so there is nothing half-seen left to forgive — while a
    // GENUINE change landing in the tail of this recovery is still only pending,
    // and adopting it here would leave the tunnel built for a gateway that is
    // gone with nothing left to notice.
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
  // in the same { ok, tunError, error } shape.
  let res;
  try {
    if (xray && xray.running) {
      res = await reapplyConnection();
    } else {
      // A previous attempt already stopped the core, so there is nothing to tear
      // down. Keep any kill-switch block that attempt deliberately left engaged —
      // doConnect() clears it up front otherwise, which would open the machine up
      // during exactly the gap the block exists to cover.
      const held = killEngaged;
      res = await doConnect(serverId, { holdKillSwitch: held });
      // Only release the block for a tunnel that actually came back. When the
      // connect abandoned itself the newer operation owns the kill switch —
      // doDisconnect() disarms it itself — and announcing "tunnel is back up"
      // here would be a restoration that never happened.
      if (held && !(res && res.stale)) {
        await disarmKillSwitch();
        send('killswitch', { engaged: false });
        send('log', { line: 'Kill switch released — tunnel is back up', level: 'info' });
      }
    }
  } catch (e) {
    // doConnect() throws where reapplyConnection() returns { ok: false }.
    res = { ok: false, error: (e && e.message) || String(e) };
  }

  // The user disconnected (or connected somewhere else) while we were rebuilding.
  // The rebuild abandoned itself without emitting anything; a log line or a
  // retry here would be about a tunnel nobody asked for any more.
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
  // Missing privileges are permanent in exactly the same way: a non-admin Windows
  // user with tun2socks installed fails with "TUN mode needs Administrator
  // rights" on every attempt, and no rebuild can grant them — retrying just costs
  // them ~25 s of torn-down proxy on every network change. isElevated() is the
  // question "could this ever have worked", so it belongs in the same judgement.
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
  // `recovering` itself is deliberately NOT cleared HERE: startNetWatcher() calls
  // this first, and a recovery's own reconnect can reach it — releasing the lock
  // there would let a second recovery start alongside the one still going.
  // doDisconnect() is where the reset belongs, and it does it explicitly.
  recoverQueued = null;
  if (netWatcher) { netWatcher.stop(); netWatcher = null; }
}

/**
 * Stop every TUN backend a connect has started, not just the current one — an
 * overlapping connect can leave an older instance holding the machine's routes
 * with nothing else pointing at it (see startedTuns).
 */
async function stopAllTuns() {
  const all = new Set(startedTuns);
  if (tun) all.add(tun);
  startedTuns.clear();
  for (const t of all) { try { await t.stop(); } catch {} }
}

/** The same sweep for the exit hook, where nothing can be awaited. */
function cleanupAllTunsSync() {
  const all = new Set(startedTuns);
  if (tun) all.add(tun);
  for (const t of all) { try { t.cleanupSync(); } catch {} }
}

async function doDisconnect() {
  userDisconnecting = true;        // intentional — don't trip the kill switch
  // Anything already in flight stops speaking for the app from this line on: a
  // doConnect() past xray.start() must not emit 'connected' or restart the
  // watchers, and a recovery that hung (a stuck PowerShell, an ignored macOS
  // password prompt) must not keep its lock and park every future trigger.
  connGen++;
  recoverGen++;
  recovering = false;
  stopProcWatcher();
  stopNetWatcher();                // nothing live to recover any more
  if (stats) stats.stop();
  // The adapters point at real resolvers again BEFORE the tunnel goes: in
  // between they would be pointing at an address that no longer routes anywhere.
  try { if (leakGuard) await leakGuard.release(); } catch {}
  // `tun` is the instance doConnect() started (makeTun), whichever backend it
  // chose — the same one before-quit and the exit hook tear down.
  await stopAllTuns();
  try { await setSystemProxy(false, {}); } catch {}
  try { await removeLanFirewall(); } catch {}
  try { await disarmKillSwitch(); } catch {}
  send('killswitch', { engaged: false });
  if (xray) await xray.stop();
  store.set('activeServerId', null);
  pinWatch.clear();
  appliedSettings = null;          // nothing live to be out of sync with
  liveDirectInterface = null;
  updateTray(false);
  updateOverlay('off');
  send('status', { state: 'disconnected' });
  userDisconnecting = false;
}

function updateTray(connected, name) {
  if (!tray) return;
  tray.setToolTip(connected ? `IRNetFree — ${name}` : 'IRNetFree — disconnected');
}

/* ----- taskbar overlay badge (green ✓ when connected, red ✕ when off) ----- */
let _overlayCache = {};
function makeStateIcon(kind) {
  if (_overlayCache[kind]) return _overlayCache[kind];
  const W = 16, H = 16;
  const buf = Buffer.alloc(W * H * 4); // BGRA, starts fully transparent
  const set = (x, y, b, g, r, a) => {
    x = Math.round(x); y = Math.round(y);
    if (x < 0 || y < 0 || x >= W || y >= H) return;
    const i = (y * W + x) * 4;
    buf[i] = b; buf[i + 1] = g; buf[i + 2] = r; buf[i + 3] = a;
  };
  const col = kind === 'on' ? [80, 185, 63] : [73, 81, 248]; // B,G,R (green / red)
  const cx = 7.5, cy = 7.5, rad = 7.3;
  for (let y = 0; y < H; y++) {
    for (let x = 0; x < W; x++) {
      const d = Math.hypot(x - cx, y - cy);
      if (d <= rad) set(x, y, col[0], col[1], col[2], d > rad - 1 ? 170 : 255);
    }
  }
  const line = (x0, y0, x1, y1) => {
    const steps = Math.ceil(Math.max(Math.abs(x1 - x0), Math.abs(y1 - y0)) * 3);
    for (let i = 0; i <= steps; i++) {
      const t = i / steps, x = x0 + (x1 - x0) * t, y = y0 + (y1 - y0) * t;
      set(x, y, 255, 255, 255, 255);
      set(x + 1, y, 255, 255, 255, 255);
      set(x, y + 1, 255, 255, 255, 255);
    }
  };
  if (kind === 'on') { line(4, 8, 6.5, 11); line(6.5, 11, 12, 4.5); }     // ✓
  else { line(4.5, 4.5, 11.5, 11.5); line(11.5, 4.5, 4.5, 11.5); }        // ✕
  const img = nativeImage.createFromBitmap(buf, { width: W, height: H });
  _overlayCache[kind] = img;
  return img;
}

/** Badge the Windows taskbar icon with the connection state. */
function updateOverlay(stateStr) {
  if (!mainWindow || mainWindow.isDestroyed() || process.platform !== 'win32') return;
  try {
    if (stateStr === 'on') mainWindow.setOverlayIcon(makeStateIcon('on'), 'Connected');
    else mainWindow.setOverlayIcon(makeStateIcon('off'), 'Disconnected');
  } catch {}
}

function getSettings() {
  return Object.assign({}, DEFAULT_SETTINGS, store.get('settings', {}));
}

/**
 * Proxy pool entries: [{ id, name, target, socksPort, httpPort, enabled }].
 * `target` is a server id or 'chain:<chainId>'. Each enabled entry becomes its
 * own local SOCKS/HTTP inbound routed to that exit (see buildPoolConfig).
 */
function getPool() {
  const raw = store.get('pool', []);
  if (!Array.isArray(raw)) return [];
  return raw
    .filter(e => e && e.id)
    .map(e => ({
      id: String(e.id),
      name: String(e.name || 'Proxy').trim() || 'Proxy',
      target: String(e.target || ''),
      socksPort: parseInt(e.socksPort, 10) || 0,
      httpPort: parseInt(e.httpPort, 10) || 0,
      enabled: e.enabled !== false
    }));
}

/**
 * One-time upgrade of the saved servers to the shape the current parser and
 * config builder expect (see migrateStoredServer). Runs at startup and writes
 * back, so it costs one pass over the list per launch at most — every later read
 * of `servers` sees the migrated records without repeating the work.
 *
 * Silent on purpose: it has to run before anything reads `servers`, and at that
 * point there is no window to send a log line to.
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

/** Named proxy chains: [{ id, name, members:[serverId,...] }]. */
function getChains() {
  const chains = store.get('chains', null);
  if (Array.isArray(chains)) return chains;
  // One-time migration: turn the old single global chain into a named chain.
  const legacy = store.get('chain', []) || [];
  const seed = legacy.length >= 2 ? [{ id: 'chain-' + Date.now().toString(36), name: 'زنجیره ۱', members: legacy.slice() }] : [];
  store.set('chains', seed);
  return seed;
}

/* ----------------------------- IPC handlers ----------------------------- */
function registerIpc() {
  ipcMain.handle('app:init', () => ({
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
    version: app.getVersion(),
    // what the desktop asks for — the renderer needs it for theme: 'system'
    systemDark: nativeTheme.shouldUseDarkColors,
    // survives a renderer reload: the banner must not disappear on refresh
    pendingReconnect: pendingKeys(),
    // set when the saved data was unreadable at startup (the window did not
    // exist yet, so the store-error event could not have been delivered)
    storeError: store.loadError
  }));

  ipcMain.handle('servers:import', (e, text) => {
    const { servers: parsed, errors } = parseMany(text);
    const existing = store.get('servers', []);
    const merged = existing.concat(parsed);
    store.set('servers', merged);
    return { added: parsed.length, errors, servers: merged };
  });

  ipcMain.handle('servers:add', (e, link) => {
    const server = parseLink(link);
    const existing = store.get('servers', []);
    existing.push(server);
    store.set('servers', existing);
    return server;
  });

  ipcMain.handle('servers:addWireguard', (e, fields) => {
    const server = makeWireguardServer(fields || {});
    const existing = store.get('servers', []);
    existing.push(server);
    store.set('servers', existing);
    return { server, servers: existing };
  });

  ipcMain.handle('servers:addProxy', (e, fields) => {
    const server = makeProxyServer(fields || {});
    const existing = store.get('servers', []);
    existing.push(server);
    store.set('servers', existing);
    return { server, servers: existing };
  });

  // Read a WireGuard .conf the user picks, and parse .conf text into form fields.
  ipcMain.handle('wg:pickConf', async () => {
    const res = await dialog.showOpenDialog(mainWindow, {
      title: 'Select a WireGuard configuration',
      properties: ['openFile'],
      filters: [{ name: 'WireGuard', extensions: ['conf', 'txt'] }]
    });
    if (res.canceled || !res.filePaths[0]) return { ok: false, canceled: true };
    try { return { ok: true, text: fs.readFileSync(res.filePaths[0], 'utf8') }; }
    catch (e) { return { ok: false, error: e.message }; }
  });
  ipcMain.handle('wg:parseConf', (e, text) => {
    try { return { ok: true, fields: parseWireguardConf(text) }; }
    catch (err) { return { ok: false, error: err.message }; }
  });

  ipcMain.handle('servers:update', (e, { id, fields }) => {
    const servers = store.get('servers', []);
    const idx = servers.findIndex(s => s.id === id);
    if (idx === -1) return { ok: false, error: 'not found', servers };
    servers[idx] = applyServerEdits(servers[idx], fields || {});
    store.set('servers', servers);
    return { ok: true, server: servers[idx], servers };
  });

  ipcMain.handle('chain:get', () => store.get('chain', []));
  ipcMain.handle('chain:set', (e, ids) => {
    const valid = Array.isArray(ids) ? ids : [];
    store.set('chain', valid);
    return valid;
  });

  // Named proxy chains (first-class configs)
  ipcMain.handle('chains:list', () => getChains());
  ipcMain.handle('chains:set', (e, chains) => {
    const valid = Array.isArray(chains)
      ? chains
          .filter(c => c && c.id)
          .map(c => ({ id: c.id, name: String(c.name || 'Chain').trim() || 'Chain', members: Array.isArray(c.members) ? c.members.filter(Boolean) : [] }))
      : [];
    store.set('chains', valid);
    return valid;
  });

  // Proxy pool (multi-config): each enabled entry becomes its own local
  // SOCKS/HTTP port routed to its own exit.
  ipcMain.handle('pool:list', () => getPool());
  ipcMain.handle('pool:set', (e, entries) => {
    const valid = Array.isArray(entries)
      ? entries
          .filter(c => c && c.id)
          .map(c => ({
            id: String(c.id),
            name: String(c.name || 'Proxy').trim() || 'Proxy',
            target: String(c.target || ''),
            socksPort: parseInt(c.socksPort, 10) || 0,
            httpPort: parseInt(c.httpPort, 10) || 0,
            enabled: c.enabled !== false
          }))
      : [];
    store.set('pool', valid);
    return valid;
  });

  // Relaunch the app elevated (Windows) so TUN mode can configure routes.
  ipcMain.handle('app:relaunchAdmin', () => {
    if (process.platform !== 'win32') return { ok: false, error: 'only on Windows' };
    if (makeTun(getSettings(), { quiet: true }).isElevated()) return { ok: false, error: 'already elevated' };
    try {
      const exe = process.execPath;
      const args = process.argv.slice(1);
      const argList = args.map(a => `'${String(a).replace(/'/g, "''")}'`).join(',');
      const psArgs = argList
        ? `Start-Process -FilePath '${exe}' -Verb RunAs -ArgumentList ${argList}`
        : `Start-Process -FilePath '${exe}' -Verb RunAs`;
      spawn('powershell', ['-NoProfile', '-NonInteractive', '-Command', psArgs], { detached: true, windowsHide: true });
      isQuitting = true;
      setTimeout(() => app.quit(), 300);
      return { ok: true };
    } catch (e) {
      return { ok: false, error: e.message };
    }
  });

  ipcMain.handle('servers:delete', (e, id) => {
    let servers = store.get('servers', []);
    servers = servers.filter(s => s.id !== id);
    store.set('servers', servers);
    return servers;
  });

  ipcMain.handle('servers:clear', () => {
    store.set('servers', []);
    return [];
  });

  ipcMain.handle('servers:list', () => store.get('servers', []));
  // Serialize a server (with ALL its settings) back into a shareable link.
  ipcMain.handle('servers:link', (e, id) => {
    const s = store.get('servers', []).find(x => x.id === id);
    return s ? buildShareLink(s) : '';
  });

  /* ----- subscriptions ----- */
  ipcMain.handle('subs:list', () => subs.list());
  ipcMain.handle('subs:add', async (e, { url, name }) => {
    const res = await subs.add(url, name);
    return { sub: res.sub, added: res.added, servers: store.get('servers', []) };
  });
  ipcMain.handle('subs:refresh', async (e, id) => {
    const res = await subs.refresh(id);
    return { added: res.added, servers: store.get('servers', []), subs: subs.list() };
  });
  ipcMain.handle('subs:refreshAll', async () => {
    const results = await subs.refreshAll();
    return { results, servers: store.get('servers', []), subs: subs.list() };
  });
  ipcMain.handle('subs:remove', (e, id) => {
    subs.remove(id);
    return { subs: subs.list(), servers: store.get('servers', []) };
  });
  ipcMain.handle('subs:autoUpdate', (e, { id, enabled }) => {
    subs.setAutoUpdate(id, enabled);
    return subs.list();
  });

  ipcMain.handle('connect', (e, id) => doConnect(id));
  ipcMain.handle('disconnect', () => doDisconnect());

  ipcMain.handle('settings:get', () => getSettings());
  /**
   * Persist settings and report which of them the live tunnel is NOT yet using.
   * Returns { settings, pendingReconnect } — the renderer offers to reconnect
   * when `pendingReconnect` is non-empty instead of pretending the change is live.
   */
  ipcMain.handle('settings:set', (e, partial) => {
    const next = Object.assign(getSettings(), partial);
    store.set('settings', next);
    // react to auto-update changes live
    if ('autoUpdateSubs' in partial || 'autoUpdateInterval' in partial) {
      if (next.autoUpdateSubs) subs.startAuto(next.autoUpdateInterval);
      else subs.stopAuto();
    }
    // turning the kill switch off should immediately restore internet
    if ('killSwitch' in partial && !next.killSwitch && killEngaged) {
      disarmKillSwitch().then(() => send('killswitch', { engaged: false }));
    }
    return { settings: next, pendingReconnect: pendingKeys() };
  });
  /**
   * Which geo codes in these rules the installed data files do not carry. The
   * core is the only authority on that (the codes change with every release),
   * so this asks it — see geoCheck.js. Called when routing rules are saved, so
   * a typo is caught there instead of taking the next connection down with it.
   */
  ipcMain.handle('routing:checkGeo', async (e, rules) => {
    const tokens = geoTokensOf(rules);
    if (!tokens.length) return { checked: true, bad: [] };
    return checkGeoTokens(tokens, (cfg) => xray.validate(cfg));
  });
  ipcMain.handle('settings:pending', () => pendingKeys());
  ipcMain.handle('settings:apply', () => reapplyConnection());

  // Resolve a ping/test target: a single server OR a named chain's entry hop.
  function resolveTarget(id) {
    const servers = store.get('servers', []);
    const server = servers.find(s => s.id === id);
    if (server) return { server, chain: null };
    const chain = getChains().find(c => c.id === id);
    if (chain) {
      const byId = {};
      for (const s of servers) byId[s.id] = s;
      const members = (chain.members || []).map(m => byId[m]).filter(Boolean);
      if (members.length) return { server: members[0], chain: members };
    }
    return { server: null, chain: null };
  }

  // TCP ping — to a server, or to a chain's first hop (its entry point).
  ipcMain.handle('ping:tcp', async (e, id) => {
    const { server } = resolveTarget(id);
    if (!server) return { ok: false, error: 'not found' };
    return tcpPing(server.address, server.port);
  });

  // Real delay: launch a throwaway xray on a free port, request through it.
  // Works for single servers and full chains (measures end-to-end latency).
  ipcMain.handle('ping:real', async (e, id) => {
    const { server, chain } = resolveTarget(id);
    if (!server) return { ok: false, error: 'not found' };
    if (!xray.binExists()) return { ok: false, error: 'xray binary missing' };
    let test;
    try {
      const port = await getFreePort();
      const cfg = buildTestConfig(chain && chain.length >= 2 ? chain : server, port);
      const plan = chain && chain.length >= 2 ? { mode: 'chain', chain } : { mode: 'single', server };
      test = await xray.startTest(cfg, testEngineFor(chooseEngine(plan, getSettings().defaultEngine)));
      const result = await httpThroughProxy(port, { host: 'cp.cloudflare.com', port: 80, path: '/' });
      return result;
    } catch (err) {
      return { ok: false, error: err.message };
    } finally {
      if (test) test.cleanup();
    }
  });

  // Upload delay: throwaway xray on a free port, push ~1.5MB through it and time
  // the flush. Surfaces configs with slow/broken UPLOAD (download can look fine).
  ipcMain.handle('ping:upload', async (e, id) => {
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
    } catch (err) {
      return { ok: false, error: err.message };
    } finally {
      if (test) test.cleanup();
    }
  });

  // IP info — direct or through the active proxy
  ipcMain.handle('ip:check', async (e, viaProxy) => {
    if (viaProxy) {
      const s = getSettings();
      return ipInfo(s.socksPort);
    }
    return ipInfo(null);
  });

  // window controls
  ipcMain.on('win:minimize', () => mainWindow.minimize());
  ipcMain.on('win:maximize', () => {
    if (!mainWindow) return;
    if (mainWindow.isMaximized()) mainWindow.unmaximize();
    else mainWindow.maximize();
  });
  ipcMain.on('win:hide', () => mainWindow.hide());
  ipcMain.on('win:close', () => { mainWindow.hide(); });
  ipcMain.on('app:quit', () => { isQuitting = true; app.quit(); });
  ipcMain.on('open:external', (e, url) => shell.openExternal(url));
  ipcMain.handle('open:dataDir', () => { shell.openPath(dataDir()); return dataDir(); });

  // runtime components (xray / tun2socks / wintun / geo files)
  ipcMain.handle('assets:status', () => assetStatus());
  ipcMain.handle('assets:download', async (e, component) => {
    try {
      const res = await downloader.download(component);
      // refresh stats binary + xray path in case a core was (re)installed.
      // binPath caches ONLY the official core — and holds the path the user
      // picked with "Locate xray…" — so downloading the fork must not clear it.
      if (component === 'xray' || component === 'xray-pattn') {
        if (component === 'xray') xray.binPath = null;
        xray.forgetVersions();
        stats.setBin(xray.anyBin());
      }
      return { ok: true, files: res.files, assets: assetStatus(), tunAvailable: makeTun(getSettings(), { quiet: true }).isAvailable(), xrayReady: xray.binExists() };
    } catch (err) {
      send('log', { line: 'Download failed (' + component + '): ' + err.message, level: 'error' });
      return { ok: false, error: err.message, assets: assetStatus() };
    }
  });

  ipcMain.handle('xray:locate', async () => {
    const res = await dialog.showOpenDialog(mainWindow, {
      title: 'Select xray executable',
      properties: ['openFile'],
      filters: [{ name: 'xray', extensions: process.platform === 'win32' ? ['exe'] : ['*'] }]
    });
    if (res.canceled || !res.filePaths[0]) return { ok: false };
    xray.binPath = res.filePaths[0];
    store.set('xrayPath', res.filePaths[0]);
    return { ok: true, path: res.filePaths[0], ready: xray.binExists() };
  });

  // core version string for an engine (e.g. "26.9.1")
  ipcMain.handle('xray:version', async (e, engineId) => {
    try { return { ok: true, version: await xray.version(engineId || 'xray') }; }
    catch (err) { return { ok: false, error: err.message }; }
  });

  // App version + GitHub "is there a newer release?" check.
  ipcMain.handle('app:checkUpdate', async () => {
    const current = app.getVersion();
    try {
      const rel = await getJSON(`https://api.github.com/repos/${GITHUB_REPO}/releases/latest`);
      const latest = String(rel.tag_name || '').replace(/^v/i, '').trim();
      if (!latest) return { ok: false, current, error: 'no release found' };
      return {
        ok: true,
        current,
        latest,
        hasUpdate: cmpVersion(latest, current) > 0,
        url: rel.html_url || `https://github.com/${GITHUB_REPO}/releases/latest`
      };
    } catch (e) {
      return { ok: false, current, error: e.message };
    }
  });

  // Running processes that currently have outbound TCP connections (for the
  // process-routing picker).
  ipcMain.handle('proc:list', async () => {
    try { return { ok: true, processes: await listProcesses() }; }
    catch (e) { return { ok: false, error: e.message, processes: [] }; }
  });

  // Clear the learned per-process IP cache (stale / shared IPs).
  ipcMain.handle('proc:clearCache', () => {
    store.set('procIpCache', {});
    return { ok: true };
  });

  // LAN sharing address (for the live IP:port display when the toggle is on).
  ipcMain.handle('net:lanInfo', () => {
    const s = getSettings();
    return { ip: lanIp(), all: lanCandidates(), socksPort: s.socksPort, httpPort: s.httpPort };
  });

  // The renderer saw the OS come back online — the fast path into the watcher
  // (polling alone would take a couple of ticks plus the debounce to notice).
  ipcMain.on('net:online', () => { if (netWatcher) netWatcher.poke('online'); });

  // Kill switch: manual disarm (restore internet) + status query.
  ipcMain.handle('killswitch:disarm', async () => { await disarmKillSwitch(); return { ok: true }; });
  ipcMain.handle('killswitch:status', () => ({ engaged: killEngaged }));

  // Delete the files the app downloaded into the writable bin (userData/bin).
  // Does NOT touch a user-located xray (store.xrayPath) or the bundled bin.
  ipcMain.handle('assets:remove', async () => {
    if (xray.running || (tun && tun.active)) {
      return { ok: false, error: 'disconnect first', assets: assetStatus() };
    }
    const dir = userBin();
    const names = ['xray', 'xray.exe', 'xray-pattn', 'xray-pattn.exe', 'tun2socks', 'tun2socks.exe', 'wintun.dll', 'geoip.dat', 'geosite.dat'];
    const removed = [];
    for (const n of names) {
      const p = path.join(dir, n);
      try { if (fs.existsSync(p)) { fs.rmSync(p, { force: true }); removed.push(n); } } catch {}
    }
    // re-resolve xray (falls back to a user-located path or bundled bin if any)
    xray.binPath = store.get('xrayPath', null);
    xray.forgetVersions();
    stats.setBin(xray.anyBin());
    send('log', { line: 'Removed downloaded files: ' + (removed.join(', ') || '(none)'), level: 'info' });
    return { ok: true, removed, assets: assetStatus(), xrayReady: xray.binExists(), tunAvailable: makeTun(getSettings(), { quiet: true }).isAvailable() };
  });
}

/** Minimal redirect-following JSON GET (GitHub API). */
function getJSON(url, depth = 0) {
  return new Promise((resolve, reject) => {
    if (depth > 6) return reject(new Error('too many redirects'));
    https.get(url, { headers: { 'User-Agent': 'IRNetFree' } }, (res) => {
      if (res.statusCode >= 300 && res.headers.location) {
        res.resume();
        return resolve(getJSON(res.headers.location, depth + 1));
      }
      if (res.statusCode !== 200) { res.resume(); return reject(new Error('HTTP ' + res.statusCode)); }
      let body = '';
      res.on('data', (c) => (body += c));
      res.on('end', () => { try { resolve(JSON.parse(body)); } catch (e) { reject(e); } });
    }).on('error', reject);
  });
}

/** Compare dotted versions: 1 if a>b, -1 if a<b, 0 if equal. */
function cmpVersion(a, b) {
  const pa = String(a).split('.').map(n => parseInt(n, 10) || 0);
  const pb = String(b).split('.').map(n => parseInt(n, 10) || 0);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const x = pa[i] || 0, y = pb[i] || 0;
    if (x > y) return 1;
    if (x < y) return -1;
  }
  return 0;
}

/* ----------------------------- lifecycle ----------------------------- */
app.whenReady().then(() => {
  const dir = dataDir();
  store = new Store(path.join(dir, 'store.json'), {
    servers: [], subscriptions: [], settings: DEFAULT_SETTINGS, activeServerId: null, xrayPath: null
  }, {
    // Losing the store means losing every saved server — never let that pass
    // unnoticed. A load error also reaches the renderer through app:init, since
    // the window does not exist yet at this point.
    onError: (kind, info) => {
      const line = kind === 'load'
        ? `Saved data could not be read: ${info.reason}` +
          (info.recovered ? ' — recovered from the unsaved copy' : '') +
          (info.backup ? ` (the unreadable file was kept at ${info.backup})` : '')
        : `Could not write saved data to disk: ${info.reason}`;
      send('log', { line, level: 'error' });
      send('store-error', Object.assign({ kind }, info));
    }
  });

  migrateServers();
  migrateSettingsStore();

  const ubin = userBin();

  xray = new XrayManager({
    binPath: store.get('xrayPath', null),
    dataDir: dir,
    extraBinDirs: [ubin],
    onLog: (line, level) => { send('log', { line, level }); healCertPin(line); },
    onStatus: (state, info) => {
      // The proc-routing watcher restarts xray in place; don't surface the
      // old instance's 'stopped' as a disconnect.
      if (xrayReloading && state === 'stopped') return;
      // Unexpected drop (xray died without us asking) while we believe we're
      // connected → engage the kill switch if enabled.
      if (state === 'stopped' && !userDisconnecting && store.get('activeServerId', null)) {
        updateOverlay('off');
        if (getSettings().killSwitch) {
          armKillSwitch().then((r) => {
            send('killswitch', { engaged: !!(r && r.ok), error: r && r.error });
            if (r && r.ok) send('log', { line: 'Kill switch engaged — internet blocked (VPN dropped unexpectedly)', level: 'warn' });
            else if (process.platform === 'win32') send('log', { line: 'Kill switch failed (run as admin): ' + (r && r.error), level: 'error' });
          });
        }
      }
      send('xray-status', { state, info });
    }
  });

  subs = new SubscriptionManager({
    getSubs: () => store.get('subscriptions', []),
    setSubs: (arr) => store.set('subscriptions', arr),
    getServers: () => store.get('servers', []),
    setServers: (arr) => store.set('servers', arr),
    onUpdate: (sub, info) => send('subs-updated', { sub, info, servers: store.get('servers', []), subs: store.get('subscriptions', []) })
  });

  // A placeholder until the first connect picks the backend for real (see
  // makeTun / doConnect) — so quit and the exit hook always have an instance.
  tun = makeTun(getSettings(), { quiet: true });

  stats = new StatsPoller({
    binPath: xray.anyBin(),
    apiPort: getSettings().apiPort,
    onStats: (s) => send('stats', s),
    onRaw: (vars) => reportSilentTunnels(vars)
  });

  downloader = new Downloader({
    destDir: ubin,
    onLog: (line, level) => send('log', { line, level }),
    onProgress: (component, pct) => send('asset-progress', { component, pct })
  });

  // Clear any leftover kill-switch firewall block from a previous crash so the
  // user is never permanently blocked.
  disarmKillSwitch().catch(() => {});

  // The leak guard and its crash repair. A `tun-state.json` left in userData
  // means the last session died with every physical adapter still pointing at a
  // tunnel that is gone — the machine has no working DNS until the originals go
  // back — and the tunnel process it started may still be running with its
  // routes in place. Deliberately NOT awaited: on macOS the restore needs a
  // password prompt and the window must not sit behind it. Every operation on
  // the state file is serialized inside the guard, so a connect that starts
  // while the repair is still running cannot lose its own record.
  leakGuard = new LeakGuard({
    userData: dir,
    onLog: (line, level) => send('log', { line, level }),
    run: tunPlatform.run,
    runScriptPrivileged: tunPlatform.runScriptPrivileged,
    platform: process.platform
  });
  leakGuard.repairAtLaunch().catch((e) => send('log', { line: 'Leak guard repair failed: ' + e.message, level: 'error' }));

  registerIpc();
  createWindow();
  createTray();

  // the OS flipped light/dark — the renderer only reacts when theme is 'system'
  nativeTheme.on('updated', () => send('system-theme', { dark: nativeTheme.shouldUseDarkColors }));

  // waking from sleep is the other way the network changes under us
  try {
    const { powerMonitor } = require('electron');
    powerMonitor.on('resume', () => { if (netWatcher) netWatcher.poke('resume'); });
  } catch {}

  mainWindow.once('ready-to-show', () => updateOverlay('off'));

  // kick off auto-update for subscriptions if enabled
  const st = getSettings();
  if (st.autoUpdateSubs) subs.startAuto(st.autoUpdateInterval);

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('before-quit', async (e) => {
  if (!isQuitting) return;
  userDisconnecting = true;   // quitting on purpose — don't trip the kill switch
  try { stopNetWatcher(); } catch {}
  try { if (stats) stats.stop(); } catch {}
  try { if (leakGuard) await leakGuard.release(); } catch {}   // adapters first, then the tunnel
  await stopAllTuns();   // every instance a connect started, not just the last
  try { await setSystemProxy(false, {}); } catch {}
  try { await removeLanFirewall(); } catch {}
  try { await disarmKillSwitch(); } catch {}
  try { if (xray) await xray.stop(); } catch {}
});

app.on('window-all-closed', () => {
  // keep running in tray; quit only on explicit request
});

// Ensure system proxy + TUN routes + kill-switch block are cleared on a hard
// exit (Windows only) — otherwise a kill-switch block would outlive the app and
// leave the machine with no internet.
process.on('exit', () => {
  // The DNS override outlives the app if nobody puts it back, so it goes before
  // the win32 gate below: on macOS (when we are already root) this is the last
  // chance to restore it without a password prompt nobody can answer here.
  try { if (leakGuard) leakGuard.releaseSync(); } catch {}
  if (process.platform !== 'win32') return;
  try { require('child_process').execFileSync(
    'reg', ['add', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings', '/v', 'ProxyEnable', '/t', 'REG_DWORD', '/d', '0', '/f'],
    { windowsHide: true }); } catch {}
  cleanupAllTunsSync();   // every backend a connect started, either kind
  try { require('child_process').execFileSync('netsh',
    ['advfirewall', 'firewall', 'delete', 'rule', `name=${KILL_RULE}`], { windowsHide: true }); } catch {}
});
