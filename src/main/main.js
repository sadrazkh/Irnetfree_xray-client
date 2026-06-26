'use strict';
const { app, BrowserWindow, ipcMain, Tray, Menu, nativeImage, shell, dialog } = require('electron');
const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');

const { parseMany, parseLink, makeWireguardServer, applyServerEdits } = require('./parser');
const { buildConfig, buildTestConfig } = require('./configBuilder');
const { XrayManager, getFreePort } = require('./xrayManager');
const { setSystemProxy } = require('./sysproxy');
const { tcpPing, httpThroughProxy, ipInfo } = require('./netutils');
const { Store } = require('./store');
const { SubscriptionManager } = require('./subscription');
const { TunManager } = require('./tunManager');
const { StatsPoller } = require('./stats');
const { Downloader } = require('./downloader');

let mainWindow = null;
let tray = null;
let xray = null;
let store = null;
let subs = null;
let tun = null;
let stats = null;
let downloader = null;
let userBinDir = null;
let isQuitting = false;

const DEFAULT_SETTINGS = {
  socksPort: 10808,
  httpPort: 10809,
  allowLan: false,
  routingMode: 'global',
  blockAds: true,
  enableSniffing: true,
  dns: ['1.1.1.1', '8.8.8.8'],
  logLevel: 'warning',
  apiPort: 10085,
  systemProxy: true,
  tunMode: false,
  autoUpdateSubs: true,
  autoUpdateInterval: 60,
  customRules: [],
  // advanced (graphical) routing — per-rule outbound selection
  advancedRouting: false,
  routeRules: [],      // [{ id, type:'ip'|'domain'|'port', value, target }]
  routeDefault: '',    // fallback target (server id | 'chain' | 'direct' | 'block')
  theme: 'dark'
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
  const dirs = [userBin(), bundledBinDir()];
  const has = (name) => dirs.some(d => fs.existsSync(path.join(d, name)));
  const win = process.platform === 'win32';
  return {
    xray: xray ? xray.binExists() : has(win ? 'xray.exe' : 'xray'),
    tun2socks: has(win ? 'tun2socks.exe' : 'tun2socks'),
    wintun: win ? has('wintun.dll') : true,
    geoip: has('geoip.dat'),
    geosite: has('geosite.dat'),
    platform: process.platform
  };
}

function send(channel, payload) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send(channel, payload);
  }
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
async function doConnect(serverId) {
  const servers = store.get('servers', []);
  const settings = getSettings();
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

  // Resolve the connection plan + the addresses the machine dials *directly*
  // (those must be bypassed under TUN so the tunnel doesn't loop on itself).
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

  if (serverId === '__advanced__') {
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

  // Are the geo databases installed? If not, geosite:/geoip: rules would make
  // xray refuse to start — buildConfig drops them and we warn the user.
  const geoSt = assetStatus();
  const geoAssets = !!(geoSt.geoip && geoSt.geosite);
  let geoWarn = null;
  const usesGeo =
    (plan.mode === 'advanced' &&
      ((settings.routeRules || []).some(r => r && /^(geoip|geosite):/i.test(String(r.value || ''))))) ||
    (plan.mode !== 'advanced' &&
      (settings.routingMode === 'bypass-ir' || settings.routingMode === 'bypass-cn' ||
        (settings.blockAds && plan.mode !== 'advanced')));
  if (!geoAssets && usesGeo) {
    geoWarn = settings.lang === 'en'
      ? 'Geo files (geoip/geosite) are missing — geo-based rules were skipped. Download them under Settings → Required files.'
      : 'فایل‌های geo (geoip/geosite) موجود نیست — قوانین مبتنی بر geo نادیده گرفته شد. از تنظیمات → فایل‌های موردنیاز دانلودشان کن.';
  }

  const config = buildConfig(Object.assign({}, plan), Object.assign({}, settings, { geoAssets }));

  send('status', { state: 'connecting', serverId });

  // Validate first so chain / advanced-routing mistakes surface as a clear
  // message instead of a config that crashes xray right after "connected".
  const check = await xray.validate(config);
  if (!check.ok) {
    send('log', { line: 'Config rejected by xray: ' + check.error, level: 'error' });
    throw new Error((settings.lang === 'en' ? 'Config error: ' : 'خطای کانفیگ: ') + check.error);
  }

  await xray.start(config);

  store.set('activeServerId', serverId);

  if (settings.systemProxy) {
    try {
      await setSystemProxy(true, { host: '127.0.0.1', httpPort: settings.httpPort, socksPort: settings.socksPort });
      send('log', { line: 'System proxy enabled', level: 'info' });
    } catch (e) {
      send('log', { line: 'System proxy failed: ' + e.message, level: 'error' });
    }
  }

  updateTray(true, label);

  // TUN mode (system-wide tunnel via tun2socks). Requires admin + tun2socks.exe.
  let tunError = null;
  if (settings.tunMode) {
    if (!tun.isAvailable()) {
      tunError = settings.lang === 'en'
        ? 'TUN needs tun2socks + wintun in the bin folder.'
        : 'حالت TUN به فایل‌های tun2socks و wintun در پوشه bin نیاز دارد.';
      send('log', { line: 'TUN requested but tun2socks/wintun not found — connected proxy-only', level: 'error' });
    } else {
      try {
        tun.lang = settings.lang || 'fa';
        await tun.start(settings.socksPort, entryAddrs, settings.dns);
        send('log', { line: 'TUN mode active (whole system)', level: 'info' });
      } catch (e) {
        tunError = e.message;
        send('log', { line: 'TUN start failed: ' + e.message, level: 'error' });
      }
    }
  }

  // Start live traffic stats
  stats.setBin(xray.resolveBin());
  stats.apiPort = settings.apiPort;
  stats.start(1000);

  send('status', { state: 'connected', serverId, server: byId(serverId) || null, label, tun: tun.active, tunError, geoWarn });
  return true;
}

async function doDisconnect() {
  if (stats) stats.stop();
  try { await tun.stop(); } catch {}
  try { await setSystemProxy(false, {}); } catch {}
  if (xray) await xray.stop();
  store.set('activeServerId', null);
  updateTray(false);
  send('status', { state: 'disconnected' });
}

function updateTray(connected, name) {
  if (!tray) return;
  tray.setToolTip(connected ? `IRNetFree — ${name}` : 'IRNetFree — disconnected');
}

function getSettings() {
  return Object.assign({}, DEFAULT_SETTINGS, store.get('settings', {}));
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
    xrayReady: xray.binExists(),
    tunAvailable: tun.isAvailable(),
    elevated: tun.isElevated(),
    assets: assetStatus(),
    platform: process.platform,
    version: app.getVersion()
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

  // Relaunch the app elevated (Windows) so TUN mode can configure routes.
  ipcMain.handle('app:relaunchAdmin', () => {
    if (process.platform !== 'win32') return { ok: false, error: 'only on Windows' };
    if (tun.isElevated()) return { ok: false, error: 'already elevated' };
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
  ipcMain.handle('settings:set', (e, partial) => {
    const next = Object.assign(getSettings(), partial);
    store.set('settings', next);
    // react to auto-update changes live
    if ('autoUpdateSubs' in partial || 'autoUpdateInterval' in partial) {
      if (next.autoUpdateSubs) subs.startAuto(next.autoUpdateInterval);
      else subs.stopAuto();
    }
    return next;
  });

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
      test = await xray.startTest(cfg);
      const result = await httpThroughProxy(port, { host: 'cp.cloudflare.com', port: 80, path: '/' });
      return result;
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
      // refresh stats binary + xray path in case xray was (re)installed
      if (component === 'xray') {
        xray.binPath = null;
        stats.setBin(xray.resolveBin());
      }
      return { ok: true, files: res.files, assets: assetStatus(), tunAvailable: tun.isAvailable(), xrayReady: xray.binExists() };
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
}

/* ----------------------------- lifecycle ----------------------------- */
app.whenReady().then(() => {
  const dir = dataDir();
  store = new Store(path.join(dir, 'store.json'), {
    servers: [], subscriptions: [], settings: DEFAULT_SETTINGS, activeServerId: null, xrayPath: null
  });

  const ubin = userBin();

  xray = new XrayManager({
    binPath: store.get('xrayPath', null),
    dataDir: dir,
    extraBinDirs: [ubin],
    onLog: (line, level) => send('log', { line, level }),
    onStatus: (state, info) => send('xray-status', { state, info })
  });

  subs = new SubscriptionManager({
    getSubs: () => store.get('subscriptions', []),
    setSubs: (arr) => store.set('subscriptions', arr),
    getServers: () => store.get('servers', []),
    setServers: (arr) => store.set('servers', arr),
    onUpdate: (sub, info) => send('subs-updated', { sub, info, servers: store.get('servers', []), subs: store.get('subscriptions', []) })
  });

  tun = new TunManager({
    binDir: bundledBinDir(),
    extraDirs: [ubin],
    onLog: (line, level) => send('log', { line, level })
  });

  stats = new StatsPoller({
    binPath: xray.resolveBin(),
    apiPort: getSettings().apiPort,
    onStats: (s) => send('stats', s)
  });

  downloader = new Downloader({
    destDir: ubin,
    onLog: (line, level) => send('log', { line, level }),
    onProgress: (component, pct) => send('asset-progress', { component, pct })
  });

  registerIpc();
  createWindow();
  createTray();

  // kick off auto-update for subscriptions if enabled
  const st = getSettings();
  if (st.autoUpdateSubs) subs.startAuto(st.autoUpdateInterval);

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('before-quit', async (e) => {
  if (!isQuitting) return;
  try { if (stats) stats.stop(); } catch {}
  try { if (tun) await tun.stop(); } catch {}
  try { await setSystemProxy(false, {}); } catch {}
  try { if (xray) await xray.stop(); } catch {}
});

app.on('window-all-closed', () => {
  // keep running in tray; quit only on explicit request
});

// Ensure system proxy + TUN routes are cleared on a hard exit (Windows only).
process.on('exit', () => {
  if (process.platform !== 'win32') return;
  try { require('child_process').execFileSync(
    'reg', ['add', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings', '/v', 'ProxyEnable', '/t', 'REG_DWORD', '/d', '0', '/f'],
    { windowsHide: true }); } catch {}
  try { if (tun) tun.cleanupSync(); } catch {}
});
