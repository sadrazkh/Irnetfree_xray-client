'use strict';
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('api', {
  // init / data
  init: () => ipcRenderer.invoke('app:init'),

  // servers
  importServers: (text) => ipcRenderer.invoke('servers:import', text),
  addServer: (link) => ipcRenderer.invoke('servers:add', link),
  addWireguard: (fields) => ipcRenderer.invoke('servers:addWireguard', fields),
  updateServer: (id, fields) => ipcRenderer.invoke('servers:update', { id, fields }),
  deleteServer: (id) => ipcRenderer.invoke('servers:delete', id),
  clearServers: () => ipcRenderer.invoke('servers:clear'),
  listServers: () => ipcRenderer.invoke('servers:list'),

  // proxy chain (legacy single chain)
  getChain: () => ipcRenderer.invoke('chain:get'),
  setChain: (ids) => ipcRenderer.invoke('chain:set', ids),

  // named proxy chains (first-class configs)
  listChains: () => ipcRenderer.invoke('chains:list'),
  setChains: (chains) => ipcRenderer.invoke('chains:set', chains),

  // subscriptions
  listSubs: () => ipcRenderer.invoke('subs:list'),
  addSub: (url, name) => ipcRenderer.invoke('subs:add', { url, name }),
  refreshSub: (id) => ipcRenderer.invoke('subs:refresh', id),
  refreshAllSubs: () => ipcRenderer.invoke('subs:refreshAll'),
  removeSub: (id) => ipcRenderer.invoke('subs:remove', id),
  setSubAutoUpdate: (id, enabled) => ipcRenderer.invoke('subs:autoUpdate', { id, enabled }),

  // connection
  connect: (id) => ipcRenderer.invoke('connect', id),
  disconnect: () => ipcRenderer.invoke('disconnect'),

  // settings
  getSettings: () => ipcRenderer.invoke('settings:get'),
  setSettings: (partial) => ipcRenderer.invoke('settings:set', partial),

  // diagnostics
  pingTcp: (id) => ipcRenderer.invoke('ping:tcp', id),
  pingReal: (id) => ipcRenderer.invoke('ping:real', id),
  checkIp: (viaProxy) => ipcRenderer.invoke('ip:check', viaProxy),

  // xray binary
  locateXray: () => ipcRenderer.invoke('xray:locate'),
  openDataDir: () => ipcRenderer.invoke('open:dataDir'),
  xrayVersion: () => ipcRenderer.invoke('xray:version'),

  // app version / update check
  checkUpdate: () => ipcRenderer.invoke('app:checkUpdate'),

  // process-based routing
  listProcesses: () => ipcRenderer.invoke('proc:list'),
  clearProcCache: () => ipcRenderer.invoke('proc:clearCache'),

  // relaunch elevated (Windows) for TUN mode
  relaunchAdmin: () => ipcRenderer.invoke('app:relaunchAdmin'),

  // runtime components (download / integrate / update / remove)
  assetsStatus: () => ipcRenderer.invoke('assets:status'),
  downloadAsset: (component) => ipcRenderer.invoke('assets:download', component),
  removeAssets: () => ipcRenderer.invoke('assets:remove'),

  // LAN sharing info + kill switch
  lanInfo: () => ipcRenderer.invoke('net:lanInfo'),
  disarmKillSwitch: () => ipcRenderer.invoke('killswitch:disarm'),
  killSwitchStatus: () => ipcRenderer.invoke('killswitch:status'),

  // window
  minimize: () => ipcRenderer.send('win:minimize'),
  maximize: () => ipcRenderer.send('win:maximize'),
  hide: () => ipcRenderer.send('win:hide'),
  close: () => ipcRenderer.send('win:close'),
  quit: () => ipcRenderer.send('app:quit'),
  openExternal: (url) => ipcRenderer.send('open:external', url),

  // events
  onLog: (cb) => ipcRenderer.on('log', (e, d) => cb(d)),
  onStatus: (cb) => ipcRenderer.on('status', (e, d) => cb(d)),
  onXrayStatus: (cb) => ipcRenderer.on('xray-status', (e, d) => cb(d)),
  onStats: (cb) => ipcRenderer.on('stats', (e, d) => cb(d)),
  onSubsUpdated: (cb) => ipcRenderer.on('subs-updated', (e, d) => cb(d)),
  onAssetProgress: (cb) => ipcRenderer.on('asset-progress', (e, d) => cb(d)),
  onKillSwitch: (cb) => ipcRenderer.on('killswitch', (e, d) => cb(d))
});
