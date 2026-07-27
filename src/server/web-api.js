'use strict';
/**
 * Browser-side replacement for the Electron preload bridge. Exposes the SAME
 * `window.api` surface the renderer expects, but backed by HTTP (/rpc) + SSE
 * (/events) instead of ipcRenderer. Loaded before i18n.js/app.js.
 */
(function () {
  // token (if any) travels in the page URL: http://host:port/?token=XXX
  const TOKEN = new URLSearchParams(location.search).get('token') || '';
  const authQS = TOKEN ? ('?token=' + encodeURIComponent(TOKEN)) : '';

  async function invoke(channel, arg) {
    const res = await fetch('/rpc' + authQS, {
      method: 'POST',
      headers: Object.assign({ 'Content-Type': 'application/json' }, TOKEN ? { 'x-irnetfree-token': TOKEN } : {}),
      body: JSON.stringify({ channel, arg })
    });
    let data;
    try { data = await res.json(); } catch { throw new Error('bad response (' + res.status + ')'); }
    if (data && data.error) throw new Error(data.error);
    return data ? data.result : null;
  }
  // fire-and-forget (window controls etc. — no-ops on the server)
  const sendOnly = (channel, arg) => { invoke(channel, arg).catch(() => {}); };

  /* ----------------------------- events (SSE) ----------------------------- */
  const handlers = {};                 // channel -> [cb, …]
  const on = (channel, cb) => { (handlers[channel] = handlers[channel] || []).push(cb); };

  function connectEvents() {
    const es = new EventSource('/events' + authQS);
    es.onmessage = (ev) => {
      let msg; try { msg = JSON.parse(ev.data); } catch { return; }
      const cbs = handlers[msg.channel];
      if (cbs) for (const cb of cbs) { try { cb(msg.payload); } catch (e) { console.error(e); } }
    };
    es.onerror = () => { /* EventSource auto-reconnects */ };
  }
  if (typeof EventSource !== 'undefined') connectEvents();

  window.api = {
    // init / data
    init: () => invoke('app:init'),

    // servers
    importServers: (text) => invoke('servers:import', text),
    addServer: (link) => invoke('servers:add', link),
    addWireguard: (fields) => invoke('servers:addWireguard', fields),
    addProxy: (fields) => invoke('servers:addProxy', fields),
    updateServer: (id, fields) => invoke('servers:update', { id, fields }),
    deleteServer: (id) => invoke('servers:delete', id),
    clearServers: () => invoke('servers:clear'),
    listServers: () => invoke('servers:list'),

    // chains
    getChain: () => invoke('chain:get'),
    setChain: (ids) => invoke('chain:set', ids),
    listChains: () => invoke('chains:list'),
    setChains: (chains) => invoke('chains:set', chains),

    // proxy pool
    listPool: () => invoke('pool:list'),
    setPool: (entries) => invoke('pool:set', entries),

    // subscriptions
    listSubs: () => invoke('subs:list'),
    addSub: (url, name) => invoke('subs:add', { url, name }),
    refreshSub: (id) => invoke('subs:refresh', id),
    refreshAllSubs: () => invoke('subs:refreshAll'),
    removeSub: (id) => invoke('subs:remove', id),
    setSubAutoUpdate: (id, enabled) => invoke('subs:autoUpdate', { id, enabled }),

    // connection
    connect: (id) => invoke('connect', id),
    disconnect: () => invoke('disconnect'),

    // settings
    getSettings: () => invoke('settings:get'),
    setSettings: (partial) => invoke('settings:set', partial),
    pendingReconnect: () => invoke('settings:pending'),
    applySettings: () => invoke('settings:apply'),

    // diagnostics
    pingTcp: (id) => invoke('ping:tcp', id),
    pingReal: (id) => invoke('ping:real', id),
    pingUpload: (id) => invoke('ping:upload', id),
    checkIp: (viaProxy) => invoke('ip:check', viaProxy),

    // xray binary / assets
    locateXray: () => invoke('xray:locate'),
    openDataDir: () => invoke('open:dataDir'),
    xrayVersion: () => invoke('xray:version'),
    checkUpdate: () => invoke('app:checkUpdate'),
    assetsStatus: () => invoke('assets:status'),
    downloadAsset: (component) => invoke('assets:download', component),
    removeAssets: () => invoke('assets:remove'),

    // process routing
    listProcesses: () => invoke('proc:list'),
    clearProcCache: () => invoke('proc:clearCache'),

    // elevated relaunch (desktop-only)
    relaunchAdmin: () => invoke('app:relaunchAdmin'),

    // LAN + kill switch
    lanInfo: () => invoke('net:lanInfo'),
    disarmKillSwitch: () => invoke('killswitch:disarm'),
    killSwitchStatus: () => invoke('killswitch:status'),

    // window controls — no-ops on the server, kept for API parity
    minimize: () => sendOnly('win:minimize'),
    maximize: () => sendOnly('win:maximize'),
    hide: () => sendOnly('win:hide'),
    close: () => sendOnly('win:close'),
    quit: () => sendOnly('app:quit'),
    openExternal: (url) => { try { window.open(url, '_blank', 'noopener'); } catch {} },

    // events
    onLog: (cb) => on('log', cb),
    onStatus: (cb) => on('status', cb),
    onXrayStatus: (cb) => on('xray-status', cb),
    onStats: (cb) => on('stats', cb),
    onSubsUpdated: (cb) => on('subs-updated', cb),
    onAssetProgress: (cb) => on('asset-progress', cb),
    onKillSwitch: (cb) => on('killswitch', cb)
  };
})();
