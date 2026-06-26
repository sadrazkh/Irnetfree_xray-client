'use strict';
/* Renderer logic — talks to main via window.api (preload bridge). */

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));
const t = (k) => window.i18n.t(k);

const state = {
  servers: [],
  subscriptions: [],
  settings: {},
  activeServerId: null,   // currently connected server
  selectedServerId: null, // chosen in the picker (target for connect)
  connected: false,
  connecting: false,
  tunAvailable: false,
  elevated: false,         // running as Administrator (Windows) — needed for TUN
  assets: {},
  chain: [],               // legacy: ordered server ids (first hop → exit)
  chains: [],              // [{ id, name, members:[serverId,...] }] — first-class chains
  editingId: null,         // server being edited in the modal
  pings: {} // id -> { tcp, real }
};

/* ----------------------------- helpers ----------------------------- */
function toast(msg, kind = '') {
  const el = $('#toast');
  el.textContent = msg;
  el.className = 'toast show ' + kind;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { el.className = 'toast'; }, 2600);
}

function pingClass(ms) {
  if (ms < 0) return 'ping-bad';
  if (ms < 200) return 'ping-good';
  if (ms < 600) return 'ping-mid';
  return 'ping-bad';
}

function fmtBytes(n) {
  n = Number(n) || 0;
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return (i === 0 ? n : n.toFixed(1)) + ' ' + units[i];
}
function fmtSpeed(n) { return fmtBytes(n) + '/s'; }

function timeAgo(ts) {
  if (!ts) return t('t.never');
  const s = Math.floor((Date.now() - ts) / 1000);
  if (s < 60) return s + ' ' + t('t.secAgo');
  if (s < 3600) return Math.floor(s / 60) + ' ' + t('t.minAgo');
  if (s < 86400) return Math.floor(s / 3600) + ' ' + t('t.hrAgo');
  return Math.floor(s / 86400) + ' ' + t('t.dayAgo');
}

/* country code (ISO-2) -> flag emoji */
function flagEmoji(cc) {
  if (!cc || cc.length !== 2) return '🏳️';
  const A = 0x1f1e6;
  return String.fromCodePoint(
    A + cc.toUpperCase().charCodeAt(0) - 65,
    A + cc.toUpperCase().charCodeAt(1) - 65
  );
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

/* ----------------------------- navigation ----------------------------- */
$$('.nav-item').forEach(btn => {
  btn.addEventListener('click', () => {
    $$('.nav-item').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    const view = btn.dataset.view;
    $$('.view').forEach(v => v.classList.remove('active'));
    $('#view-' + view).classList.add('active');
  });
});

/* window controls */
$('#btnMin').onclick = () => window.api.minimize();
$('#btnHide').onclick = () => window.api.hide();
$('#btnClose').onclick = () => window.api.close();

/* language toggle */
$('#btnLang').onclick = () => setLang(window.i18n.lang === 'fa' ? 'en' : 'fa');
$('#langSelect').onchange = () => setLang($('#langSelect').value);

function setLang(lang) {
  window.i18n.applyI18n(lang);
  $('#btnLang').textContent = lang === 'fa' ? 'EN' : 'فا';
  $('#langSelect').value = lang;
  // re-render dynamic content so it picks up the new language
  renderServers();
  renderPicker();
  renderSubs();
  renderComponents();
  renderChains();
  updateXrayStatus(state.assets.xray);
  updateTunStatus();
  setModeWidget();
  refreshConnLabels();
  saveSettings({ lang });
}

/* ----------------------------- init ----------------------------- */
async function init() {
  const data = await window.api.init();
  state.servers = data.servers || [];
  state.subscriptions = data.subscriptions || [];
  state.settings = data.settings || {};
  state.activeServerId = data.activeServerId || null;
  state.selectedServerId = data.activeServerId || (state.servers[0] && state.servers[0].id) || null;
  state.tunAvailable = !!data.tunAvailable;
  state.elevated = !!data.elevated;
  state.assets = data.assets || {};
  state.chain = (data.chain || []).filter(id => state.servers.some(s => s.id === id));
  state.chains = (data.chains || []).map(c => ({
    id: c.id, name: c.name || 'Chain',
    members: (c.members || []).filter(id => state.servers.some(s => s.id === id))
  }));

  window.i18n.applyI18n(state.settings.lang || 'fa');
  $('#btnLang').textContent = (state.settings.lang || 'fa') === 'fa' ? 'EN' : 'فا';

  applySettingsToUI();
  renderServers();
  renderPicker();
  renderSubs();
  renderComponents();
  renderChains();
  renderAdvanced();
  updateXrayStatus(data.xrayReady);
  updateTunStatus();
  setModeWidget();
}

/* ----------------------------- settings UI ----------------------------- */
function applySettingsToUI() {
  const s = state.settings;
  $('#socksPort').value = s.socksPort ?? 10808;
  $('#httpPort').value = s.httpPort ?? 10809;
  $('#dnsInput').value = (s.dns || ['1.1.1.1', '8.8.8.8']).join(',');
  $('#logLevel').value = s.logLevel || 'warning';
  $('#langSelect').value = s.lang || 'fa';
  $('#optSysProxy').checked = !!s.systemProxy;
  $('#optTun').checked = !!s.tunMode;
  $('#optAllowLan').checked = !!s.allowLan;
  $('#optBlockAds').checked = !!s.blockAds;
  $('#optSniff').checked = s.enableSniffing !== false;
  $('#optAutoUpdate').checked = s.autoUpdateSubs !== false;
  $('#autoInterval').value = s.autoUpdateInterval || 60;
  $('#customRules').value = customRulesToText(s.customRules || []);

  $$('#routingSeg .seg-btn').forEach(b => b.classList.toggle('active', b.dataset.mode === (s.routingMode || 'global')));
}

function customRulesToText(rules) {
  return rules.map(r => {
    const kind = r.domain ? 'domain' : r.ip ? 'ip' : 'port';
    const val = r.domain || r.ip || r.port;
    return `${kind}, ${Array.isArray(val) ? val.join('|') : val}, ${r.outboundTag}`;
  }).join('\n');
}
function textToCustomRules(text) {
  const out = [];
  for (const line of text.split(/\r?\n/)) {
    const parts = line.split(',').map(s => s.trim());
    if (parts.length < 3) continue;
    const [kind, val, tag] = parts;
    const rule = { outboundTag: tag };
    if (kind === 'domain') rule.domain = val.split('|');
    else if (kind === 'ip') rule.ip = val.split('|');
    else if (kind === 'port') rule.port = val;
    else continue;
    out.push(rule);
  }
  return out;
}

async function saveSettings(extra = {}) {
  const dns = $('#dnsInput').value.split(',').map(s => s.trim()).filter(Boolean);
  const partial = Object.assign({
    socksPort: parseInt($('#socksPort').value, 10) || 10808,
    httpPort: parseInt($('#httpPort').value, 10) || 10809,
    dns,
    logLevel: $('#logLevel').value,
    systemProxy: $('#optSysProxy').checked,
    tunMode: $('#optTun').checked,
    allowLan: $('#optAllowLan').checked,
    blockAds: $('#optBlockAds').checked,
    enableSniffing: $('#optSniff').checked
  }, extra);
  state.settings = await window.api.setSettings(partial);
}

$('#btnSaveSettings').onclick = async () => {
  await saveSettings();
  $('#savedHint').textContent = t('saved');
  setTimeout(() => ($('#savedHint').textContent = ''), 1800);
  toast(t('t.settingsSaved'), 'ok');
};

/* routing */
$$('#routingSeg .seg-btn').forEach(btn => {
  btn.onclick = async () => {
    $$('#routingSeg .seg-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    await saveSettings({ routingMode: btn.dataset.mode });
    toast(t('t.routingMode') + ': ' + btn.textContent, 'ok');
  };
});
$('#optBlockAds').onchange = () => saveSettings();
$('#optSniff').onchange = () => saveSettings();
$('#btnSaveRules').onclick = async () => {
  const rules = textToCustomRules($('#customRules').value);
  await saveSettings({ customRules: rules });
  toast(t('t.rulesSaved') + ' (' + rules.length + ')', 'ok');
};

/* ----------------------------- servers ----------------------------- */
function pingLabel(id) {
  const p = state.pings[id] || {};
  const tcp = p.tcp;
  if (!tcp) return { txt: '—', cls: '' };
  return { txt: tcp.ok ? tcp.ms + 'ms' : t('t.error'), cls: pingClass(tcp.ok ? tcp.ms : -1) };
}

function renderServers() {
  const list = $('#serverList');
  list.innerHTML = '';
  $('#serverEmpty').hidden = state.servers.length > 0;

  for (const s of state.servers) {
    const card = document.createElement('div');
    const isActive = s.id === state.activeServerId && state.connected;
    const isSel = s.id === state.selectedServerId;
    card.className = 'server-card' + (isActive ? ' active' : '') + (isSel ? ' selected' : '');

    const pl = pingLabel(s.id);
    const selBadge = isSel ? `<span class="sel-badge">✓ ${escapeHtml(t('srv.selected'))}</span>` : '';

    card.innerHTML = `
      <span class="proto-badge proto-${s.protocol}">${s.protocol}</span>
      <div class="srv-info">
        <div class="srv-name">${escapeHtml(s.name)} ${selBadge}</div>
        <div class="srv-addr">${escapeHtml(s.address)}:${s.port}</div>
      </div>
      <div class="srv-ping ${pl.cls}" data-ping="${s.id}">${pl.txt}</div>
      <div class="srv-actions">
        <button class="icon-btn ping-srv" data-i18n-title="btn.quickPing" title="ping">⚡</button>
        <button class="icon-btn edit-srv" data-i18n-title="btn.edit" title="edit">✎</button>
        <button class="icon-btn connect-srv" title="▶">▶</button>
        <button class="icon-btn del-srv" title="🗑">🗑</button>
      </div>`;

    // clicking the card body selects the server (syncs with the home picker)
    card.querySelector('.srv-info').onclick = () => selectServer(s.id);
    card.querySelector('.proto-badge').onclick = () => selectServer(s.id);
    card.querySelector('.ping-srv').onclick = (e) => { e.stopPropagation(); pingServer(s.id); };
    card.querySelector('.edit-srv').onclick = (e) => { e.stopPropagation(); openEdit(s.id); };
    card.querySelector('.connect-srv').onclick = (e) => { e.stopPropagation(); connect(s.id); };
    card.querySelector('.del-srv').onclick = (e) => { e.stopPropagation(); deleteServer(s.id); };
    list.appendChild(card);
  }
}

/* ----------------------------- unified picker (home) ----------------------------- */
const ADV_ID = '__advanced__';
function chainById(id) { return state.chains.find(c => c.id === id); }
function isChainId(id) { return !!chainById(id); }
function chainMembers(c) { return ((c && c.members) || []).map(srvById).filter(Boolean); }
function chainReady(c) { return chainMembers(c).length >= 2; }
function anyChainReady() { return state.chains.some(chainReady); }
function isPseudo(id) { return id === ADV_ID || isChainId(id); }
function advancedReady() {
  return !!state.settings.advancedRouting &&
    (((state.settings.routeRules || []).length > 0) || !!state.settings.routeDefault);
}

function selectServer(id) {
  state.selectedServerId = id;
  renderServers();
  renderPicker();
  // immediate ping feedback for the chosen target (skip for advanced routing)
  if (id && id !== ADV_ID && !state.pings[id]) pingServer(id);
}

function renderPicker() {
  const btnProto = $('#pickerProto');
  const btnName = $('#pickerName');
  const btnPing = $('#pickerPing');
  const menu = $('#pickerMenu');

  // drop a stale pseudo selection if its feature is no longer available
  if (isChainId(state.selectedServerId) && !chainReady(chainById(state.selectedServerId))) state.selectedServerId = null;
  if (state.selectedServerId === ADV_ID && !advancedReady()) state.selectedServerId = null;

  const selId = state.selectedServerId;
  const sel = state.servers.find(s => s.id === selId);
  const selChain = chainById(selId);
  const hasAny = state.servers.length || anyChainReady() || advancedReady();

  if (!hasAny) {
    btnProto.hidden = true;
    btnName.textContent = t('picker.none');
    btnPing.textContent = '';
  } else if (selChain && chainReady(selChain)) {
    btnProto.hidden = false;
    btnProto.textContent = '⛓';
    btnProto.className = 'proto-badge proto-chain';
    btnName.textContent = selChain.name;
    const pl = pingLabel(selChain.id);
    btnPing.textContent = pl.txt === '—' ? '' : pl.txt;
    btnPing.className = 'picker-ping ' + pl.cls;
  } else if (selId === ADV_ID) {
    btnProto.hidden = false;
    btnProto.textContent = '🧭';
    btnProto.className = 'proto-badge proto-advanced';
    btnName.textContent = t('picker.advanced');
    btnPing.textContent = '';
  } else if (sel) {
    btnProto.hidden = false;
    btnProto.textContent = sel.protocol;
    btnProto.className = 'proto-badge proto-' + sel.protocol;
    btnName.textContent = sel.name;
    const pl = pingLabel(sel.id);
    btnPing.textContent = pl.txt === '—' ? '' : pl.txt;
    btnPing.className = 'picker-ping ' + pl.cls;
  } else {
    btnProto.hidden = true;
    btnName.textContent = t('picker.choose');
    btnPing.textContent = '';
  }

  // build menu — header (ping all) + special targets + servers
  menu.innerHTML = '';
  const header = document.createElement('div');
  header.className = 'picker-head';
  header.innerHTML = `
    <span class="picker-head-label">${escapeHtml(t('picker.listLabel'))}</span>
    <button class="picker-pingall">⚡ ${escapeHtml(t('btn.pingAll'))}</button>`;
  header.querySelector('.picker-pingall').onclick = (e) => { e.stopPropagation(); pingAllVisible(); };
  menu.appendChild(header);

  const addRow = (id, badgeHtml, name, pingId, isSpecial) => {
    const pl = pingId ? pingLabel(pingId) : null;
    const row = document.createElement('div');
    row.className = 'picker-item' + (isSpecial ? ' picker-special' : '') + (id === selId ? ' active' : '');
    const pingPart = pingId
      ? `<span class="pi-ping ${pl.cls}" data-ping="${id}">${pl.txt}</span><button class="pi-ping-btn" title="ping">⚡</button>`
      : '';
    row.innerHTML = `${badgeHtml}<span class="pi-name">${escapeHtml(name)}</span>${pingPart}`;
    row.onclick = () => { selectServer(id); closePicker(); };
    const pb = row.querySelector('.pi-ping-btn');
    if (pb) pb.onclick = (e) => { e.stopPropagation(); pingServer(id); };
    menu.appendChild(row);
  };

  if (advancedReady()) addRow(ADV_ID, '<span class="proto-badge proto-advanced">🧭</span>', t('picker.advanced'), null, true);
  for (const c of state.chains) {
    if (chainReady(c)) addRow(c.id, '<span class="proto-badge proto-chain">⛓</span>', c.name, c.id, true);
  }
  for (const s of state.servers) {
    addRow(s.id, `<span class="proto-badge proto-${s.protocol}">${escapeHtml(s.protocol)}</span>`, s.name, s.id, false);
  }
}

/** Ping every server + ready chain shown in the picker (TCP handshake). */
async function pingAllVisible() {
  const ids = [...state.servers.map(s => s.id), ...state.chains.filter(chainReady).map(c => c.id)];
  if (!ids.length) return;
  toast(t('t.pingingAll'));
  await Promise.all(ids.map(id => pingServer(id)));
  renderPicker();
  toast(t('t.testDone'), 'ok');
}

function openPicker() { if (state.servers.length || anyChainReady() || advancedReady()) $('#pickerMenu').hidden = false; }
function closePicker() { $('#pickerMenu').hidden = true; }
$('#pickerBtn').onclick = (e) => {
  e.stopPropagation();
  const m = $('#pickerMenu');
  m.hidden ? openPicker() : closePicker();
};
document.addEventListener('click', (e) => {
  if (!$('#serverPicker').contains(e.target)) closePicker();
});

$('#btnAddOpen').onclick = () => { $('#importBox').hidden = !$('#importBox').hidden; };
$('#btnImportCancel').onclick = () => { $('#importBox').hidden = true; $('#importText').value = ''; };

/**
 * Smart import: figures out what was pasted and routes it correctly.
 *  - http(s) lines  -> added & fetched as subscriptions (auto-update capable)
 *  - vless/vmess/…  -> imported as servers
 *  - base64 blob    -> decoded & imported as servers (handled by parseMany)
 * Mixed input works too (URLs become subs, the rest become servers).
 */
async function smartImport(text) {
  text = String(text || '').trim();
  if (!text) return;
  const lines = text.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
  const urlLines = lines.filter(l => /^https?:\/\//i.test(l));
  const configText = lines.filter(l => !/^https?:\/\//i.test(l)).join('\n');

  let subCount = 0, subAdded = 0, srvAdded = 0, errCount = 0;

  for (const url of urlLines) {
    try { const res = await window.api.addSub(url, ''); subCount++; subAdded += res.added || 0; }
    catch (e) { errCount++; }
  }
  if (urlLines.length) {
    state.subscriptions = await window.api.listSubs();
    state.servers = await window.api.listServers();
  }
  if (configText && /\S/.test(configText)) {
    const res = await window.api.importServers(configText);
    state.servers = res.servers;
    srvAdded = res.added || 0;
    errCount += (res.errors || []).length;
  }

  if (!state.selectedServerId && state.servers.length) state.selectedServerId = state.servers[0].id;
  renderServers(); renderPicker(); renderSubs(); renderChains();

  const parts = [];
  if (subCount) parts.push(`${subCount} ${t('t.subAddedShort')} • ${subAdded} ${t('sub.servers')}`);
  if (srvAdded || (configText && !subCount)) parts.push(`${srvAdded} ${t('t.serversAdded')}`);
  const ok = subCount || srvAdded;
  const msg = (parts.join(' • ') || t('t.nothingFound')) + (errCount ? ` (${errCount} ${t('t.errors')})` : '');
  toast(msg, ok ? 'ok' : 'err');
  return { subCount, subAdded, srvAdded, errCount };
}

$('#btnImport').onclick = async () => {
  const text = $('#importText').value.trim();
  if (!text) return;
  $('#importHint').textContent = t('t.fetching');
  await smartImport(text);
  $('#importHint').textContent = '';
  $('#importText').value = '';
  $('#importBox').hidden = true;
};

/* Global paste (Ctrl+V) anywhere outside a text field — instantly add whatever
   is on the clipboard (config link OR subscription URL). Makes adding faster. */
document.addEventListener('paste', (e) => {
  const ae = document.activeElement;
  if (ae && (ae.tagName === 'INPUT' || ae.tagName === 'TEXTAREA')) return;
  const cd = e.clipboardData || window.clipboardData;
  const text = cd && cd.getData('text');
  if (!text || !text.trim()) return;
  if (!/^(https?:\/\/|vless:\/\/|vmess:\/\/|trojan:\/\/|ss:\/\/|wireguard:\/\/|wg:\/\/)/im.test(text.trim()) &&
      !/[A-Za-z0-9+/=]{24,}/.test(text.trim())) return; // ignore unrelated clipboard text
  e.preventDefault();
  toast(t('t.pasteDetected'));
  smartImport(text.trim());
});

async function deleteServer(id) {
  state.servers = await window.api.deleteServer(id);
  delete state.pings[id];
  if (state.selectedServerId === id) state.selectedServerId = state.servers[0] && state.servers[0].id || null;
  // prune the deleted server from any named chains
  const inAnyChain = state.chains.some(c => (c.members || []).includes(id));
  if (inAnyChain) {
    state.chains = state.chains.map(c => ({ ...c, members: (c.members || []).filter(x => x !== id) }));
    await window.api.setChains(state.chains);
  }
  renderServers();
  renderPicker();
  renderChains();
}

$('#btnClearServers').onclick = async () => {
  if (!state.servers.length) return;
  state.servers = await window.api.clearServers();
  state.pings = {};
  state.selectedServerId = null;
  state.chains = state.chains.map(c => ({ ...c, members: [] }));
  await window.api.setChains(state.chains);
  renderServers();
  renderPicker();
  renderChains();
  toast(t('t.allServersDeleted'));
};

/* ----------------------------- ping ----------------------------- */
async function pingServer(id) {
  // there can be several badges for one id (server card, picker row, chain card)
  const els = $$(`[data-ping="${id}"]`);
  const setCls = (el, extra) => { const base = el.classList[0] || 'srv-ping'; el.className = base + (extra ? ' ' + extra : ''); };
  els.forEach(el => { el.textContent = '...'; setCls(el, ''); });
  const tcp = await window.api.pingTcp(id);
  state.pings[id] = Object.assign(state.pings[id] || {}, { tcp });
  els.forEach(el => { el.textContent = tcp.ok ? tcp.ms + 'ms' : t('t.error'); setCls(el, pingClass(tcp.ok ? tcp.ms : -1)); });
  if (id === state.selectedServerId) renderPicker();
  return tcp;
}

$('#btnPingAll').onclick = async () => {
  toast(t('t.pingingAll'));
  await Promise.all(state.servers.map(s => pingServer(s.id)));
  renderPicker();
  toast(t('t.testDone'), 'ok');
};

/* quick ping (home) */
$('#btnQuickPing').onclick = async () => {
  const id = state.selectedServerId;
  if (!id) return toast(t('t.noServerSel'), 'err');
  $('#statTcp').textContent = '...';
  $('#statReal').textContent = '...';
  const tcp = await window.api.pingTcp(id);
  $('#statTcp').textContent = tcp.ok ? tcp.ms + 'ms' : t('t.error');
  const real = await window.api.pingReal(id);
  $('#statReal').textContent = real.ok ? real.ms + 'ms' : t('t.error');
  state.pings[id] = { tcp, real };
  renderServers();
  renderPicker();
};

/* IP check + geo description. `retries` re-tries on failure because a freshly
   connected proxy/chain may need a moment before traffic flows. */
async function checkIp(retries = 0, quiet = false) {
  $('#statIp').textContent = '...';
  let info = { ok: false };
  for (let i = 0; i <= retries; i++) {
    info = await window.api.checkIp(state.connected);
    if (info.ok) break;
    if (i < retries) await new Promise(r => setTimeout(r, 1300));
  }
  if (info.ok) {
    const flag = flagEmoji(info.countryCode);
    $('#statIp').textContent = `${flag} ${info.ip}`;
    showGeo(info);
    if (!quiet) toast(`IP: ${info.ip} — ${info.country || ''} (${info.isp || ''})`, 'ok');
  } else {
    $('#statIp').textContent = t('t.error');
    hideGeo();
    if (!quiet) toast(t('t.ipFailed') + ': ' + (info.error || ''), 'err');
  }
  return info;
}
$('#btnCheckIp').onclick = () => checkIp(1);

function showGeo(info) {
  const box = $('#connGeo');
  const parts = [info.country, info.city, info.isp].filter(Boolean);
  $('#geoFlag').textContent = flagEmoji(info.countryCode);
  $('#geoText').textContent = parts.length ? parts.join(' • ') : t('geo.unknown');
  box.hidden = false;
}
function hideGeo() { $('#connGeo').hidden = true; }

/* ----------------------------- connect / disconnect ----------------------------- */
async function connect(id) {
  if (state.connecting) return;
  if (state.connected && state.activeServerId === id) return disconnect();
  selectServer(id);
  state.connecting = true;
  setConnUI('connecting', id);
  try {
    await window.api.connect(id);
  } catch (e) {
    state.connecting = false;
    setConnUI('error');
    toast(t('t.connectFailed') + ': ' + e.message, 'err');
  }
}

async function disconnect() {
  await window.api.disconnect();
}

$('#powerBtn').onclick = () => {
  if (state.connected) return disconnect();
  const id = state.selectedServerId || state.activeServerId || (state.servers[0] && state.servers[0].id);
  if (!id) return toast(t('t.addServerFirst'), 'err');
  connect(id);
};

function refreshConnLabels() {
  setConnUI(state.connected ? 'connected' : (state.connecting ? 'connecting' : 'disconnected'),
    state.activeServerId || state.selectedServerId);
}

function setConnUI(stateStr, id) {
  const power = $('#powerBtn');
  const pill = $('#connPill');
  const pillText = $('#connPillText');
  const cs = $('#connState');
  const srv = $('#connServer');

  power.classList.remove('connecting', 'connected');
  pill.classList.remove('on');

  const effId = id || state.activeServerId || state.selectedServerId;
  const effChain = chainById(effId);
  if (effChain) {
    const names = chainMembers(effChain).map(s => s.name);
    srv.textContent = '⛓ ' + effChain.name + (names.length ? ' (' + names.join(' → ') + ')' : '');
  } else if (effId === ADV_ID) {
    srv.textContent = '🧭 ' + t('picker.advanced');
  } else {
    const server = state.servers.find(s => s.id === effId);
    srv.textContent = server ? `${server.name} — ${server.address}:${server.port}` : t('conn.noServer');
  }

  if (stateStr === 'connecting') {
    power.classList.add('connecting');
    cs.textContent = t('state.connecting');
    pillText.textContent = t('pill.connecting');
  } else if (stateStr === 'connected') {
    power.classList.add('connected');
    cs.textContent = t('state.connected');
    pill.classList.add('on');
    pillText.textContent = t('pill.connected');
  } else if (stateStr === 'error') {
    cs.textContent = t('state.error');
    pillText.textContent = t('pill.error');
  } else {
    cs.textContent = t('state.disconnected');
    pillText.textContent = t('pill.disconnected');
  }
}

/* status events from main */
window.api.onStatus((d) => {
  if (d.state === 'connected') {
    state.connected = true;
    state.connecting = false;
    state.activeServerId = d.serverId;
    setConnUI('connected', d.serverId);
    setModeWidget();
    renderServers();
    renderPicker();
    if (d.tunError) {
      toast(d.tunError, 'err');
      updateAdminBtn(true);
    } else if (state.settings.tunMode && d.tun) {
      updateAdminBtn(false);
    }
    if (d.geoWarn) toast(d.geoWarn, 'warn');
    setTimeout(() => checkIp(3, true), 1200);
  } else if (d.state === 'connecting') {
    state.connecting = true;
    setConnUI('connecting', d.serverId);
  } else if (d.state === 'disconnected') {
    state.connected = false;
    state.connecting = false;
    setConnUI('disconnected');
    $('#statIp').textContent = '—';
    hideGeo();
    resetTraffic();
    setModeWidget();
    renderServers();
    renderPicker();
  }
});

window.api.onXrayStatus((d) => {
  if (d.state === 'stopped' && state.connected) {
    state.connected = false;
    setConnUI('disconnected');
    renderServers();
    renderPicker();
    toast(t('t.disconnected'), 'err');
  }
});

/* ----------------------------- logs ----------------------------- */
const MAX_LOG_LINES = 500;
window.api.onLog((d) => {
  const box = $('#logBox');
  const line = document.createElement('div');
  line.className = 'log-' + (d.level || 'log');
  line.textContent = d.line;
  box.appendChild(line);
  while (box.childNodes.length > MAX_LOG_LINES) box.removeChild(box.firstChild);
  box.scrollTop = box.scrollHeight;
});
$('#btnClearLogs').onclick = () => { $('#logBox').innerHTML = ''; };

/* ----------------------------- xray binary ----------------------------- */
function updateXrayStatus(ready) {
  const el = $('#xrayStatus');
  if (ready) {
    el.textContent = t('xray.ok');
    el.className = 'xray-status ok';
  } else {
    el.textContent = t('xray.missing');
    el.className = 'xray-status missing';
  }
}
$('#btnLocateXray').onclick = async () => {
  const res = await window.api.locateXray();
  if (res.ok) { updateXrayStatus(res.ready); state.assets.xray = res.ready; renderComponents(); toast(t('t.xraySet'), 'ok'); }
};
$('#btnOpenData').onclick = () => window.api.openDataDir();
$('#btnDownloadHelp').onclick = () => {
  window.api.openExternal('https://github.com/XTLS/Xray-core/releases/latest');
  toast(t('t.xrayDownPage'));
};

/* ----------------------------- required components ----------------------------- */
const COMPONENTS = [
  { key: 'xray', label: 'comp.xray' },
  { key: 'geo', label: 'comp.geo', has: (a) => a.geoip && a.geosite },
  { key: 'tun2socks', label: 'comp.tun2socks' },
  { key: 'wintun', label: 'comp.wintun', winOnly: true }
];

function renderComponents() {
  const list = $('#compList');
  list.innerHTML = '';
  const a = state.assets || {};
  const isWin = (a.platform || 'win32') === 'win32';

  for (const c of COMPONENTS) {
    if (c.winOnly && !isWin) continue;
    const present = c.has ? c.has(a) : !!a[c.key];
    const row = document.createElement('div');
    row.className = 'comp-row';
    row.innerHTML = `
      <div class="comp-info">
        <span class="comp-dot ${present ? 'ok' : 'missing'}"></span>
        <span class="comp-name">${escapeHtml(t(c.label))}</span>
        <span class="comp-state ${present ? 'ok' : 'missing'}">${present ? t('comp.installed') : t('comp.missing')}</span>
      </div>
      <button class="btn ${present ? 'ghost' : 'primary'} comp-btn">${present ? t('btn.update') : t('btn.download')}</button>`;
    const btn = row.querySelector('.comp-btn');
    btn.onclick = () => downloadComponent(c.key, btn);
    list.appendChild(row);
  }
}

async function downloadComponent(key, btn) {
  const orig = btn.textContent;
  btn.disabled = true;
  btn.textContent = t('btn.downloading');
  toast(t('t.downloading') + '…');
  const res = await window.api.downloadAsset(key);
  btn.disabled = false;
  btn.textContent = orig;
  if (res.ok) {
    state.assets = res.assets || state.assets;
    state.tunAvailable = !!res.tunAvailable;
    renderComponents();
    updateXrayStatus(res.xrayReady);
    updateTunStatus();
    toast(t('t.downloaded'), 'ok');
  } else {
    state.assets = res.assets || state.assets;
    renderComponents();
    toast(t('t.downloadFailed') + ': ' + (res.error || ''), 'err');
  }
}

window.api.onAssetProgress((d) => {
  // surface coarse progress through the toast
  toast(`${t('t.downloading')} ${d.component}: ${d.pct}%`);
});

/* ----------------------------- TUN mode ----------------------------- */
$('#optTun').onchange = async () => {
  if ($('#optTun').checked && !state.tunAvailable) {
    toast(t('t.tunNeedFiles'), 'err');
  }
  await saveSettings();
  updateTunStatus();
  if (state.connected) toast(t('t.tunReconnect'), '');
};

function updateTunStatus() {
  const el = $('#tunStatus');
  if (!el) return;
  if (!state.tunAvailable) {
    el.textContent = t('tun.unavailable');
    el.className = 'tun-status warn';
  } else if (!state.elevated && state.settings.tunMode) {
    el.textContent = t('tun.needAdmin');
    el.className = 'tun-status warn';
  } else if (state.settings.tunMode) {
    el.textContent = t('tun.ready');
    el.className = 'tun-status ok';
  } else {
    el.textContent = t('tun.off');
    el.className = 'tun-status';
  }
  // show the "relaunch as admin" button when TUN is wanted but we're not elevated
  updateAdminBtn(state.settings.tunMode && state.tunAvailable && !state.elevated);
}

function updateAdminBtn(show) {
  const btn = $('#btnRunAdmin');
  if (!btn) return;
  btn.hidden = !show;
}
$('#btnRunAdmin').onclick = async () => {
  const res = await window.api.relaunchAdmin();
  if (!res || !res.ok) toast((res && res.error) || t('t.adminFailed'), 'err');
};

/* ----------------------------- subscriptions ----------------------------- */
function renderSubs() {
  const list = $('#subList');
  list.innerHTML = '';
  $('#subEmpty').hidden = state.subscriptions.length > 0;

  for (const sub of state.subscriptions) {
    const card = document.createElement('div');
    card.className = 'sub-card';
    card.innerHTML = `
      <div class="sub-ico">🔗</div>
      <div class="sub-info">
        <div class="sub-name">${escapeHtml(sub.name)}</div>
        <div class="sub-url">${escapeHtml(sub.url)}</div>
        <div class="sub-meta">${sub.serverCount || 0} ${t('sub.servers')} • ${t('sub.lastUpdate')}: ${timeAgo(sub.lastUpdated)}</div>
      </div>
      <div class="sub-actions">
        <label class="switch" data-i18n-title="autoupdate.title" title="auto">
          <input type="checkbox" class="sub-auto" ${sub.autoUpdate ? 'checked' : ''} /><span class="slider"></span>
        </label>
        <button class="icon-btn sub-refresh" title="⟳">⟳</button>
        <button class="icon-btn del-srv sub-del" title="🗑">🗑</button>
      </div>`;

    card.querySelector('.sub-refresh').onclick = () => refreshSub(sub.id);
    card.querySelector('.sub-del').onclick = () => removeSub(sub.id);
    card.querySelector('.sub-auto').onchange = (e) => window.api.setSubAutoUpdate(sub.id, e.target.checked);
    list.appendChild(card);
  }
}

$('#btnSubAddOpen').onclick = () => { $('#subAddBox').hidden = !$('#subAddBox').hidden; };
$('#btnSubAddCancel').onclick = () => { $('#subAddBox').hidden = true; $('#subUrl').value = ''; $('#subName').value = ''; };

$('#btnSubAdd').onclick = async () => {
  const url = $('#subUrl').value.trim();
  if (!url) return toast(t('t.subUrl'), 'err');
  $('#subAddHint').textContent = t('t.fetching');
  try {
    const res = await window.api.addSub(url, $('#subName').value.trim());
    state.subscriptions = await window.api.listSubs();
    state.servers = res.servers;
    if (!state.selectedServerId && state.servers.length) state.selectedServerId = state.servers[0].id;
    renderSubs(); renderServers(); renderPicker(); renderChains();
    $('#subUrl').value = ''; $('#subName').value = '';
    $('#subAddBox').hidden = true;
    $('#subAddHint').textContent = '';
    toast(`${t('t.subAdded')} — ${res.added} ${t('sub.servers')}`, 'ok');
  } catch (e) {
    $('#subAddHint').textContent = '';
    toast(t('t.failed') + ': ' + e.message, 'err');
  }
};

async function refreshSub(id) {
  toast(t('t.updating'));
  try {
    const res = await window.api.refreshSub(id);
    state.subscriptions = res.subs;
    state.servers = res.servers;
    renderSubs(); renderServers(); renderPicker(); renderChains();
    toast(`${t('t.updated')} — ${res.added} ${t('sub.servers')}`, 'ok');
  } catch (e) {
    toast(t('t.failed') + ': ' + e.message, 'err');
  }
}

async function removeSub(id) {
  const res = await window.api.removeSub(id);
  state.subscriptions = res.subs;
  state.servers = res.servers;
  renderSubs(); renderServers(); renderPicker(); renderChains();
  toast(t('t.subRemoved'));
}

$('#btnRefreshAll').onclick = async () => {
  if (!state.subscriptions.length) return toast(t('t.noSubs'), 'err');
  toast(t('t.updating'));
  const res = await window.api.refreshAllSubs();
  state.subscriptions = res.subs;
  state.servers = res.servers;
  renderSubs(); renderServers(); renderPicker(); renderChains();
  const okCount = res.results.filter(r => r.ok).length;
  toast(`${okCount}/${res.results.length} ${t('t.updated')}`, 'ok');
};

$('#optAutoUpdate').onchange = () => saveSettings({ autoUpdateSubs: $('#optAutoUpdate').checked });
$('#autoInterval').onchange = () => {
  const v = Math.max(5, parseInt($('#autoInterval').value, 10) || 60);
  $('#autoInterval').value = v;
  saveSettings({ autoUpdateInterval: v });
};

window.api.onSubsUpdated((d) => {
  state.subscriptions = d.subs;
  state.servers = d.servers;
  renderSubs(); renderServers(); renderPicker(); renderChains();
});

/* ----------------------------- edit server modal ----------------------------- */
let editOriginal = null;

function readServerFields(s) {
  const ob = s.outbound || {};
  const st = ob.streamSettings || {};
  const f = {
    name: s.name, address: s.address, port: s.port,
    network: st.network || 'tcp', security: st.security || 'none',
    sni: '', host: '', path: '', fp: '', pbk: '', sid: '', alpn: '',
    allowInsecure: false, cred: '', method: ''
  };

  if (s.protocol === 'vless' || s.protocol === 'vmess') {
    const u = ob.settings && ob.settings.vnext && ob.settings.vnext[0] && ob.settings.vnext[0].users[0];
    if (u) f.cred = u.id || '';
  } else if (s.protocol === 'trojan') {
    const srv = ob.settings && ob.settings.servers && ob.settings.servers[0];
    if (srv) f.cred = srv.password || '';
  } else if (s.protocol === 'shadowsocks') {
    const srv = ob.settings && ob.settings.servers && ob.settings.servers[0];
    if (srv) { f.cred = srv.password || ''; f.method = srv.method || ''; }
  } else if (s.protocol === 'wireguard') {
    f.cred = (ob.settings && ob.settings.secretKey) || '';
    const peer = ob.settings && ob.settings.peers && ob.settings.peers[0];
    f.wgPub = peer ? peer.publicKey : '';
    f.wgPsk = peer ? (peer.preSharedKey || '') : '';
    f.wgAddr = (ob.settings && ob.settings.address || []).join(',');
    f.wgMtu = (ob.settings && ob.settings.mtu) || 1420;
    f.wgReserved = (ob.settings && ob.settings.reserved || []).join(',');
    f.wgAllowed = (peer && peer.allowedIPs || []).join(', ');
  }

  // transport details
  if (st.wsSettings) { f.path = st.wsSettings.path || ''; f.host = (st.wsSettings.headers && st.wsSettings.headers.Host) || ''; }
  else if (st.grpcSettings) { f.path = st.grpcSettings.serviceName || ''; }
  else if (st.httpSettings) { f.path = st.httpSettings.path || ''; f.host = (st.httpSettings.host || []).join(','); }
  else if (st.xhttpSettings) { f.path = st.xhttpSettings.path || ''; f.host = st.xhttpSettings.host || ''; }
  else if (st.tcpSettings && st.tcpSettings.header && st.tcpSettings.header.request) {
    const r = st.tcpSettings.header.request;
    f.path = (r.path && r.path[0]) || '';
    f.host = (r.headers && r.headers.Host && r.headers.Host[0]) || '';
  }
  if (st.tlsSettings) {
    f.sni = st.tlsSettings.serverName || '';
    f.allowInsecure = !!st.tlsSettings.allowInsecure;
    f.fp = st.tlsSettings.fingerprint || '';
    f.alpn = (st.tlsSettings.alpn || []).join(',');
    if (!f.host && st.tlsSettings.serverName) f.host = '';
  } else if (st.realitySettings) {
    f.sni = st.realitySettings.serverName || '';
    f.fp = st.realitySettings.fingerprint || '';
    f.pbk = st.realitySettings.publicKey || '';
    f.sid = st.realitySettings.shortId || '';
  }
  return f;
}

function openEdit(id) {
  const s = state.servers.find(x => x.id === id);
  if (!s) return;
  state.editingId = id;
  editOriginal = s;
  const f = readServerFields(s);
  const proto = s.protocol;

  $('#edName').value = f.name || '';
  $('#edAddress').value = f.address || '';
  $('#edPort').value = f.port || '';
  $('#edCred').value = f.cred || '';
  $('#edNetwork').value = f.network || 'tcp';
  $('#edSecurity').value = f.security || 'none';
  $('#edSni').value = f.sni || '';
  $('#edHost').value = f.host || '';
  $('#edPath').value = f.path || '';
  $('#edFp').value = f.fp || '';
  $('#edPbk').value = f.pbk || '';
  $('#edSid').value = f.sid || '';
  $('#edInsecure').checked = !!f.allowInsecure;

  // credential label per protocol
  const credLabel = $('#edCredLabel');
  const isStd = (proto === 'vless' || proto === 'vmess' || proto === 'trojan');
  credLabel.textContent = proto === 'wireguard' ? t('wg.privateKey')
    : (proto === 'vless' || proto === 'vmess') ? t('edit.uuid')
    : t('edit.password');

  // for WireGuard, the generic address/port ARE the public endpoint (host:port)
  $('#edAddrLabel').textContent = proto === 'wireguard' ? t('wg.endpointHost') : t('edit.address');
  $('#edPortLabel').textContent = proto === 'wireguard' ? t('wg.endpointPort') : t('edit.port');

  // toggle protocol-specific sections
  const isWg = proto === 'wireguard';
  const isSs = proto === 'shadowsocks';
  show('#edTransportRow', isStd);
  show('#edTlsRow', isStd);
  show('#edPathRow', isStd);
  show('#edInsecureRow', isStd);
  show('#edWgExtra', isWg);
  $('#edRealityRow').hidden = !(isStd && $('#edSecurity').value === 'reality');

  if (isWg) {
    $('#edWgPub').value = f.wgPub || '';
    $('#edWgAddr').value = f.wgAddr || '';
    $('#edWgPsk').value = f.wgPsk || '';
    $('#edWgMtu').value = f.wgMtu || 1420;
    $('#edWgReserved').value = f.wgReserved || '';
    $('#edWgAllowed').value = f.wgAllowed || '';
  }

  $('#editModal').hidden = false;
}

function show(sel, on) { const el = $(sel); if (el) el.hidden = !on; }

$('#edSecurity').onchange = () => {
  const isStd = editOriginal && ['vless', 'vmess', 'trojan'].includes(editOriginal.protocol);
  $('#edRealityRow').hidden = !(isStd && $('#edSecurity').value === 'reality');
};

function closeEdit() { $('#editModal').hidden = true; state.editingId = null; editOriginal = null; }
$('#editClose').onclick = closeEdit;
$('#editCancel').onclick = closeEdit;
$('#editModal').onclick = (e) => { if (e.target === $('#editModal')) closeEdit(); };

$('#editSave').onclick = async () => {
  const id = state.editingId;
  if (!id || !editOriginal) return;
  const proto = editOriginal.protocol;
  const fields = {
    name: $('#edName').value,
    address: $('#edAddress').value,
    port: $('#edPort').value
  };
  const cred = $('#edCred').value.trim();
  if (proto === 'vless' || proto === 'vmess') { if (cred) fields.uuid = cred; }
  else if (proto === 'trojan' || proto === 'shadowsocks') { if (cred) fields.password = cred; }
  else if (proto === 'wireguard') { if (cred) fields.privateKey = cred; }

  if (['vless', 'vmess', 'trojan'].includes(proto)) {
    fields.network = $('#edNetwork').value;
    fields.security = $('#edSecurity').value;
    fields.sni = $('#edSni').value.trim();
    fields.host = $('#edHost').value.trim();
    const p = $('#edPath').value.trim();
    fields.path = p; fields.serviceName = p;
    fields.fp = $('#edFp').value.trim() || 'chrome';
    fields.pbk = $('#edPbk').value.trim();
    fields.sid = $('#edSid').value.trim();
    fields.allowInsecure = $('#edInsecure').checked;
    // preserve alpn from original (no field for it)
    const orig = readServerFields(editOriginal);
    if (orig.alpn) fields.alpn = orig.alpn;
  } else if (proto === 'wireguard') {
    fields.publicKey = $('#edWgPub').value.trim();
    fields.address = $('#edWgAddr').value.trim();
    fields.presharedKey = $('#edWgPsk').value.trim();
    fields.mtu = $('#edWgMtu').value;
    fields.reserved = $('#edWgReserved').value.trim();
    fields.allowedIPs = $('#edWgAllowed').value.trim();
  }

  const res = await window.api.updateServer(id, fields);
  if (res.ok) {
    state.servers = res.servers;
    renderServers(); renderPicker(); renderChains();
    closeEdit();
    toast(t('t.serverUpdated'), 'ok');
  } else {
    toast(t('t.failed'), 'err');
  }
};

/* ----------------------------- WireGuard add ----------------------------- */
$('#btnWgOpen').onclick = () => {
  const box = $('#wgBox');
  box.hidden = !box.hidden;
  $('#importBox').hidden = true;
};
$('#btnWgCancel').onclick = () => { $('#wgBox').hidden = true; };

$('#btnWgAdd').onclick = async () => {
  const fields = {
    name: $('#wgName').value.trim(),
    endpoint: $('#wgEndpoint').value.trim(),
    privateKey: $('#wgPrivate').value.trim(),
    publicKey: $('#wgPublic').value.trim(),
    address: $('#wgAddress').value.trim(),
    allowedIPs: $('#wgAllowed').value.trim(),
    presharedKey: $('#wgPsk').value.trim(),
    mtu: $('#wgMtu').value,
    reserved: $('#wgReserved').value.trim()
  };
  if (!fields.endpoint || !fields.privateKey || !fields.publicKey) {
    return toast(t('t.wgMissing'), 'err');
  }
  // Endpoint must be the PUBLIC server (host:port), not the local tunnel address.
  if (fields.endpoint.includes('/') || !/:\d{2,5}$/.test(fields.endpoint)) {
    return toast(t('t.wgBadEndpoint'), 'err');
  }
  const res = await window.api.addWireguard(fields);
  state.servers = res.servers;
  if (!state.selectedServerId) state.selectedServerId = res.server.id;
  renderServers(); renderPicker(); renderChains();
  $('#wgBox').hidden = true;
  ['wgName', 'wgEndpoint', 'wgPrivate', 'wgPublic', 'wgAddress', 'wgAllowed', 'wgPsk', 'wgReserved'].forEach(id => { $('#' + id).value = ''; });
  $('#wgMtu').value = 1420;
  toast(t('t.wgAdded'), 'ok');
};

/* ----------------------------- proxy chains (named, first-class) ----------------------------- */
function srvById(id) { return state.servers.find(s => s.id === id); }

function newChainId() { return 'chain-' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6); }

async function persistChains() {
  // prune missing members; keep order
  state.chains = state.chains.map(c => ({ id: c.id, name: c.name, members: (c.members || []).filter(srvById) }));
  await window.api.setChains(state.chains);
  renderChains();
  renderPicker();   // chains become selectable on home once they have ≥2 hops
  renderAdvanced(); // refresh routing target dropdowns that include chains
}

$('#btnAddChain').onclick = () => {
  const n = state.chains.length + 1;
  state.chains.push({ id: newChainId(), name: (window.i18n.lang === 'en' ? 'Chain ' : 'زنجیره ') + n, members: [] });
  persistChains();
};

function renderChains() {
  const wrap = $('#chainsWrap');
  if (!wrap) return;
  wrap.innerHTML = '';
  const empty = $('#chainsEmpty');
  if (empty) empty.hidden = state.chains.length > 0;

  state.chains.forEach((chain) => {
    chain.members = (chain.members || []).filter(srvById);
    const card = document.createElement('div');
    card.className = 'card chain-card';

    const pl = pingLabel(chain.id);
    const ready = chain.members.length >= 2;

    card.innerHTML = `
      <div class="chain-card-head">
        <span class="proto-badge proto-chain">⛓</span>
        <input class="input chain-name" value="${escapeHtml(chain.name)}" />
        <span class="chain-ping ${pl.cls}" data-ping="${chain.id}">${pl.txt}</span>
        <div class="chain-card-actions">
          <button class="icon-btn ch-ping" title="ping">⚡</button>
          <button class="icon-btn ch-connect" title="connect"${ready ? '' : ' disabled'}>▶</button>
          <button class="icon-btn ch-del" title="delete">🗑</button>
        </div>
      </div>
      <div class="chain-flow">
        <div class="flow-node fixed">${escapeHtml(t('chain.client'))}</div>
        <span class="flow-arrow">→</span>
        <div class="chain-nodes"></div>
        <span class="flow-arrow">→</span>
        <div class="flow-node fixed">${escapeHtml(t('chain.internet'))}</div>
      </div>
      <div class="chain-min ${ready ? '' : 'warn'}">${escapeHtml(ready ? '' : t('chain.empty'))}</div>
      <label class="field-label">${escapeHtml(t('chain.available'))}</label>
      <div class="chain-pool"></div>`;

    // name edit
    const nameInput = card.querySelector('.chain-name');
    nameInput.onchange = () => { chain.name = nameInput.value.trim() || chain.name; persistChains(); };

    // actions
    card.querySelector('.ch-ping').onclick = () => pingServer(chain.id);
    card.querySelector('.ch-connect').onclick = () => { if (ready) connect(chain.id); };
    card.querySelector('.ch-del').onclick = () => {
      state.chains = state.chains.filter(c => c.id !== chain.id);
      if (state.selectedServerId === chain.id) state.selectedServerId = null;
      persistChains();
    };

    // ordered member nodes (draggable)
    const nodes = card.querySelector('.chain-nodes');
    chain.members.forEach((id, idx) => {
      const s = srvById(id);
      const node = document.createElement('div');
      node.className = 'flow-node chain-node';
      node.draggable = true;
      node.dataset.idx = idx;
      node.innerHTML = `
        <span class="proto-badge proto-${s.protocol}">${s.protocol}</span>
        <span class="cn-name">${escapeHtml(s.name)}</span>
        <button class="cn-remove" title="remove">✕</button>`;
      node.querySelector('.cn-remove').onclick = (e) => { e.stopPropagation(); chain.members.splice(idx, 1); persistChains(); };
      node.addEventListener('dragstart', (e) => { e.dataTransfer.setData('text/plain', String(idx)); node.classList.add('dragging'); });
      node.addEventListener('dragend', () => node.classList.remove('dragging'));
      node.addEventListener('dragover', (e) => e.preventDefault());
      node.addEventListener('drop', (e) => {
        e.preventDefault();
        const from = parseInt(e.dataTransfer.getData('text/plain'), 10);
        if (Number.isNaN(from) || from === idx) return;
        const [moved] = chain.members.splice(from, 1);
        chain.members.splice(idx, 0, moved);
        persistChains();
      });
      nodes.appendChild(node);
      if (idx < chain.members.length - 1) {
        const arrow = document.createElement('span');
        arrow.className = 'flow-arrow small';
        arrow.textContent = '→';
        nodes.appendChild(arrow);
      }
    });
    if (!chain.members.length) {
      const ph = document.createElement('div');
      ph.className = 'chain-nodes-empty';
      ph.textContent = t('chain.addFromBelow');
      nodes.appendChild(ph);
    }

    // available pool (servers not already in THIS chain)
    const pool = card.querySelector('.chain-pool');
    const available = state.servers.filter(s => !chain.members.includes(s.id));
    if (!available.length) {
      pool.innerHTML = `<div class="empty small">${escapeHtml(t('chain.poolEmpty'))}</div>`;
    }
    for (const s of available) {
      const row = document.createElement('button');
      row.className = 'pool-item';
      row.innerHTML = `
        <span class="proto-badge proto-${s.protocol}">${s.protocol}</span>
        <span class="pi-name">${escapeHtml(s.name)}</span>
        <span class="pool-add">+ ${escapeHtml(t('chain.add'))}</span>`;
      row.onclick = () => { chain.members.push(s.id); persistChains(); };
      pool.appendChild(row);
    }

    wrap.appendChild(card);
  });
}

/* ----------------------------- advanced (graphical) routing ----------------------------- */
const RULE_TYPES = ['ip', 'domain', 'port'];

function targetOptions(selected) {
  // [{ value, label }] — servers + named chains + direct/block
  const opts = state.servers.map(s => ({ value: s.id, label: s.name }));
  for (const c of state.chains) {
    if (chainReady(c)) opts.push({ value: 'chain:' + c.id, label: '⛓ ' + c.name });
  }
  opts.push({ value: 'direct', label: t('adv.direct') });
  opts.push({ value: 'block', label: t('adv.block') });
  return opts.map(o =>
    `<option value="${escapeHtml(o.value)}"${o.value === selected ? ' selected' : ''}>${escapeHtml(o.label)}</option>`
  ).join('');
}

function renderAdvanced() {
  const wrap = $('#advRules');
  const body = $('#advBody');
  const optAdv = $('#optAdvanced');
  const defSel = $('#advDefault');
  if (!wrap || !optAdv || !defSel) return;

  optAdv.checked = !!state.settings.advancedRouting;
  if (body) body.hidden = !state.settings.advancedRouting;

  const rules = state.settings.routeRules || [];
  wrap.innerHTML = '';
  if (!rules.length) {
    wrap.innerHTML = `<div class="empty small">${escapeHtml(t('adv.empty'))}</div>`;
  }
  rules.forEach((r, idx) => {
    const row = document.createElement('div');
    row.className = 'adv-rule';
    const typeOpts = RULE_TYPES.map(tp =>
      `<option value="${tp}"${tp === r.type ? ' selected' : ''}>${escapeHtml(t('adv.type.' + tp))}</option>`).join('');
    row.innerHTML = `
      <select class="select adv-type">${typeOpts}</select>
      <input class="input adv-value" dir="ltr" placeholder="${escapeHtml(t('adv.valuePh'))}" value="${escapeHtml(r.value || '')}" />
      <span class="adv-arrow">→</span>
      <select class="select adv-target">${targetOptions(r.target)}</select>
      <button class="icon-btn adv-del" title="remove">🗑</button>`;
    row.querySelector('.adv-type').onchange = (e) => { rules[idx].type = e.target.value; };
    row.querySelector('.adv-value').oninput = (e) => { rules[idx].value = e.target.value; };
    row.querySelector('.adv-target').onchange = (e) => { rules[idx].target = e.target.value; };
    row.querySelector('.adv-del').onclick = () => { rules.splice(idx, 1); renderAdvanced(); };
    wrap.appendChild(row);
  });

  // default target select
  const def = state.settings.routeDefault || (state.servers[0] && state.servers[0].id) || 'direct';
  defSel.innerHTML = targetOptions(def);
}

$('#optAdvanced').onchange = async () => {
  const on = $('#optAdvanced').checked;
  const extra = { advancedRouting: on };
  // Seed a default target so the 🧭 entry is immediately usable on the home page.
  if (on && !state.settings.routeDefault) {
    extra.routeDefault = (state.servers[0] && state.servers[0].id) || 'direct';
  }
  await saveSettings(extra);
  renderAdvanced();
  renderPicker();
  toast(on ? t('t.advOn') : t('t.advOff'), 'ok');
};

$('#btnAddRule').onclick = () => {
  const rules = state.settings.routeRules || (state.settings.routeRules = []);
  const firstTarget = (state.servers[0] && state.servers[0].id) || 'direct';
  rules.push({ type: 'ip', value: '', target: firstTarget });
  renderAdvanced();
};

$('#btnSaveAdv').onclick = async () => {
  // collect from current state (kept in sync by the row handlers) + default select
  const rules = (state.settings.routeRules || [])
    .map(r => ({ type: r.type, value: (r.value || '').trim(), target: r.target }))
    .filter(r => r.value && r.target);
  const routeDefault = $('#advDefault').value;
  await saveSettings({ routeRules: rules, routeDefault, advancedRouting: $('#optAdvanced').checked });
  state.settings.routeRules = rules;
  renderAdvanced();
  renderPicker();
  $('#advSavedHint').textContent = t('saved');
  setTimeout(() => ($('#advSavedHint').textContent = ''), 1800);
  toast(t('t.advSaved') + ' (' + rules.length + ')', 'ok');
};

/* ----------------------------- live traffic stats ----------------------------- */
window.api.onStats((s) => {
  $('#downSpeed').textContent = fmtSpeed(s.downSpeed);
  $('#upSpeed').textContent = fmtSpeed(s.upSpeed);
  $('#downTotal').textContent = fmtBytes(s.totalDown);
  $('#upTotal').textContent = fmtBytes(s.totalUp);
  // session totals (cumulative since xray started for this connection)
  $('#sessDown').textContent = fmtBytes(s.totalDown);
  $('#sessUp').textContent = fmtBytes(s.totalUp);
  $('#sessSum').textContent = fmtBytes((Number(s.totalDown) || 0) + (Number(s.totalUp) || 0));
});

function resetTraffic() {
  $('#downSpeed').textContent = '0 B/s';
  $('#upSpeed').textContent = '0 B/s';
  $('#downTotal').textContent = '0 B';
  $('#upTotal').textContent = '0 B';
  $('#sessDown').textContent = '0 B';
  $('#sessUp').textContent = '0 B';
  $('#sessSum').textContent = '0 B';
}
function setModeWidget() {
  // Reflect the CHOSEN mode (so users see/can change it before connecting).
  const wantTun = !!state.settings.tunMode;
  $('#modeIco').textContent = wantTun ? '🛡' : '⚡';
  $('#modeLabel').textContent = wantTun ? t('mode.tun') : t('mode.proxy');
  $('#modeSub').textContent = wantTun ? t('mode.tunSub') : t('mode.proxySub');
  const card = $('#modeCard');
  if (card) card.title = t('mode.pick');
}

/* ----------------------------- connection-mode modal ----------------------------- */
function renderModeOptions() {
  const wantTun = !!state.settings.tunMode;
  $$('#modeModal .mode-option').forEach(opt => {
    const isTun = opt.dataset.mode === 'tun';
    opt.classList.toggle('active', isTun === wantTun);
    if (isTun) opt.classList.toggle('disabled', !state.tunAvailable);
  });
  const note = $('#modeNote');
  if (!note) return;
  if (!state.tunAvailable) note.textContent = t('tun.unavailable');
  else if (state.settings.tunMode && !state.elevated) note.textContent = t('tun.needAdmin');
  else note.textContent = '';
}
function openModeModal() { renderModeOptions(); $('#modeModal').hidden = false; }
function closeModeModal() { $('#modeModal').hidden = true; }
$('#modeCard').onclick = openModeModal;
$('#modeClose').onclick = closeModeModal;
$('#modeModal').onclick = (e) => { if (e.target === $('#modeModal')) closeModeModal(); };
$$('#modeModal .mode-option').forEach(opt => {
  opt.onclick = async () => {
    const wantTun = opt.dataset.mode === 'tun';
    if (wantTun && !state.tunAvailable) { toast(t('t.tunNeedFiles'), 'err'); return; }
    $('#optTun').checked = wantTun;
    await saveSettings({ tunMode: wantTun });
    setModeWidget();
    updateTunStatus();
    renderModeOptions();
    toast(wantTun ? t('mode.tun') : t('mode.proxy'), 'ok');
    if (state.connected) toast(t('t.tunReconnect'), '');
    setTimeout(closeModeModal, 220);
  };
});

init();
