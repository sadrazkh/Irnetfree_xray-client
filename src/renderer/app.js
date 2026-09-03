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
  activeEngine: '',       // core the live connection runs on
  selectedServerId: null, // chosen in the picker (target for connect)
  connected: false,
  connecting: false,
  tunAvailable: false,
  elevated: false,         // running as Administrator (Windows) — needed for TUN
  assets: {},
  version: '',             // app version (from main)
  coreVersions: {},        // engineId -> version string
  platform: 'win32',       // process.platform
  procList: [],            // running processes for the routing picker
  lan: null,               // { ip, socksPort, httpPort } when LAN sharing active
  chain: [],               // legacy: ordered server ids (first hop → exit)
  chains: [],              // [{ id, name, members:[serverId,...] }] — first-class chains
  pool: [],                // [{ id, name, target, socksPort, httpPort, enabled }] — multi-proxy pool
  editingId: null,         // server being edited in the modal
  // Settings saved while connected that the live tunnel is NOT using yet.
  // Owned by main (it knows what the running config was built from) — the
  // renderer only mirrors it.
  pendingReconnect: [],
  pendingDismissed: false, // user chose "later"; keep the banner out of the way
  wasReconnecting: false,  // main is rebuilding after a network change (toast on success)
  pings: {} // id -> { tcp, real }
};

/* ----------------------------- helpers ----------------------------- */
function toast(msg, kind = '', ms = 2600) {
  const el = $('#toast');
  el.textContent = msg;
  el.className = 'toast show ' + kind;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { el.className = 'toast'; }, ms);
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
  // Bytes are whole; everything else keeps ONE decimal so the text width stays
  // stable as values cross B↔KB↔MB (prevents the traffic cards from resizing).
  return (i === 0 ? Math.round(n) : n.toFixed(1)) + ' ' + units[i];
}
function fmtSpeed(n) { return fmtBytes(n) + '/s'; }

/** Human duration from seconds (days / hours / minutes). */
function fmtDuration(sec) {
  sec = Math.max(0, sec);
  const d = Math.floor(sec / 86400);
  if (d >= 1) return d + ' ' + t('sub.days');
  const h = Math.floor(sec / 3600);
  if (h >= 1) return h + ' ' + t('sub.hours');
  return Math.floor(sec / 60) + ' ' + t('sub.mins');
}

/** Data-usage + expiry progress bars for a subscription (from Subscription-Userinfo). */
function subUsageHtml(sub) {
  const u = sub.usage;
  if (!u) return '';
  let html = '';
  const used = (u.upload || 0) + (u.download || 0);
  if (u.total && u.total > 0) {
    const pct = Math.min(100, Math.round(used / u.total * 100));
    const cls = pct >= 90 ? 'bad' : pct >= 70 ? 'mid' : 'good';
    html += `
      <div class="sub-usage">
        <div class="sub-usage-row"><span>${escapeHtml(t('sub.data'))}</span><span dir="ltr">${fmtBytes(used)} / ${fmtBytes(u.total)} · ${pct}%</span></div>
        <div class="usage-bar"><div class="usage-fill ${cls}" style="width:${pct}%"></div></div>
      </div>`;
  } else if (used > 0) {
    html += `<div class="sub-usage"><div class="sub-usage-row"><span>${escapeHtml(t('sub.data'))}</span><span dir="ltr">${fmtBytes(used)} · ${escapeHtml(t('sub.unlimited'))}</span></div></div>`;
  }
  if (u.expire && u.expire > 0) {
    const remSec = u.expire - Date.now() / 1000;
    const remDays = remSec / 86400;
    const expired = remSec <= 0;
    const pct = expired ? 0 : Math.min(100, Math.round(Math.min(remDays, 30) / 30 * 100));
    const cls = expired || remDays < 3 ? 'bad' : remDays < 7 ? 'mid' : 'good';
    const label = expired ? t('sub.expired') : `${fmtDuration(remSec)} ${t('sub.left')}`;
    html += `
      <div class="sub-usage">
        <div class="sub-usage-row"><span>${escapeHtml(t('sub.time'))}</span><span dir="ltr">${escapeHtml(label)}</span></div>
        <div class="usage-bar"><div class="usage-fill ${cls}" style="width:${pct}%"></div></div>
      </div>`;
  }
  return html;
}

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

/* ----------------------------- theme ----------------------------- */
/** 'dark' | 'light' | 'system' -> the attribute the CSS keys off. */
function applyTheme(pref, systemDark) {
  const dark = pref === 'system' ? systemDark !== false : pref !== 'light';
  const theme = dark ? 'dark' : 'light';
  document.documentElement.setAttribute('data-theme', theme);
  // Remember the RESOLVED theme (not the preference) so theme-boot.js can paint
  // it from <head> on the next launch, before app:init has answered. Storage is
  // best-effort: a failure here only costs the flash it exists to avoid.
  try { localStorage.setItem('irnetfree.theme', theme); } catch {}
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
$('#btnMax').onclick = () => window.api.maximize();   // maximize/restore (was wrongly hiding the app)
$('#btnClose').onclick = () => window.api.close();

/* language toggle */
$('#btnLang').onclick = () => setLang(window.i18n.lang === 'fa' ? 'en' : 'fa');
$('#langSelect').onchange = () => setLang($('#langSelect').value);

/* default core — saves itself (readSettingsForm() deliberately leaves it out) */
$('#defaultEngine').onchange = () => saveSettings({ defaultEngine: $('#defaultEngine').value });

/* theme — renderer-only, applied immediately then persisted */
$('#themeSelect').onchange = () => {
  const theme = $('#themeSelect').value;
  applyTheme(theme, state.systemDark);
  saveSettings({ theme });
};

/* the OS switched between light and dark while the app is open */
window.api.onSystemTheme((d) => {
  state.systemDark = !!(d && d.dark);
  if ((state.settings.theme || 'dark') === 'system') applyTheme('system', state.systemDark);
});

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
  renderPool();
  renderAdvanced(); // rule/target labels and the AllowedIPs notes are built with t()
  updateXrayStatus(anyXrayCore());
  updateTunStatus();
  setModeWidget();
  refreshConnLabels();
  if ($('#xrayVersion')) $('#xrayVersion').textContent = state.xrayVersion ? (t('xray.version') + ': ' + state.xrayVersion) : '';
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
  state.version = data.version || '';
  state.platform = data.platform || (data.assets && data.assets.platform) || 'win32';
  // main only reports pending keys while something is actually connected, so a
  // fresh launch always starts empty
  state.pendingReconnect = data.pendingReconnect || [];
  state.chain = (data.chain || []).filter(id => state.servers.some(s => s.id === id));
  state.chains = (data.chains || []).map(c => ({
    id: c.id, name: c.name || 'Chain',
    members: (c.members || []).filter(id => state.servers.some(s => s.id === id))
  }));
  state.pool = (data.pool || []).map(e => ({
    id: e.id, name: e.name || 'Proxy', target: e.target || '',
    socksPort: e.socksPort || 0, httpPort: e.httpPort || 0, enabled: e.enabled !== false
  }));

  window.i18n.applyI18n(state.settings.lang || 'fa');
  $('#btnLang').textContent = (state.settings.lang || 'fa') === 'fa' ? 'EN' : 'فا';

  state.systemDark = data.systemDark !== false;
  applyTheme(state.settings.theme || 'dark', state.systemDark);

  applySettingsToUI();
  renderServers();
  renderPicker();
  renderSubs();
  renderComponents();
  renderChains();
  renderPool();
  renderAdvanced();
  updateXrayStatus(data.xrayReady);
  updateTunStatus();
  setModeWidget();
  updateLanInfo();
  updateKillStatus();
  renderPendingBanner();

  // app version + xray-core version
  $('#appVersion').textContent = 'v' + (state.version || '?');
  refreshXrayVersion();

  // the store failed to load before this window existed, so it is delivered here
  if (data.storeError) reportStoreError(Object.assign({ kind: 'load' }, data.storeError));

  // prompt to download required files on first run / when essentials are missing
  maybePromptMissingFiles();
}

/* ----------------------------- core versions ----------------------------- */
const XRAY_ENGINES = ['xray', 'xray-pattn'];
async function refreshXrayVersion() {
  for (const id of XRAY_ENGINES) {
    try {
      const res = await window.api.xrayVersion(id);
      state.coreVersions[id] = (res && res.ok) ? res.version : '';
    } catch { state.coreVersions[id] = ''; }
  }
  state.xrayVersion = state.coreVersions.xray || state.coreVersions['xray-pattn'] || '';
  const el = $('#xrayVersion');
  if (el) el.textContent = state.xrayVersion ? (t('xray.version') + ': ' + state.xrayVersion) : '';
  renderComponents();
}

/* ----------------------------- settings UI ----------------------------- */
function applySettingsToUI() {
  const s = state.settings;
  $('#socksPort').value = s.socksPort ?? 10808;
  $('#httpPort').value = s.httpPort ?? 10809;
  $('#dnsRemoteInput').value = (s.dnsRemote || []).join(', ');
  $('#dnsDirectInput').value = (s.dnsDirect || []).join(', ');
  $('#optDnsManaged').checked = s.dnsManaged !== false;
  $('#optIpv6').checked = !!s.ipv6;
  $('#logLevel').value = s.logLevel || 'warning';
  $('#langSelect').value = s.lang || 'fa';
  $('#defaultEngine').value = s.defaultEngine || 'xray';
  $('#themeSelect').value = s.theme || 'dark';
  $('#optSysProxy').checked = !!s.systemProxy;
  $('#optTun').checked = !!s.tunMode;
  $('#optTunBackend').value = s.tunBackend || 'sing-box';
  $('#optLeakGuard').value = s.leakGuard || 'standard';
  $('#optBlockUdpProxy').checked = !!s.blockUdpInProxyMode;
  $('#optAllowLan').checked = !!s.allowLan;
  $('#optKillSwitch').checked = !!s.killSwitch;
  $('#optNetAuto').checked = s.autoReconnectOnNetworkChange !== false;
  $('#optBlockAds').checked = !!s.blockAds;
  $('#optSniff').checked = s.enableSniffing !== false;
  $('#optAutoUpdate').checked = s.autoUpdateSubs !== false;
  $('#autoInterval').value = s.autoUpdateInterval || 60;
  $('#customRules').value = customRulesToText(s.customRules || []);

  $$('#routingSeg .seg-btn').forEach(b => b.classList.toggle('active', b.dataset.mode === (s.routingMode || 'global')));
  syncPreset('#dnsRemotePreset', '#dnsRemoteInput');
  syncPreset('#dnsDirectPreset', '#dnsDirectInput');
  updateGuardRows();
}

/**
 * The leak guard only exists inside the tunnel, and the proxy-mode UDP block only
 * exists outside it — so each row is dimmed and disabled in the mode where it does
 * nothing, with a note saying why instead of a control that silently has no effect.
 * Driven by the TUN *switch*, not by the live connection: this is the setting the
 * next connect will be built from.
 */
function updateGuardRows() {
  const tunOn = !!($('#optTun') && $('#optTun').checked);
  const guardRow = $('#leakGuardRow');
  if (guardRow) {
    guardRow.classList.toggle('disabled', !tunOn);
    $('#optLeakGuard').disabled = !tunOn;
    $('#guardNeedsTun').hidden = tunOn;
    // the pf anchor behind "strict" has never run on a real Mac (phase 3)
    $('#guardMacNote').hidden = (state.assets || {}).platform !== 'darwin';
    // Strict blocks everything that does not go through the tunnel — and a
    // "direct" route is exactly that. Say so where the two are chosen, not in a
    // log line the user reads after their bank stops loading.
    const s = state.settings || {};
    const bypasses = s.advancedRouting
      ? (s.routeRules || []).some(r => r && r.target === 'direct') || s.routeDefault === 'direct'
      : ['bypass-ir', 'bypass-cn', 'direct'].includes(s.routingMode || 'global');
    $('#guardStrictRouting').hidden = !(tunOn && $('#optLeakGuard').value === 'strict' && bypasses);
  }
  const udpRow = $('#udpBlockRow');
  if (udpRow) {
    udpRow.classList.toggle('disabled', tunOn);
    $('#optBlockUdpProxy').disabled = tunOn;
    $('#udpBlockNote').hidden = !tunOn;
  }
}

/** Reflect an input's value in its preset dropdown (or "custom"). */
function syncPreset(selSel, inputSel) {
  const sel = $(selSel);
  if (!sel) return;
  const cur = ($(inputSel).value || '').replace(/\s/g, '');
  const match = Array.from(sel.options).find(o => o.value && o.value.replace(/\s/g, '') === cur);
  sel.value = match ? match.value : '';
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

/** The Settings page form → settings partial. Only the "Save settings" button uses it. */
function readSettingsForm() {
  return {
    socksPort: parseInt($('#socksPort').value, 10) || 10808,
    httpPort: parseInt($('#httpPort').value, 10) || 10809,
    dnsRemote: listFromInput('#dnsRemoteInput'),
    dnsDirect: listFromInput('#dnsDirectInput'),
    dnsManaged: $('#optDnsManaged').checked,
    ipv6: $('#optIpv6').checked,
    logLevel: $('#logLevel').value,
    systemProxy: $('#optSysProxy').checked,
    tunMode: $('#optTun').checked,
    tunBackend: $('#optTunBackend').value,
    leakGuard: $('#optLeakGuard').value,
    blockUdpInProxyMode: $('#optBlockUdpProxy').checked,
    allowLan: $('#optAllowLan').checked,
    killSwitch: $('#optKillSwitch').checked,
    blockAds: $('#optBlockAds').checked,
    enableSniffing: $('#optSniff').checked
  };
}
function listFromInput(sel) {
  return $(sel).value.split(',').map(s => s.trim()).filter(Boolean);
}

/**
 * Persist a settings partial — ONLY the keys the caller changed. Reading the
 * whole Settings form here used to persist abandoned edits from other pages.
 *
 * Most settings are baked into the running xray config (or applied as a
 * connect-time side effect), so while connected they do NOTHING until the tunnel
 * is rebuilt. Main reports exactly which ones are in that state; we then ask the
 * user instead of leaving the UI claiming a change that isn't live.
 *
 * `silent: true` skips the prompt (the caller shows its own), but the pending
 * state is still recorded so the banner stays accurate.
 */
async function saveSettings(partial = {}, { silent = false } = {}) {
  const res = await window.api.setSettings(partial);
  // main returns { settings, pendingReconnect }; tolerate the older bare shape
  state.settings = (res && res.settings) ? res.settings : res;
  setPending((res && res.pendingReconnect) || []);

  if (!silent && state.pendingReconnect.length) await promptApplySettings();
  return state.pendingReconnect;
}

/* ------------------- settings that need a reconnect ------------------- */

/** Record which settings are saved-but-not-live and refresh the banner. */
function setPending(keys) {
  const next = Array.isArray(keys) ? keys : [];
  // a genuinely new change should bring the banner back even after "later"
  if (next.length > state.pendingReconnect.length) state.pendingDismissed = false;
  state.pendingReconnect = next;
  if (!next.length) state.pendingDismissed = false;
  renderPendingBanner();
}

/** Human-readable names for the changed settings, for the dialog + banner. */
function pendingLabels() {
  return state.pendingReconnect.map(k => t('set.' + k)).filter(Boolean);
}

function renderPendingBanner() {
  const banner = $('#pendingBanner');
  if (!banner) return;
  const show = state.pendingReconnect.length > 0 && state.connected && !state.pendingDismissed;
  banner.hidden = !show;
  if (!show) return;
  const names = pendingLabels();
  const sep = (state.settings.lang || 'fa') === 'en' ? ', ' : '، ';
  const shown = names.slice(0, 3).join(sep);
  $('#pendingBannerText').textContent =
    '⚠ ' + t('apply.bannerText') + ': ' + shown + (names.length > 3 ? ' +' + (names.length - 3) : '');
}

/**
 * Ask whether to rebuild the connection now. Resolves once the user picks; the
 * settings are already saved either way — the only question is when they go live.
 */
function promptApplySettings() {
  return new Promise((resolve) => {
    const modal = $('#applyModal');
    if (!modal || !state.connected || !state.pendingReconnect.length) return resolve(false);

    $('#applyList').innerHTML = pendingLabels()
      .map(n => `<li>${escapeHtml(n)}</li>`).join('');
    // the kill switch turns the reconnect gap into a full internet block —
    // say so, because the user is about to lose connectivity on purpose
    $('#applyKillNote').hidden = !state.settings.killSwitch;
    modal.hidden = false;

    const done = (v) => {
      modal.hidden = true;
      $('#applyNow').onclick = null;
      $('#applyLater').onclick = null;
      $('#applyClose').onclick = null;
      resolve(v);
    };
    // "Later" only closes the dialog — the banner stays up as the reminder that
    // the saved settings are not live yet. Only the banner's own Dismiss hides it.
    const later = () => { renderPendingBanner(); done(false); };

    $('#applyNow').onclick = async () => { done(true); await applySettingsNow(); };
    $('#applyLater').onclick = later;
    $('#applyClose').onclick = later;
  });
}

/** Tear the tunnel down and rebuild it so the pending settings take effect. */
async function applySettingsNow() {
  $('#pendingBanner').hidden = true;
  try {
    const res = await window.api.applySettings();
    if (res && res.ok) {
      setPending([]);
      toast(t('apply.done'), 'ok');
      return true;
    }
    // The user disconnected (or connected elsewhere) while the rebuild was in
    // flight, so it abandoned itself. Nothing failed — they changed their mind,
    // and the 'disconnected' status has already repainted the UI. Stay quiet.
    if (res && res.stale) { renderPendingBanner(); return false; }
    // a failed reconnect with the kill switch armed leaves the internet blocked
    // ON PURPOSE — onKillSwitch shows the disarm banner, so just explain why.
    toast((res && res.error) || t('apply.failed'), 'err');
    if (res && res.killSwitchEngaged) toast(t('apply.stillBlocked'), 'warn');
  } catch (e) {
    toast(t('apply.failed') + ': ' + e.message, 'err');
  }
  renderPendingBanner();
  return false;
}

$('#pendingApply').onclick = () => applySettingsNow();
$('#pendingDismiss').onclick = () => { state.pendingDismissed = true; renderPendingBanner(); };

$('#btnSaveSettings').onclick = async () => {
  await saveSettings(readSettingsForm());
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
    updateGuardRows();   // whether the strict guard now contradicts the routing
    toast(t('t.routingMode') + ': ' + btn.textContent, 'ok');
  };
});
$('#optBlockAds').onchange = () => saveSettings({ blockAds: $('#optBlockAds').checked });
$('#optSniff').onchange = () => saveSettings({ enableSniffing: $('#optSniff').checked });

/* DNS presets — pick a provider to fill the input, or type a custom value */
$('#dnsRemotePreset').onchange = () => {
  const v = $('#dnsRemotePreset').value;
  if (v) { $('#dnsRemoteInput').value = v.split(',').join(', '); saveSettings({ dnsRemote: listFromInput('#dnsRemoteInput') }); toast(t('dns.set'), 'ok'); }
};
$('#dnsRemoteInput').oninput = () => syncPreset('#dnsRemotePreset', '#dnsRemoteInput');
$('#dnsDirectPreset').onchange = () => {
  const v = $('#dnsDirectPreset').value;
  if (v) { $('#dnsDirectInput').value = v.split(',').join(', '); saveSettings({ dnsDirect: listFromInput('#dnsDirectInput') }); toast(t('dns.set'), 'ok'); }
};
$('#dnsDirectInput').oninput = () => syncPreset('#dnsDirectPreset', '#dnsDirectInput');
$('#optDnsManaged').onchange = () => saveSettings({ dnsManaged: $('#optDnsManaged').checked });
$('#optIpv6').onchange = () => saveSettings({ ipv6: $('#optIpv6').checked });

/* TUN backend / leak guard / proxy-mode UDP block — each saves only its own key */
$('#optTunBackend').onchange = () => saveSettings({ tunBackend: $('#optTunBackend').value });
$('#optLeakGuard').onchange = () => { saveSettings({ leakGuard: $('#optLeakGuard').value }); updateGuardRows(); };
$('#optBlockUdpProxy').onchange = () => saveSettings({ blockUdpInProxyMode: $('#optBlockUdpProxy').checked });

/* kill switch toggle — read live when a drop happens, so it needs no reconnect */
$('#optKillSwitch').onchange = async () => {
  await saveSettings({ killSwitch: $('#optKillSwitch').checked });
  updateKillStatus();
  // kill switch uses the Windows firewall → needs admin (same as TUN)
  if ($('#optKillSwitch').checked && state.platform === 'win32' && !state.elevated) {
    if (await promptRelaunchAdmin()) return;
  }
};

/* auto-reconnect toggle — read live at recovery time, so it needs no reconnect */
$('#optNetAuto').onchange = () => saveSettings({ autoReconnectOnNetworkChange: $('#optNetAuto').checked });

function updateKillStatus() {
  const el = $('#killStatus');
  if (!el) return;
  if (!state.settings.killSwitch) { el.textContent = ''; el.className = 'tun-status'; return; }
  if (state.platform !== 'win32') { el.textContent = t('kill.winOnly'); el.className = 'tun-status warn'; return; }
  if (!state.elevated) { el.textContent = t('kill.needAdmin'); el.className = 'tun-status warn'; return; }
  el.textContent = t('kill.ready'); el.className = 'tun-status ok';
}

$('#optAllowLan').onchange = async () => {
  // the reconnect prompt (saveSettings) already explains that it isn't live yet
  await saveSettings({ allowLan: $('#optAllowLan').checked });
  updateLanInfo();
};

/** Show the address LAN clients should point their proxy at (when sharing). */
async function updateLanInfo() {
  const el = $('#lanInfo');
  if (!el) return;
  if (!state.settings.allowLan) { el.textContent = ''; el.className = 'tun-status'; return; }
  // when connected the live values come from the status event; otherwise ask main
  let info = (state.connected && state.lan && state.lan.ip) ? state.lan : null;
  if (!info) { try { info = await window.api.lanInfo(); } catch { info = null; } }
  if (info && info.ip) {
    el.innerHTML = `${escapeHtml(t('lan.address'))}: ` +
      `<b dir="ltr">${escapeHtml(info.ip)}:${info.httpPort}</b> (HTTP) • ` +
      `<b dir="ltr">${escapeHtml(info.ip)}:${info.socksPort}</b> (SOCKS)`;
    el.className = 'tun-status ok';
  } else {
    el.textContent = t('lan.noIp');
    el.className = 'tun-status warn';
  }
}
$('#btnSaveRules').onclick = async () => {
  const rules = textToCustomRules($('#customRules').value);
  await saveSettings({ customRules: rules });
  toast(t('t.rulesSaved') + ' (' + rules.length + ')', 'ok');
};

/* ----------------------------- servers ----------------------------- */
// Compact latency: drop the "ms", show seconds for slow results, × for failure.
function fmtMs(ms) {
  if (!Number.isFinite(ms) || ms < 0) return '×';
  return ms >= 1000 ? (ms / 1000).toFixed(1) + 's' : String(ms);
}
function pingLabel(id) {
  const p = state.pings[id] || {};
  const tcp = p.tcp;
  if (!tcp) return { txt: '—', cls: '' };
  return { txt: tcp.ok ? fmtMs(tcp.ms) : '×', cls: pingClass(tcp.ok ? tcp.ms : -1) };
}

/** Label for any ping result ({ ok, ms } or undefined). */
function pingResultLabel(res) {
  if (!res) return { txt: '—', cls: '' };
  return { txt: res.ok ? fmtMs(res.ms) : '×', cls: pingClass(res.ok ? res.ms : -1) };
}

/** Update every TCP + Real ping badge for an id from state.pings (everywhere). */
function applyPingDisplays(id) {
  const p = state.pings[id] || {};
  const tl = pingResultLabel(p.tcp);
  const rl = pingResultLabel(p.real);
  const ul = pingResultLabel(p.upload);
  $$(`[data-ping="${id}"]`).forEach(el => { el.textContent = tl.txt; el.className = (el.dataset.pbase || 'srv-ping') + (tl.cls ? ' ' + tl.cls : ''); });
  $$(`[data-ping-real="${id}"]`).forEach(el => { el.textContent = rl.txt; el.className = (el.dataset.pbase || 'srv-ping') + (rl.cls ? ' ' + rl.cls : ''); });
  $$(`[data-ping-up="${id}"]`).forEach(el => { el.textContent = ul.txt; el.className = (el.dataset.pbase || 'srv-ping') + (ul.cls ? ' ' + ul.cls : ''); });
  // quality dot: colour only, no text (TCP result drives it)
  $$(`[data-ping-dot="${id}"]`).forEach(el => { el.className = 'q-dot' + (tl.cls ? ' ' + tl.cls : ''); });
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

    const tl = pingResultLabel((state.pings[s.id] || {}).tcp);
    const rl = pingResultLabel((state.pings[s.id] || {}).real);
    const ul = pingResultLabel((state.pings[s.id] || {}).upload);
    const selBadge = isSel ? `<span class="sel-badge">✓ ${escapeHtml(t('srv.selected'))}</span>` : '';

    card.innerHTML = `
      <span class="q-dot ${tl.cls}" data-ping-dot="${s.id}"></span>
      <span class="proto-badge proto-${s.protocol}">${s.protocol}</span>
      <div class="srv-info">
        <div class="srv-name">${escapeHtml(s.name)} ${selBadge}</div>
        <div class="srv-addr">${escapeHtml(s.address)}:${s.port}</div>
      </div>
      <div class="stat-group">
        <span class="stat" title="${escapeHtml(t('ping.tcp'))}"><i>⚡</i><b class="stat-v ${tl.cls}" data-pbase="stat-v" data-ping="${s.id}">${tl.txt}</b></span>
        <span class="stat" title="${escapeHtml(t('ping.real'))}"><i>↓</i><b class="stat-v ${rl.cls}" data-pbase="stat-v" data-ping-real="${s.id}">${rl.txt}</b></span>
        <span class="stat" title="${escapeHtml(t('ping.upload'))}"><i>↑</i><b class="stat-v ${ul.cls}" data-pbase="stat-v" data-ping-up="${s.id}">${ul.txt}</b></span>
      </div>
      <div class="srv-actions">
        <button class="icon-btn ping-srv" data-i18n-title="btn.quickPing" title="ping">⚡</button>
        <button class="icon-btn copy-srv" data-i18n-title="btn.copy" title="copy">⧉</button>
        <button class="icon-btn qr-srv" data-i18n-title="btn.qr" title="QR">▦</button>
        <button class="icon-btn edit-srv" data-i18n-title="btn.edit" title="edit">✎</button>
        <button class="icon-btn connect-srv" title="▶">▶</button>
        <button class="icon-btn del-srv" title="🗑">🗑</button>
      </div>`;

    // clicking the card body selects the server (syncs with the home picker)
    card.querySelector('.srv-info').onclick = () => selectServer(s.id);
    card.querySelector('.proto-badge').onclick = () => selectServer(s.id);
    card.querySelector('.ping-srv').onclick = (e) => { e.stopPropagation(); pingServer(s.id); };
    card.querySelector('.copy-srv').onclick = (e) => { e.stopPropagation(); copyServerLink(s.id); };
    card.querySelector('.qr-srv').onclick = (e) => { e.stopPropagation(); showServerQr(s.id); };
    card.querySelector('.edit-srv').onclick = (e) => { e.stopPropagation(); openEdit(s.id); };
    card.querySelector('.connect-srv').onclick = (e) => { e.stopPropagation(); connect(s.id); };
    card.querySelector('.del-srv').onclick = (e) => { e.stopPropagation(); deleteServer(s.id); };
    list.appendChild(card);
  }
}

/* ----------------------------- unified picker (home) ----------------------------- */
const ADV_ID = '__advanced__';
const POOL_ID = '__pool__';
function chainById(id) { return state.chains.find(c => c.id === id); }
function isChainId(id) { return !!chainById(id); }
function chainMembers(c) { return ((c && c.members) || []).map(srvById).filter(Boolean); }
function chainReady(c) { return chainMembers(c).length >= 2; }
function anyChainReady() { return state.chains.some(chainReady); }
function isPseudo(id) { return id === ADV_ID || id === POOL_ID || isChainId(id); }

/** A pool target ('chain:<id>' or a server id) that currently resolves. */
function poolTargetValid(target) {
  if (!target) return false;
  if (String(target).startsWith('chain:')) return chainReady(chainById(String(target).slice(6)));
  return !!srvById(target);
}
function poolTargetLabel(target) {
  if (String(target).startsWith('chain:')) {
    const c = chainById(String(target).slice(6));
    return '⛓ ' + (c ? c.name : '—');
  }
  const s = srvById(target);
  return s ? s.name : '—';
}
/** Enabled pool entries with a valid target + port (connectable). */
function poolEnabledValid() {
  return state.pool.filter(e => e.enabled && e.socksPort && poolTargetValid(e.target));
}
function poolReady() { return poolEnabledValid().length > 0; }
function advancedReady() {
  return !!state.settings.advancedRouting &&
    (((state.settings.routeRules || []).length > 0) || !!state.settings.routeDefault);
}

function selectServer(id) {
  state.selectedServerId = id;
  renderServers();
  renderPicker();
  // immediate ping feedback for the chosen target (chains ping too; skip adv/pool)
  if (id && id !== ADV_ID && id !== POOL_ID && !state.pings[id]) pingServer(id);
}

function renderPicker() {
  const btnProto = $('#pickerProto');
  const btnName = $('#pickerName');
  const btnPing = $('#pickerPing');
  const menu = $('#pickerMenu');

  // drop a stale pseudo selection if its feature is no longer available
  if (isChainId(state.selectedServerId) && !chainReady(chainById(state.selectedServerId))) state.selectedServerId = null;
  if (state.selectedServerId === ADV_ID && !advancedReady()) state.selectedServerId = null;
  if (state.selectedServerId === POOL_ID && !poolReady()) state.selectedServerId = null;

  const selId = state.selectedServerId;
  const sel = state.servers.find(s => s.id === selId);
  const selChain = chainById(selId);
  const hasAny = state.servers.length || anyChainReady() || advancedReady() || poolReady();

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
  } else if (selId === POOL_ID) {
    btnProto.hidden = false;
    btnProto.textContent = '🧩';
    btnProto.className = 'proto-badge proto-pool';
    btnName.textContent = t('picker.pool') + ' (' + poolEnabledValid().length + ')';
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
    const tl = pingId ? pingResultLabel((state.pings[pingId] || {}).tcp) : null;
    const rl = pingId ? pingResultLabel((state.pings[pingId] || {}).real) : null;
    const ul = pingId ? pingResultLabel((state.pings[pingId] || {}).upload) : null;
    const row = document.createElement('div');
    row.className = 'picker-item' + (isSpecial ? ' picker-special' : '') + (id === selId ? ' active' : '');
    const pingPart = pingId
      ? `<span class="stat-group">` +
          `<span class="stat" title="${escapeHtml(t('ping.tcp'))}"><i>⚡</i><b class="stat-v ${tl.cls}" data-pbase="stat-v" data-ping="${id}">${tl.txt}</b></span>` +
          `<span class="stat" title="${escapeHtml(t('ping.real'))}"><i>↓</i><b class="stat-v ${rl.cls}" data-pbase="stat-v" data-ping-real="${id}">${rl.txt}</b></span>` +
          `<span class="stat" title="${escapeHtml(t('ping.upload'))}"><i>↑</i><b class="stat-v ${ul.cls}" data-pbase="stat-v" data-ping-up="${id}">${ul.txt}</b></span>` +
        `</span>` +
        `<button class="pi-ping-btn" title="ping">⚡</button>`
      : '';
    const dot = pingId ? `<span class="q-dot ${tl.cls}" data-ping-dot="${id}"></span>` : '<span class="q-dot"></span>';
    row.innerHTML = `${dot}${badgeHtml}<span class="pi-name">${escapeHtml(name)}</span>${pingPart}`;
    row.onclick = () => { selectServer(id); closePicker(); };
    const pb = row.querySelector('.pi-ping-btn');
    if (pb) pb.onclick = (e) => { e.stopPropagation(); pingServer(id); };
    menu.appendChild(row);
  };

  if (poolReady()) addRow(POOL_ID, '<span class="proto-badge proto-pool">🧩</span>', t('picker.pool') + ' (' + poolEnabledValid().length + ')', null, true);
  if (advancedReady()) addRow(ADV_ID, '<span class="proto-badge proto-advanced">🧭</span>', t('picker.advanced'), null, true);
  for (const c of state.chains) {
    if (chainReady(c)) addRow(c.id, '<span class="proto-badge proto-chain">⛓</span>', c.name, c.id, true);
  }
  for (const s of state.servers) {
    addRow(s.id, `<span class="proto-badge proto-${s.protocol}">${escapeHtml(s.protocol)}</span>`, s.name, s.id, false);
  }
}

/** Ping every server + ready chain shown in the picker (TCP + real delay). */
async function pingAllVisible() {
  await pingMany([...state.servers.map(s => s.id), ...state.chains.filter(chainReady).map(c => c.id)]);
}

function openPicker() { if (state.servers.length || anyChainReady() || advancedReady() || poolReady()) $('#pickerMenu').hidden = false; }
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

// v2rayN-style HTTP proxy share link (`http://[b64creds@]host:port#name`): no
// path, no query. Everything else that starts with http(s):// is a subscription.
// The userinfo is either a standard-alphabet base64 blob (which may contain '/')
// or a plain `user:pass`; the host never contains a '/', so a subscription URL
// with an '@' in its path still fails to match.
// Keep in sync with HTTP_PROXY_LINK in src/main/parser.js.
const HTTP_PROXY_LINK = /^http:\/\/(?:(?:[A-Za-z0-9+/=]+|[^/?#\s@]+)@)?[^/?#\s@]+:\d{1,5}(?:#\S*)?$/i;

/**
 * Smart import: figures out what was pasted and routes it correctly.
 *  - http(s) lines  -> added & fetched as subscriptions (auto-update capable)
 *  - vless/vmess/…  -> imported as servers
 *  - http proxy link -> imported as a server (see HTTP_PROXY_LINK above)
 *  - base64 blob    -> decoded & imported as servers (handled by parseMany)
 * Mixed input works too (URLs become subs, the rest become servers).
 */
async function smartImport(text) {
  text = String(text || '').trim();
  if (!text) return;
  // A pasted WireGuard .conf is one multi-line config, not a list of links —
  // hand the whole blob to parseMany (main-side) before the per-line split.
  if (/^\s*\[interface\]/im.test(text) && /^\s*\[peer\]/im.test(text)) {
    const res = await window.api.importServers(text);
    state.servers = res.servers;
    if (!state.selectedServerId && state.servers.length) state.selectedServerId = state.servers[0].id;
    renderServers(); renderPicker(); renderChains(); renderPool();
    const failed = (res.errors || []).length;
    toast(failed ? `${t('t.failed')}: ${res.errors[0].error}` : t('t.wgAdded'), failed ? 'err' : 'ok');
    return;
  }
  const lines = text.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
  const isSubUrl = (l) => /^https?:\/\//i.test(l) && !HTTP_PROXY_LINK.test(l);
  const urlLines = lines.filter(isSubUrl);
  const configText = lines.filter(l => !isSubUrl(l)).join('\n');

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
  renderServers(); renderPicker(); renderSubs(); renderChains(); renderPool();

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
  // ignore unrelated clipboard text; a .conf blob counts as importable too
  const looksImportable = /^(https?:\/\/|vless:\/\/|vmess:\/\/|trojan:\/\/|ss:\/\/|socks:\/\/|socks5:\/\/|wireguard:\/\/|wg:\/\/)/im.test(text.trim())
    || /[A-Za-z0-9+/=]{24,}/.test(text.trim())
    || (/^\s*\[interface\]/im.test(text) && /^\s*\[peer\]/im.test(text));
  if (!looksImportable) return;
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
  renderServers(); renderAdvanced();
  renderPicker();
  renderChains();
  renderPool();
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
  renderPool();
  toast(t('t.allServersDeleted'));
};

/* ----------------------------- ping ----------------------------- */
// A config's TCP ping can be open even when the config is dead; the REAL delay
// actually dials through the config (a throwaway xray) and times a request — so
// a real-delay number is proof the config truly works. We measure & show BOTH
// everywhere (server cards, picker rows, chain cards).
function setPingPending(id) {
  $$(`[data-ping="${id}"], [data-ping-real="${id}"], [data-ping-up="${id}"]`).forEach(el => {
    el.textContent = '...'; el.className = (el.dataset.pbase || 'srv-ping');
  });
}

// Mark ONLY the cell of the phase currently being measured, so it's obvious
// whether the download (⏱/↓) or the upload (↑) test is running right now.
function setPhasePending(id, attr) {
  $$(`[${attr}="${id}"]`).forEach(el => { el.textContent = '...'; el.className = (el.dataset.pbase || 'srv-ping'); });
}

/** Ping ONE target: TCP, then real DOWNLOAD delay, then UPLOAD delay. */
async function pingServer(id) {
  setPingPending(id);
  const tcp = await window.api.pingTcp(id);
  state.pings[id] = Object.assign(state.pings[id] || {}, { tcp });
  applyPingDisplays(id);
  setPhasePending(id, 'data-ping-real');           // ← testing download now
  const real = await window.api.pingReal(id);
  state.pings[id] = Object.assign(state.pings[id] || {}, { real });
  applyPingDisplays(id);
  setPhasePending(id, 'data-ping-up');             // ← testing upload now
  const upload = await window.api.pingUpload(id);
  state.pings[id] = Object.assign(state.pings[id] || {}, { upload });
  applyPingDisplays(id);
  if (id === state.selectedServerId) renderPicker();
  return { tcp, real, upload };
}

async function pingTcpOnly(id) {
  const tcp = await window.api.pingTcp(id);
  state.pings[id] = Object.assign(state.pings[id] || {}, { tcp });
  applyPingDisplays(id);
  return tcp;
}
async function pingRealOnly(id) {
  const real = await window.api.pingReal(id);
  state.pings[id] = Object.assign(state.pings[id] || {}, { real });
  applyPingDisplays(id);
  return real;
}

/** Ping many: TCP for all in parallel (fast), then Real delay sequentially
 * (each spins a throwaway xray, so don't launch them all at once). */
async function pingMany(ids) {
  ids = [...new Set(ids.filter(Boolean))];
  if (!ids.length) return;
  toast(t('t.pingingAll'));
  ids.forEach(setPingPending);
  await Promise.all(ids.map(pingTcpOnly));
  for (const id of ids) await pingRealOnly(id);
  renderPicker();
  toast(t('t.testDone'), 'ok');
}

$('#btnPingAll').onclick = () => pingMany(state.servers.map(s => s.id));

/* quick ping (home) — fills the TCP ping + Real delay cards for one target */
async function quickPing(id) {
  if (!id || id === ADV_ID || id === POOL_ID) return;
  $('#statTcp').textContent = '...';
  $('#statReal').textContent = '...';
  const tcp = await window.api.pingTcp(id);
  $('#statTcp').textContent = tcp.ok ? tcp.ms + 'ms' : t('t.error');
  const real = await window.api.pingReal(id);
  $('#statReal').textContent = real.ok ? real.ms + 'ms' : t('t.error');
  state.pings[id] = Object.assign(state.pings[id] || {}, { tcp, real });
  applyPingDisplays(id);
  renderPicker();
}
$('#btnQuickPing').onclick = () => {
  const id = state.selectedServerId;
  if (!id) return toast(t('t.noServerSel'), 'err');
  quickPing(id);
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
  // TUN wanted but not elevated (Windows): offer to relaunch as admin first.
  if (state.settings.tunMode && state.tunAvailable && !state.elevated && state.platform === 'win32') {
    if (await promptRelaunchAdmin()) return;
  }
  selectServer(id);
  state.connecting = true;
  setConnUI('connecting', id);
  try {
    await window.api.connect(id);
  } catch (e) {
    state.connecting = false;
    setConnUI('error');
    toast(t('t.connectFailed') + ': ' + e.message, 'err');
    // the official core refused a plaintext config and the fork is not installed
    if (/Xray-PattN/.test(e.message) && !(state.assets && state.assets['xray-pattn'])) openFilesModal(['xray-pattn']);
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
  } else if (effId === POOL_ID) {
    const list = poolEnabledValid();
    srv.textContent = '🧩 ' + t('picker.pool') + ' — ' +
      (list.map(e => `${e.name}:${e.socksPort}`).join(' · ') || '—');
  } else {
    const server = state.servers.find(s => s.id === effId);
    srv.textContent = server ? `${server.name} — ${server.address}:${server.port}` : t('conn.noServer');
  }

  // which of the two Xray cores (or sing-box) the live tunnel actually runs on —
  // the backend may have fallen back to the fork for a plaintext config
  if (stateStr === 'connected' && state.activeEngine) {
    srv.textContent += ` · ${t('conn.engine')}: ${state.activeEngine === 'xray-pattn' ? t('engine.pattn') : state.activeEngine === 'sing-box' ? 'sing-box' : t('engine.official')}`;
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

  // tint the titlebar + logo badge by connection state
  const tb = $('#titlebar');
  if (tb) {
    tb.classList.toggle('conn-on', stateStr === 'connected');
    tb.classList.toggle('conn-wait', stateStr === 'connecting');
    tb.classList.toggle('conn-off', stateStr !== 'connected' && stateStr !== 'connecting');
  }
}

/* status events from main */
window.api.onStatus((d) => {
  if (d.state === 'connected') {
    state.connected = true;
    state.connecting = false;
    state.activeServerId = d.serverId;
    state.lan = d.lan || null;
    // a fresh connect is built from the current settings — nothing is stale
    setPending(d.pendingReconnect || []);
    state.activeEngine = d.engine || '';
    setConnUI('connected', d.serverId);
    // only say "reconnected" when we actually were recovering from a network change
    if (state.wasReconnecting) { toast(t('net.reconnected'), 'ok'); state.wasReconnecting = false; }
    setModeWidget();
    updateLanInfo();
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
    // auto-measure TCP ping + real delay for the active config so the home
    // cards show real numbers (real delay = proof the config actually works)
    setTimeout(() => quickPing(d.serverId), 700);
  } else if (d.state === 'connecting') {
    state.connecting = true;
    setConnUI('connecting', d.serverId);
    // the rebuild reapplyConnection() runs is still part of the recovery — keep
    // saying so instead of flashing a bare "Connecting…"
    if (state.wasReconnecting) $('#connState').textContent = t('state.reconnecting');
  } else if (d.state === 'disconnected') {
    state.connected = false;
    state.connecting = false;
    state.wasReconnecting = false;   // no live tunnel left to recover
    state.lan = null;
    state.activeEngine = '';
    setPending([]);          // nothing live to be out of sync with
    setConnUI('disconnected');
    $('#statIp').textContent = '—';
    hideGeo();
    resetTraffic();
    setModeWidget();
    updateLanInfo();
    renderServers();
    renderPicker();
  } else if (d.state === 'reconnecting') {
    // the machine's network moved under the tunnel; main is rebuilding it
    // There is no tunnel right now — the rebuild tore it down. Leaving
    // `connected` true made the power button offer "disconnect" and the pill say
    // connected while the pill text said reconnecting; the two must agree.
    state.connected = false;
    state.connecting = true;
    state.wasReconnecting = true;
    setConnUI('connecting', d.serverId || state.activeServerId);
    $('#connState').textContent = t('state.reconnecting');
  } else if (d.state === 'reconnect-failed') {
    // every retry is spent — the user has to act
    state.connecting = false;
    state.wasReconnecting = false;
    if (d.proxyUp) {
      // The tunnel itself came back and only TUN did not: xray is running and the
      // proxy ports work, so the red error state would be wrong. Stay connected
      // and say what is actually missing.
      state.connected = true;
      setConnUI('connected', state.activeServerId);
      toast(t('net.tunFailed'), 'warn', 8000);
      if (d.tunError) appendLog('Reconnect gave up on TUN: ' + d.tunError, 'warn');
      updateAdminBtn(true);
    } else {
      state.connected = false;
      setConnUI('error');
      toast(t('net.failed'), 'err', 8000);
    }
  } else if (d.state === 'error') {
    // e.g. a settings reconnect whose new config the core rejected
    state.connected = false;
    state.connecting = false;
    setConnUI('error');
    renderPendingBanner();
    renderServers();
    renderPicker();
  }
});

window.api.onXrayStatus((d) => {
  if (d.state === 'stopped' && state.connected) {
    state.connected = false;
    setConnUI('disconnected');
    renderPendingBanner();
    renderServers();
    renderPicker();
    toast(t('t.disconnected'), 'err');
  }
});

/* ----------------------------- saved data ----------------------------- */
/**
 * The store file holds every server, subscription and chain, so a read or write
 * failure is never just a log line — it is shown, and kept on screen long enough
 * to actually read. Main writes the details (including where the unreadable file
 * was preserved) to the log, which is why these point at the Logs page.
 */
function reportStoreError(d) {
  if (!d) return;
  if (d.kind === 'save') {
    appendLog('Could not write saved data to disk: ' + (d.reason || ''), 'error');
    return toast(t('store.saveFailed'), 'err', 9000);
  }
  // A load error happens before this window exists, so main's own log line was
  // emitted with nobody listening — write the details here instead, otherwise
  // the toast would point at a Logs page that never got them.
  appendLog('Saved data could not be read: ' + (d.reason || ''), 'error');
  if (d.backup) appendLog('The unreadable file was kept at: ' + d.backup, 'warn');
  if (d.recovered) appendLog('Recovered from the unsaved copy (store.json.tmp)', 'warn');
  toast(d.recovered ? t('store.recovered') : t('store.lost'), 'err', 12000);
}
window.api.onStoreError(reportStoreError);

/* ----------------------------- kill switch ----------------------------- */
window.api.onKillSwitch((d) => {
  state.killEngaged = !!(d && d.engaged);
  const banner = $('#killBanner');
  if (banner) banner.hidden = !state.killEngaged;
  if (state.killEngaged) toast(t('kill.blocked'), 'err');
});
$('#killDisarm').onclick = async () => {
  // full teardown so the machine returns to normal direct internet
  // (removes the firewall block AND any leftover TUN routes / system proxy)
  await window.api.disconnect();
  state.killEngaged = false;
  $('#killBanner').hidden = true;
  toast(t('kill.opened'), 'ok');
};
$('#killReconnect').onclick = async () => {
  const id = state.activeServerId || state.selectedServerId || (state.servers[0] && state.servers[0].id);
  await window.api.disconnect();
  state.killEngaged = false;
  $('#killBanner').hidden = true;
  if (id) connect(id);
};

/* ----------------------------- logs ----------------------------- */
const MAX_LOG_LINES = 500;
function appendLog(text, level = 'log') {
  const box = $('#logBox');
  const line = document.createElement('div');
  line.className = 'log-' + level;
  line.textContent = text;
  box.appendChild(line);
  while (box.childNodes.length > MAX_LOG_LINES) box.removeChild(box.firstChild);
  box.scrollTop = box.scrollHeight;
}
window.api.onLog((d) => appendLog(d.line, d.level || 'log'));
$('#btnClearLogs').onclick = () => { $('#logBox').innerHTML = ''; };

/* ----------------------------- xray binary ----------------------------- */
/**
 * Is ANY Xray-format core installed? The official core and the PattN fork run
 * the exact same config, so either one makes the app usable — a fork-only user
 * must not be told "Xray core not found".
 */
function anyXrayCore() {
  const a = state.assets || {};
  return !!(a.xray || a['xray-pattn']);
}

/** @param {boolean} ready any Xray-format core installed (see anyXrayCore) */
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
  { key: 'xray', label: 'comp.xray', ver: 'xray' },
  { key: 'xray-pattn', label: 'comp.xrayPattn', ver: 'xray-pattn' },
  { key: 'sing-box', label: 'comp.singbox', has: (a) => !!a['sing-box'] },
  { key: 'geo', label: 'comp.geo', has: (a) => a.geoip && a.geosite },
  { key: 'tun2socks', label: 'comp.tun2socksLegacy' },
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
    const v = c.ver && present ? state.coreVersions[c.ver] : '';
    const ver = v ? ` <span class="comp-ver">v${escapeHtml(v)}</span>` : '';
    const row = document.createElement('div');
    row.className = 'comp-row';
    row.innerHTML = `
      <div class="comp-info">
        <span class="comp-dot ${present ? 'ok' : 'missing'}"></span>
        <span class="comp-name">${escapeHtml(t(c.label))}${ver}</span>
        <span class="comp-state ${present ? 'ok' : 'missing'}">${present ? t('comp.installed') : t('comp.missing')}</span>
      </div>
      <button class="btn ${present ? 'ghost' : 'primary'} comp-btn">${present ? t('btn.update') : t('btn.download')}</button>`;
    const btn = row.querySelector('.comp-btn');
    btn.onclick = () => downloadComponent(c.key, btn);
    list.appendChild(row);
  }

  // the Routing page's "download geo files" note is a static hint today and
  // shows even when both files are installed — tie it to the real state
  const note = $('#routingGeoNote');
  if (note) note.hidden = !!(a.geoip && a.geosite);

  // What TUN needs, from the one flag that knows both backends (assets.tunReady:
  // sing-box OR tun2socks, plus wintun on Windows). Older mains do not send it —
  // then say nothing rather than guess from a single component.
  const tunNote = $('#compTunNote');
  if (tunNote) tunNote.hidden = typeof a.tunReady !== 'boolean' || a.tunReady;
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
    if (key === 'xray' || key === 'xray-pattn') refreshXrayVersion();
    toast(t('t.downloaded'), 'ok');
  } else {
    state.assets = res.assets || state.assets;
    renderComponents();
    toast(t('t.downloadFailed') + ': ' + (res.error || ''), 'err');
  }
}

window.api.onAssetProgress((d) => {
  // surface coarse progress through the toast + the files modal if open
  toast(`${t('t.downloading')} ${d.component}: ${d.pct}%`);
  const fp = $('#filesProgress');
  if (fp && !$('#filesModal').hidden) fp.textContent = `${t('t.downloading')} ${d.component}: ${d.pct}%`;
});

/* remove all downloaded runtime files */
$('#btnRemoveFiles').onclick = async () => {
  if (state.connected) return toast(t('comp.removeBusy'), 'err');
  if (!window.confirm(t('comp.removeConfirm'))) return;
  const res = await window.api.removeAssets();
  if (res && res.ok) {
    state.assets = res.assets || state.assets;
    state.tunAvailable = !!res.tunAvailable;
    renderComponents();
    updateXrayStatus(res.xrayReady);
    updateTunStatus();
    refreshXrayVersion();
    const n = (res.removed || []).length;
    toast(n ? `${t('comp.removed')} (${n})` : t('comp.removeNone'), n ? 'ok' : '');
  } else {
    toast(t('comp.removeFailed') + (res && res.error ? ': ' + res.error : ''), 'err');
  }
};

/* ----------------------------- app update check ----------------------------- */
let updateInfo = null;
$('#btnCheckUpdate').onclick = async () => {
  const st = $('#updateStatus');
  const btn = $('#btnCheckUpdate');
  btn.disabled = true;
  st.textContent = t('about.checking');
  st.className = 'update-status';
  try {
    const res = await window.api.checkUpdate();
    if (!res || !res.ok) {
      st.textContent = t('about.checkFailed') + (res && res.error ? ': ' + res.error : '');
      st.className = 'update-status warn';
    } else if (res.hasUpdate) {
      updateInfo = res;
      st.textContent = `${t('about.newVersion')} ${res.latest} (${t('about.current')} ${res.current})`;
      st.className = 'update-status ok';
      $('#btnDownloadUpdate').hidden = false;
    } else {
      st.textContent = t('about.upToDate') + ' (v' + res.current + ')';
      st.className = 'update-status ok';
      $('#btnDownloadUpdate').hidden = true;
    }
  } catch (e) {
    st.textContent = t('about.checkFailed') + ': ' + e.message;
    st.className = 'update-status warn';
  } finally {
    btn.disabled = false;
  }
};
$('#btnDownloadUpdate').onclick = () => {
  const url = (updateInfo && updateInfo.url) || 'https://github.com/sadrazkh/Irnetfree_xray-client/releases/latest';
  window.api.openExternal(url);
  toast(t('about.opening'));
};

/* ----------------------------- first-run required files modal ----------------------------- */
function missingEssentials() {
  const a = state.assets || {};
  const isWin = state.platform === 'win32';
  const want = state.settings.tunMode;   // tun files only matter if TUN is on
  const list = [];
  if (!anyXrayCore()) list.push('xray');
  if (!(a.geoip && a.geosite)) list.push('geo');
  if (want && !a.tun2socks) list.push('tun2socks');
  if (want && isWin && !a.wintun) list.push('wintun');
  return list;
}

function maybePromptMissingFiles() {
  const missing = missingEssentials();
  // Only auto-prompt when the core (xray) is missing — geo/tun are optional and
  // already surfaced in Settings → Required files.
  if (!missing.includes('xray')) return;
  openFilesModal(missing);
}

const COMP_LABEL = {
  xray: 'comp.xray', 'xray-pattn': 'comp.xrayPattn',
  geo: 'comp.geo', tun2socks: 'comp.tun2socks', wintun: 'comp.wintun'
};

function openFilesModal(missing) {
  const listEl = $('#filesList');
  listEl.innerHTML = '';
  for (const key of missing) {
    const row = document.createElement('div');
    row.className = 'files-row';
    row.innerHTML = `<span class="files-dot missing"></span><span class="files-name">${escapeHtml(t(COMP_LABEL[key] || key))}</span>`;
    listEl.appendChild(row);
  }
  $('#filesProgress').textContent = '';
  $('#filesModal').dataset.missing = missing.join(',');
  $('#filesModal').hidden = false;
}
function closeFilesModal() { $('#filesModal').hidden = true; }
$('#filesClose').onclick = closeFilesModal;
$('#filesLater').onclick = closeFilesModal;
$('#filesModal').onclick = (e) => { if (e.target === $('#filesModal')) closeFilesModal(); };

$('#filesDownload').onclick = async () => {
  const missing = ($('#filesModal').dataset.missing || '').split(',').filter(Boolean);
  const btn = $('#filesDownload');
  btn.disabled = true;
  for (const key of missing) {
    $('#filesProgress').textContent = `${t('t.downloading')} ${t(COMP_LABEL[key] || key)}…`;
    const res = await window.api.downloadAsset(key);
    if (res && res.ok) {
      state.assets = res.assets || state.assets;
      state.tunAvailable = !!res.tunAvailable;
    } else {
      $('#filesProgress').textContent = t('t.downloadFailed') + ': ' + ((res && res.error) || '');
      btn.disabled = false;
      renderComponents();
      updateXrayStatus(anyXrayCore());
      return;
    }
  }
  btn.disabled = false;
  renderComponents();
  updateXrayStatus(anyXrayCore());
  updateTunStatus();
  refreshXrayVersion();
  closeFilesModal();
  toast(t('t.downloaded'), 'ok');
};

/* ----------------------------- TUN mode ----------------------------- */
/**
 * TUN needs Administrator on Windows. When the user wants TUN but we're not
 * elevated, offer to close and relaunch elevated right away. Returns true if a
 * relaunch was started (the app is quitting), so callers should stop.
 */
async function promptRelaunchAdmin() {
  if (state.platform !== 'win32' || state.elevated) return false;
  const ok = window.confirm(t('tun.relaunchConfirm'));
  if (!ok) return false;
  const res = await window.api.relaunchAdmin();
  if (!res || !res.ok) { toast((res && res.error) || t('t.adminFailed'), 'err'); return false; }
  return true;
}

$('#optTun').onchange = async () => {
  const on = $('#optTun').checked;
  if (on && !state.tunAvailable) toast(t('t.tunNeedFiles'), 'err');
  // save silently first: relaunching as admin restarts the app, so asking about a
  // reconnect before that question is answered would be pointless
  await saveSettings({ tunMode: on }, { silent: true });
  updateTunStatus();
  if (on && state.tunAvailable && !state.elevated && state.platform === 'win32') {
    if (await promptRelaunchAdmin()) return;
  }
  if (state.pendingReconnect.length) await promptApplySettings();
};

function updateTunStatus() {
  // the guard/UDP rows follow the TUN switch, and every caller here has just
  // flipped it (settings switch, mode modal, a component download)
  updateGuardRows();
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
        ${subUsageHtml(sub)}
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
    renderSubs(); renderServers(); renderPicker(); renderChains(); renderPool();
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
    renderSubs(); renderServers(); renderPicker(); renderChains(); renderPool();
    toast(`${t('t.updated')} — ${res.added} ${t('sub.servers')}`, 'ok');
  } catch (e) {
    toast(t('t.failed') + ': ' + e.message, 'err');
  }
}

async function removeSub(id) {
  const res = await window.api.removeSub(id);
  state.subscriptions = res.subs;
  state.servers = res.servers;
  renderSubs(); renderServers(); renderPicker(); renderChains(); renderPool();
  toast(t('t.subRemoved'));
}

$('#btnRefreshAll').onclick = async () => {
  if (!state.subscriptions.length) return toast(t('t.noSubs'), 'err');
  toast(t('t.updating'));
  const res = await window.api.refreshAllSubs();
  state.subscriptions = res.subs;
  state.servers = res.servers;
  renderSubs(); renderServers(); renderPicker(); renderChains(); renderPool();
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
  renderSubs(); renderServers(); renderPicker(); renderChains(); renderPool();
});

/* ----------------------------- edit server modal ----------------------------- */
let editOriginal = null;
let editClearPin = false;   // "clear pin" pressed in the open edit form

function readServerFields(s) {
  const ob = s.outbound || {};
  const st = ob.streamSettings || {};
  const f = {
    name: s.name, address: s.address, port: s.port,
    network: st.network || 'tcp', security: st.security || 'none',
    sni: '', host: '', path: '', fp: '', pbk: '', sid: '', alpn: '',
    allowInsecure: false, cred: '', method: '',
    fragment: ob._fragment || '',
    noise: ob._noise || '',
    cipherSuites: (st.tlsSettings && st.tlsSettings.cipherSuites) || '',
    finalMask: st.finalmask ? JSON.stringify(st.finalmask) : '',
    engine: s.engine || 'xray',
    certPin: s.certPin || ''
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
  } else if (s.protocol === 'socks' || s.protocol === 'http') {
    const srv = ob.settings && ob.settings.servers && ob.settings.servers[0];
    const u = srv && srv.users && srv.users[0];
    f.pxUser = u ? (u.user || '') : '';
    f.pxPass = u ? (u.pass || '') : '';
  } else if (s.protocol === 'wireguard') {
    f.cred = (ob.settings && ob.settings.secretKey) || '';
    const peer = ob.settings && ob.settings.peers && ob.settings.peers[0];
    f.wgPub = peer ? peer.publicKey : '';
    f.wgPsk = peer ? (peer.preSharedKey || '') : '';
    f.wgAddr = (ob.settings && ob.settings.address || []).join(',');
    f.wgMtu = (ob.settings && ob.settings.mtu) || 1420;
    f.wgReserved = (ob.settings && ob.settings.reserved || []).join(',');
    f.wgAllowed = (peer && peer.allowedIPs || []).join(', ');
    // One field, as wg-quick writes it: resolvers first, then search domains.
    f.wgDns = [...(Array.isArray(s.dns) ? s.dns : []), ...(Array.isArray(s.dnsDomains) ? s.dnsDomains : [])].join(', ');
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

// Anti-DPI noise: preset keywords the dropdown maps to; anything else is Custom.
const NOISE_PRESET_KEYS = ['random', 'faketls', 'fakehello'];

// Populate the noise <select> + custom text field from a stored spec.
function setNoiseFields(noise) {
  const sel = $('#edNoise'); const custom = $('#edNoiseCustom');
  if (!sel) return;
  const nz = String(noise || '').trim();
  const key = nz.toLowerCase();
  if (!nz) { sel.value = 'off'; if (custom) custom.value = ''; }
  else if (NOISE_PRESET_KEYS.includes(key)) { sel.value = key === 'fakehello' ? 'faketls' : key; if (custom) custom.value = ''; }
  else { sel.value = 'custom'; if (custom) custom.value = nz; }
  syncNoiseCustom();
}

// Read the effective noise spec from the dropdown (+ custom field when Custom).
function readNoiseField() {
  const sel = $('#edNoise'); if (!sel) return '';
  const v = sel.value;
  if (v === 'off') return '';
  if (v === 'custom') return ($('#edNoiseCustom').value || '').trim();
  return v; // preset keyword, expanded at build time
}

// Show the custom spec input only when the dropdown is set to Custom.
function syncNoiseCustom() {
  const sel = $('#edNoise'); if (!sel) return;
  show('#edNoiseCustomRow', sel.value === 'custom');
}

/* --------------------- copy / QR share link (carries ALL settings) --------------------- */
async function copyServerLink(id) {
  try {
    const link = await window.api.serverLink(id);
    if (!link) return toast('—', 'err');
    await copyText(link);
    toast(t('t.copied') || 'Copied ✓', 'ok');
  } catch (e) { toast('copy failed', 'err'); }
}
async function copyText(text) {
  try { await navigator.clipboard.writeText(text); }
  catch { const ta = document.createElement('textarea'); ta.value = text; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); ta.remove(); }
}
async function showServerQr(id) {
  const link = await window.api.serverLink(id);
  if (!link) return toast('—', 'err');
  const box = $('#qrImage'); box.innerHTML = '';
  try {
    const qr = qrcode(0, 'L'); qr.addData(link); qr.make();
    box.innerHTML = qr.createImgTag(4, 6);
  } catch (e) {
    box.innerHTML = '<p class="hint" style="padding:24px 8px">' + (t('qr.tooBig') || 'Link too long for a QR — use Copy.') + '</p>';
  }
  $('#qrLink').value = link;
  $('#qrModal').hidden = false;
}
if ($('#qrClose')) $('#qrClose').onclick = () => { $('#qrModal').hidden = true; };
if ($('#qrModal')) $('#qrModal').onclick = (e) => { if (e.target === $('#qrModal')) $('#qrModal').hidden = true; };
if ($('#qrCopy')) $('#qrCopy').onclick = () => { copyText($('#qrLink').value); toast(t('t.copied') || 'Copied ✓', 'ok'); };

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
  $('#edFragment').value = f.fragment || '';
  setNoiseFields(f.noise || '');
  if ($('#edCipherSuites')) $('#edCipherSuites').value = f.cipherSuites || '';
  if ($('#edFinalMask')) $('#edFinalMask').value = f.finalMask || '';
  if ($('#edEngine')) $('#edEngine').value = f.engine || 'xray';
  $('#edInsecure').checked = !!f.allowInsecure;
  // The certificate pinned on first use stands in for "allow insecure" now
  // (certPin.js). Shown abbreviated, the full hash in the tooltip; clearing it
  // makes the next connect read the certificate again.
  editClearPin = false;
  $('#edCertPin').textContent = f.certPin ? f.certPin.slice(0, 6) + '…' + f.certPin.slice(-4) : '';
  $('#edCertPin').title = f.certPin || '';

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
  const isProxy = proto === 'socks' || proto === 'http';
  show('#edTransportRow', isStd);
  show('#edTlsRow', isStd);
  show('#edPathRow', isStd);
  show('#edPattWrap', isStd);
  show('#edInsecureRow', isStd);
  show('#edInsecureHint', isStd);
  show('#edCertPinRow', isStd && !!f.certPin);
  show('#edWgExtra', isWg);
  show('#edProxyRow', isProxy);
  // socks/http carry no single "credential" field — user/pass live in edProxyRow
  show('#edCredWrap', !isProxy);
  $('#edRealityRow').hidden = !(isStd && $('#edSecurity').value === 'reality');
  updateSpoofLabels();

  if (isProxy) {
    $('#edProxyUser').value = f.pxUser || '';
    $('#edProxyPass').value = f.pxPass || '';
  }

  if (isWg) {
    $('#edWgPub').value = f.wgPub || '';
    $('#edWgAddr').value = f.wgAddr || '';
    $('#edWgPsk').value = f.wgPsk || '';
    $('#edWgMtu').value = f.wgMtu || 1420;
    $('#edWgReserved').value = f.wgReserved || '';
    $('#edWgAllowed').value = f.wgAllowed || '';
    $('#edWgDns').value = f.wgDns || '';
  }

  $('#editModal').hidden = false;
}

function show(sel, on) { const el = $(sel); if (el) el.hidden = !on; }

/**
 * Make the SNI section speak the truth for the current security+transport, so
 * the user knows exactly what to type (and the "two SNIs" confusion is gone):
 *  - REALITY  → SNI must match the server's serverNames (not a free fake)
 *  - TLS + ws/grpc/xhttp/h2 (frontable) → Front SNI (censor+CDN see this) + Host = real backend
 *  - TLS + tcp → SNI must match the server certificate
 *  - none → no TLS SNI at all (section hidden)
 */
function updateSpoofLabels() {
  const isStd = editOriginal && ['vless', 'vmess', 'trojan'].includes(editOriginal.protocol);
  const sec = $('#edSecurity').value || 'none';
  const net = $('#edNetwork').value || 'tcp';
  const on = isStd && (sec === 'tls' || sec === 'reality');
  show('#edSpoofHead', on); show('#edTlsRow', on);
  show('#edHideSniRow', on);
  const hintEl = $('#edSpoofHint'); if (hintEl) hintEl.hidden = !on;
  if (!on) return;

  const frontable = ['ws', 'grpc', 'xhttp', 'splithttp', 'h2', 'http'].includes(net);
  let head, sni, hint, showHost;
  if (sec === 'reality') { head = 'spoof.realityTitle'; sni = 'spoof.realitySni'; hint = 'spoof.realityHint'; showHost = false; }
  else if (frontable) { head = 'spoof.frontTitle'; sni = 'spoof.frontSni'; hint = 'spoof.frontHint'; showHost = true; }
  else { head = 'spoof.tlsTitle'; sni = 'spoof.tlsSni'; hint = 'spoof.tlsHint'; showHost = false; }

  $('#edSpoofHeadText').textContent = t(head);
  $('#edSniLabel').textContent = t(sni);
  $('#edHostLabel').textContent = t('spoof.frontHost');
  $('#edSpoofHint').textContent = t(hint);
  const hostWrap = $('#edHostWrap'); if (hostWrap) hostWrap.style.display = showHost ? '' : 'none';

  // bypass controls (all TLS/reality): the Hide-SNI toggle reflects the
  // fragment state.
  $('#edHideSniLabel').textContent = t('spoof.hideSni');
  $('#edHideSni').checked = !!($('#edFragment').value || '').trim();
}

// The default SNI-hiding fragment (patterniha-style: fragment the ClientHello
// so DPI can't read the SNI). Editable later in Advanced → Fragment.
const HIDE_SNI_FRAGMENT = 'tlshello,100-200,10-20';

$('#edSecurity').onchange = () => {
  const isStd = editOriginal && ['vless', 'vmess', 'trojan'].includes(editOriginal.protocol);
  $('#edRealityRow').hidden = !(isStd && $('#edSecurity').value === 'reality');
  updateSpoofLabels();
};
$('#edNetwork').onchange = () => updateSpoofLabels();
// Hide-SNI toggle drives the (advanced) Fragment field with a sensible default.
if ($('#edHideSni')) $('#edHideSni').onchange = () => {
  const frag = $('#edFragment');
  if ($('#edHideSni').checked) { if (!frag.value.trim()) frag.value = HIDE_SNI_FRAGMENT; }
  else frag.value = '';
};

function closeEdit() { $('#editModal').hidden = true; state.editingId = null; editOriginal = null; editClearPin = false; }

// The pin goes when the form is saved; until then the row just disappears.
$('#edCertPinClear').onclick = () => { editClearPin = true; show('#edCertPinRow', false); };
$('#editClose').onclick = closeEdit;
$('#editCancel').onclick = closeEdit;
$('#editModal').onclick = (e) => { if (e.target === $('#editModal')) closeEdit(); };
if ($('#edNoise')) $('#edNoise').onchange = syncNoiseCustom;

$('#editSave').onclick = async () => {
  const id = state.editingId;
  if (!id || !editOriginal) return;
  const proto = editOriginal.protocol;
  const fields = {
    name: $('#edName').value,
    address: $('#edAddress').value,
    port: $('#edPort').value,
    fragment: $('#edFragment').value.trim(),  // '' clears it
    noise: readNoiseField(),                  // '' clears it
    engine: $('#edEngine') ? $('#edEngine').value : 'xray'
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
    if (editClearPin) fields.clearCertPin = true;
    // patterniha custom-TLS: cipherSuites + finalMask ('' clears them)
    fields.cipherSuites = $('#edCipherSuites') ? $('#edCipherSuites').value.trim() : '';
    fields.finalMask = $('#edFinalMask') ? $('#edFinalMask').value.trim() : '';
    // preserve alpn from original (no field for it)
    const orig = readServerFields(editOriginal);
    if (orig.alpn) fields.alpn = orig.alpn;
  } else if (proto === 'wireguard') {
    fields.publicKey = $('#edWgPub').value.trim();
    // `address` above is the ENDPOINT host (#edAddress); the interface address
    // is its own key. Sending both under `address` is what overwrote the
    // endpoint with "10.10.10.42/32" and stopped the core from starting.
    fields.localAddress = $('#edWgAddr').value.trim();
    fields.dns = $('#edWgDns').value.trim();
    // the endpoint field must hold the PUBLIC host — the interface address
    // pasted here is exactly how the record used to get corrupted
    if (!String(fields.address).trim() || String(fields.address).includes('/')) return toast(t('t.wgBadEndpoint'), 'err');
    fields.presharedKey = $('#edWgPsk').value.trim();
    fields.mtu = $('#edWgMtu').value;
    fields.reserved = $('#edWgReserved').value.trim();
    fields.allowedIPs = $('#edWgAllowed').value.trim();
  } else if (proto === 'socks' || proto === 'http') {
    fields.username = $('#edProxyUser').value.trim();
    fields.password = $('#edProxyPass').value.trim();
  }

  // finalmask goes to the core untouched, so catch bad JSON here rather than
  // letting xray refuse the whole config at connect time
  const fmText = $('#edFinalMask') ? $('#edFinalMask').value.trim() : '';
  if (fmText) {
    try { JSON.parse(fmText); }
    catch { return toast(t('edit.finalMaskBad'), 'err'); }
  }

  const res = await window.api.updateServer(id, fields);
  if (res.ok) {
    state.servers = res.servers;
    renderServers(); renderPicker(); renderChains(); renderPool(); renderAdvanced();
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
  $('#proxyBox').hidden = true;
};
$('#btnWgCancel').onclick = () => { $('#wgBox').hidden = true; };

/* Load a WireGuard .conf into the form. Electron opens a native dialog; the
   headless build has no dialog, so fall back to a hidden file input. */
$('#btnWgPickConf').onclick = async () => {
  let text = '';
  try {
    const res = await window.api.pickWireguardConf();
    if (res && res.ok) text = res.text;
    else if (res && res.canceled) return;
  } catch {}
  if (!text) text = await pickLocalFile('.conf,.txt');
  if (!text) return;
  await fillWgFormFromConf(text);
};

/**
 * Browser fallback: a throwaway <input type="file"> resolved to its text.
 * Resolves '' when nothing was picked — a cancelled dialog fires no 'change' at
 * all, and a promise that never settles would hang the caller's await forever.
 */
function pickLocalFile(accept) {
  return new Promise((resolve) => {
    const inp = document.createElement('input');
    inp.type = 'file';
    inp.accept = accept;

    let settled = false;
    function finish(text) {
      if (settled) return;
      settled = true;
      window.removeEventListener('focus', onWindowFocus);
      resolve(text);
    }
    // Last resort for engines that fire neither 'change' nor 'cancel': the picker
    // is modal, so the window getting focus back means it closed. The delay lets
    // a real 'change'/'cancel' (which arrive right after focus) win the race.
    function onWindowFocus() { setTimeout(() => finish(''), 1500); }

    inp.addEventListener('cancel', () => finish(''));
    inp.addEventListener('change', () => {
      const f = inp.files && inp.files[0];
      if (!f) return finish('');
      const fr = new FileReader();
      fr.onload = () => finish(String(fr.result || ''));
      fr.onerror = () => finish('');
      fr.readAsText(f);
    });
    window.addEventListener('focus', onWindowFocus, { once: true });
    inp.click();
  });
}

/** Fill the WireGuard form from .conf text. Parsing happens in main. */
async function fillWgFormFromConf(text) {
  // The call answers { ok: false } for a conf it could not parse, but the bridge
  // itself REJECTS when the RPC fails (the headless one throws on a non-JSON
  // response). Both mean the same thing to the user, so both land on the hint —
  // otherwise a reject here would be an unhandled promise rejection.
  let res;
  try {
    res = await window.api.parseWireguardConf(text);
  } catch (e) {
    $('#wgConfHint').textContent = (e && e.message) || t('wg.confFailed');
    return;
  }
  if (!res || !res.ok) { $('#wgConfHint').textContent = (res && res.error) || t('wg.confFailed'); return; }
  const f = res.fields;
  $('#wgName').value = f.name || '';
  $('#wgEndpoint').value = f.endpoint || '';
  $('#wgPrivate').value = f.privateKey || '';
  $('#wgPublic').value = f.publicKey || '';
  $('#wgAddress').value = f.address || '';
  $('#wgAllowed').value = f.allowedIPs || '0.0.0.0/0, ::/0';
  $('#wgPsk').value = f.presharedKey || '';
  $('#wgMtu').value = f.mtu || 1420;
  $('#wgReserved').value = f.reserved || '';
  $('#wgDns').value = f.dns || '';
  $('#wgConfHint').textContent = t('wg.confLoaded');
}

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
    reserved: $('#wgReserved').value.trim(),
    dns: $('#wgDns').value.trim()
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
  renderServers(); renderPicker(); renderChains(); renderAdvanced();
  $('#wgBox').hidden = true;
  ['wgName', 'wgEndpoint', 'wgPrivate', 'wgPublic', 'wgAddress', 'wgAllowed', 'wgPsk', 'wgReserved', 'wgDns'].forEach(id => { $('#' + id).value = ''; });
  $('#wgMtu').value = 1420;
  toast(t('t.wgAdded'), 'ok');
};

/* ----------------------------- SOCKS / HTTP proxy add ----------------------------- */
$('#btnProxyOpen').onclick = () => {
  const box = $('#proxyBox');
  box.hidden = !box.hidden;
  $('#importBox').hidden = true;
  $('#wgBox').hidden = true;
};
$('#btnProxyCancel').onclick = () => { $('#proxyBox').hidden = true; };

$('#btnProxyAdd').onclick = async () => {
  const fields = {
    type: $('#pxType').value,
    name: $('#pxName').value.trim(),
    address: $('#pxHost').value.trim(),
    port: $('#pxPort').value,
    username: $('#pxUser').value.trim(),
    password: $('#pxPass').value.trim()
  };
  if (!fields.address || !fields.port) return toast(t('t.proxyMissing'), 'err');
  const res = await window.api.addProxy(fields);
  state.servers = res.servers;
  if (!state.selectedServerId) state.selectedServerId = res.server.id;
  renderServers(); renderPicker(); renderChains(); renderPool();
  $('#proxyBox').hidden = true;
  ['pxName', 'pxHost', 'pxPort', 'pxUser', 'pxPass'].forEach(id => { $('#' + id).value = ''; });
  toast(t('t.proxyAdded'), 'ok');
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
  renderPool();     // pool target dropdowns include chains too
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

    const tl = pingResultLabel((state.pings[chain.id] || {}).tcp);
    const rl = pingResultLabel((state.pings[chain.id] || {}).real);
    const ready = chain.members.length >= 2;

    card.innerHTML = `
      <div class="chain-card-head">
        <span class="proto-badge proto-chain">⛓</span>
        <input class="input chain-name" value="${escapeHtml(chain.name)}" />
        <span class="chain-pings">
          <span class="pi-ping-ico" title="${escapeHtml(t('ping.tcp'))}">⚡</span><span class="chain-ping ${tl.cls}" data-pbase="chain-ping" data-ping="${chain.id}">${tl.txt}</span>
          <span class="pi-ping-ico" title="${escapeHtml(t('ping.real'))}">⏱</span><span class="chain-ping ${rl.cls}" data-pbase="chain-ping" data-ping-real="${chain.id}">${rl.txt}</span>
        </span>
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
      <input class="input chain-pool-search" dir="auto" placeholder="${escapeHtml(t('ss.search'))}" />
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
    const poolSearch = card.querySelector('.chain-pool-search');
    const available = state.servers.filter(s => !chain.members.includes(s.id));
    if (!available.length) {
      pool.innerHTML = `<div class="empty small">${escapeHtml(t('chain.poolEmpty'))}</div>`;
      if (poolSearch) poolSearch.hidden = true;
    }
    for (const s of available) {
      const row = document.createElement('button');
      row.className = 'pool-item';
      row.dataset.name = s.name;
      row.innerHTML = `
        <span class="proto-badge proto-${s.protocol}">${s.protocol}</span>
        <span class="pi-name">${escapeHtml(s.name)}</span>
        <span class="pool-add">+ ${escapeHtml(t('chain.add'))}</span>`;
      row.onclick = () => { chain.members.push(s.id); persistChains(); };
      pool.appendChild(row);
    }
    // filter the pool as you type (handles long config lists)
    if (poolSearch) poolSearch.oninput = () => {
      const f = poolSearch.value.toLowerCase();
      pool.querySelectorAll('.pool-item').forEach(it => {
        it.style.display = (it.dataset.name || '').toLowerCase().includes(f) ? '' : 'none';
      });
    };

    wrap.appendChild(card);
  });
}

/* ----------------------------- proxy pool (multi-config) ----------------------------- */
function newPoolId() { return 'px-' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6); }

/** Every local port already claimed (settings + pool entries) — avoid clashes. */
function usedPoolPorts() {
  const set = new Set();
  const sp = parseInt(state.settings.socksPort, 10); if (sp) set.add(sp);
  const hp = parseInt(state.settings.httpPort, 10); if (hp) set.add(hp);
  const ap = parseInt(state.settings.apiPort, 10); if (ap) set.add(ap);   // api inbound (configBuilder reserves it too)
  for (const e of state.pool) {
    if (e.socksPort) set.add(parseInt(e.socksPort, 10));
    if (e.httpPort) set.add(parseInt(e.httpPort, 10));
  }
  return set;
}
/** Next free local port at/after `start` (default 60001). */
function nextPoolPort(start) {
  const used = usedPoolPorts();
  let p = start || 60001;
  while (used.has(p) && p < 65535) p++;
  return p;
}

/** [{value,label}] pool targets — servers + ready chains (no direct/block). */
function poolTargetOptions() {
  const opts = state.servers.map(s => ({ value: s.id, label: s.name }));
  for (const c of state.chains) if (chainReady(c)) opts.push({ value: 'chain:' + c.id, label: '⛓ ' + c.name });
  return opts;
}

async function persistPool() {
  state.pool = state.pool.map(e => ({
    id: e.id, name: e.name, target: e.target,
    socksPort: parseInt(e.socksPort, 10) || 0, httpPort: parseInt(e.httpPort, 10) || 0,
    enabled: !!e.enabled
  }));
  await window.api.setPool(state.pool);
  renderPool();
  renderPicker();   // the 🧩 pool entry becomes selectable once ≥1 entry is valid
}

$('#btnAddPool').onclick = () => {
  const socks = nextPoolPort(60001);
  const http = nextPoolPort(socks + 1);
  const n = state.pool.length + 1;
  const target = (state.servers[0] && state.servers[0].id) || '';
  state.pool.push({
    id: newPoolId(),
    name: (window.i18n.lang === 'en' ? 'Proxy ' : 'پروکسی ') + n,
    target, socksPort: socks, httpPort: http, enabled: true
  });
  persistPool();
};

$('#btnPoolConnect').onclick = () => {
  if (!poolReady()) return toast(t('pool.needOne'), 'err');
  connect(POOL_ID);
};

function renderPool() {
  const wrap = $('#poolWrap');
  if (!wrap) return;
  wrap.innerHTML = '';
  const empty = $('#poolEmpty');
  if (empty) empty.hidden = state.pool.length > 0;
  const opts = poolTargetOptions();

  state.pool.forEach((entry) => {
    const card = document.createElement('div');
    card.className = 'card pool-card' + (entry.enabled ? '' : ' disabled');
    const valid = poolTargetValid(entry.target);

    card.innerHTML = `
      <div class="pool-card-head">
        <span class="proto-badge proto-pool">🧩</span>
        <input class="input pool-name" value="${escapeHtml(entry.name)}" />
        <label class="switch pool-enable-sw" title="${escapeHtml(t('pool.enable'))}">
          <input type="checkbox" class="pool-enable" ${entry.enabled ? 'checked' : ''} /><span class="slider"></span>
        </label>
        <button class="icon-btn pool-del" title="delete">🗑</button>
      </div>
      <div class="pool-card-body">
        <div class="pool-field pool-target-field">
          <label class="field-label">${escapeHtml(t('pool.target'))}</label>
          <span class="pool-target-mount"></span>
        </div>
        <div class="pool-field">
          <label class="field-label">${escapeHtml(t('pool.socksPort'))}</label>
          <input type="number" class="input pool-socks" dir="ltr" value="${entry.socksPort || ''}" />
        </div>
        <div class="pool-field">
          <label class="field-label">${escapeHtml(t('pool.httpPort'))}</label>
          <input type="number" class="input pool-http" dir="ltr" value="${entry.httpPort || ''}" placeholder="—" />
        </div>
      </div>
      <div class="pool-warn ${valid ? '' : 'warn'}">${escapeHtml(valid ? '' : t('pool.invalidTarget'))}</div>`;

    const nameInput = card.querySelector('.pool-name');
    nameInput.onchange = () => { entry.name = nameInput.value.trim() || entry.name; persistPool(); };
    card.querySelector('.pool-enable').onchange = (e) => { entry.enabled = e.target.checked; persistPool(); };
    card.querySelector('.pool-del').onclick = () => {
      state.pool = state.pool.filter(x => x.id !== entry.id);
      if (!poolReady() && state.selectedServerId === POOL_ID) state.selectedServerId = null;
      persistPool();
    };
    const socksIn = card.querySelector('.pool-socks');
    socksIn.onchange = () => { entry.socksPort = parseInt(socksIn.value, 10) || 0; persistPool(); };
    const httpIn = card.querySelector('.pool-http');
    httpIn.onchange = () => { entry.httpPort = parseInt(httpIn.value, 10) || 0; persistPool(); };

    card.querySelector('.pool-target-mount').appendChild(
      makeSearchSelect({ options: opts, value: entry.target, onChange: (v) => { entry.target = v; persistPool(); } })
    );

    wrap.appendChild(card);
  });
}

/* ----------------------------- advanced (graphical) routing ----------------------------- */
const RULE_TYPES = ['ip', 'domain', 'port', 'process'];

/** Fetch the running-process list for the routing picker, then re-render. */
async function loadProcList() {
  try {
    const res = await window.api.listProcesses();
    state.procList = (res && res.ok) ? (res.processes || []) : [];
  } catch { state.procList = []; }
  renderAdvanced();
}

/** <option>s for a process <select>, ensuring the current value is present. */
function processOptions(selected) {
  const opts = [`<option value="">${escapeHtml(t('proc.pick'))}</option>`];
  for (const p of state.procList) {
    const label = p.count ? `${p.name} (${p.count})` : p.name;
    opts.push(`<option value="${escapeHtml(p.name)}"${p.name === selected ? ' selected' : ''}>${escapeHtml(label)}</option>`);
  }
  // current value that's no longer running
  if (selected && !state.procList.some(p => p.name === selected)) {
    opts.push(`<option value="${escapeHtml(selected)}" selected>${escapeHtml(selected)}</option>`);
  }
  return opts.join('');
}

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

/** [{value,label}] of routing targets — servers + ready chains + direct/block. */
function targetOptionList() {
  const opts = state.servers.map(s => ({ value: s.id, label: s.name }));
  for (const c of state.chains) if (chainReady(c)) opts.push({ value: 'chain:' + c.id, label: '⛓ ' + c.name });
  opts.push({ value: 'direct', label: t('adv.direct') });
  opts.push({ value: 'block', label: t('adv.block') });
  return opts;
}

let advDefaultSel = null;

/**
 * A searchable, scrollable dropdown (same feel as the home picker) for choosing
 * a routing target. Returns the element; call .getValue() to read the choice.
 */
function makeSearchSelect({ options, value, onChange }) {
  const wrap = document.createElement('div');
  wrap.className = 'ss';
  const cur = document.createElement('button');
  cur.type = 'button';
  cur.className = 'ss-current';
  const menu = document.createElement('div');
  menu.className = 'ss-menu';
  menu.hidden = true;
  const search = document.createElement('input');
  search.className = 'input ss-search';
  search.placeholder = t('ss.search');
  const list = document.createElement('div');
  list.className = 'ss-list';
  menu.appendChild(search); menu.appendChild(list);
  wrap.appendChild(cur); wrap.appendChild(menu);

  let current = value;
  const labelFor = (v) => { const o = options.find(x => x.value === v); return o ? o.label : '—'; };
  const renderCur = () => { cur.innerHTML = `<span class="ss-cur-label">${escapeHtml(labelFor(current))}</span><span class="ss-caret">▾</span>`; };
  const close = () => { menu.hidden = true; };
  const renderList = (f) => {
    f = (f || '').toLowerCase();
    list.innerHTML = '';
    const items = options.filter(o => o.label.toLowerCase().includes(f) || String(o.value).toLowerCase().includes(f));
    if (!items.length) { list.innerHTML = `<div class="ss-empty">${escapeHtml(t('ss.none'))}</div>`; return; }
    for (const o of items) {
      const it = document.createElement('div');
      it.className = 'ss-item' + (o.value === current ? ' active' : '');
      it.textContent = o.label;
      it.onclick = () => { current = o.value; renderCur(); close(); if (onChange) onChange(current); };
      list.appendChild(it);
    }
  };
  const open = () => { menu.hidden = false; search.value = ''; renderList(''); setTimeout(() => search.focus(), 0); };
  cur.onclick = (e) => { e.stopPropagation(); menu.hidden ? open() : close(); };
  search.oninput = () => renderList(search.value);
  search.onclick = (e) => e.stopPropagation();
  document.addEventListener('click', (e) => { if (!wrap.contains(e.target)) close(); });
  renderCur();
  wrap.getValue = () => current;
  return wrap;
}

/**
 * The WireGuard a routing target ends in, if any: the server itself, or the
 * last member of a chain. Anything else (direct, block, a VLESS…) → null.
 */
function wgOfTarget(target) {
  if (!target || target === 'direct' || target === 'block') return null;
  let s = null;
  if (String(target).startsWith('chain:')) {
    const members = chainMembers(state.chains.find(x => 'chain:' + x.id === target));
    s = members[members.length - 1] || null;
  } else s = srvById(target);
  return s && s.protocol === 'wireguard' ? s : null;
}

/** The peer's AllowedIPs, trimmed. */
function wgAllowedIPs(s) {
  const ob = (s && s.outbound) || {};
  const peer = ob.settings && ob.settings.peers && ob.settings.peers[0];
  return ((peer && peer.allowedIPs) || []).map(a => String(a).trim()).filter(Boolean);
}

/** AllowedIPs worth suggesting: the split ranges, never the full-tunnel entries. */
function wgSuggestedRanges(s) { return wgAllowedIPs(s).filter(a => !/\/0$/.test(a)); }

/**
 * The dashed note under a routing row whose target ends in a WireGuard: the
 * ranges its AllowedIPs already names, and where its internal names resolve.
 * `onUse` fills the row's value with those ranges — omit it for the default
 * target, which has no value to fill (then only the notes are shown).
 * Returns null when the target is not a WireGuard, or has nothing to say.
 */
function wgSuggestEl(s, opts) {
  if (!s) return null;
  const { value, onUse } = opts || {};
  const ranges = wgSuggestedRanges(s);
  const dns = (Array.isArray(s.dns) ? s.dns : []).filter(Boolean);
  const showRanges = !!onUse && ranges.length > 0;
  // only /0 entries: the tunnel takes everything, so there is no range to offer
  const fullTunnel = !!onUse && wgAllowedIPs(s).length > 0 && !ranges.length;
  // as the DEFAULT, a split-tunnel WireGuard drops every destination outside
  // its ranges — the warning that matters there
  const splitDefault = !onUse && ranges.length > 0;
  if (!showRanges && !fullTunnel && !splitDefault && !dns.length) return null;

  const el = document.createElement('div');
  el.className = 'adv-suggest';
  const list = ranges.join(', ');
  const bare = (v) => String(v || '').replace(/\s+/g, '');
  let html = '';
  if (showRanges) {
    html += `<span>🧭 ${escapeHtml(t('adv.sugRanges'))}: <code>${escapeHtml(list)}</code></span>`;
    html += bare(value) === bare(list)
      ? `<span class="adv-suggest-applied">✓ ${escapeHtml(t('adv.sugApplied'))}</span>`
      : `<button class="btn ghost adv-suggest-use">${escapeHtml(t('adv.sugUse'))}</button>`;
  }
  if (fullTunnel) html += `<div class="adv-suggest-line">${escapeHtml(t('adv.sugFullTunnel'))}</div>`;
  if (splitDefault) {
    const r = `<code>${escapeHtml(list)}</code>`;
    html += `<div class="adv-suggest-line">⚠ ${escapeHtml(t('adv.sugSplitDefault')).replace('{ranges}', () => r)}</div>`;
  }
  if (dns.length) {
    // task 2 resolves internal names through whichever target owns that DNS
    const addr = `<code>${escapeHtml(dns.join(', '))}</code>`;
    html += `<div class="adv-suggest-line">${escapeHtml(t('adv.sugDns')).replace('{dns}', () => addr)}</div>`;
    if (!(Array.isArray(s.dnsDomains) ? s.dnsDomains : []).length) {
      html += `<div class="adv-suggest-line">${escapeHtml(t('adv.sugDomains'))}</div>`;
    }
  }
  el.innerHTML = html;
  const use = el.querySelector('.adv-suggest-use');
  if (use) use.onclick = () => onUse(list);
  return el;
}

/**
 * Refresh only the note under the default target, so re-rendering it does not
 * disturb the dropdown the user just picked from.
 */
function renderDefaultSuggest() {
  const body = $('#advBody');
  const defRow = body && body.querySelector('.adv-default');
  if (!defRow) return;
  body.querySelectorAll('.adv-suggest-default').forEach(n => n.remove());
  const def = state.settings.routeDefault || (state.servers[0] && state.servers[0].id) || 'direct';
  const el = wgSuggestEl(wgOfTarget(def), {});
  if (!el) return;
  el.classList.add('adv-suggest-default');
  defRow.insertAdjacentElement('afterend', el);
}

function renderAdvanced() {
  const wrap = $('#advRules');
  const body = $('#advBody');
  const optAdv = $('#optAdvanced');
  const defMount = $('#advDefaultMount');
  if (!wrap || !optAdv || !defMount) return;

  optAdv.checked = !!state.settings.advancedRouting;
  if (body) body.hidden = !state.settings.advancedRouting;
  // custom rules only apply to the simple modes (configBuilder ignores them under
  // advanced routing) — don't show an editor for something that has no effect
  const simple = $('#simpleRulesCard');
  if (simple) simple.hidden = !!state.settings.advancedRouting;

  const rules = state.settings.routeRules || [];
  wrap.innerHTML = '';
  if (!rules.length) {
    wrap.innerHTML = `<div class="empty small">${escapeHtml(t('adv.empty'))}</div>`;
  }
  let hasProc = false;
  rules.forEach((r, idx) => {
    if (r.type === 'process') hasProc = true;
    const row = document.createElement('div');
    row.className = 'adv-rule';
    const typeOpts = RULE_TYPES.map(tp =>
      `<option value="${tp}"${tp === r.type ? ' selected' : ''}>${escapeHtml(t('adv.type.' + tp))}</option>`).join('');
    // process rules use a dropdown of running processes; ip/domain get a
    // datalist of common geoip/geosite tokens so the user can pick instead of
    // memorizing them; others a plain free-text value.
    const listAttr = r.type === 'ip' ? ' list="geoipList"' : r.type === 'domain' ? ' list="geositeList"' : '';
    const valueCell = r.type === 'process'
      ? `<select class="select adv-value adv-proc">${processOptions(r.value)}</select>
         <button class="icon-btn adv-proc-refresh" title="${escapeHtml(t('proc.refresh'))}">⟳</button>`
      : `<input class="input adv-value"${listAttr} dir="ltr" placeholder="${escapeHtml(t('adv.valuePh'))}" value="${escapeHtml(r.value || '')}" />`;
    row.innerHTML = `
      <select class="select adv-type">${typeOpts}</select>
      ${valueCell}
      <span class="adv-arrow">→</span>
      <span class="adv-target-mount"></span>
      <button class="icon-btn adv-del" title="remove">🗑</button>`;
    row.querySelector('.adv-type').onchange = (e) => {
      rules[idx].type = e.target.value;
      if (e.target.value === 'process' && !state.procList.length) loadProcList();
      else renderAdvanced();
    };
    const valEl = row.querySelector('.adv-value');
    if (r.type === 'process') valEl.onchange = (e) => { rules[idx].value = e.target.value; };
    else valEl.oninput = (e) => { rules[idx].value = e.target.value; };
    const refresh = row.querySelector('.adv-proc-refresh');
    if (refresh) refresh.onclick = () => loadProcList();
    // searchable target dropdown (handles long config lists)
    row.querySelector('.adv-target-mount').appendChild(
      makeSearchSelect({
        options: targetOptionList(), value: r.target,
        // re-render so the AllowedIPs note follows the new target (the dropdown
        // has already closed itself by the time onChange runs)
        onChange: (v) => { rules[idx].target = v; renderAdvanced(); }
      })
    );
    row.querySelector('.adv-del').onclick = () => { rules.splice(idx, 1); renderAdvanced(); };
    wrap.appendChild(row);
    // when the target ends in a WireGuard, offer its ranges and say where its
    // internal names resolve
    const sug = wgSuggestEl(wgOfTarget(r.target), {
      value: r.value,
      onUse: (list) => { rules[idx].type = 'ip'; rules[idx].value = list; renderAdvanced(); }
    });
    if (sug) wrap.appendChild(sug);
  });

  // default target — searchable dropdown
  const def = state.settings.routeDefault || (state.servers[0] && state.servers[0].id) || 'direct';
  defMount.innerHTML = '';
  advDefaultSel = makeSearchSelect({
    options: targetOptionList(), value: def,
    onChange: (v) => { state.settings.routeDefault = v; renderDefaultSuggest(); }
  });
  defMount.appendChild(advDefaultSel);
  renderDefaultSuggest();

  // process-routing options panel (only when a process rule exists)
  const procOpts = $('#procOpts');
  if (procOpts) {
    procOpts.hidden = !hasProc;
    const watch = $('#optProcWatch');
    if (watch) watch.checked = !!state.settings.procRouteWatch;
  }
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

/* process-routing options */
$('#optProcWatch').onchange = async () => {
  // saveSettings offers the reconnect when this is changed while connected
  await saveSettings({ procRouteWatch: $('#optProcWatch').checked });
};
$('#btnClearProcCache').onclick = async () => {
  await window.api.clearProcCache();
  toast(t('proc.cacheCleared'), 'ok');
};
// load the running-process list when opening Routing (for the process picker)
const routingNav = document.querySelector('.nav-item[data-view="routing"]');
if (routingNav) routingNav.addEventListener('click', () => {
  if ((state.settings.routeRules || []).some(r => r && r.type === 'process')) loadProcList();
});

$('#btnSaveAdv').onclick = async () => {
  // collect from current state (kept in sync by the row handlers) + default select
  const rules = (state.settings.routeRules || [])
    .map(r => ({ type: r.type, value: (r.value || '').trim(), target: r.target }))
    .filter(r => r.value && r.target);
  const routeDefault = advDefaultSel ? advDefaultSel.getValue() : (state.settings.routeDefault || 'direct');
  await saveSettings({ routeRules: rules, routeDefault, advancedRouting: $('#optAdvanced').checked });
  state.settings.routeRules = rules;
  updateGuardRows();   // a `direct` target here contradicts the strict guard too
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
    // silent: the admin relaunch question comes first (it restarts the app), and
    // this modal has to close before the apply dialog opens on top of it
    await saveSettings({ tunMode: wantTun }, { silent: true });
    setModeWidget();
    updateTunStatus();
    renderModeOptions();
    toast(wantTun ? t('mode.tun') : t('mode.proxy'), 'ok');
    if (wantTun && state.tunAvailable && !state.elevated && state.platform === 'win32') {
      closeModeModal();
      if (await promptRelaunchAdmin()) return;
    }
    closeModeModal();
    if (state.pendingReconnect.length) await promptApplySettings();
  };
});

init();

// The OS reconnected an adapter — nudge main to re-check the tunnel. This page
// is shared with the headless panel, where "online" means the OPERATOR'S laptop
// came back and says nothing about the server's network; service.js deliberately
// makes its net:online handler a no-op for that reason.
window.addEventListener('online', () => { try { window.api.netOnline(); } catch {} });
