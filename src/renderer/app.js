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
  savedSelection: null,   // what main last stored as the selection (keepSelectionValid)
  lastServerId: null,     // the last connection made — a selection that is gone falls back to it
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
  // [{ id, name, rules, def, defVia, useMode, base }] — routing profiles (several
  // advanced routings); null on a back end without them, which keeps the
  // routing page today's single advanced routing
  profiles: null,
  profileSel: null,        // the profile the routing page edits
  editingId: null,         // server being edited in the modal
  // Settings saved while connected that the live tunnel is NOT using yet.
  // Owned by main (it knows what the running config was built from) — the
  // renderer only mirrors it.
  pendingReconnect: [],
  pendingDismissed: false, // user chose "later"; keep the banner out of the way
  wasReconnecting: false,  // main is rebuilding after a network change (toast on success)
  // what the live connection did not do — proxy only, the leak guard — kept on
  // Home under the state while it is up (connIssuesFrom / renderConnIssues)
  connIssues: [],
  // main's notices about this PC (W1/W3/W4) already toasted for this connection
  noticesToasted: new Set(),
  // …and those about the store itself (a WireGuard identity stored twice), toasted once per run
  noticesOnce: new Set(),
  // Windows: the logon task starts another copy of the app ({ task, current }) — checkAutostart
  autostartStale: null,
  // lifetime traffic per config id — survives disconnect and restart
  usage: {},
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

/**
 * A toast that carries one button — for a message whose fix is a single click
 * ("not applied yet — Reconnect"). It stays up longer than a plain toast, the
 * button runs `run` and takes the toast away, and the next plain toast()
 * replaces it like any other. Hiding drops only `show`: the toast fades out
 * where it stood (and is click-through again) instead of jumping back to the
 * plain toast's position mid-fade.
 */
function toastAction(msg, label, run, kind = 'warn', ms = 12000) {
  const el = $('#toast');
  const hide = () => { el.className = 'toast has-action ' + kind; };
  el.textContent = '';
  const text = document.createElement('span');
  text.textContent = msg;
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = 'btn small toast-action';
  btn.textContent = label;
  btn.onclick = () => { clearTimeout(toast._t); hide(); run(); };
  el.append(text, btn);
  el.className = 'toast show has-action ' + kind;
  clearTimeout(toast._t);
  toast._t = setTimeout(hide, ms);
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

/* ----------------------------- speed sparkline ----------------------------- */
// Sixty seconds of speed, two lines, one canvas. Drawn once per stats tick;
// nothing in the DOM is created or measured for it, so it costs what a
// 60-point polyline costs and no more. Declared up here, before the theme and
// skin appliers that redraw it, so no caller can reach `hist` before it exists.
const SPARK_N = 60;
const hist = { down: [], up: [], time: [] };
function pushHist(down, up) {
  const speed = value => Number.isFinite(Number(value)) ? Math.max(0, Number(value)) : 0;
  hist.down.push(speed(down)); hist.up.push(speed(up)); hist.time.push(Date.now());
  while (hist.time.length > 120 || (hist.time.length > 1 && hist.time[0] < Date.now() - 60000)) {
    hist.down.shift(); hist.up.shift(); hist.time.shift();
  }
}
function drawSpark() {
  const c = $('#speedSpark');
  if (!c || !c.getContext) return;
  const box = c.getBoundingClientRect();
  if (!box.width || !box.height) return;
  const ratio = Math.min(window.devicePixelRatio || 1, 3);
  const W = box.width, H = box.height;
  c.width = Math.round(W * ratio); c.height = Math.round(H * ratio);
  const ctx = c.getContext('2d');
  if (!ctx) return;
  ctx.scale(ratio, ratio);
  const css = getComputedStyle(document.documentElement);
  const peak = Math.max(1024, ...hist.down, ...hist.up);
  const order = Math.pow(10, Math.floor(Math.log10(peak)));
  const max = Math.ceil(peak / order) * order;
  $('#chartScale').textContent = fmtSpeed(max);
  const top = 20, bottom = H - 6, height = bottom - top;
  ctx.strokeStyle = css.getPropertyValue('--line').trim(); ctx.lineWidth = 1;
  ctx.setLineDash([3, 5]);
  for (let n = 0; n <= 2; n++) { const y = top + height * n / 2; ctx.beginPath(); ctx.moveTo(0,y); ctx.lineTo(W,y); ctx.stroke(); }
  ctx.setLineDash([]);
  const now = hist.time.at(-1) || Date.now();
  for (const [arr, token, dashed] of [[hist.down, '--accent', false], [hist.up, '--ok', true]]) {
    if (!arr.length) continue;
    const points = arr.map((v,i) => [Math.max(0, 1 - (now - hist.time[i]) / 60000) * W, bottom - (v / max) * height]);
    const color = css.getPropertyValue(token).trim() || '#888';
    ctx.beginPath(); points.forEach(([x,y],i) => i ? ctx.lineTo(x,y) : ctx.moveTo(x,y));
    ctx.lineTo(points.at(-1)[0],bottom); ctx.lineTo(points[0][0],bottom); ctx.closePath();
    const wash = ctx.createLinearGradient(0,top,0,bottom); wash.addColorStop(0,color); wash.addColorStop(1,'transparent');
    ctx.globalAlpha = dashed ? .06 : .16; ctx.fillStyle = wash; ctx.fill(); ctx.globalAlpha = 1;
    ctx.beginPath(); points.forEach(([x,y],i) => i ? ctx.lineTo(x,y) : ctx.moveTo(x,y));
    ctx.strokeStyle = color; ctx.lineWidth = 2; ctx.lineJoin = 'round'; ctx.setLineDash(dashed ? [5,3] : []); ctx.stroke(); ctx.setLineDash([]);
    const [x,y] = points.at(-1); ctx.beginPath(); ctx.arc(Math.min(W-3,x),y,2.5,0,Math.PI*2); ctx.fillStyle=color; ctx.fill();
  }
}
if (typeof ResizeObserver !== 'undefined') new ResizeObserver(drawSpark).observe($('#speedSpark'));

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
/**
 * Which of the three looks the window wears. A skin only re-declares tokens and
 * a few shapes (see skins.css) — the layout, the markup and every hook are the
 * same in all three, so switching is instant and cannot break a screen.
 * Remembered the same way the theme is, so the first paint is already right.
 */
function applySkin(skin) {
  const s = ['cockpit', 'console', 'legacy'].includes(skin) ? skin : 'console';
  document.documentElement.setAttribute('data-skin', s);
  try { localStorage.setItem('irnetfree.skin', s); } catch { /* only costs a flash */ }
  drawSpark();   // the sparkline's colours are the skin's tokens
  return s;
}

function applyTheme(pref, systemDark) {
  const dark = pref === 'system' ? systemDark !== false : pref !== 'light';
  const theme = dark ? 'dark' : 'light';
  document.documentElement.setAttribute('data-theme', theme);
  // Remember the RESOLVED theme (not the preference) so theme-boot.js can paint
  // it from <head> on the next launch, before app:init has answered. Storage is
  // best-effort: a failure here only costs the flash it exists to avoid.
  try { localStorage.setItem('irnetfree.theme', theme); } catch {}
  drawSpark();   // the sparkline's colours are the theme's tokens
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

/* ----------------------------- navigation ----------------------------- */
function showView(view) {
  const btn = document.querySelector(`.nav-item[data-view="${view}"]`);
  if (!btn) return;
  $$('.nav-item').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  $$('.view').forEach(v => v.classList.remove('active'));
  const v = $('#view-' + view);
  if (v) v.classList.add('active');
}
$$('.nav-item').forEach(btn => {
  btn.addEventListener('click', () => showView(btn.dataset.view));
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

$('#skinSelect').onchange = () => {
  const skin = applySkin($('#skinSelect').value);
  saveSettings({ skin });
};

/* the OS switched between light and dark while the app is open */
window.api.onSystemTheme((d) => {
  state.systemDark = !!(d && d.dark);
  if ((state.settings.theme || 'dark') === 'system') applyTheme('system', state.systemDark);
});

function setLang(lang) {
  window.i18n.applyI18n(lang);
  // applyI18n left the remote-access pointer as plain text: its links again
  if (state.flavor === 'openwrt') renderRemotePointer();
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
  renderAutostartBanner();
  renderSettingCards();   // option labels are translated strings
  // the chrome carries three strings that are not data-i18n nodes: the mode
  // badge, the path diagram's own labels and the inspector's on/off words
  applyUiMode(state.settings.uiMode || defaultUiMode());
  renderTrafficPath(state.connected ? 'connected' : state.connecting ? 'connecting' : 'disconnected');
  renderInspector();
  refreshJsonFormLang();   // an open JSON edit form: its help line and summary are built with t()
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
  state.lastServerId = data.lastServerId || null;
  state.tunAvailable = !!data.tunAvailable;
  state.elevated = !!data.elevated;
  state.assets = data.assets || {};
  state.version = data.version || '';
  state.platform = data.platform || (data.assets && data.assets.platform) || 'win32';
  // the router flavour of Linux: the device list shows, the desktop-only rows go
  state.flavor = data.flavor || null;
  // main only reports pending keys while something is actually connected, so a
  // fresh launch always starts empty
  state.pendingReconnect = data.pendingReconnect || [];
  state.usage = data.usage || {};
  state.chain = (data.chain || []).filter(id => state.servers.some(s => s.id === id));
  state.chains = (data.chains || []).map(c => ({
    id: c.id, name: c.name || 'Chain',
    members: (c.members || []).filter(id => state.servers.some(s => s.id === id))
  }));
  state.pool = (data.pool || []).map(e => ({
    id: e.id, name: e.name || 'Proxy', target: e.target || '',
    socksPort: e.socksPort || 0, httpPort: e.httpPort || 0, enabled: e.enabled !== false
  }));
  // Routing profiles, before the selection is resolved: '__advanced__:<id>' is
  // selectable only once they are in. null on a back end without them.
  state.profiles = await loadRoutingProfiles(data);
  state.profileSel = (profileOfSel(data.selectedServerId) || (state.profiles && state.profiles[0]) || {}).id || null;
  // The picker's choice survives a restart: the one main stored, then the live
  // connection (a reload of a connected window), then the last one made, then
  // the first server. Resolved once the chains, the pool and the settings are
  // in — they decide what can still be selected.
  state.savedSelection = data.selectedServerId || null;
  state.selectedServerId = resolveSelection([data.selectedServerId, data.activeServerId, data.lastServerId], selectable, state.servers);

  window.i18n.applyI18n(state.settings.lang || 'fa');
  $('#btnLang').textContent = (state.settings.lang || 'fa') === 'fa' ? 'EN' : 'فا';

  state.systemDark = data.systemDark !== false;
  applyTheme(state.settings.theme || 'dark', state.systemDark);
  applySkin(state.settings.skin || 'console');

  // the view preference, before anything paints, so a simple-mode user never
  // sees the pro surfaces flash past
  applyUiMode(state.settings.uiMode || defaultUiMode());

  applySettingsToUI();
  renderServers();
  renderPicker();
  renderSubs();
  renderComponents();
  renderChains();
  renderPool();
  renderAdvanced();
  // first paint: name the selected config instead of leaving the markup's
  // "no server selected" placeholder standing next to a filled picker
  refreshConnLabels();
  updateXrayStatus(data.xrayReady);
  updateTunStatus();
  setModeWidget();
  updateLanInfo();
  updateKillStatus();
  applyFlavor();
  renderPendingBanner();
  // The connection as it IS (S1): a page that loads while the tunnel is up
  // starts connected, with the real uptime — not on "disconnected" until an
  // event that never comes on a stable tunnel.
  if (data.conn) applyConnSnapshot(data.conn);

  // app version (Settings → About, and small under the logo) + xray-core version
  $('#appVersion').textContent = 'v' + (state.version || '?');
  $('#tbVersion').textContent = state.version ? 'v' + state.version : '';
  refreshXrayVersion();

  // the store failed to load before this window existed, so it is delivered here
  if (data.storeError) reportStoreError(Object.assign({ kind: 'load' }, data.storeError));

  // prompt to download required files on first run / when essentials are missing
  maybePromptMissingFiles();

  // Windows: does the logon task start another copy of the app? (main reads it; a banner if so)
  checkAutostart();
}

/* ----------------------------- core versions ----------------------------- */
// the cores with a version beside their row (and the version picker, corePicker.js)
const CORE_KEYS = ['xray', 'xray-pattn', 'sing-box'];
/** A core's own `version` answer as its number ('sing-box version 1.13.14' → '1.13.14'); anything else as it was. */
function coreVersionText(v) {
  const m = /(\d+\.\d+\.\d+(?:-[0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*)?)/.exec(String(v || ''));
  return m ? m[1] : String(v || '').trim();
}
async function refreshXrayVersion() {
  for (const id of CORE_KEYS) {
    try {
      const res = await window.api.xrayVersion(id);
      state.coreVersions[id] = (res && res.ok) ? coreVersionText(res.version) : '';
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
  $('#skinSelect').value = s.skin || 'console';
  $('#optSysProxy').checked = !!s.systemProxy;
  $('#optTun').checked = !!s.tunMode;
  $('#optTunBackend').value = s.tunBackend || 'sing-box';
  $('#optTunAppMode').value = s.tunAppMode || 'off';
  // stored as a list, typed as lines
  $('#optTunApps').value = (Array.isArray(s.tunApps) ? s.tunApps : []).join('\n');
  $('#optTunBackend option[value="native-macos"]').hidden = state.platform !== 'darwin';
  $('#nativeMacControls').hidden = state.platform !== 'darwin';
  $('#optLeakGuard').value = s.leakGuard || 'standard';
  $('#optBlockUdpProxy').checked = !!s.blockUdpInProxyMode;
  $('#optAllowLan').checked = !!s.allowLan;
  $('#optKillSwitch').checked = !!s.killSwitch;
  $('#optNetAuto').checked = s.autoReconnectOnNetworkChange !== false;
  $('#optNotify').checked = s.notifications !== false;
  $('#optLaunchAtLogin').checked = !!s.launchAtLogin;
  $('#optAutoConnect').checked = !!s.autoConnect;
  $('#optAutoUpdateAssets').value = ['off', 'geo', 'all'].includes(s.autoUpdateAssets) ? s.autoUpdateAssets : 'geo';
  $('#optMux').value = ['auto', 'on', 'off'].includes(s.mux) ? s.mux : 'off';   // off unless the user turned it on
  $('#optBlockAds').checked = !!s.blockAds;
  $('#optSniff').checked = s.enableSniffing !== false;
  $('#optAutoUpdate').checked = s.autoUpdateSubs !== false;
  $('#autoInterval').value = s.autoUpdateInterval || 60;
  $('#customRules').value = customRulesToText(s.customRules || []);

  $$('#routingSeg .seg-btn').forEach(b => b.classList.toggle('active', b.dataset.mode === (s.routingMode || 'global')));
  renderSettingCards();   // the cards mirror the selects, so they follow every load
  syncPreset('#dnsRemotePreset', '#dnsRemoteInput');
  syncPreset('#dnsDirectPreset', '#dnsDirectInput');
  updateGuardRows();
  updateTunAppRows();
}

/**
 * The leak guard only exists inside the tunnel, and the proxy-mode UDP block only
 * exists outside it — so each row is dimmed and disabled in the mode where it does
 * nothing, with a note saying why instead of a control that silently has no effect.
 * Driven by the TUN *switch*, not by the live connection: this is the setting the
 * next connect will be built from.
 */
/**
 * A <select> whose options are CHOICES WITH CONSEQUENCES, drawn as cards.
 *
 * Two of these menus carry whole sentences as option labels — the leak guard's
 * are 110 characters — and no width makes a dropdown a good home for that.
 * Worse, `appearance: none` had them rendering as flat boxes, so the page was a
 * column of identical rectangles hiding the most consequential choices there
 * are.
 *
 * The <select> stays, and stays authoritative: every existing read of `.value`,
 * every `onchange`, and the reconnect dialog that watches these keys keep
 * working untouched. The cards only set the value and dispatch `change`.
 *
 * The label is split on the em dash the strings already use — "Standard — every
 * adapter's DNS…" becomes a title and a description — so there is still ONE
 * copy of each string, and translating the select translates the cards.
 */
function renderOptionCards(selectId, hostId, icons) {
  const sel = $(selectId);
  const host = $(hostId);
  if (!sel || !host) return;
  host.innerHTML = '';
  for (const opt of [...sel.options]) {
    if (opt.hidden) continue;
    const raw = opt.textContent.trim();
    const cut = raw.indexOf('—');
    const title = cut > 0 ? raw.slice(0, cut).trim() : raw;
    const desc = cut > 0 ? raw.slice(cut + 1).trim() : '';
    const card = document.createElement('button');
    card.type = 'button';
    card.className = 'opt-card' + (opt.value === sel.value ? ' active' : '');
    card.dataset.value = opt.value;
    card.disabled = sel.disabled;
    card.innerHTML = `<span class="opt-card-ico">${icons[opt.value] || '•'}</span>
      <span class="opt-card-text"><span class="opt-card-title"></span><span class="opt-card-desc"></span></span>
      <span class="opt-card-check">✓</span>`;
    card.querySelector('.opt-card-title').textContent = title;
    card.querySelector('.opt-card-desc').textContent = desc;
    card.onclick = () => {
      if (sel.disabled || sel.value === opt.value) return;
      sel.value = opt.value;
      // exactly the event picking from the menu would have raised
      sel.dispatchEvent(new Event('change', { bubbles: true }));
      renderOptionCards(selectId, hostId, icons);
    };
    host.appendChild(card);
  }
}

const GUARD_ICONS = { off: '⚪', standard: '🛡', strict: '🔒' };
const BACKEND_ICONS = { 'native-macos': '🍎', 'sing-box': '📦', tun2socks: '🧩' };
const TUNAPP_ICONS = { off: '⚪', exclude: '↩', only: '🎯' };

/** Every card group, from whatever the selects currently hold. */
function renderSettingCards() {
  renderOptionCards('#optLeakGuard', '#leakGuardCards', GUARD_ICONS);
  renderOptionCards('#optTunBackend', '#tunBackendCards', BACKEND_ICONS);
  renderOptionCards('#optTunAppMode', '#tunAppModeCards', TUNAPP_ICONS);
}

function updateGuardRows() {
  const tunOn = !!($('#optTun') && $('#optTun').checked);
  const nativeSelected = state.platform === 'darwin' && $('#optTunBackend').value === 'native-macos';
  $('#nativeMacStrict').hidden = !nativeSelected;
  const guardRow = $('#leakGuardRow');
  if (guardRow) {
    guardRow.classList.toggle('disabled', !tunOn);
    $('#optLeakGuard').disabled = !tunOn;
    $('#guardNeedsTun').hidden = tunOn;
    // the pf anchor behind "strict" has never run on a real Mac (phase 3)
    $('#guardMacNote').hidden = state.platform !== 'darwin' || nativeSelected;
    // Strict blocks everything that does not go through the tunnel — and a
    // "direct" route is exactly that. Say so where the two are chosen, not in a
    // log line the user reads after their bank stops loading.
    const s = state.settings || {};
    const modeBypasses = ['bypass-ir', 'bypass-cn', 'direct'].includes(s.routingMode || 'global');
    const bypasses = s.advancedRouting
      // an advanced plan can send traffic direct through its own rules, and —
      // since v0.15 — through the routing mode it applies underneath them
      // (any routing profile that does: each of them can be the one connected)
      ? advPlans().some(p => (p.rules || []).some(r => r && r.target === 'direct') || p.def === 'direct' ||
        (!!p.useMode && modeBypasses))
      : modeBypasses;
    $('#guardStrictRouting').hidden = !(tunOn && $('#optLeakGuard').value === 'strict' && bypasses);
  }
  // the cards carry the row's disabled state too
  renderSettingCards();
  const udpRow = $('#udpBlockRow');
  if (udpRow) {
    udpRow.classList.toggle('disabled', tunOn);
    $('#optBlockUdpProxy').disabled = tunOn;
    $('#udpBlockNote').hidden = !tunOn;
  }
}

/**
 * The per-app row: the list only exists once a mode is chosen, and each warning
 * appears only while it is actually true.
 *
 * Both warnings are about a choice made a few centimetres away, so they belong
 * here and not in a log line read after the fact. Strict promises that nothing
 * leaves outside the tunnel — which is precisely what "send these apps around
 * it" asks for, so one of the two has to give. And only sing-box can see the
 * process behind a packet; under tun2socks the list is simply not applied.
 *
 * Values come from the controls, not from state.settings, so the row is right
 * the moment a card is clicked and still right after the save comes back.
 */
function updateTunAppRows() {
  const row = $('#tunAppRow');
  if (!row) return;                     // the settings view is not built yet
  const on = ($('#optTunAppMode').value || 'off') !== 'off';
  $('#tunAppsBlock').hidden = !on;
  $('#tunAppStrictNote').hidden = !(on && $('#optLeakGuard').value === 'strict');
  // Every backend that is not sing-box, not just tun2socks: the native macOS
  // service runs a sing-box of its own, but the app never writes that config,
  // so the rule would never reach it either.
  $('#tunAppNeedsSingbox').hidden = !(on && $('#optTunBackend').value !== 'sing-box');
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
    tunAppMode: $('#optTunAppMode').value,
    tunApps: readTunApps(),
    leakGuard: $('#optLeakGuard').value,
    blockUdpInProxyMode: $('#optBlockUdpProxy').checked,
    allowLan: $('#optAllowLan').checked,
    killSwitch: $('#optKillSwitch').checked,
    notifications: $('#optNotify').checked,
    autoConnect: $('#optAutoConnect').checked,
    autoUpdateAssets: $('#optAutoUpdateAssets').value,
    mux: $('#optMux').value,
    blockAds: $('#optBlockAds').checked,
    enableSniffing: $('#optSniff').checked
  };
}
function listFromInput(sel) {
  return $(sel).value.split(',').map(s => s.trim()).filter(Boolean);
}

/**
 * The per-app textarea → the list that is stored: one name per line, trimmed,
 * blank lines dropped, repeats dropped, typing order kept. A name repeated in
 * a routing rule set is not an error the user should be told about — it is
 * just the same name twice — so it is quietly folded away instead.
 */
function readTunApps() {
  const apps = [];
  for (const line of $('#optTunApps').value.split(/\r?\n/)) {
    const name = line.trim();
    if (name && !apps.includes(name)) apps.push(name);
  }
  return apps;
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
  // main returns { settings, pendingReconnect, error? }; tolerate the older bare shape
  state.settings = (res && res.settings) ? res.settings : res;
  state.lastSettingsError = (res && res.error) || null;   // a key main refused (and reverted)
  setPending((res && res.pendingReconnect) || []);

  // The home diagram and the inspector are built from settings, so this is the
  // one place they can go stale. Rebuilding here — on a user action — is what
  // keeps them off the per-second stats path entirely.
  renderTrafficPath(state.connected ? 'connected' : state.connecting ? 'connecting' : 'disconnected');
  renderInspector();

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
// Windows: the logon task starts another copy — point it at this one, or leave it for this run
$('#autostartFix').onclick = () => repointAutostart();
$('#autostartDismiss').onclick = () => { state.autostartStale = null; renderAutostartBanner(); };

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
    renderAdvanced();    // the advanced card names the mode it applies
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

/* TUN backend / leak guard / proxy-mode UDP block — each saves only its own key.
   The backend and the guard both decide whether the per-app row's warnings are
   true, so each of them refreshes that row too. */
$('#optTunBackend').onchange = () => { saveSettings({ tunBackend: $('#optTunBackend').value }); updateGuardRows(); updateTunAppRows(); };
$$('[data-native-service]').forEach(button => {
  button.onclick = async () => {
    const buttons = $$('[data-native-service]');
    buttons.forEach(item => { item.disabled = true; });
    const output = $('#nativeMacStatus');
    output.textContent = t('native.working');
    try {
      const reply = await window.api.nativeService(button.dataset.nativeService);
      if (!reply || !reply.ok) throw new Error(reply?.error || t('native.failed'));
      const known = ['enabled', 'requiresApproval', 'notRegistered', 'notFound'];
      output.textContent = known.includes(reply.status) ? t(`native.${reply.status}`) : t('native.unknown');
      if (reply.active === true) output.textContent += ' · ' + t('native.active');
    } catch (error) {
      // The daemon's words are English and technical. They go on a line of their
      // own, UNDER a sentence the user can read — never glued to the end of it.
      output.replaceChildren(t('native.failed'));
      if (error.message) output.append(document.createElement('br'), error.message);
      toast(t('native.failed'), 'err');
    } finally { buttons.forEach(item => { item.disabled = false; }); }
  };
});
$('#optLeakGuard').onchange = () => { saveSettings({ leakGuard: $('#optLeakGuard').value }); updateGuardRows(); updateTunAppRows(); };
$('#optBlockUdpProxy').onchange = () => saveSettings({ blockUdpInProxyMode: $('#optBlockUdpProxy').checked });

/* per-app routing — the mode saves itself, the list is cleaned up before it is stored */
$('#optTunAppMode').onchange = () => { saveSettings({ tunAppMode: $('#optTunAppMode').value }); updateTunAppRows(); };
$('#optTunApps').onchange = () => saveTunApps();

/** Store the app list, and show back exactly what was stored. */
function saveTunApps() {
  const apps = readTunApps();
  $('#optTunApps').value = apps.join('\n');
  return saveSettings({ tunApps: apps });
}

/**
 * Pick a name instead of typing it. The list is the apps that currently have an
 * open connection — not every running app — and what goes into the box is each
 * one's `exe`: the image file's leaf name (`chrome.exe`, `Google Chrome`),
 * which is the only string sing-box's `process_name` rule matches. The name the
 * OS calls the process by ('chrome') is a different string that matches nothing
 * here — the routing page's picker goes on storing that one, which is why the
 * two ask processOptions() for different values.
 */
$('#btnTunAppsPick').onclick = async () => {
  let res = null;
  try { res = await window.api.listProcesses(); } catch { res = null; }
  // the enumeration itself failed: say what went wrong instead of claiming the
  // machine is running nothing
  if (res && res.error) { toast(res.error, 'err'); return; }
  const procs = (res && res.ok) ? (res.processes || []) : [];
  // nothing to offer: say so rather than opening an empty menu. The list the
  // routing page already loaded is left alone — this failure says nothing about it.
  if (!procs.length) { toast(t('tunapp.pickNone'), 'warn'); return; }
  state.procList = procs;
  const pick = $('#tunAppsPick');
  pick.innerHTML = processOptions('', { exe: true });   // escapes every name it puts in
  pick.value = '';
  pick.hidden = false;
};

$('#tunAppsPick').onchange = () => {
  const name = $('#tunAppsPick').value;
  const ta = $('#optTunApps');
  $('#tunAppsPick').hidden = true;      // picked or dismissed, the menu is done
  if (!name) return;
  ta.value = ta.value.trim() ? ta.value.trimEnd() + '\n' + name : name;
  saveTunApps();                        // a duplicate name folds away in here
};

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
$('#optNotify').onchange = () => saveSettings({ notifications: $('#optNotify').checked });
$('#optAutoConnect').onchange = () => saveSettings({ autoConnect: $('#optAutoConnect').checked });
$('#optAutoUpdateAssets').onchange = () => saveSettings({ autoUpdateAssets: $('#optAutoUpdateAssets').value });
// mux is written into the config: saved, then offered as a reconnect like the other config keys
$('#optMux').onchange = () => saveSettings({ mux: $('#optMux').value });
// Deliberately NOT in readSettingsForm(): a plain "save" must never re-run the
// OS registration. Main refuses and reverts when the OS says no — the switch
// then follows what was actually stored, and the reason is shown.
$('#optLaunchAtLogin').onchange = async () => {
  await saveSettings({ launchAtLogin: $('#optLaunchAtLogin').checked });
  $('#optLaunchAtLogin').checked = !!state.settings.launchAtLogin;
  if (state.lastSettingsError) toast(t('login.failed') + ': ' + state.lastSettingsError, 'err');
};

function updateKillStatus() {
  const el = $('#killStatus');
  if (!el) return;
  if (state.flavor === 'openwrt') {
    // the router's: armed — and whether it blocks right now — comes from the service (a snapshot, a killswitch event)
    const ks = state.killSwitch;
    if (!ks || !ks.armed) { el.textContent = ''; el.className = 'tun-status'; return; }
    el.textContent = t(ks.blocking ? 'kill.routerBlocked' : 'kill.routerArmed');
    el.className = 'tun-status ' + (ks.blocking ? 'warn' : 'ok');
    return;
  }
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
      `<b dir="ltr">${escapeHtml(info.ip)}:${escapeHtml(info.httpPort)}</b> (HTTP) • ` +
      `<b dir="ltr">${escapeHtml(info.ip)}:${escapeHtml(info.socksPort)}</b> (SOCKS)`;
    el.className = 'tun-status ok';
  } else {
    el.textContent = t('lan.noIp');
    el.className = 'tun-status warn';
  }
}

/**
 * OpenWrt: the router IS the tunnel for the LAN, so the switches that only
 * mean something on a desktop go (system proxy, login item, the TUN switch
 * and its backend choice — fixed there, per-app routing — no process behind a
 * forwarded packet, the proxy-mode UDP block, the leak-guard cards) and the
 * device list comes. The parts that read state as they render (the mode card,
 * the TUN status line, Required files, the inspector) check the flavour
 * themselves.
 */
function applyFlavor() {
  const rt = state.flavor === 'openwrt';
  $('#gwRow').hidden = !rt;
  $('#insGatewayRow').hidden = !rt;
  // ...and "DNS managed by the app": on a router the service forces it on (the
  // core must answer every port-53 packet from the LAN), so the switch would lie
  for (const id of ['optSysProxy', 'optLaunchAtLogin', 'optDnsManaged']) {
    const row = $('#' + id).closest('.switch-row');
    if (row) row.hidden = rt;
  }
  // The kill switch row stays on the router, with the router's wording (K1):
  // while the VPN is on and the tunnel is down, the LAN has no internet. The
  // banner's wording and its "off" action follow (K4): turning the VPN off
  // (= disconnect) is what disarms it. Relabelled through data-i18n so a
  // language switch keeps the wording.
  const relabel = (el, key) => { if (!el) return; el.setAttribute('data-i18n', key); el.textContent = t(key); };
  const ksRow = $('#optKillSwitch').closest('.switch-row');
  if (ksRow) {
    ksRow.hidden = false;
    relabel(ksRow.querySelector('.switch-title'), rt ? 'kill.routerTitle' : 'kill.title');
    relabel(ksRow.querySelector('.switch-sub'), rt ? 'kill.routerSub' : 'kill.sub');
  }
  relabel($('#killBanner .kill-banner-text'), rt ? 'kill.routerBlocked' : 'kill.blocked');
  relabel($('#killDisarm'), rt ? 'kill.routerOff' : 'kill.disarm');
  $('#killStatus').hidden = false;
  // "Connect automatically" is, on a router, "Connect when the router starts":
  // after a reboot or a power cut the VPN comes back as it was (B1) — the same
  // setting, named for what it does there
  const acRow = $('#optAutoConnect').closest('.switch-row');
  if (acRow) {
    relabel(acRow.querySelector('.switch-title'), rt ? 'autoconn.routerTitle' : 'autoconn.title');
    relabel(acRow.querySelector('.switch-sub'), rt ? 'autoconn.routerSub' : 'autoconn.sub');
  }
  $('#tunBackendRow').hidden = rt;
  $('#tunAppRow').hidden = rt;
  // The router's tunnel is the whole network's, always (field report G2): no
  // TUN switch (its wording is the desktop's — admin rights, "the system"), in
  // its place one line saying so; no proxy-mode UDP block (there is no proxy
  // mode), and no leak-guard cards (the DNS guard they choose is skipped on a
  // router, where dnsmasq answers the LAN through the tunnel) — except while
  // the store still holds "strict" (a desktop backup restored earlier): that
  // level does reach the router's sing-box (strict_route), so it stays in
  // view, where it can be set back.
  const tunRow = $('#optTun').closest('.switch-row');
  if (tunRow) tunRow.hidden = rt;
  $('#tunRouterNote').hidden = !rt;
  $('#udpBlockRow').hidden = rt;
  const guardHidden = rt && (state.settings || {}).leakGuard !== 'strict';
  $('#leakGuardRow').hidden = guardHidden;
  // The inspector mirrors Settings: a row there that no switch stands behind
  // is the "Gateway" the owner could not place (G1). The whole-network row
  // stands for TUN; the guard row follows the guard (renderInspector).
  $('#insTunRow').hidden = rt;
  $('#insGuardRow').hidden = guardHidden;
  // "Allow LAN" on a router only opens the SOCKS/HTTP ports to the LAN (the
  // whole network is tunnelled either way): named for that, or "off" reads as
  // "the LAN gets no VPN"
  const lanRow = $('#optAllowLan').closest('.switch-row');
  if (lanRow) {
    relabel(lanRow.querySelector('.switch-title'), rt ? 'lan.routerTitle' : 'lan.title');
    relabel(lanRow.querySelector('.switch-sub'), rt ? 'lan.routerSub' : 'lan.sub');
  }
  // remote access is set up in LuCI; this page says where, with links
  $('#gwRemoteRow').hidden = !rt;
  if (rt) renderRemotePointer();
  $('#gwQuicRow').hidden = !rt;
  $('#optLanBlockQuic').checked = !!state.settings.lanBlockQuic;
  if (rt) renderLanDevices();
}
$('#optLanBlockQuic').onchange = async () => {
  // not a reconnect key: the service replaces the nft table under the live tunnel
  await saveSettings({ lanBlockQuic: $('#optLanBlockQuic').checked }, { silent: true });
  toast(t('gw.saved'), 'ok');
};

/** The devices behind the router, each with its "direct" tick. */
async function renderLanDevices() {
  const host = $('#gwList');
  if (!host || state.flavor !== 'openwrt' || !window.api.lanDevices) return;
  let devices = [];
  try { devices = (await window.api.lanDevices()) || []; } catch { devices = []; }
  const bypass = new Set((state.settings.lanBypassMacs || []).map(m => String(m).toLowerCase()));
  // an excluded device that is not on the network right now still shows, so it can be un-excluded
  for (const mac of bypass) if (!devices.some(d => d.mac === mac)) devices.push({ mac, ip: '', name: '', online: false });
  host.innerHTML = '';
  if (!devices.length) {
    const p = document.createElement('p');
    p.className = 'hint';
    p.textContent = t('gw.none');
    host.appendChild(p);
    return;
  }
  for (const d of devices) {
    const row = document.createElement('label');
    row.className = 'gw-item';
    row.innerHTML =
      `<span class="gw-dot${d.online ? ' on' : ''}" title="${escapeHtml(t(d.online ? 'gw.online' : 'gw.offline'))}"></span>` +
      `<span class="gw-name">${escapeHtml(d.name || d.mac)}</span>` +
      `<span class="gw-meta">${escapeHtml(d.ip || '')}${d.ip ? ' · ' : ''}${escapeHtml(d.mac)}</span>` +
      `<span class="gw-direct">${escapeHtml(t('gw.direct'))}</span>` +
      `<input type="checkbox" class="gw-check"${bypass.has(d.mac) ? ' checked' : ''} />`;
    row.querySelector('.gw-check').onchange = async (e) => {
      const next = new Set(bypass);
      if (e.target.checked) next.add(d.mac); else next.delete(d.mac);
      // not a reconnect key: the service replaces the nft set under the live tunnel
      await saveSettings({ lanBypassMacs: [...next] }, { silent: true });
      toast(t('gw.saved'), 'ok');
      renderLanDevices();
    };
    host.appendChild(row);
  }
}
$('#btnGwRefresh').onclick = () => renderLanDevices();

/**
 * Settings, scrolled to one row. A category chip or a search can be hiding the
 * row's card — then the page is un-filtered first, or the jump lands nowhere.
 * Only the content column scrolls: scrollIntoView would scroll the page itself
 * as well and push the frameless window's title bar out of view.
 */
function openSettingAt(sel) {
  showView('settings');
  const el = $(sel);
  if (!el) return;
  const card = el.closest('.card');
  if (card && card.hidden) {
    const all = document.querySelector('.settings-chip[data-category="all"]');
    if (all) all.click();
  }
  const column = el.closest('.content');
  if (column) column.scrollTop += el.getBoundingClientRect().top - column.getBoundingClientRect().top - 12;
}
// The inspector's gateway row is a status, not a switch: its tooltip says what
// it means, and a click opens the one thing about it that can be changed — which
// devices go direct (#gwRow starts with the same explanation).
$('#insGatewayRow').onclick = () => openSettingAt('#gwRow');

/**
 * The router's pointer to remote access (field report 17), its two places as
 * links: LuCI's Remote access page on this router (uhttpd, the router's own
 * port — not this page's) and the guide. The words are gw.remote verbatim; a
 * translation without "LuCI … (" and "docs/remote.md" in it stays plain text.
 * applyI18n resets the paragraph to that plain text, so a language switch
 * renders it again.
 */
function renderRemotePointer() {
  const p = $('#gwRemote');
  if (!p) return;
  const text = t('gw.remote');
  const guide = 'docs/remote.md';
  const a = text.indexOf('LuCI'), b = text.indexOf(' (', a), g = text.indexOf(guide, b);
  if (a < 0 || b < 0 || g < 0) { p.replaceChildren(text); return; }
  const link = (label, href) => {
    const el = document.createElement('a');
    el.textContent = label;
    el.href = href;
    el.target = '_blank';
    el.rel = 'noopener';
    return el;
  };
  p.replaceChildren(
    text.slice(0, a),
    link(text.slice(a, b), `${location.protocol}//${location.hostname}/cgi-bin/luci/admin/services/irnetfree/remote`),
    text.slice(b, g),
    link(guide, 'https://github.com/sadrazkh/Irnetfree_xray-client/blob/main/' + guide),
    text.slice(g + guide.length));
}

$('#btnSaveRules').onclick = async () => {
  const rules = textToCustomRules($('#customRules').value);
  await saveSettings({ customRules: rules });
  await warnAboutGeoCodes(rules);
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
  if (!tcp || tcp.na) return { txt: '—', cls: '' };
  return { txt: tcp.ok ? fmtMs(tcp.ms) : '×', cls: pingClass(tcp.ok ? tcp.ms : -1) };
}

/** Label for any ping result ({ ok, ms } or undefined). */
function pingResultLabel(res) {
  // `na`: nothing to measure this way (a UDP-only server has no TCP port)
  if (!res || res.na) return { txt: '—', cls: '' };
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

/**
 * The servers list, GROUPED BY WHERE EACH CONFIG CAME FROM.
 *
 * Subscription servers already carry `subId` (subscription.js sets it so a
 * refresh can replace them), but the list showed one flat run of cards — with
 * two subscriptions and a few hand-added configs there was no way to tell what
 * belonged to what, or which of them the next refresh was about to replace.
 *
 * Hand-added configs come first: they are the ones a user curates by hand, and
 * the only ones that survive every refresh.
 */
/**
 * How much has EVER gone through a config, in one short string. Empty when
 * nothing has, so a config that has never been used carries no column at all
 * rather than a row of zeroes.
 */
function usageLabel(id) {
  const u = (state.usage || {})[id];
  if (!u || (!u.down && !u.up)) return '';
  return `↓${escapeHtml(fmtBytes(u.down))}<span class="u-sep">·</span>↑${escapeHtml(fmtBytes(u.up))}`;
}

function serverGroups() {
  const byId = new Map((state.subscriptions || []).map(x => [x.id, x]));
  const manual = [];
  const groups = new Map();          // subId -> { name, items }
  for (const s of state.servers) {
    if (!s.subId) { manual.push(s); continue; }
    if (!groups.has(s.subId)) {
      const sub = byId.get(s.subId);
      // A subscription can be deleted while its servers stay behind. Name the
      // group honestly rather than tipping them into the hand-added pile, where
      // the next refresh would look like it had lost them.
      groups.set(s.subId, { name: sub ? sub.name : t('srv.subGone'), sub: sub || null, items: [] });
    }
    groups.get(s.subId).items.push(s);
  }
  const out = [];
  if (manual.length) out.push({ id: '', name: t('srv.manual'), sub: null, items: manual });
  for (const [id, g] of groups) out.push({ id, name: g.name, sub: g.sub, items: g.items });
  return out;
}

/* ------------------- folded groups (remembered per window) ------------------- */
// The groups the user folded, by key ('manual', 'sub:<id>'). Kept the way the
// theme is — in this window's storage, and per browser on the router — and
// open is the default, so a group nobody folded (a new subscription too) shows
// its servers.
const FOLDED_KEY = 'irnetfree.foldedGroups';
const foldedGroups = loadFoldedGroups();
function loadFoldedGroups() {
  try {
    const v = JSON.parse(localStorage.getItem(FOLDED_KEY) || '[]');
    return new Set(Array.isArray(v) ? v.filter((k) => typeof k === 'string') : []);
  } catch { return new Set(); }
}
function setGroupFolded(key, folded) {
  if (folded) foldedGroups.add(key); else foldedGroups.delete(key);
  try { localStorage.setItem(FOLDED_KEY, JSON.stringify([...foldedGroups])); } catch { /* only costs remembering it */ }
}
/** A group's key: the subscription it came from, or the hand-added pile. */
function groupKey(subId) { return subId ? 'sub:' + subId : 'manual'; }

/**
 * A subscription's quota and time left, short enough for its group head:
 * { data, time, level } — empty strings for what it does not report; `level`
 * by the thresholds subUsageHtml() colours its bars with ('' | 'mid' | 'bad').
 * `data` is figures only (it is set left-to-right in both languages): an
 * unlimited quota reads "1.5 GB / ∞".
 */
function subUsageBrief(sub) {
  const out = { data: '', time: '', level: '' };
  const u = sub && sub.usage;
  if (!u) return out;
  const used = (u.upload || 0) + (u.download || 0);
  let pct = 0;
  if (u.total > 0) {
    pct = Math.round(used / u.total * 100);
    out.data = `${fmtBytes(used)} / ${fmtBytes(u.total)}`;
  } else if (used > 0) {
    out.data = `${fmtBytes(used)} / ∞`;
  }
  let days = Infinity;
  if (u.expire > 0) {
    const rem = u.expire - Date.now() / 1000;
    days = rem / 86400;
    out.time = rem <= 0 ? t('sub.expired') : `${fmtDuration(rem)} ${t('sub.left')}`;
  }
  out.level = (pct >= 90 || days < 3) ? 'bad' : (pct >= 70 || days < 7) ? 'mid' : '';
  return out;
}

function renderServers() {
  const list = $('#serverList');
  list.innerHTML = '';
  $('#serverEmpty').hidden = state.servers.length > 0;

  const groups = serverGroups();
  // no headings when there is nothing to tell apart
  const labelled = groups.length > 1 || !!(groups[0] && groups[0].id);
  if (!labelled) {
    for (const g of groups) for (const s of g.items) list.appendChild(serverCard(s));
    return;
  }
  groups.forEach((g, n) => list.appendChild(serverGroup(g, n)));
  refreshSelection();   // a folded group holding the selection says so on its head
}

/**
 * One group of the list. Its head folds it — a button with aria-expanded, the
 * count always on it — and a subscription's head carries that subscription's
 * own refresh, and its quota and time left when it reports them, so it can be
 * looked after from here (adding and editing stay on the Subscriptions page).
 * Any group of two or more configs also carries 📶 (test them all) and ⚡
 * (connect to the fastest of them).
 * A folded group builds no cards until it is opened: a 300-server
 * subscription folded away costs one row.
 */
function serverGroup(g, n) {
  const key = groupKey(g.id);
  const open = !foldedGroups.has(key);
  const wrap = document.createElement('div');
  wrap.className = 'srv-group' + (open ? '' : ' folded');
  wrap.dataset.group = key;

  const head = document.createElement('div');
  head.className = 'srv-group-head';
  const toggle = document.createElement('button');
  toggle.className = 'srv-group-toggle';
  toggle.type = 'button';
  toggle.innerHTML = `<span class="srv-group-chev" aria-hidden="true">▾</span>
    <span class="srv-group-ico" aria-hidden="true">${g.id ? '🔗' : '✎'}</span>
    <span class="srv-group-name"></span><span class="srv-group-count"></span>`;
  toggle.querySelector('.srv-group-name').textContent = g.name;
  toggle.querySelector('.srv-group-count').textContent = String(g.items.length);
  toggle.title = t('srv.groupToggle');
  toggle.setAttribute('aria-expanded', String(open));
  toggle.setAttribute('aria-controls', 'srvGroup' + n);
  head.appendChild(toggle);

  if (g.sub) {
    const brief = subUsageBrief(g.sub);
    if (brief.data || brief.time) {
      const meta = document.createElement('span');
      meta.className = 'srv-group-meta' + (brief.level ? ' ' + brief.level : '');
      meta.title = t('sub.lastUpdate') + ': ' + timeAgo(g.sub.lastUpdated);
      for (const [text, dir] of [[brief.data, 'ltr'], [brief.time, '']]) {
        if (!text) continue;
        const part = document.createElement('span');
        if (dir) part.dir = dir;
        part.textContent = text;
        meta.appendChild(part);
      }
      head.appendChild(meta);
    }
  }

  // 📶 tests every config of the group, ⚡ connects to its fastest (connectAuto);
  // with one config there is nothing to rank or to choose between
  if (g.items.length >= 2) {
    const ids = g.items.map(s => s.id);
    const ping = document.createElement('button');
    ping.className = 'icon-btn srv-group-ping';
    ping.type = 'button';
    ping.textContent = '📶';
    ping.title = t('srv.groupPing');
    ping.setAttribute('aria-label', ping.title);
    ping.onclick = () => { ping.disabled = true; pingMany(ids).finally(() => { ping.disabled = false; }); };
    const fast = document.createElement('button');
    fast.className = 'icon-btn srv-group-fastest';
    fast.type = 'button';
    fast.textContent = '⚡';
    fast.title = t('srv.groupFastest');
    fast.setAttribute('aria-label', fast.title);
    fast.onclick = () => connectAuto({ ids, name: g.name });
    head.appendChild(ping);
    head.appendChild(fast);
  }

  if (g.sub) {
    const refresh = document.createElement('button');
    refresh.className = 'icon-btn srv-group-refresh';
    refresh.type = 'button';
    refresh.textContent = '⟳';
    refresh.title = t('srv.subRefresh');
    refresh.setAttribute('aria-label', refresh.title);
    refresh.onclick = () => {
      refresh.disabled = true;
      refreshSub(g.id).finally(() => { refresh.disabled = false; });
    };
    head.appendChild(refresh);
  }
  wrap.appendChild(head);

  const body = document.createElement('div');
  body.className = 'srv-group-body';
  body.id = 'srvGroup' + n;
  body.hidden = !open;
  if (open) for (const s of g.items) body.appendChild(serverCard(s));
  wrap.appendChild(body);

  toggle.onclick = () => {
    const nowOpen = toggle.getAttribute('aria-expanded') !== 'true';
    setGroupFolded(key, !nowOpen);
    toggle.setAttribute('aria-expanded', String(nowOpen));
    wrap.classList.toggle('folded', !nowOpen);
    body.hidden = !nowOpen;
    if (nowOpen && !body.firstChild) for (const s of g.items) body.appendChild(serverCard(s));
  };
  return wrap;
}

/** One server's card, wired. */
function serverCard(s) {
  const card = document.createElement('div');
  const isActive = s.id === state.activeServerId && state.connected;
  const isSel = s.id === state.selectedServerId;
  card.className = 'server-card' + (isActive ? ' active' : '') + (isSel ? ' selected' : '');
  card.dataset.srvId = s.id;

  const tl = pingResultLabel((state.pings[s.id] || {}).tcp);
  const rl = pingResultLabel((state.pings[s.id] || {}).real);
  const ul = pingResultLabel((state.pings[s.id] || {}).upload);
  // always in the markup, hidden when not selected: refreshSelection() can
  // then move it between cards without rebuilding either of them
  const selBadge = `<span class="sel-badge"${isSel ? '' : ' hidden'}>✓ ${escapeHtml(t('srv.selected'))}</span>`;
  // A JSON config (source 'json'): the badge says so and, on hover, how it runs
  const isJson = s.source === 'json';
  const jsonRaw = isJson && s.jsonMode === 'raw';
  const jsonBadge = isJson
    ? ` <span class="proto-badge proto-json json-badge${jsonRaw ? ' raw' : ''}" title="${escapeHtml(t(jsonRaw ? 'ed.jsonRaw' : 'ed.jsonFull'))}">${escapeHtml(t('srv.jsonBadge'))}</span>`
    : '';
  // what Copy copies: the config itself for a JSON server, the share link otherwise
  const copyKey = isJson ? 'ed.jsonCopy' : 'btn.copy';
  const copyTitle = isJson ? escapeHtml(t('ed.jsonCopy')) : 'copy';

  card.innerHTML = `
    <span class="q-dot ${tl.cls}" data-ping-dot="${escapeHtml(s.id)}"></span>
    <span class="proto-badge proto-${escapeHtml(s.protocol)}">${escapeHtml(s.protocol)}</span>
    <div class="srv-info">
      <div class="srv-name">${escapeHtml(s.name)} ${selBadge}</div>
      <div class="srv-addr">${escapeHtml(s.address)}:${escapeHtml(s.port)}${jsonBadge}</div>
    </div>
    <div class="stat-group">
      <span class="stat" title="${escapeHtml(t('ping.tcp'))}"><i>⚡</i><b class="stat-v ${tl.cls}" data-pbase="stat-v" data-ping="${escapeHtml(s.id)}">${tl.txt}</b></span>
      <span class="stat" title="${escapeHtml(t('ping.real'))}"><i>↓</i><b class="stat-v ${rl.cls}" data-pbase="stat-v" data-ping-real="${escapeHtml(s.id)}">${rl.txt}</b></span>
      <span class="stat" title="${escapeHtml(t('ping.upload'))}"><i>↑</i><b class="stat-v ${ul.cls}" data-pbase="stat-v" data-ping-up="${escapeHtml(s.id)}">${ul.txt}</b></span>
    </div>
    <span class="srv-usage" data-usage="${escapeHtml(s.id)}" title="${escapeHtml(t('srv.usage'))} — ${escapeHtml(t('srv.usageClick'))}">${usageLabel(s.id)}</span>
    <div class="srv-actions">
      <button class="icon-btn ping-srv" data-i18n-title="btn.quickPing" title="ping">⚡</button>
      <button class="icon-btn copy-srv" data-i18n-title="${copyKey}" title="${copyTitle}">⧉</button>
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
  connectGlyph(card.querySelector('.connect-srv')).onclick = (e) => { e.stopPropagation(); connect(s.id); };
  card.querySelector('.del-srv').onclick = (e) => { e.stopPropagation(); deleteServer(s.id); };
  // the lifetime figure is its own clear button — nothing to clear when empty
  card.querySelector('.srv-usage').onclick = (e) => { e.stopPropagation(); clearUsageFor(s.id); };
  return card;
}

/**
 * Selection changed: toggle the class and the badge on the cards that exist.
 * Rebuilding the whole list for one click reset the scroll position and,
 * under a large subscription, cost hundreds of nodes per keystroke.
 */
function refreshSelection() {
  const sel = state.selectedServerId;
  $$('#serverList .server-card[data-srv-id]').forEach((card) => {
    const on = card.dataset.srvId === sel;
    card.classList.toggle('selected', on);
    const badge = card.querySelector('.sel-badge');
    if (badge) badge.hidden = !on;
  });
  // a folded group has no cards to mark: its head says it holds the selection
  const selSrv = srvById(sel);
  const selGroup = selSrv ? groupKey(selSrv.subId) : null;
  $$('#serverList .srv-group[data-group]').forEach((g) => g.classList.toggle('has-sel', g.dataset.group === selGroup));
}

/** Lifetime totals changed: rewrite the spans that show them, nothing else. */
function applyUsageDisplays() {
  $$('[data-usage]').forEach((el) => { el.innerHTML = usageLabel(el.dataset.usage); });
}

/**
 * Forget what one config has ever carried, or all of them (`id` null). The
 * user's own "start over": a subscription that changed hands, a server that
 * was only ever a test. The configs themselves are untouched.
 */
async function clearUsageFor(id) {
  if (!window.api.clearUsage) return;
  if (id != null && !usageLabel(id)) return;             // nothing to clear
  if (!window.confirm(t(id == null ? 'confirm.clearUsageAll' : 'confirm.clearUsageOne'))) return;
  const res = await window.api.clearUsage(id);
  state.usage = (res && res.totals) || {};
  applyUsageDisplays();
  toast(t('t.usageCleared'), 'ok');
}

/* ----------------------------- unified picker (home) ----------------------------- */
const ADV_ID = '__advanced__';
const POOL_ID = '__pool__';
/** The picker's "Auto" row: not a selection but an action — test, then connect to the fastest. */
const AUTO_ID = '__auto__';

/** When each target's last test finished — a group's ⚡ trusts results younger than GROUP_FRESH_MS. */
const pingAt = {};
const GROUP_FRESH_MS = 3 * 60 * 1000;

/**
 * The fastest tested server — of `ids` when given (a group's ⚡), else of every
 * server: real delay first (it proves the tunnel carries traffic), the TCP
 * handshake as the fallback for servers that only have that. null when nothing
 * in it has been tested — the caller runs the test first.
 */
function bestServerId(ids) {
  const pool = ids ? ids.map(srvById).filter(Boolean) : state.servers;
  const scored = pool.map((s) => {
    const p = state.pings[s.id] || {};
    const real = p.real && p.real.ok ? p.real.ms : null;
    const tcp = p.tcp && p.tcp.ok ? p.tcp.ms : null;
    return { id: s.id, key: real != null ? real : (tcp != null ? 100000 + tcp : null) };
  }).filter(x => x.key != null).sort((a, b) => a.key - b.key);
  return scored.length ? scored[0].id : null;
}

/**
 * ⚡: test, then connect to the fastest — of every server (the picker's Auto
 * row: tested only when nothing ever was, as before), or of one group
 * (`scope` = { ids, name }: a group head's ⚡ and the "Fastest — <subscription>"
 * rows), tested again unless all of it was tested in the last GROUP_FRESH_MS.
 */
async function connectAuto(scope) {
  if (state.connecting) {
    // The picker's ⚡ Auto row is the Cancel while connecting (it says so:
    // power.cancelHint). A group's ⚡ and a "⚡ Fastest — <subscription>" row
    // keep their connect label, so a tap there must not quietly cancel the
    // connect in flight: it says what is happening instead.
    if (!scope) return cancelConnect();
    return toast(t('t.autoGroupBusy'), 'warn');
  }
  const ids = scope ? scope.ids : null;
  let best = bestServerId(ids);
  const stale = !!scope && ids.some((id) => !(pingAt[id] > Date.now() - GROUP_FRESH_MS));
  if (!best || stale) { await pingMany(ids || state.servers.map(s => s.id)); best = bestServerId(ids); }
  if (!best) return toast(t(scope ? 't.autoGroupNone' : 't.autoNone'), 'err');
  // The test takes a while. A connect that began meanwhile (another ⚡, a ▶) is
  // the later choice, and connect() below would be its Cancel: leave it be.
  if (scope && state.connecting) return;
  const s = srvById(best);
  const label = scope ? t('picker.autoSub').replace('{name}', () => scope.name) : t('picker.auto');
  toast(`${label} → ${s ? s.name : best}`, 'ok');
  // Already on the group's fastest: connect() would be that connection's toggle.
  if (scope && state.connected && state.activeServerId === best) return;
  return connect(best);
}
function chainById(id) { return state.chains.find(c => c.id === id); }
function isChainId(id) { return !!chainById(id); }
function chainMembers(c) { return ((c && c.members) || []).map(srvById).filter(Boolean); }
function chainReady(c) { return chainMembers(c).length >= 2; }
function anyChainReady() { return state.chains.some(chainReady); }
function isPseudo(id) { return id === ADV_ID || String(id).startsWith(ADV_ID + ':') || id === POOL_ID || isChainId(id); }

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
/**
 * Whether advanced routing can be connected: `id` one selection of it
 * ('__advanced__' = the first profile, '__advanced__:<id>' = that one), or —
 * without `id` — any of it. With routing profiles a profile counts once it has
 * rules or a default; without them (an older back end) today's settings do,
 * and a profile id means nothing.
 */
function advancedReady(id) {
  if (!state.settings.advancedRouting) return false;
  if (!Array.isArray(state.profiles)) {
    if (id !== undefined && id !== ADV_ID) return false;
    return ((state.settings.routeRules || []).length > 0) || !!state.settings.routeDefault;
  }
  return id === undefined ? state.profiles.some(profileReady) : profileReady(profileOfSel(id));
}

/**
 * Which config the picker points at: the first of `candidates` that can still
 * be selected (`valid`), else the first server, else nothing. Pure — the order
 * of the candidates is the caller's (see init and keepSelectionValid).
 */
function resolveSelection(candidates, valid, servers) {
  for (const id of candidates || []) if (id && valid(id)) return id;
  return (servers && servers[0] && servers[0].id) || null;
}

/** Whether `id` can be connected right now: a server, a ready chain, advanced routing or the pool once set up. */
function selectable(id) {
  if (id === ADV_ID || String(id).startsWith(ADV_ID + ':')) return advancedReady(id);
  if (id === POOL_ID) return poolReady();
  if (isChainId(id)) return chainReady(chainById(id));
  return !!srvById(id);
}

/**
 * The selection survives a restart (main's selectedServerId). Checked whenever
 * the picker is drawn — which every change of what can be selected ends in —
 * so one that is gone falls back to the live connection, the last one made,
 * then the first server; and whatever it is now goes to main when it moved.
 */
function keepSelectionValid() {
  const id = resolveSelection([state.selectedServerId, state.activeServerId, state.lastServerId], selectable, state.servers);
  if (id !== state.selectedServerId) {
    state.selectedServerId = id;
    refreshSelection();
  }
  if (id !== state.savedSelection && window.api.setSelection) {
    state.savedSelection = id;
    Promise.resolve(window.api.setSelection(id)).catch(() => { state.savedSelection = undefined; });
  }
}

function selectServer(id) {
  state.selectedServerId = id;
  refreshSelection();
  renderPicker();
  // the path draws the SELECTED config's route, so it follows this choice
  refreshConnLabels();
  // immediate ping feedback for the chosen target (chains ping too; skip adv/pool)
  if (id && id !== ADV_ID && id !== POOL_ID && !String(id).startsWith(ADV_ID + ':') && !state.pings[id]) pingServer(id);
}

function renderPicker() {
  const btnProto = $('#pickerProto');
  const btnName = $('#pickerName');
  const btnPing = $('#pickerPing');
  const menu = $('#pickerMenu');

  // a selection that can no longer be connected (a server deleted or dropped
  // by a refresh, a chain that lost a hop, the pool or advanced routing
  // emptied) falls back — and whatever it is now, main keeps it
  keepSelectionValid();

  const selId = state.selectedServerId;
  const sel = state.servers.find(s => s.id === selId);
  const selChain = chainById(selId);
  const hasAny = state.servers.length || anyChainReady() || advancedReady() || poolReady();
  // the plain '__advanced__' selection (LuCI, an older store) is the first
  // routing profile, and that profile's row is the one marked
  const selKey = selId === ADV_ID && Array.isArray(state.profiles) && state.profiles[0] ? ADV_ID + ':' + state.profiles[0].id : selId;

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
  } else if (selId === ADV_ID || String(selId).startsWith(ADV_ID + ':')) {
    btnProto.hidden = false;
    btnProto.textContent = '🧭';
    btnProto.className = 'proto-badge proto-advanced';
    btnName.textContent = advSelName(selId);
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
    row.className = 'picker-item' + (isSpecial ? ' picker-special' : '') + (id === selId || id === selKey ? ' active' : '');
    const pingPart = pingId
      ? `<span class="stat-group">` +
          `<span class="stat" title="${escapeHtml(t('ping.tcp'))}"><i>⚡</i><b class="stat-v ${tl.cls}" data-pbase="stat-v" data-ping="${escapeHtml(id)}">${tl.txt}</b></span>` +
          `<span class="stat" title="${escapeHtml(t('ping.real'))}"><i>↓</i><b class="stat-v ${rl.cls}" data-pbase="stat-v" data-ping-real="${escapeHtml(id)}">${rl.txt}</b></span>` +
          `<span class="stat" title="${escapeHtml(t('ping.upload'))}"><i>↑</i><b class="stat-v ${ul.cls}" data-pbase="stat-v" data-ping-up="${escapeHtml(id)}">${ul.txt}</b></span>` +
        `</span>` +
        `<button class="pi-ping-btn" title="ping">⚡</button>`
      : '';
    const dot = pingId ? `<span class="q-dot ${tl.cls}" data-ping-dot="${escapeHtml(id)}"></span>` : '<span class="q-dot"></span>';
    row.innerHTML = `${dot}${badgeHtml}<span class="pi-name">${escapeHtml(name)}</span>${pingPart}`;
    row.onclick = () => { selectServer(id); closePicker(); };
    const pb = row.querySelector('.pi-ping-btn');
    if (pb) pb.onclick = (e) => { e.stopPropagation(); pingServer(id); };
    menu.appendChild(row);
  };

  // "Auto": with two or more servers there is something to choose between.
  // Not a selection (the selected target stays what it was) — a click tests
  // and connects, and the picker then shows the server that won.
  if (state.servers.length >= 2) {
    const row = document.createElement('div');
    row.className = 'picker-item picker-special picker-auto';
    row.innerHTML = `<span class="q-dot"></span><span class="proto-badge proto-auto">⚡</span><span class="pi-name">${escapeHtml(t(state.connecting ? 'power.cancelHint' : 'picker.auto'))}</span>`;
    row.onclick = () => { closePicker(); connectAuto(); };
    menu.appendChild(row);
  }
  // "Fastest — <subscription>": the same ⚡ for one subscription, when there are
  // groups to choose between. The Servers page has the hand-added pile's own.
  const groups = serverGroups();
  if (groups.length >= 2) {
    for (const g of groups) {
      if (!g.id || g.items.length < 2) continue;
      const row = document.createElement('div');
      row.className = 'picker-item picker-special picker-auto picker-auto-sub';
      row.innerHTML = '<span class="q-dot"></span><span class="proto-badge proto-auto">⚡</span><span class="pi-name"></span>';
      row.querySelector('.pi-name').textContent = t('picker.autoSub').replace('{name}', () => g.name);
      row.onclick = () => { closePicker(); connectAuto({ ids: g.items.map(s => s.id), name: g.name }); };
      menu.appendChild(row);
    }
  }
  if (poolReady()) addRow(POOL_ID, '<span class="proto-badge proto-pool">🧩</span>', t('picker.pool') + ' (' + poolEnabledValid().length + ')', null, true);
  if (Array.isArray(state.profiles)) {
    // one 🧭 row per routing profile that has rules or a default
    if (state.settings.advancedRouting) {
      for (const p of state.profiles) {
        if (profileReady(p)) addRow(ADV_ID + ':' + p.id, '<span class="proto-badge proto-advanced">🧭</span>', p.name || t('picker.advanced'), null, true);
      }
    }
  } else if (advancedReady()) addRow(ADV_ID, '<span class="proto-badge proto-advanced">🧭</span>', t('picker.advanced'), null, true);
  for (const c of state.chains) {
    if (chainReady(c)) addRow(c.id, '<span class="proto-badge proto-chain">⛓</span>', c.name, c.id, true);
  }
  for (const s of state.servers) {
    addRow(s.id, `<span class="proto-badge proto-${escapeHtml(s.protocol)}">${escapeHtml(s.protocol)}</span>`, s.name, s.id, false);
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
 * Text that opens like a JSON document: an object, or an array of them. Only a
 * routing hint — whether it is a config at all is parseMany's call (main side),
 * which also reads a WireGuard `[Interface]` blob first (smartImport checks that
 * before this, so an `[` here is never a .conf).
 */
function looksLikeJsonText(text) {
  // \x7b is "{" — an escape, so the tests that cut functions out of this file by counting braces keep their count
  return /^\s*[\[\x7b]/.test(String(text || ''));
}

/** The first import error's reason, short enough for a toast ('' when there is none). */
function importErrorReason(errors) {
  const e = (errors || [])[0];
  const why = e ? String((e && e.error) || (typeof e === 'string' ? e : '')) : '';
  return why.length > 140 ? why.slice(0, 137) + '…' : why;
}

/**
 * Smart import: figures out what was pasted and routes it correctly.
 *  - http(s) lines  -> added & fetched as subscriptions (auto-update capable)
 *  - vless/vmess/…  -> imported as servers
 *  - http proxy link -> imported as a server (see HTTP_PROXY_LINK above)
 *  - base64 blob    -> decoded & imported as servers (handled by parseMany)
 *  - JSON config(s) -> sent whole to parseMany (one server per config, or per balancer outbound)
 *  - irnetfree://routing/… -> a routing profile's or a chain's share link: its own preview, then import
 * Mixed input works too (URLs become subs, the rest become servers).
 */
async function smartImport(text) {
  text = String(text || '').trim();
  if (!text) return;
  // A routing or chain share link carries servers, chains and a profile in one
  // line: nothing is written before its preview has been seen and accepted.
  if (/^irnetfree:\/\/routing\//i.test(text)) return openRoutingImport(text);
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
  // Pasted JSON — one Xray / sing-box config, or an array of them — is one
  // document: it goes to the main process exactly as typed, never split into
  // lines (parseMany reads it before it looks for links).
  if (looksLikeJsonText(text)) {
    const res = await window.api.importServers(text);
    state.servers = res.servers;
    if (!state.selectedServerId && state.servers.length) state.selectedServerId = state.servers[0].id;
    renderServers(); renderPicker(); renderChains(); renderPool();
    const errCount = (res.errors || []).length;
    const why = importErrorReason(res.errors);
    const added = res.added || 0;
    toast(added ? `${added} ${t('t.serversAdded')}` + (errCount ? ` (${errCount} ${t('t.errors')}${why ? ': ' + why : ''})` : '')
      : (why ? `${t('t.failed')}: ${why}` : t('t.nothingFound')), added ? 'ok' : 'err');
    return;
  }
  const lines = text.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
  const isSubUrl = (l) => /^https?:\/\//i.test(l) && !HTTP_PROXY_LINK.test(l);
  const urlLines = lines.filter(isSubUrl);
  const configText = lines.filter(l => !isSubUrl(l)).join('\n');

  let subCount = 0, subAdded = 0, srvAdded = 0, errCount = 0, firstWhy = '';

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
    firstWhy = importErrorReason(res.errors);
  }

  if (!state.selectedServerId && state.servers.length) state.selectedServerId = state.servers[0].id;
  renderServers(); renderPicker(); renderSubs(); renderChains(); renderPool();

  const parts = [];
  if (subCount) parts.push(`${subCount} ${t('t.subAddedShort')} • ${subAdded} ${t('sub.servers')}`);
  if (srvAdded || (configText && !subCount)) parts.push(`${srvAdded} ${t('t.serversAdded')}`);
  const ok = subCount || srvAdded;
  // the first error's reason rides along: "Clash YAML is not supported — use the
  // subscription link" is the whole point of that refusal
  const msg = (parts.join(' • ') || t('t.nothingFound')) + (errCount ? ` (${errCount} ${t('t.errors')}${firstWhy ? ': ' + firstWhy : ''})` : '');
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
  // ignore unrelated clipboard text; a .conf blob counts as importable too, and
  // so does a routing / chain share link (smartImport opens its preview)
  const looksImportable = /^(https?:\/\/|vless:\/\/|vmess:\/\/|trojan:\/\/|ss:\/\/|socks:\/\/|socks5:\/\/|wireguard:\/\/|wg:\/\/|hysteria2:\/\/|hy2:\/\/|irnetfree:\/\/routing\/)/im.test(text.trim())
    || /[A-Za-z0-9+/=]{24,}/.test(text.trim())
    || (/^\s*\[interface\]/im.test(text) && /^\s*\[peer\]/im.test(text))
    || (looksLikeJsonText(text) && text.includes('"outbounds"'));   // an Xray / sing-box config
  if (!looksImportable) return;
  e.preventDefault();
  toast(t('t.pasteDetected'));
  smartImport(text.trim());
});

async function deleteServer(id) {
  state.servers = await window.api.deleteServer(id);
  delete state.pings[id];
  // the picker falls back to the live connection, the last one made, then the first server (keepSelectionValid)
  if (state.selectedServerId === id) state.selectedServerId = null;
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
  renderAdvanced();   // every target is gone: the rules and the flow tree say so
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
  pingAt[id] = Date.now();
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
  pingAt[id] = Date.now();
  applyPingDisplays(id);
  return real;
}

/** Ping many: TCP for all in parallel, then real delay for all through ONE
 * throwaway core per engine (see ping:realMany). Falls back to one core per
 * target when the backend is older than this renderer. */
async function pingMany(ids) {
  ids = [...new Set(ids.filter(Boolean))];
  if (!ids.length) return;
  toast(t('t.pingingAll'));
  ids.forEach(setPingPending);
  await Promise.all(ids.map(pingTcpOnly));
  ids.forEach((id) => setPhasePending(id, 'data-ping-real'));
  if (window.api.pingRealMany) {
    const res = await window.api.pingRealMany(ids);
    for (const id of ids) {
      state.pings[id] = Object.assign(state.pings[id] || {}, { real: (res && res[id]) || { ok: false, error: 'no result' } });
      pingAt[id] = Date.now();
      applyPingDisplays(id);
    }
  } else {
    for (const id of ids) await pingRealOnly(id);
  }
  renderPicker();
  toast(t('t.testDone'), 'ok');
}

$('#btnPingAll').onclick = () => pingMany(state.servers.map(s => s.id));
$('#btnClearUsage').onclick = () => clearUsageFor(null);

/* quick ping (home) — fills the TCP ping + Real delay cards for one target */
async function quickPing(id) {
  if (!id || id === ADV_ID || id === POOL_ID || String(id).startsWith(ADV_ID + ':')) return;
  $('#statTcp').textContent = '...';
  $('#statReal').textContent = '...';
  const tcp = await window.api.pingTcp(id);
  $('#statTcp').textContent = tcp.ok ? tcp.ms + 'ms' : (tcp.na ? '—' : t('t.error'));
  const real = await window.api.pingReal(id);
  $('#statReal').textContent = real.ok ? real.ms + 'ms' : t('t.error');
  state.pings[id] = Object.assign(state.pings[id] || {}, { tcp, real });
  pingAt[id] = Date.now();
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
$('#btnDiagnostics').onclick = () => window.IRNFDiagnostics.open();
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
// The connect this window is waiting on, and the last one the user cancelled:
// a cancelled connect that then fails has failed because of the cancel, and
// is no error to show.
let connectSeq = 0;
let cancelledSeq = 0;

async function connect(id) {
  // A connect in flight (or a rebuild): every control that would start one is
  // its Cancel. It used to do nothing here, so a connect that hung — a dead
  // server, no network — could only be waited out.
  if (state.connecting) return cancelConnect();
  if (state.connected && state.activeServerId === id) return disconnect();
  // TUN wanted but not elevated (Windows): offer to relaunch as admin first.
  if (state.settings.tunMode && state.tunAvailable && !state.elevated && state.platform === 'win32') {
    if (await promptRelaunchAdmin()) return;
  }
  selectServer(id);
  const seq = ++connectSeq;
  state.connecting = true;
  setConnUI('connecting', id);
  try {
    await window.api.connect(id);
  } catch (e) {
    if (seq <= cancelledSeq) return;   // the 'disconnected' the Cancel brought is the last word
    state.connecting = false;
    setConnUI('error');
    toast(t('t.connectFailed') + ': ' + e.message, 'err');
    // the official core refused a plaintext config and the fork is not installed
    if (/Xray-PattN/.test(e.message) && !(state.assets && state.assets['xray-pattn'])) openFilesModal(['xray-pattn']);
  }
}

async function disconnect() {
  try { await window.api.disconnect(); } catch (e) { toast(e.message, 'err'); }
}

/**
 * Stop the connect in flight. It is a disconnect: main's (or the service's)
 * disconnect overtakes the connect, which gives way at its next step and
 * undoes whatever it started after the teardown, and the 'disconnected' status
 * brings every window — and every browser on the router — back.
 */
function cancelConnect() {
  cancelledSeq = connectSeq;
  $('#connState').textContent = t('state.cancelling');
  return disconnect();
}

$('#powerBtn').onclick = () => {
  if (state.connecting) return cancelConnect();
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
  } else if (effId === ADV_ID || String(effId).startsWith(ADV_ID + ':')) {
    srv.textContent = '🧭 ' + advSelName(effId);
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
  // Reconnect only makes sense over a live tunnel — there is nothing to
  // rebuild otherwise, and the IPC would refuse it anyway.
  const rc = $('#btnReconnect');
  if (rc) rc.hidden = stateStr !== 'connected';
  const tbState = $('#tbState');
  if (tbState) {
    tbState.textContent = stateStr === 'connected' ? t('tb.online')
      : stateStr === 'connecting' ? t('tb.wait') : t('tb.offline');
  }
  startUptime(stateStr === 'connected');
  renderTrafficPath(stateStr);
  renderInspector();
  renderConnIssues(stateStr);
  refreshConnectControls();
}

/**
 * While a connect is in flight every control that would start one says what it
 * does now: Cancel (see connect()). The power button's tooltip and accessible
 * name, the ▶ of each server and chain, the pool's connect button and the
 * picker's Auto row — rewritten where they exist; the ones built later ask
 * connectGlyph() themselves.
 */
function refreshConnectControls() {
  const busy = !!state.connecting;
  const hint = t(busy ? 'power.cancelHint' : state.connected ? 'power.disconnect' : 'power.connect');
  const power = $('#powerBtn');
  power.title = hint;
  power.setAttribute('aria-label', hint);
  $$('.connect-srv, .ch-connect').forEach((b) => connectGlyph(b));
  const pool = $('#btnPoolConnect');
  if (pool) pool.textContent = t(busy ? 'power.cancel' : 'pool.connect');
  const auto = $('#pickerMenu .picker-auto .pi-name');
  if (auto) auto.textContent = t(busy ? 'power.cancelHint' : 'picker.auto');
}

/** A ▶ button: play while idle, stop (the connect's Cancel) while one is in flight. */
function connectGlyph(btn) {
  const busy = !!state.connecting;
  btn.textContent = busy ? '■' : '▶';
  btn.title = t(busy ? 'power.cancel' : 'power.connect');
  btn.setAttribute('aria-label', btn.title);
  return btn;
}

/* ------------------------- title-bar uptime clock ------------------------- */

/**
 * How long the tunnel has been up. One setInterval that only formats a number
 * — it starts when the tunnel comes up and is cleared the moment it goes down,
 * so a disconnected app has no timer running at all.
 */
let uptimeTimer = null;
let uptimeFrom = 0;
/** `from`: when the service says the tunnel came up (a snapshot) — else now. */
function startUptime(on, from) {
  const el = $('#tbUptime');
  const meta = $('#connMeta');
  if (!on) {
    if (uptimeTimer) { clearInterval(uptimeTimer); uptimeTimer = null; }
    uptimeFrom = 0;
    if (el) el.textContent = '';
    if (meta) meta.textContent = state.xrayVersion ? 'core ' + state.xrayVersion : '';
    return;
  }
  if (uptimeTimer) {                    // already counting this connection
    if (from) uptimeFrom = from;        // …but the service knows better when it came up
    return;
  }
  uptimeFrom = from || Date.now();
  const tick = () => {
    const s = Math.max(0, Math.floor((Date.now() - uptimeFrom) / 1000));
    const hh = String(Math.floor(s / 3600)).padStart(2, '0');
    const mm = String(Math.floor((s % 3600) / 60)).padStart(2, '0');
    const ss = String(s % 60).padStart(2, '0');
    const clock = `${hh}:${mm}:${ss}`;
    if (el) el.textContent = clock;
    if (meta) meta.textContent = (state.xrayVersion ? 'core ' + state.xrayVersion + '\n' : '') + 'uptime ' + clock;
  };
  tick();
  uptimeTimer = setInterval(tick, 1000);
}

/* ---------------------- the connection as one fact (snapshot) ---------------------- */

/**
 * What the service says the connection IS — app:init.conn on every page load
 * and the first event of every events (re)connect (web-api.js). Applied
 * idempotently: no toast, no log line, the uptime from the service's `since`.
 * A phone that reloads a background tab used to see "disconnected" while the
 * tunnel was up, with no event ever coming to correct it (v1.16 S1).
 */
function applyConnSnapshot(conn) {
  if (!conn || !conn.state) return;
  const id = conn.serverId || null;
  state.wasReconnecting = false;
  if (conn.state === 'connected') {
    state.connected = true;
    state.connecting = false;
    state.activeServerId = id;
    state.activeEngine = conn.engine || '';
    setConnUI('connected', id);
    startUptime(true, conn.since || null);
  } else if (conn.state === 'connecting') {
    state.connected = false;
    state.connecting = true;
    setConnUI('connecting', id || state.activeServerId);
  } else if (conn.state === 'reconnecting' || conn.state === 'waiting') {
    state.connected = false;
    state.connecting = true;
    state.wasReconnecting = conn.state === 'reconnecting';
    state.reconnectReason = conn.reason || '';
    setConnUI('connecting', id || state.activeServerId);
    $('#connState').textContent = attemptText(conn.state, conn.attempt);
  } else if (conn.state === 'error') {
    state.connected = false;
    state.connecting = false;
    state.activeServerId = null;
    state.activeEngine = '';
    setConnUI('error');
    showErrorReason(conn.reason);
  } else {
    state.connected = false;
    state.connecting = false;
    state.activeServerId = null;
    state.activeEngine = '';
    setConnUI('disconnected');
  }
  applyKillSwitchState(conn.killSwitch);
  renderServers();
  renderPicker();
}

/**
 * The router's error state with its reason, as LuCI's badge says it
 * ("Error: …"): a connect the router made on its own (at boot, in a
 * recovery) that the core refused — a finalmask server with no Xray-PattN —
 * has no click waiting for a toast, and a bare "Error" said nothing.
 */
function showErrorReason(reason) {
  if (state.flavor === 'openwrt' && reason) $('#connState').textContent = t('state.error') + ': ' + reason;
}

/* ------------- what the connection did not do, and what this PC does to it (v1.16.3) ------------- */

/**
 * The lines Home keeps under the connection state while it is up: failures of
 * THIS connection that were only ever a log line — TUN was asked for and the
 * tunnel did not come up (the connect went on proxy-only), or the tunnel came
 * up and the leak guard did not (the adapters kept their own resolvers, so
 * names can leave outside it). A guardError with no tunnel is the proxy mode's
 * UDP block, not the guard: not said here.
 */
function connIssuesFrom(d) {
  const out = [];
  if (!d) return out;
  if (d.tunError) out.push({ id: 'proxyOnly', reason: String(d.tunError) });
  if (d.tun && d.guardError) out.push({ id: 'guardFailed', reason: String(d.guardError) });
  return out;
}

/**
 * A notice in the user's language: 'notice.<id>' with each {field} filled in
 * from the notice, literally. A field main cannot say in the user's language —
 * a record's group "added by hand" — comes as { t: <i18n key> } and is this
 * window's own string.
 */
function noticeText(n) {
  if (!n || !n.id) return '';
  return t('notice.' + n.id).replace(/\{(\w+)\}/g, (m, k) => {
    const v = n[k];
    if (v == null) return m;
    if (typeof v === 'object') return typeof v.t === 'string' ? t(v.t) : m;
    return String(v);
  });
}

/** Those lines: shown while connected, gone with the connection; repainted by setConnUI (a language switch too). */
function renderConnIssues(stateStr) {
  const box = $('#connIssues');
  if (!box) return;
  const list = stateStr === 'connected' ? (state.connIssues || []) : [];
  box.textContent = '';
  for (const n of list) {
    const line = document.createElement('div');
    line.className = 'conn-issue';
    line.textContent = noticeText(n);
    box.appendChild(line);
  }
  box.hidden = !list.length;
}

/**
 * What a 'connected' status says in toasts, in order: the failures above (the
 * tunError toast, now saying what it means), the missing geo files as before,
 * then what main found (Windows only: a WireGuard identity stored twice, a LAN
 * that holds what a routed tunnel needs, managed DNS off for a corporate
 * resolver), each with what to do. A recovery that finds the same thing again
 * never repeats it. This PC's findings come back with the next connection (its
 * network may have changed); a WireGuard identity stored twice is a fact about
 * the store, the same on every connect — said once per run.
 */
function connectToasts(d) {
  const out = connIssuesFrom(d).map(n => ({ msg: noticeText(n), kind: 'err', ms: 9000 }));
  if (d && d.geoWarn) out.push({ msg: d.geoWarn, kind: 'warn', ms: 2600 });
  if (!state.noticesToasted) state.noticesToasted = new Set();
  if (!state.noticesOnce) state.noticesOnce = new Set();
  const listed = new Set();
  for (const n of (d && Array.isArray(d.notices)) ? d.notices : []) {
    if (!n || !n.id) continue;
    const key = JSON.stringify(n);
    // wgSharedKey / wgSharedAddress and their …Sub forms (the twin in a subscription): the store's, once per run
    const said = /^wgShared(Key|Address)(Sub)?$/.test(n.id) ? state.noticesOnce : state.noticesToasted;
    if (said.has(key) || listed.has(key)) continue;
    listed.add(key);
    // said once it is on screen: a series cut short (the connection went) leaves it to the next connection
    out.push({ msg: noticeText(n), kind: 'warn', ms: 12000, shown: () => said.add(key) });
  }
  return out;
}

/**
 * Toasts one after another: there is one toast element, and a second toast()
 * replaces the first unread. One series at a time — a new one ends the last,
 * and so does the connection going (cancelToastSeries); an item's `shown` runs
 * once it is actually on screen.
 */
function toastSeries(items) {
  cancelToastSeries();
  const list = (items || []).filter(i => i && i.msg);
  const next = () => {
    toastSeries._t = null;
    const it = list.shift();
    if (!it) return;
    toast(it.msg, it.kind, it.ms);
    if (typeof it.shown === 'function') it.shown();
    if (list.length) toastSeries._t = setTimeout(next, it.ms + 300);
  };
  next();
}

/** The rest of a series, not shown yet, goes with its connection (a disconnect, a switch, a rebuild). */
function cancelToastSeries() {
  clearTimeout(toastSeries._t);
  toastSeries._t = null;
}

/* ------------- Windows: the logon task starts another copy (v1.16.3, L1) ------------- */

/**
 * Asked once the window has loaded — main only READS the task: a logon task
 * that starts ANOTHER copy of the app (an old build from before the v1.14 DNS
 * fix, a portable that was moved) gets a banner whose button points it at this
 * one. Silent everywhere else: off Windows, on the router's page (its web api
 * has no such call), and where the task is this copy, absent or unreadable.
 */
async function checkAutostart() {
  if (state.platform !== 'win32' || !window.api.autostartCheck) return;
  let r = null;
  try { r = await window.api.autostartCheck(); } catch { return; }
  state.autostartStale = (r && r.stale) ? { task: r.taskExe, current: r.currentExe } : null;
  renderAutostartBanner();
}

function renderAutostartBanner() {
  const banner = $('#autostartBanner');
  if (!banner) return;
  const s = state.autostartStale;
  banner.hidden = !s;
  if (s) $('#autostartBannerText').textContent = noticeText(Object.assign({ id: 'autostartStale' }, s));
}

/** The banner's button — the one write of this check, and only on this click. */
async function repointAutostart() {
  let r = null;
  try { r = await window.api.autostartRepoint(); } catch (e) { r = { ok: false, error: (e && e.message) || String(e) }; }
  if (r && r.ok) {
    state.autostartStale = null;
    renderAutostartBanner();
    toast(t('notice.autostartFixed'), 'ok');
  } else {
    toast(noticeText({ id: 'autostartFixFailed', error: (r && r.error) || '' }), 'err', 8000);
  }
}

/** "Reconnecting… (attempt n)" / "Waiting for internet… (attempt n)" — the router's two in-between states. */
function attemptText(kind, n) {
  return t(kind === 'waiting' ? 'state.waiting' : 'state.reconnectingN').replace('{n}', String(n || 1));
}

/**
 * The router's kill switch, from a snapshot or a killswitch event:
 * {enabled, armed, blocking} — the banner shows while it blocks the LAN
 * (the tunnel is down and the VPN is meant to be on; "Turn the VPN off" =
 * disconnect, which disarms it).
 */
function applyKillSwitchState(ks) {
  if (!ks || typeof ks !== 'object' || state.flavor !== 'openwrt') return;
  state.killSwitch = ks;
  state.killEngaged = !!ks.blocking;
  const banner = $('#killBanner');
  if (banner) banner.hidden = !ks.blocking;
  if (typeof updateKillStatus === 'function') updateKillStatus();
}

/* ---------------------------- the traffic path ---------------------------- */

/** A node in the path diagram. */
function pathNode(ico, name, meta, cls) {
  const el = document.createElement('div');
  el.className = 'path-node' + (cls ? ' ' + cls : '');
  el.innerHTML = `<span class="path-ico">${ico}</span>
    <span class="path-name"></span>
    <span class="path-meta"></span>`;
  el.querySelector('.path-name').textContent = name;
  el.querySelector('.path-meta').textContent = meta || '';
  return el;
}

function pathLink(live, capId) {
  const el = document.createElement('div');
  el.className = 'path-link' + (live ? ' live' : '');
  if (capId) {
    const cap = document.createElement('span');
    cap.className = 'path-cap';
    cap.id = capId;
    el.appendChild(cap);
  }
  return el;
}

/** Short label for a routing target, in the user's language. */
function targetLabel(target) {
  if (!target || target === 'direct') return t('path.direct');
  if (target === 'block') return t('path.block');
  if (target === 'chain') return '⛓';
  if (String(target).indexOf('chain:') === 0) {
    const c = (state.chains || []).find(x => x.id === String(target).slice(6));
    return '⛓ ' + (c ? c.name : '—');
  }
  const s = (state.servers || []).find(x => x.id === target);
  return s ? s.name : '—';
}


/** The outbound tag configBuilder will have given a routing target. */
function outboundTagFor(target) {
  if (!target || target === 'direct') return 'direct';
  if (target === 'block') return 'block';
  if (target === 'chain') return 'out-chain';
  if (String(target).indexOf('chain:') === 0) return 'out-chain-' + String(target).slice(6);
  return 'out-' + target;
}

/** A base's key inside configBuilder's tags: the server's id, or 'chain-<cid>' for a chain. */
function baseKeyOf(base) {
  return String(base).indexOf('chain:') === 0 ? 'chain-' + String(base).slice(6) : String(base);
}

/** The tag of a target dialled through a base: 'out-<id>@<baseKey>' / 'out-chain-<cid>@<baseKey>'. */
function viaTagFor(target, base) { return outboundTagFor(target) + '@' + baseKeyOf(base); }

/** A base's own outbound (its exit, shared by everything through it): 'base-<id>' / 'base-chain-<cid>'. */
function baseTagFor(base) { return 'base-' + baseKeyOf(base); }

/** First of `tags` the core actually reported, so single/chain ('proxy') and
 *  advanced ('out-…') plans can share one lookup. */
function pickTag(per, tags) {
  for (const tg of tags) if (per && per[tg]) return tg;
  return tags[0];
}

/** A traffic caption element bound to an outbound tag. */
function trafficSpan(tags) {
  const el = document.createElement('span');
  el.className = 'pr-traffic';
  el.dataset.tags = tags.join(',');
  el.textContent = '—';
  return el;
}

/**
 * What is going where.
 *
 * Two things it must get right, both of which it used to get wrong:
 *
 *  1. It follows the CONFIG THAT IS SELECTED, not the settings. Advanced rules
 *     are drawn only when the advanced entry is the one being connected —
 *     picking a single server used to still show the rule fan-out, which is
 *     why the picture looked unrelated to the choice above it.
 *  2. Every hop carries ITS OWN traffic, read per outbound from the core's
 *     counters, so "how much went through this config" is answerable at a
 *     glance instead of being one grand total for everything at once.
 *
 * Built on a status change and on a settings save — NEVER on a stats tick. The
 * per-second update is applyPathTraffic(), which only writes text into the
 * captions this function created.
 */
function renderTrafficPath(stateStr) {
  const host = $('#trafficPath');
  if (!host) return;
  const s = state.settings || {};
  const live = stateStr === 'connected';
  // While a tunnel is up, draw what is ACTUALLY running. While idle, draw what
  // the picker is pointing at — `activeServerId` survives in the store as
  // "last connected", so preferring it when disconnected made the diagram
  // ignore the config the user had just chosen.
  const busy = stateStr === 'connected' || stateStr === 'connecting';
  const id = busy
    ? (state.activeServerId || state.selectedServerId)
    : (state.selectedServerId || state.activeServerId);
  const chain = chainById(id);
  const frag = document.createDocumentFragment();

  frag.appendChild(pathNode('🖥', t('path.device'), s.tunMode ? 'TUN' : 'SOCKS/HTTP'));

  if (id === ADV_ID || String(id).startsWith(ADV_ID + ':')) {
    // the fan-out: one line per rule, each with its own figures — of the
    // routing profile this selection connects, with the base a line dials
    // through ("via …"); today's settings on a back end without profiles
    frag.appendChild(pathLink(live, 'pathCapIn'));
    const rules = document.createElement('div');
    rules.className = 'path-rules';
    const prof = profileOfSel(id);
    const src = prof || { rules: s.routeRules || [], def: s.routeDefault };
    const list = (src.rules || []).filter(r => r && r.value && r.target);
    const SHOWN = 4;
    list.slice(0, SHOWN).forEach((r, i) => {
      rules.appendChild(pathRule(String(i + 1).padStart(2, '0'), r.value, r.target, prof ? ruleVia(r, prof) : null));
    });
    if (list.length > SHOWN) {
      const more = document.createElement('div');
      more.className = 'path-rule';
      more.innerHTML = '<span class="pr-idx">··</span><span class="pr-cond"></span>';
      more.querySelector('.pr-cond').textContent = t('path.andMore').replace('{n}', list.length - SHOWN);
      rules.appendChild(more);
    }
    // a profile without a default takes the first server, as the builder does (and its flow tree says)
    const defTarget = src.def || (prof && state.servers[0] && state.servers[0].id) || 'direct';
    const def = pathRule('↓', t('path.rest'), defTarget, prof ? ruleVia({ target: defTarget, via: prof.defVia }, prof) : null);
    def.classList.add('is-default');
    def.querySelector('.pr-cond').classList.add('is-label');
    rules.appendChild(def);
    frag.appendChild(rules);
  } else if (chain) {
    // every hop, in order, with the exit carrying the figures
    const members = chainMembers(chain);
    members.forEach((m, i) => {
      frag.appendChild(pathLink(live, i === 0 ? 'pathCapIn' : null));
      const node = pathNode('🛡', m.name, (m.protocol || '').toUpperCase(),
        live && i === members.length - 1 ? 'exit' : '');
      if (i === members.length - 1) node.appendChild(trafficSpan(['proxy', outboundTagFor(chain.id ? 'chain:' + chain.id : 'chain')]));
      frag.appendChild(node);
    });
    if (!members.length) frag.appendChild(pathNode('🛡', chain.name, '', ''));
  } else if (id === POOL_ID) {
    frag.appendChild(pathLink(live, 'pathCapIn'));
    const rules = document.createElement('div');
    rules.className = 'path-rules';
    for (const e of poolEnabledValid()) {
      rules.appendChild(pathRule(String(e.socksPort), e.name, e.target));
    }
    frag.appendChild(rules);
  } else {
    frag.appendChild(pathLink(live, 'pathCapIn'));
    const srv = srvById(id);
    const node = pathNode('🛡', srv ? srv.name : t('path.noServer'),
      srv ? (srv.protocol || '').toUpperCase() : '', live ? 'exit' : '');
    node.appendChild(trafficSpan(['proxy', outboundTagFor(id)]));
    frag.appendChild(node);
    frag.appendChild(pathLink(live));
  }

  // the exit IP is whatever the last check found — read from the readout that
  // already holds it rather than keeping a second copy in sync
  const ipEl = $('#statIp');
  const ip = ipEl && ipEl.textContent !== '—' ? ipEl.textContent : '';
  frag.appendChild(pathNode('🌐', t('path.internet'), live ? ip : t('path.offline')));
  host.replaceChildren(frag);
  applyPathTraffic(lastPerOutbound);
  // the routing page's flow tree is live only while its profile is the one up
  applyFlowTraffic(lastPerOutbound);
}

/**
 * One "condition → target" line, with its own traffic caption. `via`: the base
 * the target dials through (a routing profile's), said as "via <base>" — its
 * figures are then that target's own outbound through the base.
 */
function pathRule(idx, cond, target, via) {
  const row = document.createElement('div');
  row.className = 'path-rule';
  const kind = target === 'direct' ? ' to-direct' : target === 'block' ? ' to-block' : ' to-proxy';
  row.innerHTML = `<span class="pr-idx"></span><span class="pr-cond"></span>
    <span class="pr-arrow">→</span><span class="pr-to${kind}"></span>`;
  row.querySelector('.pr-idx').textContent = idx;
  row.querySelector('.pr-cond').textContent = cond;
  row.querySelector('.pr-to').textContent = targetLabel(target);
  if (via) {
    const v = document.createElement('span');
    v.className = 'pr-via';
    v.textContent = t('rp.viaBase').replace('{base}', () => targetLabel(via));
    row.appendChild(v);
  }
  row.appendChild(trafficSpan([via ? viaTagFor(target, via) : outboundTagFor(target)]));
  return row;
}

/**
 * Fill every caption from the core's per-outbound counters. Text only — the
 * diagram itself is never rebuilt here, which is what keeps the per-second
 * tick as cheap as it was before the diagram existed.
 */
let lastPerOutbound = {};
function applyPathTraffic(per) {
  lastPerOutbound = per || {};
  for (const el of $$('#trafficPath .pr-traffic')) {
    const tag = pickTag(lastPerOutbound, (el.dataset.tags || '').split(','));
    const v = lastPerOutbound[tag];
    el.textContent = v ? `↓${fmtBytes(v.down)} ↑${fmtBytes(v.up)}` : '—';
    el.title = v ? `↓${fmtSpeed(v.downSpeed)} ↑${fmtSpeed(v.upSpeed)}` : '';
  }
}

/** The always-visible right column. Pure reads of state — no polling. */
function renderInspector() {
  const s = state.settings || {};
  const on = t('ins.on'), off = t('ins.off');
  const set = (id, text, cls) => {
    const el = $(id);
    if (!el) return;
    el.textContent = text;
    el.classList.remove('on', 'off');
    if (cls) el.classList.add(cls);
  };
  set('#insTun', s.tunMode ? on : off, s.tunMode ? 'on' : 'off');
  set('#insKill', s.killSwitch ? on : off, s.killSwitch ? 'on' : 'off');
  set('#insGuard', s.tunMode ? (s.leakGuard || 'standard') : off, s.tunMode ? 'on' : 'off');
  set('#insIpv6', s.ipv6 ? on : off, s.ipv6 ? 'on' : 'off');
  set('#insSocks', String(s.socksPort || '—'));
  set('#insHttp', String(s.httpPort || '—'));
  set('#insCore', state.activeEngine || (s.defaultEngine === 'xray-pattn' ? 'xray-pattn' : 'xray'));
  const insRouting = $('#insRouting');
  if (insRouting) {
    // the rules of the routing profile in use (connected, else selected, else the first)
    const advProf = Array.isArray(state.profiles)
      ? (profileOfSel(state.activeServerId || state.selectedServerId) || state.profiles[0] || { rules: [] }) : null;
    insRouting.textContent = s.advancedRouting
      ? t('path.rules').replace('{n}', (advProf ? advProf.rules : (s.routeRules || [])).length)
      : (s.routingMode || 'global');
  }
  if (state.flavor === 'openwrt') {
    // the guard row is there only while a stored "strict" is live (applyFlavor),
    // and goes with the save that lowers it
    const guardRow = $('#insGuardRow');
    if (guardRow) guardRow.hidden = s.leakGuard !== 'strict';
    const n = (s.lanBypassMacs || []).length;
    // the LIVE gateway, not the switch: connected (on a router a gateway that
    // did not come up is a failed connect) with the TUN the connection was
    // built with — a switch flipped since is only pending
    const gatewayUp = !!state.connected && (!!s.tunMode !== (state.pendingReconnect || []).includes('tunMode'));
    // a recovery or the boot connect waiting for the WAN is not "the VPN is
    // off": the VPN is on its way back (and an armed kill switch is holding the LAN)
    if (!gatewayUp && state.connecting) set('#insGateway', t('state.connecting'));
    else set('#insGateway', gatewayUp ? t('gw.insWhole') + (n ? ' · ' + t('gw.insDirect').replace('{n}', n) : '') : t('gw.insOff'), gatewayUp ? 'on' : 'off');
  }
}

/* status events from main */
// The recovery reasons main.js calls a drop (DROP_REASONS there) rather than
// the network moving: the window says which of the two it was.
const DROP_REASONS = ['core-exited', 'tunnel-exited', 'reload-failed'];
function reconnectingKey() {
  return DROP_REASONS.includes(state.reconnectReason) ? 'state.reconnectingDrop' : 'state.reconnecting';
}
/** What a give-up says: a cancelled shutdown, a drop, or the network moving. */
function failedKey(reason) {
  if (reason === 'shutdown-cancelled') return 'net.shutdownCancelled';
  if (reason === 'shutdown-cancelled-partial') return 'net.shutdownCancelledPartial';
  return DROP_REASONS.includes(reason) ? 'net.dropFailed' : 'net.failed';
}
window.api.onStatus((d) => {
  // "Give my internet back" belongs to a give-up with the guard held, and to
  // nothing after it: a reconnect that came back (or is being built) owns the
  // guard again, and its button would put every adapter on the ISP's resolvers
  // under a live tunnel. A failed teardown is no new state: it leaves it be.
  const gb = $('#guardBanner');
  if (gb && d.state !== 'cleanup-failed') gb.hidden = !(d.state === 'reconnect-failed' && d.guardHeld);
  // the last connection's toasts not shown yet go with it ('connected' starts its own series)
  if (d.state !== 'connected' && d.state !== 'cleanup-failed') cancelToastSeries();
  if (d.state === 'connected') {
    state.connected = true;
    state.connecting = false;
    state.activeServerId = d.serverId;
    state.lastServerId = d.serverId;   // main's lastServerId moved with it
    state.lan = d.lan || null;
    // a fresh connect is built from the current settings — nothing is stale
    setPending(d.pendingReconnect || []);
    state.activeEngine = d.engine || '';
    // what this connection did not do stays under the state while it is up (setConnUI paints it)
    state.connIssues = connIssuesFrom(d);
    setConnUI('connected', d.serverId);
    // only say "reconnected" when we actually were recovering from a network change
    if (state.wasReconnecting) { toast(t('net.reconnected'), 'ok'); state.wasReconnecting = false; }
    setModeWidget();
    updateLanInfo();
    renderServers();
    renderPicker();
    if (d.tunError) {
      updateAdminBtn(true);
    } else if (state.settings.tunMode && d.tun) {
      updateAdminBtn(false);
    }
    // proxy only / the leak guard, the geo files, main's notices about this PC — one after another
    toastSeries(connectToasts(d));
    setTimeout(() => checkIp(3, true), 1200);
    // auto-measure TCP ping + real delay for the active config so the home
    // cards show real numbers (real delay = proof the config actually works)
    // — not on a router: a test core beside the live one on every connect
    // (and every recovery) is memory a 512 MB box does not have (S6); the
    // ⚡ button still measures on request
    if (state.flavor !== 'openwrt') setTimeout(() => quickPing(d.serverId), 700);
  } else if (d.state === 'connecting') {
    state.connecting = true;
    setConnUI('connecting', d.serverId);
    // the rebuild reapplyConnection() runs is still part of the recovery — keep
    // saying so instead of flashing a bare "Connecting…"
    if (state.wasReconnecting) $('#connState').textContent = t(reconnectingKey());
  } else if (d.state === 'disconnected') {
    state.connected = false;
    state.connecting = false;
    state.wasReconnecting = false;   // no live tunnel left to recover
    state.lan = null;
    state.activeEngine = '';
    state.connIssues = [];
    state.noticesToasted = new Set();   // the next connection says its notices again
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
    state.reconnectReason = d.reason || '';
    setConnUI('connecting', d.serverId || state.activeServerId);
    // the router says which attempt this is, and keeps saying so through the
    // backoff (S4); the desktop keeps its own wording
    $('#connState').textContent = state.flavor === 'openwrt' && d.attempt ? attemptText('reconnecting', d.attempt) : t(reconnectingKey());
  } else if (d.state === 'waiting') {
    // the router's boot connect waiting for the WAN (B3): between its
    // retries, and during one — never "error" until it comes up
    state.connected = false;
    state.connecting = true;
    state.wasReconnecting = false;
    setConnUI('connecting', d.serverId || state.activeServerId);
    $('#connState').textContent = attemptText('waiting', d.attempt);
  } else if (d.state === 'reconnect-failed') {
    // every retry is spent — the user has to act
    state.connecting = false;
    state.wasReconnecting = false;
    // The guard was HELD across every attempt so the ISP never answered a
    // lookup, and it is still holding. Nothing leaks, but nothing resolves
    // either — say so and offer the way out (#guardBanner, shown above when
    // d.guardHeld), or a leak has been traded for a mystery.
    if (d.proxyUp) {
      // The tunnel itself came back and only TUN did not: xray is running and the
      // proxy ports work, so the red error state would be wrong. Stay connected
      // and say what is actually missing.
      state.connected = true;
      state.connIssues = [{ id: 'proxyOnly', reason: d.tunError || '—' }];
      setConnUI('connected', state.activeServerId);
      toast(t('net.tunFailed'), 'warn', 8000);
      if (d.tunError) appendLog('Reconnect gave up on TUN: ' + d.tunError, 'warn');
      updateAdminBtn(true);
    } else {
      state.connected = false;
      setConnUI('error');
      toast(t(failedKey(d.reason)), 'err', 8000);
    }
  } else if (d.state === 'cleanup-failed') {
    // The state IS the code; `d.error` carries it too, for a headless consumer.
    toast(t('net.cleanupFailed'), 'err');
  } else if (d.state === 'error') {
    // e.g. a settings reconnect whose new config the core rejected
    state.connected = false;
    state.connecting = false;
    setConnUI('error');
    showErrorReason(d.message);
    renderPendingBanner();
    renderServers();
    renderPicker();
  }
});

window.api.onXrayStatus((d) => {
  // `rebuilding`: the core died under a live connection and the service is
  // about to rebuild it — its "reconnecting" follows at once; painting
  // "disconnected" with a red toast here was the whole backoff's display (S4)
  if (d.state === 'stopped' && state.connected && !d.rebuilding) {
    state.connected = false;
    cancelToastSeries();
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
// the headless server replays the connection as the first event of every
// events (re)connect; the desktop bridge has no such channel (app:init is enough there)
if (window.api.onConnSnapshot) window.api.onConnSnapshot(applyConnSnapshot);

/* ----------------------------- kill switch ----------------------------- */
window.api.onKillSwitch((d) => {
  const wasEngaged = state.killEngaged;
  state.killEngaged = !!(d && d.engaged);
  const banner = $('#killBanner');
  if (banner) banner.hidden = !state.killEngaged;
  // the router's switch carries its whole state (armed, blocking): the status
  // line follows it, and the toast says what it blocks — the LAN
  if (d && d.router) {
    applyKillSwitchState(d);
    if (state.killEngaged && !wasEngaged) toast(t('kill.routerBlocked'), 'err');
    return;
  }
  // on the way in only: a second drop under a switch already closed is not news
  if (state.killEngaged && !wasEngaged) toast(t('kill.blocked'), 'err');
});
$('#killDisarm').onclick = async () => {
  // full teardown so the machine returns to normal direct internet
  // (removes the firewall block AND any leftover TUN routes / system proxy)
  await window.api.disconnect();
  state.killEngaged = false;
  $('#killBanner').hidden = true;
  toast(t('kill.opened'), 'ok');
};
/**
 * Reconnect: the SAME leak-free rebuild the network-change recovery uses, so the
 * guard is held across the gap rather than released. Disconnecting and
 * connecting again would open exactly the window this exists to close.
 */
async function doReconnect() {
  const btn = $('#btnReconnect');
  if (btn) btn.disabled = true;
  toast(t('t.reconnecting'));
  try {
    const r = await window.api.reconnect();
    if (r && r.ok === false && r.error) toast(r.error, 'err');
  } finally {
    if (btn) btn.disabled = false;
  }
}
$('#btnReconnect').onclick = doReconnect;

$('#guardRetry').onclick = async () => {
  $('#guardBanner').hidden = true;
  await doReconnect();
};
/**
 * The guard banner's "give my internet back". Deliberate: puts the adapters'
 * own resolvers back, and from here on the machine resolves through its ISP
 * again — which is why it takes an explicit click. Main refuses while a
 * connection uses the guard (`refused`): said in the user's language.
 */
async function giveInternetBack() {
  const r = await window.api.releaseGuard();
  $('#guardBanner').hidden = true;
  if (r && r.refused) return toast(t('guard.releaseRefused'), 'err');
  toast(r && r.ok === false ? (r.error || 'failed') : t('t.guardReleased'), r && r.ok === false ? 'err' : 'ok');
}
$('#guardRelease').onclick = giveInternetBack;

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
/**
 * The tail of the same log, on the home screen. Four lines, no scrolling, no
 * second buffer — it mirrors what appendLog just wrote and drops the oldest.
 */
const HOME_LOG_LINES = 4;
function appendHomeLog(text, level) {
  const box = $('#homeLog');
  if (!box) return;
  const line = document.createElement('span');
  line.className = 'll';
  const lv = document.createElement('span');
  lv.className = 'lv' + (level === 'warn' || level === 'error' ? ' ' + level : '');
  lv.textContent = level + ' ';
  line.appendChild(lv);
  line.appendChild(document.createTextNode(text));
  box.appendChild(line);
  while (box.childNodes.length > HOME_LOG_LINES) box.removeChild(box.firstChild);
}

window.api.onLog((d) => {
  appendLog(d.line, d.level || 'log');
  appendHomeLog(d.line, d.level || 'log');
});
$('#btnClearLogs').onclick = () => { $('#logBox').innerHTML = ''; };

/* ------------------------- simple / advanced view ------------------------- */

/**
 * Which surfaces are on show. A view preference and nothing more: everything
 * `simple` hides is reachable again in one click, and nothing hidden is needed
 * to get connected — that is the rule the mode has to keep.
 *
 * The default is decided once, from what the user already has: somebody with a
 * chain, a pool entry or a routing rule is already a pro user and must not find
 * their tools missing after an update; a fresh install starts clean.
 */
function defaultUiMode() {
  const s = state.settings || {};
  const hasPro = (state.chains || []).length > 0 || (state.pool || []).length > 0 ||
    (s.routeRules || []).length > 0 || !!s.advancedRouting ||
    (state.profiles || []).some(p => (p.rules || []).length > 0);
  return hasPro ? 'advanced' : 'simple';
}

function applyUiMode(mode) {
  const m = mode === 'simple' ? 'simple' : 'advanced';
  document.body.dataset.uiMode = m;
  const btn = $('#btnUiMode');
  if (btn) btn.textContent = 'MODE: ' + (m === 'simple' ? t('ui.simple') : t('ui.advanced')).toUpperCase();
  // a hidden view must never stay the visible one
  if (m === 'simple') {
    const cur = document.querySelector('.nav-item.active');
    if (cur && cur.classList.contains('pro-only')) showView('home');
  }
}

$('#btnUiMode').onclick = async () => {
  const next = (state.settings.uiMode || defaultUiMode()) === 'simple' ? 'advanced' : 'simple';
  await saveSettings({ uiMode: next });
  applyUiMode(next);
  toast(next === 'simple' ? t('ui.toSimple') : t('ui.toAdvanced'), 'ok');
};

// the inspector repeats the two actions people reach for most
const insPing = $('#btnInsPing');
if (insPing) insPing.onclick = () => $('#btnQuickPing').click();
const insIp = $('#btnInsIp');
if (insIp) insIp.onclick = () => $('#btnCheckIp').click();

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
// `pick`: the row offers the version picker (corePicker.js) beside its update button
const COMPONENTS = [
  { key: 'xray', label: 'comp.xray', ver: 'xray', pick: true },
  { key: 'xray-pattn', label: 'comp.xrayPattn', ver: 'xray-pattn', pick: true },
  { key: 'sing-box', label: 'comp.singbox', ver: 'sing-box', pick: true, has: (a) => !!a['sing-box'] },
  { key: 'geo', label: 'comp.geo', has: (a) => a.geoip && a.geosite },
  { key: 'tun2socks', label: 'comp.tun2socksLegacy' },
  { key: 'wintun', label: 'comp.wintun', winOnly: true }
];

function renderComponents() {
  const list = $('#compList');
  list.innerHTML = '';
  const a = state.assets || {};
  const isWin = (a.platform || 'win32') === 'win32';
  const rt = state.flavor === 'openwrt';

  for (const c of COMPONENTS) {
    if (c.winOnly && !isWin) continue;
    // a router's tunnel is sing-box's: tun2socks never runs there, wintun is Windows'
    if (rt && (c.key === 'tun2socks' || c.key === 'wintun')) continue;
    const present = c.has ? c.has(a) : !!a[c.key];
    const v = c.ver && present ? state.coreVersions[c.ver] : '';
    const ver = v ? ` <span class="comp-ver">v${escapeHtml(v)}</span>` : '';
    // sing-box on a router is the whole-network tunnel, not a TUN mode's backend
    const label = rt && c.key === 'sing-box' ? 'comp.singboxRouter' : c.label;
    // a core: «انتخاب نسخه» first, then the update button exactly as it was
    const pick = c.pick ? `<button class="btn ghost comp-pick" type="button">${escapeHtml(t('cv.choose'))}</button>` : '';
    const row = document.createElement('div');
    row.className = 'comp-row';
    row.innerHTML = `
      <div class="comp-info">
        <span class="comp-dot ${present ? 'ok' : 'missing'}"></span>
        <span class="comp-name">${escapeHtml(t(label))}${ver}</span>
        <span class="comp-state ${present ? 'ok' : 'missing'}">${present ? t('comp.installed') : t('comp.missing')}</span>
      </div>
      <div class="comp-actions">${pick}<button class="btn ${present ? 'ghost' : 'primary'} comp-btn">${present ? t('btn.update') : t('btn.download')}</button></div>`;
    const btn = row.querySelector('.comp-btn');
    btn.onclick = () => downloadComponent(c.key, btn);
    const pickBtn = row.querySelector('.comp-pick');
    if (pickBtn) pickBtn.onclick = () => openCorePicker(c.key, pickBtn);
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
  if (!tunNote) return;
  if (rt) {
    // The router's own reading: tunReady also counts tun2socks, which cannot
    // carry the gateway — the tunnel's availability is the service's to say.
    const key = routerTunMissingKey();
    tunNote.setAttribute('data-i18n', key);
    tunNote.textContent = t(key);
    tunNote.hidden = !!state.tunAvailable;
  } else {
    tunNote.hidden = typeof a.tunReady !== 'boolean' || a.tunReady;
  }
}

/**
 * Why the router's whole-network tunnel is unavailable, as a string key. It
 * needs sing-box AND nft (TunOpenwrt.isAvailable): with sing-box there, the
 * missing half is nft — "download sing-box" would fix nothing (and
 * missingEssentials does not ask for it then).
 */
function routerTunMissingKey() {
  return (state.assets || {})['sing-box'] ? 'tun.routerNoNft' : 'tun.routerUnavailable';
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
    if (CORE_KEYS.includes(key)) refreshXrayVersion();
    toast(t('t.downloaded'), 'ok');
  } else {
    state.assets = res.assets || state.assets;
    renderComponents();
    // a version install (corePicker.js) holds this core right now: said, not an error
    if (res.coreBusy) toast(t('comp.coreBusy'), 'warn');
    else toast(t('t.downloadFailed') + ': ' + (res.error || ''), 'err');
  }
}

/**
 * Settings → Required files → «انتخاب نسخه»: the version picker (corePicker.js)
 * for one core. Busy is this window's own reading of the connection (the
 * service refuses on its own as well); after an install the rows, the core
 * status and the versions are read again, as after a download.
 */
function openCorePicker(key, opener) {
  if (!window.corePicker) return;
  window.corePicker.open(key, {
    opener,
    busy: () => !!(state.connected || state.connecting),
    toast,
    onInstalled: async (res) => {
      let r = res || {};
      // an install whose answer was lost (the picker asked the service how it
      // ended) carries no assets: read them, and keep what is not said
      if (!r.assets && window.api.assetsStatus) {
        try { r = Object.assign({}, r, { assets: await window.api.assetsStatus() }); } catch { /* the rows keep what they had */ }
      }
      if (r.assets) state.assets = r.assets;
      if (typeof r.tunAvailable === 'boolean') state.tunAvailable = r.tunAvailable;
      renderComponents();
      updateXrayStatus(typeof r.xrayReady === 'boolean' ? r.xrayReady : anyXrayCore());
      updateTunStatus();
      refreshXrayVersion();
    }
  });
}

window.api.onAssetProgress((d) => {
  // the app's own installer reports into the About card, not the toast
  if (d && d.component === 'app') {
    const st = $('#updateStatus');
    if (st) st.textContent = t('about.downloading') + ' ' + Math.round(Number(d.pct) || 0) + '%';
    return;
  }
  // a version the picker is installing: its card shows the progress, no toast on top
  if (window.corePicker && window.corePicker.progress(d)) return;
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
/* ----------------------------- backup / restore ----------------------------- */
$('#btnBackupExport').onclick = async () => {
  const text = await window.api.exportBackup();
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
  a.download = 'irnetfree-backup-' + new Date().toISOString().slice(0, 10) + '.json';
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  toast(t('backup.exported'), 'ok');
};
$('#btnBackupImport').onclick = () => $('#backupFile').click();
$('#backupFile').onchange = async () => {
  const f = $('#backupFile').files[0];
  $('#backupFile').value = '';
  if (!f) return;
  const res = await window.api.importBackup(await f.text());
  if (!res || !res.ok) return toast(t('backup.failed') + (res && res.error ? ': ' + res.error : ''), 'err');
  // the store changed under the renderer: re-read it the way a launch does
  const data = await window.api.init();
  state.servers = data.servers || [];
  state.subscriptions = data.subscriptions || [];
  state.settings = data.settings || {};
  state.chains = (data.chains || []).map(c => ({ id: c.id, name: c.name || 'Chain', members: (c.members || []).filter(id => state.servers.some(s => s.id === id)) }));
  state.pool = (data.pool || []).map(e => ({ id: e.id, name: e.name || 'Proxy', target: e.target || '', socksPort: e.socksPort || 0, httpPort: e.httpPort || 0, enabled: e.enabled !== false }));
  state.usage = data.usage || {};
  state.pendingReconnect = data.pendingReconnect || [];
  applySettingsToUI(); renderServers(); renderPicker(); renderSubs(); renderChains(); renderPool(); renderAdvanced(); renderPendingBanner();
  const n = res.added;
  toast(`${t('backup.done')}: ${n.servers} / ${n.subscriptions} / ${n.chains} / ${n.pool}`, 'ok');
};

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
$('#btnDownloadUpdate').onclick = async () => {
  const url = (updateInfo && updateInfo.url) || 'https://github.com/sadrazkh/Irnetfree_xray-client/releases/latest';
  // No installer named for this machine (or an older backend): the release page, as before.
  if (!updateInfo || !updateInfo.asset || !window.api.downloadUpdate) {
    window.api.openExternal(url);
    toast(t('about.opening'));
    return;
  }
  const btn = $('#btnDownloadUpdate'), st = $('#updateStatus');
  btn.disabled = true;
  st.textContent = t('about.downloading') + ' 0%';
  st.className = 'update-status';
  const res = await window.api.downloadUpdate({ asset: updateInfo.asset, sums: updateInfo.sums || [] });
  btn.disabled = false;
  if (!res || !res.ok) {
    st.textContent = t('about.downloadFailed') + (res && res.error ? ': ' + res.error : '');
    st.className = 'update-status warn';
    return;
  }
  st.textContent = res.verified ? t('about.installerOpened') : t('about.downloadedUnverified');
  st.className = 'update-status ok';
};

/* ----------------------------- first-run required files modal ----------------------------- */
function missingEssentials() {
  const a = state.assets || {};
  const isWin = state.platform === 'win32';
  const want = state.settings.tunMode;   // tun files only matter if TUN is on
  const list = [];
  if (!anyXrayCore()) list.push('xray');
  if (!(a.geoip && a.geosite)) list.push('geo');
  // On a router sing-box is the backend and tun2socks never runs — and sing-box
  // is not optional there: without it the whole-network tunnel cannot start, and
  // the package does not depend on it (a freshly flashed router meets it first
  // as a failed connect). Only when it is the missing piece: with sing-box
  // present and the tunnel still unavailable, downloading it again fixes nothing.
  if (state.flavor === 'openwrt') {
    if (!state.tunAvailable && !a['sing-box']) list.push('sing-box');
  } else {
    if (want && !a.tun2socks) list.push('tun2socks');
    if (want && isWin && !a.wintun) list.push('wintun');
  }
  return list;
}

function maybePromptMissingFiles() {
  const missing = missingEssentials();
  // Only auto-prompt when the core (xray) is missing — geo/tun are optional and
  // already surfaced in Settings → Required files. On a router sing-box is not
  // optional (it IS the gateway), so it prompts too.
  if (!missing.includes('xray') && !missing.includes('sing-box')) return;
  openFilesModal(missing);
}

const COMP_LABEL = {
  xray: 'comp.xray', 'xray-pattn': 'comp.xrayPattn', 'sing-box': 'comp.singbox',
  geo: 'comp.geo', tun2socks: 'comp.tun2socks', wintun: 'comp.wintun'
};
/** The prompt's name for a component: on a router sing-box is the whole-network tunnel. */
function compLabel(key) {
  if (key === 'sing-box' && state.flavor === 'openwrt') return 'comp.singboxRouter';
  return COMP_LABEL[key] || key;
}

function openFilesModal(missing) {
  const listEl = $('#filesList');
  listEl.innerHTML = '';
  for (const key of missing) {
    const row = document.createElement('div');
    row.className = 'files-row';
    row.innerHTML = `<span class="files-dot missing"></span><span class="files-name">${escapeHtml(t(compLabel(key)))}</span>`;
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
    $('#filesProgress').textContent = `${t('t.downloading')} ${t(compLabel(key))}…`;
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
  if (state.flavor === 'openwrt') {
    // The router has no TUN switch and no admin question: the whole-network
    // tunnel is ready, or sing-box (else nft) is missing — the line says which,
    // and where to get it.
    el.textContent = t(state.tunAvailable ? 'tun.routerReady' : routerTunMissingKey());
    el.className = 'tun-status ' + (state.tunAvailable ? 'ok' : 'warn');
    updateAdminBtn(false);
    return;
  }
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
        <div class="sub-meta">${escapeHtml(sub.serverCount || 0)} ${escapeHtml(t('sub.servers'))} • ${escapeHtml(t('sub.lastUpdate'))}: ${escapeHtml(timeAgo(sub.lastUpdated))}</div>
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
  // a refresh that dropped a server a routing profile uses: its rule and its tree say so
  if (Array.isArray(state.profiles)) renderAdvanced();
});

/* ----------------------------- edit server modal ----------------------------- */
let editOriginal = null;
let editClearPin = false;   // "clear pin" pressed in the open edit form

function readServerFields(s) {
  const ob = s.outbound || {};
  const st = ob.streamSettings || {};
  const f = {
    name: s.name, address: s.address, port: s.port,
    // `raw` is tcp under its newer name, and the select has no option for it
    network: (st.network === 'raw' ? 'tcp' : st.network) || 'tcp', security: st.security || 'none',
    sni: '', host: '', path: '', fp: '', pbk: '', sid: '', alpn: '',
    allowInsecure: false, cred: '', method: '',
    fragment: ob._fragment || '',
    noise: ob._noise || '',
    cipherSuites: (st.tlsSettings && st.tlsSettings.cipherSuites) || '',
    finalMask: st.finalmask ? JSON.stringify(st.finalmask) : '',
    engine: s.engine || 'xray',
    certPin: s.certPin || '',
    ech: '', pcs: '', vcn: '', pqv: '', hy2Obfs: '', hy2Ports: ''
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
  } else if (s.protocol === 'hysteria2') {
    f.cred = (st.hysteriaSettings && st.hysteriaSettings.auth) || '';
    const masks = (st.finalmask && Array.isArray(st.finalmask.udp)) ? st.finalmask.udp : [];
    const sal = masks.find(m => m && m.type === 'salamander');
    const hop = masks.find(m => m && m.type === 'udphop');
    f.hy2Obfs = (sal && sal.settings && sal.settings.password) || '';
    f.hy2Ports = hop && hop.settings ? String(hop.settings.remotePorts || '') : '';
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
  else if (st.grpcSettings) { f.path = st.grpcSettings.serviceName || ''; f.host = st.grpcSettings.authority || ''; }
  else if (st.httpSettings) { f.path = st.httpSettings.path || ''; f.host = (st.httpSettings.host || []).join(','); }
  else if (st.xhttpSettings) { f.path = st.xhttpSettings.path || ''; f.host = st.xhttpSettings.host || ''; }
  else if (st.httpupgradeSettings) { f.path = st.httpupgradeSettings.path || ''; f.host = st.httpupgradeSettings.host || ''; }
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
    f.ech = st.tlsSettings.echConfigList || '';
    f.pcs = st.tlsSettings.pinnedPeerCertSha256 || '';
    f.vcn = st.tlsSettings.verifyPeerCertByName || '';
  } else if (st.realitySettings) {
    f.sni = st.realitySettings.serverName || '';
    f.fp = st.realitySettings.fingerprint || '';
    f.pbk = st.realitySettings.publicKey || '';
    f.sid = st.realitySettings.shortId || '';
    f.pqv = st.realitySettings.mldsa65Verify || '';
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
  // A preset keeps its own spelling (`fakehello`, `FakeTLS`): mapped onto the
  // nearest option, a save that changed nothing would rewrite it.
  if (!nz) { selectValue(sel, 'off'); if (custom) custom.value = ''; }
  else if (NOISE_PRESET_KEYS.includes(key)) { selectValue(sel, nz); if (custom) custom.value = ''; }
  else { selectValue(sel, 'custom'); if (custom) custom.value = nz; }
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
/**
 * A JSON server's QR carries its config as minified JSON — when it is small
 * enough to scan. 1,700 bytes is about version 30 at level L (137 modules):
 * the 320px box (.qr-image, less its padding and the quiet zone) then keeps
 * 2 px per module, which a phone camera can still resolve; the largest code
 * (2,953 bytes, 177 modules) gets 1.6 px and does not scan. Above the limit
 * nothing is drawn, and the dialog says so.
 */
const QR_JSON_MAX_BYTES = 1700;

/**
 * The text a QR encodes for a JSON server: the config minified, with every
 * non-ASCII character written as a \uXXXX escape. The QR library keeps one
 * byte per character (the low 8 bits), so a Persian remark or an emoji would
 * come out scrambled; the escape is plain ASCII that any scanner reads, and
 * JSON.parse gives the same config back. ASCII only, so its length is its
 * size in bytes.
 */
function qrJsonText(pretty) {
  let min = pretty;
  try { min = JSON.stringify(JSON.parse(pretty)); } catch {}
  return min.replace(/[\u0080-\uffff]/g, (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
}

async function showServerQr(id) {
  const link = await window.api.serverLink(id);
  if (!link) return toast('—', 'err');
  const srv = (state.servers || []).find(x => x.id === id);
  const isJson = !!srv && srv.source === 'json';
  const text = isJson ? qrJsonText(link) : link;
  const box = $('#qrImage'); box.innerHTML = '';
  try {
    if (isJson && text.length > QR_JSON_MAX_BYTES) throw new Error('too large for a QR');
    const qr = qrcode(0, 'L'); qr.addData(text); qr.make();
    // A scalable SVG, not createImgTag's fixed-size GIF: a long link (an xhttp
    // `extra` object, a WireGuard peer) makes a 350px+ bitmap that overflowed the
    // modal and could not shrink. The SVG takes whatever width the box gives it
    // and stays crisp. margin 16 = the 4 modules of quiet zone the QR spec asks
    // for; 6px was 1.5 modules, which scanners refuse.
    box.innerHTML = qr.createSvgTag({ cellSize: 4, margin: 16, scalable: true });
  } catch (e) {
    box.innerHTML = '<p class="hint" style="padding:24px 8px">' + (t(isJson ? 'qr.tooLarge' : 'qr.tooBig') || 'Link too long for a QR — use Copy.') + '</p>';
  }
  // too large to draw: the readable (pretty) JSON stays in the box to copy
  $('#qrLink').value = isJson && text.length > QR_JSON_MAX_BYTES ? link : text;
  $('#qrCopy').textContent = t(isJson ? 'ed.jsonCopy' : 'qr.copy');
  $('#qrModal').hidden = false;
}
if ($('#qrClose')) $('#qrClose').onclick = () => { $('#qrModal').hidden = true; };
if ($('#qrModal')) $('#qrModal').onclick = (e) => { if (e.target === $('#qrModal')) $('#qrModal').hidden = true; };
if ($('#qrCopy')) $('#qrCopy').onclick = () => { copyText($('#qrLink').value); toast(t('t.copied') || 'Copied ✓', 'ok'); };

/* ---------- a JSON server's edit form: the config itself, no link fields ---------- */
let editJsonMode = 'full';   // the Full / Raw switch of the open JSON form

/** Show the JSON form or the link form in the edit modal (never both). */
function setEditKind(isJson) {
  show('#edJsonWrap', isJson);
  show('#edLinkFields', !isJson);
  show('#edAddrWrap', !isJson);       // the name stays, alone in its row
  $('#edNameRow').classList.toggle('single', isJson);
}

/** The reason a save was refused, under the editor; null clears it. */
function showJsonError(reason) {
  const el = $('#edJsonError');
  if (!el) return;
  const text = reason === null || reason === undefined ? '' : (t('ed.jsonInvalid') + (reason ? ': ' + reason : ''));
  el.textContent = text;
  el.hidden = !text;
  if (text) {
    toast(text, 'err');
    if (el.scrollIntoView) el.scrollIntoView({ block: 'nearest' });
  }
}

/**
 * One of jsonInfo's rules, in words: "<match> → <to>". The core writes neutral
 * tokens — match `*` for the rule that catches everything left over (else its
 * conditions joined with " + "), to `balancer:<tag>` for a balancer and empty
 * for none. The other condition words are the config's own and stay as written.
 */
function jsonRuleText(r) {
  const m = r && r.match != null ? String(r.match) : '';
  const to = r && r.to != null ? String(r.to) : '';
  const match = m === '*' ? t('ed.jsonNaAll') : (m || '?');
  const target = !to ? '—' : to.startsWith('balancer:') ? t('ed.jsonNaBalancer').replace('{tag}', () => to.slice(9)) : to;
  return match + ' → ' + target;
}

/**
 * What full mode leaves unused, from the record's jsonInfo: the config's own
 * routing rules (each "match → to"), and a line each for its DNS, balancers and
 * observatory. Shown in full mode only — raw runs all of it. Values are the
 * config's own text, so they go in as text nodes, never as markup.
 */
function renderJsonInfo(info, mode) {
  const box = $('#edJsonInfo');
  if (!box) return;
  box.innerHTML = '';
  const i = info || {};
  const rules = Array.isArray(i.rules) ? i.rules : [];
  const list = document.createElement('ul');
  list.className = 'ed-json-list';
  const item = (text) => {
    const li = document.createElement('li');
    li.textContent = text;
    list.appendChild(li);
    return li;
  };
  if (rules.length) {
    const li = item(t('ed.jsonNaRules').replace('{n}', () => String(rules.length)));
    const sub = document.createElement('ul');
    sub.className = 'ed-json-rules';
    for (const r of rules) {
      const row = document.createElement('li');
      const text = document.createElement('bdi');
      text.dir = 'ltr';
      text.textContent = jsonRuleText(r);
      row.appendChild(text);
      sub.appendChild(row);
    }
    li.appendChild(sub);
  }
  if (i.dns) item(t('ed.jsonNaDns'));
  if (i.balancers) item(t('ed.jsonNaBalancers'));
  if (i.observatory) item(t('ed.jsonNaObservatory'));
  if (list.children.length) {
    const head = document.createElement('div');
    head.className = 'field-label';
    head.textContent = t('ed.jsonNotApplied');
    box.appendChild(head);
    box.appendChild(list);
  }
  box.hidden = mode !== 'full' || !list.children.length;
}

/** Full / Raw: the switch, its one line, and the not-applied summary that only full has. */
function setJsonMode(mode) {
  editJsonMode = mode === 'raw' ? 'raw' : 'full';
  $$('#edJsonMode .seg-btn').forEach((b) => {
    const on = b.dataset.jsonMode === editJsonMode;
    b.classList.toggle('active', on);
    b.setAttribute('aria-checked', String(on));
  });
  $('#edJsonHelp').textContent = t(editJsonMode === 'raw' ? 'ed.jsonRawHelp' : 'ed.jsonFullHelp');
  // the router's web UI keeps the Raw option, but the router always runs the full form
  const note = $('#edJsonRouterNote');
  const onRouter = state.flavor === 'openwrt';
  note.textContent = onRouter ? t('ed.jsonRawRouter') : '';
  note.hidden = !(onRouter && editJsonMode === 'raw');
  renderJsonInfo(editOriginal && editOriginal.jsonInfo, editJsonMode);
}

/** The language changed with a JSON edit form open: say its help line and summary again. */
function refreshJsonFormLang() {
  // editingId first: setLang also runs at start-up, before the edit state below exists
  if (!state.editingId || !editOriginal || editOriginal.source !== 'json') return;
  setJsonMode(editJsonMode);
}

function openEditJson(s) {
  $('#edName').value = s.name || '';
  $('#edJson').value = JSON.stringify(s.json || {}, null, 2);
  showJsonError(null);
  setJsonMode(s.jsonMode);
  $('#editModal').hidden = false;
  $('#edJson').scrollTop = 0;
}

/** { name, jsonMode, json } for a save — or null, with the reason on screen, when the text is not a JSON object. */
function collectJsonFields() {
  let json;
  try { json = JSON.parse($('#edJson').value); }
  catch (e) { showJsonError(e && e.message ? e.message : String(e)); return null; }
  if (!json || typeof json !== 'object' || Array.isArray(json)) { showJsonError(t('ed.jsonNotObject')); return null; }
  showJsonError(null);
  return { name: $('#edName').value, jsonMode: editJsonMode, json };
}

$$('#edJsonMode .seg-btn').forEach((b) => { b.onclick = () => setJsonMode(b.dataset.jsonMode); });
/** Copy JSON: what is in the editor (edits included), pretty as shown. */
async function copyEditJson() {
  await copyText($('#edJson').value);
  toast(t('t.copied') || 'Copied ✓', 'ok');
}
if ($('#edJsonCopy')) $('#edJsonCopy').onclick = copyEditJson;

function openEdit(id) {
  const s = state.servers.find(x => x.id === id);
  if (!s) return;
  state.editingId = id;
  editOriginal = s;
  setEditKind(s.source === 'json');
  if (s.source === 'json') return openEditJson(s);
  const f = readServerFields(s);
  const proto = s.protocol;
  fillEditForm(f, proto);
  // The certificate pinned on first use stands in for "allow insecure" now
  // (certPin.js). Shown abbreviated, the full hash in the tooltip; clearing it
  // makes the next connect read the certificate again.
  editClearPin = false;
  $('#edCertPin').textContent = f.certPin ? f.certPin.slice(0, 6) + '…' + f.certPin.slice(-4) : '';
  $('#edCertPin').title = f.certPin || '';

  // credential label per protocol
  const credLabel = $('#edCredLabel');
  const isStd = (proto === 'vless' || proto === 'vmess' || proto === 'trojan');
  const isHy2 = proto === 'hysteria2';
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
  show('#edTlsRow', isStd || isHy2);
  show('#edPathRow', isStd);
  show('#edPattWrap', isStd);
  show('#edInsecureRow', isStd || isHy2);
  show('#edInsecureHint', isStd || isHy2);
  // Hysteria2 is QUIC: no first-use pin — what the switch does there is its own
  $('#edInsecureHint').textContent = t(isHy2 ? 'edit.insecureHintHy2' : 'edit.insecureHint');
  show('#edCertPinRow', (isStd || isHy2) && !!f.certPin);
  show('#edHy2Row', isHy2);
  show('#edWgExtra', isWg);
  show('#edProxyRow', isProxy);
  // socks/http carry no single "credential" field — user/pass live in edProxyRow
  show('#edCredWrap', !isProxy);
  $('#edRealityRow').hidden = !(isStd && $('#edSecurity').value === 'reality');
  updateSpoofLabels();

  $('#editModal').hidden = false;
}

/**
 * Put a record's form view (readServerFields) into the edit form. What this
 * shows is what a save sends back, so a save that changes nothing changes
 * nothing — the main process records a field as the user's edit only when
 * the submitted value differs from the shown one (parser.applyServerEdits).
 */
function fillEditForm(f, proto) {
  $('#edName').value = f.name || '';
  $('#edAddress').value = f.address || '';
  $('#edPort').value = f.port || '';
  $('#edCred').value = f.cred || '';
  $('#edNetwork').value = f.network || 'tcp';
  $('#edSecurity').value = f.security || 'none';
  $('#edSni').value = f.sni || '';
  $('#edHost').value = f.host || '';
  $('#edPath').value = f.path || '';
  selectValue($('#edFp'), f.fp || '');
  $('#edPbk').value = f.pbk || '';
  $('#edSid').value = f.sid || '';
  $('#edFragment').value = f.fragment || '';
  setNoiseFields(f.noise || '');
  if ($('#edCipherSuites')) $('#edCipherSuites').value = f.cipherSuites || '';
  if ($('#edFinalMask')) $('#edFinalMask').value = f.finalMask || '';
  if ($('#edEngine')) selectValue($('#edEngine'), f.engine || 'xray');
  $('#edInsecure').checked = !!f.allowInsecure;
  $('#edEch').value = f.ech || '';
  $('#edPcs').value = f.pcs || '';
  $('#edVcn').value = f.vcn || '';
  $('#edPqv').value = f.pqv || '';
  $('#edHy2Obfs').value = f.hy2Obfs || '';
  $('#edHy2Ports').value = f.hy2Ports || '';

  if (proto === 'socks' || proto === 'http') {
    $('#edProxyUser').value = f.pxUser || '';
    $('#edProxyPass').value = f.pxPass || '';
  }

  if (proto === 'wireguard') {
    $('#edWgPub').value = f.wgPub || '';
    $('#edWgAddr').value = f.wgAddr || '';
    $('#edWgPsk').value = f.wgPsk || '';
    $('#edWgMtu').value = f.wgMtu || 1420;
    $('#edWgReserved').value = f.wgReserved || '';
    $('#edWgAllowed').value = f.wgAllowed || '';
    $('#edWgDns').value = f.wgDns || '';
  }
}

/**
 * Set a <select>, adding the value as an option of its own when the record
 * holds one the markup does not list (a fingerprint like `qq`, an engine from
 * a link): otherwise the select reads back as another value, and a save that
 * changed nothing would rewrite it. Options added for an earlier record go.
 */
function selectValue(sel, v) {
  if (!sel) return;
  for (const o of [...sel.querySelectorAll('option[data-own]')]) o.remove();
  if (v && ![...sel.options].some(o => o.value === v)) {
    const o = document.createElement('option');
    o.value = v;
    o.textContent = v;
    o.dataset.own = '1';
    sel.appendChild(o);
  }
  sel.value = v;
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
  // Hysteria2 is always TLS (over QUIC), with no transport of its own to pick
  const isHy2 = !!editOriginal && editOriginal.protocol === 'hysteria2';
  const sec = isHy2 ? 'tls' : ($('#edSecurity').value || 'none');
  const net = isHy2 ? 'hysteria' : ($('#edNetwork').value || 'tcp');
  const on = (isStd || isHy2) && (sec === 'tls' || sec === 'reality');
  show('#edSpoofHead', on); show('#edTlsRow', on);
  show('#edTlsExtra', on && sec === 'tls');
  show('#edPqvRow', isStd && sec === 'reality');
  // the TLS fragment splits a TCP ClientHello: nothing to split in QUIC
  show('#edHideSniRow', on && !isHy2);
  updateHideSniNote();   // follows the switch row, shown or not
  const hintEl = $('#edSpoofHint'); if (hintEl) hintEl.hidden = !on;
  if (!on) return;

  const frontable = ['ws', 'grpc', 'xhttp', 'splithttp', 'h2', 'http', 'httpupgrade'].includes(net);
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

/**
 * A server that already fragments its ClientHello with finalmask (the
 * patterniha subscriptions) gets a second, generic fragmenter in front of it
 * when Hide SNI is turned on — say so under the switch, while the form's
 * finalmask is non-empty and the switch is showing.
 */
function updateHideSniNote() {
  const row = $('#edHideSniRow');
  const fm = $('#edFinalMask');
  show('#edHideSniFmNote', !!(row && !row.hidden && fm && (fm.value || '').trim()));
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
if ($('#edFinalMask')) $('#edFinalMask').oninput = updateHideSniNote;
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

/**
 * What a save sends: every field of the form, read back from the inputs that
 * fillEditForm() filled. `orig` is the record being edited.
 */
function collectEditFields(orig, clearPin) {
  const proto = orig.protocol;
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
  else if (proto === 'trojan' || proto === 'shadowsocks' || proto === 'hysteria2') { if (cred) fields.password = cred; }
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
    if (clearPin) fields.clearCertPin = true;
    // patterniha custom-TLS: cipherSuites + finalMask ('' clears them)
    fields.cipherSuites = $('#edCipherSuites') ? $('#edCipherSuites').value.trim() : '';
    fields.finalMask = $('#edFinalMask') ? $('#edFinalMask').value.trim() : '';
    // preserve alpn from original (no field for it)
    const shown = readServerFields(orig);
    if (shown.alpn) fields.alpn = shown.alpn;
    // newer TLS / REALITY knobs ('' clears them)
    fields.ech = $('#edEch').value.trim();
    fields.pcs = $('#edPcs').value.trim();
    fields.vcn = $('#edVcn').value.trim();
    fields.pqv = $('#edPqv').value.trim();
  } else if (proto === 'hysteria2') {
    fields.sni = $('#edSni').value.trim();
    fields.allowInsecure = $('#edInsecure').checked;
    if (clearPin) fields.clearCertPin = true;
    fields.ech = $('#edEch').value.trim();
    fields.pcs = $('#edPcs').value.trim();
    fields.vcn = $('#edVcn').value.trim();
    fields.obfsPassword = $('#edHy2Obfs').value.trim();
    fields.mport = $('#edHy2Ports').value.trim();
  } else if (proto === 'wireguard') {
    fields.publicKey = $('#edWgPub').value.trim();
    // `address` above is the ENDPOINT host (#edAddress); the interface address
    // is its own key. Sending both under `address` is what overwrote the
    // endpoint with "10.10.10.42/32" and stopped the core from starting.
    fields.localAddress = $('#edWgAddr').value.trim();
    fields.dns = $('#edWgDns').value.trim();
    fields.presharedKey = $('#edWgPsk').value.trim();
    fields.mtu = $('#edWgMtu').value;
    fields.reserved = $('#edWgReserved').value.trim();
    fields.allowedIPs = $('#edWgAllowed').value.trim();
  } else if (proto === 'socks' || proto === 'http') {
    fields.username = $('#edProxyUser').value.trim();
    fields.password = $('#edProxyPass').value.trim();
  }

  return fields;
}

/**
 * Is server `id` part of the connection that is up right now — the server
 * itself, a member of the live chain, or a target of the live pool or advanced
 * plan (resolved the way the main process builds them)? A save only writes the
 * store: the running tunnel keeps the record it was built from until a
 * reconnect, so an edit of a live server is not live yet.
 */
function serverInLivePlan(id) {
  const live = state.activeServerId;
  if (!id || !live || !state.connected) return false;
  if (live === id) return true;
  const chainHas = (cid) => {
    const c = (state.chains || []).find(x => x.id === cid);
    return !!(c && (c.members || []).includes(id));
  };
  const targetHas = (tg) => tg === id
    || (tg === 'chain' && (state.chain || []).includes(id))
    || (String(tg).startsWith('chain:') && chainHas(String(tg).slice(6)));
  if (live === '__chain__') return (state.chain || []).includes(id);
  // the pool runs the entries that are enabled AND have a port (as main builds it)
  if (live === '__pool__') return (state.pool || []).some(e => e && e.enabled && e.socksPort && targetHas(e.target));
  if (live === '__advanced__' || String(live).startsWith('__advanced__:')) {
    const s = state.settings || {};
    const first = (state.servers || [])[0];
    if (Array.isArray(state.profiles)) {
      // the routing profile that is up: its targets, its rules' vias and its base all dial
      const p = profileOfSel(live);
      if (!p) return false;
      const refs = [...p.rules.map(r => r && r.target), p.def || (first && first.id) || 'direct',
        ...p.rules.map(r => r && r.via), p.defVia, p.base];
      return refs.filter(v => v && v !== 'inherit' && v !== 'none').some(targetHas);
    }
    const def = s.routeDefault || (first && first.id) || 'direct';
    return [...(s.routeRules || []).map(r => r && r.target), def].some(targetHas);
  }
  return chainHas(live);
}

async function saveEdit() {
  const id = state.editingId;
  if (!id || !editOriginal) return;
  // a JSON server sends its mode and config, not the link form's fields
  const isJson = editOriginal.source === 'json';
  const proto = editOriginal.protocol;
  const fields = isJson ? collectJsonFields() : collectEditFields(editOriginal, editClearPin);
  if (!fields) return;   // a JSON form has said why, under the editor

  // the link form's own checks; its inputs are hidden (and stale) for a JSON server
  if (!isJson) {
    // the endpoint field must hold the PUBLIC host — the interface address
    // pasted here is exactly how the record used to get corrupted
    if (proto === 'wireguard' && (!String(fields.address).trim() || String(fields.address).includes('/'))) return toast(t('t.wgBadEndpoint'), 'err');

    // finalmask goes to the core untouched, so catch bad JSON here rather than
    // letting xray refuse the whole config at connect time
    const fmText = $('#edFinalMask') ? $('#edFinalMask').value.trim() : '';
    if (fmText) {
      try { JSON.parse(fmText); }
      catch { return toast(t('edit.finalMaskBad'), 'err'); }
    }
    // an ML-DSA-65 key is 1952 bytes as base64url (2603 characters); the parser
    // leaves anything else out, so say so rather than drop it in silence
    const pqvText = $('#edPqv') && $('#edPqvRow') && !$('#edPqvRow').hidden ? $('#edPqv').value.trim() : '';
    if (pqvText && !/^[A-Za-z0-9_\-+/]{2603}={0,2}$/.test(pqvText)) return toast(t('edit.pqvBad'), 'err');
  }

  const res = await window.api.updateServer(id, fields);
  if (res.ok) {
    state.servers = res.servers;
    // The service judges an edit against the plan it actually built and keeps
    // it pending ('servers') until a reconnect: the lasting banner from its
    // list, the toast from its verdict. A main that sends neither (older
    // builds) leaves the banner alone, and the renderer reads the plan itself.
    if (Array.isArray(res.pendingReconnect)) setPending(res.pendingReconnect);
    const live = typeof res.live === 'boolean' ? res.live : serverInLivePlan(id);
    renderServers(); renderPicker(); renderChains(); renderPool(); renderAdvanced();
    closeEdit();
    // The edit is in the store, not in the running tunnel: say so, with the
    // one click that applies it (the same leak-free rebuild as the Reconnect
    // button) — a Disconnect + Connect would go direct in between.
    if (live) toastAction(t('t.serverUpdatedLive'), t('btn.reconnect'), doReconnect);
    else toast(t('t.serverUpdated'), 'ok');
  } else if (isJson) {
    // refused (bad JSON, no proxy outbound left…): the reason stays under the editor and the form stays open
    showJsonError(res.error || '');
  } else {
    toast(t('t.failed'), 'err');
  }
}
$('#editSave').onclick = saveEdit;

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
    card.dataset.chainId = chain.id;   // the routing page's flow tree opens a chain by it

    const tl = pingResultLabel((state.pings[chain.id] || {}).tcp);
    const rl = pingResultLabel((state.pings[chain.id] || {}).real);
    const ready = chain.members.length >= 2;
    // its share link comes with routing profiles (the same back end writes both)
    const share = Array.isArray(state.profiles)
      ? `<button class="icon-btn ch-share" title="${escapeHtml(t('rp.copyLink'))}" aria-label="${escapeHtml(t('rp.copyLink'))}"${ready ? '' : ' disabled'}>🔗</button>`
      : '';

    card.innerHTML = `
      <div class="chain-card-head">
        <span class="proto-badge proto-chain">⛓</span>
        <input class="input chain-name" value="${escapeHtml(chain.name)}" />
        <span class="chain-pings">
          <span class="pi-ping-ico" title="${escapeHtml(t('ping.tcp'))}">⚡</span><span class="chain-ping ${tl.cls}" data-pbase="chain-ping" data-ping="${escapeHtml(chain.id)}">${tl.txt}</span>
          <span class="pi-ping-ico" title="${escapeHtml(t('ping.real'))}">⏱</span><span class="chain-ping ${rl.cls}" data-pbase="chain-ping" data-ping-real="${escapeHtml(chain.id)}">${rl.txt}</span>
        </span>
        <span class="srv-usage" data-usage="chain:${escapeHtml(chain.id)}" title="${escapeHtml(t('srv.usage'))}">${usageLabel('chain:' + chain.id)}</span>
        <div class="chain-card-actions">
          <button class="icon-btn ch-ping" title="ping">⚡</button>
          <button class="icon-btn ch-connect" title="connect"${ready ? '' : ' disabled'}>▶</button>
          ${share}
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
    connectGlyph(card.querySelector('.ch-connect')).onclick = () => { if (ready) connect(chain.id); };
    const shareBtn = card.querySelector('.ch-share');
    if (shareBtn) shareBtn.onclick = () => { if (ready) shareRouting('chain', chain.id); };
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
        <span class="proto-badge proto-${escapeHtml(s.protocol)}">${escapeHtml(s.protocol)}</span>
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
        <span class="proto-badge proto-${escapeHtml(s.protocol)}">${escapeHtml(s.protocol)}</span>
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
  if (state.connecting) return cancelConnect();
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
        <span class="srv-usage" data-usage="${escapeHtml(entry.target || '')}" title="${escapeHtml(t('srv.usage'))}">${usageLabel(entry.target)}</span>
        <button class="icon-btn pool-del" title="delete">🗑</button>
      </div>
      <div class="pool-card-body">
        <div class="pool-field pool-target-field">
          <label class="field-label">${escapeHtml(t('pool.target'))}</label>
          <span class="pool-target-mount"></span>
        </div>
        <div class="pool-field">
          <label class="field-label">${escapeHtml(t('pool.socksPort'))}</label>
          <input type="number" class="input pool-socks" dir="ltr" value="${escapeHtml(entry.socksPort || '')}" />
        </div>
        <div class="pool-field">
          <label class="field-label">${escapeHtml(t('pool.httpPort'))}</label>
          <input type="number" class="input pool-http" dir="ltr" value="${escapeHtml(entry.httpPort || '')}" placeholder="—" />
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

/**
 * <option>s for a process <select>, ensuring the current value is present.
 *
 * Two consumers, two different values off the same list. The advanced routing
 * rules store the process NAME the OS reports ('chrome') — that is what the IP
 * cache and the saved rules key on, and it must not change. The per-app TUN
 * list needs the image file's leaf name ('chrome.exe'), because that is the
 * only thing sing-box's `process_name` rule matches: `{ exe: true }`.
 */
function processOptions(selected, opts = {}) {
  const valueOf = (p) => (opts && opts.exe ? (p.exe || p.name) : p.name);
  const out = [`<option value="">${escapeHtml(t('proc.pick'))}</option>`];
  for (const p of state.procList) {
    const value = valueOf(p);
    const label = p.count ? `${value} (${p.count})` : value;
    out.push(`<option value="${escapeHtml(value)}"${value === selected ? ' selected' : ''}>${escapeHtml(label)}</option>`);
  }
  // current value that's no longer running
  if (selected && !state.procList.some(p => valueOf(p) === selected)) {
    out.push(`<option value="${escapeHtml(selected)}" selected>${escapeHtml(selected)}</option>`);
  }
  return out.join('');
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
  const prof = Array.isArray(state.profiles) ? advDraft() : null;
  const def = (prof ? prof.def : state.settings.routeDefault) || (state.servers[0] && state.servers[0].id) || 'direct';
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

  // Routing profiles: the list, and the draft of the one being edited (its rule
  // edits wait for Save, as today's did). null on a back end without them —
  // then everything below is today's single advanced routing.
  const prof = Array.isArray(state.profiles) ? advDraft() : null;
  renderProfileBar();

  // "…and apply the routing mode too": show which mode that currently is, so
  // the switch is not a promise the user has to go and verify somewhere else.
  const useMode = $('#optAdvUseMode');
  if (useMode) {
    useMode.checked = prof ? !!prof.useMode : !!state.settings.advancedUseMode;
    const now = $('#advUseModeNow');
    if (now) {
      const mode = state.settings.routingMode || 'global';
      const btn = document.querySelector(`#routingSeg .seg-btn[data-mode="${mode}"]`);
      now.hidden = !useMode.checked;
      now.textContent = t('adv.useMode.now').replace('{mode}', (btn && btn.textContent.trim()) || mode);
    }
  }
  // custom rules only apply to the simple modes (configBuilder ignores them under
  // advanced routing) — don't show an editor for something that has no effect
  const simple = $('#simpleRulesCard');
  if (simple) simple.hidden = !!state.settings.advancedRouting;

  // (profiles but none at all: the editor is hidden, and there is nothing to list)
  const rules = prof ? prof.rules : Array.isArray(state.profiles) ? [] : (state.settings.routeRules || []);
  wrap.innerHTML = '';
  if (!rules.length) {
    wrap.innerHTML = `<div class="empty small">${escapeHtml(t('adv.empty'))}</div>`;
  }
  let hasProc = false;
  rules.forEach((r, idx) => {
    if (r.type === 'process') hasProc = true;
    const row = document.createElement('div');
    row.className = 'adv-rule';
    row.dataset.idx = String(idx);   // the flow tree's rule nodes open their row by it
    // a profile's proxy target can dial through a base: its "via" picker
    const viaOn = !!prof && !!r.target && r.target !== 'direct' && r.target !== 'block';
    const viaCell = viaOn
      ? `<span class="adv-via"><span class="adv-via-label">${escapeHtml(t('rp.via'))}</span><span class="adv-via-mount"></span></span>`
      : '';
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
      ${viaCell}
      <button class="icon-btn adv-del" title="remove">🗑</button>`;
    row.querySelector('.adv-type').onchange = (e) => {
      rules[idx].type = e.target.value;
      if (e.target.value === 'process' && !state.procList.length) loadProcList();
      else renderAdvanced();
    };
    const valEl = row.querySelector('.adv-value');
    // the flow tree follows the value as it is typed (its rules are the draft)
    if (r.type === 'process') valEl.onchange = (e) => { rules[idx].value = e.target.value; if (prof) renderFlowSoon(); };
    else valEl.oninput = (e) => { rules[idx].value = e.target.value; if (prof) renderFlowSoon(); };
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
    if (viaOn) {
      row.querySelector('.adv-via-mount').appendChild(makeSearchSelect({
        options: viaOptionList(prof, r.target), value: r.via || 'inherit',
        onChange: (v) => { rules[idx].via = v; renderAdvanced(); }
      }));
    }
    row.querySelector('.adv-del').onclick = () => { rules.splice(idx, 1); renderAdvanced(); };
    wrap.appendChild(row);
    // a target or a base that is gone: the rule says so, in the danger colour
    const why = prof ? ruleProblem(r, prof) : '';
    if (why) {
      row.classList.add('danger');
      const warn = document.createElement('div');
      warn.className = 'adv-warn';
      warn.textContent = '⚠ ' + t(why);
      wrap.appendChild(warn);
    }
    // when the target ends in a WireGuard, offer its ranges and say where its
    // internal names resolve
    const sug = wgSuggestEl(wgOfTarget(r.target), {
      value: r.value,
      onUse: (list) => { rules[idx].type = 'ip'; rules[idx].value = list; renderAdvanced(); }
    });
    if (sug) wrap.appendChild(sug);
  });

  // default target — searchable dropdown
  const def = (prof ? prof.def : state.settings.routeDefault) || (state.servers[0] && state.servers[0].id) || 'direct';
  defMount.innerHTML = '';
  advDefaultSel = makeSearchSelect({
    options: targetOptionList(), value: def,
    onChange: (v) => {
      if (prof) { prof.def = v; renderProfileExtras(); renderFlowTree(); }
      else state.settings.routeDefault = v;
      renderDefaultSuggest();
    }
  });
  defMount.appendChild(advDefaultSel);
  renderDefaultSuggest();
  // a profile's default via and its base sit next to the default target
  renderProfileExtras();
  renderFlowTree();

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
  const seed = (state.servers[0] && state.servers[0].id) || 'direct';
  // Seed a default target so the 🧭 entry is immediately usable on the home page.
  if (on && !Array.isArray(state.profiles) && !state.settings.routeDefault) extra.routeDefault = seed;
  await saveSettings(extra);
  // …with profiles: the first one, when none of them could be connected yet
  if (on && Array.isArray(state.profiles) && state.profiles[0] && !state.profiles.some(profileReady)) {
    await patchProfile(state.profiles[0].id, { def: seed });
  }
  renderAdvanced();
  renderPicker();
  toast(on ? t('t.advOn') : t('t.advOff'), 'ok');
};

// Saved on its own rather than with the Save button: it changes nothing about
// the rules, and leaving it pending would make the mode note lie about what the
// next connect will do. With profiles it is the edited profile's own.
$('#optAdvUseMode').onchange = async () => {
  const on = $('#optAdvUseMode').checked;
  const prof = Array.isArray(state.profiles) ? advDraft() : null;
  if (prof) await patchProfile(prof.id, { useMode: on });
  else await saveSettings({ advancedUseMode: on });
  updateGuardRows();   // a country bypass under the rules is a direct route too
  renderAdvanced();
};

$('#btnAddRule').onclick = () => {
  const prof = Array.isArray(state.profiles) ? advDraft() : null;
  const rules = prof ? prof.rules : (state.settings.routeRules || (state.settings.routeRules = []));
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
  if (advPlans().some(p => (p.rules || []).some(r => r && r.type === 'process'))) loadProcList();
  // the flow tree was drawn while the page was hidden: its lines need the real boxes
  drawFlowSoon();
});

/**
 * Ask the core whether the geo codes in these rules exist in the installed data
 * files, and say which do not.
 *
 * One unknown code — `geosite:ir`, which the app itself used to suggest, is not
 * in geosite.dat at all — makes the core refuse the ENTIRE config, and its
 * message ("code not found in geosite.dat: IR") reads like the geo files are
 * missing. Catching it where the rule is written is the difference between a
 * typo and a connection that will not come up.
 */
async function warnAboutGeoCodes(rules) {
  if (!window.api || !window.api.checkGeoRules) return;
  let res = null;
  try { res = await window.api.checkGeoRules(rules); } catch { return; }
  if (!res || !res.checked || !res.bad || !res.bad.length) return;
  toast(t('adv.geoBad').replace('{codes}', res.bad.join('، ')), 'err');
}

$('#btnSaveAdv').onclick = async () => {
  // a routing profile: its draft becomes the saved profile (routing:setProfiles)
  if (Array.isArray(state.profiles)) {
    const rules = await saveProfileDraft();
    if (!rules) return;
    if ($('#optAdvanced').checked !== !!state.settings.advancedRouting) await saveSettings({ advancedRouting: $('#optAdvanced').checked });
    updateGuardRows();
    renderAdvanced();
    renderPicker();
    $('#advSavedHint').textContent = t('saved');
    setTimeout(() => ($('#advSavedHint').textContent = ''), 1800);
    toast(t('t.advSaved') + ' (' + rules.length + ')', 'ok');
    await warnAboutGeoCodes(rules);
    return;
  }
  // collect from current state (kept in sync by the row handlers) + default select
  const rules = (state.settings.routeRules || [])
    .map(r => ({ type: r.type, value: (r.value || '').trim(), target: r.target }))
    .filter(r => r.value && r.target);
  const routeDefault = advDefaultSel ? advDefaultSel.getValue() : (state.settings.routeDefault || 'direct');
  await saveSettings({
    routeRules: rules, routeDefault,
    advancedRouting: $('#optAdvanced').checked,
    advancedUseMode: $('#optAdvUseMode').checked
  });
  state.settings.routeRules = rules;
  updateGuardRows();   // a `direct` target here contradicts the strict guard too
  renderAdvanced();
  renderPicker();
  $('#advSavedHint').textContent = t('saved');
  setTimeout(() => ($('#advSavedHint').textContent = ''), 1800);
  toast(t('t.advSaved') + ' (' + rules.length + ')', 'ok');
  await warnAboutGeoCodes(rules);
};

/* ----------------------------- routing profiles ----------------------------- */
// Several advanced routings ("profiles"), each with its own rules, default and
// an optional base that its proxy targets dial through. The list is the main
// process's (routing:profiles). On a back end without it state.profiles stays
// null, and every function here leaves today's single advanced routing as it was.

/** The profile a selection connects: '__advanced__' = the first, '__advanced__:<id>' = that one; null otherwise or without profiles. */
function profileOfSel(id) {
  if (!Array.isArray(state.profiles) || id == null) return null;
  if (id === ADV_ID) return state.profiles[0] || null;
  const s = String(id);
  if (!s.startsWith(ADV_ID + ':')) return null;
  const pid = s.slice(ADV_ID.length + 1);
  return state.profiles.find(p => p.id === pid) || null;
}

/** A profile the home picker offers: it has rules or a default. */
function profileReady(p) { return !!p && ((p.rules || []).length > 0 || !!p.def); }

/** The name an advanced-routing selection goes by: its profile's, else "Advanced routing". */
function advSelName(id) {
  const p = profileOfSel(id);
  return (p && p.name) || t('picker.advanced');
}

/** Everything advanced routing holds: the profiles, or today's settings as one. */
function advPlans() {
  if (Array.isArray(state.profiles)) return state.profiles;
  const s = state.settings || {};
  return [{ rules: s.routeRules || [], def: s.routeDefault, useMode: !!s.advancedUseMode }];
}

/** A target that never takes a via: direct, block (or none at all). */
function terminalTarget(tg) { return !tg || tg === 'direct' || tg === 'block'; }

/**
 * A profile as the renderer keeps it: { id, name, rules, def, defVia, useMode,
 * base } (anything else the back end sent rides along untouched). A via is
 * kept only where it means something — on a proxy target, and not 'inherit',
 * which is what a missing one says — so a saved profile and its draft compare
 * equal however either was written.
 */
function normalizeUiProfile(p) {
  const src = (p && typeof p === 'object') ? p : {};
  const rules = (Array.isArray(src.rules) ? src.rules : []).filter(r => r && typeof r === 'object').map((r) => {
    const out = { type: r.type, value: r.value == null ? '' : String(r.value), target: r.target ? String(r.target) : '' };
    if (!terminalTarget(out.target) && r.via && r.via !== 'inherit') out.via = String(r.via);
    return out;
  });
  const def = src.def ? String(src.def) : '';
  return Object.assign({}, src, {
    id: String(src.id || ''),
    name: String(src.name || ''),
    rules,
    def,
    defVia: !terminalTarget(def) && src.defVia && src.defVia !== 'inherit' ? String(src.defVia) : 'inherit',
    useMode: !!src.useMode,
    base: src.base ? String(src.base) : null
  });
}

/**
 * The profiles, from init's data when main sends them there, else asked for.
 * null when the back end has none: the bridge is missing, or its handler is
 * (Electron's "No handler registered", the service's "unknown channel").
 */
async function loadRoutingProfiles(data) {
  if (data && Array.isArray(data.routingProfiles)) return data.routingProfiles.map(normalizeUiProfile);
  if (!window.api || typeof window.api.routingProfiles !== 'function') return null;
  try {
    const res = await window.api.routingProfiles();
    const list = Array.isArray(res) ? res : (res && res.profiles);
    return Array.isArray(list) ? list.map(normalizeUiProfile) : null;
  } catch { return null; }
}

function newProfileId() { return 'rp-' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6); }

/** `name`, or "name (2)", "name (3)"… — the first that no other profile (but `exceptId`) goes by. */
function uniqueProfileName(name, exceptId) {
  const want = String(name || '').trim() || t('picker.advanced');
  const taken = new Set((state.profiles || []).filter(p => p.id !== exceptId).map(p => p.name));
  if (!taken.has(want)) return want;
  const stem = want.replace(/ \(\d+\)$/, '');
  for (let n = 2; ; n++) {
    const next = `${stem} (${n})`;
    if (!taken.has(next)) return next;
  }
}

/* The draft: the profile being edited. Its rules, default, default via and
   base wait for Save, as today's rule edits do; its name and "apply the
   routing mode too" are saved the moment they change. */
let rpDraft = null;

/** The draft of the profile the routing page edits (the first when none is chosen); null without profiles. */
function advDraft() {
  if (!Array.isArray(state.profiles)) return null;
  let p = state.profiles.find(x => x.id === state.profileSel);
  if (!p) { p = state.profiles[0] || null; state.profileSel = p ? p.id : null; }
  if (!p) { rpDraft = null; return null; }
  if (!rpDraft || rpDraft.id !== p.id) rpDraft = normalizeUiProfile(JSON.parse(JSON.stringify(p)));
  return rpDraft;
}

/** What Save writes of a profile. */
function draftKey(p) {
  const n = normalizeUiProfile(p);
  return JSON.stringify([n.rules, n.def, n.defVia, n.base]);
}

/** Whether the draft holds edits that are not saved. */
function draftDirty() {
  if (!rpDraft || !Array.isArray(state.profiles)) return false;
  const saved = state.profiles.find(p => p.id === rpDraft.id);
  return !!saved && draftKey(rpDraft) !== draftKey(saved);
}

/** Leave the draft: at once when nothing in it is unsaved, else only once the user says so. */
function confirmDiscardDraft() {
  return !draftDirty() || window.confirm(t('rp.discard'));
}

/**
 * The base a rule's target dials through — the default's too, as { target:
 * def, via: defVia }: its own via, else ('inherit') the profile's base. None
 * for 'none', for direct and block, and for a target that IS that base.
 */
function ruleVia(r, prof) {
  const target = r && r.target;
  if (terminalTarget(target)) return null;
  const v = r.via;
  const via = !v || v === 'inherit' ? ((prof && prof.base) || null) : (v === 'none' ? null : v);
  return via && via !== target ? via : null;
}

/** Why a target or a base cannot be dialled — an i18n key, '' when it can: a server gone, a chain gone or short. */
function refProblem(ref) {
  if (terminalTarget(ref)) return '';
  if (String(ref).startsWith('chain:')) return chainReady(chainById(String(ref).slice(6))) ? '' : 'rp.why.chainGone';
  return srvById(ref) ? '' : 'rp.why.serverGone';
}

/** What is wrong with one rule of a profile ('' when nothing): its target, else the base it dials through. */
function ruleProblem(r, prof) {
  const own = refProblem(r && r.target);
  if (own) return own;
  const via = ruleVia(r, prof);
  return via && refProblem(via) ? 'rp.why.baseGone' : '';
}

/** Whether a profile could not be connected as it stands: a rule, its default or its base points at nothing. */
function profileBroken(p) {
  if (!p) return false;
  if ((p.rules || []).some(r => r && String(r.value || '').trim() && ruleProblem(r, p))) return true;
  const def = p.def || (state.servers[0] && state.servers[0].id) || 'direct';
  return !!ruleProblem({ target: def, via: p.defVia }, p) || !!(p.base && refProblem(p.base));
}

/** The name of a server or chain reference, plain ('—' when it is gone). */
function refName(ref) {
  if (String(ref).startsWith('chain:')) {
    const c = chainById(String(ref).slice(6));
    return c ? c.name : '—';
  }
  const s = srvById(ref);
  return s ? s.name : '—';
}

/**
 * [{value,label}] for a via picker: the profile's base (inherit, named), none,
 * then every server and ready chain but the target itself — and the current
 * choice when it is gone, so the picker shows it rather than a blank.
 */
function viaOptionList(prof, target, current) {
  const base = prof && prof.base;
  const opts = [
    { value: 'inherit', label: base ? t('rp.viaInherit').replace('{base}', () => targetLabel(base)) : t('rp.viaInheritNone') },
    { value: 'none', label: t('rp.viaNone') }
  ];
  for (const o of poolTargetOptions()) if (o.value !== target) opts.push(o);
  if (current && !opts.some(o => o.value === current)) opts.push({ value: current, label: '⚠ ' + targetLabel(current) });
  return opts;
}

/** [{value,label}] for the base picker: none, then every server and ready chain (and a gone current one). */
function baseOptionList(current) {
  const opts = [{ value: '', label: t('rp.baseNone') }, ...poolTargetOptions()];
  if (current && !opts.some(o => o.value === current)) opts.push({ value: current, label: '⚠ ' + targetLabel(current) });
  return opts;
}

/**
 * Write the list (routing:setProfiles) and take the back end's answer as the
 * truth. `opts.select` moves the editor to that profile, `opts.resetDraft`
 * drops the draft (it is what was just saved). An edit of the profile that is
 * up is saved, not live: main says so in pendingReconnect, and a key that is
 * new there brings the same offer to reconnect a settings save does.
 */
async function persistProfiles(list, opts = {}) {
  let res = null;
  try { res = await window.api.setRoutingProfiles(list); }
  catch (e) { res = { ok: false, error: (e && e.message) || String(e) }; }
  if (!res || res.ok === false) {
    toast(t('t.failed') + (res && res.error ? ': ' + res.error : ''), 'err');
    return false;
  }
  const before = (state.pendingReconnect || []).slice();
  state.profiles = (Array.isArray(res.profiles) ? res.profiles : list).map(normalizeUiProfile);
  if (opts.select) state.profileSel = opts.select;
  if (opts.resetDraft) rpDraft = null;
  if (Array.isArray(res.pendingReconnect)) setPending(res.pendingReconnect);
  afterProfilesChanged();
  if (state.connected && (state.pendingReconnect || []).some(k => !before.includes(k))) await promptApplySettings();
  return true;
}

/** Everything drawn from the profiles: the routing page, the picker, the home path and the guard note. */
function afterProfilesChanged() {
  renderAdvanced();
  renderPicker();
  refreshConnLabels();
  updateGuardRows();
}

/** Change fields of a saved profile at once (its name, useMode or default), and the draft's with it. */
async function patchProfile(id, patch) {
  if (!Array.isArray(state.profiles)) return false;
  const list = state.profiles.map(p => (p.id === id ? normalizeUiProfile(Object.assign({}, p, patch)) : p));
  if (rpDraft && rpDraft.id === id) Object.assign(rpDraft, patch);
  const ok = await persistProfiles(list);
  if (!ok && rpDraft && rpDraft.id === id) {
    const saved = state.profiles.find(p => p.id === id);
    if (saved) for (const k of Object.keys(patch)) rpDraft[k] = saved[k];
    renderAdvanced();
  }
  return ok;
}

/** Save: the draft's rules (the empty ones dropped), default, default via and base. Resolves to the saved rules, or null. */
async function saveProfileDraft() {
  const d = Array.isArray(state.profiles) ? advDraft() : null;
  if (!d) return null;
  const rules = d.rules
    .map(r => Object.assign({ type: r.type, value: String(r.value || '').trim(), target: r.target }, r.via ? { via: r.via } : {}))
    .filter(r => r.value && r.target);
  const def = (advDefaultSel && advDefaultSel.getValue()) || d.def;
  const useMode = $('#optAdvUseMode') ? !!$('#optAdvUseMode').checked : !!d.useMode;
  const next = normalizeUiProfile(Object.assign({}, d, { rules, def, useMode }));
  const list = state.profiles.map(p => (p.id === d.id ? next : p));
  return (await persistProfiles(list, { resetDraft: true })) ? next.rules : null;
}

async function addProfile() {
  if (!Array.isArray(state.profiles) || !confirmDiscardDraft()) return;
  const p = normalizeUiProfile({
    id: newProfileId(),
    name: uniqueProfileName(t('rp.newName').replace('{n}', state.profiles.length + 1)),
    rules: [], def: (state.servers[0] && state.servers[0].id) || 'direct', defVia: 'inherit', useMode: false, base: null
  });
  await persistProfiles([...state.profiles, p], { select: p.id, resetDraft: true });
}

async function renameProfile(id, name) {
  const p = (state.profiles || []).find(x => x.id === id);
  const clean = String(name || '').trim();
  if (!p || !clean || clean === p.name) { renderProfileBar(); return; }
  await patchProfile(id, { name: uniqueProfileName(clean, id) });
  // the field still has focus, so the redraw left it alone: show the name it got ("Work (2)")
  const saved = (state.profiles || []).find(x => x.id === id);
  const field = $('#rpName');
  if (saved && field && state.profileSel === id) field.value = saved.name;
}

/** A copy of the saved profile, named "<name> (2)", right after it — and edited next. */
async function duplicateProfile(id) {
  const p = (state.profiles || []).find(x => x.id === id);
  if (!p || !confirmDiscardDraft()) return;
  const copy = normalizeUiProfile(Object.assign(JSON.parse(JSON.stringify(p)), { id: newProfileId(), name: uniqueProfileName(p.name) }));
  const list = state.profiles.slice();
  list.splice(list.indexOf(p) + 1, 0, copy);
  await persistProfiles(list, { select: copy.id, resetDraft: true });
}

async function deleteProfile(id) {
  const p = (state.profiles || []).find(x => x.id === id);
  if (!p) return;
  if (state.profiles.length <= 1) { toast(t('rp.lastOne'), 'warn'); return; }
  if (!window.confirm(t('rp.confirmDelete').replace('{name}', () => p.name))) return;
  const list = state.profiles.filter(x => x.id !== id);
  await persistProfiles(list, { select: list[0].id, resetDraft: true });
}

/** The default profile is the first: what plain '__advanced__' (LuCI, an older selection) connects. */
async function makeDefaultProfile(id) {
  const p = (state.profiles || []).find(x => x.id === id);
  if (!p || state.profiles[0] === p) return;
  await persistProfiles([p, ...state.profiles.filter(x => x !== p)]);
}

function selectProfileForEdit(id) {
  if (id === state.profileSel || !confirmDiscardDraft()) return;
  state.profileSel = id;
  rpDraft = null;
  renderAdvanced();
}

/** A <span> of `cls` holding `text`, appended to `parent`. */
function spanIn(parent, cls, text) {
  const s = document.createElement('span');
  s.className = cls;
  s.textContent = text;
  parent.appendChild(s);
  return s;
}

/** The profile list (tabs: ★ the default, ● the one up, the danger colour for one that points at nothing) and the edited one's head. */
function renderProfileBar() {
  const bar = $('#rpBar');
  const list = $('#rpList');
  const head = $('#rpHead');
  if (!bar || !list || !head) return;
  const on = Array.isArray(state.profiles);
  const prof = on ? advDraft() : null;
  bar.hidden = !on;
  head.hidden = !prof;
  const empty = $('#rpEmpty');
  if (empty) empty.hidden = !on || !!prof;
  const editor = $('#advEditor');
  if (editor) editor.hidden = on && !prof;
  list.innerHTML = '';
  if (!on) return;
  list.setAttribute('aria-label', t('rp.listLabel'));
  state.profiles.forEach((p, i) => {
    const active = !!prof && p.id === prof.id;
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'rp-tab' + (active ? ' active' : '') + (profileBroken(p) ? ' danger' : '');
    b.dataset.id = p.id;
    b.setAttribute('role', 'tab');
    b.setAttribute('aria-selected', active ? 'true' : 'false');
    spanIn(b, 'rp-tab-ico', '🧭');
    spanIn(b, 'rp-tab-name', p.name || t('picker.advanced'));
    if (i === 0) spanIn(b, 'rp-tab-def', '★').title = t('rp.isDefault');
    if (profileLive(p.id)) spanIn(b, 'rp-tab-live', '●').title = t('rp.flowLive');
    b.onclick = () => selectProfileForEdit(p.id);
    list.appendChild(b);
  });
  if (!prof) return;
  const saved = state.profiles.find(p => p.id === prof.id) || prof;
  const nameIn = $('#rpName');
  if (nameIn && document.activeElement !== nameIn) nameIn.value = saved.name;
  const isDefault = state.profiles[0] === saved;
  $('#rpDefBadge').hidden = !isDefault;
  $('#btnRpDefault').hidden = isDefault;
  for (const [sel, key] of [['#btnRpDup', 'rp.duplicate'], ['#btnRpShare', 'rp.copyLink'], ['#btnRpDel', 'rp.delete']]) {
    const el = $(sel);
    el.title = t(key);
    el.setAttribute('aria-label', t(key));
  }
  const del = $('#btnRpDel');
  del.disabled = state.profiles.length <= 1;
  if (del.disabled) del.title = t('rp.lastOne');
}

/** Next to the default target: its via picker (a proxy default only) and the profile's base picker. */
function renderProfileExtras() {
  const viaWrap = $('#advDefVia');
  const viaMount = $('#advDefViaMount');
  const baseRow = $('#advBaseRow');
  const baseMount = $('#advBaseMount');
  if (!viaWrap || !viaMount || !baseRow || !baseMount) return;
  const prof = Array.isArray(state.profiles) ? advDraft() : null;
  viaMount.innerHTML = '';
  baseMount.innerHTML = '';
  baseRow.hidden = !prof;
  const def = prof ? ((advDefaultSel && advDefaultSel.getValue()) || prof.def) : '';
  viaWrap.hidden = !prof || terminalTarget(def);
  const why = $('#advBaseWhy');
  if (!prof) { if (why) why.hidden = true; return; }
  if (!terminalTarget(def)) {
    viaMount.appendChild(makeSearchSelect({
      options: viaOptionList(prof, def, prof.defVia), value: prof.defVia || 'inherit',
      onChange: (v) => { prof.defVia = v; renderFlowTree(); }
    }));
  }
  baseMount.appendChild(makeSearchSelect({
    options: baseOptionList(prof.base), value: prof.base || '',
    // every "inherit" label and every rule's danger note follow the base
    onChange: (v) => { prof.base = v || null; renderAdvanced(); }
  }));
  const k = prof.base ? refProblem(prof.base) : '';
  if (why) {
    why.hidden = !k;
    why.textContent = k ? '⚠ ' + t('rp.why.baseGone') : '';
  }
}

/* ------------------------- the flow tree (rules → targets → bases) ------------------------- */

/** The glyph of a rule type in the flow tree. */
function ruleTypeIcon(type) {
  return type === 'ip' ? '📍' : type === 'port' ? '🔌' : type === 'process' ? '⚙' : '🌐';
}

/** A group's values, short: the first two, how many more, and all of them (the tooltip). */
function ruleSummary(items) {
  const all = [];
  for (const it of items || []) {
    for (const v of String((it && it.value) || '').split(',')) {
      const s = v.trim();
      if (s) all.push(s);
    }
  }
  return { text: all.slice(0, 2).join(', '), more: Math.max(0, all.length - 2), full: all.join(', ') };
}

/**
 * A profile's flow, as data. Left to right (RTL mirrors it):
 *   groups  — the rules, consecutive ones to the same target and base as one
 *             node, then the default as "everything else";
 *   targets — one node per target and base it dials through (a server used
 *             both directly and via a base is two: two outbounds);
 *   bases   — each drawn once, every target through it pointing at it.
 * Edges run rule → target → base; direct and block end where they are. A
 * target or base that is gone carries `why` (an i18n key) and its edges are
 * danger. `tags` are the outbounds whose live counters a node shows.
 */
function flowModel(prof) {
  const groups = [], targets = [], bases = [], ruleEdges = [], baseEdges = [];
  const tIndex = {}, bIndex = {};
  const baseNode = (ref, first) => {
    const key = 'b:' + ref;
    if (!bIndex[key]) {
      bIndex[key] = { key, kind: 'base', ref, why: refProblem(ref) ? 'rp.why.baseGone' : '', tags: [baseTagFor(ref)], first, into: 0 };
      bases.push(bIndex[key]);
    }
    return bIndex[key];
  };
  const targetNode = (ref, via, first) => {
    const key = 't:' + ref + (via ? '@' + via : '');
    if (!tIndex[key]) {
      const kind = ref === 'direct' || ref === 'block' ? ref : (String(ref).startsWith('chain:') ? 'chain' : 'server');
      tIndex[key] = { key, kind, ref, via: via || null, why: refProblem(ref), tags: [via ? viaTagFor(ref, via) : outboundTagFor(ref)], first };
      targets.push(tIndex[key]);
      if (via) {
        const b = baseNode(via, first);
        b.into++;
        baseEdges.push({ from: key, to: b.key, danger: !!b.why });
      }
    }
    return tIndex[key];
  };
  (prof.rules || []).forEach((r, idx) => {
    // a row still being written (no value yet) does nothing — Save drops it
    if (!r || !r.target || !String(r.value || '').trim()) return;
    const via = ruleVia(r, prof);
    const last = groups[groups.length - 1];
    if (last && last.target === r.target && last.via === via && last.idxs[last.idxs.length - 1] === idx - 1) {
      last.idxs.push(idx);
      last.items.push({ type: r.type, value: r.value });
      return;
    }
    const tn = targetNode(r.target, via, idx);
    const g = { key: 'g' + idx, kind: 'rule', isDefault: false, idxs: [idx], items: [{ type: r.type, value: r.value }], target: r.target, via, to: tn.key };
    groups.push(g);
    ruleEdges.push({ from: g.key, to: tn.key, danger: !!tn.why });
  });
  // what the builder takes when no default is set: the first server, else direct
  const def = prof.def || (state.servers[0] && state.servers[0].id) || 'direct';
  const dv = ruleVia({ target: def, via: prof.defVia }, prof);
  const dt = targetNode(def, dv, 'def');
  groups.push({ key: 'def', kind: 'rule', isDefault: true, idxs: [], items: [], target: def, via: dv, to: dt.key });
  ruleEdges.push({ from: 'def', to: dt.key, danger: !!dt.why });
  return { profileId: prof.id, groups, targets, bases, edges: ruleEdges.concat(baseEdges) };
}

let rfModel = null;   // the flow tree on screen (its edges are drawn from it)

/** A node of the flow tree: a real button (keyboard-reachable), keyed for its edges. */
function flowButton(cls, key) {
  const b = document.createElement('button');
  b.type = 'button';
  b.className = 'rf-node ' + cls;
  b.dataset.key = key;
  return b;
}

function flowRuleNode(g) {
  const b = flowButton('rf-rule' + (g.isDefault ? ' rf-default' : ''), g.key);
  const to = (g.target === 'direct' ? t('adv.direct') : g.target === 'block' ? t('adv.block') : refName(g.target)) +
    (g.via ? ' · ' + t('rp.viaBase').replace('{base}', () => refName(g.via)) : '');
  if (g.isDefault) {
    spanIn(b, 'rf-ico', '↓');
    spanIn(b, 'rf-label', t('rp.everythingElse'));
    b.title = t('rp.everythingElse') + ' → ' + to;
  } else {
    const nums = g.idxs.map(i => String(i + 1).padStart(2, '0'));
    spanIn(b, 'rf-idx', nums.length > 1 ? nums[0] + '–' + nums[nums.length - 1] : nums[0]);
    spanIn(b, 'rf-ico', [...new Set(g.items.map(it => it.type))].map(ruleTypeIcon).join(''));
    const sum = ruleSummary(g.items);
    spanIn(b, 'rf-label', sum.text || '—').dir = 'ltr';
    if (sum.more) spanIn(b, 'rf-more', '+' + sum.more);
    b.title = sum.full + ' → ' + to;
  }
  // the narrow (stacked) layout has no lines: this says where the rule goes instead
  spanIn(b, 'rf-to', '→ ' + to);
  b.setAttribute('aria-label', b.title);
  b.onclick = () => flowNodeClick(g);
  return b;
}

/** A target or a base node: what it is, the base it dials through, why it is broken, its live speed. */
function flowRefNode(n) {
  const isBase = n.kind === 'base';
  const terminal = n.kind === 'direct' || n.kind === 'block';
  const cls = isBase ? 'rf-base' : 'rf-target to-' + (terminal ? n.kind : 'proxy');
  const b = flowButton(cls + (n.why ? ' danger' : ''), n.key);
  const icon = isBase ? '⚓' : n.kind === 'direct' ? '↗' : n.kind === 'block' ? '⛔' : n.kind === 'chain' ? '⛓' : '🛡';
  const label = n.kind === 'direct' ? t('adv.direct') : n.kind === 'block' ? t('adv.block') : refName(n.ref);
  spanIn(b, 'rf-ico', icon);
  spanIn(b, 'rf-label', label);
  const parts = [label];
  if (isBase) {
    spanIn(b, 'rf-tag', t('rp.base'));
    parts.push(t('rp.base'));
  } else if (n.via) {
    const via = t('rp.viaBase').replace('{base}', () => refName(n.via));
    spanIn(b, 'rf-sub', via);
    parts.push(via);
  }
  if (n.why) {
    spanIn(b, 'rf-why', '⚠ ' + t(n.why));
    parts.push(t(n.why));
  }
  // block carries nothing worth counting
  if (n.kind !== 'block') spanIn(b, 'rf-traffic', '').dataset.tags = n.tags.join(',');
  b.title = parts.join(' — ');
  b.setAttribute('aria-label', b.title);
  b.onclick = () => flowNodeClick(n);
  return b;
}

/** Draw the flow tree of the profile being edited — its draft, so an edit shows before it is saved. */
function renderFlowTree() {
  const wrap = $('#rpFlowWrap');
  const host = $('#rpFlow');
  if (!wrap || !host) return;
  const prof = Array.isArray(state.profiles) ? advDraft() : null;
  wrap.hidden = !prof;
  host.innerHTML = '';
  rfModel = prof ? flowModel(prof) : null;
  if (!rfModel) return;
  const grid = document.createElement('div');
  grid.className = 'rf' + (rfModel.bases.length ? '' : ' no-bases');
  const column = (cls, label) => {
    const box = document.createElement('div');
    box.className = 'rf-colwrap';
    spanIn(box, 'rf-head', label);
    const col = document.createElement('div');
    col.className = 'rf-col ' + cls;
    col.setAttribute('role', 'group');
    col.setAttribute('aria-label', label);
    box.appendChild(col);
    grid.appendChild(box);
    return col;
  };
  const rulesCol = column('rf-rules', t('rp.colRules'));
  const targetsCol = column('rf-targets', t('rp.colTargets'));
  for (const g of rfModel.groups) rulesCol.appendChild(flowRuleNode(g));
  for (const n of rfModel.targets) targetsCol.appendChild(flowRefNode(n));
  if (rfModel.bases.length) {
    const basesCol = column('rf-bases', t('rp.colBases'));
    for (const n of rfModel.bases) basesCol.appendChild(flowRefNode(n));
  }
  // the lines: one SVG under the nodes, drawn once the boxes are laid out
  const layer = document.createElement('div');
  layer.className = 'rf-edges';
  layer.setAttribute('aria-hidden', 'true');
  grid.appendChild(layer);
  host.appendChild(grid);
  applyFlowTraffic(lastPerOutbound);
  drawFlowSoon();
}

/**
 * A click on a node opens what it stands for: a rule its row in the editor,
 * the default its row; a server its edit form, a chain its card. Direct,
 * block and anything gone have no editor — the rule that uses them opens, and
 * a gone base its picker.
 */
function flowNodeClick(n) {
  if (n.kind === 'rule') return focusAdvRow(n.isDefault ? null : n.idxs[0]);
  const ref = n.ref;
  if (!n.why && String(ref).startsWith('chain:')) return openChainCard(String(ref).slice(6));
  if (!n.why && !terminalTarget(ref)) return openEdit(ref);
  if (n.kind === 'base') return flashInto($('#advBaseRow'), '.ss-current');
  return focusAdvRow(n.first === 'def' || n.first == null ? null : n.first);
}

/** Scroll to an element, light it up for a moment and focus `focusSel` inside it. */
function flashInto(el, focusSel) {
  if (!el) return;
  if (el.scrollIntoView) el.scrollIntoView({ block: 'center', behavior: 'smooth' });
  el.classList.add('flash');
  setTimeout(() => el.classList.remove('flash'), 1600);
  const f = focusSel && el.querySelector ? el.querySelector(focusSel) : null;
  if (f && f.focus) f.focus({ preventScroll: true });
}

/** A rule's row in the editor (idx null: the default's). */
function focusAdvRow(idx) {
  let el = null;
  if (idx == null) el = $('#advBody') ? $('#advBody').querySelector('.adv-default') : null;
  else el = $$('#advRules .adv-rule').find(r => r.dataset.idx === String(idx)) || null;
  flashInto(el, '.adv-value, .ss-current');
}

/** A chain's card on the chains page. */
function openChainCard(cid) {
  showView('chain');
  flashInto($$('#chainsWrap .chain-card').find(c => c.dataset.chainId === cid) || null, '.chain-name');
}

/**
 * Each edge as an SVG path, from the boxes of its two nodes (`rects` by key,
 * `box` the tree's own): the source's far side to the target's near side — in
 * RTL the far side is the left — as an S-curve between the columns.
 */
function flowEdgePaths(edges, rects, box, rtl) {
  const r1 = (v) => Math.round(v * 10) / 10;
  const out = [];
  for (const e of edges || []) {
    const a = rects[e.from], b = rects[e.to];
    if (!a || !b) continue;
    const x1 = (rtl ? a.left : a.right) - box.left;
    const y1 = a.top + a.height / 2 - box.top;
    const x2 = (rtl ? b.right : b.left) - box.left;
    const y2 = b.top + b.height / 2 - box.top;
    const c = (x2 - x1) / 2;
    out.push({ from: e.from, to: e.to, danger: !!e.danger,
      d: `M${r1(x1)} ${r1(y1)} C${r1(x1 + c)} ${r1(y1)} ${r1(x2 - c)} ${r1(y2)} ${r1(x2)} ${r1(y2)}` });
  }
  return out;
}

/** Draw the tree's lines from where its nodes landed. Nothing while it is hidden — the ResizeObserver draws it when it shows. */
function drawFlowEdges() {
  const host = $('#rpFlow');
  const grid = host && host.querySelector ? host.querySelector('.rf') : null;
  const layer = grid ? grid.querySelector('.rf-edges') : null;
  if (!layer || !rfModel || typeof grid.getBoundingClientRect !== 'function') return;
  const box = grid.getBoundingClientRect();
  if (!box.width || !box.height) return;
  const rects = {};
  for (const n of grid.querySelectorAll('.rf-node')) rects[n.dataset.key] = n.getBoundingClientRect();
  const rtl = getComputedStyle(grid).direction === 'rtl';
  const w = Math.ceil(box.width), h = Math.ceil(box.height);
  // everything below is a literal or a number: the boxes' coordinates
  const head = '<path d="M0 0 L8 4 L0 8 z"/></marker>';
  const markers = '<marker id="rfArrow" class="rf-mark" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto">' + head +
    '<marker id="rfArrowBad" class="rf-mark bad" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto">' + head;
  layer.innerHTML = `<svg width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" focusable="false"><defs>${markers}</defs>` +
    flowEdgePaths(rfModel.edges, rects, box, rtl)
      .map(line => `<path class="rf-edge${line.danger ? ' danger' : ''}" d="${line.d}" marker-end="url(#${line.danger ? 'rfArrowBad' : 'rfArrow'})"/>`).join('') +
    '</svg>';
}

let rfDrawPending = false;
/** Draw the lines on the next frame (once, however many renders asked). */
function drawFlowSoon() {
  if (rfDrawPending) return;
  rfDrawPending = true;
  const run = () => { rfDrawPending = false; drawFlowEdges(); };
  if (typeof requestAnimationFrame === 'function') requestAnimationFrame(run);
  else setTimeout(run, 0);
}

let rfRenderTimer = null;
/** Redraw the tree a moment after the last keystroke in a rule's value. */
function renderFlowSoon() {
  clearTimeout(rfRenderTimer);
  rfRenderTimer = setTimeout(renderFlowTree, 150);
}
// the window, the column or the page resizing moves every node: the lines follow
if (typeof ResizeObserver !== 'undefined' && $('#rpFlow')) new ResizeObserver(() => drawFlowSoon()).observe($('#rpFlow'));

/** Whether profile `id` is the one connected right now. */
function profileLive(id) {
  if (!state.connected || !id) return false;
  const p = profileOfSel(state.activeServerId);
  return !!p && p.id === id;
}

/**
 * Each branch's live speed in the flow tree, from the core's per-outbound
 * counters (a target through a base is 'out-…@<base>', a base 'base-…') —
 * only while the profile on screen is the one up. Text only, like the home path.
 */
function applyFlowTraffic(per) {
  const host = $('#rpFlow');
  if (!host || typeof host.querySelectorAll !== 'function') return;
  const live = !!rfModel && profileLive(rfModel.profileId);
  const grid = host.querySelector('.rf');
  if (grid) grid.classList.toggle('live', live);
  const badge = $('#rpFlowLive');
  if (badge) badge.hidden = !live;
  for (const el of host.querySelectorAll('.rf-traffic')) {
    const v = live && per ? per[String(el.dataset.tags || '').split(',')[0]] : null;
    el.textContent = v ? `↓${fmtSpeed(v.downSpeed)} ↑${fmtSpeed(v.upSpeed)}` : '';
    el.title = v ? `↓${fmtBytes(v.down)} ↑${fmtBytes(v.up)}` : '';
  }
}

$('#btnRpAdd').onclick = () => addProfile();
$('#btnRpDup').onclick = () => duplicateProfile(state.profileSel);
$('#btnRpDel').onclick = () => deleteProfile(state.profileSel);
$('#btnRpDefault').onclick = () => makeDefaultProfile(state.profileSel);
$('#btnRpShare').onclick = () => shareRouting('profile', state.profileSel);
$('#rpName').onchange = () => renameProfile(state.profileSel, $('#rpName').value);

/* ------------------------- share links (irnetfree://routing/…) ------------------------- */

/** A share link is QR-coded when its text is ≤ 1,700 bytes (the JSON QR's limit, for the same 320px box; the link is ASCII). */
function shareQrFits(link) { return String(link || '').length <= QR_JSON_MAX_BYTES; }

/**
 * "Copy link" of a profile or a chain: main builds the link (it carries every
 * server it needs, in full); the dialog says so before the Copy button.
 */
async function shareRouting(kind, id) {
  const call = kind === 'chain' ? window.api.shareChain : window.api.shareRoutingProfile;
  if (!id || typeof call !== 'function') return toast(t('t.failed'), 'err');
  // the link is built from what is saved
  if (kind !== 'chain' && rpDraft && rpDraft.id === id && draftDirty()) toast(t('rp.shareSaved'), 'warn');
  let res = null;
  try { res = await call(id); } catch (e) { res = { ok: false, error: (e && e.message) || String(e) }; }
  if (!res || !res.ok || !res.link) return toast(t('t.failed') + (res && res.error ? ': ' + res.error : ''), 'err');
  openShareModal(kind, res);
}

/** The share dialog: the warning, a QR when the link fits one, the link and its Copy. Returns whether a QR was drawn. */
function openShareModal(kind, res) {
  const link = String(res.link);
  const n = Array.isArray(res.servers) ? res.servers.length : (Number(res.servers) || 0);
  $('#rpShareTitle').textContent = t(kind === 'chain' ? 'rp.shareChainTitle' : 'rp.shareTitle');
  $('#rpShareWarn').textContent = '⚠ ' + t('rp.shareWarn').replace('{n}', n);
  const box = $('#rpShareQr');
  box.innerHTML = '';
  let drawn = false;
  if (shareQrFits(link) && typeof qrcode === 'function') {
    try {
      const qr = qrcode(0, 'L'); qr.addData(link); qr.make();
      box.innerHTML = qr.createSvgTag({ cellSize: 4, margin: 16, scalable: true });
      drawn = true;
    } catch { drawn = false; }
  }
  if (!drawn) box.innerHTML = `<p class="hint rp-share-big">${escapeHtml(t('qr.tooBig'))}</p>`;
  $('#rpShareLink').value = link;
  $('#rpShareModal').hidden = false;
  return drawn;
}
$('#rpShareClose').onclick = () => { $('#rpShareModal').hidden = true; };
$('#rpShareModal').onclick = (e) => { if (e.target === $('#rpShareModal')) $('#rpShareModal').hidden = true; };
$('#rpShareCopy').onclick = () => { copyText($('#rpShareLink').value); toast(t('t.copied'), 'ok'); };

/* the import: preview first, nothing written before Import */
let rpImportText = '';

/** A count in a summary: an array's length or a number. */
function importCount(v) { return Array.isArray(v) ? v.length : (Number(v) || 0); }

/** The names in a summary list (strings, or { name|key, error }); [] for a bare count. */
function importNames(v) {
  if (!Array.isArray(v)) return [];
  return v.map((x) => {
    if (typeof x === 'string') return x;
    if (!x || typeof x !== 'object') return '';
    return [x.name || x.key || '', x.error || x.reason || ''].filter(Boolean).join(': ');
  }).filter(Boolean);
}

/** Ask main what a pasted link holds, and show it. Resolves to whether the preview opened. */
async function openRoutingImport(text) {
  const link = String(text || '').trim().split(/\s+/)[0];
  const fail = (why) => { toast(t('rp.importFailed').replace('{reason}', () => why || '—'), 'err'); return false; };
  if (!window.api || typeof window.api.routingImportPreview !== 'function') return fail('');
  let res = null;
  try { res = await window.api.routingImportPreview(link); } catch (e) { res = { ok: false, error: (e && e.message) || String(e) }; }
  if (!res || !res.ok || !res.summary) return fail(res && res.error);
  rpImportText = link;
  renderImportSummary(res.summary);
  $('#rpImportGo').disabled = false;
  $('#rpImportModal').hidden = false;
  return true;
}

/** The preview: what it is and its name, its rules and chains, the servers already here, the new ones and what could not be read. */
function renderImportSummary(sum) {
  const box = $('#rpImportSum');
  box.innerHTML = '';
  const row = (key, value, names, cls) => {
    const r = document.createElement('div');
    r.className = 'rp-im-row' + (cls ? ' ' + cls : '');
    spanIn(r, 'rp-im-k', t(key));
    spanIn(r, 'rp-im-v', value);
    if (names && names.length) {
      const l = document.createElement('div');
      l.className = 'rp-im-names';
      for (const n of names) {
        const b = document.createElement('bdi');
        b.textContent = n;
        l.appendChild(b);
      }
      r.appendChild(l);
    }
    box.appendChild(r);
  };
  const chain = sum.kind === 'chain';
  row('rp.imKind', t(chain ? 'rp.imKindChain' : 'rp.imKindProfile'));
  if (sum.name) row('rp.imName', String(sum.name));
  if (!chain) row('rp.imRules', String(importCount(sum.rules)));
  row('rp.imChains', String(importCount(sum.chains)), importNames(sum.chains));
  row('rp.imExisting', String(importCount(sum.serversExisting)), importNames(sum.serversExisting));
  row('rp.imNew', String(importCount(sum.serversNew)), importNames(sum.serversNew));
  if (importCount(sum.unreadable)) row('rp.imUnreadable', String(importCount(sum.unreadable)), importNames(sum.unreadable), 'danger');
}

function closeRoutingImport() {
  $('#rpImportModal').hidden = true;
  rpImportText = '';
}

/** Import: main writes it all; the lists come back and every page that draws them is redrawn. */
async function runRoutingImport() {
  if (!rpImportText) return false;
  const go = $('#rpImportGo');
  go.disabled = true;
  let res = null;
  try { res = await window.api.routingImport(rpImportText); } catch (e) { res = { ok: false, error: (e && e.message) || String(e) }; }
  go.disabled = false;
  if (!res || !res.ok) {
    toast(t('rp.importFailed').replace('{reason}', () => (res && res.error) || '—'), 'err');
    return false;
  }
  closeRoutingImport();
  await refreshAfterImport(res);
  const a = res.added || {};
  let msg = t('rp.imported').replace('{servers}', importCount(a.servers)).replace('{chains}', importCount(a.chains)).replace('{profiles}', importCount(a.profiles));
  if (res.profileId && !state.settings.advancedRouting) msg += ' — ' + t('rp.importedOff');
  toast(msg, 'ok', 5000);
  return true;
}

/** The servers, chains and profiles after an import: from its answer where it carries them, else asked for. */
async function refreshAfterImport(res) {
  try { state.servers = Array.isArray(res.servers) ? res.servers : await window.api.listServers(); } catch { /* the lists stay as they were */ }
  try {
    const chains = Array.isArray(res.chains) ? res.chains : await window.api.listChains();
    if (Array.isArray(chains)) {
      state.chains = chains.map(c => ({ id: c.id, name: c.name || 'Chain', members: (c.members || []).filter(id => state.servers.some(s => s.id === id)) }));
    }
  } catch { /* as above */ }
  const profiles = Array.isArray(res.profiles) ? res.profiles.map(normalizeUiProfile) : await loadRoutingProfiles(null);
  if (profiles) state.profiles = profiles;
  // the imported profile is edited next — unless that would drop unsaved edits
  if (res.profileId && Array.isArray(state.profiles) && state.profiles.some(p => p.id === res.profileId) && !draftDirty()) {
    state.profileSel = res.profileId;
    rpDraft = null;
  }
  if (!state.selectedServerId && state.servers.length) state.selectedServerId = state.servers[0].id;
  renderServers(); renderPicker(); renderChains(); renderPool(); renderAdvanced();
  refreshConnLabels();
  if (res.profileId) showView('routing');
  else if (res.chainId) showView('chain');
}
$('#rpImportGo').onclick = () => runRoutingImport();
$('#rpImportCancel').onclick = closeRoutingImport;
$('#rpImportClose').onclick = closeRoutingImport;
$('#rpImportModal').onclick = (e) => { if (e.target === $('#rpImportModal')) closeRoutingImport(); };

/* ----------------------------- live traffic stats ----------------------------- */
// Lifetime totals arrive every few seconds — the per-second figures ride the
// stats event, so this one does not need that resolution. Rewrite the spans
// that show them; the list itself is left standing (a rebuild every five
// seconds under a 200-server subscription reset the scroll and cost 1,400
// handler bindings for a number in a corner).
if (window.api.onUsage) {
  window.api.onUsage((d) => {
    state.usage = (d && d.totals) || {};
    applyUsageDisplays();
  });
}

window.api.onStats((s) => {
  $('#downSpeed').textContent = fmtSpeed(s.downSpeed);
  $('#upSpeed').textContent = fmtSpeed(s.upSpeed);
  pushHist(s.downSpeed, s.upSpeed);
  drawSpark();
  $('#downTotal').textContent = fmtBytes(s.totalDown);
  $('#upTotal').textContent = fmtBytes(s.totalUp);
  // session totals (cumulative since xray started for this connection)
  $('#sessDown').textContent = fmtBytes(s.totalDown);
  $('#sessUp').textContent = fmtBytes(s.totalUp);
  $('#sessSum').textContent = fmtBytes((Number(s.totalDown) || 0) + (Number(s.totalUp) || 0));
  // the throughput caption floating over the path's first link. One textContent
  // write per second onto a node the path already built — the diagram itself is
  // never rebuilt here.
  const cap = $('#pathCapIn');
  if (cap) cap.textContent = `↓${fmtSpeed(s.downSpeed)}  ↑${fmtSpeed(s.upSpeed)}`;
  // and each hop's own figures, so the path answers "how much went through
  // THIS config" instead of showing one total for everything at once
  if (s.per) applyPathTraffic(s.per);
  // …and each branch of the routing page's flow tree, while its profile is the one up
  if (s.per) applyFlowTraffic(s.per);
});

function resetTraffic() {
  $('#downSpeed').textContent = '0 B/s';
  $('#upSpeed').textContent = '0 B/s';
  $('#downTotal').textContent = '0 B';
  $('#upTotal').textContent = '0 B';
  $('#sessDown').textContent = '0 B';
  $('#sessUp').textContent = '0 B';
  $('#sessSum').textContent = '0 B';
  hist.down.length = 0; hist.up.length = 0; hist.time.length = 0;
  drawSpark();
}
function setModeWidget() {
  const card = $('#modeCard');
  if (state.flavor === 'openwrt') {
    // A router has one mode — the whole network through the tunnel — so the
    // card names it and never offers Proxy ("Proxy" there meant a LAN going
    // direct while the UI said connected). It is not a dead control either:
    // its tooltip is the gateway's own explanation and a click opens the one
    // router choice, which devices go direct (openModeModal).
    $('#modeIco').textContent = '🛡';
    $('#modeLabel').textContent = t('mode.router');
    $('#modeSub').textContent = t('mode.routerSub');
    if (card) card.title = t('gw.insHint');
    return;
  }
  // Reflect the CHOSEN mode (so users see/can change it before connecting).
  const wantTun = !!state.settings.tunMode;
  $('#modeIco').textContent = wantTun ? '🛡' : '⚡';
  $('#modeLabel').textContent = wantTun ? t('mode.tun') : t('mode.proxy');
  $('#modeSub').textContent = wantTun ? t('mode.tunSub') : t('mode.proxySub');
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
  const fix = $('#modeGetFiles');
  if (!note) return;
  // TUN is the default now, so "the backend is missing" is the FIRST thing a
  // fresh install meets. Saying it in a grey line and connecting proxy-only is
  // how that became "it says connected but only the browser is tunnelled":
  // say it as a warning, and put the fix one click away.
  note.classList.toggle('bad', !state.tunAvailable);
  if (fix) fix.hidden = state.tunAvailable;
  if (!state.tunAvailable) note.textContent = t('tun.unavailable');
  else if (state.settings.tunMode && !state.elevated) note.textContent = t('tun.needAdmin');
  else note.textContent = '';
}
function openModeModal() {
  // one mode on a router, nothing to pick: the card opens the device list instead (setModeWidget)
  if (state.flavor === 'openwrt') { openSettingAt('#gwRow'); return; }
  renderModeOptions();
  $('#modeModal').hidden = false;
}
function closeModeModal() { $('#modeModal').hidden = true; }
$('#modeCard').onclick = openModeModal;
// straight to the place the missing backend is downloaded from
$('#modeGetFiles').onclick = () => {
  closeModeModal();
  showView('settings');
  const c = $('#compList');
  if (c) c.scrollIntoView({ block: 'center' });
};
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
