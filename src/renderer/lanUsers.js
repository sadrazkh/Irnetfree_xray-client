'use strict';
/**
 * «کاربران» / "Users" — the people on this network, each with a username and
 * password, a config of their own and a data cap (module lanUsers; the core is
 * src/modules/lanUsers/, its channels lanusers:get / config / user / device).
 *
 * Three blocks, drawn like the multi-internet card (multiWan.js) with text nodes
 * only — names, usernames, passwords and hostnames come from people and from the
 * network, so nothing here is HTML:
 *   1. the settings card: proxy accounts on or off, their two ports and the
 *      address to give people (a line per LAN address and protocol, each with a
 *      copy button); on the router the transparent mode (nothing to set on the
 *      device), what a device nobody is assigned to gets (the sign-in page, the
 *      current connection, or nothing) and how long a sign-in lasts; on Windows
 *      the Mobile Hotspot note — people on the PC's hotspot use the same proxy
 *      with their username and password, the transparent mode is the router's
 *      — its address marked, and said when it is missing (the hotspot is off);
 *      above it all, when there are users and no way in for any of them, a
 *      line that says so with the button that turns the proxy on;
 *   2. a box per user: who, whether they can connect now (on / off / expired /
 *      over a limit / VPN or direct alone / outside their hours, and until
 *      when), their live rate while connected, the password (hidden; show,
 *      copy, a new one), the config they ride (the app's own picker — every
 *      config by its subscription — plus the current connection, direct and
 *      blocked) and the routing it follows, a bar per limit (its kind and
 *      period, used of cap, what is left; amber from 80 %, red when over) or,
 *      with none, today's and this month's VPN and direct totals, the speed
 *      they get now (the router's), top up and reset, the expiry (its date in
 *      the Persian calendar in Persian) and the allowed hours, on the router
 *      how many devices, the on/off switch, and the last 30 days as stacked
 *      bars (VPN and direct, an SVG drawn node by node); one dialog adds and
 *      edits a user — the limits' grid (Total / VPN / Direct × daily /
 *      monthly / one-off, on the router each with "cut" or "slow to"), the
 *      routing (as the config, Iranian sites direct, or one of the app's
 *      routing profiles), the allowed hours, on the router the speed — and
 *      says where its rules are broken; a small one tops a limit up for its
 *      period; another gives a phone the user's account as a socks:// link and
 *      its QR (shareLink) — imported in IRNetFree or v2rayNG, every app rides it;
 *   3. on the router the devices — online first, each with its name, IP and MAC
 *      (left to right in Persian too), the user it belongs to (and, when a
 *      sign-in gave it to them for good, "by sign-in" and when), a block
 *      switch and its usage.
 *
 * v1.40 on top: a bar over the blocks — Users | Vouchers (the vouchers are
 * ordinary user records with a `voucher`: the Users tab never lists them; the
 * Vouchers tab is luVouchers.js's, mounted when it is there), Backup (one JSON
 * file of the module alone, passwords inside — said before it is saved) and
 * Restore (the file read here, what it holds said, then Merge or Replace). On
 * the router the settings card also holds what the user's status page says
 * (a note, a contact, whether a top-up can be asked for there) and the speed
 * shaping (the line's speed, smooth limits on or off, and what the router does
 * now — tc, nft policing with the packages to install, or nothing). A user's
 * box gains a line of tags (content filter, priority, remembered devices), the
 * days left before it expires, a "asked for a top-up" line with Top up and
 * Dismiss, on the router a sign-in card to print (the QR of the sign-in page
 * with the username filled in, the password only when ticked), and the 12
 * months / CSV / statement of luReports.js when it is there; the dialog gains
 * the content filter (categories, safe search, blocked domains) and, on the
 * router, the priority and "remember devices". `window.LanUsersKit` hands the
 * page's own pieces to luVouchers.js and luReports.js.
 *
 * Every change is saved at once and drawn at once; the service's answer (the
 * whole lanusers:get payload) is the truth, and app.js's `applied` hook brings
 * the "reconnect to apply" question when the answer says the running connection
 * must be rebuilt. app.js decides when the page reads (refresh() each time it
 * opens), hands it each stats tick (tick()) and each connection change
 * (connection()), and redraws it on a language switch (render()).
 */
(() => {
  const t = (key) => window.i18n.t(key);
  const fill = (s, map) => String(s).replace(/\{(\w+)\}/g, (m, k) => (Object.prototype.hasOwnProperty.call(map, k) ? map[k] : m));
  const lang = () => (window.i18n && window.i18n.lang) || document.documentElement.lang || 'fa';
  const KINDS = ['total', 'vpn', 'direct'];       // what a limit counts (model.js limits): the grid's rows…
  const LPERIODS = ['day', 'month', 'none'];      // …and for how long, its columns — 'none' one amount for good
  const GB_MAX = 1000000;                         // model.js QUOTA_MAX_GB
  const KBPS_MAX = 10000000;                      // a speed's ceiling (model.js), 10 Gbps
  const SPEED_WINDOWS = 4;                        // the peak-hour windows a user may have (model.js)
  const HHMM = /^([01]\d|2[0-3]):[0-5]\d$/;
  /** The week as each language's calendar starts it: Saturday in Persian, Monday in English (0 = Sunday, as JS getDay). */
  const WEEK = { fa: [6, 0, 1, 2, 3, 4, 5], en: [1, 2, 3, 4, 5, 6, 0] };
  const CHART_DAYS = 30;                          // the usage history the meter keeps (meter.js lanUsersHistory)
  const SVG_NS = 'http://www.w3.org/2000/svg';
  const DAYS = Array.from({ length: 31 }, (_, i) => i + 1);   // the day a month renews on (capPeriods.js)
  const UNASSIGNED = ['login', 'allow', 'block'];
  const SPECIAL = ['', 'direct', 'block'];        // the targets that are not a config
  const HOTSPOT_IP = '192.168.137.1';             // Windows' Mobile Hotspot address (ipc.js HOTSPOT_IP)
  const NEAR = 0.8;                               // from here the usage bar warns that the cap is close
  const REFRESH_MS = 5000;                        // while the page is open, a stats tick reads it again this often at most
  const USERNAME = /^[A-Za-z0-9._-]{1,32}$/;      // the contract's rule (model.js validateUser)
  const PASS_MIN = 4;
  // a new password: ten of these — no 0/O, 1/l/I, said aloud or typed on a phone without a mix-up
  const PASS_CHARS = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const PASS_LEN = 10;
  const EMPTY = {
    proxy: { enabled: false, port: 30820, httpPort: 30821 },
    transparent: { enabled: false, unassigned: 'login', sessionHours: 24, portalPort: 30822 },
    // what the router's status page says (v1.40, model.js config.portal) and its speed shaping (config.shaping)
    portal: { note: '', contact: '', requests: true },
    shaping: { down: 0, up: 0, smooth: true }
  };
  /**
   * The content filter's categories, in the model's order (model.js
   * FILTER_CATEGORIES) — each a geosite list the app's geosite.dat really has
   * (no gambling: there is no list for it).
   */
  const FILTER_CATS = ['adult', 'social', 'games', 'ads'];
  const FILTER_DOMAINS_MAX = 200;                 // model.js FILTER_DOMAINS_MAX
  /** A blocked domain as the model keeps it: 'example.com', 'full:www.example.com', 'keyword:casino'. */
  const FILTER_DOMAIN = /^(?:(?:full|keyword):)?[a-z0-9._-]{1,253}$/;
  const PRIORITIES = ['high', 'normal', 'low'];   // model.js PRIORITIES — the router's shaper
  const NOTE_MAX = 300;                           // config.portal.note, one line
  const CONTACT_MAX = 64;
  /** A backup file of the Users module alone (lanusers:backup's bundle). */
  const BACKUP_KIND = 'irnetfree-lanusers';
  const BACKUP_VERSION = 1;
  /** The channels and the window.api calls that carry them (preload.js / web-api.js). */
  const API = {
    'lanusers:get': 'lanUsersGet',
    'lanusers:config': 'lanUsersConfig',
    'lanusers:user': 'lanUsersUser',
    'lanusers:device': 'lanUsersDevice',
    'lanusers:backup': 'lanUsersBackup',
    'lanusers:restore': 'lanUsersRestore'
  };

  /* ------------------------------ building blocks ------------------------------ */

  /** An element with its classes and, as text, its words. */
  function el(tag, className, text) {
    const n = document.createElement(tag);
    if (className) n.className = className;
    if (text != null && text !== '') n.textContent = String(text);
    return n;
  }
  function button(className, text) {
    const b = el('button', className, text);
    b.type = 'button';
    return b;
  }
  /** A small icon button, named for assistive tech and in its tooltip. `key` keeps the focus across a redraw. */
  function iconButton(icon, label, key, onClick) {
    const b = button('icon-btn', icon);
    b.setAttribute('aria-label', label);
    b.title = label;
    b.dataset.lu = key;
    b.addEventListener('click', onClick);
    return b;
  }
  /** Left to right inside a Persian line: usernames, passwords, addresses, ports, IPs, MACs. */
  function ltr(n) { n.setAttribute('dir', 'ltr'); return n; }
  /** A <select> of [value, label] pairs, named for assistive tech, saving on change. */
  function select(pairs, value, label, key, onChange) {
    const s = el('select', 'select');
    for (const [v, text] of pairs) {
      const o = el('option', null, text);
      o.value = String(v);
      if (String(v) === String(value)) o.selected = true;
      s.appendChild(o);
    }
    s.value = String(value);
    s.setAttribute('aria-label', label);
    s.dataset.lu = key;
    s.addEventListener('change', () => onChange(s.value));
    return s;
  }
  /** The app's rectangular switch around a checkbox. */
  function switchEl(checked, label, key, onChange) {
    const sw = el('label', 'switch');
    const input = el('input');
    input.type = 'checkbox';
    input.checked = !!checked;
    input.setAttribute('aria-label', label);
    input.dataset.lu = key;
    input.addEventListener('change', () => onChange(input.checked));
    sw.append(input, el('span', 'slider'));
    return sw;
  }
  /** A number box, left to right. */
  function numInput(value, label, key, { min = '0', step = '1', placeholder = '' } = {}) {
    const n = ltr(el('input', 'input'));
    n.type = 'number';
    n.min = min;
    n.step = step;
    n.value = value == null ? '' : String(value);
    n.placeholder = placeholder;
    n.setAttribute('aria-label', label);
    n.dataset.lu = key;
    return n;
  }
  /** A label over its control. */
  function field(label, ...controls) {
    const box = el('div', 'lu-field');
    box.append(el('div', 'field-label', label), ...controls.filter(Boolean));
    return box;
  }
  /**
   * A template's words with each value in a <bdi> of its own: inside a Persian
   * line a size ('3.0 GB', '1 GB VPN') keeps its left-to-right order and a date
   * ('10 آبان') its own — the browser picks each one's direction.
   */
  function tpl(template, map) {
    return String(template).split(/(\{\w+\})/).filter(Boolean).map((p) => {
      const m = /^\{(\w+)\}$/.exec(p);
      return m && Object.prototype.hasOwnProperty.call(map, m[1]) ? el('bdi', null, map[m[1]]) : p;
    });
  }
  /** The app's settings line: a title, its explanation, and the switch at the end. */
  function switchRow(title, sub, checked, key, onChange) {
    const row = el('div', 'switch-row');
    const words = el('div');
    words.append(el('div', 'switch-title', title), el('div', 'switch-sub', sub));
    row.append(words, switchEl(checked, title, key, onChange));
    return row;
  }

  /* ------------------------------ formats ------------------------------ */

  /** Bytes as the app writes them everywhere (app.js fmtBytes): binary units, one decimal. */
  function bytesText(n) {
    let v = Number(n) || 0;
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return (i === 0 ? Math.round(v) : v.toFixed(1)) + ' ' + units[i];
  }
  const rateText = (bytesPerSec) => bytesText(bytesPerSec) + '/s';
  function format(ms, opts) {
    const d = new Date(Number(ms));
    if (!Number.isFinite(d.getTime())) return '';
    // fa-IR is the Persian calendar; Latin digits, as every number in the app
    try { return new Intl.DateTimeFormat(lang() === 'fa' ? 'fa-IR-u-nu-latn' : 'en', opts).format(d); }
    catch { return d.toISOString().slice(0, 10); }
  }
  /** When a period ends: '1 November', '10 آبان'. */
  const dateText = (ms) => (Number(ms) > 0 ? format(ms, { month: 'long', day: 'numeric' }) : '');
  /** An expiry, with its year: '30 November 2026', '9 آذر 1405'. */
  const fullDate = (ms) => (Number(ms) > 0 ? format(ms, { year: 'numeric', month: 'long', day: 'numeric' }) : '');
  const pad = (n) => String(n).padStart(2, '0');
  /** ms → a date box's 'YYYY-MM-DD' (this device's day). */
  function dayInput(ms) {
    const d = new Date(Number(ms));
    if (!(Number(ms) > 0) || !Number.isFinite(d.getTime())) return '';
    return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate());
  }
  /** A date box's 'YYYY-MM-DD' → the END of that day (the user may connect all of it); '' → 0, never. */
  function fromDayInput(v) {
    const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(v || '').trim());
    if (!m) return 0;
    const ms = new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]), 23, 59, 59, 999).getTime();
    return Number.isFinite(ms) ? ms : 0;
  }
  /** An address people type: an IPv6 one in brackets before its port. */
  const hostPort = (ip, port) => (String(ip).includes(':') ? '[' + ip + ']' : String(ip)) + ':' + port;
  /** GB as a box shows it: '20', '0.5' — no trailing zeros. */
  const gbText = (v) => String(Math.round(Number(v) * 1000) / 1000);
  /** A speed is stored in kbps and typed in Mbps: 2000 ↔ '2', 1500 ↔ '1.5'; none is ''. */
  const mbpsText = (kbps) => (Number(kbps) > 0 ? String(Math.round(Number(kbps)) / 1000) : '');
  const kbpsOf = (mbps) => Math.round(Number(mbps) * 1000);
  /** A speed in words: '2 Mbps', '1.5 Mbps', '512 kbps'. */
  const rateWord = (kbps) => (Number(kbps) >= 1000 ? String(Math.round(Number(kbps) / 100) / 10) + ' Mbps' : Math.round(Number(kbps)) + ' kbps');
  /** The clock time of ms on this device: '18:00'. */
  const clock = (ms) => { const d = new Date(Number(ms)); return pad(d.getHours()) + ':' + pad(d.getMinutes()); };
  /** When a hold lifts: its time when that is today ('18:00'), else its day, with the time unless it is midnight. */
  function whenText(ms, now = Date.now()) {
    if (!(Number(ms) > 0)) return '';
    const d = new Date(Number(ms));
    if (d.toDateString() === new Date(now).toDateString()) return clock(ms);
    return dateText(ms) + (d.getHours() || d.getMinutes() ? ' ' + clock(ms) : '');
  }
  /** A local day 'YYYY-MM-DD' → its number of days since 1970 (by the calendar: a clock change moves nothing). */
  function dayNumber(day) {
    const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(day || ''));
    return m ? Math.round(Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3])) / 86400000) : NaN;
  }

  /* ------------------------------ state ------------------------------ */

  const ui = {
    host: null,
    hooks: {},        // app.js: { applied(res), connected(), targets(), picker(o), routingProfiles(), platform(), router(), visible(), copy(text), confirm(msg), toast(msg, kind) }
    data: null,       // the last lanusers:* answer, normalized
    loading: false,
    error: '',
    seq: 0,           // an answer to an older request is dropped
    busy: 0,          // saves in flight: a stats tick does not read over them
    lastRefresh: 0,
    shown: {},        // userId → its password shown in its box
    wasConnected: false,
    form: null,       // the dialog's fields while it is open
    modal: null,      // the dialog's overlay
    opener: null,     // what had the focus when the dialog opened: it gets it back
    share: null,      // the link dialog's overlay
    shareOpener: null,
    topup: null,      // the top-up dialog's overlay
    topupOpener: null,
    card: null,       // the sign-in card dialog's overlay (router)
    cardOpener: null,
    restore: null,    // the restore dialog's overlay
    restoreOpener: null,
    safeGroupPaint: null,   // the dialog's "safe search does not apply through a group" line, said again when the config changes
    tab: 'users',     // the page's tab: 'users' | 'vouchers'
    months: {},       // userId → its 12 months shown (luReports.js)
    dom: { usage: {}, rates: {}, devUse: {} }
  };

  const hook = (name, ...args) => { try { return ui.hooks[name] ? ui.hooks[name](...args) : undefined; } catch { return undefined; } };
  const toast = (msg, kind) => { hook('toast', msg, kind); };
  const connected = () => !!hook('connected');
  const obj = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : {});
  const arr = (v) => (Array.isArray(v) ? v : []);
  const clone = (v) => JSON.parse(JSON.stringify(v));

  /** A lanusers:* answer as the page draws it — a field missing from it reads as empty, never as an error. */
  function normalize(res) {
    const r = obj(res);
    const c = obj(r.config);
    return {
      config: {
        proxy: Object.assign({}, EMPTY.proxy, obj(c.proxy)),
        transparent: Object.assign({}, EMPTY.transparent, obj(c.transparent)),
        portal: Object.assign({}, EMPTY.portal, obj(c.portal)),
        shaping: Object.assign({}, EMPTY.shaping, obj(c.shaping))
      },
      shaper: shaperOf(r.shaper),
      users: arr(r.users).filter((u) => u && u.id),
      devices: arr(r.devices).filter((d) => d && d.mac).map((d) => Object.assign({}, d, { mac: String(d.mac).toLowerCase() })),
      usage: Object.assign({}, obj(r.usage)),
      live: Object.assign({}, obj(r.live)),
      online: Object.fromEntries(Object.entries(obj(r.online)).map(([mac, o]) => [String(mac).toLowerCase(), obj(o)])),
      deviceUsage: Object.fromEntries(Object.entries(obj(r.deviceUsage)).map(([mac, v]) => [String(mac).toLowerCase(), v])),
      platform: String(r.platform || ''),
      lanAddresses: arr(r.lanAddresses).filter((a) => typeof a === 'string' && a),
      hotspot: hotspotOf(r.hotspot),
      // whether geoip.dat / geosite.dat are there, when the payload says (absent: not known here)
      geo: typeof r.geo === 'boolean' ? r.geo : null,
      portal: portalOf(r.portal)
    };
  }
  /** The payload's `portal` (the router's sign-in page — router/index.js portalInfo): plain http addresses only, or null. */
  function portalOf(p) {
    const url = (v) => (typeof v === 'string' && /^http:\/\/[^\s"'<>]+$/.test(v) ? v : '');
    if (!p || typeof p !== 'object' || !url(p.url)) return null;
    return { url: url(p.url), nameUrl: url(p.nameUrl) };
  }
  /**
   * The payload's `shaper` (the router's — router/index.js shaperInfo): how it
   * limits speeds now ('tc' shaping, 'police' nft drops, 'off' nothing to do),
   * the OpenWrt packages smooth limits lack (plain names only: they go into a
   * command line to copy), the line it shares out, whether a priority can
   * apply each way (`prio`: false where the line's speed is not set), another
   * shaper on the interface (`busy`: SQM's root or ingress qdisc — the limits
   * fall back to policing) and its reason in a line (`why`, English: the log's
   * words). null elsewhere.
   */
  function shaperOf(s) {
    if (!s || typeof s !== 'object') return null;
    const mode = ['tc', 'police', 'off'].includes(s.mode) ? s.mode : 'off';
    const missing = arr(s.missing).filter((p) => typeof p === 'string' && /^[a-z0-9][a-z0-9._+-]*$/.test(p));
    const line = obj(s.line);
    const prio = s.prio && typeof s.prio === 'object' ? { down: s.prio.down !== false, up: s.prio.up !== false } : null;
    const busy = s.busy === 'root' || s.busy === 'ingress' ? s.busy : null;
    const why = typeof s.why === 'string' ? oneLine(s.why).slice(0, 200) : '';
    return { mode, missing, line: { down: Number(line.down) || 0, up: Number(line.up) || 0 }, prio, busy, why };
  }
  /** The payload's `hotspot` (a Windows desktop's — hotspot.js) as the card draws it, or null. */
  function hotspotOf(h) {
    if (!h || typeof h !== 'object') return null;
    const devices = arr(h.devices).filter((d) => d && typeof d.ip === 'string' && d.ip)
      .map((d) => ({ ip: d.ip, mac: String(d.mac || ''), seen: !!d.seen, open: Number(d.open) || 0, bytes: Number(d.bytes) || 0 }));
    return { on: !!h.on, tun: !!h.tun, error: String(h.error || ''), devices };
  }
  /** Take an answer that carries the payload; a bare `{ ok: true }` leaves the page as it is. */
  function take(res) {
    const r = obj(res);
    if (!('users' in r) && !('config' in r)) return false;
    ui.data = normalize(r);
    return true;
  }

  const cfg = () => (ui.data ? ui.data.config : clone(EMPTY));
  /** Every user record — the vouchers too (a username is unique among all of them). */
  const users = () => (ui.data ? ui.data.users : []);
  /** A voucher: a user record made from a code (model.js isVoucher) — the Vouchers tab's, never the Users list's. */
  const isVoucher = (u) => !!(u && u.voucher && typeof u.voucher === 'object');
  const people = () => users().filter((u) => !isVoucher(u));
  const vouchers = () => users().filter(isVoucher);
  const usageOf = (id) => (ui.data ? ui.data.usage[id] : null) || null;
  const liveOf = (id) => (ui.data ? ui.data.live[id] : null) || null;
  /** The router's page (the OpenWrt build: the same renderer) — the payload says so, or app.js does. */
  const isRouter = () => !!hook('router') || /^(openwrt|router)$/i.test(ui.data ? ui.data.platform : '');
  /** A Windows PC — its Mobile Hotspot note. */
  const isWin = () => !isRouter() && (hook('platform') === 'win32' || (ui.data && ui.data.platform === 'win32'));
  const nameOf = (u) => (u && (String(u.name || '').trim() || u.username)) || '';
  /** A user in a picker: «Sara · sara», or the username alone. */
  const pickLabel = (u) => (u.name && String(u.name).trim() && u.name !== u.username ? String(u.name).trim() + ' · ' + u.username : u.username);
  const initial = (u) => (Array.from(nameOf(u))[0] || '?').toUpperCase();

  /**
   * Whether a user can connect now: off, expired, outside their hours, over a
   * limit (all stopped), the VPN alone stopped ('novpn': direct routes still
   * work — the owner's choice), the direct routes alone ('nodirect'), or on.
   * The meter's hold says it (meter.js holdOf); an older service's `over` is
   * the one cap reached.
   */
  function stateOf(u, now = Date.now()) {
    if (!u.enabled) return 'off';
    if (Number(u.expiresAt) > 0 && Number(u.expiresAt) <= now) return 'expired';
    const us = usageOf(u.id);
    const hold = us && us.hold;
    if (hold === 'vpn') return 'novpn';
    if (hold === 'direct') return 'nodirect';
    if (hold === 'all') return us.why === 'schedule' ? 'schedule' : us.why === 'disabled' ? 'off' : us.why === 'expired' ? 'expired' : 'over';
    if (us && us.over) return 'over';
    return 'on';
  }
  /** Still connects, in part or in full: its box is not dimmed. */
  const connects = (st) => st === 'on' || st === 'novpn' || st === 'nodirect';

  /* ------------------------------ limits, meters, routing, hours, speed ------------------------------ */

  /**
   * A user's limits as the page edits them, in the grid's order: `limits`
   * (model.js, v1.39), or — a record saved before them — its one cap as a
   * Total limit (what normalizeLanUsers migrates it to).
   */
  function limitsOf(u) {
    const src = u && Array.isArray(u.limits) ? u.limits
      : (u && Number(u.quotaGb) > 0 ? [{ kind: 'total', period: LPERIODS.includes(u.quotaPeriod) ? u.quotaPeriod : 'month', gb: Number(u.quotaGb) }] : []);
    const ok = src.filter((l) => l && KINDS.includes(l.kind) && LPERIODS.includes(l.period) && Number(l.gb) > 0);
    const at = (l) => KINDS.indexOf(l.kind) * 3 + LPERIODS.indexOf(l.period);
    return ok.slice().sort((a, b) => at(a) - at(b));
  }
  const limitOf = (u, kind, period) => limitsOf(u).find((l) => l.kind === kind && l.period === period) || null;
  const meterOrder = (m) => KINDS.indexOf(m.kind) * 3 + LPERIODS.indexOf(m.period);

  /**
   * A user's meters: the payload's (meter.js usage().meters — each kind by the
   * day and by the month, and 'none' where a one-off limit is), or, from an
   * older service, one Total meter made of its single cap (`legacy`: its own
   * period key says which).
   */
  function metersOf(id) {
    const us = usageOf(id);
    if (us && Array.isArray(us.meters)) {
      return us.meters.filter((m) => m && KINDS.includes(m.kind) && LPERIODS.includes(m.period)).sort((a, b) => meterOrder(a) - meterOrder(b));
    }
    const key = String((us && us.period) || '');
    const cap = us ? Number(us.quotaBytes) || 0 : 0;
    // a day's key is 'YYYY-MM-DD'; a month's any other ('2026-10', 'j1405-08', '2026-10@15'); 'all' is neither
    const period = /^\d{4}-\d{2}-\d{2}$/.test(key) ? 'day' : key === 'all' ? 'none' : 'month';
    return [{ kind: 'total', period, key, bytes: us ? Number(us.bytes) || 0 : 0, capBytes: cap, extraBytes: 0, until: us ? Number(us.until) || 0 : 0, over: !!(us && us.over), legacy: true }];
  }
  /** "this month", "today", "one-off" — a meter's period in a line. */
  const periodWord = (p) => t(p === 'day' ? 'lu.today' : p === 'month' ? 'lu.thisMonth' : 'lu.oneOff');
  /** "VPN · today" */
  const meterLabel = (kind, period) => t('lu.kind.' + kind) + ' · ' + periodWord(period);

  /** The routing modes a user can have besides the app's profiles (model.js routing). */
  const ROUTE_RE = /^(?:|global|bypass-ir|profile:[\w-]+)$/;
  /** The app's routing profiles, as app.js hands them: [{ id, name }]. */
  const profiles = () => arr(hook('routingProfiles')).filter((p) => p && typeof p.id === 'string' && p.id).map((p) => ({ id: p.id, name: String(p.name || p.id) }));
  /** A user's routing in words, or '' for the plain one ('' and 'global': everything through the config). */
  function routeName(routing) {
    const r = String(routing || '');
    if (r === '' || r === 'global') return '';
    if (r === 'bypass-ir') return t('lu.route.bypassIr');
    if (r.startsWith('profile:')) {
      const p = profiles().find((x) => 'profile:' + x.id === r);
      return p ? p.name : '⚠ ' + t('lu.target.missing');
    }
    return r;
  }

  /** A week's days as a line: "every day", "Saturday to Wednesday", "Mon, Wed, Fri" — in the page's week order. */
  function daysText(days) {
    const set = new Set(arr(days).map(Number));
    const week = WEEK[lang() === 'fa' ? 'fa' : 'en'];
    if (week.every((d) => set.has(d))) return t('lu.everyDay');
    const runs = [];      // the picked days that follow each other in the week's order
    let run = null;
    for (const d of week) {
      if (!set.has(d)) { run = null; continue; }
      if (run) run.push(d); else runs.push(run = [d]);
    }
    const sep = lang() === 'fa' ? '، ' : ', ';
    return runs.map((r) => (r.length >= 3 ? fill(t('lu.dayRange'), { from: t('lu.wd.' + r[0]), to: t('lu.wd.' + r[r.length - 1]) })
      : r.map((d) => t('lu.wd.' + d)).join(sep))).join(sep);
  }
  /** A window's hours: '08:00–22:00', or "all day" when they meet. */
  const hoursText = (w) => (w.from === w.to ? t('lu.allDay') : w.from + '–' + w.to);

  /** The speed a user gets now (meter.js speedOf, the router's): '↓ 2 Mbps ↑ 1 Mbps' and why, or null. */
  function speedWords(sp, u) {
    if (!sp || typeof sp !== 'object' || !(Number(sp.down) > 0 || Number(sp.up) > 0)) return null;
    const rate = [Number(sp.down) > 0 ? '↓ ' + rateWord(sp.down) : '', Number(sp.up) > 0 ? '↑ ' + rateWord(sp.up) : ''].filter(Boolean).join(' ');
    // each reason: words, or a template and its values ("after {amount} {period}" — the amount left to right in Persian)
    const why = arr(sp.why).map((w) => {
      if (w === 'base') return t('lu.why.base');
      if (w === 'hours') return t('lu.why.hours');
      const m = /^after:(total|vpn|direct):(day|month|none)$/.exec(String(w));
      if (!m) return '';
      const l = limitOf(u, m[1], m[2]);
      const amount = ((l ? gbText(l.gb) + ' GB' : '') + (m[1] === 'total' ? '' : ' ' + t('lu.kind.' + m[1]))).trim();
      return { template: t('lu.why.after').replace(/\s*\{period\}/, m[2] === 'none' ? '' : ' {period}'), map: { amount, period: periodWord(m[2]) } };
    }).filter(Boolean);
    return { rate, why };
  }

  /* ------------------------------ the router's devices ------------------------------ */

  /** Every device the router knows or sees now: the stored ones and the online ones, online first, by name. */
  function deviceRows() {
    if (!ui.data) return [];
    const on = ui.data.online;
    const rows = new Map();
    for (const d of ui.data.devices) rows.set(d.mac, Object.assign({ name: '', userId: '', blocked: false }, d));
    for (const [mac, o] of Object.entries(on)) if (!rows.has(mac)) rows.set(mac, { mac, name: '', userId: o.userId || '', blocked: false });
    const label = (d) => String(d.name || (on[d.mac] && on[d.mac].hostname) || d.mac).toLowerCase();
    return [...rows.values()]
      .map((d) => Object.assign(d, { live: on[d.mac] || null, userId: d.userId || (on[d.mac] && on[d.mac].userId) || '' }))
      .sort((a, b) => (!!b.live - !!a.live) || label(a).localeCompare(label(b)));
  }
  /** A device's bytes, when the service counts them (transparent mode): deviceUsage[mac] or online[mac].bytes. */
  function deviceBytes(mac) {
    if (!ui.data) return null;
    const v = ui.data.deviceUsage[mac];
    if (v != null) return typeof v === 'object' ? Number(v.bytes) || 0 : Number(v) || 0;
    const o = ui.data.online[mac];
    return o && o.bytes != null ? Number(o.bytes) || 0 : null;
  }
  const onlineOf = (userId) => (ui.data ? Object.values(ui.data.online).filter((o) => o.userId === userId).length : 0);

  /* ------------------------------ the config picker ------------------------------ */

  /**
   * What a user can ride: the current connection, direct, blocked, then every
   * config the app's pickers offer (app.js configOptions: the hand-added ones,
   * each subscription by its name, the chains, the groups). One that is gone
   * stays in the list as gone, so the picker never shows a choice that is not
   * the saved one.
   */
  function targetOptions(current) {
    const out = [
      { value: '', label: t('lu.target.current') },
      { value: 'direct', label: t('lu.target.direct') },
      { value: 'block', label: t('lu.target.block') }
    ];
    for (const o of arr(hook('targets'))) if (o && o.value != null && !SPECIAL.includes(String(o.value))) out.push(o);
    if (current && !out.some((o) => o.value === current)) out.push({ value: current, label: '⚠ ' + t('lu.target.missing') });
    return out;
  }
  /** The app's own searchable picker (app.js makeSearchSelect) when it is there; else a <select> with a group per subscription. */
  function targetPicker(value, label, key, onChange) {
    const v = value || '';
    const options = targetOptions(v);
    const box = el('div', 'lu-target');
    box.dataset.lu = key;
    const picked = hook('picker', { options, value: v, onChange });
    if (picked) { box.append(picked); return box; }
    const s = el('select', 'select');
    s.setAttribute('aria-label', label);
    s.dataset.lu = key + ':select';
    const add = (parent, o) => {
      const opt = el('option', null, o.label);
      opt.value = String(o.value);
      if (String(o.value) === v) opt.selected = true;
      parent.appendChild(opt);
    };
    const groups = new Map();
    for (const o of options) {
      if (!o.pile) { add(s, o); continue; }
      let g = groups.get(o.pile.key);
      if (!g) {
        g = el('optgroup');
        g.label = (o.pile.ico ? o.pile.ico + ' ' : '') + o.pile.name;
        groups.set(o.pile.key, g);
        s.appendChild(g);
      }
      add(g, o);
    }
    s.value = v;
    s.addEventListener('change', () => onChange(s.value));
    box.append(s);
    return box;
  }

  /* ------------------------------ saving ------------------------------ */

  /** An answer that refuses: `{ ok: false, error }` is an error like a thrown one — its `detail` (which part) goes along. */
  function checkAnswer(res) {
    if (res && typeof res === 'object' && res.ok === false) {
      const e = new Error(res.error || res.code || 'refused');
      if (res.detail != null) e.detail = String(res.detail);
      throw e;
    }
  }
  /**
   * A refusal in words: a key the core answers ('usernameTaken', 'lu.err.password')
   * in the page's language — the one of its detail first where there is one
   * ('lu.err.filter.domain') — else as it came. An answer `{ ok: false, error,
   * detail }` reads as a thrown one.
   */
  function errText(e) {
    const msg = String((e && (e.message || e.error)) || (typeof e === 'string' ? e : '') || '');
    const detail = e && e.detail != null ? String(e.detail) : '';
    const keys = [];
    for (const k of [msg, 'lu.err.' + msg]) {
      if (detail && /^\w+$/.test(detail)) keys.push(k + '.' + detail);
      keys.push(k);
    }
    for (const k of keys) if (/^lu\.err\.\w+(?:\.\w+)?$/.test(k) && t(k) !== k) return t(k);
    return msg;
  }
  const errKey = (e) => {
    const msg = String((e && e.message) || e || '');
    return /^(?:lu\.err\.)?(\w+)$/.test(msg) ? msg.replace(/^lu\.err\./, '') : '';
  };

  /**
   * One change, through one of the four channels: drawn at once (`draft` edits
   * the page's copy), then the service's answer is the truth; a refusal says
   * why and the page goes back to what was saved.
   */
  async function call(fn, arg, draft) {
    if (!window.api || !window.api[fn]) return null;
    const prev = ui.data ? clone(ui.data) : null;
    if (draft && ui.data) { draft(ui.data); render(); }
    const seq = ++ui.seq;      // a read still on its way is older than this change: dropped
    ui.busy++;
    try {
      const res = await window.api[fn](arg);
      checkAnswer(res);
      if (seq === ui.seq && !take(res)) refresh();
      // the "reconnect to apply" question, when the running connection was built without this
      Promise.resolve(hook('applied', res)).catch(() => {});
      return res || {};
    } catch (e) {
      toast(t('lu.saveFailed') + ': ' + errText(e), 'err');
      if (prev && seq === ui.seq) ui.data = prev;
      return null;
    } finally {
      ui.busy--;
      render();
    }
  }

  /** A part of the settings: `{ proxy: { enabled } }`, `{ transparent: { unassigned } }`. */
  function saveConfig(partial) {
    return call('lanUsersConfig', partial, (d) => {
      for (const k of Object.keys(partial)) d.config[k] = Object.assign({}, d.config[k], partial[k]);
    });
  }
  /** One user changed: the whole user goes, as the service stores it. */
  function saveUser(id, patch) {
    const u = users().find((x) => x.id === id);
    if (!u) return null;
    const next = Object.assign({}, u, patch);
    return call('lanUsersUser', { op: 'update', user: next }, (d) => { d.users = d.users.map((x) => (x.id === id ? next : x)); });
  }
  async function removeUser(id) {
    const u = users().find((x) => x.id === id);
    if (!u) return false;
    const msg = fill(t('lu.confirmDelete'), { name: nameOf(u) });
    if (!(ui.hooks.confirm ? hook('confirm', msg) : window.confirm(msg))) return false;
    const res = await call('lanUsersUser', { op: 'delete', user: { id } }, (d) => {
      d.users = d.users.filter((x) => x.id !== id);
      for (const dev of d.devices) if (dev.userId === id) dev.userId = '';
    });
    if (res && ui.form && ui.form.id === id) closeDialog();
    return !!res;
  }
  /** A device's user, block or name: `{ mac, userId }`, `{ mac, blocked }`, `{ mac, name }`. */
  function setDevice(mac, patch) {
    return call('lanUsersDevice', Object.assign({ mac }, patch), (d) => {
      const dev = d.devices.find((x) => x.mac === mac);
      if (dev) Object.assign(dev, patch);
      else d.devices.push(Object.assign({ mac, name: '', userId: '', blocked: false }, patch));
    });
  }

  /** Ten characters from PASS_CHARS, from the platform's random source. */
  function genPassword() {
    const buf = new Uint32Array(PASS_LEN);
    const c = (typeof crypto !== 'undefined' && crypto && crypto.getRandomValues) ? crypto
      : (window.crypto && window.crypto.getRandomValues ? window.crypto : null);
    if (c) c.getRandomValues(buf);
    else for (let i = 0; i < PASS_LEN; i++) buf[i] = Math.floor(Math.random() * 4294967296);
    let out = '';
    for (let i = 0; i < PASS_LEN; i++) out += PASS_CHARS[buf[i] % PASS_CHARS.length];
    return out;
  }
  async function copy(text) {
    try {
      if (ui.hooks.copy) await ui.hooks.copy(text);
      else await navigator.clipboard.writeText(text);
      toast(t('lu.copied'), 'ok');
    } catch { toast(t('lu.copyFailed'), 'err'); }
  }
  /** A user's box: a new password, after asking — their devices sign in again with it. */
  function newPassword(id) {
    const u = users().find((x) => x.id === id);
    if (!u) return null;
    const msg = fill(t('lu.confirmGenerate'), { name: nameOf(u) });
    if (!(ui.hooks.confirm ? hook('confirm', msg) : window.confirm(msg))) return null;
    ui.shown[id] = true;    // the admin has to read it out: shown
    return saveUser(id, { password: genPassword() });
  }
  /** This period's usage of every kind back to nothing (and its top-ups gone), after asking; the 30 days stay (meter.js resetUsage). */
  async function resetUsage(id) {
    const u = users().find((x) => x.id === id);
    if (!u) return false;
    const msg = fill(t('lu.confirmReset'), { name: nameOf(u) });
    if (!(ui.hooks.confirm ? hook('confirm', msg) : window.confirm(msg))) return false;
    const res = await call('lanUsersUser', { op: 'resetUsage', user: { id } });
    if (res) toast(fill(t('lu.resetDone'), { name: nameOf(u) }), 'ok');
    return !!res;
  }
  /** A top-up request seen and let go without one (meter.js dismissRequest): its line goes at once. */
  async function dismissRequest(id) {
    const res = await call('lanUsersUser', { op: 'dismissRequest', user: { id } }, (d) => {
      if (d.usage[id]) d.usage[id] = Object.assign({}, d.usage[id], { request: null });
    });
    return !!res;
  }

  /**
   * Any channel of the module, for luVouchers.js and luReports.js (the kit's
   * invoke): the answer as it came — a refusal too, `{ ok: false, error,
   * detail }`, and a thrown error as one; the caller says a refusal in its own
   * place (a form's line, a toast), so nothing is said here unless asked
   * (`{ toast: true }`: "Not saved: …"). An answer carrying the payload is
   * the page's new truth and is drawn; a change that does not carry it reads
   * the page again; the "reconnect to apply" question goes to app.js as for
   * the page's own changes.
   */
  async function invoke(channel, payload, opts) {
    const fn = API[channel] || channel;
    const quiet = !(opts && opts.toast);
    if (!window.api || typeof window.api[fn] !== 'function') return { ok: false, error: 'unavailable' };
    const reads = fn === 'lanUsersGet' || fn === 'lanUsersBackup';
    const seq = reads ? ui.seq : ++ui.seq;     // a change makes a read on its way old
    if (!reads) ui.busy++;
    try {
      const res = await (payload === undefined ? window.api[fn]() : window.api[fn](payload));
      if (res && typeof res === 'object' && res.ok === false) {
        if (!quiet) toast(t(reads ? 'lu.loadFailed' : 'lu.saveFailed') + ': ' + errText(res), 'err');
        return res;
      }
      if (fn === 'lanUsersGet') { if (seq === ui.seq && take(res)) render(); }
      else if (!reads) {
        if (seq === ui.seq && !take(res)) refresh(); else render();
        Promise.resolve(hook('applied', res)).catch(() => {});
      }
      return res && typeof res === 'object' ? res : { ok: true, result: res };
    } catch (e) {
      if (!quiet) toast(t(reads ? 'lu.loadFailed' : 'lu.saveFailed') + ': ' + errText(e), 'err');
      return { ok: false, error: String((e && e.message) || e || 'failed') };
    } finally {
      if (!reads) ui.busy--;
    }
  }

  /* ------------------------------ reading ------------------------------ */

  /** What decides the page's layout — a read that changes none of it repaints the numbers in place. */
  function shape() {
    if (!ui.data) return '';
    const d = ui.data;
    const online = Object.entries(d.online).map(([mac, o]) => [mac, o.ip || '', o.hostname || '', o.userId || '']).sort();
    // a top-up request that came or went is a line of its own in the box
    const holds = d.users.map((u) => { const x = d.usage[u.id]; return x ? [!!x.over, x.hold || null, x.why || null, Number(x.holdUntil) || 0, x.request ? Number(x.request.at) || 1 : 0] : null; });
    return JSON.stringify([d.config, d.users, d.devices, d.platform, d.lanAddresses, d.portal, d.shaper, online, holds, d.users.map((u) => stateOf(u))]);
  }

  /**
   * Ask the service: the settings, the users, the devices, the usage. `quiet`
   * (a stats tick): no loading line, nothing over a save in flight, and when
   * nothing but numbers changed only the numbers are repainted — the controls
   * stay where the admin is.
   */
  async function refresh(opts) {
    if (!window.api || !window.api.lanUsersGet) return;
    const quiet = !!(opts && opts.quiet);
    if (quiet && ui.busy) return;
    const seq = ++ui.seq;
    ui.lastRefresh = Date.now();
    if (!quiet) { ui.loading = true; ui.error = ''; render(); }
    let same = false;
    try {
      const res = await window.api.lanUsersGet();
      if (seq !== ui.seq) return;
      checkAnswer(res);
      const before = shape();
      if (!take(res) && !ui.data) ui.data = normalize({});
      ui.error = '';
      same = quiet && before !== '' && before === shape();
    } catch (e) {
      if (seq !== ui.seq) return;
      if (quiet) return;      // the next tick asks again; the page stays as it was
      ui.error = (e && e.message) || String(e);
    }
    ui.loading = false;
    if (same) paintLive(); else render();
  }

  /* ------------------------------ drawing: numbers in place ------------------------------ */

  /** An SVG node and its attributes — its class too: an SVG element's className is not a string to set. */
  function svgEl(tag, attrs) {
    const n = document.createElementNS(SVG_NS, tag);
    for (const [k, v] of Object.entries(attrs || {})) n.setAttribute(k, String(v));
    return n;
  }
  const svgNum = (v) => String(Math.round(v * 100) / 100);

  /**
   * One limit: "VPN · today   0.4 GB / 1.0 GB", its bar (amber from 80 %,
   * red over it) and what is left — over it, when it comes back (a 'slow'
   * limit: until when it is slowed). A top-up for the period counts in the cap.
   */
  function meterRow(u, m) {
    const extra = Number(m.extraBytes) || 0;
    const cap = (Number(m.capBytes) || 0) + extra;
    const bytes = Number(m.bytes) || 0;
    const ratio = cap > 0 ? Math.min(1, bytes / cap) : 0;
    const over = !!m.over || ratio >= 1;
    const near = !over && ratio >= NEAR;
    const l = limitOf(u, m.kind, m.period);
    const label = meterLabel(m.kind, m.period);
    const row = el('div', 'lu-meter' + (over ? ' lu-m-over' : near ? ' lu-m-near' : ''));
    row.dataset.meter = m.kind + ':' + m.period;
    const top = el('div', 'lu-mline');
    top.append(el('span', 'lu-mlabel', label), ltr(el('span', 'lu-mnum', bytesText(bytes) + ' / ' + bytesText(cap))));
    const bar = el('div', 'lu-bar');
    bar.setAttribute('role', 'progressbar');
    bar.setAttribute('aria-valuemin', '0');
    bar.setAttribute('aria-valuemax', '100');
    bar.setAttribute('aria-valuenow', String(Math.round(ratio * 100)));
    bar.setAttribute('aria-label', label);
    const fillEl = el('i', over ? 'over' : near ? 'warn' : '');
    fillEl.style.width = (ratio * 100).toFixed(1) + '%';
    bar.append(fillEl);
    const until = Number(m.until) || 0;
    const left = bytesText(Math.max(0, cap - bytes));
    const [key, map] = over
      ? (l && l.action === 'slow' ? (until ? ['lu.slowUntil', { date: whenText(until) }] : ['lu.slowNow', {}])
        : (until ? ['lu.backOn', { date: whenText(until) }] : ['lu.usedUp', {}]))
      : (m.period === 'month' && until ? ['lu.leftUntil', { left, date: dateText(until) }] : ['lu.left', { left }]);
    const foot = el('div', 'lu-mfoot');
    foot.append(...tpl(t(key), map));
    if (extra > 0) foot.append(' · ' + t('lu.extra') + ' ', ltr(el('bdi', 'lu-extra', '+' + bytesText(extra))));
    row.append(top, bar, foot);
    return row;
  }
  /** An older service's user with no cap: what it carried, and in which period. */
  function legacyLine(m) {
    const q = el('div', 'lu-quota');
    const p = m.key;
    q.append(el('span', null, fill(t('lu.used'), { used: bytesText(m.bytes) })),
      el('span', null, /^\d{4}-\d{2}-\d{2}$/.test(p) ? t('lu.today') : p && p !== 'all' ? t('lu.thisMonth') : ''));
    return q;
  }
  /** No limit at all: today's and this month's VPN and direct, a line each. */
  function totalLines(meters) {
    const bytesOf = (k, p) => { const m = meters.find((x) => x.kind === k && x.period === p); return m ? Number(m.bytes) || 0 : 0; };
    return ['day', 'month'].map((p) => {
      const line = el('div', 'lu-tot');
      line.dataset.period = p;
      line.append(el('span', 'lu-totp', t('lu.tot.' + p)));
      for (const k of ['vpn', 'direct']) {
        const part = el('span', 'lu-totk', t('lu.kind.' + k) + ' ');
        part.append(ltr(el('bdi', null, bytesText(bytesOf(k, p)))));
        line.append(part);
      }
      return line;
    });
  }
  function meterNodes(u, meters) {
    const capped = meters.filter((m) => Number(m.capBytes) > 0);
    if (capped.length) return capped.map((m) => meterRow(u, m));
    if (meters.length === 1 && meters[0].legacy) return [legacyLine(meters[0])];
    return totalLines(meters);
  }
  /** The speed a user gets now, when there is a limit on it (the router's): "Speed ↓ 2 Mbps ↑ 1 Mbps · after 2 GB today". */
  function paintSpeed(n, us, u) {
    const w = speedWords(us && us.speed, u);
    n.hidden = !w;
    if (!w) { n.replaceChildren(); return; }
    n.replaceChildren(el('span', 'lu-speed-k', t('lu.speed')), ltr(el('bdi', 'lu-speed-rate', w.rate)));
    for (const why of w.why) n.append(' · ', ...(typeof why === 'string' ? [why] : tpl(why.template, why.map)));
  }

  /**
   * The last 30 days (meter.js history: { day, vpn, direct }, oldest first): a
   * bar a day, VPN under direct, each with its numbers in its <title>. Time
   * runs left to right, as the numbers in it do, up to today or the last day
   * the service counted, whichever is later — the router's clock and this
   * browser's may be a day apart. Hidden with nothing to show.
   */
  function paintChart(box, us) {
    const days = arr(us && us.history).filter((h) => h && Number.isFinite(dayNumber(h.day)))
      .map((h) => ({ day: h.day, n: dayNumber(h.day), vpn: Math.max(0, Number(h.vpn) || 0), direct: Math.max(0, Number(h.direct) || 0) }));
    const end = Math.max(dayNumber(dayInput(Date.now())), ...days.map((d) => d.n));
    const shown = days.filter((d) => d.n > end - CHART_DAYS && d.n <= end && d.vpn + d.direct > 0);
    box.hidden = !shown.length;
    if (!shown.length) { box.replaceChildren(); return; }
    const W = 10;           // a day's slot in the view box; its bar is BAR of it
    const BAR = 7;
    const H = 40;
    const max = Math.max(...shown.map((d) => d.vpn + d.direct));
    const sum = (k) => shown.reduce((a, d) => a + d[k], 0);
    const svg = svgEl('svg', { class: 'lu-chart', viewBox: '0 0 ' + CHART_DAYS * W + ' ' + H, preserveAspectRatio: 'none', role: 'img',
      'aria-label': fill(t('lu.chartAria'), { vpn: bytesText(sum('vpn')), direct: bytesText(sum('direct')) }) });
    svg.appendChild(svgEl('line', { class: 'lu-cbase', x1: 0, y1: H - 0.5, x2: CHART_DAYS * W, y2: H - 0.5 }));
    for (const d of shown) {
      const slot = (CHART_DAYS - 1 - (end - d.n)) * W;
      const g = svgEl('g', { class: 'lu-cbar', 'data-day': d.day });
      const title = svgEl('title');
      const [y, mo, da] = d.day.split('-').map(Number);
      title.textContent = fill(t('lu.chartBar'), { date: dateText(new Date(y, mo - 1, da).getTime()), vpn: bytesText(d.vpn), direct: bytesText(d.direct) });
      // the whole slot answers the pointer: a short bar is still easy to point at
      g.append(title, svgEl('rect', { class: 'lu-chit', x: slot, y: 0, width: W, height: H }));
      let top = H - 1;
      for (const k of ['vpn', 'direct']) {
        if (!(d[k] > 0)) continue;
        const h = Math.max(1, d[k] / max * (H - 2));
        top -= h;
        g.appendChild(svgEl('rect', { class: k === 'vpn' ? 'lu-cvpn' : 'lu-cdirect', x: svgNum(slot + (W - BAR) / 2), y: svgNum(top), width: BAR, height: svgNum(h) }));
      }
      svg.appendChild(g);
    }
    const head = el('div', 'lu-chead');
    head.append(el('span', 'lu-ctitle', t('lu.chart')));
    for (const k of ['vpn', 'direct']) {
      const key = el('span', 'lu-ckey');
      const sw = el('i', 'lu-csw');
      sw.classList.add('lu-csw-' + k);
      sw.setAttribute('aria-hidden', 'true');
      key.append(sw, t('lu.kind.' + k) + ' ', ltr(el('bdi', null, bytesText(sum(k)))));
      head.append(key);
    }
    box.replaceChildren(head, svg);
  }

  /** A user's meters, the speed they get, their 30 days and (open) 12 months — a stats tick repaints them, the controls stay put. */
  function paintUsage(d, id) {
    d.meters.replaceChildren(...meterNodes(d.user, metersOf(id)));
    paintSpeed(d.speed, usageOf(id), d.user);
    paintChart(d.chart, usageOf(id));
    if (d.months) paintMonths(d.months, d.user);
  }
  /** A live rate, while connected: '↓ 1.2 MB/s  ↑ 40.0 KB/s'. */
  function rateLine(l) {
    if (!l || !(Number(l.down) > 0 || Number(l.up) > 0)) return '';
    return '↓ ' + rateText(l.down) + '  ↑ ' + rateText(l.up);
  }
  function paintRate(span, id) {
    const line = connected() ? rateLine(liveOf(id)) : '';
    span.textContent = line;
    span.hidden = !line;
  }
  /** A device's bytes and, while connected, its rate — a line each. */
  function paintDevUse(d, mac) {
    const bytes = deviceBytes(mac);
    const line = connected() ? rateLine(ui.data && ui.data.online[mac]) : '';
    d.bytes.textContent = bytes != null ? bytesText(bytes) : '';
    d.bytes.hidden = bytes == null;
    d.rate.textContent = line;
    d.rate.hidden = !line;
  }
  function paintLive() {
    if (!ui.host || !ui.data) return;
    for (const [id, d] of Object.entries(ui.dom.usage)) paintUsage(d, id);
    for (const [id, span] of Object.entries(ui.dom.rates)) paintRate(span, id);
    for (const [mac, d] of Object.entries(ui.dom.devUse)) paintDevUse(d, mac);
  }

  /* ------------------------------ drawing: the settings card ------------------------------ */

  function portInput(value, which) {
    const n = numInput(value || '', t(which === 'port' ? 'lu.socksPort' : 'lu.httpPort'), which, { min: '1' });
    n.max = '65535';
    n.addEventListener('change', () => {
      const p = cfg().proxy;
      const v = Number(n.value);
      const other = which === 'port' ? p.httpPort : p.port;
      if (!Number.isInteger(v) || v < 1 || v > 65535 || v === Number(other)) {
        toast(t('lu.err.port'), 'err');
        n.value = String(p[which] || '');
        return;
      }
      if (v !== Number(p[which])) saveConfig({ proxy: { [which]: v } });
    });
    return n;
  }

  /** The address to give people: a line per LAN address and protocol, each copied with one click. */
  function addressBox(c) {
    const box = el('div', 'lu-addr');
    box.append(el('div', 'field-label', t('lu.address')));
    const ips = ui.data ? ui.data.lanAddresses : [];
    if (!ips.length) {
      box.append(el('p', 'hint warn', ui.data ? t('lu.noAddress') : t('lu.loading')));
      return box;
    }
    for (const ip of ips) {
      for (const [proto, port] of [['SOCKS5', c.proxy.port], ['HTTP', c.proxy.httpPort]]) {
        if (!port) continue;
        const text = hostPort(ip, port);
        const row = el('div', 'lu-addr-row');
        const value = ltr(el('span', 'lu-mono', text));
        value.dataset.addr = proto;
        const b = button('btn ghost small lu-copy', t('lu.copy'));
        b.setAttribute('aria-label', t('lu.copy') + ' — ' + proto + ' ' + text);
        b.dataset.lu = 'copy:' + proto + ':' + ip;
        b.addEventListener('click', () => copy(text));
        row.append(el('span', 'lu-proto', proto), value);
        // which of a Windows PC's addresses is its hotspot's: the one the phones on it use
        if (isWin() && ip === HOTSPOT_IP) row.append(el('span', 'lu-tag lu-hs', t('lu.hotspotTag')));
        row.append(b);
        box.append(row);
      }
    }
    return box;
  }

  /**
   * Where the router's sign-in page is (login mode): its short name and its
   * address, each copied with one click, the QR of the first and a sheet to
   * print for the wall. A device that is signed in is no longer sent there by
   * itself, and the phone whose own check does not open it needs the address.
   */
  function portalBox() {
    const p = ui.data ? ui.data.portal : null;
    const box = el('div', 'lu-addr lu-portal');
    box.append(el('div', 'field-label', t('lu.portalAt')));
    if (!p) {
      box.append(el('p', 'hint', t('lu.portalDown')), portalSettings());
      return box;
    }
    const urls = [p.nameUrl, p.url].filter(Boolean);
    for (const u of urls) {
      const row = el('div', 'lu-addr-row');
      const value = ltr(el('span', 'lu-mono', u));
      value.dataset.portal = u === p.nameUrl ? 'name' : 'address';
      const b = button('btn ghost small lu-copy', t('lu.copy'));
      b.setAttribute('aria-label', t('lu.copy') + ' — ' + u);
      b.dataset.lu = 'copy:portal:' + value.dataset.portal;
      b.addEventListener('click', () => copy(u));
      row.append(value, b);
      box.append(row);
    }
    if (p.nameUrl) box.append(el('p', 'hint', t('lu.portalNameHint')));
    const foot = el('div', 'lu-portal-foot');
    const img = qrImage(urls[0], t('lu.portalQr'));
    if (img) {
      const plate = el('div', 'qr-image lu-portal-qr');
      plate.append(img);
      foot.append(plate);
    }
    const print = button('btn small', t('lu.portalPrint'));
    print.dataset.lu = 'portalPrint';
    print.addEventListener('click', () => printPortal(p));
    foot.append(print);
    box.append(foot, portalSettings());
    return box;
  }

  /** One line of words as the model keeps it (config.portal): no control characters, no line breaks, trimmed. */
  const oneLine = (v) => String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f]+/g, ' ').replace(/\s{2,}/g, ' ').trim();

  /**
   * What a signed-in user's status page says besides their own numbers
   * (config.portal): a note to everyone ("top-ups at the month's end"), how to
   * reach the admin (a phone number is a link to call there), and whether the
   * page has a "request a top-up" button — a request shows on the user's box
   * here. Saved as each box is left; the page is down or up, the words stay.
   */
  function portalSettings() {
    const p = cfg().portal;
    const box = el('div', 'lu-ptset');
    box.append(el('div', 'lu-boxtitle', t('lu.pt.title')));
    const grid = el('div', 'lu-ptgrid');
    const line = (key, value, label, max, placeholder) => {
      const n = el('input', 'input');
      n.type = 'text';
      n.value = String(value || '');
      n.maxLength = max;
      n.placeholder = placeholder;
      n.setAttribute('aria-label', label);
      n.setAttribute('dir', 'auto');
      n.dataset.lu = key;
      n.addEventListener('change', () => {
        const v = oneLine(n.value);
        if (v.length > max) { toast(t('lu.err.portal'), 'err'); n.value = String(value || ''); return; }
        if (v !== String(value || '')) saveConfig({ portal: { [key === 'ptNote' ? 'note' : 'contact']: v } });
      });
      return n;
    };
    grid.append(field(t('lu.pt.note'), line('ptNote', p.note, t('lu.pt.note'), NOTE_MAX, t('lu.pt.notePh'))),
      field(t('lu.pt.contact'), line('ptContact', p.contact, t('lu.pt.contact'), CONTACT_MAX, t('lu.pt.contactPh'))));
    box.append(grid, switchRow(t('lu.pt.requests'), t('lu.pt.requestsSub'), p.requests !== false, 'ptRequests', (on) => saveConfig({ portal: { requests: on } })));
    return box;
  }

  /** The OpenWrt command that installs what smooth limits lack (the shaper's `missing`): copied, never run by the app. */
  const opkgLine = (missing) => 'opkg update && opkg install ' + missing.join(' ');

  /**
   * The router's speed shaping (config.shaping, router/shaper.js): the line's
   * real speed — what the priorities share out (empty: they cannot apply) —
   * smooth limits on or off, and what the router does now in words: shaping
   * with tc, policing with nft drops (by choice, or for want of the packages:
   * then the command that installs them, to copy into its shell), or nothing.
   */
  function shapingBox() {
    const s = cfg().shaping;
    const info = ui.data ? ui.data.shaper : null;
    const box = el('div', 'lu-addr lu-shaping');
    box.append(el('div', 'field-label', t('lu.shp.title')));
    const grid = el('div', 'lu-grid');
    for (const [k, word, arrow] of [['down', 'lu.shp.down', '↓'], ['up', 'lu.shp.up', '↑']]) {
      const n = numInput(mbpsText(s[k]), t(word), 'shp:' + k, { step: 'any', placeholder: '—' });
      n.addEventListener('change', () => {
        const raw = String(n.value).trim();
        const v = raw === '' || Number(raw) === 0 ? 0 : kbpsBox(raw);
        if (v === null) { toast(t('lu.err.shaping'), 'err'); n.value = mbpsText(s[k]); return; }
        if (v !== (Number(s[k]) || 0)) saveConfig({ shaping: { [k]: v } });
      });
      grid.append(field(t(word), arrowed(arrow, n)));
    }
    box.append(grid, el('div', 'lu-sub', t('lu.shp.lineHint')),
      switchRow(t('lu.shp.smooth'), t('lu.shp.smoothSub'), s.smooth !== false, 'shpSmooth', (on) => saveConfig({ shaping: { smooth: on } })));
    const now = el('div', 'lu-shpnow');
    now.setAttribute('role', 'status');
    const dot = el('span', 'lu-dot' + (info && info.mode === 'tc' ? ' on' : info && info.mode === 'police' ? ' lu-dot-warn' : ''));
    dot.setAttribute('aria-hidden', 'true');
    now.dataset.mode = info ? info.mode : '';
    now.append(dot, el('span', null, t(info ? 'lu.shp.mode.' + info.mode : 'lu.shp.unknown')));
    // the shaper's own reason, in its (English) words: the detail behind the line above
    if (info && info.why) now.title = info.why;
    box.append(now);
    if (info && info.why) {
      // on the page's side, as the line above it; isolated, so its own punctuation stays its own
      const why = el('div', 'lu-sub lu-shpwhy');
      why.append(el('bdi', null, info.why));
      box.append(why);
    }
    // another shaper owns the interface (OpenWrt's SQM, say): this one stays out of its way and polices
    if (info && info.busy) box.append(el('div', 'lu-sub lu-bad lu-shpbusy', t('lu.shp.busy')));
    // shaping, but a direction without the line's speed: no priority there
    if (info && info.mode === 'tc' && info.prio && (!info.prio.down || !info.prio.up)) {
      const which = !info.prio.down && !info.prio.up ? 'both' : !info.prio.down ? 'down' : 'up';
      box.append(el('div', 'lu-sub lu-bad lu-shpprio', fill(t('lu.shp.noPrio'), { which: t('lu.shp.which.' + which) })));
    }
    if (info && s.smooth !== false && info.missing.length) {
      const cmd = opkgLine(info.missing);
      const row = el('div', 'lu-addr-row lu-cmd');
      const code = ltr(el('code', 'lu-mono lu-cmdline', cmd));
      const b = button('btn ghost small lu-copy', t('lu.copy'));
      b.setAttribute('aria-label', t('lu.copy') + ' — ' + cmd);
      b.dataset.lu = 'copy:opkg';
      b.addEventListener('click', () => copy(cmd));
      row.append(code, b);
      box.append(el('div', 'lu-sub', t('lu.shp.missing')), row);
    }
    return box;
  }

  /** The wall sheet: the same words as the sign-in page — Persian, English under it — whatever the window's language. */
  const SHEET = [
    ['ورود به اینترنت', 'Sign in to use the internet'],
    ['۱. به وای‌فای وصل شوید.', '1. Join the Wi-Fi.'],
    ['۲. صفحهٔ ورود معمولاً خودش باز می‌شود؛ اگر نشد، این کد را اسکن کنید یا این نشانی را باز کنید:', '2. The sign-in page usually opens by itself; if not, scan this code or open:'],
    ['۳. نام کاربری و رمزی را که مدیر شبکه به شما داده وارد کنید.', '3. Enter the username and password the network’s admin gave you.']
  ];

  /** A line of a sheet: its Persian words, the English under them in a smaller line. */
  function sheetLine(tag, pair, className) {
    const n = el(tag, 'lu-ps-line' + (className ? ' ' + className : ''), pair[0]);
    n.append(ltr(el('span', 'lu-ps-en', pair[1])));
    return n;
  }

  /** Print the wall sheet: put in the page for the print alone (styles.css hides the rest), gone after. */
  function printPortal(p) {
    if (typeof window.print !== 'function') return false;
    const urls = [p.nameUrl, p.url].filter(Boolean);
    const sheet = el('div', 'lu-printsheet');
    sheet.setAttribute('dir', 'rtl');
    sheet.append(sheetLine('h1', SHEET[0]), sheetLine('p', SHEET[1]), sheetLine('p', SHEET[2]));
    const img = qrImage(urls[0], SHEET[0][1]);
    if (img) { img.className = 'lu-ps-qr'; sheet.append(img); }
    for (const u of urls) sheet.append(ltr(el('div', 'lu-ps-url', u)));
    sheet.append(sheetLine('p', SHEET[3]));
    return printSheet(sheet);
  }

  /**
   * Print one sheet (a `.lu-printsheet` node — the wall sheet, a sign-in card,
   * luVouchers.js's cards, luReports.js's statement): in the page for the print
   * alone (settings.css hides the rest, styles.css makes the paper white), gone
   * after. A browser that never says "afterprint" leaves it hidden (it is
   * screen-hidden) until a minute on. → false where nothing prints.
   */
  function printSheet(sheet) {
    if (typeof window.print !== 'function' || !sheet) return false;
    if (sheet.classList && !sheet.classList.contains('lu-printsheet')) sheet.classList.add('lu-printsheet');
    const root = document.documentElement;
    let timer = null;
    const done = () => {
      root.classList.remove('lu-printing');
      if (sheet.parentNode) sheet.parentNode.removeChild(sheet);
      window.removeEventListener('afterprint', done);
      if (timer != null) { clearTimeout(timer); timer = null; }
    };
    document.body.appendChild(sheet);
    root.classList.add('lu-printing');
    window.addEventListener('afterprint', done);
    try { window.print(); } finally {
      if (sheet.parentNode) {
        timer = setTimeout(done, 60000);
        // a timer of its own keeps nothing alive (node's test runner; a browser's is a number)
        if (timer && typeof timer.unref === 'function') timer.unref();
      }
    }
    return true;
  }

  function settingsCard() {
    const c = cfg();
    const router = isRouter();
    const card = el('div', 'card lu-card lu-settings');

    card.append(switchRow(t('lu.proxy'), t('lu.proxySub'), c.proxy.enabled, 'proxy', (on) => saveConfig({ proxy: { enabled: on } })));
    const body = el('div', 'lu-body');
    body.hidden = !c.proxy.enabled;
    const ports = el('div', 'lu-grid');
    ports.append(field(t('lu.socksPort'), portInput(c.proxy.port, 'port')), field(t('lu.httpPort'), portInput(c.proxy.httpPort, 'httpPort')));
    body.append(ports, addressBox(c));
    // the accounts are inbounds of the running core: none while disconnected
    if (!connected()) body.append(el('p', 'hint lu-hint', t('lu.whileConnected')));
    card.append(body);

    if (router) {
      card.append(switchRow(t('lu.transparent'), t('lu.transparentSub'), c.transparent.enabled, 'transparent', (on) => saveConfig({ transparent: { enabled: on } })));
      const tb = el('div', 'lu-body');
      tb.hidden = !c.transparent.enabled;
      const grid = el('div', 'lu-grid');
      const policy = UNASSIGNED.includes(c.transparent.unassigned) ? c.transparent.unassigned : 'login';
      const hours = numInput(c.transparent.sessionHours || '', t('lu.sessionHours'), 'sessionHours', { min: '1' });
      hours.addEventListener('change', () => {
        const v = Number(hours.value);
        if (!Number.isInteger(v) || v < 1 || v > 8760) {
          toast(t('lu.err.hours'), 'err');
          hours.value = String(c.transparent.sessionHours || '');
          return;
        }
        saveConfig({ transparent: { sessionHours: v } });
      });
      grid.append(field(t('lu.unassigned'), select(UNASSIGNED.map((p) => [p, t('lu.unassigned.' + p)]), policy, t('lu.unassigned'), 'unassigned', (v) => saveConfig({ transparent: { unassigned: v } }))));
      // a sign-in only lasts where there is one
      if (policy === 'login') grid.append(field(t('lu.sessionHours'), hours));
      tb.append(grid, el('p', 'hint lu-hint', t('lu.unassignedHint.' + policy)));
      if (policy === 'login') tb.append(portalBox());
      // the speeds and priorities are the transparent mode's, whatever the policy for nobody's devices
      tb.append(shapingBox());
      card.append(tb);
    } else {
      // a Windows PC's hotspot is the usual way a desktop shares: the same proxy, the same accounts
      card.append(el('p', 'lu-note' + (isWin() ? ' lu-hotspot' : ''), t(isWin() ? 'lu.hotspot' : 'lu.desktopNote')));
      // the hotspot's address is not there: it is off, and the phones meant to join it see no network
      if (isWin() && ui.data && c.proxy.enabled && !ui.data.lanAddresses.includes(HOTSPOT_IP)) {
        card.append(el('p', 'hint lu-hint', t('lu.hotspotOff')));
      }
    }
    return card;
  }

  /**
   * Users are there, and no way for any of them in: the proxy is off (and on
   * the router the transparent mode too). The owner made a user, gave the
   * phone the password — and nothing listened; the switch sat at the top,
   * off, with nothing saying it mattered. Said above everything, with the
   * switch's own action beside it.
   */
  function noWayIn() {
    const c = cfg();
    if (!ui.data || !users().length || c.proxy.enabled || (isRouter() && c.transparent.enabled)) return null;
    const box = el('div', 'lu-alert');
    box.setAttribute('role', 'status');
    const on = button('btn primary small', t('lu.turnOn'));
    on.dataset.lu = 'turnon';
    on.addEventListener('click', () => saveConfig({ proxy: { enabled: true } }));
    box.append(el('span', 'lu-alert-text', t(isRouter() ? 'lu.noWayInRouter' : 'lu.noWayIn')), on);
    return box;
  }

  /* ------------------------------ drawing: the users ------------------------------ */

  /** The day a month renews on as a number 1–31 (1: the 1st, every cap before there was a choice). */
  const dayOf = (v) => (DAYS.includes(Number(v)) ? Number(v) : 1);
  /** The two months a limit can follow (quotaCalendar), the page's own calendar first. */
  const calendarChoices = () => (lang() === 'fa' ? ['jalali', 'gregorian'] : ['gregorian', 'jalali']);

  /**
   * A user's usage in their box: a bar per limit, else the totals; the speed
   * they get now; Top up (a limit to top up) and Reset. The limits themselves
   * are the dialog's (✎): a grid of nine has no room in a box this size.
   */
  function usageControls(u, label) {
    const box = el('div', 'lu-field');
    const d = { user: u, meters: el('div', 'lu-meters'), speed: el('div', 'lu-speed'), chart: el('div', 'lu-hist') };
    d.chart.dataset.chart = u.id;
    ui.dom.usage[u.id] = d;
    paintUsage(d, u.id);
    const acts = el('div', 'lu-useacts');
    if (limitsOf(u).length) {
      const up = button('btn ghost small', t('lu.topUp'));
      up.dataset.lu = 'topup:' + u.id;
      up.setAttribute('aria-label', t('lu.topUp') + ' — ' + label);
      up.addEventListener('click', () => openTopUp(u.id));
      acts.append(up);
    }
    const reset = button('btn ghost small', t('lu.reset'));
    reset.dataset.lu = 'reset:' + u.id;
    reset.setAttribute('aria-label', t('lu.reset') + ' — ' + label);
    reset.addEventListener('click', () => resetUsage(u.id));
    acts.append(reset);
    box.append(el('div', 'field-label', t('lu.usage')), d.meters, d.speed, acts);
    return { box, chart: d.chart };
  }

  /** The state's pill, with when it lifts (the meter's holdUntil) and, for a hold of its own, what it means. */
  function stateBadge(u, st) {
    const b = el('span', 'lu-state lu-s-' + st, t('lu.state.' + st));
    const us = usageOf(u.id);
    const until = us && us.hold && Number(us.holdUntil) > 0 ? Number(us.holdUntil) : 0;
    if (until && !['on', 'off', 'expired'].includes(st)) {
      const when = el('span', 'lu-until', ' · ');
      when.append(...tpl(t('lu.backOn'), { date: whenText(until) }));
      b.append(when);
    }
    if (st === 'novpn' || st === 'nodirect' || st === 'schedule') b.title = t('lu.stateHint.' + st);
    return b;
  }

  /** The expiry: a date box, its day in words (the Persian calendar in Persian), and a way back to never. */
  function expiryWords(ms) {
    if (!(Number(ms) > 0)) return { text: t('lu.never'), bad: false };
    const date = fullDate(ms);
    return Number(ms) <= Date.now() ? { text: fill(t('lu.expiredOn'), { date }), bad: true } : { text: fill(t('lu.expiresOn'), { date }), bad: false };
  }
  const SOON_DAYS = 3;                            // from here the days left are said in the warning ink
  /**
   * How long until an expiry, in days of the calendar (an expiry is the end of
   * its day): '12 days left', '1 day left', 'ends today' — and whether that is
   * soon; null when there is none or it is past.
   */
  function daysLeft(ms, now = Date.now()) {
    if (!(Number(ms) > now)) return null;
    const n = dayNumber(dayInput(ms)) - dayNumber(dayInput(now));
    const text = n <= 0 ? t('lu.endsToday') : n === 1 ? t('lu.dayLeft') : fill(t('lu.daysLeft'), { n: String(n) });
    return { n, text, soon: n <= SOON_DAYS };
  }
  function expiryControls(u, label) {
    const line = el('div', 'lu-exp');
    const date = ltr(el('input', 'input lu-date'));
    date.type = 'date';
    date.value = dayInput(u.expiresAt);
    date.setAttribute('aria-label', t('lu.expires') + ' — ' + label);
    date.dataset.lu = 'expires:' + u.id;
    date.addEventListener('change', () => saveUser(u.id, { expiresAt: fromDayInput(date.value) }));
    line.append(date);
    if (Number(u.expiresAt) > 0) line.append(iconButton('×', t('lu.clearDate') + ' — ' + label, 'noexpiry:' + u.id, () => saveUser(u.id, { expiresAt: 0 })));
    const w = expiryWords(u.expiresAt);
    const words = el('div', 'lu-sub' + (w.bad ? ' lu-bad' : ''), w.text);
    // how many days that is, at a glance — in the warning ink once it is close
    const left = daysLeft(u.expiresAt);
    if (left) words.append(' · ', el('span', 'lu-left' + (left.soon ? ' lu-soon' : ''), left.text));
    // and when, within that, they may connect: their allowed hours
    const s = u.schedule && typeof u.schedule === 'object' ? u.schedule : null;
    const hours = s ? el('div', 'lu-sub lu-hours', fill(t('lu.hoursLine'), { days: daysText(s.days) }) + ' ') : null;
    if (hours) hours.append(ltr(el('bdi', null, hoursText(s))));
    return field(t('lu.expires'), line, words, hours);
  }

  /** "Adult, Gambling · safe search · 3 domains": a user's content filter in a line, or '' with none. */
  function filterWords(f) {
    if (!f || typeof f !== 'object') return '';
    const sep = lang() === 'fa' ? '، ' : ', ';
    const cats = FILTER_CATS.filter((c) => arr(f.block).includes(c)).map((c) => t('lu.flt.' + c)).join(sep);
    const n = arr(f.domains).length;
    return [cats, f.safeSearch ? t('lu.tag.safe') : '', n ? fill(t('lu.tag.domains'), { n: String(n) }) : ''].filter(Boolean).join(' · ');
  }

  /**
   * Under the name, what the box does not say elsewhere: the content filter,
   * on the router the priority (when it is not the usual one) and "remembers
   * devices" (with how many a sign-in gave them). null with none of them.
   */
  function tagsLine(u, router) {
    const tags = [];
    const fw = filterWords(u.filter);
    if (fw) tags.push(['lu-chip lu-chip-filter', '🛡 ' + fill(t('lu.tag.filter'), { what: fw })]);
    if (router && PRIORITIES.includes(u.priority) && u.priority !== 'normal') {
      tags.push(['lu-chip lu-chip-prio lu-prio-' + u.priority, (u.priority === 'high' ? '▲ ' : '▼ ') + fill(t('lu.tag.prio'), { p: t('lu.prio.' + u.priority) })]);
    }
    if (router && u.remember && !isVoucher(u)) {
      const n = ui.data ? ui.data.devices.filter((d) => d.userId === u.id && d.remembered).length : 0;
      tags.push(['lu-chip lu-chip-rem', '🔑 ' + t('lu.tag.remember') + (n ? ' · ' + n : '')]);
    }
    if (!tags.length) return null;
    const line = el('div', 'lu-tags');
    for (const [cls, text] of tags) line.append(el('span', cls, text));
    return line;
  }

  /**
   * A top-up the user asked for on the router's status page (meter.js request):
   * when, and the two answers — Top up (a limit to top up; it clears the
   * request) or Dismiss.
   */
  function requestLine(u, label) {
    const us = usageOf(u.id);
    const r = us && us.request && typeof us.request === 'object' ? us.request : null;
    if (!r) return null;
    const line = el('div', 'lu-req');
    line.setAttribute('role', 'status');
    const ico = el('span', 'lu-req-ico', '🔔');
    ico.setAttribute('aria-hidden', 'true');
    const words = el('span', 'lu-req-text');
    words.append(...tpl(t('lu.req'), { when: Number(r.at) > 0 ? whenText(r.at) : '' }));
    line.append(ico, words);
    if (limitsOf(u).length) {
      const up = button('btn primary small', t('lu.topUp'));
      up.dataset.lu = 'reqtopup:' + u.id;
      up.setAttribute('aria-label', t('lu.topUp') + ' — ' + label);
      up.addEventListener('click', () => openTopUp(u.id));
      line.append(up);
    }
    const no = button('btn ghost small', t('lu.reqDismiss'));
    no.dataset.lu = 'dismiss:' + u.id;
    no.setAttribute('aria-label', t('lu.reqDismiss') + ' — ' + label);
    no.addEventListener('click', () => dismissRequest(u.id));
    line.append(no);
    return line;
  }

  /** luReports.js, when the page has it (U2's): its functions, each called inside a try — a fault of its own never breaks the page. */
  const reports = () => (typeof window.LuReports === 'object' && window.LuReports ? window.LuReports : null);
  function tryReport(name, ...args) {
    const r = reports();
    if (!r || typeof r[name] !== 'function') return undefined;
    try { return r[name](...args); } catch (e) { if (typeof console !== 'undefined') console.error('LuReports.' + name, e); return undefined; }
  }
  /** A month of the user's (usage().months: { key, from, to }) in a picker: '23 Oct – 21 Nov 2026'. */
  const monthRange = (m) => format(m.from, { month: 'short', day: 'numeric' }) + ' – ' + format(Math.max(Number(m.from), Number(m.to) - 1), { year: 'numeric', month: 'short', day: 'numeric' });

  /**
   * luReports.js on a user's box: the 12 months behind a toggle (its chart
   * under the 30 days, drawn again with each tick while open), the CSV of the
   * months and days, and a month's statement to print. Nothing without it.
   */
  function reportsRow(u, label) {
    const r = reports();
    if (!r) return null;
    const box = el('div', 'lu-reps');
    const row = el('div', 'lu-reps-row');
    const area = el('div', 'lu-months');
    area.dataset.months = u.id;
    const open = !!ui.months[u.id];
    area.hidden = !open;
    if (typeof r.monthsChart === 'function') {
      const tog = button('btn ghost small', '📊 ' + t('lu.ux.months'));
      tog.dataset.lu = 'months:' + u.id;
      tog.setAttribute('aria-expanded', String(open));
      tog.setAttribute('aria-label', t('lu.ux.months') + ' — ' + label);
      tog.addEventListener('click', () => {
        ui.months[u.id] = !ui.months[u.id];
        tog.setAttribute('aria-expanded', String(!!ui.months[u.id]));
        area.hidden = !ui.months[u.id];
        paintMonths(area, u);
      });
      row.append(tog);
    }
    if (typeof r.csv === 'function') {
      const csv = button('btn ghost small', '⤓ ' + t('lu.ux.csv'));
      csv.dataset.lu = 'csv:' + u.id;
      csv.setAttribute('aria-label', t('lu.ux.csv') + ' — ' + label);
      csv.addEventListener('click', () => tryReport('csv', u));
      row.append(csv);
    }
    if (typeof r.printBill === 'function') {
      // the months to pick from, newest first: luReports.js's own (their names in the user's calendar), else the usage's
      const listed = arr(tryReport('monthList', u, usageOf(u.id))).filter((m) => m && m.key).map((m) => [String(m.key), String(m.label || m.key)]);
      const months = listed.length ? listed
        : arr((usageOf(u.id) || {}).months).filter((m) => m && m.key).slice().reverse().map((m) => [String(m.key), monthRange(m)]);
      const pick = el('span', 'lu-billpick');
      // none listed: the statement of the newest month (printBill with no key)
      let key = months.length ? months[0][0] : undefined;
      if (months.length) pick.append(select(months, key, t('lu.ux.billMonth') + ' — ' + label, 'billmonth:' + u.id, (v) => { key = v; }));
      const bill = button('btn ghost small', '🖨 ' + t('lu.ux.bill'));
      bill.dataset.lu = 'bill:' + u.id;
      bill.setAttribute('aria-label', t('lu.ux.bill') + ' — ' + label);
      bill.addEventListener('click', () => (key === undefined ? tryReport('printBill', u) : tryReport('printBill', u, key)));
      pick.append(bill);
      row.append(pick);
    }
    if (!row.children.length) return null;
    box.append(row, area);
    if (open) paintMonths(area, u);
    return { box, area };
  }
  /** The 12 months' chart, while it is open: luReports.js draws it from the user's usage (usage()[id], its `months`). */
  function paintMonths(area, u) {
    if (!area || area.hidden) return;
    const node = tryReport('monthsChart', u, usageOf(u.id));
    area.replaceChildren(...(node && typeof node === 'object' && node.nodeType ? [node] : []));
  }

  function passwordControls(u, label) {
    const box = el('div', 'lu-pass');
    const shown = !!ui.shown[u.id];
    const secret = ltr(el('span', 'lu-secret', shown ? (u.password || '') : '••••••••'));
    secret.dataset.secret = u.id;
    const eye = iconButton(shown ? '🙈' : '👁', t(shown ? 'lu.hide' : 'lu.show') + ' — ' + label, 'show:' + u.id, () => {
      ui.shown[u.id] = !ui.shown[u.id];
      const on = ui.shown[u.id];
      secret.textContent = on ? (u.password || '') : '••••••••';
      eye.textContent = on ? '🙈' : '👁';
      eye.setAttribute('aria-label', t(on ? 'lu.hide' : 'lu.show') + ' — ' + label);
      eye.title = eye.getAttribute('aria-label');
      eye.setAttribute('aria-pressed', String(on));
    });
    eye.setAttribute('aria-pressed', String(shown));
    box.append(secret, eye,
      iconButton('⧉', t('lu.copy') + ' — ' + t('lu.password') + ' — ' + label, 'copypass:' + u.id, () => copy(u.password || '')),
      iconButton('↻', t('lu.generate') + ' — ' + label, 'gen:' + u.id, () => newPassword(u.id)));
    return field(t('lu.password'), box);
  }

  function userRow(u) {
    const st = stateOf(u);
    const label = nameOf(u);
    const router = isRouter();
    const box = el('div', 'lu-user' + (connects(st) ? '' : ' lu-dim'));
    box.dataset.user = u.id;

    const head = el('div', 'lu-row');
    const av = el('div', 'lu-av', initial(u));
    av.setAttribute('aria-hidden', 'true');
    const who = el('div', 'lu-who');
    // under the name: the username and, while connected, the live rate — a phone row has no room beside the buttons
    const sub = el('div', 'lu-sub lu-line');
    const rate = ltr(el('span', 'lu-rate'));
    ui.dom.rates[u.id] = rate;
    paintRate(rate, u.id);
    sub.append(ltr(el('span', 'lu-uname', u.username)), rate);
    who.append(el('div', 'lu-name', label), sub);
    head.append(av, who, stateBadge(u, st));
    const n = router ? onlineOf(u.id) : 0;
    if (n) {
      const tag = el('span', 'lu-tag', fill(t('lu.online'), { n: String(n) }));
      // which ones: their names (or addresses) as its tooltip
      tag.title = Object.entries(ui.data.online).filter(([, o]) => o.userId === u.id).map(([mac, o]) => {
        const dev = ui.data.devices.find((x) => x.mac === mac);
        return (dev && dev.name) || o.hostname || o.ip || mac;
      }).join(', ');
      head.append(tag);
    }
    const acts = el('div', 'lu-acts');
    const del = iconButton('🗑', t('lu.delete') + ' — ' + label, 'delete:' + u.id, () => removeUser(u.id));
    del.classList.add('danger');
    acts.append(switchEl(!!u.enabled, t('lu.enable') + ' — ' + label, 'enabled:' + u.id, (on) => saveUser(u.id, { enabled: on })));
    // the router's sign-in page with this username filled in, on a card to print (login mode)
    if (cardable()) acts.append(iconButton('🪪', t('lu.card') + ' — ' + label, 'card:' + u.id, () => openCard(u.id)));
    acts.append(
      iconButton('🔗', t('lu.share') + ' — ' + label, 'share:' + u.id, () => openShare(u.id)),
      iconButton('✎', t('lu.edit') + ' — ' + label, 'edit:' + u.id, () => openDialog(u.id)),
      del);
    head.append(acts);

    const ctl = el('div', 'lu-ctl');
    // the routing the config follows, under it, when it is not the plain one
    const route = routeName(u.routing);
    const usage = usageControls(u, label);
    ctl.append(
      passwordControls(u, label),
      field(t('lu.target'), targetPicker(u.target, t('lu.target') + ' — ' + label, 'target:' + u.id, (v) => saveUser(u.id, { target: v })),
        route ? el('div', 'lu-sub lu-route', fill(t('lu.routeLine'), { name: route })) : null),
      usage.box,
      expiryControls(u, label)
    );
    if (router) {
      // a device limit is the sign-in page's to keep: the proxy cannot count devices
      // empty is 0, any number of devices: said in the box itself
      const max = numInput(u.maxDevices ? u.maxDevices : '', t('lu.maxDevices') + ' — ' + label, 'max:' + u.id, { placeholder: t('lu.maxDevicesHint') });
      max.addEventListener('change', () => {
        const v = Number(max.value);
        saveUser(u.id, { maxDevices: Number.isInteger(v) && v > 0 ? v : 0 });
      });
      ctl.append(field(t('lu.maxDevices'), max));
    }
    const rep = reportsRow(u, label);
    if (rep) ui.dom.usage[u.id].months = rep.area;
    box.append(...[head, tagsLine(u, router), requestLine(u, label), ctl, usage.chart, rep && rep.box].filter(Boolean));
    return box;
  }

  function blockHead(title, meta, ...actions) {
    const head = el('div', 'lu-head');
    const words = el('div', 'lu-head-words');
    words.append(el('div', 'lu-title', title));
    if (meta) words.append(el('div', 'lu-meta', meta));
    head.append(words, ...actions.filter(Boolean));
    return head;
  }

  function usersCard() {
    const card = el('div', 'card lu-card lu-users');
    const add = button('btn primary small', t('lu.add'));
    add.dataset.lu = 'add';
    add.disabled = !ui.data;
    add.addEventListener('click', () => openDialog(null));
    // the people, not the vouchers (those are the Vouchers tab's); how many asked for a top-up beside how many there are
    const list = people();
    const asked = requests().length;
    const meta = ui.data ? fill(t('lu.count'), { n: String(list.length) }) + (asked ? ' · ' + fill(t('lu.reqCount'), { n: String(asked) }) : '') : '';
    card.append(blockHead(t('lu.list'), meta, add));
    if (!ui.data) {
      card.append(el('p', 'hint', ui.error ? t('lu.loadFailed') + ': ' + ui.error : t('lu.loading')));
    } else if (!list.length) {
      card.append(el('div', 'empty', t('lu.none')));
    } else {
      const box = el('div', 'lu-list');
      for (const u of list) box.append(userRow(u));
      card.append(box);
    }
    return card;
  }
  /** The people whose top-up request is waiting (usage()[id].request). */
  const requests = () => people().filter((u) => { const us = usageOf(u.id); return !!(us && us.request && typeof us.request === 'object'); });

  /* ------------------------------ a user's link for a phone ------------------------------ */

  /**
   * A user's proxy account as a share link, `socks://<base64url(user:pass)>@ip:port#name`
   * — the form v2rayN and v2rayNG write, and the one IRNetFree reads on both
   * platforms (parser.js / LinkParser.kt parseProxyLink). Imported on a phone
   * it is a VPN: every app rides the account, where a Wi-Fi proxy reaches the
   * browser alone and Android's never asks for a password. The password goes
   * percent-encoded inside the base64 (both IRNetFree parsers decode it; one
   * of letters and digits, genPassword's, reads the same anywhere), and the
   * base64 is the URL-safe kind: a '/' in the user part ends it for a URI parser.
   */
  function shareLink(u, ip, port) {
    const cred = String(u.username || '') + ':' + encodeURIComponent(String(u.password == null ? '' : u.password));
    const b64 = (typeof btoa === 'function' ? btoa(cred) : Buffer.from(cred, 'utf8').toString('base64'))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    return 'socks://' + b64 + '@' + hostPort(ip, port) + '#' + encodeURIComponent(nameOf(u));
  }

  /**
   * The QR of a link as an image (qrcode.js's own GIF: no markup goes into the
   * page), or null — no qrcode.js, or a link too long for one.
   */
  function qrImage(text, label) {
    if (typeof qrcode !== 'function') return null;
    try {
      const qr = qrcode(0, 'M');
      qr.addData(text);
      qr.make();
      const img = el('img', 'lu-qrimg');
      img.src = qr.createDataURL(6, 16);
      img.alt = label;
      return img;
    } catch { return null; }
  }

  /** The link dialog of a user: the address to put in it (when there are several), its QR, the link and Copy. */
  function openShare(id, ip) {
    if (!ui.data) return false;
    const u = users().find((x) => x.id === id);
    if (!u) return false;
    const ips = ui.data.lanAddresses.filter((a) => !a.includes(':'));
    const at = ips.includes(ip) ? ip : ips[0] || '';
    if (!ui.share) {
      const overlay = el('div', 'modal-overlay lu-overlay');
      overlay.id = 'luShare';
      overlay.addEventListener('click', (e) => { if (e && e.target === overlay) closeShare(); });
      overlay.addEventListener('keydown', (e) => { if (e && e.key === 'Escape') { if (e.preventDefault) e.preventDefault(); closeShare(); } });
      ui.share = overlay;
    }
    if (!ui.share.parentNode) {
      ui.shareOpener = document.activeElement || null;
      document.body.appendChild(ui.share);
    }
    const c = cfg();
    const modal = el('div', 'modal lu-modal lu-share');
    modal.setAttribute('role', 'dialog');
    modal.setAttribute('aria-modal', 'true');
    modal.setAttribute('aria-labelledby', 'luShareTitle');
    const head = el('div', 'modal-head');
    const ico = el('span', 'lu-av', '🔗');
    ico.setAttribute('aria-hidden', 'true');
    const title = el('span', 'modal-title', fill(t('lu.shareTitle'), { name: nameOf(u) }));
    title.id = 'luShareTitle';
    const x = button('tb-btn', '✕');
    x.setAttribute('aria-label', t('tb.close'));
    x.title = t('tb.close');
    x.dataset.lu = 's:close';
    x.addEventListener('click', () => closeShare());
    head.append(ico, title, x);

    const body = el('div', 'modal-body lu-form');
    if (!c.proxy.enabled) body.append(el('p', 'hint warn lu-hint', t('lu.shareOff')));
    if (!at) {
      body.append(el('p', 'hint warn lu-hint', t('lu.noAddress')));
    } else {
      if (ips.length > 1) {
        const pick = el('div', 'lu-ips');
        pick.setAttribute('role', 'group');
        pick.setAttribute('aria-label', t('lu.shareAddr'));
        for (const a of ips) {
          const b = button('btn small ' + (a === at ? 'primary' : 'ghost'), a);
          ltr(b);
          b.dataset.lu = 's:ip:' + a;
          b.setAttribute('aria-pressed', String(a === at));
          if (isWin() && a === HOTSPOT_IP) b.textContent = a + ' · ' + t('lu.hotspotTag');
          b.addEventListener('click', () => openShare(id, a));
          pick.append(b);
        }
        body.append(el('div', 'field-label', t('lu.shareAddr')), pick);
      }
      const link = shareLink(u, at, c.proxy.port);
      const img = qrImage(link, fill(t('lu.shareTitle'), { name: nameOf(u) }));
      const qr = el('div', 'qr-image lu-qr');
      qr.append(img || el('p', 'hint', t('qr.tooBig')));
      const line = ltr(el('div', 'lu-mono lu-link', link));
      line.dataset.lu = 's:link';
      body.append(qr, line, el('p', 'hint lu-hint', t('lu.shareHow')), el('p', 'hint warn lu-hint', t('lu.shareWarn')));
      const foot = el('div', 'modal-foot');
      const cp = button('btn primary', t('lu.copyLink'));
      cp.dataset.lu = 's:copy';
      cp.addEventListener('click', () => copy(link));
      foot.append(cp);
      modal.append(head, body, foot);
      ui.share.replaceChildren(modal);
      const focus = findKey(ui.share, ip ? 's:ip:' + at : 's:copy');
      if (focus && focus.focus) focus.focus();
      return true;
    }
    modal.append(head, body);
    ui.share.replaceChildren(modal);
    if (x.focus) x.focus();
    return true;
  }

  function closeShare() {
    if (ui.share && ui.share.parentNode) ui.share.parentNode.removeChild(ui.share);
    const back = ui.shareOpener;
    ui.shareOpener = null;
    if (back && back.dataset && back.dataset.lu && ui.host) {
      const again = findKey(ui.host, back.dataset.lu);
      if (again && again.focus) again.focus();
    }
  }

  /* ------------------------------ a user's sign-in card (router) ------------------------------ */

  /** A sign-in card is the router's, in login mode (the sign-in page is where it points). */
  const cardable = () => {
    const c = cfg().transparent;
    return isRouter() && !!c.enabled && (UNASSIGNED.includes(c.unassigned) ? c.unassigned : 'login') === 'login';
  };
  /** The sign-in page with a username filled in (portal.js reads `?u=`). */
  const withUser = (base, username) => String(base) + (String(base).includes('?') ? '&' : '?') + 'u=' + encodeURIComponent(String(username || ''));
  /** The card's words on paper: Persian, English under it, whatever the window's language (as the wall sheet). */
  const CARD = {
    title: ['ورود به اینترنت', 'Sign in to use the internet'],
    scan: ['این کد را با دوربینِ گوشی اسکن کنید — نام کاربری خودش پر می‌شود.', 'Scan this code with the phone’s camera — the username is filled in.'],
    user: ['نام کاربری', 'Username'],
    pass: ['رمز', 'Password'],
    ask: ['رمز را از مدیرِ شبکه بگیرید.', 'Get the password from the network’s admin.'],
    open: ['یا این نشانی را باز کنید:', 'or open:'],
    contact: ['تماس با مدیر', 'Admin']
  };

  /**
   * The card of a user's own (the router's, login mode): the sign-in page's
   * address with `?u=<username>` — its QR, which needs no DNS of the router's
   * (the address, not the short name) — the name and the username, the password
   * only when the admin ticks it, the short name to type, and the admin's
   * contact. Printed as the wall sheet is (printSheet).
   */
  function cardSheet(u, p, withPass) {
    const url = withUser(p.url, u.username);
    const sheet = el('div', 'lu-printsheet lu-pcard');
    sheet.setAttribute('dir', 'rtl');
    const card = el('div', 'lu-pc');
    card.append(sheetLine('h1', CARD.title), el('div', 'lu-pc-name', nameOf(u)));
    const img = qrImage(url, CARD.title[1]);
    if (img) { img.className = 'lu-ps-qr lu-pc-qr'; card.append(img); }
    card.append(sheetLine('p', CARD.scan, 'lu-pc-small'));
    const row = (pair, value) => {
      const r = el('div', 'lu-pc-row');
      r.append(el('span', 'lu-pc-k', pair[0] + ' · ' + pair[1]), ltr(el('span', 'lu-pc-v', value)));
      return r;
    };
    card.append(row(CARD.user, u.username));
    if (withPass) card.append(row(CARD.pass, u.password || ''));
    else card.append(sheetLine('p', CARD.ask, 'lu-pc-small'));
    card.append(sheetLine('p', CARD.open, 'lu-pc-small'));
    for (const a of [p.nameUrl, url].filter(Boolean)) card.append(ltr(el('div', 'lu-ps-url lu-pc-url', a)));
    const contact = oneLine(cfg().portal.contact);
    if (contact) card.append(row(CARD.contact, contact));
    sheet.append(card);
    return sheet;
  }

  function openCard(id) {
    if (!ui.data) return false;
    const u = users().find((x) => x.id === id);
    if (!u) return false;
    if (!ui.card) {
      const overlay = el('div', 'modal-overlay lu-overlay');
      overlay.id = 'luCard';
      overlay.addEventListener('click', (e) => { if (e && e.target === overlay) closeCard(); });
      overlay.addEventListener('keydown', (e) => { if (e && e.key === 'Escape') { if (e.preventDefault) e.preventDefault(); closeCard(); } });
      ui.card = overlay;
    }
    if (!ui.card.parentNode) {
      ui.cardOpener = document.activeElement || null;
      document.body.appendChild(ui.card);
    }
    const p = ui.data.portal;
    let withPass = false;
    const modal = el('div', 'modal lu-modal lu-cardm');
    modal.setAttribute('role', 'dialog');
    modal.setAttribute('aria-modal', 'true');
    modal.setAttribute('aria-labelledby', 'luCardTitle');
    const head = el('div', 'modal-head');
    const ico = el('span', 'lu-av', '🪪');
    ico.setAttribute('aria-hidden', 'true');
    const title = el('span', 'modal-title', fill(t('lu.cardTitle'), { name: nameOf(u) }));
    title.id = 'luCardTitle';
    const x = button('tb-btn', '✕');
    x.setAttribute('aria-label', t('tb.close'));
    x.title = t('tb.close');
    x.dataset.lu = 'c:close';
    x.addEventListener('click', () => closeCard());
    head.append(ico, title, x);
    const body = el('div', 'modal-body lu-form');
    const foot = el('div', 'modal-foot');
    if (!p) {
      body.append(el('p', 'hint warn lu-hint', t('lu.portalDown')));
    } else {
      const url = withUser(p.url, u.username);
      const qr = el('div', 'qr-image lu-qr');
      qr.append(qrImage(url, fill(t('lu.cardTitle'), { name: nameOf(u) })) || el('p', 'hint', t('qr.tooBig')));
      const link = ltr(el('div', 'lu-mono lu-link', url));
      link.dataset.lu = 'c:link';
      const warn = el('p', 'hint warn lu-hint', t('lu.cardPassWarn'));
      warn.hidden = true;
      const pass = el('div', 'lu-switchline');
      pass.append(switchEl(false, t('lu.cardPass'), 'c:pass', (v) => { withPass = v; warn.hidden = !v; }), el('span', null, t('lu.cardPass')));
      body.append(qr, link, el('p', 'hint lu-hint', t('lu.cardHow')), pass, warn);
      const print = button('btn primary', '🖨 ' + t('lu.cardPrint'));
      print.dataset.lu = 'c:print';
      print.addEventListener('click', () => printSheet(cardSheet(u, p, withPass)));
      foot.append(print);
    }
    const cancel = button('btn ghost', t('tb.close'));
    cancel.dataset.lu = 'c:cancel';
    cancel.addEventListener('click', () => closeCard());
    foot.append(cancel);
    modal.append(head, body, foot);
    ui.card.replaceChildren(modal);
    const focus = findKey(ui.card, p ? 'c:print' : 'c:close');
    if (focus && focus.focus) focus.focus();
    return true;
  }

  function closeCard() {
    if (ui.card && ui.card.parentNode) ui.card.parentNode.removeChild(ui.card);
    const back = ui.cardOpener;
    ui.cardOpener = null;
    if (back && back.dataset && back.dataset.lu && ui.host) {
      const again = findKey(ui.host, back.dataset.lu);
      if (again && again.focus) again.focus();
    }
  }

  /* ------------------------------ topping a limit up ------------------------------ */

  /** A limit in a picker: "VPN · Monthly — 20 GB". */
  const limitWords = (l) => t('lu.kind.' + l.kind) + ' · ' + t('lu.col.' + l.period) + ' — ' + gbText(l.gb) + ' GB';

  /**
   * The top-up dialog: which of the user's limits, and how many GB more on it
   * for its current period alone (meter.js topUp — gone with the period). The
   * limit that is over comes first: it is the one people ask about.
   */
  function openTopUp(id) {
    if (!ui.data) return false;
    const u = users().find((x) => x.id === id);
    const lims = u ? limitsOf(u) : [];
    if (!lims.length) return false;
    if (!ui.topup) {
      const overlay = el('div', 'modal-overlay lu-overlay');
      overlay.id = 'luTopUp';
      overlay.addEventListener('click', (e) => { if (e && e.target === overlay) closeTopUp(); });
      overlay.addEventListener('keydown', (e) => { if (e && e.key === 'Escape') { if (e.preventDefault) e.preventDefault(); closeTopUp(); } });
      ui.topup = overlay;
    }
    if (!ui.topup.parentNode) {
      ui.topupOpener = document.activeElement || null;
      document.body.appendChild(ui.topup);
    }
    const meters = metersOf(id);
    const first = lims.find((l) => meters.some((m) => m.kind === l.kind && m.period === l.period && m.over)) || lims[0];
    let pick = first.kind + ':' + first.period;

    const modal = el('div', 'modal lu-modal lu-topup');
    modal.setAttribute('role', 'dialog');
    modal.setAttribute('aria-modal', 'true');
    modal.setAttribute('aria-labelledby', 'luTopUpTitle');
    const head = el('div', 'modal-head');
    const ico = el('span', 'lu-av', '+');
    ico.setAttribute('aria-hidden', 'true');
    const title = el('span', 'modal-title', fill(t('lu.topUpTitle'), { name: nameOf(u) }));
    title.id = 'luTopUpTitle';
    const x = button('tb-btn', '✕');
    x.setAttribute('aria-label', t('tb.close'));
    x.title = t('tb.close');
    x.dataset.lu = 't:close';
    x.addEventListener('click', () => closeTopUp());
    head.append(ico, title, x);

    const body = el('div', 'modal-body lu-form');
    const which = select(lims.map((l) => [l.kind + ':' + l.period, limitWords(l)]), pick, t('lu.topUpWhich'), 't:limit', (v) => { pick = v; });
    const gb = numInput('', t('lu.topUpGb'), 't:gb', { step: 'any', placeholder: '1' });
    const err = el('div', 'lu-err');
    err.setAttribute('role', 'alert');
    body.append(field(t('lu.topUpWhich'), which), field(t('lu.topUpGb'), gb, err), el('p', 'hint lu-hint', t('lu.topUpHint')));

    const foot = el('div', 'modal-foot');
    const add = button('btn primary', t('lu.topUpAdd'));
    add.dataset.lu = 't:save';
    const cancel = button('btn ghost', t('btn.cancel'));
    cancel.dataset.lu = 't:cancel';
    cancel.addEventListener('click', () => closeTopUp());
    const save = async () => {
      const v = Number(String(gb.value).trim());
      if (!(String(gb.value).trim() !== '' && Number.isFinite(v) && v > 0 && v <= GB_MAX)) {
        err.textContent = t('lu.err.topUp');
        gb.setAttribute('aria-invalid', 'true');
        if (gb.focus) gb.focus();
        return false;
      }
      const [kind, period] = pick.split(':');
      add.disabled = true;
      const res = await call('lanUsersUser', { op: 'topUp', user: { id }, kind, period, gb: v });
      add.disabled = false;
      if (!res) return false;     // call() said why; the dialog stays for another try
      closeTopUp();
      toast(fill(t('lu.topUpDone'), { gb: gbText(v), name: nameOf(u) }), 'ok');
      return true;
    };
    add.addEventListener('click', () => save());
    gb.addEventListener('input', () => { err.textContent = ''; gb.removeAttribute('aria-invalid'); });
    gb.addEventListener('keydown', (e) => { if (e && e.key === 'Enter') { if (e.preventDefault) e.preventDefault(); save(); } });
    foot.append(add, cancel);
    modal.append(head, body, foot);
    ui.topup.replaceChildren(modal);
    if (gb.focus) gb.focus();
    return true;
  }

  function closeTopUp() {
    if (ui.topup && ui.topup.parentNode) ui.topup.parentNode.removeChild(ui.topup);
    const back = ui.topupOpener;
    ui.topupOpener = null;
    if (back && back.dataset && back.dataset.lu && ui.host) {
      const again = findKey(ui.host, back.dataset.lu);
      if (again && again.focus) again.focus();
    }
  }

  /* ------------------------------ drawing: the router's devices ------------------------------ */

  function deviceRow(d, policy, transparent) {
    const on = !!d.live;
    const host = (d.live && d.live.hostname) || '';
    const label = d.name || host || d.mac;
    const row = el('div', 'lu-dev' + (on ? '' : ' lu-gone'));
    row.dataset.mac = d.mac;
    const dot = el('span', 'lu-dot' + (on ? ' on' : ''));
    dot.setAttribute('role', 'img');
    dot.setAttribute('aria-label', t(on ? 'lu.dev.online' : 'lu.dev.offline'));
    dot.title = dot.getAttribute('aria-label');

    const who = el('div', 'lu-who');
    const name = el('input', 'input lu-devname');
    name.value = d.name || '';
    name.placeholder = host || t('lu.dev.namePh');
    name.setAttribute('aria-label', t('lu.dev.name') + ' — ' + d.mac);
    name.dataset.lu = 'devname:' + d.mac;
    name.addEventListener('change', () => {
      const v = name.value.trim();
      if (v !== (d.name || '')) setDevice(d.mac, { name: v });
    });
    const addrs = el('div', 'lu-sub lu-addrs');
    const ip = d.live && d.live.ip ? ltr(el('span', 'lu-mono lu-ip', d.live.ip)) : null;
    const mac = ltr(el('span', 'lu-mono lu-mac', d.mac));
    if (ip) addrs.append(ip);
    addrs.append(mac);
    who.append(name, addrs);

    // the people; a voucher only when it is this device's own (a code is not someone to hand a device to)
    const owner = users().find((u) => u.id === d.userId) || null;
    const userPairs = [['', t('lu.dev.unassigned')], ...people().map((u) => [u.id, pickLabel(u)])];
    if (owner && isVoucher(owner)) userPairs.push([owner.id, '🎫 ' + owner.username]);
    if (d.userId && !owner) userPairs.push([d.userId, '⚠ ' + t('lu.target.missing')]);
    const userCell = el('div', 'lu-dcell');
    userCell.append(select(userPairs, d.userId || '', t('lu.dev.user') + ' — ' + label, 'devuser:' + d.mac, (v) => setDevice(d.mac, { userId: v })));
    // what a device nobody has gets, said on its row (only where the transparent mode decides it)
    if (d.blocked) userCell.append(el('div', 'lu-sub lu-bad', t('lu.dev.blocked')));
    else if (!d.userId && transparent) userCell.append(el('div', 'lu-sub' + (policy === 'block' ? ' lu-bad' : ''), t('lu.unassigned.' + policy)));
    // a device its user's sign-in gave them for good (a user with "remember devices"): by sign-in, and when
    if (d.userId && d.remembered) {
      const rem = el('div', 'lu-sub lu-remembered');
      rem.title = t('lu.dev.rememberedHint');
      rem.append('🔑 ', ...(Number(d.at) > 0 ? tpl(t('lu.dev.remembered'), { date: dateText(d.at) }) : [t('lu.dev.rememberedNow')]));
      userCell.append(rem);
    }

    const blockCell = el('div', 'lu-dcell lu-block');
    blockCell.append(switchEl(!!d.blocked, t('lu.dev.block') + ' — ' + label, 'devblock:' + d.mac, (b) => setDevice(d.mac, { blocked: b })), el('span', null, t('lu.dev.block')));

    const useCell = el('div', 'lu-dcell lu-use');
    const use = { bytes: ltr(el('span', 'lu-mono lu-bytes')), rate: ltr(el('span', 'lu-mono lu-devrate')) };
    ui.dom.devUse[d.mac] = use;
    paintDevUse(use, d.mac);
    useCell.append(use.bytes, use.rate);

    row.append(dot, who, userCell, blockCell, useCell);
    return row;
  }

  function devicesCard() {
    const c = cfg();
    const rows = deviceRows();
    const card = el('div', 'card lu-card lu-devices');
    const again = button('btn ghost small', t('lu.refresh'));
    again.dataset.lu = 'devrefresh';
    again.disabled = !!ui.loading;
    again.addEventListener('click', () => refresh());
    const online = rows.filter((r) => r.live).length;
    card.append(blockHead(t('lu.devices'), ui.data ? fill(t('lu.devicesSub'), { online: String(online), total: String(rows.length) }) : '', again));
    if (!c.transparent.enabled) card.append(el('p', 'hint lu-hint', t('lu.devTransparentOff')));
    if (!ui.data) return card;
    if (!rows.length) { card.append(el('div', 'empty', t('lu.noDevices'))); return card; }
    const policy = UNASSIGNED.includes(c.transparent.unassigned) ? c.transparent.unassigned : 'login';
    const list = el('div', 'lu-devs');
    for (const d of rows) list.append(deviceRow(d, policy, !!c.transparent.enabled));
    card.append(list);
    return card;
  }

  /* ------------------------------ drawing: the hotspot check (Windows) ------------------------------ */

  /**
   * Does a device on this PC's hotspot ride the tunnel? (src/modules/lanUsers/hotspot.js)
   * The question before a transparent mode for the hotspot, answered on the
   * owner's own laptop: the devices on 192.168.137.1, and for each whether
   * the TUN has had a connection from it. A Windows desktop's, from the
   * payload's `hotspot`.
   */
  function hotspotCard() {
    const h = ui.data.hotspot;
    const card = el('div', 'card lu-card lu-hscard');
    const again = button('btn ghost small', t('lu.refresh'));
    again.dataset.lu = 'hsrefresh';
    again.disabled = !!ui.loading;
    again.addEventListener('click', () => refresh());
    card.append(blockHead(t('lu.hs.title'), t('lu.hs.sub'), again));
    if (!h.on) card.append(el('p', 'hint warn lu-hint', t('lu.hs.off')));
    else if (!h.tun) card.append(el('p', 'hint warn lu-hint', t('lu.hs.noTun')));
    else if (h.error) card.append(el('p', 'hint warn lu-hint', t('lu.hs.apiError') + ': ' + h.error));
    if (h.devices.length) {
      const list = el('div', 'lu-hslist');
      for (const d of h.devices) list.append(hotspotRow(d, h.tun));
      card.append(list);
    } else if (h.on) card.append(el('div', 'empty', t('lu.hs.none')));
    card.append(el('p', 'lu-note lu-hotspot', t('lu.hs.how')));
    return card;
  }

  function hotspotRow(d, tun) {
    const row = el('div', 'lu-hsrow');
    row.dataset.ip = d.ip;
    const who = el('div', 'lu-hswho');
    who.append(ltr(el('span', 'lu-mono lu-ip', d.ip)));
    if (d.mac) who.append(ltr(el('span', 'lu-mono lu-mac', d.mac)));
    row.append(who, el('span', 'lu-tag ' + (d.seen ? 'lu-hs-yes' : 'lu-hs-no'), t(d.seen ? 'lu.hs.yes' : (tun ? 'lu.hs.notYet' : 'lu.hs.unknown'))));
    // the line keeps the page's direction (in Persian the words read right to left); the size inside is isolated
    if (d.seen) {
      const use = el('span', 'lu-sub lu-hsuse');
      const [before, after] = t('lu.hs.use').replace('{n}', String(d.open)).split('{bytes}');
      use.append(before || '', ltr(el('bdi', null, bytesText(d.bytes))), after || '');
      row.append(use);
    }
    return row;
  }

  /* ------------------------------ the tabs, backup and restore ------------------------------ */

  /** luVouchers.js, when the page has it: the Vouchers tab is its panel. */
  const voucherPanel = () => (typeof window.LuVouchers === 'object' && window.LuVouchers && typeof window.LuVouchers.panel === 'function' ? window.LuVouchers : null);
  const tabNow = () => (ui.tab === 'vouchers' && voucherPanel() ? 'vouchers' : 'users');

  function setTab(tab) {
    ui.tab = tab === 'vouchers' ? 'vouchers' : 'users';
    render();
    const b = findKey(ui.host, 'tab:' + tabNow());
    if (b && b.focus) b.focus();
  }

  /**
   * The bar over the blocks: Users | Vouchers (each with how many — and on
   * Users how many asked for a top-up), then the module's own file: an "All
   * users" CSV (luReports.js), Backup and Restore. The arrow keys move between
   * the tabs, as a tab list's do.
   */
  function toolbar() {
    const bar = el('div', 'lu-toolbar');
    if (voucherPanel()) {
      const tabs = el('div', 'seg lu-tabs');
      tabs.setAttribute('role', 'tablist');
      tabs.setAttribute('aria-label', t('lu.tab.aria'));
      const now = tabNow();
      const asked = ui.data ? requests().length : 0;
      for (const [key, n] of [['users', ui.data ? people().length : null], ['vouchers', ui.data ? vouchers().length : null]]) {
        const b = button('seg-btn lu-tab' + (key === now ? ' active' : ''), t('lu.tab.' + key));
        b.setAttribute('role', 'tab');
        b.setAttribute('aria-selected', String(key === now));
        b.setAttribute('aria-controls', 'luPane');
        b.id = 'luTab-' + key;
        b.tabIndex = key === now ? 0 : -1;
        b.dataset.lu = 'tab:' + key;
        if (n != null) b.append(' ', el('span', 'lu-tabn', String(n)));
        if (key === 'users' && asked) {
          const r = el('span', 'lu-tabreq', '🔔 ' + asked);
          r.title = fill(t('lu.reqCount'), { n: String(asked) });
          b.append(' ', r);
        }
        b.addEventListener('click', () => { if (tabNow() !== key) setTab(key); });
        b.addEventListener('keydown', (e) => {
          if (!e || !['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(e.key)) return;
          if (e.preventDefault) e.preventDefault();
          setTab(tabNow() === 'users' ? 'vouchers' : 'users');
        });
        tabs.append(b);
      }
      bar.append(tabs);
    }
    const acts = el('div', 'lu-tbacts');
    if (reports() && typeof reports().csvAll === 'function') {
      const csv = button('btn ghost small', '⤓ ' + t('lu.tb.csvAll'));
      csv.dataset.lu = 'csvAll';
      csv.disabled = !ui.data;
      csv.addEventListener('click', () => tryReport('csvAll'));
      acts.append(csv);
    }
    const save = button('btn ghost small', '💾 ' + t('lu.tb.backup'));
    save.dataset.lu = 'backup';
    save.title = t('lu.bk.tip');
    save.disabled = !ui.data || !window.api || typeof window.api.lanUsersBackup !== 'function';
    save.addEventListener('click', () => backup());
    const load = button('btn ghost small', '⟲ ' + t('lu.tb.restore'));
    load.dataset.lu = 'restore';
    load.disabled = !ui.data || !window.api || typeof window.api.lanUsersRestore !== 'function';
    load.addEventListener('click', () => pickBackup());
    acts.append(save, load);
    bar.append(acts);
    return bar;
  }

  /** Today as a file name's part: 2026-10-29. */
  const stamp = (ms = Date.now()) => dayInput(ms) || 'backup';

  /**
   * Backup: lanusers:backup's bundle (the store record, the meter's state) as
   * one JSON file, through a Blob and a link — the window and the router's page
   * alike. It holds every password: asked first.
   */
  async function backup() {
    if (!window.api || typeof window.api.lanUsersBackup !== 'function') return false;
    const msg = t('lu.bk.confirm');
    if (!(ui.hooks.confirm ? hook('confirm', msg) : window.confirm(msg))) return false;
    let res;
    try {
      res = await window.api.lanUsersBackup();
      checkAnswer(res);
    } catch (e) {
      toast(t('lu.bk.failed') + ': ' + errText(e), 'err');
      return false;
    }
    const bundle = res && typeof res === 'object' ? res.bundle : null;
    if (!bundle || typeof bundle !== 'object') { toast(t('lu.bk.failed'), 'err'); return false; }
    const ok = download('irnetfree-users-' + stamp(Number(bundle.at) || Date.now()) + '.json', JSON.stringify(bundle, null, 2), 'application/json');
    if (ok) toast(t('lu.bk.saved'), 'ok');
    return ok;
  }
  /** A file to save, made here: a Blob behind a link that is clicked (Electron asks where; a browser downloads it). */
  function download(name, text, type) {
    try {
      const url = URL.createObjectURL(new Blob([text], { type: type || 'application/octet-stream' }));
      const a = el('a');
      a.href = url;
      a.download = name;
      a.rel = 'noopener';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(() => { try { URL.revokeObjectURL(url); } catch { /* gone already */ } }, 5000);
      return true;
    } catch {
      toast(t('lu.bk.failed'), 'err');
      return false;
    }
  }

  /** Restore, step one: a file from this device (a file box, clicked for the admin), read here. */
  function pickBackup() {
    const input = el('input');
    input.type = 'file';
    input.accept = '.json,application/json';
    input.hidden = true;
    input.dataset.lu = 'restoreFile';
    input.addEventListener('change', async () => {
      const f = input.files && input.files[0];
      if (input.parentNode) input.parentNode.removeChild(input);
      if (!f) return;
      let text = '';
      try { text = typeof f.text === 'function' ? await f.text() : await readText(f); } catch { toast(t('lu.bk.readFailed'), 'err'); return; }
      openRestore(text);
    });
    document.body.appendChild(input);
    input.click();
    return input;
  }
  /** A file's words where Blob.text is not there (an older engine): FileReader. */
  const readText = (f) => new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(String(r.result || ''));
    r.onerror = () => reject(r.error || new Error('read'));
    r.readAsText(f);
  });

  /**
   * A backup file, read: its bundle and what it holds — people, devices,
   * vouchers — or why it is not one (the lu.err.backup details: another kind of
   * file — the whole app's backup is Settings' —, a newer version, a shape that
   * is not the store's). The service checks it all again.
   */
  function readBundle(text) {
    let b;
    try { b = JSON.parse(String(text || '')); } catch { return { error: 'shape' }; }
    if (!b || typeof b !== 'object' || Array.isArray(b)) return { error: 'shape' };
    if (b.kind !== BACKUP_KIND) return { error: 'kind' };
    if (!(Number(b.version) >= 1)) return { error: 'shape' };
    if (Number(b.version) > BACKUP_VERSION) return { error: 'version' };
    const lu = b.lanUsers;
    if (!lu || typeof lu !== 'object' || !Array.isArray(lu.users)) return { error: 'shape' };
    const all = lu.users.filter((u) => u && typeof u === 'object');
    return {
      bundle: b,
      users: all.filter((u) => !isVoucher(u)).length,
      vouchers: all.filter(isVoucher).length,
      devices: arr(lu.devices).filter((d) => d && typeof d === 'object').length,
      at: Number(b.at) || 0,
      app: typeof b.app === 'string' ? b.app.slice(0, 32) : '',
      platform: typeof b.platform === 'string' ? b.platform.slice(0, 32) : ''
    };
  }

  /**
   * Restore, step two: what the file holds and when it was made, the warning
   * that it carries passwords, and the two ways in — Merge (what is new is
   * added, what both have is updated, nobody here goes) or Replace (after
   * asking: the page becomes the file). A file that is not a Users backup is
   * said in the dialog, with nothing to press but Close.
   */
  function openRestore(text) {
    const info = readBundle(text);
    if (!ui.restore) {
      const overlay = el('div', 'modal-overlay lu-overlay');
      overlay.id = 'luRestore';
      overlay.addEventListener('click', (e) => { if (e && e.target === overlay) closeRestore(); });
      overlay.addEventListener('keydown', (e) => { if (e && e.key === 'Escape') { if (e.preventDefault) e.preventDefault(); closeRestore(); } });
      ui.restore = overlay;
    }
    if (!ui.restore.parentNode) {
      ui.restoreOpener = document.activeElement || null;
      document.body.appendChild(ui.restore);
    }
    const modal = el('div', 'modal lu-modal lu-restore');
    modal.setAttribute('role', 'dialog');
    modal.setAttribute('aria-modal', 'true');
    modal.setAttribute('aria-labelledby', 'luRestoreTitle');
    const head = el('div', 'modal-head');
    const ico = el('span', 'lu-av', '⟲');
    ico.setAttribute('aria-hidden', 'true');
    const title = el('span', 'modal-title', t('lu.bk.title'));
    title.id = 'luRestoreTitle';
    const x = button('tb-btn', '✕');
    x.setAttribute('aria-label', t('tb.close'));
    x.title = t('tb.close');
    x.dataset.lu = 'r:close';
    x.addEventListener('click', () => closeRestore());
    head.append(ico, title, x);
    const body = el('div', 'modal-body lu-form');
    const foot = el('div', 'modal-foot');
    const err = el('p', 'lu-formerr');
    err.setAttribute('role', 'alert');
    err.hidden = true;
    if (info.error) {
      err.textContent = t('lu.err.backup.' + info.error);
      err.hidden = false;
      body.append(err);
    } else {
      const sum = el('div', 'lu-bksum');
      sum.dataset.lu = 'r:summary';
      sum.append(...tpl(t('lu.bk.file'), { users: String(info.users), devices: String(info.devices), vouchers: String(info.vouchers) }));
      body.append(sum);
      if (info.at) {
        const when = el('div', 'lu-sub');
        // the app and its version in one isolate: «IRNetFree 1.40.0» reads left to right inside a Persian line
        when.append(...tpl(t('lu.bk.when'), { date: fullDate(info.at) + ' ' + clock(info.at), app: 'IRNetFree' + (info.app ? ' ' + info.app : '') }));
        body.append(when);
      }
      body.append(el('p', 'hint warn lu-hint', t('lu.bk.warn')));
      const way = (key, word, sub) => {
        const b = el('div', 'lu-bkway');
        b.append(el('div', 'lu-bkway-t', word), el('div', 'lu-sub', sub));
        return b;
      };
      body.append(way('merge', t('lu.bk.merge'), t('lu.bk.mergeSub')), way('replace', t('lu.bk.replace'), t('lu.bk.replaceSub')), err);
      const go = async (mode, btn) => {
        if (mode === 'replace') {
          const msg = t('lu.bk.confirmReplace');
          if (!(ui.hooks.confirm ? hook('confirm', msg) : window.confirm(msg))) return false;
        }
        for (const b of [merge, replace]) b.disabled = true;
        btn.setAttribute('aria-busy', 'true');
        const res = await restore(info.bundle, mode);
        for (const b of [merge, replace]) b.disabled = false;
        btn.removeAttribute('aria-busy');
        if (res.ok) { closeRestore(); return true; }
        err.textContent = t('lu.saveFailed') + ': ' + errText(res);
        err.hidden = false;
        return false;
      };
      const merge = button('btn primary', t('lu.bk.merge'));
      merge.dataset.lu = 'r:merge';
      merge.addEventListener('click', () => go('merge', merge));
      const replace = button('btn danger ghost', t('lu.bk.replace'));
      replace.dataset.lu = 'r:replace';
      replace.addEventListener('click', () => go('replace', replace));
      foot.append(replace, merge);
    }
    const cancel = button('btn ghost', t('btn.cancel'));
    cancel.dataset.lu = 'r:cancel';
    cancel.addEventListener('click', () => closeRestore());
    foot.append(cancel);
    modal.append(head, body, foot);
    ui.restore.replaceChildren(modal);
    const focus = findKey(ui.restore, info.error ? 'r:cancel' : 'r:merge');
    if (focus && focus.focus) focus.focus();
    return !info.error;
  }

  /** lanusers:restore, then the page read again (the store and the meter changed under it) and what came in said. */
  async function restore(bundle, mode) {
    if (!window.api || typeof window.api.lanUsersRestore !== 'function') return { ok: false, error: 'unavailable' };
    ui.seq++;
    ui.busy++;
    let res;
    try {
      res = await window.api.lanUsersRestore({ bundle, mode: mode === 'replace' ? 'replace' : 'merge' });
      checkAnswer(res);
    } catch (e) {
      ui.busy--;
      return { ok: false, error: String((e && e.message) || e || 'failed'), detail: e && e.detail };
    }
    ui.busy--;
    if (!take(res)) await refresh(); else render();
    Promise.resolve(hook('applied', res)).catch(() => {});
    const n = (o, k) => Number(obj(o)[k]) || 0;
    const r = obj(res);
    const updated = n(r.updated, 'users') + n(r.updated, 'devices');
    toast(fill(t('lu.bk.done'), { users: String(n(r.added, 'users')), devices: String(n(r.added, 'devices')), vouchers: String(n(r.added, 'vouchers')), updated: String(updated) })
      + (n(r.skipped, 'users') ? ' · ' + fill(t('lu.bk.skipped'), { n: String(n(r.skipped, 'users')) }) : ''), n(r.skipped, 'users') ? 'warn' : 'ok');
    return Object.assign({ ok: true }, r);
  }

  function closeRestore() {
    if (ui.restore && ui.restore.parentNode) ui.restore.parentNode.removeChild(ui.restore);
    const back = ui.restoreOpener;
    ui.restoreOpener = null;
    if (back && back.dataset && back.dataset.lu && ui.host) {
      const again = findKey(ui.host, back.dataset.lu);
      if (again && again.focus) again.focus();
    }
  }

  /** The Vouchers tab: luVouchers.js's panel, built on the kit — a fault of its own said here, the rest of the page untouched. */
  function vouchersPane() {
    const pane = el('div', 'lu-vpane');
    try {
      const node = voucherPanel().panel(kit);
      if (node && typeof node === 'object' && node.nodeType) pane.append(node);
    } catch (e) {
      if (typeof console !== 'undefined') console.error('LuVouchers.panel', e);
      pane.append(el('p', 'hint warn', t('lu.loadFailed') + ': ' + String((e && e.message) || e)));
    }
    return pane;
  }

  /* ------------------------------ drawing: the page ------------------------------ */

  /** The first element under `node` that `pred` accepts — by walking, not querySelector, so a key needs no escaping. */
  function findBy(node, pred) {
    for (const c of (node && node.children) || []) {
      if (pred(c)) return c;
      const hit = findBy(c, pred);
      if (hit) return hit;
    }
    return null;
  }
  const findKey = (node, key) => findBy(node, (c) => !!c.dataset && c.dataset.lu === key);

  function render() {
    const host = ui.host;
    if (!host) return;
    // a redraw replaces the controls: the one in use keeps the focus
    const active = document.activeElement;
    const focusKey = active && active !== host && host.contains && host.contains(active) && active.dataset ? active.dataset.lu : null;
    ui.dom = { usage: {}, rates: {}, devUse: {} };
    ui.wasConnected = connected();
    // the blocks of the tab that is open: the Users tab is the page as it always was, the Vouchers tab luVouchers.js's
    const blocks = [];
    if (tabNow() === 'vouchers') blocks.push(vouchersPane());
    else {
      blocks.push(settingsCard(), usersCard());
      if (isRouter()) blocks.push(devicesCard());
      else if (ui.data && ui.data.hotspot) blocks.push(hotspotCard());
    }
    const parts = [el('p', 'hint lu-intro', t('lu.intro')), noWayIn(), toolbar()].filter(Boolean);
    if (voucherPanel()) {
      const pane = el('div', 'lu-pane');
      pane.id = 'luPane';
      pane.setAttribute('role', 'tabpanel');
      pane.setAttribute('aria-labelledby', 'luTab-' + tabNow());
      pane.append(...blocks);
      parts.push(pane);
    } else parts.push(...blocks);
    host.replaceChildren(...parts);
    if (focusKey) {
      const n = findKey(host, focusKey);
      if (n && !n.disabled && n.focus) n.focus();
    }
  }

  /* ------------------------------ the add / edit dialog ------------------------------ */

  const blank = (v) => String(v == null ? '' : v).trim() === '';
  /** A speed box's Mbps → its kbps (1 kbps to 10 Gbps), or null: empty, or not a speed. */
  function kbpsBox(v) {
    if (blank(v) || !Number.isFinite(Number(String(v).trim()))) return null;
    const k = kbpsOf(String(v).trim());
    return k >= 1 && k <= KBPS_MAX ? k : null;
  }
  /** Two rate boxes: each empty or a speed, and not both empty. */
  const ratesOk = (down, up) => (blank(down) || kbpsBox(down) !== null) && (blank(up) || kbpsBox(up) !== null) && !(blank(down) && blank(up));
  /** A window of the week (the allowed hours, a speed window): a day at least, and two times. */
  const windowOk = (w) => !!w && arr(w.days).length > 0 && arr(w.days).every((d) => Number.isInteger(Number(d)) && Number(d) >= 0 && Number(d) <= 6)
    && HHMM.test(String(w.from)) && HHMM.test(String(w.to));
  const sortDays = (days) => [...new Set(arr(days).map(Number))].sort((a, b) => a - b);

  /**
   * The rules the service keeps (model.js validateUser), said before it is
   * asked: a username of English letters, digits, dot, dash or underscore, 1 to
   * 32 of them, no other user's (case aside: «Ali» and «ali» are one person on
   * a phone keyboard); a password of 4 characters or more, kept as typed; a
   * device count that is a whole number; each limit a number of GB (empty or
   * 0: none) up to GB_MAX, a 'slow' one with a speed to slow to; a routing the
   * service knows; allowed hours with a day and two times; speeds from 1 kbps
   * to 10 Gbps, each peak-hour window with a day, two times and a speed.
   * A form of before the limits (`quotaGb`) is checked as it was.
   * → { field: i18n key }.
   */
  function validate(f, others) {
    const e = {};
    const username = String(f.username || '').trim();
    if (!USERNAME.test(username)) e.username = 'lu.err.username';
    else if (arr(others).some((u) => String(u.username || '').toLowerCase() === username.toLowerCase())) e.username = 'lu.err.usernameTaken';
    if (String(f.password == null ? '' : f.password).length < PASS_MIN) e.password = 'lu.err.password';
    const q = String(f.quotaGb == null ? '' : f.quotaGb).trim();
    if (q !== '' && !(Number.isFinite(Number(q)) && Number(q) >= 0)) e.quotaGb = 'lu.err.quota';
    for (const [cell, raw] of Object.entries(obj(f.limits))) {
      if (blank(raw)) continue;
      const gb = Number(String(raw).trim());
      if (!Number.isFinite(gb) || gb < 0 || gb > GB_MAX) { e.limits = 'lu.err.limits'; break; }
      const a = obj(f.acts)[cell];
      if (gb > 0 && a && a.action === 'slow' && !ratesOk(a.down, a.up)) { e.limits = 'lu.err.slow'; break; }
    }
    if (f.routing != null && !ROUTE_RE.test(String(f.routing))) e.routing = 'lu.err.routing';
    if (f.sched && f.sched.on && !windowOk(f.sched)) e.schedule = 'lu.err.schedule';
    const sp = f.speed;
    if (sp && !((blank(sp.down) || kbpsBox(sp.down) !== null) && (blank(sp.up) || kbpsBox(sp.up) !== null))) e.speed = 'lu.err.speed';
    const wins = arr(f.speedHours);
    if (wins.length > SPEED_WINDOWS || wins.some((w) => !windowOk(w) || !ratesOk(w.down, w.up))) e.speed = 'lu.err.speed';
    const m = String(f.maxDevices == null ? '' : f.maxDevices).trim();
    if (m !== '' && !/^\d+$/.test(m)) e.maxDevices = 'lu.err.maxDevices';
    // a priority is the speed panel's (it sits there)
    if (f.priority != null && !PRIORITIES.includes(f.priority) && !e.speed) e.speed = 'lu.err.priority';
    if (f.filter) {
      if (arr(f.filter.block).some((c) => !FILTER_CATS.includes(c))) e.filter = 'lu.err.filter.category';
      else {
        const list = domainLines(f.filter.domains);
        if (list.some((d) => !FILTER_DOMAIN.test(d))) e.filter = 'lu.err.filter.domain';
        else if (list.length > FILTER_DOMAINS_MAX) e.filter = 'lu.err.filter.domains';
      }
    }
    return e;
  }

  /**
   * The blocked domains box → its entries as the model keeps them: a line
   * each (commas and spaces split too — a pasted list), lowercased, trimmed,
   * empty lines gone, each once; 'Full:' and 'KEYWORD:' read as their prefix,
   * 'domain:' as none (Xray's word for the plain one), and a pasted address
   * ('https://www.example.com/page') as its host.
   */
  function domainLines(text) {
    const out = [];
    for (const raw of String(text == null ? '' : text).split(/[\s,،;]+/)) {
      let v = raw.trim().toLowerCase().replace(/^(full|keyword|domain):/, (m, p) => (p === 'domain' ? '' : p + ':'));
      if (/^[a-z][a-z0-9+.-]*:\/\//.test(v)) v = v.replace(/^[a-z][a-z0-9+.-]*:\/\//, '').replace(/[/?#:].*$/, '');
      if (v && !out.includes(v)) out.push(v);
    }
    return out;
  }

  /**
   * The dialog's fields → the user the service stores (its other fields, if
   * any, kept): the limits in the grid's order, and beside them the single cap
   * an older reader of the same store knows — the first Total limit's, as
   * model.js writes it; the speed only where it is edited (the router).
   */
  function toUser(f) {
    const old = f.id ? users().find((u) => u.id === f.id) : null;
    const m = String(f.maxDevices == null ? '' : f.maxDevices).trim();
    const limits = [];
    for (const kind of KINDS) {
      for (const period of LPERIODS) {
        const raw = obj(f.limits)[kind + ':' + period];
        const gb = blank(raw) ? 0 : Number(String(raw).trim());
        if (!(gb > 0)) continue;
        const l = { kind, period, gb };
        const a = obj(f.acts)[kind + ':' + period];
        if (a && a.action === 'slow') {
          l.action = 'slow';
          if (kbpsBox(a.down) !== null) l.down = kbpsBox(a.down);
          if (kbpsBox(a.up) !== null) l.up = kbpsBox(a.up);
        }
        limits.push(l);
      }
    }
    const total = limits.find((l) => l.kind === 'total');
    const user = Object.assign({}, old || {}, {
      username: String(f.username).trim(),
      password: String(f.password),
      name: String(f.name || '').trim(),
      target: f.target || '',
      routing: String(f.routing || ''),
      limits,
      quotaGb: total ? total.gb : 0,
      quotaPeriod: total ? total.period : 'month',
      quotaCalendar: f.calendar === 'jalali' ? 'jalali' : 'gregorian',
      quotaResetDay: dayOf(f.quotaResetDay),
      schedule: f.sched && f.sched.on ? { days: sortDays(f.sched.days), from: f.sched.from, to: f.sched.to } : null,
      expiresAt: fromDayInput(f.expires),
      maxDevices: m === '' ? 0 : Number(m),
      enabled: !!f.enabled,
      filter: filterOf(f.filter)
    });
    // the router's alone, as the speed: a desktop's save leaves what the record has
    if (f.priority != null) user.priority = PRIORITIES.includes(f.priority) ? f.priority : 'normal';
    if (f.remember != null) user.remember = !!f.remember;
    if (f.speed) {
      const rates = (w) => Object.assign({}, kbpsBox(w.down) !== null ? { down: kbpsBox(w.down) } : {}, kbpsBox(w.up) !== null ? { up: kbpsBox(w.up) } : {});
      const base = rates(f.speed);
      user.speed = Object.keys(base).length ? base : null;
      user.speedHours = arr(f.speedHours).map((w) => Object.assign({ days: sortDays(w.days), from: w.from, to: w.to }, rates(w)));
    }
    if (f.id) user.id = f.id; else delete user.id;   // a new one gets its id from the service (model.js newUserId)
    return user;
  }
  /** The filter's fields → the model's `filter`: the categories in its order, the domains as kept — null when it filters nothing. */
  function filterOf(ff) {
    if (!ff) return null;
    const block = FILTER_CATS.filter((c) => arr(ff.block).includes(c));
    const domains = domainLines(ff.domains);
    const safeSearch = !!ff.safeSearch;
    return block.length || safeSearch || domains.length ? { block, safeSearch, domains } : null;
  }

  /**
   * A user — or none: a new one — as the dialog's fields. A new user: a
   * password ready (shown — the admin reads it out), the current connection,
   * no limit, any time; its month, when a monthly limit is typed, is the
   * Persian one from its 1st in Persian (only the form's default: a saved user
   * changes only when saved). The speed is the router's alone.
   */
  function formOf(u) {
    const limits = {};
    const acts = {};
    for (const kind of KINDS) {
      for (const period of LPERIODS) {
        const l = u ? limitOf(u, kind, period) : null;
        limits[kind + ':' + period] = l ? gbText(l.gb) : '';
        acts[kind + ':' + period] = { action: l && l.action === 'slow' ? 'slow' : 'cut', down: l ? mbpsText(l.down) : '', up: l ? mbpsText(l.up) : '' };
      }
    }
    const s = u && u.schedule && typeof u.schedule === 'object' ? u.schedule : null;
    const sp = obj(u && u.speed);
    const flt = obj(u && u.filter);
    const f = u
      ? { id: u.id, name: u.name || '', username: u.username || '', password: u.password || '', target: u.target || '',
        expires: dayInput(u.expiresAt), maxDevices: u.maxDevices ? String(u.maxDevices) : '', enabled: u.enabled !== false, showPass: false }
      : { id: '', name: '', username: '', password: genPassword(), target: '', expires: '', maxDevices: '', enabled: true, showPass: true };
    return Object.assign(f, {
      routing: u ? String(u.routing || '') : '',
      limits,
      acts,
      calendar: u ? (u.quotaCalendar === 'jalali' ? 'jalali' : 'gregorian') : (lang() === 'fa' ? 'jalali' : 'gregorian'),
      quotaResetDay: u ? dayOf(u.quotaResetDay) : 1,
      sched: s ? { on: true, days: sortDays(s.days), from: String(s.from || ''), to: String(s.to || '') }
        : { on: false, days: [0, 1, 2, 3, 4, 5, 6], from: '08:00', to: '23:00' },
      speed: isRouter() ? { down: mbpsText(sp.down), up: mbpsText(sp.up) } : null,
      speedHours: isRouter() ? arr(u && u.speedHours).slice(0, SPEED_WINDOWS).filter((w) => w && typeof w === 'object')
        .map((w) => ({ days: sortDays(w.days), from: String(w.from || ''), to: String(w.to || ''), down: mbpsText(w.down), up: mbpsText(w.up) })) : null,
      // the content filter (every platform); the priority and "remember devices" the router's — a voucher never remembers
      filter: { block: FILTER_CATS.filter((c) => arr(flt.block).includes(c)), safeSearch: !!flt.safeSearch, domains: arr(flt.domains).join('\n') },
      priority: isRouter() ? (PRIORITIES.includes(u && u.priority) ? u.priority : 'normal') : null,
      remember: isRouter() && !isVoucher(u) ? !!(u && u.remember) : null,
      voucher: isVoucher(u),
      errors: {},
      error: '',
      saving: false
    });
  }

  function openDialog(id) {
    if (!ui.data) return false;
    const u = id ? users().find((x) => x.id === id) : null;
    if (id && !u) return false;
    ui.opener = document.activeElement || null;
    ui.form = formOf(u);
    if (!ui.modal) {
      const overlay = el('div', 'modal-overlay lu-overlay');
      overlay.id = 'luModal';
      overlay.addEventListener('click', (e) => { if (e && e.target === overlay) closeDialog(); });
      overlay.addEventListener('keydown', (e) => { if (e && e.key === 'Escape') { if (e.preventDefault) e.preventDefault(); closeDialog(); } });
      ui.modal = overlay;
    }
    if (!ui.modal.parentNode) document.body.appendChild(ui.modal);
    renderDialog();
    const first = findKey(ui.modal, u ? 'f:name' : 'f:username');
    if (first && first.focus) first.focus();
    return true;
  }

  function closeDialog() {
    ui.form = null;
    ui.safeGroupPaint = null;
    if (ui.modal && ui.modal.parentNode) ui.modal.parentNode.removeChild(ui.modal);
    const back = ui.opener;
    ui.opener = null;
    // the button that opened it, when it is still on the page (an edit redraws the list)
    if (back && back.dataset && back.dataset.lu && ui.host) {
      const again = findKey(ui.host, back.dataset.lu);
      if (again && again.focus) again.focus();
    }
  }

  /** A field's error gone (the admin is fixing it): its words under it too. */
  function clearErr(key) {
    const f = ui.form;
    if (!f || !f.errors[key]) return;
    delete f.errors[key];
    const e = findBy(ui.modal, (c) => c.dataset && c.dataset.err === key);
    if (e) e.textContent = '';
  }
  /** Enter in a box of the dialog saves it, as its Save button does. */
  const enterSaves = (n) => n.addEventListener('keydown', (e) => { if (e && e.key === 'Enter') { if (e.preventDefault) e.preventDefault(); submitDialog(); } });

  /** A dialog field: its label, the control(s), a hint, and its error under it. */
  function formField(key, label, controls, hint) {
    const f = ui.form;
    const box = el('div', 'lu-field');
    box.dataset.field = key;
    box.append(el('div', 'field-label', label), ...controls);
    if (hint) box.append(el('div', 'lu-sub', hint));
    const err = el('div', 'lu-err', f.errors[key] ? t(f.errors[key]) : '');
    err.setAttribute('role', 'alert');
    err.dataset.err = key;
    box.append(err);
    return box;
  }
  /** A part of the dialog in a panel of its own (the limits, the hours, the speed): its title, its controls, a hint, its error. */
  function section(key, title, nodes, hint) {
    const f = ui.form;
    const box = el('div', 'lu-sect');
    box.dataset.field = key;
    box.append(el('div', 'lu-sect-title', title), ...nodes.filter(Boolean));
    if (hint) box.append(el('div', 'lu-sub', hint));
    const err = el('div', 'lu-err', f.errors[key] ? t(f.errors[key]) : '');
    err.setAttribute('role', 'alert');
    err.dataset.err = key;
    box.append(err);
    return box;
  }
  /** A text box bound to the dialog's field `key`; typing clears that field's error. */
  function formInput(key, label, { type = 'text', dir = '', placeholder = '' } = {}) {
    const f = ui.form;
    const n = el('input', 'input');
    n.type = type;
    n.value = f[key] == null ? '' : String(f[key]);
    if (dir) n.setAttribute('dir', dir);
    if (placeholder) n.placeholder = placeholder;
    n.setAttribute('aria-label', label);
    n.setAttribute('autocomplete', 'off');
    if (dir === 'ltr') {
      // a username or a password: exactly as typed — no capital the keyboard adds, no spelling fix
      n.setAttribute('spellcheck', 'false');
      n.setAttribute('autocapitalize', 'none');
    }
    n.dataset.lu = 'f:' + key;
    if (f.errors[key]) n.setAttribute('aria-invalid', 'true');
    n.addEventListener('input', () => {
      f[key] = n.value;
      if (f.errors[key]) n.removeAttribute('aria-invalid');
      clearErr(key);
    });
    enterSaves(n);
    return n;
  }

  /**
   * A user's routing: as the config ('' — on the router, as the router routes
   * every device: its own rules first), Iranian sites direct, or one of the
   * app's routing profiles (hooks.routingProfiles — its rules, the user's
   * config the default). A profile that is gone stays, said as gone; 'global'
   * is the plain one by another name, and stays as it is unless changed.
   */
  function routingPicker(value, key, onChange) {
    const v = value === 'global' ? '' : String(value || '');
    const s = el('select', 'select');
    s.setAttribute('aria-label', t('lu.routing'));
    s.dataset.lu = key;
    const add = (parent, val, text) => {
      const o = el('option', null, text);
      o.value = val;
      if (val === v) o.selected = true;
      parent.appendChild(o);
    };
    add(s, '', t(isRouter() ? 'lu.route.router' : 'lu.route.all'));
    add(s, 'bypass-ir', t('lu.route.bypassIr'));
    const list = profiles();
    if (list.length || v.startsWith('profile:')) {
      const g = el('optgroup');
      g.label = t('lu.route.profiles');
      for (const p of list) add(g, 'profile:' + p.id, p.name);
      if (v.startsWith('profile:') && !list.some((p) => 'profile:' + p.id === v)) add(g, v, '⚠ ' + t('lu.target.missing'));
      s.appendChild(g);
    }
    s.value = v;
    s.addEventListener('change', () => onChange(s.value));
    return s;
  }

  /**
   * The month every monthly limit follows — its calendar (the Persian month
   * or the Gregorian) and the day it renews on — shown while a monthly limit
   * is set; past the shortest month of its calendar (28, the Persian 29) the
   * note that a month without that day renews on its last one.
   */
  function monthLine(f) {
    const line = el('div', 'lu-renew');
    const note = el('div', 'lu-sub', t('lu.renewLast'));
    const paint = () => {
      const on = KINDS.some((k) => !blank(f.limits[k + ':month']));
      line.hidden = !on;
      note.hidden = !on || dayOf(f.quotaResetDay) <= (f.calendar === 'jalali' ? 29 : 28);
    };
    const cal = select(calendarChoices().map((c) => [c, t('lu.cal.' + c)]), f.calendar, t('lu.calendar'), 'f:calendar', (v) => { f.calendar = v; paint(); });
    cal.classList.add('lu-cal');
    const day = select(DAYS.map((d) => [d, String(d)]), dayOf(f.quotaResetDay), t('lu.renewDay'), 'f:renew', (v) => { f.quotaResetDay = Number(v); paint(); });
    line.append(cal, el('span', null, t('lu.renewDay')), day);
    paint();
    return { nodes: [line, note], paint };
  }

  /**
   * A cell of the limits' grid: its GB (empty: none) and, on the router, what
   * happens when it is used up — cut (the meter's hold) or slowed to a speed
   * until its period renews. The action shows once there is a limit to act.
   */
  function limitCell(f, kind, period, router, monthPaint) {
    const key = kind + ':' + period;
    const cell = el('div', 'lu-lcell');
    const label = t('lu.kind.' + kind) + ' — ' + t('lu.col.' + period) + ' (GB)';
    const n = numInput(f.limits[key], label, 'f:limit:' + key, { step: 'any', placeholder: '—' });
    cell.append(n);
    const a = f.acts[key];
    let act = null;
    let slow = null;
    const paint = () => {
      if (!act) return;
      const has = !blank(f.limits[key]);
      act.hidden = !has;
      slow.hidden = !has || a.action !== 'slow';
    };
    if (router) {
      act = select([['cut', t('lu.act.cut')], ['slow', t('lu.act.slow')]], a.action, t('lu.actLabel') + ' — ' + label, 'f:act:' + key, (v) => { a.action = v; paint(); clearErr('limits'); });
      slow = el('div', 'lu-slow');
      for (const [k, word, arrow] of [['down', 'lu.speedDown', '↓'], ['up', 'lu.speedUp', '↑']]) {
        const r = numInput(a[k], t(word) + ' — ' + label, 'f:slow:' + k + ':' + key, { step: 'any', placeholder: 'Mbps' });
        r.addEventListener('input', () => { a[k] = r.value; clearErr('limits'); });
        enterSaves(r);
        slow.append(arrowed(arrow, r));
      }
      cell.append(act, slow);
    }
    n.addEventListener('input', () => {
      f.limits[key] = n.value;
      paint();
      clearErr('limits');
      if (period === 'month') monthPaint();
    });
    enterSaves(n);
    paint();
    return cell;
  }

  /** The limits: Total / VPN / Direct × daily / monthly / one-off, then the month they follow. */
  function limitsSection(f, router) {
    const grid = el('div', 'lu-limits');
    grid.setAttribute('role', 'group');
    grid.setAttribute('aria-label', t('lu.limits'));
    grid.append(el('span', 'lu-lhead'));
    for (const p of LPERIODS) grid.append(el('span', 'lu-lhead', t('lu.col.' + p)));
    const month = monthLine(f);
    for (const kind of KINDS) {
      grid.append(el('span', 'lu-lkind', t('lu.kind.' + kind)));
      for (const period of LPERIODS) grid.append(limitCell(f, kind, period, router, month.paint));
    }
    return section('limits', t('lu.limits'), [grid, ...month.nodes], t(router ? 'lu.limitsHintRouter' : 'lu.limitsHint'));
  }

  /** The days of the week as chips, the page's week order (Saturday first in Persian); each toggles in `days` itself. */
  function dayChips(days, key, label, errKey) {
    const box = el('div', 'lu-days');
    box.setAttribute('role', 'group');
    box.setAttribute('aria-label', label);
    for (const d of WEEK[lang() === 'fa' ? 'fa' : 'en']) {
      const b = button('lu-day', t('lu.wd.' + d));
      b.dataset.lu = key + ':' + d;
      b.setAttribute('aria-pressed', String(days.includes(d)));
      b.addEventListener('click', () => {
        const i = days.indexOf(d);
        if (i > -1) days.splice(i, 1); else days.push(d);
        b.setAttribute('aria-pressed', String(i < 0));
        clearErr(errKey);
      });
      box.append(b);
    }
    return box;
  }
  /** A speed box with its arrow before it (↓ download, ↑ upload): a typed value has no placeholder left to say which. */
  function arrowed(arrow, input) {
    const box = el('label', 'lu-ratein');
    const a = el('span', 'lu-arrow', arrow);
    a.setAttribute('aria-hidden', 'true');
    box.append(a, input);
    return box;
  }
  /** From and to, as two time boxes bound to `w`; `label` names what they are the hours of. */
  function timePair(w, key, errKey, label) {
    const box = el('div', 'lu-hrs');
    const time = (k, word) => {
      const n = ltr(el('input', 'input lu-time'));
      n.type = 'time';
      n.value = w[k] || '';
      n.setAttribute('aria-label', label + ' — ' + t(word));
      n.dataset.lu = key + ':' + k;
      const take = () => { w[k] = n.value; clearErr(errKey); };
      n.addEventListener('input', take);
      n.addEventListener('change', take);
      return n;
    };
    // each word with its box: on a phone "to" wraps with its own time, not apart from it
    const pair = (k, word) => {
      const p = el('span', 'lu-hr');
      p.append(el('span', null, t(word)), time(k, word));
      return p;
    };
    box.append(pair('from', 'lu.from'), pair('to', 'lu.to'));
    return box;
  }

  /** Allowed hours: any time, or days of the week and a window (overnight when "to" comes before "from"). */
  function hoursSection(f) {
    const s = f.sched;
    const any = el('div', 'lu-switchline');
    any.append(switchEl(!s.on, t('lu.anyTime'), 'f:anytime', (v) => { s.on = !v; clearErr('schedule'); renderDialog('f:anytime'); }), el('span', null, t('lu.anyTime')));
    const nodes = [any];
    if (s.on) nodes.push(dayChips(s.days, 'f:day', t('lu.days'), 'schedule'), timePair(s, 'f:sched', 'schedule', t('lu.hours')));
    return section('schedule', t('lu.hours'), nodes, s.on ? t('lu.hoursHint') : '');
  }

  /**
   * The router's speed: a download and an upload for every hour, then up to
   * four windows of the week with their own (peak hours, or the night) — the
   * lowest of what is on at a moment applies, a 'slow' limit's with them
   * (meter.js speedOf). Empty is no limit.
   */
  function speedSection(f) {
    const rate = (src, k, key, label, placeholder) => {
      const n = numInput(src[k], label, key, { step: 'any', placeholder });
      n.addEventListener('input', () => { src[k] = n.value; clearErr('speed'); });
      enterSaves(n);
      return n;
    };
    const base = el('div', 'lu-grid');
    base.append(field(t('lu.speedDown'), rate(f.speed, 'down', 'f:speedDown', t('lu.speedDown'), t('lu.unlimited'))),
      field(t('lu.speedUp'), rate(f.speed, 'up', 'f:speedUp', t('lu.speedUp'), t('lu.unlimited'))));
    const wins = el('div', 'lu-wins');
    f.speedHours.forEach((w, i) => {
      const key = 'f:win:' + i;
      const box = el('div', 'lu-win');
      box.dataset.win = String(i);
      const top = el('div', 'lu-win-top');
      const rm = iconButton('×', t('lu.speedWinRemove'), key + ':remove', () => {
        f.speedHours.splice(i, 1);
        clearErr('speed');
        renderDialog(f.speedHours.length ? 'f:win:' + Math.max(0, i - 1) + ':remove' : 'f:winAdd');
      });
      top.append(dayChips(w.days, key + ':day', t('lu.days'), 'speed'), rm);
      const rates = el('div', 'lu-win-rates');
      rates.append(timePair(w, key, 'speed', t('lu.speed')),
        arrowed('↓', rate(w, 'down', key + ':down', t('lu.speedDown'), 'Mbps')),
        arrowed('↑', rate(w, 'up', key + ':up', t('lu.speedUp'), 'Mbps')));
      box.append(top, rates);
      wins.append(box);
    });
    const add = button('btn ghost small lu-winadd', t('lu.speedWinAdd'));
    add.dataset.lu = 'f:winAdd';
    add.disabled = f.speedHours.length >= SPEED_WINDOWS;
    add.addEventListener('click', () => {
      if (f.speedHours.length >= SPEED_WINDOWS) return;
      f.speedHours.push({ days: [0, 1, 2, 3, 4, 5, 6], from: '18:00', to: '23:00', down: '', up: '' });
      renderDialog('f:win:' + (f.speedHours.length - 1) + ':down');
    });
    // the priority: the shaper's share of the line between users (router/shaper.js) — nothing without the line's speed
    const line = cfg().shaping;
    const prio = select(PRIORITIES.map((p) => [p, t('lu.prio.' + p)]), f.priority || 'normal', t('lu.prio'), 'f:priority', (v) => { f.priority = v; clearErr('speed'); });
    const prioBox = el('div', 'lu-prio');
    prioBox.append(el('span', 'lu-sect-sub', t('lu.prio')), prio);
    const prioHint = el('div', 'lu-sub' + (!(Number(line.down) > 0 || Number(line.up) > 0) ? ' lu-bad' : ''),
      t(Number(line.down) > 0 || Number(line.up) > 0 ? 'lu.prioHint' : 'lu.prioNoLine'));
    return section('speed', t('lu.speed'), [base, el('div', 'lu-sub', t('lu.speedHint')), el('div', 'lu-sect-sub', t('lu.speedWins')), wins, add, prioBox, prioHint]);
  }

  /**
   * The content filter (every platform — xray.js puts it first among the
   * user's rules): categories to block as chips (each a geosite list),
   * safe search (the engines' safe hosts, YouTube restricted), and domains
   * of the admin's own, a line each.
   */
  function filterSection(f) {
    const ff = f.filter;
    const chips = el('div', 'lu-cats');
    chips.setAttribute('role', 'group');
    chips.setAttribute('aria-label', t('lu.flt.cats'));
    for (const c of FILTER_CATS) {
      const b = button('lu-day lu-cat', t('lu.flt.' + c));
      b.dataset.lu = 'f:cat:' + c;
      b.setAttribute('aria-pressed', String(ff.block.includes(c)));
      b.addEventListener('click', () => {
        const i = ff.block.indexOf(c);
        if (i > -1) ff.block.splice(i, 1); else ff.block.push(c);
        b.setAttribute('aria-pressed', String(i < 0));
        clearErr('filter');
      });
      chips.append(b);
    }
    // the categories are geosite lists: without the geo files they do nothing — said, when the page knows (the payload, or app.js)
    const geo = ui.data && ui.data.geo === false ? false : hook('geo');
    const noGeo = geo === false ? el('div', 'lu-sub lu-bad lu-nogeo', t('lu.flt.noGeo')) : null;
    const safe = el('div', 'lu-switchline');
    const safeWords = el('span');
    safeWords.append(el('span', 'lu-sw-t', t('lu.flt.safe')), el('span', 'lu-sub lu-sw-s', t('lu.flt.safeSub')));
    safe.append(switchEl(ff.safeSearch, t('lu.flt.safe'), 'f:safe', (v) => { ff.safeSearch = v; clearErr('filter'); }), safeWords);
    const area = ltr(el('textarea', 'input lu-domains'));
    area.value = ff.domains;
    area.rows = 4;
    area.placeholder = 'example.com\nfull:www.example.com\nkeyword:casino';
    area.setAttribute('aria-label', t('lu.flt.domains'));
    area.setAttribute('spellcheck', 'false');
    area.setAttribute('autocapitalize', 'none');
    area.dataset.lu = 'f:domains';
    if (f.errors.filter) area.setAttribute('aria-invalid', 'true');
    area.addEventListener('input', () => { ff.domains = area.value; area.removeAttribute('aria-invalid'); clearErr('filter'); });
    // safe search rides a freedom outbound dialing through the user's config — a group (a balancer) cannot be dialed through
    const group = el('div', 'lu-sub lu-bad lu-safegroup', t('lu.flt.safeGroup'));
    ui.safeGroupPaint = () => { group.hidden = !isGroupTarget(f.target); };
    ui.safeGroupPaint();
    const ex = el('div', 'lu-fltex');
    for (const [code, words] of [['example.com', 'lu.flt.ex.domain'], ['full:www.example.com', 'lu.flt.ex.full'], ['keyword:casino', 'lu.flt.ex.keyword']]) {
      ex.append(ltr(el('code', 'lu-mono lu-fltex-c', code)), el('span', 'lu-fltex-w', t(words)));
    }
    return section('filter', t('lu.flt'), [el('div', 'lu-sect-sub', t('lu.flt.cats')), chips, noGeo, safe, group, el('div', 'lu-sect-sub', t('lu.flt.domains')), area, ex], t('lu.flt.hint'));
  }
  /** A config that is a group (several configs as one, a balancer): app.js's picker lists it in its 'groups' pile. */
  function isGroupTarget(v) {
    if (!v || SPECIAL.includes(String(v))) return false;
    return arr(hook('targets')).some((o) => o && String(o.value) === String(v) && o.pile && o.pile.key === 'groups');
  }

  /** The dialog, drawn from ui.form — every box writes there as it is typed in, so a redraw loses nothing; `focusKey` gets the focus after. */
  function renderDialog(focusKey) {
    const f = ui.form;
    if (!f || !ui.modal) return;
    const router = isRouter();
    const modal = el('div', 'modal lu-modal');
    modal.setAttribute('role', 'dialog');
    modal.setAttribute('aria-modal', 'true');
    modal.setAttribute('aria-labelledby', 'luModalTitle');

    const head = el('div', 'modal-head');
    const ico = el('span', 'lu-av', '👤');
    ico.setAttribute('aria-hidden', 'true');
    const title = el('span', 'modal-title', t(f.id ? 'lu.editTitle' : 'lu.newTitle'));
    title.id = 'luModalTitle';
    const x = button('tb-btn', '✕');
    x.setAttribute('aria-label', t('tb.close'));
    x.title = t('tb.close');
    x.dataset.lu = 'f:close';
    x.addEventListener('click', () => closeDialog());
    head.append(ico, title, x);

    const body = el('div', 'modal-body lu-form');
    const two = el('div', 'lu-grid');
    two.append(
      formField('name', t('lu.name'), [formInput('name', t('lu.name'), { placeholder: t('lu.namePh') })]),
      formField('username', t('lu.username'), [formInput('username', t('lu.username'), { dir: 'ltr', placeholder: 'sara' })], t('lu.usernameHint'))
    );
    body.append(two);

    const pw = el('div', 'lu-pwrow');
    const pass = formInput('password', t('lu.password'), { type: f.showPass ? 'text' : 'password', dir: 'ltr' });
    const eye = iconButton(f.showPass ? '🙈' : '👁', t(f.showPass ? 'lu.hide' : 'lu.show'), 'f:show', () => {
      f.showPass = !f.showPass;
      pass.type = f.showPass ? 'text' : 'password';
      eye.textContent = f.showPass ? '🙈' : '👁';
      eye.setAttribute('aria-label', t(f.showPass ? 'lu.hide' : 'lu.show'));
      eye.title = eye.getAttribute('aria-label');
      eye.setAttribute('aria-pressed', String(f.showPass));
    });
    eye.setAttribute('aria-pressed', String(!!f.showPass));
    const gen = iconButton('↻', t('lu.generate'), 'f:gen', () => {
      f.password = genPassword();
      f.showPass = true;
      delete f.errors.password;
      renderDialog();
    });
    pw.append(pass, eye, gen);
    body.append(formField('password', t('lu.password'), [pw], t('lu.passwordHint')));

    // the config, and the routing it follows — nothing to route when it is direct or blocked
    const route = el('div', 'lu-grid');
    const plain = (v) => v === 'direct' || v === 'block';
    const routing = routingPicker(f.routing, 'f:routing', (v) => { f.routing = v; clearErr('routing'); });
    routing.disabled = plain(f.target);
    route.append(
      formField('target', t('lu.target'), [targetPicker(f.target, t('lu.target'), 'f:target', (v) => {
        f.target = v;
        routing.disabled = plain(v);
        if (ui.safeGroupPaint) ui.safeGroupPaint();
      })]),
      formField('routing', t('lu.routing'), [routing], t('lu.routingHint'))
    );
    body.append(route, limitsSection(f, router));

    const when = el('div', 'lu-grid');
    const date = formInput('expires', t('lu.expires'), { type: 'date', dir: 'ltr' });
    date.classList.add('lu-date');
    const words = el('div', 'lu-sub', expiryWords(fromDayInput(f.expires)).text);
    date.addEventListener('change', () => { f.expires = date.value; words.textContent = expiryWords(fromDayInput(f.expires)).text; });
    date.addEventListener('input', () => { words.textContent = expiryWords(fromDayInput(date.value)).text; });
    when.append(formField('expires', t('lu.expires'), [date, words]));
    const on = el('div', 'lu-switchline');
    on.append(switchEl(f.enabled, t('lu.enable'), 'f:enabled', (v) => { f.enabled = v; }), el('span', null, t('lu.enable')));
    if (router) {
      const max = formInput('maxDevices', t('lu.maxDevices'), { type: 'number', dir: 'ltr', placeholder: '0' });
      max.min = '0';
      when.append(formField('maxDevices', t('lu.maxDevices'), [max], t('lu.maxDevicesHint')));
      body.append(when, hoursSection(f), speedSection(f), filterSection(f));
      // a device that signs in as this user stays theirs (never a voucher's: a code is for a while, not a person)
      if (!f.voucher && f.remember != null) {
        const rem = switchRow(t('lu.rem'), t('lu.remSub'), !!f.remember, 'f:remember', (v) => { f.remember = v; });
        rem.classList.add('lu-remrow');
        body.append(rem);
      }
      body.append(on);
    } else {
      when.append(on);
      // a speed limit is the router's (nft): the desktop's Xray has none per user — said where it would be
      body.append(when, hoursSection(f), filterSection(f), el('p', 'lu-note lu-speednote', t('lu.speedRouter')));
    }
    if (f.error) {
      const e = el('p', 'lu-formerr', f.error);
      e.setAttribute('role', 'alert');
      body.append(e);
    }

    const foot = el('div', 'modal-foot');
    if (f.id) {
      const del = button('btn danger ghost lu-del', t('lu.delete'));
      del.dataset.lu = 'f:delete';
      del.disabled = f.saving;
      del.addEventListener('click', () => removeUser(f.id));
      foot.append(del);
    }
    const save = button('btn primary', t('lu.save'));
    save.dataset.lu = 'f:save';
    save.disabled = f.saving;
    save.setAttribute('aria-busy', String(!!f.saving));
    save.addEventListener('click', () => submitDialog());
    const cancel = button('btn ghost', t('btn.cancel'));
    cancel.dataset.lu = 'f:cancel';
    cancel.addEventListener('click', () => closeDialog());
    foot.append(save, cancel);

    modal.append(head, body, foot);
    ui.modal.replaceChildren(modal);
    if (focusKey) {
      const n = findKey(ui.modal, focusKey);
      if (n && !n.disabled && n.focus) n.focus();
    }
  }

  /** Where the focus goes for a broken rule: the field's own box, or its section's first. */
  const ERR_FOCUS = { limits: 'f:limit:total:day', schedule: 'f:anytime', speed: 'f:speedDown', routing: 'f:routing', filter: 'f:domains', priority: 'f:priority' };
  /** The service's refusals that belong under a field of the dialog (ipc.js codes); the priority's is the speed panel's. */
  const FIELD_CODES = ['limits', 'routing', 'schedule', 'speed', 'filter', 'priority'];
  const FIELD_OF = { priority: 'speed' };

  /** Save: checked here first (each broken rule under its field), then the service — its refusal said in the dialog, which stays open. */
  async function submitDialog() {
    const f = ui.form;
    if (!f || f.saving) return false;
    f.errors = validate(f, users().filter((u) => u.id !== f.id));
    f.error = '';
    const bad = Object.keys(f.errors);
    if (bad.length) {
      renderDialog();
      const n = findKey(ui.modal, ERR_FOCUS[bad[0]] || 'f:' + bad[0]);
      if (n && n.focus) n.focus();
      return false;
    }
    const user = toUser(f);
    f.saving = true;
    renderDialog();
    try {
      const res = await window.api.lanUsersUser({ op: f.id ? 'update' : 'add', user });
      checkAnswer(res);
      ui.seq++;     // a read on its way predates this user
      if (!take(res)) refresh();
      Promise.resolve(hook('applied', res)).catch(() => {});
      if (ui.form === f) closeDialog();
      render();
      toast(fill(t(f.id ? 'lu.saved' : 'lu.added'), { name: user.name || user.username }), 'ok');
      return true;
    } catch (e) {
      if (ui.form !== f) return false;
      f.saving = false;
      const k = errKey(e);
      // the service's own refusal of a field goes where that field is: the username, the limits, the hours, the filter…
      const where = /^username/i.test(k) ? 'username' : FIELD_CODES.includes(k) ? (FIELD_OF[k] || k) : '';
      // …in the words of its detail where there are some ('lu.err.filter.domain')
      const exact = e && e.detail && /^\w+$/.test(e.detail) && t('lu.err.' + k + '.' + e.detail) !== 'lu.err.' + k + '.' + e.detail ? 'lu.err.' + k + '.' + e.detail : '';
      if (where && (exact || t('lu.err.' + k) !== 'lu.err.' + k)) f.errors[where] = exact || 'lu.err.' + k;
      else f.error = t('lu.saveFailed') + ': ' + errText(e);
      renderDialog();
      return false;
    }
  }

  /* ------------------------------ app.js's hooks ------------------------------ */

  /** The page's box and app.js's hooks; on a back end without the channels the page and its nav item stay hidden. */
  function mount(host, hooks) {
    ui.host = host || null;
    ui.hooks = hooks || {};
    if (!ui.host) return;
    if (!window.api || !window.api.lanUsersGet) {
      ui.host.hidden = true;
      const nav = document.querySelector ? document.querySelector('.nav-item[data-view="users"]') : null;
      if (nav) nav.hidden = true;
      return;
    }
    render();
  }

  /**
   * A stats tick: `s.lanUsers` ({ live, usage }) when the service sends it —
   * repainted in place; and while the page is open, a quiet read every few
   * seconds for what only lanusers:get knows (who is online, their rates).
   */
  function tick(d) {
    if (!ui.host || !ui.data) return;
    if (d && typeof d === 'object') {
      const before = shape();
      if (d.live && typeof d.live === 'object') ui.data.live = Object.assign({}, d.live);
      if (d.usage && typeof d.usage === 'object') Object.assign(ui.data.usage, d.usage);
      // a hold that began or lifted (a limit reached, the hours over) changes the box's pill: drawn again
      if (shape() !== before) render(); else paintLive();
    }
    if (!hook('visible')) return;
    if (Date.now() - ui.lastRefresh < REFRESH_MS) return;
    refresh({ quiet: true });
  }

  /** Connected or not: the live rates and the "while connected" line come and go with it. */
  function connection(on) {
    if (!on && ui.data) ui.data.live = {};
    if (!ui.host) return;
    if (!!on !== ui.wasConnected) { render(); return; }
    paintLive();
  }

  /**
   * The page's own pieces for luVouchers.js (the Vouchers tab) and
   * luReports.js (a user's 12 months, CSV, statement) — the contract's §8:
   * the words, the drawing helpers (text nodes only, as here), the channels
   * (invoke: the answer as it came, a refusal `{ ok: false, error, detail }`
   * said in a toast unless `{ quiet: true }`; an answer with the payload drawn),
   * the payload and its users split in two (people / vouchers), the sign-in
   * page's address. Beyond the contract's list, what a panel of the page's
   * kind needs: the formats (the Persian calendar in Persian), the pickers,
   * copy / toast / confirm, the QR and the print of a sheet.
   */
  const kit = {
    t,
    el,
    button,
    select,
    field,
    ltr,
    switchEl,
    fmtBytes: bytesText,
    invoke,
    refresh: (opts) => refresh(opts),
    data: () => ui.data,
    users: () => people(),
    vouchers: () => vouchers(),
    /** The router's sign-in page: { url, nameUrl } (plain http addresses), or null while it is down / not the router's. */
    portal: () => (ui.data ? ui.data.portal : null),
    // beyond the contract's list
    fill,
    tpl,
    lang,
    isRouter,
    isVoucher,
    nameOf,
    errText,
    usageOf,
    numInput,
    iconButton,
    targetPicker,
    routingPicker,
    copy,
    toast,
    /**
     * A question with a yes: app.js's own (window.confirm in both windows) —
     * its answer as it comes: a boolean at once (luVouchers.js reads it so;
     * `await` takes it too), a promise of one from an asynchronous hook.
     */
    confirm: (msg) => {
      const v = ui.hooks.confirm ? hook('confirm', msg) : window.confirm(msg);
      return v && typeof v.then === 'function' ? Promise.resolve(v).then((x) => !!x, () => false) : !!v;
    },
    /** The configs a user can ride, as the picker lists them: [{ value, label, pile? }] — current, direct, blocked, then every config. */
    targets: () => targetOptions('').map((o) => Object.assign({}, o, { value: String(o.value), label: String(o.label) })),
    /** The app's routing profiles: [{ id, name }]. */
    routingProfiles: () => profiles(),
    qrImage,
    printSheet,
    sheetLine,
    download,
    withUser,
    format: { bytesText, dateText, fullDate, dayInput, fromDayInput, gbText, mbpsText, kbpsOf, rateWord, whenText, clock, date: format }
  };
  window.LanUsersKit = kit;

  window.lanUsersPage = {
    mount,
    refresh,
    render,
    tick,
    connection,
    open: openDialog,
    close: closeDialog,
    share: openShare,
    closeShare,
    topUp: openTopUp,
    closeTopUp,
    card: openCard,
    closeCard,
    restore: openRestore,
    closeRestore,
    backup,
    tab: setTab,
    shareLink,
    loaded: () => !!ui.data,
    validate,
    domainLines,
    format: { bytesText, dateText, fullDate, dayInput, fromDayInput, hostPort, mbpsText, kbpsOf, rateWord, whenText },
    genPassword
  };
})();
