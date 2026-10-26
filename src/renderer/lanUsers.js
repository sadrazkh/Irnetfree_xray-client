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
 *      with their username and password, the transparent mode is the router's;
 *   2. a box per user: who, whether they can connect now (on / off / expired /
 *      at the cap), their live rate while connected, the password (hidden; show,
 *      copy, a new one), the config they ride (the app's own picker — every
 *      config by its subscription — plus the current connection, direct and
 *      blocked), the cap with this period's usage bar and when the period ends,
 *      the expiry (its date in the Persian calendar in Persian), on the router
 *      how many devices, and the on/off switch; one dialog adds and edits a
 *      user and says where the username and password rules are broken;
 *   3. on the router the devices — online first, each with its name, IP and MAC
 *      (left to right in Persian too), the user it belongs to, a block switch
 *      and its usage.
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
  const PERIODS = ['month', 'day', 'none'];
  const UNASSIGNED = ['login', 'allow', 'block'];
  const SPECIAL = ['', 'direct', 'block'];        // the targets that are not a config
  const NEAR = 0.8;                               // from here the usage bar warns that the cap is close
  const REFRESH_MS = 5000;                        // while the page is open, a stats tick reads it again this often at most
  const USERNAME = /^[A-Za-z0-9._-]{1,32}$/;      // the contract's rule (model.js validateUser)
  const PASS_MIN = 4;
  // a new password: ten of these — no 0/O, 1/l/I, said aloud or typed on a phone without a mix-up
  const PASS_CHARS = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const PASS_LEN = 10;
  const EMPTY = {
    proxy: { enabled: false, port: 30820, httpPort: 30821 },
    transparent: { enabled: false, unassigned: 'login', sessionHours: 24, portalPort: 30822 }
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

  /* ------------------------------ state ------------------------------ */

  const ui = {
    host: null,
    hooks: {},        // app.js: { applied(res), connected(), targets(), picker(o), platform(), router(), visible(), copy(text), confirm(msg), toast(msg, kind) }
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
      config: { proxy: Object.assign({}, EMPTY.proxy, obj(c.proxy)), transparent: Object.assign({}, EMPTY.transparent, obj(c.transparent)) },
      users: arr(r.users).filter((u) => u && u.id),
      devices: arr(r.devices).filter((d) => d && d.mac).map((d) => Object.assign({}, d, { mac: String(d.mac).toLowerCase() })),
      usage: Object.assign({}, obj(r.usage)),
      live: Object.assign({}, obj(r.live)),
      online: Object.fromEntries(Object.entries(obj(r.online)).map(([mac, o]) => [String(mac).toLowerCase(), obj(o)])),
      deviceUsage: Object.fromEntries(Object.entries(obj(r.deviceUsage)).map(([mac, v]) => [String(mac).toLowerCase(), v])),
      platform: String(r.platform || ''),
      lanAddresses: arr(r.lanAddresses).filter((a) => typeof a === 'string' && a)
    };
  }
  /** Take an answer that carries the payload; a bare `{ ok: true }` leaves the page as it is. */
  function take(res) {
    const r = obj(res);
    if (!('users' in r) && !('config' in r)) return false;
    ui.data = normalize(r);
    return true;
  }

  const cfg = () => (ui.data ? ui.data.config : clone(EMPTY));
  const users = () => (ui.data ? ui.data.users : []);
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

  /** Whether a user can connect now: off, expired, at its cap this period, or on. */
  function stateOf(u, now = Date.now()) {
    if (!u.enabled) return 'off';
    if (Number(u.expiresAt) > 0 && Number(u.expiresAt) <= now) return 'expired';
    const us = usageOf(u.id);
    if (us && us.over) return 'over';
    return 'on';
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

  /** An answer that refuses: `{ ok: false, error }` is an error like a thrown one. */
  function checkAnswer(res) {
    if (res && typeof res === 'object' && res.ok === false) throw new Error(res.error || res.code || 'refused');
  }
  /** A refusal in words: a key the core answers ('usernameTaken', 'lu.err.password') in the page's language, else as it came. */
  function errText(e) {
    const msg = String((e && e.message) || e || '');
    for (const k of [msg, 'lu.err.' + msg]) if (/^lu\.err\.\w+$/.test(k) && t(k) !== k) return t(k);
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

  /* ------------------------------ reading ------------------------------ */

  /** What decides the page's layout — a read that changes none of it repaints the numbers in place. */
  function shape() {
    if (!ui.data) return '';
    const d = ui.data;
    const online = Object.entries(d.online).map(([mac, o]) => [mac, o.ip || '', o.hostname || '', o.userId || '']).sort();
    return JSON.stringify([d.config, d.users, d.devices, d.platform, d.lanAddresses, online,
      d.users.map((u) => !!(d.usage[u.id] && d.usage[u.id].over)), d.users.map((u) => stateOf(u))]);
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

  /** A user's usage bar and its two lines — a stats tick repaints them, the controls stay put. */
  function paintUsage(d, u) {
    const bytes = u ? Number(u.bytes) || 0 : 0;
    const cap = u ? Number(u.quotaBytes) || 0 : 0;
    const ratio = cap > 0 ? Math.min(1, bytes / cap) : 0;
    const over = cap > 0 && (ratio >= 1 || !!(u && u.over));
    d.bar.hidden = !(cap > 0);
    d.fill.style.width = (ratio * 100).toFixed(1) + '%';
    d.fill.className = over ? 'over' : ratio >= NEAR ? 'warn' : '';
    d.bar.setAttribute('aria-valuenow', String(Math.round(ratio * 100)));
    const map = { used: bytesText(bytes), cap: bytesText(cap), date: dateText(u && u.until) };
    if (cap > 0) {
      d.left.textContent = fill(t(over ? 'lu.usedOver' : ratio >= NEAR ? 'lu.usedNear' : 'lu.usedOf'), map);
      d.right.textContent = over ? (map.date ? fill(t('lu.backOn'), map) : '') : ratio >= NEAR ? t('lu.atCap') : (map.date ? fill(t('lu.until'), map) : '');
    } else {
      d.left.textContent = fill(t('lu.used'), map);
      const p = String((u && u.period) || '');
      d.right.textContent = p.length === 10 ? t('lu.today') : p.length === 7 ? t('lu.thisMonth') : '';
    }
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
    for (const [id, d] of Object.entries(ui.dom.usage)) paintUsage(d, usageOf(id));
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
        row.append(el('span', 'lu-proto', proto), value, b);
        box.append(row);
      }
    }
    return box;
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
      card.append(tb);
    } else {
      // a Windows PC's hotspot is the usual way a desktop shares: the same proxy, the same accounts
      card.append(el('p', 'lu-note' + (isWin() ? ' lu-hotspot' : ''), t(isWin() ? 'lu.hotspot' : 'lu.desktopNote')));
    }
    return card;
  }

  /* ------------------------------ drawing: the users ------------------------------ */

  function capControls(u, label) {
    const box = el('div', 'lu-field');
    const pair = el('div', 'lu-cap');
    const period = PERIODS.includes(u.quotaPeriod) ? u.quotaPeriod : 'none';
    const num = numInput(u.quotaGb ? u.quotaGb : '', t('lu.capGb') + ' — ' + label, 'quota:' + u.id, { step: 'any', placeholder: '0' });
    num.disabled = period === 'none';
    num.addEventListener('change', () => {
      const v = Number(num.value);
      saveUser(u.id, { quotaGb: Number.isFinite(v) && v > 0 ? v : 0 });
    });
    pair.append(num, select(PERIODS.map((p) => [p, t('lu.period.' + p)]), period, t('lu.cap') + ' — ' + label, 'period:' + u.id, (v) => saveUser(u.id, { quotaPeriod: v })));
    const bar = el('div', 'lu-bar');
    bar.setAttribute('role', 'progressbar');
    bar.setAttribute('aria-valuemin', '0');
    bar.setAttribute('aria-valuemax', '100');
    bar.setAttribute('aria-label', t('lu.cap') + ' — ' + label);
    const fillEl = el('i');
    bar.append(fillEl);
    const q = el('div', 'lu-quota');
    const left = el('span');
    const right = el('span');
    q.append(left, right);
    const d = { bar, fill: fillEl, left, right };
    ui.dom.usage[u.id] = d;
    paintUsage(d, usageOf(u.id));
    box.append(el('div', 'field-label', t('lu.cap')), pair, bar, q);
    return box;
  }

  /** The expiry: a date box, its day in words (the Persian calendar in Persian), and a way back to never. */
  function expiryWords(ms) {
    if (!(Number(ms) > 0)) return { text: t('lu.never'), bad: false };
    const date = fullDate(ms);
    return Number(ms) <= Date.now() ? { text: fill(t('lu.expiredOn'), { date }), bad: true } : { text: fill(t('lu.expiresOn'), { date }), bad: false };
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
    return field(t('lu.expires'), line, el('div', 'lu-sub' + (w.bad ? ' lu-bad' : ''), w.text));
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
    const box = el('div', 'lu-user' + (st === 'on' ? '' : ' lu-dim'));
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
    head.append(av, who, el('span', 'lu-state lu-s-' + st, t('lu.state.' + st)));
    const n = router ? onlineOf(u.id) : 0;
    if (n) head.append(el('span', 'lu-tag', fill(t('lu.online'), { n: String(n) })));
    const acts = el('div', 'lu-acts');
    const del = iconButton('🗑', t('lu.delete') + ' — ' + label, 'delete:' + u.id, () => removeUser(u.id));
    del.classList.add('danger');
    acts.append(
      switchEl(!!u.enabled, t('lu.enable') + ' — ' + label, 'enabled:' + u.id, (on) => saveUser(u.id, { enabled: on })),
      iconButton('✎', t('lu.edit') + ' — ' + label, 'edit:' + u.id, () => openDialog(u.id)),
      del);
    head.append(acts);

    const ctl = el('div', 'lu-ctl');
    ctl.append(
      passwordControls(u, label),
      field(t('lu.target'), targetPicker(u.target, t('lu.target') + ' — ' + label, 'target:' + u.id, (v) => saveUser(u.id, { target: v }))),
      capControls(u, label),
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
    box.append(head, ctl);
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
    card.append(blockHead(t('lu.list'), ui.data ? fill(t('lu.count'), { n: String(users().length) }) : '', add));
    if (!ui.data) {
      card.append(el('p', 'hint', ui.error ? t('lu.loadFailed') + ': ' + ui.error : t('lu.loading')));
    } else if (!users().length) {
      card.append(el('div', 'empty', t('lu.none')));
    } else {
      const list = el('div', 'lu-list');
      for (const u of users()) list.append(userRow(u));
      card.append(list);
    }
    return card;
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

    const userPairs = [['', t('lu.dev.unassigned')], ...users().map((u) => [u.id, pickLabel(u)])];
    if (d.userId && !users().some((u) => u.id === d.userId)) userPairs.push([d.userId, '⚠ ' + t('lu.target.missing')]);
    const userCell = el('div', 'lu-dcell');
    userCell.append(select(userPairs, d.userId || '', t('lu.dev.user') + ' — ' + label, 'devuser:' + d.mac, (v) => setDevice(d.mac, { userId: v })));
    // what a device nobody has gets, said on its row (only where the transparent mode decides it)
    if (d.blocked) userCell.append(el('div', 'lu-sub lu-bad', t('lu.dev.blocked')));
    else if (!d.userId && transparent) userCell.append(el('div', 'lu-sub' + (policy === 'block' ? ' lu-bad' : ''), t('lu.unassigned.' + policy)));

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
    const parts = [el('p', 'hint lu-intro', t('lu.intro')), settingsCard(), usersCard()];
    if (isRouter()) parts.push(devicesCard());
    host.replaceChildren(...parts);
    if (focusKey) {
      const n = findKey(host, focusKey);
      if (n && !n.disabled && n.focus) n.focus();
    }
  }

  /* ------------------------------ the add / edit dialog ------------------------------ */

  /**
   * The rules the service keeps (model.js validateUser), said before it is
   * asked: a username of English letters, digits, dot, dash or underscore, 1 to
   * 32 of them, no other user's (case aside: «Ali» and «ali» are one person on
   * a phone keyboard); a password of 4 characters or more, kept as typed; a cap
   * and a device count that are numbers. → { field: i18n key }.
   */
  function validate(f, others) {
    const e = {};
    const username = String(f.username || '').trim();
    if (!USERNAME.test(username)) e.username = 'lu.err.username';
    else if (arr(others).some((u) => String(u.username || '').toLowerCase() === username.toLowerCase())) e.username = 'lu.err.usernameTaken';
    if (String(f.password == null ? '' : f.password).length < PASS_MIN) e.password = 'lu.err.password';
    const q = String(f.quotaGb == null ? '' : f.quotaGb).trim();
    if (q !== '' && !(Number.isFinite(Number(q)) && Number(q) >= 0)) e.quotaGb = 'lu.err.quota';
    const m = String(f.maxDevices == null ? '' : f.maxDevices).trim();
    if (m !== '' && !/^\d+$/.test(m)) e.maxDevices = 'lu.err.maxDevices';
    return e;
  }

  /** The dialog's fields → the user the service stores (its other fields, if any, kept). */
  function toUser(f) {
    const old = f.id ? users().find((u) => u.id === f.id) : null;
    const q = String(f.quotaGb == null ? '' : f.quotaGb).trim();
    const m = String(f.maxDevices == null ? '' : f.maxDevices).trim();
    const user = Object.assign({}, old || {}, {
      username: String(f.username).trim(),
      password: String(f.password),
      name: String(f.name || '').trim(),
      target: f.target || '',
      quotaGb: q === '' ? 0 : Number(q),
      quotaPeriod: PERIODS.includes(f.quotaPeriod) ? f.quotaPeriod : 'none',
      expiresAt: fromDayInput(f.expires),
      maxDevices: m === '' ? 0 : Number(m),
      enabled: !!f.enabled
    });
    if (f.id) user.id = f.id; else delete user.id;   // a new one gets its id from the service (model.js newUserId)
    return user;
  }

  function openDialog(id) {
    if (!ui.data) return false;
    const u = id ? users().find((x) => x.id === id) : null;
    if (id && !u) return false;
    ui.opener = document.activeElement || null;
    ui.form = u
      ? { id: u.id, name: u.name || '', username: u.username || '', password: u.password || '', target: u.target || '',
        quotaGb: u.quotaGb ? String(u.quotaGb) : '', quotaPeriod: PERIODS.includes(u.quotaPeriod) ? u.quotaPeriod : 'none',
        expires: dayInput(u.expiresAt), maxDevices: u.maxDevices ? String(u.maxDevices) : '', enabled: u.enabled !== false,
        showPass: false, errors: {}, error: '', saving: false }
      // a new user: a password ready (shown — the admin reads it out), the current connection, a monthly count
      : { id: '', name: '', username: '', password: genPassword(), target: '', quotaGb: '', quotaPeriod: 'month', expires: '',
        maxDevices: '', enabled: true, showPass: true, errors: {}, error: '', saving: false };
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
    if (ui.modal && ui.modal.parentNode) ui.modal.parentNode.removeChild(ui.modal);
    const back = ui.opener;
    ui.opener = null;
    // the button that opened it, when it is still on the page (an edit redraws the list)
    if (back && back.dataset && back.dataset.lu && ui.host) {
      const again = findKey(ui.host, back.dataset.lu);
      if (again && again.focus) again.focus();
    }
  }

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
      if (f.errors[key]) {
        delete f.errors[key];
        n.removeAttribute('aria-invalid');
        const e = findBy(ui.modal, (c) => c.dataset && c.dataset.err === key);
        if (e) e.textContent = '';
      }
    });
    n.addEventListener('keydown', (e) => { if (e && e.key === 'Enter') { if (e.preventDefault) e.preventDefault(); submitDialog(); } });
    return n;
  }

  function renderDialog() {
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

    body.append(formField('target', t('lu.target'), [targetPicker(f.target, t('lu.target'), 'f:target', (v) => { f.target = v; })]));

    const capRow = el('div', 'lu-grid');
    const pair = el('div', 'lu-cap');
    const q = formInput('quotaGb', t('lu.capGb'), { type: 'number', dir: 'ltr', placeholder: '0' });
    q.min = '0';
    q.step = 'any';
    q.disabled = f.quotaPeriod === 'none';
    pair.append(q, select(PERIODS.map((p) => [p, t('lu.period.' + p)]), f.quotaPeriod, t('lu.cap'), 'f:period', (v) => { f.quotaPeriod = v; q.disabled = v === 'none'; }));
    const date = formInput('expires', t('lu.expires'), { type: 'date', dir: 'ltr' });
    date.classList.add('lu-date');
    const words = el('div', 'lu-sub', expiryWords(fromDayInput(f.expires)).text);
    date.addEventListener('change', () => { f.expires = date.value; words.textContent = expiryWords(fromDayInput(f.expires)).text; });
    date.addEventListener('input', () => { words.textContent = expiryWords(fromDayInput(date.value)).text; });
    capRow.append(formField('quotaGb', t('lu.cap'), [pair]), formField('expires', t('lu.expires'), [date, words]));
    body.append(capRow);

    const last = el('div', 'lu-grid');
    if (router) {
      const max = formInput('maxDevices', t('lu.maxDevices'), { type: 'number', dir: 'ltr', placeholder: '0' });
      max.min = '0';
      last.append(formField('maxDevices', t('lu.maxDevices'), [max], t('lu.maxDevicesHint')));
    }
    const on = el('div', 'lu-switchline');
    on.append(switchEl(f.enabled, t('lu.enable'), 'f:enabled', (v) => { f.enabled = v; }), el('span', null, t('lu.enable')));
    last.append(on);
    body.append(last);
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
  }

  /** Save: checked here first (each broken rule under its field), then the service — its refusal said in the dialog, which stays open. */
  async function submitDialog() {
    const f = ui.form;
    if (!f || f.saving) return false;
    f.errors = validate(f, users().filter((u) => u.id !== f.id));
    f.error = '';
    const bad = Object.keys(f.errors);
    if (bad.length) {
      renderDialog();
      const n = findKey(ui.modal, 'f:' + bad[0]);
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
      // the service's own username refusal goes where the username is
      if (/^username/i.test(k) && t('lu.err.' + k) !== 'lu.err.' + k) f.errors.username = 'lu.err.' + k;
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
      if (d.live && typeof d.live === 'object') ui.data.live = Object.assign({}, d.live);
      if (d.usage && typeof d.usage === 'object') Object.assign(ui.data.usage, d.usage);
      paintLive();
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

  window.lanUsersPage = {
    mount,
    refresh,
    render,
    tick,
    connection,
    open: openDialog,
    close: closeDialog,
    loaded: () => !!ui.data,
    validate,
    format: { bytesText, dateText, fullDate, dayInput, fromDayInput, hostPort },
    genPassword
  };
})();
