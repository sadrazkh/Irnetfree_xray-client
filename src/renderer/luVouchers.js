'use strict';
/**
 * «کارت‌ها» / Vouchers — the Users page's second tab (lanUsers.js mounts
 * `LuVouchers.panel(kit)` there): one-time codes a guest types on the router's
 * sign-in page instead of a username and password, made in batches and
 * printed as cards.
 *
 * A voucher is an ordinary user record (model.js §1): username and password
 * both the code ('XXXX-XXXX'), `voucher: { batch, hours, activatedAt }`, its
 * data amount — when it has one — a one-off Total limit, `maxDevices` devices.
 * Its time runs from its first use: the router writes activatedAt and, with
 * hours, expiresAt at the first sign-in (or the first bytes counted anywhere),
 * and the expiry the page already knows holds it from then on. So the states
 * here are the record's and the meter's, said the core's way (voucherState):
 *   unused   never signed in (activatedAt 0)
 *   used     its one-off amount is spent (the meter's total:none is over)
 *   expired  its time is up (expiresAt passed)
 *   active   the rest
 *
 * The tab, top to bottom, drawn with text nodes only (codes, labels and
 * config names are data):
 *   1. "New batch": how many, the time (with the usual lengths as chips), the
 *      data, devices per card, the config and routing every card rides, a
 *      label, on the router a speed — checked here with the core's limits
 *      before `lanusers:user { op: 'vouchers' }` is asked;
 *   2. the batches, newest first: label, when made, the counts by state, and
 *      Print (the unused cards), Codes (each code with its state and its time
 *      or data left, a copy button), Delete unused, Delete batch — the last
 *      two `lanusers:user { op: 'deleteBatch' }` after asking.
 * Printing puts cards on A4 — eight to a page with cut lines, each the code
 * large, its time and data, the sign-in page's address and a QR of that
 * address with `?code=<code>` (the page fills the code in); the card's words
 * Persian with English beneath, like the wall sheet, whatever the window's
 * language — a guest reads them, not the admin.
 *
 * Built on window.LanUsersKit (lanUsers.js): its words, bytes, data, invoke
 * and refresh; the parts it may not have (a config picker, routing profiles,
 * confirm, toast, copy) have plain stand-ins here. The form's values, the
 * open batches and the last answer live in this file, so the page may build
 * the tab again on every redraw and nothing typed is lost.
 */
(function (root, factory) {
  const api = factory(root);
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.LuVouchers = api;
}(typeof window !== 'undefined' ? window : (typeof self !== 'undefined' ? self : this), function (root) {
  // the core's limits (ipc.js op 'vouchers', model.js): said here before it is asked
  const COUNT_MAX = 200;
  const HOURS_MAX = 8760;
  const GB_MAX = 1000000;
  const DEVICES_MAX = 1000;
  const NAME_MAX = 64;
  const KBPS_MAX = 10000000;
  const PER_PAGE = 8;                               // cards on an A4 page: two columns of four
  const PRESETS = [1, 2, 24, 168, 720];             // the usual times: an hour, two, a day, a week, 30 days
  const STATES = ['unused', 'active', 'used', 'expired'];
  const SPECIAL = ['', 'direct', 'block'];          // the targets that are not a config (lanUsers.js)

  /**
   * The card's words: Persian, English beneath — the same two languages as the
   * sign-in page and the wall sheet (lanUsers.js SHEET), whatever the window's.
   */
  const CARD = {
    title: ['کارت اینترنت', 'Internet card'],
    portal: ['کد را در صفحهٔ ورود بزنید یا QR را اسکن کنید:', 'Type the code on the sign-in page, or scan the QR:'],
    portalNoQr: ['این کد را در صفحهٔ ورود بزنید.', 'Enter this code on the sign-in page.'],
    proxy: ['نام کاربری و رمز: همین کد', 'Username and password: this code'],
    fromFirst: ['از اولین ورود', 'from the first sign-in'],
    noTime: ['بدون محدودیتِ زمان', 'no time limit'],
    noData: ['بدون سقفِ حجم', 'no data cap']
  };

  const ui = {
    kit: null,
    root: null,         // the tab's element as last built (panel)
    form: null,         // the new batch's fields as typed (strings)
    errors: {},         // field → i18n key
    formError: '',      // the core's refusal, or the form's own (neither time nor data)
    notice: '',         // the last batch made
    busy: false,        // an answer is on its way
    open: {},           // batch id → its codes shown
    made: {},           // batch id → when this window made it (a record of before carries no date)
    fresh: ''           // the batch just made: marked
  };

  /* ------------------------------ the page around it ------------------------------ */

  const kit = () => ui.kit || (root && root.LanUsersKit) || null;
  const doc = () => (root && root.document) || (typeof document !== 'undefined' ? document : null);
  function t(key) {
    const k = kit();
    if (k && typeof k.t === 'function') return k.t(key);
    return root && root.i18n && typeof root.i18n.t === 'function' ? root.i18n.t(key) : key;
  }
  const fill = (s, map) => String(s).replace(/\{(\w+)\}/g, (m, k) => (Object.prototype.hasOwnProperty.call(map, k) ? map[k] : m));
  function lang() {
    if (root && root.i18n && root.i18n.lang) return root.i18n.lang;
    const d = doc();
    return (d && d.documentElement && d.documentElement.lang) || 'fa';
  }
  const obj = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : {});
  const arr = (v) => (Array.isArray(v) ? v : []);
  const num = (v) => Math.max(0, Number(v) || 0);
  const blank = (v) => String(v == null ? '' : v).trim() === '';
  const call = (name, ...args) => { const k = kit(); try { return k && typeof k[name] === 'function' ? k[name](...args) : undefined; } catch { return undefined; } };
  const has = (name) => { const k = kit(); return !!k && typeof k[name] === 'function'; };
  const data = () => obj(call('data'));

  function bytesText(n) {
    if (has('fmtBytes')) return kit().fmtBytes(n);
    let v = Number(n) || 0;
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return (i === 0 ? Math.round(v) : v.toFixed(1)) + ' ' + units[i];
  }
  /** GB as typed: '20', '0.5' — no trailing zeros. */
  const gbText = (v) => String(Math.round(Number(v) * 1000) / 1000);

  function el(tag, className, text) {
    const n = doc().createElement(tag);
    if (className) n.className = className;
    if (text != null && text !== '') n.textContent = String(text);
    return n;
  }
  function button(className, text, key) {
    const b = el('button', className, text);
    b.type = 'button';
    if (key) b.dataset.lu = key;
    return b;
  }
  function ltr(n) { n.setAttribute('dir', 'ltr'); return n; }
  /** A value in a line of its own direction: '1.0 GB' inside a Persian line keeps its order (lanUsers.js tpl). */
  const bdi = (text) => el('bdi', null, text);
  /** A template's words with each value in a <bdi> of its own. */
  function tpl(template, map) {
    return String(template).split(/(\{\w+\})/).filter(Boolean).map((p) => {
      const m = /^\{(\w+)\}$/.exec(p);
      return m && Object.prototype.hasOwnProperty.call(map, m[1]) ? bdi(map[m[1]]) : p;
    });
  }
  /** Parts (each a string, a node or a list of them) joined with ' · '. */
  const joined = (parts) => parts.filter((p) => p && (!Array.isArray(p) || p.length)).flatMap((p, i) => [i ? ' · ' : null].concat(p)).filter((p) => p != null);
  /** A label over its control (lanUsers.js field), and the line its error is said on. */
  function field(label, key, ...controls) {
    const box = el('div', 'lu-field');
    box.append(el('div', 'field-label', label), ...controls.filter(Boolean));
    const err = el('div', 'lu-err', ui.errors[key] ? t(ui.errors[key]) : '');
    err.dataset.err = key;
    box.append(err);
    return box;
  }
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

  /** The router's page, where the sign-in page is: the kit says so, or the payload's platform does. */
  function isRouter() {
    if (has('isRouter')) return !!call('isRouter');
    return /^(openwrt|router)$/i.test(String(data().platform || '')) || !!call('portal');
  }
  /** The sign-in page's addresses (the payload's portal): plain http only, or null. */
  function portal() {
    const p = obj(call('portal'));
    const url = (v) => (typeof v === 'string' && /^http:\/\/[^\s"'<>]+$/.test(v) ? v : '');
    return url(p.url) ? { url: url(p.url), nameUrl: url(p.nameUrl) } : null;
  }
  function vouchers() {
    if (has('vouchers')) return arr(call('vouchers')).filter((u) => u && u.id && u.voucher);
    return arr(data().users).filter((u) => u && u.id && u.voucher && typeof u.voucher === 'object');
  }
  const usageOf = (id) => obj(obj(data().usage)[id]);
  function toast(msg, kind) { call('toast', msg, kind); }
  function confirmed(msg) {
    if (has('confirm')) return !!call('confirm', msg);
    return typeof root.confirm === 'function' ? !!root.confirm(msg) : false;
  }
  async function copy(text) {
    try {
      if (has('copy')) await kit().copy(text);
      else await root.navigator.clipboard.writeText(text);
      toast(t('lu.copied'), 'ok');
    } catch { toast(t('lu.copyFailed'), 'err'); }
  }

  /* ------------------------------ dates and durations ------------------------------ */

  function format(ms, opts) {
    const d = new Date(Number(ms));
    if (!Number.isFinite(d.getTime())) return '';
    try { return new Intl.DateTimeFormat(lang() === 'fa' ? 'fa-IR-u-nu-latn' : 'en', opts).format(d); }
    catch { return d.toISOString().slice(0, 10); }
  }
  const pad = (n) => String(n).padStart(2, '0');
  const dateText = (ms) => (Number(ms) > 0 ? format(ms, { month: 'long', day: 'numeric' }) : '');
  /** A moment with its day: '7 آبان 18:30', its year too when it is not this one. */
  function momentText(ms, now = Date.now()) {
    if (!(Number(ms) > 0)) return '';
    const d = new Date(Number(ms));
    const sameYear = d.getFullYear() === new Date(now).getFullYear();
    const day = format(ms, sameYear ? { month: 'long', day: 'numeric' } : { year: 'numeric', month: 'long', day: 'numeric' });
    return day + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes());
  }
  /** A voucher's time in the page's language: '2 ساعت', '7 روز' / '2 h', '7 d' — whole days as days. */
  const hoursUi = (h) => (h >= 24 && h % 24 === 0 ? fill(t('lu.vch.dur.d'), { n: h / 24 }) : fill(t('lu.vch.dur.h'), { n: h }));
  /** Time left: '3 روز و 4 ساعت', '1 h 20 min', '5 min' — two parts at most, a minute at least. */
  function leftUi(ms) {
    const min = Math.max(1, Math.ceil(num(ms) / 60000));
    const d = Math.floor(min / 1440);
    const h = Math.floor((min % 1440) / 60);
    const m = min % 60;
    const parts = d > 0 ? [fill(t('lu.vch.dur.d'), { n: d }), h ? fill(t('lu.vch.dur.h'), { n: h }) : '']
      : h > 0 ? [fill(t('lu.vch.dur.h'), { n: h }), m ? fill(t('lu.vch.dur.m'), { n: m }) : ''] : [fill(t('lu.vch.dur.m'), { n: m })];
    return parts.filter(Boolean).join(t('lu.vch.dur.and'));
  }
  /** The card's time, in both languages: ['2 ساعت', '2 hours'], ['7 روز', '7 days']. */
  function hoursCard(h) {
    if (h >= 24 && h % 24 === 0) { const d = h / 24; return [d + ' روز', d + (d === 1 ? ' day' : ' days')]; }
    return [h + ' ساعت', h + (h === 1 ? ' hour' : ' hours')];
  }

  /* ------------------------------ the vouchers and their batches ------------------------------ */

  const meterOf = (us, kind, period) => arr(us.meters).find((m) => m && m.kind === kind && m.period === period) || null;
  /** A voucher's data, in GB: its one-off Total limit (0: none). */
  function gbOf(u) {
    const l = arr(u.limits).find((x) => x && x.kind === 'total' && x.period === 'none' && Number(x.gb) > 0);
    return l ? Number(l.gb) : 0;
  }

  /** unused | used | expired | active — model.js voucherState's rule, with the meter's word on `used`. */
  function stateOf(u, us, now = Date.now()) {
    const v = obj(u && u.voucher);
    if (!(Number(v.activatedAt) > 0)) return 'unused';
    const m = meterOf(obj(us), 'total', 'none');
    if (m && num(m.capBytes) > 0 && (m.over || num(m.bytes) >= num(m.capBytes) + num(m.extraBytes))) return 'used';
    if (Number(u.expiresAt) > 0 && Number(u.expiresAt) <= now) return 'expired';
    return 'active';
  }

  /** A card's number in its batch: the core names them '<label> #<n>'. */
  const numberOf = (u) => { const m = /#(\d+)\s*$/.exec(String(u.name || '')); return m ? Number(m[1]) : 0; };
  const labelOf = (u) => String(u.name || '').replace(/\s*#\d+\s*$/, '').trim();
  /** When a batch was made: a date the record carries (none in v1.40's), else when this window made it. */
  function madeOf(list, id) {
    let at = 0;
    for (const u of list) for (const v of [obj(u.voucher).madeAt, obj(u.voucher).at, u.createdAt]) if (Number(v) > at) at = Number(v);
    return at || ui.made[id] || 0;
  }

  /**
   * The vouchers by batch, newest first (a date when there is one, else the
   * order the store keeps — the core appends a batch at the end): each with
   * its label, what every card gives (from its first card: one batch, one
   * kind of card), its cards in their numbers' order — each with its state,
   * its meter and, when used, what is left — and the count of each state.
   */
  function batchesOf(list, usage, now = Date.now()) {
    const map = new Map();
    arr(list).forEach((u, i) => {
      const id = String(obj(u && u.voucher).batch || '');
      if (!id) return;
      let b = map.get(id);
      if (!b) map.set(id, b = { id, label: labelOf(u), users: [], order: i });
      b.users.push(u);
      b.order = i;
    });
    const out = [];
    for (const b of map.values()) {
      const first = b.users[0];
      const codes = b.users.map((u) => {
        const us = obj(obj(usage)[u.id]);
        const m = meterOf(us, 'total', 'none');
        return { id: u.id, code: String(u.username || ''), n: numberOf(u), state: stateOf(u, us, now), enabled: u.enabled !== false,
          expiresAt: num(u.expiresAt), hours: num(obj(u.voucher).hours), gb: gbOf(u),
          bytes: m ? num(m.bytes) : 0, cap: m ? num(m.capBytes) + num(m.extraBytes) : 0 };
      }).sort((a, c) => (a.n - c.n) || a.code.localeCompare(c.code));
      const counts = Object.fromEntries(STATES.map((s) => [s, codes.filter((c) => c.state === s).length]));
      out.push({ id: b.id, label: b.label || b.id, order: b.order, madeAt: madeOf(b.users, b.id),
        hours: num(obj(first.voucher).hours), gb: gbOf(first), maxDevices: num(first.maxDevices), target: String(first.target || ''),
        codes, counts });
    }
    return out.sort((a, c) => (c.madeAt - a.madeAt) || (c.order - a.order));
  }

  /* ------------------------------ the new batch ------------------------------ */

  const blankForm = () => ({ count: '10', hours: '2', gb: '', devices: '1', name: '', target: '', routing: '', down: '', up: '' });
  const intOf = (v) => (/^\s*\d+\s*$/.test(String(v == null ? '' : v)) ? Number(v) : NaN);
  function kbpsOf(v) {
    if (blank(v)) return 0;
    const k = Math.round(Number(String(v).trim()) * 1000);
    return Number.isFinite(k) && k >= 1 && k <= KBPS_MAX ? k : NaN;
  }

  /**
   * The form → { errors: { field: i18n key }, batch } — the core's rules
   * (count 1–200, whole hours 0–8760, GB 0–1,000,000, devices 0–1000, a label
   * of 64 at most, speeds 1 kbps–10 Gbps), and one of its own: a card with
   * neither time nor data is the internet for good, not a voucher. The label
   * left empty is "Cards of <today>": a batch is told from the next by it.
   */
  function validateBatch(f, router, now = Date.now()) {
    const e = {};
    const count = intOf(f.count);
    if (!(count >= 1 && count <= COUNT_MAX)) e.count = 'lu.vch.err.count';
    const hours = blank(f.hours) ? 0 : intOf(f.hours);
    if (!(hours >= 0 && hours <= HOURS_MAX)) e.hours = 'lu.vch.err.hours';
    const gb = blank(f.gb) ? 0 : Number(String(f.gb).trim());
    if (!(Number.isFinite(gb) && gb >= 0 && gb <= GB_MAX)) e.gb = 'lu.vch.err.gb';
    if (!e.hours && !e.gb && hours === 0 && gb === 0) e.empty = 'lu.vch.err.empty';
    const devices = blank(f.devices) ? 1 : intOf(f.devices);
    if (!(devices >= 0 && devices <= DEVICES_MAX)) e.devices = 'lu.vch.err.devices';
    const name = String(f.name || '').replace(/[\x00-\x1f\x7f]/g, '').trim();
    if (name.length > NAME_MAX) e.name = 'lu.vch.err.name';
    const batch = { count, hours, gb, target: String(f.target || ''), routing: String(f.routing || ''), maxDevices: devices,
      name: name || fill(t('lu.vch.defaultName'), { date: dateText(now) }) };
    if (router) {
      const down = kbpsOf(f.down);
      const up = kbpsOf(f.up);
      if (Number.isNaN(down) || Number.isNaN(up)) e.speed = 'lu.vch.err.speed';
      else if (down || up) batch.speed = { down, up };
    }
    return { errors: e, batch };
  }

  /** A number box, left to right; what is typed is kept (ui.form) and its error goes. */
  function numBox(key, label, { min = '0', max = '', step = '1', placeholder = '' } = {}) {
    const n = ltr(el('input', 'input'));
    n.type = 'number';
    n.min = min;
    if (max) n.max = max;
    n.step = step;
    n.value = ui.form[key];
    n.placeholder = placeholder;
    n.setAttribute('aria-label', label);
    n.dataset.lu = 'vch:' + key;
    if (ui.errors[key]) n.setAttribute('aria-invalid', 'true');
    n.addEventListener('input', () => typed(key, n.value));
    return n;
  }
  /** A value typed: kept, its own error and the form's cleared — the count also names the button. */
  function typed(key, value) {
    ui.form[key] = value;
    const r = ui.root;
    if (ui.errors[key] || ui.errors.empty || ui.formError) {
      delete ui.errors[key];
      if (key === 'hours' || key === 'gb') delete ui.errors.empty;
      ui.formError = '';
      paint();
      return;
    }
    if (key === 'count') {
      const b = r && findKey(r, 'vch:make');
      if (b) b.textContent = makeLabel();
    }
  }
  const makeLabel = () => fill(t('lu.vch.make'), { n: Number.isInteger(intOf(ui.form.count)) ? String(intOf(ui.form.count)) : '…' });

  /** What every card rides: the page's own picker when the kit lends it, else a <select> of the kit's configs. */
  function targetControl() {
    const label = t('lu.target');
    const onChange = (v) => { ui.form.target = v; };
    if (has('targetPicker')) {
      const n = call('targetPicker', ui.form.target, label, 'vch:target', onChange);
      if (n) return n;
    }
    const pairs = [['', t('lu.target.current')], ['direct', t('lu.target.direct')], ['block', t('lu.target.block')]];
    for (const o of arr(call('targets'))) if (o && o.value != null && !SPECIAL.includes(String(o.value))) pairs.push([String(o.value), String(o.label || o.value)]);
    return select(pairs, ui.form.target, label, 'vch:target', onChange);
  }
  /** Its routing: the page's own picker when the kit lends it, else as the config / Iranian sites direct / the profiles. */
  function routingControl() {
    const onChange = (v) => { ui.form.routing = v; };
    if (has('routingPicker')) {
      const n = call('routingPicker', ui.form.routing, 'vch:routing', onChange);
      if (n) return n;
    }
    const pairs = [['', t(isRouter() ? 'lu.route.router' : 'lu.route.all')], ['bypass-ir', t('lu.route.bypassIr')]];
    for (const p of arr(call('routingProfiles'))) if (p && typeof p.id === 'string' && p.id) pairs.push(['profile:' + p.id, String(p.name || p.id)]);
    return select(pairs, ui.form.routing, t('lu.routing'), 'vch:routing', onChange);
  }

  function newCard() {
    const router = isRouter();
    const card = el('div', 'card lu-card lu-vch-new');
    card.append(head(t('lu.vch.new'), t('lu.vch.newSub')));

    const hours = numBox('hours', t('lu.vch.hours'), { max: String(HOURS_MAX), placeholder: '0' });
    const chips = el('div', 'lu-vch-presets');
    for (const h of PRESETS) {
      const c = button('lu-vch-chip', hoursUi(h), 'vch:preset:' + h);
      c.setAttribute('aria-pressed', String(String(intOf(ui.form.hours)) === String(h)));
      c.addEventListener('click', () => { ui.form.hours = String(h); delete ui.errors.hours; delete ui.errors.empty; ui.formError = ''; paint(); });
      chips.append(c);
    }
    const nums = el('div', 'lu-vch-grid');
    nums.append(
      field(t('lu.vch.count'), 'count', numBox('count', t('lu.vch.count'), { min: '1', max: String(COUNT_MAX) })),
      field(t('lu.vch.hours'), 'hours', hours, chips, el('div', 'lu-sub', t('lu.vch.hoursHint'))),
      field(t('lu.vch.gb'), 'gb', numBox('gb', t('lu.vch.gb'), { step: 'any', placeholder: '0' }), el('div', 'lu-sub', t('lu.vch.gbHint'))),
      field(t('lu.vch.devices'), 'devices', numBox('devices', t('lu.vch.devices'), { max: String(DEVICES_MAX) }), el('div', 'lu-sub', t('lu.vch.devicesHint'))));

    const rides = el('div', 'lu-grid');
    rides.append(field(t('lu.target'), 'target', targetControl()), field(t('lu.routing'), 'routing', routingControl()));

    const more = el('div', 'lu-grid');
    const name = el('input', 'input');
    name.type = 'text';
    name.maxLength = NAME_MAX;
    name.value = ui.form.name;
    name.placeholder = t('lu.vch.namePh');
    name.setAttribute('aria-label', t('lu.vch.name'));
    name.dataset.lu = 'vch:name';
    if (ui.errors.name) name.setAttribute('aria-invalid', 'true');
    name.addEventListener('input', () => typed('name', name.value));
    more.append(field(t('lu.vch.name'), 'name', name));
    if (router) {
      const rates = el('div', 'lu-vch-rates');
      for (const [k, arrow, label] of [['down', '↓', t('lu.speedDown')], ['up', '↑', t('lu.speedUp')]]) {
        const box = el('div', 'lu-ratein');
        const a = el('span', 'lu-arrow', arrow);
        a.setAttribute('aria-hidden', 'true');
        box.append(a, numBox(k, label, { step: 'any', placeholder: t('lu.unlimited') }));
        rates.append(box);
      }
      more.append(field(t('lu.vch.speed'), 'speed', rates));
    }

    const foot = el('div', 'lu-vch-foot');
    const make = button('btn primary', makeLabel(), 'vch:make');
    make.disabled = ui.busy || !ui.kit;
    make.addEventListener('click', () => { makeBatch(); });
    foot.append(make);
    const msg = ui.errors.empty ? t(ui.errors.empty) : ui.formError;
    if (msg) {
      const e = el('p', 'lu-formerr lu-vch-ferr', msg);
      e.setAttribute('role', 'alert');
      foot.append(e);
    } else if (ui.notice) {
      foot.append(el('p', 'lu-vch-notice', ui.notice));
    }
    card.append(nums, rides, more, foot);
    return card;
  }

  /** Ask the core for the batch; the answer (its codes) opens it in the list, marked. */
  async function makeBatch() {
    if (ui.busy) return null;
    const { errors, batch } = validateBatch(ui.form, isRouter());
    ui.errors = errors;
    ui.formError = '';
    ui.notice = '';
    if (Object.keys(errors).length) { paint(); return null; }
    const res = await run({ op: 'vouchers', batch }, true);
    const made = res && obj(res.batch);
    if (!made || !made.id) return null;
    ui.open[made.id] = true;
    ui.made[made.id] = Date.now();
    ui.fresh = made.id;
    ui.form.name = '';
    ui.notice = fill(t('lu.vch.made'), { n: String(arr(made.codes).length || batch.count), name: batch.name });
    toast(ui.notice, 'ok');
    paint();
    return made;
  }

  /** A refusal in words: the core's code ('batch', 'lu.err.voucher') in the page's language, else as it came. */
  function errText(e) {
    const msg = String((e && e.message) || e || '');
    const code = msg.replace(/^lu\.(?:err|vch\.err)\./, '');
    for (const k of ['lu.err.' + code, 'lu.vch.err.' + code]) if (/^[\w.]+$/.test(k) && t(k) !== k) return t(k);
    return msg;
  }
  /**
   * One change through `lanusers:user`: the kit's invoke takes the answer as
   * the page's truth and draws the page again (lanUsers.js call) — an answer
   * without the payload is read with refresh(). A refusal says why: in the
   * form for a new batch, as a toast for the rest.
   */
  async function run(payload, inForm) {
    const k = kit();
    if (!k || typeof k.invoke !== 'function') return null;
    ui.busy = true;
    paint();
    try {
      const res = await k.invoke('lanusers:user', payload);
      if (res && typeof res === 'object' && res.ok === false) throw new Error(res.error || res.code || 'refused');
      if (!res || typeof res !== 'object') return null;      // the kit said why already
      if (!('users' in res) && typeof k.refresh === 'function') await k.refresh();
      return res;
    } catch (e) {
      const why = errText(e);
      if (inForm) ui.formError = t('lu.saveFailed') + ': ' + why;
      toast(t('lu.saveFailed') + ': ' + why, 'err');
      return null;
    } finally {
      ui.busy = false;
      paint();
    }
  }

  /* ------------------------------ the batches ------------------------------ */

  function head(title, meta, ...actions) {
    const h = el('div', 'lu-head');
    const words = el('div', 'lu-head-words');
    words.append(el('div', 'lu-title', title));
    if (meta) words.append(el('div', 'lu-meta', meta));
    h.append(words, ...actions.filter(Boolean));
    return h;
  }

  /** What every card of a batch gives, in a line: '2 h · 1 GB · devices: 1' — each value in its own direction. */
  function specLine(b) {
    return joined([b.hours ? tpl(t('lu.vch.fromFirst'), { dur: hoursUi(b.hours) }) : t('lu.vch.noTime'),
      b.gb ? [bdi(gbText(b.gb) + ' GB')] : t('lu.vch.noData'),
      b.maxDevices ? tpl(t('lu.vch.devicesN'), { n: String(b.maxDevices) }) : t('lu.vch.anyDevices')]);
  }
  /** A card's own line: what it gives (unused), what is left (active), or when it ended. */
  function leftLine(c, now = Date.now()) {
    if (c.state === 'unused') return joined([c.hours ? [bdi(hoursUi(c.hours))] : null, c.gb ? [bdi(gbText(c.gb) + ' GB')] : null]);
    if (c.state === 'expired') return tpl(t('lu.vch.endedOn'), { date: momentText(c.expiresAt, now) });
    if (c.state === 'used') return tpl(t('lu.vch.usedAll'), { used: bytesText(c.bytes) });
    return joined([c.expiresAt > now ? tpl(t('lu.vch.leftTime'), { dur: leftUi(c.expiresAt - now) }) : null,
      c.cap > 0 ? tpl(t('lu.vch.leftData'), { left: bytesText(Math.max(0, c.cap - c.bytes)), cap: bytesText(c.cap) }) : null]);
  }

  function codeRow(b, c) {
    const row = el('div', 'lu-vcode' + (c.enabled ? '' : ' lu-dim'));
    row.dataset.code = c.code;
    const code = ltr(el('span', 'lu-vc-mono', c.code));
    const pill = el('span', 'lu-state lu-vs-' + c.state, t('lu.vch.st.' + c.state));
    const left = el('span', 'lu-vc-left');
    left.append(...leftLine(c));
    const cp = button('icon-btn', '⧉', 'vch:copy:' + c.code);
    cp.setAttribute('aria-label', t('lu.copy') + ' — ' + c.code);
    cp.title = cp.getAttribute('aria-label');
    cp.addEventListener('click', () => copy(c.code));
    row.append(code, pill, left, cp);
    if (!c.enabled) row.append(el('span', 'lu-state lu-s-off', t('lu.state.off')));
    return row;
  }

  function batchBox(b) {
    const box = el('div', 'lu-vbatch' + (b.id === ui.fresh ? ' lu-vb-fresh' : ''));
    box.dataset.batch = b.id;
    const top = el('div', 'lu-row');
    const words = el('div', 'lu-vb-words');
    words.append(el('div', 'lu-vb-name', b.label));
    const meta = el('div', 'lu-sub lu-vb-meta');
    if (b.madeAt) meta.append(...tpl(t('lu.vch.madeOn'), { date: dateText(b.madeAt) }), ' · ');
    meta.append(...specLine(b));
    words.append(meta);
    const counts = el('div', 'lu-vb-counts');
    for (const s of STATES) {
      if (!b.counts[s]) continue;
      const pill = el('span', 'lu-state lu-vs-' + s, b.counts[s] + ' ' + t('lu.vch.st.' + s));
      pill.dataset.count = s;
      counts.append(pill);
    }
    top.append(words, counts);

    const acts = el('div', 'lu-vb-acts');
    const unused = b.counts.unused;
    const print = button('btn small', fill(t('lu.vch.print'), { n: String(unused) }), 'vch:print:' + b.id);
    print.disabled = !unused;
    print.addEventListener('click', () => printCards(b.id));
    const open = !!ui.open[b.id];
    const show = button('btn ghost small', fill(t(open ? 'lu.vch.hideCodes' : 'lu.vch.showCodes'), { n: String(b.codes.length) }), 'vch:codes:' + b.id);
    show.setAttribute('aria-expanded', String(open));
    show.addEventListener('click', () => { ui.open[b.id] = !ui.open[b.id]; paint(); });
    acts.append(print, show);
    // all unused: "delete unused" would be the whole batch — one button says it
    if (unused && unused < b.codes.length) {
      const du = button('btn ghost small', t('lu.vch.delUnused'), 'vch:delUnused:' + b.id);
      du.disabled = ui.busy;
      du.addEventListener('click', () => removeBatch(b.id, true));
      acts.append(du);
    }
    const db = button('btn ghost small danger lu-vb-del', t('lu.vch.delBatch'), 'vch:delBatch:' + b.id);
    db.disabled = ui.busy;
    db.addEventListener('click', () => removeBatch(b.id, false));
    acts.append(db);
    box.append(top, acts);

    if (open) {
      const list = el('div', 'lu-vcodes');
      list.setAttribute('role', 'list');
      for (const c of b.codes) {
        const r = codeRow(b, c);
        r.setAttribute('role', 'listitem');
        list.append(r);
      }
      box.append(list);
    }
    return box;
  }

  const currentBatches = () => batchesOf(vouchers(), obj(data().usage));

  function listCard() {
    const card = el('div', 'card lu-card lu-vch-list');
    const loaded = has('data') && call('data') != null;
    const list = loaded ? currentBatches() : [];
    const cards = list.reduce((a, b) => a + b.codes.length, 0);
    card.append(head(t('lu.vch.batches'), loaded ? fill(t('lu.vch.batchesMeta'), { b: String(list.length), n: String(cards) }) : ''));
    if (!loaded) {
      card.append(el('p', 'hint', t('lu.loading')));
      return card;
    }
    if (!list.length) {
      card.append(el('div', 'empty', t('lu.vch.none')));
    } else {
      const box = el('div', 'lu-vbatches');
      for (const b of list) box.append(batchBox(b));
      card.append(box);
    }
    // where the cards' QR would point: said when it cannot be printed
    if (isRouter() && !portal()) card.append(el('p', 'hint lu-vch-note', t('lu.vch.noPortal')));
    if (!isRouter()) card.append(el('p', 'hint lu-vch-note', t('lu.vch.desktopNote')));
    return card;
  }

  async function removeBatch(id, unused) {
    const b = currentBatches().find((x) => x.id === id);
    if (!b) return false;
    const n = unused ? b.counts.unused : b.codes.length;
    if (!n) return false;
    if (!confirmed(fill(t(unused ? 'lu.vch.confirmUnused' : 'lu.vch.confirmBatch'), { n: String(n), name: b.label }))) return false;
    const res = await run({ op: 'deleteBatch', batch: { id }, unused: !!unused });
    if (!res) return false;
    if (!unused) { delete ui.open[id]; if (ui.fresh === id) ui.fresh = ''; }
    toast(fill(t('lu.vch.deleted'), { n: String(n) }), 'ok');
    return true;
  }

  /* ------------------------------ the printed cards ------------------------------ */

  /** The sign-in page's address with the code in it: the page fills the code box from `?code=`. */
  function codeUrl(url, code) {
    try {
      const u = new URL(url);
      u.searchParams.set('code', code);
      return u.toString();
    } catch { return String(url) + (String(url).includes('?') ? '&' : '?') + 'code=' + encodeURIComponent(code); }
  }
  /** A QR as an image (qrcode.js's own GIF — no markup goes into the page), or null. */
  function qrImage(text, label) {
    const make = typeof root.qrcode === 'function' ? root.qrcode : (typeof qrcode === 'function' ? qrcode : null);   // eslint-disable-line no-undef
    if (!make) return null;
    try {
      const qr = make(0, 'M');
      qr.addData(text);
      qr.make();
      const img = el('img', 'lu-vc-qr');
      // four modules of quiet zone around it: what a phone's camera needs on any paper
      img.src = qr.createDataURL(4, 16);
      img.alt = label;
      return img;
    } catch { return null; }
  }
  /** A line in both languages: the Persian (words, or nodes with their values in <bdi>), the English in a smaller line beneath. */
  function both(cls, pair) {
    const n = el('div', cls);
    n.append(...(Array.isArray(pair[0]) ? pair[0] : [pair[0]]), ltr(el('span', 'lu-vc-en', pair[1])));
    return n;
  }
  /** On a PC the card is a proxy account: the address to set, when the accounts are on. */
  function proxyAddress() {
    const d = data();
    const p = obj(obj(d.config).proxy);
    const ip = arr(d.lanAddresses).find((a) => typeof a === 'string' && a && !a.includes(':'));
    return p.enabled && ip && p.port ? 'SOCKS5 ' + ip + ':' + p.port : '';
  }

  function card(b, c, where) {
    const n = el('div', 'lu-vc-card');
    n.dataset.code = c.code;
    const text = el('div', 'lu-vc-text');
    text.append(both('lu-vc-title', CARD.title), ltr(el('div', 'lu-vc-code', c.code)));
    const time = c.hours ? hoursCard(c.hours) : null;
    const fa = [time ? [bdi(time[0]), ' ' + CARD.fromFirst[0]] : CARD.noTime[0], c.gb ? [bdi(gbText(c.gb) + ' GB')] : CARD.noData[0]];
    const en = [time ? time[1] + ' ' + CARD.fromFirst[1] : CARD.noTime[1], c.gb ? gbText(c.gb) + ' GB' : CARD.noData[1]];
    if (b.maxDevices > 1) { fa.push([bdi(String(b.maxDevices)), ' دستگاه']); en.push(b.maxDevices + ' devices'); }
    text.append(both('lu-vc-spec', [joined(fa), en.join(' · ')]));
    text.append(both('lu-vc-how', where.portal ? (where.qr ? CARD.portal : CARD.portalNoQr) : where.router ? CARD.portalNoQr : CARD.proxy));
    for (const u of where.lines) text.append(ltr(el('div', 'lu-vc-url', u)));
    text.append(el('div', 'lu-vc-label', b.label + (c.n ? ' · #' + c.n : '')));
    n.append(text);
    if (where.portal) {
      const img = qrImage(codeUrl(where.portal.url, c.code), CARD.title[1] + ' ' + c.code);
      if (img) n.append(img);
    }
    return n;
  }

  /**
   * Print a batch's unused cards: A4 pages of eight (two columns of four, cut
   * lines between), on paper alone — LuReports.printSheet puts the sheet in
   * the page for the print and takes it away after, as the wall sheet is
   * printed. The QR holds the sign-in page's numeric address (no DNS needed:
   * a phone on Private DNS opens it too) with the code; the card also says the
   * short name, the one to type.
   */
  function printCards(id) {
    const b = currentBatches().find((x) => x.id === id);
    const reports = root.LuReports;
    if (!b || !reports || typeof reports.printSheet !== 'function' || typeof root.print !== 'function') return false;
    const codes = b.codes.filter((c) => c.state === 'unused');
    if (!codes.length) return false;
    const p = portal();
    const router = isRouter();
    const lines = p ? [p.nameUrl, p.url].filter(Boolean) : [proxyAddress()].filter(Boolean);
    const where = { portal: p, router, lines, qr: !!p && typeof (root.qrcode || (typeof qrcode === 'function' ? qrcode : null)) === 'function' };   // eslint-disable-line no-undef
    const sheet = el('div', 'lu-printsheet lu-vcards');
    sheet.setAttribute('dir', 'rtl');
    sheet.dataset.batch = b.id;
    for (let i = 0; i < codes.length; i += PER_PAGE) {
      const page = el('div', 'lu-vc-page');
      for (const c of codes.slice(i, i + PER_PAGE)) page.append(card(b, c, where));
      sheet.append(page);
    }
    return reports.printSheet(sheet);
  }

  /* ------------------------------ the tab ------------------------------ */

  function findKey(node, key) {
    for (const c of (node && node.children) || []) {
      if (c.dataset && c.dataset.lu === key) return c;
      const hit = findKey(c, key);
      if (hit) return hit;
    }
    return null;
  }

  /** Draw the tab again in its element; the control in use keeps the focus. */
  function paint() {
    const box = ui.root;
    if (!box) return;
    if (!ui.form) ui.form = blankForm();
    const d = doc();
    const active = d && d.activeElement;
    const focusKey = active && active !== box && box.contains && box.contains(active) && active.dataset ? active.dataset.lu : null;
    box.replaceChildren(el('p', 'hint lu-vch-intro', t('lu.vch.intro')), newCard(), listCard());
    if (focusKey) {
      const n = findKey(box, focusKey);
      if (n && !n.disabled && n.focus) n.focus();
    }
  }

  /**
   * The Vouchers tab as an element, built on `kit` (window.LanUsersKit). The
   * page may call it on every redraw: what is typed, which batches are open
   * and the last batch made are kept here, not in the element.
   */
  function panel(k) {
    if (k) ui.kit = k;
    if (!ui.form) ui.form = blankForm();
    const box = el('div', 'lu-vch');
    ui.root = box;
    paint();
    return box;
  }

  return {
    panel,
    // for tests and the page: the pure parts and the tab's actions
    validateBatch, batchesOf, stateOf, codeUrl, printCards, makeBatch, removeBatch,
    reset: () => { Object.assign(ui, { kit: null, root: null, form: null, errors: {}, formError: '', notice: '', busy: false, open: {}, made: {}, fresh: '' }); }
  };
}));
