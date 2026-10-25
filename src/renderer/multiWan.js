'use strict';
/**
 * Settings → «ترکیب اینترنت‌ها» / "Combine internets" — several connected
 * internets used together (src/main/multiWan.js builds it into the config).
 *
 * One settings card, as the approved mockup draws it: the on/off switch; three
 * mode cards (combine / backup / upload and download apart), each with its
 * one-line explanation; one row per internet — its icon by kind, its name, its
 * address and gateway (left to right, monospace), whether it is connected now,
 * its last speed test, and its role, share and data cap with the period's
 * usage bar; the upload / download pickers in split mode only; while connected,
 * two live share bars (download, upload); "test each internet" and "find
 * again"; and the honest note that one download is never faster than its own
 * internet.
 *
 * The same file runs in the window and on the router's page: window.api's
 * multiWanGet / multiWanSet / multiWanTest. Every change is saved at once
 * (multiwan:set) through app.js's hook, which also brings the "reconnect to
 * apply" question the other settings bring. Text only — names and addresses
 * come from the OS and the store, so nothing here is HTML. The page decides the
 * direction and the language; app.js decides when the card loads (refresh())
 * and hands it each stats tick (live()) and each connection change.
 */
(() => {
  const t = (key) => window.i18n.t(key);
  const fill = (s, map) => String(s).replace(/\{(\w+)\}/g, (m, k) => (Object.prototype.hasOwnProperty.call(map, k) ? map[k] : m));
  const lang = () => (window.i18n && window.i18n.lang) || document.documentElement.lang || 'fa';
  const MODES = ['balance', 'failover', 'split'];
  const ROLES = ['use', 'backup', 'off'];
  const SHARES = [3, 2, 1];
  const PERIODS = ['month', 'day', 'none'];
  const ICONS = { wifi: '📶', ethernet: '🔌', cellular: '📱', usb: '📱', other: '🌐' };
  const COLORS = 4;     // .mi-c0 … .mi-c3 (settings.css): the share bars' segments, in order
  const NEAR = 0.8;     // from here the usage bar warns that the cap is close
  const EMPTY = { enabled: false, mode: 'balance', links: [], split: { up: '', down: '' } };

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
  /** A <select> of [value, label] pairs, named for assistive tech, saving on change. `key` keeps the focus across a redraw. */
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
    s.dataset.mi = key;
    s.addEventListener('change', () => onChange(s.value));
    return s;
  }
  /** A label over its control, as the mockup's three columns are. */
  function field(label, control) {
    const box = el('div', 'mi-field');
    box.append(el('div', 'field-label', label), control);
    return box;
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
  /** Megabits per second from a test's Mbps or a live bytes/s figure. */
  const mbps = (v) => (Number.isFinite(Number(v)) ? Number(v).toFixed(1) : '—');
  const rateMbps = (bytesPerSec) => mbps((Number(bytesPerSec) || 0) * 8 / 1e6);
  /** A day of the year in the page's language — '1 November', '10 آبان' (Latin digits, as every number in the app). */
  function dateText(ms) {
    const d = new Date(Number(ms));
    if (!Number.isFinite(d.getTime())) return '';
    try { return new Intl.DateTimeFormat(lang() === 'fa' ? 'fa-IR-u-nu-latn' : 'en', { month: 'long', day: 'numeric' }).format(d); }
    catch { return d.toISOString().slice(0, 10); }
  }

  /* ------------------------------ state ------------------------------ */

  const ui = {
    host: null,
    hooks: {},        // app.js: { save(partial) → answer, connected() → bool, settings() → stored multiWan, toast(msg, kind) }
    data: null,       // the last multiwan:get answer: { settings, links, usage, live }
    loading: false,
    error: '',
    seq: 0,           // an answer to an older request is dropped
    testing: null,    // { [linkId]: 'wait' | 'run' | 'done' } while "test each internet" runs
    live: null,       // the last stats tick's { live, usage } (connected only)
    wasConnected: false,
    dom: { speed: {}, usage: {}, live: null }
  };

  const toast = (msg, kind) => { try { if (ui.hooks.toast) ui.hooks.toast(msg, kind); } catch { /* a toast is never worth an error */ } };
  const connected = () => { try { return !!(ui.hooks.connected && ui.hooks.connected()); } catch { return false; } };
  /** The settings the card shows: the last answer's, else what app.js holds. */
  function settings() {
    if (ui.data && ui.data.settings) return ui.data.settings;
    let s = null;
    try { s = ui.hooks.settings ? ui.hooks.settings() : null; } catch { s = null; }
    return Object.assign({}, EMPTY, s && typeof s === 'object' ? s : {}, { links: (s && Array.isArray(s.links)) ? s.links : [], split: Object.assign({}, EMPTY.split, s && s.split) });
  }
  const rows = () => (ui.data && Array.isArray(ui.data.links) ? ui.data.links : []);
  /** A row's configured values — a link found but never configured is in the mix, normal share, no cap. */
  function cfgOf(row) {
    const c = settings().links.find((l) => l.id === row.id);
    return {
      role: c ? c.role : 'use',
      weight: c ? c.weight : 2,
      quotaGb: c ? c.quotaGb : 0,
      quotaPeriod: c ? c.quotaPeriod : 'none'
    };
  }
  /**
   * Every row as a configured link, one of them patched: what is saved. The
   * builder knows only the configured links, so the card's rows — found or
   * configured — are written as the card shows them.
   */
  function linksForSave(id, patch) {
    return rows().map((r) => Object.assign({ id: r.id, iface: r.iface, name: r.name }, cfgOf(r), r.id === id ? patch : {}));
  }
  /** `partial` with the rows as links — only once the internets are loaded: before that the card has none to write, and must not write none over the saved ones. */
  function withLinks(partial) {
    if (ui.data) partial.links = linksForSave();
    return partial;
  }

  /* ------------------------------ actions ------------------------------ */

  /** Save a part of the settings: drawn at once, then the service's answer is the truth. */
  async function save(partial) {
    const cur = settings();
    const draft = Object.assign({}, cur, partial, { split: Object.assign({}, cur.split, partial.split || {}) });
    if (ui.data) ui.data.settings = draft;
    render();
    try {
      const res = ui.hooks.save ? await ui.hooks.save(partial) : await window.api.multiWanSet(partial);
      if (res && res.multiWan && ui.data) ui.data.settings = res.multiWan;
    } catch (e) {
      toast(t('mi.saveFailed') + ': ' + ((e && e.message) || e), 'err');
      if (ui.data) ui.data.settings = cur;
    }
    render();
  }

  function toggle(on) {
    // turned on, the internets the card shows become the configured ones
    save(on ? withLinks({ enabled: true }) : { enabled: false });
  }

  /** Upload over the internet that tested fastest up, download over the fastest down — else the first two. */
  function guessSplit() {
    const c = rows().filter((r) => r.present && cfgOf(r).role !== 'off');
    const tested = (r, k) => (r.test && r.test.ok && Number.isFinite(Number(r.test[k])) ? Number(r.test[k]) : -1);
    if (c.length < 2) return { up: '', down: c[0] ? c[0].id : '' };
    const down = c.slice().sort((a, b) => tested(b, 'downMbps') - tested(a, 'downMbps'))[0];
    const up = c.filter((r) => r !== down).sort((a, b) => tested(b, 'upMbps') - tested(a, 'upMbps'))[0];
    return { up: up.id, down: down.id };
  }

  function pickMode(mode) {
    const s = settings();
    if (s.mode === mode) return;
    const partial = withLinks({ mode });
    if (mode === 'split' && ui.data && (!s.split.up || !s.split.down)) partial.split = guessSplit();
    save(partial);
  }

  function editLink(id, patch) { if (ui.data) save({ links: linksForSave(id, patch) }); }

  /** Each connected internet measured on its own, one after another — its row says how far it got. */
  async function testAll() {
    if (ui.testing) return;
    const ids = rows().filter((r) => r.present).map((r) => r.id);
    if (!ids.length) return;
    ui.testing = {};
    for (const id of ids) ui.testing[id] = 'wait';
    render();
    for (const id of ids) {
      ui.testing[id] = 'run';
      paintSpeed(id);
      let r;
      try {
        const res = await window.api.multiWanTest([id]);
        r = Array.isArray(res) ? res.find((x) => x && x.id === id) || res[0] : null;
      } catch (e) { r = { id, ok: false, error: (e && e.message) || String(e) }; }
      const row = rows().find((x) => x.id === id);
      if (row && r) row.test = r;
      ui.testing[id] = 'done';
      paintSpeed(id);
      // no server to test through: every other one would say the same
      if (r && r.code === 'noServer') { toast(t('mi.err.noServer'), 'err'); break; }
    }
    ui.testing = null;
    render();
  }

  /** Ask the service again: the settings, the internets connected now, the usage. */
  async function refresh() {
    if (!window.api || !window.api.multiWanGet) return;
    const seq = ++ui.seq;
    ui.loading = true;
    ui.error = '';
    render();
    try {
      const res = await window.api.multiWanGet();
      if (seq !== ui.seq) return;
      ui.data = {
        settings: Object.assign({}, EMPTY, res && res.settings),
        links: (res && Array.isArray(res.links) ? res.links : []).filter((l) => l && l.id),
        usage: (res && res.usage) || {},
        live: (res && res.live) || {}
      };
      if (connected() && Object.keys(ui.data.live).length) ui.live = { live: ui.data.live, usage: ui.data.usage };
    } catch (e) {
      if (seq !== ui.seq) return;
      ui.error = (e && e.message) || String(e);
    } finally {
      if (seq === ui.seq) { ui.loading = false; render(); }
    }
  }

  /* ------------------------------ drawing ------------------------------ */

  /** A row's speed: its last test, the test running now, or nothing yet. */
  function speedParts(row) {
    const phase = ui.testing && ui.testing[row.id];
    if (phase === 'run') return [el('span', 'mi-wait', t('mi.testing'))];
    if (phase === 'wait') return [el('span', 'mi-wait', t('mi.queued'))];
    const r = row.test;
    if (r && r.ok) return [el('span', 'dn', '↓ ' + mbps(r.downMbps)), el('span', 'up', '↑ ' + mbps(r.upMbps)), el('span', 'mi-unit', 'Mbps')];
    if (r) {
      // what went wrong, per internet: the app's own refusal in words, else the test's ('download: timeout')
      const e = el('span', 'mi-err', '✕ ' + (r.code ? t('mi.err.' + r.code) : (r.error || t('mi.testFailed'))));
      e.setAttribute('dir', 'auto');
      e.title = t('mi.testFailed');
      return [e];
    }
    return [el('span', 'mi-unit', t('mi.untested'))];
  }
  function paintSpeed(id) {
    const node = ui.dom.speed[id];
    const row = rows().find((x) => x.id === id);
    if (node && row) node.replaceChildren(...speedParts(row));
  }

  /** A row's usage bar and its two lines, in place — a stats tick repaints them, the selects stay put. */
  function paintUsage(d, u) {
    const bytes = u ? Number(u.bytes) || 0 : 0;
    const cap = u ? Number(u.quotaBytes) || 0 : 0;
    const ratio = cap > 0 ? Math.min(1, bytes / cap) : 0;
    d.bar.hidden = !(cap > 0);
    d.fill.style.width = (ratio * 100).toFixed(1) + '%';
    d.fill.className = ratio >= 1 ? 'over' : ratio >= NEAR ? 'warn' : '';
    d.bar.setAttribute('aria-valuenow', String(Math.round(ratio * 100)));
    const used = bytesText(bytes);
    const date = dateText(u && u.until);
    if (cap > 0) {
      const map = { used, cap: bytesText(cap), date };
      d.left.textContent = fill(t(ratio >= 1 ? 'mi.usedOver' : ratio >= NEAR ? 'mi.usedNear' : 'mi.usedOf'), map);
      d.right.textContent = ratio >= 1 ? fill(t('mi.backOn'), map) : ratio >= NEAR ? t('mi.atCap') : fill(t('mi.until'), map);
    } else {
      d.left.textContent = fill(t('mi.used'), { used });
      d.right.textContent = t(u && String(u.period || '').length === 10 ? 'mi.today' : 'mi.thisMonth');
    }
  }

  function linkRow(row) {
    const cfg = cfgOf(row);
    const box = el('div', 'mi-net' + (row.present ? '' : ' mi-gone'));
    box.dataset.link = row.id;

    const head = el('div', 'mi-row');
    const ic = el('div', 'mi-ic', ICONS[row.kind] || ICONS.other);
    ic.setAttribute('aria-hidden', 'true');
    const who = el('div', 'mi-who');
    const meta = el('div', 'mi-meta', [row.address, row.gateway ? 'gw ' + row.gateway : ''].filter(Boolean).join(' · ') || row.iface);
    meta.setAttribute('dir', 'ltr');
    who.append(el('div', 'mi-name', row.name), meta);
    const state = el('span', row.present ? 'mi-ok' : 'mi-off', (row.present ? '● ' : '○ ') + t(row.present ? 'mi.present' : 'mi.absent'));
    const spd = el('div', 'mi-spd');
    spd.setAttribute('dir', 'ltr');
    spd.append(...speedParts(row));
    ui.dom.speed[row.id] = spd;
    head.append(ic, who, state, spd);

    const ctl = el('div', 'mi-ctl');
    ctl.append(field(t('mi.role'), select(ROLES.map((r) => [r, t('mi.role.' + r)]), cfg.role, t('mi.role') + ' — ' + row.name, 'role:' + row.id, (v) => editLink(row.id, { role: v }))));
    ctl.append(field(t('mi.share'), select(SHARES.map((w) => [w, t('mi.share.' + w)]), cfg.weight, t('mi.share') + ' — ' + row.name, 'weight:' + row.id, (v) => editLink(row.id, { weight: Number(v) }))));

    const capBox = el('div', 'mi-field');
    const pair = el('div', 'mi-cap');
    const num = el('input', 'input');
    num.type = 'number';
    num.min = '0';
    num.step = 'any';
    num.value = cfg.quotaGb ? String(cfg.quotaGb) : '';
    num.placeholder = '0';
    num.setAttribute('dir', 'ltr');
    num.setAttribute('aria-label', t('mi.capGb') + ' — ' + row.name);
    num.dataset.mi = 'quota:' + row.id;
    num.disabled = cfg.quotaPeriod === 'none';
    num.addEventListener('change', () => {
      const v = Number(num.value);
      editLink(row.id, { quotaGb: Number.isFinite(v) && v > 0 ? v : 0 });
    });
    const per = select(PERIODS.map((p) => [p, t('mi.period.' + p)]), cfg.quotaPeriod, t('mi.cap') + ' — ' + row.name, 'period:' + row.id, (v) => editLink(row.id, { quotaPeriod: v }));
    pair.append(num, per);
    const bar = el('div', 'mi-bar');
    bar.setAttribute('role', 'progressbar');
    bar.setAttribute('aria-valuemin', '0');
    bar.setAttribute('aria-valuemax', '100');
    bar.setAttribute('aria-label', t('mi.cap') + ' — ' + row.name);
    const fillEl = el('i');
    bar.append(fillEl);
    const q = el('div', 'mi-quota');
    const left = el('span');
    const right = el('span');
    q.append(left, right);
    const d = { bar, fill: fillEl, left, right };
    ui.dom.usage[row.id] = d;
    paintUsage(d, ((ui.live && ui.live.usage) || (ui.data && ui.data.usage) || {})[row.id]);
    capBox.append(el('div', 'field-label', t('mi.cap')), pair, bar, q);
    ctl.append(capBox);

    box.append(head, ctl);
    return box;
  }

  /** One live share bar: each internet's part of the download (or upload) right now. */
  function shareCard(dir, live) {
    const card = el('div', 'mi-box');
    card.dataset.dir = dir;
    card.append(el('div', 'field-label', t(dir === 'down' ? 'mi.liveDown' : 'mi.liveUp')));
    const named = rows().map((r) => r.id);
    const ids = [...named.filter((id) => live[id]), ...Object.keys(live).filter((id) => !named.includes(id))];
    const nameOf = (id) => { const r = rows().find((x) => x.id === id); return r ? r.name : id; };
    const total = ids.reduce((sum, id) => sum + (Number(live[id] && live[id][dir]) || 0), 0);
    const bar = el('div', 'mi-share');
    bar.setAttribute('role', 'img');
    const legend = el('div', 'mi-legend');
    const words = [];
    ids.forEach((id, i) => {
      const v = Number(live[id] && live[id][dir]) || 0;
      const pct = total > 0 ? (v / total) * 100 : 0;
      const seg = el('i', 'mi-c' + (i % COLORS));
      seg.style.width = pct.toFixed(1) + '%';
      bar.append(seg);
      const text = fill(t('mi.shareLegend'), { name: nameOf(id), pct: String(Math.round(pct)), mbps: rateMbps(v) });
      const item = el('span', 'mi-leg');
      item.append(el('i', 'mi-dot mi-c' + (i % COLORS)), text);
      legend.append(item);
      words.push(text);
    });
    bar.setAttribute('aria-label', words.join(', '));
    card.append(bar, legend);
    return card;
  }

  /** The live share bars: only while connected and several internets carry the connection. */
  function paintLive() {
    const box = ui.dom.live;
    if (!box) return;
    const live = ui.live && ui.live.live;
    const on = connected() && !!live && Object.keys(live).length > 0;
    box.hidden = !on;
    if (!on) { box.replaceChildren(); return; }
    box.replaceChildren(shareCard('down', live), shareCard('up', live));
  }

  function render() {
    const host = ui.host;
    if (!host) return;
    // a redraw replaces the controls: the one in use keeps the focus
    const active = document.activeElement;
    const focusKey = active && active !== host && host.contains(active) && active.dataset ? active.dataset.mi : null;
    ui.dom = { speed: {}, usage: {}, live: null };
    ui.wasConnected = connected();
    const s = settings();

    const top = el('div', 'switch-row');
    const words = el('div');
    words.append(el('div', 'switch-title', t('mi.title')), el('div', 'switch-sub', t('mi.sub')));
    const sw = el('label', 'switch');
    const input = el('input');
    input.type = 'checkbox';
    input.id = 'optMultiWan';
    input.checked = !!s.enabled;
    input.setAttribute('aria-label', t('mi.title'));
    input.dataset.mi = 'enabled';
    input.addEventListener('change', () => toggle(input.checked));
    sw.append(input, el('span', 'slider'));
    top.append(words, sw);

    const body = el('div', 'mi-body');
    body.hidden = !s.enabled;

    const modes = el('div', 'mi-modes');
    modes.setAttribute('role', 'group');
    modes.setAttribute('aria-label', t('mi.title'));
    for (const m of MODES) {
      const b = button('mi-mode' + (s.mode === m ? ' on' : ''));
      b.setAttribute('aria-pressed', String(s.mode === m));
      b.dataset.mode = m;
      b.dataset.mi = 'mode:' + m;
      b.append(el('b', null, t('mi.mode.' + m)), el('span', null, t('mi.mode.' + m + 'Sub')));
      b.addEventListener('click', () => pickMode(m));
      modes.append(b);
    }
    body.append(modes);

    const list = el('div', 'mi-links');
    if (!ui.data) {
      list.append(el('p', 'hint', ui.error ? t('mi.loadFailed') + ': ' + ui.error : t('mi.loading')));
    } else if (!rows().length) {
      list.append(el('p', 'hint', ui.loading ? t('mi.loading') : t('mi.noLinks')));
    } else {
      for (const r of rows()) list.append(linkRow(r));
      if (rows().filter((r) => r.present).length < 2) list.append(el('p', 'hint warn', t('mi.needTwo')));
    }
    body.append(list);

    if (s.mode === 'split') {
      const box = el('div', 'mi-box mi-splitbox');
      box.append(el('div', 'field-label', t('mi.splitTitle')));
      const usable = rows().filter((r) => cfgOf(r).role !== 'off');
      const tested = (r, k, arrow) => (r.test && r.test.ok ? ` — ${arrow} ${mbps(r.test[k])}` : '');
      const grid = el('div', 'mi-split');
      grid.append(
        field(t('mi.upFrom'), select([['', t('mi.pick')], ...usable.map((r) => [r.id, r.name + tested(r, 'upMbps', '↑')])], s.split.up, t('mi.upFrom'), 'split:up', (v) => save({ split: { up: v } }))),
        field(t('mi.downFrom'), select([['', t('mi.pick')], ...usable.map((r) => [r.id, r.name + tested(r, 'downMbps', '↓')])], s.split.down, t('mi.downFrom'), 'split:down', (v) => save({ split: { down: v } })))
      );
      box.append(grid, el('p', 'hint', t('mi.splitHint')));
      if (s.split.up && s.split.up === s.split.down) box.append(el('p', 'hint warn', t('mi.splitSame')));
      body.append(box);
    }

    const live = el('div', 'mi-live');
    ui.dom.live = live;
    body.append(live);
    paintLive();

    const actions = el('div', 'mi-actions');
    const test = button('btn ghost small', t('mi.test'));
    test.dataset.mi = 'test';
    test.disabled = !!ui.testing || !rows().some((r) => r.present);
    test.addEventListener('click', () => testAll());
    // reading the internets takes seconds (PowerShell on Windows): the button turns while it runs
    const again = button('btn ghost small', ui.loading ? t('mi.finding') : t('mi.find'));
    again.dataset.mi = 'find';
    again.disabled = ui.loading || !!ui.testing;
    again.setAttribute('aria-busy', String(!!ui.loading));
    if (ui.loading) { const spin = el('span', 'mi-spin'); spin.setAttribute('aria-hidden', 'true'); again.prepend(spin); }
    again.addEventListener('click', () => refresh());
    actions.append(test, again);
    body.append(actions);
    // a test while connected shares the line with the live tunnel — said, not refused
    if (connected()) body.append(el('p', 'hint mi-shared', t('mi.testShared')));
    body.append(el('p', 'mi-note', t('mi.note')));

    host.replaceChildren(top, body);
    if (focusKey) {
      const n = (function find(node) {
        for (const c of node.children || []) {
          if (c.dataset && c.dataset.mi === focusKey) return c;
          const hit = find(c);
          if (hit) return hit;
        }
        return null;
      })(host);
      if (n && !n.disabled) n.focus();
    }
  }

  /* ------------------------------ app.js's hooks ------------------------------ */

  /** The card's box and app.js's hooks; on a back end without the three channels the card stays hidden. */
  function mount(host, hooks) {
    ui.host = host || null;
    ui.hooks = hooks || {};
    if (!ui.host) return;
    if (!window.api || !window.api.multiWanGet) { ui.host.hidden = true; return; }
    render();
  }

  /** A stats tick: `s.multiWan` ({ live, usage }) while several internets carry the connection. */
  function live(d) {
    ui.live = d && typeof d === 'object' && d.live ? d : null;
    if (!ui.host || !ui.data) return;
    if (ui.live && ui.live.usage) {
      for (const [id, dom] of Object.entries(ui.dom.usage)) paintUsage(dom, ui.live.usage[id] || (ui.data.usage || {})[id]);
      Object.assign(ui.data.usage, ui.live.usage);
    }
    paintLive();
  }

  /** Connected or not: the live bars and the shared-line note come and go with the connection. */
  function connection(on) {
    if (!on) ui.live = null;
    if (!ui.host) return;
    // the note is drawn with the card; a connection that came or went (rare) redraws it
    if (!!on !== ui.wasConnected) { ui.wasConnected = !!on; render(); return; }
    paintLive();
  }

  window.multiWanCard = {
    mount,
    refresh,
    render,
    live,
    connection,
    loaded: () => !!ui.data,
    format: { bytesText, dateText, rateMbps }
  };
})();
