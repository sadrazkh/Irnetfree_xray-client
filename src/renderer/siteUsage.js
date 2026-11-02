'use strict';
/**
 * «مصرف سایت‌ها» / "Traffic by site": the Logs page's third tab, how much went where
 * (src/main/siteUsage.js, channels sites:get and sites:clear). Text nodes only: names
 * come from the network, so nothing here is HTML. One measure on one scale, biggest
 * first: a bar per row in the accent colour, with its share and bytes beside it as
 * text, so the row reads without the bar.
 *
 * Read when the tab opens and every REFRESH_MS while it is on screen; the page stops by
 * itself once it is not (hooks.visible()). app.js hands it the switch (hooks.enabled,
 * hooks.save, which asks to reconnect like any other reconnect key).
 *
 * A router's answer has `devices`: a picker for the whole house or one device, and
 * `cost`, the last read's figures, for deciding whether to turn the option off.
 */
(() => {
  const t = (key) => window.i18n.t(key);
  const fill = (s, map) => String(s).replace(/\{(\w+)\}/g, (m, k) => (Object.prototype.hasOwnProperty.call(map, k) ? map[k] : m));
  const REFRESH_MS = 5000;
  /** The rows drawn until "show more"; the page stays readable, the rest stay a click away. */
  const FIRST_ROWS = 15;
  const RANGES = [['today', 'su.range.today'], ['7', 'su.range.7'], ['30', 'su.range.30'], ['all', 'su.range.all']];
  /** Why nothing is being recorded → its line; 'recording' has its own. */
  const WHY = {
    off: 'su.why.off', notConnected: 'su.why.notConnected', noTun: 'su.why.noTun',
    tun2socks: 'su.why.tun2socks', native: 'su.why.native', reconnect: 'su.why.reconnect'
  };

  const ui = { host: null, hooks: {}, parts: null, range: '7', device: '', devicesDrawn: '', data: null, timer: null, seq: 0, showAll: false, armed: 0 };
  const hook = (name, ...a) => (typeof ui.hooks[name] === 'function' ? ui.hooks[name](...a) : undefined);

  function el(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }

  /** Bytes as the app writes them everywhere (app.js fmtBytes): binary units, one decimal. */
  function bytesText(n) {
    let v = Number(n) || 0;
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return (i === 0 ? Math.round(v) : v.toFixed(1)) + ' ' + units[i];
  }
  /** A share as a person reads it: one decimal under 10 %, none above; '<0.1' for a sliver. */
  function shareText(part, total) {
    if (!(total > 0)) return '0%';
    const p = (part / total) * 100;
    if (p > 0 && p < 0.1) return '<0.1%';
    return (p < 10 ? p.toFixed(1) : Math.round(p)) + '%';
  }
  const rowName = (r) => (r.kind === 'other' ? t('su.other') : r.name);
  const rowHint = (r) => (r.kind === 'other' ? t('su.otherHint') : r.kind === 'app' ? fill(t('su.appHint'), { name: r.name }) : '');

  function build() {
    const p = {};
    p.toggle = el('input');
    p.toggle.type = 'checkbox';
    p.toggle.id = 'siteUsageOn';
    p.toggle.onchange = () => { Promise.resolve(hook('save', { siteUsage: p.toggle.checked })).then(read, read); };
    const label = el('label', 'su-toggle');
    p.toggleText = el('span');
    label.append(p.toggle, p.toggleText);

    p.seg = el('div', 'seg su-range');
    p.segButtons = RANGES.map(([id, key]) => {
      const b = el('button', 'seg-btn');
      b.type = 'button';
      b.dataset.range = id;
      b.dataset.key = key;
      b.onclick = () => { ui.range = id; ui.showAll = false; read(); };
      p.seg.appendChild(b);
      return b;
    });
    p.clear = el('button', 'btn ghost small su-clear');
    p.clear.type = 'button';
    p.clear.onclick = clearClicked;
    const bar = el('div', 'su-bar');
    bar.append(label, p.seg, p.clear);

    p.devWrap = el('label', 'su-dev');
    p.devLabel = el('span', 'su-dev-label');
    p.dev = el('select', 'select su-dev-pick');
    p.dev.onchange = () => { ui.device = p.dev.value; ui.showAll = false; read(); };
    p.devWrap.append(p.devLabel, p.dev);

    p.why = el('p', 'su-why');
    p.why.setAttribute('role', 'status');
    p.sum = el('p', 'su-sum');
    p.list = el('div', 'su-list');
    p.list.setAttribute('role', 'list');
    p.more = el('button', 'btn ghost small su-more');
    p.more.type = 'button';
    p.more.onclick = () => { ui.showAll = true; paint(); };
    p.empty = el('p', 'su-empty');
    p.note = el('p', 'su-note');
    p.cost = el('p', 'su-cost');
    ui.host.append(bar, p.devWrap, p.why, p.sum, p.list, p.more, p.empty, p.note, p.cost);
    ui.parts = p;
  }

  /** The button asks once more before it empties anything: a second click within 4 s. */
  function clearClicked() {
    if (Date.now() - ui.armed > 4000) {
      ui.armed = Date.now();
      paint();
      setTimeout(paint, 4100);
      return;
    }
    ui.armed = 0;
    window.api.sitesClear().then(read, () => {});
  }

  function paintRow(r, top, total) {
    const row = el('div', 'su-row');
    row.setAttribute('role', 'listitem');
    row.title = fill(t('su.rowTitle'), { down: bytesText(r.down), up: bytesText(r.up) }) + (rowHint(r) ? '\n' + rowHint(r) : '');
    const name = el('span', 'su-name' + (r.kind === 'other' ? ' su-name-other' : ''), rowName(r));
    if (r.kind !== 'other') name.dir = 'ltr';
    const track = el('span', 'su-track');
    const fillBar = el('span', 'su-fill');
    fillBar.style.inlineSize = (top > 0 ? Math.max(1, (r.total / top) * 100) : 0).toFixed(1) + '%';
    track.appendChild(fillBar);
    const share = el('span', 'su-share', shareText(r.total, total));
    share.dir = 'ltr';
    const bytes = el('span', 'su-bytes', bytesText(r.total));
    bytes.dir = 'ltr';
    row.append(name, track, share, bytes);
    return row;
  }

  /** The device picker: rebuilt only when its list changed, and never under an open menu (a rebuild resets a select). */
  function paintDevices(d) {
    const p = ui.parts;
    p.devWrap.hidden = !Array.isArray(d.devices);
    if (p.devWrap.hidden) return;
    p.devLabel.textContent = t('su.device');
    const list = [{ id: '', label: t('su.device.all') }].concat(d.devices.map((x) => ({
      id: x.id,
      label: (x.id === 'router' ? t('su.device.router') : (x.name || x.id)) + ' · ' + bytesText(x.total)
    })));
    if (ui.device && !list.some((x) => x.id === ui.device)) list.push({ id: ui.device, label: ui.device });
    const drawn = t('su.device.all') + '|' + list.map((x) => x.id + '=' + x.label).join('|');
    if (drawn === ui.devicesDrawn || document.activeElement === p.dev) return;
    ui.devicesDrawn = drawn;
    p.dev.textContent = '';
    for (const x of list) {
      const o = el('option', '', x.label);
      o.value = x.id;
      p.dev.appendChild(o);
    }
    p.dev.value = ui.device;
  }

  function paint() {
    const p = ui.parts;
    if (!p) return;
    const d = ui.data || { status: 'off', rows: [], total: { up: 0, down: 0, total: 0 }, since: '', more: 0 };
    p.toggleText.textContent = t('su.toggle');
    p.toggle.checked = !!hook('enabled');
    paintDevices(d);
    for (const b of p.segButtons) {
      b.textContent = t(b.dataset.key);
      b.classList.toggle('active', b.dataset.range === ui.range);
    }
    p.clear.textContent = t(Date.now() - ui.armed <= 4000 ? 'su.clearSure' : 'su.clear');
    p.clear.hidden = !d.rows.length;

    p.why.textContent = d.status === 'recording' ? t('su.recording') : t(WHY[d.status] || 'su.why.off');
    p.why.className = 'su-why' + (d.status === 'recording' ? ' su-why-on' : (d.status === 'off' ? '' : ' su-why-warn'));

    p.sum.hidden = !d.rows.length;
    p.sum.textContent = d.rows.length ? fill(t('su.sum'), { total: bytesText(d.total.total), down: bytesText(d.total.down), up: bytesText(d.total.up) }) : '';

    p.list.textContent = '';
    const shown = ui.showAll ? d.rows : d.rows.slice(0, FIRST_ROWS);
    const top = d.rows.length ? d.rows[0].total : 0;
    for (const r of shown) p.list.appendChild(paintRow(r, top, d.total.total));
    const hiddenRows = d.rows.length - shown.length + (ui.showAll ? d.more : 0);
    p.more.hidden = ui.showAll || hiddenRows <= 0;
    p.more.textContent = fill(t('su.more'), { n: hiddenRows });

    p.empty.hidden = !!d.rows.length || d.status === 'off';
    p.empty.textContent = t('su.empty');
    p.note.textContent = hook('router') ? fill(t('su.note.router'), { n: d.deviceDays || 0 }) : t('su.note');
    p.cost.hidden = !d.cost;
    p.cost.textContent = d.cost ? fill(t('su.cost'), { n: d.cost.conns, ms: d.cost.ms, s: Math.round(d.cost.everyMs / 1000) }) : '';
  }

  async function read() {
    const seq = ++ui.seq;
    let d = null;
    try { d = await window.api.sitesGet({ range: ui.range, device: ui.device }); } catch { d = null; }
    if (seq !== ui.seq) return;
    ui.data = d && typeof d === 'object' && Array.isArray(d.rows) ? d : null;
    paint();
  }

  function stop() {
    if (ui.timer) clearInterval(ui.timer);
    ui.timer = null;
  }

  function open() {
    if (!ui.parts) return;
    paint();
    read();
    stop();
    ui.timer = setInterval(() => {
      if (!hook('visible')) { stop(); return; }
      read();
    }, REFRESH_MS);
  }

  function mount(host, hooks) {
    ui.hooks = hooks || {};
    if (!host || !window.api || typeof window.api.sitesGet !== 'function') return false;
    ui.host = host;
    if (!ui.parts) build();
    paint();
    return true;
  }

  window.sitesPage = { mount, open, stop, render: () => paint(), polling: () => !!ui.timer, format: { bytesText, shareText } };
})();
