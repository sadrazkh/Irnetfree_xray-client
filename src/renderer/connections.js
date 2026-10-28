'use strict';
/**
 * «اتصال‌ها» / "Connections" — the Logs page's second tab: the tunnel's open
 * connections right now, app by app (src/main/connectionsWatch.js, channels
 * conns:get and conns:close). Drawn like the Users page (lanUsers.js) with
 * text nodes only: program names, host names and rule texts come from the
 * machine and the network, so nothing here is HTML.
 *
 *   - a bar: the filter (an app, a destination, an address or a route), how
 *     many connections are open and how fast the tunnel moves, expand /
 *     collapse all;
 *   - a row per app, folded to its head: the program's file name (left to
 *     right; its full path in the tooltip), how many connections, its live
 *     rates and its bytes; opened, a row per connection: where to (left to
 *     right), TCP or UDP, from which device when it is not this PC (a phone on
 *     the hotspot), its bytes and rate, how long it has been open, the way it
 *     took (the tunnel, direct, or an outbound of its own — the rule that sent
 *     it there in the tooltip) and a button that closes it;
 *   - when there is nothing to show, why: not connected, no TUN, a backend
 *     that cannot say (tun2socks, the native macOS service), an API silent.
 *
 * Read every POLL_MS while the tab is on screen and the connection is up:
 * app.js says when the tab opens (open()), when the connection comes or goes
 * (connection()) and when the language changes (render()); the page stops by
 * itself once it is not on screen (hooks.visible()), and while there is
 * nothing a next read could change (not connected, no TUN, a backend without
 * the API). Rows are kept by key and updated in place, and while the pointer
 * or the focus is inside the list none is added, moved or removed — one that
 * ended is dimmed instead — so a close button never slides away from under
 * the cursor between two reads.
 */
(() => {
  const t = (key) => window.i18n.t(key);
  const fill = (s, map) => String(s).replace(/\{(\w+)\}/g, (m, k) => (Object.prototype.hasOwnProperty.call(map, k) ? map[k] : m));
  const lang = () => (window.i18n && window.i18n.lang) || document.documentElement.lang || 'fa';
  const POLL_MS = 1500;
  // where a program on this PC is seen from inside the tunnel: the TUN's own addresses (tunSingbox.js), loopback
  const LOCAL = ['', '172.19.0.1', 'fdfe:dcba:9876::1', '127.0.0.1', '::1'];
  // the outbounds of tunSingbox.buildTunConfig everyone knows; any other tag is shown as it is named
  const OUT = { 'socks-out': 'cn.out.tunnel', direct: 'cn.out.direct' };

  const ui = {
    host: null, hooks: {}, parts: null,
    data: null,            // the last conns:get answer (normalized), null before the first / while disconnected
    loading: false,
    seq: 0, timer: null,
    filter: '',
    open: new Set(),       // the apps unfolded, by name
    apps: new Map(),       // app name → its row
    conns: new Map(),      // connection id → its row
    gone: new Set(),       // closed from here; the next read may still list them
    pointer: false, focus: false
  };

  /* ------------------------------ building blocks ------------------------------ */

  function mk(tag, className, text) {
    const n = document.createElement(tag);
    if (className) n.className = className;
    if (text != null && text !== '') n.textContent = String(text);
    return n;
  }
  function button(className, text) {
    const b = mk('button', className, text);
    b.type = 'button';
    return b;
  }
  /** Left to right inside a Persian line: program names, destinations, addresses, bytes. */
  function ltr(n) { n.setAttribute('dir', 'ltr'); return n; }
  const hook = (name, ...a) => (typeof ui.hooks[name] === 'function' ? ui.hooks[name](...a) : undefined);
  const connected = () => !!hook('connected');
  const visible = () => !!hook('visible');
  function detach(n) { if (n && n.parentNode) n.parentNode.removeChild(n); }
  /** The children of `parent` in `nodes`' order — only what is out of place moves (a moved node loses focus). */
  function order(parent, nodes) {
    nodes.forEach((n, i) => { if (parent.childNodes[i] !== n) parent.insertBefore(n, parent.childNodes[i] || null); });
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
  /** '↓ 1.2 MB/s  ↑ 3.0 KB/s' while it moves, '' when it does not. */
  const rateLine = (x) => (x && (Number(x.down) > 0 || Number(x.up) > 0) ? '↓ ' + rateText(x.down) + '  ↑ ' + rateText(x.up) : '');
  const bytesLine = (x) => '↓ ' + bytesText(x.download) + '  ↑ ' + bytesText(x.upload);
  /** How long a connection has been open: '12 ثانیه', '4 min', '1 h 5 min'. */
  function ageText(ms) {
    const s = Math.max(0, Math.floor((Number(ms) || 0) / 1000));
    if (s < 60) return fill(t('cn.age.s'), { s });
    const m = Math.floor(s / 60);
    if (m < 60) return fill(t('cn.age.m'), { m });
    return fill(t('cn.age.h'), { h: Math.floor(m / 60), m: m % 60 });
  }
  /** The way a connection took, as people name it: the tunnel, direct, or the outbound's own tag. */
  const outName = (tag) => (OUT[tag] ? t(OUT[tag]) : (hook('outboundName', tag) || tag || '—'));
  const outClass = (tag) => (tag === 'socks-out' ? 'cn-out cn-out-tunnel' : tag === 'direct' ? 'cn-out cn-out-direct' : 'cn-out');
  const ruleText = (rule) => (!rule || rule === 'final' ? t('cn.rule.final') : rule);
  const appName = (app) => app || t('cn.unknown');

  /** Why there is nothing to show (connectionsWatch.js `reason`). */
  function whyText(d) {
    if (d.reason === 'off') return t('cn.why.off');
    if (d.reason === 'noTun') return t('cn.why.noTun');
    if (d.reason === 'router') return t('cn.why.router');
    if (d.reason === 'backend') return t(d.backend === 'tun2socks' ? 'cn.why.tun2socks' : d.backend === 'native-macos' ? 'cn.why.native' : 'cn.why.backend');
    return fill(t('cn.why.error'), { error: d.error || '—' });
  }

  /** The answer as the page draws it: anything malformed is an error, never a throw mid-draw. */
  function normalize(d) {
    if (!d || typeof d !== 'object') return { available: false, reason: 'error', error: 'no answer' };
    if (!d.available) return { available: false, reason: String(d.reason || 'error'), backend: d.backend || '', error: d.error || '' };
    const apps = (Array.isArray(d.apps) ? d.apps : []).filter((g) => g && typeof g === 'object').map((g) => ({
      app: typeof g.app === 'string' ? g.app : '',
      paths: Array.isArray(g.paths) ? g.paths.map(String) : [],
      count: Number(g.count) || 0, more: Number(g.more) || 0,
      upload: Number(g.upload) || 0, download: Number(g.download) || 0, up: Number(g.up) || 0, down: Number(g.down) || 0,
      connections: (Array.isArray(g.connections) ? g.connections : []).filter((c) => c && typeof c.id === 'string')
    }));
    const totals = Object.assign({ count: 0, upload: 0, download: 0, up: 0, down: 0 }, d.totals || {});
    return { available: true, at: Number(d.at) || 0, processes: d.processes !== false, apps, totals };
  }

  /* ------------------------------ what the filter keeps ------------------------------ */

  const has = (s, q) => String(s == null ? '' : s).toLowerCase().includes(q);
  /** A connection matches by where it goes, its address, the device it came from, the way it took. */
  const matches = (c, q) => [c.dest, c.ip, c.source, c.network, c.outbound, outName(c.outbound)].some((s) => has(s, q));
  /**
   * [{ g, conns, forced }]: an app whose name (or path) matches with all its
   * connections; else one with some that match, only those, unfolded (`forced`).
   */
  function shown(apps) {
    const q = ui.filter.trim().toLowerCase();
    const out = [];
    for (const g of apps) {
      const conns = g.connections;
      if (!q || has(appName(g.app), q) || g.paths.some((p) => has(p, q))) { out.push({ g, conns, forced: false }); continue; }
      const hit = conns.filter((c) => matches(c, q));
      if (hit.length) out.push({ g, conns: hit, forced: true });
    }
    return out;
  }

  /* ------------------------------ drawing ------------------------------ */

  /** The bar, the status line and the list: built once at mount, filled by paint(). */
  function build() {
    const bar = mk('div', 'cn-bar');
    const filter = mk('input', 'input cn-filter');
    filter.type = 'search';
    filter.setAttribute('dir', 'auto');
    filter.dataset.cn = 'filter';
    filter.addEventListener('input', () => { ui.filter = filter.value; paint(); });
    const sum = mk('span', 'cn-sum');
    const sumRate = ltr(mk('span', 'cn-sum-rate'));
    const tools = mk('span', 'cn-tools');
    const expand = button('cg-link');
    expand.dataset.cn = 'expand';
    expand.addEventListener('click', () => { for (const g of (ui.data && ui.data.apps) || []) ui.open.add(g.app); paint(); });
    const collapse = button('cg-link');
    collapse.dataset.cn = 'collapse';
    collapse.addEventListener('click', () => { ui.open.clear(); paint(); });
    tools.append(expand, collapse);
    bar.append(filter, sum, sumRate, tools);
    const status = mk('p', 'hint cn-status');
    const list = mk('div', 'cn-list');
    // while the pointer or the focus is in the list, its rows hold still (see the header)
    list.addEventListener('pointerenter', () => { ui.pointer = true; });
    list.addEventListener('pointerleave', () => { ui.pointer = false; paint(); });
    list.addEventListener('focusin', () => { ui.focus = true; });
    list.addEventListener('focusout', (ev) => { if (ev && ev.relatedTarget && list.contains(ev.relatedTarget)) return; ui.focus = false; paint(); });
    ui.host.replaceChildren(bar, status, list);
    ui.parts = { bar, filter, sum, sumRate, expand, collapse, status, list };
  }

  /** An app's row: its head (a button that folds it) and the box its connections go in. */
  function appRow(name) {
    const el = mk('div', 'cn-app');
    el.dataset.app = name;
    const head = button('cn-head');
    head.dataset.cn = 'a:' + name;
    const caret = mk('span', 'cn-caret');
    caret.setAttribute('aria-hidden', 'true');
    const label = mk('span', 'cn-name');
    if (name) ltr(label);
    const count = mk('span', 'cn-count');
    const rate = ltr(mk('span', 'cn-rate'));
    const bytes = ltr(mk('span', 'cn-bytes'));
    // the name stays beside the caret, the figures at the row's end (a left-to-right name that grew would sit at its own left)
    head.append(caret, label, mk('span', 'cn-fill'), count, rate, bytes);
    head.addEventListener('click', () => {
      if (ui.open.has(name)) ui.open.delete(name); else ui.open.add(name);
      paint();
    });
    const body = mk('div', 'cn-conns');
    const more = mk('p', 'hint cn-more');
    el.append(head, body);
    return { el, head, caret, label, count, rate, bytes, body, more, name };
  }

  /** A connection's row: where to, how, how much, how long, which way — and its close button. */
  function connRow(id) {
    const el = mk('div', 'cn-conn');
    el.dataset.id = id;
    const dest = ltr(mk('span', 'cn-dest'));
    const net = mk('span', 'cn-net');
    const from = mk('span', 'cn-from');
    const bytes = ltr(mk('span', 'cn-bytes'));
    const rate = ltr(mk('span', 'cn-rate'));
    const age = mk('span', 'cn-age');
    const out = mk('span', 'cn-out');
    const x = button('icon-btn danger cn-x', '✕');
    x.dataset.cn = 'x:' + id;
    x.addEventListener('click', () => closeConn(id));
    el.append(dest, mk('span', 'cn-fill'), net, from, bytes, rate, age, out, x);
    return { el, dest, net, from, bytes, rate, age, out, x, id, app: null };
  }

  function paintConn(r, c, gone) {
    r.dest.textContent = c.dest || c.ip || '—';
    r.dest.title = [c.dest, c.ip && !String(c.dest || '').includes(c.ip) ? c.ip : ''].filter(Boolean).join(' · ');
    r.net.textContent = String(c.network || '').toUpperCase();
    r.net.hidden = !c.network;
    const away = !LOCAL.includes(String(c.source || ''));
    r.from.textContent = away ? fill(t('cn.from'), { ip: c.source }) : '';
    r.from.hidden = !away;
    r.bytes.textContent = bytesLine(c);
    const rate = gone ? '' : rateLine(c);
    r.rate.textContent = rate;
    r.rate.hidden = !rate;
    r.age.textContent = ageText(c.age);
    r.out.className = outClass(c.outbound);
    r.out.textContent = outName(c.outbound);
    r.out.title = ruleText(c.rule) + ((c.chain || []).length > 1 ? ' · ' + c.chain.join(' → ') : '');
    r.x.setAttribute('aria-label', t('cn.close'));
    r.x.title = t('cn.close');
    r.x.disabled = !!gone;
    r.el.classList.toggle('cn-gone', !!gone);
  }

  function paintApp(row, g, conns, forced, still) {
    const open = forced || ui.open.has(g.app);
    row.head.setAttribute('aria-expanded', String(open));
    row.caret.textContent = open ? '▾' : (lang() === 'fa' ? '◂' : '▸');
    row.label.textContent = appName(g.app);
    row.head.title = g.paths.join('\n');
    row.count.textContent = fill(t('cn.count'), { n: g.count });
    const rate = rateLine(g);
    row.rate.textContent = rate;
    row.rate.hidden = !rate;
    row.bytes.textContent = bytesLine(g);
    row.el.classList.remove('cn-gone');
    row.body.hidden = !open;
    // a folded app keeps no rows (thousands of a torrent client's would be redrawn for nobody)
    const want = open ? conns : [];
    const keep = new Set();
    const nodes = [];
    for (const c of want) {
      let r = ui.conns.get(c.id);
      // one closed from here: dimmed while the list holds still, else not drawn
      const gone = ui.gone.has(c.id);
      if (gone && !still) continue;
      if (!r) {
        if (still) continue;
        r = connRow(c.id);
        ui.conns.set(c.id, r);
      }
      r.app = g.app;
      keep.add(c.id);
      nodes.push(r.el);
      paintConn(r, c, gone);
    }
    for (const [id, r] of ui.conns) {
      if (r.app !== g.app || keep.has(id)) continue;
      if (still && r.el.parentNode === row.body) { r.el.classList.add('cn-gone'); r.x.disabled = true; r.rate.hidden = true; continue; }
      detach(r.el);
      ui.conns.delete(id);
    }
    if (!still) {
      order(row.body, nodes);
      const more = open && g.more > 0 && !ui.filter.trim();
      row.more.textContent = more ? fill(t('cn.more'), { n: g.more }) : '';
      if (more) row.body.appendChild(row.more); else detach(row.more);
    }
  }

  /** The status line: why nothing is drawn, or what is odd about what is. */
  function statusText(d, rows) {
    if (!connected()) return t('cn.why.off');
    if (!d) return ui.loading ? t('cn.loading') : '';
    if (!d.available) return whyText(d);
    if (!d.apps.length) return t('cn.none');
    if (!rows.length) return t('cn.noMatch');
    if (!d.processes) return t('cn.noProcess');
    return '';
  }

  /**
   * Everything from ui.data. `still` (a read's paint while the pointer or the
   * focus is in the list): rows only change their words — none comes, goes or
   * moves until the pointer leaves.
   */
  function paint(opts) {
    if (!ui.parts) return;
    const P = ui.parts;
    const still = !!(opts && opts.fromRead) && (ui.pointer || ui.focus);
    P.filter.placeholder = t('cn.filter');
    P.filter.setAttribute('aria-label', t('cn.filter'));
    P.expand.textContent = t('cn.expandAll');
    P.collapse.textContent = t('cn.collapseAll');
    const d = connected() ? ui.data : null;
    const live = !!(d && d.available);
    const rows = live ? shown(d.apps) : [];
    P.bar.hidden = !live;
    P.sum.textContent = live ? fill(t('cn.sum'), { n: d.totals.count }) : '';
    const tr = live ? rateLine(d.totals) : '';
    P.sumRate.textContent = tr;
    P.sumRate.hidden = !tr;
    P.expand.hidden = P.collapse.hidden = !rows.length;
    const msg = statusText(d, rows);
    P.status.textContent = msg;
    P.status.hidden = !msg;
    P.status.classList.toggle('cn-warn', !!(d && !d.available && d.reason === 'error'));

    const keep = new Set();
    const nodes = [];
    for (const { g, conns, forced } of rows) {
      let row = ui.apps.get(g.app);
      if (!row) {
        if (still) continue;
        row = appRow(g.app);
        ui.apps.set(g.app, row);
      }
      keep.add(g.app);
      nodes.push(row.el);
      paintApp(row, g, conns, forced, still);
    }
    for (const [name, row] of ui.apps) {
      if (keep.has(name)) continue;
      if (still && row.el.parentNode === P.list) { row.el.classList.add('cn-gone'); continue; }
      detach(row.el);
      ui.apps.delete(name);
      for (const [id, r] of ui.conns) if (r.app === name) ui.conns.delete(id);
    }
    if (!still) order(P.list, nodes);
    P.list.hidden = !nodes.length && !still;
  }

  /* ------------------------------ reading, closing ------------------------------ */

  function stop() {
    if (ui.timer) clearTimeout(ui.timer);
    ui.timer = null;
  }
  function schedule() {
    stop();
    if (!ui.parts || !visible() || !connected()) return;
    ui.timer = setTimeout(() => { ui.timer = null; read(); }, POLL_MS);
  }

  /** One conns:get, drawn; the next one scheduled while there is something a read can change. */
  async function read() {
    stop();
    if (!ui.parts || !visible()) return;
    if (!connected()) { ui.data = null; paint(); return; }
    const seq = ++ui.seq;
    ui.loading = true;
    if (!ui.data) paint();
    let d;
    try { d = await window.api.connsGet(); } catch (e) { d = { available: false, reason: 'error', error: (e && e.message) || String(e) }; }
    if (seq !== ui.seq) return;     // a newer read is on its way
    ui.loading = false;
    ui.data = normalize(d);
    // a connection closed from here: forgotten once the tunnel no longer lists it
    if (ui.gone.size) {
      const listed = new Set();
      if (ui.data.available) for (const g of ui.data.apps) for (const c of g.connections) listed.add(c.id);
      for (const id of [...ui.gone]) if (!listed.has(id)) ui.gone.delete(id);
    }
    paint({ fromRead: true });
    // connections to watch, or an API that may answer next time; not connected / no TUN / no API: wait for connection()
    if (ui.data.available || ui.data.reason === 'error') schedule();
  }

  /** The close button: DELETE on the tunnel's API; the program sees its connection reset. */
  async function closeConn(id) {
    const r = ui.conns.get(id);
    if (r) r.x.disabled = true;
    let res;
    try { res = await window.api.connsClose(id); } catch (e) { res = { ok: false, error: (e && e.message) || String(e) }; }
    if (res && res.ok) {
      ui.gone.add(id);
      paint({ fromRead: true });   // dimmed while the pointer is on the list, gone once it leaves
      return true;
    }
    if (r) r.x.disabled = false;
    hook('toast', t('cn.closeFailed') + (res && res.error ? ': ' + res.error : ''), 'err');
    return false;
  }

  /* ------------------------------ app.js's hooks ------------------------------ */

  /**
   * The tab's box and app.js's hooks — { connected(), visible(), router(),
   * toast(msg, kind), outboundName(tag)? }. → whether the tab is there at all:
   * not on a back end without the channels, not on the router (its tunnel
   * carries devices, not programs: the Users page shows those).
   */
  function mount(host, hooks) {
    ui.host = host || null;
    ui.hooks = hooks || {};
    ui.parts = null;
    if (!ui.host) return false;
    if (!window.api || !window.api.connsGet || hook('router')) { ui.host.hidden = true; return false; }
    build();
    paint();
    return true;
  }

  /** The tab came on screen: read now, then every POLL_MS while it stays. */
  function open() { return read(); }

  /** Connected or not: gone — everything forgotten; back while on screen — read at once. */
  function connection(on) {
    if (!on) {
      stop();
      ui.seq++;          // a read on its way answers for the connection that ended
      ui.data = null;
      ui.loading = false;
      ui.gone.clear();
      paint();
      return;
    }
    if (ui.parts && visible()) read(); else paint();
  }

  window.connsPage = {
    mount,
    open,
    connection,
    render: () => paint(),
    stop,
    polling: () => !!ui.timer,
    format: { bytesText, ageText }
  };
})();
