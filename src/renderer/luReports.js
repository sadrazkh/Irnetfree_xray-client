'use strict';
/**
 * «گزارش‌ها» / Reports — what each user of the Users page (lanUsers.js) used,
 * beyond the 30 days their box draws:
 *
 *   monthsChart(user, usage)  the last 12 months as stacked bars (VPN under
 *                             direct), drawn like the 30-day chart (the same
 *                             SVG node by node, the same swatches); the months
 *                             are THE USER'S — the calendar and renew day their
 *                             monthly limits follow (capPeriods.js keys:
 *                             'j1405-08' Aban 1405, '2026-10@15' 15 Oct – 15
 *                             Nov) — and their labels that calendar's names:
 *                             Persian months for a jalali user («آبان», or
 *                             "Aban" in English), Gregorian for the rest. A
 *                             month nothing was used in is an empty slot, so a
 *                             gap reads as a gap and twelve slots are always
 *                             twelve months.
 *   csv(user) / csvAll()      one row per month and one per day of the 30-day
 *                             history — the period, VPN, direct and total in
 *                             bytes and in GB — UTF-8 with a BOM (Excel opens
 *                             Persian names as Persian only with one), saved
 *                             through a Blob link: the same in the window and
 *                             on the router's web page, no file dialog of the
 *                             app's own.
 *   printBill(user, monthKey) a statement to print: who, the month and its
 *                             dates, VPN / direct / total, the month's limits
 *                             and top-ups when it is the running one (the
 *                             meter keeps no caps of a month gone by), its days
 *                             from the 30-day history, and the admin's contact.
 *   monthList(user, usage)    the months there are, newest first, for a picker.
 *
 * The numbers are the meter's (src/modules/lanUsers/meter.js): usage()[id]
 * .months — [{ key, from, to, vpn, direct }] oldest first, the running month
 * the last — and .history — [{ day, vpn, direct }]. Everything else (the
 * words, the bytes as the app writes them, the users) comes through
 * window.LanUsersKit, read at the time of each call: the page that exposes it
 * may load after this file. Text nodes only, as everywhere on that page —
 * names come from people.
 *
 * One file for the window, the router's page (window.LuReports) and Node
 * (tests require its pure parts: month keys, labels, rows, the CSV text).
 */
(function (root, factory) {
  const api = factory(root);
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.LuReports = api;
}(typeof window !== 'undefined' ? window : (typeof self !== 'undefined' ? self : this), function (root) {
  const SVG_NS = 'http://www.w3.org/2000/svg';
  const MONTHS = 12;                                // the chart's slots (the meter keeps 13: a year back and this month)
  const GIB = 1024 ** 3;
  const BOM = '﻿';
  /** A month's key, as capPeriods.js writes one: 'YYYY-MM', 'YYYY-MM@D', 'jYYYY-MM', 'jYYYY-MM@D'. */
  const MONTH_KEY = /^(j?)(\d{4})-(\d{2})(?:@(\d{1,2}))?$/;
  const DAY_KEY = /^(\d{4})-(\d{2})-(\d{2})$/;
  const COLS = ['username', 'name', 'kind', 'period', 'label', 'from', 'to', 'vpn', 'direct', 'total', 'vpnGb', 'directGb', 'totalGb'];
  const TEXT_COLS = new Set(['username', 'name', 'label']);

  /* ------------------------------ the page around it ------------------------------ */

  const kit = () => (root && root.LanUsersKit && typeof root.LanUsersKit === 'object' ? root.LanUsersKit : null);
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
  const fa = () => lang() === 'fa';
  const obj = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : {});
  const arr = (v) => (Array.isArray(v) ? v : []);
  const num = (v) => Math.max(0, Number(v) || 0);

  /** Bytes as the app writes them (app.js fmtBytes): the kit's, else the same rule — binary units, one decimal. */
  function bytesText(n) {
    const k = kit();
    if (k && typeof k.fmtBytes === 'function') return k.fmtBytes(n);
    let v = Number(n) || 0;
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return (i === 0 ? Math.round(v) : v.toFixed(1)) + ' ' + units[i];
  }
  /** GB as a column of numbers: three decimals, a dot — what a spreadsheet sums. */
  const gbCol = (bytes) => (num(bytes) / GIB).toFixed(3);

  function el(tag, className, text) {
    const n = doc().createElement(tag);
    if (className) n.className = className;
    if (text != null && text !== '') n.textContent = String(text);
    return n;
  }
  function ltr(n) { n.setAttribute('dir', 'ltr'); return n; }
  function svgEl(tag, attrs) {
    const n = doc().createElementNS(SVG_NS, tag);
    for (const [k, v] of Object.entries(attrs || {})) n.setAttribute(k, String(v));
    return n;
  }
  const svgNum = (v) => String(Math.round(v * 100) / 100);

  /** A user's usage: the one handed in (usage[id], or the whole map), else the kit's payload's. */
  function usageFor(user, usage) {
    const id = user && user.id;
    const u = obj(usage);
    if (Array.isArray(u.months) || Array.isArray(u.history) || Array.isArray(u.meters)) return u;
    if (id && u[id] && typeof u[id] === 'object') return u[id];
    const k = kit();
    const data = k && typeof k.data === 'function' ? obj(k.data()) : {};
    return id ? obj(obj(data.usage)[id]) : {};
  }

  /* ------------------------------ dates ------------------------------ */

  const pad = (n) => String(n).padStart(2, '0');
  /** ms → 'YYYY-MM-DD', this device's day ('' for none) — the date a spreadsheet reads in any locale. */
  function isoDay(ms) {
    const d = new Date(Number(ms));
    if (!(Number(ms) > 0) || !Number.isFinite(d.getTime())) return '';
    return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate());
  }
  /** 'YYYY-MM-DD' → local midnight of that day, ms (NaN for anything else). */
  function dayMs(day) {
    const m = DAY_KEY.exec(String(day || ''));
    return m ? new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3])).getTime() : NaN;
  }
  function format(ms, opts) {
    const d = new Date(Number(ms));
    if (!Number.isFinite(d.getTime())) return '';
    // fa-IR is the Persian calendar; Latin digits, as every number in the app (lanUsers.js format)
    try { return new Intl.DateTimeFormat(fa() ? 'fa-IR-u-nu-latn' : 'en', opts).format(d); }
    catch { return isoDay(ms); }
  }
  /** A day with its year: '4 آبان 1405', 'October 26, 2026'. */
  const fullDate = (ms) => (Number(ms) > 0 ? format(ms, { year: 'numeric', month: 'long', day: 'numeric' }) : '');

  /* ------------------------------ month keys ------------------------------ */

  /** A month's key → { jalali, y, m, day } (day: the renew day, 1 for none), or null. */
  function parseKey(key) {
    const k = MONTH_KEY.exec(String(key == null ? '' : key));
    if (!k) return null;
    const m = Number(k[3]);
    const day = k[4] ? Number(k[4]) : 1;
    if (m < 1 || m > 12 || day < 1 || day > 31) return null;
    return { jalali: k[1] === 'j', y: Number(k[2]), m, day };
  }
  const keyOf = (p) => (p.jalali ? 'j' : '') + p.y + '-' + pad(p.m) + (p.day > 1 ? '@' + p.day : '');
  /** The key `n` months after `key`, in its calendar, renewing on its day: both calendars have twelve. */
  function stepKey(key, n) {
    const p = parseKey(key);
    if (!p) return null;
    const i = p.y * 12 + (p.m - 1) + n;
    const y = Math.floor(i / 12);
    return keyOf({ jalali: p.jalali, y, m: i - y * 12 + 1, day: p.day });
  }
  /** Two keys of one kind of month: one calendar, one renew day. */
  const sameFrame = (a, b) => !!a && !!b && a.jalali === b.jalali && a.day === b.day;

  /**
   * A day in the middle of Persian month y/m, as a Date. Farvardin 1 falls on
   * 20, 21 or 22 March of year y + 621, the first six months have 31 days and
   * the next five 30: its 15th from 21 March is never more than a day off, and
   * a day off is still the same month — the window's Intl then names it in
   * the Persian calendar (tests check every month of 1380–1450 against
   * src/main/jalali.js). The page has no calendar arithmetic of its own; this
   * is all a label needs.
   */
  function midJalali(y, m) {
    const offset = m <= 6 ? (m - 1) * 31 : 186 + (m - 7) * 30;
    return new Date(y + 621, 2, 21 + offset + 14);
  }
  /**
   * A month's name in its own calendar and the page's language: آبان / Aban
   * for a Persian month, اکتبر / October (Oct when `short`) for a Gregorian one.
   */
  function monthName(p, short) {
    const d = p.jalali ? midJalali(p.y, p.m) : new Date(p.y, p.m - 1, 15);
    const loc = p.jalali ? (fa() ? 'fa-IR-u-nu-latn' : 'en-u-ca-persian') : (fa() ? 'fa-IR-u-ca-gregory-nu-latn' : 'en');
    try { return new Intl.DateTimeFormat(loc, { month: short && !fa() ? 'short' : 'long' }).format(d); }
    catch { return pad(p.m); }
  }
  /** A month as words: 'آبان 1405', 'Aban 1405', 'October 2026' — the year its key's (the calendar's own). */
  function monthLabel(key, short) {
    const p = parseKey(key);
    return p ? monthName(p, short) + ' ' + p.y : String(key || '');
  }

  /**
   * The meter's months as the chart's twelve slots, oldest first, the newest
   * the last month the meter has (the running one). Every key of one calendar
   * and renew day — the usual case — fills the twelve months up to it, a month
   * without an entry an empty slot (`gap`); keys of more than one (the calendar
   * or the renew day changed within the year) cannot be laid on one line of
   * months, so the last twelve are shown as they are.
   */
  function monthSlots(months, n = MONTHS) {
    const list = arr(months).filter((m) => m && parseKey(m.key))
      .map((m) => ({ key: String(m.key), from: num(m.from), to: num(m.to), vpn: num(m.vpn), direct: num(m.direct), gap: false }));
    if (!list.length) return [];
    const last = list[list.length - 1];
    const frame = parseKey(last.key);
    if (!list.every((m) => sameFrame(parseKey(m.key), frame))) return list.slice(-n);
    const byKey = new Map(list.map((m) => [m.key, m]));
    const out = [];
    for (let i = n - 1; i >= 0; i--) {
      const key = stepKey(last.key, -i);
      out.push(byKey.get(key) || { key, from: 0, to: 0, vpn: 0, direct: 0, gap: true });
    }
    return out;
  }

  /** The months there are, newest first: [{ key, label, from, to, vpn, direct }] — a statement's picker. */
  function monthList(user, usage) {
    return arr(usageFor(user, usage).months).filter((m) => m && parseKey(m.key))
      .map((m) => ({ key: String(m.key), label: monthLabel(m.key), from: num(m.from), to: num(m.to), vpn: num(m.vpn), direct: num(m.direct) }))
      .reverse();
  }

  /** A month's dates in words: '1 آبان 1405 تا 30 آبان 1405' — its last day is the one before the next begins. */
  function rangeText(from, to) {
    if (!(from > 0) || !(to > from)) return '';
    return fill(t('lu.rep.range'), { from: fullDate(from), to: fullDate(to - 1) });
  }

  /* ------------------------------ the 12-month chart ------------------------------ */

  /**
   * The last twelve months of `user` (`usage`: their usage, or the whole map):
   * a head with the twelve months' VPN and direct totals beside their
   * swatches, a bar a month (VPN under direct, each with its month, its dates
   * and its numbers in its <title>), and the months' names under the bars —
   * HTML, not SVG text: the bars stretch to the box (preserveAspectRatio
   * none, as the 30-day chart's), which would stretch letters with them. Time
   * runs left to right in both languages, as on the 30-day chart; the running
   * month's name is marked, and a month that opens a year carries the year.
   * Always an element — with no months yet, the line that says so.
   */
  function monthsChart(user, usage) {
    const box = el('div', 'lu-mchart');
    box.dataset.months = String((user && user.id) || '');
    const slots = monthSlots(usageFor(user, usage).months);
    const used = slots.filter((s) => s.vpn + s.direct > 0);
    if (!used.length) {
      box.append(el('p', 'hint lu-mc-empty', t('lu.rep.noMonths')));
      return box;
    }
    const W = 10;            // a month's slot in the view box; its bar is BAR of it
    const BAR = 7;
    const H = 60;
    const max = Math.max(...used.map((s) => s.vpn + s.direct));
    const sum = (k) => slots.reduce((a, s) => a + s[k], 0);
    const n = slots.length;
    const svg = svgEl('svg', { class: 'lu-mc-svg', viewBox: '0 0 ' + n * W + ' ' + H, preserveAspectRatio: 'none', role: 'img',
      'aria-label': fill(t('lu.rep.monthsAria'), { vpn: bytesText(sum('vpn')), direct: bytesText(sum('direct')) }) });
    svg.appendChild(svgEl('line', { class: 'lu-cbase', x1: 0, y1: H - 0.5, x2: n * W, y2: H - 0.5 }));
    const labels = ltr(el('div', 'lu-mc-labels'));
    labels.style.gridTemplateColumns = 'repeat(' + n + ', minmax(0, 1fr))';
    slots.forEach((s, i) => {
      const x = i * W;
      const g = svgEl('g', { class: 'lu-cbar', 'data-key': s.key });
      const title = svgEl('title');
      const words = fill(t('lu.rep.monthBar'), { month: monthLabel(s.key), vpn: bytesText(s.vpn), direct: bytesText(s.direct) });
      const range = rangeText(s.from, s.to);
      title.textContent = words + (range ? ' (' + range + ')' : '');
      // the whole slot answers the pointer: a short bar is still easy to point at
      g.append(title, svgEl('rect', { class: 'lu-chit', x, y: 0, width: W, height: H }));
      let top = H - 1;
      for (const k of ['vpn', 'direct']) {
        if (!(s[k] > 0)) continue;
        const h = Math.max(1, s[k] / max * (H - 2));
        top -= h;
        g.appendChild(svgEl('rect', { class: k === 'vpn' ? 'lu-cvpn' : 'lu-cdirect', x: svgNum(x + (W - BAR) / 2), y: svgNum(top), width: BAR, height: svgNum(h) }));
      }
      svg.appendChild(g);
      const p = parseKey(s.key);
      const cell = el('div', 'lu-mc-label' + (i === n - 1 ? ' lu-mc-now' : ''));
      cell.dataset.key = s.key;
      cell.title = monthLabel(s.key);
      cell.append(el('span', 'lu-mc-m', p ? monthName(p, true) : s.key));
      // the year under the first month of the chart and under each month that opens one
      if (p && (i === 0 || p.m === 1)) cell.append(el('span', 'lu-mc-y', String(p.y)));
      labels.append(cell);
    });
    const head = el('div', 'lu-chead');
    head.append(el('span', 'lu-ctitle', t('lu.rep.months')));
    for (const k of ['vpn', 'direct']) {
      const key = el('span', 'lu-ckey');
      const sw = el('i', 'lu-csw');
      sw.classList.add('lu-csw-' + k);
      sw.setAttribute('aria-hidden', 'true');
      key.append(sw, t('lu.kind.' + k) + ' ', ltr(el('bdi', null, bytesText(sum(k)))));
      head.append(key);
    }
    box.append(head, svg, labels);
    return box;
  }

  /* ------------------------------ CSV ------------------------------ */

  /**
   * A user's rows: a month a row (oldest first; its first and last day), then
   * a day a row of the 30-day history. Bytes as whole numbers, GB with three
   * decimals; the label in the page's language (the month's name in the
   * user's calendar, the day in the Persian calendar in Persian).
   */
  function rowsOf(user, usage) {
    const u = obj(user);
    const us = usageFor(u, usage);
    const who = { username: String(u.username || ''), name: String(u.name || '').trim() };
    const row = (kind, period, label, from, to, vpn, direct) => Object.assign({}, who, {
      kind: t('lu.rep.kind.' + kind), period, label, from, to,
      vpn: String(Math.round(num(vpn))), direct: String(Math.round(num(direct))), total: String(Math.round(num(vpn) + num(direct))),
      vpnGb: gbCol(vpn), directGb: gbCol(direct), totalGb: gbCol(num(vpn) + num(direct))
    });
    const out = [];
    for (const m of arr(us.months)) {
      if (!m || !parseKey(m.key)) continue;
      out.push(row('month', String(m.key), monthLabel(m.key), isoDay(m.from), num(m.to) > num(m.from) ? isoDay(num(m.to) - 1) : '', m.vpn, m.direct));
    }
    for (const h of arr(us.history)) {
      if (!h || !Number.isFinite(dayMs(h.day))) continue;
      out.push(row('day', String(h.day), fullDate(dayMs(h.day)), String(h.day), String(h.day), h.vpn, h.direct));
    }
    return out;
  }

  /**
   * One CSV field: quoted when it holds a comma, a quote, a line break or
   * edge spaces (RFC 4180); a text that starts like a formula (= + - @, a tab)
   * gets an apostrophe before it — a spreadsheet would run a name such as
   * "=HYPERLINK(…)" otherwise.
   */
  function field(v, text) {
    let s = String(v == null ? '' : v);
    if (text && /^[=+\-@\t\r]/.test(s)) s = "'" + s;
    return /[",\r\n]|^\s|\s$/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  }
  /** Rows → the file's text: a BOM, the header in the page's language, CRLF lines (what Excel writes). */
  function csvText(rows) {
    const lines = [COLS.map((c) => field(t('lu.rep.col.' + c), true)).join(',')];
    for (const r of arr(rows)) lines.push(COLS.map((c) => field(r[c], TEXT_COLS.has(c))).join(','));
    return BOM + lines.join('\r\n') + '\r\n';
  }

  /**
   * Save `text` as a file through a Blob link — the window (Electron saves a
   * link's download as a browser does) and the router's page alike. The link
   * is in the page for its click alone (a browser that clicks only what is
   * there), its URL let go after.
   */
  function download(text, filename, type) {
    const d = doc();
    const B = root && root.Blob ? root.Blob : (typeof Blob === 'function' ? Blob : null);
    const U = root && root.URL && root.URL.createObjectURL ? root.URL : (typeof URL === 'function' && URL.createObjectURL ? URL : null);
    if (!d || !B || !U) return false;
    const url = U.createObjectURL(new B([text], { type: type || 'text/csv;charset=utf-8' }));
    const a = el('a');
    a.href = url;
    a.download = filename;
    a.hidden = true;
    d.body.appendChild(a);
    try { a.click(); } finally { if (a.parentNode) a.parentNode.removeChild(a); }
    const later = root && typeof root.setTimeout === 'function' ? root.setTimeout : setTimeout;
    later(() => { try { U.revokeObjectURL(url); } catch { /* gone already */ } }, 2000);
    return true;
  }
  const today = () => isoDay(Date.now());
  /** A file's name from a username (letters, digits, . _ - only: the model's rule), whatever it holds. */
  const safe = (s) => String(s || '').replace(/[^A-Za-z0-9._-]+/g, '_').slice(0, 40) || 'user';

  /** One user's months and days as a CSV file: irnetfree-usage-<username>-<today>.csv. */
  function csv(user) {
    if (!user) return false;
    return download(csvText(rowsOf(user)), 'irnetfree-usage-' + safe(user.username) + '-' + today() + '.csv');
  }

  /** Every user's, one file: the users, then the vouchers that were used (an unused one has no rows to give). */
  function csvAll() {
    const k = kit();
    const list = (name) => (k && typeof k[name] === 'function' ? arr(k[name]()) : []);
    let people = list('users');
    if (!people.length && !list('vouchers').length && k && typeof k.data === 'function') people = arr(obj(k.data()).users);
    const rows = [];
    for (const u of people.concat(list('vouchers'))) rows.push(...rowsOf(u));
    return download(csvText(rows), 'irnetfree-usage-all-' + today() + '.csv');
  }

  /* ------------------------------ the statement ------------------------------ */

  /**
   * The month a statement is for: its entry, or — the key of a month nothing
   * was used in — zeros; with no key, the newest. A meter of before (no
   * months) still has the running month's VPN and direct in its meters.
   */
  function billMonth(us, monthKey) {
    const months = arr(us.months).filter((m) => m && parseKey(m.key));
    const pick = monthKey ? months.find((m) => String(m.key) === String(monthKey)) : months[months.length - 1];
    if (pick) return { key: String(pick.key), from: num(pick.from), to: num(pick.to), vpn: num(pick.vpn), direct: num(pick.direct), last: pick === months[months.length - 1] };
    if (monthKey && parseKey(monthKey)) return { key: String(monthKey), from: 0, to: 0, vpn: 0, direct: 0, last: false };
    const meter = (kind) => arr(us.meters).find((m) => m && m.kind === kind && m.period === 'month');
    const v = meter('vpn');
    const dr = meter('direct');
    if (!v && !dr) return null;
    const any = v || dr;
    return { key: '', from: num(any.since), to: num(any.until), vpn: num(v && v.bytes), direct: num(dr && dr.bytes), last: true };
  }
  /** The admin's words for the page: config.portal's contact and note (§1), when the payload has them. */
  function portalWords() {
    const k = kit();
    const data = k && typeof k.data === 'function' ? obj(k.data()) : {};
    const p = obj(obj(data.config).portal);
    return { contact: String(p.contact || '').trim(), note: String(p.note || '').trim() };
  }

  /** A template's words with each value in a <bdi> of its own: '3.5 GB از 25.0 GB' reads right in Persian. */
  function tpl(template, map) {
    return String(template).split(/(\{\w+\})/).filter(Boolean).map((p) => {
      const m = /^\{(\w+)\}$/.exec(p);
      return m && Object.prototype.hasOwnProperty.call(map, m[1]) ? el('bdi', null, map[m[1]]) : p;
    });
  }
  /**
   * A table of label → value rows. A value is a text (a size, a name: in a
   * <bdi> of its own, so a Persian name in an English statement and a size in
   * a Persian one each keep their order) or nodes from tpl().
   */
  function table(rows, cls) {
    const tb = el('table', 'lu-bill-tbl' + (cls ? ' ' + cls : ''));
    const body = el('tbody');
    for (const r of rows) {
      const tr = el('tr');
      r.forEach((c, i) => {
        const cell = el(i === 0 ? 'th' : 'td', i === 0 ? '' : 'lu-bill-num', i === 0 ? c : '');
        if (i > 0) cell.append(...(Array.isArray(c) ? c : (c === '' ? [] : [el('bdi', null, c)])));
        tr.append(cell);
      });
      body.append(tr);
    }
    tb.append(body);
    return tb;
  }

  /**
   * Print `user`'s statement for the month `monthKey` (the newest when none):
   * put in the page for the print alone (settings.css hides the rest while
   * html has .lu-printing, styles.css gives it white paper), gone after —
   * the wall sheet's way (lanUsers.js printPortal). The running month's
   * limits come from the meters, with their top-ups; a past month's are not
   * kept anywhere, so it has none.
   */
  function printBill(user, monthKey) {
    const d = doc();
    if (!user || !d || typeof root.print !== 'function') return false;
    const us = usageFor(user);
    const m = billMonth(us, monthKey) || { key: '', from: 0, to: 0, vpn: 0, direct: 0, last: false };
    const name = String(user.name || '').trim() || String(user.username || '');
    const sheet = el('div', 'lu-printsheet lu-bill');
    sheet.setAttribute('dir', fa() ? 'rtl' : 'ltr');
    sheet.dataset.key = m.key;

    const head = el('div', 'lu-bill-head');
    const words = el('div');
    words.append(el('h1', 'lu-bill-title', t('lu.rep.billTitle')), el('div', 'lu-bill-meta', fill(t('lu.rep.issued'), { date: fullDate(Date.now()) })));
    head.append(words, el('div', 'lu-bill-brand', 'IRNetFree'));
    sheet.append(head);

    const period = m.key ? monthLabel(m.key) : t('lu.thisMonth');
    const range = rangeText(m.from, m.to);
    const who = el('div', 'lu-bill-who');
    who.append(table([
      [t('lu.name'), name],
      [t('lu.username'), String(user.username || '')],
      [t('lu.rep.period'), period + (range ? ' — ' + range : '')]
    ], 'lu-bill-kv'));
    sheet.append(who);

    const now = Date.now();
    const sect = (title, ...nodes) => {
      const s = el('section', 'lu-bill-sect');
      s.append(el('h2', null, title), ...nodes);
      sheet.append(s);
      return s;
    };
    const total = m.vpn + m.direct;
    const use = [[t('lu.kind.vpn'), bytesText(m.vpn), gbCol(m.vpn) + ' GB'], [t('lu.kind.direct'), bytesText(m.direct), gbCol(m.direct) + ' GB'],
      [t('lu.kind.total'), bytesText(total), gbCol(total) + ' GB']];
    const useSect = sect(t('lu.usage'), table(use, 'lu-bill-use'));
    if (!total) useSect.append(el('p', 'lu-bill-note', t('lu.rep.noUse')));
    if (m.last && m.to > now) useSect.append(el('p', 'lu-bill-note', t('lu.rep.running')));

    // the running month's limits and top-ups: what the meters say now
    if (m.last) {
      const caps = arr(us.meters).filter((x) => x && (x.period === 'month' || x.period === 'none') && num(x.capBytes) > 0);
      if (caps.length) {
        const rows = caps.map((x) => {
          const extra = num(x.extraBytes);
          return [t('lu.kind.' + x.kind) + ' · ' + t(x.period === 'month' ? 'lu.thisMonth' : 'lu.oneOff'),
            tpl(t('lu.rep.capUsed'), { used: bytesText(x.bytes), cap: bytesText(num(x.capBytes) + extra) }),
            extra > 0 ? tpl(t('lu.rep.topUps'), { extra: '+' + bytesText(extra) }) : ''];
        });
        sect(t('lu.limits'), table(rows, 'lu-bill-caps'));
      }
    }

    // the month's days the 30-day history still has
    const days = arr(us.history).filter((h) => h && Number.isFinite(dayMs(h.day)) && (!(m.from > 0) || (dayMs(h.day) >= m.from && dayMs(h.day) < m.to)))
      .filter((h) => num(h.vpn) + num(h.direct) > 0);
    if (days.length && (m.from > 0 || !m.key)) {
      const tb = el('table', 'lu-bill-tbl lu-bill-days');
      const hr = el('tr');
      for (const c of [t('lu.rep.day'), t('lu.kind.vpn'), t('lu.kind.direct'), t('lu.kind.total')]) hr.append(el('th', null, c));
      const thead = el('thead');
      thead.append(hr);
      const body = el('tbody');
      for (const h of days) {
        const tr = el('tr');
        tr.append(el('td', null, fullDate(dayMs(h.day))));
        for (const v of [num(h.vpn), num(h.direct), num(h.vpn) + num(h.direct)]) tr.append(ltr(el('td', 'lu-bill-num', bytesText(v))));
        body.append(tr);
      }
      tb.append(thead, body);
      sect(t('lu.rep.days'), tb, el('p', 'lu-bill-note', t('lu.rep.daysNote')));
    }

    const p = portalWords();
    const foot = el('div', 'lu-bill-foot');
    if (p.note) foot.append(el('p', null, p.note));
    if (p.contact) {
      const c = el('p', null, t('lu.rep.contact') + ' ');
      c.append(ltr(el('bdi', 'lu-bill-contact', p.contact)));
      foot.append(c);
    }
    if (foot.childNodes.length) sheet.append(foot);
    return printSheet(sheet);
  }

  /** One sheet at a time on paper: the one before it (no afterprint yet) goes first. */
  let printing = null;
  function printSheet(sheet) {
    const d = doc();
    const html = d.documentElement;
    if (printing) printing();
    const done = () => {
      html.classList.remove('lu-printing');
      if (sheet.parentNode) sheet.parentNode.removeChild(sheet);
      if (typeof root.removeEventListener === 'function') root.removeEventListener('afterprint', done);
      if (printing === done) printing = null;
    };
    printing = done;
    d.body.appendChild(sheet);
    html.classList.add('lu-printing');
    if (typeof root.addEventListener === 'function') root.addEventListener('afterprint', done);
    const later = typeof root.setTimeout === 'function' ? root.setTimeout : setTimeout;
    // afterprint takes it away; a browser that never says so leaves it hidden (screen) until this
    try { root.print(); } finally { later(done, 60000); }
    return true;
  }

  return {
    monthsChart, csv, csvAll, printBill, monthList,
    // the pure parts, for tests and for the vouchers' cards (luVouchers.js)
    parseKey, stepKey, monthLabel, monthSlots, midJalali, rowsOf, csvText, download, printSheet
  };
}));
