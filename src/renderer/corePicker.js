'use strict';
/**
 * The cores' version picker — Settings → Required files → «انتخاب نسخه» /
 * "Choose version" (docs/superpowers/specs/2026-10-03-core-version-picker-design.md).
 *
 * One modal for Xray, Xray-PattN and sing-box, built here on first use and kept:
 * the core's name, what is installed and what this device downloads; Stable |
 * With pre-releases; one card per version — ⭐ Suggested, Latest, Installed ✓,
 * Pre-release, its age and size — whose button upgrades, downgrades (amber) or
 * reinstalls. A version older than the suggested one asks first, inside its
 * card. The install's progress, its success and its error (with Retry) stay in
 * that card; while connected or connecting every action is off and the modal
 * says to disconnect first (main and the router's service refuse it as well).
 *
 * The same file runs in the window and on the router's page: window.api's
 * coreVersions / installCoreVersion, and the asset-progress event app.js hands
 * over (progress()). Text only — tags, sizes and errors come from GitHub and the
 * service, so nothing here is HTML. The page decides the direction and the
 * language; app.js decides when it opens (open()). The «به‌روزرسانی» button
 * beside it is not this file's: it installs the latest release as it always did.
 */
(() => {
  const t = (key) => window.i18n.t(key);
  const fill = (s, map) => String(s).replace(/\{(\w+)\}/g, (m, k) => (Object.prototype.hasOwnProperty.call(map, k) ? map[k] : m));
  const lang = () => (window.i18n && window.i18n.lang) || document.documentElement.lang || 'fa';
  const NAMES = { xray: 'Xray', 'xray-pattn': 'Xray-PattN', 'sing-box': 'sing-box' };
  const ARCH = { x64: 'x64', arm64: 'ARM64', arm: 'ARMv7', ia32: 'x86', mips: 'MIPS', mipsel: 'MIPSel' };
  const OS = { win32: 'cv.os.win32', darwin: 'cv.os.darwin', linux: 'cv.os.linux' };
  const ACTIONS = {
    upgrade: { key: 'cv.act.upgrade', cls: 'cv-tonal' },
    install: { key: 'cv.act.install', cls: 'cv-tonal' },
    downgrade: { key: 'cv.act.downgrade', cls: 'cv-amber' },
    reinstall: { key: 'cv.act.reinstall', cls: 'ghost' }
  };
  const SKELETONS = 4;
  const LEAVE_MS = 160;   // the closing fade (settings.css, cv-leaving)

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

  /* ------------------------------ formats ------------------------------ */

  /** Bytes as the app writes them: '19.6 MB', '879 KB'; '' for nothing. */
  function size(bytes) {
    const n = Number(bytes) || 0;
    if (n <= 0) return '';
    if (n >= 1048576) return (n / 1048576).toFixed(1) + ' MB';
    return Math.max(1, Math.round(n / 1024)) + ' KB';
  }

  /** How long ago, in the page's language — '11 days ago', '۱۱ روز پیش'; '' without a date. */
  function age(iso, now, language) {
    const at = Date.parse(iso);
    if (!iso || !Number.isFinite(at)) return '';
    const s = (at - now) / 1000;
    const abs = Math.abs(s);
    let value, unit;
    if (abs < 3600) { value = Math.round(s / 60); unit = 'minute'; }
    else if (abs < 86400) { value = Math.round(s / 3600); unit = 'hour'; }
    else if (abs < 30 * 86400) { value = Math.round(s / 86400); unit = 'day'; }
    else if (abs < 365 * 86400) { value = Math.round(s / (30.44 * 86400)); unit = 'month'; }
    else { value = Math.round(s / (365.25 * 86400)); unit = 'year'; }
    // Latin digits in Persian too, as every number in the app is written
    try { return new Intl.RelativeTimeFormat(language === 'fa' ? 'fa-u-nu-latn' : 'en', { numeric: 'auto' }).format(value, unit); }
    catch { return String(iso).slice(0, 10); }
  }

  /* ------------------------------ state ------------------------------ */

  const ui = {
    m: null,            // the modal's elements, built on the first open
    open: false,
    component: null,
    hooks: {},          // app.js: { opener, busy(), onInstalled(res), toast(msg, kind) }
    opener: null,       // the button that opened it: the focus goes back there
    prerelease: false,
    res: null,          // the last cores:versions answer for this core
    loading: false,     // the skeleton (a first load, a Retry)
    refreshing: false,  // a quiet reload: the cards stay, dimmed
    fresh: false,       // the cards just came from an answer: they enter with a stagger
    seq: 0,             // an answer to an older request is dropped
    confirm: null,      // the tag whose "older than the suggested version" question is open
    job: null,          // the install in flight or just ended: { component, tag, card, pct, phase, error, refused }
    serverBusy: false,  // refused as connected — until the window's own state says otherwise
    downOnBackdrop: null,
    otherTimer: 0,      // asking again while another client's install runs (watchOther)
    listening: false
  };

  // 'checking': the answer was lost on the way (the remote relay's 60 s limit, a dropped call) and the service is being asked how it ended
  const running = () => !!(ui.job && (ui.job.phase === 'download' || ui.job.phase === 'verify' || ui.job.phase === 'checking'));
  /** Connected or connecting: the window's state, the service's own word, or a refusal just now. */
  const busy = () => {
    let mine = false;
    try { mine = !!(ui.hooks.busy && ui.hooks.busy()); } catch { mine = false; }
    return mine || !!(ui.res && ui.res.busy) || ui.serverBusy;
  };
  const toast = (msg, kind) => { try { if (ui.hooks.toast) ui.hooks.toast(msg, kind); } catch { /* a toast is never worth an error */ } };

  /* ------------------------------ the modal ------------------------------ */

  /** A chip on the processor, for the head — drawn, not an image or a font. */
  function glyph() {
    const ns = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(ns, 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', '1.6');
    svg.setAttribute('stroke-linecap', 'round');
    svg.setAttribute('stroke-linejoin', 'round');
    svg.setAttribute('aria-hidden', 'true');
    for (const [name, attrs] of [
      ['rect', { x: 6, y: 6, width: 12, height: 12, rx: 2 }],
      ['rect', { x: 9.5, y: 9.5, width: 5, height: 5, rx: 0.8 }],
      ['path', { d: 'M9 2.5v3M15 2.5v3M9 18.5v3M15 18.5v3M2.5 9h3M2.5 15h3M18.5 9h3M18.5 15h3' }]
    ]) {
      const shape = document.createElementNS(ns, name);
      for (const [k, v] of Object.entries(attrs)) shape.setAttribute(k, String(v));
      svg.appendChild(shape);
    }
    const box = el('span', 'cv-glyph');
    box.setAttribute('aria-hidden', 'true');
    box.appendChild(svg);
    return box;
  }

  function build() {
    if (ui.m) return ui.m;
    const overlay = el('div', 'modal-overlay cv-overlay');
    overlay.id = 'cvModal';
    overlay.hidden = true;
    const dialog = el('div', 'modal cv-modal');
    dialog.setAttribute('role', 'dialog');
    dialog.setAttribute('aria-modal', 'true');
    dialog.setAttribute('aria-labelledby', 'cvTitle');
    dialog.tabIndex = -1;

    const head = el('div', 'modal-head cv-head');
    const headText = el('div', 'cv-headtext');
    const title = el('h2', 'modal-title cv-title');
    title.id = 'cvTitle';
    const sub = el('div', 'cv-sub');
    const installed = el('span', 'cv-chip cv-chip-installed');
    const target = el('span', 'cv-chip cv-chip-target');
    sub.append(installed, target);
    headText.append(title, sub);
    const close = button('tb-btn cv-close', '✕');
    head.append(glyph(), headText, close);

    const bar = el('div', 'cv-bar');
    const seg = el('div', 'seg cv-seg');
    seg.setAttribute('role', 'group');
    const segStable = button('seg-btn');
    segStable.dataset.channel = 'stable';
    const segPre = button('seg-btn');
    segPre.dataset.channel = 'pre';
    seg.append(segStable, segPre);
    bar.append(seg);

    const busyNote = el('p', 'cv-busy');
    busyNote.setAttribute('role', 'status');
    busyNote.hidden = true;
    // another install running — this window's on another core, or another client's (the service says)
    const otherNote = el('p', 'cv-other');
    otherNote.setAttribute('role', 'status');
    otherNote.hidden = true;

    const body = el('div', 'modal-body cv-body');
    const list = el('div', 'cv-list');
    list.setAttribute('role', 'list');
    // the note about ⭐ ends the list, in the part that scrolls: a phone keeps its height for the cards
    const foot = el('p', 'cv-foot');
    body.append(list, foot);
    dialog.append(head, bar, busyNote, otherNote, body);
    overlay.append(dialog);
    document.body.appendChild(overlay);

    close.addEventListener('click', () => closeModal());
    segStable.addEventListener('click', () => channel(false));
    segPre.addEventListener('click', () => channel(true));
    // the backdrop closes it — a press that started on it, not a drag out of the dialog
    overlay.addEventListener('mousedown', (e) => { ui.downOnBackdrop = e.target === overlay; });
    overlay.addEventListener('click', (e) => {
      const fromBackdrop = ui.downOnBackdrop !== false;
      ui.downOnBackdrop = null;
      if (e.target === overlay && fromBackdrop) closeModal();
    });
    ui.m = { overlay, dialog, title, installed, target, close, segStable, segPre, busyNote, otherNote, list, foot };
    return ui.m;
  }

  /** The window's connection changed: busy or free again — after app.js has read the same event. */
  function listen() {
    if (ui.listening || !window.api) return;
    ui.listening = true;
    const later = () => setTimeout(sync, 0);
    if (typeof window.api.onStatus === 'function') window.api.onStatus(later);
    if (typeof window.api.onXrayStatus === 'function') window.api.onXrayStatus(later);
  }
  function sync() {
    if (!ui.open) return;
    let mine = false;
    try { mine = !!(ui.hooks.busy && ui.hooks.busy()); } catch { mine = false; }
    if (!mine) ui.serverBusy = false;
    paint();
    if (!running()) load();   // the service's own word, and the installed version, again
  }

  function open(component, hooks) {
    if (!Object.prototype.hasOwnProperty.call(NAMES, component)) return;
    const m = build();
    listen();
    const same = ui.component === component;
    ui.component = component;
    ui.hooks = hooks || {};
    ui.opener = ui.hooks.opener || document.activeElement || null;
    ui.confirm = null;
    ui.serverBusy = false;
    if (ui.job && !running()) ui.job = null;
    // an install still running for this core keeps the list it was started from
    if (!(running() && ui.job.component === component)) ui.prerelease = false;
    if (!same) ui.res = null;
    ui.open = true;
    m.overlay.classList.remove('cv-leaving');
    m.overlay.hidden = false;
    document.removeEventListener('keydown', onKey);
    document.addEventListener('keydown', onKey);
    load({ skeleton: !ui.res || !ui.res.ok });
    m.dialog.focus();
  }

  function closeModal() {
    if (!ui.open) return;
    ui.open = false;
    ui.confirm = null;
    document.removeEventListener('keydown', onKey);
    const m = ui.m;
    m.overlay.classList.add('cv-leaving');
    // no transitionend/animationend to wait for: a hidden page or reduced motion never sends one
    setTimeout(() => {
      if (ui.open) return;   // opened again meanwhile
      m.overlay.hidden = true;
      m.overlay.classList.remove('cv-leaving');
    }, LEAVE_MS);
    if (ui.job && !running()) ui.job = null;
    const back = ui.opener;
    ui.opener = null;
    if (back && back.isConnected !== false && typeof back.focus === 'function') back.focus();
    else if (m.overlay.contains(document.activeElement) && typeof document.activeElement.blur === 'function') document.activeElement.blur();
  }

  /* ------------------------------ keys and focus ------------------------------ */

  /** The controls Tab moves between: enabled buttons that are not hidden. */
  function focusables(root) {
    const out = [];
    const walk = (n) => {
      for (const c of Array.from(n.children || [])) {
        if (c.hidden) continue;
        if (c.tagName === 'BUTTON' && !c.disabled) out.push(c);
        walk(c);
      }
    };
    walk(root);
    return out;
  }

  function onKey(e) {
    if (!ui.open) return;
    if (e.key === 'Escape') {
      e.preventDefault();
      if (ui.confirm) {
        const tag = ui.confirm;
        ui.confirm = null;
        paint();
        focusIn(tag, 'act');
        return;
      }
      closeModal();
      return;
    }
    if (e.key !== 'Tab') return;
    const items = focusables(ui.m.dialog);
    if (!items.length) { e.preventDefault(); ui.m.dialog.focus(); return; }
    const first = items[0];
    const last = items[items.length - 1];
    const at = document.activeElement;
    const inside = ui.m.dialog.contains(at) && at !== ui.m.dialog;
    if (e.shiftKey && (!inside || at === first)) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && (!inside || at === last)) { e.preventDefault(); first.focus(); }
  }

  /**
   * Focus a control of one card (its data-cv-focus) — or, `fallback`, the
   * dialog: a repaint replaces the cards, and the focus must never fall out of
   * the modal to the page behind it.
   */
  function focusIn(tag, role, fallback = true) {
    const card = Array.from(ui.m.list.children || []).find((c) => c.dataset && c.dataset.tag === tag);
    const target = card ? focusables(card).find((b) => b.dataset.cvFocus === role) : null;
    if (target) { target.focus(); return true; }
    if (fallback) ui.m.dialog.focus();
    return false;
  }

  /** Which card control has the focus now ({ tag, role }), so a repaint can give it back. */
  function focusedControl() {
    const a = document.activeElement;
    if (!a || !ui.m.list.contains(a)) return null;
    let card = a;
    while (card && card !== ui.m.list && !(card.dataset && card.dataset.tag)) card = card.parentNode;
    return { tag: card && card.dataset ? card.dataset.tag : null, role: a.dataset ? a.dataset.cvFocus : null };
  }

  /* ------------------------------ the data ------------------------------ */

  async function load({ force = false, skeleton = false } = {}) {
    const my = ++ui.seq;
    const component = ui.component;
    ui.loading = skeleton || !ui.res;
    ui.refreshing = !ui.loading;
    paint();
    let res;
    try {
      if (!window.api || typeof window.api.coreVersions !== 'function') throw new Error('this page cannot ask for versions — reload it');
      res = await window.api.coreVersions(component, force ? { prerelease: ui.prerelease, force: true } : { prerelease: ui.prerelease });
    } catch (e) {
      res = { ok: false, error: (e && e.message) || String(e), reason: 'network', cards: [] };
    }
    if (my !== ui.seq || component !== ui.component) return;   // a newer request, or another core
    ui.loading = false;
    ui.refreshing = false;
    ui.fresh = true;
    ui.res = res && typeof res === 'object' ? res : { ok: false, error: 'no answer', cards: [] };
    paint();
  }

  function channel(pre) {
    if (ui.prerelease === pre || running()) return;
    ui.prerelease = pre;
    ui.confirm = null;
    if (ui.job && !running()) ui.job = null;
    load();
  }

  /** A card's button: older than the suggested version asks first; anything else installs. */
  function choose(card) {
    if (busy() || running()) { paint(); return; }
    if (ui.job) ui.job = null;
    if (card.olderThanSuggested && ui.confirm !== card.tag) {
      ui.confirm = card.tag;
      paint();
      focusIn(card.tag, 'go');
      return;
    }
    install(card);
  }

  async function install(card) {
    if (busy() || running()) { paint(); return; }
    const component = ui.component;
    const job = { component, tag: card.tag, version: card.version, card, prerelease: ui.prerelease, pct: null, phase: 'download', error: '', refused: null, reason: null, lost: null, dom: null };
    ui.job = job;
    ui.confirm = null;
    paint();
    let res;
    let lost = false;
    try {
      if (!window.api || typeof window.api.installCoreVersion !== 'function') throw new Error('this page cannot install a version — reload it');
      res = await window.api.installCoreVersion(component, card.tag);
    } catch (e) {
      lost = true;   // the bridge threw: the answer, not the install, is what failed
      res = null;
    }
    if (ui.job !== job) return;
    // An answer that never came — the remote relay ends a request at 60 s, a
    // proxy answers 504, a call is dropped — says nothing about the router: it
    // may be extracting the core right now. Only the service's own failure is
    // "untouched"; for this one the service is asked how it ended (check()).
    if (lost || !res || typeof res !== 'object' || typeof res.ok !== 'boolean') {
      job.phase = 'checking';
      job.checkSince = Date.now();
      if (ui.open) paint();
      check(job);
      return;
    }
    finish(job, res);
  }

  /** The asked-again's pace, and how long a lost answer is chased before "unknown". */
  const CHECK_EVERY_MS = 3000;
  const CHECK_FOR_MS = 30 * 60 * 1000;

  /**
   * A lost answer: ask cores:versions until the install is over — while the
   * service names this tag in `installing` it is still running; then the
   * installed version says how it ended. A question that fails (the router out
   * of reach for a moment) is asked again.
   */
  function check(job) {
    setTimeout(async () => {
      if (ui.job !== job || job.phase !== 'checking') return;
      let res = null;
      try { res = await window.api.coreVersions(job.component, { prerelease: job.prerelease }); } catch { res = null; }
      if (ui.job !== job || job.phase !== 'checking') return;
      const answered = !!res && typeof res === 'object' && typeof res.installed === 'string';
      const still = answered && res.installing && res.installing.component === job.component && res.installing.tag === job.tag;
      if (!answered || still) {
        if (Date.now() - job.checkSince < CHECK_FOR_MS) { check(job); return; }
        job.lost = 'unknown';
        finish(job, { ok: false });
        return;
      }
      // the answer it asked for is the list now (the badges follow the version installed)
      if (res.ok && ui.component === job.component) { ui.res = res; ui.fresh = true; }
      if (sameVersion(res.installed, job.version)) {
        finish(job, { ok: true, component: job.component, tag: job.tag, version: job.version, checked: true });
        return;
      }
      job.lost = 'installed';
      job.lostInstalled = res.installed;
      finish(job, { ok: false });
    }, CHECK_EVERY_MS);
  }

  const sameVersion = (a, b) => !!a && !!b && String(a).replace(/^v/i, '') === String(b).replace(/^v/i, '');

  /** How an install ended — the service's answer, or what check() learned. */
  function finish(job, res) {
    const component = job.component;
    const shown = ui.open && ui.component === component;
    const name = { core: NAMES[component], v: 'v' + job.version };
    if (res.ok) {
      job.phase = 'done';
      try { if (ui.hooks.onInstalled) ui.hooks.onInstalled(res, component); } catch { /* the page refreshes itself next time */ }
      if (!shown) {
        ui.job = null;
        toast(fill(t('cv.installedToast'), name), 'ok');
        if (ui.open) paint();   // another core's modal: free again
        return;
      }
      paint();
      if (!res.checked) load();   // quiet: the badges and the actions follow the version now installed
      return;
    }
    if (res.refused === 'connected') {
      ui.job = null;
      ui.serverBusy = true;
      if (!shown) toast(t('cv.busy'), 'warn');
      if (ui.open) paint();
      return;
    }
    job.phase = 'error';
    job.refused = res.refused || null;
    job.reason = res.reason || null;
    // the reasons the page words itself carry no raw text (EPERM, a lock)
    job.error = job.refused || job.reason === 'in-use' || job.lost ? '' : String(res.error || '');
    if (!shown) {
      ui.job = null;
      toast(fill(t('cv.failedToast'), name) + ': ' + (job.error || failText(job)), 'err');
      if (ui.open) paint();
      return;
    }
    paint();
    focusIn(job.tag, 'retry');
  }

  /** The line a failed card says. Only the service's own failure is "untouched". */
  function failText(job) {
    if (job.refused === 'installing') return t('cv.oneAtATime');
    if (job.refused === 'core-busy') return t('cv.coreBusy');
    if (job.reason === 'in-use') return t('cv.inUse');
    if (job.lost === 'installed') return fill(t('cv.lostNot'), { v: job.lostInstalled ? 'v' + job.lostInstalled : t('cv.notInstalled') });
    if (job.lost === 'unknown') return t('cv.lostUnknown');
    return t('cv.failed');
  }

  /** The asset-progress event (app.js): the picker's own install only. True when it was ours. */
  function progress(d) {
    const job = ui.job;
    if (!d || !job || !running() || d.component !== job.component) return false;
    const pct = Math.max(0, Math.min(100, Math.round(Number(d.pct) || 0)));
    job.pct = pct;
    if (pct >= 100 && job.phase === 'download') job.phase = 'verify';
    showProgress(job);
    return true;
  }

  /* ------------------------------ painting ------------------------------ */

  function paint() {
    const m = ui.m;
    if (!m) return;
    const res = ui.res;
    const blocked = busy();
    m.title.textContent = fill(t('cv.title'), { core: NAMES[ui.component] || '' });
    m.installed.hidden = !res;
    m.installed.textContent = res && res.installed ? fill(t('cv.installed'), { v: 'v' + res.installed }) : t('cv.notInstalled');
    m.installed.classList.toggle('is-none', !!res && !res.installed);
    const p = res && res.platform;
    m.target.hidden = !p;
    m.target.textContent = p ? `${t(OS[p.platform] || 'cv.os.linux')} · ${ARCH[p.arch] || p.arch || ''}` : '';
    m.target.title = p && p.asset ? String(p.asset) : '';
    m.close.title = t('cv.close');
    m.close.setAttribute('aria-label', t('cv.close'));
    m.segStable.textContent = t('cv.stable');
    m.segPre.textContent = t('cv.withPre');
    for (const b of [m.segStable, m.segPre]) {
      const on = (b === m.segPre) === ui.prerelease;
      b.classList.toggle('active', on);
      b.setAttribute('aria-pressed', String(on));
      b.disabled = running();
    }
    m.busyNote.textContent = t('cv.busy');
    m.busyNote.hidden = !blocked;
    // another install running: this window's on another core, or another client's (the service's word)
    const other = otherInstall();
    m.otherNote.textContent = other ? fill(t('cv.otherInstall'), { core: NAMES[other.component] || other.component, v: other.tag }) : '';
    m.otherNote.hidden = !other;
    // asked again once the answer in hand is the latest (a reload in flight answers first)
    if (other && other.fromService && !ui.loading && !ui.refreshing) watchOther();
    m.foot.textContent = t('cv.foot');

    m.list.setAttribute('aria-busy', String(!!ui.loading));
    m.list.classList.toggle('is-refreshing', !!ui.refreshing);
    m.list.classList.toggle('cv-enter', !!ui.fresh || !!ui.loading);
    ui.fresh = false;
    const kept = focusedControl();
    const cards = res && res.ok && Array.isArray(res.cards) ? res.cards : [];
    if (ui.loading) m.list.replaceChildren(...skeleton());
    else if (!res) m.list.replaceChildren();
    else if (!res.ok) m.list.replaceChildren(errorPanel(res));
    else if (!cards.length) m.list.replaceChildren(emptyPanel(res));
    else m.list.replaceChildren(...cards.map((c, i) => cardNode(c, i, blocked || !!other)));
    // the control that had the focus, rebuilt — or the dialog, never the page behind
    if (kept && !(kept.tag && kept.role && focusIn(kept.tag, kept.role, false)) && ui.open) m.dialog.focus();
  }

  /**
   * An install other than this card's: { component, tag, fromService }, or null.
   * This window's own job on another core (closed, then another core opened),
   * or the one the service names (`installing`, another client of the router).
   */
  function otherInstall() {
    if (running() && ui.job.component !== ui.component) return { component: ui.job.component, tag: 'v' + ui.job.version, fromService: false };
    const i = ui.res && ui.res.installing;
    if (!i || !i.component || !i.tag) return null;
    if (ui.job && ui.job.component === i.component && ui.job.tag === i.tag) return null;   // this window's own
    return { component: i.component, tag: String(i.tag), fromService: true };
  }

  /** Another client's install: ask again a little later, until the service says it is over. */
  const OTHER_EVERY_MS = 4000;
  function watchOther() {
    if (ui.otherTimer) return;
    ui.otherTimer = setTimeout(() => {
      ui.otherTimer = 0;
      if (ui.open && !running()) load();
    }, OTHER_EVERY_MS);
  }

  function skeleton() {
    const out = [];
    const sr = el('p', 'cv-sr', t('cv.loading'));
    sr.setAttribute('role', 'status');
    out.push(sr);
    for (let i = 0; i < SKELETONS; i++) {
      const card = el('div', 'cv-card cv-skel');
      card.setAttribute('aria-hidden', 'true');
      card.style.setProperty('--i', String(i));
      const main = el('div', 'cv-main');
      main.append(el('span', 'cv-skel-bar cv-skel-ver'), el('span', 'cv-skel-bar cv-skel-meta'));
      const act = el('div', 'cv-act');
      act.append(el('span', 'cv-skel-bar cv-skel-btn'));
      card.append(main, act);
      out.push(card);
    }
    return out;
  }

  function errorPanel(res) {
    const box = el('div', 'cv-empty cv-error');
    box.setAttribute('role', 'alert');
    box.append(el('p', 'cv-empty-title', t(res.reason === 'rate-limit' ? 'cv.rateLimited' : 'cv.loadFailed')));
    if (res.error) {
      const why = el('code', 'cv-fail-why', String(res.error));
      why.setAttribute('dir', 'ltr');
      box.append(why);
    }
    const retry = button('btn small primary cv-retry', t('cv.retry'));
    retry.addEventListener('click', () => load({ force: true, skeleton: true }));
    box.append(retry);
    return box;
  }

  function emptyPanel(res) {
    const box = el('div', 'cv-empty');
    box.append(el('p', 'cv-empty-title', fill(t('cv.empty'), { asset: (res.platform && res.platform.asset) || '' })));
    return box;
  }

  function cardNode(c, i, blocked) {
    const job = ui.job && ui.job.component === ui.component && ui.job.tag === c.tag ? ui.job : null;
    const card = el('div', 'cv-card');
    card.setAttribute('role', 'listitem');
    card.dataset.tag = c.tag;
    card.style.setProperty('--i', String(Math.min(i, 9)));
    card.classList.toggle('is-installed', !!c.isInstalled);
    card.classList.toggle('is-suggested', !!c.isSuggested);
    card.classList.toggle('is-latest', !!c.isLatest);
    card.classList.toggle('is-pre', !!c.prerelease);

    const main = el('div', 'cv-main');
    const line = el('div', 'cv-line');
    const ver = el('span', 'cv-ver', 'v' + c.version);
    ver.setAttribute('dir', 'ltr');
    const badges = el('span', 'cv-badges');
    if (c.isSuggested) badges.append(el('span', 'cv-badge cv-badge-suggested', t('cv.badge.suggested')));
    if (c.isLatest) badges.append(el('span', 'cv-badge cv-badge-latest', t('cv.badge.latest')));
    if (c.isInstalled) badges.append(el('span', 'cv-badge cv-badge-installed', t('cv.badge.installed')));
    if (c.prerelease) badges.append(el('span', 'cv-badge cv-badge-pre', t('cv.badge.pre')));
    line.append(ver, badges);
    const meta = el('div', 'cv-meta');
    const when = el('span', 'cv-age', age(c.date, Date.now(), lang()));
    when.title = c.date ? String(c.date).slice(0, 10) : '';
    meta.append(when);
    const bytes = size(c.size);
    if (bytes) {
      const sz = el('span', 'cv-size', bytes);
      sz.setAttribute('dir', 'ltr');
      meta.append(el('span', 'cv-sep', '·'), sz);
    }
    main.append(line, meta);

    const act = el('div', 'cv-act');
    const kind = ACTIONS[c.action] || ACTIONS.install;
    const b = button('btn small cv-btn ' + kind.cls, t(kind.key));
    b.dataset.cvFocus = 'act';
    b.setAttribute('aria-label', `${t(kind.key)} — v${c.version}`);
    b.disabled = blocked || running();
    b.addEventListener('click', () => choose(c));
    act.append(b);
    card.append(main, act);

    if (job) {
      card.classList.add(job.phase === 'done' ? 'is-done' : job.phase === 'error' ? 'is-failed' : 'is-busy');
      card.append(jobRow(job, blocked));
    } else if (ui.confirm === c.tag) {
      card.classList.add('is-confirm');
      card.append(warnRow(c, blocked));
    }
    return card;
  }

  function warnRow(c, blocked) {
    const row = el('div', 'cv-warn');
    row.setAttribute('role', 'alert');
    row.append(el('p', 'cv-warn-text', fill(t('cv.older'), { v: 'v' + ((ui.res && ui.res.suggested) || '') })));
    const actions = el('div', 'cv-warn-actions');
    const cancel = button('btn small ghost cv-cancel', t('cv.cancel'));
    cancel.dataset.cvFocus = 'cancel';
    cancel.addEventListener('click', () => { ui.confirm = null; paint(); focusIn(c.tag, 'act'); });
    const go = button('btn small cv-amber cv-go', t('cv.olderGo'));
    go.dataset.cvFocus = 'go';
    go.disabled = blocked;
    go.addEventListener('click', () => install(c));
    actions.append(cancel, go);
    row.append(actions);
    return row;
  }

  function jobRow(job, blocked) {
    if (job.phase === 'done') {
      const done = el('p', 'cv-done', t('cv.done'));
      done.setAttribute('role', 'status');
      return done;
    }
    if (job.phase === 'error') {
      const box = el('div', 'cv-fail');
      box.setAttribute('role', 'alert');
      box.append(el('p', 'cv-fail-text', failText(job)));
      if (job.error) {
        const why = el('code', 'cv-fail-why', job.error);
        why.setAttribute('dir', 'ltr');
        box.append(why);
      }
      const retry = button('btn small cv-retry', t('cv.retry'));
      retry.dataset.cvFocus = 'retry';
      retry.disabled = blocked;
      retry.addEventListener('click', () => install(job.card));
      box.append(retry);
      return box;
    }
    const row = el('div', 'cv-progress');
    const track = el('div', 'cv-track');
    track.setAttribute('role', 'progressbar');
    track.setAttribute('aria-valuemin', '0');
    track.setAttribute('aria-valuemax', '100');
    track.setAttribute('aria-label', `${NAMES[job.component]} v${job.version}`);
    const bar = el('div', 'cv-fill');
    track.append(bar);
    const text = el('span', 'cv-progress-text');
    row.append(track, text);
    job.dom = { track, bar, text };
    showProgress(job);
    return row;
  }

  /** The bar and its words, in place — progress arrives several times a second, the card is not rebuilt. */
  function showProgress(job) {
    const d = job.dom;
    if (!d) return;
    const verifying = job.phase === 'verify';
    const checking = job.phase === 'checking';
    const known = !verifying && !checking && Number.isFinite(job.pct);
    d.track.classList.toggle('is-indeterminate', !known);
    if (known) {
      d.track.setAttribute('aria-valuenow', String(job.pct));
      d.bar.style.width = job.pct + '%';
    } else {
      d.track.removeAttribute('aria-valuenow');
      d.bar.style.width = '';
    }
    d.text.textContent = checking ? t('cv.checking') : verifying ? t('cv.verifying') : known ? `${t('cv.downloading')} ${job.pct}%` : t('cv.downloading');
  }

  window.corePicker = {
    open,
    close: closeModal,
    isOpen: () => ui.open,
    progress,
    format: { size, age }
  };
})();
