'use strict';
/**
 * The Extensions page («افزونه‌ها» / "Extensions") — the app's advanced parts,
 * installed or removed (src/renderer/modules.js is the registry: what each one
 * is, where it exists, what it needs; nothing here is downloaded code).
 *
 * The cards in the registry's sections (connection, routing, network,
 * security), only those that exist on this platform: the icon, the name and
 * its one line; "Installed" or the Install button, Remove (ghost) when it is;
 * "in use: N" while the store uses it — a removal then asks first, saying
 * what goes out of sight (nothing is deleted); "needs X" for what it brings
 * with it; and, on one installed that another installed one needs, "needed
 * by Y" — its removal is refused by modules:set until that one goes.
 *
 * The same file in the window and on the router's page: window.api's
 * modulesGet / modulesSet. app.js hands it its hooks (mount): the platform
 * the window is on, the installed list (state.settings.modules), what to do
 * once one changed (`changed(res)`: the body's attributes, every list and
 * picker drawn again, the reconnect question), toast and confirm. It asks for
 * the in-use counts when the page opens (refresh). Text nodes only — no
 * innerHTML. The page decides the direction and the language.
 */
(() => {
  const t = (key) => window.i18n.t(key);
  const fill = (s, map) => String(s).replace(/\{(\w+)\}/g, (m, k) => (Object.prototype.hasOwnProperty.call(map, k) ? map[k] : m));
  const lang = () => (window.i18n && window.i18n.lang) || document.documentElement.lang || 'fa';
  /** A count as the page reads it: Persian digits in Persian. */
  const num = (n) => (lang() === 'fa' ? String(n).replace(/\d/g, (d) => '۰۱۲۳۴۵۶۷۸۹'[d]) : String(n));
  const REG = () => window.IRNF_MODULES;

  let host = null;      // #modList
  let hooks = {};       // app.js's (mount)
  let inUse = null;     // modules:get's counts, once asked (null: not yet — no "in use" line)
  let platform = null;  // modules:get's platform; until then the window's own (hooks.platform)
  let busy = '';        // the extension being installed or removed: every button waits for it
  let loaded = false;

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

  const plat = () => platform || (typeof hooks.platform === 'function' ? hooks.platform() : 'desktop');
  const installed = () => REG().normalizeModules(typeof hooks.modules === 'function' ? hooks.modules() : {});
  /** An extension's own words, in the page's language. */
  const words = (m) => m[lang() === 'en' ? 'en' : 'fa'] || m.en;
  /** Extensions by name, as one list in the page's language. */
  const names = (ids) => ids.map((id) => { const m = REG().moduleOf(id); return m ? words(m).name : id; }).join(t('mod.sep'));
  const toast = (msg, kind) => { if (typeof hooks.toast === 'function') hooks.toast(msg, kind); };

  /** One extension's card. */
  function card(m, mods) {
    const on = !!mods[m.id];
    const w = words(m);
    const c = el('div', 'card mod-card' + (on ? ' on' : ''));
    c.dataset.mod = m.id;
    const ico = el('span', 'mod-ico', m.icon);
    ico.setAttribute('aria-hidden', 'true');
    const titles = el('div', 'mod-titles');
    titles.append(el('div', 'mod-name', w.name), el('div', 'mod-desc', w.desc));
    const head = el('div', 'mod-head');
    head.append(ico, titles);
    if (on) head.append(el('span', 'mod-badge', t('mod.installed')));
    c.append(head);

    const meta = el('div', 'mod-meta');
    const n = inUse ? Number(inUse[m.id]) || 0 : 0;
    if (n > 0) meta.append(el('span', 'mod-chip mod-use', fill(t('mod.inUse'), { n: num(n) })));
    const needs = REG().requiresOf(m.id).filter((r) => REG().available(r, plat()));
    if (needs.length) meta.append(el('span', 'mod-chip mod-needs', fill(t('mod.needs'), { names: names(needs) })));
    const by = REG().dependentsOf(m.id).filter((x) => mods[x] && REG().available(x, plat()));
    if (on && by.length) meta.append(el('span', 'mod-chip mod-by', fill(t('mod.neededBy'), { names: names(by) })));
    if (meta.childNodes.length) c.append(meta);

    const b = on ? button('btn ghost mod-remove', t('mod.remove')) : button('btn primary mod-install', t('mod.install'));
    b.dataset.mod = m.id;
    b.setAttribute('aria-label', (on ? t('mod.remove') : t('mod.install')) + ' — ' + w.name);
    if (busy) b.disabled = true;
    b.addEventListener('click', () => (on ? remove(m) : install(m)));
    const actions = el('div', 'mod-actions');
    actions.append(b);
    c.append(actions);
    return c;
  }

  /** The page: how many are installed, then each section with its cards. */
  function render() {
    if (!host || !REG()) return;
    const mods = installed();
    const list = REG().MODULES.filter((m) => REG().available(m.id, plat()));
    const kids = [el('p', 'mod-count', fill(t('mod.count'), { on: num(list.filter((m) => mods[m.id]).length), all: num(list.length) }))];
    for (const cat of REG().CATEGORIES) {
      const items = list.filter((m) => m.category === cat);
      if (!items.length) continue;
      const sec = el('section', 'mod-cat');
      sec.dataset.cat = cat;
      const grid = el('div', 'mod-grid');
      for (const m of items) grid.append(card(m, mods));
      sec.append(el('h3', 'mod-cat-title', t('mod.cat.' + cat)), grid);
      kids.push(sec);
    }
    host.replaceChildren(...kids);
  }

  /** The in-use counts and the platform from the back end (the page opened); the page drawn with them. */
  async function refresh() {
    try {
      const res = window.api && typeof window.api.modulesGet === 'function' ? await window.api.modulesGet() : null;
      if (res && typeof res === 'object') {
        inUse = res.inUse && typeof res.inUse === 'object' ? res.inUse : inUse;
        if (typeof res.platform === 'string') platform = res.platform;
      }
    } catch { /* the counts are a nicety: the page draws without them */ }
    loaded = true;
    render();
  }

  /** modules:set, and what follows: app.js's hook, then one toast. → the answer, or null when nothing changed. */
  async function set(m, on) {
    if (busy) return null;
    busy = m.id;
    render();
    let res;
    try { res = await window.api.modulesSet({ id: m.id, on }); } catch (e) { res = { error: (e && e.message) || String(e) }; }
    busy = '';
    if (res && res.inUse && typeof res.inUse === 'object') inUse = res.inUse;
    const w = words(m);
    if (!res || res.error || !res.modules) {
      toast(fill(t('mod.failed'), { msg: (res && res.error) || '?' }), 'err');
      render();
      return null;
    }
    if (Array.isArray(res.blockedBy) && res.blockedBy.length) {
      toast(fill(t('mod.blocked'), { name: w.name, names: names(res.blockedBy) }), 'warn');
      render();
      return null;
    }
    const before = installed();
    if (typeof hooks.changed === 'function') await hooks.changed(res);
    render();
    if (on) {
      const also = Object.keys(REG().normalizeModules(res.modules)).filter((id) => id !== m.id && !before[id]);
      toast(also.length ? fill(t('mod.done.installWith'), { name: w.name, names: names(also) }) : fill(t('mod.done.install'), { name: w.name }), 'ok');
    } else toast(fill(t('mod.done.remove'), { name: w.name }), 'ok');
    return res;
  }

  function install(m) { return set(m, true); }

  /** Remove — one in use asks first, saying what goes out of sight (nothing is deleted). */
  function remove(m) {
    const n = inUse ? Number(inUse[m.id]) || 0 : 0;
    if (n > 0) {
      const w = words(m);
      const ask = typeof hooks.confirm === 'function' ? hooks.confirm : () => true;
      if (!ask(fill(t('mod.confirmRemove'), { name: w.name, n: num(n), hides: w.hides }))) return Promise.resolve(null);
    }
    return set(m, false);
  }

  /** The page's box and app.js's hooks; the pointer in Settings opens it. */
  function mount(box, h) {
    host = box || null;
    hooks = h || {};
    const open = document.getElementById ? document.getElementById('btnOpenModules') : null;
    if (open && typeof hooks.showView === 'function') open.addEventListener('click', () => hooks.showView('modules'));
    render();
  }

  window.extensionsPage = { mount, render, refresh, loaded: () => loaded, install: (id) => install(REG().moduleOf(id)), remove: (id) => remove(REG().moduleOf(id)) };
})();
