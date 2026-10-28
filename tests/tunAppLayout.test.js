'use strict';
/**
 * The per-app list in the TUN card ON SCREEN (app.js renderTunAppList +
 * settings.css .tunapp-*): a real render of the window's own markup and CSS
 * (tests/renderCheck.js) with the list drawn by app.js's own functions run in
 * the page — renderTunAppList, its options, and the routing pages' searchable
 * picker (makeSearchSelect) — over a fake store of configs by subscription:
 * four apps, one with a name too long for any row, one on a config whose name
 * runs on, one on a config that is gone. In Persian (RTL) and English (LTR), at
 * the desktop window as it opens (1080x720) and a phone's width (390x760):
 * every row inside the list, its name, picker and ✕ inside the row and the ✕
 * clickable, the add box and its button inside the block, an open picker's
 * menu inside the window, and no sideways scroll anywhere.
 *
 * The render runs on CI, or wherever IRNF_RENDER_BROWSER names a browser —
 * never on a machine that did not ask. The harness is checked as text everywhere.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { checkPage, serveRenderer, findBrowser, renderInBrowser } = require('./renderCheck');

const R = (...p) => fs.readFileSync(path.join(__dirname, '..', ...p), 'utf8').replace(/\r\n/g, '\n');
const APP = R('src', 'renderer', 'app.js');
const CSS = R('src', 'renderer', 'settings.css');

/** A top-level function of app.js, by brace counting from its body's brace (default arguments may hold parentheses). */
function fnSource(name) {
  let start = APP.indexOf(`\nfunction ${name}(`);
  if (start === -1) start = APP.indexOf(`\nasync function ${name}(`);
  assert.ok(start > -1, `app.js has no function ${name}`);
  let depth = 0;
  let j = APP.indexOf(') {', start) + 2;
  for (; j < APP.length; j++) {
    if (APP[j] === '{') depth++;
    else if (APP[j] === '}' && --depth === 0) break;
  }
  return APP.slice(start, j + 1);
}

const FNS = ['escapeHtml', 'readTunApps', 'readTunAppTargets', 'tunAppDefault', 'tunAppTargetOptions', 'renderTunAppList',
  'pileFolds', 'setPileFold', 'pileHead', 'makeSearchSelect'];

const APPS = ['Telegram.exe', 'chrome.exe', 'Microsoft.Photos.BackgroundTaskHost.Extremely.Long.Name.exe', 'steam.exe'];
const MAP = { 'Telegram.exe': 'sv-long', 'chrome.exe': '', 'steam.exe': 'sv-gone' };
const CONFIGS = [
  { value: 'sv-a', label: 'Germany — Frankfurt 01', pile: { key: 's:1', name: 'My subscription', ico: '🔗' } },
  { value: 'sv-long', label: 'Netherlands-Amsterdam-VLESS-Reality-xhttp-ipv6-premium-node-0042', pile: { key: 's:1', name: 'My subscription', ico: '🔗' } },
  { value: 'chain:c1', label: '⛓ Corp chain', pile: { key: 'chains', name: 'Chains', ico: '⛓' } }
];

function checkJs() {
  return `(function () {
  var $ = function (s) { return document.querySelector(s); };
  var t = function (k) { return window.i18n.t(k); };
  var state = { settings: { tunAppMode: 'exclude', tunApps: ${JSON.stringify(APPS)}, tunAppTargets: ${JSON.stringify(MAP)} } };
  var configOptions = function () { return ${JSON.stringify(CONFIGS)}; };
  var saveSettings = function () { return Promise.resolve([]); };
  ${FNS.map(fnSource).join('\n')}
  // the settings page, its per-app row open on "except these"
  Array.prototype.forEach.call(document.querySelectorAll('.view'), function (v) { v.classList.remove('active'); });
  $('#view-settings').classList.add('active');
  $('#optTunAppMode').value = 'exclude';
  $('#tunAppsBlock').hidden = false;
  var box = function (n) { var b = n.getBoundingClientRect(); return { top: b.top, bottom: b.bottom, left: b.left, right: b.right, width: b.width, height: b.height }; };
  var hits = function (n) { var b = n.getBoundingClientRect(); var at = document.elementFromPoint(b.left + b.width / 2, b.top + b.height / 2); return !!at && n.contains(at); };
  var out = { width: innerWidth, height: innerHeight, runs: [] };
  ['fa', 'en'].forEach(function (lang) {
    window.i18n.applyI18n(lang);
    renderTunAppList();
    var list = $('#tunAppsList');
    list.scrollIntoView({ block: 'start' });
    var rows = Array.prototype.map.call(list.querySelectorAll('.tunapp-item'), function (row) {
      row.scrollIntoView({ block: 'center' });
      var name = row.querySelector('.tunapp-name'), cur = row.querySelector('.ss-current'), del = row.querySelector('.tunapp-del');
      return { row: box(row), name: box(name), nameText: name.textContent, nameClipped: name.scrollWidth > name.clientWidth,
        picker: box(cur), pickerText: cur.textContent, del: box(del), delHit: hits(del), rowOverflow: row.scrollWidth - row.clientWidth };
    });
    var add = $('#tunAppAdd'), addBtn = $('#btnTunAppAdd');
    addBtn.scrollIntoView({ block: 'center' });
    var addRun = { input: box(add), button: box(addBtn), buttonHit: hits(addBtn), block: box($('#tunAppsBlock')) };
    // the first row's picker, opened: its menu stays inside the window
    var first = list.querySelector('.tunapp-item .ss-current');
    first.scrollIntoView({ block: 'center' });
    first.click();
    var menu = list.querySelector('.ss-menu:not([hidden])');
    var menuBox = menu ? box(menu) : null;
    if (menu) document.body.click();
    out.runs.push({ lang: lang, dir: document.documentElement.dir, list: box(list), rows: rows, add: addRun, menu: menuBox,
      empty: $('#tunAppsEmpty').hidden,
      pageOverflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
      viewOverflow: $('#view-settings').scrollWidth - $('#view-settings').clientWidth });
  });
  var pre = document.createElement('pre');
  pre.id = 'render-result';
  pre.hidden = true;
  pre.textContent = encodeURIComponent(JSON.stringify(out));
  document.body.appendChild(pre);
})();
`;
}

/* ------------------------------ everywhere ------------------------------ */

test('the per-app list’s render check is built from app.js’s own functions and parses; its classes are styled', () => {
  const js = checkJs();
  assert.doesNotThrow(() => new vm.Script(js));
  for (const name of FNS) assert.ok(js.includes(`function ${name}(`), name);
  for (const cls of ['.tunapp-list', '.tunapp-item', '.tunapp-name', '.tunapp-target', '.tunapp-del', '.tunapp-add']) assert.ok(CSS.includes(cls + ' ') || CSS.includes(cls + ','), cls);
  // the picker is the Users page's: the connection, direct, blocked, then every config by its pile
  const opts = JSON.parse(vm.runInNewContext(`(function () { var t = function (k) { return k; }; var configOptions = function () { return ${JSON.stringify(CONFIGS)}; };
    ${fnSource('tunAppTargetOptions')}; return JSON.stringify(tunAppTargetOptions('sv-gone')); })()`));
  assert.deepEqual(opts.map((o) => o.value), ['', 'direct', 'block', 'sv-a', 'sv-long', 'chain:c1', 'sv-gone']);
  assert.equal(opts[opts.length - 1].label, '⚠ tunapp.target.missing');
  const page = checkPage({ scripts: ['i18n.js', 'settingsExperience.js'] });
  assert.ok(page.includes('id="tunAppsList"') && page.includes('id="tunAppAdd"'));
});

test('adding, removing and picking save exactly what the connect reads: the list, and each listed app’s config', async () => {
  const saved = [];
  const drawn = [];
  const ctx = vm.createContext({
    state: { settings: { tunAppMode: 'exclude', tunApps: [' Telegram.exe', 'chrome.exe', 'chrome.exe', 7], tunAppTargets: { 'chrome.exe': 'block', 'gone.exe': 'x' } } },
    saveSettings: async (partial) => { saved.push(JSON.parse(JSON.stringify(partial))); Object.assign(ctx.state.settings, partial); return []; },
    renderTunAppList: (apps, map) => drawn.push([apps, map])
  });
  vm.runInContext(['readTunApps', 'readTunAppTargets', 'saveTunAppTarget', 'addTunApps', 'removeTunApp'].map(fnSource).join('\n'), ctx);
  const plain = (v) => JSON.parse(JSON.stringify(v));
  assert.deepEqual(plain(ctx.readTunApps()), ['Telegram.exe', 'chrome.exe'], 'cleaned as the connect cleans it');
  // several at once — lines or commas, one already listed not twice, a name with a space kept whole
  assert.equal(await ctx.addTunApps('steam.exe, chrome.exe\nGoogle Chrome\n  '), true);
  assert.deepEqual(saved.pop(), { tunApps: ['Telegram.exe', 'chrome.exe', 'steam.exe', 'Google Chrome'] });
  assert.deepEqual(plain(drawn.pop()[0]), ['Telegram.exe', 'chrome.exe', 'steam.exe', 'Google Chrome'], 'drawn at once, not after the reconnect question');
  assert.equal(await ctx.addTunApps('chrome.exe'), false, 'nothing new: nothing saved');
  assert.equal(saved.length, 0);
  // a pick stores that app's config beside the others
  await ctx.saveTunAppTarget('Telegram.exe', 'sv-1');
  assert.deepEqual(saved.pop(), { tunAppTargets: { 'chrome.exe': 'block', 'gone.exe': 'x', 'Telegram.exe': 'sv-1' } });
  // removing an app takes its config with it
  await ctx.removeTunApp('chrome.exe');
  assert.deepEqual(saved.pop(), { tunApps: ['Telegram.exe', 'steam.exe', 'Google Chrome'], tunAppTargets: { 'gone.exe': 'x', 'Telegram.exe': 'sv-1' } });
});

/* ------------------------------ a real render ------------------------------ */

const BROWSER = findBrowser();
const SIZES = [{ width: 1080, height: 720 }, { width: 390, height: 760 }];

test('a real render: the per-app list, both directions, the window’s size and a phone’s — nothing outside its row, nothing sideways', { skip: BROWSER ? false : 'no browser for a render (CI, or IRNF_RENDER_BROWSER=<chrome or edge>)', timeout: 180000 }, async () => {
  const served = await serveRenderer(checkJs(), { scripts: ['i18n.js', 'settingsExperience.js'] });
  try {
    const all = await renderInBrowser(BROWSER, served, SIZES);
    for (const size of SIZES) {
      const out = all.find((r) => r.size && r.size.width === size.width && r.size.height === size.height);
      assert.ok(out && !out.error, `no measurement for ${size.width}x${size.height}: ${JSON.stringify(out && (out.error || out)).slice(0, 2000)}`);
      const W = out.width;
      const within = (r, o) => r.left >= o.left - 0.5 && r.right <= o.right + 0.5 && r.top >= o.top - 0.5 && r.bottom <= o.bottom + 0.5;
      const across = (r) => r.left >= -0.5 && r.right <= W + 0.5;
      assert.equal(out.runs.length, 2);
      for (const run of out.runs) {
        const at = `${run.lang} (${run.dir}) at ${size.width}x${size.height}`;
        assert.equal(run.dir, run.lang === 'fa' ? 'rtl' : 'ltr', at);
        assert.ok(run.pageOverflow <= 1 && run.viewOverflow <= 1, `sideways scroll — ${at}: page ${run.pageOverflow}, view ${run.viewOverflow}`);
        assert.equal(run.empty, true, `"no app yet" hidden while there are apps — ${at}`);
        assert.equal(run.rows.length, 4, at);
        for (const r of run.rows) {
          const where = `${r.nameText} — ${at}`;
          assert.ok(r.row.width > 0 && across(r.row) && within(r.row, run.list), `the row outside the list: ${where} ${JSON.stringify(r.row)} in ${JSON.stringify(run.list)}`);
          assert.ok(r.rowOverflow <= 1, `the row overflows by ${r.rowOverflow}px: ${where}`);
          for (const k of ['name', 'picker', 'del']) assert.ok(r[k].width > 0 && within(r[k], r.row), `${k} outside its row: ${where} ${JSON.stringify(r[k])}`);
          assert.ok(r.delHit, `✕ not clickable: ${where}`);
          assert.ok(r.picker.width >= 140, `the picker squeezed to ${r.picker.width}px: ${where}`);
        }
        // the long name gives way (ellipsis), the short ones do not
        assert.equal(run.rows[2].nameClipped, true, at);
        assert.equal(run.rows[1].nameClipped, false, at);
        // what each picker shows: its config, the mode's default, a gone one as gone
        assert.match(run.rows[0].pickerText, /Netherlands-Amsterdam/, at);
        assert.match(run.rows[2].pickerText, run.lang === 'fa' ? /مستقیم/ : /Direct/, at);
        assert.match(run.rows[3].pickerText, /⚠/, at);
        assert.ok(within(run.add.input, run.add.block) && within(run.add.button, run.add.block) && run.add.buttonHit, `the add box — ${at}: ${JSON.stringify(run.add)}`);
        assert.ok(run.menu && across(run.menu), `the open picker's menu leaves the window — ${at}: ${JSON.stringify(run.menu)}`);
      }
    }
  } finally {
    await served.close();
  }
});
