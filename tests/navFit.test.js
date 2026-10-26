'use strict';
/**
 * The rail keeps every item in view (app.js fitNav + styles.css --navz). Its
 * items at their own size ran past the rail's end on a short window — with
 * every extension installed, in a labelled skin, on the router's page with a
 * phone held sideways — and the last of them (Extensions, Settings) were not
 * there at all. Now they shrink together to fit and grow back as the window
 * does, never past their own size.
 *
 * A real render of the window's own markup and CSS (tests/renderCheck.js),
 * with fitNav's own source from app.js run in the page: every skin, Simple and
 * Pro, both directions, five window sizes — each item inside the rail, none
 * over another, and their own size wherever that fits. The render runs on CI,
 * or wherever IRNF_RENDER_BROWSER names a browser; the rest is checked as text
 * everywhere.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { serveRenderer, findBrowser, renderInBrowser } = require('./renderCheck');

const R = (...p) => fs.readFileSync(path.join(__dirname, '..', ...p), 'utf8').replace(/\r\n/g, '\n');
const APP = R('src', 'renderer', 'app.js');
const CSS = R('src', 'renderer', 'styles.css');

/** fitNav and its constant, as app.js has them (brace counting from the function's own brace). */
function fitNavSource() {
  const start = APP.indexOf('const NAV_MIN_ZOOM');
  const fn = APP.indexOf('function fitNav() {', start);
  assert.ok(start > -1 && fn > -1, 'app.js: NAV_MIN_ZOOM and fitNav()');
  let i = APP.indexOf('{', fn);
  for (let depth = 0; i < APP.length; i++) {
    if (APP[i] === '{') depth++;
    else if (APP[i] === '}' && --depth === 0) break;
  }
  return APP.slice(start, i + 1);
}

const SKINS = ['', 'console', 'legacy'];
const MODES = ['pro', 'simple'];

function checkJs() {
  return `(function () {
  ${fitNavSource()}
  var SKINS = ${JSON.stringify(SKINS)}, MODES = ${JSON.stringify(MODES)};
  var rail = document.querySelector('.sidebar');
  var box = function (n) { var b = n.getBoundingClientRect(); return { top: b.top, bottom: b.bottom, left: b.left, right: b.right, height: b.height }; };
  var out = { width: innerWidth, height: innerHeight, min: NAV_MIN_ZOOM, runs: [] };
  SKINS.forEach(function (skin) {
    MODES.forEach(function (mode) {
      ['rtl', 'ltr'].forEach(function (dir) {
        if (skin) document.documentElement.setAttribute('data-skin', skin); else document.documentElement.removeAttribute('data-skin');
        document.body.dataset.uiMode = mode;
        document.documentElement.dir = dir;
        fitNav();
        var items = Array.prototype.slice.call(rail.children).filter(function (n) { return !n.classList.contains('sidebar-spacer') && n.getClientRects().length; });
        out.runs.push({ skin: skin || 'rail', mode: mode, dir: dir, zoom: rail.style.getPropertyValue('--navz'), compact: 'navCompact' in rail.dataset, scroll: 'navScroll' in rail.dataset, rail: box(rail),
          items: items.map(function (n) { return Object.assign({ key: n.getAttribute('data-view') || n.id }, box(n)); }) });
      });
    });
  });
  var pre = document.createElement('pre');
  pre.id = 'render-result';
  pre.hidden = true;
  pre.textContent = encodeURIComponent(JSON.stringify(out));
  document.body.appendChild(pre);
})();
`;
}

test('fitNav and the rail’s --navz are where the page uses them; the check built from them parses', () => {
  assert.match(APP, /new ResizeObserver\(fitNavSoon\)\.observe\(document\.querySelector\('\.sidebar'\)\)/, 'a resize of the rail measures again');
  assert.match(APP, /watch\.observe\(document\.body, \{ attributes: true \}\)/, 'an extension installed or removed, Simple / Pro');
  assert.match(CSS, /\.sidebar > :not\(\.sidebar-spacer\) \{ zoom: var\(--navz, 1\); flex-shrink: 0; \}/, 'zoomed, never squeezed by the column');
  assert.match(CSS, /\.sidebar\[data-nav-compact\] \.nav-item > span:not\(\.nav-ico\) \{ display: none; \}/);
  assert.match(CSS, /\.sidebar\[data-nav-scroll\] \{ overflow-y: auto;/);
  assert.match(CSS, /gap: calc\(8px \* var\(--navz, 1\)\);\s*padding-block: calc\(14px \* var\(--navz, 1\)\);/, 'the gaps and the padding shrink with the items');
  assert.doesNotThrow(() => new vm.Script(checkJs()));
});

const BROWSER = findBrowser();
// the window as it opens, its minimum, a tall one, the router's page on a phone upright and sideways
const SIZES = [{ width: 1080, height: 720 }, { width: 900, height: 600 }, { width: 1080, height: 900 }, { width: 390, height: 760 }, { width: 760, height: 390 }];

test('a real render: every rail item in view, none over another, their own size wherever it fits — every skin, Simple and Pro, both directions, five sizes', { skip: BROWSER ? false : 'no browser for a render (CI, or IRNF_RENDER_BROWSER=<chrome or edge>)', timeout: 240000 }, async () => {
  const served = await serveRenderer(checkJs());
  try {
    const all = await renderInBrowser(BROWSER, served, SIZES);
    assert.equal(all.length, SIZES.length);
    let shrunk = 0;
    for (const size of SIZES) {
      const out = all.find((r) => r.size && r.size.width === size.width && r.size.height === size.height);
      assert.ok(out && !out.error, `no measurement for ${size.width}x${size.height}: ${JSON.stringify(out && (out.error || out)).slice(0, 2000)}`);
      assert.equal(out.runs.length, SKINS.length * MODES.length * 2);
      for (const run of out.runs) {
        const at = `${run.skin} ${run.mode} ${run.dir} at ${size.width}x${size.height} (--navz ${run.zoom || 'unset'})`;
        const z = run.zoom ? Number(run.zoom) : 1;
        assert.ok(z >= out.min && z <= 1, `the zoom stays between ${out.min} and 1 — ${at}`);
        assert.ok(z > out.min, `these sizes fit without reaching the floor — ${at}`);
        assert.equal(run.scroll, false, `no scrolling needed at these sizes — ${at}`);
        assert.ok(run.items.some((i) => i.key === 'settings') && run.items.some((i) => i.key === 'modules'), `Settings and Extensions are drawn — ${at}`);
        for (const it of run.items) {
          assert.ok(it.height > 0 && it.top >= run.rail.top - 0.5 && it.bottom <= run.rail.bottom + 0.5,
            `${it.key} outside the rail (${it.top}–${it.bottom} in ${run.rail.top}–${run.rail.bottom}) — ${at}`);
        }
        const byTop = run.items.slice().sort((a, b) => a.top - b.top);
        for (let i = 1; i < byTop.length; i++) {
          assert.ok(byTop[i].top >= byTop[i - 1].bottom - 0.5, `${byTop[i].key} over ${byTop[i - 1].key} — ${at}`);
        }
        if (run.zoom) shrunk++;
        // a tall window: everything at its own size in the icon rail
        if (size.height === 900 && run.skin === 'rail') assert.equal(run.zoom, '', `room enough: not shrunk — ${at}`);
      }
    }
    assert.ok(shrunk > 0, 'some size needed the items smaller — else this proves nothing');
  } finally {
    await served.close();
  }
});
