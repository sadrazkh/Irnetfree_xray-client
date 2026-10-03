'use strict';
/**
 * The window's banners are ON SCREEN when shown (v1.16.3 review).
 *
 * #killBanner (the kill switch blocked the internet), #guardBanner ("give my
 * internet back" after a failed reconnect), #pendingBanner (settings saved
 * but not applied) and #autostartBanner (the logon task starts another copy —
 * windows-android-report L1) lost their fixed position in the 52ac922 redesign
 * and became static blocks after `.layout` (100vh minus the title bar) in a
 * window whose html/body never scroll: each one rendered with its top at
 * exactly innerHeight — 0 visible pixels, elementFromPoint there was the power
 * button — while the tests that looked at `hidden` passed.
 *
 * Two layers: the markup/CSS facts that put them on screen, read as text
 * everywhere; and a real render (tests/renderCheck.js) in a headless Chromium
 * that measures getBoundingClientRect() — on CI, or wherever
 * IRNF_RENDER_BROWSER names a browser. Never on a machine that did not ask:
 * the owner runs this suite on the PC their VPN runs on.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { BANNERS, checkPage, harnessPage, parseSizes, serveRenderer, bannerCheckJs, bannerTexts, longestNotice, findBrowser, renderInBrowser } = require('./renderCheck');

const R = (...p) => fs.readFileSync(path.join(__dirname, '..', ...p), 'utf8').replace(/\r\n/g, '\n');
const HTML = R('src', 'renderer', 'index.html');
const STYLES = R('src', 'renderer', 'styles.css');
const ALL_CSS = ['styles.css', 'home.css', 'lists.css', 'routing.css', 'settings.css', 'skins.css', 'diagnostics.css']
  .map((f) => R('src', 'renderer', f)).join('\n');

/** The declarations of the first rule whose selector list is exactly `sel`. */
function rule(css, sel) {
  const at = css.indexOf('\n' + sel + ' {');
  assert.ok(at > -1, `no rule ${sel}`);
  return css.slice(css.indexOf('{', at) + 1, css.indexOf('}', at));
}
const px = (decls, prop) => {
  const m = new RegExp(`(?:^|;|\\n)\\s*${prop}:\\s*(-?\\d+)px`).exec(decls);
  return m ? Number(m[1]) : null;
};

/* ------------------------------ markup and CSS, everywhere ------------------------------ */

test('the four banners live in one fixed stack — the only one, in this order, and nothing else in it', () => {
  const open = '<div class="banner-stack" id="bannerStack">';
  assert.equal(HTML.split(open).length - 1, 1, 'one banner stack');
  const start = HTML.indexOf(open);
  const end = HTML.indexOf('\n  </div>', start);
  const stack = HTML.slice(start, end);
  const ids = [...stack.matchAll(/<div class="(kill|pending)-banner" id="(\w+)" hidden>/g)].map((m) => m[2]);
  assert.deepEqual(ids, BANNERS);
  for (const id of BANNERS) assert.equal(HTML.split(`id="${id}"`).length - 1, 1, `${id} once, inside the stack`);
  // the stack comes after the layout (like the toast), outside every page
  assert.ok(HTML.indexOf('<div class="layout">') < start && HTML.indexOf('</main>') < start);
});

test('the stack is fixed over the window’s foot, above the toast’s edge, under the modals and the toast, and takes no clicks itself', () => {
  const stack = rule(STYLES, '.banner-stack');
  assert.match(stack, /position: fixed;/);
  assert.match(stack, /left: 50%;/);
  assert.match(stack, /transform: translateX\(-50%\);/, 'physical centring: the same in Persian and English');
  const bottom = px(stack, 'bottom');
  const toastBottom = px(rule(STYLES, '.toast'), 'inset-block-end');
  assert.ok(bottom > toastBottom, `the stack (${bottom}px) sits above the toast’s resting edge (${toastBottom}px)`);
  const z = Number((/z-index: (\d+);/.exec(stack) || [])[1]);
  const modal = Number((/z-index: (\d+);/.exec(rule(STYLES, '.modal-overlay')) || [])[1]);
  const toast = Number((/z-index: (\d+);/.exec(rule(STYLES, '.toast')) || [])[1]);
  assert.ok(z > 50 && z < modal && z < toast, `z-index ${z}: over the pages and their menus, under the modals (${modal}) and the toast (${toast})`);
  assert.match(stack, /max-width: min\(\d+px, calc\(100vw - \d+px\)\);/, 'never wider than the window');
  assert.match(stack, /max-height: calc\(100vh - /, 'never taller than the window');
  assert.match(stack, /pointer-events: none;/, 'the empty stack is not a dead zone over the page');
  assert.match(rule(STYLES, '.banner-stack > *'), /pointer-events: auto;/);
  // the banners themselves flow inside it: no rule anywhere moves one out again
  for (const m of ALL_CSS.matchAll(/([^{}]*)\{([^}]*)\}/g)) {
    if (/\.(kill|pending)-banner\b(?![-\w])/.test(m[1]) && !/\.banner-stack/.test(m[1])) {
      assert.doesNotMatch(m[2], /position:|margin-bottom:/, `${m[1].trim()} must not take a banner out of the stack`);
    }
  }
  // a long path (the logon-task banner names two) wraps instead of running off the side
  assert.match(rule(STYLES, '.kill-banner-text, .pending-banner-text'), /overflow-wrap: anywhere;/);
});

test('the toast is centred on the physical left edge, plain or with a button — in Persian a logical inset put a long one half off the window', () => {
  // inset-inline-start: 50% is `right: 50%` in RTL, and translateX(-50%) is
  // physical: a plain toast as wide as its max-width started off the window's
  // left side (measured left -270 px at 1080x720, -225 px at 900x600)
  const toast = rule(STYLES, '.toast');
  assert.match(toast, /(^|[\s;])left: 50%;/);
  assert.match(toast, /(^|[\s;])right: auto;/);
  assert.doesNotMatch(toast, /inset-inline-(start|end):|inset-inline:/, 'no logical horizontal inset');
  assert.match(toast, /transform: translateX\(-50%\) translateY\(12px\);/);
  assert.match(rule(STYLES, '.toast.show'), /transform: translateX\(-50%\) translateY\(0\);/);
  assert.match(toast, /max-width: min\(560px, 88vw\);/, 'never wider than the window');
  // no later rule puts a logical inset (or another left/right) back on any toast
  for (const m of ALL_CSS.matchAll(/([^{}]*)\{([^}]*)\}/g)) {
    const sel = m[1].replace(/\/\*[\s\S]*?\*\//g, '').trim();
    if (/\.toast\b(?![-\w])/.test(sel) && sel !== '.toast') {
      assert.doesNotMatch(m[2], /inset-inline|(^|[\s;])(left|right):/, `${sel} must not move the toast off its physical centre`);
    }
  }
});

test('the render check serves the real markup and CSS — only the scripts are left out', () => {
  const page = checkPage();
  assert.doesNotMatch(page.replace('<script src="/__render-check.js"></script>', ''), /<script\b/);
  for (const sheet of ['styles.css', 'home.css', 'skins.css']) assert.ok(page.includes(`href="${sheet}"`), sheet);
  for (const id of BANNERS) assert.ok(page.includes(`id="${id}"`), id);
  // the check script itself parses, with the app's real texts filled in
  const texts = bannerTexts();
  assert.match(texts.autostart, /IRNetFree-Portable-1\.13\.0-x64-setup-copy\.exe/);
  assert.doesNotMatch(texts.autostart + texts.pending, /\{\w+\}/);
  // the toast's texts: the longest notice of each language, every field filled
  assert.equal(texts.toasts.length, 2);
  assert.match(texts.toasts[0], /[؀-ۿ]/, 'the first is Persian');
  assert.doesNotMatch(texts.toasts[1], /[؀-ۿ]/, 'the second is English');
  for (const s of texts.toasts) {
    assert.doesNotMatch(s, /\{\w+\}/, s);
    assert.ok(s.length > 300, `the longest notice, not a short one (${s.length})`);
  }
  assert.equal(longestNotice('fa'), texts.toasts[0]);
  assert.doesNotThrow(() => new vm.Script(bannerCheckJs(texts)));
  // the harness: one iframe of exactly each size, around the page above
  assert.deepEqual(parseSizes('1080x720, 900x600,390x760,x,99999x1'), [{ width: 1080, height: 720 }, { width: 900, height: 600 }, { width: 390, height: 760 }]);
  const harness = harnessPage(parseSizes('1080x720,390x760'));
  assert.match(harness, /<iframe id="f0" data-width="1080" data-height="720" src="\/\?frame=0" style="width:1080px;height:720px"><\/iframe>/);
  assert.match(harness, /<iframe id="f1" data-width="390" data-height="760" src="\/\?frame=1" style="width:390px;height:760px"><\/iframe>/);
  // never a browser on a machine that did not ask for one
  assert.equal(findBrowser({}, 'win32'), null);
  assert.equal(findBrowser({}, 'linux'), null);
  assert.equal(findBrowser({ IRNF_RENDER_BROWSER: 'X:\\chrome.exe' }, 'win32'), 'X:\\chrome.exe');
});

/* ------------------------------ a real render ------------------------------ */

const BROWSER = findBrowser();
const SIZES = [
  { width: 1080, height: 720, together: true },   // the desktop window as it opens
  { width: 900, height: 600, together: true },    // its minimum size
  { width: 390, height: 760, together: false }    // the router's page on a phone: one banner at a time there
];

test('a real render: every banner, shown, lies inside the viewport, is what is under its centre, and so are its buttons — and the longest toast lies inside it too', { skip: BROWSER ? false : 'no browser for a render (CI, or IRNF_RENDER_BROWSER=<chrome or edge>)', timeout: 240000 }, async () => {
  // the app's own Persian texts; the logon-task banner at its longest (two unbreakable Windows paths)
  const served = await serveRenderer(bannerCheckJs(bannerTexts()));
  try {
    // one browser, one iframe of exactly each size (a headless window's own size differs per OS)
    const all = await renderInBrowser(BROWSER, served, SIZES);
    assert.equal(all.length, SIZES.length);
    for (const size of SIZES) {
      const out = all.find((r) => r.size && r.size.width === size.width && r.size.height === size.height);
      assert.ok(out && !out.error, `no measurement for ${size.width}x${size.height}: ${JSON.stringify(out)}`);
      const W = out.width, H = out.height;
      const where = (b) => `${size.width}x${size.height} (viewport ${W}x${H}) ${b.id}: ${JSON.stringify(b.box)}`;
      assert.ok(Math.abs(W - size.width) <= 1 && Math.abs(H - size.height) <= 1, `the frame’s viewport: ${W}x${H}`);
      const inside = (r) => r.width > 0 && r.height > 0 && r.top >= -0.5 && r.left >= -0.5 && r.bottom <= H + 0.5 && r.right <= W + 0.5;
      for (const run of out.runs) {
        if (run.shown.length > 1 && !size.together) continue;
        for (const b of run.banners) {
          const at = `${run.dir}, ${run.shown.length === 1 ? 'alone' : 'all four'}: ${where(b)}`;
          assert.ok(inside(b.box), `off screen — ${at}`);
          assert.ok(b.hit, `covered — ${at}`);
          assert.ok(b.text && inside(b.text), `its text off screen — ${at}`);
          assert.ok(b.textOverflow <= 1, `its text overflows by ${b.textOverflow}px — ${at}`);
          assert.ok(b.buttons.length >= 2, at);
          for (const btn of b.buttons) assert.ok(inside(btn.box) && btn.hit, `button ${btn.id} not clickable — ${at} ${JSON.stringify(btn.box)}`);
        }
        // shown together they stack: none over another
        const list = run.banners;
        for (let i = 0; i < list.length; i++) {
          for (let j = i + 1; j < list.length; j++) {
            const a = list[i].box, c = list[j].box;
            assert.ok(a.bottom <= c.top + 0.5 || c.bottom <= a.top + 0.5, `${list[i].id} and ${list[j].id} overlap at ${size.width}x${size.height} ${run.dir}`);
          }
        }
      }
      // the toast with the longest notice (Persian, English), plain and with its button, in both directions:
      // all of it inside the window — a logical inset put a long Persian one half off its left edge
      assert.equal(out.toasts.length, 2 * 2 * 2, `${size.width}x${size.height}: ${JSON.stringify(out.toasts)}`);
      for (const tst of out.toasts) {
        const at = `the toast (${tst.dir}, ${tst.action ? 'with its button' : 'plain'}, ${tst.length} chars) at ${size.width}x${size.height}: ${JSON.stringify(tst.box)}`;
        assert.ok(tst.box.width > 0 && tst.box.height > 0, at);
        assert.ok(tst.box.left >= -0.5, `off the left edge — ${at}`);
        assert.ok(tst.box.right <= W + 0.5, `off the right edge — ${at}`);
        assert.ok(tst.box.top >= -0.5 && tst.box.bottom <= H + 0.5, `off the top or bottom — ${at}`);
      }
    }
  } finally {
    await served.close();
  }
});
