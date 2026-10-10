'use strict';
/**
 * The version picker's modal ON SCREEN (corePicker.js + settings.css): a real
 * render of the window's own markup and CSS (tests/renderCheck.js) with the
 * real modal driven through every state — loading, the stable list, the list
 * with pre-releases, three badges on one card, the warning before a version
 * older than the suggested one, an install at 42 %, a failed install with a
 * long reason, connected, and a list GitHub refused — in Persian (RTL) and
 * English (LTR), at the desktop window as it opens (1080x720), its minimum
 * (900x600) and the router's page on a phone (390x760). Nothing may lie outside
 * the window, outside its card or under something else; nothing may overflow.
 *
 * The render runs on CI, or wherever IRNF_RENDER_BROWSER names a browser —
 * never on a machine that did not ask (the owner runs this suite on the PC
 * their VPN runs on). The harness itself is checked as text everywhere.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');
const { PICKER_STATES, checkPage, serveRenderer, corePickerCheckJs, findBrowser, renderInBrowser } = require('./renderCheck');
const { buildCards, SUGGESTED } = require('../src/main/coreVersions');
const { Downloader } = require('../src/main/downloader');
const rel = require('./coreReleases');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-cpl-'));
test.after(() => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {} });

/** cores:versions answers, from the real card builder: sing-box on a router, Xray on a Windows PC. */
function fixtures() {
  const router = new Downloader({ destDir: tmp, platform: 'linux', arch: 'arm' });
  const pc = new Downloader({ destDir: tmp, platform: 'win32', arch: 'x64' });
  const sbList = rel.singbox();   // the 30 newest hold the suggested 1.14.3: nothing fetched by its tag
  const answer = (d, component, releases, installed, latestTag, prerelease) => ({
    ok: true, component, installed, suggested: SUGGESTED[component], latest: latestTag.replace(/^v/, ''), platform: d.target(component), prerelease, busy: false, installing: null,
    cards: buildCards({ releases, matchAsset: d.assetMatcher(component), installed, latestTag, suggested: SUGGESTED[component], prerelease })
  });
  return {
    answers: {
      'sing-box': { stable: answer(router, 'sing-box', sbList, '1.14.2', 'v1.14.3', false), pre: answer(router, 'sing-box', sbList, '1.14.2', 'v1.14.3', true) },
      // Xray as a download installs it now: the suggested 26.9.30, which XTLS
      // calls a pre-release — its card the one with three badges; 26.3.27 GitHub's latest
      xray: { stable: answer(pc, 'xray', rel.xtls(), '26.9.30', 'v26.3.27', false), pre: answer(pc, 'xray', rel.xtls(), '26.9.30', 'v26.3.27', true) }
    },
    older: '26.2.6',            // Xray, older than the suggested 26.9.30: the warning
    newer: '1.15.0-alpha.10',   // sing-box's newest pre-release: the install
    // a reason as long as a real one, with a path that has no space to break at
    installError: 'the downloaded sing-box did not run (spawn C:\\Users\\someone-with-a-long-name\\AppData\\Local\\Temp\\irnf-sing-box-1727999999999\\sing-box-1.15.0-alpha.10-windows-amd64\\sing-box.exe EACCES) — nothing was replaced',
    listError: {
      ok: false, component: 'sing-box', installed: '1.14.2', suggested: SUGGESTED['sing-box'], latest: '', platform: router.target('sing-box'), prerelease: false, busy: false, installing: null, cards: [],
      reason: 'rate-limit', error: 'GitHub: HTTP 403 — API rate limit exceeded for 2a01:4f8:1c1c:9b7e:0:0:0:1. (But here’s the good news: Authenticated requests get a higher rate limit. Check out the documentation for more details.)'
    }
  };
}

/* ------------------------------ the harness, everywhere ------------------------------ */

test('the picker’s render check serves the real markup and CSS with i18n.js and corePicker.js, and its script parses', () => {
  const page = checkPage({ scripts: ['i18n.js', 'corePicker.js'] });
  const scripts = [...page.matchAll(/<script src="([^"]+)"><\/script>/g)].map((m) => m[1]);
  assert.deepEqual(scripts, ['i18n.js', 'corePicker.js', '/__render-check.js'], 'only these, the check last — never app.js');
  for (const sheet of ['styles.css', 'settings.css', 'skins.css']) assert.ok(page.includes(`href="${sheet}"`), sheet);
  const f = fixtures();
  assert.equal(f.answers['sing-box'].pre.cards[0].version, '1.15.0-alpha.10');
  assert.ok(f.answers.xray.stable.cards.some((c) => c.version === f.older && c.olderThanSuggested));
  assert.ok(f.answers.xray.stable.cards.some((c) => c.version === '26.9.30' && c.isSuggested && c.isInstalled && c.prerelease), 'one card with three badges');
  assert.equal(f.answers.xray.stable.cards.length, 7, 'the 6 stables and the suggested pre-release');
  assert.doesNotThrow(() => new vm.Script(corePickerCheckJs(f)));
  assert.deepEqual(PICKER_STATES, ['loading', 'stable', 'pre', 'badges', 'warn', 'progress', 'failed', 'busy', 'listError']);
});

/* ------------------------------ a real render ------------------------------ */

const BROWSER = findBrowser();
const SIZES = [{ width: 1080, height: 720 }, { width: 900, height: 600 }, { width: 390, height: 760 }];

test('a real render: the version picker, in every state, both directions, three sizes — nothing off screen, covered, outside its card or overflowing', { skip: BROWSER ? false : 'no browser for a render (CI, or IRNF_RENDER_BROWSER=<chrome or edge>)', timeout: 240000 }, async () => {
  const served = await serveRenderer(corePickerCheckJs(fixtures()), { scripts: ['i18n.js', 'corePicker.js'] });
  try {
    const all = await renderInBrowser(BROWSER, served, SIZES);
    assert.equal(all.length, SIZES.length);
    for (const size of SIZES) {
      const out = all.find((r) => r.size && r.size.width === size.width && r.size.height === size.height);
      assert.ok(out && !out.error, `no measurement for ${size.width}x${size.height}: ${JSON.stringify(out && (out.error || out)).slice(0, 2000)}`);
      const W = out.width, H = out.height;
      assert.ok(Math.abs(W - size.width) <= 1 && Math.abs(H - size.height) <= 1, `the frame’s viewport: ${W}x${H}`);
      assert.equal(out.runs.length, PICKER_STATES.length * 2, `every state in both directions at ${W}x${H}`);
      const inView = (r) => r.width > 0 && r.height > 0 && r.top >= -0.5 && r.left >= -0.5 && r.bottom <= H + 0.5 && r.right <= W + 0.5;
      const within = (r, o) => r.left >= o.left - 0.5 && r.right <= o.right + 0.5 && r.top >= o.top - 0.5 && r.bottom <= o.bottom + 0.5;
      for (const run of out.runs) {
        const at = `${run.state} ${run.dir} (${run.component}) at ${W}x${H}`;
        assert.ok(inView(run.modal), `the modal is off screen — ${at}: ${JSON.stringify(run.modal)}`);
        assert.ok(run.overflowX <= 1, `the modal overflows sideways by ${run.overflowX}px — ${at}`);
        assert.ok(inView(run.title) && run.titleOverflow <= 1, `the title — ${at}`);
        for (const c of run.chips) assert.ok(within(c, run.modal), `a chip outside the modal — ${at}: ${JSON.stringify(c)}`);
        assert.equal(run.controls.length, 3, `✕ and the two list buttons — ${at}`);
        for (const b of run.controls) assert.ok(inView(b.box) && b.hit, `"${b.text}" not clickable — ${at}: ${JSON.stringify(b.box)}`);
        assert.ok(inView(run.foot) && within(run.foot, run.footBody), `the foot note, scrolled to — ${at}: ${JSON.stringify(run.foot)}`);
        if (run.state === 'busy') assert.ok(run.busy && inView(run.busy), `"disconnect first" off screen — ${at}`);
        else assert.equal(run.busy, null, `"disconnect first" shown when free — ${at}`);
        if (run.state === 'listError') {
          assert.equal(run.cards.length, 0);
          assert.equal(run.panels.length, 1, at);
          const p = run.panels[0];
          assert.ok(inView(p.box) && p.overflowX <= 1, `the error panel — ${at}`);
          for (const t of p.texts) assert.ok(within(t.box, p.box) && t.overflow <= 1, `${t.cls} spills — ${at}`);
          assert.equal(p.buttons.length, 1);
          assert.ok(inView(p.buttons[0].box) && p.buttons[0].hit, `Retry not clickable — ${at}`);
          continue;
        }
        // sing-box: its 6 newest stable (the suggested 1.14.3 first), + 4 pre-releases; Xray (badges, warn): 6 + the suggested pre-release
        const want = { loading: 4, stable: 6, pre: 10, badges: 7, warn: 7, progress: 10, failed: 10, busy: 6 }[run.state];
        assert.equal(run.cards.length, want, `${want} cards — ${at}`);
        for (const card of run.cards) {
          const where = `${card.tag} — ${at}`;
          assert.ok(inView(card.box), `card off screen: ${where} ${JSON.stringify(card.box)}`);
          assert.ok(within(card.box, card.body), `card outside the scrolling list: ${where} ${JSON.stringify(card.box)} in ${JSON.stringify(card.body)}`);
          assert.ok(card.overflowX <= 1, `card overflows by ${card.overflowX}px: ${where}`);
          for (const t of card.texts) {
            assert.ok(within(t.box, card.box), `${t.cls} outside its card: ${where} ${JSON.stringify(t.box)} in ${JSON.stringify(card.box)}`);
            if (/cv-fail-why|cv-warn-text|cv-done|cv-fail-text/.test(t.cls)) assert.ok(t.overflow <= 1, `${t.cls} clipped by ${t.overflow}px: ${where}`);
          }
          if (run.state !== 'loading') assert.ok(card.buttons.length >= 1, `no button: ${where}`);
          for (const b of card.buttons) assert.ok(inView(b.box) && within(b.box, card.box) && b.hit, `"${b.text}" not clickable: ${where} ${JSON.stringify(b.box)}`);
        }
        // the states themselves are on screen in the card they belong to
        const tagged = (tag) => run.cards.find((c) => c.tag === tag);
        if (run.state === 'warn') assert.ok(tagged('v26.2.6').texts.some((t) => /cv-warn-text/.test(t.cls)) && tagged('v26.2.6').buttons.length === 3, `the warning and its two buttons — ${at}`);
        if (run.state === 'progress') assert.ok(tagged('v1.15.0-alpha.10').texts.some((t) => /cv-track/.test(t.cls) && t.box.width > 40), `the progress bar — ${at}`);
        if (run.state === 'failed') assert.ok(tagged('v1.15.0-alpha.10').texts.some((t) => /cv-fail-why/.test(t.cls)), `the reason — ${at}`);
        if (run.state === 'badges') assert.ok(tagged('v26.9.30').texts.filter((t) => /cv-badge/.test(t.cls)).length === 3, `three badges — ${at}`);
      }
    }
  } finally {
    await served.close();
  }
});
