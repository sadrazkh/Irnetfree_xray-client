'use strict';
/**
 * The share-config QR.
 *
 * A share link carries EVERY setting, so it is long: an xhttp config with an
 * `extra` object or a WireGuard peer runs past 600 characters, and the QR that
 * encodes it is 85 modules square. The modal that shows it is 400px wide.
 *
 * The old code asked the library for a GIF at a fixed pixel size
 * (`createImgTag(4, 6)`) and no stylesheet rule ever constrained it: a 621-char
 * link rendered a 352px image into a 243px box — measured, it overflowed by
 * 109px — and the 6px margin was 1.5 modules where the QR spec requires 4, so
 * what did fit on screen was refused by scanners.
 *
 * The fix is a scalable SVG plus the CSS that was missing. Both halves are
 * pinned here, together with the property that actually matters: for every
 * link length the app can produce, the code fits the modal and keeps enough
 * pixels per module to scan.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const R = (...p) => path.join(__dirname, '..', 'src', 'renderer', ...p);
const APP = fs.readFileSync(R('app.js'), 'utf8');
const CSS = fs.readFileSync(R('styles.css'), 'utf8');

/** The vendored library, loaded the way the renderer loads it (a plain script). */
function loadQrcode() {
  const ctx = { window: {}, self: {} };
  vm.createContext(ctx);
  vm.runInContext(fs.readFileSync(R('vendor', 'qrcode.js'), 'utf8'), ctx);
  const qrcode = ctx.qrcode || ctx.window.qrcode;
  assert.equal(typeof qrcode, 'function', 'vendor/qrcode.js did not define qrcode()');
  return qrcode;
}

/** The shape of a real share link, at the lengths the app actually produces. */
const BASE = 'vless://11111111-2222-3333-4444-555555555555@some.long.domain.example.com:443'
  + '?type=xhttp&path=%2Fapi%2Fv1&host=cdn.example.com&mode=auto&security=reality'
  + '&pbk=0123456789abcdef0123456789abcdef0123456789ab&sid=abcd1234&fp=chrome'
  + '&sni=www.microsoft.com#UK-Server';
const LINKS = {
  short: 'vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?type=tcp&security=reality&pbk=ABCDEF#S',
  typical: BASE,
  withExtra: BASE + '&extra=%7B%22scMaxEachPostBytes%22%3A%221000000%22%2C%22xPaddingBytes%22%3A%22100-1000%22%7D',
  long: BASE + '&extra=%7B%22scMaxEachPostBytes%22%3A%221000000%22%7D&note=' + 'x'.repeat(260)
};

test('the QR is generated as a scalable SVG, not a fixed-size bitmap', () => {
  assert.match(APP, /qr\.createSvgTag\(\{[^}]*scalable:\s*true/,
    'showServerQr must ask for a scalable SVG — a fixed-size image cannot shrink into the modal');
  // A call, not a mention — the comment above the fix names the old API.
  assert.ok(!/\.createImgTag\s*\(/.test(APP),
    'createImgTag is being called again: it emits width/height in pixels and overflowed the modal for long links');
});

test('the quiet zone is the 4 modules the spec requires', () => {
  const call = APP.match(/qr\.createSvgTag\(\{([^}]*)\}\)/);
  assert.ok(call, 'no createSvgTag call found in app.js');
  const cellSize = Number((call[1].match(/cellSize:\s*(\d+)/) || [])[1]);
  const margin = Number((call[1].match(/margin:\s*(\d+)/) || [])[1]);
  assert.ok(cellSize > 0, 'createSvgTag needs an explicit cellSize');
  assert.ok(margin >= cellSize * 4,
    `margin ${margin} is ${margin / cellSize} modules — the QR spec asks for 4, and scanners enforce it`);
});

test('the stylesheet bounds the code and puts a white plate behind it', () => {
  // Without these rules the SVG is laid out at whatever size its box allows and
  // the dark skins show a QR with no plate — this file had NO .qr-image rule at all.
  const rule = CSS.match(/\.qr-image\s*\{([^}]*)\}/);
  assert.ok(rule, 'styles.css has no .qr-image rule');
  assert.match(rule[1], /width:\s*min\(\s*\d+px\s*,\s*100%\s*\)/,
    '.qr-image must cap its width AND stay inside a narrow modal (min(Npx, 100%))');
  assert.match(rule[1], /background:\s*#fff/i, 'the code needs a white plate on the dark skins');
  assert.match(CSS, /\.qr-image svg\s*\{[^}]*width:\s*100%/,
    'the SVG must fill .qr-image; otherwise it falls back to its intrinsic size');
});

test('every link length fits the modal with enough pixels per module to scan', () => {
  const qrcode = loadQrcode();
  // What the CSS grants the code: the .qr-image cap, less its own padding.
  const cap = Number(CSS.match(/\.qr-image\s*\{[^}]*width:\s*min\(\s*(\d+)px/)[1]);
  const pad = Number((CSS.match(/\.qr-image\s*\{[^}]*padding:\s*(\d+)px/) || [0, 0])[1]);
  const drawn = cap - pad * 2;
  // .modal-sm is the box it has to live in.
  const modal = Number(CSS.match(/\.modal-sm\s*\{\s*width:\s*min\((\d+)px/)[1]);
  const body = Number(CSS.match(/\.modal-body\s*\{\s*padding:\s*(\d+)px/)[1]);
  assert.ok(cap <= modal - body * 2, `the QR box (${cap}px) does not fit .modal-sm (${modal - body * 2}px of content)`);

  for (const [name, link] of Object.entries(LINKS)) {
    const qr = qrcode(0, 'L');
    qr.addData(link);
    qr.make();
    const modules = qr.getModuleCount();
    const svg = qr.createSvgTag({ cellSize: 4, margin: 16, scalable: true });
    // scalable = a viewBox and no width/height attribute, so CSS decides the size.
    assert.ok(!/\swidth="\d+px"/.test(svg), `${name}: the SVG carries a fixed width — it cannot scale`);
    assert.match(svg, /viewBox="0 0 \d+ \d+"/, `${name}: no viewBox`);
    // 8 = the 4-module quiet zone on each side, which is inside the viewBox.
    const pxPerModule = drawn / (modules + 8);
    assert.ok(pxPerModule >= 2,
      `${name} (${link.length} chars, ${modules} modules): ${pxPerModule.toFixed(2)}px per module — under 2px a phone camera cannot resolve it`);
  }
});

test('a link too long to encode still leaves the user the copy button', () => {
  const qrcode = loadQrcode();
  // Type 40 at level L holds ~2953 bytes; past that the library throws and
  // showServerQr must catch it rather than leave an empty modal.
  assert.throws(() => { const qr = qrcode(0, 'L'); qr.addData('v'.repeat(5000)); qr.make(); });
  assert.match(APP, /catch \(e\) \{[\s\S]{0,200}qr\.tooBig/,
    'showServerQr must fall back to the "too long" hint when the library refuses the link');
});
