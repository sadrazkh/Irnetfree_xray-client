'use strict';
/**
 * The bundled country-flag font.
 *
 * A flag emoji is two Regional Indicator letters (app.js flagEmoji) that the
 * font has to ligate. Segoe UI Emoji carries no national flags, so on Windows
 * the app showed "GB" where a Mac showed a flag. src/renderer/vendor holds a
 * COLRv1 font with those ligatures and nothing else, and every part of the
 * wiring can break silently: a missing file is an invisible 404, a wrong
 * `unicode-range` would let it answer for ordinary text, and a family that is
 * not FIRST in the type tokens is never consulted at all. So all of it is
 * pinned here, including the font's own bytes.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const R = (...p) => path.join(__dirname, '..', 'src', 'renderer', ...p);
const CSS = fs.readFileSync(R('styles.css'), 'utf8');
const FONT = R('vendor', 'TwemojiCountryFlags.woff2');
const FAMILY = 'Twemoji Country Flags';
/** The regional-indicator block, the whole of it and nothing else. */
const RANGE = 'U+1F1E6-1F1FF';

test('the font file is there, is a real woff2, and is small enough to bundle', () => {
  assert.ok(fs.existsSync(FONT), 'src/renderer/vendor/TwemojiCountryFlags.woff2 is missing');
  const buf = fs.readFileSync(FONT);
  assert.equal(buf.subarray(0, 4).toString('latin1'), 'wOF2', 'not a woff2 file (bad signature)');
  // The flag subset is ~78 KB. A file an order of magnitude bigger would mean
  // somebody swapped in a full emoji font, which would then also answer for
  // every other emoji in the UI.
  assert.ok(buf.length > 20 * 1024 && buf.length < 300 * 1024, `unexpected size ${buf.length} bytes`);
});

test('the licence and attribution the artwork requires ship next to it', () => {
  const lic = fs.readFileSync(R('vendor', 'LICENSE-TwemojiCountryFlags.txt'), 'utf8');
  for (const must of ['Twemoji', 'CC-BY 4.0', 'creativecommons.org/licenses/by/4.0', 'MIT']) {
    assert.ok(lic.includes(must), `the licence file does not mention ${must}`);
  }
  const buf = fs.readFileSync(FONT);
  const stated = lic.match(/sha256\s+([0-9a-f]{64})/);
  assert.ok(stated, 'the licence file states no sha256 for the font');
  assert.equal(require('node:crypto').createHash('sha256').update(buf).digest('hex'), stated[1],
    'the font file does not match the sha256 the licence file records — say where the new one came from');
  assert.match(lic, new RegExp(`size\\s+${buf.length} bytes`), 'the recorded size does not match the file');
});

test('@font-face declares the family, the file and the regional-indicator range only', () => {
  const block = CSS.match(/@font-face\s*\{[^}]*\}/g) || [];
  assert.equal(block.length, 1, 'expected exactly one @font-face in styles.css');
  const face = block[0];
  assert.match(face, new RegExp(`font-family:\\s*"${FAMILY}"`));
  assert.match(face, /src:\s*url\("vendor\/TwemojiCountryFlags\.woff2"\)\s*format\("woff2"\)/,
    'the src must be the relative path styles.css sits next to, or the font 404s in the packaged app');
  assert.match(face, new RegExp(`unicode-range:\\s*${RANGE.replace('+', '\\+')}\\s*;`, 'i'),
    'without exactly this range the font would be asked for text it has no glyphs for');
  assert.match(face, /font-display:\s*swap/, 'the UI must not block on a font it only needs for flags');
});

test('both type tokens name the flag family first, and nothing else in the CSS names it', () => {
  const token = (name) => {
    const m = CSS.match(new RegExp(`--${name}:\\s*([^;]+);`));
    assert.ok(m, `--${name} is not declared`);
    return m[1].trim();
  };
  for (const name of ['ui', 'mono']) {
    const value = token(name);
    assert.ok(value.startsWith(`"${FAMILY}"`), `--${name} must start with the flag family, got: ${value}`);
    // the stack it used to be still follows it
    assert.ok(value.split(',').length >= 3, `--${name} lost its fallbacks: ${value}`);
  }
  assert.ok(token('ui').includes('"Segoe UI"') && token('ui').includes('"Iran Sans"'));
  assert.ok(token('mono').includes('Consolas') && token('mono').includes('monospace'));
  // Every element takes its font from one of those two tokens, so no RULE
  // should name the family itself. Comments may say whatever they need to, so
  // they come out before counting.
  for (const file of fs.readdirSync(R()).filter(f => f.endsWith('.css'))) {
    const code = fs.readFileSync(R(file), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '');
    const named = code.split(FAMILY).length - 1;
    const allowed = file === 'styles.css' ? 3 : 0;   // @font-face + the two tokens
    assert.ok(named <= allowed, `${file} names the flag family ${named} times in code; it belongs in the tokens only`);
  }
});

test('the font is packaged: it lives under src/, which build.files ships whole', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));
  assert.ok(pkg.build.files.includes('src/**/*'), 'build.files no longer ships all of src/ — the font would be left out');
  assert.equal(pkg.build.files.some(p => /woff2|!.*vendor/.test(p)), false, 'a filter now excludes the font');
  assert.deepEqual(pkg.dependencies || {}, {}, 'the flag font is a bundled file, not a dependency');
});
