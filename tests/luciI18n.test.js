'use strict';
/**
 * LuCI translates the menu (Services → IRNetFree → Overview | Settings |
 * Remote access | Log) from its own catalogs, not from the pages: the browser
 * looks every title up in window.TR, which LuCI fills from every
 * /usr/lib/lua/luci/i18n/*.<lang>.lmo. So the package carries
 * irnetfree.fa.lmo, compiled at build time from openwrt/files/luci/po/fa/
 * irnetfree.po by openwrt/lmo.js — the same bytes LuCI's po2lmo writes.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { sfh, parsePo, buildLmo } = require('../openwrt/lmo');
const { tgz, untgz } = require('../openwrt/tar');
const { buildIpk } = require('../openwrt/build-ipk');

const ROOT = path.join(__dirname, '..');
const PO = path.join(ROOT, 'openwrt', 'files', 'luci', 'po', 'fa', 'irnetfree.po');

test('sfh: the hash LuCI keys translations by, byte for byte with the browser\'s own (cbi.js)', () => {
  // computed with LuCI 23.05's cbi.js sfh() in a browser, 2026-10-01
  const vectors = {
    'a': '115ea782', 'ab': '516b8b44', 'abc': 'd2be198a', 'abcd': 'dad8b8db',
    'Overview': 'adbaae97', 'Settings': '60cc7d18', 'Remote access': '45517f0a', 'Log': 'eecc73fd',
    'IRNetFree': 'bbcc1363', 'IRNetFree: status, settings and remote access': '0e2ec9b2', 'Save & Apply': '610beed4',
    'دسترسی از راه دور': '49d3f5b8', 'نمای کلی': '1bb116a0'
  };
  for (const [s, hex] of Object.entries(vectors)) assert.equal(sfh(s).toString(16).padStart(8, '0'), hex, s);
  assert.equal(sfh(''), 0);
});

test('parsePo: msgid/msgstr pairs, continuation lines and escapes; the header and comments are skipped', () => {
  const pairs = parsePo([
    '# a comment', 'msgid ""', 'msgstr ""', '"Content-Type: text/plain; charset=UTF-8\\n"', '',
    'msgid "Overview"', 'msgstr "نمای کلی"', '',
    'msgid "Say \\"hi\\""', 'msgstr ""', '"a "', '"b"', '',
    'msgid "Untranslated"', 'msgstr ""', ''
  ].join('\n'));
  assert.deepEqual(pairs, [['Overview', 'نمای کلی'], ['Say "hi"', 'a b']]);
  assert.throws(() => parsePo('msgid "x"\nmsgstr "y\\n"\n'), /escape/, 'po2lmo keeps other escapes verbatim: refused rather than guessed');
  assert.throws(() => parsePo('msgid "x"\nmsgstr "y"\nmsgid "x"\nmsgstr "z"\n'), /twice/);
});

/** Read an lmo the way luci-base/src/lib/lmo.c does: the index offset in the last 4 bytes, 16-byte big-endian entries, binary search. */
function lmoLookup(buf, msgid) {
  const idx = buf.readUInt32BE(buf.length - 4);
  assert.ok(idx < buf.length, 'index offset inside the file');
  const n = (buf.length - idx - 4) / 16;
  assert.equal(n, Math.floor(n), 'whole index entries');
  const key = sfh(msgid);
  let l = 0, r = n - 1;
  while (l <= r) {
    const m = l + ((r - l) >> 1);
    const k = buf.readUInt32BE(idx + m * 16);
    if (k === key) {
      const off = buf.readUInt32BE(idx + m * 16 + 8), len = buf.readUInt32BE(idx + m * 16 + 12);
      assert.equal(buf.readUInt32BE(idx + m * 16 + 4), 1, 'val_id 1: a singular translation');
      assert.ok(off + len <= idx, 'the string lies before the index');
      return buf.subarray(off, off + len).toString('utf8');
    }
    if (k > key) r = m - 1; else l = m + 1;
  }
  return null;
}

test('buildLmo: strings padded to 4 bytes, the index sorted by key, its offset last — readable as lmo.c reads it', () => {
  const pairs = [['Overview', 'نمای کلی'], ['Log', 'لاگ'], ['abc', 'x'], ['Same', 'Same']];
  const buf = buildLmo(pairs);
  const idx = buf.readUInt32BE(buf.length - 4);
  assert.equal(idx % 4, 0);
  const keys = [];
  for (let o = idx; o < buf.length - 4; o += 16) keys.push(buf.readUInt32BE(o));
  assert.deepEqual(keys, [...keys].sort((a, b) => a - b), 'sorted for the binary search');
  assert.equal(keys.length, 3, 'a "translation" equal to its msgid is left out, as po2lmo does');
  assert.equal(lmoLookup(buf, 'Overview'), 'نمای کلی');
  assert.equal(lmoLookup(buf, 'Log'), 'لاگ');
  assert.equal(lmoLookup(buf, 'abc'), 'x');
  assert.equal(lmoLookup(buf, 'Missing'), null);
  assert.ok(buildLmo(pairs).equals(buf), 'deterministic');
  assert.throws(() => buildLmo([]), /empty/, 'po2lmo writes no file for an empty catalog — neither do we');
});

test('the Persian catalog: every tab title and the ACL description, the same words the pages use', () => {
  const pairs = parsePo(fs.readFileSync(PO, 'utf8'));
  const fa = Object.fromEntries(pairs);
  const menu = JSON.parse(fs.readFileSync(path.join(ROOT, 'openwrt/files/luci/menu.json'), 'utf8'));
  for (const node of Object.values(menu)) {
    if (node.title === 'IRNetFree') continue;   // the name stays as it is
    assert.ok(fa[node.title], `no Persian for the tab "${node.title}"`);
    assert.match(fa[node.title], /[؀-ۿ]/);
  }
  const acl = JSON.parse(fs.readFileSync(path.join(ROOT, 'openwrt/files/luci/acl.json'), 'utf8'));
  assert.ok(fa[acl['luci-app-irnetfree'].description], 'the ACL description (luci-app-acl shows it)');
  // where a page says the same thing, it says it the same way
  const dictSrc = fs.readFileSync(path.join(ROOT, 'openwrt/files/luci/irnetfree-common.js'), 'utf8');
  for (const [en, p] of pairs) {
    const m = new RegExp(`^\\t'${en.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}': '([^']*)',?$`, 'm').exec(dictSrc);
    if (m) assert.equal(p, m[1], `"${en}" is translated differently in the menu and on the page`);
  }
});

test('the package carries the compiled catalog where LuCI loads it', () => {
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-i18n-'));
  try {
    const built = buildIpk({ root: ROOT, outDir, mtime: 0 });
    const outer = untgz(fs.readFileSync(built.out));
    const data = Object.fromEntries(untgz(outer.find((e) => e.name === './data.tar.gz').data).map((e) => [e.name, e]));
    const lmo = data['./usr/lib/lua/luci/i18n/irnetfree.fa.lmo'];
    assert.ok(lmo, 'irnetfree.fa.lmo is in the package');
    assert.equal(lmo.mode, 0o644);
    assert.ok(lmo.data.equals(buildLmo(parsePo(fs.readFileSync(PO, 'utf8')))));
    assert.equal(lmoLookup(lmo.data, 'Remote access'), 'دسترسی از راه دور');
    assert.ok(data['./usr/lib/lua/luci/i18n/'] && data['./usr/lib/lua/luci/i18n/'].type === '5', 'its directory has an entry');
  }
  finally { fs.rmSync(outDir, { recursive: true, force: true }); }
  assert.ok(tgz, 'tar helpers loaded');
});
