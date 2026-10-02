'use strict';
/**
 * .po → .lmo in Node core: the catalog format LuCI reads its translations
 * from (/usr/lib/lua/luci/i18n/<name>.<lang>.lmo — every file for the
 * language is loaded). The same bytes LuCI's own po2lmo writes, for the subset
 * used here: singular messages, no msgctxt, no plural forms.
 *
 * Layout (luci-base/src/po2lmo.c, src/lib/lmo.c): every translation, each
 * padded with NULs to a multiple of 4 bytes; then the index, one 16-byte entry
 * per message sorted by key — key_id (the hash of the msgid), val_id (1 for a
 * singular msgstr), offset, length, all big-endian uint32; then the index's
 * offset as the file's last 4 bytes. The browser looks titles up in
 * window.TR, keyed by the same hash computed in cbi.js — so sfh() below must
 * agree with LuCI's to the bit (tests/luciI18n.test.js pins it).
 */

/** SuperFastHash over the UTF-8 bytes, seeded with the length: lmo.c sfh_hash(), cbi.js sfh(). */
function sfh(str) {
  const b = Buffer.from(String(str), 'utf8');
  let len = b.length;
  if (!len) return 0;
  const get16 = (o) => b[o] | (b[o + 1] << 8);
  const s8 = (o) => (b[o] << 24) >> 24;          // (signed char)
  let hash = len >>> 0, tmp, off = 0;
  const rem = len & 3;
  len >>>= 2;
  for (; len > 0; len--) {
    hash = (hash + get16(off)) >>> 0;
    tmp = ((get16(off + 2) << 11) ^ hash) >>> 0;
    hash = ((hash << 16) ^ tmp) >>> 0;
    off += 4;
    hash = (hash + (hash >>> 11)) >>> 0;
  }
  switch (rem) {
    case 3:
      hash = (hash + get16(off)) >>> 0;
      hash = (hash ^ (hash << 16)) >>> 0;
      hash = (hash ^ (s8(off + 2) << 18)) >>> 0;
      hash = (hash + (hash >>> 11)) >>> 0;
      break;
    case 2:
      hash = (hash + get16(off)) >>> 0;
      hash = (hash ^ (hash << 11)) >>> 0;
      hash = (hash + (hash >>> 17)) >>> 0;
      break;
    case 1:
      hash = (hash + s8(off)) >>> 0;
      hash = (hash ^ (hash << 10)) >>> 0;
      hash = (hash + (hash >>> 1)) >>> 0;
      break;
  }
  hash = (hash ^ (hash << 3)) >>> 0;
  hash = (hash + (hash >>> 5)) >>> 0;
  hash = (hash ^ (hash << 4)) >>> 0;
  hash = (hash + (hash >>> 17)) >>> 0;
  hash = (hash ^ (hash << 25)) >>> 0;
  hash = (hash + (hash >>> 6)) >>> 0;
  return hash;
}

/**
 * [[msgid, msgstr], …] from a .po file: continuation lines joined, \" and \\
 * unescaped; the header (msgid "") and untranslated messages skipped. Any
 * other escape is refused — po2lmo would keep it verbatim, and a catalog that
 * means something else than it says is worse than a build error.
 */
function parsePo(text) {
  const out = [];
  const seen = new Set();
  let id = null, str = null, field = null, bad = null;
  const unquote = (s) => {
    const m = /^"((?:[^"\\]|\\.)*)"\s*$/.exec(s.trim());
    if (!m) throw new Error(`po: not a quoted string: ${s}`);
    return m[1].replace(/\\(.)/g, (all, c) => {
      if (c === '"' || c === '\\') return c;
      bad = bad || all;
      return all;
    });
  };
  const flush = () => {
    if (id && str) {
      if (bad) throw new Error(`po: unsupported escape ${bad} in "${id}"`);
      if (seen.has(id)) throw new Error(`po: "${id}" is in the catalog twice`);
      seen.add(id);
      out.push([id, str]);
    }
    id = str = field = null;
    bad = null;
  };
  for (const raw of String(text).split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    if (line.startsWith('msgctxt ') || line.startsWith('msgid_plural ') || line.startsWith('msgstr[')) throw new Error(`po: not supported here: ${line}`);
    if (line.startsWith('msgid ')) { flush(); id = unquote(line.slice(6)); field = 'id'; continue; }
    if (line.startsWith('msgstr ')) { str = unquote(line.slice(7)); field = 'str'; continue; }
    if (line.startsWith('"') && field) {
      const s = unquote(line);
      if (field === 'id') id += s; else str += s;
      continue;
    }
    throw new Error(`po: cannot read: ${line}`);
  }
  flush();
  return out;
}

/** The .lmo bytes for [[msgid, msgstr], …]. */
function buildLmo(pairs) {
  const index = [];
  const parts = [];
  let offset = 0;
  for (const [id, str] of pairs) {
    const key = sfh(id);
    if (key === sfh(str)) continue;   // a "translation" that is the msgid itself: po2lmo leaves it out
    const buf = Buffer.from(str, 'utf8');
    const pad = (4 - (buf.length % 4)) % 4;
    index.push({ key, offset, length: buf.length });
    parts.push(buf, Buffer.alloc(pad));
    offset += buf.length + pad;
  }
  if (!index.length) throw new Error('lmo: an empty catalog (po2lmo writes no file for one)');
  index.sort((a, b) => a.key - b.key);
  const idx = Buffer.alloc(index.length * 16 + 4);
  index.forEach((e, i) => {
    idx.writeUInt32BE(e.key, i * 16);
    idx.writeUInt32BE(1, i * 16 + 4);
    idx.writeUInt32BE(e.offset, i * 16 + 8);
    idx.writeUInt32BE(e.length, i * 16 + 12);
  });
  idx.writeUInt32BE(offset, index.length * 16);
  return Buffer.concat([...parts, idx]);
}

module.exports = { sfh, parsePo, buildLmo };
