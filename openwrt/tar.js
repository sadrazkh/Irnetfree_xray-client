'use strict';
/**
 * A ustar writer and reader in Node core — all an ipk needs (an ipk is a
 * gzipped tar of debian-binary + control.tar.gz + data.tar.gz). Ours, so the
 * package builds identically on the owner's Windows box and on the runner:
 * owner 0:0, a fixed mtime, no `tar` flag that differs between GNU and BSD.
 *
 * Limits, checked: names under 100 bytes (ours are), sizes under 8 GiB.
 */
const zlib = require('zlib');

/** `%0<len-1>o\0` — the octal field shape ustar uses for mode/uid/gid/size/mtime. */
function oct(n, len) { return n.toString(8).padStart(len - 1, '0') + '\0'; }

function header({ name, size, mode, type, mtime }) {
  if (Buffer.byteLength(name, 'utf8') > 99) throw new Error('tar name too long: ' + name);
  const h = Buffer.alloc(512);
  h.write(name, 0, 'utf8');
  h.write(oct(mode, 8), 100);
  h.write(oct(0, 8), 108);            // uid
  h.write(oct(0, 8), 116);            // gid
  h.write(oct(size, 12), 124);
  h.write(oct(mtime, 12), 136);
  h.write('        ', 148);           // checksum: spaces while summing
  h.write(type, 156);                 // '0' file, '5' directory
  h.write('ustar\0', 257);
  h.write('00', 263);
  h.write('root', 265);
  h.write('root', 297);
  let sum = 0;
  for (const b of h) sum += b;
  h.write(sum.toString(8).padStart(6, '0') + '\0 ', 148);
  return h;
}

/**
 * entries: [{ name, data?: Buffer|string, mode?, dir?: true }] — names without
 * the leading './' (added here, the way opkg's own packages look). Directories
 * get a trailing slash. Two 512-byte zero blocks end the archive.
 */
function tar(entries, { mtime = 0 } = {}) {
  const parts = [];
  for (const e of entries) {
    const dir = !!e.dir;
    const data = dir ? Buffer.alloc(0) : (Buffer.isBuffer(e.data) ? e.data : Buffer.from(e.data == null ? '' : String(e.data), 'utf8'));
    const name = './' + e.name.replace(/^\.?\//, '') + (dir && !e.name.endsWith('/') ? '/' : '');
    parts.push(header({ name, size: data.length, mode: e.mode == null ? (dir ? 0o755 : 0o644) : e.mode, type: dir ? '5' : '0', mtime }));
    if (!dir) {
      parts.push(data);
      const rem = data.length % 512;
      if (rem) parts.push(Buffer.alloc(512 - rem));
    }
  }
  parts.push(Buffer.alloc(1024));
  return Buffer.concat(parts);
}

function field(h, off, len) { return h.subarray(off, off + len).toString('utf8').replace(/\0[\s\S]*$/, '').trim(); }

/** The entries of an uncompressed tar: [{ name, mode, type, data }]. */
function untar(buf) {
  const out = [];
  let off = 0;
  while (off + 512 <= buf.length) {
    const h = buf.subarray(off, off + 512);
    if (h.every(b => b === 0)) break;
    const size = parseInt(field(h, 124, 12), 8) || 0;
    out.push({ name: field(h, 0, 100), mode: parseInt(field(h, 100, 8), 8), type: String.fromCharCode(h[156]) || '0', data: buf.subarray(off + 512, off + 512 + size) });
    off += 512 + Math.ceil(size / 512) * 512;
  }
  return out;
}

const tgz = (entries, o) => zlib.gzipSync(tar(entries, o), { level: 9 });
const untgz = (buf) => untar(zlib.gunzipSync(buf));

module.exports = { tar, untar, tgz, untgz };
