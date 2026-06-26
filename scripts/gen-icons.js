'use strict';
/**
 * Generates IRNetFree app icons with zero external dependencies.
 * Draws the shield + globe logo into RGBA pixel buffers, then writes:
 *   assets/icon.png   (512)  — used by electron-builder to derive all sizes
 *   assets/tray.png   (32)
 *   assets/icon.ico   (multi-size 16/32/48/64/128/256) for Windows
 *
 * Run: node scripts/gen-icons.js
 */
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const OUT = path.join(__dirname, '..', 'assets');

/* ---------- tiny canvas ---------- */
function canvas(size) {
  return { w: size, h: size, px: new Uint8ClampedArray(size * size * 4) };
}
function setpx(c, x, y, r, g, b, a) {
  if (x < 0 || y < 0 || x >= c.w || y >= c.h) return;
  const i = (y * c.w + x) * 4;
  const ia = a / 255;
  // alpha over existing
  const oa = c.px[i + 3] / 255;
  const na = ia + oa * (1 - ia);
  if (na <= 0) return;
  c.px[i]     = (r * ia + c.px[i]     * oa * (1 - ia)) / na;
  c.px[i + 1] = (g * ia + c.px[i + 1] * oa * (1 - ia)) / na;
  c.px[i + 2] = (b * ia + c.px[i + 2] * oa * (1 - ia)) / na;
  c.px[i + 3] = na * 255;
}
function lerp(a, b, t) { return a + (b - a) * t; }
// gradient blue(#4f8cff) -> teal(#2dd4bf) by diagonal position t in [0,1]
function grad(t) {
  return [Math.round(lerp(0x4f, 0x2d, t)), Math.round(lerp(0x8c, 0xd4, t)), Math.round(lerp(0xff, 0xbf, t))];
}

/* ---------- primitives (supersampled via fractional coverage) ---------- */
function fillRoundRect(c, x0, y0, w, h, rad, colorFn) {
  for (let y = 0; y < c.h; y++) {
    for (let x = 0; x < c.w; x++) {
      const px = x - x0, py = y - y0;
      if (px < 0 || py < 0 || px >= w || py >= h) continue;
      // rounded corner test
      let inside = true;
      const cxs = [rad, w - rad], cys = [rad, h - rad];
      if ((px < rad || px > w - rad) && (py < rad || py > h - rad)) {
        const cx = px < rad ? rad : w - rad;
        const cy = py < rad ? rad : h - rad;
        if (Math.hypot(px - cx, py - cy) > rad) inside = false;
      }
      if (!inside) continue;
      const t = (x + y) / (c.w + c.h);
      const col = colorFn(t);
      setpx(c, x, y, col[0], col[1], col[2], 255);
    }
  }
}
function strokeCircle(c, cx, cy, r, lw, colorFn, a = 255) {
  const r0 = r - lw / 2, r1 = r + lw / 2;
  for (let y = Math.floor(cy - r1); y <= Math.ceil(cy + r1); y++) {
    for (let x = Math.floor(cx - r1); x <= Math.ceil(cx + r1); x++) {
      const d = Math.hypot(x - cx, y - cy);
      if (d >= r0 && d <= r1) {
        const t = (x + y) / (c.w + c.h);
        const col = colorFn(t);
        setpx(c, x, y, col[0], col[1], col[2], a);
      }
    }
  }
}
function strokeEllipse(c, cx, cy, rx, ry, lw, colorFn, a = 255) {
  for (let y = Math.floor(cy - ry - lw); y <= Math.ceil(cy + ry + lw); y++) {
    for (let x = Math.floor(cx - rx - lw); x <= Math.ceil(cx + rx + lw); x++) {
      const dn = ((x - cx) / rx) ** 2 + ((y - cy) / ry) ** 2;
      const inner = ((x - cx) / (rx - lw / 2)) ** 2 + ((y - cy) / (ry - lw / 2)) ** 2;
      const outer = ((x - cx) / (rx + lw / 2)) ** 2 + ((y - cy) / (ry + lw / 2)) ** 2;
      if (outer <= 1 && inner >= 1) {
        const t = (x + y) / (c.w + c.h);
        const col = colorFn(t);
        setpx(c, x, y, col[0], col[1], col[2], a);
      }
    }
  }
}
function line(c, x1, y1, x2, y2, lw, colorFn, a = 255) {
  const steps = Math.ceil(Math.hypot(x2 - x1, y2 - y1)) * 2;
  for (let i = 0; i <= steps; i++) {
    const t = i / steps;
    const x = lerp(x1, x2, t), y = lerp(y1, y2, t);
    for (let dy = -lw / 2; dy <= lw / 2; dy++) {
      for (let dx = -lw / 2; dx <= lw / 2; dx++) {
        if (dx * dx + dy * dy > (lw / 2) ** 2) continue;
        const gt = (x + y) / (c.w + c.h);
        const col = colorFn(gt);
        setpx(c, Math.round(x + dx), Math.round(y + dy), col[0], col[1], col[2], a);
      }
    }
  }
}
function dot(c, cx, cy, r, col) {
  for (let y = Math.floor(cy - r); y <= Math.ceil(cy + r); y++)
    for (let x = Math.floor(cx - r); x <= Math.ceil(cx + r); x++)
      if (Math.hypot(x - cx, y - cy) <= r) setpx(c, x, y, col[0], col[1], col[2], 255);
}
// shield outline as a thick stroked polyline
function strokeShield(c, S, lw, colorFn) {
  const k = S / 512;
  const pts = [
    [256, 92], [392, 142], [392, 268], [256, 432], [120, 268], [120, 142], [256, 92]
  ].map(([x, y]) => [x * k, y * k]);
  for (let i = 0; i < pts.length - 1; i++) {
    line(c, pts[i][0], pts[i][1], pts[i + 1][0], pts[i + 1][1], lw, colorFn);
  }
}

/* ---------- compose logo at given size ---------- */
function renderLogo(S) {
  const c = canvas(S);
  const k = S / 512;
  // background rounded panel (dark)
  fillRoundRect(c, 16 * k, 16 * k, 480 * k, 480 * k, 108 * k, () => [0x10, 0x16, 0x20]);
  // accent border
  // shield
  strokeShield(c, S, Math.max(2, 16 * k), grad);
  // globe
  strokeCircle(c, 256 * k, 262 * k, 78 * k, Math.max(2, 9 * k), grad);
  strokeEllipse(c, 256 * k, 262 * k, 34 * k, 78 * k, Math.max(2, 9 * k), grad);
  line(c, 178 * k, 262 * k, 334 * k, 262 * k, Math.max(2, 9 * k), grad);
  line(c, 190 * k, 218 * k, 322 * k, 218 * k, Math.max(2, 9 * k), grad);
  line(c, 190 * k, 306 * k, 322 * k, 306 * k, Math.max(2, 9 * k), grad);
  // nodes (teal)
  const teal = [0x2d, 0xd4, 0xbf];
  dot(c, 256 * k, 184 * k, Math.max(2, 11 * k), teal);
  dot(c, 334 * k, 262 * k, Math.max(2, 11 * k), teal);
  dot(c, 178 * k, 262 * k, Math.max(2, 11 * k), teal);
  dot(c, 256 * k, 340 * k, Math.max(2, 11 * k), teal);
  return c;
}

/* ---------- PNG encoder ---------- */
function crc32(buf) {
  let c = ~0;
  for (let i = 0; i < buf.length; i++) {
    c ^= buf[i];
    for (let j = 0; j < 8; j++) c = (c >>> 1) ^ (0xEDB88320 & -(c & 1));
  }
  return ~c >>> 0;
}
function chunk(type, data) {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length, 0);
  const t = Buffer.from(type, 'ascii');
  const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(Buffer.concat([t, data])), 0);
  return Buffer.concat([len, t, data, crc]);
}
function encodePNG(c) {
  const { w, h, px } = c;
  const raw = Buffer.alloc((w * 4 + 1) * h);
  for (let y = 0; y < h; y++) {
    raw[y * (w * 4 + 1)] = 0; // filter none
    for (let x = 0; x < w * 4; x++) raw[y * (w * 4 + 1) + 1 + x] = px[y * w * 4 + x];
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0); ihdr.writeUInt32BE(h, 4);
  ihdr[8] = 8; ihdr[9] = 6; ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0;
  const sig = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  return Buffer.concat([sig, chunk('IHDR', ihdr), chunk('IDAT', zlib.deflateSync(raw, { level: 9 })), chunk('IEND', Buffer.alloc(0))]);
}

/* ---------- ICO (embeds PNGs) ---------- */
function encodeICO(sizes) {
  const imgs = sizes.map(s => ({ s, png: encodePNG(renderLogo(s)) }));
  const header = Buffer.alloc(6);
  header.writeUInt16LE(0, 0); header.writeUInt16LE(1, 2); header.writeUInt16LE(imgs.length, 4);
  let offset = 6 + imgs.length * 16;
  const dir = [];
  for (const im of imgs) {
    const e = Buffer.alloc(16);
    e[0] = im.s >= 256 ? 0 : im.s;
    e[1] = im.s >= 256 ? 0 : im.s;
    e[2] = 0; e[3] = 0;
    e.writeUInt16LE(1, 4); e.writeUInt16LE(32, 6);
    e.writeUInt32LE(im.png.length, 8);
    e.writeUInt32LE(offset, 12);
    offset += im.png.length;
    dir.push(e);
  }
  return Buffer.concat([header, ...dir, ...imgs.map(i => i.png)]);
}

/* ---------- ICNS (macOS, embeds PNGs) ---------- */
// Apple Icon Image format: 'icns' magic + total length, then a sequence of
// typed entries. The OSTypes below all accept a raw PNG payload, so we reuse
// the same PNG encoder used for Windows/Linux. Sizes cover normal + retina.
function encodeICNS() {
  const entries = [
    ['icp4', 16],   // 16x16
    ['icp5', 32],   // 32x32 (also 16@2x)
    ['icp6', 64],   // 64x64 (also 32@2x)
    ['ic07', 128],  // 128x128
    ['ic08', 256],  // 256x256
    ['ic09', 512],  // 512x512
    ['ic10', 1024], // 1024x1024 (512@2x)
    ['ic11', 32],   // 16@2x
    ['ic12', 64],   // 32@2x
    ['ic13', 256],  // 128@2x
    ['ic14', 512]   // 256@2x
  ];
  const chunks = [];
  for (const [type, size] of entries) {
    const png = encodePNG(renderLogo(size));
    const header = Buffer.alloc(8);
    header.write(type, 0, 'ascii');
    header.writeUInt32BE(png.length + 8, 4);
    chunks.push(header, png);
  }
  const body = Buffer.concat(chunks);
  const head = Buffer.alloc(8);
  head.write('icns', 0, 'ascii');
  head.writeUInt32BE(body.length + 8, 4);
  return Buffer.concat([head, body]);
}

/* ---------- run ---------- */
fs.mkdirSync(OUT, { recursive: true });
fs.writeFileSync(path.join(OUT, 'icon.png'), encodePNG(renderLogo(512)));
fs.writeFileSync(path.join(OUT, 'tray.png'), encodePNG(renderLogo(32)));
fs.writeFileSync(path.join(OUT, 'icon.ico'), encodeICO([16, 32, 48, 64, 128, 256]));
fs.writeFileSync(path.join(OUT, 'icon.icns'), encodeICNS());
console.log('✓ Generated icon.png (512), tray.png (32), icon.ico (multi-size), icon.icns (macOS)');
