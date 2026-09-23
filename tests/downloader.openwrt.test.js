'use strict';
/**
 * Which release asset the downloader picks on a router. The Google Wifi
 * AC-1304 is 32-bit ARMv7 (`os.arch()` → 'arm'); nobody here can download on
 * it, so the names are pinned against what the three upstream release pages
 * publish — copied verbatim from patterniha/Xray-core v26.9.13 (identical
 * names on XTLS/Xray-core), sing-box and xjasonlyu/tun2socks.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { Downloader } = require('../src/main/downloader');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-dl-openwrt-'));
const dl = new Downloader({ destDir: dir });
test.after(() => { try { fs.rmSync(dir, { recursive: true, force: true }); } catch {} });

// Real asset names from the release pages (2026-09-23).
const XRAY_ASSETS = ['Xray-linux-32.zip', 'Xray-linux-64.zip', 'Xray-linux-arm32-v5.zip', 'Xray-linux-arm32-v6.zip',
  'Xray-linux-arm32-v7a.zip', 'Xray-linux-arm64-v8a.zip', 'Xray-linux-mips32.zip', 'Xray-linux-mips32le.zip',
  'Xray-linux-mips64.zip', 'Xray-linux-mips64le.zip'];
const SB_ASSETS = ['sing-box-1.12.4-linux-amd64.tar.gz', 'sing-box-1.12.4-linux-amd64v3.tar.gz', 'sing-box-1.12.4-linux-arm64.tar.gz',
  'sing-box-1.12.4-linux-armv5.tar.gz', 'sing-box-1.12.4-linux-armv6.tar.gz', 'sing-box-1.12.4-linux-armv7.tar.gz',
  'sing-box-1.12.4-linux-mips.tar.gz', 'sing-box-1.12.4-linux-mipsle.tar.gz', 'sing-box-1.12.4-linux-mips64.tar.gz',
  'sing-box-1.12.4-linux-armv7.tar.gz.sha256', 'sing-box-1.12.4-android-armv7.tar.gz'];
const T2S_ASSETS = ['tun2socks-linux-amd64.zip', 'tun2socks-linux-arm64.zip', 'tun2socks-linux-armv5.zip', 'tun2socks-linux-armv6.zip',
  'tun2socks-linux-armv7.zip', 'tun2socks-linux-mips.zip', 'tun2socks-linux-mipsle.zip', 'tun2socks-linux-mips64.zip'];

test('Xray / Xray-PattN: an ARMv7 router asks for arm32-v7a; mips routers for mips32/mips32le', () => {
  assert.equal(dl.xrayAssetName('linux', 'arm'), 'Xray-linux-arm32-v7a.zip');
  assert.equal(dl.xrayAssetName('linux', 'mips'), 'Xray-linux-mips32.zip');
  assert.equal(dl.xrayAssetName('linux', 'mipsel'), 'Xray-linux-mips32le.zip');
  for (const a of ['arm', 'mips', 'mipsel', 'arm64', 'x64']) assert.ok(XRAY_ASSETS.includes(dl.xrayAssetName('linux', a)), a);
  // the rows that existed did not move
  assert.equal(dl.xrayAssetName('linux', 'x64'), 'Xray-linux-64.zip');
  assert.equal(dl.xrayAssetName('linux', 'arm64'), 'Xray-linux-arm64-v8a.zip');
  assert.equal(dl.xrayAssetName('linux', 'ppc64'), 'Xray-linux-64.zip', 'an arch with no row falls back to 64, as before');
  assert.equal(dl.xrayAssetName('win32', 'x64'), 'Xray-windows-64.zip');
  assert.equal(dl.xrayAssetName('darwin', 'arm64'), 'Xray-macos-arm64-v8a.zip');
});

test('sing-box: linux-armv7 for the router, and only that file in the release', () => {
  const pick = (platform, arch) => SB_ASSETS.filter(a => dl.singboxAssetPattern(platform, arch).test(a));
  assert.deepEqual(pick('linux', 'arm'), ['sing-box-1.12.4-linux-armv7.tar.gz'], 'not the .sha256, not android');
  assert.deepEqual(pick('linux', 'mips'), ['sing-box-1.12.4-linux-mips.tar.gz']);
  assert.deepEqual(pick('linux', 'mipsel'), ['sing-box-1.12.4-linux-mipsle.tar.gz']);
  assert.deepEqual(pick('linux', 'arm64'), ['sing-box-1.12.4-linux-arm64.tar.gz']);
  assert.deepEqual(pick('linux', 'x64'), ['sing-box-1.12.4-linux-amd64.tar.gz'], 'amd64v3 is a different build');
});

test('tun2socks: linux-armv7 / mips / mipsle, and the binary inside is named like the zip', () => {
  assert.equal(dl.tun2socksAssetName('linux', 'arm'), 'tun2socks-linux-armv7.zip');
  assert.equal(dl.tun2socksAssetName('linux', 'mips'), 'tun2socks-linux-mips.zip');
  assert.equal(dl.tun2socksAssetName('linux', 'mipsel'), 'tun2socks-linux-mipsle.zip');
  for (const a of ['arm', 'mips', 'mipsel', 'arm64', 'x64']) assert.ok(T2S_ASSETS.includes(dl.tun2socksAssetName('linux', a)), a);
  assert.equal(dl.tun2socksAssetName('linux', 'x64'), 'tun2socks-linux-amd64.zip');
  assert.equal(dl.tun2socksAssetName('win32', 'arm64'), 'tun2socks-windows-arm64.zip');
  assert.equal(dl.tun2socksAssetName('darwin', 'x64'), 'tun2socks-darwin-amd64.zip');
});
