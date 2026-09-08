'use strict';
/**
 * Which release asset the downloader picks on a Mac. Nobody on this project
 * can watch that download happen, so the names are pinned here against what
 * the three upstream release pages actually publish — a renamed asset (or a
 * typo in ours) then fails the suite on every platform instead of failing the
 * one user with a MacBook.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { Downloader } = require('../src/main/downloader');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-dl-darwin-'));
const dl = new Downloader({ destDir: dir });
test.after(() => { try { fs.rmSync(dir, { recursive: true, force: true }); } catch {} });

// Real asset names, copied from a release of each project.
const XRAY_ASSETS = ['Xray-macos-64.zip', 'Xray-macos-arm64-v8a.zip', 'Xray-windows-64.zip', 'Xray-linux-arm64-v8a.zip'];
const T2S_ASSETS = ['tun2socks-darwin-amd64.zip', 'tun2socks-darwin-arm64.zip', 'tun2socks-windows-amd64.zip', 'tun2socks-linux-arm64.zip'];
const SB_ASSETS = [
  'sing-box-1.12.4-darwin-amd64.tar.gz', 'sing-box-1.12.4-darwin-arm64.tar.gz',
  'sing-box-1.12.4-linux-amd64.tar.gz', 'sing-box-1.12.4-linux-amd64v3.tar.gz',
  'sing-box-1.12.4-windows-amd64.zip', 'sing-box-1.12.4-windows-amd64-legacy.zip',
  'sing-box-1.12.4-darwin-arm64.tar.gz.sha256', 'sing-box-1.12.4-android-arm64-v8a.tar.gz'
];

test('Xray: Intel and Apple Silicon Macs ask for the two macos zips Xray-core publishes', () => {
  assert.equal(dl.xrayAssetName('darwin', 'x64'), 'Xray-macos-64.zip');
  assert.equal(dl.xrayAssetName('darwin', 'arm64'), 'Xray-macos-arm64-v8a.zip');
  for (const p of ['x64', 'arm64']) assert.ok(XRAY_ASSETS.includes(dl.xrayAssetName('darwin', p)), p);
  // and the other platforms did not move
  assert.equal(dl.xrayAssetName('win32', 'x64'), 'Xray-windows-64.zip');
  assert.equal(dl.xrayAssetName('linux', 'arm64'), 'Xray-linux-arm64-v8a.zip');
});

test('tun2socks: darwin-amd64 / darwin-arm64 zips, and the binary inside is named like the zip', () => {
  assert.equal(dl.tun2socksAssetName('darwin', 'x64'), 'tun2socks-darwin-amd64.zip');
  assert.equal(dl.tun2socksAssetName('darwin', 'arm64'), 'tun2socks-darwin-arm64.zip');
  for (const p of ['x64', 'arm64']) assert.ok(T2S_ASSETS.includes(dl.tun2socksAssetName('darwin', p)), p);
  // getTun2socks() looks for `<asset name without .zip>` first — no `.exe` off Windows
  assert.equal(dl.tun2socksAssetName('darwin', 'arm64').replace('.zip', ''), 'tun2socks-darwin-arm64');
  assert.equal(dl.tun2socksAssetName('win32', 'x64'), 'tun2socks-windows-amd64.zip');
});

test('sing-box: the darwin tar.gz of the right arch, and nothing else in the release', () => {
  const pick = (platform, arch) => SB_ASSETS.filter(a => dl.singboxAssetPattern(platform, arch).test(a));
  assert.deepEqual(pick('darwin', 'x64'), ['sing-box-1.12.4-darwin-amd64.tar.gz']);
  assert.deepEqual(pick('darwin', 'arm64'), ['sing-box-1.12.4-darwin-arm64.tar.gz'], 'not the .sha256 next to it');
  assert.deepEqual(pick('linux', 'x64'), ['sing-box-1.12.4-linux-amd64.tar.gz'], 'amd64v3 is a different build');
  assert.deepEqual(pick('win32', 'x64'), ['sing-box-1.12.4-windows-amd64.zip'], 'not the -legacy build');
});

test('the pickers default to this machine, as every caller relies on', () => {
  assert.equal(dl.xrayAssetName(), dl.xrayAssetName(os.platform(), os.arch()));
  assert.equal(dl.tun2socksAssetName(), dl.tun2socksAssetName(os.platform(), os.arch()));
  assert.equal(String(dl.singboxAssetPattern()), String(dl.singboxAssetPattern(os.platform(), os.arch())));
});
