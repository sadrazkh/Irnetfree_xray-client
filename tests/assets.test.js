'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { assetStatus } = require('../src/main/assets');

function withDirs(fn) {
  const a = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-bin-a-'));
  const b = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-bin-b-'));
  try { return fn(a, b); } finally { fs.rmSync(a, { recursive: true, force: true }); fs.rmSync(b, { recursive: true, force: true }); }
}

test('reports every engine and component, searching all dirs', () => {
  withDirs((a, b) => {
    fs.writeFileSync(path.join(a, 'xray.exe'), '');
    fs.writeFileSync(path.join(b, 'sing-box.exe'), '');
    fs.writeFileSync(path.join(b, 'geoip.dat'), '');
    const st = assetStatus([a, b], 'win32');
    assert.equal(st.platform, 'win32');
    assert.equal(st.xray, true);
    assert.equal(st['sing-box'], true);      // main.js reported this, service.js forgot it
    assert.equal(st.tun2socks, false);
    assert.equal(st.wintun, false);
    assert.equal(st.geoip, true);
    assert.equal(st.geosite, false);
  });
});

test('uses the platform’s executable names and treats wintun as present off Windows', () => {
  withDirs((a) => {
    fs.writeFileSync(path.join(a, 'xray'), '');
    fs.writeFileSync(path.join(a, 'tun2socks'), '');
    const st = assetStatus([a], 'darwin');
    assert.equal(st.xray, true);
    assert.equal(st.tun2socks, true);
    assert.equal(st.wintun, true);
    assert.equal(assetStatus([a], 'win32').xray, false, 'xray.exe is the Windows name');
  });
});

test('ignores empty / missing dirs', () => {
  const st = assetStatus(['', null, '/definitely/not/here'], 'linux');
  assert.equal(st.xray, false);
  assert.equal(st.geosite, false);
});

/* ------------------------------ tunReady ------------------------------ */
// Either TUN backend makes the machine TUN-capable: sing-box or tun2socks, each
// with wintun on Windows. The renderer's Required-files list and the TUN
// switch read this one flag instead of `tun2socks` (task 4).

test('tunReady: sing-box + wintun, or tun2socks + wintun, on Windows', () => {
  withDirs((a, b) => {
    fs.writeFileSync(path.join(a, 'sing-box.exe'), '');
    assert.equal(assetStatus([a, b], 'win32').tunReady, false, 'sing-box without wintun');
    fs.writeFileSync(path.join(b, 'wintun.dll'), '');
    assert.equal(assetStatus([a, b], 'win32').tunReady, true, 'sing-box + wintun');
  });
  withDirs((a, b) => {
    fs.writeFileSync(path.join(a, 'tun2socks.exe'), '');
    assert.equal(assetStatus([a, b], 'win32').tunReady, false, 'tun2socks without wintun');
    fs.writeFileSync(path.join(b, 'wintun.dll'), '');
    assert.equal(assetStatus([a, b], 'win32').tunReady, true, 'tun2socks + wintun');
  });
  withDirs((a) => {
    fs.writeFileSync(path.join(a, 'wintun.dll'), '');
    fs.writeFileSync(path.join(a, 'xray.exe'), '');
    assert.equal(assetStatus([a], 'win32').tunReady, false, 'wintun alone is not a backend');
  });
  assert.equal(assetStatus([], 'win32').tunReady, false);
});

test('tunReady: off Windows either backend alone is enough; the old keys stay as they were', () => {
  withDirs((a) => {
    fs.writeFileSync(path.join(a, 'sing-box'), '');
    const st = assetStatus([a], 'darwin');
    assert.equal(st.tunReady, true);
    assert.equal(st.tun2socks, false, 'the legacy key still means tun2socks only');
    assert.equal(st.wintun, true);
  });
  withDirs((a) => {
    fs.writeFileSync(path.join(a, 'tun2socks'), '');
    assert.equal(assetStatus([a], 'linux').tunReady, true);
  });
  assert.equal(assetStatus([], 'darwin').tunReady, false);
});
