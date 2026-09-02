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
