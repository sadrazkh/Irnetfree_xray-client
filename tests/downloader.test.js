'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { downloadFile } = require('../src/main/downloader');

// Every test needs a directory to download into. They used to be left behind —
// nine per run, hundreds on a machine that runs the suite all day.
const tmpDirs = [];
function tmpFile(name) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-dl-'));
  tmpDirs.push(dir);
  return path.join(dir, name);
}
test.after(() => {
  for (const d of tmpDirs) { try { fs.rmSync(d, { recursive: true, force: true }); } catch {} }
});

function serve(handler) {
  return new Promise((resolve) => {
    const srv = http.createServer(handler);
    srv.listen(0, '127.0.0.1', () => resolve({ srv, port: srv.address().port }));
  });
}

test('a non-200 response rejects and leaves no temp file behind', async () => {
  const { srv, port } = await serve((req, res) => { res.writeHead(403); res.end('rate limited'); });
  const dest = tmpFile('geoip.dat.tmp');
  try {
    await assert.rejects(downloadFile(`http://127.0.0.1:${port}/geoip.dat`, dest), /HTTP 403/);
    assert.equal(fs.existsSync(dest), false, 'temp file must be removed');
  } finally { srv.close(); }
});

test('a 200 response is written in full and reports progress', async () => {
  const body = Buffer.alloc(100000, 7);
  const { srv, port } = await serve((req, res) => { res.writeHead(200, { 'Content-Length': body.length }); res.end(body); });
  const dest = tmpFile('file.bin');
  const seen = [];
  try {
    await downloadFile(`http://127.0.0.1:${port}/file.bin`, dest, (p) => seen.push(p));
    assert.equal(fs.readFileSync(dest).length, body.length);
    assert.equal(seen.at(-1), 100);
  } finally { srv.close(); }
});

test('redirects are followed', async () => {
  const { srv, port } = await serve((req, res) => {
    if (req.url === '/a') { res.writeHead(302, { Location: `http://127.0.0.1:${port}/b` }); return res.end(); }
    res.writeHead(200); res.end('ok');
  });
  const dest = tmpFile('r.txt');
  try {
    await downloadFile(`http://127.0.0.1:${port}/a`, dest);
    assert.equal(fs.readFileSync(dest, 'utf8'), 'ok');
  } finally { srv.close(); }
});

test('a redirect onto a non-loopback http:// URL is refused, not downloaded', async () => {
  // These downloads are EXECUTABLES (xray / sing-box / tun2socks). Plain http is
  // a local-test seam only; a redirect hop must not reopen it.
  const { srv, port } = await serve((req, res) => {
    res.writeHead(302, { Location: 'http://mirror.invalid/xray.zip' });
    res.end();
  });
  const dest = tmpFile('xray.zip');
  try {
    await assert.rejects(downloadFile(`http://127.0.0.1:${port}/xray.zip`, dest), /plain http/i);
    assert.equal(fs.existsSync(dest), false, 'nothing may be left on disk');
    // and the same rule applies to the URL we are handed in the first place
    await assert.rejects(downloadFile('http://mirror.invalid/xray.zip', dest), /plain http/i);
  } finally { srv.close(); }
});

const { Downloader } = require('../src/main/downloader');

test('each Xray engine downloads from its own GitHub repo', () => {
  assert.equal(Downloader.releaseApiUrl('xray'), 'https://api.github.com/repos/XTLS/Xray-core/releases/latest');
  assert.equal(Downloader.releaseApiUrl('xray-pattn'), 'https://api.github.com/repos/patterniha/Xray-core/releases/latest');
  assert.throws(() => Downloader.releaseApiUrl('sing-box'), /not an Xray-format engine/);
});
