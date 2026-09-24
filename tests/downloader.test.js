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

// ENOSPC / EIO / EACCES on the destination: the write stream had no 'error'
// listener, so the failure was an uncaught exception — the whole process gone,
// and on a router that is the gateway. An unopenable destination takes the
// same path as a full disk, and is one that can be made on any OS.
test('a destination that cannot be written rejects cleanly instead of throwing out of the process', async () => {
  const { srv, port } = await serve((req, res) => { res.writeHead(200, { 'Content-Length': 5 }); res.end('hello'); });
  const dest = path.join(path.dirname(tmpFile('x')), 'no-such-dir', 'sub', 'file.bin');
  try {
    await assert.rejects(downloadFile(`http://127.0.0.1:${port}/file.bin`, dest), /ENOENT|no such file/i);
    assert.equal(fs.existsSync(dest), false);
  } finally { srv.close(); }
});

test('a response cut off mid-body rejects and leaves no partial file', async () => {
  const { srv, port } = await serve((req, res) => {
    res.writeHead(200, { 'Content-Length': 100000 });
    res.write(Buffer.alloc(1000, 1));
    setTimeout(() => res.socket.destroy(), 50);
  });
  const dest = tmpFile('cut.bin');
  try {
    await assert.rejects(downloadFile(`http://127.0.0.1:${port}/cut.bin`, dest));
    assert.equal(fs.existsSync(dest), false, 'a truncated core or geo file must never be left to be put in place');
  } finally { srv.close(); }
});

const { Downloader } = require('../src/main/downloader');

test('place() never truncates the working file: the copy goes to .new and is renamed over it', () => {
  const destDir = path.dirname(tmpFile('x'));
  const src = path.join(destDir, 'download', 'xray');
  fs.mkdirSync(path.dirname(src), { recursive: true });
  fs.writeFileSync(src, 'NEW CORE');
  fs.writeFileSync(path.join(destDir, 'xray'), 'WORKING CORE');

  // a copy that dies half way (ENOSPC): the core in place must be untouched
  const failing = new Downloader({ destDir, copyFile: (from, to) => { fs.writeFileSync(to, 'NEW'); throw Object.assign(new Error('ENOSPC: no space left on device'), { code: 'ENOSPC' }); } });
  assert.throws(() => failing.place(src, 'xray', true), /ENOSPC/);
  assert.equal(fs.readFileSync(path.join(destDir, 'xray'), 'utf8'), 'WORKING CORE');
  assert.equal(fs.existsSync(path.join(destDir, 'xray.new')), false, 'the half copy is removed');

  // a good copy replaces it whole (`exec` only on Linux: on a Mac it would
  // codesign this text file, which is not what is being tested)
  const ok = new Downloader({ destDir });
  const exec = process.platform === 'linux';
  assert.equal(ok.place(src, 'xray', exec), path.join(destDir, 'xray'));
  assert.equal(fs.readFileSync(path.join(destDir, 'xray'), 'utf8'), 'NEW CORE');
  assert.equal(fs.existsSync(path.join(destDir, 'xray.new')), false);
  if (exec) assert.equal(fs.statSync(path.join(destDir, 'xray')).mode & 0o111, 0o111, 'still executable');
});

test('each Xray engine downloads from its own GitHub repo', () => {
  assert.equal(Downloader.releaseApiUrl('xray'), 'https://api.github.com/repos/XTLS/Xray-core/releases/latest');
  assert.equal(Downloader.releaseApiUrl('xray-pattn'), 'https://api.github.com/repos/patterniha/Xray-core/releases/latest');
  assert.throws(() => Downloader.releaseApiUrl('sing-box'), /not an Xray-format engine/);
});
