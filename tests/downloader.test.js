'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { downloadFile } = require('../src/main/downloader');

function serve(handler) {
  return new Promise((resolve) => {
    const srv = http.createServer(handler);
    srv.listen(0, '127.0.0.1', () => resolve({ srv, port: srv.address().port }));
  });
}

test('a non-200 response rejects and leaves no temp file behind', async () => {
  const { srv, port } = await serve((req, res) => { res.writeHead(403); res.end('rate limited'); });
  const dest = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-dl-')), 'geoip.dat.tmp');
  try {
    await assert.rejects(downloadFile(`http://127.0.0.1:${port}/geoip.dat`, dest), /HTTP 403/);
    assert.equal(fs.existsSync(dest), false, 'temp file must be removed');
  } finally { srv.close(); }
});

test('a 200 response is written in full and reports progress', async () => {
  const body = Buffer.alloc(100000, 7);
  const { srv, port } = await serve((req, res) => { res.writeHead(200, { 'Content-Length': body.length }); res.end(body); });
  const dest = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-dl-')), 'file.bin');
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
  const dest = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-dl-')), 'r.txt');
  try {
    await downloadFile(`http://127.0.0.1:${port}/a`, dest);
    assert.equal(fs.readFileSync(dest, 'utf8'), 'ok');
  } finally { srv.close(); }
});
