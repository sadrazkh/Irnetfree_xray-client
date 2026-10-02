'use strict';
/**
 * The real server.js as a child on an ephemeral loopback port, in a temp data
 * dir, with no router env and nothing to connect — the harness
 * serverRequest.test.js grew, shared by the v1.16 test files. It binds nothing
 * else and is killed (SIGKILL: no shutdown path runs) when a test ends. Not a
 * test file itself.
 */
const { spawn } = require('node:child_process');
const net = require('node:net');
const http = require('node:http');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const SERVER = path.join(__dirname, '..', 'src', 'server', 'server.js');

function startServer(dir, extra = [], envExtra = {}) {
  return new Promise((resolve, reject) => {
    const env = Object.assign({}, process.env, envExtra);
    delete env.IRNETFREE_PLATFORM;
    // A Ctrl+C on `npm test` reaches this child too, and its shutdown turns the
    // system proxy off — on Windows a registry write on whoever ran the suite.
    env.IRNETFREE_NO_SYSTEM_PROXY = '1';
    const child = spawn(process.execPath, [SERVER, '--port', '0', '--host', '127.0.0.1', '--data-dir', dir, ...extra],
      { env, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    let out = '';
    let done = false;
    const exit = new Promise((r) => child.on('exit', (code, signal) => r({ code, signal })));
    const timer = setTimeout(() => { if (!done) { done = true; child.kill('SIGKILL'); reject(new Error('the server did not start:\n' + out)); } }, 30000);
    const onData = (d) => {
      out += d;
      // the whole banner: its last line on a loopback bind (it can arrive in several chunks)
      const m = /Listening: http:\/\/127\.0\.0\.1:(\d+)\/[\s\S]*in your browser\./.exec(out);
      if (m && !done) { done = true; clearTimeout(timer); resolve({ child, port: Number(m[1]), out: () => out, exit }); }
    };
    child.stdout.on('data', onData);
    child.stderr.on('data', onData);
    child.on('exit', (code) => {
      if (done) return;
      done = true; clearTimeout(timer);
      reject(new Error(`the server exited (${code}) before it listened:\n${out}`));
    });
  });
}

/** One raw request over TCP; resolves with whatever came back before the socket closed. */
function raw(port, text) {
  return new Promise((resolve) => {
    let buf = '';
    const s = net.connect({ host: '127.0.0.1', port }, () => s.write(text));
    s.setEncoding('utf8');
    s.on('data', (d) => { buf += d; });
    s.on('close', () => resolve(buf));
    s.on('error', () => { /* a reset reads as whatever arrived before it */ });
    s.setTimeout(10000, () => s.destroy());
  });
}

/** An HTTP request; resolves { status, headers, body, json } (json null when the body is not JSON). */
function request(port, { method = 'GET', path: p = '/', headers = {}, body = null } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method, path: p, headers }, (res) => {
      let data = '';
      res.setEncoding('utf8');
      res.on('data', (c) => { data += c; });
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(data); } catch { /* not JSON */ }
        resolve({ status: res.statusCode, headers: res.headers, body: data, json });
      });
    });
    req.on('error', reject);
    req.setTimeout(10000, () => { req.destroy(new Error('timeout')); });
    if (body != null) req.write(body);
    req.end();
  });
}

/** The first `n` SSE `data:` lines of GET `path` (the response is closed afterwards). */
function sseLines(port, p, n = 1, ms = 10000) {
  return new Promise((resolve, reject) => {
    const lines = [];
    const req = http.get({ host: '127.0.0.1', port, path: p }, (res) => {
      if (res.statusCode !== 200) { res.resume(); return reject(new Error('events: HTTP ' + res.statusCode)); }
      let buf = '';
      res.setEncoding('utf8');
      res.on('data', (c) => {
        buf += c;
        for (const line of buf.split('\n')) if (line.startsWith('data: ')) lines.push(line.slice(6));
        buf = buf.slice(buf.lastIndexOf('\n') + 1);
        if (lines.length >= n) { req.destroy(); resolve(lines.slice(0, n)); }
      });
    });
    req.on('error', (e) => { if (lines.length >= n) return; reject(e); });
    setTimeout(() => { req.destroy(); if (lines.length < n) reject(new Error(`only ${lines.length} events in ${ms} ms`)); }, ms).unref();
  });
}

function tempDir(store = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-server-'));
  // no subscription timer, no asset updater, no connect at start
  fs.writeFileSync(path.join(dir, 'store.json'), JSON.stringify(Object.assign({ settings: { autoUpdateSubs: false, autoUpdateAssets: 'off', autoConnect: false } }, store)));
  return dir;
}

function stop(srv, dir) {
  try { srv.child.kill('SIGKILL'); } catch {}
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
}

module.exports = { SERVER, startServer, raw, request, sseLines, tempDir, stop };
