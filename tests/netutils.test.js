'use strict';
/**
 * SOCKS5 client handshake tests.
 *
 * `socks5Connect` dials our own local xray inbound for the latency tests and the
 * egress-IP check. TCP gives no message framing, so a reply may arrive in two
 * segments, or with the first bytes of the tunnelled stream glued on. Both cases
 * used to be misread as a broken proxy, which painted a healthy config with a
 * red x on its ping badge. These tests pin down the framing.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');

const { socks5Connect } = require('../src/main/netutils');

/** A SOCKS5 server that writes its replies in deliberately awkward pieces. */
function fakeSocks(onConnected) {
  return new Promise((resolve) => {
    const srv = net.createServer((sock) => {
      sock.on('error', () => {});               // a peer reset must fail a test, not kill the runner
      let stage = 0;
      sock.on('data', (d) => {
        if (stage === 0) {                       // greeting -> reply byte by byte
          stage = 1;
          sock.write(Buffer.from([0x05]));
          setTimeout(() => sock.write(Buffer.from([0x00])), 10);
        } else if (stage === 1) {                // CONNECT -> reply split, then payload glued on
          stage = 2;
          sock.write(Buffer.from([0x05, 0x00, 0x00, 0x01]));
          setTimeout(() => sock.write(Buffer.concat([Buffer.from([1, 2, 3, 4, 0, 80]), Buffer.from('HELLO')])), 10);
          onConnected && onConnected(sock);
        }
      });
    });
    srv.listen(0, '127.0.0.1', () => resolve({ srv, port: srv.address().port }));
  });
}

/**
 * A SOCKS5 server that accepts, waves the greeting through, then writes the
 * CONNECT reply as the given segments — one per tick — so the client has to
 * reassemble it across several TCP reads. The last segment normally carries the
 * first bytes of the tunnelled stream glued on.
 */
function fakeSocksSegments(segments) {
  return new Promise((resolve) => {
    const srv = net.createServer((sock) => {
      sock.on('error', () => {});
      let stage = 0;
      sock.on('data', () => {
        if (stage === 0) { stage = 1; sock.write(Buffer.from([0x05, 0x00])); return; }
        if (stage === 1) {
          stage = 2;
          segments.forEach((seg, i) => setTimeout(() => sock.write(seg), (i + 1) * 10));
        }
      });
    });
    srv.listen(0, '127.0.0.1', () => resolve({ srv, port: srv.address().port }));
  });
}

/** First chunk the caller sees, or a clean failure — never an endless wait. */
function firstChunk(socket, ms = 2000) {
  return new Promise((resolve, reject) => {
    const to = setTimeout(() => reject(new Error(`no tunnelled data within ${ms}ms`)), ms);
    socket.once('data', (d) => { clearTimeout(to); resolve(d.toString()); });
  });
}

/** Settle the way `p` settles, or fail loudly — a hang must not stall the runner. */
function within(p, ms, what) {
  let to;
  const bound = new Promise((_, reject) => {
    to = setTimeout(() => reject(new Error(`${what} never settled within ${ms}ms`)), ms);
  });
  return Promise.race([p, bound]).finally(() => clearTimeout(to));
}

test('handshake completes when replies arrive in pieces and keeps the leftover payload', async () => {
  const { srv, port } = await fakeSocks();
  let socket;
  try {
    socket = await socks5Connect('127.0.0.1', port, 'example.com', 80, 2000);
    const first = await firstChunk(socket);
    assert.equal(first, 'HELLO', 'bytes after the reply belong to the tunnelled stream');
  } finally {
    if (socket) socket.destroy();
    srv.close();
  }
});

test('a domain (ATYP=3) reply split across segments completes and keeps the payload', async () => {
  const name = Buffer.from('proxy.local', 'utf8');       // 11 bytes -> reply is 5 + 11 + 2
  const { srv, port } = await fakeSocksSegments([
    Buffer.from([0x05, 0x00, 0x00, 0x03]),               // VER REP RSV ATYP
    Buffer.from([name.length]),                          // the length byte on its own
    Buffer.concat([name, Buffer.from([0, 80]), Buffer.from('DOMAIN-OK')])
  ]);
  let socket;
  try {
    socket = await socks5Connect('127.0.0.1', port, 'example.com', 80, 2000);
    assert.equal(await firstChunk(socket), 'DOMAIN-OK', 'the whole BND.ADDR must be consumed, no more, no less');
  } finally {
    if (socket) socket.destroy();
    srv.close();
  }
});

test('an IPv6 (ATYP=4) reply split across segments completes and keeps the payload', async () => {
  const addr = Buffer.alloc(16, 0x11);                   // 16-byte BND.ADDR -> reply is 22 bytes
  const { srv, port } = await fakeSocksSegments([
    Buffer.from([0x05, 0x00, 0x00, 0x04]),
    addr.subarray(0, 10),
    Buffer.concat([addr.subarray(10), Buffer.from([0, 80]), Buffer.from('V6-OK')])
  ]);
  let socket;
  try {
    socket = await socks5Connect('127.0.0.1', port, 'example.com', 80, 2000);
    assert.equal(await firstChunk(socket), 'V6-OK', 'the whole BND.ADDR must be consumed, no more, no less');
  } finally {
    if (socket) socket.destroy();
    srv.close();
  }
});

/**
 * A peer that hangs up mid-handshake used to leave the promise unsettled forever:
 * allowHalfOpen is false, so Node auto-destroys on FIN, and _destroy() clears the
 * socket timeout — so 'timeout' never fires either. ping:real / ping:upload /
 * ip:check then spun their UI badge for good instead of reporting a failure.
 */
test('a hang-up mid-handshake rejects instead of leaving the promise unsettled', async () => {
  const srv = net.createServer((sock) => {
    sock.on('error', () => {});
    sock.on('data', () => sock.end());                   // read the greeting, then FIN
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  try {
    // A generous handshake timeout: the rejection has to come from the close, not from it.
    const connect = socks5Connect('127.0.0.1', srv.address().port, 'example.com', 80, 30000);
    await assert.rejects(within(connect, 1500, 'socks5Connect'), /socks connection closed/);
  } finally { srv.close(); }
});

test('a failed CONNECT reply rejects with its code', async () => {
  const srv = net.createServer((sock) => {
    sock.on('error', () => {});
    let n = 0;
    sock.on('data', () => { n++; sock.write(n === 1 ? Buffer.from([0x05, 0x00]) : Buffer.from([0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  try {
    await assert.rejects(socks5Connect('127.0.0.1', srv.address().port, 'example.com', 80, 2000), /socks connect failed code 5/);
  } finally { srv.close(); }
});
