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

/** First chunk the caller sees, or a clean failure — never an endless wait. */
function firstChunk(socket, ms = 2000) {
  return new Promise((resolve, reject) => {
    const to = setTimeout(() => reject(new Error(`no tunnelled data within ${ms}ms`)), ms);
    socket.once('data', (d) => { clearTimeout(to); resolve(d.toString()); });
  });
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

test('a failed CONNECT reply rejects with its code', async () => {
  const srv = net.createServer((sock) => {
    let n = 0;
    sock.on('data', () => { n++; sock.write(n === 1 ? Buffer.from([0x05, 0x00]) : Buffer.from([0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  try {
    await assert.rejects(socks5Connect('127.0.0.1', srv.address().port, 'example.com', 80, 2000), /socks connect failed code 5/);
  } finally { srv.close(); }
});
