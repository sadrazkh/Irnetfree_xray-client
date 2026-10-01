'use strict';
/**
 * The WebSocket subset both ends of the relay link run on (src/server/remote/ws.js):
 * a server made of http.createServer + wsAccept, a client made with wsConnect,
 * both on loopback. No `ws` package: the router runs node 18 with no global
 * WebSocket, and the ipk ships no node_modules.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const crypto = require('node:crypto');
const { wsConnect, wsAccept, encodeFrame, OP } = require('../src/server/remote/ws');

const listen = (server) => new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
const once = (em, ev) => new Promise((resolve) => em.once(ev, (...a) => resolve(a)));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** A loopback server + one client connected to it; the server side's WsConn is handed back too. */
async function pair(t, { serverOpts = {}, clientOpts = {} } = {}) {
  const srv = http.createServer((req, res) => { res.writeHead(404); res.end(); });
  let settle;
  const serverConn = new Promise((resolve) => { settle = resolve; });
  srv.on('upgrade', (req, socket, head) => {
    try { settle(wsAccept(req, socket, head, serverOpts)); } catch (e) { settle(Promise.reject(e)); }
  });
  const port = await listen(srv);
  t.after(() => srv.close());
  const client = await wsConnect(`ws://127.0.0.1:${port}/link`, clientOpts);
  const server = await serverConn;
  t.after(() => { try { client.socket.destroy(); } catch {} try { server.socket.destroy(); } catch {} });
  return { client, server, port };
}

test('text and binary messages round trip in both directions', async (t) => {
  const { client, server } = await pair(t);
  const gotServer = once(server, 'message');
  client.send('سلام relay');
  const [m1, bin1] = await gotServer;
  assert.equal(bin1, false);
  assert.equal(m1.toString('utf8'), 'سلام relay');

  const gotClient = once(client, 'message');
  server.send(Buffer.from([0, 1, 2, 250, 251]));
  const [m2, bin2] = await gotClient;
  assert.equal(bin2, true);
  assert.deepEqual([...m2], [0, 1, 2, 250, 251]);

  const back = once(server, 'message');
  client.send(Buffer.from('bytes'));
  const [m3, bin3] = await back;
  assert.equal(bin3, true);
  assert.equal(m3.toString(), 'bytes');
});

test('a 1 MB binary message arrives whole, in both directions', async (t) => {
  const { client, server } = await pair(t);
  const big = crypto.randomBytes(1 << 20);
  const p1 = once(server, 'message');
  client.send(big);
  const [m1] = await p1;
  assert.equal(m1.length, big.length);
  assert.ok(m1.equals(big));
  const p2 = once(client, 'message');
  server.send(big);
  const [m2] = await p2;
  assert.ok(m2.equals(big));
});

test('the client masks every frame it sends, the server masks none (RFC 6455 §5.1)', async (t) => {
  const { client, server } = await pair(t);
  const sent = { client: [], server: [] };
  for (const [name, conn] of [['client', client], ['server', server]]) {
    const w = conn.socket.write.bind(conn.socket);
    conn.socket.write = (chunk, ...rest) => { sent[name].push(Buffer.from(chunk)); return w(chunk, ...rest); };
  }
  const p1 = once(server, 'message');
  client.send('masked?');
  await p1;
  const p2 = once(client, 'message');
  server.send('masked?');
  await p2;
  assert.equal(sent.client.length, 1);
  assert.equal(sent.client[0][1] & 0x80, 0x80, 'the client frame carries the MASK bit');
  assert.equal(sent.client[0][0], 0x81, 'FIN + text');
  assert.equal(sent.server.length, 1);
  assert.equal(sent.server[0][1] & 0x80, 0, 'the server frame carries no MASK bit');
  // and the masked bytes on the wire are not the text itself
  assert.ok(!sent.client[0].includes('masked?'), 'the payload is not in clear on the client side');
  assert.ok(sent.server[0].includes('masked?'), 'the server payload is in clear');
});

test('a fragmented message (FIN=0, then a continuation) arrives as one message', async (t) => {
  const { client, server } = await pair(t);
  const got = once(server, 'message');
  // written by hand on the raw socket: a text frame with FIN=0 and a continuation with FIN=1, both masked (client side)
  client.socket.write(encodeFrame(OP.TEXT, 'first half, ', { fin: false, mask: true }));
  await sleep(20);
  client.socket.write(encodeFrame(OP.CONT, 'second half', { fin: true, mask: true }));
  const [m, bin] = await got;
  assert.equal(bin, false);
  assert.equal(m.toString(), 'first half, second half');
  // the link still works after it
  const next = once(server, 'message');
  client.send('after');
  assert.equal((await next)[0].toString(), 'after');
});

test('a ping is answered by a pong within a second, from either side', async (t) => {
  const { client, server } = await pair(t);
  const pong = once(client, 'pong');
  client.ping(Buffer.from('p1'));
  const [[payload]] = await Promise.all([pong, sleep(0)]);
  assert.equal(payload.toString(), 'p1');
  const pong2 = Promise.race([once(server, 'pong'), sleep(1000).then(() => { throw new Error('no pong within 1 s'); })]);
  server.ping();
  await pong2;
});

test('a payload over the cap closes the link with 1009 on both ends', async (t) => {
  const { client, server } = await pair(t, { serverOpts: { maxPayload: 1024 } });
  const closes = Promise.all([once(client, 'close'), once(server, 'close')]);
  client.send(crypto.randomBytes(2000));
  const [[cCode], [sCode]] = await closes;
  assert.equal(sCode, 1009);
  assert.equal(cCode, 1009);
  assert.equal(client.readyState, 'closed');
  assert.equal(server.readyState, 'closed');
});

test('a fragmented message whose total passes the cap is refused too', async (t) => {
  const { client, server } = await pair(t, { serverOpts: { maxPayload: 1024 } });
  const closed = once(server, 'close');
  client.socket.write(encodeFrame(OP.BINARY, crypto.randomBytes(800), { fin: false, mask: true }));
  client.socket.write(encodeFrame(OP.CONT, crypto.randomBytes(800), { fin: true, mask: true }));
  const [code] = await closed;
  assert.equal(code, 1009);
});

test('a server whose Sec-WebSocket-Accept is wrong makes wsConnect reject', async (t) => {
  const srv = http.createServer();
  srv.on('upgrade', (req, socket) => {
    socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: bm90IHRoZSByaWdodCBhbnN3ZXI=\r\n\r\n');
  });
  const port = await listen(srv);
  t.after(() => srv.close());
  await assert.rejects(wsConnect(`ws://127.0.0.1:${port}/`), /handshake/);
});

test('a plain HTTP answer (401) rejects with that status, so the agent can tell a revoked token', async (t) => {
  const srv = http.createServer((req, res) => { res.writeHead(401); res.end('no'); });
  const port = await listen(srv);
  t.after(() => srv.close());
  await assert.rejects(wsConnect(`ws://127.0.0.1:${port}/`), (e) => e.status === 401);
});

test('wsAccept refuses a request that is not a websocket handshake with a 400', async (t) => {
  const srv = http.createServer();
  let threw = null;
  srv.on('upgrade', (req, socket, head) => { try { wsAccept(req, socket, head); } catch (e) { threw = e; } });
  const port = await listen(srv);
  t.after(() => srv.close());
  await assert.rejects(wsConnect(`ws://127.0.0.1:${port}/`, { headers: { 'Sec-WebSocket-Version': '8' } }));
  assert.ok(threw && /handshake/.test(threw.message));
});

test('close(1000) ends the link with a close event on both ends, and nothing can be sent after', async (t) => {
  const { client, server } = await pair(t);
  const closes = Promise.all([once(client, 'close'), once(server, 'close')]);
  client.close(1000, 'bye');
  const [[cCode, cReason], [sCode, sReason]] = await closes;
  assert.equal(sCode, 1000);
  assert.equal(sReason, 'bye');
  assert.equal(cCode, 1000);
  assert.equal(typeof cReason, 'string');
  assert.equal(client.send('late'), false);
  assert.equal(server.send('late'), false);
});

test('a socket that dies without a close frame reports 1006', async (t) => {
  const { client, server } = await pair(t);
  const closed = once(server, 'close');
  client.socket.destroy();
  const [code] = await closed;
  assert.equal(code, 1006);
});

test('the request headers given to wsConnect reach the server (the Bearer token travels there)', async (t) => {
  const srv = http.createServer();
  let seen = null;
  srv.on('upgrade', (req, socket, head) => { seen = req.headers; wsAccept(req, socket, head); });
  const port = await listen(srv);
  t.after(() => srv.close());
  const c = await wsConnect(`ws://127.0.0.1:${port}/_relay/agent`, { headers: { Authorization: 'Bearer abc' } });
  t.after(() => c.socket.destroy());
  assert.equal(seen.authorization, 'Bearer abc');
  assert.equal(seen.host, `127.0.0.1:${port}`);
});

test('an already-connected socket is used as it is (the agent dials through SOCKS or to a pinned IP itself)', async (t) => {
  const net = require('node:net');
  const srv = http.createServer();
  let seenHost = null;
  srv.on('upgrade', (req, socket, head) => { seenHost = req.headers.host; const c = wsAccept(req, socket, head); c.on('message', (m) => c.send(m)); });
  const port = await listen(srv);
  t.after(() => srv.close());
  const sock = await new Promise((resolve, reject) => { const s = net.connect(port, '127.0.0.1', () => resolve(s)); s.on('error', reject); });
  // a wss:// url and a plain socket: the caller did (or faked) the TLS layer
  const c = await wsConnect('wss://relay.example/_relay/agent', { socket: sock });
  t.after(() => c.socket.destroy());
  assert.equal(seenHost, 'relay.example');
  const echo = once(c, 'message');
  c.send('through');
  assert.equal((await echo)[0].toString(), 'through');
});

test('bufferedAmount reflects what the socket still holds, and drain is re-emitted', async (t) => {
  const { client, server } = await pair(t);
  assert.equal(client.bufferedAmount, 0);
  let drained = false;
  client.on('drain', () => { drained = true; });
  server.socket.pause();
  const big = crypto.randomBytes(2 << 20);
  for (let i = 0; i < 4; i++) client.send(big);
  assert.ok(client.bufferedAmount > 0, 'bytes wait in the socket while the peer does not read');
  server.socket.resume();
  await sleep(300);
  assert.ok(drained, 'drain fired once the peer read');
});
