'use strict';
/**
 * A small WebSocket (RFC 6455) client and server — the subset the relay link
 * needs, shared by both ends: the router's agent (src/server/remote/agent.js,
 * node 18 on OpenWrt 23.05 — no global WebSocket there) and the relay app
 * (relay/, node 22) — with no npm package, because the ipk ships no
 * node_modules and the relay is zero-dependency on purpose.
 *
 * What is in: text and binary messages, the client masking every frame it
 * sends (and refusing masked frames from a server, as a server refuses
 * unmasked ones from a client), fragmented messages on the way in, ping/pong,
 * the close handshake, a payload cap (1009), and backpressure through
 * `bufferedAmount` + 'drain'. What is not: extensions (permessage-deflate is
 * negotiated away by never offering it), subprotocols, UTF-8 validation of
 * text frames, fragmented frames on the way out (a message is one frame).
 *
 *   wsConnect(url, { headers, agent, socket, servername, maxPayload, timeoutMs }) → Promise<WsConn>
 *   wsAccept(req, socket, head, { maxPayload }) → WsConn       (inside http.Server's 'upgrade')
 *
 * `socket`: an already-connected socket to speak over, TLS done by the caller —
 * the agent dials a pinned IP with its own servername, or goes through the
 * local SOCKS inbound, and hands the result here.
 */
const crypto = require('crypto');
const http = require('http');
const https = require('https');
const { EventEmitter } = require('events');

const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const OP = { CONT: 0, TEXT: 1, BINARY: 2, CLOSE: 8, PING: 9, PONG: 10 };
const DEFAULT_MAX_PAYLOAD = 4 << 20;
const CLOSE_GRACE_MS = 5000;

const acceptKey = (key) => crypto.createHash('sha1').update(key + GUID).digest('base64');

/**
 * One frame. `mask`: a client masks every frame it sends (RFC 6455 §5.3), a
 * server never does. Exported for the tests, which write fragments by hand.
 */
function encodeFrame(op, payload, { fin = true, mask = false } = {}) {
  const data = Buffer.isBuffer(payload) ? payload : Buffer.from(payload == null ? '' : String(payload), 'utf8');
  const len = data.length;
  const extra = len < 126 ? 0 : len < 65536 ? 2 : 8;
  const head = Buffer.alloc(2 + extra + (mask ? 4 : 0));
  head[0] = (fin ? 0x80 : 0) | (op & 0x0f);
  head[1] = (mask ? 0x80 : 0) | (extra === 0 ? len : extra === 2 ? 126 : 127);
  if (extra === 2) head.writeUInt16BE(len, 2);
  else if (extra === 8) { head.writeUInt32BE(Math.floor(len / 0x100000000), 2); head.writeUInt32BE(len >>> 0, 6); }
  if (!mask) return Buffer.concat([head, data]);
  const key = crypto.randomBytes(4);
  key.copy(head, 2 + extra);
  const masked = Buffer.allocUnsafe(len);
  for (let i = 0; i < len; i++) masked[i] = data[i] ^ key[i & 3];
  return Buffer.concat([head, masked]);
}

class WsConn extends EventEmitter {
  /**
   * @param {import('net').Socket} socket  the upgraded socket
   * @param {{ isClient: boolean, maxPayload?: number, head?: Buffer }} opts
   */
  constructor(socket, { isClient, maxPayload = DEFAULT_MAX_PAYLOAD, head } = {}) {
    super();
    this.socket = socket;
    this.isClient = !!isClient;
    this.maxPayload = maxPayload;
    /** 'open' | 'closing' | 'closed' */
    this.readyState = 'open';
    this._buf = head && head.length ? Buffer.from(head) : Buffer.alloc(0);
    this._frags = null;      // the fragments of a message in progress
    this._fragOp = 0;
    this._fragLen = 0;
    this._closeSent = false;
    this._closeCode = null;  // whoever started the close sets it first
    this._closeReason = '';
    this._closeTimer = null;
    this._ended = false;
    socket.on('data', (chunk) => this._feed(chunk));
    socket.on('drain', () => this.emit('drain'));
    // an error ends the socket (close follows); only told to someone listening,
    // since an unheard 'error' would end the process instead
    socket.on('error', (e) => { if (this.listenerCount('error')) this.emit('error', e); });
    socket.on('end', () => { if (!this._ended) { this._ended = true; try { socket.end(); } catch { /* gone */ } } });
    socket.on('close', () => this._finish(this._closeCode == null ? 1006 : this._closeCode, this._closeReason));
    // bytes that came with the upgrade are parsed once the caller has attached
    // its listeners — a 'data' chunk arriving before that lands behind them in
    // _buf, so the order is kept either way
    if (this._buf.length) setImmediate(() => { if (this.readyState !== 'closed') this._feed(Buffer.alloc(0)); });
  }

  /** Bytes the socket still holds for the peer — pause the source while this is high. */
  get bufferedAmount() { return this.socket.writableLength || 0; }

  /** A string goes as a text frame, a Buffer as binary. False once the link is closing, or when the socket wants a drain. */
  send(data) {
    if (this.readyState !== 'open') return false;
    return this._write(encodeFrame(typeof data === 'string' ? OP.TEXT : OP.BINARY, data, { mask: this.isClient }));
  }

  ping(payload) {
    if (this.readyState !== 'open') return false;
    return this._write(encodeFrame(OP.PING, payload || Buffer.alloc(0), { mask: this.isClient }));
  }

  /** Start the close handshake; 'close' fires when the socket is gone (the peer echoes, or the grace period ends). */
  close(code = 1000, reason = '') {
    if (this.readyState !== 'open') return;
    this.readyState = 'closing';
    if (this._closeCode == null) { this._closeCode = code; this._closeReason = reason; }
    this._sendClose(code, reason);
    this._closeTimer = setTimeout(() => { try { this.socket.destroy(); } catch { /* gone */ } }, CLOSE_GRACE_MS);
    if (this._closeTimer.unref) this._closeTimer.unref();
  }

  _write(buf) {
    if (this.socket.destroyed || this.readyState === 'closed') return false;
    try { return this.socket.write(buf); } catch { return false; }
  }

  _sendClose(code, reason) {
    if (this._closeSent) return;
    this._closeSent = true;
    const r = Buffer.from(reason || '', 'utf8').subarray(0, 123);
    const p = Buffer.alloc(2 + r.length);
    p.writeUInt16BE(code, 0);
    r.copy(p, 2);
    this._write(encodeFrame(OP.CLOSE, p, { mask: this.isClient }));
  }

  /** A protocol violation or an oversized payload: close with the code and let the peer go. */
  _fail(code, reason) {
    if (this.readyState === 'open') { this.close(code, reason); return; }
    if (this._closeCode == null) { this._closeCode = code; this._closeReason = reason; }
  }

  _finish(code, reason) {
    if (this.readyState === 'closed') return;
    this.readyState = 'closed';
    if (this._closeTimer) { clearTimeout(this._closeTimer); this._closeTimer = null; }
    this._buf = Buffer.alloc(0);
    this._frags = null;
    this.emit('close', code, reason || '');
  }

  _feed(chunk) {
    if (this.readyState === 'closed') return;
    this._buf = this._buf.length ? Buffer.concat([this._buf, chunk]) : chunk;
    for (;;) {
      if (this.readyState === 'closed') return;
      const b = this._buf;
      if (b.length < 2) return;
      const fin = (b[0] & 0x80) !== 0;
      const rsv = b[0] & 0x70;
      const op = b[0] & 0x0f;
      const masked = (b[1] & 0x80) !== 0;
      let len = b[1] & 0x7f;
      let off = 2;
      if (len === 126) {
        if (b.length < 4) return;
        len = b.readUInt16BE(2); off = 4;
      } else if (len === 127) {
        if (b.length < 10) return;
        const hi = b.readUInt32BE(2);
        const lo = b.readUInt32BE(6);
        if (hi > 0x1fffff) return this._fail(1009, 'payload too large');
        len = hi * 0x100000000 + lo; off = 10;
      }
      if (rsv) return this._fail(1002, 'reserved bits set');
      // a client receives unmasked frames only, a server masked ones only
      if (masked === this.isClient) return this._fail(1002, this.isClient ? 'masked frame from the server' : 'unmasked frame from the client');
      if (op >= 8 && (!fin || len > 125)) return this._fail(1002, 'bad control frame');
      if (op < 8 && (len > this.maxPayload || (this._frags && this._fragLen + len > this.maxPayload))) return this._fail(1009, 'payload too large');
      const dataOff = off + (masked ? 4 : 0);
      const total = dataOff + len;
      if (b.length < total) return;
      let payload;
      if (masked) {
        const key = b.subarray(off, off + 4);
        payload = Buffer.allocUnsafe(len);
        for (let i = 0; i < len; i++) payload[i] = b[dataOff + i] ^ key[i & 3];
      } else {
        payload = Buffer.from(b.subarray(dataOff, total));   // its own bytes: _buf is replaced below
      }
      this._buf = total === b.length ? Buffer.alloc(0) : b.subarray(total);
      this._frame(fin, op, payload);
    }
  }

  _frame(fin, op, payload) {
    switch (op) {
      case OP.CONT: {
        if (!this._frags) return this._fail(1002, 'continuation without a start');
        this._frags.push(payload);
        this._fragLen += payload.length;
        if (!fin) return;
        const msg = Buffer.concat(this._frags);
        const isBinary = this._fragOp === OP.BINARY;
        this._frags = null; this._fragLen = 0;
        this.emit('message', msg, isBinary);
        return;
      }
      case OP.TEXT:
      case OP.BINARY:
        if (this._frags) return this._fail(1002, 'a new message inside a fragmented one');
        if (fin) { this.emit('message', payload, op === OP.BINARY); return; }
        this._frags = [payload]; this._fragOp = op; this._fragLen = payload.length;
        return;
      case OP.CLOSE: {
        let code = 1005;
        let reason = '';
        if (payload.length >= 2) { code = payload.readUInt16BE(0); reason = payload.subarray(2).toString('utf8'); }
        else if (payload.length === 1) code = 1002;
        if (this._closeCode == null) { this._closeCode = code; this._closeReason = reason; }
        this.readyState = 'closing';
        this._sendClose(code === 1005 ? 1000 : code, '');     // the echo (a no-op when we started the close)
        this._ended = true;
        try { this.socket.end(); } catch { /* gone */ }
        return;
      }
      case OP.PING:
        if (this.readyState === 'open') this._write(encodeFrame(OP.PONG, payload, { mask: this.isClient }));
        this.emit('ping', payload);
        return;
      case OP.PONG:
        this.emit('pong', payload);
        return;
      default:
        return this._fail(1002, 'unknown opcode ' + op);
    }
  }
}

/**
 * Dial `url` (ws:// or wss://) and complete the handshake. Rejects with
 * `status` set when the server answered with plain HTTP (a 401 for a bad
 * token), without it for a network error, a timeout or a wrong accept key.
 */
function wsConnect(url, opts = {}) {
  const { headers = {}, agent, socket, maxPayload = DEFAULT_MAX_PAYLOAD, timeoutMs = 15000 } = opts;
  return new Promise((resolve, reject) => {
    let u;
    try { u = new URL(String(url)); } catch { return reject(new Error('bad websocket url')); }
    const secure = u.protocol === 'wss:';
    if (!secure && u.protocol !== 'ws:') return reject(new Error('the url must be ws:// or wss://'));
    const port = Number(u.port) || (secure ? 443 : 80);
    const key = crypto.randomBytes(16).toString('base64');
    const reqOpts = {
      method: 'GET',
      host: u.hostname,
      port,
      path: u.pathname + u.search,
      headers: Object.assign({
        Host: u.host, Upgrade: 'websocket', Connection: 'Upgrade',
        'Sec-WebSocket-Key': key, 'Sec-WebSocket-Version': '13'
      }, headers)
    };
    let mod = secure ? https : http;
    if (socket) {
      // the caller's socket, as it is (TLS included, when any): no agent, so
      // http uses createConnection — with `agent: false` it would not
      mod = http;
      reqOpts.createConnection = () => socket;
    } else {
      reqOpts.agent = agent === undefined ? false : agent;
      if (secure) reqOpts.servername = opts.servername || u.hostname;
    }
    let settled = false;
    let timer = null;
    const fail = (e) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { req.destroy(); } catch { /* gone */ }
      reject(e);
    };
    const req = mod.request(reqOpts);
    timer = setTimeout(() => fail(new Error('websocket handshake timeout')), timeoutMs);
    req.on('upgrade', (res, sock, head) => {
      if (settled) { sock.destroy(); return; }
      settled = true;
      clearTimeout(timer);
      const accept = String(res.headers['sec-websocket-accept'] || '');
      if (res.statusCode !== 101 || accept !== acceptKey(key)) {
        sock.destroy();
        return reject(Object.assign(new Error('bad websocket handshake answer'), { status: res.statusCode }));
      }
      sock.setTimeout(0);
      if (sock.setNoDelay) sock.setNoDelay(true);
      resolve(new WsConn(sock, { isClient: true, maxPayload, head }));
    });
    req.on('response', (res) => {
      res.resume();
      fail(Object.assign(new Error('unexpected answer ' + res.statusCode + ' to the websocket handshake'), { status: res.statusCode }));
    });
    req.on('error', fail);
    req.end();
  });
}

/**
 * Server side, inside http.Server's 'upgrade' handler. Answers 101 and returns
 * the connection; a request that is not a WebSocket handshake gets a 400, the
 * socket is destroyed, and this throws.
 */
function wsAccept(req, socket, head, { maxPayload = DEFAULT_MAX_PAYLOAD } = {}) {
  const key = String(req.headers['sec-websocket-key'] || '');
  const upgrade = String(req.headers.upgrade || '').toLowerCase();
  const version = String(req.headers['sec-websocket-version'] || '');
  const keyOk = key && /^[A-Za-z0-9+/]{22}==$/.test(key);
  if (upgrade !== 'websocket' || version !== '13' || !keyOk) {
    try { socket.write('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n'); } catch { /* gone */ }
    socket.destroy();
    throw new Error('not a websocket handshake');
  }
  socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + acceptKey(key) + '\r\n\r\n');
  socket.setTimeout(0);
  if (socket.setNoDelay) socket.setNoDelay(true);
  return new WsConn(socket, { isClient: false, maxPayload, head });
}

module.exports = { wsConnect, wsAccept, WsConn, encodeFrame, OP, DEFAULT_MAX_PAYLOAD };
