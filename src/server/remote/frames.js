'use strict';
/**
 * The relay link's frame format — one binary WebSocket message each:
 *
 *   [type u8][stream u32 big-endian][payload …]
 *
 * HELLO (JSON: name, version, path) opens the link; a browser request is one
 * stream: REQ_HEAD (JSON: method, path, headers) → REQ_BODY* → REQ_END, answered
 * by RES_HEAD (JSON: status, headers) → RES_BODY* → RES_END; CANCEL ends a
 * stream early from either side. The relay and the router's agent both encode
 * and decode with this one module (the relay's Dockerfile copies it).
 */
const T = Object.freeze({ HELLO: 1, REQ_HEAD: 2, REQ_BODY: 3, REQ_END: 4, RES_HEAD: 5, RES_BODY: 6, RES_END: 7, CANCEL: 8 });
const TYPE_NAMES = Object.freeze(Object.fromEntries(Object.entries(T).map(([k, v]) => [v, k])));
const HEADER = 5;
const MAX_STREAM = 0xffffffff;

/**
 * @param {number} type     one of T
 * @param {number} stream   0 … 2^32-1 (0 for the link itself: HELLO)
 * @param {Buffer|string|object} [payload]   a Buffer as it is, a string as UTF-8, anything else as JSON
 */
function encode(type, stream, payload) {
  if (!TYPE_NAMES[type]) throw new Error('frames: unknown type ' + type);
  if (!Number.isInteger(stream) || stream < 0 || stream > MAX_STREAM) throw new Error('frames: bad stream id ' + stream);
  let body;
  if (payload == null) body = Buffer.alloc(0);
  else if (Buffer.isBuffer(payload)) body = payload;
  else if (typeof payload === 'string') body = Buffer.from(payload, 'utf8');
  else if (typeof payload === 'object') body = Buffer.from(JSON.stringify(payload), 'utf8');
  else throw new Error('frames: a payload must be a Buffer, a string or an object');
  const head = Buffer.alloc(HEADER);
  head[0] = type;
  head.writeUInt32BE(stream, 1);
  return Buffer.concat([head, body]);
}

/** Throws on anything shorter than the header or with a type nobody knows. */
function decode(buf) {
  if (!Buffer.isBuffer(buf)) throw new Error('frames: not a Buffer');
  if (buf.length < HEADER) throw new Error('frames: too short (' + buf.length + ' bytes)');
  const type = buf[0];
  if (!TYPE_NAMES[type]) throw new Error('frames: unknown type ' + type);
  const stream = buf.readUInt32BE(1);
  const payload = buf.subarray(HEADER);
  let parsed;
  let done = false;
  return {
    type,
    stream,
    payload,
    json() {
      if (!done) {
        try { parsed = JSON.parse(payload.toString('utf8')); }
        catch (e) { throw new Error('frames: the payload is not JSON (' + e.message + ')'); }
        done = true;
      }
      return parsed;
    }
  };
}

module.exports = { T, TYPE_NAMES, encode, decode, HEADER };
