'use strict';
/**
 * The relay's frame format (src/server/remote/frames.js): one binary
 * WebSocket message = [type u8][stream u32 BE][payload], the payload a
 * Buffer or JSON. Both ends encode and decode with this one module.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { T, encode, decode, TYPE_NAMES } = require('../src/server/remote/frames');

test('the eight types have the numbers the spec gives them', () => {
  assert.deepEqual(T, { HELLO: 1, REQ_HEAD: 2, REQ_BODY: 3, REQ_END: 4, RES_HEAD: 5, RES_BODY: 6, RES_END: 7, CANCEL: 8 });
  assert.equal(TYPE_NAMES[T.RES_BODY], 'RES_BODY');
});

test('every type round trips with a Buffer payload, an empty payload, and a JSON payload', () => {
  for (const [name, type] of Object.entries(T)) {
    const body = Buffer.from('payload of ' + name);
    const f = decode(encode(type, 7, body));
    assert.equal(f.type, type, name);
    assert.equal(f.stream, 7, name);
    assert.ok(f.payload.equals(body), name);

    const empty = decode(encode(type, 0));
    assert.equal(empty.type, type);
    assert.equal(empty.stream, 0);
    assert.equal(empty.payload.length, 0);

    const obj = { name: 'router', n: 3, list: [1, 'دو'], nested: { ok: true } };
    const j = decode(encode(type, 42, obj));
    assert.deepEqual(j.json(), obj, name);
  }
});

test('the wire layout is exactly 1 + 4 bytes of header, big-endian stream id', () => {
  const buf = encode(T.RES_BODY, 0x01020304, Buffer.from([9, 9]));
  assert.deepEqual([...buf], [6, 1, 2, 3, 4, 9, 9]);
});

test('stream ids go up to 2^32-1', () => {
  for (const id of [0, 1, 65535, 65536, 2 ** 31 - 1, 2 ** 31, 2 ** 32 - 1]) {
    assert.equal(decode(encode(T.CANCEL, id)).stream, id, String(id));
  }
  assert.throws(() => encode(T.CANCEL, 2 ** 32), /stream/);
  assert.throws(() => encode(T.CANCEL, -1), /stream/);
  assert.throws(() => encode(T.CANCEL, 1.5), /stream/);
});

test('a truncated buffer throws, an unknown type throws, a bad payload type throws', () => {
  assert.throws(() => decode(Buffer.alloc(0)), /short/);
  assert.throws(() => decode(Buffer.from([1, 0, 0])), /short/);
  assert.throws(() => decode(Buffer.from([1, 0, 0, 0])), /short/);
  assert.doesNotThrow(() => decode(Buffer.from([1, 0, 0, 0, 0])));
  assert.throws(() => decode(Buffer.from([0, 0, 0, 0, 0])), /type/);
  assert.throws(() => decode(Buffer.from([9, 0, 0, 0, 0])), /type/);
  assert.throws(() => decode(Buffer.from([200, 0, 0, 0, 0])), /type/);
  assert.throws(() => encode(0, 1), /type/);
  assert.throws(() => encode(9, 1), /type/);
  assert.throws(() => encode(T.HELLO, 1, 12), /payload/);
  assert.throws(() => decode('not a buffer'), /buffer/i);
});

test('json() parses once and throws on a payload that is not JSON', () => {
  const f = decode(encode(T.HELLO, 1, { a: 1 }));
  assert.deepEqual(f.json(), { a: 1 });
  assert.equal(f.json(), f.json(), 'the same object the second time');
  const raw = decode(encode(T.RES_BODY, 1, Buffer.from('<html>')));
  assert.throws(() => raw.json(), /JSON/);
});

test('a string payload is sent as UTF-8 bytes (the relay forwards text bodies as they are)', () => {
  const f = decode(encode(T.RES_BODY, 1, 'chunk فارسی'));
  assert.equal(f.payload.toString('utf8'), 'chunk فارسی');
});
