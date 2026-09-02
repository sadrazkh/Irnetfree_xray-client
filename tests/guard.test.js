'use strict';
/**
 * Request guards for the headless panel. Both attacks are possible in the
 * recommended setup (bound to 127.0.0.1, no token): any web page can POST to
 * /rpc cross-origin, and DNS rebinding turns "127.0.0.1" into "attacker.example".
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { hostAllowed, originAllowed, hostnameOf } = require('../src/server/guard');

test('hostnameOf strips the port and lower-cases, keeps IPv6 brackets', () => {
  assert.equal(hostnameOf('127.0.0.1:6969'), '127.0.0.1');
  assert.equal(hostnameOf('LocalHost'), 'localhost');
  assert.equal(hostnameOf('[::1]:6969'), '[::1]');
  assert.equal(hostnameOf(undefined), '');
});

test('without a token only loopback Host values are accepted', () => {
  for (const h of ['127.0.0.1:6969', 'localhost:8080', '[::1]:6969', 'localhost']) {
    assert.equal(hostAllowed(h, {}), true, h);
  }
  // DNS rebinding: the browser resolved attacker.example to 127.0.0.1
  assert.equal(hostAllowed('attacker.example:6969', {}), false);
  assert.equal(hostAllowed('', {}), false);
});

test('a token (or --no-auth) lifts the Host restriction', () => {
  assert.equal(hostAllowed('203.0.113.9:6969', { token: 'abc' }), true);
  assert.equal(hostAllowed('203.0.113.9:6969', { noAuth: true }), true);
});

test('browser requests must come from the panel’s own origin', () => {
  const host = '127.0.0.1:6969';
  assert.equal(originAllowed({ host, origin: 'http://127.0.0.1:6969' }), true);
  assert.equal(originAllowed({ host, referer: 'http://127.0.0.1:6969/?token=x' }), true);
  assert.equal(originAllowed({ host, origin: 'https://evil.example' }), false);
  assert.equal(originAllowed({ host, referer: 'not a url' }), false);
  // a forwarded port: the page was opened on 8080, so Host and Origin agree on 8080
  assert.equal(originAllowed({ host: '127.0.0.1:8080', origin: 'http://127.0.0.1:8080' }), true);
});

test('non-browser clients (no Origin/Referer) pass the origin guard', () => {
  assert.equal(originAllowed({ host: '127.0.0.1:6969' }), true);
});
