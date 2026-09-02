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

test('a token lifts the Host restriction on any bind', () => {
  assert.equal(hostAllowed('203.0.113.9:6969', { token: 'abc' }), true);
  assert.equal(hostAllowed('203.0.113.9:6969', { token: 'abc', loopbackBind: true }), true);
});

test('--no-auth does NOT lift the Host restriction on a loopback bind', () => {
  // On a loopback bind the server never auto-generates a token and authed()
  // passes whenever TOKEN is falsy — so --no-auth changes nothing about
  // authentication there. Its only remaining effect would be to switch off the
  // rebinding guard, which is the one thing it must not do.
  const opts = { noAuth: true, loopbackBind: true };
  assert.equal(hostAllowed('attacker.example:6969', opts), false);
  // the honest Host values still work, ports still ignored (ssh -L)
  for (const h of ['127.0.0.1:6969', 'localhost:8080', '[::1]:6969', 'localhost']) {
    assert.equal(hostAllowed(h, opts), true, h);
  }
});

test('--no-auth on a non-loopback bind still accepts any Host', () => {
  // The user bound to a public interface and explicitly opted out of a token:
  // the Host is whatever name they reach the box by, so there is nothing to check.
  const opts = { noAuth: true, loopbackBind: false };
  assert.equal(hostAllowed('203.0.113.9:6969', opts), true);
  assert.equal(hostAllowed('panel.example:6969', opts), true);
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
