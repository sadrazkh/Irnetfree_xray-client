'use strict';
/**
 * The macOS half of the system proxy, without a Mac: the service-list parsing
 * and the networksetup argv are pinned against canned output, and the one
 * behaviour that matters for a non-administrator — the call FAILS instead of
 * logging success — is asserted. `exec` is injected; nothing is spawned.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { parseMacServices, enableMac, disableMac } = require('../src/main/sysproxy');

// What `networksetup -listallnetworkservices` prints on a MacBook with a
// disabled Thunderbolt Bridge: the legend first, the disabled one starred.
const LISTING = [
  'An asterisk (*) denotes that a network service is disabled.',
  'Wi-Fi',
  'iPhone USB',
  '*Thunderbolt Bridge',
  ''
].join('\n');

/** An exec that answers the listing and records every write; `fail(svc)` decides which writes throw. */
function fakeExec(fail = () => false) {
  const calls = [];
  const exec = async (cmd, args) => {
    calls.push([cmd, ...args]);
    if (args[0] === '-listallnetworkservices') return LISTING;
    if (fail(args[1])) throw new Error(`${args[1]}: You must be an administrator to run this command.`);
    return '';
  };
  return { exec, calls };
}

test('parseMacServices drops the legend, strips the asterisk of a disabled service, ignores blank lines', () => {
  assert.deepEqual(parseMacServices(LISTING), ['Wi-Fi', 'iPhone USB', 'Thunderbolt Bridge']);
  assert.deepEqual(parseMacServices(LISTING.replace(/\n/g, '\r\n')), ['Wi-Fi', 'iPhone USB', 'Thunderbolt Bridge'], 'CRLF tolerated');
  assert.deepEqual(parseMacServices(''), []);
  assert.deepEqual(parseMacServices(null), []);
});

test('parseMacServices keeps the first line when it is a service, not the legend', () => {
  // the old slice(1) would have thrown "Wi-Fi" away here
  assert.deepEqual(parseMacServices('Wi-Fi\nEthernet\n'), ['Wi-Fi', 'Ethernet']);
});

test('enableMac sets SOCKS, HTTP and HTTPS on every service, in networksetup argv form', async () => {
  const { exec, calls } = fakeExec();
  await enableMac('127.0.0.1', 10808, 10809, exec);
  assert.deepEqual(calls[0], ['networksetup', '-listallnetworkservices']);
  const writes = calls.slice(1);
  assert.equal(writes.length, 3 * 6, 'six writes per service');
  assert.deepEqual(writes.slice(0, 6), [
    ['networksetup', '-setsocksfirewallproxy', 'Wi-Fi', '127.0.0.1', '10808'],
    ['networksetup', '-setsocksfirewallproxystate', 'Wi-Fi', 'on'],
    ['networksetup', '-setwebproxy', 'Wi-Fi', '127.0.0.1', '10809'],
    ['networksetup', '-setwebproxystate', 'Wi-Fi', 'on'],
    ['networksetup', '-setsecurewebproxy', 'Wi-Fi', '127.0.0.1', '10809'],
    ['networksetup', '-setsecurewebproxystate', 'Wi-Fi', 'on']
  ]);
  // a service name with a space travels as ONE argv entry — never re-split by a shell
  assert.ok(writes.some(c => c[2] === 'iPhone USB'));
  assert.ok(writes.some(c => c[2] === 'Thunderbolt Bridge'), 'the disabled service is set too, asterisk gone');
});

test('enableMac fails when networksetup refuses every service (a non-administrator)', async () => {
  const { exec, calls } = fakeExec(() => true);
  await assert.rejects(enableMac('127.0.0.1', 10808, 10809, exec), /refused the proxy on every network service.*administrator/);
  // it did try every service before giving up, one write each
  assert.equal(calls.filter(c => c[1] === '-setsocksfirewallproxy').length, 3);
});

test('enableMac succeeds when at least one service took the proxy', async () => {
  const { exec } = fakeExec((svc) => svc === 'Thunderbolt Bridge');
  await enableMac('127.0.0.1', 10808, 10809, exec);
});

test('enableMac fails when there is no service at all', async () => {
  const exec = async () => '';
  await assert.rejects(enableMac('127.0.0.1', 10808, 10809, exec), /no network service/);
});

test('disableMac turns all three off on every service and swallows failures', async () => {
  const { exec, calls } = fakeExec(() => true);
  await disableMac(exec);
  const offs = calls.slice(1);
  assert.equal(offs.length, 3 * 3);
  assert.deepEqual(offs.slice(0, 3), [
    ['networksetup', '-setsocksfirewallproxystate', 'Wi-Fi', 'off'],
    ['networksetup', '-setwebproxystate', 'Wi-Fi', 'off'],
    ['networksetup', '-setsecurewebproxystate', 'Wi-Fi', 'off']
  ]);
});
