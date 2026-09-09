'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { collectDiagnostics, explainRoutes, probeDestination } = require('../src/main/connectionDiagnostics');

const config = {
  outbounds: [
    { tag: 'private-exit', protocol: 'wireguard', settings: { secretKey: 'SECRET-KEY' }, streamSettings: { sockopt: { dialerProxy: 'private-entry' } } },
    { tag: 'private-entry', protocol: 'vless', settings: { address: 'secret.example' } },
    { tag: 'direct', protocol: 'freedom' }
  ],
  routing: { rules: [
    { domain: ['internal.example'], outboundTag: 'private-exit' },
    { ip: ['10.0.0.0/8'], outboundTag: 'direct' }
  ] }, dns: { servers: ['secret-dns.example'] }
};

test('running report explains effective rule and physical hop order without exporting private values', async () => {
  const original = JSON.stringify(config);
  const result = await collectDiagnostics({ coreRunning: true, tunRequested: true, config, plan: { mode: 'advanced', name: 'secret-name' } }, {
    socks5Connect() { throw new Error('Unexpected network access'); }
  });
  assert.deepEqual(result.routes.paths[0].hops, ['vless', 'wireguard']);
  assert.deepEqual(result.routes.rules.map(r => r.target), ['path-1', 'direct']);
  assert.equal(result.routes.fallback, 'path-1');
  assert.equal(result.tun.status, 'inactive');
  assert.equal(result.connectivity.status, 'not-tested');
  assert.equal(result.dns.status, 'configured-unverified');
  assert.doesNotMatch(JSON.stringify(result), /SECRET|secret|private-exit|private-entry|internal\.example|10\.0\.0\.0/);
  assert.equal(JSON.stringify(config), original);
});

test('explicit private-service probe uses SOCKS only and destroys the returned socket', async () => {
  let destroyed = false;
  let calls = 0;
  const result = await collectDiagnostics({ coreRunning: true, socksPort: 1080, probe: { host: '10.20.1.9', port: 445 } }, {
    socks5Connect: async (...args) => {
      calls++;
      assert.deepEqual(args, ['127.0.0.1', 1080, '10.20.1.9', 445, 5000]);
      return { destroy() { destroyed = true; } };
    }
  });
  assert.equal(calls, 1);
  assert.equal(destroyed, true);
  assert.equal(result.connectivity.status, 'reachable');
  assert.doesNotMatch(JSON.stringify(result), /10\.20\.1\.9|445/);
});

test('stopped core cannot probe or report stale routing as running', async () => {
  const result = await collectDiagnostics({ coreRunning: false, config, probe: { host: 'example.com', port: 80 } }, {
    socks5Connect() { assert.fail('Must not probe stopped core'); }
  });
  assert.equal(result.routes.status, 'unavailable');
  assert.equal(result.connectivity.status, 'core-stopped');
});

test('invalid probe input never contacts network and raw errors are redacted', async () => {
  for (const target of [{ host: 'https://private.example', port: 80 }, { host: 'x', port: 65536 }, { host: 'x\nsecret', port: 80 }]) {
    assert.equal((await probeDestination(1080, target, { socks5Connect() { assert.fail(); } })).status, 'invalid-input');
  }
  const result = await probeDestination(1080, { host: 'private.example', port: 443 }, {
    socks5Connect: async () => { throw new Error('timeout private.example user:password'); }
  });
  assert.deepEqual(result, { status: 'unreachable', via: 'local-socks', reason: 'timeout' });
});

test('sing-box detours and routing actions are explained and cycles are bounded', () => {
  const result = explainRoutes({ outbounds: [{ tag: 'exit', type: 'wireguard', detour: 'entry' }, { tag: 'entry', type: 'socks', detour: 'exit' }], route: { final: 'exit', rules: [{ action: 'hijack-dns' }, { action: 'reject' }] } });
  assert.deepEqual(result.rules.map(r => r.target), ['dns', 'block']);
  assert.equal(result.paths[0].complete, false);
  assert.equal(result.paths[0].hops.length, 2);
});
