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

/**
 * The probe has two ways to be impossible, and they blame different people.
 * A bad host or port is the user's to fix; a missing local SOCKS port is ours —
 * the core has just started and liveDiagnostics has not been captured yet — and
 * reporting that as "invalid input" sends the user off to correct a hostname
 * that was never wrong.
 */
test('a probe with no live SOCKS port says so instead of blaming the destination', async () => {
  for (const port of [undefined, null, 0, -1, 70000, '1080', 1.5]) {
    const result = await probeDestination(port, { host: 'internal.example', port: 443 }, {
      socks5Connect() { assert.fail('Must not probe without a listener'); }
    });
    assert.equal(result.status, 'no-live-socks', `socksPort ${JSON.stringify(port)}`);
    assert.equal(result.via, 'local-socks');
  }
  // and a live listener with a bad destination is still the user's to fix
  assert.equal((await probeDestination(1080, { host: 'x y', port: 443 }, {
    socks5Connect() { assert.fail(); }
  })).status, 'invalid-input');
});

/**
 * Underscores are illegal in a public hostname and ordinary in a private one:
 * internal and WireGuard-side names carry them, and this probe exists precisely
 * to reach those. Refusing them made the corporate destination untestable.
 */
test('an underscore in a label is a destination, not a typo', async () => {
  let asked;
  const result = await probeDestination(1080, { host: 'wg_gateway.corp_intra', port: 445 }, {
    socks5Connect: async (...args) => { asked = args; return { destroy() {} }; }
  });
  assert.equal(result.status, 'reachable');
  assert.equal(asked[2], 'wg_gateway.corp_intra');
  assert.equal((await probeDestination(1080, { host: '_', port: 445 }, {
    socks5Connect: async () => ({ destroy() {} })
  })).status, 'reachable');
});

test('sing-box detours and routing actions are explained and cycles are bounded', () => {
  const result = explainRoutes({ outbounds: [{ tag: 'exit', type: 'wireguard', detour: 'entry' }, { tag: 'entry', type: 'socks', detour: 'exit' }], route: { final: 'exit', rules: [{ action: 'hijack-dns' }, { action: 'reject' }] } });
  assert.deepEqual(result.rules.map(r => r.target), ['dns', 'block']);
  assert.equal(result.paths[0].complete, false);
  assert.equal(result.paths[0].hops.length, 2);
});
