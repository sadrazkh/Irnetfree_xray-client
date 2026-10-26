'use strict';
/**
 * The chain relay (configBuilder.relayHopDials): a TCP dial through a hop
 * rides a real loopback socket — a SOCKS inbound `chain-relay`, one account per
 * hop, routed by that account to the hop — because straight through the hop
 * the core dropped the end of a response the far side closed
 * (scripts/probe-chain-tail.js has the cores doing both). Which dials take it,
 * which keep their dialerProxy, and that a config with nothing dialled through
 * a hop — or built without a port — is exactly what it was.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const B = require('../src/main/configBuilder');
const G = require('../src/main/groups');
const F = require('./fixtures');
const { parseLink } = require('../src/main/parser');

const PORT = 10900;
const UUID = '2c0f0d9a-6b3a-4f0e-9a1f-8c2b4d6e7a10';
const srv = (id, link) => Object.assign(parseLink(link), { id });
const H = srv('h', `vless://${UUID}@cdn.example.com:443?type=ws&security=tls&path=%2Fw#H`);
const X = srv('x', `vless://${UUID}@de.example.net:8443?type=tcp&security=none#X`);
const Y = srv('y', `trojan://pw@nl.example.net:443?security=tls&sni=nl.example.net#Y`);
const H3 = srv('h3', `vless://${UUID}@h3.example.net:443?type=xhttp&security=tls&alpn=h3&path=%2Fx#H3`);
const S = (over) => F.settings(Object.assign({ chainRelayPort: PORT }, over));
const out = (c, tag) => c.outbounds.find((o) => o.tag === tag);
const via = (o) => o && o.streamSettings && o.streamSettings.sockopt && o.streamSettings.sockopt.dialerProxy;
const relayIn = (c) => c.inbounds.find((i) => i.tag === 'chain-relay');
const R = (...p) => fs.readFileSync(path.join(__dirname, '..', ...p), 'utf8').replace(/\r\n/g, '\n');

test('a chain: the exit dials its hop over the relay, the relay is loopback, password-locked, and routed first', () => {
  const c = B.buildConfig({ mode: 'chain', chain: [H, X] }, S());
  assert.equal(via(out(c, 'proxy')), 'chain-relay~proxy-h0');
  assert.equal(via(out(c, 'proxy-h0')), undefined, 'the hop dials by itself, as before');
  assert.deepEqual(out(c, 'chain-relay~proxy-h0'), { tag: 'chain-relay~proxy-h0', protocol: 'socks',
    settings: { servers: [{ address: '127.0.0.1', port: PORT, users: [{ user: 'proxy-h0', pass: 'chain-relay' }] }] } });
  const ib = relayIn(c);
  assert.equal(ib.listen, '127.0.0.1');
  assert.equal(ib.port, PORT);
  assert.equal(ib.protocol, 'socks');
  assert.deepEqual(ib.settings, { auth: 'password', accounts: [{ user: 'proxy-h0', pass: 'chain-relay' }], udp: false, userLevel: 1 });
  assert.equal(ib.sniffing, undefined, 'nothing sniffed: the relay hands over the exit’s own bytes');
  assert.deepEqual(c.routing.rules[0], { type: 'field', inboundTag: ['chain-relay'], user: ['proxy-h0'], outboundTag: 'proxy-h0' });
  // the accounts' level has no user counters: a LAN user may be called proxy-h0 too
  assert.equal(c.policy.levels['1'], undefined);
});

test('a three-hop chain: each later hop over the relay, one account per hop', () => {
  const c = B.buildConfig({ mode: 'chain', chain: [H, Y, X] }, S());
  assert.equal(via(out(c, 'proxy-h1')), 'chain-relay~proxy-h0');
  assert.equal(via(out(c, 'proxy')), 'chain-relay~proxy-h1');
  assert.deepEqual(relayIn(c).settings.accounts.map((a) => a.user).sort(), ['proxy-h0', 'proxy-h1']);
  assert.deepEqual(c.routing.rules.slice(0, 2).map((r) => [r.user[0], r.outboundTag]).sort(), [['proxy-h0', 'proxy-h0'], ['proxy-h1', 'proxy-h1']]);
});

test('without a port, or with nothing dialled through a hop, the config is what it was', () => {
  const chain = { mode: 'chain', chain: [H, X] };
  const plain = B.buildConfig(chain, F.settings());
  assert.equal(via(out(plain, 'proxy')), 'proxy-h0');
  assert.equal(relayIn(plain), undefined);
  assert.deepEqual(B.buildConfig(chain, F.settings({ chainRelayPort: 0 })), plain);
  const single = { mode: 'single', server: X };
  assert.deepEqual(B.buildConfig(single, S()), B.buildConfig(single, F.settings()));
});

test('a port the config already listens on: no relay rather than a core that cannot start', () => {
  const c = B.buildConfig({ mode: 'chain', chain: [H, X] }, S({ chainRelayPort: 10808 }));
  assert.equal(via(out(c, 'proxy')), 'proxy-h0');
  assert.equal(c.inbounds.filter((i) => i.port === 10808).length, 1);
  const m = B.buildConfig({ mode: 'chain', chain: [H, X] }, S({ chainRelayPort: 10085 }));   // the metrics listener
  assert.equal(relayIn(m), undefined);
});

test('what keeps its dialerProxy: a WireGuard, a UDP transport, a Shadowsocks exit, and a freedom dialer', () => {
  const wg = B.buildConfig({ mode: 'chain', chain: [H, F.WG_CORP] }, S());
  assert.equal(via(out(wg, 'proxy')), 'proxy-h0', 'a WireGuard dials its hop over UDP');
  assert.equal(relayIn(wg), undefined);
  const h3 = B.buildConfig({ mode: 'chain', chain: [H, H3] }, S());
  assert.equal(via(out(h3, 'proxy')), 'proxy-h0', 'XHTTP over HTTP/3 is QUIC');
  const ss = B.buildConfig({ mode: 'chain', chain: [H, F.SS_TCP] }, S());
  assert.equal(via(out(ss, 'proxy')), 'proxy-h0', 'Shadowsocks has UDP of its own');
  // a hop with an anti-DPI dialer: the hop keeps its freedom dialer, the exit rides the relay
  const frag = B.buildConfig({ mode: 'chain', chain: [F.vlessWithMarkers('sv-frag', { _fragment: 'tlshello' }), X] }, S());
  const hopVia = via(out(frag, 'proxy-h0'));
  assert.ok(hopVia && !hopVia.startsWith('chain-relay'), 'the first hop still dials through its fragment dialer: ' + hopVia);
  assert.equal(via(out(frag, 'proxy')), 'chain-relay~proxy-h0');
});

test('a group in a chain: every variant’s exit rides the relay to its own hop, and no balancer picks a relay', () => {
  const byId = { h: H, x: X, y: Y };
  const grp = G.groupRecord({ id: 'g', name: 'G', members: [{ id: 'x' }, { id: 'y' }] }, byId);
  const first = B.buildConfig({ mode: 'chain', chain: [grp, H] }, S());
  for (const i of [0, 1]) assert.equal(via(out(first, `proxy~gm${i}`)), `chain-relay~proxy~gh${i}-h0`);
  const after = B.buildConfig({ mode: 'chain', chain: [H, grp] }, S());
  for (const i of [0, 1]) assert.equal(via(out(after, `proxy~gm${i}`)), 'chain-relay~proxy-h0');
  for (const c of [first, after]) {
    const relays = c.outbounds.filter((o) => o.tag.startsWith('chain-relay~')).map((o) => o.tag);
    assert.ok(relays.length > 0);
    for (const b of c.routing.balancers) for (const sel of b.selector) assert.ok(relays.every((t) => !t.startsWith(sel)), sel);
    // the group's loop back still meets its balancer before anything but the relay
    const k = c.routing.rules.findIndex((r) => r.balancerTag);
    assert.ok(c.routing.rules.slice(0, k).every((r) => r.inboundTag && r.inboundTag[0] === 'chain-relay'));
  }
});

test('advanced routing and the pool: a chain target rides the relay too, and its rules come before the users’', () => {
  const adv = B.buildConfig({
    mode: 'advanced', serversById: { h: H, x: X }, chainsById: { c1: [H, X] }, chain: [],
    rules: [{ type: 'ip', value: '10.20.0.0/16', target: 'chain:c1' }], def: 'x'
  }, S({ dnsManaged: true }));
  const exit = adv.outbounds.find((o) => o.tag === 'out-chain-c1');
  assert.ok(exit, adv.outbounds.map((o) => o.tag).join(' '));
  assert.equal(via(exit), 'chain-relay~out-chain-c1-h0');
  assert.equal(adv.routing.rules[0].inboundTag[0], 'chain-relay');
  const pool = B.buildConfig({
    mode: 'pool', entries: [{ id: 'e1', target: 'chain:c1', socksPort: 20001 }], primary: 'x',
    serversById: { h: H, x: X }, chainsById: { c1: [H, X] }, chain: []
  }, S());
  assert.ok(pool.outbounds.some((o) => via(o) && via(o).startsWith('chain-relay~')));
  assert.equal(relayIn(pool).port, PORT);
});

test('the desktop and the router hand every connect and reload a relay port of its own', () => {
  for (const f of ['src/main/main.js', 'src/server/service.js']) {
    const src = R(f);
    assert.equal((src.match(/const \[apiCtlPort, chainRelayPort\] = await getFreePorts\(2\);/g) || []).length, 1, f + ': connect');
    assert.equal((src.match(/const \[freePort, chainRelayPort\] = await getFreePorts\(2\);/g) || []).length, 1, f + ': reload');
  }
  const kt = R('android/app/src/main/java/com/irnetfree/vpn/vpn/XrayVpnService.kt');
  assert.match(kt, /val relayPort = if \(engine == EngineChoice\.SINGBOX\) 0 else freeLocalPort\(setOf\(s\.socksPort, s\.httpPort, metricsPort\)\)/);
  assert.match(kt, /metricsPort = metricsPort, relayPort = relayPort,/);
});
