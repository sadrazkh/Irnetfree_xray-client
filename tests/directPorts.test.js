'use strict';
/**
 * Direct ports (src/main/directPorts.js): local ports that leave outside the VPN.
 * What matters: the empty list changes no config at all; a row opens a loopback
 * port with no sniffing whose rule comes before every other, on every plan; the
 * exit is bound to the NIC under TUN; a port something else holds is not opened,
 * and the log says so. scripts/probe-direct-ports.js says the same on real cores.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { buildConfig, buildRawConfig } = require('../src/main/configBuilder');
const { buildSingboxConfig } = require('../src/main/singboxBuilder');
const { normalizeDirectPorts, directPortsOf, directPortsNotes, MAX_PORTS } = require('../src/main/directPorts');
const { reservedPorts } = require('../src/main/tunAppTargets');
const { RECONNECT_KEYS } = require('../src/main/settingsMeta');
const { parseLink } = require('../src/main/parser');
const F = require('./fixtures');

const DP = [{ port: 30810, type: 'socks' }, { port: 30811, type: 'http' }];
const single = () => ({ mode: 'single', server: F.VLESS_WS_TLS });
const dpInbounds = (c) => c.inbounds.filter((i) => String(i.tag).startsWith('dp-'));

test('normalizeDirectPorts keeps valid rows, a port once, and no more than the limit', () => {
  assert.deepEqual(normalizeDirectPorts([{ port: 30810 }, { port: '30811', type: 'http' }, { port: 30810, type: 'http' }, { port: 0 }, { port: 70000 }, { port: 1.5 }, null, 'x', { port: 30812, type: 'bad' }]),
    [{ port: 30810, type: 'socks' }, { port: 30811, type: 'http' }, { port: 30812, type: 'socks' }]);
  for (const junk of [null, undefined, 3, 'x', {}]) assert.deepEqual(normalizeDirectPorts(junk), []);
  const many = Array.from({ length: MAX_PORTS + 5 }, (_, i) => ({ port: 20000 + i }));
  assert.equal(normalizeDirectPorts(many).length, MAX_PORTS);
});

test('an empty list, or none, writes the very config of before, on every builder', () => {
  const plain = F.settings({});
  for (const list of [[], undefined, null, 'junk']) {
    const s = F.settings({ directPorts: list });
    assert.deepEqual(buildConfig(single(), s), buildConfig(single(), plain));
    assert.deepEqual(buildRawConfig({ json: { outbounds: [{ protocol: 'freedom', tag: 'x' }] } }, s), buildRawConfig({ json: { outbounds: [{ protocol: 'freedom', tag: 'x' }] } }, plain));
  }
  const tuic = parseLink('tuic://11111111-1111-1111-1111-111111111111:pw@1.2.3.4:443?sni=x.example&alpn=h3#t');
  assert.deepEqual(buildSingboxConfig(tuic, { directPorts: [] }), buildSingboxConfig(tuic, {}));
});

test('a row: a loopback port with no sniffing, SOCKS or HTTP, whatever allowLan says', () => {
  const c = buildConfig(single(), F.settings({ directPorts: DP, allowLan: true, enableSniffing: true }));
  assert.deepEqual(dpInbounds(c), [
    { tag: 'dp-30810', port: 30810, listen: '127.0.0.1', protocol: 'socks', settings: { auth: 'noauth', udp: true } },
    { tag: 'dp-30811', port: 30811, listen: '127.0.0.1', protocol: 'http', settings: {} }
  ]);
  assert.ok(c.inbounds.find((i) => i.tag === 'socks-in').sniffing.enabled, 'the app\'s own ports keep their sniffing');
});

test('the rule comes first and names only these inbounds; the exit asks the OS for names', () => {
  const c = buildConfig(single(), F.settings({ directPorts: DP, routingMode: 'bypass-ir' }));
  assert.deepEqual(c.routing.rules[0], { type: 'field', inboundTag: ['dp-30810', 'dp-30811'], outboundTag: 'dp-direct' });
  const out = c.outbounds.find((o) => o.tag === 'dp-direct');
  assert.deepEqual(out, { tag: 'dp-direct', protocol: 'freedom', settings: { domainStrategy: 'AsIs' } }, 'no TUN: no bind, the OS route is outside already');
  assert.ok(c.outbounds.find((o) => o.tag === 'direct'), 'the app\'s own direct stays');
});

test('under TUN the exit is bound to the physical interface, on every builder', () => {
  const c = buildConfig(single(), F.settings({ directPorts: DP, tunMode: true, directInterface: 'Wi-Fi' }));
  assert.deepEqual(c.outbounds.find((o) => o.tag === 'dp-direct').streamSettings, { sockopt: { interface: 'Wi-Fi' } });
  const tuic = parseLink('tuic://11111111-1111-1111-1111-111111111111:pw@1.2.3.4:443?sni=x.example&alpn=h3#t');
  const sb = buildSingboxConfig(tuic, { socksPort: 30808, httpPort: 30809, directPorts: DP, directInterface: 'Wi-Fi' });
  assert.deepEqual(sb.outbounds.find((o) => o.tag === 'dp-direct'), { type: 'direct', tag: 'dp-direct', bind_interface: 'Wi-Fi' });
  assert.deepEqual(sb.route.rules[0], { inbound: ['dp-30810', 'dp-30811'], outbound: 'dp-direct' });
  assert.deepEqual(sb.inbounds.filter((i) => i.tag.startsWith('dp-')).map((i) => [i.type, i.listen, i.listen_port]), [['socks', '127.0.0.1', 30810], ['http', '127.0.0.1', 30811]]);
  assert.equal(sb.route.final, 'proxy', 'everything else stays on the server');
});

test('every plan opens them: chain, pool and a raw config', () => {
  const chain = buildConfig({ mode: 'chain', chain: [F.VLESS_WS_TLS, F.TROJAN_TCP_TLS] }, F.settings({ directPorts: DP }));
  assert.equal(dpInbounds(chain).length, 2);
  assert.equal(chain.routing.rules[0].outboundTag, 'dp-direct');
  const pool = buildConfig({
    mode: 'pool', primary: 'sv-vless', entries: [{ id: 'e1', target: 'sv-vless', socksPort: 40001 }],
    serversById: { 'sv-vless': F.VLESS_WS_TLS }, chainsById: {}, chain: []
  }, F.settings({ directPorts: DP }));
  assert.equal(dpInbounds(pool).length, 2);
  assert.equal(pool.routing.rules[0].outboundTag, 'dp-direct');
  const raw = buildRawConfig({ json: { outbounds: [{ protocol: 'vless', tag: 'proxy' }], routing: { rules: [{ type: 'field', port: '0-65535', outboundTag: 'proxy' }] } } }, F.settings({ directPorts: DP }));
  assert.equal(dpInbounds(raw).length, 2);
  assert.equal(raw.routing.rules[0].outboundTag, 'dp-direct');
  assert.equal(raw.routing.rules[1].outboundTag, 'proxy', 'the JSON\'s own rules follow, unchanged');
  const noRouting = buildRawConfig({ json: {} }, F.settings({ directPorts: DP }));
  assert.equal(noRouting.routing.rules.length, 1);
  assert.equal(noRouting.outbounds.length, 1);
});

test('a port something else holds is not opened, and the log says which', () => {
  const s = F.settings({ socksPort: 30808, httpPort: 30809, apiPort: 30085, directPorts: [{ port: 30808 }, { port: 30085 }, { port: 30810 }] });
  const c = buildConfig(single(), s);
  assert.deepEqual(dpInbounds(c).map((i) => i.port), [30810]);
  assert.deepEqual(directPortsOf(s).clashing, [30808, 30085]);
  assert.deepEqual(directPortsNotes(s), [
    'Direct ports, outside the VPN: 127.0.0.1:30810 (SOCKS)',
    'Direct port 30808 not opened: another of the app\'s ports holds it',
    'Direct port 30085 not opened: another of the app\'s ports holds it'
  ]);
  // a pool entry's port, known only from the inbounds already built
  const pool = buildConfig({
    mode: 'pool', primary: 'sv-vless', entries: [{ id: 'e1', target: 'sv-vless', socksPort: 40001 }],
    serversById: { 'sv-vless': F.VLESS_WS_TLS }, chainsById: {}, chain: []
  }, F.settings({ directPorts: [{ port: 40001 }, { port: 30810 }] }));
  assert.deepEqual(dpInbounds(pool).map((i) => i.port), [30810]);
  assert.equal(pool.inbounds.filter((i) => i.port === 40001).length, 1);
  assert.deepEqual(directPortsNotes({}), [], 'none: the log says nothing');
  // what a connect logs, on the config but not in what is written to disk
  assert.deepEqual(c.directPortsNotes, directPortsNotes(s, c.inbounds.filter((i) => !String(i.tag).startsWith('dp-')).map((i) => i.port)));
  assert.equal(Object.keys(c).includes('directPortsNotes'), false);
  assert.equal(buildConfig(single(), F.settings({})).directPortsNotes, undefined);
});

test('a per-app inbound never takes one, and a changed list asks for a reconnect', () => {
  assert.ok(reservedPorts({ directPorts: DP }).has(30810));
  assert.ok(reservedPorts({ directPorts: DP }).has(30811));
  assert.ok(RECONNECT_KEYS.includes('directPorts'));
});

test('the settings page has the list, and both languages name it', () => {
  const dir = path.join(__dirname, '..', 'src', 'renderer');
  const html = fs.readFileSync(path.join(dir, 'index.html'), 'utf8');
  const i18n = fs.readFileSync(path.join(dir, 'i18n.js'), 'utf8');
  for (const id of ['directPortsBox', 'btnDirectPortAdd', 'directPortsList']) assert.match(html, new RegExp(`id="${id}"`));
  for (const key of ['dp.title', 'dp.add', 'dp.hint', 'dp.port', 'dp.type', 'dp.remove', 'dp.badPort', 'dp.dup', 'dp.clash', 'set.directPorts']) {
    assert.equal(i18n.split(`'${key}':`).length - 1, 2, key);
  }
});
