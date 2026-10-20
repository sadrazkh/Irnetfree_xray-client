'use strict';
/**
 * An ECH outbound (PattN's `echOutbound`, patterniha 2026-10-20): the ECH key
 * fetched through an outbound of the server's own — from the link to the
 * config, the editor and back into a share link.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { parseLink, buildShareLink, editFields, applyServerEdits } = require('../src/main/parser');
const { buildConfig, buildTestConfig, buildMultiTestConfig, buildPoolConfig, applyEchOutbounds, echResolverIpsOf } = require('../src/main/configBuilder');
const { sumOutbounds, byOutbound } = require('../src/main/stats');
const SF = require('../src/renderer/serverFields');

const EO = {
  tag: 'tls-repack-dns', protocol: 'direct', settings: { redirect: '1.1.1.1:443' },
  streamSettings: { security: 'tls', tlsSettings: { serverName: 'www.microsoft.com', verifyPeerCertByName: 'fromMitM,www.microsoft.com', alpn: ['fromMitM'], fingerprint: 'chrome' } }
};
const H2C = 'cloudflare-ech.com+h2c://1.1.1.1/dns-query';
const PORTS = { socksPort: 47908, httpPort: 47909, apiPort: 47985 };

function link(host, extra) {
  const q = Object.assign({ type: 'ws', security: 'tls', sni: host, path: '/', ech: H2C, echOutbound: JSON.stringify(EO) }, extra);
  const qs = Object.keys(q).filter((k) => q[k] != null).map((k) => k + '=' + encodeURIComponent(q[k])).join('&');
  return `vless://11111111-2222-3333-4444-555555555555@${host}:443?${qs}#${host}`;
}
function server(host, id, extra) {
  const s = parseLink(link(host, extra));
  s.id = id;
  return s;
}
const tlsOf = (o) => o.streamSettings.tlsSettings;
const echOuts = (cfg) => cfg.outbounds.filter((o) => /^ech-\d+$/.test(o.tag));

/* ------------------------------- the link ------------------------------- */

test('a link’s echOutbound is kept on the record, inside tlsSettings, as an object', () => {
  const s = server('a.example', 'a');
  assert.deepEqual(tlsOf(s.outbound).echOutbound, EO);
  assert.equal(tlsOf(s.outbound).echConfigList, H2C);
});

test('PattN writes it with comments and trailing commas: read; what is not an outbound is dropped', () => {
  const commented = '{ // the fronted DoH\n "protocol": "direct", /* to 1.1.1.1 */ "settings": { "redirect": "1.1.1.1:443", }, }';
  assert.deepEqual(tlsOf(server('a.example', 'a', { echOutbound: commented }).outbound).echOutbound,
    { protocol: 'direct', settings: { redirect: '1.1.1.1:443' } });
  // a // inside a string is the string's
  assert.equal(tlsOf(server('a.example', 'a', { echOutbound: '{"protocol":"direct","x":"http://y"}' }).outbound).echOutbound.x, 'http://y');
  for (const bad of ['not json', '[1,2]', '{"settings":{}}', '{"protocol":""}', '"direct"', '42']) {
    assert.equal('echOutbound' in tlsOf(server('a.example', 'a', { echOutbound: bad }).outbound), false, bad);
  }
});

test('the share link carries it on one line, with a tag (PattN refuses one without) — and reads back the same', () => {
  const s = server('a.example', 'a');
  const out = buildShareLink(s);
  const q = new URL(out).searchParams;
  assert.deepEqual(JSON.parse(q.get('echOutbound')), EO);
  assert.equal(q.get('echOutbound').includes('\n'), false);
  assert.deepEqual(tlsOf(parseLink(out).outbound).echOutbound, EO);
  const untagged = server('a.example', 'a', { echOutbound: JSON.stringify({ protocol: 'direct' }) });
  assert.deepEqual(JSON.parse(new URL(buildShareLink(untagged)).searchParams.get('echOutbound')), { tag: 'ech-out', protocol: 'direct' });
});

test('VMess JSON links and Hysteria2 links carry it too', () => {
  const vm = { v: '2', ps: 'v', add: 'v.example', port: '443', id: '11111111-2222-3333-4444-555555555555', aid: '0', net: 'ws', path: '/', tls: 'tls', sni: 'v.example', ech: H2C, echOutbound: JSON.stringify(EO) };
  const v = parseLink('vmess://' + Buffer.from(JSON.stringify(vm)).toString('base64'));
  assert.deepEqual(tlsOf(v.outbound).echOutbound, EO);
  const back = JSON.parse(Buffer.from(buildShareLink(v).slice('vmess://'.length), 'base64').toString());
  assert.deepEqual(JSON.parse(back.echOutbound), EO);
  const h = parseLink(`hysteria2://pw@h.example:443?sni=h.example&ech=${encodeURIComponent(H2C)}&echOutbound=${encodeURIComponent(JSON.stringify(EO))}#h`);
  assert.deepEqual(tlsOf(h.outbound).echOutbound, EO);
  assert.deepEqual(JSON.parse(new URL(buildShareLink(h)).searchParams.get('echOutbound')), EO);
});

/* ------------------------------- the config ------------------------------- */

test('the config: the outbound appended as ech-1, the query dialled through it, no core-unknown key left', () => {
  const cfg = buildConfig({ mode: 'single', server: server('a.example', 'a') }, Object.assign({ routingMode: 'global' }, PORTS));
  const px = cfg.outbounds.find((o) => o.tag === 'proxy');
  assert.equal('echOutbound' in tlsOf(px), false);
  assert.deepEqual(tlsOf(px).echSockopt, { dialerProxy: 'ech-1' });
  const ech = echOuts(cfg);
  assert.equal(ech.length, 1);
  assert.deepEqual(ech[0], Object.assign({}, EO, { tag: 'ech-1' }));
  assert.equal(cfg.outbounds.at(-1).tag === 'ech-1' || cfg.outbounds.indexOf(ech[0]) > cfg.outbounds.indexOf(px), true);
  assert.equal(JSON.stringify(cfg).includes('"echOutbound"'), false);
  assert.equal(JSON.stringify(cfg).includes('tls-repack-dns'), false, 'the user’s tag is replaced by ours');
});

test('under TUN: the ECH outbound bound to the NIC like any direct dial, the query’s own sockopt not — and its redirect is the strict guard’s hole', () => {
  const cfg = buildConfig({ mode: 'single', server: server('a.example', 'a') }, Object.assign({ routingMode: 'global', directInterface: 'Wi-Fi' }, PORTS));
  const px = cfg.outbounds.find((o) => o.tag === 'proxy');
  assert.deepEqual(tlsOf(px).echSockopt, { dialerProxy: 'ech-1' });
  assert.equal(echOuts(cfg)[0].streamSettings.sockopt.interface, 'Wi-Fi');
  assert.deepEqual(echResolverIpsOf(cfg), ['1.1.1.1']);
  const other = parseLink(link('b.example', { echOutbound: JSON.stringify(Object.assign({}, EO, { settings: { redirect: '104.16.1.2:443' } })) }));
  other.id = 'b';
  assert.deepEqual(echResolverIpsOf(buildConfig({ mode: 'single', server: other }, Object.assign({ routingMode: 'global' }, PORTS))), ['1.1.1.1', '104.16.1.2']);
});

test('one ECH outbound per distinct one: a chain of two with the same shares ech-1, a different one gets ech-2', () => {
  const same = buildConfig({ mode: 'chain', chain: [server('a.example', 'a'), server('b.example', 'b')] }, Object.assign({ routingMode: 'global' }, PORTS));
  assert.deepEqual(echOuts(same).map((o) => o.tag), ['ech-1']);
  const diff = buildConfig({ mode: 'chain', chain: [server('a.example', 'a'),
    server('b.example', 'b', { echOutbound: JSON.stringify(Object.assign({}, EO, { tag: 'mine', settings: { redirect: '8.8.8.8:443' } })) })] }, Object.assign({ routingMode: 'global' }, PORTS));
  assert.deepEqual(echOuts(diff).map((o) => o.tag), ['ech-1', 'ech-2']);
  const via = diff.outbounds.filter((o) => o.streamSettings && o.streamSettings.tlsSettings && o.streamSettings.tlsSettings.echSockopt).map((o) => tlsOf(o).echSockopt.dialerProxy);
  assert.deepEqual(via.sort(), ['ech-1', 'ech-2']);
});

test('nothing to fetch, nothing to wire: a base64 list or no list drops it', () => {
  for (const ech of ['AEX+/base64list', '']) {
    const cfg = buildConfig({ mode: 'single', server: server('a.example', 'a', { ech }) }, Object.assign({ routingMode: 'global' }, PORTS));
    const px = cfg.outbounds.find((o) => o.tag === 'proxy');
    assert.equal(echOuts(cfg).length, 0, ech);
    assert.equal('echOutbound' in tlsOf(px), false, ech);
    assert.equal(!!(tlsOf(px).echSockopt && tlsOf(px).echSockopt.dialerProxy), false, ech);
  }
});

test('the pings and the pool carry it too — a test without it would ask for the key directly', () => {
  const t = buildTestConfig(server('a.example', 'a'), 40001);
  assert.deepEqual(tlsOf(t.outbounds[0]).echSockopt, { dialerProxy: 'ech-1' });
  assert.equal(echOuts(t).length, 1);
  const m = buildMultiTestConfig([server('a.example', 'a'), server('b.example', 'b')], [40001, 40002]);
  assert.deepEqual(echOuts(m).map((o) => o.tag), ['ech-1']);
  const a = server('a.example', 'a');
  const pool = buildPoolConfig({ entries: [{ id: 'p1', name: 'P', target: 'a', socksPort: 47911, httpPort: 0, enabled: true }], serversById: { a }, chainsById: {} },
    Object.assign({ routingMode: 'global' }, PORTS), '127.0.0.1', true);
  assert.equal(echOuts(pool).length, 1);
});

test('applyEchOutbounds leaves a config without one exactly as it was', () => {
  const outs = [{ tag: 'proxy', protocol: 'vless', streamSettings: { security: 'tls', tlsSettings: { serverName: 'x', echConfigList: H2C } } }];
  const before = JSON.stringify(outs);
  assert.equal(applyEchOutbounds(outs), outs);
  assert.equal(JSON.stringify(outs), before);
});

/* ------------------------------- the meter ------------------------------- */

test('the live meter leaves the ECH outbound out: it carries the key query, never the user’s traffic', () => {
  const vars = { stats: { outbound: { proxy: { uplink: 100, downlink: 1000 }, 'ech-1': { uplink: 7, downlink: 9 } } } };
  assert.deepEqual(sumOutbounds(vars), { up: 100, down: 1000 });
  assert.deepEqual(Object.keys(byOutbound(vars)), ['proxy']);
});

/* ------------------------------- the editor ------------------------------- */

test('the editor: the field in the ECH group (Pro), the record’s value shown indented, an edit written back, an empty one clears it', () => {
  const f = SF.FIELDS.find((x) => x.id === 'echOutbound');
  assert.equal(f.group, 'ech');
  assert.equal(f.kind, 'json');
  assert.equal(!!f.simple, false);
  const s = server('a.example', 'a');
  assert.equal(editFields(s).echOutbound, JSON.stringify(EO, null, 2));
  // the form sends every field it shows (app.js draftFields)
  const form = (edits) => Object.assign(editFields(s), edits);
  const changed = applyServerEdits(JSON.parse(JSON.stringify(s)), form({ echOutbound: JSON.stringify({ protocol: 'freedom' }) }));
  assert.deepEqual(tlsOf(changed.outbound).echOutbound, { protocol: 'freedom' });
  const cleared = applyServerEdits(JSON.parse(JSON.stringify(s)), form({ echOutbound: '' }));
  assert.equal('echOutbound' in tlsOf(cleared.outbound), false);
  // an edit of something else keeps it
  const other = applyServerEdits(JSON.parse(JSON.stringify(s)), { sni: 'c.example' });
  assert.deepEqual(tlsOf(other.outbound).echOutbound, EO);
});

test('the editor’s Example: the post’s outbound, and the ECH value it goes with under the name the field asks for', () => {
  const ex = SF.echOutboundExample('cloudflare-ech.com+udp://1.1.1.1');
  assert.equal(ex.ech, 'cloudflare-ech.com+h2c://1.1.1.1/dns-query');
  assert.deepEqual(JSON.parse(ex.echOutbound), EO);
  assert.equal(SF.echOutboundExample('').ech, 'cloudflare-ech.com+h2c://1.1.1.1/dns-query');
  assert.equal(SF.echOutboundExample('other.example+https://8.8.8.8/dns-query').ech, 'other.example+h2c://1.1.1.1/dns-query');
  assert.equal(SF.echOutboundExample('udp://8.8.8.8').ech, 'h2c://1.1.1.1/dns-query');
  assert.equal(SF.echOutboundExample('AEX+base64list').ech, 'cloudflare-ech.com+h2c://1.1.1.1/dns-query');
});

test('the connect says what to update when the core is too old for it — desktop and router, in the user’s language', () => {
  const read = (f) => fs.readFileSync(path.join(__dirname, '..', f), 'utf8');
  for (const f of ['src/main/main.js', 'src/server/service.js']) {
    const src = read(f);
    assert.match(src, /if \(check\.echOutboundUnsupported\) \{/, f);
    assert.match(src, /This server's ECH outbound needs Xray \$\{check\.need\} or newer/, f);
    assert.match(src, /خروجی ECH این سرور به Xray نسخهٔ ≥ \$\{check\.need\} نیاز دارد/, f);
  }
});
