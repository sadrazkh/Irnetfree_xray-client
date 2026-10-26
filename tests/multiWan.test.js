'use strict';
/**
 * Multi-internet (v1.32.0, src/main/multiWan.js): the settings, which links a
 * build uses, and what buildConfig / buildPoolConfig write with them — a
 * server over the links as a group (balance with weights and a backup link,
 * failover), an XHTTP server uploading on one link and downloading on the
 * other (split), a group's members multiplied, chains untouched, the anti-DPI
 * dialers per interface, TUN's NIC binding leaving the links alone, the
 * configs byte-identical with it off, and the bytes counted per link.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const M = require('../src/main/multiWan');
const B = require('../src/main/configBuilder');
const G = require('../src/main/groups');
const S = require('../src/main/stats');
const F = require('./fixtures');
const { parseLink } = require('../src/main/parser');

const UUID = '11111111-2222-3333-4444-555555555555';
const srv = (id, link) => Object.assign(parseLink(link), { id });
const XTLS = srv('sv-xtls', `vless://${UUID}@x.example.com:443?encryption=none&type=xhttp&security=tls&sni=x.example.com&fp=chrome&path=%2Fxh&host=x.example.com&mode=auto#XHTTP TLS`);
const XREAL = srv('sv-xreal', `vless://${UUID}@r.example.com:443?encryption=none&type=xhttp&security=reality&sni=www.microsoft.com&fp=chrome&pbk=${Buffer.alloc(32, 9).toString('base64url')}&sid=ab12&path=%2Fxr&mode=auto#XHTTP REALITY`);
const XONE = srv('sv-xone', `vless://${UUID}@o.example.com:443?encryption=none&type=xhttp&security=tls&sni=o.example.com&path=%2Fo&mode=stream-one#XHTTP one`);
const VLESS = F.VLESS_WS_TLS;
const TROJAN = F.TROJAN_TCP_TLS;

const LINKS = [
  { id: 'Wi-Fi', iface: 'Wi-Fi', name: 'Home', role: 'use', weight: 2 },
  { id: 'Ethernet 2', iface: 'Ethernet 2', name: 'Phone', role: 'use', weight: 1 },
  { id: 'eth9', iface: 'eth9', name: 'Spare', role: 'backup', weight: 2 }
];
const mwOf = (over) => Object.assign({ enabled: true, mode: 'balance', links: LINKS, split: { up: 'Wi-Fi', down: 'Ethernet 2' } }, over);
const build = (plan, over) => B.buildConfig(plan, F.settings(over));
const find = (cfg, tag) => cfg.outbounds.find((o) => o.tag === tag);
const iface = (o) => ((o && o.streamSettings && o.streamSettings.sockopt) || {}).interface;
const dials = (o) => ((o && o.streamSettings && o.streamSettings.sockopt) || {}).dialerProxy;
const members = (cfg, T) => cfg.outbounds.filter((o) => new RegExp(`^${T.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}~gm\\d+$`).test(o.tag));
const json = (cfg) => JSON.stringify(cfg);

/* ------------------------------------ settings ------------------------------------ */
test('normalizeMultiWan: always the full shape — junk dropped, weight 1..3, role/mode/period validated, links deduped by id, a finite cap ≥ 0', () => {
  assert.deepEqual(M.normalizeMultiWan(undefined), { enabled: false, mode: 'balance', links: [], split: { up: '', down: '' } });
  assert.deepEqual(M.normalizeMultiWan('x'), M.normalizeMultiWan(null));
  const n = M.normalizeMultiWan({
    enabled: true, mode: 'split', extra: 1, split: { up: ' Wi-Fi ', down: 7, x: 1 },
    links: [
      { id: 'Wi-Fi', name: 'Home', role: 'backup', weight: 7, quotaGb: '5', quotaPeriod: 'month', junk: true },
      { id: 'Wi-Fi', name: 'dup' },
      { iface: 'Ethernet 2', weight: 0, quotaGb: -3, quotaPeriod: 'year', role: 'sometimes' },
      { id: 'usb0', weight: 'x', quotaGb: 'lots' },
      { id: 'wwan', weight: 2.6, quotaGb: Infinity, role: 'off' },
      null, 'eth0', { name: 'no id' }, { id: '   ' }
    ]
  });
  assert.deepEqual(n, {
    enabled: true, mode: 'split', split: { up: 'Wi-Fi', down: '7' },
    links: [
      { id: 'Wi-Fi', iface: 'Wi-Fi', name: 'Home', role: 'backup', weight: 3, quotaGb: 5, quotaPeriod: 'month' },
      { id: 'Ethernet 2', iface: 'Ethernet 2', name: 'Ethernet 2', role: 'use', weight: 1, quotaGb: 0, quotaPeriod: 'none' },
      { id: 'usb0', iface: 'usb0', name: 'usb0', role: 'use', weight: 2, quotaGb: 0, quotaPeriod: 'none' },
      { id: 'wwan', iface: 'wwan', name: 'wwan', role: 'off', weight: 3, quotaGb: 0, quotaPeriod: 'none' }
    ]
  });
  assert.equal(M.normalizeMultiWan({ enabled: 'yes', mode: 'aggregate' }).enabled, false, 'only true is on');
  assert.equal(M.normalizeMultiWan({ mode: 'aggregate' }).mode, 'balance');
  // the interface is the id unless it says otherwise
  assert.equal(M.normalizeMultiWan({ links: [{ id: 'wan', iface: 'pppoe-wan' }] }).links[0].iface, 'pppoe-wan');
  // normalizing twice changes nothing
  assert.deepEqual(M.normalizeMultiWan(n), n);
});

test('usableLinks / applies: not off, an interface, not set aside for its cap, in order; balance and failover want two, split an up and a down that differ; a capped link with one left still applies', () => {
  const links = [{ id: 'a', role: 'use' }, { id: 'b', role: 'off' }, { id: 'c', role: 'backup' }, { id: 'd' }];
  assert.deepEqual(M.usableLinks({ links }).map((l) => l.id), ['a', 'c', 'd']);
  assert.deepEqual(M.usableLinks({ links }, ['a']).map((l) => l.id), ['c', 'd']);
  assert.deepEqual(M.usableLinks({ links }, new Set(['d'])).map((l) => l.id), ['a', 'c']);
  assert.equal(M.applies({ enabled: false, links }), false, 'off');
  assert.equal(M.applies({ enabled: true, links }), true);
  assert.equal(M.applies({ enabled: true, mode: 'failover', links }), true);
  assert.equal(M.applies({ enabled: true, links: [{ id: 'a' }, { id: 'b', role: 'off' }] }), false, 'one link: nothing to combine');
  assert.equal(M.applies({ enabled: true, links: [] }), false);
  assert.equal(M.applies({ enabled: true, mode: 'split', links, split: { up: 'a', down: 'd' } }), true);
  assert.equal(M.applies({ enabled: true, mode: 'split', links, split: { up: 'a', down: 'a' } }), false, 'up and down the same link');
  assert.equal(M.applies({ enabled: true, mode: 'split', links, split: { up: 'a', down: 'b' } }), false, 'the down link is off');
  assert.equal(M.applies({ enabled: true, mode: 'split', links, split: { up: 'a', down: '' } }), false);
  // a link over its cap: what is left carries everything — even one link alone
  const two = [{ id: 'a' }, { id: 'b' }];
  assert.equal(M.applies({ enabled: true, links: two }, ['b']), true);
  assert.equal(M.applies({ enabled: true, mode: 'split', links: two, split: { up: 'a', down: 'b' } }, ['a']), true);
  assert.equal(M.applies({ enabled: true, links: two }, ['a', 'b']), false, 'nothing left: the config as it was');
  assert.equal(M.applies({ enabled: false, links: two }, ['b']), false);
});

/* ------------------------------------- balance ------------------------------------- */
test('balance: the server becomes a group over the links — weight copies interleaved, ids <server>#<link>, each bound to its interface, round robin, the backup link the fallback', () => {
  const cfg = build({ mode: 'single', server: VLESS }, { multiWan: mwOf() });
  assert.deepEqual(find(cfg, 'proxy'), { tag: 'proxy', protocol: 'loopback', settings: { inboundTag: 'proxy~in' } });
  const ms = members(cfg, 'proxy');
  assert.deepEqual(ms.map((o) => [o.tag, iface(o)]), [['proxy~gm0', 'Wi-Fi'], ['proxy~gm1', 'Ethernet 2'], ['proxy~gm2', 'Wi-Fi']]);
  for (const o of ms) {
    assert.equal(o.protocol, 'vless');
    assert.equal(o.settings.vnext[0].address, 'a.example.com');
    assert.equal(o.streamSettings.wsSettings.path, '/ws', 'the server as it is, only bound');
    assert.equal('allowInsecure' in o.streamSettings.tlsSettings, false);
  }
  assert.equal(iface(find(cfg, 'proxy~fb')), 'eth9');
  assert.deepEqual(cfg.routing.balancers, [{ tag: 'proxy~bal', selector: ['proxy~gm'], strategy: { type: 'roundRobin' }, fallbackTag: 'proxy~fb' }]);
  assert.deepEqual(cfg.routing.rules[0], { type: 'field', inboundTag: ['proxy~in'], balancerTag: 'proxy~bal' });
  assert.deepEqual(cfg.observatory.subjectSelector, ['proxy~gm']);
  assert.equal(json(cfg).includes('_group'), false);
  assert.equal(new Set(cfg.outbounds.map((o) => o.tag)).size, cfg.outbounds.length, 'every tag unique');
  // the live view: the server's name, members "<server> · <link>", copies of one link one id
  assert.deepEqual(cfg.groupTags, [{
    tag: 'proxy', groupId: 'mw:proxy', name: 'VLESS WS', strategy: 'roundRobin', direct: true,
    fallback: { id: 'sv-vless#eth9', name: 'VLESS WS · Spare' },
    members: [
      { id: 'sv-vless#Wi-Fi', name: 'VLESS WS · Home', address: 'a.example.com', port: 443, direct: true },
      { id: 'sv-vless#Ethernet 2', name: 'VLESS WS · Phone', address: 'a.example.com', port: 443, direct: true },
      { id: 'sv-vless#Wi-Fi', name: 'VLESS WS · Home', address: 'a.example.com', port: 443, direct: true }
    ]
  }]);
  assert.equal(B.groupMemberKey('mw:proxy', cfg.groupTags[0].members[0]), B.groupMemberKey('mw:proxy', cfg.groupTags[0].members[2]), 'a link is set aside whole');
  // no backup link: no fallback (the first member is the balancer's)
  const nb = build({ mode: 'single', server: VLESS }, { multiWan: mwOf({ links: LINKS.slice(0, 2) }) });
  assert.equal(nb.routing.balancers[0].fallbackTag, 'proxy~gm0');
  assert.equal(find(nb, 'proxy~fb'), undefined);
  // only backups: the first is the member, the next the fallback
  const ob = build({ mode: 'single', server: VLESS }, { multiWan: mwOf({ links: [{ id: 'a', role: 'backup', weight: 3 }, { id: 'b', role: 'backup' }] }) });
  assert.deepEqual(members(ob, 'proxy').map(iface), ['a']);
  assert.equal(iface(find(ob, 'proxy~fb')), 'b');
});

test('a link over its cap is left out (multiWanSkip): the rest carry everything — one link left is a group of one', () => {
  const cfg = build({ mode: 'single', server: VLESS }, { multiWan: mwOf({ links: LINKS.slice(0, 2) }), multiWanSkip: ['Wi-Fi'] });
  assert.deepEqual(members(cfg, 'proxy').map((o) => iface(o)), ['Ethernet 2']);
  assert.equal(cfg.groupTags[0].members[0].id, 'sv-vless#Ethernet 2');
  assert.equal(json(cfg).includes('"Wi-Fi"'), false, 'the capped link carries nothing');
});

/* ------------------------------------- failover ------------------------------------- */
test('failover: the first link alone, the next one (a use link before a backup) the fallback — no weight copies', () => {
  const cfg = build({ mode: 'single', server: VLESS }, { multiWan: mwOf({ mode: 'failover' }) });
  assert.deepEqual(members(cfg, 'proxy').map((o) => [o.tag, iface(o)]), [['proxy~gm0', 'Wi-Fi']]);
  assert.equal(iface(find(cfg, 'proxy~fb')), 'Ethernet 2');
  assert.equal(cfg.routing.balancers[0].fallbackTag, 'proxy~fb');
  // the order configured, use links first
  const c2 = build({ mode: 'single', server: VLESS }, { multiWan: mwOf({ mode: 'failover', links: [{ id: 'b1', role: 'backup' }, { id: 'u1' }, { id: 'u2' }] }) });
  assert.deepEqual([iface(find(c2, 'proxy~gm0')), iface(find(c2, 'proxy~fb'))], ['u1', 'u2']);
  const c3 = build({ mode: 'single', server: VLESS }, { multiWan: mwOf({ mode: 'failover', links: [{ id: 'b1', role: 'backup' }, { id: 'u1' }] }) });
  assert.deepEqual([iface(find(c3, 'proxy~gm0')), iface(find(c3, 'proxy~fb'))], ['u1', 'b1']);
});

/* --------------------------------------- split --------------------------------------- */
test('split, XHTTP over TLS: one outbound, uploading on the up link; a download leg written for the same server (address, port, TLS, path, Host) on the down link', () => {
  const cfg = build({ mode: 'single', server: XTLS }, { multiWan: mwOf({ mode: 'split' }) });
  const o = find(cfg, 'proxy');
  assert.equal(o.protocol, 'vless');
  assert.equal(iface(o), 'Wi-Fi');
  const xs = o.streamSettings.xhttpSettings;
  assert.deepEqual([xs.path, xs.host, xs.mode], ['/xh', 'x.example.com', 'auto']);
  assert.deepEqual(xs.extra.downloadSettings, {
    address: 'x.example.com', port: 443, network: 'xhttp', security: 'tls',
    tlsSettings: { serverName: 'x.example.com', fingerprint: 'chrome' },
    xhttpSettings: { path: '/xh', host: 'x.example.com' },
    sockopt: { interface: 'Ethernet 2' }
  });
  assert.equal('balancers' in cfg.routing, false, 'no group');
  assert.equal(json(cfg).includes('_mwSplit'), false);
  assert.deepEqual(cfg.multiWanSplit, [{ tag: 'proxy', up: 'Wi-Fi', down: 'Ethernet 2' }]);
  assert.equal(Object.keys(cfg).includes('multiWanSplit'), false, 'beside the config, never in it');
  // under TUN with the name answered from the config: the download leg asks xray's DNS as the upload does
  const tun = build({ mode: 'single', server: XTLS }, { multiWan: mwOf({ mode: 'split' }), tunMode: true, directInterface: 'Wi-Fi', entryHostIps: { 'x.example.com': ['203.0.113.5'] } });
  const t = find(tun, 'proxy');
  assert.deepEqual(t.streamSettings.sockopt, { interface: 'Wi-Fi', domainStrategy: 'UseIPv4' });
  assert.deepEqual(t.streamSettings.xhttpSettings.extra.downloadSettings.sockopt, { interface: 'Ethernet 2', domainStrategy: 'UseIPv4' });
  assert.deepEqual(tun.dns.hosts['x.example.com'], ['203.0.113.5']);
  assert.equal(iface(find(tun, 'direct')), 'Wi-Fi');
});

test('split, XHTTP over REALITY: the download leg carries the same REALITY settings', () => {
  const cfg = build({ mode: 'single', server: XREAL }, { multiWan: mwOf({ mode: 'split', split: { up: 'Ethernet 2', down: 'Wi-Fi' } }) });
  const o = find(cfg, 'proxy');
  assert.equal(iface(o), 'Ethernet 2');
  const ds = o.streamSettings.xhttpSettings.extra.downloadSettings;
  assert.deepEqual([ds.address, ds.port, ds.network, ds.security, ds.sockopt.interface], ['r.example.com', 443, 'xhttp', 'reality', 'Wi-Fi']);
  assert.deepEqual(ds.realitySettings, o.streamSettings.realitySettings);
  assert.equal(ds.realitySettings.publicKey, Buffer.alloc(32, 9).toString('base64url'));
  assert.equal(ds.tlsSettings, undefined);
  assert.deepEqual(ds.xhttpSettings, { path: '/xr', host: '' });
});

test('split keeps a download leg the server already has — its own address and settings — and binds it; a stream without `extra` has its keys moved into one (the core then reads only extra)', () => {
  const own = JSON.parse(JSON.stringify(XTLS));
  own.outbound.streamSettings.xhttpSettings.extra = {
    xPaddingBytes: '100-1000',
    downloadSettings: { address: 'dl.example.com', port: 8443, network: 'xhttp', security: 'tls', tlsSettings: { serverName: 'dl.example.com' }, xhttpSettings: { path: '/dl' }, sockopt: { tcpFastOpen: true } }
  };
  const cfg = build({ mode: 'single', server: own }, { multiWan: mwOf({ mode: 'split' }) });
  const extra = find(cfg, 'proxy').streamSettings.xhttpSettings.extra;
  assert.equal(extra.xPaddingBytes, '100-1000');
  assert.deepEqual(extra.downloadSettings, { address: 'dl.example.com', port: 8443, network: 'xhttp', security: 'tls', tlsSettings: { serverName: 'dl.example.com' }, xhttpSettings: { path: '/dl' }, sockopt: { tcpFastOpen: true, interface: 'Ethernet 2' } });
  // a JSON-style stream with its keys (and its download leg) at the top: moved into extra
  const top = JSON.parse(JSON.stringify(XTLS));
  Object.assign(top.outbound.streamSettings.xhttpSettings, { xmux: { maxConcurrency: '16-32' }, downloadSettings: { address: 'dl.example.com', port: 443, network: 'xhttp' } });
  const xs = find(build({ mode: 'single', server: top }, { multiWan: mwOf({ mode: 'split' }) }), 'proxy').streamSettings.xhttpSettings;
  assert.deepEqual(Object.keys(xs).sort(), ['extra', 'host', 'mode', 'path']);
  assert.deepEqual(xs.extra, { xmux: { maxConcurrency: '16-32' }, downloadSettings: { address: 'dl.example.com', port: 443, network: 'xhttp', sockopt: { interface: 'Ethernet 2' } } });
  assert.equal(M.splittable(top.outbound), true);
});

test('split falls back to balance over the up and the down: an XHTTP in stream-one mode (the one mode that refuses a download leg), and a server that is not XHTTP', () => {
  for (const server of [XONE, VLESS]) {
    const cfg = build({ mode: 'single', server }, { multiWan: mwOf({ mode: 'split' }) });
    assert.equal(find(cfg, 'proxy').protocol, 'loopback', server.name);
    assert.deepEqual(members(cfg, 'proxy').map(iface), ['Wi-Fi', 'Ethernet 2', 'Wi-Fi'], `${server.name}: up and down at their weights`);
    assert.equal(find(cfg, 'proxy~fb'), undefined, 'the backup link is not part of a split');
    assert.equal(json(cfg).includes('downloadSettings'), false);
    assert.equal(cfg.multiWanSplit, null);
  }
  assert.equal(M.splittable(XONE.outbound), false);
  assert.equal(M.splittable(VLESS.outbound), false);
  assert.equal(M.splittable(XTLS.outbound), true);
});

/* -------------------------------- groups, chains, the pool -------------------------------- */
const byId = { 'sv-vless': VLESS, 'sv-trojan': TROJAN, 'sv-wgcorp': F.WG_CORP, 'sv-xtls': XTLS };
const groupOf = (members, fallback) => G.groupRecord(Object.assign({ id: 'grp-g', name: 'G', members }, fallback ? { fallback } : {}), byId);

test('a group plan: each member a copy per link (× weight), ids <member>#<link>; its own fallback kept; a WireGuard member left as it is; no fallback of its own → its first member on the backup link', () => {
  const cfg = build({ mode: 'single', server: groupOf(['sv-vless', 'sv-trojan', 'sv-wgcorp'], 'sv-xtls') }, { multiWan: mwOf() });
  const ids = cfg.groupTags[0].members.map((m) => m.id);
  assert.deepEqual(ids, ['sv-vless#Wi-Fi', 'sv-vless#Ethernet 2', 'sv-vless#Wi-Fi', 'sv-trojan#Wi-Fi', 'sv-trojan#Ethernet 2', 'sv-trojan#Wi-Fi', 'sv-wgcorp']);
  assert.equal(cfg.groupTags[0].groupId, 'grp-g', 'the same group');
  assert.equal(cfg.groupTags[0].name, 'G');
  assert.deepEqual(cfg.groupTags[0].members.slice(0, 2).map((m) => m.name), ['VLESS WS · Home', 'VLESS WS · Phone']);
  assert.deepEqual(members(cfg, 'proxy').map(iface), ['Wi-Fi', 'Ethernet 2', 'Wi-Fi', 'Wi-Fi', 'Ethernet 2', 'Wi-Fi', undefined]);
  assert.equal(find(cfg, 'proxy~gm6').protocol, 'wireguard');
  // its own fallback, unbound, as before
  assert.deepEqual(cfg.groupTags[0].fallback, { id: 'sv-xtls', name: 'XHTTP TLS' });
  assert.equal(iface(find(cfg, 'proxy~fb')), undefined);
  // none of its own: its first member on the backup link
  const nf = build({ mode: 'single', server: groupOf(['sv-vless', 'sv-trojan']) }, { multiWan: mwOf() });
  assert.deepEqual(nf.groupTags[0].fallback, { id: 'sv-vless#eth9', name: 'VLESS WS · Spare' });
  assert.equal(iface(find(nf, 'proxy~fb')), 'eth9');
  // failover: each member on the first link once; the fallback the first member on the next
  const fo = build({ mode: 'single', server: groupOf(['sv-vless', 'sv-trojan']) }, { multiWan: mwOf({ mode: 'failover' }) });
  assert.deepEqual(fo.groupTags[0].members.map((m) => m.id), ['sv-vless#Wi-Fi', 'sv-trojan#Wi-Fi']);
  assert.equal(fo.groupTags[0].fallback.id, 'sv-vless#Ethernet 2');
  // split: the XHTTP member split in place (its id kept), the others over up and down
  const sp = build({ mode: 'single', server: groupOf(['sv-xtls', 'sv-trojan']) }, { multiWan: mwOf({ mode: 'split' }) });
  assert.deepEqual(sp.groupTags[0].members.map((m) => m.id), ['sv-xtls', 'sv-trojan#Wi-Fi', 'sv-trojan#Ethernet 2', 'sv-trojan#Wi-Fi']);
  assert.equal(find(sp, 'proxy~gm0').streamSettings.xhttpSettings.extra.downloadSettings.sockopt.interface, 'Ethernet 2');
  assert.deepEqual(sp.multiWanSplit, [{ tag: 'proxy~gm0', up: 'Wi-Fi', down: 'Ethernet 2' }]);
});

test('a group member the app set aside for not answering (groupSkip) stays out — never back as a copy per link; unless none would be left', () => {
  const g = groupOf(['sv-vless', 'sv-trojan']);
  const [, trojan] = g.outbound._group.members;
  const key = B.groupMemberKey('grp-g', trojan);
  const cfg = build({ mode: 'single', server: g }, { multiWan: mwOf(), groupSkip: [key] });
  assert.deepEqual(cfg.groupTags[0].members.map((m) => m.id), ['sv-vless#Wi-Fi', 'sv-vless#Ethernet 2', 'sv-vless#Wi-Fi']);
  const both = build({ mode: 'single', server: g }, { multiWan: mwOf(), groupSkip: [key, B.groupMemberKey('grp-g', g.outbound._group.members[0])] });
  assert.equal(both.groupTags[0].members.length, 6, 'every one set aside: all of them, as expandGroups does');
});

test('a chain plan is left exactly as it was — a TCP hop never dials a loopback; a group inside a chain too', () => {
  const g = groupOf(['sv-vless', 'sv-trojan']);
  for (const chain of [[VLESS, TROJAN], [TROJAN, VLESS, F.SS_TCP], [g, VLESS], [VLESS, g], [g, F.WG_CORP]]) {
    const off = build({ mode: 'chain', chain }, {});
    const on = build({ mode: 'chain', chain }, { multiWan: mwOf() });
    assert.equal(json(on), json(off), chain.map((s) => s.name).join(' → '));
  }
});

test('advanced routing: each server target over the links; a base stays one outbound (the targets dial it), its targets behind it untouched', () => {
  const plan = {
    mode: 'advanced', serversById: byId, chainsById: { c1: [VLESS, TROJAN] }, chain: [],
    rules: [{ type: 'domain', value: 'a.com', target: 'sv-trojan' }, { type: 'domain', value: 'b.com', target: 'sv-xtls', via: 'sv-vless' }, { type: 'ip', value: '10.0.0.0/8', target: 'chain:c1' }],
    def: 'sv-vless'
  };
  const cfg = build(plan, { multiWan: mwOf() });
  assert.equal(find(cfg, 'out-sv-trojan').protocol, 'loopback');
  assert.equal(find(cfg, 'out-sv-vless').protocol, 'loopback');
  assert.deepEqual(members(cfg, 'out-sv-trojan').map(iface), ['Wi-Fi', 'Ethernet 2', 'Wi-Fi']);
  assert.equal(cfg.groupTags.find((g) => g.tag === 'out-sv-trojan').name, 'Trojan');
  assert.equal(find(cfg, 'base-sv-vless').protocol, 'vless');
  assert.equal(iface(find(cfg, 'base-sv-vless')), undefined);
  assert.equal(dials(find(cfg, 'out-sv-xtls@sv-vless')), 'base-sv-vless');
  assert.equal(dials(find(cfg, 'out-chain-c1')), 'out-chain-c1-h0');
  assert.equal(find(cfg, 'out-chain-c1-h0').protocol, 'vless');
  const loops = new Set(cfg.outbounds.filter((o) => o.protocol === 'loopback').map((o) => o.tag));
  assert.equal(cfg.outbounds.some((o) => loops.has(dials(o))), false, 'nothing dials a loopback');
});

test('the pool: each entry\'s exit and the primary over the links; the standard ports still routed to the primary', () => {
  const plan = { mode: 'pool', entries: [{ id: 'e1', target: 'sv-trojan', socksPort: 41090, httpPort: 0 }], primary: 'sv-vless', serversById: byId, chainsById: {}, chain: [] };
  const cfg = build(plan, { multiWan: mwOf(), apiPort: 41099 });
  assert.equal(find(cfg, 'out-sv-vless').protocol, 'loopback');
  assert.deepEqual(members(cfg, 'out-sv-trojan').map(iface), ['Wi-Fi', 'Ethernet 2', 'Wi-Fi']);
  assert.deepEqual(cfg.routing.balancers.map((b) => b.tag).sort(), ['out-sv-trojan~bal', 'out-sv-vless~bal']);
  assert.ok(cfg.routing.rules.some((r) => r.outboundTag === 'out-sv-vless' && (r.inboundTag || []).includes('socks-in')));
  assert.ok(cfg.observatory);
  const sp = B.buildConfig({ mode: 'pool', entries: [], primary: 'sv-xtls', serversById: byId, chainsById: {}, chain: [] }, F.settings({ multiWan: mwOf({ mode: 'split' }), apiPort: 41099 }));
  assert.deepEqual(sp.multiWanSplit, [{ tag: 'out-sv-xtls', up: 'Wi-Fi', down: 'Ethernet 2' }]);
});

/* ------------------------------ the health check over the links ------------------------------ */
test('a share is written as the fewest copies that give it — every copy is a probe on its link: 2:2 (the default) and 3:3 are one copy a link, 3:2 stays five', () => {
  const at = (...weights) => members(build({ mode: 'single', server: VLESS },
    { multiWan: mwOf({ links: weights.map((w, i) => ({ id: 'l' + i, role: 'use', weight: w })) }) }), 'proxy').map(iface);
  assert.deepEqual(at(2, 2), ['l0', 'l1']);
  assert.deepEqual(at(3, 3), ['l0', 'l1']);
  assert.deepEqual(at(1, 1), ['l0', 'l1']);
  assert.deepEqual(at(2, 2, 2), ['l0', 'l1', 'l2']);
  assert.deepEqual(at(2, 1), ['l0', 'l1', 'l0'], 'no common factor: as before, interleaved');
  assert.deepEqual(at(3, 1), ['l0', 'l1', 'l0', 'l0']);
  assert.deepEqual(at(3, 2), ['l0', 'l1', 'l0', 'l1', 'l0']);
  // no weight given: the default 2 on each link, one copy each
  assert.deepEqual(members(build({ mode: 'single', server: VLESS }, { multiWan: mwOf({ links: [{ id: 'a' }, { id: 'b' }, { id: 'c', role: 'backup' }] }) }), 'proxy').map(iface), ['a', 'b']);
  // a group the plan runs: one copy of each member a link
  const g = build({ mode: 'single', server: groupOf(['sv-vless', 'sv-trojan']) }, { multiWan: mwOf({ links: [{ id: 'a', weight: 2 }, { id: 'b', weight: 2 }] }) });
  assert.deepEqual(g.groupTags[0].members.map((m) => m.id), ['sv-vless#a', 'sv-vless#b', 'sv-trojan#a', 'sv-trojan#b']);
  // split's fallback to balance over the up and the down: the same rule
  const sp = build({ mode: 'single', server: XONE }, { multiWan: mwOf({ mode: 'split', links: [{ id: 'a', weight: 3 }, { id: 'b', weight: 3 }], split: { up: 'a', down: 'b' } }) });
  assert.deepEqual(members(sp, 'proxy').map(iface), ['a', 'b']);
});

test('the health check over the links asks every 30 s — every 60 s while a probed copy rides a capped link; a capped backup (never probed) or a link set aside for its cap does not count; without multi-internet 10 s as before', () => {
  const cap = (l, over) => Object.assign({}, l, { quotaGb: 5, quotaPeriod: 'month' }, over);
  const every = (plan, mw, over) => {
    const c = build(plan, Object.assign({ multiWan: mw }, over));
    return c.observatory ? c.observatory.probeInterval : null;
  };
  const one = { mode: 'single', server: VLESS };
  assert.deepEqual([M.PROBE_EVERY_S, M.PROBE_EVERY_CAPPED_S], [30, 60]);
  assert.equal(every(one, mwOf()), '30s');
  assert.equal(every(one, mwOf({ links: [LINKS[0], cap(LINKS[1]), LINKS[2]] })), '60s', 'a use link with a monthly cap');
  assert.equal(every(one, mwOf({ links: [LINKS[0], cap(LINKS[1], { quotaGb: 1, quotaPeriod: 'day' })] })), '60s', 'a daily cap');
  assert.equal(every(one, mwOf({ links: [LINKS[0], cap(LINKS[1], { quotaPeriod: 'none' })] })), '30s', 'GB with no period to count them in is no cap (the meter’s capBytes)');
  assert.equal(every(one, mwOf({ links: [LINKS[0], LINKS[1], cap(LINKS[2])] })), '30s', 'the capped link is the backup: the fallback, never probed');
  assert.equal(every(one, mwOf({ links: [LINKS[0], cap(LINKS[1])] }), { multiWanSkip: ['Ethernet 2'] }), '30s', 'over its cap and set aside: no copy rides it');
  // failover: only the primary is probed
  assert.equal(every(one, mwOf({ mode: 'failover', links: [cap(LINKS[0]), LINKS[1]] })), '60s');
  assert.equal(every(one, mwOf({ mode: 'failover', links: [LINKS[0], cap(LINKS[1])] })), '30s');
  // split: an XHTTP split in place is no group (nothing probed); one that cannot split is balanced over both legs
  assert.equal(every({ mode: 'single', server: XTLS }, mwOf({ mode: 'split', links: [LINKS[0], cap(LINKS[1])] })), null);
  assert.equal(every({ mode: 'single', server: XONE }, mwOf({ mode: 'split', links: [LINKS[0], cap(LINKS[1])] })), '60s');
  // a group the plan runs, its members multiplied; the pool's groups
  const g = groupOf(['sv-vless', 'sv-trojan']);
  assert.equal(every({ mode: 'single', server: g }, mwOf()), '30s');
  assert.equal(every({ mode: 'single', server: g }, mwOf({ links: [cap(LINKS[0]), LINKS[1]] })), '60s');
  assert.equal(B.buildConfig({ mode: 'pool', entries: [{ id: 'e1', target: 'sv-trojan', socksPort: 41090, httpPort: 0 }], primary: 'sv-vless', serversById: byId, chainsById: {}, chain: [] },
    F.settings({ multiWan: mwOf({ links: [cap(LINKS[0]), LINKS[1]] }), apiPort: 41099 })).observatory.probeInterval, '60s');
  // one observatory for the config: a group the links leave alone (inside a chain) is asked as often as the rest
  const adv = build({ mode: 'advanced', serversById: byId, chainsById: { c1: [g, TROJAN] }, chain: [], rules: [{ type: 'ip', value: '10.0.0.0/8', target: 'chain:c1' }], def: 'sv-vless' }, { multiWan: mwOf() });
  assert.deepEqual(adv.observatory.subjectSelector, ['out-chain-c1~gm', 'out-sv-vless~gm']);
  assert.deepEqual(adv.groupTags[0].members.map((m) => m.id), ['sv-vless', 'sv-trojan'], 'the chain’s group, not over the links');
  assert.equal(adv.observatory.probeInterval, '30s');
  // no multi-internet (off, or nothing to combine): the 10 s groups always had, and the marker never reaches the core
  assert.equal(every({ mode: 'single', server: g }, undefined), '10s');
  assert.equal(every({ mode: 'single', server: g }, mwOf({ enabled: false })), '10s');
  assert.equal(every({ mode: 'single', server: g }, mwOf({ links: [LINKS[0]] })), '10s');
  for (const c of [build(one, { multiWan: mwOf() }), build({ mode: 'single', server: g }, { multiWan: mwOf() }), adv]) {
    assert.equal(json(c).includes('probeEvery'), false);
  }
});

/* ------------------------------ dialers, TUN, WireGuard ------------------------------ */
test('the anti-DPI dialer: each member dials one bound to its link\'s interface — one dialer per interface, the member itself unbound', () => {
  const frag = F.vlessWithMarkers('sv-frag', { _fragment: 'tlshello,100-200,10-20' });
  const cfg = build({ mode: 'single', server: frag }, { multiWan: mwOf() });
  const ms = members(cfg, 'proxy');
  assert.deepEqual(ms.map(dials), ['dpi-1', 'dpi-2', 'dpi-1']);
  assert.deepEqual(ms.map(iface), [undefined, undefined, undefined]);
  assert.equal(dials(find(cfg, 'proxy~fb')), 'dpi-3');
  const dpi = cfg.outbounds.filter((o) => /^dpi-/.test(o.tag));
  assert.deepEqual(dpi.map((o) => [o.tag, iface(o), !!o.settings.fragment]), [['dpi-1', 'Wi-Fi', true], ['dpi-2', 'Ethernet 2', true], ['dpi-3', 'eth9', true]]);
  assert.equal(json(cfg).includes('_fragment'), false);
  // with it off: one shared dialer, no interface, exactly as before
  const off = build({ mode: 'single', server: frag }, {});
  assert.deepEqual(off.outbounds.filter((o) => /^dpi-/.test(o.tag)).map((o) => [o.tag, o.streamSettings]), [['dpi-1', undefined]]);
});

test('under TUN the NIC binding leaves the links alone: members and their dialers keep their own interface, everything else that dials itself is bound as before; a WireGuard is never copied', () => {
  const frag = F.vlessWithMarkers('sv-frag', { _fragment: 'tlshello,100-200,10-20' });
  const cfg = build({ mode: 'single', server: frag }, { multiWan: mwOf(), tunMode: true, directInterface: 'Wi-Fi' });
  assert.deepEqual(cfg.outbounds.filter((o) => /^dpi-/.test(o.tag)).map(iface), ['Wi-Fi', 'Ethernet 2', 'eth9']);
  assert.equal(iface(find(cfg, 'direct')), 'Wi-Fi');
  const plain = build({ mode: 'single', server: VLESS }, { multiWan: mwOf(), tunMode: true, directInterface: 'eth0' });
  assert.deepEqual(members(plain, 'proxy').map(iface), ['Wi-Fi', 'Ethernet 2', 'Wi-Fi']);
  assert.equal(iface(find(plain, 'proxy~fb')), 'eth9');
  assert.equal(iface(find(plain, 'direct')), 'eth0');
  // a WireGuard: one key is one session — dialled once, as without multi-internet (by the default route / the NIC under TUN)
  for (const over of [{}, { tunMode: true, directInterface: 'eth0' }]) {
    assert.equal(json(build({ mode: 'single', server: F.WG_CORP }, Object.assign({ multiWan: mwOf() }, over))), json(build({ mode: 'single', server: F.WG_CORP }, over)));
  }
  // a raw config's own binding is kept under TUN too
  const raw = { id: 'r', name: 'R', source: 'json', jsonMode: 'raw', outbound: { protocol: 'freedom' },
    json: { outbounds: [{ tag: 'out', protocol: 'freedom', streamSettings: { sockopt: { interface: 'usb0' } } }, { tag: 'other', protocol: 'freedom' }] } };
  const rc = B.buildRawConfig(raw, F.settings({ directInterface: 'eth0' }));
  assert.deepEqual(rc.outbounds.map(iface), ['usb0', 'eth0']);
});

test('off, or with nothing to combine, every config is byte-identical to one built without the setting', () => {
  const g = groupOf(['sv-vless', 'sv-trojan']);
  const plans = [
    { mode: 'single', server: VLESS }, { mode: 'single', server: XTLS }, { mode: 'single', server: g },
    { mode: 'single', server: F.vlessWithMarkers('sv-frag', { _fragment: 'tlshello', _noise: 'faketls' }) },
    { mode: 'chain', chain: [VLESS, TROJAN] },
    { mode: 'advanced', serversById: byId, chainsById: {}, chain: [], rules: [{ type: 'domain', value: 'a.com', target: 'sv-trojan' }], def: 'sv-vless' },
    { mode: 'pool', entries: [{ id: 'e1', target: 'sv-trojan', socksPort: 41090 }], primary: 'sv-vless', serversById: byId, chainsById: {}, chain: [] }
  ];
  const offs = [
    { enabled: false, mode: 'balance', links: LINKS },
    { enabled: true, mode: 'balance', links: [LINKS[0]] },
    { enabled: true, mode: 'split', links: LINKS, split: { up: 'Wi-Fi', down: 'Wi-Fi' } },
    { enabled: true, links: LINKS.map((l) => Object.assign({}, l, { role: 'off' })) },
    undefined, null, 'junk'
  ];
  for (const plan of plans) {
    for (const extra of [{}, { tunMode: true, directInterface: 'Wi-Fi', entryHostIps: { 'a.example.com': ['203.0.113.10'] } }]) {
      const base = build(plan, extra);
      for (const mw of offs) {
        const cfg = build(plan, Object.assign({ multiWan: mw }, extra));
        assert.equal(json(cfg), json(base), `${plan.mode} ${JSON.stringify(mw)}`);
        assert.equal(cfg.multiWanSplit, null);
      }
    }
  }
});

/* ------------------------------------ counting ------------------------------------ */
test('linkOfMemberId: what follows the #, nothing for any other member', () => {
  assert.equal(M.linkOfMemberId('sv-vless#Wi-Fi'), 'Wi-Fi');
  assert.equal(M.linkOfMemberId('proxy#Ethernet 2'), 'Ethernet 2');
  assert.equal(M.linkOfMemberId('sv-vless'), '');
  assert.equal(M.linkOfMemberId(''), '');
  assert.equal(M.linkOfMemberId(undefined), '');
  assert.equal(M.linkOfMemberId('ab12#Ethernet #2'), 'Ethernet #2', 'an adapter renamed with a # in it');
  // the id taken apart, the one way the meter and the window both read it
  assert.deepEqual(M.memberIdParts('sv-vless#Wi-Fi'), { server: 'sv-vless', link: 'Wi-Fi' });
  assert.deepEqual(M.memberIdParts('ab12#Ethernet #2'), { server: 'ab12', link: 'Ethernet #2' });
  for (const id of ['sv-vless', '', undefined, null]) assert.equal(M.memberIdParts(id), null, String(id));
});

test('the live payload names a server’s copies on each internet — serverId and link, from the same reading of the id; an ordinary member as before', () => {
  const cfg = build({ mode: 'single', server: VLESS }, { multiWan: mwOf() });
  const live = S.groupsLive(cfg.groupTags, {}, {}, { 'proxy~gm1': { alive: true, delay: 80 } }, 1);
  assert.deepEqual(live[0].members.map((m) => [m.id, m.serverId, m.link, m.alive]), [
    ['sv-vless#Wi-Fi', 'sv-vless', 'Wi-Fi', null], ['sv-vless#Ethernet 2', 'sv-vless', 'Ethernet 2', true], ['sv-vless#Wi-Fi', 'sv-vless', 'Wi-Fi', null]]);
  const g = build({ mode: 'single', server: groupOf(['sv-vless', 'sv-trojan']) }, {});
  for (const m of S.groupsLive(g.groupTags, {}, {}, {}, 1)[0].members) assert.equal('serverId' in m || 'link' in m, false, m.id);
});

test('linkUsage: each link\'s bytes from the raw counters and the running groups — members by their #link, the fallback, a split\'s uplink on its up and downlink on its down; other groups and tags left out', () => {
  const cfg = build({ mode: 'single', server: VLESS }, { multiWan: mwOf() });
  const raw = {
    proxy: { uplink: 0, downlink: 0 },
    'proxy~gm0': { uplink: 100, downlink: 1000 }, 'proxy~gm1': { uplink: 10, downlink: 20 }, 'proxy~gm2': { uplink: 1, downlink: 2 },
    'proxy~fb': { uplink: 5, downlink: 50 }, 'dpi-1': { uplink: 999, downlink: 999 }, direct: { uplink: 7, downlink: 7 }
  };
  assert.deepEqual(M.linkUsage(raw, cfg.groupTags), { 'Wi-Fi': { up: 101, down: 1002 }, 'Ethernet 2': { up: 10, down: 20 }, eth9: { up: 5, down: 50 } });
  // every link the groups dial, before a byte has gone
  assert.deepEqual(M.linkUsage({}, cfg.groupTags), { 'Wi-Fi': { up: 0, down: 0 }, 'Ethernet 2': { up: 0, down: 0 }, eth9: { up: 0, down: 0 } });
  // an ordinary group's members name no link; a split counts by its legs
  const map = [{ tag: 'out-grp', members: [{ id: 'de' }, { id: 'de#usb0' }], fallback: { id: 'warp' } }];
  const split = [{ tag: 'proxy', up: 'Wi-Fi', down: 'Ethernet 2' }];
  assert.deepEqual(M.linkUsage({ 'out-grp~gm0': { uplink: 3, downlink: 3 }, 'out-grp~gm1': { uplink: 4, downlink: 40 }, 'out-grp~fb': { uplink: 9, downlink: 9 }, proxy: { uplink: 60, downlink: 600 } }, map, split),
    { usb0: { up: 4, down: 40 }, 'Wi-Fi': { up: 60, down: 0 }, 'Ethernet 2': { up: 0, down: 600 } });
  assert.deepEqual(M.linkUsage(null, null), {});
  assert.deepEqual(M.linkUsage({ x: 1 }, [null, { members: [{ id: 'a#b' }] }], [null]), {});
});

test('the meter still counts the server once: its link copies (and the backup) folded into its tag', () => {
  const vars = { stats: { outbound: { proxy: { uplink: 0, downlink: 0 }, 'proxy~gm0': { uplink: 100, downlink: 1000 }, 'proxy~gm1': { uplink: 10, downlink: 20 }, 'proxy~fb': { uplink: 5, downlink: 50 }, 'dpi-1': { uplink: 99, downlink: 99 } } } };
  assert.deepEqual(S.sumOutbounds(vars), { up: 115, down: 1070 });
  assert.deepEqual(S.byOutbound(vars), { proxy: { up: 115, down: 1070 } });
  const cfg = build({ mode: 'single', server: VLESS }, { multiWan: mwOf() });
  const live = S.groupsLive(cfg.groupTags, S.memberCounters(vars), {}, {}, 1);
  assert.deepEqual(live[0].members.map((m) => [m.name, m.down]), [['VLESS WS · Home', 1000], ['VLESS WS · Phone', 20], ['VLESS WS · Home', 0]]);
});

test('applyMultiWan on its own: the list as it was when nothing applies, the records named by opts.servers, a tag without one named by its tag', () => {
  const outs = [{ tag: 'proxy', protocol: 'vless', settings: { vnext: [{ address: 'z.example', port: 8443, users: [] }] } }, { tag: 'direct', protocol: 'freedom', settings: {} }];
  assert.equal(M.applyMultiWan(outs, { enabled: false }), outs);
  const two = mwOf({ links: LINKS.slice(0, 2) });
  const [g] = M.applyMultiWan(outs, two);
  assert.deepEqual([g.tag, g.protocol, g._group.id, g._group.name], ['proxy', 'loopback', 'mw:proxy', 'proxy']);
  assert.deepEqual(g._group.members.map((m) => [m.id, m.name, m.address, m.port, m.outbound.streamSettings.sockopt.interface, 'tag' in m.outbound]),
    [['proxy#Wi-Fi', 'proxy · Home', 'z.example', 8443, 'Wi-Fi', false], ['proxy#Ethernet 2', 'proxy · Phone', 'z.example', 8443, 'Ethernet 2', false], ['proxy#Wi-Fi', 'proxy · Home', 'z.example', 8443, 'Wi-Fi', false]]);
  assert.equal(outs[0].protocol, 'vless', 'the input untouched');
  const [named] = M.applyMultiWan(outs, two, [], { servers: { proxy: { id: 'abc', name: 'Mine', address: 'z.example', port: 8443 } } });
  assert.equal(named._group.members[0].id, 'abc#Wi-Fi');
  // left alone: a hop (named by another's dialerProxy), one dialling through something, a helper, one bound already, a WireGuard
  const left = [
    { tag: 'hop', protocol: 'vless', settings: {} },
    { tag: 'exit', protocol: 'trojan', settings: {}, streamSettings: { sockopt: { dialerProxy: 'hop' } } },
    { tag: 'x~h', protocol: 'vless', settings: {} },
    { tag: 'bound', protocol: 'vless', settings: {}, streamSettings: { sockopt: { interface: 'usb0' } } },
    { tag: 'wg', protocol: 'wireguard', settings: {} }
  ];
  assert.deepEqual(M.applyMultiWan(left, two), left);
});
