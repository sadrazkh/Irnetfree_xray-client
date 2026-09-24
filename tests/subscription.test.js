'use strict';
/**
 * Subscription refresh.
 *
 * Everything the app keeps about a server refers to it by id: the connected and
 * the last server, a chain's members, a pool entry, an advanced-routing rule
 * and its default, the usage meter. A refresh re-parses the whole list, and the
 * parser gives every server a brand-new random id — so each hourly refresh used
 * to leave all of those pointing at nothing (a network-change recovery then
 * failed with "Server not found", an advanced rule quietly went `direct`), and
 * wiped what the user had set on the server itself. These pin the refresh down:
 * the same server keeps its id and the user's own settings; only what the
 * provider changed changes.
 */
const test = require('node:test');
const assert = require('node:assert/strict');

const { SubscriptionManager, reconcileServers } = require('../src/main/subscription');
const { parseMany, parseLink } = require('../src/main/parser');
const { buildConfig } = require('../src/main/configBuilder');
const F = require('./fixtures');

const b64 = (s) => Buffer.from(s, 'utf8').toString('base64');
const vmessLink = (o) => 'vmess://' + b64(JSON.stringify(Object.assign({ v: '2', add: 'vm.example.com', port: '443', id: 'uuid-vm', aid: '0', net: 'ws', path: '/vm', host: 'vm.example.com', tls: 'tls', sni: 'vm.example.com' }, o)));

const XH = 'vless://11111111-2222-3333-4444-555555555555@x.example.com:443?type=xhttp&security=reality&sni=www.speedtest.net&fp=chrome&pbk=PUBKEY&sid=ab12&path=%2Fxh&mode=auto&encryption=none';
const TR = 'trojan://pw@t.example.com:443?security=tls&sni=t.example.com&type=ws&path=%2Ftr&host=t.example.com';

/** Parse a subscription body the way fetchSubscription does. */
function sub(lines, subId = 'sub1') {
  const { servers } = parseMany(lines.join('\n'));
  for (const s of servers) s.subId = subId;
  return servers;
}

/** An in-memory store and a manager whose fetch returns what the test says. */
function harness({ servers = [], subs = [{ id: 'sub1', name: 'S', url: 'https://sub.example/x', autoUpdate: true }], bodies }) {
  const store = { servers, subs };
  const queue = bodies.slice();
  const updates = [];
  const mgr = new SubscriptionManager({
    getSubs: () => JSON.parse(JSON.stringify(store.subs)),
    setSubs: (a) => { store.subs = a; },
    getServers: () => JSON.parse(JSON.stringify(store.servers)),
    setServers: (a) => { store.servers = a; },
    onUpdate: (s, info) => updates.push(info),
    fetch: async (url, subId) => {
      const body = queue.shift();
      if (body instanceof Error) throw body;
      const { servers: fresh, errors } = parseMany(body);
      for (const s of fresh) s.subId = subId;
      return { servers: fresh, errors, usage: null };
    }
  });
  return { store, mgr, updates };
}

/* ------------------------------ reconcileServers ------------------------------ */

test('the very same link keeps its id', () => {
  const old = sub([XH + '#DE-1', TR + '#NL-1']);
  const fresh = sub([XH + '#DE-1', TR + '#NL-1']);
  assert.notEqual(fresh[0].id, old[0].id, 'the parser alone gives new ids — this is what the refresh has to undo');
  const next = reconcileServers(old, fresh);
  assert.deepEqual(next.map(s => s.id), old.map(s => s.id));
});

test('a changed remark (the panel writes the traffic left into it) keeps the id and takes the new name', () => {
  const old = sub([XH + '#DE-1%20%7C%2012GB', TR + '#NL-1%20%7C%2012GB']);
  const next = reconcileServers(old, sub([XH + '#DE-1%20%7C%2011GB', TR + '#NL-1%20%7C%2011GB']));
  assert.deepEqual(next.map(s => s.id), old.map(s => s.id));
  assert.deepEqual(next.map(s => s.name), ['DE-1 | 11GB', 'NL-1 | 11GB']);
});

test('a vmess server whose ps changed is matched by what it connects to', () => {
  const old = sub([vmessLink({ ps: 'A 12GB' })]);
  const next = reconcileServers(old, sub([vmessLink({ ps: 'A 11GB' })]));
  assert.equal(next[0].id, old[0].id);
  assert.equal(next[0].name, 'A 11GB');
});

test('the same server with a new SNI / fingerprint keeps its id, and the provider’s new values win', () => {
  const old = sub([XH + '#DE']);
  const moved = XH.replace('sni=www.speedtest.net', 'sni=www.microsoft.com').replace('fp=chrome', 'fp=firefox');
  const next = reconcileServers(old, sub([moved + '#DE']));
  assert.equal(next[0].id, old[0].id);
  assert.equal(next[0].outbound.streamSettings.realitySettings.serverName, 'www.microsoft.com');
  assert.equal(next[0].outbound.streamSettings.realitySettings.fingerprint, 'firefox');
  assert.equal(next[0].raw, moved + '#DE');
});

test('a different server is a new server: new credential, address, port, transport or path', () => {
  const old = sub([XH + '#DE']);
  for (const other of [
    XH.replace('11111111-2222', '99999999-2222'),
    XH.replace('x.example.com', 'y.example.com'),
    XH.replace(':443?', ':8443?'),
    XH.replace('type=xhttp', 'type=ws'),
    XH.replace('path=%2Fxh', 'path=%2Fother')
  ]) {
    const next = reconcileServers(old, sub([other + '#DE']));
    assert.notEqual(next[0].id, old[0].id, other);
  }
});

test('servers that left the subscription go, new ones get their own fresh id', () => {
  const old = sub([XH + '#DE', TR + '#NL']);
  const extra = 'vless://uuid-new@n.example.com:443?security=tls#NEW';
  const fresh = sub([TR + '#NL', extra]);
  const newId = fresh[1].id;
  const next = reconcileServers(old, fresh);
  assert.deepEqual(next.map(s => s.id), [old[1].id, newId]);
});

test('duplicates in the fresh list never both claim one old id', () => {
  const old = sub([XH + '#DE']);
  const next = reconcileServers(old, sub([XH + '#DE', XH + '#DE']));
  assert.equal(next[0].id, old[0].id);
  assert.notEqual(next[1].id, old[0].id);
  assert.equal(new Set(next.map(s => s.id)).size, 2);
});

test('several servers sharing one identity are paired in order, one old id each', () => {
  // the same uuid/address/path twice, told apart only by the SNI — and the
  // remarks changed, so neither link matches exactly
  const a = XH.replace('sni=www.speedtest.net', 'sni=a.example');
  const b = XH.replace('sni=www.speedtest.net', 'sni=b.example');
  const old = sub([a + '#one', b + '#two']);
  const next = reconcileServers(old, sub([a + '#one*', b + '#two*']));
  assert.deepEqual(next.map(s => s.id), old.map(s => s.id));
  // an exact link beats an identity match even when it comes later in the list
  const swapped = reconcileServers(old, sub([XH + '#third', b + '#two']));
  assert.equal(swapped[1].id, old[1].id, 'b matched its own link exactly');
  assert.equal(swapped[0].id, old[0].id, 'the identity match takes what is left');
});

test('the user’s own settings on a server survive the refresh', () => {
  const [old] = sub([XH + '#DE']);
  old.engine = 'xray-pattn';
  old.outbound._fragment = 'tlshello,100-200,10-20';
  old.outbound._noise = 'faketls';
  old.outbound.streamSettings.finalmask = { tcp: [{ type: 'fragment', settings: { packets: 'tlshello', lengths: ['100-200'], delays: ['10-20'] } }] };
  old.certPin = 'ab11bf7ac877baa539294f5a3c864b8ed43e6fe3a9a8230fc2db7fff85c27fde';
  old.certPinAt = '2026-09-24T10:00:00.000Z';
  old.certPinCheckedAt = 1790000000000;
  old.name = 'My exit';   // renamed by the user

  const [next] = reconcileServers([old], sub([XH + '#DE%20%7C%209GB']));
  assert.equal(next.id, old.id);
  assert.equal(next.engine, 'xray-pattn');
  assert.equal(next.outbound._fragment, 'tlshello,100-200,10-20');
  assert.equal(next.outbound._noise, 'faketls');
  assert.deepEqual(next.outbound.streamSettings.finalmask, old.outbound.streamSettings.finalmask);
  assert.equal(next.certPin, old.certPin);
  assert.equal(next.certPinAt, old.certPinAt);
  assert.equal(next.certPinCheckedAt, old.certPinCheckedAt);
  assert.equal(next.name, 'My exit', 'a rename is the user’s');
  assert.equal(next.subId, 'sub1');
  assert.equal(next.raw, XH + '#DE%20%7C%209GB', 'the link itself is the provider’s');
});

test('cipherSuites edited on a TLS server survive; a WireGuard server keeps its edited DNS', () => {
  const tls = 'vless://u@c.example.com:443?security=tls&sni=c.example.com&fp=unsafe#C';
  const [old] = sub([tls]);
  old.outbound.streamSettings.tlsSettings.cipherSuites = 'TLS_AES_128_GCM_SHA256';
  const [next] = reconcileServers([old], sub([tls]));
  assert.equal(next.outbound.streamSettings.tlsSettings.cipherSuites, 'TLS_AES_128_GCM_SHA256');

  const wg = 'wireguard://K@wg.example.com:51820?publickey=P&address=10.0.0.5%2F32#W';
  const [ow] = sub([wg]);
  ow.dns = ['192.168.60.1']; ow.dnsDomains = ['tes.systems'];
  const [nw] = reconcileServers([ow], sub([wg]));
  assert.equal(nw.id, ow.id);
  assert.deepEqual(nw.dns, ['192.168.60.1']);
  assert.deepEqual(nw.dnsDomains, ['tes.systems']);
});

test('what the user did not touch follows the provider — a new fragment, name or engine in the link goes through', () => {
  const [old] = sub([XH + '&fragment=tlshello,1-2,1-2&engine=xray-pattn#DE']);
  const [next] = reconcileServers([old], sub([XH + '&fragment=tlshello,5-9,5-9#DE-renamed']));
  assert.equal(next.id, old.id);
  assert.equal(next.outbound._fragment, 'tlshello,5-9,5-9', 'the provider changed its own fragment');
  assert.equal(next.name, 'DE-renamed', 'the provider renamed a server the user never renamed');
  assert.equal('engine' in next, false, 'the provider dropped its engine hint');
});

test('a setting the user cleared stays cleared', () => {
  const [old] = sub([XH + '&fragment=tlshello,1-2,1-2#DE']);
  delete old.outbound._fragment;   // "Hide SNI" switched off in the edit form
  const [next] = reconcileServers([old], sub([XH + '&fragment=tlshello,1-2,1-2#DE']));
  assert.equal('_fragment' in next.outbound, false);
});

test('an old server whose link no longer parses still hands over its id and settings', () => {
  const [old] = sub([XH + '#DE']);
  const odd = Object.assign({}, old, { raw: 'not a link', engine: 'xray-pattn' });
  const [next] = reconcileServers([odd], sub([XH + '#DE-2']));
  assert.equal(next.id, old.id, 'matched by identity');
  assert.equal(next.engine, 'xray-pattn', 'without the old link to compare with, what the old record had is kept');
  assert.equal(next.name, 'DE-2', 'a rename cannot be proven, so the provider’s name is taken');
});

test('reconcileServers is pure', () => {
  const old = sub([XH + '#DE']);
  old[0].engine = 'xray-pattn';
  const fresh = sub([XH + '#DE2']);
  const o = JSON.stringify(old), f = JSON.stringify(fresh);
  reconcileServers(old, fresh);
  assert.equal(JSON.stringify(old), o);
  assert.equal(JSON.stringify(fresh), f);
});

/* ------------------------------ SubscriptionManager.refresh ------------------------------ */

test('refresh keeps ids and leaves manual servers and other subscriptions alone', async () => {
  const mine = sub([XH + '#DE 12GB', TR + '#NL 12GB']);
  const manual = parseLink(XH + '#manual copy');          // same link, no subId
  const other = sub([XH + '#other sub'], 'sub2');
  const { store, mgr } = harness({
    servers: [manual, ...mine, ...other],
    subs: [{ id: 'sub1', url: 'https://a' }, { id: 'sub2', url: 'https://b' }],
    bodies: [[XH + '#DE 11GB', TR + '#NL 11GB'].join('\n')]
  });
  const r = await mgr.refresh('sub1');
  assert.equal(r.added, 2);
  const ids = store.servers.map(s => s.id);
  assert.deepEqual(ids, [manual.id, other[0].id, mine[0].id, mine[1].id]);
  assert.equal(store.servers.find(s => s.id === manual.id).name, 'manual copy');
  assert.equal(store.subs.find(s => s.id === 'sub1').serverCount, 2);
});

test('a subscription removed while its refresh was on the network stays removed, servers and all', async () => {
  let release;
  const gate = new Promise(r => { release = r; });
  const store = { subs: [{ id: 'sub1', url: 'https://a' }, { id: 'sub2', url: 'https://b', serverCount: 7 }], servers: sub([TR + '#NL'], 'sub2') };
  const mgr = new SubscriptionManager({
    getSubs: () => JSON.parse(JSON.stringify(store.subs)),
    setSubs: (a) => { store.subs = a; },
    getServers: () => JSON.parse(JSON.stringify(store.servers)),
    setServers: (a) => { store.servers = a; },
    fetch: async (url, subId) => { await gate; return { servers: sub([XH + '#DE'], subId), errors: [], usage: null }; }
  });
  const pending = mgr.refresh('sub1');
  mgr.remove('sub1');
  store.subs[0].serverCount = 8;   // another refresh of sub2 landed meanwhile
  release();
  await assert.rejects(pending, /subscription not found/);
  assert.deepEqual(store.subs.map(s => s.id), ['sub2'], 'not resurrected');
  assert.equal(store.subs[0].serverCount, 8, 'the other subscription’s newer record is not overwritten');
  assert.equal(store.servers.some(s => s.subId === 'sub1'), false);
});

test('the owner’s plan still routes through the subscription server after two refreshes', async () => {
  // advanced routing ON: corporate ranges → chain [xhttp (from the sub) → corporate WireGuard],
  // default = the same xhttp server. The ids in the rule, the chain and the
  // default were chosen before the refresh; the refresh must not orphan them.
  const [xh] = sub([XH + '#DE | 12GB']);
  const wg = Object.assign(JSON.parse(JSON.stringify(F.WG_CORP)), { id: 'wg-corp' });
  const { store, mgr } = harness({
    servers: [xh, wg],
    bodies: [XH + '#DE | 11GB', XH + '#DE | 10GB']
  });
  const chain = { id: 'tes', members: [xh.id, wg.id] };
  const rules = [{ type: 'ip', value: '192.168.0.0/16, 10.0.0.0/8, 192.168.45.0/24', target: 'chain:tes' }];
  await mgr.refresh('sub1');
  await mgr.refresh('sub1');

  const byId = Object.fromEntries(store.servers.map(s => [s.id, s]));
  assert.ok(byId[xh.id], 'the id the chain and the default hold still exists');
  const plan = {
    mode: 'advanced', serversById: byId,
    chainsById: { tes: chain.members.map(id => byId[id]).filter(Boolean) }, chain: [],
    rules, def: xh.id
  };
  assert.equal(plan.chainsById.tes.length, 2, 'the chain did not lose its first hop');
  const c = buildConfig(plan, F.settings({ routingMode: 'bypass-ir' }));
  const catchAll = c.routing.rules.at(-1);
  assert.equal(catchAll.outboundTag, 'out-' + xh.id, 'the default is the proxy, not direct');
  const corp = c.routing.rules.find(r => Array.isArray(r.ip) && r.ip.includes('192.168.45.0/24'));
  assert.equal(corp.outboundTag, 'out-chain-tes');
  const exit = c.outbounds.find(o => o.tag === 'out-chain-tes');
  assert.equal(exit.protocol, 'wireguard');
  assert.equal(exit.streamSettings.sockopt.dialerProxy, 'out-chain-tes-h0', 'the WireGuard still rides the xhttp hop');
});
