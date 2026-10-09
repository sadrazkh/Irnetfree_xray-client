'use strict';
// the router's service is started below (the real one over the gateway fakes): its flavour is read at load
process.env.IRNETFREE_PLATFORM = 'openwrt';
/**
 * Routing share links (src/main/routeShare.js, spec 2026-10-09 §4): a profile
 * or a chain with every server and chain it needs, as one
 * `irnetfree://routing/<base64url(deflate-raw(JSON))>` text — encode, decode,
 * preview, import — and the four IPC channels main.js and the router's
 * service share (createRouteShareApi). The payload and its link are the
 * fixtures the Android tests read too (tests/fixtures/routing/).
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');
const RS = require('../src/main/routeShare');
const { parseLink, parseMany, buildShareLink } = require('../src/main/parser');
const { serverIdentity } = require('../src/main/subscription');

const FIX = path.join(__dirname, 'fixtures', 'routing');
const LINK = fs.readFileSync(path.join(FIX, 'profile-link.txt'), 'utf8').trim();
const PAYLOAD = JSON.parse(fs.readFileSync(path.join(FIX, 'profile-payload.json'), 'utf8'));
const clone = (v) => JSON.parse(JSON.stringify(v));
const identityOf = (s) => serverIdentity(s, true);
/** parser's parseMany-style: the first server of the text, or the reason it has none. */
const parse = (link) => {
  const r = parseMany(link);
  if (!r.servers.length) throw new Error((r.errors[0] && r.errors[0].error) || 'unreadable');
  return r.servers[0];
};
/** Deterministic ids: chain-t1, rp-t2, … */
function counterIds() { let n = 0; return (kind) => (kind === 'chain' ? 'chain-t' : kind === 'profile' ? 'rp-t' : 'srv-t') + (++n); }
/** The raw text of a share link as it would be with this JSON inside (no validation). */
const pack = (json) => RS.SHARE_PREFIX + zlib.deflateRawSync(Buffer.from(json)).toString('base64url');

/** The sender's store behind the fixture: its four servers (own ids), one more, the chain and the profile. */
function senderStore() {
  const byKey = {};
  for (const e of PAYLOAD.servers) byKey[e.key] = Object.assign(parseLink(e.link), { id: 'id-' + e.key });
  const other = Object.assign(parseLink('trojan://other@other.example.com:443?security=tls&sni=other.example.com#Other'), { id: 'id-other' });
  // store order differs from the payload's key order: keys follow the profile, not the list
  const servers = [other, byKey.s4, byKey.s3, byKey.s2, byKey.s1];
  const chains = [
    { id: 'chain-unused', name: 'Unused', members: ['id-other', 'id-s1'] },
    { id: 'chain-nlus', name: 'NL→US', members: ['id-s4', 'id-s3'] }
  ];
  const profile = {
    id: 'rp-work', name: 'Work', useMode: true, base: 'id-s1', def: 'id-s1', defVia: 'none',
    rules: [
      { type: 'domain', value: 'corp.example,intranet.example', target: 'id-s2', via: 'inherit' },
      { type: 'domain', value: 'geosite:netflix', target: 'id-s3', via: 'inherit' },
      { type: 'domain', value: 'geosite:category-ir', target: 'direct' },
      { type: 'ip', value: 'geoip:ir', target: 'direct' },
      { type: 'port', value: '5060', target: 'chain:chain-nlus', via: 'none' }
    ]
  };
  return { servers, chains, profile, byKey };
}
/** The fixture's links exactly (buildShareLink would reorder their query). */
const rawLink = (s) => s.raw;

/* ------------------------------ encode / decode ------------------------------ */

test('decodeShare(the fixture link) is the fixture payload', () => {
  assert.deepEqual(RS.decodeShare(LINK), PAYLOAD);
  // what a paste or a QR scan adds around it: whitespace, a CRLF
  assert.deepEqual(RS.decodeShare('  ' + LINK + '\r\n'), PAYLOAD);
});

test('encodeShare → decodeShare round trip; one line, base64url, the prefix', () => {
  const text = RS.encodeShare(PAYLOAD);
  assert.ok(text.startsWith('irnetfree://routing/'));
  assert.match(text.slice(RS.SHARE_PREFIX.length), /^[A-Za-z0-9_-]+$/, 'base64url, no padding, no line breaks');
  assert.deepEqual(RS.decodeShare(text), PAYLOAD);
  // raw deflate: what the fixture holds inflates the same way
  const body = zlib.inflateRawSync(Buffer.from(text.slice(RS.SHARE_PREFIX.length), 'base64url')).toString('utf8');
  assert.deepEqual(JSON.parse(body), PAYLOAD);
});

test('the constants the UI and Android rely on', () => {
  assert.equal(RS.SHARE_PREFIX, 'irnetfree://routing/');
  assert.equal(RS.MAX_DECODED, 65536);
  assert.equal(RS.QR_MAX_BYTES, 1700);
});

test('QR decision: ≤ 1,700 bytes gets a QR, a larger text does not', () => {
  assert.equal(RS.fitsQr(LINK), true, 'the fixture link (' + Buffer.byteLength(LINK) + ' bytes)');
  assert.equal(RS.fitsQr('x'.repeat(1700)), true);
  assert.equal(RS.fitsQr('x'.repeat(1701)), false);
  // bytes, not characters
  assert.equal(RS.fitsQr('ب'.repeat(851)), false);
});

/* ------------------------------ payloads ------------------------------ */

test('profilePayload: keys s1…/c1… in the order the profile uses them, targets rewritten, base and vias kept, only what it needs', () => {
  const { servers, chains, profile } = senderStore();
  const p = RS.profilePayload({ profile, servers, chains, linkOf: rawLink });
  assert.deepEqual(p, PAYLOAD);
  // the same key order as the fixture, so the same JSON text
  assert.equal(JSON.stringify(p), JSON.stringify(PAYLOAD));
  assert.ok(!JSON.stringify(p).includes('id-'), 'never the sender’s ids');
  assert.ok(!JSON.stringify(p).includes('other.example.com'), 'a server the profile does not use stays home');
  assert.ok(!JSON.stringify(p).includes('Unused'), 'a chain the profile does not use stays home');
});

test('profilePayload: buildShareLink is the link (what Copy gives), a JSON server as its JSON text', () => {
  const { servers, chains } = senderStore();
  const json = parseMany(fs.readFileSync(path.join(__dirname, 'fixtures', 'json', 'xray-fragment.json'), 'utf8')).servers[0];
  json.id = 'id-json';
  const profile = { id: 'rp-x', name: 'J', rules: [{ type: 'domain', value: 'a.example', target: 'id-json' }], def: 'direct', defVia: 'inherit', useMode: false, base: null };
  const p = RS.profilePayload({ profile, servers: servers.concat(json), chains, linkOf: buildShareLink });
  assert.equal(p.servers.length, 1);
  assert.equal(p.servers[0].link, buildShareLink(json));
  assert.equal(p.servers[0].link[0], '{', 'the config itself');
  assert.deepEqual(p.profile, { name: 'J', useMode: false, base: null, def: 'direct', defVia: 'inherit', rules: [{ type: 'domain', value: 'a.example', target: 's1' }] });
});

test('profilePayload: direct/block never carry a via; an empty default is the sender’s first server (what a connect uses)', () => {
  const { servers, chains } = senderStore();
  const profile = { id: 'rp-y', name: 'Y', rules: [{ type: 'ip', value: '1.1.1.1', target: 'block', via: 'id-s1' }], def: '', useMode: false };
  const p = RS.profilePayload({ profile, servers, chains, linkOf: rawLink });
  assert.deepEqual(p.profile.rules, [{ type: 'ip', value: '1.1.1.1', target: 'block' }]);
  assert.equal(p.profile.def, 's1');
  assert.equal(p.servers[0].name, 'Other', 'servers[0] of the store');
  assert.equal(p.profile.defVia, 'inherit');
  assert.equal(p.profile.base, null);
});

test('profilePayload: the old single chain (target "chain") travels as a named chain', () => {
  const { servers, chains } = senderStore();
  const profile = { id: 'rp-z', name: 'Z', rules: [{ type: 'port', value: '22', target: 'chain' }], def: 'direct' };
  const p = RS.profilePayload({ profile, servers, chains, linkOf: rawLink, legacyChain: ['id-s4', 'id-s1'] });
  assert.deepEqual(p.chains, [{ key: 'c1', name: 'Hop NL → 🇩🇪 Base DE', members: ['s1', 's2'] }]);
  assert.equal(p.profile.rules[0].target, 'chain:c1');
});

test('profilePayload refuses a reference that no longer exists, and a chain that lost a server', () => {
  const { servers, chains, profile } = senderStore();
  const gone = clone(profile); gone.rules[1].target = 'id-deleted';
  assert.throws(() => RS.profilePayload({ profile: gone, servers, chains, linkOf: rawLink }), (e) => e.code === 'gone' && /rule 2/i.test(e.message));
  const goneBase = clone(profile); goneBase.base = 'chain:nope';
  assert.throws(() => RS.profilePayload({ profile: goneBase, servers, chains, linkOf: rawLink }), (e) => e.code === 'gone' && /base/i.test(e.message));
  const goneVia = clone(profile); goneVia.rules[0].via = 'id-deleted';
  assert.throws(() => RS.profilePayload({ profile: goneVia, servers, chains, linkOf: rawLink }), (e) => e.code === 'gone');
  const lost = clone(chains); lost[1].members = ['id-s4', 'id-deleted'];
  assert.throws(() => RS.profilePayload({ profile, servers, chains: lost, linkOf: rawLink }), (e) => e.code === 'chainLost' && /NL→US/.test(e.message));
  // Persian when the app is in Persian
  assert.throws(() => RS.profilePayload({ profile: gone, servers, chains, linkOf: rawLink, lang: 'fa' }), (e) => /قانونِ ۲|قانون ۲|قانونِ 2/.test(e.message));
});

test('chainPayload: the chain and its servers only, keys s1…/c1', () => {
  const { servers, chains } = senderStore();
  const p = RS.chainPayload({ chain: chains[1], servers, linkOf: rawLink });
  assert.deepEqual(p, {
    v: 1, kind: 'chain',
    servers: [
      { key: 's1', name: 'Hop NL', link: PAYLOAD.servers[3].link },
      { key: 's2', name: 'Netflix US', link: PAYLOAD.servers[2].link }
    ],
    chains: [{ key: 'c1', name: 'NL→US', members: ['s1', 's2'] }]
  });
  assert.equal(p.profile, undefined);
  assert.deepEqual(RS.decodeShare(RS.encodeShare(p)), p);
  const lost = { id: 'c', name: 'Lost', members: ['id-s4', 'id-gone'] };
  assert.throws(() => RS.chainPayload({ chain: lost, servers, linkOf: rawLink }), (e) => e.code === 'chainLost');
});

/* ------------------------------ preview ------------------------------ */

test('previewImport into an empty store: 4 new servers, 1 chain, 5 rules', () => {
  const s = RS.previewImport(PAYLOAD, { servers: [], chains: [], profiles: [], parse, identityOf });
  assert.deepEqual(s, { kind: 'profile', name: 'Work', rules: 5, chains: 1, serversNew: 4, serversExisting: 0, unreadable: [] });
});

test('previewImport into a store already holding s1 and s3 (same identity, other ids and names): 2 existing, 2 new', () => {
  const have = [
    Object.assign(parseLink(PAYLOAD.servers[0].link), { id: 'mine-1', name: 'my base' }),
    Object.assign(parseLink(PAYLOAD.servers[2].link), { id: 'mine-3', name: 'my us' }),
    Object.assign(parseLink('trojan://x@unrelated.example:443?security=tls#U'), { id: 'mine-u' })
  ];
  const s = RS.previewImport(PAYLOAD, { servers: have, chains: [], profiles: [], parse, identityOf });
  assert.equal(s.serversExisting, 2);
  assert.equal(s.serversNew, 2);
  assert.deepEqual(s.unreadable, []);
});

test('previewImport names what it cannot read; a chain link previews its chain', () => {
  const p = clone(PAYLOAD);
  p.servers[1].link = 'tuic://nope@x.example:443#Corp%20WG';
  const s = RS.previewImport(p, { servers: [], chains: [], profiles: [], parse, identityOf });
  assert.equal(s.serversNew, 3);
  assert.equal(s.unreadable.length, 1);
  assert.match(s.unreadable[0], /^Corp WG/);
  const { servers, chains } = senderStore();
  const c = RS.previewImport(RS.chainPayload({ chain: chains[1], servers, linkOf: rawLink }), { servers: [], chains: [], profiles: [], parse, identityOf });
  assert.deepEqual(c, { kind: 'chain', name: 'NL→US', rules: 0, chains: 1, serversNew: 2, serversExisting: 0, unreadable: [] });
});

/* ------------------------------ import ------------------------------ */

test('applyImport into an empty store: new ids, the chain mapped, every target mapped, inputs untouched', () => {
  const store = { servers: [], chains: [], profiles: [] };
  const before = clone(store);
  const r = RS.applyImport(PAYLOAD, Object.assign({}, store, { parse, identityOf, newId: counterIds() }));
  assert.deepEqual(store, before, 'pure: new lists, the old ones as they were');
  assert.deepEqual(r.added, { servers: 4, chains: 1, profiles: 1 });
  assert.equal(r.servers.length, 4);
  const idOf = (name) => r.servers.find((s) => s.name === name).id;
  for (const s of r.servers) assert.match(s.id, /^[0-9a-f]{16}$/, 'ids as the parser makes them');
  assert.equal(new Set(r.servers.map((s) => s.id)).size, 4);
  assert.deepEqual(r.chains, [{ id: 'chain-t1', name: 'NL→US', members: [idOf('Hop NL'), idOf('Netflix US')] }]);
  assert.equal(r.chainId, undefined);
  assert.equal(r.profileId, 'rp-t2');
  assert.deepEqual(r.profiles, [{
    id: 'rp-t2', name: 'Work',
    rules: [
      { type: 'domain', value: 'corp.example,intranet.example', target: idOf('Corp WG'), via: 'inherit' },
      { type: 'domain', value: 'geosite:netflix', target: idOf('Netflix US'), via: 'inherit' },
      { type: 'domain', value: 'geosite:category-ir', target: 'direct' },
      { type: 'ip', value: 'geoip:ir', target: 'direct' },
      { type: 'port', value: '5060', target: 'chain:chain-t1', via: 'none' }
    ],
    def: idOf('🇩🇪 Base DE'), defVia: 'none', useMode: true, base: idOf('🇩🇪 Base DE')
  }]);
  // the servers are the links' own records (no subscription), named as the link says
  const wg = r.servers.find((s) => s.name === 'Corp WG');
  assert.equal(wg.protocol, 'wireguard');
  assert.equal(wg.sub, undefined);
});

test('applyImport into a populated store: s1 and s3 reused by identity, the name de-duplicated, an equal chain reused', () => {
  const mine1 = Object.assign(parseLink(PAYLOAD.servers[0].link), { id: 'mine-1', name: 'my base' });
  const mine3 = Object.assign(parseLink(PAYLOAD.servers[2].link), { id: 'mine-3', name: 'my us' });
  const servers = [mine1, mine3];
  const profiles = [{ id: 'rp-default', name: 'Advanced routing', rules: [], def: 'direct', defVia: 'inherit', useMode: false, base: null },
    { id: 'rp-w', name: 'Work', rules: [], def: 'direct', defVia: 'inherit', useMode: false, base: null }];
  const r1 = RS.applyImport(PAYLOAD, { servers, chains: [], profiles, parse, identityOf, newId: counterIds() });
  assert.deepEqual(r1.added, { servers: 2, chains: 1, profiles: 1 });
  assert.deepEqual(r1.servers.slice(0, 2), servers, 'the existing records untouched, in place');
  const p = r1.profiles.find((x) => x.id === r1.profileId);
  assert.equal(p.name, 'Work (2)');
  assert.equal(p.base, 'mine-1');
  assert.equal(p.def, 'mine-1');
  assert.equal(p.rules[1].target, 'mine-3');
  const hop = r1.servers.find((s) => s.name === 'Hop NL');
  assert.deepEqual(r1.chains[0].members, [hop.id, 'mine-3']);
  assert.deepEqual(r1.profiles.slice(0, 2), profiles, 'the first profile stays first (plain __advanced__)');

  // the same link again: every server and the chain reused, only the profile is new — "Work (3)"
  const r2 = RS.applyImport(PAYLOAD, { servers: r1.servers, chains: r1.chains, profiles: r1.profiles, parse, identityOf, newId: counterIds() });
  assert.deepEqual(r2.added, { servers: 0, chains: 0, profiles: 1 });
  assert.equal(r2.profiles.find((x) => x.id === r2.profileId).name, 'Work (3)');
  assert.equal(r2.profiles.find((x) => x.id === r2.profileId).rules[4].target, 'chain:' + r1.chains[0].id);
});

test('applyImport of a chain link: the chain and its servers only — a same-named chain with other members is a new one', () => {
  const { servers, chains } = senderStore();
  const payload = RS.chainPayload({ chain: chains[1], servers, linkOf: rawLink });
  const theirs = [{ id: 'chain-mine', name: 'NL→US', members: ['a', 'b'] }];
  const r = RS.applyImport(payload, { servers: [], chains: theirs, profiles: [{ id: 'rp-default', name: 'x', rules: [] }], parse, identityOf, newId: counterIds() });
  assert.deepEqual(r.added, { servers: 2, chains: 1, profiles: 0 });
  assert.equal(r.chainId, 'chain-t1');
  assert.equal(r.profileId, undefined);
  assert.equal(r.chains[1].name, 'NL→US (2)');
  assert.equal(r.profiles.length, 1);
});

test('applyImport: an unreadable server is reported and left a dangling reference (the builder refuses or skips it), never a shorter chain', () => {
  const p = clone(PAYLOAD);
  p.servers[3].link = 'tuic://nope@x.example:443#Hop%20NL';   // s4, the chain's first hop
  const r = RS.applyImport(p, { servers: [], chains: [], profiles: [], parse, identityOf, newId: counterIds() });
  assert.equal(r.added.servers, 3);
  assert.equal(r.unreadable.length, 1);
  assert.equal(r.chains[0].members.length, 2, 'the hop stays, as a reference to nothing');
  assert.ok(!r.servers.some((s) => s.id === r.chains[0].members[0]));
});

test('applyImport: a JSON server travels as its JSON text and comes back as the same server', () => {
  const json = parseMany(fs.readFileSync(path.join(__dirname, 'fixtures', 'json', 'xray-fragment.json'), 'utf8')).servers[0];
  json.id = 'id-json';
  const profile = { id: 'rp-j', name: 'J', rules: [{ type: 'domain', value: 'a.example', target: 'id-json' }], def: 'id-json', defVia: 'inherit', useMode: false, base: null };
  const text = RS.encodeShare(RS.profilePayload({ profile, servers: [json], chains: [], linkOf: buildShareLink }));
  const empty = RS.applyImport(RS.decodeShare(text), { servers: [], chains: [], profiles: [], parse, identityOf, newId: counterIds() });
  assert.equal(empty.servers[0].source, 'json');
  assert.equal(empty.servers[0].name, json.name);
  assert.equal(identityOf(empty.servers[0]), identityOf(json));
  const same = RS.applyImport(RS.decodeShare(text), { servers: [json], chains: [], profiles: [], parse, identityOf, newId: counterIds() });
  assert.equal(same.added.servers, 0);
  assert.equal(same.profiles[0].def, 'id-json');
});

/* ------------------------------ refusals ------------------------------ */

const hostile = {
  'a wrong prefix': ['irnetfree://other/' + LINK.slice(RS.SHARE_PREFIX.length), 'prefix'],
  'a share link of a server': ['vless://00000000-0000-4000-8000-000000000001@a.example:443#x', 'prefix'],
  'bad base64': [RS.SHARE_PREFIX + 'nVPB!!!$$', 'base64'],
  'an empty body': [RS.SHARE_PREFIX, 'base64'],
  'a truncated deflate': [LINK.slice(0, LINK.length - 40), 'deflate'],
  'not deflate at all': [RS.SHARE_PREFIX + Buffer.from('hello world, plainly').toString('base64url'), 'deflate'],
  '> 64 KB decoded': [pack(JSON.stringify(Object.assign(clone(PAYLOAD), { pad: 'x'.repeat(70000) }))), 'size'],
  'a huge text': [RS.SHARE_PREFIX + 'A'.repeat(200000), 'size'],
  'not JSON': [pack('{"v":1,'), 'json'],
  'v !== 1': [pack(JSON.stringify(Object.assign(clone(PAYLOAD), { v: 2 }))), 'version'],
  'no v': [pack(JSON.stringify({ kind: 'profile' })), 'version'],
  'an unknown kind': [pack(JSON.stringify(Object.assign(clone(PAYLOAD), { kind: 'pool' }))), 'kind'],
  'a profile target naming a missing key': [pack(JSON.stringify((() => { const p = clone(PAYLOAD); p.profile.rules[0].target = 's9'; return p; })())), 'missing'],
  'a via naming a missing key': [pack(JSON.stringify((() => { const p = clone(PAYLOAD); p.profile.rules[1].via = 'chain:c7'; return p; })())), 'missing'],
  'a base naming a missing key': [pack(JSON.stringify((() => { const p = clone(PAYLOAD); p.profile.base = 's5'; return p; })())), 'missing'],
  'a chain member naming a missing key': [pack(JSON.stringify((() => { const p = clone(PAYLOAD); p.chains[0].members.push('s8'); return p; })())), 'missing'],
  'a sender id instead of a key': [pack(JSON.stringify((() => { const p = clone(PAYLOAD); p.profile.def = '891dbf257a1e3439'; return p; })())), 'missing'],
  'a profile link without a profile': [pack(JSON.stringify((() => { const p = clone(PAYLOAD); delete p.profile; return p; })())), 'shape'],
  'a chain link without a chain': [pack(JSON.stringify({ v: 1, kind: 'chain', servers: [], chains: [] })), 'shape'],
  'an unknown rule type': [pack(JSON.stringify((() => { const p = clone(PAYLOAD); p.profile.rules[0].type = 'protocol'; return p; })())), 'shape'],
  'a server without a link': [pack(JSON.stringify((() => { const p = clone(PAYLOAD); delete p.servers[0].link; return p; })())), 'shape'],
  'two servers with one key': [pack(JSON.stringify((() => { const p = clone(PAYLOAD); p.servers[1].key = 's1'; return p; })())), 'shape'],
  'a JSON array': [pack('[1,2]'), 'json']
};

for (const [what, [text, code]] of Object.entries(hostile)) {
  test('refused: ' + what + ' (' + code + ')', () => {
    assert.throws(() => RS.decodeShare(text), (e) => {
      assert.equal(e.code, code, e.message);
      assert.ok(e.message.length > 10, 'a reason');
      return true;
    });
  });
}

test('refusals are worded in the app’s language', () => {
  assert.throws(() => RS.decodeShare('nope', { lang: 'en' }), /routing link/i);
  assert.throws(() => RS.decodeShare('nope', { lang: 'fa' }), /لینک/);
  assert.throws(() => RS.decodeShare(pack(JSON.stringify({ v: 3 })), { lang: 'en' }), /v3|version/i);
});

test('encodeShare refuses a payload the receiver would refuse (> 64 KB)', () => {
  const big = Object.assign(clone(PAYLOAD), { servers: PAYLOAD.servers.concat([{ key: 's9', name: 'big', link: 'x'.repeat(70000) }]) });
  assert.throws(() => RS.encodeShare(big), (e) => e.code === 'size');
});

/* ------------------------------ the IPC api (main.js and service.js) ------------------------------ */

/** A store like main's: get/set/assign, every write recorded. */
function fakeStore(data) {
  const writes = [];
  return {
    data, writes,
    get: (k, d) => (k in data ? data[k] : d),
    set: (k, v) => { writes.push([k]); data[k] = v; return true; },
    assign: (o) => { writes.push(Object.keys(o)); Object.assign(data, o); return true; }
  };
}
function api(data, extra = {}) {
  const store = fakeStore(data);
  const marks = [];
  const a = RS.createRouteShareApi(Object.assign({
    store,
    getSettings: () => Object.assign({ lang: 'en', routeRules: [], routeDefault: '', advancedUseMode: false }, store.get('settings', {})),
    getChains: () => store.get('chains', []),
    linkOf: buildShareLink,
    parseMany,
    identityOf,
    liveSelection: () => null,
    markLive: () => marks.push('live'),
    pendingKeys: () => (marks.length ? ['servers'] : []),
    rp: null,
    newId: counterIds()
  }, extra));
  return { a, store, marks };
}

test('api: shareProfile → { ok, link, bytes, servers, qr }; the link decodes to the profile with its servers', () => {
  const { servers, chains, profile } = senderStore();
  const { a } = api({ servers, chains, routingProfiles: [profile] });
  const r = a.shareProfile('rp-work');
  assert.equal(r.ok, true, r.error);
  assert.equal(r.bytes, Buffer.byteLength(r.link));
  assert.equal(r.servers, 4);
  assert.equal(r.qr, r.bytes <= 1700);
  const p = RS.decodeShare(r.link);
  assert.deepEqual(p.profile, PAYLOAD.profile);
  assert.deepEqual(p.servers.map((s) => s.name), PAYLOAD.servers.map((s) => s.name));
  assert.deepEqual(p.servers.map((s) => s.link), [servers[4], servers[3], servers[2], servers[1]].map(buildShareLink), 'linkOf = buildShareLink');
  assert.deepEqual(a.shareProfile('rp-nope'), { ok: false, error: 'Not found — it may have been deleted.' });
});

test('api: shareChain → the chain link; a broken chain says why', () => {
  const { servers, chains } = senderStore();
  const { a } = api({ servers, chains: chains.concat({ id: 'chain-lost', name: 'Lost', members: ['id-s1', 'gone'] }) });
  const r = a.shareChain('chain-nlus');
  assert.equal(r.ok, true, r.error);
  assert.equal(r.servers, 2);
  assert.equal(RS.decodeShare(r.link).kind, 'chain');
  const bad = a.shareChain('chain-lost');
  assert.equal(bad.ok, false);
  assert.match(bad.error, /Lost/);
  assert.equal(a.shareChain('nope').ok, false);
});

test('api: with no stored profiles, rp-default is today’s settings (before R1’s migration ran)', () => {
  const { servers, chains } = senderStore();
  const settings = { routeRules: [{ type: 'ip', value: '10.0.0.0/8', target: 'id-s2' }], routeDefault: 'id-s1', advancedUseMode: true };
  const { a } = api({ servers, chains, settings });
  const r = a.shareProfile('rp-default');
  assert.equal(r.ok, true, r.error);
  const p = RS.decodeShare(r.link).profile;
  assert.equal(p.name, 'Advanced routing');
  assert.deepEqual(p.rules, [{ type: 'ip', value: '10.0.0.0/8', target: 's2' }]);
  assert.equal(p.def, 's1');
  assert.equal(p.useMode, true);
});

test('api: importPreview → { ok, summary }; a refusal → { ok: false, error } and nothing written', () => {
  const { a, store } = api({ servers: [], chains: [] });
  assert.deepEqual(a.importPreview(LINK), { ok: true, summary: { kind: 'profile', name: 'Work', rules: 5, chains: 1, serversNew: 4, serversExisting: 0, unreadable: [] } });
  const bad = a.importPreview('irnetfree://routing/!!');
  assert.equal(bad.ok, false);
  assert.match(bad.error, /damaged|base64/i);
  assert.equal(store.writes.length, 0);
});

test('api: import persists servers, chains and profiles in ONE write and answers with them', () => {
  const { a, store, marks } = api({ servers: [], chains: [], routingProfiles: [{ id: 'rp-default', name: 'Advanced routing', rules: [], def: '', defVia: 'inherit', useMode: false, base: null }] });
  const r = a.importShare(LINK);
  assert.equal(r.ok, true, r.error);
  assert.deepEqual(store.writes, [['servers', 'chains', 'routingProfiles']]);
  assert.deepEqual(r.added, { servers: 4, chains: 1, profiles: 1 });
  assert.equal(r.servers, store.data.servers);
  assert.equal(r.chains, store.data.chains);
  assert.equal(r.profiles, store.data.routingProfiles);
  assert.equal(r.profiles[0].id, 'rp-default');
  assert.equal(r.profiles[1].id, r.profileId);
  assert.deepEqual(marks, [], 'nothing live');
  assert.deepEqual(r.pendingReconnect, []);
  // a chain link writes no profiles
  const { servers, chains } = senderStore();
  const chainLink = RS.encodeShare(RS.chainPayload({ chain: chains[1], servers, linkOf: rawLink }));
  const before = store.writes.length;
  const c = a.importShare(chainLink);
  assert.equal(c.ok, true, c.error);
  assert.deepEqual(store.writes.slice(before), [['servers', 'chains']]);
  assert.deepEqual(c.added, { servers: 0, chains: 0, profiles: 0 }, 'both servers and the chain were already here');
  assert.equal(c.chainId, r.chains[0].id);
});

test('api: every refusal writes nothing', () => {
  for (const [what, [text]] of Object.entries(hostile)) {
    const { a, store } = api({ servers: [], chains: [], routingProfiles: [] });
    const r = a.importShare(text);
    assert.equal(r.ok, false, what);
    assert.ok(r.error, what);
    assert.deepEqual(store.writes, [], what);
  }
});

test('api: an import that changes what the live plain __advanced__ resolves to marks the reconnect state', () => {
  // no profile yet: the imported one becomes the first, which plain __advanced__ means
  const { a, marks } = api({ servers: [], chains: [], routingProfiles: [] }, { liveSelection: () => '__advanced__' });
  const r = a.importShare(LINK);
  assert.equal(r.ok, true, r.error);
  assert.deepEqual(marks, ['live']);
  assert.deepEqual(r.pendingReconnect, ['servers']);
  // a profile appended behind the live one touches nothing live
  const two = api({ servers: [], chains: [], routingProfiles: [{ id: 'rp-default', name: 'A', rules: [] }] }, { liveSelection: () => '__advanced__:rp-default' });
  assert.equal(two.a.importShare(LINK).ok, true);
  assert.deepEqual(two.marks, []);
});

test('api: a profile import mirrors through routingProfiles.mirrorToSettings when R1’s module exists', () => {
  const calls = [];
  const rp = {
    profileIdOf: (sel, list) => (sel === '__advanced__' ? (list[0] && list[0].id) || null : String(sel).split(':')[1] || null),
    migrateProfiles: ({ settings }) => ({ profiles: [{ id: 'rp-default', name: 'Advanced routing', rules: settings.routeRules, def: settings.routeDefault, defVia: 'inherit', useMode: !!settings.advancedUseMode, base: null }], changed: true }),
    mirrorToSettings: (profiles, settings) => { calls.push(profiles.map((p) => p.id)); const d = profiles.find((p) => p.id === 'rp-default'); return Object.assign({}, settings, { routeRules: d.rules, routeDefault: d.def, advancedUseMode: d.useMode }); },
    newProfileId: () => 'rp-fromr1'
  };
  const settings = { lang: 'en', routeRules: [{ type: 'ip', value: '1.1.1.1', target: 'direct' }], routeDefault: 'direct', advancedUseMode: false };
  const { a, store } = api({ servers: [], chains: [], settings }, { rp, newId: undefined });
  const r = a.importShare(LINK);
  assert.equal(r.ok, true, r.error);
  assert.deepEqual(calls, [['rp-default', 'rp-fromr1']]);
  assert.equal(r.profileId, 'rp-fromr1', 'R1’s id maker');
  assert.deepEqual(store.data.routingProfiles.map((p) => p.id), ['rp-default', 'rp-fromr1'], 'the migration ran first: rp-default stays first');
  assert.deepEqual(store.data.settings, settings, 'the mirror changed nothing, so nothing of the settings was rewritten');
  assert.ok(!store.writes.some((w) => w.includes('settings')));
});

/* ------------------------------ wiring (main.js as text, the router's service for real) ------------------------------ */

test('router: the real service imports a link, persists it, shares it back, and previews it as already here', async (t) => {
  const H = require('./serviceHarness');
  t.after(() => H.cleanupDirs());
  const s = H.start({ chains: [] });
  t.after(() => s.service.shutdown());
  const before = await s.service.invoke('servers:list');

  const pre = await s.service.invoke('routing:importPreview', LINK);
  assert.deepEqual(pre, { ok: true, summary: { kind: 'profile', name: 'Work', rules: 5, chains: 1, serversNew: 4, serversExisting: 0, unreadable: [] } });

  const r = await s.service.invoke('routing:import', LINK);
  assert.equal(r.ok, true, r.error);
  assert.deepEqual(r.added, { servers: 4, chains: 1, profiles: 1 });
  assert.deepEqual(r.servers.slice(0, before.length), before, 'the router’s own servers untouched, first');
  assert.equal(r.profiles[0].id, 'rp-default', 'today’s routing stays the first profile');
  assert.equal(r.profiles[1].id, r.profileId);
  assert.deepEqual(r.pendingReconnect, []);

  // on disk, in one store
  const disk = JSON.parse(fs.readFileSync(path.join(s.dir, 'store.json'), 'utf8'));
  assert.equal(disk.servers.length, before.length + 4);
  assert.deepEqual(disk.chains, r.chains);
  assert.deepEqual(disk.routingProfiles, r.profiles);
  assert.deepEqual(await s.service.invoke('chains:list'), r.chains);

  // shared back: the same profile and the same servers (their links as Copy gives them)
  const back = await s.service.invoke('routing:shareProfile', r.profileId);
  assert.equal(back.ok, true, back.error);
  assert.equal(back.servers, 4);
  assert.equal(back.qr, true);
  const p = RS.decodeShare(back.link);
  assert.deepEqual(p.profile, PAYLOAD.profile);
  assert.deepEqual(p.chains, PAYLOAD.chains);
  assert.deepEqual(p.servers.map((x) => x.name), PAYLOAD.servers.map((x) => x.name));
  for (let i = 0; i < 4; i++) assert.equal(identityOf(parseLink(p.servers[i].link)), identityOf(parseLink(PAYLOAD.servers[i].link)));

  const chain = await s.service.invoke('routing:shareChain', r.chains[0].id);
  assert.equal(chain.ok, true, chain.error);
  assert.deepEqual(RS.decodeShare(chain.link).chains, [{ key: 'c1', name: 'NL→US', members: ['s1', 's2'] }]);

  // the same link again: everything is already here, the profile is "Work (2)"
  const again = await s.service.invoke('routing:importPreview', LINK);
  assert.equal(again.summary.serversExisting, 4);
  assert.equal(again.summary.serversNew, 0);
  const r2 = await s.service.invoke('routing:import', LINK);
  assert.deepEqual(r2.added, { servers: 0, chains: 0, profiles: 1 });
  assert.equal(r2.profiles.find((x) => x.id === r2.profileId).name, 'Work (2)');

  // refused: the reason, in the router's language (en here), and nothing written
  const mtime = fs.statSync(path.join(s.dir, 'store.json')).mtimeMs;
  const bad = await s.service.invoke('routing:import', LINK.slice(0, 300));
  assert.equal(bad.ok, false);
  assert.match(bad.error, /damaged|cut short/);
  assert.equal(fs.statSync(path.join(s.dir, 'store.json')).mtimeMs, mtime);
  assert.equal((await s.service.invoke('routing:shareProfile', 'rp-nope')).ok, false);
});


const R = (...p) => fs.readFileSync(path.join(__dirname, '..', ...p), 'utf8').replace(/\r\n/g, '\n');

test('desktop: main.js registers the four channels on the shared api', () => {
  const MAIN = R('src', 'main', 'main.js');
  assert.match(MAIN, /require\('\.\/routeShare'\)/);
  assert.match(MAIN, /serverIdentity\b[^;]*require\('\.\/subscription'\)/);
  for (const [ch, fn] of [['routing:shareProfile', 'shareProfile'], ['routing:shareChain', 'shareChain'], ['routing:importPreview', 'importPreview'], ['routing:import', 'importShare']]) {
    assert.match(MAIN, new RegExp(`ipcMain\\.handle\\('${ch}', \\(e, arg\\) => routeShare\\.${fn}\\(arg\\)\\);`));
  }
  const block = MAIN.slice(MAIN.indexOf('const routeShare = createRouteShareApi({'), MAIN.indexOf("ipcMain.handle('routing:shareProfile'"));
  assert.match(block, /linkOf: buildShareLink/);
  assert.match(block, /parseMany/);
  assert.match(block, /identityOf: \(s\) => serverIdentity\(s, true\)/);
  assert.match(block, /afterWrite: \(\) => refreshTray\(\)/, 'the tray follows the servers list');
  assert.match(block, /liveSelection: \(\) => \(appliedSettings \? store\.get\('activeServerId', null\) : null\)/);
  assert.match(block, /markLive: \(\) => \{ serverEditPending = true; \}/);
  assert.match(block, /pendingKeys/);
});

test('router: service.js wires the same four channels', () => {
  const SVC = R('src', 'server', 'service.js');
  assert.match(SVC, /require\('\.\.\/main\/routeShare'\)/);
  for (const [ch, fn] of [['routing:shareProfile', 'shareProfile'], ['routing:shareChain', 'shareChain'], ['routing:importPreview', 'importPreview'], ['routing:import', 'importShare']]) {
    assert.match(SVC, new RegExp(`'${ch}': \\(arg\\) => routeShare\\.${fn}\\(arg\\),`));
  }
  assert.match(SVC, /identityOf: \(s\) => serverIdentity\(s, true\)/);
  assert.match(SVC, /markLive: \(\) => \{ serverEditPending = true; \}/);
});

/* ---------------- "exit at the base" (target 'base'): carried as it is ---------------- */

const XLINK = fs.readFileSync(path.join(FIX, 'exit-base-link.txt'), 'utf8').trim();
const XPAYLOAD = JSON.parse(fs.readFileSync(path.join(FIX, 'exit-base-payload.json'), 'utf8'));

test('"exit at the base": the shared fixture decodes to its payload; a profile at its base shares and imports with the target as it is, no via on it', () => {
  assert.deepEqual(RS.decodeShare(XLINK), XPAYLOAD);
  const { servers, byKey } = senderStore();
  const profile = { id: 'rp-x', name: 'Exit at the base', useMode: true, base: 'id-s1', def: 'base', defVia: 'chain:gone',
    rules: [
      { type: 'ip', value: '10.0.0.0/8,192.168.0.0/16', target: 'id-s2', via: 'inherit' },
      { type: 'domain', value: 'geosite:category-ir', target: 'direct' },
      { type: 'domain', value: 'news.example', target: 'base', via: 'id-s3' }
    ] };
  const linkOf = (srv) => PAYLOAD.servers.find((e) => 'id-' + e.key === srv.id).link;
  const out = RS.profilePayload({ profile, servers, chains: [], linkOf });
  assert.deepEqual(out, XPAYLOAD, 'the very payload the fixture holds (a stale via on the base, or on a default at it, never travels)');
  assert.ok(byKey.s1);
  const r = RS.applyImport(XPAYLOAD, { servers: [], chains: [], profiles: [], parse, identityOf, newId: counterIds() });
  const base = r.servers.find((x) => x.name === '🇩🇪 Base DE').id;
  assert.deepEqual([r.profiles[0].def, r.profiles[0].defVia, r.profiles[0].base], ['base', 'inherit', base]);
  assert.deepEqual(r.profiles[0].rules[2], { type: 'domain', value: 'news.example', target: 'base' });
  // the base itself is a target only: as a via or as the base it names nothing
  for (const bad of [
    (p) => { p.profile.rules[0].via = 'base'; },
    (p) => { p.profile.defVia = 'base'; p.profile.def = 's2'; },
    (p) => { p.profile.base = 'base'; }
  ]) {
    const p = clone(XPAYLOAD);
    bad(p);
    assert.throws(() => RS.decodeShare(RS.encodeShare(p)), /base/);
  }
});
