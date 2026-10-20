'use strict';
/**
 * Groups (v1.27.0, .superpowers/sdd/groups/design.md): several saved servers
 * used as one — the stored group, the record a plan carries, a member at its
 * own address (addressSwap), the expansion into members + balancer + rule +
 * health check wherever the plan puts a group, what the machine dials itself,
 * the engine, the backup, and the wiring in main.js and the router.
 */
process.env.IRNETFREE_PLATFORM = 'openwrt';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const G = require('../src/main/groups');
const A = require('../src/main/addressSwap');
const B = require('../src/main/configBuilder');
const { chooseEngine, planServers } = require('../src/main/engineChoice');
const { exportBundle, importBundle } = require('../src/main/backup');
const { parseLink } = require('../src/main/parser');
const H = require('./serviceHarness');

process.setMaxListeners(60);
test.after(() => H.cleanupDirs());

const R = (...p) => fs.readFileSync(path.join(__dirname, '..', ...p), 'utf8').replace(/\r\n/g, '\n');
const UUID = '2c0f0d9a-6b3a-4f0e-9a1f-8c2b4d6e7a10';
const srv = (id, link) => Object.assign(parseLink(link), { id });
const CDN = srv('cdn', `vless://${UUID}@cdn.example.com:443?type=ws&security=tls&path=%2Fw#CDN`);
const DE = srv('de', `vless://${UUID}@de.example.net:8443?type=tcp&security=none#DE`);
const NL = srv('nl', `trojan://pw@nl.example.net:443?security=tls&sni=nl.example.net#NL`);
const byId = { cdn: CDN, de: DE, nl: NL };
const SETTINGS = { socksPort: 41080, httpPort: 41081, apiPort: 41082, routingMode: 'global', blockAds: false, geoAssets: false, dnsManaged: false, logLevel: 'warning' };

/* ------------------------------ the stored group ------------------------------ */
test('normalizeGroup: its own fields, a strategy of the three (roundRobin by default), members as servers — a group, a blank or a bad address never one', () => {
  const now = () => Date.UTC(2026, 9, 19);
  const g = G.normalizeGroup({ id: 'grp-a1', name: '  Fast  ', strategy: 'leastPing', extra: 1,
    members: ['de', { id: 'cdn', address: '[2606:4700::1]', port: '2053' }, { id: 'grp-x' }, { id: '' }, { id: 'nl', address: 'a b', port: 99999 }, null] }, now);
  assert.deepEqual(g, { id: 'grp-a1', name: 'Fast', strategy: 'leastPing',
    members: [{ id: 'de' }, { id: 'cdn', address: '2606:4700::1', port: 2053 }, { id: 'nl' }] });
  assert.equal(G.normalizeGroup({ strategy: 'leastLoad' }, now).strategy, 'roundRobin');
  assert.match(G.normalizeGroup({ id: 'chain-1' }, now).id, /^grp-[0-9a-z]+[0-9a-f]{4}$/);
  assert.equal(G.normalizeGroup({}, now).name, 'Group');
  assert.equal(G.normalizeGroup(null), null);
  const list = G.normalizeGroups([{ id: 'grp-a' }, { id: 'grp-a', name: 'dup' }, 'x', { id: 'grp-b' }]);
  assert.deepEqual(list.map((x) => x.id), ['grp-a', 'grp-b']);
  assert.equal(G.isGroupId('grp-a'), true);
  assert.equal(G.isGroupId('chain-a'), false);
});

test('groupRecord: a loopback marked _group with its member records — a gone member skipped, none left → null; a member at its own address keeps its id', () => {
  const rec = G.groupRecord({ id: 'grp-1', name: 'CDN ×2', members: [{ id: 'cdn', address: '104.16.1.1' }, { id: 'cdn', address: '104.17.2.2', port: 2053 }, { id: 'gone' }] }, byId);
  assert.equal(rec.id, 'grp-1');
  assert.equal(rec.protocol, 'group');
  assert.deepEqual(rec.group, { strategy: 'roundRobin', size: 2 });
  assert.equal(rec.outbound.protocol, 'loopback');
  const [a, b] = rec.outbound._group.members;
  assert.deepEqual([a.id, a.address, a.port, b.id, b.address, b.port], ['cdn', '104.16.1.1', 443, 'cdn', '104.17.2.2', 2053]);
  assert.equal(CDN.address, 'cdn.example.com', 'the stored server is untouched');
  assert.equal(G.isGroupRecord(rec), true);
  assert.equal(G.isGroupRecord(CDN), false);
  assert.deepEqual(G.serversOf(rec).map((s) => s.address), ['104.16.1.1', '104.17.2.2']);
  assert.deepEqual(G.serversOf(DE), [DE]);
  assert.equal(G.groupRecord({ id: 'grp-2', members: [{ id: 'gone' }] }, byId), null);
  // a group never holds a group
  const withGroup = Object.assign({}, byId, { 'grp-1': rec });
  assert.equal(G.groupRecord({ id: 'grp-3', members: [{ id: 'grp-1' }] }, withGroup), null);
  assert.deepEqual(Object.keys(G.groupRecordsById([{ id: 'grp-1', members: ['de'] }, { id: 'grp-2', members: ['gone'] }], byId)), ['grp-1']);
});

test('addressSwap.withTarget: the clean IP where the protocol keeps it; SNI and Host filled from the original name when the link left them empty; REALITY untouched; a WireGuard endpoint; bad ports refused', () => {
  const out = A.withTarget(CDN, { address: '104.16.1.1', port: 2053 });
  const st = out.outbound.streamSettings;
  assert.deepEqual([out.address, out.port, out.outbound.settings.vnext[0].address, out.outbound.settings.vnext[0].port], ['104.16.1.1', 2053, '104.16.1.1', 2053]);
  assert.equal(st.tlsSettings.serverName, 'cdn.example.com');
  assert.equal(st.wsSettings.headers.Host || st.wsSettings.host, 'cdn.example.com');
  assert.equal(CDN.outbound.settings.vnext[0].address, 'cdn.example.com');
  // an SNI already set stays
  assert.equal(A.withTarget(NL, { address: '1.2.3.4' }).outbound.streamSettings.tlsSettings.serverName, 'nl.example.net');
  const reality = srv('r', `vless://${UUID}@r.example.net:443?type=tcp&security=reality&sni=www.microsoft.com&pbk=AAAA&fp=chrome#R`);
  const r2 = A.withTarget(reality, { address: '5.6.7.8' });
  assert.equal(r2.outbound.streamSettings.realitySettings.serverName, 'www.microsoft.com');
  assert.equal(r2.outbound.streamSettings.tlsSettings, undefined);
  const wg = srv('w', 'wireguard://' + encodeURIComponent('cHJpdmF0ZS1rZXktQS1BQUFBQUFBQUFBQUFBQUFBQUE=') + '@engage.example.com:2408?publickey=' + encodeURIComponent('Q29ycG9yYXRlU2VydmVyUHVibGljS2V5MDAwMDAwMDA=') + '&address=10.0.0.2%2F32#W');
  assert.equal(A.withTarget(wg, { address: '2606:4700::1' }).outbound.settings.peers[0].endpoint, '[2606:4700::1]:2408');
  assert.throws(() => A.withTarget(CDN, { port: 70000 }), (e) => e.code === 'invalid');
  assert.throws(() => A.withTarget({ id: 'x', protocol: 'socks', outbound: { protocol: 'socks', settings: {} } }, { address: '1.1.1.1' }), (e) => e.code === 'unsupported');
});

/* ------------------------------ the builder ------------------------------ */
const groupOf = (members, strategy) => G.groupRecord({ id: 'grp-g', name: 'G', strategy, members }, byId);
const tagsOf = (cfg) => cfg.outbounds.map((o) => o.tag);
const find = (cfg, tag) => cfg.outbounds.find((o) => o.tag === tag);

test('a group selected: the loopback as the exit, its members T~gm<i>, the balancer (fallback = the first member) and its rule FIRST, one observatory', () => {
  const cfg = B.buildConfig({ mode: 'single', server: groupOf([{ id: 'de' }, { id: 'nl' }]) }, SETTINGS);
  assert.deepEqual(find(cfg, 'proxy'), { tag: 'proxy', protocol: 'loopback', settings: { inboundTag: 'proxy~in' } });
  assert.equal(find(cfg, 'proxy~gm0').protocol, 'vless');
  assert.equal(find(cfg, 'proxy~gm1').protocol, 'trojan');
  assert.deepEqual(cfg.routing.balancers, [{ tag: 'proxy~bal', selector: ['proxy~gm'], strategy: { type: 'roundRobin' }, fallbackTag: 'proxy~gm0' }]);
  assert.deepEqual(cfg.routing.rules[0], { type: 'field', inboundTag: ['proxy~in'], balancerTag: 'proxy~bal' });
  assert.deepEqual(cfg.observatory, { subjectSelector: ['proxy~gm'], probeUrl: 'http://cp.cloudflare.com/', probeInterval: '10s', enableConcurrency: true });
  assert.equal(JSON.stringify(cfg).includes('_group'), false, 'no marker left for the core');
  // every outbound the plan dials still has a unique tag
  assert.equal(new Set(tagsOf(cfg)).size, tagsOf(cfg).length);
  // the strategy as chosen
  assert.equal(B.buildConfig({ mode: 'single', server: groupOf(['de', 'nl'], 'leastPing') }, SETTINGS).routing.balancers[0].strategy.type, 'leastPing');
  // no group, no balancer, no observatory
  const plain = B.buildConfig({ mode: 'single', server: DE }, SETTINGS);
  assert.equal('balancers' in plain.routing, false);
  assert.equal('observatory' in plain, false);
});

test('a chain through a group is a group of whole chains — one variant per member in its place, hops named outside the member prefix; nothing dials a loopback', () => {
  const g = groupOf(['de', 'nl']);
  const dials = (cfg, tag) => ((find(cfg, tag).streamSettings || {}).sockopt || {}).dialerProxy;
  // [G → CDN]: CDN reached through DE, or through NL
  let cfg = B.buildConfig({ mode: 'chain', chain: [g, CDN] }, SETTINGS);
  assert.deepEqual(find(cfg, 'proxy'), { tag: 'proxy', protocol: 'loopback', settings: { inboundTag: 'proxy~in' } });
  assert.equal(find(cfg, 'proxy~gm0').settings.vnext[0].address, 'cdn.example.com');
  assert.equal(dials(cfg, 'proxy~gm0'), 'proxy~gh0-h0');
  assert.equal(find(cfg, 'proxy~gh0-h0').settings.vnext[0].address, 'de.example.net');
  assert.equal(dials(cfg, 'proxy~gm1'), 'proxy~gh1-h0');
  assert.equal(find(cfg, 'proxy~gh1-h0').protocol, 'trojan');
  assert.deepEqual(cfg.routing.balancers, [{ tag: 'proxy~bal', selector: ['proxy~gm'], strategy: { type: 'roundRobin' }, fallbackTag: 'proxy~gm0' }]);
  // [CDN → G]: CDN built ONCE, DE and NL each behind it
  cfg = B.buildConfig({ mode: 'chain', chain: [CDN, g] }, SETTINGS);
  assert.equal(find(cfg, 'proxy-h0').settings.vnext[0].address, 'cdn.example.com');
  assert.equal(find(cfg, 'proxy~gm0').settings.vnext[0].address, 'de.example.net');
  assert.equal(dials(cfg, 'proxy~gm0'), 'proxy-h0');
  assert.equal(dials(cfg, 'proxy~gm1'), 'proxy-h0');
  assert.equal(cfg.outbounds.filter((o) => (o.settings && o.settings.vnext || [])[0] && o.settings.vnext[0].address === 'cdn.example.com').length, 1);
  // two groups: every combination
  const g2 = G.groupRecord({ id: 'grp-2', name: 'G2', members: ['cdn', 'nl'] }, byId);
  cfg = B.buildConfig({ mode: 'chain', chain: [g, g2] }, SETTINGS);
  assert.equal(cfg.outbounds.filter((o) => /^proxy~gm\d+$/.test(o.tag)).length, 4);
  // no TCP hop anywhere dials a loopback
  const loops = new Set(cfg.outbounds.filter((o) => o.protocol === 'loopback').map((o) => o.tag));
  assert.equal(cfg.outbounds.some((o) => loops.has(((o.streamSettings || {}).sockopt || {}).dialerProxy)), false);
});

test('a WireGuard in a chain with a group is ONE outbound — after the group it dials the group\'s loopback (never one copy per member: one key, one session); before it, every member dials it', () => {
  const wg = Object.assign(srv('w', 'wireguard://' + encodeURIComponent('cHJpdmF0ZS1rZXktQS1BQUFBQUFBQUFBQUFBQUFBQUE=') + '@162.159.192.1:2408?publickey=' + encodeURIComponent('Q29ycG9yYXRlU2VydmVyUHVibGljS2V5MDAwMDAwMDA=') + '&address=172.16.0.2%2F32#WARP'), {});
  const ids = Object.assign({ w: wg }, byId);
  const g = G.groupRecord({ id: 'grp-c', members: [{ id: 'cdn', address: '104.16.1.1' }, { id: 'cdn', address: '104.17.2.2' }] }, ids);
  const dials = (cfg, tag) => ((find(cfg, tag).streamSettings || {}).sockopt || {}).dialerProxy;
  const wgs = (cfg) => cfg.outbounds.filter((o) => o.protocol === 'wireguard');
  // [G → WARP]: the group's loopback at hop 0, the one WireGuard dialling it
  let cfg = B.buildConfig({ mode: 'chain', chain: [g, wg] }, SETTINGS);
  assert.equal(wgs(cfg).length, 1);
  assert.equal(wgs(cfg)[0].tag, 'proxy');
  assert.equal(find(cfg, 'proxy-h0').protocol, 'loopback');
  assert.equal(dials(cfg, 'proxy'), 'proxy-h0');
  assert.deepEqual(['proxy-h0~gm0', 'proxy-h0~gm1'].map((t) => find(cfg, t).settings.vnext[0].address), ['104.16.1.1', '104.17.2.2']);
  assert.equal(cfg.routing.rules[0].balancerTag, 'proxy-h0~bal');
  // [G → DE → WARP]: the stretch [G → DE] varies, the WireGuard after it once
  cfg = B.buildConfig({ mode: 'chain', chain: [g, DE, wg] }, SETTINGS);
  assert.equal(wgs(cfg).length, 1);
  assert.equal(dials(cfg, 'proxy'), 'proxy-h1');
  assert.equal(find(cfg, 'proxy-h1').protocol, 'loopback');
  assert.equal(find(cfg, 'proxy-h1~gm0').settings.vnext[0].address, 'de.example.net');
  assert.equal(dials(cfg, 'proxy-h1~gm0'), 'proxy-h1~gh0-h0');
  // [WARP → G]: the WireGuard first, once; both members behind it
  const g2 = G.groupRecord({ id: 'grp-d', members: ['de', 'nl'] }, ids);
  cfg = B.buildConfig({ mode: 'chain', chain: [wg, g2] }, SETTINGS);
  assert.equal(wgs(cfg).length, 1);
  assert.equal(wgs(cfg)[0].tag, 'proxy-h0');
  assert.deepEqual(['proxy~gm0', 'proxy~gm1'].map((t) => dials(cfg, t)), ['proxy-h0', 'proxy-h0']);
});

test('a chain base with a group in it registers nothing: each target through it is the whole chain [base → target]', () => {
  const g = groupOf(['de', 'nl']);
  const plan = {
    mode: 'advanced', serversById: Object.assign({}, byId, { 'grp-g': g }), chainsById: { c2: [g, NL] }, chain: [],
    rules: [{ type: 'domain', value: 'example.com', target: 'cdn', via: 'chain:c2' }], def: 'de'
  };
  const cfg = B.buildConfig(plan, SETTINGS);
  assert.equal(cfg.outbounds.some((o) => o.tag.startsWith('base-')), false);
  assert.equal(find(cfg, 'out-cdn@chain-c2').protocol, 'loopback');
  // the variant [DE → NL → CDN]: CDN at the exit, behind the variant's NL, behind its DE
  const exit = find(cfg, 'out-cdn@chain-c2~gm0');
  assert.equal(exit.settings.vnext[0].address, 'cdn.example.com');
  assert.equal(exit.streamSettings.sockopt.dialerProxy, 'out-cdn@chain-c2~gh0-h1');
  assert.equal(find(cfg, 'out-cdn@chain-c2~gh0-h1').protocol, 'trojan');
});

test('a group in advanced routing: a rule target, the default — its own loopback; as a base, each target through it is [group → target]; a group gone is a target that no longer exists', () => {
  const g = groupOf(['de', 'nl']);
  const plan = {
    mode: 'advanced', serversById: Object.assign({}, byId, { 'grp-g': g }), chainsById: {}, chain: [],
    rules: [{ type: 'domain', value: 'example.org', target: 'grp-g' }, { type: 'domain', value: 'example.com', target: 'cdn', via: 'grp-g' }],
    def: 'de'
  };
  const cfg = B.buildConfig(plan, SETTINGS);
  const rule = cfg.routing.rules.find((r) => r.domain && r.domain.includes('example.org'));
  assert.equal(rule.outboundTag, 'out-grp-g');
  assert.equal(find(cfg, 'out-grp-g').protocol, 'loopback');
  // the base registers nothing of its own; the target is a group of [DE → CDN], [NL → CDN]
  assert.equal(cfg.outbounds.some((o) => o.tag.startsWith('base-')), false);
  assert.equal(find(cfg, 'out-cdn@grp-g').protocol, 'loopback');
  assert.equal(find(cfg, 'out-cdn@grp-g~gm0').settings.vnext[0].address, 'cdn.example.com');
  assert.equal(find(cfg, 'out-cdn@grp-g~gm0').streamSettings.sockopt.dialerProxy, 'out-cdn@grp-g~gh0-h0');
  assert.deepEqual(cfg.routing.balancers.map((b) => b.tag).sort(), ['out-cdn@grp-g~bal', 'out-grp-g~bal']);
  assert.deepEqual(cfg.routing.rules.slice(0, 2).map((r) => r.balancerTag).sort(), ['out-cdn@grp-g~bal', 'out-grp-g~bal']);
  assert.deepEqual(cfg.observatory.subjectSelector.sort(), ['out-cdn@grp-g~gm', 'out-grp-g~gm']);
  // the default gone (a group whose members are all gone has no record) → refused, as a deleted server is
  assert.throws(() => B.buildConfig(Object.assign({}, plan, { def: 'grp-gone' }), SETTINGS), /no longer exists|دیگر وجود ندارد/);
});

test('a group in the pool and in the latency tests: expanded the same way (the tests without a health check)', () => {
  const g = groupOf(['de', 'nl']);
  const pool = B.buildConfig({ mode: 'pool', entries: [{ id: 'p1', name: 'P', target: 'grp-g', socksPort: 41090, httpPort: 0 }], primary: 'grp-g', serversById: Object.assign({}, byId, { 'grp-g': g }), chainsById: {}, chain: [] }, SETTINGS);
  assert.equal(pool.routing.rules[0].balancerTag, 'out-grp-g~bal');
  assert.ok(pool.observatory);
  const t = B.buildTestConfig(g, 41095);
  assert.deepEqual(t.routing.rules[0], { type: 'field', inboundTag: ['proxy~in'], balancerTag: 'proxy~bal' });
  assert.equal(t.routing.rules[1].outboundTag, 'proxy');
  assert.equal('observatory' in t, false);
  const m = B.buildMultiTestConfig([g, DE], [41096, 41097]);
  assert.equal(m.routing.rules[0].balancerTag, 'test-out-0~bal');
  assert.ok(find(m, 'test-out-0~gm1'));
});

test('a JSON member\'s helpers are named outside the balancer\'s prefix — the balancer can never pick a fragment dialer', () => {
  const json = { id: 'j', name: 'J', protocol: 'vless', source: 'json', address: 'j.example.net', port: 443,
    outbound: { protocol: 'vless', settings: { vnext: [{ address: 'j.example.net', port: 443, users: [{ id: UUID, encryption: 'none' }] }] }, streamSettings: { network: 'tcp', sockopt: { dialerProxy: 'frag' } } },
    extraOutbounds: [{ tag: 'frag', protocol: 'freedom', settings: { fragment: { packets: 'tlshello', length: '100-200', interval: '10-20' } } }] };
  const g = G.groupRecord({ id: 'grp-j', members: ['j', 'de'] }, Object.assign({ j: json }, byId));
  const cfg = B.buildConfig({ mode: 'single', server: g }, SETTINGS);
  assert.equal(find(cfg, 'proxy~gm0').streamSettings.sockopt.dialerProxy, 'proxy~gh0~frag');
  assert.ok(find(cfg, 'proxy~gh0~frag'));
  assert.equal(cfg.outbounds.filter((o) => o.tag.startsWith('proxy~gm')).length, 2, 'the prefix holds the two members only');
});

test('what the machine dials itself: a group is entered at each member — addresses, hosts to resolve first, WireGuard endpoints and resolvers', () => {
  const wg = Object.assign(srv('w', 'wireguard://' + encodeURIComponent('cHJpdmF0ZS1rZXktQS1BQUFBQUFBQUFBQUFBQUFBQUE=') + '@vpn.corp.example:51820?publickey=' + encodeURIComponent('Q29ycG9yYXRlU2VydmVyUHVibGljS2V5MDAwMDAwMDA=') + '&address=10.0.0.2%2F32#W'), { dns: ['192.168.60.1'] });
  const g = G.groupRecord({ id: 'grp-e', members: [{ id: 'cdn', address: '104.16.1.1' }, 'nl', 'w'] }, Object.assign({ w: wg }, byId));
  assert.deepEqual(B.entryAddressesOf(g), ['104.16.1.1', 'nl.example.net', 'vpn.corp.example']);
  assert.deepEqual(B.entryHosts({ mode: 'single', server: g }), ['nl.example.net']);
  assert.deepEqual(B.wgEndpointHosts({ mode: 'single', server: g }), ['vpn.corp.example']);
  assert.deepEqual(B.wgResolverAddresses({ mode: 'single', server: g }), ['192.168.60.1']);
  assert.deepEqual(planServers({ mode: 'single', server: g }).map((s) => s.id), ['cdn', 'nl', 'w']);
});

test('the engine: a group runs on Xray — Xray-PattN when a member asks for it — never sing-box', () => {
  const sb = Object.assign({}, DE, { id: 'sb', engine: 'sing-box' });
  const pn = Object.assign({}, NL, { id: 'pn', engine: 'xray-pattn' });
  assert.equal(chooseEngine({ mode: 'single', server: G.groupRecord({ id: 'grp-s', members: ['sb', 'de'] }, Object.assign({ sb }, byId)) }), 'xray');
  assert.equal(chooseEngine({ mode: 'single', server: G.groupRecord({ id: 'grp-p', members: ['pn', 'de'] }, Object.assign({ pn }, byId)) }), 'xray-pattn');
  assert.equal(chooseEngine({ mode: 'single', server: sb }), 'sing-box', 'a server alone as before');
});

test('the backup carries groups; a restore merges them by id, without the members it left out', () => {
  const b = exportBundle({ store: { servers: [DE], groups: [{ id: 'grp-1', name: 'G', strategy: 'random', members: [{ id: 'de' }, { id: 'zz' }] }] } });
  assert.equal(b.groups.length, 1);
  assert.equal('groups' in exportBundle({ store: { servers: [] } }), false, 'none → absent, as before');
  const r = importBundle(b, { servers: [], groups: [{ id: 'grp-0', name: 'Mine', strategy: 'roundRobin', members: [] }] });
  assert.equal(r.added.groups, 1);
  assert.deepEqual(r.next.groups.map((g) => g.id), ['grp-0', 'grp-1']);
  assert.deepEqual(r.next.groups[1].members, [{ id: 'de' }, { id: 'zz' }]);
});

test('wired: main.js and the router keep groups beside the servers in a plan, answer groups:list / groups:set, give app:init its groups; the bridges call them', () => {
  for (const [label, src] of [['main.js', R('src', 'main', 'main.js')], ['service.js', R('src', 'server', 'service.js')]]) {
    assert.match(src, /Object\.assign\(serversById, groupRecordsById\(getGroups\(\), Object\.assign\(\{\}, serversById\)\)\);/, label);
    assert.match(src, /groups: getGroups\(\),\n\s*pool: getPool\(\),/, `${label}: app:init`);
    assert.match(src, /isGroupRecord\(server\)\) return \{ ok: false, na: true/, `${label}: ping:tcp`);
  }
  assert.match(R('src', 'main', 'main.js'), /ipcMain\.handle\('groups:set', \(e, groups\) => \{\n\s*const valid = normalizeGroups\(groups\);/);
  assert.match(R('src', 'server', 'service.js'), /'groups:set': \(groups\) => \{ const v = normalizeGroups\(groups\); store\.set\('groups', v\); return v; \},/);
  assert.match(R('src', 'preload', 'preload.js'), /setGroups: \(groups\) => ipcRenderer\.invoke\('groups:set', groups\),/);
  assert.match(R('src', 'server', 'web-api.js'), /setGroups: \(groups\) => invoke\('groups:set', groups\),/);
});

test('router: a group saved, selected, built and pinged through the real service — its config has the balancer; a TCP ping says it has no one address', async (t) => {
  const s = H.start({}, {});
  t.after(() => s.service.shutdown());
  const saved = await s.service.invoke('groups:set', [{ id: 'grp-r', name: 'R', members: [{ id: H.SERVER.id }, { id: H.SERVER_B.id }] }]);
  assert.deepEqual(saved.map((g) => [g.id, g.strategy, g.members.length]), [['grp-r', 'roundRobin', 2]]);
  assert.deepEqual((await s.service.invoke('groups:list')).map((g) => g.id), ['grp-r']);
  assert.deepEqual((await s.service.invoke('app:init')).groups.map((g) => g.id), ['grp-r']);
  const ping = await s.service.invoke('ping:tcp', 'grp-r');
  assert.equal(ping.na, true);
});

test('the traffic meter: a group\'s members count as the group (the core counts nothing on its loopback) — once in the total, under the group\'s tag per outbound; hops and helpers stay out', () => {
  const { sumOutbounds, byOutbound } = require('../src/main/stats');
  const vars = { stats: { outbound: {
    proxy: { uplink: 0, downlink: 0 },
    'proxy~gm0': { uplink: 10, downlink: 100 }, 'proxy~gm1': { uplink: 5, downlink: 50 },
    'proxy~gh0-h0': { uplink: 10, downlink: 100 }, 'proxy~gh1~frag': { uplink: 1, downlink: 1 },
    'out-grp-x': { uplink: 0, downlink: 0 }, 'out-grp-x~gm0': { uplink: 2, downlink: 20 },
    direct: { uplink: 3, downlink: 30 }
  } } };
  assert.deepEqual(sumOutbounds(vars), { up: 17, down: 170 });
  const per = byOutbound(vars);
  assert.deepEqual(per.proxy, { up: 15, down: 150 });
  assert.deepEqual(per['out-grp-x'], { up: 2, down: 20 });
  assert.equal(Object.keys(per).some((t) => t.includes('~')), false);
  assert.deepEqual(per.direct, { up: 3, down: 30 });
});

test('the live view: each group in the config with who T~gm<i> is (a chain variant by the member it takes) — beside the config, never in what is written', () => {
  const g = groupOf([{ id: 'cdn', address: '104.16.1.1' }, 'de']);
  const cfg = B.buildConfig({ mode: 'single', server: g }, SETTINGS);
  assert.deepEqual(cfg.groupTags, [{ tag: 'proxy', groupId: 'grp-g', name: 'G', strategy: 'roundRobin', direct: true, fallback: null, members: [
    { id: 'cdn', name: 'CDN', address: '104.16.1.1', port: 443, direct: true }, { id: 'de', name: 'DE', address: 'de.example.net', port: 8443, direct: true }] }]);
  assert.equal(JSON.stringify(cfg).includes('groupTags'), false);
  assert.equal(Object.keys(cfg).includes('groupTags'), false);
  // a chain through the group: the variants named by their member
  const c = B.buildConfig({ mode: 'chain', chain: [NL, g] }, SETTINGS);
  assert.deepEqual(c.groupTags.map((x) => [x.tag, x.members.map((m) => m.id)]), [['proxy', ['cdn', 'de']]]);
  // ...which the app cannot test member by member as the core dials them (groupEvict.js leaves them to the core)
  assert.deepEqual(c.groupTags[0].members.map((m) => m.direct), [false, false]);
  // advanced: one entry per instance, by its own tag
  const adv = B.buildConfig({ mode: 'advanced', serversById: Object.assign({}, byId, { 'grp-g': g }), chainsById: {}, chain: [],
    rules: [{ type: 'domain', value: 'example.org', target: 'grp-g' }], def: 'de' }, SETTINGS);
  assert.deepEqual(adv.groupTags.map((x) => x.tag), ['out-grp-g']);
  // no group: null
  assert.equal(B.buildConfig({ mode: 'single', server: DE }, SETTINGS).groupTags, null);
});

test('the meter\'s groups: each member\'s bytes, speed and health from the core (alive with its delay; a dead one false; not probed yet null)', () => {
  const S = require('../src/main/stats');
  const vars = { stats: { outbound: { proxy: { uplink: 0, downlink: 0 }, 'proxy~gm0': { uplink: 100, downlink: 5000 }, 'proxy~gm1': { uplink: 50, downlink: 1000 }, direct: { uplink: 1, downlink: 1 } } },
    observatory: { 'proxy~gm0': { alive: true, delay: 84 }, 'proxy~gm2': { delay: 99999999, last_error_reason: 'dead' } } };
  assert.deepEqual(S.memberCounters(vars), { 'proxy~gm0': { up: 100, down: 5000 }, 'proxy~gm1': { up: 50, down: 1000 } });
  assert.deepEqual(S.healthOf(vars), { 'proxy~gm0': { alive: true, delay: 84 }, 'proxy~gm2': { alive: false, delay: null } });
  const map = [{ tag: 'proxy', groupId: 'grp-g', name: 'G', strategy: 'roundRobin', members: [{ id: 'a' }, { id: 'b' }, { id: 'c' }] }];
  const live = S.groupsLive(map, S.memberCounters(vars), { 'proxy~gm0': { up: 0, down: 3000 } }, S.healthOf(vars), 2);
  assert.deepEqual(live[0].members.map((m) => [m.id, m.down, m.downSpeed, m.alive, m.delay]),
    [['a', 5000, 1000, true, 84], ['b', 1000, 0, null, null], ['c', 0, 0, false, null]]);
});

test('the poller sends groups only while a group runs; main.js and the router hand it the map at every connect', async () => {
  const http = require('node:http');
  const { StatsPoller } = require('../src/main/stats');
  const body = JSON.stringify({ stats: { outbound: { proxy: { uplink: 0, downlink: 0 }, 'proxy~gm0': { uplink: 10, downlink: 20 } } }, observatory: { 'proxy~gm0': { alive: true, delay: 5 } } });
  const srv = http.createServer((q, r) => { r.writeHead(200); r.end(body); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  try {
    const seen = [];
    const p = new StatsPoller({ apiPort: srv.address().port, onStats: (s) => seen.push(s) });
    p.last.t = Date.now() - 1000;
    await p.tick();
    assert.equal('groups' in seen[0], false, 'no map, no groups');
    p.groupMap = [{ tag: 'proxy', groupId: 'grp-g', name: 'G', strategy: 'roundRobin', members: [{ id: 'a', name: 'A' }] }];
    await p.tick();
    assert.deepEqual(seen[1].groups[0].members.map((m) => [m.id, m.down, m.alive, m.delay]), [['a', 20, true, 5]]);
    assert.deepEqual(seen[1].per.proxy.down, 20, 'the member still counts as its group');
  } finally { srv.close(); }
  for (const src of [R('src', 'main', 'main.js'), R('src', 'server', 'service.js')]) assert.match(src, /stats\.groupMap = config\.groupTags \|\| null;/);
});

test('the log says when a member leaves the rotation and when it rejoins — only changes, and once when no member answers', () => {
  const { GroupHealthWatch } = require('../src/main/stats');
  const w = new GroupHealthWatch();
  const tick = (a, b) => [{ tag: 'proxy', groupId: 'grp-g', name: 'CDN', members: [{ id: 's1', name: 'DE', address: '1.2.3.4', port: 443, alive: a }, { id: 's2', name: 'NL', alive: b }] }];
  assert.deepEqual(w.update(tick(null, null)), [], 'not checked yet: nothing');
  assert.deepEqual(w.update(tick(true, true)), [], 'the first verdict is no change');
  assert.deepEqual(w.update(tick(true, false)), [{ line: 'Group CDN: NL stopped answering — left out until it answers again', level: 'warn' }]);
  assert.deepEqual(w.update(tick(true, false)), [], 'still down: said once');
  const down = w.update(tick(false, false));
  assert.deepEqual(down.map((x) => x.line), ['Group CDN: DE (1.2.3.4:443) stopped answering — left out until it answers again', 'Group CDN: no member answers — its traffic waits on the first until one does']);
  assert.deepEqual(w.update(tick(false, true)).map((x) => [x.line, x.level]), [['Group CDN: NL answers again — back in the rotation', 'info']]);
  w.reset();
  assert.deepEqual(w.update(tick(false, false)).map((x) => x.line), ['Group CDN: no member answers — its traffic waits on the first until one does'], 'after a reconnect: no "stopped" for a first verdict, but the all-down warning');
  assert.deepEqual(w.update(undefined), []);
  for (const src of [R('src', 'main', 'main.js'), R('src', 'server', 'service.js')]) {
    assert.match(src, /for \(const l of groupHealth\.update\(s\.groups\)\) send\('log', l\);/);
    assert.match(src, /stats\.groupMap = config\.groupTags \|\| null;\n\s*groupHealth\.reset\(\);/);
  }
});

test('a group’s fallback (a WARP, say): kept as a server id, dialled as T~fb outside the members’ prefix, the balancer’s fallbackTag; never probed; folded into the group on the meter', () => {
  const WARP = srv('warp', `wireguard://${encodeURIComponent('cGVla2V5c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0MDA=')}@162.159.192.1:2408?publickey=${encodeURIComponent('bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=')}&address=172.16.0.2%2F32#WARP`);
  const all = Object.assign({}, byId, { warp: WARP });
  // stored: a server id only — a group's id, or nothing, leaves no field
  assert.equal(G.normalizeGroup({ id: 'grp-f', name: 'F', members: ['cdn'], fallback: ' warp ' }).fallback, 'warp');
  assert.equal('fallback' in G.normalizeGroup({ id: 'grp-f', name: 'F', members: ['cdn'], fallback: 'grp-x' }), false);
  assert.equal('fallback' in G.normalizeGroup({ id: 'grp-f', name: 'F', members: ['cdn'] }), false);
  const g = G.groupRecord({ id: 'grp-f', name: 'F', members: [{ id: 'cdn' }, { id: 'de' }], fallback: 'warp' }, all);
  assert.equal(g.outbound._group.fallback, WARP);
  assert.deepEqual(G.serversOf(g).map((s) => s.id), ['cdn', 'de', 'warp'], 'it is dialled too: endpoints, pins, the engine see it');
  assert.equal(G.groupRecord({ id: 'grp-f', name: 'F', members: [{ id: 'cdn' }], fallback: 'gone' }, all).outbound._group.fallback, null, 'a fallback deleted since: none');
  const cfg = B.buildConfig({ mode: 'single', server: g }, SETTINGS);
  assert.equal(cfg.routing.balancers[0].fallbackTag, 'proxy~fb');
  assert.deepEqual(cfg.routing.balancers[0].selector, ['proxy~gm']);
  assert.deepEqual(cfg.observatory.subjectSelector, ['proxy~gm'], 'never probed');
  assert.equal(cfg.outbounds.find((o) => o.tag === 'proxy~fb').protocol, 'wireguard');
  assert.deepEqual(cfg.groupTags[0].fallback, { id: 'warp', name: 'WARP' });
  // without one: the first member, as before
  const plain = B.buildConfig({ mode: 'single', server: G.groupRecord({ id: 'grp-f', name: 'F', members: [{ id: 'cdn' }, { id: 'de' }] }, all) }, SETTINGS);
  assert.equal(plain.routing.balancers[0].fallbackTag, 'proxy~gm0');
  assert.equal(plain.outbounds.some((o) => o.tag === 'proxy~fb'), false);
  // a group behind a hop: its fallback rides the same hop
  const behind = B.buildConfig({ mode: 'chain', chain: [NL, g] }, SETTINGS);
  const fbOut = behind.outbounds.find((o) => /~fb$/.test(o.tag));
  assert.ok(!fbOut || (fbOut.streamSettings && fbOut.streamSettings.sockopt && fbOut.streamSettings.sockopt.dialerProxy), 'through the hop, never straight out');
  // the meter: the fallback's bytes are the group's
  const S = require('../src/main/stats');
  assert.deepEqual(S.foldGroups({ proxy: { uplink: 0, downlink: 0 }, 'proxy~gm0': { uplink: 1, downlink: 10 }, 'proxy~fb': { uplink: 2, downlink: 20 } }), { proxy: { uplink: 3, downlink: 30 } });
  // the log names it when no member answers
  const w = new S.GroupHealthWatch();
  w.update([{ tag: 'proxy', name: 'F', fallback: { id: 'warp', name: 'WARP' }, members: [{ alive: true }, { alive: true }] }]);
  const lines = w.update([{ tag: 'proxy', name: 'F', fallback: { id: 'warp', name: 'WARP' }, members: [{ alive: false }, { alive: false }] }]);
  assert.ok(lines.some((l) => /its traffic goes through its fallback, WARP, until one does/.test(l.line)));
});
