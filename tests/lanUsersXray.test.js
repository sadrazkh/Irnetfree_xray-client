'use strict';
/**
 * Users and devices (module lanUsers) in the Xray config — through the app's
 * own builder (configBuilder.buildConfig / buildPoolConfig, which call
 * src/modules/lanUsers/xray.js): one SOCKS5 and one HTTP inbound with every
 * active user's account, one rule per user by username (the core names a
 * SOCKS/HTTP session's user by it — xray.js cites the source), each user's
 * target as an outbound that every pass of the builder reaches, and not a byte
 * of the config changed while the module is off.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { buildConfig } = require('../src/main/configBuilder');
const { groupRecord } = require('../src/main/groups');
const X = require('../src/modules/lanUsers/xray');
const F = require('./fixtures');

const ON = { modules: { lanUsers: true } };
const MANAGED = { dnsManaged: true, dnsRemote: ['https://1.1.1.1/dns-query'], dnsDirect: ['178.22.122.100'] };
const user = (id, username, over) => Object.assign({ id, username, password: 'pw-' + username, name: '', target: '', quotaGb: 0, quotaPeriod: 'month', expiresAt: 0, maxDevices: 0, enabled: true }, over);
const NOW = 1_800_000_000_000;
const GROUP = groupRecord({ id: 'grp-1', name: 'G', strategy: 'roundRobin', members: [{ id: 'sv-trojan' }, { id: 'sv-ss' }] }, { 'sv-trojan': F.TROJAN_TCP_TLS, 'sv-ss': F.SS_TCP });

/** The build input ipc.js forBuild() makes: the store's record, the moment, the listen, the records the targets name. */
function lu(users, over) {
  return Object.assign({
    config: { proxy: { enabled: true, port: 30820, httpPort: 30821 } },
    users, devices: [], over: [], now: NOW,
    serversById: { 'sv-trojan': F.TROJAN_TCP_TLS, 'sv-ss': F.SS_TCP, 'sv-vless': F.VLESS_WS_TLS, 'grp-1': GROUP },
    chainsById: { c1: [F.SS_TCP, F.TROJAN_TCP_TLS] }
  }, over);
}
const single = { mode: 'single', server: F.VLESS_WS_TLS };
const inbound = (cfg, tag) => cfg.inbounds.find((i) => i.tag === tag);
const ruleFor = (cfg, username) => cfg.routing.rules.find((r) => Array.isArray(r.user) && r.user.includes(username));

/* ------------------------------ off: byte for byte ------------------------------ */

test('off — module not installed, proxy off, nobody active, or no store at all — the config is byte-identical to one built without it', () => {
  const someone = lu([user('usr-a', 'ali', { target: 'sv-trojan' })]);
  const plans = {
    single,
    chain: { mode: 'chain', chain: [F.VLESS_WS_TLS, F.TROJAN_TCP_TLS] },
    advanced: { mode: 'advanced', serversById: { 'sv-vless': F.VLESS_WS_TLS, 'sv-trojan': F.TROJAN_TCP_TLS }, chainsById: {}, chain: [], rules: [{ type: 'domain', value: 'a.com', target: 'sv-trojan' }], def: 'sv-vless' },
    pool: { mode: 'pool', entries: [{ id: 'e1', target: 'sv-trojan', socksPort: 60001 }], primary: 'sv-vless', serversById: { 'sv-vless': F.VLESS_WS_TLS, 'sv-trojan': F.TROJAN_TCP_TLS }, chainsById: {}, chain: [] }
  };
  for (const [name, plan] of Object.entries(plans)) {
    for (const base of [{}, MANAGED, Object.assign({ tunMode: true, directInterface: 'Wi-Fi' }, MANAGED)]) {
      const plain = JSON.stringify(buildConfig(plan, F.settings(base)));
      const variants = {
        'no module': { lanUsers: someone },
        'module off': { modules: { lanUsers: false }, lanUsers: someone },
        'proxy off': Object.assign({ lanUsers: lu(someone.users, { config: { proxy: { enabled: false } } }) }, ON),
        'nobody active': Object.assign({ lanUsers: lu([user('usr-a', 'ali', { enabled: false }), user('usr-b', 'sara', { expiresAt: NOW - 1 })]) }, ON),
        'no store': Object.assign({ lanUsers: null }, ON)
      };
      for (const [v, over] of Object.entries(variants)) {
        assert.equal(JSON.stringify(buildConfig(plan, F.settings(Object.assign({}, base, over)))), plain, `${name} / ${v}`);
      }
    }
  }
});

/* ------------------------------ the inbounds ------------------------------ */

test('on: lu-socks (SOCKS5, password, UDP) and lu-http with every ACTIVE user’s account — disabled, expired and capped users are simply not in them', () => {
  const cfg = buildConfig(single, F.settings(Object.assign({ lanUsers: lu([
    user('usr-a', 'ali'), user('usr-b', 'off', { enabled: false }), user('usr-c', 'old', { expiresAt: NOW - 1000 }),
    user('usr-d', 'capped', { quotaGb: 1 }), user('usr-e', 'sara', { expiresAt: NOW + 86400000 })
  ], { over: ['usr-d'] }) }, ON)));
  const socks = inbound(cfg, 'lu-socks');
  const http = inbound(cfg, 'lu-http');
  assert.deepEqual(socks, {
    tag: 'lu-socks', port: 30820, listen: '0.0.0.0', protocol: 'socks',
    settings: { auth: 'password', accounts: [{ user: 'ali', pass: 'pw-ali' }, { user: 'sara', pass: 'pw-sara' }], udp: true },
    sniffing: { enabled: true, destOverride: ['http', 'tls', 'quic'], routeOnly: false }
  });
  assert.deepEqual(http.settings, { accounts: [{ user: 'ali', pass: 'pw-ali' }, { user: 'sara', pass: 'pw-sara' }], allowTransparent: false });
  assert.equal(http.listen, '0.0.0.0');
  assert.equal(http.port, 30821);
  // the app's own inbounds as they were: loopback, no accounts
  assert.deepEqual(cfg.inbounds.slice(0, 2).map((i) => [i.tag, i.listen]), [['socks-in', '127.0.0.1'], ['http-in', '127.0.0.1']]);
  // per-user counters: level 0 counts them (the core's user>>><username>>>>traffic)
  assert.deepEqual(cfg.policy.levels['0'], { statsUserUplink: true, statsUserDownlink: true });
});

test('the listen: the desktop’s every address (as LAN sharing), the router’s LAN address, none known → no proxy at all; httpPort 0 → SOCKS only', () => {
  const users = [user('usr-a', 'ali')];
  const at = (over) => buildConfig(single, F.settings(Object.assign({ lanUsers: lu(users, over) }, ON)));
  assert.equal(inbound(at({}), 'lu-socks').listen, '0.0.0.0', 'desktop: no listen named');
  assert.equal(inbound(at({ listen: '192.168.1.1' }), 'lu-socks').listen, '192.168.1.1', 'router: its LAN address');
  assert.equal(inbound(at({ listen: '192.168.1.1' }), 'lu-http').listen, '192.168.1.1');
  const none = at({ listen: '' });
  assert.equal(inbound(none, 'lu-socks'), undefined, 'no address: no inbound');
  assert.ok(!none.outbounds.some((o) => o.tag.startsWith('lu-')), 'and no outbound made for nothing');
  assert.equal(inbound(at({ listen: 'not-an-ip' }), 'lu-socks'), undefined);
  const socksOnly = at({ config: { proxy: { enabled: true, port: 30820, httpPort: 0 } } });
  assert.ok(inbound(socksOnly, 'lu-socks'));
  assert.equal(inbound(socksOnly, 'lu-http'), undefined);
  assert.deepEqual(ruleFor(socksOnly, 'ali').inboundTag, ['lu-socks']);
});

test('a port the config already holds (the app’s own, the metrics, a pool entry’s) is left out — the core would refuse to start over it', () => {
  const clash = buildConfig(single, F.settings(Object.assign({ socksPort: 30820, lanUsers: lu([user('usr-a', 'ali')]) }, ON)));
  assert.equal(clash.inbounds.filter((i) => i.port === 30820).length, 1);
  assert.equal(inbound(clash, 'lu-socks'), undefined);
  assert.ok(inbound(clash, 'lu-http'), 'the other one stands');
  assert.deepEqual(ruleFor(clash, 'ali').inboundTag, ['lu-http']);
  const metrics = buildConfig(single, F.settings(Object.assign({ apiPort: 30821, lanUsers: lu([user('usr-a', 'ali')]) }, ON)));
  assert.equal(inbound(metrics, 'lu-http'), undefined, 'the metrics listener’s port');
});

/* ------------------------------ the rules ------------------------------ */

test('the rules: after the DNS rules, ahead of everything of the plan’s — loopback blocked, one rule per username, the rest of the users’ inbounds blocked; the catch-all stays last', () => {
  const cfg = buildConfig(single, F.settings(Object.assign({ routingMode: 'bypass-ir', lanUsers: lu([user('usr-a', 'ali', { target: 'sv-trojan' }), user('usr-b', 'sara')]) }, ON, MANAGED)));
  const rules = cfg.routing.rules;
  const first = rules.findIndex((r) => (r.inboundTag || []).includes('lu-socks'));
  // everything before is the DNS plan's
  for (const r of rules.slice(0, first)) assert.ok((r.inboundTag && r.inboundTag.includes('dns-internal')) || r.outboundTag === 'dns-out', JSON.stringify(r));
  assert.ok(first > 0, 'the DNS rules come first: a user’s port-53 query is answered by the app’s resolver');
  const ours = rules.slice(first, first + 5);
  assert.deepEqual(ours, [
    { type: 'field', inboundTag: ['lu-socks', 'lu-http'], ip: ['127.0.0.0/8', '0.0.0.0/8', '::1/128', '::/128'], outboundTag: 'block' },
    { type: 'field', inboundTag: ['lu-socks', 'lu-http'], domain: ['domain:localhost'], outboundTag: 'block' },
    { type: 'field', inboundTag: ['lu-socks', 'lu-http'], user: ['ali'], outboundTag: 'lu-out-sv-trojan' },
    { type: 'field', inboundTag: ['lu-socks', 'lu-http'], user: ['sara'], outboundTag: 'proxy' },
    { type: 'field', inboundTag: ['lu-socks', 'lu-http'], outboundTag: 'block' }
  ]);
  // the plan's own (the private bypass, Iran direct, the catch-all) all after
  const priv = rules.findIndex((r) => Array.isArray(r.ip) && r.ip.includes('192.168.0.0/16') && !r.inboundTag);
  assert.ok(priv > first + 4);
  assert.deepEqual(rules[rules.length - 1], { type: 'field', port: '0-65535', outboundTag: 'proxy' });
});

test('advanced routing: the owner’s rules never apply to a user (a corporate WireGuard for a domain stays his); a target the plan already dials shares its outbound', () => {
  const plan = {
    mode: 'advanced', serversById: { 'sv-vless': F.VLESS_WS_TLS, 'sv-trojan': F.TROJAN_TCP_TLS, 'sv-wgcorp': F.WG_CORP }, chainsById: {}, chain: [],
    rules: [{ type: 'domain', value: 'corp.example', target: 'sv-wgcorp' }, { type: 'domain', value: 'a.com', target: 'sv-trojan' }], def: 'sv-vless'
  };
  const cfg = buildConfig(plan, F.settings(Object.assign({ wgEndpointIps: { 'cobra.example': '198.51.100.21' }, lanUsers: lu([user('usr-a', 'ali', { target: 'sv-trojan' }), user('usr-b', 'sara', { target: 'sv-ss' })]) }, ON)));
  const at = (pred) => cfg.routing.rules.findIndex(pred);
  assert.ok(at((r) => r.user && r.user[0] === 'ali') < at((r) => r.domain && r.domain.includes('corp.example')), 'users first');
  assert.equal(ruleFor(cfg, 'ali').outboundTag, 'out-sv-trojan', 'shared with the plan’s own rule target');
  assert.equal(cfg.outbounds.filter((o) => o.tag.endsWith('sv-trojan')).length, 1, 'one outbound for it, not two');
  assert.equal(ruleFor(cfg, 'sara').outboundTag, 'lu-out-sv-ss');
});

/* ------------------------------ the targets ------------------------------ */

test('targets: "" → the current connection, direct, block, a server, a chain (its hops dialled through), a group (members, balancer, its loopback rule first)', () => {
  const cfg = buildConfig(single, F.settings(Object.assign({ lanUsers: lu([
    user('u1', 'now'), user('u2', 'dir', { target: 'direct' }), user('u3', 'blk', { target: 'block' }),
    user('u4', 'srv', { target: 'sv-trojan' }), user('u5', 'chn', { target: 'chain:c1' }), user('u6', 'grp', { target: 'grp-1' })
  ]) }, ON)));
  const to = (u) => ruleFor(cfg, u).outboundTag;
  // v1.39.0: 'direct' rides the user's own direct outbound (lu-d-<id>), whose counter is their direct bytes
  assert.deepEqual(['now', 'dir', 'blk', 'srv', 'chn', 'grp'].map(to), ['proxy', 'lu-d-u2', 'block', 'lu-out-sv-trojan', 'lu-out-chain-c1', 'lu-out-grp-1']);
  const out = (tag) => cfg.outbounds.find((o) => o.tag === tag);
  assert.deepEqual(out('lu-out-sv-trojan').settings, F.TROJAN_TCP_TLS.outbound.settings, 'the server’s own outbound');
  assert.equal(out('lu-out-chain-c1').protocol, 'trojan', 'the chain’s exit');
  assert.equal(out('lu-out-chain-c1').streamSettings.sockopt.dialerProxy, 'lu-out-chain-c1-h0', 'dialled through its first hop');
  assert.equal(out('lu-out-chain-c1-h0').protocol, 'shadowsocks');
  // the group: written out by expandGroups like the plan's own
  assert.deepEqual(out('lu-out-grp-1'), { tag: 'lu-out-grp-1', protocol: 'loopback', settings: { inboundTag: 'lu-out-grp-1~in' } });
  assert.ok(out('lu-out-grp-1~gm0') && out('lu-out-grp-1~gm1'));
  assert.ok(cfg.routing.balancers.some((b) => b.tag === 'lu-out-grp-1~bal'));
  assert.deepEqual(cfg.routing.rules[0], { type: 'field', inboundTag: ['lu-out-grp-1~in'], balancerTag: 'lu-out-grp-1~bal' }, 'what loops back meets its balancer before any rule');
  assert.ok(cfg.observatory.subjectSelector.includes('lu-out-grp-1~gm'));
  assert.ok(cfg.groupTags.some((g) => g.tag === 'lu-out-grp-1'), 'the live group meter sees it');
});

test('a target that is gone, a chain that lost a member, a WireGuard endpoint nobody resolved → block, never direct', () => {
  const cfg = buildConfig(single, F.settings(Object.assign({ lanUsers: lu([
    user('u1', 'gone', { target: 'sv-deleted' }), user('u2', 'broken', { target: 'chain:c9' }), user('u3', 'nochain', { target: 'chain:nope' }),
    user('u4', 'wg', { target: 'sv-wgcorp' })
  ], { chainsById: { c9: null }, serversById: { 'sv-wgcorp': F.WG_CORP } }) }, ON)));
  for (const u of ['gone', 'broken', 'nochain', 'wg']) assert.equal(ruleFor(cfg, u).outboundTag, 'block', u);
  assert.ok(!cfg.outbounds.some((o) => o.tag.startsWith('lu-out-')), 'nothing written for them');
  // resolved by ipc.js (lu.wgEndpointIps): the WireGuard runs, its endpoint the address
  const ok = buildConfig(single, F.settings(Object.assign({ lanUsers: lu([user('u4', 'wg', { target: 'sv-wgcorp' })], { serversById: { 'sv-wgcorp': F.WG_CORP }, wgEndpointIps: { 'cobra.example': '198.51.100.21' } }) }, ON)));
  assert.equal(ruleFor(ok, 'wg').outboundTag, 'lu-out-sv-wgcorp');
  assert.equal(ok.outbounds.find((o) => o.tag === 'lu-out-sv-wgcorp').settings.peers[0].endpoint, '198.51.100.21:42421');
});

test('a WireGuard the plan already dials is shared, never dialled twice (two sessions on one key cut each other off): the selection, a chain’s exit', () => {
  const sel = buildConfig({ mode: 'single', server: F.WG_CORP }, F.settings(Object.assign({ wgEndpointIps: { 'cobra.example': '198.51.100.21' }, lanUsers: lu([user('u1', 'wg', { target: 'sv-wgcorp' })], { serversById: { 'sv-wgcorp': F.WG_CORP } }) }, ON)));
  assert.equal(ruleFor(sel, 'wg').outboundTag, 'proxy');
  assert.equal(sel.outbounds.filter((o) => o.protocol === 'wireguard').length, 1);
  const chain = buildConfig({ mode: 'chain', chain: [F.VLESS_WS_TLS, F.WG_CORP] }, F.settings(Object.assign({ wgEndpointIps: { 'cobra.example': '198.51.100.21' }, lanUsers: lu([user('u1', 'wg', { target: 'sv-wgcorp' }), user('u2', 'same', { target: 'chain:cw' })], { serversById: { 'sv-wgcorp': F.WG_CORP }, chainsById: { cw: [F.VLESS_WS_TLS, F.WG_CORP] } }) }, ON)));
  assert.equal(ruleFor(chain, 'wg').outboundTag, 'proxy', 'the chain’s exit is that WireGuard');
  assert.equal(ruleFor(chain, 'same').outboundTag, 'proxy', 'the very chain the plan dials');
  assert.equal(chain.outbounds.filter((o) => o.protocol === 'wireguard').length, 1);
});

test('every pass of the builder reaches a user’s outbound: under TUN it is bound to the NIC, its anti-DPI dialer made like the plan’s', () => {
  const frag = F.vlessWithMarkers('sv-frag', { _fragment: 'tlshello,100-200,10-20' });
  const cfg = buildConfig(single, F.settings(Object.assign({ tunMode: true, directInterface: 'Wi-Fi', lanUsers: lu([user('u1', 'a', { target: 'sv-trojan' }), user('u2', 'b', { target: 'sv-frag' })], { serversById: { 'sv-trojan': F.TROJAN_TCP_TLS, 'sv-frag': frag } }) }, ON)));
  assert.deepEqual(cfg.outbounds.find((o) => o.tag === 'lu-out-sv-trojan').streamSettings.sockopt, { interface: 'Wi-Fi' });
  const viaDpi = cfg.outbounds.find((o) => o.tag === 'lu-out-sv-frag').streamSettings.sockopt.dialerProxy;
  assert.match(viaDpi, /^dpi-\d+$/);
  assert.equal(cfg.outbounds.find((o) => o.tag === viaDpi).streamSettings.sockopt.interface, 'Wi-Fi');
  assert.equal(new Set(cfg.outbounds.map((o) => o.tag)).size, cfg.outbounds.length, 'no tag twice');
});

/* ------------------------------ the pool ------------------------------ */

test('the pool: the users’ rules after the DNS rules and ahead of the private bypass and the entries; an entry’s target is shared', () => {
  const pool = { mode: 'pool', entries: [{ id: 'e1', target: 'sv-trojan', socksPort: 60001 }], primary: 'sv-vless', serversById: { 'sv-vless': F.VLESS_WS_TLS, 'sv-trojan': F.TROJAN_TCP_TLS }, chainsById: {}, chain: [] };
  const cfg = buildConfig(pool, F.settings(Object.assign({ lanUsers: lu([user('u1', 'a', { target: 'sv-trojan' }), user('u2', 'b')]) }, ON, MANAGED)));
  assert.ok(inbound(cfg, 'lu-socks'));
  assert.equal(ruleFor(cfg, 'a').outboundTag, 'out-sv-trojan');
  assert.equal(ruleFor(cfg, 'b').outboundTag, 'out-sv-vless', 'the current connection: the pool’s primary');
  const rules = cfg.routing.rules;
  const mine = rules.findIndex((r) => (r.inboundTag || []).includes('lu-socks'));
  const priv = rules.findIndex((r) => Array.isArray(r.ip) && r.ip.includes('192.168.0.0/16') && !r.inboundTag);
  const entry = rules.findIndex((r) => (r.inboundTag || []).includes('ps-e1'));
  assert.ok(mine > 0 && mine < priv && priv < entry, JSON.stringify([mine, priv, entry]));
  // a pool entry on the users' port: the users' inbound gives way
  const taken = buildConfig(Object.assign({}, pool, { entries: [{ id: 'e1', target: 'sv-trojan', socksPort: 30820 }] }), F.settings(Object.assign({ lanUsers: lu([user('u1', 'a')]) }, ON)));
  assert.equal(inbound(taken, 'lu-socks'), undefined);
  assert.equal(inbound(taken, 'ps-e1').port, 30820);
});

/* ------------------------------ the router's transparent inbounds ------------------------------ */

test('transparent inbounds (the router’s, from USERS-ROUTER): lu-tp-<n> on loopback, no auth, each routed to its target — with the proxy off too', () => {
  const cfg = buildConfig(single, F.settings(Object.assign({ lanUsers: lu([], { config: { proxy: { enabled: false } }, tp: [{ n: 0, port: 41100, target: 'sv-trojan' }, { tag: 'lu-tp-1', port: 41101, target: '' }, { n: 2, port: 41102, target: 'chain:"><x>' }] }) }, ON)));
  assert.deepEqual(inbound(cfg, 'lu-tp-0'), { tag: 'lu-tp-0', port: 41100, listen: '127.0.0.1', protocol: 'socks', settings: { auth: 'noauth', udp: true }, sniffing: { enabled: true, destOverride: ['http', 'tls', 'quic'], routeOnly: false } });
  assert.equal(inbound(cfg, 'lu-socks'), undefined, 'the proxy is off');
  assert.equal(inbound(cfg, 'lu-tp-2'), undefined, 'a target in a shape the app never writes');
  const r0 = cfg.routing.rules.find((r) => r.inboundTag && r.inboundTag.length === 1 && r.inboundTag[0] === 'lu-tp-0' && r.outboundTag !== 'block');
  assert.equal(r0.outboundTag, 'lu-out-sv-trojan');
  assert.equal(cfg.routing.rules.find((r) => r.inboundTag && r.inboundTag[0] === 'lu-tp-1' && r.inboundTag.length === 1).outboundTag, 'proxy');
  assert.deepEqual(cfg.routing.rules[0].inboundTag, ['lu-tp-0', 'lu-tp-1'], 'their loopback guard');
  assert.equal(X.applies({ modules: { lanUsers: true }, lanUsers: { config: { proxy: { enabled: false } }, tp: [{ n: 0, port: 41100, target: '' }] } }), true);
});

test('applies(): only with the module installed and the proxy on (or transparent inbounds)', () => {
  assert.equal(X.applies({}), false);
  assert.equal(X.applies({ modules: { lanUsers: true } }), false, 'no store');
  assert.equal(X.applies({ modules: {}, lanUsers: lu([]) }), false);
  assert.equal(X.applies({ modules: { lanUsers: true }, lanUsers: lu([]) }), true);
  assert.equal(X.applies({ modules: { lanUsers: true }, lanUsers: lu([], { config: {} }) }), false);
});

test('applyLanUsers on a config made elsewhere (the contract’s one-call form): it finds the outbounds the config has, blocks the rest, and turns the per-user counters on', () => {
  const cfg = { inbounds: [{ tag: 'socks-in', port: 10808 }], outbounds: [{ tag: 'proxy', protocol: 'vless' }, { tag: 'lu-out-s1', protocol: 'trojan' }, { tag: 'direct' }, { tag: 'block' }], routing: { rules: [{ type: 'field', port: '0-65535', outboundTag: 'proxy' }] } };
  X.applyLanUsers(cfg, lu([user('u1', 'a', { target: 's1' }), user('u2', 'b', { target: 's2' }), user('u3', 'c')]), {});
  assert.deepEqual(['a', 'b', 'c'].map((u) => ruleFor(cfg, u).outboundTag), ['lu-out-s1', 'block', 'proxy']);
  assert.deepEqual(cfg.routing.rules[cfg.routing.rules.length - 1], { type: 'field', port: '0-65535', outboundTag: 'proxy' });
  assert.deepEqual(cfg.policy.levels['0'], { statsUserUplink: true, statsUserDownlink: true });
});

/* ------------------------------ v1.39.0: a direct outbound per user, per-user routing, holds ------------------------------ */

const { buildRoutingRules } = require('../src/main/configBuilder');
const { sumOutbounds, byOutbound } = require('../src/main/stats');
const PROFILE = {
  id: 'rp-lu', name: 'P', def: 'sv-vless', defVia: 'sv-trojan', useMode: true, base: 'sv-trojan',
  rules: [
    { type: 'ip', value: '203.0.113.9/32, 198.51.100.0/24', target: 'direct' },
    { type: 'domain', value: 'ads.example|geosite:category-ads-all', target: 'block' },
    { type: 'domain', value: 'corp.example', target: 'sv-ss', via: 'sv-trojan' },
    { type: 'port', value: '25,465', target: 'base' },
    { type: 'domain', value: 'gone.example', target: 'sv-deleted' },
    { type: 'process', value: 'chrome.exe', target: 'direct' },
    { type: 'domain', value: 'geosite:category-ir', target: 'direct' }
  ]
};
const rulesOf = (cfg, username) => cfg.routing.rules.filter((r) => Array.isArray(r.user) && r.user.includes(username));

test('every user the build routes gets a direct outbound of their own, lu-d-<id>: a copy of the plan’s direct that every pass binds alike — under TUN on the NIC, as direct is (single, advanced, pool)', () => {
  const plans = {
    single,
    advanced: { mode: 'advanced', serversById: { 'sv-vless': F.VLESS_WS_TLS, 'sv-trojan': F.TROJAN_TCP_TLS }, chainsById: {}, chain: [], rules: [{ type: 'domain', value: 'a.com', target: 'sv-trojan' }], def: 'sv-vless' },
    pool: { mode: 'pool', entries: [{ id: 'e1', target: 'sv-trojan', socksPort: 60001 }], primary: 'sv-vless', serversById: { 'sv-vless': F.VLESS_WS_TLS, 'sv-trojan': F.TROJAN_TCP_TLS }, chainsById: {}, chain: [] }
  };
  for (const [name, plan] of Object.entries(plans)) {
    for (const base of [{}, { tunMode: true, directInterface: 'Wi-Fi' }, { tunMode: true, directInterface: 'Wi-Fi', ipv6: true }]) {
      const cfg = buildConfig(plan, F.settings(Object.assign({ lanUsers: lu([user('usr-a', 'ali', { routing: 'bypass-ir' }), user('usr-b', 'sara', { target: 'direct' }), user('usr-c', 'off', { enabled: false })]) }, ON, base)));
      const direct = cfg.outbounds.find((o) => o.tag === 'direct');
      for (const id of ['usr-a', 'usr-b']) {
        const own = cfg.outbounds.find((o) => o.tag === 'lu-d-' + id);
        assert.ok(own, `${name}: lu-d-${id}`);
        assert.deepEqual(Object.assign({}, own, { tag: 'direct' }), direct, `${name} ${JSON.stringify(base)}: the same as direct, bound the same`);
      }
      if (base.tunMode) assert.deepEqual(cfg.outbounds.find((o) => o.tag === 'lu-d-usr-a').streamSettings.sockopt, { interface: 'Wi-Fi' }, 'under TUN: on the NIC, never into the tunnel');
      assert.equal(cfg.outbounds.find((o) => o.tag === 'lu-d-usr-c'), undefined, 'not for a user the build leaves out');
      assert.deepEqual(cfg.policy.system, { statsInboundUplink: true, statsInboundDownlink: true, statsOutboundUplink: true, statsOutboundDownlink: true }, 'the outbound counters: a user’s direct bytes');
      assert.equal(new Set(cfg.outbounds.map((o) => o.tag)).size, cfg.outbounds.length, 'no tag twice');
    }
  }
});

test('routing bypass-ir: private ranges, Iranian names and addresses to the user’s own direct outbound, the rest to their target — without the geo files, the private ranges alone', () => {
  const users = [user('usr-a', 'ali', { routing: 'bypass-ir', target: 'sv-trojan' })];
  const cfg = buildConfig(single, F.settings(Object.assign({ lanUsers: lu(users) }, ON)));
  const m = { inboundTag: ['lu-socks', 'lu-http'], user: ['ali'] };
  assert.deepEqual(rulesOf(cfg, 'ali'), [
    Object.assign({ type: 'field' }, m, { ip: X.PRIVATE_IPS, outboundTag: 'lu-d-usr-a' }),
    Object.assign({ type: 'field' }, m, { domain: ['geosite:category-ir', 'regexp:.*\\.ir$'], outboundTag: 'lu-d-usr-a' }),
    Object.assign({ type: 'field' }, m, { ip: ['geoip:ir'], outboundTag: 'lu-d-usr-a' }),
    Object.assign({ type: 'field' }, m, { outboundTag: 'lu-out-sv-trojan' })
  ]);
  assert.deepEqual(X.PRIVATE_IPS, buildRoutingRules('global', false, true)[0].ip, 'the app’s own private ranges');
  const noGeo = buildConfig(single, F.settings(Object.assign({ geoAssets: false, lanUsers: lu(users) }, ON)));
  assert.deepEqual(rulesOf(noGeo, 'ali').map((r) => r.ip || r.domain || 'catch-all'), [X.PRIVATE_IPS, 'catch-all']);
  assert.ok(!JSON.stringify(noGeo).includes('geosite:') && !JSON.stringify(noGeo).includes('geoip:'), 'no geo name at all: the core would refuse the config');
  const said = buildConfig(single, F.settings(Object.assign({ lanUsers: lu(users, { geo: false }) }, ON)));
  assert.equal(rulesOf(said, 'ali').length, 2, 'the input’s geo:false too');
});

test('routing by a profile: its rules in order — direct to the user’s own, block, a server to its outbound, "exit at the base" its base — a gone target or a process rule left out; its default and vias never used', () => {
  const users = [user('usr-a', 'ali', { routing: 'profile:rp-lu', target: 'sv-vless' }), user('usr-b', 'sara', { routing: 'profile:rp-gone', target: 'sv-trojan' })];
  const cfg = buildConfig(single, F.settings(Object.assign({ lanUsers: lu(users, { profilesById: { 'rp-lu': PROFILE } }) }, ON)));
  const m = { inboundTag: ['lu-socks', 'lu-http'], user: ['ali'] };
  assert.deepEqual(rulesOf(cfg, 'ali'), [
    Object.assign({ type: 'field' }, m, { ip: ['203.0.113.9/32', '198.51.100.0/24'], outboundTag: 'lu-d-usr-a' }),
    Object.assign({ type: 'field' }, m, { domain: ['ads.example', 'geosite:category-ads-all'], outboundTag: 'block' }),
    Object.assign({ type: 'field' }, m, { domain: ['corp.example'], outboundTag: 'lu-out-sv-ss' }),
    Object.assign({ type: 'field' }, m, { port: '25,465', outboundTag: 'lu-out-sv-trojan' }),
    Object.assign({ type: 'field' }, m, { domain: ['geosite:category-ir'], outboundTag: 'lu-d-usr-a' }),
    Object.assign({ type: 'field' }, m, { outboundTag: 'proxy' })
  ], 'sv-vless is the selection: the catch-all rides proxy');
  assert.ok(cfg.outbounds.some((o) => o.tag === 'lu-out-sv-ss') && cfg.outbounds.some((o) => o.tag === 'lu-out-sv-trojan'), 'the profile’s targets are built');
  assert.equal(cfg.outbounds.find((o) => o.tag === 'lu-out-sv-ss').streamSettings.sockopt, undefined, 'its via is not used: the server dialled as it is');
  assert.deepEqual(rulesOf(cfg, 'sara'), [{ type: 'field', inboundTag: ['lu-socks', 'lu-http'], user: ['sara'], outboundTag: 'lu-out-sv-trojan' }], 'a profile that is gone: as before');
  const noGeo = buildConfig(single, F.settings(Object.assign({ geoAssets: false, lanUsers: lu(users, { profilesById: { 'rp-lu': PROFILE } }) }, ON)));
  assert.deepEqual(rulesOf(noGeo, 'ali').map((r) => r.domain || r.ip || r.port || r.outboundTag), [['203.0.113.9/32', '198.51.100.0/24'], ['ads.example'], ['corp.example'], '25,465', 'proxy']);
});

test('holds: under "vpn" everything not to the user’s own direct outbound is blocked (their direct routes keep working); under "direct" the other way', () => {
  const users = [user('usr-a', 'ali', { routing: 'profile:rp-lu', target: 'sv-trojan' }), user('usr-b', 'sara', { routing: 'bypass-ir', target: 'direct' })];
  const cfg = buildConfig(single, F.settings(Object.assign({ lanUsers: lu(users, { profilesById: { 'rp-lu': PROFILE }, holds: { 'usr-a': 'vpn', 'usr-b': { hold: 'direct', why: 'direct', until: 0 } } }) }, ON)));
  assert.deepEqual(rulesOf(cfg, 'ali').map((r) => r.outboundTag), ['lu-d-usr-a', 'block', 'block', 'block', 'lu-d-usr-a', 'block']);
  assert.deepEqual(rulesOf(cfg, 'sara').map((r) => r.outboundTag), ['block', 'block', 'block', 'block'], 'target direct, direct held: nothing goes');
  assert.ok(inbound(cfg, 'lu-socks').settings.accounts.some((a) => a.user === 'ali'), 'held in part: still an account');
});

test('userRouteRules (the router shares it): a transparent inbound’s scope, the platform’s own direct rules counted as the user’s for routing "", the catch-all always last', () => {
  const base = [
    { type: 'field', ip: ['10.0.0.0/8'], outboundTag: 'direct' },
    { type: 'field', inboundTag: ['dns-internal'], ip: ['178.22.122.100'], outboundTag: 'direct' },
    { type: 'field', domain: ['geosite:category-ir'], outboundTag: 'direct' }
  ];
  const u = { id: 'usr-a', username: 'ali', target: 'sv-1', routing: '' };
  const r = X.userRouteRules({ user: u, match: { inboundTag: ['lu-tp-1'] }, targetTag: 'out-sv-1', baseDirect: base, geo: true });
  assert.deepEqual(r, [
    { type: 'field', inboundTag: ['lu-tp-1'], ip: ['10.0.0.0/8'], outboundTag: 'lu-d-usr-a' },
    { type: 'field', inboundTag: ['lu-tp-1'], domain: ['geosite:category-ir'], outboundTag: 'lu-d-usr-a' },
    { type: 'field', inboundTag: ['lu-tp-1'], outboundTag: 'out-sv-1' }
  ], 'the DNS rule is another inbound’s');
  assert.deepEqual(X.userRouteRules({ user: u, match: { inboundTag: ['lu-tp-1'] }, targetTag: 'out-sv-1', baseDirect: base, hold: 'vpn' }).map((x) => x.outboundTag), ['lu-d-usr-a', 'lu-d-usr-a', 'block']);
  assert.deepEqual(X.userRouteRules({ user: Object.assign({}, u, { routing: 'bypass-ir' }), match: { inboundTag: ['lu-tp-1'] }, targetTag: 'out-sv-1', baseDirect: base, geo: false }).map((x) => x.ip || x.outboundTag), [X.PRIVATE_IPS, 'out-sv-1'], 'a mode of their own: the platform’s are not repeated');
  assert.deepEqual(X.userRouteRules({ user: Object.assign({}, u, { routing: 'profile:rp-lu' }), profilesById: { 'rp-lu': PROFILE }, match: {}, targetTag: 'proxy', tagFor: (t) => (t === 'sv-ss' ? 'out-sv-ss' : null), geo: true }).map((x) => x.outboundTag),
    ['lu-d-usr-a', 'block', 'out-sv-ss', 'lu-d-usr-a', 'proxy'], 'tagFor null: the rule left out');
  assert.deepEqual(X.profileTargets(PROFILE), ['sv-ss', 'sv-trojan', 'sv-deleted']);
});

test('the router’s transparent inbounds with a user: that user’s rules, inboundTag alone, and their own direct outbound — with the proxy off too', () => {
  const users = [user('usr-a', 'ali', { routing: 'bypass-ir', target: 'sv-trojan' })];
  const cfg = buildConfig(single, F.settings(Object.assign({ tunMode: true, directInterface: 'eth0', lanUsers: lu(users, { config: { proxy: { enabled: false } }, tp: [{ tag: 'lu-tp-1', port: 41100, target: 'sv-trojan', userId: 'usr-a' }, { tag: 'lu-tp-2', port: 41101, target: '' }] }) }, ON)));
  const tp1 = cfg.routing.rules.filter((r) => r.inboundTag && r.inboundTag.length === 1 && r.inboundTag[0] === 'lu-tp-1');
  assert.deepEqual(tp1.map((r) => [r.ip || r.domain || null, r.outboundTag]), [[X.PRIVATE_IPS, 'lu-d-usr-a'], [['geosite:category-ir', 'regexp:.*\\.ir$'], 'lu-d-usr-a'], [['geoip:ir'], 'lu-d-usr-a'], [null, 'lu-out-sv-trojan']]);
  assert.ok(tp1.every((r) => !r.user), 'no account on a transparent inbound');
  assert.deepEqual(cfg.outbounds.find((o) => o.tag === 'lu-d-usr-a').streamSettings.sockopt, { interface: 'eth0' });
  assert.equal(cfg.routing.rules.find((r) => r.inboundTag && r.inboundTag[0] === 'lu-tp-2' && r.inboundTag.length === 1).outboundTag, 'proxy', 'no user: its target, as before');
});

test('the live meter and the home screen: a user’s direct outbound is direct traffic, never the tunnel’s', () => {
  const vars = { stats: { outbound: { proxy: { uplink: 10, downlink: 100 }, direct: { uplink: 1, downlink: 2 }, 'lu-d-usr-a': { uplink: 3, downlink: 40 }, 'lu-out-sv-1': { uplink: 5, downlink: 50 } } } };
  assert.deepEqual(sumOutbounds(vars), { up: 15, down: 150 });
  assert.deepEqual(byOutbound(vars), { proxy: { up: 10, down: 100 }, direct: { up: 4, down: 42 }, 'lu-out-sv-1': { up: 5, down: 50 } });
});

/* ------------------------------ v1.40.0: the content filter ------------------------------ */

const FILTER = { block: ['adult', 'gambling', 'ads'], safeSearch: true, domains: ['bad.example', 'full:www.bad.example', 'keyword:casino'] };
/** The engines' search hosts as the rules name them, in SAFE_SEARCH's order: Google (2), Bing (2), DuckDuckGo (1), YouTube (5). */
const ENGINES = [
  'full:www.google.com', 'regexp:^www\\.google\\.(com?\\.)?[a-z]{2,3}$', 'full:www.bing.com', 'full:edgeservices.bing.com', 'full:duckduckgo.com',
  'full:www.youtube.com', 'full:m.youtube.com', 'full:youtubei.googleapis.com', 'full:youtube.googleapis.com', 'full:www.youtube-nocookie.com'
];
const SNIFF_ON = { enabled: true, destOverride: ['http', 'tls', 'quic'], routeOnly: true };

test('filterOf: the model’s shape or junk — known categories once in their order, domains in their three forms once each (lowercased, nothing the matcher reads otherwise), at most 200; null when there is nothing to do', () => {
  assert.equal(X.filterOf({}), null);
  assert.equal(X.filterOf({ filter: null }), null);
  assert.equal(X.filterOf({ filter: 'x' }), null);
  assert.equal(X.filterOf({ filter: { block: [], safeSearch: false, domains: [] } }), null);
  assert.deepEqual(X.filterOf({ filter: { block: ['ads', 'adult', 'ads', 'nope', 7], safeSearch: 'yes', domains: ['  Bad.Example ', 'bad.example', 'FULL:WWW.Bad.example', 'keyword:casino', 'regexp:x', 'a b', 'domain:x', '', null, 'x'.repeat(254)] } }),
    { block: ['adult', 'ads'], safeSearch: false, domains: ['bad.example', 'full:www.bad.example', 'keyword:casino'] });
  assert.equal(X.filterOf({ filter: { domains: Array.from({ length: 300 }, (_, i) => `d${i}.example`) } }).domains.length, 200);
  assert.deepEqual(X.filterOf({ filter: { safeSearch: true } }), { block: [], safeSearch: true, domains: [] });
  assert.deepEqual(['bad.example', 'full:a.b', 'keyword:c'].map(X.domainRule), ['domain:bad.example', 'full:a.b', 'keyword:c']);
  // a user handed over by a model that does not know the field: the store's record of the same id still has it
  assert.deepEqual(X.filterFor({ users: [{ id: 'u1', filter: { safeSearch: true } }] }, { id: 'u1' }), { block: [], safeSearch: true, domains: [] });
  assert.equal(X.filterFor({ users: [{ id: 'u2', filter: { safeSearch: true } }] }, { id: 'u1' }), null);
  assert.deepEqual(X.FILTER_GEOSITE, { adult: 'geosite:category-porn', social: 'geosite:category-social-media-!cn', games: 'geosite:category-games', ads: 'geosite:category-ads-all' }, 'the lists read in v2fly’s data/ — none for gambling');
  assert.deepEqual(X.SAFE_SEARCH.map((e) => [e.key, e.host]), [['google', 'forcesafesearch.google.com'], ['bing', 'strict.bing.com'], ['ddg', 'safe.duckduckgo.com'], ['youtube', 'restrict.youtube.com']]);
  assert.deepEqual(X.SAFE_SEARCH.flatMap((e) => e.domains), ENGINES);
});

test('a filtered user (desktop): the filter FIRST among their rules — the custom domains → block, the categories → block, the engines’ hosts on UDP 443 → block and on TCP 443 → a safe-search outbound per engine dialled through their config; then their routing and catch-all', () => {
  const users = [user('usr-a', 'ali', { target: 'sv-trojan', routing: 'bypass-ir', filter: FILTER }), user('usr-b', 'sara', { target: 'sv-ss' })];
  const cfg = buildConfig(single, F.settings(Object.assign({ lanUsers: lu(users) }, ON)));
  const m = { inboundTag: ['lu-socks', 'lu-http'], user: ['ali'] };
  const R = (cond, outboundTag) => Object.assign({ type: 'field' }, m, cond, { outboundTag });
  assert.deepEqual(rulesOf(cfg, 'ali'), [
    R({ domain: ['domain:bad.example', 'full:www.bad.example', 'keyword:casino'] }, 'block'),
    R({ domain: ['geosite:category-porn', 'geosite:category-ads-all'] }, 'block'),
    R({ domain: ENGINES, port: '443', network: 'udp' }, 'block'),
    R({ domain: ENGINES.slice(0, 2), port: '443', network: 'tcp' }, 'lu-ss-usr-a-google'),
    R({ domain: ENGINES.slice(2, 4), port: '443', network: 'tcp' }, 'lu-ss-usr-a-bing'),
    R({ domain: ENGINES.slice(4, 5), port: '443', network: 'tcp' }, 'lu-ss-usr-a-ddg'),
    R({ domain: ENGINES.slice(5), port: '443', network: 'tcp' }, 'lu-ss-usr-a-youtube'),
    R({ ip: X.PRIVATE_IPS }, 'lu-d-usr-a'),
    R({ domain: ['geosite:category-ir', 'regexp:.*\\.ir$'] }, 'lu-d-usr-a'),
    R({ ip: ['geoip:ir'] }, 'lu-d-usr-a'),
    R({}, 'lu-out-sv-trojan')
  ]);
  assert.deepEqual(cfg.outbounds.filter((o) => o.tag.startsWith('lu-ss-')),
    X.SAFE_SEARCH.map((e) => ({ tag: 'lu-ss-usr-a-' + e.key, protocol: 'freedom', settings: { redirect: e.host + ':443' }, streamSettings: { sockopt: { dialerProxy: 'lu-out-sv-trojan' } } })),
    'a freedom per engine: redirect to the safe host, dialled through her config');
  assert.deepEqual(rulesOf(cfg, 'sara'), [{ type: 'field', inboundTag: ['lu-socks', 'lu-http'], user: ['sara'], outboundTag: 'lu-out-sv-ss' }], 'no filter: as before');
  assert.ok(!cfg.outbounds.some((o) => o.tag.startsWith('lu-ss-usr-b')), 'and no outbound made for her');
  // 'gambling' has no geosite list: the model (FILTER_CATEGORIES) drops it on read, so there is nothing to say
  assert.deepEqual(cfg.lanUsersNotes, []);
  assert.equal(Object.keys(cfg).includes('lanUsersNotes'), false, 'the notes are not written to disk');
  assert.equal(new Set(cfg.outbounds.map((o) => o.tag)).size, cfg.outbounds.length, 'no tag twice');
});

test('without the geo files the categories are left out and said in the notes (and to ctx.log when the caller gives one); a user handed over without the field is read from the store’s record', () => {
  const users = [user('usr-a', 'ali', { target: 'sv-trojan', filter: { block: ['adult', 'social', 'games'], safeSearch: false, domains: ['bad.example'] } })];
  const noGeo = buildConfig(single, F.settings(Object.assign({ geoAssets: false, lanUsers: lu(users) }, ON)));
  assert.deepEqual(rulesOf(noGeo, 'ali').map((r) => r.domain || r.outboundTag), [['domain:bad.example'], 'lu-out-sv-trojan']);
  assert.ok(!JSON.stringify(noGeo).includes('geosite:'), 'no geosite name: the core would refuse the config');
  assert.deepEqual(noGeo.lanUsersNotes, ['Users: "ali"’s blocked categories (adult, social, games) need the geo files (geoip.dat, geosite.dat) — left out until they are there']);
  const withGeo = buildConfig(single, F.settings(Object.assign({ lanUsers: lu(users) }, ON)));
  assert.deepEqual(rulesOf(withGeo, 'ali')[1].domain, ['geosite:category-porn', 'geosite:category-social-media-!cn', 'geosite:category-games']);
  assert.deepEqual(withGeo.lanUsersNotes, []);
  // the one-call form: ctx.log gets each note; the store's record's filter counts when the normalized user lost it
  const said = [];
  const cfg = { inbounds: [], outbounds: [{ tag: 'proxy', protocol: 'vless' }, { tag: 'lu-out-s1', protocol: 'trojan' }, { tag: 'direct', protocol: 'freedom' }, { tag: 'block', protocol: 'blackhole' }], routing: { rules: [] } };
  X.applyLanUsers(cfg, lu([user('u1', 'a', { target: 's1', filter: { block: ['adult'], safeSearch: true } })]), { geo: false, log: (line, level) => said.push([level, line]) });
  assert.deepEqual(said, [['warn', 'Users: "a"’s blocked categories (adult) need the geo files (geoip.dat, geosite.dat) — left out until they are there']]);
  assert.deepEqual([ruleFor(cfg, 'a').network, ruleFor(cfg, 'a').outboundTag], ['udp', 'block'], 'her first rule: QUIC to the engines blocked');
  assert.ok(cfg.outbounds.some((o) => o.tag === 'lu-ss-u1-google' && o.streamSettings.sockopt.dialerProxy === 'lu-out-s1'));
});

test('safe search rides what the user rides: a copy of their own direct outbound (bound as it is) when their config is direct — held with direct; blocked under a VPN hold otherwise; not made for a group (said in the notes), its block rules still written', () => {
  const users = [
    user('usr-a', 'ali', { target: 'direct', filter: { safeSearch: true } }),
    user('usr-b', 'sara', { target: 'sv-trojan', filter: { safeSearch: true, domains: ['bad.example'] } }),
    user('usr-c', 'reza', { target: 'grp-1', filter: { safeSearch: true, block: ['adult'] } }),
    user('usr-d', 'mina', { target: 'direct', filter: { safeSearch: true } })
  ];
  const cfg = buildConfig(single, F.settings(Object.assign({ tunMode: true, directInterface: 'Wi-Fi', lanUsers: lu(users, { holds: { 'usr-a': 'direct', 'usr-b': 'vpn' } }) }, ON)));
  const out = (tag) => cfg.outbounds.find((o) => o.tag === tag);
  const direct = out('lu-d-usr-d');
  assert.deepEqual(out('lu-ss-usr-d-google'), Object.assign({}, direct, { tag: 'lu-ss-usr-d-google', settings: Object.assign({}, direct.settings, { redirect: 'forcesafesearch.google.com:443' }) }), 'her own direct outbound with the redirect on: the NIC binding and all');
  assert.equal(out('lu-ss-usr-d-google').streamSettings.sockopt.interface, 'Wi-Fi');
  assert.deepEqual(rulesOf(cfg, 'mina').map((r) => r.outboundTag), ['block', 'lu-ss-usr-d-google', 'lu-ss-usr-d-bing', 'lu-ss-usr-d-ddg', 'lu-ss-usr-d-youtube', 'lu-d-usr-d']);
  assert.deepEqual(rulesOf(cfg, 'ali').map((r) => r.outboundTag), ['block', 'block', 'block', 'block', 'block', 'block'], 'direct held: her searches ride direct, so they are held too');
  assert.deepEqual(rulesOf(cfg, 'sara').map((r) => r.outboundTag), ['block', 'block', 'block', 'block', 'block', 'block', 'block'], 'VPN held: her searches ride the VPN');
  assert.ok(out('lu-ss-usr-b-bing'), 'the outbound stands all the same (the hold lifts without it)');
  assert.deepEqual(rulesOf(cfg, 'reza'), [
    { type: 'field', inboundTag: ['lu-socks', 'lu-http'], user: ['reza'], domain: ['geosite:category-porn'], outboundTag: 'block' },
    { type: 'field', inboundTag: ['lu-socks', 'lu-http'], user: ['reza'], outboundTag: 'lu-out-grp-1' }
  ], 'a group: nothing dials through its loopback (the tail of a TCP stream dialled through one is lost now and then)');
  assert.ok(!cfg.outbounds.some((o) => o.tag.startsWith('lu-ss-usr-c')));
  assert.deepEqual(cfg.lanUsersNotes, ['Users: "reza": safe search needs a server, a chain or direct as the config — not a group, nor the router’s balancer — left out']);
  assert.equal(new Set(cfg.outbounds.map((o) => o.tag)).size, cfg.outbounds.length, 'no tag twice');
});

test('the names must be seen: inbounds whose sniffing is off get it on (routeOnly) when a filtered user rides them — the shared ones, a transparent one — and are left alone otherwise', () => {
  const plain = [user('usr-a', 'ali', { target: 'sv-trojan' })];
  const filtered = [user('usr-a', 'ali', { target: 'sv-trojan', filter: { domains: ['bad.example'] } })];
  const off = (users, over) => buildConfig(single, F.settings(Object.assign({ enableSniffing: false, lanUsers: lu(users, over) }, ON)));
  const was = inbound(off(plain), 'socks-in').sniffing;
  assert.notEqual(was && was.enabled, true, 'sniffing off in the settings');
  assert.deepEqual(inbound(off(plain), 'lu-socks').sniffing, was, 'nobody filtered: as the owner set it');
  assert.deepEqual(inbound(off(filtered), 'lu-socks').sniffing, SNIFF_ON);
  assert.deepEqual(inbound(off(filtered), 'lu-http').sniffing, SNIFF_ON);
  assert.deepEqual(inbound(off(filtered), 'socks-in').sniffing, was, 'the app’s own inbound is the owner’s');
  const tp = off(filtered, { config: { proxy: { enabled: false } }, tp: [{ tag: 'lu-tp-1', port: 41100, target: 'sv-trojan', userId: 'usr-a' }, { tag: 'lu-tp-2', port: 41101, target: '' }] });
  assert.deepEqual(inbound(tp, 'lu-tp-1').sniffing, SNIFF_ON);
  assert.deepEqual(inbound(tp, 'lu-tp-2').sniffing, was, 'nobody filtered on it');
  assert.deepEqual(tp.routing.rules.filter((r) => r.inboundTag && r.inboundTag.length === 1 && r.inboundTag[0] === 'lu-tp-1').map((r) => [r.domain || null, r.outboundTag]), [[['domain:bad.example'], 'block'], [null, 'lu-out-sv-trojan']]);
  // sniffing the owner turned on is left as he set it
  const on = buildConfig(single, F.settings(Object.assign({ lanUsers: lu(filtered) }, ON)));
  assert.deepEqual(inbound(on, 'lu-socks').sniffing, { enabled: true, destOverride: ['http', 'tls', 'quic'], routeOnly: false });
});

test('userRouteRules: a filter handed in is the one used (null: none); an engine the caller has no outbound for is left out, QUIC block and redirect both; no outbound maker at all: the blocks alone — and the helpers the router shares', () => {
  const u = { id: 'usr-a', username: 'ali', target: 'sv-1', routing: '', filter: { safeSearch: true, domains: ['bad.example'] } };
  const m = { inboundTag: ['lu-tp-1'] };
  const only = X.userRouteRules({ user: u, match: m, targetTag: 'out-sv-1', safeSearchTag: (k) => (k === 'google' ? 'ss-g' : null) });
  assert.deepEqual(only.map((r) => [r.domain || null, r.network || null, r.outboundTag]), [
    [['domain:bad.example'], null, 'block'], [ENGINES.slice(0, 2), 'udp', 'block'], [ENGINES.slice(0, 2), 'tcp', 'ss-g'], [null, null, 'out-sv-1']
  ]);
  assert.deepEqual(X.userRouteRules({ user: u, match: m, targetTag: 'out-sv-1' }).map((r) => r.outboundTag), ['block', 'out-sv-1'], 'no outbound maker: the custom domains alone');
  assert.deepEqual(X.userRouteRules({ user: u, match: m, targetTag: 'out-sv-1', filter: null }), [{ type: 'field', inboundTag: ['lu-tp-1'], outboundTag: 'out-sv-1' }], 'filter null: none, whatever the user carries');
  assert.deepEqual(X.userRouteRules({ user: { id: 'u', target: 'sv-1' }, match: m, targetTag: 'out-sv-1', filter: { block: ['adult', 'gambling'], safeSearch: false, domains: [] }, geo: true }).map((r) => r.domain || r.outboundTag), [['geosite:category-porn'], 'out-sv-1'], 'gambling: no list, no rule');
  // the helpers the router shares
  const cfg = { outbounds: [{ tag: 'proxy', protocol: 'vless' }, { tag: 'grp', protocol: 'loopback' }, { tag: 'block', protocol: 'blackhole' }] };
  assert.deepEqual(['proxy', 'grp', 'block', 'nope', '', null].map((t) => X.safeSearchVia(cfg, t)), ['proxy', null, null, null, null, null]);
  assert.deepEqual(X.safeSearchOutbounds({ id: 'u1' }, {}), { outbounds: [], tags: {} });
  const viaOut = X.safeSearchOutbounds({ id: 'u1' }, { via: 'proxy' });
  assert.deepEqual(viaOut.tags, { google: 'lu-ss-u1-google', bing: 'lu-ss-u1-bing', ddg: 'lu-ss-u1-ddg', youtube: 'lu-ss-u1-youtube' });
  assert.deepEqual(viaOut.outbounds[2], { tag: 'lu-ss-u1-ddg', protocol: 'freedom', settings: { redirect: 'safe.duckduckgo.com:443' }, streamSettings: { sockopt: { dialerProxy: 'proxy' } } });
  const d = X.safeSearchOutbounds({ id: 'u1' }, { direct: { tag: 'lu-d-u1', protocol: 'freedom', settings: { domainStrategy: 'UseIPv4' }, streamSettings: { sockopt: { interface: 'eth0' } } } });
  assert.deepEqual(d.outbounds[0], { tag: 'lu-ss-u1-google', protocol: 'freedom', settings: { domainStrategy: 'UseIPv4', redirect: 'forcesafesearch.google.com:443' }, streamSettings: { sockopt: { interface: 'eth0' } } });
  assert.deepEqual(X.ensureSniffing({ tag: 'x' }).sniffing, SNIFF_ON);
  assert.deepEqual(X.ensureSniffing({ tag: 'x', sniffing: { enabled: true, destOverride: ['tls'] } }).sniffing, { enabled: true, destOverride: ['tls'] });
  assert.deepEqual(X.filterNotes({ id: 'u1', name: 'Kid' }, { block: ['adult', 'gambling'], safeSearch: true, domains: [] }, { geo: false, safe: false }), [
    'Users: "Kid"’s blocked categories (adult, gambling) need the geo files (geoip.dat, geosite.dat) — left out until they are there',
    'Users: "Kid": geosite.dat has no list for the category "gambling" — left out',
    'Users: "Kid": safe search needs a server, a chain or direct as the config — not a group, nor the router’s balancer — left out'
  ]);
  assert.deepEqual(X.filterNotes({ id: 'u1' }, null, {}), []);
});
