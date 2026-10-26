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
  assert.deepEqual(['now', 'dir', 'blk', 'srv', 'chn', 'grp'].map(to), ['proxy', 'direct', 'block', 'lu-out-sv-trojan', 'lu-out-chain-c1', 'lu-out-grp-1']);
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
