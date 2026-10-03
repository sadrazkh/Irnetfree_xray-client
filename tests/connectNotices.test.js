'use strict';
/**
 * v1.16.3 (Windows visibility, report W1 / W4 / L1): what a connect — or a
 * launch — can see on THIS machine that explains a tunnel that "does not work
 * properly" here while the same configs work on another PC. Said, never acted
 * on: these helpers only read, and each returns nothing at all for a machine
 * where its condition does not hold. "Healthy" is not "silent", though: a
 * WireGuard identity stored twice is in the store, so a PC that works says it
 * too (the window once per run); a LAN inside a broad routed range is only a
 * log line unless the target needs an address in that LAN.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { makeWireguardServer, makeProxyServer } = require('../src/main/parser');
const {
  sharedWgIdentities, localSubnets, lanOverlaps, targetNeeds, routeTargetName, noticeLine, noticeLevel, forWindow, LOG_ONLY
} = require('../src/main/connectNotices');
const {
  schtasksQueryXmlArgs, schtasksQueryArgs, taskExeFromXml, autostartStale
} = require('../src/main/autostart');

const CORP_PUB = 'Q29ycG9yYXRlU2VydmVyUHVibGljS2V5MDAwMDAwMDA=';
const WARP_PUB = 'bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=';
const KEY_A = 'cHJpdmF0ZS1rZXktQS1BQUFBQUFBQUFBQUFBQUFBQUE=';
const KEY_B = 'cHJpdmF0ZS1rZXktQi1CQkJCQkJCQkJCQkJCQkJCQkI=';

function wg(id, name, f = {}) {
  return Object.assign(makeWireguardServer(Object.assign({
    name, endpoint: 'vpn.corp.example:51820', publicKey: CORP_PUB, privateKey: KEY_A, address: '10.10.10.42/32'
  }, f)), { id });
}

/* ------------------------------ W1: one WireGuard identity, stored twice ------------------------------ */

test('W1: the plan’s WireGuard record shares its private key with another record for the same server — named, the key never', () => {
  const chainWg = wg('b47f', 'tes-wg');
  const twin = wg('fa69', 'tes-wg (copy)');
  const vless = Object.assign(makeProxyServer({ type: 'socks', address: '192.0.2.10', port: 1080, name: 'hop' }), { id: 'hop' });
  const out = sharedWgIdentities(new Set(['hop', 'b47f']), [vless, chainWg, twin]);
  // a record added by hand: its group is the window's own "Added by hand" label, in the user's language
  assert.deepEqual(out, [{ id: 'wgSharedKey', name: 'tes-wg', other: 'tes-wg (copy)', group: { t: 'srv.manual' } }]);
  const said = JSON.stringify(out) + noticeLine(out[0]);
  assert.ok(!said.includes(KEY_A), 'the private key is never in a notice or a log line');
  assert.equal(noticeLine(out[0]),
    'WireGuard tes-wg: the same private key is also stored in another record, “tes-wg (copy)” in the group “Added by hand” — a WireGuard server accepts one device per key, so when both are used (on two devices, or that record tested while you are connected) one of them stalls. Delete the copy you do not use, do not test it while connected, and get one peer per device from the server’s admin');
});

test('W1: twin records with ONE name are told apart — the other one’s group (its subscription) is named, and what to do', () => {
  // the owner's laptop: the chain's cobra.tes.ca was added by hand, its twin came with a subscription
  const subs = [{ id: 'sub0554', name: 'tes-vpn-service.platform.irnetfree.info' }, { id: 'sub191f', name: 'sub.irnetfree.info' }];
  const chainWg = wg('b47f', 'cobra.tes.ca');
  const twin = Object.assign(wg('fa69', 'cobra.tes.ca'), { subId: 'sub0554' });
  const out = sharedWgIdentities(['b47f'], [chainWg, twin], subs);
  assert.deepEqual(out, [{ id: 'wgSharedKey', name: 'cobra.tes.ca', other: 'cobra.tes.ca', group: 'tes-vpn-service.platform.irnetfree.info' }]);
  assert.match(noticeLine(out[0]), /^WireGuard cobra\.tes\.ca: the same private key is also stored in another record, “cobra\.tes\.ca” in the group “tes-vpn-service\.platform\.irnetfree\.info” — /);
  // the other way round: the plan uses the subscription's copy, the twin was added by hand
  assert.deepEqual(sharedWgIdentities(['fa69'], [chainWg, twin], subs),
    [{ id: 'wgSharedKey', name: 'cobra.tes.ca', other: 'cobra.tes.ca', group: { t: 'srv.manual' } }]);
  // a subscription deleted while its records stayed: the window's "Deleted subscription" group
  const orphan = Object.assign(wg('o1', 'cobra.tes.ca'), { subId: 'gone' });
  const gone = sharedWgIdentities(['b47f'], [chainWg, orphan], subs);
  assert.deepEqual(gone, [{ id: 'wgSharedKey', name: 'cobra.tes.ca', other: 'cobra.tes.ca', group: { t: 'srv.subGone' } }]);
  assert.match(noticeLine(gone[0]), /in the group “Deleted subscription” — /);
  // no subscription list at all (an old store): never a throw, the group is still said
  assert.deepEqual(sharedWgIdentities(['b47f'], [chainWg, twin], null)[0].group, { t: 'srv.subGone' });
});

test('W1: the same tunnel address under another key for the same server is said too — the address, never a key, and what to do', () => {
  const chainWg = wg('b47f', 'tes-wg');
  const reza = wg('r1', 'reza-wire', { privateKey: KEY_B });
  const out = sharedWgIdentities(['b47f'], [chainWg, reza]);
  assert.deepEqual(out, [{ id: 'wgSharedAddress', name: 'tes-wg', other: 'reza-wire', group: { t: 'srv.manual' }, address: '10.10.10.42' }]);
  const line = noticeLine(out[0]);
  assert.ok(!line.includes(KEY_A) && !line.includes(KEY_B));
  assert.equal(line,
    'WireGuard tes-wg: its tunnel address 10.10.10.42 is also stored in another record, “reza-wire” in the group “Added by hand”, with another key for the same server — the server gives an address to one key only (unless it gives every device the same one), so one of the two may carry nothing. Keep the record the server’s admin made for this device, delete the other, and do not test it while connected');
});

test('W1: nothing to say where nothing is shared — another server, Cloudflare WARP’s one address, records the plan does not use', () => {
  const chainWg = wg('b47f', 'tes-wg');
  // the same key against ANOTHER server is a separate session there: no clash
  const otherServer = wg('o1', 'home-wg', { publicKey: 'SG9tZVNlcnZlclB1YmxpY0tleTAwMDAwMDAwMDAwMDA=' });
  assert.deepEqual(sharedWgIdentities(['b47f'], [chainWg, otherServer]), []);
  // every WARP device has 172.16.0.2 under its own key — that is how WARP works
  const warp1 = wg('w1', 'warp-1', { publicKey: WARP_PUB, privateKey: KEY_A, address: '172.16.0.2/32', endpoint: 'engage.cloudflareclient.com:2408' });
  const warp2 = wg('w2', 'warp-2', { publicKey: WARP_PUB, privateKey: KEY_B, address: '172.16.0.2/32', endpoint: 'engage.cloudflareclient.com:2408' });
  assert.deepEqual(sharedWgIdentities(['w1'], [warp1, warp2]), []);
  // …but one WARP key stored twice is one device twice
  const warp1copy = wg('w3', 'warp-1 copy', { publicKey: WARP_PUB, privateKey: KEY_A, address: '172.16.0.2/32', endpoint: 'engage.cloudflareclient.com:2408' });
  assert.deepEqual(sharedWgIdentities(['w1'], [warp1, warp1copy]), [{ id: 'wgSharedKey', name: 'warp-1', other: 'warp-1 copy', group: { t: 'srv.manual' } }]);
  // duplicates the plan does not touch are not this connect's business
  assert.deepEqual(sharedWgIdentities(['hop'], [chainWg, wg('fa69', 'tes-wg (copy)')]), []);
  // a healthy store: one record per identity
  assert.deepEqual(sharedWgIdentities(['b47f'], [chainWg]), []);
  // malformed input never throws
  assert.deepEqual(sharedWgIdentities(null, null), []);
  assert.deepEqual(sharedWgIdentities(['x'], [null, { id: 'x' }, { id: 'y', protocol: 'wireguard' }]), []);
});

test('W1: a pair the plan uses twice is said once', () => {
  const a = wg('a', 'A');
  const b = wg('b', 'B');
  assert.equal(sharedWgIdentities(['a', 'b'], [a, b]).length, 1);
});

/* ------------------------------ W4: a local subnet inside a routed private range ------------------------------ */

const IFACES = {
  'Wi-Fi': [
    { address: 'fe80::1c2b:3a4d:5e6f:7a8b', netmask: 'ffff:ffff:ffff:ffff::', family: 'IPv6', internal: false, cidr: 'fe80::1c2b:3a4d:5e6f:7a8b/64' },
    { address: '192.168.1.5', netmask: '255.255.255.0', family: 'IPv4', internal: false, cidr: '192.168.1.5/24' }
  ],
  // our own tunnels: never "your local network"
  IRNetFree: [{ address: '172.19.0.1', netmask: '255.255.255.252', family: 'IPv4', internal: false, cidr: '172.19.0.1/30' }],
  XrayTun: [{ address: '10.255.0.2', netmask: '255.255.255.0', family: 'IPv4', internal: false, cidr: '10.255.0.2/24' }],
  'Loopback Pseudo-Interface 1': [{ address: '127.0.0.1', netmask: '255.0.0.0', family: 'IPv4', internal: true, cidr: '127.0.0.1/8' }],
  // no DHCP answer: APIPA is not a network anyone routes to
  'Ethernet 2': [{ address: '169.254.3.4', netmask: '255.255.0.0', family: 'IPv4', internal: false, cidr: '169.254.3.4/16' }],
  // another VPN's /32 has no on-link subnet to shadow anything
  'wg-other': [{ address: '10.66.0.7', netmask: '255.255.255.255', family: 'IPv4', internal: false, cidr: '10.66.0.7/32' }],
  'VirtualBox Host-Only Network': [{ address: '192.168.56.1', netmask: '255.255.255.0', family: 'IPv4', internal: false, cidr: '192.168.56.1/24' }]
};
const OWN = (name) => name === 'IRNetFree' || name === 'XrayTun';
const NAMES = { 'chain:tes': 'Tes Chain', srvWg: 'tes-wg' };
const nameOf = (tg) => NAMES[tg] || null;

test('W4: this PC’s own connected IPv4 subnets — not our tunnels, loopback, APIPA, a /32 or IPv6', () => {
  const subnets = localSubnets(IFACES, OWN);
  assert.deepEqual(subnets, [
    { cidr: '192.168.1.0/24', iface: 'Wi-Fi' },
    { cidr: '192.168.56.0/24', iface: 'VirtualBox Host-Only Network' }
  ]);
  // a netmask without a cidr (older Node) gives the same network
  assert.deepEqual(localSubnets({ eth: [{ address: '10.1.2.3', netmask: '255.255.0.0', family: 4, internal: false }] }),
    [{ cidr: '10.1.0.0/16', iface: 'eth' }]);
  assert.deepEqual(localSubnets(null), []);
});

// The owner's corporate WireGuard as it is stored on the laptop: its DNS, its tunnel
// address and AllowedIPs exactly as wide as the advanced rule that sends them to it.
const CORP = { dns: '192.168.60.1, tes.systems', allowedIPs: '192.168.0.0/16, 10.0.0.0/8' };
const HOP = { id: 'hop', name: '🇬🇧-2', protocol: 'vless', outbound: { protocol: 'vless' } };
const TES_WG = wg('b47f', 'cobra.tes.ca', CORP);
const SRV_WG = wg('srvWg', 'tes-wg', CORP);
const PLAN = { mode: 'advanced', serversById: { hop: HOP, b47f: TES_WG, srvWg: SRV_WG }, chainsById: { tes: [HOP, TES_WG] }, chain: [] };
const needsOf = (tg) => targetNeeds(tg, PLAN);
const OWNER_RULES = [{ type: 'ip', value: '192.168.0.0/16, 10.0.0.0/8', target: 'chain:tes' }];

test('W4: what a routing target needs through its tunnel — its WireGuard’s DNS, tunnel address and AllowedIPs, never a key', () => {
  const tes = [
    { address: '192.168.60.1', key: 'DNS' },
    { address: '10.10.10.42', key: 'Address' },
    { address: '192.168.0.0/16', key: 'AllowedIPs' },
    { address: '10.0.0.0/8', key: 'AllowedIPs' }
  ];
  assert.deepEqual(targetNeeds('chain:tes', PLAN), tes);
  assert.deepEqual(targetNeeds('srvWg', PLAN), tes);
  assert.deepEqual(targetNeeds('chain', { chain: [HOP, TES_WG] }), tes);
  // a full tunnel, IPv6, a resolver by name or URL, a prefix on the tunnel address: only real IPv4 facts
  const odd = wg('odd', 'odd', { dns: '1.1.1.1, 2606:4700::1111, https://dns.example/dns-query', address: '10.66.0.7/24, fd00::7/128', allowedIPs: '0.0.0.0/0, ::/0, 10.66.0.0/16' });
  assert.deepEqual(targetNeeds('odd', { serversById: { odd } }), [
    { address: '1.1.1.1', key: 'DNS' }, { address: '10.66.0.7', key: 'Address' }, { address: '10.66.0.0/16', key: 'AllowedIPs' }
  ]);
  // not a WireGuard, not a target, gone: nothing
  for (const tg of ['hop', 'direct', 'block', '', null, 'gone', 'chain:gone']) assert.deepEqual(targetNeeds(tg, PLAN), [], String(tg));
  assert.deepEqual(targetNeeds('chain:tes', null), []);
  assert.ok(!JSON.stringify(targetNeeds('chain:tes', PLAN)).includes(KEY_A));
});

test('W4: the owner’s rule (192.168.0.0/16, 10.0.0.0/8 → Tes Chain) with a home LAN in 192.168.1.x is a log line only — nothing the chain needs is in it', () => {
  const subnets = localSubnets(IFACES, OWN);
  const out = lanOverlaps(subnets, [{ type: 'domain', value: 'domain:tes.systems', target: 'chain:tes' }, ...OWNER_RULES], nameOf, needsOf);
  assert.deepEqual(out, [
    { id: 'lanInBroadRange', lan: '192.168.1.0/24', iface: 'Wi-Fi', range: '192.168.0.0/16', target: 'Tes Chain' },
    { id: 'lanInBroadRange', lan: '192.168.56.0/24', iface: 'VirtualBox Host-Only Network', range: '192.168.0.0/16', target: 'Tes Chain' }
  ]);
  // never to the window, and an info line rather than a warning
  for (const n of out) {
    assert.equal(forWindow(n), false);
    assert.equal(noticeLevel(n), 'info');
  }
  assert.ok(LOG_ONLY.has('lanInBroadRange'));
  assert.equal(noticeLine(out[0]),
    'Your local network 192.168.1.0/24 (Wi-Fi) lies inside 192.168.0.0/16 that advanced routing sends to Tes Chain; none of the addresses Tes Chain is known to need (a WireGuard DNS, Address or narrower AllowedIPs) is in it, so this matters only if a host you reach through Tes Chain has an address in 192.168.1.0/24');
  // geoip:private is the same broad case
  assert.deepEqual(lanOverlaps([{ cidr: '192.168.1.0/24', iface: 'Wi-Fi' }], [{ type: 'ip', value: 'geoip:private', target: 'chain:tes' }], nameOf, needsOf),
    [{ id: 'lanInBroadRange', lan: '192.168.1.0/24', iface: 'Wi-Fi', range: '192.168.0.0/16 (geoip:private)', target: 'Tes Chain' }]);
  // a target with no WireGuard behind it knows of nothing it needs: broad too
  assert.deepEqual(lanOverlaps([{ cidr: '192.168.1.0/24', iface: 'Wi-Fi' }], [{ type: 'ip', value: '192.168.0.0/16', target: 'hop' }], () => '🇬🇧-2', needsOf).map((n) => n.id), ['lanInBroadRange']);
  // without a needsOf at all (an old caller): broad, never a throw
  assert.deepEqual(lanOverlaps([{ cidr: '192.168.1.0/24', iface: 'Wi-Fi' }], OWNER_RULES, nameOf).map((n) => n.id), ['lanInBroadRange']);
});

test('W4: a LAN that holds what the target needs — its WireGuard’s DNS, its tunnel address, a narrower AllowedIPs — is a notice, with what to do', () => {
  const at = (cidr, iface = 'Ethernet', rules = OWNER_RULES) => lanOverlaps([{ cidr, iface }], rules, nameOf, needsOf);
  // the corporate resolver is on this PC's own LAN: the corporate hosts beside it are too
  const dns = at('192.168.60.0/24');
  assert.deepEqual(dns, [{ id: 'lanInRange', lan: '192.168.60.0/24', iface: 'Ethernet', range: '192.168.0.0/16', target: 'Tes Chain', address: '192.168.60.1', key: 'DNS' }]);
  assert.equal(forWindow(dns[0]), true);
  assert.equal(noticeLevel(dns[0]), 'warn');
  assert.equal(noticeLine(dns[0]),
    'Your local network 192.168.60.0/24 (Ethernet) overlaps 192.168.60.1 — the DNS of Tes Chain’s WireGuard — inside 192.168.0.0/16 that advanced routing sends to Tes Chain: addresses in 192.168.60.0/24 stay on the LAN and never reach the tunnel. Move that LAN, VM or host-only network to another subnet');
  // the tunnel's own address
  assert.deepEqual(at('10.10.10.0/24', 'VMware Network Adapter VMnet8'),
    [{ id: 'lanInRange', lan: '10.10.10.0/24', iface: 'VMware Network Adapter VMnet8', range: '10.0.0.0/8', target: 'Tes Chain', address: '10.10.10.42', key: 'Address' }]);
  // an AllowedIPs entry narrower than the rule that overlaps the LAN, either way round
  const narrowAllowed = { serversById: { n: wg('n', 'narrow', { allowedIPs: '192.168.1.0/24, 172.20.0.0/14' }) } };
  const needsN = (tg) => targetNeeds(tg, narrowAllowed);
  assert.deepEqual(lanOverlaps([{ cidr: '192.168.1.0/24', iface: 'Wi-Fi' }], [{ type: 'ip', value: '192.168.0.0/16', target: 'n' }], () => 'narrow', needsN),
    [{ id: 'lanInRange', lan: '192.168.1.0/24', iface: 'Wi-Fi', range: '192.168.0.0/16', target: 'narrow', address: '192.168.1.0/24', key: 'AllowedIPs' }]);
  assert.deepEqual(lanOverlaps([{ cidr: '172.21.4.0/24', iface: 'vEthernet (WSL)' }], [{ type: 'ip', value: '172.16.0.0/12', target: 'n' }], () => 'narrow', needsN),
    [{ id: 'lanInRange', lan: '172.21.4.0/24', iface: 'vEthernet (WSL)', range: '172.16.0.0/12', target: 'narrow', address: '172.20.0.0/14', key: 'AllowedIPs' }]);
});

test('W4: a rule as narrow as the LAN, or narrower, is a notice whatever the target — the user asked for hosts that sit on the LAN', () => {
  const lan = [{ cidr: '192.168.1.0/24', iface: 'Wi-Fi' }];
  const host = lanOverlaps(lan, [{ type: 'ip', value: '192.168.1.20', target: 'srvWg' }], nameOf, needsOf);
  assert.deepEqual(host, [{ id: 'rangeInLan', lan: '192.168.1.0/24', iface: 'Wi-Fi', range: '192.168.1.20/32', target: 'tes-wg' }]);
  assert.equal(forWindow(host[0]), true);
  assert.equal(noticeLine(host[0]),
    '192.168.1.20/32 that advanced routing sends to tes-wg is part of your local network 192.168.1.0/24 (Wi-Fi) — hosts in 192.168.1.20/32 stay on the LAN, not the tunnel. Move that LAN, VM or host-only network to another subnet');
  // the LAN itself
  assert.deepEqual(lanOverlaps(lan, [{ type: 'ip', value: '192.168.1.0/24', target: 'chain:tes' }], nameOf, needsOf),
    [{ id: 'rangeInLan', lan: '192.168.1.0/24', iface: 'Wi-Fi', range: '192.168.1.0/24', target: 'Tes Chain' }]);
});

test('W4: silent where the LAN is not inside anything sent to a tunnel', () => {
  const lan = [{ cidr: '192.168.1.0/24', iface: 'Wi-Fi' }];
  // the owner's healthy shape: corporate ranges that do not touch this LAN
  assert.deepEqual(lanOverlaps(lan, [{ type: 'ip', value: '192.168.60.0/24,10.10.10.0/24', target: 'chain:tes' }], nameOf), []);
  // an earlier rule that keeps the LAN direct (or blocked) decides it first
  assert.deepEqual(lanOverlaps(lan, [
    { type: 'ip', value: '192.168.1.0/24', target: 'direct' },
    { type: 'ip', value: '192.168.0.0/16', target: 'chain:tes' }
  ], nameOf), []);
  // to direct, to block, to "nowhere" (''): no tunnel involved
  for (const target of ['direct', 'block', '']) {
    assert.deepEqual(lanOverlaps(lan, [{ type: 'ip', value: '192.168.0.0/16', target }], nameOf), [], target);
  }
  // a target that no longer exists: configBuilder drops that rule
  assert.deepEqual(lanOverlaps(lan, [{ type: 'ip', value: '192.168.0.0/16', target: 'gone' }], nameOf), []);
  // public ranges, IPv6, geoip of a country, garbage: not "private ranges"
  assert.deepEqual(lanOverlaps([{ cidr: '5.6.7.0/24', iface: 'odd' }], [{ type: 'ip', value: '5.0.0.0/8', target: 'chain:tes' }], nameOf), []);
  assert.deepEqual(lanOverlaps(lan, [{ type: 'ip', value: 'fc00::/7, geoip:ir, 192.168.1.300, 192.168.0.0/40, nonsense', target: 'chain:tes' }], nameOf), []);
  assert.deepEqual(lanOverlaps(lan, null, nameOf), []);
  assert.deepEqual(lanOverlaps(null, [{ type: 'ip', value: '192.168.0.0/16', target: 'chain:tes' }], nameOf), []);
});

test('W4: one line per local network — the strongest finding, the first rule among equals', () => {
  const lan = [{ cidr: '192.168.1.0/24', iface: 'Wi-Fi' }];
  // a narrow rule after a broad one: the narrow one is what the user needs through the tunnel
  const out = lanOverlaps(lan, [
    { type: 'ip', value: '192.168.0.0/16', target: 'chain:tes' },
    { type: 'ip', value: '192.168.1.20,192.168.1.21', target: 'srvWg' }
  ], nameOf, needsOf);
  assert.deepEqual(out, [{ id: 'rangeInLan', lan: '192.168.1.0/24', iface: 'Wi-Fi', range: '192.168.1.20/32', target: 'tes-wg' }]);
  // two broad rules: the first
  const two = lanOverlaps(lan, [
    { type: 'ip', value: '192.168.0.0/16', target: 'chain:tes' },
    { type: 'ip', value: '192.168.0.0/17', target: 'srvWg' }
  ], nameOf, needsOf);
  assert.deepEqual(two.map((n) => [n.id, n.range]), [['lanInBroadRange', '192.168.0.0/16']]);
  // a later rule whose target needs something in the LAN beats an earlier broad one
  const needy = { serversById: { n: wg('n', 'narrow', { allowedIPs: '192.168.1.0/24' }) }, chainsById: PLAN.chainsById };
  const mixed = lanOverlaps(lan, [
    { type: 'ip', value: '192.168.0.0/16', target: 'chain:tes' },
    { type: 'ip', value: '192.168.0.0/16', target: 'n' }
  ], (tg) => (tg === 'n' ? 'narrow' : nameOf(tg)), (tg) => targetNeeds(tg, needy));
  assert.deepEqual(mixed.map((n) => [n.id, n.target, n.key]), [['lanInRange', 'narrow', 'AllowedIPs']]);
});

test('routing targets by the name the user gave them', () => {
  const plan = { serversById: { s1: { id: 's1', name: 'tes-wg' } }, chain: [{ name: 'hop' }, { name: 'tes-wg' }] };
  const chains = [{ id: 'tes', name: 'Tes Chain', members: ['hop', 's1'] }];
  assert.equal(routeTargetName('chain:tes', plan, chains), 'Tes Chain');
  assert.equal(routeTargetName('s1', plan, chains), 'tes-wg');
  assert.equal(routeTargetName('chain', plan, chains), 'hop → tes-wg');
  for (const tg of ['direct', 'block', '', null, 'chain:gone', 'gone']) assert.equal(routeTargetName(tg, plan, chains), null, String(tg));
  assert.equal(routeTargetName('chain', { chain: [] }, []), null);
});

/* ------------------------------ L1: the logon task names another copy ------------------------------ */

const TASK_XML = (command, args = '--hidden') => [
  '<?xml version="1.0" encoding="UTF-16"?>',
  '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">',
  '  <Actions Context="Author">',
  '    <Exec>',
  `      <Command>${command}</Command>`,
  `      <Arguments>${args}</Arguments>`,
  '    </Exec>',
  '  </Actions>',
  '</Task>'
].join('\r\r\n');

test('L1: the logon task is READ with /Query … /XML — the existing query and every write stay as they were', () => {
  assert.deepEqual(schtasksQueryXmlArgs(), ['/Query', '/TN', 'IRNetFree', '/XML']);
  assert.deepEqual(schtasksQueryArgs(), ['/Query', '/TN', 'IRNetFree']);
  const read = schtasksQueryXmlArgs().map((a) => a.toUpperCase());
  for (const write of ['/CREATE', '/DELETE', '/CHANGE', '/RUN', '/END', '/F']) assert.ok(!read.includes(write), write);
});

test('L1: the file the task runs, out of its XML', () => {
  assert.equal(taskExeFromXml(TASK_XML('"C:\\Program Files\\IRNetFree\\IRNetFree.exe"')), 'C:\\Program Files\\IRNetFree\\IRNetFree.exe');
  assert.equal(taskExeFromXml(TASK_XML('C:\\Users\\me\\Desktop\\IRNetFree-Portable-1.15.0.exe')), 'C:\\Users\\me\\Desktop\\IRNetFree-Portable-1.15.0.exe');
  assert.equal(taskExeFromXml(TASK_XML('&quot;D:\\a &amp; b\\IRNetFree.exe&quot;')), 'D:\\a & b\\IRNetFree.exe');
  // a command line in one piece: the quoted program, without its arguments
  assert.equal(taskExeFromXml(TASK_XML('"C:\\x\\IRNetFree.exe" --hidden', '')), 'C:\\x\\IRNetFree.exe');
  for (const bad of ['', 'not xml', '<Task><Actions></Actions></Task>', null, undefined]) assert.equal(taskExeFromXml(bad), '', String(bad));
});

test('L1: stale only when the task certainly names ANOTHER file — any doubt is silence', () => {
  const here = 'C:\\Program Files\\IRNetFree\\IRNetFree.exe';
  assert.equal(autostartStale('C:\\Users\\me\\Desktop\\IRNetFree-Portable-1.15.0.exe', here), true);
  assert.equal(autostartStale('C:\\Program Files\\IRNetFree Plus\\IRNetFree Plus.exe', here), true);
  // the same file, however it is spelt
  assert.equal(autostartStale('c:\\program files\\irnetfree\\IRNETFREE.EXE', here), false);
  assert.equal(autostartStale('C:/Program Files/IRNetFree/IRNetFree.exe', here), false);
  assert.equal(autostartStale('C:\\Program Files\\\\IRNetFree\\IRNetFree.exe ', here), false);
  // schtasks prints the XML in the console code page: a non-ASCII path arrives mangled, so it is never compared
  assert.equal(autostartStale('C:\\Users\\???\\Desktop\\IRNetFree.exe', 'C:\\Users\\سعید\\Desktop\\IRNetFree.exe'), false);
  assert.equal(autostartStale('C:\\Users\\\uFFFD\uFFFD\\Desktop\\IRNetFree.exe', 'C:\\Users\\سعید\\Desktop\\IRNetFree.exe'), false);
  assert.equal(autostartStale('C:\\Users\\a\\IRNetFree.exe', 'C:\\Users\\سعید\\IRNetFree.exe'), false);
  // an environment variable we cannot expand, nothing read, nothing running
  assert.equal(autostartStale('%NOPE_NOT_SET_X%\\IRNetFree.exe', here, { env: {} }), false);
  assert.equal(autostartStale('%ProgramFiles%\\IRNetFree\\IRNetFree.exe', here, { env: { PROGRAMFILES: 'C:\\Program Files' } }), false);
  assert.equal(autostartStale('', here), false);
  assert.equal(autostartStale(here, ''), false);
  // the caller's own "is it the same file" (an 8.3 name, a junction) wins
  assert.equal(autostartStale('C:\\PROGRA~1\\IRNetFree\\IRNetFree.exe', here, { same: () => true }), false);
  assert.equal(autostartStale('C:\\old\\IRNetFree.exe', here, { same: () => false }), true);
});
