'use strict';
/**
 * v1.16.3 (Windows visibility, report W1 / W4 / L1): what a connect — or a
 * launch — can see on THIS machine that explains a tunnel that "does not work
 * properly" here while the same configs work on another PC. Said, never acted
 * on: these helpers only read, and each returns nothing at all for a machine
 * where its condition does not hold, which is what keeps a healthy PC quiet.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { makeWireguardServer, makeProxyServer } = require('../src/main/parser');
const {
  sharedWgIdentities, localSubnets, lanOverlaps, routeTargetName, noticeLine
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
  assert.deepEqual(out, [{ id: 'wgSharedKey', name: 'tes-wg', other: 'tes-wg (copy)' }]);
  const said = JSON.stringify(out) + noticeLine(out[0]);
  assert.ok(!said.includes(KEY_A), 'the private key is never in a notice or a log line');
  assert.match(noticeLine(out[0]), /^WireGuard tes-wg: this identity is also stored as tes-wg \(copy\) — a WireGuard server accepts one device per key; used on two devices \(or tested while connected\) one of them stalls/);
});

test('W1: the same tunnel address under another key for the same server is said too — the address, never a key', () => {
  const chainWg = wg('b47f', 'tes-wg');
  const reza = wg('r1', 'reza-wire', { privateKey: KEY_B });
  const out = sharedWgIdentities(['b47f'], [chainWg, reza]);
  assert.deepEqual(out, [{ id: 'wgSharedAddress', name: 'tes-wg', other: 'reza-wire', address: '10.10.10.42' }]);
  const line = noticeLine(out[0]);
  assert.ok(!line.includes(KEY_A) && !line.includes(KEY_B));
  assert.match(line, /10\.10\.10\.42/);
  assert.match(line, /reza-wire/);
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
  assert.deepEqual(sharedWgIdentities(['w1'], [warp1, warp1copy]), [{ id: 'wgSharedKey', name: 'warp-1', other: 'warp-1 copy' }]);
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

test('W4: a LAN inside a private range advanced routing sends to a chain is said — with the range and the target by name', () => {
  const subnets = localSubnets(IFACES, OWN);
  const rules = [
    { type: 'domain', value: 'domain:tes.systems', target: 'chain:tes' },
    { type: 'ip', value: '10.0.0.0/8, 192.168.0.0/16', target: 'chain:tes' }
  ];
  const out = lanOverlaps(subnets, rules, nameOf);
  assert.deepEqual(out, [
    { id: 'lanInRange', lan: '192.168.1.0/24', iface: 'Wi-Fi', range: '192.168.0.0/16', target: 'Tes Chain' },
    { id: 'lanInRange', lan: '192.168.56.0/24', iface: 'VirtualBox Host-Only Network', range: '192.168.0.0/16', target: 'Tes Chain' }
  ]);
  assert.equal(noticeLine(out[0]),
    'Your local network 192.168.1.0/24 (Wi-Fi) lies inside 192.168.0.0/16 that advanced routing sends to Tes Chain — hosts in 192.168.1.0/24 stay on the LAN, not the tunnel');
});

test('W4: a routed host or range inside the LAN is said the other way round; geoip:private counts as the private ranges', () => {
  const lan = [{ cidr: '192.168.1.0/24', iface: 'Wi-Fi' }];
  assert.deepEqual(lanOverlaps(lan, [{ type: 'ip', value: '192.168.1.20', target: 'srvWg' }], nameOf),
    [{ id: 'rangeInLan', lan: '192.168.1.0/24', iface: 'Wi-Fi', range: '192.168.1.20/32', target: 'tes-wg' }]);
  assert.match(noticeLine({ id: 'rangeInLan', lan: '192.168.1.0/24', iface: 'Wi-Fi', range: '192.168.1.20/32', target: 'tes-wg' }),
    /^192\.168\.1\.20\/32 that advanced routing sends to tes-wg lies inside your local network 192\.168\.1\.0\/24 \(Wi-Fi\) — hosts in 192\.168\.1\.20\/32 stay on the LAN, not the tunnel$/);
  assert.deepEqual(lanOverlaps(lan, [{ type: 'ip', value: 'geoip:private', target: 'chain:tes' }], nameOf),
    [{ id: 'lanInRange', lan: '192.168.1.0/24', iface: 'Wi-Fi', range: '192.168.0.0/16 (geoip:private)', target: 'Tes Chain' }]);
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

test('W4: one line per local network — the first rule that reaches it', () => {
  const lan = [{ cidr: '192.168.1.0/24', iface: 'Wi-Fi' }];
  const out = lanOverlaps(lan, [
    { type: 'ip', value: '192.168.0.0/16', target: 'chain:tes' },
    { type: 'ip', value: '192.168.1.20,192.168.1.21', target: 'srvWg' }
  ], nameOf);
  assert.equal(out.length, 1);
  assert.equal(out[0].range, '192.168.0.0/16');
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
