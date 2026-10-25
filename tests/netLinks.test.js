'use strict';
/**
 * Multi-internet: the list of internets (src/main/netLinks.js listLinks) and
 * the speed test of each one through the server (speedTest / testAll).
 *
 * The list is pinned against recorded command output of every OS the feature
 * runs on — Windows (Wi-Fi + a phone's USB tethering, a disconnected NIC, our
 * own TUN), macOS (Wi-Fi + iPhone USB), Linux (two DHCP'd defaults), OpenWrt
 * (wan on a VLAN + a QMI modem, netifd's names) — through an injected `run`:
 * no command runs. The speed test runs no core and reaches nothing: a fake
 * core starter, a fake measurement, and for the HTTP client itself a fake
 * Cloudflare behind a fake socket.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');

const L = require('../src/main/netLinks');
const P = require('../src/main/tunPlatform');
const { buildTestConfig } = require('../src/main/configBuilder');
const { server, VLESS_WS_TLS, TROJAN_TCP_TLS } = require('./fixtures');

/** A `run` answering from a table of [regex over `cmd argv…`, stdout | () => stdout]; anything else fails like a missing command. */
function fakeRun(table) {
  const calls = [];
  const run = async (cmd, args) => {
    const line = [cmd, ...(args || [])].join(' ');
    calls.push({ cmd, args, line });
    for (const [re, out] of table) if (re.test(line)) return typeof out === 'function' ? out() : out;
    throw new Error('not found: ' + line);
  };
  return { run, calls };
}

// ---------------------------------------------------------------- Windows ---

/** LINKS_PS's answer as Windows PowerShell 5.1 prints it (-Compress), from a machine with Wi-Fi and a phone on USB. */
const WIN_OUT = JSON.stringify({
  routes: [
    { nextHop: '192.168.1.1', ifIndex: 23, alias: 'Wi-Fi', routeMetric: 0, ifMetric: 45, state: 'Connected' },
    { nextHop: '192.168.42.129', ifIndex: 31, alias: 'Ethernet 2', routeMetric: 0, ifMetric: 25, state: 'Connected' },
    { nextHop: '192.168.0.1', ifIndex: 5, alias: 'Ethernet', routeMetric: 0, ifMetric: 25, state: 'Disconnected' },
    { nextHop: '0.0.0.0', ifIndex: 22, alias: 'IRNetFree', routeMetric: 0, ifMetric: 5, state: 'Connected' }
  ],
  adapters: [
    { ifIndex: 23, name: 'Wi-Fi', desc: 'Killer(R) Wi-Fi 6 AX1650i 160MHz Wireless Network Adapter (201NGW)', media: 'Native 802.11', phys: 'Native 802.11', medium: 9, status: 'Up' },
    { ifIndex: 31, name: 'Ethernet 2', desc: 'Remote NDIS based Internet Sharing Device', media: '802.3', phys: 'Unspecified', medium: 0, status: 'Up' },
    { ifIndex: 5, name: 'Ethernet', desc: 'Killer E2600 Gigabit Ethernet Controller', media: '802.3', phys: '802.3', medium: 14, status: 'Disconnected' },
    { ifIndex: 22, name: 'IRNetFree', desc: 'sing-tun Tunnel', media: 'IP', phys: 'Unspecified', medium: 0, status: 'Up' }
  ],
  addrs: [
    { ifIndex: 23, ip: '169.254.10.20', state: 'Deprecated' },
    { ifIndex: 23, ip: '192.168.1.23', state: 'Preferred' },
    { ifIndex: 31, ip: '192.168.42.77', state: 'Preferred' },
    { ifIndex: 5, ip: '192.168.0.50', state: 'Tentative' },
    { ifIndex: 22, ip: '172.19.0.1', state: 'Preferred' }
  ],
  profiles: [
    { ifIndex: 23, name: 'Home' },
    { ifIndex: 31, name: 'Network 3' },
    { ifIndex: 22, name: 'IRNetFree' }
  ]
}) + '\r\n';

test('listLinks (win32): every connected default route, our TUN and a dead NIC left out, the OS\'s preferred first', async () => {
  const { run, calls } = fakeRun([[/^powershell /, WIN_OUT]]);
  const links = await L.listLinks({ platform: 'win32', run });
  assert.deepEqual(links, [
    // a phone's RNDIS tethering reports a faster link than the Wi-Fi: Windows prefers it (25 < 45)
    { id: 'Ethernet 2', iface: 'Ethernet 2', name: 'Ethernet 2', kind: 'usb', address: '192.168.42.77', gateway: '192.168.42.129', metric: 25 },
    { id: 'Wi-Fi', iface: 'Wi-Fi', name: 'Wi-Fi — Home', kind: 'wifi', address: '192.168.1.23', gateway: '192.168.1.1', metric: 45 }
  ]);
  assert.equal(calls.length, 1, 'one PowerShell for routes, adapters, addresses and profiles');
  assert.deepEqual(calls[0].args, P.psArgs(L.LINKS_PS), 'psArgs: UTF-8 output, so a renamed adapter "اترنت" comes back as itself');
  const script = calls[0].args.at(-1);
  assert.ok(script.startsWith(P.DEFAULT_ROUTE_ROWS_PS), 'the very rows the gateway pick reads');
  for (const cmdlet of ['Get-NetAdapter', 'Get-NetIPAddress -AddressFamily IPv4', 'Get-NetConnectionProfile', '-PolicyStore ActiveStore']) {
    assert.ok(script.includes(cmdlet), cmdlet);
  }
  assert.doesNotMatch(script, /\b(Set|New|Remove|Disable|Enable|Restart)-Net/, 'it only reads');
});

test('listLinks (win32): on-link defaults (PPPoE) count, an adapter that is not Up does not, PS 5.1 unwrapping, junk and failures', async () => {
  const one = JSON.stringify({
    routes: [
      { nextHop: '0.0.0.0', ifIndex: 40, alias: 'Pars Online', routeMetric: 0, ifMetric: 50, state: 'Connected' },
      { nextHop: '10.0.0.1', ifIndex: 41, alias: 'Ethernet 3', routeMetric: 0, ifMetric: 10, state: 'Connected' }
    ],
    // one adapter: PowerShell 5.1 prints the object itself, not a one-element array
    adapters: { ifIndex: 41, name: 'Ethernet 3', desc: 'Realtek USB GbE Family Controller', media: '802.3', phys: '802.3', medium: 14, status: 'Disabled' },
    addrs: { ifIndex: 40, ip: '5.6.7.8', state: 'Preferred' },
    profiles: []
  });
  const links = await L.listLinks({ platform: 'win32', run: fakeRun([[/^powershell /, 'WARNING: something\r\n' + one]]).run });
  assert.deepEqual(links, [
    // a PPP connection is no "net adapter": no facts about it, still a way out — with no next hop
    { id: 'Pars Online', iface: 'Pars Online', name: 'Pars Online', kind: 'other', address: '5.6.7.8', gateway: '', metric: 50 }
  ]);
  assert.deepEqual(await L.listLinks({ platform: 'win32', run: fakeRun([[/^powershell /, 'Get-NetRoute : boom\r\n']]).run }), [], 'not JSON: nothing');
  assert.deepEqual(await L.listLinks({ platform: 'win32', run: fakeRun([]).run }), [], 'a failing command: nothing, no throw');
});

test('kindWin: the description first — a phone is an 802.3 adapter to Windows, and so is a VPN\'s TAP', () => {
  const k = (desc, media = '', phys = '', medium = 0) => L.kindWin({ desc, media, phys, medium });
  assert.equal(k('Remote NDIS based Internet Sharing Device', '802.3'), 'usb');
  assert.equal(k('Remote NDIS Compatible Device', '802.3'), 'usb');
  assert.equal(k('Apple Mobile Device Ethernet', '802.3'), 'usb');
  assert.equal(k('Intel(R) Wi-Fi 6E AX211 160MHz', 'Native 802.11', 'Native 802.11', 9), 'wifi');
  assert.equal(k('Generic Mobile Broadband Adapter', 'Mobile Broadband', 'Wireless WAN', 8), 'cellular');
  assert.equal(k('Killer E2600 Gigabit Ethernet Controller', '802.3', '802.3', 14), 'ethernet');
  assert.equal(k('Bluetooth Device (Personal Area Network)', '802.3', 'BlueTooth', 10), 'other');
  assert.equal(k('TAP-Windows Adapter V9 for OpenVPN Connect', '802.3'), 'other');
  assert.equal(k('WireGuard Tunnel', 'IP'), 'other');
  assert.equal(L.kindWin(null), 'other');
  for (const kind of ['usb', 'wifi', 'cellular', 'ethernet', 'other']) assert.ok(L.KINDS.includes(kind));
});

// ------------------------------------------------------------------ macOS ---

const NETSTAT = [
  'Routing tables',
  '',
  'Internet:',
  'Destination        Gateway            Flags               Netif Expire',
  'default            192.168.1.1        UGScg                 en0       ',
  'default            172.20.10.1        UGScIg                en7       ',
  'default            link#22            UCSIg               utun3       ',
  '127                127.0.0.1          UCS                   lo0       ',
  '127.0.0.1          127.0.0.1          UH                    lo0       ',
  '169.254            link#11            UCS                   en0      !',
  '172.20.10/28       link#18            UCS                   en7      !',
  '192.168.1          link#11            UCS                   en0      !',
  ''
].join('\n');
const HW_PORTS = [
  '',
  'Hardware Port: Ethernet',
  'Device: en5',
  'Ethernet Address: aa:bb:cc:00:00:05',
  '',
  'Hardware Port: Wi-Fi',
  'Device: en0',
  'Ethernet Address: aa:bb:cc:00:00:00',
  '',
  'Hardware Port: Thunderbolt Bridge',
  'Device: bridge0',
  'Ethernet Address: aa:bb:cc:00:00:0b',
  '',
  'Hardware Port: iPhone USB',
  'Device: en7',
  'Ethernet Address: aa:bb:cc:00:00:07',
  '',
  'VLAN Configurations',
  '===================',
  ''
].join('\n');
const SERVICE_ORDER = [
  'An asterisk (*) denotes that a network service is disabled.',
  '(1) Wi-Fi',
  '(Hardware Port: Wi-Fi, Device: en0)',
  '',
  '(2) iPhone USB',
  '(Hardware Port: iPhone USB, Device: en7)',
  '',
  '(3) Thunderbolt Bridge',
  '(Hardware Port: Thunderbolt Bridge, Device: bridge0)',
  ''
].join('\n');
const MAC_IFACES = {
  lo0: [{ address: '127.0.0.1', family: 'IPv4', internal: true }],
  en0: [{ address: 'fe80::1', family: 'IPv6', internal: false }, { address: '192.168.1.40', family: 'IPv4', internal: false }],
  en7: [{ address: '172.20.10.2', family: 'IPv4', internal: false }],
  utun3: [{ address: '172.19.0.1', family: 'IPv4', internal: false }]
};

test('listLinks (darwin): the primary default, then the scoped ones by service order — never a utun', async () => {
  const { run, calls } = fakeRun([
    [/^netstat -rn -f inet$/, NETSTAT],
    [/^networksetup -listallhardwareports$/, HW_PORTS],
    [/^networksetup -listnetworkserviceorder$/, SERVICE_ORDER]
  ]);
  const links = await L.listLinks({ platform: 'darwin', run, interfaces: () => MAC_IFACES });
  assert.deepEqual(links, [
    { id: 'en0', iface: 'en0', name: 'Wi-Fi', kind: 'wifi', address: '192.168.1.40', gateway: '192.168.1.1', metric: 0 },
    { id: 'en7', iface: 'en7', name: 'iPhone USB', kind: 'usb', address: '172.20.10.2', gateway: '172.20.10.1', metric: 1 }
  ]);
  assert.deepEqual(calls.map((c) => c.cmd), ['netstat', 'networksetup', 'networksetup']);
  // the names and the order are extras: without networksetup the devices still come, unscoped first
  const bare = await L.listLinks({ platform: 'darwin', run: fakeRun([[/^netstat/, NETSTAT]]).run, interfaces: () => ({}) });
  assert.deepEqual(bare.map((l) => [l.iface, l.name, l.metric]), [['en0', 'en0', 0], ['en7', 'en7', 1]]);
});

test('parseNetstatDefaults: the Netif column from the header (old macOS had Refs and Use), down routes skipped', () => {
  const old = [
    'Destination        Gateway            Flags        Refs      Use   Netif Expire',
    'default            10.0.1.1           UGSc           12        0     en1',
    'default            10.0.2.1           GSc             0        0     en2',
    'default            link#9             UCSI            0        0   ppp0'
  ].join('\n');
  assert.deepEqual(L.parseNetstatDefaults(old), [
    { dev: 'en1', gateway: '10.0.1.1', scoped: false },
    { dev: 'ppp0', gateway: '', scoped: true }   // on-link: no gateway, still a way out
  ]);
  assert.deepEqual(L.parseHardwarePorts(HW_PORTS), { en5: 'Ethernet', en0: 'Wi-Fi', bridge0: 'Thunderbolt Bridge', en7: 'iPhone USB' });
  assert.deepEqual(L.parseServiceOrder(SERVICE_ORDER), ['en0', 'en7', 'bridge0']);
  assert.equal(L.kindMac('USB 10/100/1000 LAN', 'en8'), 'ethernet', 'a LAN dongle on USB is a wired link');
  assert.equal(L.kindMac('iPad USB', 'en9'), 'usb');
  assert.equal(L.kindMac('Bluetooth PAN', 'en6'), 'other');
});

// ------------------------------------------------------------------ Linux ---

const LINUX_ROUTES = [
  'default via 192.168.1.1 dev wlp2s0 proto dhcp src 192.168.1.50 metric 600 ',
  'default via 192.168.42.129 dev usb0 proto dhcp src 192.168.42.10 metric 100 ',
  'default via 10.9.0.1 dev enp3s0 proto dhcp metric 50 linkdown ',
  'default dev tun0 scope link metric 5 ',
  ''
].join('\n');
const LINUX_ADDRS = [
  '1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever',
  '2: enp3s0    inet 10.9.0.33/24 brd 10.9.0.255 scope global dynamic enp3s0\\       valid_lft 3000sec preferred_lft 3000sec',
  '3: wlp2s0    inet 192.168.1.50/24 brd 192.168.1.255 scope global dynamic noprefixroute wlp2s0\\       valid_lft 86000sec preferred_lft 86000sec',
  '5: usb0    inet 192.168.42.10/24 brd 192.168.42.255 scope global dynamic noprefixroute usb0\\       valid_lft 3500sec preferred_lft 3500sec',
  '6: tun0    inet 198.18.0.1/15 scope global tun0\\       valid_lft forever preferred_lft forever',
  ''
].join('\n');

test('listLinks (linux): every `default via` line by metric — linkdown and our tun0 left out', async () => {
  const { run, calls } = fakeRun([
    [/^ip -4 route show default$/, LINUX_ROUTES],
    [/^ip -4 -o addr show$/, LINUX_ADDRS]
  ]);
  const links = await L.listLinks({ platform: 'linux', openwrt: false, run, sysInfo: () => ({}) });
  assert.deepEqual(links, [
    { id: 'usb0', iface: 'usb0', name: 'usb0', kind: 'usb', address: '192.168.42.10', gateway: '192.168.42.129', metric: 100 },
    { id: 'wlp2s0', iface: 'wlp2s0', name: 'wlp2s0', kind: 'wifi', address: '192.168.1.50', gateway: '192.168.1.1', metric: 600 }
  ]);
  assert.deepEqual(calls.map((c) => c.line), ['ip -4 route show default', 'ip -4 -o addr show'], 'no ubus off a router');
  // sysfs knows better than the name: a phone on cdc_ncm named enx…, a modem behind qmi_wwan
  const sys = { enx0a1b2c3d4e5f: { driver: 'cdc_ncm' }, wwp0s20u4i6: { driver: 'qmi_wwan', devtype: 'wwan' } };
  const more = await L.listLinks({
    platform: 'linux', openwrt: false, sysInfo: (dev) => sys[dev] || {},
    run: fakeRun([[/route show default/, 'default via 10.1.1.1 dev enx0a1b2c3d4e5f metric 100\ndefault dev wwp0s20u4i6 proto static scope link metric 700\n'], [/addr/, '']]).run
  });
  assert.deepEqual(more.map((l) => [l.iface, l.kind, l.gateway]), [['enx0a1b2c3d4e5f', 'usb', '10.1.1.1'], ['wwp0s20u4i6', 'cellular', '']]);
  assert.deepEqual(await L.listLinks({ platform: 'linux', openwrt: false, run: fakeRun([]).run }), [], 'no ip: nothing, no throw');
});

test('parseIpDefaultRoutes: a multipath default is one way out per nexthop; `via inet` and no metric read', () => {
  const text = [
    'default proto static metric 1024 ',
    '\tnexthop via 10.0.0.1 dev eth0 weight 1 ',
    '\tnexthop via 10.0.1.1 dev eth1 weight 1 linkdown',
    'default via inet 10.2.0.1 dev eth2 ',
    '10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.5 '
  ].join('\n');
  assert.deepEqual(L.parseIpDefaultRoutes(text), [
    { dev: 'eth0', gateway: '10.0.0.1', metric: 1024, src: '' },
    { dev: 'eth2', gateway: '10.2.0.1', metric: 0, src: '' }
  ]);
  assert.deepEqual(L.parseIpAddrs('7: eth0.2    inet 192.168.1.100/24 brd 192.168.1.255 scope global eth0.2\\       valid_lft forever'), { 'eth0.2': '192.168.1.100' });
});

// ---------------------------------------------------------------- OpenWrt ---

const OWRT_ROUTES = [
  'default via 192.168.1.1 dev eth0.2 proto static src 192.168.1.100 metric 10 ',
  'default via 10.64.12.8 dev wwan0 proto static src 10.64.12.7 metric 20 ',
  ''
].join('\n');
const OWRT_ADDRS = [
  '1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever',
  '9: br-lan    inet 192.168.8.1/24 brd 192.168.8.255 scope global br-lan\\       valid_lft forever preferred_lft forever',
  '10: eth0.2    inet 192.168.1.100/24 brd 192.168.1.255 scope global eth0.2\\       valid_lft forever preferred_lft forever',
  '14: wwan0    inet 10.64.12.7/29 brd 10.64.12.7 scope global wwan0\\       valid_lft forever preferred_lft forever',
  ''
].join('\n');
/** `ubus call network.interface dump`, trimmed to what matters: wan + wan6 share a device, the QMI modem's addresses live on wwan_4. */
const OWRT_DUMP = JSON.stringify({
  interface: [
    { interface: 'lan', up: true, proto: 'static', device: 'br-lan', l3_device: 'br-lan', 'ipv4-address': [{ address: '192.168.8.1', mask: 24 }], route: [] },
    { interface: 'loopback', up: true, proto: 'static', device: 'lo', l3_device: 'lo', route: [] },
    { interface: 'wan', up: true, proto: 'dhcp', device: 'eth0.2', l3_device: 'eth0.2', metric: 10,
      'ipv4-address': [{ address: '192.168.1.100', mask: 24 }], route: [{ target: '0.0.0.0', mask: 0, nexthop: '192.168.1.1', source: '192.168.1.100/32' }] },
    { interface: 'wan6', up: true, proto: 'dhcpv6', device: 'eth0.2', l3_device: 'eth0.2', route: [{ target: '::', mask: 0, nexthop: 'fe80::1' }] },
    { interface: 'wwan', up: true, proto: 'qmi', device: '/dev/cdc-wdm0', l3_device: 'wwan0', metric: 20, route: [] },
    { interface: 'wwan_4', up: true, proto: 'static', dynamic: true, device: 'wwan0', l3_device: 'wwan0', metric: 20,
      'ipv4-address': [{ address: '10.64.12.7', mask: 29 }], route: [{ target: '0.0.0.0', mask: 0, nexthop: '10.64.12.8', source: '10.64.12.7/32' }] }
  ]
});

test('listLinks (openwrt): the kernel\'s defaults, named the way LuCI names them — wan, wwan', async () => {
  const { run, calls } = fakeRun([
    [/^ip -4 route show default$/, OWRT_ROUTES],
    [/^ip -4 -o addr show$/, OWRT_ADDRS],
    [/^ubus call network\.interface dump$/, OWRT_DUMP]
  ]);
  const links = await L.listLinks({ platform: 'linux', openwrt: true, run, sysInfo: () => ({}) });
  assert.deepEqual(links, [
    { id: 'eth0.2', iface: 'eth0.2', name: 'wan', kind: 'ethernet', address: '192.168.1.100', gateway: '192.168.1.1', metric: 10 },
    { id: 'wwan0', iface: 'wwan0', name: 'wwan', kind: 'cellular', address: '10.64.12.7', gateway: '10.64.12.8', metric: 20 }
  ]);
  assert.deepEqual(calls.map((c) => c.cmd), ['ip', 'ip', 'ubus']);
  // 'openwrt' as the platform, and the router's own detection (openwrtNet.isOpenwrt) — the same answer
  assert.deepEqual(await L.listLinks({ platform: 'openwrt', run, sysInfo: () => ({}) }), links);
  const saved = process.env.IRNETFREE_PLATFORM;
  process.env.IRNETFREE_PLATFORM = 'openwrt';
  try { assert.deepEqual(await L.listLinks({ platform: 'linux', run, sysInfo: () => ({}) }), links); }
  finally { if (saved === undefined) delete process.env.IRNETFREE_PLATFORM; else process.env.IRNETFREE_PLATFORM = saved; }
  // no ubus answer: the devices themselves, still listed
  const bare = await L.listLinks({ platform: 'openwrt', sysInfo: () => ({}), run: fakeRun([[/route show default/, OWRT_ROUTES], [/addr/, OWRT_ADDRS]]).run });
  assert.deepEqual(bare.map((l) => [l.iface, l.name, l.kind]), [['eth0.2', 'eth0.2', 'ethernet'], ['wwan0', 'wwan0', 'cellular']]);
});

test('kindLinux: driver, then DEVTYPE, then OpenWrt\'s protocol, then the name', () => {
  assert.equal(L.kindLinux('eth1', { driver: 'rndis_host' }), 'usb', 'an Android phone on USB');
  assert.equal(L.kindLinux('eth1', { driver: 'ipheth' }), 'usb', 'an iPhone on USB');
  assert.equal(L.kindLinux('usb0', {}), 'usb');
  assert.equal(L.kindLinux('wlan0', {}), 'wifi');
  assert.equal(L.kindLinux('phy0-sta0', {}), 'wifi', 'OpenWrt 23\'s Wi-Fi client');
  assert.equal(L.kindLinux('wwan0', {}), 'cellular');
  assert.equal(L.kindLinux('eth2', {}, 'ncm'), 'cellular', 'a modem in NCM mode on OpenWrt');
  assert.equal(L.kindLinux('pppoe-wan', {}, 'pppoe'), 'ethernet');
  assert.equal(L.kindLinux('wan', {}), 'ethernet', 'a DSA port');
  assert.equal(L.kindLinux('eth0', { devtype: 'wlan' }), 'wifi');
  assert.equal(L.kindLinux('wg0', {}), 'other');
  const names = L.logicalByDev(JSON.parse(OWRT_DUMP));
  assert.deepEqual(names.get('eth0.2'), { name: 'wan', proto: 'dhcp', def4: true }, 'wan, not wan6, on the shared device');
  assert.deepEqual(names.get('wwan0'), { name: 'wwan', proto: 'qmi', def4: true }, 'the modem\'s wwan_4 is the user\'s wwan');
  assert.equal(names.has('lo'), false);
});

// ------------------------------------------------------------- speed test ---

const XHTTP_ECH_FRAG = server('sv-x', 'XHTTP', 'vless', 'x.example.com', 443, {
  protocol: 'vless',
  _fragment: 'tlshello,100-200,10-20',
  settings: { vnext: [{ address: 'x.example.com', port: 443, users: [{ id: 'uuid-x', encryption: 'none' }] }] },
  streamSettings: {
    network: 'xhttp',
    security: 'tls',
    xhttpSettings: { path: '/x', mode: 'auto', extra: { downloadSettings: { address: 'd.example.com', port: 443, network: 'xhttp', security: 'tls', xhttpSettings: { path: '/x' } } } },
    tlsSettings: { serverName: 'x.example.com', echConfigList: 'x.example.com+https://1.1.1.1/dns-query' }
  }
});

/** A core starter that starts nothing: records the config, counts cleanups. */
function fakeCore() {
  const state = { configs: [], cleaned: 0 };
  state.startTest = async (config) => {
    state.configs.push(JSON.parse(JSON.stringify(config)));
    return { proc: { exitCode: null, signalCode: null }, cleanup: () => { state.cleaned++; } };
  };
  return state;
}

test('speedTest: every dial the core makes itself leaves by the link — the fragment dialer, XHTTP\'s downlink, the ECH query', async () => {
  const core = fakeCore();
  const seen = [];
  const r = await L.speedTest({
    link: { id: 'Ethernet 2', iface: 'Ethernet 2' },
    server: XHTTP_ECH_FRAG,
    buildTestConfig: (s, port) => { seen.push(port); return buildTestConfig(s, port); },
    startTest: core.startTest,
    port: 31234,
    measure: async ({ port, deadline }) => {
      assert.equal(port, 31234, 'measured through the SOCKS the config listens on');
      assert.ok(deadline > Date.now());
      return { rttMs: 123.456, downMbps: 12.345, upMbps: 3.21 };
    }
  });
  assert.deepEqual(r, { id: 'Ethernet 2', ok: true, rttMs: 123.5, downMbps: 12.3, upMbps: 3.2, error: null });
  assert.deepEqual(seen, [31234]);
  assert.equal(core.cleaned, 1, 'the core is killed after');
  const cfg = core.configs[0];
  assert.equal(cfg.inbounds[0].port, 31234);
  const byTag = Object.fromEntries(cfg.outbounds.map((o) => [o.tag, o]));
  const proxy = byTag.proxy.streamSettings;
  assert.deepEqual(proxy.sockopt, { dialerProxy: 'dpi-1' }, 'it dials through the fragment dialer — that one is bound, not it');
  assert.equal(byTag['dpi-1'].streamSettings.sockopt.interface, 'Ethernet 2');
  assert.equal(byTag.direct.streamSettings.sockopt.interface, 'Ethernet 2');
  assert.equal(proxy.xhttpSettings.extra.downloadSettings.sockopt.interface, 'Ethernet 2', 'the downlink dials with its own sockopt');
  assert.equal(proxy.tlsSettings.echSockopt.interface, 'Ethernet 2', 'the ECH config is fetched by the core itself');
});

test('speedTest: a chain\'s first hop is bound, the hop behind it is not; a set interface is replaced; ports alias', async () => {
  const core = fakeCore();
  const chain = [VLESS_WS_TLS, TROJAN_TCP_TLS];
  const r = await L.speedTest({
    link: { id: 'wan', iface: 'eth0.2' },
    server: chain,
    buildTestConfig: (s, port) => {
      const cfg = buildTestConfig(s, port);
      cfg.outbounds[0].streamSettings.sockopt = { interface: 'Wi-Fi', tcpFastOpen: true };   // the record's own binding
      return cfg;
    },
    startTest: core.startTest,
    ports: [40001],
    fetch: async () => ({ rttMs: 80, downMbps: 50, upMbps: 9 })   // the contract's name for the measurement
  });
  assert.equal(r.ok, true);
  assert.equal(r.id, 'wan', 'the link\'s id, not its device');
  const byTag = Object.fromEntries(core.configs[0].outbounds.map((o) => [o.tag, o]));
  assert.equal(core.configs[0].inbounds[0].port, 40001);
  assert.deepEqual(byTag['proxy-h0'].streamSettings.sockopt, { interface: 'eth0.2', tcpFastOpen: true }, 'the test is of THIS link');
  assert.deepEqual(byTag.proxy.streamSettings.sockopt, { dialerProxy: 'proxy-h0' });
  // the binder alone: nothing that never dials is touched, nothing without an interface changes
  const cfg = { outbounds: [{ tag: 'dns-out', protocol: 'dns' }, { tag: 'block', protocol: 'blackhole' }, { tag: 'T', protocol: 'loopback', settings: {} }] };
  assert.deepEqual(L.bindToInterface(JSON.parse(JSON.stringify(cfg)), 'en0'), cfg);
  const plain = { outbounds: [{ tag: 'proxy', protocol: 'vless' }] };
  assert.deepEqual(L.bindToInterface(JSON.parse(JSON.stringify(plain)), '  '), plain);
});

test('speedTest: the hard timeout kills the core and keeps what was measured; a late core is cleaned too', async () => {
  const core = fakeCore();
  let destroyed = 0;
  const t0 = Date.now();
  const r = await L.speedTest({
    link: { id: 'Wi-Fi', iface: 'Wi-Fi' }, server: VLESS_WS_TLS, buildTestConfig, startTest: core.startTest, port: 30001, timeoutMs: 300,
    measure: async ({ acc, track }) => {
      acc.rttMs = 41.26;
      track({ destroy: () => { destroyed++; } });
      await new Promise(() => {});   // the download never ends
    }
  });
  assert.ok(Date.now() - t0 < 2000, 'the budget holds');
  assert.deepEqual(r, { id: 'Wi-Fi', ok: false, rttMs: 41.3, downMbps: null, upMbps: null, error: 'timeout' });
  assert.equal(core.cleaned, 1);
  assert.equal(destroyed, 1, 'its sockets are destroyed');

  // a core that only comes up after the deadline is never used, and still killed
  let lateCleaned = 0;
  let measured = false;
  const late = await L.speedTest({
    link: { iface: 'en0' }, server: VLESS_WS_TLS, buildTestConfig, port: 30002, timeoutMs: 100,
    startTest: () => new Promise((resolve) => setTimeout(() => resolve({ proc: {}, cleanup: () => { lateCleaned++; } }), 250)),
    measure: async () => { measured = true; }
  });
  assert.equal(late.error, 'timeout');
  assert.equal(late.id, 'en0', 'no id: the device');
  await new Promise((r2) => setTimeout(r2, 300));
  assert.equal(lateCleaned, 1);
  assert.equal(measured, false);
});

test('speedTest: partial results, a core that does not start, and what is missing — never a throw', async () => {
  const core = fakeCore();
  const partial = await L.speedTest({
    link: { id: 'usb0', iface: 'usb0' }, server: VLESS_WS_TLS, buildTestConfig, startTest: core.startTest, port: 30003,
    measure: async ({ acc }) => { acc.rttMs = 300; acc.downMbps = 1.04; acc.error = 'upload: timeout'; }
  });
  assert.deepEqual(partial, { id: 'usb0', ok: false, rttMs: 300, downMbps: 1, upMbps: null, error: 'upload: timeout' });
  assert.equal(core.cleaned, 1);

  const refused = await L.speedTest({
    link: { iface: 'usb0' }, server: VLESS_WS_TLS, buildTestConfig, port: 30004,
    startTest: async () => { throw new Error('xray binary not found'); }, measure: async () => assert.fail('no core, no measurement')
  });
  assert.equal(refused.ok, false);
  assert.equal(refused.error, 'the core did not start: xray binary not found');

  const noBin = await L.speedTest({ link: { iface: 'usb0' }, server: VLESS_WS_TLS, buildTestConfig, port: 30005, xrayBin: '', measure: async () => assert.fail('no core') });
  assert.equal(noBin.error, 'the core did not start: xray binary missing');

  let started = 0;
  const startTest = async () => { started++; return { proc: {}, cleanup() {} }; };
  assert.equal((await L.speedTest({ link: { id: 'x' }, server: VLESS_WS_TLS, buildTestConfig, startTest })).error, 'no interface');
  assert.equal((await L.speedTest({ link: { iface: 'en0' }, buildTestConfig, startTest })).error, 'no server');
  assert.equal((await L.speedTest({ link: { iface: 'en0' }, server: VLESS_WS_TLS, startTest })).error, 'no test config');
  assert.equal((await L.speedTest()).error, 'no interface');
  assert.equal(started, 0);
});

test('testAll: one link at a time, in order, each result handed over as it comes', async () => {
  const core = fakeCore();
  let active = 0;
  let most = 0;
  const order = [];
  const handed = [];
  const links = [{ id: 'Wi-Fi', iface: 'Wi-Fi' }, { id: 'Ethernet 2', iface: 'Ethernet 2' }, { id: 'gone', iface: '' }];
  const results = await L.testAll({
    links, server: VLESS_WS_TLS, buildTestConfig, startTest: core.startTest, port: 30010,
    onResult: (r) => handed.push(r.id),
    measure: async () => {
      active++; most = Math.max(most, active);
      await new Promise((r) => setTimeout(r, 20));
      active--;
      order.push(core.configs.at(-1).outbounds[0].streamSettings.sockopt.interface);
      return { rttMs: 10, downMbps: 20, upMbps: 5 };
    }
  });
  assert.equal(most, 1, 'never two at once: they would share the bandwidth');
  assert.deepEqual(order, ['Wi-Fi', 'Ethernet 2']);
  assert.deepEqual(results.map((r) => [r.id, r.ok, r.error]), [['Wi-Fi', true, null], ['Ethernet 2', true, null], ['gone', false, 'no interface']]);
  assert.deepEqual(handed, ['Wi-Fi', 'Ethernet 2', 'gone']);
  assert.equal(core.cleaned, 2);
  assert.deepEqual(await L.testAll({}), []);
});

// ------------------------------------------------- the HTTP client itself ---

/**
 * Cloudflare's speed endpoints behind a fake socket: requests are parsed off
 * what the client writes, answers are handed back in pieces (split heads,
 * chunk sizes cut in half) a few milliseconds apart.
 */
function fakeCloudflare(opts = {}) {
  const srv = { requests: [], conns: 0 };
  const pieces = (buf, size) => { const out = []; for (let i = 0; i < buf.length; i += size) out.push(buf.subarray(i, i + size)); return out; };
  srv.answer = (req) => {
    const close = opts.close ? 'Connection: close\r\n' : '';
    if (req.method === 'GET' && req.path === '/__down?bytes=0' && opts.noLength) return [Buffer.from('HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n')];   // and never closes
    if (req.method === 'GET' && req.path === '/__down?bytes=0') return [Buffer.from('HTTP/1.1 200 OK\r\nCont'), Buffer.from(`ent-Length: 0\r\n${close}\r\n`)];
    if (req.method === 'GET' && req.path.startsWith('/__down?bytes=')) {
      const n = Number(req.path.split('=')[1]);
      if (opts.trickle) return { head: Buffer.from(`HTTP/1.1 200 OK\r\nContent-Length: ${n}\r\n${close}\r\n`), trickle: true };
      const parts = [Buffer.from(`HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n${close}\r\n`)];
      for (let left = n; left > 0;) {
        const c = Math.min(65536, left);
        parts.push(Buffer.from(c.toString(16) + '\r\n'), Buffer.alloc(c, 0x61), Buffer.from('\r\n'));
        left -= c;
      }
      parts.push(Buffer.from('0\r\n\r\n'));
      return pieces(Buffer.concat(parts), 70001);
    }
    if (req.method === 'POST' && req.path === '/__up') return [Buffer.from(`HTTP/1.1 200 OK\r\nContent-Length: 2\r\n${close}\r\nok`)];
    return [Buffer.from('HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n')];
  };
  class Sock extends EventEmitter {
    constructor() { super(); this.n = ++srv.conns; this.inbuf = Buffer.alloc(0); this.cur = null; this.destroyed = false; }
    write(data) {
      if (this.destroyed) return false;
      this.inbuf = Buffer.concat([this.inbuf, Buffer.from(data)]);
      this.parse();
      return true;
    }
    parse() {
      for (;;) {
        if (this.cur) {
          const take = Math.min(this.cur.left, this.inbuf.length);
          this.cur.left -= take;
          this.inbuf = this.inbuf.subarray(take);
          if (this.cur.left > 0) return;
          const req = this.cur;
          this.cur = null;
          this.respond(req);
          continue;
        }
        const at = this.inbuf.indexOf('\r\n\r\n');
        if (at === -1) return;
        const [line, ...hs] = this.inbuf.subarray(0, at).toString('latin1').split('\r\n');
        this.inbuf = this.inbuf.subarray(at + 4);
        const h = {};
        for (const l of hs) { const c = l.indexOf(':'); h[l.slice(0, c).toLowerCase()] = l.slice(c + 1).trim(); }
        const [method, path] = line.split(' ');
        const req = { method, path, headers: h, left: Number(h['content-length'] || 0) };
        srv.requests.push({ conn: this.n, method, path, length: req.left, host: h.host });
        if (req.left > 0) { this.cur = req; continue; }
        this.respond(req);
      }
    }
    respond(req) {
      const a = srv.answer(req);
      const emit = (list, i) => {
        if (this.destroyed) return;
        if (i >= list.length) { if (opts.close) this.destroy(); return; }
        this.emit('data', list[i]);
        setTimeout(() => emit(list, i + 1), 2);
      };
      if (a.trickle) {
        const drip = () => { if (this.destroyed) return; this.emit('data', Buffer.alloc(10000, 0x62)); setTimeout(drip, 20); };
        setTimeout(() => { if (!this.destroyed) { this.emit('data', a.head); drip(); } }, 2);
        return;
      }
      setTimeout(() => emit(a, 0), 3);
    }
    destroy() {
      if (this.destroyed) return;
      this.destroyed = true;
      setImmediate(() => this.emit('close'));
    }
  }
  srv.connect = async ({ host }) => { assert.equal(host, L.SPEED_HOST); return new Sock(); };
  return srv;
}

test('measureThroughSocks: latency on a warm connection, 4 MB down, 2 MB up in four parts — one keep-alive connection', async () => {
  const cf = fakeCloudflare();
  const acc = {};
  const opened = [];
  await L.measureThroughSocks({ port: 1080, deadline: Date.now() + 20000, acc, connect: cf.connect, track: (s) => opened.push(s) });
  assert.equal(acc.error, undefined, String(acc.error));
  assert.ok(acc.rttMs >= 0 && acc.downMbps > 0 && acc.upMbps > 0, JSON.stringify(acc));
  assert.equal(cf.conns, 1, 'one connection, kept alive');
  assert.equal(opened.length, 1, 'every socket handed to track (the hard timeout destroys them)');
  assert.ok(opened[0].destroyed, 'closed at the end');
  assert.deepEqual(cf.requests.map((r) => [r.method, r.path, r.length]), [
    ['GET', '/__down?bytes=0', 0], ['GET', '/__down?bytes=0', 0],
    ['GET', '/__down?bytes=4000000', 0],
    ['POST', '/__up', 500000], ['POST', '/__up', 500000], ['POST', '/__up', 500000], ['POST', '/__up', 500000]
  ]);
  assert.ok(cf.requests.every((r) => r.host === 'speed.cloudflare.com'));
});

test('measureThroughSocks: a server that closes after each answer is reconnected to; a refused port is a core still starting', async () => {
  const cf = fakeCloudflare({ close: true });
  const acc = {};
  let refusals = 2;
  const connect = async (o) => {
    if (refusals-- > 0) throw Object.assign(new Error('connect ECONNREFUSED 127.0.0.1:1080'), { code: 'ECONNREFUSED' });
    return cf.connect(o);
  };
  await L.measureThroughSocks({ port: 1080, deadline: Date.now() + 20000, acc, connect });
  assert.equal(acc.error, undefined, String(acc.error));
  assert.ok(acc.downMbps > 0 && acc.upMbps > 0);
  assert.equal(cf.conns, 7, 'a connection per request when the server says close');

  // the core has exited: a refused port is the answer, not a reason to wait
  const dead = {};
  await L.measureThroughSocks({
    port: 1080, deadline: Date.now() + 20000, acc: dead, isAlive: () => false,
    connect: async () => { throw Object.assign(new Error('connect ECONNREFUSED 127.0.0.1:1080'), { code: 'ECONNREFUSED' }); }
  });
  assert.deepEqual(dead, { error: 'latency: connect ECONNREFUSED 127.0.0.1:1080' }, 'no latency: nothing else is tried');

  // a latency answer with no length that the server never closes: the head is the answer, the connection is dropped
  const open = fakeCloudflare({ noLength: true });
  const acc2 = {};
  const t0 = Date.now();
  await L.measureThroughSocks({ port: 1080, deadline: Date.now() + 20000, acc: acc2, connect: open.connect });
  assert.ok(Date.now() - t0 < 8000, 'not held until the deadline');
  assert.equal(acc2.error, undefined, String(acc2.error));
  assert.ok(acc2.rttMs >= 0 && acc2.downMbps > 0 && acc2.upMbps > 0);
  assert.equal(open.conns, 3, 'one per latency answer, then one kept alive for the rest');
});

test('measureThroughSocks: a download that runs out of its box is measured by what arrived; an upload with no time left says so', async () => {
  const cf = fakeCloudflare({ trickle: true });
  const acc = {};
  const t0 = Date.now();
  await L.measureThroughSocks({ port: 1080, deadline: t0 + 1200, acc, connect: cf.connect });
  assert.ok(Date.now() - t0 < 3000);
  assert.ok(acc.rttMs >= 0);
  // ~10 kB every 20 ms ≈ 4 Mbps; only roughly, timers being timers
  assert.ok(acc.downMbps > 0.5 && acc.downMbps < 40, String(acc.downMbps));
  assert.equal(acc.upMbps, undefined);
  assert.equal(acc.error, 'upload: timeout');
});

test('chunkedCounter: payload bytes only, chunk-size lines cut anywhere, extensions and trailers', () => {
  const body = Buffer.from('5;ext=1\r\nhello\r\n10\r\n0123456789abcdef\r\n0\r\nX-Trailer: 1\r\n\r\n');
  for (const size of [1, 2, 3, 7, body.length]) {
    const c = L.chunkedCounter();
    let bytes = 0;
    let done = false;
    for (let i = 0; i < body.length; i += size) { const r = c.push(body.subarray(i, i + size)); bytes += r.bytes; done = done || r.done; }
    assert.equal(bytes, 21, 'piece size ' + size);
    assert.equal(done, true);
  }
  assert.throws(() => L.chunkedCounter().push(Buffer.from('zz\r\n')), /bad chunked body/);
});
