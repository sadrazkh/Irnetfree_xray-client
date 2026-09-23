'use strict';
/**
 * The OpenWrt gateway's pure half: what the router's files and commands are
 * parsed into, and the exact kernel tables the backend writes. Nothing here
 * touches the machine — the same lines run on Windows, where the owner works.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const net = require('../src/main/openwrtNet');

test('isOpenwrt: the release file, or the env override the tests and QEMU use', () => {
  assert.equal(net.isOpenwrt({}, () => false), false);
  assert.equal(net.isOpenwrt({}, (p) => p === '/etc/openwrt_release'), true);
  assert.equal(net.isOpenwrt({ IRNETFREE_PLATFORM: 'openwrt' }, () => false), true);
  assert.equal(net.isOpenwrt({ IRNETFREE_PLATFORM: 'linux' }, () => false), false);
  // a throwing existsSync is "no"
  assert.equal(net.isOpenwrt({}, () => { throw new Error('EACCES'); }), false);
});

test('MACs: lower-cased, validated, de-duplicated, order kept — never interpolated raw into nft', () => {
  assert.equal(net.normalizeMac('AA:BB:CC:DD:EE:FF'), 'aa:bb:cc:dd:ee:ff');
  assert.equal(net.normalizeMac(' aa:bb:cc:dd:ee:ff '), 'aa:bb:cc:dd:ee:ff');
  assert.equal(net.normalizeMac('aa-bb-cc-dd-ee-ff'), null);
  assert.equal(net.normalizeMac('aa:bb:cc:dd:ee'), null);
  assert.equal(net.normalizeMac('aa:bb:cc:dd:ee:ff }; flush ruleset; #'), null);
  assert.equal(net.normalizeMac(null), null);
  assert.deepEqual(net.validMacs(['AA:BB:CC:DD:EE:FF', 'bad', 'aa:bb:cc:dd:ee:ff', '02:00:00:00:00:01']),
    ['aa:bb:cc:dd:ee:ff', '02:00:00:00:00:01']);
  assert.deepEqual(net.validMacs(undefined), []);
  assert.deepEqual(net.validMacs('aa:bb:cc:dd:ee:ff'), [], 'a string is not a list');
});

test('dhcp.leases: busybox dnsmasq lines, * for a nameless client, junk skipped', () => {
  const text = [
    '1758650000 aa:bb:cc:dd:ee:01 192.168.1.23 sadra-phone 01:aa:bb:cc:dd:ee:01',
    '1758650100 AA:BB:CC:DD:EE:02 192.168.1.40 * *',
    'duid 00:01:00:01:2b:...',
    '',
    'not a lease line'
  ].join('\n');
  assert.deepEqual(net.parseDhcpLeases(text), [
    { expires: 1758650000, mac: 'aa:bb:cc:dd:ee:01', ip: '192.168.1.23', name: 'sadra-phone' },
    { expires: 1758650100, mac: 'aa:bb:cc:dd:ee:02', ip: '192.168.1.40', name: '' }
  ]);
  assert.deepEqual(net.parseDhcpLeases(''), []);
  assert.deepEqual(net.parseDhcpLeases(undefined), []);
});

test('ip neigh: REACHABLE/STALE/DELAY/PROBE/PERMANENT are online, FAILED/INCOMPLETE are not', () => {
  const text = [
    '192.168.1.23 lladdr aa:bb:cc:dd:ee:01 REACHABLE',
    '192.168.1.40 lladdr aa:bb:cc:dd:ee:02 STALE',
    '192.168.1.41 lladdr aa:bb:cc:dd:ee:03 FAILED',
    '192.168.1.42  INCOMPLETE',
    'fe80::1 lladdr aa:bb:cc:dd:ee:01 router REACHABLE'
  ].join('\n');
  assert.deepEqual(net.parseNeigh(text), [
    { ip: '192.168.1.23', mac: 'aa:bb:cc:dd:ee:01', online: true },
    { ip: '192.168.1.40', mac: 'aa:bb:cc:dd:ee:02', online: true },
    { ip: '192.168.1.41', mac: 'aa:bb:cc:dd:ee:03', online: false },
    { ip: 'fe80::1', mac: 'aa:bb:cc:dd:ee:01', online: true }
  ]);
});

test('mergeDevices: one row per MAC, the lease names it, the neighbour table says it is here', () => {
  const leases = net.parseDhcpLeases([
    '1 aa:bb:cc:dd:ee:01 192.168.1.23 sadra-phone *',
    '1 aa:bb:cc:dd:ee:02 192.168.1.40 * *',
    '1 aa:bb:cc:dd:ee:04 192.168.1.50 old-laptop *'
  ].join('\n'));
  const neigh = net.parseNeigh([
    '192.168.1.23 lladdr aa:bb:cc:dd:ee:01 REACHABLE',
    'fe80::1 lladdr aa:bb:cc:dd:ee:01 REACHABLE',
    '192.168.1.40 lladdr aa:bb:cc:dd:ee:02 FAILED',
    '192.168.1.99 lladdr aa:bb:cc:dd:ee:03 STALE'
  ].join('\n'));
  assert.deepEqual(net.mergeDevices(leases, neigh), [
    // online first; within a group the named ones (by name), then the bare MACs
    { mac: 'aa:bb:cc:dd:ee:01', ip: '192.168.1.23', name: 'sadra-phone', online: true },
    { mac: 'aa:bb:cc:dd:ee:03', ip: '192.168.1.99', name: '', online: true },
    { mac: 'aa:bb:cc:dd:ee:04', ip: '192.168.1.50', name: 'old-laptop', online: false },
    { mac: 'aa:bb:cc:dd:ee:02', ip: '192.168.1.40', name: '', online: false }
  ]);
  assert.deepEqual(net.mergeDevices([], []), []);
});

test('the nft ruleset: atomic replace, one set, one mangle rule; byte-exact', () => {
  const two = net.buildNftRuleset({ lanIf: 'br-lan', macs: ['AA:BB:CC:DD:EE:01', 'aa:bb:cc:dd:ee:02', 'garbage'] });
  assert.equal(two, [
    'table inet irnetfree',
    'delete table inet irnetfree',
    'table inet irnetfree {',
    '  set bypass_macs { type ether_addr; elements = { aa:bb:cc:dd:ee:01, aa:bb:cc:dd:ee:02 }; }',
    '  chain pre {',
    '    type filter hook prerouting priority mangle; policy accept;',
    '    iifname "br-lan" ether saddr @bypass_macs meta mark set 0x1f1e counter',
    '  }',
    '}',
    ''
  ].join('\n'));
  // no exclusions: the set still exists, so a later add has something to add to
  const none = net.buildNftRuleset({ lanIf: 'br-lan', macs: [] });
  assert.match(none, /set bypass_macs \{ type ether_addr; \}/);
  assert.doesNotMatch(none, /elements/);
  // defaults: br-lan and the shared mark
  assert.equal(net.buildNftRuleset(), none);
  // an interface name is a token, never a quote-breaker
  assert.match(net.buildNftRuleset({ lanIf: 'br-lan" } ; flush ruleset; "' }), /iifname "br-lanflushruleset"/);
  assert.match(net.buildNftRuleset({ lanIf: '' }), /iifname "br-lan"/);
  assert.match(net.buildNftRuleset({ mark: 0x2a }), /mark set 0x2a counter/);
});

test('the bypass rule sits before every sing-box rule and points marked packets at main', () => {
  assert.deepEqual(net.bypassRuleArgs('add'), [
    ['-4', 'rule', 'add', 'pref', '8999', 'fwmark', '0x1f1e', 'lookup', 'main'],
    ['-6', 'rule', 'add', 'pref', '8999', 'fwmark', '0x1f1e', 'lookup', 'main']
  ]);
  assert.deepEqual(net.bypassRuleArgs('del')[0], ['-4', 'rule', 'del', 'pref', '8999', 'fwmark', '0x1f1e', 'lookup', 'main']);
  assert.ok(net.BYPASS_RULE_PREF < 9000, 'sing-box starts its rules at iproute2_rule_index 9000');
  assert.throws(() => net.bypassRuleArgs('flush'), /add or del/);
});

test('lanInterface: ubus names the LAN device; anything else means br-lan', async () => {
  const ubus = async (cmd, args) => {
    assert.equal(cmd, 'ubus');
    assert.deepEqual(args, ['call', 'network.interface.lan', 'status']);
    return JSON.stringify({ up: true, l3_device: 'br-lan0', device: 'br-lan0' });
  };
  assert.equal(await net.lanInterface(ubus), 'br-lan0');
  assert.equal(await net.lanInterface(async () => 'not json'), 'br-lan');
  assert.equal(await net.lanInterface(async () => JSON.stringify({ up: false })), 'br-lan');
  assert.equal(await net.lanInterface(async () => { throw new Error('ubus: not found'); }), 'br-lan');
});

test('lanDevices: leases + neighbours, each source optional, and the exact commands used', async () => {
  const calls = [];
  const devices = await net.lanDevices({
    lanIf: 'br-lan',
    readFile: async (p) => { calls.push(['read', p]); return '1 aa:bb:cc:dd:ee:01 192.168.1.23 phone *\n'; },
    run: async (cmd, args) => { calls.push([cmd, ...args]); return '192.168.1.23 lladdr aa:bb:cc:dd:ee:01 REACHABLE\n192.168.1.9 lladdr aa:bb:cc:dd:ee:09 STALE\n'; }
  });
  assert.deepEqual(calls, [['read', '/tmp/dhcp.leases'], ['ip', 'neigh', 'show', 'dev', 'br-lan']]);
  assert.deepEqual(devices, [
    { mac: 'aa:bb:cc:dd:ee:01', ip: '192.168.1.23', name: 'phone', online: true },
    { mac: 'aa:bb:cc:dd:ee:09', ip: '192.168.1.9', name: '', online: true }
  ]);
  // no lease file yet (fresh router), neighbour command missing: an empty list, not an error
  assert.deepEqual(await net.lanDevices({
    readFile: async () => { throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' }); },
    run: async () => { throw new Error('ip: not found'); }
  }), []);
});
