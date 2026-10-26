'use strict';
/**
 * The users module's router half, the devices: who is behind the router, by
 * MAC, with every address each one uses — what the per-user rule-sets in
 * sing-box are written from. Parsed from the router's own files and commands
 * (fixtures of dnsmasq's lease file and `ip neigh`), never this machine's.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const dev = require('../src/modules/lanUsers/router/devices');

const NOW = 1761480000000;   // 2025-10-26, in ms
const LEASES = [
  `${NOW / 1000 + 3600} aa:bb:cc:dd:ee:01 192.168.1.23 sadra-phone 01:aa:bb:cc:dd:ee:01`,
  `${NOW / 1000 + 3600} AA:BB:CC:DD:EE:02 192.168.1.40 * *`,
  `${NOW / 1000 - 60} aa:bb:cc:dd:ee:04 192.168.1.50 old-laptop *`,     // its lease ran out: the name stays, the address does not
  '0 aa:bb:cc:dd:ee:05 192.168.1.60 printer *',                          // 0: a lease that never ends
  'duid 00:01:00:01:2b:...',
  ''
].join('\n');
const NEIGH = [
  '192.168.1.23 lladdr aa:bb:cc:dd:ee:01 REACHABLE',
  '2001:db8:1::23 lladdr aa:bb:cc:dd:ee:01 STALE',
  'fe80::a8bb:ccff:fedd:ee01 lladdr aa:bb:cc:dd:ee:01 router REACHABLE',   // link-local: never forwarded, never in a rule-set
  '192.168.1.40 lladdr aa:bb:cc:dd:ee:02 FAILED',                           // not here now: no address from the table
  '192.168.1.99 lladdr aa:bb:cc:dd:ee:03 DELAY',                            // a static address, no lease
  '192.168.1.77  INCOMPLETE'
].join('\n');

test('mergeAll: one row per MAC, every live address (v4 first, then v6; no link-local), the lease names it', () => {
  const { parseDhcpLeases, parseNeigh } = require('../src/main/openwrtNet');
  const rows = dev.mergeAll(parseDhcpLeases(LEASES), parseNeigh(NEIGH), { now: NOW });
  assert.deepEqual(rows, [
    { mac: 'aa:bb:cc:dd:ee:01', ip: '192.168.1.23', ips: ['192.168.1.23', '2001:db8:1::23'], leased: ['192.168.1.23'], hostname: 'sadra-phone', online: true },
    { mac: 'aa:bb:cc:dd:ee:03', ip: '192.168.1.99', ips: ['192.168.1.99'], leased: [], hostname: '', online: true },
    { mac: 'aa:bb:cc:dd:ee:04', ip: '', ips: [], leased: [], hostname: 'old-laptop', online: false },
    { mac: 'aa:bb:cc:dd:ee:05', ip: '192.168.1.60', ips: ['192.168.1.60'], leased: ['192.168.1.60'], hostname: 'printer', online: false },
    { mac: 'aa:bb:cc:dd:ee:02', ip: '192.168.1.40', ips: ['192.168.1.40'], leased: ['192.168.1.40'], hostname: '', online: false }
  ]);
});

test('mergeAll: a device on another\'s leased address — both rows list it (what each one uses), only the lease\'s says it is leased', () => {
  const { parseDhcpLeases, parseNeigh } = require('../src/main/openwrtNet');
  // .23 is leased to ee:01 (away now); ee:0c took it, and the neighbour table has ee:0c at it
  const rows = dev.mergeAll(parseDhcpLeases(`${NOW / 1000 + 3600} aa:bb:cc:dd:ee:01 192.168.1.23 sadra-phone *\n`),
    parseNeigh('192.168.1.23 lladdr aa:bb:cc:dd:ee:0c REACHABLE\n'), { now: NOW });
  const by = Object.fromEntries(rows.map(r => [r.mac, r]));
  assert.deepEqual([by['aa:bb:cc:dd:ee:01'].ips, by['aa:bb:cc:dd:ee:01'].leased], [['192.168.1.23'], ['192.168.1.23']]);
  assert.deepEqual([by['aa:bb:cc:dd:ee:0c'].ips, by['aa:bb:cc:dd:ee:0c'].leased], [['192.168.1.23'], []]);
});

test('scanDevices: the lease file and `ip neigh show dev <lan>` (both families), each optional; never throws', async () => {
  const calls = [];
  const rows = await dev.scanDevices({
    lanIf: 'br-lan', now: NOW,
    readFile: async (p) => { calls.push(['read', p]); return LEASES; },
    run: async (cmd, args) => { calls.push([cmd, ...args]); return NEIGH; }
  });
  assert.deepEqual(calls, [['read', '/tmp/dhcp.leases'], ['ip', 'neigh', 'show', 'dev', 'br-lan']]);
  assert.equal(rows.length, 5);
  // a fresh router: no lease file, no `ip`
  assert.deepEqual(await dev.scanDevices({
    readFile: async () => { throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' }); },
    run: async () => { throw new Error('ip: not found'); }
  }), []);
  // the LAN device name is a token handed to ip as one argument
  const seen = [];
  await dev.scanDevices({ lanIf: 'br-lan0', readFile: async () => '', run: async (cmd, args) => { seen.push(args); return ''; } });
  assert.deepEqual(seen, [['neigh', 'show', 'dev', 'br-lan0']]);
});

test('macOfIp: the client address the portal sees (a dual-stack socket\'s ::ffff: form too) → its MAC', () => {
  const { parseDhcpLeases, parseNeigh } = require('../src/main/openwrtNet');
  const rows = dev.mergeAll(parseDhcpLeases(LEASES), parseNeigh(NEIGH), { now: NOW });
  assert.equal(dev.macOfIp(rows, '192.168.1.23'), 'aa:bb:cc:dd:ee:01');
  assert.equal(dev.macOfIp(rows, '::ffff:192.168.1.99'), 'aa:bb:cc:dd:ee:03');
  assert.equal(dev.macOfIp(rows, '2001:DB8:1::23'), 'aa:bb:cc:dd:ee:01');
  assert.equal(dev.macOfIp(rows, '192.168.1.200'), null);
  assert.equal(dev.macOfIp(rows, undefined), null);
  assert.equal(dev.macOfIp(null, '192.168.1.23'), null);
});

test('macOfIp: a device that took a signed-in one’s address is the one asking — the neighbour table’s MAC, not the lease holder’s', () => {
  const now = 1790000000000;
  const lease = [{ expires: now / 1000 + 3600, mac: 'aa:bb:cc:dd:ee:01', ip: '192.168.1.23', name: 'alice-phone' }];
  // the holder answers for its own address: it is the one asking
  const own = dev.mergeAll(lease, [{ ip: '192.168.1.23', mac: 'aa:bb:cc:dd:ee:01', online: true }], { now });
  assert.equal(dev.macOfIp(own, '192.168.1.23'), 'aa:bb:cc:dd:ee:01');
  // another device answers for it now: that one is asking (its status, its sign-in — not alice's)
  const taken = dev.mergeAll(lease, [{ ip: '192.168.1.23', mac: '02:1a:00:00:00:c3', online: true }], { now });
  assert.equal(dev.macOfIp(taken, '192.168.1.23'), '02:1a:00:00:00:c3');
  // nobody in the neighbour table at it: the lease's holder, as before
  assert.equal(dev.macOfIp(dev.mergeAll(lease, [], { now }), '192.168.1.23'), 'aa:bb:cc:dd:ee:01');
});

test('routableIp / plainIp: what can be a packet\'s source through the router', () => {
  assert.equal(dev.plainIp('::FFFF:10.0.0.5'), '10.0.0.5');
  assert.equal(dev.routableIp('192.168.1.5'), '192.168.1.5');
  assert.equal(dev.routableIp('2001:db8::5'), '2001:db8::5');
  for (const bad of ['fe80::1', 'febf::1', '0.0.0.0', '::', 'host.lan', '', null, '1.2.3']) assert.equal(dev.routableIp(bad), null, String(bad));
});
