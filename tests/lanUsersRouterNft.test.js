'use strict';
/**
 * The users module's transparent mode in the gateway's nft table, byte for
 * byte: off, the table is exactly the one before the module (the QEMU smoke
 * and tests/tunOpenwrt.test.js pin it); on, the blocked set, the gate for
 * unassigned devices, the sign-in page's redirect with the sessions'
 * timeouts, and a byte counter per device — and the gateway replacing them
 * live without touching sing-box. Only the kernel can say it accepts the
 * text: the QEMU / CI jobs.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const net = require('../src/main/openwrtNet');
const nft = require('../src/modules/lanUsers/router/nft');
const { TunOpenwrt } = require('../src/main/tunOpenwrt');
const { nftJson } = require('./lanUsersRouterFakes');

const A = 'aa:bb:cc:dd:ee:01', B = 'aa:bb:cc:dd:ee:02', C = 'aa:bb:cc:dd:ee:03';
const BEFORE = [
  'table inet irnetfree',
  'delete table inet irnetfree',
  'table inet irnetfree {',
  '  set bypass_macs { type ether_addr; elements = { 02:00:00:00:00:01 }; }',
  '  chain pre {',
  '    type filter hook prerouting priority mangle; policy accept;',
  '    iifname "br-lan" ether saddr @bypass_macs meta mark set 0x1f1e counter',
  '  }',
  '}',
  ''
].join('\n');

test('off: no `lanUsers`, null or undefined — the table of before, byte for byte', () => {
  const base = { lanIf: 'br-lan', macs: ['02:00:00:00:00:01'] };
  assert.equal(net.buildNftRuleset(base), BEFORE);
  assert.equal(net.buildNftRuleset(Object.assign({ lanUsers: null }, base)), BEFORE);
  assert.equal(net.buildNftRuleset(Object.assign({ lanUsers: undefined }, base)), BEFORE);
  assert.equal(net.buildNftRuleset(Object.assign({ lanUsers: 'on' }, base)), BEFORE, 'not an object: nothing of the module');
  // with the QUIC refusal too
  assert.equal(net.buildNftRuleset(Object.assign({ blockQuic: true, lanUsers: null }, base)), net.buildNftRuleset(Object.assign({ blockQuic: true }, base)));
});

test('allow mode: the blocked set drops, no gate, no redirect — and every device is counted', () => {
  const text = net.buildNftRuleset({ lanIf: 'br-lan', macs: [], lanUsers: {
    unassigned: 'allow', blocked: [A], allowed: [B], authorized: [], direct: [],
    counters: [{ mac: A, ips: ['192.168.1.23'] }, { mac: B, ips: ['192.168.1.40', '2001:db8::40'] }]
  } });
  assert.equal(text, [
    'table inet irnetfree',
    'delete table inet irnetfree',
    'table inet irnetfree {',
    '  set bypass_macs { type ether_addr; }',
    `  set lu_blocked { type ether_addr; elements = { ${A} }; }`,
    `  set lu_allowed { type ether_addr; elements = { ${B} }; }`,
    '  set lu_authorized { type ether_addr; flags timeout; }',
    '  counter cu_aabbccddee01 { packets 0 bytes 0 }',
    '  counter cd_aabbccddee01 { packets 0 bytes 0 }',
    '  counter cu_aabbccddee02 { packets 0 bytes 0 }',
    '  counter cd_aabbccddee02 { packets 0 bytes 0 }',
    `  map lu_up { type ether_addr : counter; elements = { ${A} : "cu_aabbccddee01", ${B} : "cu_aabbccddee02" }; }`,
    '  map lu_dn4 { type ipv4_addr : counter; elements = { 192.168.1.23 : "cd_aabbccddee01", 192.168.1.40 : "cd_aabbccddee02" }; }',
    '  map lu_dn6 { type ipv6_addr : counter; elements = { 2001:db8::40 : "cd_aabbccddee02" }; }',
    '  chain pre {',
    '    type filter hook prerouting priority mangle; policy accept;',
    '    iifname "br-lan" ether saddr @bypass_macs meta mark set 0x1f1e counter',
    '  }',
    '  chain lu_fwd {',
    '    type filter hook forward priority filter - 5; policy accept;',
    '    iifname "br-lan" ether saddr @lu_blocked counter drop',
    '    iifname "br-lan" counter name ether saddr map @lu_up',
    '    oifname "br-lan" counter name ip daddr map @lu_dn4',
    '    oifname "br-lan" counter name ip6 daddr map @lu_dn6',
    '  }',
    '}',
    ''
  ].join('\n'));
});

test('login mode: signed-in devices with their sessions\' remaining time, the gate (DNS passes, the rest refused), the redirect of tcp/80 to the page', () => {
  const text = net.buildNftRuleset({ lanIf: 'br-lan', macs: ['02:00:00:00:00:01'], blockQuic: true, lanUsers: {
    unassigned: 'login', blocked: [], allowed: [B], authorized: [{ mac: A, timeoutS: 86399.2 }, { mac: C, timeoutS: 0 }], direct: [],
    counters: [], portal: { ip: '192.168.1.1', port: 30822 }
  } });
  assert.ok(text.includes(`  set lu_authorized { type ether_addr; flags timeout; elements = { ${A} timeout 86400s }; }\n`), 'whole seconds, rounded up; a session already over is no element');
  assert.ok(text.includes([
    '  chain lu_gate {',
    '    meta l4proto { tcp, udp } th dport 53 accept',
    '    counter reject',
    '  }',
    '  chain lu_fwd {',
    '    type filter hook forward priority filter - 5; policy accept;',
    '    iifname "br-lan" ether saddr @lu_blocked counter drop',
    '    iifname "br-lan" ether saddr != @lu_allowed ether saddr != @lu_authorized ether saddr != @bypass_macs jump lu_gate',
    '    iifname "br-lan" counter name ether saddr map @lu_up',
    '    oifname "br-lan" counter name ip daddr map @lu_dn4',
    '    oifname "br-lan" counter name ip6 daddr map @lu_dn6',
    '  }',
    '  chain lu_portal {',
    '    type nat hook prerouting priority dstnat - 5; policy accept;',
    '    iifname "br-lan" ether saddr != @lu_allowed ether saddr != @lu_authorized ether saddr != @bypass_macs ether saddr != @lu_blocked ip daddr != 192.168.1.1 tcp dport 80 counter dnat ip to 192.168.1.1:30822',
    '  }',
    '}',
    ''
  ].join('\n')), text);
  // the gateway's own chains are where they were, the module's after them; the gate is declared before the jump to it
  assert.ok(text.indexOf('chain pre') < text.indexOf('chain quic') && text.indexOf('chain quic') < text.indexOf('chain lu_gate'));
  assert.ok(text.indexOf('chain lu_gate') < text.indexOf('chain lu_fwd'));
  assert.ok(text.indexOf('set lu_authorized') < text.indexOf('chain pre'), 'every set is declared before a rule names it');
  // no LAN address for the page: the gate holds, nothing is redirected
  const noPage = net.buildNftRuleset({ lanUsers: { unassigned: 'login', portal: null } });
  assert.match(noPage, /jump lu_gate/);
  assert.doesNotMatch(noPage, /dnat|lu_portal/);
});

test('block mode: unassigned devices get nothing at all — no DNS, no page', () => {
  const text = net.buildNftRuleset({ lanUsers: { unassigned: 'block', portal: { ip: '192.168.1.1', port: 30822 } } });
  assert.ok(text.includes('  chain lu_gate {\n    counter drop\n  }\n'), text);
  assert.match(text, /jump lu_gate/);
  assert.doesNotMatch(text, /dport 53|dnat|lu_portal/);
});

test('users whose config is "direct" join the bypass set (the same way around the tunnel); the gateway\'s own exclusions stay first', () => {
  const text = net.buildNftRuleset({ macs: ['02:00:00:00:00:01'], lanUsers: { unassigned: 'allow', direct: [A, '02:00:00:00:00:01'] } });
  assert.ok(text.includes(`  set bypass_macs { type ether_addr; elements = { 02:00:00:00:00:01, ${A} }; }\n`), text);
});

test('nothing unsafe reaches the kernel: junk MACs, a port or address that is not one, an address two devices claim, link-local v6', () => {
  const text = net.buildNftRuleset({ lanIf: 'br-lan', lanUsers: {
    unassigned: 'login',
    blocked: ['aa:bb:cc:dd:ee:ff }; flush ruleset; #', A, A.toUpperCase()],
    allowed: ['not a mac'],
    authorized: [{ mac: 'zz', timeoutS: 50 }, { mac: B, timeoutS: 'x' }, { mac: C, timeoutS: 1e12 }],
    counters: [{ mac: A, ips: ['192.168.1.23', 'fe80::1', '1.2.3', '192.168.1.23'] }, { mac: B, ips: ['192.168.1.23', '192.168.1.40'] }, { mac: 'bad', ips: ['10.0.0.1'] }],
    portal: { ip: '192.168.1.1; flush ruleset', port: 30822 }
  } });
  assert.ok(text.includes(`set lu_blocked { type ether_addr; elements = { ${A} }; }`));
  assert.ok(text.includes('set lu_allowed { type ether_addr; }'));
  assert.ok(text.includes(`elements = { ${C} timeout 31536000s }`), 'at most a year');
  assert.ok(text.includes('map lu_dn4 { type ipv4_addr : counter; elements = { 192.168.1.23 : "cd_aabbccddee01", 192.168.1.40 : "cd_aabbccddee02" }; }'), 'the address once, for the device that claimed it first');
  assert.ok(text.includes('map lu_dn6 { type ipv6_addr : counter; }'));
  assert.doesNotMatch(text, /flush|10\.0\.0\.1|fe80|dnat/);
  assert.equal(nft.cleanDesc({ portal: { ip: '192.168.1.1', port: 70000 } }).portal, null);
  assert.equal(nft.cleanDesc({ unassigned: 'allow', portal: { ip: '192.168.1.1', port: 30822 } }).portal, null, 'only login mode redirects');
});

test('parseCounters: the named counters of `nft -j list table` → bytes per device, up and down; the rules\' own counters and junk ignored', () => {
  const json = nftJson({ [A]: { up: 1200, down: 56000 }, [B]: { up: 0, down: 7 } });
  json.nftables.push({ counter: { family: 'inet', name: 'someone_else', table: 'irnetfree', bytes: 5 } });
  assert.deepEqual(nft.parseCounters(JSON.stringify(json)), { [A]: { up: 1200, down: 56000 }, [B]: { up: 0, down: 7 } });
  assert.deepEqual(nft.parseCounters(json), { [A]: { up: 1200, down: 56000 }, [B]: { up: 0, down: 7 } }, 'parsed JSON too');
  assert.deepEqual(nft.parseCounters('Error: No such file or directory'), {});
  assert.deepEqual(nft.parseCounters(''), {});
  assert.deepEqual(nft.parseCounters('{"nftables":[{"counter":{"name":"cu_aabbccddee01","bytes":-4}}]}'), { [A]: { up: 0, down: 0 } });
  assert.equal(nft.counterName(A, 'up'), 'cu_aabbccddee01');
  assert.deepEqual(nft.parseCounterName('cd_aabbccddee01'), { mac: A, dir: 'down' });
  assert.equal(nft.parseCounterName('cd_aabbccddee0'), null);
});

/* ------------------------------ the gateway: live, never the tunnel ------------------------------ */

function gateway() {
  const lines = [], writes = [];
  const inner = {
    calls: [], active: false, proc: null, exited: Promise.resolve(), excludeIps: [], interfaceName: 'IRNetFree', dnsPeer: '172.19.0.2', dnsPeer6: 'fdfe:dcba:9876::2',
    isAvailable: () => true, isElevated: () => true, physicalInterface: async () => ({ name: 'eth0' }),
    get linkUp() { return this.active; },
    async start(port, bypass, dns, opts) { this.calls.push(['start', opts]); this.exited = new Promise(() => {}); this.proc = { kill() {} }; this.active = true; },
    async stop() { this.calls.push(['stop']); this.active = false; this.proc = null; },
    cleanupSync() {}
  };
  const run = async (cmd, args) => {
    const line = [cmd, ...args].join(' ');
    lines.push(line);
    if (/^ip rule show/.test(line)) return '9002:\tnot from all iif lo lookup 2022\n';
    if (/^ip link show IRNetFree/.test(line)) { if (!inner.active) throw new Error('no device'); return ''; }
    if (/ rule del /.test(line)) throw new Error('none');
    return '';
  };
  const tun = new TunOpenwrt({ inner, run, runSync: () => {}, writeFile: (p, t) => writes.push(t), lanStatus: async () => ({ device: 'br-lan', address: '192.168.1.1', mask: 24 }),
    which: () => true, lang: 'en', tmpDir: '/tmp/irnf-test', verifyWaitMs: 200, linkWaitMs: 50, uid: 0, uidsOf: () => [0, 453] });
  return { tun, inner, lines, writes };
}

test('the gateway starts with the users\' sets in its first table, and hands their sing-box routes down untouched', async () => {
  const { tun, inner, writes } = gateway();
  const desc = { unassigned: 'login', blocked: [A], allowed: [], authorized: [], direct: [], counters: [], portal: { ip: '192.168.1.1', port: 30822 } };
  const singbox = { targets: [{ tag: 'lu-tp-1', port: 41001, path: '/tmp/irnetfree-lu/lu-tp-1.json' }] };
  await tun.start(30808, [], [], { bypassMacs: [], lanUsers: { nft: desc, singbox } });
  assert.equal(writes[0], net.buildNftRuleset({ lanIf: 'br-lan', macs: [], lanUsers: desc }));
  assert.match(writes[0], /dnat ip to 192\.168\.1\.1:30822/);
  assert.deepEqual(inner.calls[0][1].lanUsers.singbox, singbox, 'the inner backend gets the routes (tunSingbox writeConfig takes them on a router only)');
  assert.equal(tun.tableGen, 1);
});

test('setLanUsers while up: one atomic load of our table, sing-box untouched; while down only remembered; null is the table of before', async () => {
  const { tun, inner, lines, writes } = gateway();
  await tun.setLanUsers({ unassigned: 'allow', blocked: [A] });
  assert.equal(lines.length, 0, 'nothing runs before the tunnel is up');
  await tun.start(30808, [], [], { bypassMacs: ['02:00:00:00:00:01'] });
  assert.equal(writes[0], BEFORE, 'a start without the option is the gateway of before — whatever was remembered');
  const starts = inner.calls.length;
  lines.length = 0;
  await tun.setLanUsers({ unassigned: 'allow', blocked: [B] });
  assert.deepEqual(lines, ['nft -f /tmp/irnf-test/irnetfree-nft.conf']);
  assert.match(writes[writes.length - 1], new RegExp(`set lu_blocked \\{ type ether_addr; elements = \\{ ${B} \\}; \\}`));
  assert.equal(inner.calls.length, starts, 'sing-box untouched');
  // the exclusions and the QUIC refusal keep the users' sets when they reload the table
  await tun.setBypassMacs(['02:00:00:00:00:09']);
  assert.match(writes[writes.length - 1], /lu_blocked/);
  assert.match(writes[writes.length - 1], /02:00:00:00:00:09/);
  await tun.setLanUsers(null);
  assert.equal(writes[writes.length - 1], BEFORE.replace('02:00:00:00:00:01', '02:00:00:00:00:09'));
  assert.equal(tun.tableGen, 4, 'every load counted: the counters in it start again from zero');
});
