'use strict';
/**
 * The users module's shaper (src/modules/lanUsers/router/shaper.js): the tc
 * commands it runs for a decision, byte for byte — the HTB tree on the LAN
 * device for the download, the IFB and its tree for the upload, the router's
 * own traffic to the direct queue, the shares under a line, caps without one
 * — and what it does around them: applies only a changed description, tears
 * down only what is its own, falls back to the table's policing with the
 * packages to install when tc or a kernel piece is missing, leaves another
 * shaper's qdiscs alone, tries again after a minute. The kernel's word on
 * the commands comes from scripts/probe-lan-shape.js (CI, network
 * namespaces) and the QEMU smoke (openwrt/ci/guest-smoke.sh: a router
 * without tc). Nothing here runs `tc` or `ip` on the machine running the
 * tests.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const sh = require('../src/modules/lanUsers/router/shaper');

const { createShaper, cleanShape, shapeCommands, parseQdiscs, parseAddrs, quantumOf } = sh;
const A = 'aa:bb:cc:dd:ee:01', B = 'aa:bb:cc:dd:ee:02';
const ROUTER_ADDRS = ['192.168.1.1', 'fd12:3456::1', 'fe80::1'];

/**
 * The router's LAN as the shaper's commands see it: whose root and ingress
 * `br-lan` carries (null | 'ours' | 'foreign'), whether our IFB exists, the
 * router's own addresses; every command line in `calls`; `fail` maps a
 * command-line prefix to the error it answers with; `noTc`: no tc binary.
 */
function fakeRouter(init = {}) {
  const st = Object.assign({ root: null, ingress: null, ifb: false, addrs: ROUTER_ADDRS.slice(), calls: [], fail: {}, noTc: false }, init);
  st.run = async (cmd, args) => {
    const line = [cmd, ...args].join(' ');
    st.calls.push(line);
    for (const [prefix, msg] of Object.entries(st.fail)) if (line.startsWith(prefix)) throw new Error(msg);
    if (cmd === 'tc' && st.noTc) throw new Error('spawn tc ENOENT');
    if (line === 'tc qdisc show dev br-lan') {
      const out = [st.root === 'ours' ? 'qdisc htb 1f1e: root refcnt 2 r2q 10 default 0x20 direct_packets_stat 0 direct_qlen 1000'
        : st.root === 'foreign' ? 'qdisc cake 1: root refcnt 2 bandwidth 50Mbit diffserv3 triple-isolate nonat nowash no-ack-filter split-gso rtt 100ms raw overhead 0'
          : 'qdisc noqueue 0: root refcnt 2'];
      if (st.root === 'ours') out.push('qdisc fq_codel 8001: parent 1f1e:20 limit 10240p flows 1024 quantum 1514 target 5ms interval 100ms memory_limit 32Mb ecn drop_batch 64');
      if (st.ingress) out.push('qdisc ingress ffff: parent ffff:fff1 ----------------');
      return out.join('\n') + '\n';
    }
    if (line === 'ip -o addr show dev br-lan') {
      return st.addrs.map((a) => (a.includes(':')
        ? `12: br-lan    inet6 ${a}/64 scope ${a.startsWith('fe80') ? 'link' : 'global dynamic noprefixroute'} \\       valid_lft forever preferred_lft forever`
        : `12: br-lan    inet ${a}/24 brd 192.168.1.255 scope global br-lan\\       valid_lft forever preferred_lft forever`)).join('\n') + '\n';
    }
    if (line === 'tc qdisc del dev br-lan root handle 1f1e:') {
      if (st.root !== 'ours') throw new Error(st.root ? 'Error: Invalid handle.' : 'Error: Cannot delete qdisc with handle of zero.');
      st.root = null; return '';
    }
    if (line === 'ip link show dev ifb-lu') { if (!st.ifb) throw new Error('Device "ifb-lu" does not exist.'); return '7: ifb-lu: <BROADCAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc htb state UNKNOWN mode DEFAULT group default qlen 32\n'; }
    if (line === 'tc qdisc del dev br-lan ingress') { if (!st.ingress) throw new Error('Error: Cannot find specified qdisc on specified device.'); st.ingress = null; return ''; }
    if (line === 'ip link del ifb-lu') { if (!st.ifb) throw new Error('Cannot find device "ifb-lu"'); st.ifb = false; return ''; }
    if (line === 'ip link add ifb-lu type ifb') { if (st.ifb) throw new Error('RTNETLINK answers: File exists'); st.ifb = true; return ''; }
    if (line.startsWith('tc qdisc add dev br-lan root handle 1f1e:')) { if (st.root) throw new Error('Error: Exclusivity flag on, cannot modify.'); st.root = 'ours'; return ''; }
    if (line === 'tc qdisc add dev br-lan handle ffff: ingress') { if (st.ingress) throw new Error('Error: Exclusivity flag on, cannot modify.'); st.ingress = 'ours'; return ''; }
    if (/^(tc|ip) /.test(line)) return '';
    throw new Error('not faked: ' + line);
  };
  return st;
}

/** A /lib/modules and /sys/module in memory, for a router without tc. */
function fakeFs(files = []) {
  const set = new Set(files);
  return {
    accessSync(p) { if (!set.has(String(p).replace(/\\/g, '/'))) throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' }); },
    readFileSync(p) { throw Object.assign(new Error('ENOENT: ' + p), { code: 'ENOENT' }); }
  };
}

/** Two users' devices: A high with no cap, B low with caps, a third address of B's link-local (never shaped), MACs in any case. */
const DESC = {
  line: { down: 10000, up: 2000 },
  classes: [
    { mac: B.toUpperCase(), ips: ['192.168.1.40', '2001:db8::40', 'fe80::40'], down: 2000, up: 500, prio: 'low' },
    { mac: A, ips: ['192.168.1.23'], down: 0, up: 0, prio: 'high' }
  ]
};
const LOOK = ['tc qdisc del dev br-lan root handle 1f1e:', 'ip link show dev ifb-lu', 'tc qdisc show dev br-lan', 'ip -o addr show dev br-lan'];
const TREE = [
  // the download tree on the LAN device: the line, the default class, the router's own to the direct queue, then the devices
  'tc qdisc add dev br-lan root handle 1f1e: htb default 20 direct_qlen 1000',
  'tc class add dev br-lan parent 1f1e: classid 1f1e:1 htb rate 10000kbit ceil 10000kbit quantum 125000',
  'tc class add dev br-lan parent 1f1e:1 classid 1f1e:20 htb rate 3333kbit ceil 10000kbit prio 1 quantum 41662',
  'tc qdisc add dev br-lan parent 1f1e:20 fq_codel',
  'tc filter add dev br-lan parent 1f1e: protocol ip prio 1 u32 match ip src 192.168.1.1/32 flowid 1f1e:0',
  'tc filter add dev br-lan parent 1f1e: protocol ipv6 prio 2 u32 match ip6 src fd12:3456::1/128 flowid 1f1e:0',
  'tc filter add dev br-lan parent 1f1e: protocol ipv6 prio 2 u32 match ip6 src fe80::1/128 flowid 1f1e:0',
  // A: high, no cap — its share guaranteed, the line its ceiling, prio 0
  'tc class add dev br-lan parent 1f1e:1 classid 1f1e:101 htb rate 3333kbit ceil 10000kbit prio 0 quantum 41662',
  'tc qdisc add dev br-lan parent 1f1e:101 fq_codel',
  'tc filter add dev br-lan parent 1f1e: protocol ip prio 10 u32 match ip dst 192.168.1.23/32 flowid 1f1e:101',
  // B: low, 2000 down — the cap is below its share, so rate = ceil = the cap, prio 2; its link-local address is not here
  'tc class add dev br-lan parent 1f1e:1 classid 1f1e:102 htb rate 2000kbit ceil 2000kbit prio 2 quantum 25000',
  'tc qdisc add dev br-lan parent 1f1e:102 fq_codel',
  'tc filter add dev br-lan parent 1f1e: protocol ip prio 10 u32 match ip dst 192.168.1.40/32 flowid 1f1e:102',
  'tc filter add dev br-lan parent 1f1e: protocol ipv6 prio 11 u32 match ip6 dst 2001:db8::40/128 flowid 1f1e:102',
  // the IFB, its upload tree (the other way round: a device is the source, the router the destination)
  'ip link add ifb-lu type ifb',
  'ip link set ifb-lu up',
  'tc qdisc add dev ifb-lu root handle 1f1e: htb default 20 direct_qlen 1000',
  'tc class add dev ifb-lu parent 1f1e: classid 1f1e:1 htb rate 2000kbit ceil 2000kbit quantum 25000',
  'tc class add dev ifb-lu parent 1f1e:1 classid 1f1e:20 htb rate 666kbit ceil 2000kbit prio 1 quantum 8325',
  'tc qdisc add dev ifb-lu parent 1f1e:20 fq_codel',
  'tc filter add dev ifb-lu parent 1f1e: protocol ip prio 1 u32 match ip dst 192.168.1.1/32 flowid 1f1e:0',
  'tc filter add dev ifb-lu parent 1f1e: protocol ipv6 prio 2 u32 match ip6 dst fd12:3456::1/128 flowid 1f1e:0',
  'tc filter add dev ifb-lu parent 1f1e: protocol ipv6 prio 2 u32 match ip6 dst fe80::1/128 flowid 1f1e:0',
  'tc class add dev ifb-lu parent 1f1e:1 classid 1f1e:101 htb rate 666kbit ceil 2000kbit prio 0 quantum 8325',
  'tc qdisc add dev ifb-lu parent 1f1e:101 fq_codel',
  'tc filter add dev ifb-lu parent 1f1e: protocol ip prio 10 u32 match ip src 192.168.1.23/32 flowid 1f1e:101',
  'tc class add dev ifb-lu parent 1f1e:1 classid 1f1e:102 htb rate 500kbit ceil 500kbit prio 2 quantum 6250',
  'tc qdisc add dev ifb-lu parent 1f1e:102 fq_codel',
  'tc filter add dev ifb-lu parent 1f1e: protocol ip prio 10 u32 match ip src 192.168.1.40/32 flowid 1f1e:102',
  'tc filter add dev ifb-lu parent 1f1e: protocol ipv6 prio 11 u32 match ip6 src 2001:db8::40/128 flowid 1f1e:102',
  // last: the ingress and the redirect of everything into the IFB
  'tc qdisc add dev br-lan handle ffff: ingress',
  'tc filter add dev br-lan parent ffff: protocol all prio 10 u32 match u32 0 0 action mirred egress redirect dev ifb-lu'
];
/** Our tree gone: the root by handle; the IFB there means the ingress is ours — the redirect first, then the device. */
const TEARDOWN = ['tc qdisc del dev br-lan root handle 1f1e:', 'ip link show dev ifb-lu', 'tc qdisc del dev br-lan ingress', 'ip link del ifb-lu'];

test('the tree, byte for byte: a look at the LAN device, the router’s own addresses, the download tree, the IFB and its upload tree, the ingress redirect last', async () => {
  const lan = fakeRouter();
  const logs = [];
  const s = createShaper({ run: lan.run, log: (m, l) => logs.push(`${l}: ${m}`), lanIf: 'br-lan' });
  assert.deepEqual(s.info(), { mode: 'off', missing: [], line: { down: 0, up: 0 }, prio: { down: false, up: false }, busy: null, why: null, lanIf: 'br-lan', ifb: 'ifb-lu' });
  const r = await s.apply(DESC);
  assert.deepEqual(lan.calls, [...LOOK, ...TREE]);
  assert.deepEqual(r, { mode: 'tc', missing: [], line: { down: 10000, up: 2000 }, prio: { down: true, up: true }, busy: null, why: null, lanIf: 'br-lan', ifb: 'ifb-lu' });
  assert.equal(lan.root, 'ours'); assert.equal(lan.ingress, 'ours'); assert.equal(lan.ifb, true);
  assert.deepEqual(logs, ['info: Users: speeds are shaped with tc on br-lan (HTB; the upload through ifb-lu) — 2 device classes, line 10000/2000 kbps']);
  // the pure part says the same commands
  assert.deepEqual(shapeCommands(cleanShape(DESC), { lanIf: 'br-lan', ifb: 'ifb-lu', routerIps: ROUTER_ADDRS }).map(x => [x.cmd, ...x.args].join(' ')), TREE);
});

test('idempotent: the same description runs nothing; a changed one tears ours down (root by handle, ingress and IFB) and builds anew', async () => {
  const lan = fakeRouter();
  const s = createShaper({ run: lan.run });
  await s.apply(DESC);
  lan.calls = [];
  await s.apply(JSON.parse(JSON.stringify(DESC)));
  assert.deepEqual(lan.calls, [], 'nothing for the same description');
  // the MACs' case and the classes' order do not make a new description
  await s.apply({ line: DESC.line, classes: [DESC.classes[1], Object.assign({}, DESC.classes[0], { mac: B })] });
  assert.deepEqual(lan.calls, []);
  // a new address for A: the tree anew
  const changed = { line: DESC.line, classes: [DESC.classes[0], Object.assign({}, DESC.classes[1], { ips: ['192.168.1.23', '192.168.1.24'] })] };
  await s.apply(changed);
  assert.deepEqual(lan.calls.slice(0, 4), TEARDOWN);
  assert.deepEqual(lan.calls.slice(4, 6), ['tc qdisc show dev br-lan', 'ip -o addr show dev br-lan']);
  assert.ok(lan.calls.includes('tc filter add dev br-lan parent 1f1e: protocol ip prio 10 u32 match ip dst 192.168.1.24/32 flowid 1f1e:101'));
  assert.equal(lan.calls.filter(c => c.startsWith('tc qdisc add dev br-lan root')).length, 1);
});

test('no class left: the pieces are tried once (the verdict), then nothing of ours stays; the same empty description runs nothing again', async () => {
  const lan = fakeRouter();
  const s = createShaper({ run: lan.run });
  const r = await s.apply({ line: { down: 10000, up: 2000 }, classes: [] });
  assert.equal(r.mode, 'tc');
  assert.ok(lan.calls.includes('tc qdisc add dev br-lan root handle 1f1e: htb default 20 direct_qlen 1000'), 'the skeleton was built');
  assert.deepEqual(lan.calls.slice(-4), TEARDOWN, 'and torn down at once');
  assert.equal(lan.root, null); assert.equal(lan.ingress, null); assert.equal(lan.ifb, false);
  lan.calls = [];
  await s.apply({ line: { down: 10000, up: 2000 }, classes: [] });
  assert.deepEqual(lan.calls, []);
  // a class comes: built and kept
  await s.apply(DESC);
  assert.equal(lan.root, 'ours'); assert.equal(lan.ifb, true);
});

test('no line: caps alone, rate = ceil = the cap straight under the root, unclassified traffic direct (default 0); a priority has no class and info says it cannot apply', async () => {
  const lan = fakeRouter();
  const s = createShaper({ run: lan.run });
  const r = await s.apply({ line: { down: 0, up: 0 }, classes: DESC.classes });
  assert.deepEqual(r.prio, { down: false, up: false });
  assert.equal(r.mode, 'tc');
  assert.deepEqual(lan.calls.slice(LOOK.length), [
    'tc qdisc add dev br-lan root handle 1f1e: htb default 0 direct_qlen 1000',
    'tc filter add dev br-lan parent 1f1e: protocol ip prio 1 u32 match ip src 192.168.1.1/32 flowid 1f1e:0',
    'tc filter add dev br-lan parent 1f1e: protocol ipv6 prio 2 u32 match ip6 src fd12:3456::1/128 flowid 1f1e:0',
    'tc filter add dev br-lan parent 1f1e: protocol ipv6 prio 2 u32 match ip6 src fe80::1/128 flowid 1f1e:0',
    // only B has a cap: A (a priority alone) gets no class — the first class is still 1f1e:101
    'tc class add dev br-lan parent 1f1e: classid 1f1e:101 htb rate 2000kbit ceil 2000kbit quantum 25000',
    'tc qdisc add dev br-lan parent 1f1e:101 fq_codel',
    'tc filter add dev br-lan parent 1f1e: protocol ip prio 10 u32 match ip dst 192.168.1.40/32 flowid 1f1e:101',
    'tc filter add dev br-lan parent 1f1e: protocol ipv6 prio 11 u32 match ip6 dst 2001:db8::40/128 flowid 1f1e:101',
    'ip link add ifb-lu type ifb',
    'ip link set ifb-lu up',
    'tc qdisc add dev ifb-lu root handle 1f1e: htb default 0 direct_qlen 1000',
    'tc filter add dev ifb-lu parent 1f1e: protocol ip prio 1 u32 match ip dst 192.168.1.1/32 flowid 1f1e:0',
    'tc filter add dev ifb-lu parent 1f1e: protocol ipv6 prio 2 u32 match ip6 dst fd12:3456::1/128 flowid 1f1e:0',
    'tc filter add dev ifb-lu parent 1f1e: protocol ipv6 prio 2 u32 match ip6 dst fe80::1/128 flowid 1f1e:0',
    'tc class add dev ifb-lu parent 1f1e: classid 1f1e:101 htb rate 500kbit ceil 500kbit quantum 6250',
    'tc qdisc add dev ifb-lu parent 1f1e:101 fq_codel',
    'tc filter add dev ifb-lu parent 1f1e: protocol ip prio 10 u32 match ip src 192.168.1.40/32 flowid 1f1e:101',
    'tc filter add dev ifb-lu parent 1f1e: protocol ipv6 prio 11 u32 match ip6 src 2001:db8::40/128 flowid 1f1e:101',
    'tc qdisc add dev br-lan handle ffff: ingress',
    'tc filter add dev br-lan parent ffff: protocol all prio 10 u32 match u32 0 0 action mirred egress redirect dev ifb-lu'
  ]);
  // one way with a line, the other without: each direction on its own
  lan.calls = [];
  const r2 = await s.apply({ line: { down: 8000, up: 0 }, classes: DESC.classes });
  assert.deepEqual(r2.prio, { down: true, up: false });
  assert.ok(lan.calls.includes('tc class add dev br-lan parent 1f1e: classid 1f1e:1 htb rate 8000kbit ceil 8000kbit quantum 100000'));
  assert.ok(lan.calls.includes('tc qdisc add dev ifb-lu root handle 1f1e: htb default 0 direct_qlen 1000'));
  assert.ok(!lan.calls.some(c => c.startsWith('tc class add dev ifb-lu parent 1f1e: classid 1f1e:1 ')), 'no line class on the IFB');
});

test('a cap above the line is the line; the share is the line among the classes and the default; a cap below its share keeps the cap as its rate; the least share is 8 kbit', () => {
  const d = cleanShape({ line: { down: 1000, up: 30 }, classes: [
    { mac: A, ips: ['10.0.0.2'], down: 5000, up: 10, prio: 'normal' },
    { mac: B, ips: ['10.0.0.3'], down: 100, up: 0, prio: 'high' },
    { mac: 'aa:bb:cc:dd:ee:03', ips: ['10.0.0.4'], down: 0, up: 0, prio: 'low' }
  ] });
  const lines = shapeCommands(d, { routerIps: [] }).map(x => [x.cmd, ...x.args].join(' ')).filter(c => c.startsWith('tc class'));
  assert.deepEqual(lines, [
    // down: share = floor(1000 / 4) = 250
    'tc class add dev br-lan parent 1f1e: classid 1f1e:1 htb rate 1000kbit ceil 1000kbit quantum 12500',
    'tc class add dev br-lan parent 1f1e:1 classid 1f1e:20 htb rate 250kbit ceil 1000kbit prio 1 quantum 3125',
    'tc class add dev br-lan parent 1f1e:1 classid 1f1e:101 htb rate 250kbit ceil 1000kbit prio 1 quantum 3125',
    'tc class add dev br-lan parent 1f1e:1 classid 1f1e:102 htb rate 100kbit ceil 100kbit prio 0 quantum 1514',
    'tc class add dev br-lan parent 1f1e:1 classid 1f1e:103 htb rate 250kbit ceil 1000kbit prio 2 quantum 3125',
    // up: share = max(8, floor(30 / 4)) = 8
    'tc class add dev ifb-lu parent 1f1e: classid 1f1e:1 htb rate 30kbit ceil 30kbit quantum 1514',
    'tc class add dev ifb-lu parent 1f1e:1 classid 1f1e:20 htb rate 8kbit ceil 30kbit prio 1 quantum 1514',
    'tc class add dev ifb-lu parent 1f1e:1 classid 1f1e:101 htb rate 8kbit ceil 10kbit prio 1 quantum 1514',
    'tc class add dev ifb-lu parent 1f1e:1 classid 1f1e:102 htb rate 8kbit ceil 30kbit prio 0 quantum 1514',
    'tc class add dev ifb-lu parent 1f1e:1 classid 1f1e:103 htb rate 8kbit ceil 30kbit prio 2 quantum 1514'
  ]);
  assert.equal(quantumOf(10000000), 200000, 'the kernel’s own ceiling');
  assert.equal(quantumOf(1), 1514, 'one packet at least');
});

test('stop: ours down and mode off; a second stop finds nothing (the root delete is refused by the kernel on a handle not ours, the IFB is not there)', async () => {
  const lan = fakeRouter();
  const logs = [];
  const s = createShaper({ run: lan.run, log: (m) => logs.push(m) });
  await s.apply(DESC);
  lan.calls = [];
  await s.stop();
  assert.deepEqual(lan.calls, TEARDOWN);
  assert.equal(s.info().mode, 'off');
  assert.equal(lan.root, null); assert.equal(lan.ingress, null); assert.equal(lan.ifb, false);
  lan.calls = [];
  await s.stop();
  assert.deepEqual(lan.calls, ['tc qdisc del dev br-lan root handle 1f1e:', 'ip link show dev ifb-lu']);
  // after a stop the same description is applied again (a new gateway), and said again
  lan.calls = [];
  await s.apply(DESC);
  assert.deepEqual(lan.calls, [...LOOK, ...TREE]);
  assert.equal(logs.length, 2);
});

test('a tree a crashed service left behind is ours by its marks: the root by handle, the ingress by our IFB — taken down before the build', async () => {
  const lan = fakeRouter({ root: 'ours', ingress: 'ours', ifb: true });
  const s = createShaper({ run: lan.run });
  await s.apply(DESC);
  assert.deepEqual(lan.calls.slice(0, 4), TEARDOWN);
  assert.equal(lan.calls.filter(c => c === 'tc qdisc add dev br-lan handle ffff: ingress').length, 1);
  assert.equal(s.info().mode, 'tc');
});

test('no tc: mode police, tc-tiny named, the kernel pieces by their files, the IFB tried for real — and the Users page’s opkg line in the log; nothing of ours left', async () => {
  for (const [files, missing] of [
    [[], ['tc-tiny', 'kmod-sched-core']],
    [['/sys/module/sch_htb', '/lib/modules/6.6.73/sch_ingress.ko', '/lib/modules/6.6.73/cls_u32.ko', '/lib/modules/6.6.73/act_mirred.ko'], ['tc-tiny']],
    [['/lib/modules/6.6.73/sch_htb.ko'], ['tc-tiny', 'kmod-sched-core']]
  ]) {
    const lan = fakeRouter({ noTc: true });
    const logs = [];
    const s = createShaper({ run: lan.run, log: (m, l) => logs.push(`${l}: ${m}`), fs: fakeFs(files), release: () => '6.6.73' });
    const r = await s.apply(DESC);
    assert.equal(r.mode, 'police');
    assert.deepEqual(r.missing, missing, JSON.stringify(files));
    assert.equal(r.why, 'no tc on this router');
    assert.deepEqual(r.prio, { down: false, up: false });
    assert.ok(lan.calls.includes('ip link add ifb-lu type ifb') && lan.calls.includes('ip link del ifb-lu'), 'the IFB tried and removed');
    assert.equal(lan.ifb, false);
    assert.ok(!lan.calls.some(c => c.startsWith('tc qdisc add')), 'nothing was built');
    assert.deepEqual(logs, [`warn: Users: smooth speed limits need ${missing.join(', ')} — \`opkg install ${missing.join(' ')}\`; until then speeds are policed in the table as before`]);
  }
  // the IFB cannot be made either
  const lan = fakeRouter({ noTc: true, fail: { 'ip link add ifb-lu type ifb': 'RTNETLINK answers: Operation not supported' } });
  const r = await createShaper({ run: lan.run, fs: fakeFs([]), release: () => '6.6.73' }).apply(DESC);
  assert.deepEqual(r.missing, ['tc-tiny', 'kmod-sched-core', 'kmod-ifb']);
});

test('tc there, the kernel without the schedulers: the first refusal names kmod-sched-core, the IFB is still tried, what was built is torn down', async () => {
  const lan = fakeRouter({ fail: { 'tc qdisc add dev br-lan root handle 1f1e:': 'Error: Specified qdisc kind is unknown.' } });
  const s = createShaper({ run: lan.run });
  const r = await s.apply(DESC);
  assert.equal(r.mode, 'police');
  assert.deepEqual(r.missing, ['kmod-sched-core']);
  assert.equal(r.why, 'tc qdisc add dev br-lan root handle 1f1e: htb default 20 direct_qlen 1000: Error: Specified qdisc kind is unknown.');
  assert.ok(lan.calls.includes('ip link add ifb-lu type ifb'), 'the IFB tried on its own');
  assert.equal(lan.ifb, false);
  assert.deepEqual(lan.calls.slice(-2), ['tc qdisc del dev br-lan root handle 1f1e:', 'ip link show dev ifb-lu'], 'torn down');
  // the classifier missing instead: the same package, the download root already there is taken down
  const lan2 = fakeRouter({ fail: { 'tc filter add dev br-lan parent 1f1e: protocol ip prio 1': 'Error: Specified filter kind is unknown.' } });
  const r2 = await createShaper({ run: lan2.run }).apply(DESC);
  assert.deepEqual([r2.mode, r2.missing], ['police', ['kmod-sched-core']]);
  assert.equal(lan2.root, null, 'the half-built download tree is gone');
  // a refusal that is not a missing piece: police, no package, the reason kept
  const lan3 = fakeRouter({ fail: { 'tc class add dev br-lan parent 1f1e:1 classid 1f1e:101': 'RTNETLINK answers: Invalid argument' } });
  const r3 = await createShaper({ run: lan3.run }).apply(DESC);
  assert.deepEqual([r3.mode, r3.missing], ['police', []]);
  assert.match(r3.why, /^tc class add dev br-lan parent 1f1e:1 classid 1f1e:101 .*: RTNETLINK answers: Invalid argument$/);
});

test('no IFB in this kernel: kmod-ifb, the download tree taken down with the rest', async () => {
  const lan = fakeRouter({ fail: { 'ip link add ifb-lu type ifb': 'RTNETLINK answers: Operation not supported' } });
  const r = await createShaper({ run: lan.run }).apply(DESC);
  assert.deepEqual([r.mode, r.missing], ['police', ['kmod-ifb']]);
  assert.equal(lan.root, null);
  assert.ok(!lan.calls.some(c => c.startsWith('tc qdisc add dev ifb-lu')), 'nothing on an IFB that is not there');
});

test('another shaper on the LAN device: its root or its ingress is left alone — mode police, busy says which, no package to install', async () => {
  const lan = fakeRouter({ root: 'foreign' });
  const logs = [];
  const s = createShaper({ run: lan.run, log: (m, l) => logs.push(`${l}: ${m}`) });
  const r = await s.apply(DESC);
  assert.deepEqual([r.mode, r.busy, r.missing], ['police', 'root', []]);
  assert.equal(r.why, 'another shaper holds br-lan’s root (cake 1:)');
  assert.equal(lan.root, 'foreign', 'theirs untouched');
  assert.ok(!lan.calls.some(c => c.startsWith('tc qdisc add') || c.startsWith('ip link add')));
  assert.deepEqual(logs, ['warn: Users: speeds are policed in the table as before — another shaper holds br-lan’s root (cake 1:)']);
  await s.stop();
  assert.equal(lan.root, 'foreign');
  const lan2 = fakeRouter({ ingress: 'foreign' });
  const r2 = await createShaper({ run: lan2.run }).apply(DESC);
  assert.deepEqual([r2.mode, r2.busy], ['police', 'ingress']);
  assert.equal(lan2.ingress, 'foreign');
  assert.ok(!lan2.calls.includes('tc qdisc del dev br-lan ingress'), 'an ingress without our IFB is not ours to delete');
});

test('after a fallback the same description is tried again only after a minute — the admin installs the packages, the next decision finds them', async () => {
  let t = 1000000;
  const lan = fakeRouter({ noTc: true });
  const s = createShaper({ run: lan.run, now: () => t, fs: fakeFs([]), release: () => '6.6.73' });
  assert.equal((await s.apply(DESC)).mode, 'police');
  lan.calls = [];
  t += sh.RETRY_MS - 1;
  assert.equal((await s.apply(DESC)).mode, 'police');
  assert.deepEqual(lan.calls, [], 'too soon');
  lan.noTc = false;    // tc-tiny installed meanwhile
  t += 1;
  const r = await s.apply(DESC);
  assert.equal(r.mode, 'tc');
  assert.deepEqual(lan.calls.slice(-TREE.length), TREE);
  // a changed description is tried at once, whatever the clock — here tc vanished under a running tree (the
  // package removed): the root and the ingress cannot be taken down, so the IFB stays as the mark that says the
  // ingress is ours, and the IFB probe leaves it alone
  lan.noTc = true;
  lan.calls = [];
  await s.apply({ line: DESC.line, classes: [] });
  assert.equal(s.info().mode, 'police');
  assert.equal(lan.ifb, true, 'the mark stays');
  assert.equal(lan.ingress, 'ours');
  assert.ok(!lan.calls.includes('ip link del ifb-lu'));
  // tc back: the leftover is ours by that mark — taken down, and the tree built anew (not "another shaper's ingress")
  lan.noTc = false;
  lan.calls = [];
  const r2 = await s.apply(DESC);
  assert.equal(r2.mode, 'tc');
  assert.equal(r2.busy, null);
  assert.deepEqual(lan.calls.slice(0, 4), TEARDOWN);
});

test('an IFB of ours without an ingress to delete (a crash between the two): the listing shows no ingress, so the device goes too', async () => {
  const lan = fakeRouter({ ifb: true });
  const s = createShaper({ run: lan.run });
  await s.stop();
  assert.deepEqual(lan.calls, ['tc qdisc del dev br-lan root handle 1f1e:', 'ip link show dev ifb-lu', 'tc qdisc del dev br-lan ingress', 'tc qdisc show dev br-lan', 'ip link del ifb-lu']);
  assert.equal(lan.ifb, false);
});

test('the router’s own addresses unreadable: said once, its replies share the default class (no direct filters), still shaping', async () => {
  const lan = fakeRouter({ fail: { 'ip -o addr show dev br-lan': 'Device "br-lan" does not exist.' } });
  const logs = [];
  const s = createShaper({ run: lan.run, log: (m, l) => logs.push(`${l}: ${m}`) });
  const r = await s.apply(DESC);
  assert.equal(r.mode, 'tc');
  assert.ok(!lan.calls.some(c => c.includes('flowid 1f1e:0')));
  assert.equal(logs[0], 'warn: Users: the router’s own addresses on br-lan could not be read (Device "br-lan" does not exist.) — its replies share the default class');
  await s.apply({ line: DESC.line, classes: [DESC.classes[0]] });
  assert.equal(logs.filter(l => l.includes('own addresses')).length, 1);
});

test('without a command runner: police, no package, the reason', async () => {
  const r = await createShaper({}).apply(DESC);
  assert.deepEqual([r.mode, r.missing, r.why], ['police', [], 'no command runner']);
});

test('cleanShape: MACs one shape and sorted, addresses those a counter keys on (no link-local v6) each in one class, speeds whole kbps, a class with nothing to shape left out', () => {
  const d = cleanShape({ line: { down: '10000.4', up: -5 }, classes: [
    { mac: 'AA:BB:CC:DD:EE:02', ips: ['192.168.1.40', ' 2001:DB8::40 ', 'fe80::40', 'junk', '192.168.1.40'], down: 1999.6, up: 0.2, prio: 'low' },
    { mac: A, ips: ['192.168.1.23', '192.168.1.40'], down: 0, up: 0, prio: 'high' },
    { mac: A, ips: ['192.168.1.99'], down: 5, up: 5 },                       // the same MAC twice: the first counts
    { mac: 'aa:bb:cc:dd:ee:03', ips: ['192.168.1.50'], down: 0, up: 0 },      // normal, no cap: nothing to shape
    { mac: 'aa:bb:cc:dd:ee:04', ips: ['fe80::4'], down: 100, up: 0 },          // no address a counter keys on
    { mac: 'not-a-mac', ips: ['192.168.1.60'], down: 100, up: 0 },
    { mac: 'aa:bb:cc:dd:ee:05', ips: ['192.168.1.70'], down: 1e12, up: 3, prio: 'urgent' },
    null, 'x'
  ] });
  // 192.168.1.40 is claimed by A and B: sorted first, so the lower MAC (A) keeps it — the order the table's
  // pins and counters keep a shared address in too (plan.decide hands MACs sorted, nft.cleanDesc keeps the first)
  assert.deepEqual(d, { line: { down: 10000, up: 0 }, classes: [
    { mac: A, ips: ['192.168.1.23', '192.168.1.40'], down: 0, up: 0, prio: 'high' },
    { mac: B, ips: ['2001:db8::40'], down: 2000, up: 0, prio: 'low' },
    { mac: 'aa:bb:cc:dd:ee:05', ips: ['192.168.1.70'], down: sh.KBPS_MAX, up: 3, prio: 'normal' }
  ] });
  assert.deepEqual(cleanShape(null), { line: { down: 0, up: 0 }, classes: [] });
  assert.deepEqual(cleanShape({ line: 'fast', classes: 'all' }), { line: { down: 0, up: 0 }, classes: [] });
});

test('parseQdiscs and parseAddrs read tc’s and ip’s listings', () => {
  assert.deepEqual(parseQdiscs([
    'qdisc htb 1f1e: root refcnt 2 r2q 10 default 0x20 direct_packets_stat 0 direct_qlen 1000',
    'qdisc fq_codel 8001: parent 1f1e:20 limit 10240p flows 1024 quantum 1514 target 5ms interval 100ms memory_limit 32Mb ecn drop_batch 64',
    'qdisc ingress ffff: parent ffff:fff1 ----------------',
    'qdisc noqueue 0: root refcnt 2',
    'qdisc mq 0: root',
    'qdisc clsact ffff: parent ffff:fff1',
    'junk'
  ].join('\n')), [
    { kind: 'htb', handle: '1f1e', root: true, ingress: false },
    { kind: 'fq_codel', handle: '8001', root: false, ingress: false },
    { kind: 'ingress', handle: 'ffff', root: false, ingress: true },
    { kind: 'noqueue', handle: '0', root: true, ingress: false },
    { kind: 'mq', handle: '0', root: true, ingress: false },
    { kind: 'clsact', handle: 'ffff', root: false, ingress: true }
  ]);
  assert.deepEqual(parseQdiscs(''), []);
  assert.deepEqual(parseAddrs([
    '12: br-lan    inet 192.168.1.1/24 brd 192.168.1.255 scope global br-lan\\       valid_lft forever preferred_lft forever',
    '12: br-lan    inet6 fd12:3456::1/60 scope global dynamic noprefixroute \\       valid_lft 6927sec preferred_lft 3327sec',
    '12: br-lan    inet6 fe80::1234:5678:9abc:def0/64 scope link \\       valid_lft forever preferred_lft forever',
    '12: br-lan    inet 192.168.1.1/24 scope global secondary br-lan'
  ].join('\n')), ['192.168.1.1', 'fd12:3456::1', 'fe80::1234:5678:9abc:def0']);
  assert.deepEqual(parseAddrs(''), []);
});

/* ------------------------------ the CI probe: its pure parts and its guard ------------------------------ */

const L = require('../scripts/probe-lan-shape');

test('the shape probe runs only in CI: without its flag (and Linux and root) it refuses before touching anything', () => {
  const r = spawnSync(process.execPath, [path.join(__dirname, '..', 'scripts', 'probe-lan-shape.js')], {
    encoding: 'utf8', env: Object.assign({}, process.env, { IRNF_LS_PROBE: '' }), timeout: 15000
  });
  assert.equal(r.status, 2);
  assert.match(r.stderr, /CI only/);
});

test('the shape probe’s ports: never the app’s own, below the ephemeral range; its descriptions are plan.decide’s `shape`; the policing it compares against is the app’s own table', () => {
  for (const p of [10808, 10809, 10085, 30808, 30809, 30085, 30820, 30821, 30822]) assert.ok(L.APP_PORTS.includes(p));
  for (const p of Object.values(L.P)) { assert.ok(!L.APP_PORTS.includes(p)); assert.ok(p > 1024 && p < 32768); }
  assert.equal(L.BASE, 24400);
  for (const d of [L.shapeDesc(), L.prioDesc()]) {
    assert.deepEqual(Object.keys(d).sort(), ['classes', 'line']);
    assert.deepEqual(Object.keys(d.line).sort(), ['down', 'up']);
    for (const c of d.classes) assert.deepEqual(Object.keys(c).sort(), ['down', 'ips', 'mac', 'prio', 'up']);
    const clean = cleanShape(d);
    assert.equal(clean.classes.length, d.classes.length, 'every class survives the cleaning');
  }
  assert.equal(L.shapeDesc().classes[0].down, L.CAP_KBPS);
  assert.deepEqual(L.prioDesc().classes.map(c => c.prio), ['high', 'low']);
  assert.deepEqual(L.prioDesc().line, { down: L.LINE_KBPS, up: L.LINE_KBPS });
  // the comparison: the gateway's table, with A policed at the cap both ways, down by its two addresses
  const table = L.policeTable();
  assert.ok(table.startsWith('table inet irnetfree\ndelete table inet irnetfree\n'));
  assert.ok(table.includes(`    oifname "${L.LAN_IF}" ip daddr ${L.DEV.a.ip} limit rate over 250 kbytes/second burst 250 kbytes counter drop`));
  assert.ok(table.includes(`    oifname "${L.LAN_IF}" ip6 daddr ${L.DEV.a.ip6} limit rate over 250 kbytes/second burst 250 kbytes counter drop`));
  assert.ok(table.includes(`    iifname "${L.LAN_IF}" ether saddr ${L.DEV.a.mac} limit rate over 250 kbytes/second burst 250 kbytes counter drop`));
  assert.ok(!table.includes('lu_gate'), 'no gate: unassigned devices are let through');
  // the numbers: a rate in kbit/s, the evenness over the samples with the partial first and last left out
  assert.deepEqual(L.stats({ bytes: 2621440, ms: 10000, samples: [10, 50000, 50000, 50000, 50000, 50000, 50000, 7] }), { kbit: 2097, cv: 0, n: 6 });
  const uneven = L.stats({ bytes: 2621440, ms: 10000, samples: [0, 100000, 0, 100000, 0, 100000, 0, 5] });
  assert.equal(uneven.n, 6);
  assert.ok(uneven.cv > 0.9 && uneven.cv < 1.1, `a sawtooth: cv ≈ 1 (${uneven.cv})`);
  assert.deepEqual(L.stats({ bytes: 100, ms: 10, samples: [1, 2, 3] }), { kbit: 80, cv: null, n: 1 });
  assert.deepEqual(L.stats({ error: 'x' }), { kbit: 0, cv: null, n: 0 });
  assert.ok(L.within(1500, 2000) && L.within(2500, 2000) && !L.within(1499, 2000) && !L.within(2501, 2000));
});
