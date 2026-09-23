'use strict';
/**
 * The OpenWrt gateway backend, with the sing-box backend and every command
 * faked: the tests pin the ORDER of the steps (nft table, ip rules, sing-box,
 * verify), the rollback at each failure, the live set replacement that never
 * touches the tunnel, and that DNS is declared the backend's own.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { TunOpenwrt } = require('../src/main/tunOpenwrt');
const net = require('../src/main/openwrtNet');

/** A fake TunSingbox: records calls; `failStart` makes start() throw. */
function fakeInner({ available = true, failStart = false } = {}) {
  return {
    calls: [],
    active: false,
    excludeIps: [],
    interfaceName: 'IRNetFree',
    dnsPeer: '172.19.0.2',
    dnsPeer6: 'fdfe:dcba:9876::2',
    lang: 'fa',
    isAvailable: () => available,
    isElevated: () => true,
    prepare: async () => {},
    physicalInterface: async () => ({ name: 'eth0', ifIndex: null, gateway: '192.168.1.2' }),
    async start(socksPort, bypass, dns, opts) {
      this.calls.push(['start', socksPort, bypass, opts]);
      if (failStart) throw new Error('sing-box exited immediately');
      this.active = true; this.excludeIps = ['1.2.3.4/32'];
    },
    async stop() { this.calls.push(['stop']); this.active = false; this.excludeIps = []; },
    cleanupSync() { this.calls.push(['cleanupSync']); }
  };
}

/** A fake command runner: `answers` maps a regex over "cmd args…" to stdout or an Error. */
function fakeRun(answers = []) {
  const lines = [];
  const run = async (cmd, args) => {
    const line = [cmd, ...args].join(' ');
    lines.push(line);
    for (const [re, out] of answers) if (re.test(line)) { if (out instanceof Error) throw out; return out; }
    return '';
  };
  return { run, lines };
}

const RULES_OK = '0:\tfrom all lookup local\n9000:\tfrom all to 172.19.0.0/30 lookup 2022\n9002:\tnot from all iif lo lookup 2022\n32766:\tfrom all lookup main\n';

function make(opts = {}) {
  const inner = opts.inner || fakeInner();
  const { run, lines } = fakeRun(opts.answers || [[/^ip rule show/, RULES_OK]]);
  const writes = [];
  const logs = [];
  const tun = new TunOpenwrt({
    inner, run,
    runSync: (cmd, args) => { lines.push('SYNC ' + [cmd, ...args].join(' ')); },
    writeFile: (p, text) => { writes.push([p, text]); },
    lanStatus: async () => (opts.lan || { device: 'br-lan', address: '192.168.1.1', mask: 24 }),
    which: (name) => (opts.which ? opts.which(name) : true),
    onLog: (line, level) => logs.push([level, line]),
    lang: 'en', tmpDir: '/tmp/irnf-test',
    verifyWaitMs: opts.verifyWaitMs || 300     // the real 15s is for an emulated CPU; the fakes answer at once
  });
  return { tun, inner, lines, writes, logs };
}

test('contract: the fields the service reads, and DNS declared as the backend’s own', () => {
  const { tun } = make();
  assert.equal(tun.backendId, 'openwrt');
  assert.equal(tun.managesDns, true, 'the leak guard must not touch the router’s resolver');
  assert.equal(tun.interfaceName, 'IRNetFree');
  assert.equal(tun.dnsPeer, '172.19.0.2');
  assert.equal(tun.dnsPeer6, 'fdfe:dcba:9876::2');
  assert.equal(tun.active, false);
  assert.deepEqual(tun.excludeIps, []);
});

test('isAvailable: sing-box present AND nft on PATH', () => {
  assert.equal(make().tun.isAvailable(), true);
  assert.equal(make({ inner: fakeInner({ available: false }) }).tun.isAvailable(), false);
  assert.equal(make({ which: (n) => n !== 'nft' }).tun.isAvailable(), false);
});

test('start: nft table, then the bypass rules, then sing-box, then verify — in that order, with the MACs', async () => {
  const { tun, inner, lines, writes, logs } = make();
  await tun.start(10808, ['1.2.3.4'], ['172.19.0.2'], { ipv6: false, strict: false, apps: null, bypassMacs: ['AA:BB:CC:DD:EE:01', 'bad'] });
  assert.equal(tun.active, true);
  assert.deepEqual(tun.excludeIps, ['1.2.3.4/32'], 'the live bypass list is the inner backend’s');
  // the ruleset went to a file and nft read it
  assert.equal(writes.length, 1);
  assert.equal(writes[0][0], '/tmp/irnf-test/irnetfree-nft.conf');
  assert.equal(writes[0][1], net.buildNftRuleset({ lanIf: 'br-lan', macs: ['aa:bb:cc:dd:ee:01'] }));
  assert.deepEqual(lines, [
    'nft -f /tmp/irnf-test/irnetfree-nft.conf',
    'ip -4 rule del pref 8998 lookup main suppress_prefixlength 0',   // idempotent: clear leftovers first
    'ip -6 rule del pref 8998 lookup main suppress_prefixlength 0',
    'ip -4 rule del pref 8999 fwmark 0x1f1e lookup main',
    'ip -6 rule del pref 8999 fwmark 0x1f1e lookup main',
    'ip -4 rule add pref 8998 lookup main suppress_prefixlength 0',   // main-first BEFORE the bypass, both before sing-box
    'ip -6 rule add pref 8998 lookup main suppress_prefixlength 0',
    'ip -4 rule add pref 8999 fwmark 0x1f1e lookup main',
    'ip -6 rule add pref 8999 fwmark 0x1f1e lookup main',
    'ip link show IRNetFree',
    'ip rule show',
    'ip route get 192.168.1.3'                                          // the router's own path to a LAN client
  ]);
  assert.deepEqual(inner.calls[0], ['start', 10808, ['1.2.3.4'], { ipv6: false, strict: false, apps: null, bypassMacs: ['AA:BB:CC:DD:EE:01', 'bad'] }]);
  assert.equal(inner.lang, 'en', 'the language the service set is handed down');
  assert.ok(logs.some(([, l]) => /Gateway up on br-lan.*1 excluded/.test(l)), JSON.stringify(logs));
  // a second start is a no-op while active
  await tun.start(10808, [], [], {});
  assert.equal(inner.calls.filter(c => c[0] === 'start').length, 1);
});

test('start fails at nft: nothing else runs, the error names the step', async () => {
  const { tun, inner, lines } = make({ answers: [[/^nft -f/, new Error('nft: command not found')]] });
  await assert.rejects(tun.start(10808, [], [], {}), /Gateway did not come up \(nft\): nft: command not found/);
  assert.equal(tun.active, false);
  assert.equal(inner.calls.filter(c => c[0] === 'start').length, 0, 'sing-box was never started');
  // rollback still clears what might be there
  assert.ok(lines.includes('ip -4 rule del pref 8999 fwmark 0x1f1e lookup main'));
  assert.ok(lines.includes('nft delete table inet irnetfree'));
});

test('start fails inside sing-box: the table and rules are rolled back', async () => {
  const { tun, inner, lines } = make({ inner: fakeInner({ failStart: true }) });
  await assert.rejects(tun.start(10808, [], [], {}), /\(sing-box\): sing-box exited immediately/);
  assert.equal(tun.active, false);
  assert.deepEqual(inner.calls.map(c => c[0]), ['start', 'stop']);
  assert.equal(lines[lines.length - 1], 'nft delete table inet irnetfree');
  assert.ok(lines.filter(l => l === 'ip -4 rule del pref 8999 fwmark 0x1f1e lookup main').length >= 2, 'cleared before add, and again on rollback');
});

test('verify: no TUN device, or no sing-box rule, is a failure with the rule dump in it', async () => {
  const noLink = make({ answers: [[/^ip link show IRNetFree/, new Error('Device "IRNetFree" does not exist.')]] });
  await assert.rejects(noLink.tun.start(10808, [], [], {}), /\(verify\): Device "IRNetFree" does not exist/);
  assert.deepEqual(noLink.inner.calls.map(c => c[0]), ['start', 'stop']);

  const noRule = make({ answers: [[/^ip rule show/, '0:\tfrom all lookup local\n32766:\tfrom all lookup main\n']] });
  await assert.rejects(noRule.tun.start(10808, [], [], {}), /\(verify\): sing-box laid no policy route[\s\S]*32766/);
  assert.ok(noRule.lines.filter(l => l === 'ip rule show').length >= 2, 'the rules were polled, not read once');
});

test('verify waits for rules that arrive a moment after the device (sing-box lays them late on a slow CPU)', async () => {
  let reads = 0;
  const { tun } = make({ answers: [[/^ip rule show/, '']], verifyWaitMs: 2000 });
  // the third read has the rules; the first two are the window CI fell into
  tun.run = (function (orig) { return async (cmd, args) => {
    if (cmd === 'ip' && args[0] === 'rule') { reads++; return reads >= 3 ? RULES_OK : '0:\tfrom all lookup local\n'; }
    return orig(cmd, args);
  }; })(tun.run);
  await tun.start(10808, [], [], {});
  assert.equal(tun.active, true);
  assert.ok(reads >= 3, `polled ${reads} times`);
});

test('setBypassMacs while active replaces the set and leaves the tunnel alone; while inactive it only remembers', async () => {
  const { tun, inner, lines, writes } = make();
  await tun.setBypassMacs(['aa:bb:cc:dd:ee:02']);
  assert.equal(lines.length, 0, 'nothing runs before the tunnel is up');
  await tun.start(10808, [], [], { bypassMacs: [] });
  const before = inner.calls.length;
  lines.length = 0; writes.length = 0;
  await tun.setBypassMacs(['aa:bb:cc:dd:ee:03', 'AA:BB:CC:DD:EE:03']);
  assert.deepEqual(lines, ['nft -f /tmp/irnf-test/irnetfree-nft.conf']);
  assert.match(writes[0][1], /elements = \{ aa:bb:cc:dd:ee:03 \};/);
  assert.equal(inner.calls.length, before, 'sing-box untouched');
  assert.equal(tun.active, true);
});

test('stop: sing-box first, then the rules and the table; a second stop is a no-op', async () => {
  const { tun, inner, lines } = make();
  await tun.start(10808, [], [], {});
  lines.length = 0;
  await tun.stop();
  assert.equal(tun.active, false);
  assert.deepEqual(tun.excludeIps, []);
  assert.deepEqual(inner.calls.map(c => c[0]), ['start', 'stop']);
  assert.deepEqual(lines, [
    'ip -4 rule del pref 8998 lookup main suppress_prefixlength 0',
    'ip -6 rule del pref 8998 lookup main suppress_prefixlength 0',
    'ip -4 rule del pref 8999 fwmark 0x1f1e lookup main',
    'ip -6 rule del pref 8999 fwmark 0x1f1e lookup main',
    'nft delete table inet irnetfree'
  ]);
  lines.length = 0;
  await tun.stop();
  assert.deepEqual(lines, []);
});

test('verify refuses a gateway that would swallow the router’s own LAN traffic (the v1.13.2 outage)', async () => {
  // what the AC-1304 showed: sing-box’s split ranges in table 2022 catch 192.168.1.x
  const bad = make({ answers: [[/^ip rule show/, RULES_OK], [/^ip route get 192\.168\.1\.3/, '192.168.1.3 dev IRNetFree table 2022 src 172.19.0.1 uid 0\n    cache\n']] });
  await assert.rejects(bad.tun.start(10808, ['1.2.3.4'], [], {}), /\(verify\): the router's own traffic to its LAN \(192\.168\.1\.3\) would enter the tunnel[\s\S]*dev IRNetFree/);
  assert.equal(bad.tun.active, false);
  assert.deepEqual(bad.inner.calls.map(c => c[0]), ['start', 'stop'], 'rolled back, not left running');
  // the healthy answer: br-lan
  const good = make({ answers: [[/^ip rule show/, RULES_OK], [/^ip route get 192\.168\.1\.3/, '192.168.1.3 dev br-lan src 192.168.1.1 uid 0\n    cache\n']] });
  await good.tun.start(10808, ['1.2.3.4'], [], {});
  assert.equal(good.tun.active, true);
  // a LAN with no usable IPv4 has nothing to probe — no route lookup, no false refusal
  const noLan = make({ lan: { device: 'br-lan', address: null, mask: null } });
  await noLan.tun.start(10808, [], [], {});
  assert.equal(noLan.tun.active, true);
  assert.ok(!noLan.lines.some(l => l.startsWith('ip route get')), 'nothing to probe');
});

test('stop keeps going when a delete fails (nothing to delete is the common case)', async () => {
  const { tun, lines } = make({ answers: [
    [/^ip rule show/, RULES_OK],
    [/^ip -4 rule del/, new Error('RTNETLINK answers: No such file or directory')],
    [/^nft delete/, new Error('Error: No such file or directory')]
  ] });
  await tun.start(10808, [], [], {});
  await tun.stop();
  assert.ok(lines.includes('ip -6 rule del pref 8999 fwmark 0x1f1e lookup main'));
  assert.ok(lines.includes('nft delete table inet irnetfree'));
});

test('cleanupSync: the synchronous best effort for process exit, inner first', () => {
  const { tun, inner, lines } = make();
  tun.cleanupSync();
  assert.deepEqual(inner.calls, [['cleanupSync']]);
  assert.deepEqual(lines, [
    'SYNC ip -4 rule del pref 8998 lookup main suppress_prefixlength 0',
    'SYNC ip -6 rule del pref 8998 lookup main suppress_prefixlength 0',
    'SYNC ip -4 rule del pref 8999 fwmark 0x1f1e lookup main',
    'SYNC ip -6 rule del pref 8999 fwmark 0x1f1e lookup main',
    'SYNC nft delete table inet irnetfree'
  ]);
});

test('the pass-throughs the service calls', async () => {
  const { tun } = make();
  assert.equal(tun.isElevated(), true);
  assert.deepEqual(await tun.physicalInterface(), { name: 'eth0', ifIndex: null, gateway: '192.168.1.2' });
  await tun.prepare({ strict: false });   // must not throw
});
