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

/**
 * A fake TunSingbox: records calls; `failStart` makes start() throw. Like the
 * real one, start() arms a fresh `exited` promise; `crash()` is sing-box dying
 * on its own, stop() the exit we asked for. The IRNetFree device exists while
 * the process runs — or, with `linger`, after it (a sing-box that ignores
 * SIGTERM); `proc.kill('SIGKILL')` ends a lingering one.
 */
function fakeInner({ available = true, failStart = false } = {}) {
  const inner = {
    calls: [],
    kills: [],
    active: false,
    linger: false,
    proc: null,
    exited: Promise.resolve(),
    excludeIps: [],
    interfaceName: 'IRNetFree',
    dnsPeer: '172.19.0.2',
    dnsPeer6: 'fdfe:dcba:9876::2',
    lang: 'fa',
    isAvailable: () => available,
    isElevated: () => true,
    prepare: async () => {},
    physicalInterface: async () => ({ name: 'eth0', ifIndex: null, gateway: '192.168.1.2' }),
    get linkUp() { return this.active || this.linger; },
    async start(socksPort, bypass, dns, opts) {
      this.calls.push(['start', socksPort, bypass, opts]);
      if (failStart) throw new Error('sing-box exited immediately');
      this.exited = new Promise((resolve) => { this.gone = resolve; });
      this.proc = { kill: (sig) => { this.kills.push(sig); if (sig === 'SIGKILL') this.linger = false; } };
      this.active = true; this.excludeIps = ['1.2.3.4/32'];
    },
    crash(info = { code: null, signal: 'SIGKILL' }) { this.active = false; this.proc = null; this.gone(info); },
    async stop() {
      this.calls.push(['stop']);
      const was = this.active;
      this.active = false; this.excludeIps = []; this.proc = this.linger ? this.proc : null;
      if (was && this.gone) this.gone({ code: 0, signal: 'SIGTERM' });
    },
    cleanupSync() { this.calls.push(['cleanupSync']); }
  };
  return inner;
}

/**
 * A fake command runner: `answers` maps a regex over "cmd args…" to stdout,
 * an Error, or a function of the line returning either.
 */
function fakeRun(answers = []) {
  const lines = [];
  const run = async (cmd, args) => {
    const line = [cmd, ...args].join(' ');
    lines.push(line);
    for (const [re, ans] of answers) {
      if (!re.test(line)) continue;
      const out = typeof ans === 'function' ? ans(line) : ans;
      if (out instanceof Error) throw out;
      return out;
    }
    return '';
  };
  return { run, lines };
}

const NO_LINK = () => new Error('Device "IRNetFree" does not exist.');

const RULES_OK = '0:\tfrom all lookup local\n9000:\tfrom all to 172.19.0.0/30 lookup 2022\n9002:\tnot from all iif lo lookup 2022\n32766:\tfrom all lookup main\n';
/** What the kernel says to `ip rule del pref N` when there is none: the deletion loop stops on it. */
const NO_RULE = [/^ip -[46] rule del /, new Error('RTNETLINK answers: No such file or directory')];

function make(opts = {}) {
  const inner = opts.inner || fakeInner();
  // the device is there exactly while the fake says so, unless a test overrides it
  const link = [/^ip link show IRNetFree/, () => (inner.linkUp ? '' : NO_LINK())];
  const { run, lines } = fakeRun([...(opts.answers || [[/^ip rule show/, RULES_OK]]), link, NO_RULE]);
  const writes = [];
  const logs = [];
  const exits = [];
  const tun = new TunOpenwrt({
    inner, run,
    runSync: (cmd, args) => {
      const line = [cmd, ...args].join(' ');
      lines.push('SYNC ' + line);
      if (/ rule del /.test(line)) throw new Error('No such file or directory');
      if (/^ip link show IRNetFree/.test(line) && !inner.linkUp) throw NO_LINK();
    },
    writeFile: (p, text) => { writes.push([p, text]); },
    lanStatus: async () => (opts.lan || { device: 'br-lan', address: '192.168.1.1', mask: 24 }),
    which: (name) => (opts.which ? opts.which(name) : true),
    onLog: (line, level) => logs.push([level, line]),
    onUnexpectedExit: (err) => exits.push(err),
    lang: 'en', tmpDir: '/tmp/irnf-test',
    verifyWaitMs: opts.verifyWaitMs || 300,    // the real 15s is for an emulated CPU; the fakes answer at once
    linkWaitMs: opts.linkWaitMs || 150
  });
  return { tun, inner, lines, writes, logs, exits };
}

const tick = () => new Promise((r) => setImmediate(r));

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
    'ip -4 rule del pref 8998',                                            // idempotent: clear leftovers first (by preference, any selectors)
    'ip -6 rule del pref 8998',
    'ip -4 rule del pref 8999',
    'ip -6 rule del pref 8999',
    'ip -4 rule add not dport 53 pref 8998 lookup main suppress_prefixlength 0',   // main-first BEFORE the bypass, both before sing-box; DNS never shortcut
    'ip -6 rule add not dport 53 pref 8998 lookup main suppress_prefixlength 0',
    'ip -4 rule add pref 8999 fwmark 0x1f1e lookup main',
    'ip -6 rule add pref 8999 fwmark 0x1f1e lookup main',
    'ip link show IRNetFree',
    'ip rule show',
    'ip route get 192.168.1.3'                                             // the router's own path to a LAN client
  ]);
  assert.deepEqual(inner.calls[0], ['start', 10808, ['1.2.3.4'], { ipv6: false, strict: false, apps: null, bypassMacs: ['AA:BB:CC:DD:EE:01', 'bad'] }],
    'the options are passed through untouched (no gso key: sing-box 1.12 refuses it, and enables GSO itself)');
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
  assert.ok(lines.includes('ip -4 rule del pref 8999'));
  assert.ok(lines.includes('nft delete table inet irnetfree'));
});

test('start fails inside sing-box: the table and rules are rolled back', async () => {
  const { tun, inner, lines } = make({ inner: fakeInner({ failStart: true }) });
  await assert.rejects(tun.start(10808, [], [], {}), /\(sing-box\): sing-box exited immediately/);
  assert.equal(tun.active, false);
  assert.deepEqual(inner.calls.map(c => c[0]), ['start', 'stop']);
  assert.equal(lines[lines.length - 1], 'nft delete table inet irnetfree');
  assert.ok(lines.filter(l => l === 'ip -4 rule del pref 8999').length >= 2, 'cleared before add, and again on rollback');
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

test('stop: sing-box first, then — once its device is gone — the rules and the table; a second stop is a no-op', async () => {
  const { tun, inner, lines } = make();
  await tun.start(10808, [], [], {});
  lines.length = 0;
  await tun.stop();
  assert.equal(tun.active, false);
  assert.deepEqual(tun.excludeIps, []);
  assert.deepEqual(inner.calls.map(c => c[0]), ['start', 'stop']);
  assert.deepEqual(lines, [
    'ip link show IRNetFree',                 // gone: only now may 8998 go
    'ip -4 rule del pref 8998',
    'ip -6 rule del pref 8998',
    'ip -4 rule del pref 8999',
    'ip -6 rule del pref 8999',
    'nft delete table inet irnetfree'
  ]);
  lines.length = 0;
  await tun.stop();
  assert.deepEqual(lines, []);
});

test('deleting by preference repeats until the kernel has none left — a doubled or older rule cannot survive', async () => {
  let dels = 0;
  const { tun, lines } = make({ answers: [[/^ip rule show/, RULES_OK], [/^ip -4 rule del pref 8998/, '']] });
  // the -4 8998 deletion "succeeds" every time in this fake → bounded at 4
  await tun.start(10808, [], [], {});
  dels = lines.filter(l => l === 'ip -4 rule del pref 8998').length;
  assert.equal(dels, 4, `bounded: ${dels}`);
  assert.equal(lines.filter(l => l === 'ip -6 rule del pref 8998').length, 1, 'the one that says "none" stops at once');
});

test('the QUIC refusal follows the setting, live, without touching sing-box', async () => {
  const { tun, inner, writes } = make();
  await tun.start(10808, [], [], { blockQuic: true });
  assert.match(writes[writes.length - 1][1], /udp dport 443 counter reject/);
  const calls = inner.calls.length;
  await tun.setBlockQuic(false);
  assert.doesNotMatch(writes[writes.length - 1][1], /dport 443/);
  await tun.setBlockQuic(true);
  assert.match(writes[writes.length - 1][1], /udp dport 443 counter reject/);
  assert.equal(inner.calls.length, calls, 'sing-box untouched');
  // off by default
  const plain = make();
  await plain.tun.start(10808, [], [], {});
  assert.doesNotMatch(plain.writes[0][1], /dport 443/);
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
  assert.ok(lines.includes('ip -6 rule del pref 8999'));
  assert.ok(lines.includes('nft delete table inet irnetfree'));
});

test('cleanupSync: the synchronous best effort for process exit, inner first, the rules once the device is gone', async () => {
  const { tun, inner, lines } = make();
  await tun.start(10808, [], [], {});
  // what the real inner's cleanupSync does on Linux: SIGTERM — the process then exits
  inner.cleanupSync = function () { this.calls.push(['cleanupSync']); this.active = false; };
  lines.length = 0;
  tun.cleanupSync();
  assert.deepEqual(inner.calls.map(c => c[0]), ['start', 'cleanupSync']);
  assert.deepEqual(lines, [
    'SYNC ip link show IRNetFree',
    'SYNC ip -4 rule del pref 8998',
    'SYNC ip -6 rule del pref 8998',
    'SYNC ip -4 rule del pref 8999',
    'SYNC ip -6 rule del pref 8999',
    'SYNC nft delete table inet irnetfree'
  ]);
  // an instance that never laid anything has nothing to clean — and must not
  // sit out the device wait while ANOTHER instance's sing-box is still up
  const idle = make();
  idle.tun.cleanupSync();
  assert.deepEqual(idle.lines, []);
});

test('the inner sing-box is built WITHOUT the caller’s onUnexpectedExit — this class reports the exit, once', () => {
  let called = 0;
  const tun = new TunOpenwrt({ onUnexpectedExit: () => { called++; }, run: async () => '', runSync: () => {} });
  assert.notEqual(tun.inner.onUnexpectedExit, tun.onUnexpectedExit);
  tun.inner.onUnexpectedExit(new Error('x'));
  assert.equal(called, 0, 'a pass-through would fire twice once TunSingbox reports its own exits');
});

test('sing-box dying on its own: the gateway is no longer active and the service is told, once, with the reason', async () => {
  const { tun, inner, exits, logs } = make();
  await tun.start(10808, [], [], {});
  assert.equal(tun.active, true);
  inner.crash({ code: null, signal: 'SIGKILL' });
  await tick();
  assert.equal(tun.active, false, 'active follows the inner’s liveness');
  assert.deepEqual(tun.excludeIps, []);
  assert.equal(exits.length, 1);
  assert.match(exits[0].message, /SIGKILL/);
  assert.ok(logs.some(([lvl, l]) => lvl === 'error' && /sing-box exited on its own/.test(l)), JSON.stringify(logs));
});

test('an exit we asked for is never reported — not during stop, not late, not from a previous run', async () => {
  const { tun, inner, exits } = make();
  await tun.start(10808, [], [], {});
  const first = inner.gone;
  await tun.stop();
  await tick();
  assert.equal(exits.length, 0, 'stop');
  await tun.start(10808, [], [], {});
  first({ code: 0, signal: 'SIGTERM' });   // the old process's exit, arriving after the restart
  await tick();
  assert.equal(exits.length, 0, 'a late exit of the previous run');
  assert.equal(tun.active, true);
  // a failed start's rollback is ours too
  const bad = make({ answers: [[/^ip rule show/, RULES_OK], [/^ip route get/, '192.168.1.3 dev IRNetFree table 2022\n']] });
  await assert.rejects(bad.tun.start(10808, [], [], {}));
  await tick();
  assert.equal(bad.exits.length, 0, 'rollback');
});

test('stop after sing-box died still clears our rules and table (its device went with it)', async () => {
  const { tun, inner, lines } = make();
  await tun.start(10808, [], [], {});
  inner.crash();
  await tick();
  lines.length = 0;
  await tun.stop();
  assert.ok(lines.includes('ip -4 rule del pref 8998'), lines.join('\n'));
  assert.ok(lines.includes('ip -6 rule del pref 8999'));
  assert.equal(lines[lines.length - 1], 'nft delete table inet irnetfree', 'the QUIC refusal must not outlive the gateway');
});

test('rule 8998 is never deleted while the IRNetFree device still exists (the v1.13.2 outage under a live table 2022)', async () => {
  // a sing-box that outlives SIGTERM: SIGKILL, then the rules
  const slow = make();
  await slow.tun.start(10808, [], [], {});
  slow.inner.linger = true;
  slow.lines.length = 0;
  await slow.tun.stop();
  assert.deepEqual(slow.inner.kills, ['SIGKILL']);
  const firstDel = slow.lines.indexOf('ip -4 rule del pref 8998');
  assert.ok(firstDel > 0, slow.lines.join('\n'));
  assert.equal(slow.lines[firstDel - 1], 'ip link show IRNetFree', 'the last look before the delete saw no device');

  // a device that will not go: our rules stay (harmless without sing-box), the table goes, and it is said
  const stuck = make();
  await stuck.tun.start(10808, [], [], {});
  stuck.inner.linger = true;
  stuck.inner.proc = null;         // nothing of ours left to kill
  stuck.inner.kills.length = 0;
  stuck.lines.length = 0;
  await stuck.tun.stop();
  assert.ok(!stuck.lines.some(l => / rule del /.test(l)), stuck.lines.join('\n'));
  assert.ok(stuck.lines.includes('nft delete table inet irnetfree'));
  assert.ok(stuck.logs.some(([lvl, l]) => lvl === 'error' && /IRNetFree device is still there/.test(l)), JSON.stringify(stuck.logs));
  // ...and the next stop, once it is gone, finishes the job
  stuck.inner.linger = false;
  stuck.lines.length = 0;
  await stuck.tun.stop();
  assert.ok(stuck.lines.includes('ip -4 rule del pref 8998'));

  // the exit hook keeps the same rule
  const exitHook = make();
  await exitHook.tun.start(10808, [], [], {});
  exitHook.inner.linger = true;
  exitHook.inner.proc = null;
  exitHook.lines.length = 0;
  exitHook.tun.cleanupSync();
  assert.ok(!exitHook.lines.some(l => / rule del /.test(l)), exitHook.lines.join('\n'));
});

test('a rollback removes 8998 only after sing-box and its device are gone', async () => {
  const bad = make({ answers: [[/^ip rule show/, RULES_OK], [/^ip route get 192\.168\.1\.3/, '192.168.1.3 dev IRNetFree table 2022\n']] });
  await assert.rejects(bad.tun.start(10808, ['1.2.3.4'], [], {}), /would enter the tunnel/);
  const probe = bad.lines.indexOf('ip route get 192.168.1.3');
  const after = bad.lines.slice(probe + 1);
  assert.equal(after[0], 'ip link show IRNetFree');
  assert.equal(after[1], 'ip -4 rule del pref 8998');
  assert.deepEqual(bad.inner.calls.map(c => c[0]), ['start', 'stop']);
});

test('clearLeftovers: what a killed service left (rules, table) goes at the next start — only with no device', async () => {
  const { tun, lines } = make();
  assert.equal(await tun.clearLeftovers(), true);
  assert.deepEqual(lines, [
    'ip link show IRNetFree',
    'ip -4 rule del pref 8998', 'ip -6 rule del pref 8998', 'ip -4 rule del pref 8999', 'ip -6 rule del pref 8999',
    'nft delete table inet irnetfree'
  ]);
  const held = make();
  held.inner.linger = true;      // a sing-box nobody could stop still holds the device
  assert.equal(await held.tun.clearLeftovers(), false);
  assert.ok(!held.lines.some(l => / rule del /.test(l)));
});

test('the pass-throughs the service calls', async () => {
  const { tun } = make();
  assert.equal(tun.isElevated(), true);
  assert.deepEqual(await tun.physicalInterface(), { name: 'eth0', ifIndex: null, gateway: '192.168.1.2' });
  await tun.prepare({ strict: false });   // must not throw
});
