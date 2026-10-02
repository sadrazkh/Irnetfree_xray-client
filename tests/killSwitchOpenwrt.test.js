'use strict';
/**
 * The router's kill switch (v1.16 K1–K6): while the VPN is meant to be on
 * (settings.killSwitch && connectIntent) and the tunnel is not up, LAN
 * devices' forwarded traffic to the internet is rejected — never the excluded
 * devices, LAN↔LAN, replies of inbound connections, or the router's own
 * traffic. Its own nft table (`inet irnetfree_ks`), untouched by the gateway's
 * teardown; applied atomically (`nft -c -f` first); persisted as a snippet
 * `/etc/init.d/irnetfree-ks` replays at boot before any interface is up.
 *
 * The module over a recording `run` and an in-memory fs; the service's wiring
 * over the real module with the gateway fakes.
 */
process.env.IRNETFREE_PLATFORM = 'openwrt';
const test = require('node:test');
const assert = require('node:assert/strict');
const { ksSnippet, createKillSwitch, KS_TABLE } = require('../src/main/killSwitchOpenwrt');
const H = require('./serviceHarness');

process.setMaxListeners(60);
test.after(() => H.cleanupDirs());
const { SERVER, until, sleep, connectedCount } = H;

/* ----------------------------- the snippet ----------------------------- */

test('ksSnippet: the idempotent three-statement header, the bypass set, both families’ private ranges, the reject rule — and nothing that is not a MAC', () => {
  const text = ksSnippet({ bypassMacs: ['AA:BB:CC:DD:EE:01', 'zz:zz:zz:zz:zz:zz', 'aa:bb:cc:dd:ee:ff; flush ruleset', 'aa:bb:cc:dd:ee:02', 'AA:BB:CC:DD:EE:02'], wanDevs: ['pppoe-wan', 'eth0; bad'] });
  const lines = text.split('\n');
  const first = lines.filter(l => !l.startsWith('#')).slice(0, 3);
  assert.deepEqual(first, ['table inet irnetfree_ks', 'delete table inet irnetfree_ks', 'table inet irnetfree_ks {'], 'create-if-missing, delete, recreate: one atomic replace');
  assert.match(text, /set bypass \{ type ether_addr; elements = \{ aa:bb:cc:dd:ee:01, aa:bb:cc:dd:ee:02 \}; \}/, 'lower-cased, deduplicated, junk dropped');
  assert.doesNotMatch(text, /zz:zz|flush ruleset/);
  assert.match(text, /chain pre \{\n\t\ttype filter hook prerouting priority mangle \+ 5; policy accept;\n\t\tether saddr @bypass meta mark set 0x1f1e\n\t\}/);
  assert.match(text, /chain fwd \{\n\t\ttype filter hook forward priority filter - 5; policy accept;/);
  for (const rule of ['ct direction reply accept', 'iifname "IRNetFree" accept', 'oifname "IRNetFree" accept', 'meta mark 0x1f1e accept',
    'ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 255.255.255.255 } accept',
    'ip6 daddr { ::1, fc00::/7, fe80::/10, ff00::/8 } accept',
    'counter reject with icmpx type admin-prohibited']) {
    assert.ok(text.includes('\t\t' + rule + '\n'), 'missing: ' + rule);
  }
  const fwd = text.slice(text.indexOf('chain fwd'));
  assert.ok(fwd.indexOf('ct direction reply accept') < fwd.indexOf('reject'), 'the reject is last');
  assert.ok(fwd.indexOf('meta mark 0x1f1e accept') < fwd.indexOf('reject'));
  assert.match(text, /^# wan devices: pppoe-wan eth0bad$/m, 'the WAN names persisted (sanitised) for whoever needs them later');
  assert.ok(text.endsWith('}\n'));
  // no MACs: the set is declared without elements (an empty `elements = { }` is a syntax error for nft)
  const none = ksSnippet({ bypassMacs: [], wanDevs: [] });
  assert.match(none, /set bypass \{ type ether_addr; \}/);
  assert.doesNotMatch(none, /elements/);
  assert.equal(ksSnippet(), none);
  assert.equal(KS_TABLE, 'inet irnetfree_ks');
});

/* ----------------------------- arm / disarm over fakes ----------------------------- */

function fakeFs() {
  const files = new Map();
  return {
    files,
    writeFileSync: (p, text) => { files.set(p, String(text)); },
    readFileSync: (p) => { if (!files.has(p)) throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' }); return files.get(p); },
    unlinkSync: (p) => { if (!files.delete(p)) throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' }); },
    existsSync: (p) => files.has(p),
    mkdirSync: () => {}
  };
}
function fakeRun(answers = {}) {
  const lines = [];
  const run = async (cmd, args) => {
    const line = [cmd, ...args].join(' ');
    lines.push(line);
    for (const [re, ans] of Object.entries(answers)) {
      if (!new RegExp(re).test(line)) continue;
      const out = typeof ans === 'function' ? ans(line) : ans;
      if (out instanceof Error) throw out;
      return out;
    }
    return '';
  };
  return { run, lines };
}
const make = (answers) => {
  const fs = fakeFs();
  const { run, lines } = fakeRun(answers);
  const ks = createKillSwitch({ run, dataDir: '/etc/irnetfree', fs, tmpDir: '/tmp' });
  return { ks, fs, lines };
};

test('arm: nft -c -f (validate) before nft -f (apply), then the snippet is written for the boot script', async () => {
  const { ks, fs, lines } = make();
  assert.equal(ks.isArmed(), false);
  await ks.arm({ bypassMacs: ['aa:bb:cc:dd:ee:01'], wanDevs: ['eth0'] });
  assert.deepEqual(lines, ['nft -c -f /tmp/irnetfree-ks.nft', 'nft -f /tmp/irnetfree-ks.nft']);
  assert.equal(ks.isArmed(), true);
  assert.equal(fs.files.get('/etc/irnetfree/killswitch.nft'), ksSnippet({ bypassMacs: ['aa:bb:cc:dd:ee:01'], wanDevs: ['eth0'] }));
  assert.equal(fs.files.get('/tmp/irnetfree-ks.nft'), fs.files.get('/etc/irnetfree/killswitch.nft'), 'what nft loaded is what boot replays');
  assert.equal(ks.snippetPath, '/etc/irnetfree/killswitch.nft');
});

test('arm: a snippet nft refuses is never applied and never written; the switch stays disarmed', async () => {
  const { ks, fs, lines } = make({ '^nft -c -f': new Error('/tmp/irnetfree-ks.nft:7:3-10: Error: syntax error, unexpected string') });
  await assert.rejects(ks.arm({ bypassMacs: [] }), /syntax error/);
  assert.deepEqual(lines, ['nft -c -f /tmp/irnetfree-ks.nft'], 'nothing applied');
  assert.equal(fs.files.has('/etc/irnetfree/killswitch.nft'), false, 'nothing for the boot script to replay');
  assert.equal(ks.isArmed(), false);
});

test('disarm: the snippet goes, the table goes; "No such file or directory" from nft (not armed in the kernel) is fine', async () => {
  const { ks, fs, lines } = make({ '^nft delete table': new Error('Error: Could not process rule: No such file or directory\ndelete table inet irnetfree_ks\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^') });
  await ks.arm({ bypassMacs: ['aa:bb:cc:dd:ee:01'] });
  lines.length = 0;
  await ks.disarm();
  assert.deepEqual(lines, ['nft delete table inet irnetfree_ks']);
  assert.equal(fs.files.has('/etc/irnetfree/killswitch.nft'), false);
  assert.equal(ks.isArmed(), false);
  // disarming what is not armed is fine too (a service start with the setting off)
  await ks.disarm();
  assert.equal(ks.isArmed(), false);
  // any other nft failure is reported, and the switch still counts as armed (the table may well still be there)
  const bad = make({ '^nft delete table': new Error('Error: Operation not permitted') });
  await bad.ks.arm({ bypassMacs: [] });
  await assert.rejects(bad.ks.disarm(), /not permitted/);
  assert.equal(bad.ks.isArmed(), true);
});

test('setBypassMacs while armed rewrites the kernel set and the snippet atomically; while disarmed it is nothing', async () => {
  const { ks, fs, lines } = make();
  await ks.setBypassMacs(['aa:bb:cc:dd:ee:09']);
  assert.deepEqual(lines, [], 'nothing to rewrite');
  await ks.arm({ bypassMacs: [], wanDevs: ['eth0'] });
  lines.length = 0;
  await ks.setBypassMacs(['AA:BB:CC:DD:EE:09', 'nope']);
  assert.deepEqual(lines, ['nft -c -f /tmp/irnetfree-ks.nft', 'nft -f /tmp/irnetfree-ks.nft']);
  assert.match(fs.files.get('/etc/irnetfree/killswitch.nft'), /elements = \{ aa:bb:cc:dd:ee:09 \}/);
  assert.match(fs.files.get('/etc/irnetfree/killswitch.nft'), /# wan devices: eth0/, 'the WAN names are kept across a set change');
  assert.deepEqual(ks.bypassMacs(), ['aa:bb:cc:dd:ee:09']);
});

/* ----------------------------- the service's wiring ----------------------------- */

/** A service whose kill switch is the real module over a recording run and an in-memory fs. */
function service(store = {}, extra = {}) {
  const fs = fakeFs();
  const { run, lines } = fakeRun(extra.answers || {});
  const s = H.start(store, { killSwitch: ({ dataDir }) => createKillSwitch({ run, dataDir, fs, tmpDir: '/tmp' }) });
  return Object.assign(s, { ks: { fs, lines } });
}
const armed = (s) => s.ks.lines.filter(l => l === 'nft -f /tmp/irnetfree-ks.nft').length;
const disarmed = (s) => s.ks.lines.filter(l => l === 'nft delete table inet irnetfree_ks').length;
const snippetThere = (s) => s.ks.fs.files.has(require('node:path').join(s.dir, 'killswitch.nft'));
const ksEvents = (s) => s.events.filter(([ch]) => ch === 'killswitch').map(([, p]) => p);

test('K2: the setting on + a connect → armed; sing-box dying → still armed and blocking until the rebuild; the user’s disconnect → disarmed', async (t) => {
  const s = service({ settings: { killSwitch: true } }, { timing: undefined });
  t.after(() => s.service.shutdown());
  await sleep(50);
  assert.equal(armed(s), 0, 'no intent yet: nothing armed at start');
  const d0 = disarmed(s);   // the start clears whatever a killed run left (a disarm with nothing armed)
  assert.deepEqual(s.service.connSnapshot().killSwitch, { enabled: true, armed: false, blocking: false });

  await s.service.invoke('connect', SERVER.id);
  assert.equal(armed(s), 1, 'armed with the intent, before the gateway came up');
  assert.ok(s.ks.lines.indexOf('nft -c -f /tmp/irnetfree-ks.nft') < s.ks.lines.indexOf('nft -f /tmp/irnetfree-ks.nft'));
  assert.ok(s.state.commands.indexOf('nft -f /tmp/irnetfree-ks.nft') === -1, 'its own runner, its own table');
  assert.ok(snippetThere(s));
  assert.deepEqual(s.service.connSnapshot().killSwitch, { enabled: true, armed: true, blocking: false });
  assert.ok(s.logs.some(l => /Kill switch armed \(connect\)/.test(l.line)), JSON.stringify(s.logs.map(l => l.line)));
  // armed BEFORE the gateway came up: that gap is blocked (the point of arming first), then the gateway lifts it
  const armEvent = ksEvents(s).find(e => e.armed);
  assert.deepEqual(armEvent, { engaged: true, router: true, enabled: true, armed: true, blocking: true });
  assert.deepEqual(ksEvents(s).at(-1), { engaged: false, router: true, enabled: true, armed: true, blocking: false });

  // the tunnel dies: the table stays (the gateway's teardown never touches it), status says blocking, the LAN is told
  s.state.gatewayFails = true;
  s.state.inners.find(i => i.active).crash();
  await until(() => s.service.connSnapshot().killSwitch.blocking === true, 'blocking');
  assert.equal(disarmed(s) - d0, 0, 'never disarmed by a drop');
  assert.ok(ksEvents(s).some(e => e.engaged === true && e.blocking === true));
  assert.ok(s.logs.some(l => l.level === 'warn' && /Kill switch: the tunnel is down — LAN internet is blocked/.test(l.line)));
  await until(() => s.statuses.filter(x => x.state === 'reconnecting').length >= 2, 'the recovery retrying', 8000);
  assert.deepEqual(s.service.connSnapshot().killSwitch, { enabled: true, armed: true, blocking: true }, 'blocking through the retries');
  assert.equal(disarmed(s) - d0, 0);
  s.state.gatewayFails = false;
  await until(() => connectedCount(s) === 2, 'the rebuild', 8000);
  assert.deepEqual(s.service.connSnapshot().killSwitch, { enabled: true, armed: true, blocking: false });
  assert.ok(ksEvents(s).at(-1).blocking === false);
  assert.ok(s.logs.some(l => /Kill switch: the tunnel is back — LAN internet restored/.test(l.line)));
  assert.equal(armed(s), 1, 'armed once; a rebuild does not re-arm');

  // the user turns the VPN off: disarmed BEFORE the gateway goes down, so the LAN is never blocked by the teardown
  await s.service.invoke('disconnect');
  assert.equal(disarmed(s) - d0, 1);
  assert.ok(!snippetThere(s), 'nothing for the boot script to replay');
  assert.deepEqual(s.service.connSnapshot().killSwitch, { enabled: true, armed: false, blocking: false });
  const stopIdx = s.state.events.lastIndexOf('xray:stop');
  assert.ok(s.ks.lines.length && s.logs.some(l => /Kill switch disarmed \(disconnect\)/.test(l.line)));
  assert.ok(ksEvents(s).at(-1).armed === false && ksEvents(s).at(-1).engaged === false);
  assert.ok(stopIdx >= 0);
});

test('K2: a server switch keeps it armed (blocking across the gap); the setting turned off while connected disarms; turned on while connected arms; the bypass list changes the set live', async (t) => {
  const s = service({ settings: { killSwitch: true } });
  t.after(() => s.service.shutdown());
  await sleep(50);
  const d0 = s.ks.lines.filter(l => l === 'nft delete table inet irnetfree_ks').length;   // the start's clearing
  const disarmed = () => s.ks.lines.filter(l => l === 'nft delete table inet irnetfree_ks').length - d0;
  await s.service.invoke('connect', SERVER.id);
  assert.equal(armed(s), 1);
  await s.service.invoke('connect', H.SERVER_B.id);
  assert.equal(disarmed(s), 0, 'a switch is not the user turning the VPN off');
  assert.equal(armed(s), 1);
  assert.deepEqual(s.service.connSnapshot().killSwitch, { enabled: true, armed: true, blocking: false });

  await s.service.invoke('settings:set', { lanBypassMacs: ['AA:BB:CC:DD:EE:07'] });
  assert.equal(armed(s), 2, 'the set rewritten (atomic reload)');
  assert.match(s.ks.fs.files.get(require('node:path').join(s.dir, 'killswitch.nft')), /elements = \{ aa:bb:cc:dd:ee:07 \}/);

  await s.service.invoke('settings:set', { killSwitch: false });
  assert.equal(disarmed(s), 1);
  assert.deepEqual(s.service.connSnapshot().killSwitch, { enabled: false, armed: false, blocking: false });
  await s.service.invoke('settings:set', { killSwitch: true });
  assert.equal(armed(s), 3, 'armed again: the VPN is on');
  assert.deepEqual(s.service.connSnapshot().killSwitch, { enabled: true, armed: true, blocking: false });
  // the setting on with nothing connected: nothing to arm
  await s.service.invoke('disconnect');
  assert.equal(disarmed(s), 2);
  await s.service.invoke('settings:set', { killSwitch: false });
  await s.service.invoke('settings:set', { killSwitch: true });
  assert.equal(armed(s), 3, 'no intent, no arm');
});

test('K3: a new service started with the intent set and the setting on arms BEFORE the boot connect starts; with the setting off it clears a leftover table', async (t) => {
  const s = service({ connectIntent: SERVER.id, settings: { killSwitch: true, autoConnect: true } });
  t.after(() => s.service.shutdown());
  await until(() => connectedCount(s) === 1, 'the boot connect');
  assert.equal(armed(s), 1);
  // the arm happened before the gateway (and the core) of the boot connect
  const order = [];
  s.ks.lines.forEach((l) => { if (l === 'nft -f /tmp/irnetfree-ks.nft') order.push('ks'); });
  assert.ok(s.logs.findIndex(l => /Kill switch armed \(start\)/.test(l.line)) >= 0, JSON.stringify(s.logs.map(l => l.line)));
  assert.ok(s.logs.findIndex(l => /Kill switch armed \(start\)/.test(l.line)) < s.logs.findIndex(l => /Gateway up on/.test(l.line)), 'armed before the gateway came up');
  assert.deepEqual(s.service.connSnapshot().killSwitch, { enabled: true, armed: true, blocking: false });

  const off = service({ connectIntent: SERVER.id, settings: { killSwitch: false, autoConnect: false } });
  t.after(() => off.service.shutdown());
  await sleep(80);
  assert.equal(armed(off), 0);
  assert.equal(disarmed(off), 1, 'whatever a killed run or the boot script left is cleared');
  assert.ok(!off.logs.some(l => /Kill switch disarmed/.test(l.line)), 'silently: nothing was armed');
});

test('K3: an arm that fails (nft refuses the snippet) is logged, the connect goes on, and the switch reports not armed', async (t) => {
  const s = service({ settings: { killSwitch: true } }, { answers: { '^nft -c -f': new Error('nft: command not found') } });
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  assert.equal(connectedCount(s), 1, 'the connect is not refused for it');
  assert.ok(s.logs.some(l => l.level === 'error' && /Kill switch: connect failed: nft: command not found/.test(l.line)), JSON.stringify(s.logs.map(l => l.line)));
  assert.deepEqual(s.service.connSnapshot().killSwitch, { enabled: true, armed: false, blocking: false });
});
