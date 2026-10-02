'use strict';
/**
 * Cloudflare Tunnel's pure parts (src/server/remote/cloudflared.js): the
 * bypass list, the dnsmasq drop-in, the UCI batch (the token on stdin, never
 * in argv), the fallback's spawn shape, and the driver against a fake `run`.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const cf = require('../src/server/remote/cloudflared');

test('the bypass list is Cloudflare\'s published tunnel edge: both /24s, both IPv6 ranges, the edge names — and never 1.1.1.1', () => {
  const b = cf.bypassList();
  assert.deepEqual(b.cidrs, ['198.41.192.0/24', '198.41.200.0/24', '2606:4700:a0::/123', '2606:4700:a8::/123']);
  for (const h of ['region1.v2.argotunnel.com', 'region2.v2.argotunnel.com', 'h2.cftunnel.com', 'quic.cftunnel.com']) assert.ok(b.hosts.includes(h), h);
  assert.ok(!b.cidrs.some((c) => c.startsWith('1.1.1.1')) && !b.hosts.includes('one.one.one.one'));
  const src = require('node:fs').readFileSync(require.resolve('../src/server/remote/cloudflared'), 'utf8');
  assert.match(src, /developers\.cloudflare\.com\/cloudflare-one\/connections\/connect-networks\/configure-tunnels\/tunnel-with-firewall\//, 'the docs URL is cited');
  // a fresh copy each time: nobody can edit the shared list
  b.cidrs.push('0.0.0.0/0');
  assert.equal(cf.bypassList().cidrs.length, 4);
});

test('the dnsmasq drop-in names every edge domain for every direct resolver, and nothing else', () => {
  const text = cf.dnsmasqDropIn(['178.22.122.100', '185.51.200.2', 'not an ip']);
  const lines = text.split('\n').filter((l) => l && !l.startsWith('#'));
  assert.deepEqual(lines, [
    'server=/argotunnel.com/178.22.122.100', 'server=/argotunnel.com/185.51.200.2',
    'server=/cftunnel.com/178.22.122.100', 'server=/cftunnel.com/185.51.200.2'
  ]);
  assert.ok(text.endsWith('\n'));
  assert.equal(cf.DROP_IN, '/tmp/dnsmasq.d/irnetfree-cloudflared.conf');
});

test('the drop-in binds every server line to the WAN device when there is one — the in-country resolvers are in the whole-LAN tunnel since v1.16.1', () => {
  // dnsmasq's query (its own user) to them would ride the tunnel, where the
  // port-53 hijack refuses SRV — cloudflared's edge discovery — and the DoT
  // fallback at 1.1.1.1:853 rides the tunnel too: dead with the VPN. `@<dev>`
  // is SO_BINDTODEVICE, which skips table 2022 like the core's bound dials.
  const lines = (t) => t.split('\n').filter((l) => l && !l.startsWith('#'));
  assert.deepEqual(lines(cf.dnsmasqDropIn(['178.22.122.100', '2001:db8::53'], 'wan')), [
    'server=/argotunnel.com/178.22.122.100@wan', 'server=/argotunnel.com/2001:db8::53@wan',
    'server=/cftunnel.com/178.22.122.100@wan', 'server=/cftunnel.com/2001:db8::53@wan'
  ]);
  assert.deepEqual(lines(cf.dnsmasqDropIn(['178.22.122.100'], 'pppoe-wan')), ['server=/argotunnel.com/178.22.122.100@pppoe-wan', 'server=/cftunnel.com/178.22.122.100@pppoe-wan']);
  // no device known (no WAN yet), or a name that is not one: the plain lines, as before
  for (const dev of [null, '', 'bad name', 'a/b', 'x'.repeat(16)]) {
    assert.deepEqual(lines(cf.dnsmasqDropIn(['178.22.122.100'], dev)), ['server=/argotunnel.com/178.22.122.100', 'server=/cftunnel.com/178.22.122.100'], String(dev));
  }
});

test('apply on writes the drop-in bound to the device the service names (directDevice)', async () => {
  const { run } = fakeRun();
  const fsImpl = fakeFs({ '/usr/bin/cloudflared': '' });
  const d = cf.createCloudflared({ run, fsImpl, service: { directResolvers: () => ['178.22.122.100'], directDevice: () => 'wan' } });
  await d.apply({ enabled: true, token: 'x'.repeat(50) });
  assert.equal(fsImpl.files[cf.DROP_IN], cf.dnsmasqDropIn(['178.22.122.100'], 'wan'));
  assert.match(fsImpl.files[cf.DROP_IN], /^server=\/argotunnel\.com\/178\.22\.122\.100@wan$/m);
});

test('a drop-in written before the WAN had a device (a boot) is bound once one appears — rechecked while on, dnsmasq restarted only on a change, never after off', async () => {
  const { run, calls } = fakeRun();
  const fsImpl = fakeFs({ '/usr/bin/cloudflared': '' });
  let dev = null;
  let resolvers = ['178.22.122.100'];
  const ticks = [];
  const timers = { setInterval: (fn, ms) => { ticks.push({ fn, ms, live: true }); return ticks.length; }, clearInterval: (id) => { if (ticks[id - 1]) ticks[id - 1].live = false; } };
  const logs = [];
  const d = cf.createCloudflared({ run, fsImpl, timers, log: (l, lv) => logs.push(`${lv || 'info'}: ${l}`), service: { directResolvers: () => resolvers, directDevice: () => dev } });
  await d.apply({ enabled: true, token: 'x'.repeat(50) });
  assert.equal(fsImpl.files[cf.DROP_IN], cf.dnsmasqDropIn(['178.22.122.100']), 'no device yet: the plain lines');
  assert.equal(ticks.length, 1);
  assert.equal(ticks[0].ms, 60000);
  const restarts = () => calls.filter((c) => c.cmd === '/etc/init.d/dnsmasq' && c.args[0] === 'restart').length;
  const before = restarts();
  await ticks[0].fn();
  assert.equal(restarts(), before, 'nothing changed: dnsmasq is left alone');
  dev = 'pppoe-wan';
  await ticks[0].fn();
  assert.equal(fsImpl.files[cf.DROP_IN], cf.dnsmasqDropIn(['178.22.122.100'], 'pppoe-wan'));
  assert.equal(restarts(), before + 1);
  assert.ok(logs.some((l) => /^info: cloudflared: edge discovery .*pppoe-wan/.test(l)), logs.join('\n'));
  // the device unknown again for a moment (the WAN redialing): the binding stays
  dev = null;
  await ticks[0].fn();
  assert.equal(fsImpl.files[cf.DROP_IN], cf.dnsmasqDropIn(['178.22.122.100'], 'pppoe-wan'));
  assert.equal(restarts(), before + 1);
  // the direct resolvers change (a routing mode with others): rewritten
  resolvers = ['185.51.200.2'];
  await ticks[0].fn();
  assert.equal(fsImpl.files[cf.DROP_IN], cf.dnsmasqDropIn(['185.51.200.2'], 'pppoe-wan'));
  assert.equal(restarts(), before + 2);
  await d.apply({ enabled: false, token: '' });
  assert.equal(ticks[0].live, false, 'off ends the recheck');
  assert.ok(!(cf.DROP_IN in fsImpl.files));
  // a second on does not leave two rechecks running
  await d.apply({ enabled: true, token: 'x'.repeat(50) });
  await d.apply({ enabled: true, token: 'x'.repeat(50) });
  assert.equal(ticks.filter((x) => x.live).length, 1);
});

test('the UCI batch: enabled, the token, protocol http2, one commit; off clears enabled and keeps the token out', () => {
  const on = cf.uciBatch({ section: 'config', token: 'eyJhIjoiMTIzIn0', enabled: true });
  assert.equal(on, "set cloudflared.config.enabled='1'\nset cloudflared.config.token='eyJhIjoiMTIzIn0'\nset cloudflared.config.protocol='http2'\ncommit cloudflared\n");
  const off = cf.uciBatch({ section: 'config', token: null, enabled: false });
  assert.equal(off, "set cloudflared.config.enabled='0'\nset cloudflared.config.protocol='http2'\ncommit cloudflared\n");
  assert.equal(cf.uciBatch({ section: 'cfg0', token: "a'b", enabled: true }).includes("token='ab'"), true, 'a quote cannot break out of the value');
  assert.equal(cf.sectionOf("cloudflared.config=cloudflared\ncloudflared.config.enabled='0'\n"), 'config');
  assert.equal(cf.sectionOf("cloudflared.main=cloudflared\n"), 'main');
  assert.equal(cf.sectionOf(''), 'config');
});

test('the spawn shape of the fallback: the token only in the environment, --protocol http2, --no-autoupdate', () => {
  const r = cf.runArgs();
  assert.equal(r.cmd, '/usr/bin/cloudflared');
  assert.deepEqual(r.args, ['tunnel', '--no-autoupdate', '--protocol', 'http2', 'run']);
  assert.equal(r.envKey, 'TUNNEL_TOKEN');
  assert.ok(!r.args.some((a) => /token/i.test(a)));
});

test('a tunnel token looks like a long base64 string', () => {
  assert.equal(cf.isTunnelToken('eyJhIjoiYWJjZGVmMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODkiLCJ0IjoiMTIzIn0='), true);
  assert.equal(cf.isTunnelToken('short'), false);
  assert.equal(cf.isTunnelToken('has spaces '.repeat(5)), false);
  assert.equal(cf.isTunnelToken(42), false);
});

function fakeRun(answers = {}) {
  const calls = [];
  const run = async (cmd, args, opts = {}) => {
    calls.push({ cmd, args, input: opts.input || null });
    const key = cmd + ' ' + args.join(' ');
    const a = Object.entries(answers).find(([k]) => key.startsWith(k));
    return a ? a[1] : { code: 0, stdout: '', stderr: '' };
  };
  return { run, calls };
}
function fakeFs(files = {}) {
  return {
    files,
    existsSync: (p) => p in files,
    writeFileSync: (p, data) => { files[p] = String(data); },
    readFileSync: (p) => { if (!(p in files)) throw new Error('ENOENT ' + p); return files[p]; },
    readdirSync: (dir) => Object.keys(files).filter((p) => p.startsWith(dir + '/')).map((p) => p.slice(dir.length + 1)).filter((n) => !n.includes('/')),
    unlinkSync: (p) => { delete files[p]; },
    mkdirSync: () => {}
  };
}

test('the drop-in dirs come from dnsmasq\'s generated config: 23.05\'s /tmp/dnsmasq.d, 24.10\'s per-instance dir; 23.05\'s when there is none', () => {
  const none = fakeFs({});
  assert.deepEqual(cf.dnsmasqConfDirs(none), ['/tmp/dnsmasq.d']);
  const v23 = fakeFs({ '/var/etc/dnsmasq.conf.cfg01411c': 'conf-file=/etc/dnsmasq.conf\nconf-dir=/tmp/dnsmasq.d\n' });
  assert.deepEqual(cf.dnsmasqConfDirs(v23), ['/tmp/dnsmasq.d']);
  const v24 = fakeFs({ '/var/etc/dnsmasq.conf.cfg01411c': 'conf-file=/etc/dnsmasq.conf\nconf-dir=/tmp/dnsmasq.cfg01411c.d\nconf-file=/usr/share/dnsmasq/rfc6761.conf\n', '/var/etc/dnsmasq.conf.guest': 'conf-dir=/tmp/dnsmasq.guest.d,*.conf\n', '/var/etc/other.conf': 'conf-dir=/nope\n' });
  assert.deepEqual(cf.dnsmasqConfDirs(v24), ['/tmp/dnsmasq.cfg01411c.d', '/tmp/dnsmasq.guest.d']);
});

test('apply on writes the drop-in into every dir dnsmasq reads (24.10 shape), apply off removes them all', async () => {
  const { run } = fakeRun();
  const fsImpl = fakeFs({ '/usr/bin/cloudflared': '', '/var/etc/dnsmasq.conf.cfg01411c': 'conf-dir=/tmp/dnsmasq.cfg01411c.d\n', '/var/etc/dnsmasq.conf.guest': 'conf-dir=/tmp/dnsmasq.guest.d\n' });
  const d = cf.createCloudflared({ run, fsImpl, service: { directResolvers: () => ['178.22.122.100'] } });
  await d.apply({ enabled: true, token: 'x'.repeat(50) });
  assert.equal(fsImpl.files['/tmp/dnsmasq.cfg01411c.d/irnetfree-cloudflared.conf'], cf.dnsmasqDropIn(['178.22.122.100']));
  assert.equal(fsImpl.files['/tmp/dnsmasq.guest.d/irnetfree-cloudflared.conf'], cf.dnsmasqDropIn(['178.22.122.100']));
  assert.ok(!('/tmp/dnsmasq.d/irnetfree-cloudflared.conf' in fsImpl.files), 'not written where dnsmasq does not look');
  await d.apply({ enabled: false, token: '' });
  assert.ok(!Object.keys(fsImpl.files).some((p) => p.endsWith('irnetfree-cloudflared.conf')), 'all gone');
});

test('apply on: the UCI batch on stdin (never argv), the drop-in written from the direct resolvers, the bypass set, dnsmasq restarted (a reload reads no conf-dir), the service enabled and restarted', async () => {
  const { run, calls } = fakeRun({ 'uci -q show cloudflared': { code: 0, stdout: "cloudflared.config=cloudflared\ncloudflared.config.enabled='0'\n", stderr: '' } });
  const fsImpl = fakeFs({ '/usr/bin/cloudflared': '' });
  const bypass = [];
  const logs = [];
  const d = cf.createCloudflared({ run, fsImpl, log: (l, lv) => logs.push(l), service: { directResolvers: () => ['178.22.122.100'], setRemoteBypass: async (owner, list) => bypass.push([owner, list]) } });
  const token = 'eyJhIjoiYWJjZGVmMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODkiLCJ0IjoiMTIzIn0=';
  const r = await d.apply({ enabled: true, token });
  assert.deepEqual(r, { ok: true });
  const uci = calls.find((c) => c.cmd === 'uci' && c.args[1] === 'batch');
  assert.ok(uci, 'uci batch ran');
  assert.match(uci.input, /set cloudflared\.config\.token='eyJ/);
  assert.ok(!calls.some((c) => c.args.some((a) => a.includes(token))), 'the token is in no argv');
  assert.equal(fsImpl.files[cf.DROP_IN], cf.dnsmasqDropIn(['178.22.122.100']));
  assert.deepEqual(bypass, [['cloudflared', cf.bypassList()]]);
  const seq = calls.map((c) => c.cmd + ' ' + c.args.join(' '));
  // OpenWrt's dnsmasq reload is a SIGHUP, and dnsmasq re-reads no config on
  // one: a new drop-in in its conf-dir waited for the next restart (review of v1.16.1)
  assert.ok(seq.includes('/etc/init.d/dnsmasq restart'), seq.join('\n'));
  assert.ok(!seq.includes('/etc/init.d/dnsmasq reload'));
  assert.ok(seq.indexOf('/etc/init.d/dnsmasq restart') < seq.indexOf('/etc/init.d/cloudflared restart'), 'dnsmasq knows the edge domains before cloudflared asks');
  assert.ok(seq.indexOf('/etc/init.d/cloudflared enable') < seq.indexOf('/etc/init.d/cloudflared restart'));
  assert.ok(logs.some((l) => /http2/.test(l) && /direct/.test(l)), 'the log says http2 and direct only');
});

test('apply off: enabled=0 committed, the service stopped and disabled, the drop-in removed, dnsmasq restarted, the bypass cleared', async () => {
  const { run, calls } = fakeRun();
  const fsImpl = fakeFs({ '/usr/bin/cloudflared': '', [cf.DROP_IN]: 'old' });
  const bypass = [];
  const d = cf.createCloudflared({ run, fsImpl, service: { setRemoteBypass: async (owner, list) => bypass.push([owner, list]) } });
  await d.apply({ enabled: false, token: 'whatever' });
  const uci = calls.find((c) => c.cmd === 'uci' && c.args[1] === 'batch');
  assert.match(uci.input, /enabled='0'/);
  assert.doesNotMatch(uci.input, /token=/);
  assert.ok(!(cf.DROP_IN in fsImpl.files), 'the drop-in is gone');
  assert.deepEqual(bypass, [['cloudflared', { hosts: [], cidrs: [] }]]);
  const seq = calls.map((c) => c.cmd + ' ' + c.args.join(' '));
  assert.ok(seq.includes('/etc/init.d/cloudflared stop') && seq.includes('/etc/init.d/cloudflared disable') && seq.includes('/etc/init.d/dnsmasq restart'), seq.join('\n'));
});

test('not installed: apply does nothing but say so; status says installed:false without running anything', async () => {
  const { run, calls } = fakeRun();
  const logs = [];
  const d = cf.createCloudflared({ run, fsImpl: fakeFs({}), log: (l) => logs.push(l) });
  assert.deepEqual(await d.apply({ enabled: true, token: 'x'.repeat(50) }), { ok: false, error: 'not installed' });
  assert.equal(calls.length, 0);
  const s = await d.status();
  assert.equal(s.installed, false);
  assert.equal(s.running, false);
  assert.equal(s.viaVpn, false);
  assert.equal(calls.length, 0);
  assert.ok(logs.some((l) => /not installed/.test(l)));
});

test('status when installed: running from pidof, the last syslog line, the version once', async () => {
  const { run, calls } = fakeRun({
    'pidof cloudflared': { code: 0, stdout: '1234\n', stderr: '' },
    'sh -c logread': { code: 0, stdout: 'Thu Oct  1 10:00:00 2026 daemon.info cloudflared[1234]: Registered tunnel connection\n', stderr: '' },
    '/usr/bin/cloudflared --version': { code: 0, stdout: 'cloudflared version 2024.4.1 (built 2024-04-22)\n', stderr: '' }
  });
  const d = cf.createCloudflared({ run, fsImpl: fakeFs({ '/usr/bin/cloudflared': '' }) });
  const s = await d.status();
  assert.equal(s.installed, true);
  assert.equal(s.running, true);
  assert.match(s.lastLine, /Registered tunnel connection/);
  assert.equal(s.version, 'cloudflared version 2024.4.1 (built 2024-04-22)');
  await d.status();
  assert.equal(calls.filter((c) => c.args[0] === '--version').length, 1, 'the version is asked once');
});

test('status is memoised for 15 s (LuCI polls every 3 s on a Cortex-A7), and an apply makes it fresh at once (review M6)', async () => {
  const { run, calls } = fakeRun({ 'pidof cloudflared': { code: 0, stdout: '1\n', stderr: '' } });
  let now = 1000000;
  const d = cf.createCloudflared({ run, fsImpl: fakeFs({ '/usr/bin/cloudflared': '' }), now: () => now });
  const probes = () => calls.filter((c) => c.cmd === 'pidof' || (c.cmd === 'sh' && /logread/.test(c.args[1]))).length;
  await d.status(); await d.status(); await d.status();
  assert.equal(probes(), 2, 'one pidof + one logread for three polls');
  now += 14 * 1000;
  await d.status();
  assert.equal(probes(), 2, 'still cached inside the window');
  now += 2 * 1000;
  await d.status();
  assert.equal(probes(), 4, 'probed again after 15 s');
  await d.apply({ enabled: false, token: '' });
  await d.status();
  assert.equal(probes(), 6, 'an apply drops the cache so the page sees the change at once');
});

test('install: opkg update then opkg install in the background, accepted at once, applied after when asked', async () => {
  const files = {};
  const { run, calls } = fakeRun({ 'opkg install cloudflared': { code: 0, stdout: 'Installing cloudflared', stderr: '' } });
  const wrapped = async (cmd, args, opts) => { const r = await run(cmd, args, opts); if (cmd === 'opkg' && args[0] === 'install') files['/usr/bin/cloudflared'] = ''; return r; };
  const logs = [];
  const d = cf.createCloudflared({ run: wrapped, fsImpl: fakeFs(files), log: (l) => logs.push(l) });
  let applied = 0;
  assert.deepEqual(d.install(() => { applied++; }), { accepted: true });
  assert.equal(d.installing, true);
  assert.deepEqual(d.install(), { accepted: true, already: true });
  await new Promise((r) => setTimeout(r, 30));
  assert.equal(d.installing, false);
  assert.deepEqual(calls.filter((c) => c.cmd === 'opkg').map((c) => c.args), [['update'], ['install', 'cloudflared']]);
  assert.equal(applied, 1);
  assert.equal((await d.status()).lastInstall.ok, true);
  assert.ok(logs.some((l) => /installed/.test(l)));
});
