'use strict';
/**
 * The router's network watcher wired into the service (v1.16 S3): the dump
 * comes through the injected runner (`ubus call network.interface dump`), the
 * probe through a seam, the timing from deps — nothing here touches a real
 * ubus or SOCKS. What is pinned: a WAN address change that the tunnel
 * survives is logged and kept; one it does not survive is rebuilt through the
 * existing recovery; an IPv6 prefix rotation is nothing; the device xray binds
 * to vanishing is a rebuild without asking.
 */
process.env.IRNETFREE_PLATFORM = 'openwrt';
const test = require('node:test');
const assert = require('node:assert/strict');
const H = require('./serviceHarness');

process.setMaxListeners(60);
test.after(() => H.cleanupDirs());
const { SERVER, until, sleep, connectedCount } = H;

const wan = (o = {}) => ({ interface: 'wan', up: o.up !== false, l3_device: o.dev || 'eth0', device: 'eth0', proto: 'dhcp',
  'ipv4-address': [{ address: o.addr || '192.0.2.10', mask: 24 }], 'ipv6-address': [], route: o.up === false ? [] : [{ target: '0.0.0.0', mask: 0, nexthop: o.gw || '192.0.2.1' }] });
const wan6 = (p = 'a1') => ({ interface: 'wan6', up: true, l3_device: 'eth0', device: 'eth0', proto: 'dhcpv6',
  'ipv6-address': [{ address: `2001:db8:${p}::1`, mask: 64 }], 'ipv6-prefix': [{ address: `2001:db8:${p}::`, mask: 56 }], route: [{ target: '::', mask: 0, nexthop: 'fe80::1' }] });
const lan = { interface: 'lan', up: true, l3_device: 'br-lan', device: 'br-lan', proto: 'static', 'ipv4-address': [{ address: '192.168.1.1', mask: 24 }], route: [] };

/** A service whose ubus answers `s.dump` (the test replaces it) and whose probe answers `answers` in turn. */
function service(answers) {
  let s;
  const lanRun = async (cmd, args) => {
    const line = [cmd, ...args].join(' ');
    s.asked.push(line);
    if (line === 'ubus call network.interface dump') return JSON.stringify(s.dump);
    throw new Error('no ' + cmd + ' here');
  };
  const probeTunnel = async () => answers[Math.min(s.probes++, answers.length - 1)];
  const timing = Object.assign({}, H.fakes.deps(H.fakes.makeState()).timing, { wanIntervalMs: 20, wanSettleMs: 40, wanProbeGapMs: 10 });
  s = Object.assign(H.start({}, { lanRun, probeTunnel, timing }), { dump: { interface: [lan, wan(), wan6()] }, probes: 0, asked: [] });
  return s;
}

test('S3: a WAN address change the tunnel survives is kept — logged with the diff and the verdict, no rebuild', async (t) => {
  const s = service([false, true]);   // the first ask fails (the dial races the new address), the second answers
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  await until(() => s.asked.filter(l => /network\.interface dump/.test(l)).length >= 2, 'the watcher polling');
  s.dump = { interface: [lan, wan({ addr: '192.0.2.77' }), wan6()] };
  await until(() => s.logs.some(l => /Network changed \(wan: 192\.0\.2\.10\/24 → 192\.0\.2\.77\/24\) — the tunnel answers, kept/.test(l.line)), 'the verdict', 5000);
  assert.equal(s.probes, 2);
  await sleep(100);
  assert.equal(connectedCount(s), 1, 'no rebuild');
  assert.ok(!s.statuses.some(x => x.state === 'reconnecting'));
  assert.equal(s.service.connSnapshot().state, 'connected');
});

test('S3: a WAN change the tunnel does not survive is rebuilt through the recovery (reason wan-changed, cause netwatch)', async (t) => {
  const s = service([false, false]);
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  await until(() => s.asked.filter(l => /network\.interface dump/.test(l)).length >= 2, 'the watcher polling');
  s.dump = { interface: [lan, wan({ addr: '192.0.2.77', gw: '192.0.2.254' }), wan6()] };
  await until(() => connectedCount(s) === 2, 'the rebuild', 8000);
  assert.ok(s.logs.some(l => l.level === 'warn' && /Network changed \(wan: 192\.0\.2\.10\/24 → 192\.0\.2\.77\/24; wan: gateway 192\.0\.2\.1 → 192\.0\.2\.254\) — the tunnel does not answer, rebuilding/.test(l.line)), JSON.stringify(s.logs.map(l => l.line)));
  const rec = s.statuses.find(x => x.state === 'reconnecting');
  assert.equal(rec.reason, 'wan-changed');
  assert.equal(rec.cause, 'netwatch');
  assert.equal(s.service.connSnapshot().cause, 'netwatch');
  assert.equal(s.probes, 2);
});

test('S3: an IPv6 prefix rotation is nothing; the device xray binds to vanishing is a rebuild without asking', async (t) => {
  const s = service([true]);
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  await until(() => s.asked.filter(l => /network\.interface dump/.test(l)).length >= 2, 'the watcher polling');
  s.dump = { interface: [lan, wan(), wan6('b7')] };
  await sleep(250);
  assert.ok(!s.logs.some(l => /Network changed/.test(l.line)), 'a prefix rotation is not a network change: ' + s.logs.map(l => l.line).join('\n'));
  assert.equal(s.probes, 0);
  // the WAN device the live connection's direct dials are bound to (eth0, from the fake physicalInterface) is gone
  s.dump = { interface: [lan, wan({ up: false }), { interface: 'wan6', up: false, proto: 'dhcpv6', device: 'eth0' }] };
  await until(() => connectedCount(s) === 2, 'the rebuild', 8000);
  assert.equal(s.probes, 0, 'not asked');
  assert.ok(s.logs.some(l => /Network changed \(wan: default v4 route gone; wan6: default v6 route gone\) — the WAN device the tunnel is bound to \(eth0\) is gone, rebuilding/.test(l.line)), JSON.stringify(s.logs.map(l => l.line)));
});

test('I3: a change that settles while a rebuild is in flight (or the gateway is down for a drop) is not judged, and never queued behind the recovery — exactly one rebuild', async (t) => {
  const s = service([false, false]);
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  await until(() => s.asked.filter(l => /network\.interface dump/.test(l)).length >= 2, 'the watcher polling');
  // sing-box dies and cannot come back for a while: the recovery retries (reconnecting…)
  s.state.gatewayFails = true;
  s.state.inners.find(i => i.active).crash();
  await until(() => s.statuses.filter(x => x.state === 'reconnecting').length >= 2, 'the recovery retrying', 8000);
  // …and the WAN moves meanwhile (a PPPoE renewal in the window)
  s.dump = { interface: [lan, wan({ addr: '192.0.2.77' }), wan6()] };
  await until(() => s.logs.some(l => /Network changed \(wan: 192\.0\.2\.10\/24 → 192\.0\.2\.77\/24\) — a rebuild is in flight/.test(l.line)), 'the change seen but not judged', 8000);
  assert.equal(s.probes, 0, 'the probe would only answer for a tunnel being rebuilt');
  s.state.gatewayFails = false;
  await until(() => connectedCount(s) === 2, 'the recovery brings it back', 8000);
  await sleep(300);
  assert.equal(connectedCount(s), 2, 'no second rebuild for the change');
  assert.ok(!s.statuses.some(x => x.state === 'reconnecting' && x.reason === 'wan-changed'), JSON.stringify(s.statuses.map(x => [x.state, x.reason])));
  assert.equal(s.service.connSnapshot().state, 'connected');
});

test('M4: a verdict reached after the connection moved (a disconnect and a connect during the probes) is dropped', async (t) => {
  const s = service([false, false]);
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  await until(() => s.asked.filter(l => /network\.interface dump/.test(l)).length >= 2, 'the watcher polling');
  s.dump = { interface: [lan, wan({ addr: '192.0.2.77' }), wan6()] };
  await until(() => s.probes >= 1, 'the first probe', 5000);
  // the user turns the VPN off and on while the judge waits for its second probe
  await s.service.invoke('disconnect');
  await s.service.invoke('connect', SERVER.id);
  await until(() => s.logs.some(l => /Network changed \(wan: 192\.0\.2\.10\/24 → 192\.0\.2\.77\/24\) — the connection moved meanwhile, verdict dropped/.test(l.line)), 'the stale verdict dropped', 5000);
  await sleep(300);
  assert.ok(!s.statuses.some(x => x.state === 'reconnecting' && x.reason === 'wan-changed'), 'the fresh connection is not torn down for it');
  assert.equal(connectedCount(s), 2);
});

test('S3: the watcher stops with a disconnect; a failed ubus read is no change; the desktop fingerprint is not consulted on a router', async (t) => {
  const s = service([true]);
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  await until(() => s.asked.filter(l => /network\.interface dump/.test(l)).length >= 2, 'the watcher polling');
  await s.service.invoke('disconnect');
  const n = s.asked.length;
  await sleep(120);
  assert.equal(s.asked.length, n, 'no polling after the disconnect');
  const src = require('node:fs').readFileSync(require('node:path').join(__dirname, '..', 'src', 'server', 'service.js'), 'utf8').replace(/\r\n/g, '\n');
  assert.match(src, /function currentNetFingerprint\(\) \{\n\s*if \(OPENWRT\) return null;/, 'no "changed during connect" rebuild from os.networkInterfaces on a router');
});
