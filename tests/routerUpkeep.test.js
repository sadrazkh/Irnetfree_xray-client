'use strict';
/**
 * Three router-only gaps in keeping a connection that runs day and night:
 *
 * - the access log: the connect turned it off, a reload (process routes, a
 *   group's member set aside) brought it back — a line per LAN connection
 *   into the 500-line ring and every events stream. Every config the router
 *   builds now comes without it (buildActive).
 * - the geo files: the weekly update never ran under a live tunnel, so a
 *   router connected 24/7 never refreshed geoip/geosite and bypass-Iran went
 *   stale. In its quiet hours (03:00-05:00 local) it runs under the live
 *   connection and the core is reloaded on the new files.
 * - a tunnel up with nothing passing: the core and the gateway alive, so no
 *   drop path fired. The watchdog asks the tunnel (probeTunnel) every few
 *   minutes and hands two misses in a row to the drop recovery.
 *
 * Every seam faked (serviceHarness / gatewayFakes): nothing is downloaded,
 * probed, spawned or bound.
 */
process.env.IRNETFREE_PLATFORM = 'openwrt';
const test = require('node:test');
const assert = require('node:assert/strict');
const H = require('./serviceHarness');

process.setMaxListeners(60);
test.after(() => H.cleanupDirs());
const { SERVER, until, sleep, connectedCount } = H;

const baseTiming = () => H.fakes.deps(H.fakes.makeState()).timing;
const gatewayStarts = (s) => s.state.events.filter((e) => e === 'gateway:start').length;

/** deps.downloader: fetches nothing; what was asked for is recorded. */
function fakeDownloader(asked) {
  return () => ({
    download: async (c) => { asked.push(c); return { ok: true }; },
    latestVersion: async () => '99.0.0'
  });
}

// local times: the quiet hours are the router's own clock
const AFTERNOON = new Date(2026, 9, 20, 14, 0).getTime();
const WEEK_ON_AFTERNOON = new Date(2026, 9, 28, 14, 0).getTime();
const WEEK_ON_NIGHT = new Date(2026, 9, 28, 3, 30).getTime();

/** A router whose last asset run was this afternoon, with a clock the test moves and an updater that looks every 20 ms. */
function quietService(settings = {}) {
  const asked = [];
  let now = AFTERNOON;
  const s = H.start({ assetsCheckedAt: AFTERNOON, settings: Object.assign({ autoUpdateAssets: 'geo' }, settings) }, {
    downloader: fakeDownloader(asked),
    now: () => now,
    timing: Object.assign(baseTiming(), { assetFirstMs: 20, assetEveryMs: 20 })
  });
  return Object.assign(s, { asked, setNow: (t) => { now = t; } });
}

/* ------------------------------ the access log and the quiet-hours update ------------------------------ */

test('the weekly geo update reaches a router that stays connected: deferred in the afternoon, run at 03:30 under the live connection, then the core reloads on the new files — the tunnel stays up', async (t) => {
  const s = quietService();
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  assert.equal(s.state.xray.starts.length, 1);

  // a week on, in the afternoon: due, but a live connection in the daytime is left alone (as on the desktop)
  s.setNow(WEEK_ON_AFTERNOON);
  await sleep(150);
  assert.deepEqual(s.asked, [], 'not under a live connection outside the quiet hours');
  assert.equal(s.state.xray.starts.length, 1);

  // 03:30: the run goes ahead and is applied
  s.setNow(WEEK_ON_NIGHT);
  await until(() => s.logs.some((l) => /Updated in the quiet hours \(geo\) — the core reloaded on the new files/.test(l.line)), 'the reload', 4000);
  assert.deepEqual(s.asked, ['geo'], 'downloaded as usual');
  assert.equal(s.state.xray.starts.length, 2, 'the core restarted once, on the new files');
  assert.ok(s.logs.some((l) => /Updated automatically: geo/.test(l.line)));
  assert.equal(gatewayStarts(s), 1, 'the gateway was not rebuilt: only the core reloads');
  assert.equal(connectedCount(s), 1, 'no reconnect');
  assert.ok(!s.statuses.some((x) => x.state === 'reconnecting'));
  assert.equal(s.service.connSnapshot().state, 'connected');

  // done for the week
  await sleep(120);
  assert.deepEqual(s.asked, ['geo']);
  assert.equal(s.state.xray.starts.length, 2);
});

test('disconnected, the router updates at any hour exactly as before — and reloads nothing', async (t) => {
  const s = quietService();
  t.after(() => s.service.shutdown());
  s.setNow(WEEK_ON_AFTERNOON);
  await until(() => s.asked.length === 1, 'the weekly run', 4000);
  assert.deepEqual(s.asked, ['geo']);
  await sleep(60);
  assert.equal(s.state.xray.starts.length, 0, 'no core to reload');
  assert.ok(!s.logs.some((l) => /quiet hours/.test(l.line)));
});

test('every config the router builds runs without the access log — the connect\'s and a reload\'s; a verbose level keeps it', async (t) => {
  const s = quietService();
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  assert.equal(s.state.xray.starts[0].config.log.access, 'none');
  s.setNow(WEEK_ON_NIGHT);   // a reload through rebuildActiveConfig (the quiet-hours update)
  await until(() => s.state.xray.starts.length === 2, 'the reload', 4000);
  assert.equal(s.state.xray.starts[1].config.log.access, 'none', 'a reload used to bring back a line per LAN connection');

  // logLevel info: the user asked to see it — both times
  const v = quietService({ logLevel: 'info' });
  t.after(() => v.service.shutdown());
  await v.service.invoke('connect', SERVER.id);
  assert.notEqual(v.state.xray.starts[0].config.log.access, 'none');
  v.setNow(WEEK_ON_NIGHT);
  await until(() => v.state.xray.starts.length === 2, 'the reload', 4000);
  assert.notEqual(v.state.xray.starts[1].config.log.access, 'none');
});

/* ------------------------------ the tunnel watchdog ------------------------------ */

/**
 * A router whose tunnel answers the watchdog's probes with `answers` in turn
 * (the last one repeats); `probeAt`: when each probe came. The watchdog asks
 * every 150 ms here, a miss again after 10 ms.
 */
function watchService(answers, settings = {}, timing = {}) {
  const s = { probes: 0, probeAt: [] };
  const probeTunnel = async () => {
    s.probeAt.push(Date.now());
    return answers[Math.min(s.probes++, answers.length - 1)];
  };
  return Object.assign(s, H.start({ settings }, {
    probeTunnel,
    timing: Object.assign(baseTiming(), { tunnelWatchMs: 150, tunnelRecheckMs: 10, tunnelRebuildGapMs: 0 }, timing)
  }));
}

test('watchdog: a tunnel that answers is asked every interval and left alone — nothing said', async (t) => {
  const s = watchService([true]);
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  await until(() => s.probes >= 3, 'three probes', 4000);
  assert.ok(s.probeAt[2] - s.probeAt[1] >= 100, 'at the interval, not faster');
  assert.equal(connectedCount(s), 1);
  assert.ok(!s.logs.some((l) => /Tunnel watchdog/.test(l.line)), 'a tunnel that answers is not news');
});

test('watchdog: two misses in a row (the second soon after the first) start the drop recovery as tunnel-stalled — even with "reconnect on network change" off', async (t) => {
  const s = watchService([false, false, true], { autoReconnectOnNetworkChange: false }, { tunnelWatchMs: 400 });
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  await until(() => connectedCount(s) === 2, 'the rebuild', 6000);
  assert.ok(s.probeAt[1] - s.probeAt[0] < 300, 'the miss was asked again after the short recheck, not a full interval');
  const lines = s.logs.map((l) => l.line);
  const miss = s.logs.find((l) => /^Tunnel watchdog: the tunnel did not answer — asking again in/.test(l.line));
  assert.ok(miss && miss.level === 'warn', JSON.stringify(lines));
  const stalled = s.logs.find((l) => /^Tunnel watchdog: the tunnel did not answer twice in a row — the gateway is up but nothing passes through it; rebuilding the connection/.test(l.line));
  assert.ok(stalled && stalled.level === 'warn', JSON.stringify(lines));
  assert.ok(lines.some((l) => /The connection dropped \(tunnel-stalled\) — rebuilding the connection/.test(l)), 'the drop recovery ran it');
  const rec = s.statuses.find((x) => x.state === 'reconnecting');
  assert.equal(rec.reason, 'tunnel-stalled');
  assert.equal(rec.cause, 'recovery', 'a drop, not the network moving');
  assert.equal(gatewayStarts(s), 2, 'core and gateway rebuilt');
  // the rebuilt tunnel answers: watched again, never rebuilt again
  const n = s.probes;
  await until(() => s.probes >= n + 2, 'watched again after the rebuild', 4000);
  assert.equal(connectedCount(s), 2);
  assert.equal(s.service.connSnapshot().state, 'connected');
});

test('watchdog: one miss and then an answer is kept, and said', async (t) => {
  const s = watchService([false, true]);
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  await until(() => s.logs.some((l) => /^Tunnel watchdog: the tunnel answers again — kept/.test(l.line)), 'the second answer', 4000);
  await sleep(50);
  assert.equal(connectedCount(s), 1);
  assert.ok(!s.statuses.some((x) => x.state === 'reconnecting'));
});

test('watchdog: at most one rebuild per gap — a tunnel that stays dead is not rebuilt again and again', async (t) => {
  const s = watchService([false], {}, { tunnelRebuildGapMs: 60000 });
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  await until(() => s.logs.some((l) => /^Tunnel watchdog: the tunnel did not answer twice in a row — not rebuilt again, the last watchdog rebuild was \d+s ago \(at most one per 1 min\)/.test(l.line)), 'the second stall held back', 6000);
  assert.equal(connectedCount(s), 2, 'one rebuild only');
  assert.equal(s.statuses.filter((x) => x.state === 'reconnecting' && x.reason === 'tunnel-stalled').length, 1);
});

test('watchdog: not asked while the gateway is down for a drop being rebuilt; stopped by a disconnect', async (t) => {
  const s = watchService([true]);
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  await until(() => s.probes >= 1, 'the first probe', 4000);
  // sing-box dies and cannot come back for a while: the recovery retries
  s.state.gatewayFails = true;
  s.state.inners.find((i) => i.active).crash();
  await until(() => s.statuses.filter((x) => x.state === 'reconnecting').length >= 2, 'the recovery retrying', 6000);
  const during = s.probes;
  await sleep(400);
  assert.equal(s.probes, during, 'a gateway that is down cannot answer: not asked, not counted');
  s.state.gatewayFails = false;
  await until(() => connectedCount(s) === 2, 'the recovery brings it back', 6000);
  await until(() => s.probes > during, 'watched again once it is up', 4000);
  assert.ok(!s.logs.some((l) => /Tunnel watchdog/.test(l.line)), s.logs.map((l) => l.line).join('\n'));

  await s.service.invoke('disconnect');
  const after = s.probes;
  await sleep(400);
  assert.equal(s.probes, after, 'no probe after the disconnect');
});
