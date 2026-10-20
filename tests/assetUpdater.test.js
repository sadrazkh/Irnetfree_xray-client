'use strict';
/**
 * The weekly asset update. What must hold: nothing happens while a tunnel is
 * up — unless its owner opens a live window (the router's quiet hours), and
 * then what changed is applied to the live connection; the geo files are
 * refreshed by default and cores only when asked; a core
 * is downloaded only when the release is genuinely newer than the installed
 * one; a failed download is a log line and the week still counts.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { AssetUpdater, cmpVersion, versionNumber, WEEK_MS } = require('../src/main/assetUpdater');

/**
 * `ver`: what each core answers `version` with now; a download installs what
 * `h.installs(id)` says — the latest release by default, as the downloader
 * does when it can fetch it (a test may make it put the same version back).
 */
function make(over) {
  const log = [], dl = [];
  let checkedAt = 0, now = 10 * WEEK_MS;
  const ver = { xray: 'Xray 26.3.27 (Xray, Penetrates Everything.)', 'xray-pattn': '26.9.1' };
  const latest = { xray: '26.4.1', 'xray-pattn': 'v26.9.1' };
  const h = { dl, log, ver, latest, installs: (id) => latest[id] };
  const u = new AssetUpdater(Object.assign({
    getSettings: () => ({ autoUpdateAssets: 'all' }),
    getCheckedAt: () => checkedAt,
    setCheckedAt: (t) => { checkedAt = t; },
    download: async (c) => { dl.push(c); if (c in ver) ver[c] = h.installs(c); },
    installed: (id) => id !== 'sing-box',
    currentVersion: async (id) => ver[id],
    latestVersion: async (id) => latest[id],
    busy: () => false,
    onLog: (l, level) => log.push(level ? `[${level}] ${l}` : l),
    now: () => now
  }, over || {}));
  return Object.assign(h, { u, set: (t) => { now = t; }, checked: () => checkedAt });
}

test('cmpVersion and versionNumber', () => {
  assert.ok(cmpVersion('26.4.1', '26.3.27') > 0);
  assert.equal(cmpVersion('1.6.0', '1.6.0'), 0);
  assert.ok(cmpVersion('v1.6', '1.10') < 0);
  assert.equal(versionNumber('Xray 26.9.1 (Xray, Penetrates Everything.)'), '26.9.1');
  assert.equal(versionNumber('sing-box version 1.13.14\n\nEnvironment: go1.24'), '1.13.14');
  assert.equal(versionNumber(''), '');
  assert.equal(versionNumber('no number here'), '');
});

// The version picker (coreVersions.js) orders release tags, and sing-box's are
// semver with a pre-release part: 1.13.0-beta.3 comes BEFORE 1.13.0. Split on
// the dots alone, "0-beta" read as 0 and the beta's ".3" as a fourth number, so
// the beta outranked its own release.
test('cmpVersion orders pre-release tags the way semver does', () => {
  assert.ok(cmpVersion('1.13.0-beta.3', '1.13.0') < 0, 'a release outranks its own pre-releases');
  assert.ok(cmpVersion('1.13.0', '1.13.0-rc.1') > 0);
  assert.ok(cmpVersion('1.13.0-beta.3', '1.13.0-beta.10') < 0, 'numeric identifiers compare as numbers');
  assert.ok(cmpVersion('1.15.0-alpha.10', '1.15.0-alpha.9') > 0);
  assert.ok(cmpVersion('1.14.0-alpha.2', '1.14.0-beta.1') < 0, 'alpha < beta < rc');
  assert.ok(cmpVersion('1.14.0-rc.1', '1.14.0-beta.17') > 0);
  assert.ok(cmpVersion('1.14.0-rc', '1.14.0-rc.1') < 0, 'fewer identifiers sort first when the rest are equal');
  assert.ok(cmpVersion('1.14.0-beta.1', '1.13.21') > 0, 'the numbers decide before the pre-release part');
  assert.equal(cmpVersion('v1.13.0-BETA.3', '1.13.0-beta.3'), 0, 'a leading v and the case do not matter');
  assert.ok(cmpVersion('v26.9.22', '26.9.13') > 0);
  // plain dotted versions compare exactly as before
  assert.ok(cmpVersion('26.10.3', '26.9.27') > 0);
  assert.equal(cmpVersion('26.3.27', 'v26.3.27'), 0);
  assert.ok(cmpVersion('1.6', '1.6.1') < 0);
});

test('all: geo every week, a core only when newer, installed cores only', async () => {
  const h = make();
  assert.deepEqual(await h.u.tick(), { ran: true, done: ['geo', 'xray'] });
  assert.deepEqual(h.dl, ['geo', 'xray'], 'PattN is current and sing-box is not installed');
  assert.equal(h.checked(), 10 * WEEK_MS);
  assert.deepEqual(await h.u.tick(), { ran: false }, 'not due again');
  h.set(11 * WEEK_MS + 1);
  assert.equal((await h.u.tick()).ran, true);
});

test('geo (the default): only the geo files, never a core', async () => {
  const h = make({ getSettings: () => ({ autoUpdateAssets: 'geo' }) });
  assert.deepEqual(await h.u.tick(), { ran: true, done: ['geo'] });
  assert.deepEqual(h.dl, ['geo']);
  const unknown = make({ getSettings: () => ({}) });
  assert.deepEqual(await unknown.u.tick(), { ran: false }, 'an unset or unknown value is off');
});

test('off: never; busy (a tunnel is up): deferred without moving the stamp', async () => {
  assert.deepEqual(await make({ getSettings: () => ({ autoUpdateAssets: 'off' }) }).u.tick(), { ran: false });
  const b = make({ busy: () => true });
  assert.deepEqual(await b.u.tick(), { ran: false, deferred: true });
  assert.equal(b.checked(), 0, 'the next tick tries again');
  assert.deepEqual(b.dl, []);
});

// A router is connected day and night: "never while a tunnel is up" was never
// at all there, and its geoip/geosite went stale. The service opens a live
// window (its quiet hours) and reloads the core on what was downloaded.
test('a live window (the router\'s quiet hours): busy, yet the run goes ahead and is applied to the live connection', async () => {
  const applied = [];
  let inWindow = false;
  const asked = [];
  const h = make({
    busy: () => true,
    getSettings: () => ({ autoUpdateAssets: 'geo' }),
    liveWindow: (ms) => { asked.push(ms); return inWindow; },
    applyLive: async (done) => { applied.push(done); }
  });
  assert.deepEqual(await h.u.tick(), { ran: false, deferred: true }, 'outside the window: deferred, as before');
  assert.deepEqual(h.dl, []);
  assert.equal(h.checked(), 0);
  assert.deepEqual(asked, [10 * WEEK_MS], 'asked with the clock the updater runs on');
  inWindow = true;
  assert.deepEqual(await h.u.tick(), { ran: true, done: ['geo'], live: true });
  assert.deepEqual(h.dl, ['geo'], 'downloaded as usual');
  assert.deepEqual(applied, [['geo']], 'and handed to the live connection');
  assert.equal(h.checked(), 10 * WEEK_MS);
  assert.ok(h.log.some((l) => /Updated automatically: geo/.test(l)));
  assert.deepEqual(await h.u.tick(), { ran: false }, 'not due again');
  assert.deepEqual(applied, [['geo']]);
});

test('a live window with every asset on: only the geo files go live — a new core waits for the connection to be down', async () => {
  const applied = [];
  const h = make({ busy: () => true, getSettings: () => ({ autoUpdateAssets: 'all' }), liveWindow: () => true, applyLive: async (done) => { applied.push(done); } });
  assert.deepEqual(await h.u.tick(), { ran: true, done: ['geo'], live: true });
  assert.deepEqual(h.dl, ['geo'], 'no core downloaded under the live connection');
  assert.deepEqual(applied, [['geo']]);
  assert.ok(h.log.some((l) => /Cores are not updated under a live connection/.test(l)));
});

test('a live run that changed nothing applies nothing; one the connection could not take is a log line, and the week counts', async () => {
  const applied = [];
  const none = make({ busy: () => true, getSettings: () => ({ autoUpdateAssets: 'geo' }), liveWindow: () => true, applyLive: async (d) => { applied.push(d); } });
  none.u.o.download = async () => { throw new Error('net'); };
  assert.deepEqual(await none.u.tick(), { ran: true, done: [], live: true });
  assert.deepEqual(applied, [], 'nothing new: the core is not reloaded for nothing');
  assert.equal(none.checked(), 10 * WEEK_MS);
  const bad = make({ busy: () => true, getSettings: () => ({ autoUpdateAssets: 'geo' }), liveWindow: () => true, applyLive: async () => { throw new Error('the core refused the config'); } });
  assert.deepEqual(await bad.u.tick(), { ran: true, done: ['geo'], live: true }, 'resolves: a failed apply does not throw out of the timer');
  assert.ok(bad.log.some((l) => /^\[warn\] Updated \(geo\), but the running connection could not take it: the core refused the config/.test(l)), JSON.stringify(bad.log));
  assert.equal(bad.checked(), 10 * WEEK_MS, 'the files are in place: the week counts');
});

test('not busy: the window is not asked and nothing is applied; busy without a window (main.js passes none): deferred as before', async () => {
  let asked = 0;
  const applied = [];
  const idle = make({ liveWindow: () => { asked++; return true; }, applyLive: async (d) => { applied.push(d); } });
  assert.deepEqual(await idle.u.tick(), { ran: true, done: ['geo', 'xray'] }, 'the same answer as ever');
  assert.equal(asked, 0);
  assert.deepEqual(applied, [], 'no live connection to apply it to');
  const desk = make({ busy: () => true, applyLive: async (d) => { applied.push(d); } });
  assert.deepEqual(await desk.u.tick(), { ran: false, deferred: true });
  assert.deepEqual(desk.dl, []);
  assert.deepEqual(applied, []);
});

test('a failing download or an unreadable version is a log line, not a stuck week', async () => {
  const f = make();
  const install = f.u.o.download;   // the cores still install; only the geo download fails
  f.u.o.download = async (c) => { if (c === 'geo') throw new Error('net'); return install(c); };
  assert.deepEqual(await f.u.tick(), { ran: true, done: ['xray'] });
  assert.ok(f.log.some(l => /Geo update failed: net/.test(l)));
  assert.equal(f.checked(), 10 * WEEK_MS, 'the week still counts');
  const v = make({ currentVersion: async () => 'garbage' });
  assert.deepEqual(await v.u.tick(), { ran: true, done: ['geo'] }, 'no version, no download');
});

test('a core download that puts the same version back is not "Updated automatically" — and is not downloaded again until the target moves', async () => {
  // Final review, minor 5 (downloader.defaultRelease): `tags/v26.9.30` could
  // not be fetched — a 404, or the API's 60-an-hour limit — while
  // `releases/latest` could, so the weekly tick reinstalled the same 26.3.27
  // every week and logged "Updated automatically: xray".
  const h = make();
  h.latest.xray = '26.9.30';
  h.installs = (id) => (id === 'xray' ? 'Xray 26.3.27 (Xray, Penetrates Everything.)' : h.latest[id]);
  assert.deepEqual(await h.u.tick(), { ran: true, done: ['geo'] }, 'tried, but nothing changed');
  assert.deepEqual(h.dl, ['geo', 'xray']);
  assert.ok(!h.log.some((l) => /Updated automatically: .*xray/.test(l)), JSON.stringify(h.log));
  assert.ok(h.log.some((l) => /^\[warn\] .*xray.*26\.3\.27.*26\.9\.30/.test(l)), 'said, with both versions: ' + JSON.stringify(h.log));
  // a week on, the same target: not downloaded again
  h.set(11 * WEEK_MS + 1);
  assert.deepEqual(await h.u.tick(), { ran: true, done: ['geo'] });
  assert.deepEqual(h.dl, ['geo', 'xray', 'geo'], 'no second download of the same miss');
  // the target moves (a newer release, or the suggested one reachable now): tried again — and this time it took
  h.latest.xray = '26.10.1';
  h.installs = (id) => h.latest[id];
  h.set(12 * WEEK_MS + 2);
  assert.deepEqual(await h.u.tick(), { ran: true, done: ['geo', 'xray'] });
  assert.ok(h.log.some((l) => /Updated automatically: geo, xray/.test(l)));
});

test('a core download whose version cannot be read afterwards is not claimed as an update either', async () => {
  const h = make();
  h.installs = (id) => (id === 'xray' ? 'garbage' : h.latest[id]);
  assert.deepEqual(await h.u.tick(), { ran: true, done: ['geo'] });
  assert.deepEqual(h.dl, ['geo', 'xray']);
});

test('start() arms an interval and a first run; stop() clears both; neither holds the process', async () => {
  const h = make({ getSettings: () => ({ autoUpdateAssets: 'geo' }) });
  h.u.start(60000, 10);
  assert.ok(h.u.timer && h.u.firstTimer);
  await new Promise(r => setTimeout(r, 40));
  assert.deepEqual(h.dl, ['geo'], 'the first run happened');
  h.u.stop();
  assert.equal(h.u.timer, null);
  assert.equal(h.u.firstTimer, null);
});
