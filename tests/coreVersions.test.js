'use strict';
/**
 * The cores' version picker (Settings → Required files → Choose version): which
 * releases it offers, how each is labelled, and the two handlers main.js and
 * the router's service.js share. Releases are the three projects' own lists
 * (tests/coreReleases.js); the downloader is a fake — nothing here reaches
 * GitHub or replaces a binary.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { CORE_IDS, SUGGESTED, STABLE_COUNT, PRERELEASE_COUNT, fullVersion, isPrerelease, latestOf, buildCards, createCoreVersionsApi } = require('../src/main/coreVersions');
const { Downloader } = require('../src/main/downloader');
const rel = require('./coreReleases');

const dl = new Downloader({ destDir: fs.mkdtempSync(path.join(require('node:os').tmpdir(), 'irnf-cv-')) });
const xrayWin = (name) => name === dl.xrayAssetName('win32', 'x64');
const xrayRouter = (name) => name === dl.xrayAssetName('linux', 'arm');
const sbWin = (name) => dl.singboxAssetPattern('win32', 'x64').test(name);
const versions = (cards) => cards.map((c) => c.version);

/* ------------------------------ the table and the parsing ------------------------------ */

test('one suggested version per core, each a plain x.y.z, for exactly the three cores with a picker', () => {
  assert.deepEqual(CORE_IDS, ['xray', 'xray-pattn', 'sing-box']);
  assert.deepEqual(Object.keys(SUGGESTED).sort(), [...CORE_IDS].sort());
  for (const id of CORE_IDS) assert.match(SUGGESTED[id], /^\d+\.\d+\.\d+$/, id);
  assert.equal(SUGGESTED.xray, '26.3.27');
  assert.equal(SUGGESTED['xray-pattn'], '26.9.22');
  assert.equal(SUGGESTED['sing-box'], '1.13.14');
  assert.equal(STABLE_COUNT, 6);
  assert.equal(PRERELEASE_COUNT, 4);
  assert.throws(() => { SUGGESTED.xray = '1.0.0'; }, TypeError, 'the table is frozen');
});

test('the table says beside each value where it was verified — and those places say that version', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'src', 'main', 'coreVersions.js'), 'utf8');
  const table = src.slice(src.indexOf('const SUGGESTED'), src.indexOf('});', src.indexOf('const SUGGESTED')));
  for (const id of CORE_IDS) {
    const at = table.indexOf(`${id === 'xray' ? 'xray:' : `'${id}':`} '${SUGGESTED[id]}'`);
    assert.ok(at > -1, `${id}: ${table}`);
    // the comment block right above the value
    const before = table.slice(0, at).split(/\n\s*\n/).pop();
    assert.match(before, /\/\/ .*verified/i, `${id}: no comment saying where it was verified`);
  }
  // the files the comments name do say so
  const read = (...p) => fs.readFileSync(path.join(__dirname, '..', ...p), 'utf8');
  assert.match(read('src', 'server', 'service.js'), /CORE_DNS_VERIFIED = '26\.3\.27'/);
  assert.match(read('src', 'main', 'xrayManager.js'), /FINALMASK_SINCE = '26\.3\.27'/);
  assert.match(read('src', 'main', 'certPin.js'), /Xray 26\.3\.27, PattN 26\.9\.1/);
  assert.match(read('src', 'main', 'tunSingbox.js'), /sing-box check` on 1\.13\.14/);
  assert.match(read('scripts', 'build-mac-native.js'), /const VERSION = '1\.13\.14';/);
});

test('fullVersion: a tag or a core’s own output, its pre-release part kept', () => {
  assert.equal(fullVersion('v26.9.22'), '26.9.22');
  assert.equal(fullVersion('v1.15.0-alpha.10'), '1.15.0-alpha.10');
  assert.equal(fullVersion('Xray 26.3.27 (Xray, Penetrates Everything.) 2bed6d4 (go1.26.1 windows/amd64)'), '26.3.27');
  assert.equal(fullVersion('sing-box version 1.13.14\n\nEnvironment: go1.24.4 linux/arm'), '1.13.14');
  assert.equal(fullVersion('sing-box version 1.15.0-alpha.10\nEnvironment: go1.25.1'), '1.15.0-alpha.10');
  assert.equal(fullVersion('26.9.1'), '26.9.1');
  assert.equal(fullVersion('nightly'), '');
  assert.equal(fullVersion(''), '');
  assert.equal(fullVersion(null), '');
});

test('a pre-release is GitHub’s flag, or a semver pre-release tag GitHub was not told about', () => {
  assert.equal(isPrerelease({ tag_name: 'v26.9.30', prerelease: true }), true);
  assert.equal(isPrerelease({ tag_name: 'v26.3.27', prerelease: false }), false);
  assert.equal(isPrerelease({ tag_name: 'v1.15.0-alpha.3', prerelease: false }), true);
});

/* ------------------------------ the cards ------------------------------ */

test('Xray-PattN, stable: the 6 newest with this platform’s build, newest first, each with its action', () => {
  const cards = buildCards({ releases: rel.pattn(), matchAsset: xrayWin, installed: '26.9.22', latestTag: 'v26.10.3', suggested: SUGGESTED['xray-pattn'], prerelease: false });
  assert.deepEqual(versions(cards), ['26.10.3', '26.9.27', '26.9.26', '26.9.24', '26.9.22', '26.9.13']);
  assert.deepEqual(cards.map((c) => c.action), ['upgrade', 'upgrade', 'upgrade', 'upgrade', 'reinstall', 'downgrade']);
  const [latest, , , , here, older] = cards;
  assert.deepEqual(latest, {
    version: '26.10.3', tag: 'v26.10.3', date: '2026-10-03T09:30:00Z', size: 20594290, asset: 'Xray-windows-64.zip',
    prerelease: false, isInstalled: false, isSuggested: false, isLatest: true, action: 'upgrade', olderThanSuggested: false
  });
  assert.equal(here.isInstalled && here.isSuggested && !here.isLatest, true);
  assert.equal(older.olderThanSuggested, true, 'older than the suggested 26.9.22');
  assert.equal(cards.filter((c) => c.isLatest).length, 1);
});

test('Xray (official), stable: 26.3.27 is GitHub’s latest and the suggested one; every 2026 pre-release stays out', () => {
  const cards = buildCards({ releases: rel.xtls(), matchAsset: xrayRouter, installed: '26.3.27', latestTag: 'v26.3.27', suggested: SUGGESTED.xray, prerelease: false });
  assert.deepEqual(versions(cards), ['26.3.27', '26.2.6', '26.1.23', '25.12.8', '25.10.15', '25.9.11']);
  assert.equal(cards[0].isLatest && cards[0].isSuggested && cards[0].isInstalled, true);
  assert.equal(cards[0].asset, 'Xray-linux-arm32-v7a.zip', 'the router’s build');
  assert.ok(cards.slice(1).every((c) => c.action === 'downgrade' && c.olderThanSuggested && !c.prerelease));
});

test('with pre-releases: the 4 newest pre-releases join the stables, ordered by version', () => {
  const cards = buildCards({ releases: rel.xtls(), matchAsset: xrayWin, installed: '26.3.27', latestTag: 'v26.3.27', suggested: SUGGESTED.xray, prerelease: true });
  assert.deepEqual(versions(cards), ['26.9.30', '26.9.9', '26.9.8', '26.7.28', '26.3.27', '26.2.6', '26.1.23', '25.12.8', '25.10.15', '25.9.11']);
  assert.deepEqual(cards.slice(0, 4).map((c) => [c.prerelease, c.action, c.isLatest]), Array(4).fill([true, 'upgrade', false]));
});

test('sing-box: alphas sort by their number, the suggested 1.13.14 is offered although it is older than the 6 newest', () => {
  const releases = rel.singbox().concat(rel.singboxTag('v1.13.14'));   // the downloader adds the suggested tag (listReleases)
  const pre = buildCards({ releases, matchAsset: sbWin, installed: '1.14.2', latestTag: 'v1.14.2', suggested: SUGGESTED['sing-box'], prerelease: true });
  assert.deepEqual(versions(pre), ['1.15.0-alpha.10', '1.15.0-alpha.9', '1.15.0-alpha.8', '1.15.0-alpha.7',
    '1.14.2', '1.14.1', '1.14.0', '1.13.21', '1.13.20', '1.13.19', '1.13.14']);
  assert.equal(pre[0].asset, 'sing-box-1.15.0-alpha.10-windows-amd64.zip', 'not the -legacy build');
  const sug = pre.at(-1);
  assert.equal(sug.isSuggested && sug.action === 'downgrade' && !sug.olderThanSuggested, true);
  assert.equal(pre.find((c) => c.version === '1.13.19').olderThanSuggested, false, 'newer than 1.13.14');
  const stable = buildCards({ releases, matchAsset: sbWin, installed: '1.14.2', latestTag: 'v1.14.2', suggested: SUGGESTED['sing-box'], prerelease: false });
  assert.deepEqual(versions(stable), ['1.14.2', '1.14.1', '1.14.0', '1.13.21', '1.13.20', '1.13.19', '1.13.14']);
  assert.equal(stable[0].isInstalled && stable[0].isLatest && stable[0].action === 'reinstall', true);
});

test('the installed version is always a card — a pre-release in the stable list, marked as one', () => {
  const cards = buildCards({ releases: rel.xtls(), matchAsset: xrayWin, installed: '26.9.9', latestTag: 'v26.3.27', suggested: SUGGESTED.xray, prerelease: false });
  assert.deepEqual(versions(cards), ['26.9.9', '26.3.27', '26.2.6', '26.1.23', '25.12.8', '25.10.15', '25.9.11']);
  assert.deepEqual([cards[0].isInstalled, cards[0].prerelease, cards[0].action], [true, true, 'reinstall']);
  assert.equal(cards[1].action, 'downgrade');
  // a pre-release sing-box reads its suffix from the core's own output, not just x.y.z
  const sb = buildCards({ releases: rel.singbox(), matchAsset: sbWin, installed: fullVersion('sing-box version 1.15.0-alpha.9'), latestTag: 'v1.14.2', suggested: SUGGESTED['sing-box'], prerelease: true });
  assert.deepEqual(sb.filter((c) => c.isInstalled).map((c) => c.version), ['1.15.0-alpha.9']);
  assert.deepEqual(sb.slice(0, 2).map((c) => c.action), ['upgrade', 'reinstall']);
});

test('nothing installed (or a version that cannot be read): every card installs', () => {
  for (const installed of ['', null, undefined]) {
    const cards = buildCards({ releases: rel.pattn(), matchAsset: xrayWin, installed, latestTag: 'v26.10.3', suggested: SUGGESTED['xray-pattn'], prerelease: false });
    assert.equal(cards.length, STABLE_COUNT);
    assert.ok(cards.every((c) => c.action === 'install' && !c.isInstalled), String(installed));
  }
});

test('never a draft, never a release without this platform’s build, never a tag with no version', () => {
  const releases = rel.pattn();
  releases[0].draft = true;                                                         // 26.10.3
  releases[1].assets = releases[1].assets.filter((a) => !/windows/.test(a.name));  // 26.9.27: no Windows build
  releases.push({ tag_name: 'nightly', prerelease: false, draft: false, published_at: '2026-10-01T00:00:00Z', assets: rel.xrayAssets('patterniha/Xray-core', 'nightly') });
  releases.push(Object.assign({}, releases[4], { tag_name: '26.9.22' }));          // the same version twice
  const cards = buildCards({ releases, matchAsset: xrayWin, installed: '', latestTag: '', suggested: '26.9.22', prerelease: true });
  assert.deepEqual(versions(cards), ['26.9.26', '26.9.24', '26.9.22', '26.9.13', '26.9.9', '26.9.8']);
  assert.equal(cards.filter((c) => c.version === '26.9.22').length, 1);
  // GitHub's latest unknown: the newest stable release that is not a draft —
  // 26.9.27, whose missing Windows build means no card here is "Latest"
  // (Update, which installs that one, would not find a build either)
  assert.equal(latestOf(releases, ''), '26.9.27', 'not the draft');
  assert.equal(cards.some((c) => c.isLatest), false);
  assert.equal(latestOf(releases, 'v26.9.26'), '26.9.26', 'GitHub’s word when it gave one');
  assert.equal(buildCards({ releases, matchAsset: xrayWin, installed: '', latestTag: 'v26.9.26', suggested: '', prerelease: false })[0].isLatest, true);
  assert.equal(latestOf([], ''), '');
  // a garbage list is no cards, not a throw
  assert.deepEqual(buildCards({ releases: [null, 42, {}], matchAsset: xrayWin, installed: '', latestTag: '', suggested: '', prerelease: true }), []);
  assert.deepEqual(buildCards({ releases: null, matchAsset: xrayWin }), []);
});

/* ------------------------------ the handlers (main.js and service.js) ------------------------------ */

function fakeDownloader(over = {}) {
  const calls = [];
  const d = Object.assign({
    calls,
    target: (id) => ({ platform: 'linux', arch: 'arm', asset: id === 'sing-box' ? 'sing-box-*-linux-armv7.tar.gz' : 'Xray-linux-arm32-v7a.zip' }),
    assetMatcher: () => xrayRouter,
    listReleases: async (id, opts) => { calls.push(['list', id, opts]); return { releases: rel.pattn(), latestTag: 'v26.10.3' }; },
    installVersion: async (id, tag, opts) => { calls.push(['install', id, tag]); if (opts && opts.beforePlace) await opts.beforePlace(); return { ok: true, component: id, tag, version: tag.replace(/^v/, '') }; }
  }, over);
  return d;
}

function makeApi(over = {}) {
  const log = [];
  const after = [];
  let busy = false;
  const downloader = over.downloader || fakeDownloader();
  const api = createCoreVersionsApi(Object.assign({
    downloader,
    installedVersion: async (id) => (id === 'sing-box' ? 'sing-box version 1.13.14' : 'Xray 26.9.22 (Xray, Penetrates Everything.)'),
    busy: () => busy,
    afterInstall: (id) => after.push(id),
    result: () => ({ assets: { 'xray-pattn': true }, tunAvailable: true, xrayReady: true }),
    onLog: (line, level) => log.push([level, line])
  }, over));
  return { api, log, after, downloader, setBusy: (b) => { busy = b; } };
}

test('cores:versions — the installed, suggested and latest versions, the platform and the cards', async () => {
  const h = makeApi();
  const res = await h.api.versions({ component: 'xray-pattn', prerelease: false });
  assert.equal(res.ok, true);
  assert.equal(res.component, 'xray-pattn');
  assert.equal(res.installed, '26.9.22', 'read out of `xray-pattn version`');
  assert.equal(res.suggested, '26.9.22');
  assert.equal(res.latest, '26.10.3');
  assert.deepEqual(res.platform, { platform: 'linux', arch: 'arm', asset: 'Xray-linux-arm32-v7a.zip' });
  assert.equal(res.busy, false);
  assert.equal(res.installing, null);
  assert.deepEqual(versions(res.cards), ['26.10.3', '26.9.27', '26.9.26', '26.9.24', '26.9.22', '26.9.13']);
  assert.deepEqual(h.downloader.calls, [['list', 'xray-pattn', { force: false }]]);
  // Retry asks GitHub again
  await h.api.versions({ component: 'xray-pattn', prerelease: true, force: true });
  assert.deepEqual(h.downloader.calls[1], ['list', 'xray-pattn', { force: true }]);
  // while connected the list still comes, with busy set (the modal disables its actions)
  h.setBusy(true);
  assert.equal((await h.api.versions({ component: 'xray-pattn' })).busy, true);
});

test('cores:versions — GitHub unreachable or rate-limited is a reason the modal can word, not a throw', async () => {
  const down = makeApi({ downloader: fakeDownloader({ listReleases: async () => { throw Object.assign(new Error('getaddrinfo ENOTFOUND api.github.com'), { code: 'ENOTFOUND' }); } }) });
  const res = await down.api.versions({ component: 'xray' });
  assert.equal(res.ok, false);
  assert.equal(res.reason, 'network');
  assert.match(res.error, /ENOTFOUND/);
  assert.equal(res.installed, '26.9.22');
  assert.deepEqual(res.cards, []);
  const limited = makeApi({ downloader: fakeDownloader({ listReleases: async () => { throw Object.assign(new Error('GitHub: HTTP 403 — API rate limit exceeded'), { status: 403, rateLimited: true }); } }) });
  assert.equal((await limited.api.versions({ component: 'xray' })).reason, 'rate-limit');
  // an installed version that cannot be read is '' — the cards then say Install
  const unread = makeApi({ installedVersion: async () => { throw new Error('spawn EACCES'); } });
  const r2 = await unread.api.versions({ component: 'xray-pattn' });
  assert.equal(r2.installed, '');
  assert.ok(r2.cards.every((c) => c.action === 'install'));
  // a core without a picker
  assert.deepEqual(await down.api.versions({ component: 'geo' }), { ok: false, error: 'unknown core: geo' });
  assert.deepEqual(await down.api.versions(null), { ok: false, error: 'unknown core: undefined' });
});

test('cores:install — refused while connected or connecting, before anything is downloaded', async () => {
  const h = makeApi();
  h.setBusy(true);
  const res = await h.api.install({ component: 'xray-pattn', tag: 'v26.9.13' });
  assert.deepEqual(res, { ok: false, refused: 'connected', component: 'xray-pattn', tag: 'v26.9.13' });
  assert.deepEqual(h.downloader.calls, [], 'nothing fetched');
  assert.deepEqual(h.after, []);
});

test('cores:install — a connect that starts during the download is refused before the binary is replaced', async () => {
  const h = makeApi();
  h.downloader.installVersion = async (id, tag, opts) => { h.setBusy(true); await opts.beforePlace(); throw new Error('placed anyway'); };
  const res = await h.api.install({ component: 'xray', tag: 'v26.3.27' });
  assert.equal(res.ok, false);
  assert.equal(res.refused, 'connected');
  assert.deepEqual(h.after, [], 'nothing to refresh: nothing changed');
});

test('cores:install — installs, then the same refresh as a download, and answers like one', async () => {
  const h = makeApi();
  const res = await h.api.install({ component: 'xray-pattn', tag: 'v26.9.13' });
  assert.deepEqual(res, { ok: true, component: 'xray-pattn', tag: 'v26.9.13', version: '26.9.13', assets: { 'xray-pattn': true }, tunAvailable: true, xrayReady: true });
  assert.deepEqual(h.downloader.calls, [['install', 'xray-pattn', 'v26.9.13']]);
  assert.deepEqual(h.after, ['xray-pattn']);
  assert.ok(h.log.some(([level, line]) => level === 'info' && /Xray-PattN.*26\.9\.13/.test(line)), JSON.stringify(h.log));
});

test('cores:install — one at a time; a failure is said, nothing is refreshed, and the next one may run', async () => {
  const h = makeApi();
  let open;
  h.downloader.installVersion = (id, tag) => new Promise((resolve, reject) => { open = { resolve, reject, tag }; });
  const first = h.api.install({ component: 'sing-box', tag: 'v1.13.14' });
  await new Promise((r) => setImmediate(r));
  const second = await h.api.install({ component: 'xray', tag: 'v26.3.27' });
  assert.deepEqual(second, { ok: false, refused: 'installing', component: 'xray', tag: 'v26.3.27', installing: { component: 'sing-box', tag: 'v1.13.14' } });
  assert.deepEqual((await h.api.versions({ component: 'xray' })).installing, { component: 'sing-box', tag: 'v1.13.14' });
  open.reject(new Error('the downloaded core says it is 1.13.13, not 1.13.14 — nothing was replaced'));
  const res = await first;
  assert.equal(res.ok, false);
  assert.match(res.error, /nothing was replaced/);
  assert.deepEqual(res.assets, { 'xray-pattn': true }, 'what is on disk, as a download failure answers');
  assert.deepEqual(h.after, []);
  assert.ok(h.log.some(([level, line]) => level === 'error' && /sing-box v1\.13\.14/.test(line)));
  h.downloader.installVersion = async (id, tag) => ({ ok: true, component: id, tag, version: '26.3.27' });
  assert.equal((await h.api.install({ component: 'xray', tag: 'v26.3.27' })).ok, true, 'the lock went with the failure');
});

test('cores:install — another download of this core (M1) and the core file in use (M2) come back as reasons, not raw errors', async () => {
  const busy = makeApi();
  busy.downloader.installVersion = async () => { throw Object.assign(new Error('another download or install of this core is running'), { code: 'ECOREBUSY' }); };
  assert.deepEqual(await busy.api.install({ component: 'sing-box', tag: 'v1.13.14' }), { ok: false, refused: 'core-busy', component: 'sing-box', tag: 'v1.13.14' });
  assert.deepEqual(busy.after, []);
  const inUse = makeApi();
  inUse.downloader.installVersion = async () => { throw Object.assign(new Error('the core file is in use — close latency tests and try again; nothing was replaced'), { code: 'ECOREINUSE' }); };
  const res = await inUse.api.install({ component: 'xray', tag: 'v26.3.27' });
  assert.equal(res.ok, false);
  assert.equal(res.reason, 'in-use');
  assert.match(res.error, /in use/);
  assert.deepEqual(res.assets, { 'xray-pattn': true });
  assert.ok(inUse.log.some(([level, line]) => level === 'warn' && /in use/.test(line)), 'a warning, not an error: nothing broke');
});

test('cores:install — only the three cores, only a release tag', async () => {
  const h = makeApi();
  for (const [component, tag] of [['geo', 'v1.0.0'], ['wintun', 'v0.14.1'], ['xray', '../../etc/passwd'], ['xray', 'latest'], ['xray', ''], ['xray', 'v26.3.27/../x']]) {
    const res = await h.api.install({ component, tag });
    assert.equal(res.ok, false, `${component} ${tag}`);
    assert.match(res.error, /unknown core|not a release tag/);
  }
  assert.deepEqual(h.downloader.calls, []);
});
