'use strict';
/**
 * The downloader's half of the version picker: the release list (GitHub's API,
 * cached ten minutes per core) and the install of one chosen tag — downloaded,
 * extracted, run (`<bin> version` must name the tag's version) and only then
 * put in place. Whatever fails, the installed core stays as it was.
 *
 * GitHub, the download, the archive and the core's run are the downloader's
 * seams; a local http server stands in for the network where the real helpers
 * are tested. Nothing here reaches GitHub, runs a core or touches a real bin.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');

const { Downloader, downloadFile, fetchJSON, runVersion, RELEASES_TTL_MS } = require('../src/main/downloader');
const rel = require('./coreReleases');

const tmpDirs = [];
function tmp(tag) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), `irnf-dlv-${tag}-`));
  tmpDirs.push(d);
  return d;
}
test.after(() => { for (const d of tmpDirs) { try { fs.rmSync(d, { recursive: true, force: true }); } catch {} } });

function serve(handler) {
  return new Promise((resolve) => {
    const srv = http.createServer(handler);
    srv.listen(0, '127.0.0.1', () => resolve({ srv, port: srv.address().port, url: (p) => `http://127.0.0.1:${srv.address().port}${p}` }));
  });
}
const close = (srv) => new Promise((r) => { if (srv.closeAllConnections) srv.closeAllConnections(); srv.close(() => r()); });

/* ------------------------------ GitHub's API ------------------------------ */

test('fetchJSON: the answer parsed; redirects followed', { timeout: 15000 }, async () => {
  const s = await serve((req, res) => {
    if (req.url === '/moved') { res.writeHead(301, { Location: '/releases' }); return res.end(); }
    assert.equal(req.headers['user-agent'], 'IRNetFree');
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify([{ tag_name: 'v1.2.3' }]));
  });
  try {
    assert.deepEqual(await fetchJSON(s.url('/moved')), [{ tag_name: 'v1.2.3' }]);
  } finally { await close(s.srv); }
});

test('fetchJSON: an HTTP error rejects with GitHub’s own message, and a rate limit says so', { timeout: 15000 }, async () => {
  const s = await serve((req, res) => {
    if (req.url === '/limited') {
      res.writeHead(403, { 'Content-Type': 'application/json', 'x-ratelimit-remaining': '0' });
      return res.end(JSON.stringify({ message: 'API rate limit exceeded for 5.6.7.8. (But here’s the good news: …)' }));
    }
    if (req.url === '/notjson') { res.writeHead(200); return res.end('<html>'); }
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ message: 'Not Found' }));
  });
  try {
    await assert.rejects(fetchJSON(s.url('/limited')), (e) => e.status === 403 && e.rateLimited === true && /HTTP 403 — API rate limit exceeded/.test(e.message));
    await assert.rejects(fetchJSON(s.url('/repos/x/y/releases/tags/v9.9.9')), (e) => e.status === 404 && e.rateLimited === false && /HTTP 404 — Not Found/.test(e.message));
    await assert.rejects(fetchJSON(s.url('/notjson')), /not JSON/);
  } finally { await close(s.srv); }
});

test('fetchJSON: a server that stops answering is a timeout, not a modal that spins for ever', { timeout: 15000 }, async () => {
  const s = await serve(() => { /* never answers */ });
  try {
    const t0 = Date.now();
    await assert.rejects(fetchJSON(s.url('/releases'), { idleTimeoutMs: 150 }), (e) => e.code === 'ETIMEDOUT' && /did not answer in time/.test(e.message));
    assert.ok(Date.now() - t0 < 3000);
    // and plain http is the tests' seam only
    await assert.rejects(fetchJSON('http://api.github.invalid/repos'), /plain http/);
  } finally { await close(s.srv); }
});

test('downloadFile: with an idle timeout, a download that stalls is given up and leaves nothing behind', { timeout: 15000 }, async () => {
  const s = await serve((req, res) => {
    res.writeHead(200, { 'Content-Length': 100000 });
    res.write(Buffer.alloc(1000, 1));   // then nothing, connection held open
  });
  const dest = path.join(tmp('stall'), 'Xray-linux-64.zip');
  try {
    await assert.rejects(downloadFile(s.url('/x.zip'), dest, null, { idleTimeoutMs: 150 }), /stalled|cut off/);
    assert.equal(fs.existsSync(dest), false);
  } finally { await close(s.srv); }
});

/* ------------------------------ the platform's build ------------------------------ */

test('assetMatcher / target: this machine’s archive of each core, as the update button picks it', () => {
  const router = new Downloader({ destDir: tmp('m1'), platform: 'linux', arch: 'arm' });
  const m = router.assetMatcher('xray-pattn');
  assert.equal(m('Xray-linux-arm32-v7a.zip'), true);
  assert.equal(m('Xray-linux-arm32-v7a.zip.dgst'), false);
  assert.equal(m('Xray-linux-arm32-v6.zip'), false);
  assert.deepEqual(router.target('xray'), { platform: 'linux', arch: 'arm', asset: 'Xray-linux-arm32-v7a.zip' });
  assert.deepEqual(router.target('sing-box'), { platform: 'linux', arch: 'arm', asset: 'sing-box-*-linux-armv7.tar.gz' });
  const sb = router.assetMatcher('sing-box');
  assert.equal(sb('sing-box-1.15.0-alpha.10-linux-armv7.tar.gz'), true);
  assert.equal(sb('sing-box-1.13.14-linux-armv7.tar.gz.sha256'), false);
  // the display name and the matcher agree on every platform
  for (const [platform, arch] of [['win32', 'x64'], ['win32', 'arm64'], ['darwin', 'x64'], ['darwin', 'arm64'], ['linux', 'x64'], ['linux', 'arm64'], ['linux', 'arm'], ['linux', 'mipsel']]) {
    const d = new Downloader({ destDir: tmp('m2'), platform, arch });
    assert.equal(d.assetMatcher('sing-box')(d.target('sing-box').asset.replace('*', '1.13.14')), true, `${platform} ${arch}`);
    assert.equal(d.assetMatcher('xray')(d.target('xray').asset), true, `${platform} ${arch}`);
    assert.equal(d.target('xray').asset, d.xrayAssetName(platform, arch));
  }
  assert.throws(() => router.target('geo'), /unknown core/);
  assert.throws(() => router.assetMatcher('wintun'), /unknown core/);
});

/* ------------------------------ the release list ------------------------------ */

function lister(answers, over = {}) {
  const asked = [];
  let now = 1000000;
  const d = new Downloader(Object.assign({
    destDir: tmp('list'), platform: 'win32', arch: 'x64', now: () => now,
    fetchJSON: async (url) => {
      asked.push(url);
      const a = answers(url);
      if (a instanceof Error) throw a;
      return a;
    }
  }, over));
  return { d, asked, tick: (ms) => { now += ms; } };
}

test('listReleases: the 30 newest and GitHub’s latest, from the core’s own repo — trimmed to what the picker uses', async () => {
  const h = lister((url) => (url.endsWith('/latest') ? rel.pattn()[0] : rel.pattn()));
  const got = await h.d.listReleases('xray-pattn');
  assert.deepEqual(h.asked.sort(), [
    'https://api.github.com/repos/patterniha/Xray-core/releases/latest',
    'https://api.github.com/repos/patterniha/Xray-core/releases?per_page=30'
  ]);
  assert.equal(got.latestTag, 'v26.10.3');
  assert.equal(got.releases.length, rel.pattn().length);
  assert.deepEqual(got.releases[4], {
    tag_name: 'v26.9.22', name: 'v26.9.22', prerelease: false, draft: false, published_at: '2026-09-22T09:30:00Z',
    assets: [{ name: 'Xray-windows-64.zip', size: 20594290, browser_download_url: 'https://github.com/patterniha/Xray-core/releases/download/v26.9.22/Xray-windows-64.zip' }]
  }, 'one asset — this platform’s — and no uploader, body or the other 19 builds');
  assert.ok(JSON.stringify(got).length < 10000, 'kept small: a router holds this for ten minutes');
});

test('listReleases: cached ten minutes per core; Retry (force) asks again; a failure is not cached', async () => {
  let fail = false;
  const list = (url) => (url.includes('/patterniha/') ? rel.pattn() : rel.xtls());
  const h = lister((url) => (fail ? Object.assign(new Error('getaddrinfo ENOTFOUND api.github.com'), { code: 'ENOTFOUND' })
    : url.endsWith('/latest') ? list(url).find((r) => !r.prerelease) : list(url)));
  await h.d.listReleases('xray');
  assert.equal(h.asked.length, 2);
  h.tick(RELEASES_TTL_MS - 1);
  await h.d.listReleases('xray');
  assert.equal(h.asked.length, 2, 'within ten minutes: the cache');
  await h.d.listReleases('xray-pattn');
  assert.equal(h.asked.length, 4, 'another core is another list');
  h.tick(2);
  await h.d.listReleases('xray');
  assert.equal(h.asked.length, 6, 'after ten minutes: GitHub again');
  await h.d.listReleases('xray', { force: true });
  assert.equal(h.asked.length, 8, 'Retry');
  fail = true;
  await assert.rejects(h.d.listReleases('xray', { force: true }), /ENOTFOUND/);
  fail = false;
  h.tick(RELEASES_TTL_MS + 1);
  await assert.doesNotReject(h.d.listReleases('xray'));
  assert.equal(RELEASES_TTL_MS, 10 * 60 * 1000);
});

test('listReleases: two windows asking at once share one request', async () => {
  let release;
  const gate = new Promise((r) => { release = r; });
  const h = lister(() => null, { fetchJSON: async (url) => { h.asked.push(url); await gate; return url.endsWith('/latest') ? rel.pattn()[0] : rel.pattn(); } });
  const a = h.d.listReleases('xray-pattn');
  const b = h.d.listReleases('xray-pattn');
  release();
  assert.equal(await a, await b);
  assert.equal(h.asked.length, 2);
});

test('listReleases: a suggested release missing from the 30 newest is fetched by its tag — sing-box’s 1.14.3 on a list from before it', async () => {
  const h = lister((url) => {
    if (url.endsWith('/releases/tags/v1.14.3')) return rel.singboxTag('v1.14.3');
    if (url.endsWith('/latest')) return rel.singbox()[4];       // v1.14.2
    return rel.singbox().slice(1);                              // the list of 2026-10-03, before 1.14.3
  });
  const got = await h.d.listReleases('sing-box');
  assert.ok(h.asked.includes('https://api.github.com/repos/SagerNet/sing-box/releases/tags/v1.14.3'), h.asked.join('\n'));
  assert.equal(got.releases.at(-1).tag_name, 'v1.14.3');
  assert.deepEqual(got.releases.at(-1).assets.map((a) => a.name), ['sing-box-1.14.3-windows-amd64.zip']);
  assert.equal(got.latestTag, 'v1.14.2');
  // today's list holds it: no request by tag
  const now = lister((url) => (url.endsWith('/latest') ? rel.singbox()[0] : rel.singbox()));
  await now.d.listReleases('sing-box');
  assert.equal(now.asked.filter((u) => /\/tags\//.test(u)).length, 0);
  // in the list already: no extra request; that request failing, or /latest failing, costs nothing
  const p = lister((url) => (url.endsWith('/latest') ? rel.pattn()[0] : rel.pattn()));
  await p.d.listReleases('xray-pattn');
  assert.equal(p.asked.filter((u) => /\/tags\//.test(u)).length, 0);
  const f = lister((url) => (/\/tags\/|\/latest$/.test(url) ? Object.assign(new Error('GitHub: HTTP 404 — Not Found'), { status: 404 }) : rel.singbox()));
  const res = await f.d.listReleases('sing-box');
  assert.equal(res.releases.length, 30);
  assert.equal(res.latestTag, '');
});

test('listReleases: anything but a list (GitHub’s error object, null) is an error, not an empty picker', async () => {
  const h = lister((url) => (url.endsWith('/latest') ? null : { message: 'Bad credentials' }));
  await assert.rejects(h.d.listReleases('xray'), /did not answer with a list/);
  await assert.rejects(h.d.listReleases('geo'), /unknown core/);
});

/* ------------------------------ the default target: what a plain download installs ------------------------------ */

/** A downloader whose GitHub is `fetchJSON`; its log lines in `.logs`. */
function makeDownloader({ fetchJSON }) {
  const logs = [];
  const d = new Downloader({ destDir: tmp('def'), platform: 'win32', arch: 'x64', fetchJSON, onLog: (line, level) => logs.push([level, line]) });
  d.logs = logs;
  return d;
}

test('a plain download installs the suggested Xray when it is newer than GitHub’s latest stable', async () => {
  const asked = [];
  const d = makeDownloader({ fetchJSON: async (url) => {
    asked.push(url);
    if (url.endsWith('/releases/latest')) return { tag_name: 'v26.3.27', assets: [] };
    if (url.endsWith('/releases/tags/v26.9.30')) return { tag_name: 'v26.9.30', assets: [] };
    throw new Error('unexpected ' + url);
  } });
  const rel = await d.defaultRelease('xray');
  assert.equal(rel.tag_name, 'v26.9.30');
  assert.ok(asked.some(u => u.endsWith('/tags/v26.9.30')));
  assert.deepEqual(asked, [
    'https://api.github.com/repos/XTLS/Xray-core/releases/latest',
    'https://api.github.com/repos/XTLS/Xray-core/releases/tags/v26.9.30'
  ], 'the official core’s own repo');
});

test('a newer stable than the suggested one wins, and the suggested tag is not even fetched', async () => {
  const d = makeDownloader({ fetchJSON: async (url) => {
    if (url.endsWith('/releases/latest')) return { tag_name: 'v27.1.1', assets: [] };
    throw new Error('should not ask ' + url);
  } });
  assert.equal((await d.defaultRelease('xray')).tag_name, 'v27.1.1');
  // the same release as the suggested one: nothing more to ask either
  const same = makeDownloader({ fetchJSON: async (url) => {
    if (url.endsWith('/releases/latest')) return { tag_name: 'v26.9.30', assets: [] };
    throw new Error('should not ask ' + url);
  } });
  assert.equal((await same.defaultRelease('xray')).tag_name, 'v26.9.30');
});

test('the suggested release that cannot be fetched falls back to the latest stable', async () => {
  const d = makeDownloader({ fetchJSON: async (url) => {
    if (url.endsWith('/releases/latest')) return { tag_name: 'v26.3.27', assets: [] };
    throw new Error('HTTP 404');
  } });
  assert.equal((await d.defaultRelease('xray')).tag_name, 'v26.3.27');
  assert.ok(d.logs.some(([level, line]) => level === 'warn' && /Xray 26\.9\.30 could not be fetched \(HTTP 404\).*v26\.3\.27/.test(line)), JSON.stringify(d.logs));
  // an answer that is no release (no assets list) is the same miss
  const odd = makeDownloader({ fetchJSON: async (url) => (url.endsWith('/releases/latest') ? { tag_name: 'v26.3.27', assets: [] } : { message: 'Not Found' }) });
  assert.equal((await odd.defaultRelease('xray')).tag_name, 'v26.3.27');
});

test('Xray-PattN and sing-box: their latest stable is newer than the suggested one — installed as today, from their own repos', async () => {
  for (const [id, url, tag] of [
    ['xray-pattn', 'https://api.github.com/repos/patterniha/Xray-core/releases/latest', 'v26.10.3'],
    ['sing-box', 'https://api.github.com/repos/SagerNet/sing-box/releases/latest', 'v1.14.4'],
    // the same as the suggested one: nothing more to ask
    ['sing-box', 'https://api.github.com/repos/SagerNet/sing-box/releases/latest', 'v1.14.3']
  ]) {
    const asked = [];
    const d = makeDownloader({ fetchJSON: async (u) => { asked.push(u); return { tag_name: tag, assets: [] }; } });
    assert.equal((await d.defaultRelease(id)).tag_name, tag, id);
    assert.deepEqual(asked, [url], id);
  }
});

test('latestVersion names the default target: the weekly updater moves 26.3.27 to 26.9.30, never below', async () => {
  const d = makeDownloader({ fetchJSON: async () => ({ tag_name: 'v26.3.27', assets: [] }) });
  assert.equal(await d.latestVersion('xray'), '26.9.30');
  const e = makeDownloader({ fetchJSON: async () => ({ tag_name: 'v1.14.4', assets: [] }) });
  assert.equal(await e.latestVersion('sing-box'), '1.14.4');   // latest stable above ⭐ 1.14.3
  const older = makeDownloader({ fetchJSON: async (u) => ({ tag_name: /\/tags\//.test(u) ? 'v1.14.3' : 'v1.14.2', assets: [] }) });
  assert.equal(await older.latestVersion('sing-box'), '1.14.3', 'never below the suggested one');
  const f = makeDownloader({ fetchJSON: async () => ({ tag_name: 'v27.1.1', assets: [] }) });
  assert.equal(await f.latestVersion('xray'), '27.1.1');
});

test('Update (download) of a core goes through the default target: the suggested Xray’s release is the one searched for this platform’s build', async (t) => {
  // getXray / getSingbox download with the real https helpers, so this stops at
  // the asset lookup: the release they searched is the one the API calls name.
  // The preload blocks commands, not sockets: a lookup that went past the seam
  // (the module's own getJSON) must fail here, never reach GitHub.
  const https = require('node:https');
  const offline = () => { throw new Error('this test reached the real network'); };
  t.mock.method(https, 'get', offline);
  t.mock.method(http, 'get', offline);
  const asked = [];
  const answers = {
    'https://api.github.com/repos/XTLS/Xray-core/releases/latest': 'v26.3.27',
    'https://api.github.com/repos/XTLS/Xray-core/releases/tags/v26.9.30': 'v26.9.30',
    'https://api.github.com/repos/SagerNet/sing-box/releases/latest': 'v1.14.3'
  };
  const d = makeDownloader({ fetchJSON: async (url) => {
    asked.push(url);
    if (!answers[url]) throw new Error('unexpected ' + url);
    return { tag_name: answers[url], assets: [] };
  } });
  await assert.rejects(d.download('xray'), /asset not found/);
  assert.deepEqual(asked, [
    'https://api.github.com/repos/XTLS/Xray-core/releases/latest',
    'https://api.github.com/repos/XTLS/Xray-core/releases/tags/v26.9.30'
  ]);
  assert.ok(d.logs.some(([, line]) => line === '[download] Fetching Xray (official) release info…'), JSON.stringify(d.logs));
  asked.length = 0;
  await assert.rejects(d.download('sing-box'), /sing-box asset not found/);
  assert.deepEqual(asked, ['https://api.github.com/repos/SagerNet/sing-box/releases/latest']);
});

/* ------------------------------ installing one version ------------------------------ */

/**
 * A downloader over fakes: a "release" for every tag, an archive that holds
 * `files`, a core that answers `version`. `fail` names the stage that breaks.
 */
function installer({ platform = 'linux', arch = 'arm', component = 'xray-pattn', fail = null, files = null, versionOut = null } = {}) {
  const destDir = tmp('dest');
  const calls = [];
  const work = { dir: null };
  const sb = component === 'sing-box';
  const win = platform === 'win32';
  const placedName = sb ? (win ? 'sing-box.exe' : 'sing-box') : (component === 'xray' ? (win ? 'xray.exe' : 'xray') : (win ? 'xray-pattn.exe' : 'xray-pattn'));
  const d = new Downloader({
    destDir, platform, arch,
    onLog: (line) => calls.push('log:' + line),
    onProgress: (c, p) => calls.push(`progress:${c}:${p}`),
    fetchJSON: async (url) => {
      calls.push('api:' + url);
      if (fail === 'release') throw Object.assign(new Error('GitHub: HTTP 404 — Not Found'), { status: 404 });
      const tag = decodeURIComponent(url.split('/tags/')[1]);
      const r = sb ? rel.singboxTag(tag) : rel.releases(component === 'xray' ? 'XTLS/Xray-core' : 'patterniha/Xray-core', [[tag, '2026-09-13', false]], (t) => rel.xrayAssets('x/y', t))[0];
      if (fail === 'asset') r.assets = r.assets.filter((a) => !/linux-arm|windows|macos/.test(a.name));
      return r;
    },
    fetchFile: async (url, dest, onProgress, opts) => {
      work.dir = path.dirname(dest);
      calls.push(`download:${path.basename(dest)}:${opts && opts.idleTimeoutMs}`);
      if (fail === 'download') throw new Error('the download was cut off');
      onProgress(40); onProgress(100);
      fs.writeFileSync(dest, 'ARCHIVE');
    },
    extractArchive: async (archive, dir) => {
      calls.push('extract:' + path.basename(archive));
      if (fail === 'extract') throw new Error('End-of-central-directory signature not found');
      const put = files || (sb ? { [`sing-box-1.13.14-${platform}-x/${placedName}`]: 'NEW SING-BOX' } : { [win ? 'xray.exe' : 'xray']: 'NEW CORE', 'geoip.dat': 'NEW GEOIP', 'geosite.dat': 'NEW GEOSITE', LICENSE: 'MPL' });
      for (const [rel, body] of Object.entries(put)) {
        fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
        fs.writeFileSync(path.join(dir, rel), body);
      }
    },
    runVersion: async (bin) => {
      calls.push('run:' + path.basename(bin) + ':' + fs.readFileSync(bin, 'utf8'));
      if (fail === 'run') throw new Error('spawn EACCES');
      return versionOut != null ? versionOut : (sb ? 'sing-box version 1.13.14\n\nEnvironment: go1.24.4 linux/arm\n' : 'Xray 26.9.13 (Xray, Penetrates Everything.) 0d3fd61 (go1.26.1 linux/arm)\nA unified platform for anti-censorship.\n');
    },
    copyFile: fail === 'place' ? (from, to) => { fs.writeFileSync(to, 'HALF'); throw Object.assign(new Error('ENOSPC: no space left on device'), { code: 'ENOSPC' }); } : undefined
  });
  // a Mac's quarantine strip + ad-hoc signature: recorded, never run. place()
  // asks for it again on the `.new` copy when the suite runs on a real Mac —
  // that is place()'s own step, not one this install adds, so it is not recorded.
  d.macPrepareBinary = (file, exec) => { if (!/\.new$/.test(file)) calls.push(`macprep:${path.basename(file)}:${exec}`); };
  // what is installed now, and the geo files the last download put there
  fs.writeFileSync(path.join(destDir, placedName), 'WORKING CORE');
  fs.writeFileSync(path.join(destDir, 'geoip.dat'), 'OLD GEOIP');
  return { d, destDir, calls, work, placedName, installed: () => fs.readFileSync(path.join(destDir, placedName), 'utf8') };
}

test('installVersion: downloads the tag’s build, runs it, and only then puts it in place — the geo files stay', async () => {
  const h = installer();
  const res = await h.d.installVersion('xray-pattn', 'v26.9.13');
  assert.deepEqual(res, { ok: true, component: 'xray-pattn', tag: 'v26.9.13', version: '26.9.13', file: path.join(h.destDir, 'xray-pattn') });
  assert.equal(h.installed(), 'NEW CORE');
  assert.equal(fs.readFileSync(path.join(h.destDir, 'geoip.dat'), 'utf8'), 'OLD GEOIP', 'a version install never replaces the geo files');
  assert.equal(fs.existsSync(path.join(h.destDir, 'geosite.dat')), false);
  assert.deepEqual(h.calls.filter((c) => !c.startsWith('log:')), [
    'api:https://api.github.com/repos/patterniha/Xray-core/releases/tags/v26.9.13',
    'download:Xray-linux-arm32-v7a.zip:60000',
    'progress:xray-pattn:40', 'progress:xray-pattn:100',
    'extract:Xray-linux-arm32-v7a.zip',
    'run:xray:NEW CORE'
  ]);
  assert.equal(fs.existsSync(h.work.dir), false, 'the work dir is gone');
  assert.equal(fs.existsSync(path.join(h.destDir, 'xray-pattn.new')), false);
  if (process.platform !== 'win32') assert.equal(fs.statSync(path.join(h.destDir, 'xray-pattn')).mode & 0o111, 0o111, 'executable');
});

for (const stage of ['release', 'asset', 'download', 'extract', 'missing', 'run', 'mismatch', 'noversion', 'connected', 'place']) {
  test(`installVersion: a failure at "${stage}" leaves the installed core exactly as it was`, async () => {
    const h = installer({
      fail: stage,
      files: stage === 'missing' ? { 'README.md': 'no binary in here' } : null,
      versionOut: stage === 'mismatch' ? 'Xray 26.9.12 (Xray, Penetrates Everything.)' : stage === 'noversion' ? 'Illegal instruction' : null
    });
    const opts = stage === 'connected' ? { beforePlace: () => { throw Object.assign(new Error('a connection started'), { refused: 'connected' }); } } : {};
    const want = {
      release: /HTTP 404/, asset: /v26\.9\.13 has no build for this platform \(Xray-linux-arm32-v7a\.zip\)/, download: /cut off/,
      extract: /End-of-central-directory/, missing: /xray not found in Xray-linux-arm32-v7a\.zip/, run: /did not run \(spawn EACCES\)/,
      mismatch: /says it is 26\.9\.12, not 26\.9\.13/, noversion: /did not say its version/, connected: /a connection started/, place: /ENOSPC/
    }[stage];
    await assert.rejects(h.d.installVersion('xray-pattn', 'v26.9.13', opts), (e) => want.test(e.message) && (stage !== 'connected' || e.refused === 'connected'));
    assert.equal(h.installed(), 'WORKING CORE');
    assert.equal(fs.existsSync(path.join(h.destDir, 'xray-pattn.new')), false);
    assert.equal(fs.readFileSync(path.join(h.destDir, 'geoip.dat'), 'utf8'), 'OLD GEOIP');
    if (h.work.dir) assert.equal(fs.existsSync(h.work.dir), false, 'the work dir is gone');
    if (['mismatch', 'noversion', 'run'].includes(stage)) assert.ok(/nothing was replaced/.test((await h.d.installVersion('xray-pattn', 'v26.9.13').catch((e) => e)).message));
  });
}

test('installVersion: on a Mac the binary is unquarantined and signed before it is run', async () => {
  const h = installer({ platform: 'darwin', arch: 'arm64' });
  await h.d.installVersion('xray-pattn', 'v26.9.13');
  const order = h.calls.filter((c) => /^(macprep|run|download):/.test(c));
  assert.deepEqual(order.slice(0, 3), ['download:Xray-macos-arm64-v8a.zip:60000', 'macprep:xray:true', 'run:xray:NEW CORE']);
  assert.equal(h.installed(), 'NEW CORE');
});

test('installVersion: sing-box from its tar.gz, the binary in a folder inside — Windows names', async () => {
  const h = installer({ platform: 'win32', arch: 'x64', component: 'sing-box' });
  const res = await h.d.installVersion('sing-box', 'v1.13.14');
  assert.equal(res.version, '1.13.14');
  assert.equal(res.file, path.join(h.destDir, 'sing-box.exe'));
  assert.equal(h.installed(), 'NEW SING-BOX');
  assert.ok(h.calls.includes('download:sing-box-1.13.14-windows-amd64.zip:60000'), h.calls.join('\n'));
  assert.ok(h.calls.includes('run:sing-box.exe:NEW SING-BOX'));
});

test('installVersion: a release the list already holds is not asked for again', async () => {
  const h = installer({ platform: 'win32', arch: 'x64' });
  h.d.fetchJSON = async (url) => { h.calls.push('api:' + url); return url.endsWith('/latest') ? rel.pattn()[0] : rel.pattn(); };
  await h.d.listReleases('xray-pattn');
  h.calls.length = 0;
  h.d.fetchJSON = async (url) => { throw new Error('asked GitHub again: ' + url); };
  await h.d.installVersion('xray-pattn', 'v26.9.13');
  assert.ok(h.calls.includes('download:Xray-windows-64.zip:60000'), h.calls.join('\n'));
  assert.equal(h.installed(), 'NEW CORE');
});

test('installVersion: only the three cores, only a release tag — nothing fetched otherwise', async () => {
  const h = installer();
  for (const [c, tag, re] of [['geo', 'v1.0.0', /unknown core/], ['xray', 'latest', /not a release tag/], ['xray', '../v1.2.3', /not a release tag/], ['xray', 'v1.2.3/x', /not a release tag/]]) {
    await assert.rejects(h.d.installVersion(c, tag), re, `${c} ${tag}`);
  }
  assert.deepEqual(h.calls, []);
});

/* ------------------------------ review fixes: one core, one writer (M1); the file in use (M2) ------------------------------ */

test('M1: Update (download) and a version install never run on the same core at once — either way round; other cores are free', async () => {
  const h = installer();
  let release;
  h.d.getXray = () => new Promise((r) => { release = () => r({ ok: true, files: [] }); });
  const update = h.d.download('xray-pattn');
  await assert.rejects(h.d.installVersion('xray-pattn', 'v26.9.13'), (e) => e.code === 'ECOREBUSY' && /another download or install of this core is running/.test(e.message));
  assert.equal(h.installed(), 'WORKING CORE');
  assert.equal(h.calls.filter((c) => c.startsWith('api:')).length, 0, 'refused before asking GitHub');
  // the official core is another file: installed meanwhile
  assert.equal((await h.d.installVersion('xray', 'v26.9.13')).ok, true);
  release();
  await update;
  // the other way round: an Update while an install downloads
  let open;
  h.d.fetchFile = (url, dest) => new Promise((r) => { open = () => { fs.writeFileSync(dest, 'zip'); r(); }; });
  const install = h.d.installVersion('xray-pattn', 'v26.9.13');
  await assert.rejects(h.d.download('xray-pattn'), (e) => e.code === 'ECOREBUSY');
  await new Promise((r) => setImmediate(r));
  open();
  await install;
  assert.equal(h.installed(), 'NEW CORE');
  // released after a failure too; the geo files are never held
  h.d.getXray = async () => { throw new Error('HTTP 403'); };
  await assert.rejects(h.d.download('xray-pattn'), /HTTP 403/);
  h.d.getXray = async () => ({ ok: true, files: [] });
  assert.deepEqual(await h.d.download('xray-pattn'), { ok: true, files: [] });
  h.d.getGeo = async () => ({ ok: true, files: [] });
  await Promise.all([h.d.download('geo'), h.d.download('geo')]);
});

test('M2: Windows — the core file held by a short-lived core (a latency test, a config check) is said in plain words, and nothing is replaced', async () => {
  for (const code of ['EPERM', 'EBUSY', 'EACCES']) {
    const h = installer({ platform: 'win32', arch: 'x64' });
    h.d.place = () => { throw Object.assign(new Error(`${code}: operation not permitted, rename 'C:\\bin\\xray-pattn.exe.new' -> 'C:\\bin\\xray-pattn.exe'`), { code }); };
    await assert.rejects(h.d.installVersion('xray-pattn', 'v26.9.13'),
      (e) => e.code === 'ECOREINUSE' && /in use/.test(e.message) && /nothing was replaced/.test(e.message) && !/rename/.test(e.message), code);
    assert.equal(h.installed(), 'WORKING CORE');
  }
  // anything else from place() goes on as it was
  const h = installer({ platform: 'win32', arch: 'x64', fail: 'place' });
  await assert.rejects(h.d.installVersion('xray-pattn', 'v26.9.13'), (e) => /ENOSPC/.test(e.message) && e.code === 'ENOSPC');
});

/* ------------------------------ the real `<bin> version` ------------------------------ */

test('runVersion: a binary that fails says why in a few words — never its path, which could read as a version', { timeout: 30000 }, async () => {
  // node given the argument `version` looks for a script by that name and exits 1
  await assert.rejects(runVersion(process.execPath), (e) => e.message === 'exit code 1' && !e.message.includes(path.dirname(process.execPath)));
  await assert.rejects(runVersion(path.join(tmp('nobin'), 'xray-26.9.13', 'xray')), (e) => /^(ENOENT|EACCES|exit code \d+)$/.test(e.message) && !/26\.9\.13/.test(e.message));
});

test('runVersion: the core’s answer, stdout and stderr together', { skip: process.platform === 'win32' ? 'a shell script stands in for the core' : false, timeout: 30000 }, async () => {
  const bin = path.join(tmp('bin'), 'xray');
  fs.writeFileSync(bin, '#!/bin/sh\n[ "$1" = version ] || exit 3\necho "Xray 26.9.22 (Xray, Penetrates Everything.)"\necho "A unified platform for anti-censorship." >&2\n', { mode: 0o755 });
  assert.equal(await runVersion(bin), 'Xray 26.9.22 (Xray, Penetrates Everything.)\nA unified platform for anti-censorship.\n');
});
