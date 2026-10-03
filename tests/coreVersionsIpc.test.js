'use strict';
/**
 * The version picker's two channels — 'cores:versions' and 'cores:install' —
 * in the router's service (the real service over the gateway fakes, the real
 * Downloader over a fake GitHub, archive and core: nothing is fetched, spawned
 * or bound), in main.js (its wiring, read as text: Electron does not load
 * here) and in the two bridges the one renderer talks through.
 */
process.env.IRNETFREE_PLATFORM = 'openwrt';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const H = require('./serviceHarness');
const rel = require('./coreReleases');
const { Downloader } = require('../src/main/downloader');

process.setMaxListeners(60);   // every service registers its own exit hook
test.after(() => H.cleanupDirs());

const R = (...p) => fs.readFileSync(path.join(__dirname, '..', ...p), 'utf8').replace(/\r\n/g, '\n');
const { SERVER, until } = H;

/**
 * deps.downloader: the real Downloader as the service builds it (its bin dir,
 * its log and progress), on a router (linux/arm), with GitHub, the download,
 * the archive and `<bin> version` faked. `seen` records what it was asked.
 */
function fakeGithub(seen) {
  return (opts) => {
    const d = new Downloader(Object.assign({}, opts, {
      platform: 'linux', arch: 'arm',
      fetchJSON: async (url) => {
        seen.push('api:' + url);
        const list = url.includes('/patterniha/') ? rel.pattn() : url.includes('/SagerNet/') ? rel.singbox() : rel.xtls();
        if (url.endsWith('/latest')) return list.find((r) => !r.prerelease);
        const tag = url.split('/tags/')[1];
        if (tag) return list.find((r) => r.tag_name === decodeURIComponent(tag)) || rel.singboxTag(decodeURIComponent(tag));
        return list;
      },
      fetchFile: async (url, dest, onProgress) => { seen.push('download:' + path.basename(dest)); onProgress(55); onProgress(100); fs.writeFileSync(dest, 'zip'); },
      extractArchive: async (archive, dir) => {
        const sb = /sing-box/.test(archive);
        fs.mkdirSync(path.join(dir, 'pkg'), { recursive: true });
        fs.writeFileSync(path.join(dir, 'pkg', sb ? 'sing-box' : 'xray'), 'CORE FROM ' + path.basename(archive));
      },
      runVersion: async (bin) => {
        const from = fs.readFileSync(bin, 'utf8');
        const v = (/(\d+\.\d+\.\d+)/.exec(seen.filter((x) => x.startsWith('install-tag:')).at(-1) || '') || [])[1] || '0.0.0';
        return /sing-box/.test(from) ? `sing-box version ${v}\n` : `Xray ${v} (Xray, Penetrates Everything.)\n`;
      }
    }));
    d.macPrepareBinary = () => {};   // a Mac CI runner would sign this text file
    const install = d.installVersion.bind(d);
    d.installVersion = (c, tag, o) => { seen.push('install-tag:' + tag); return install(c, tag, o); };
    d.download = async (c) => { seen.push('update:' + c); return { ok: true, files: [] }; };   // the update button: not under test here
    return d;
  };
}

function start(store = {}, extra = {}) {
  const seen = [];
  const s = H.start(store, Object.assign({ downloader: fakeGithub(seen) }, extra));
  const x = s.state.xray;
  x.forgot = 0;
  x.forgetVersions = () => { x.forgot++; };
  return Object.assign(s, { seen, binDir: path.join(s.dir, 'bin') });
}

test('router: cores:versions answers with the installed, suggested and latest versions and the router’s cards', async (t) => {
  const s = start();
  t.after(() => s.service.shutdown());
  const res = await s.service.invoke('cores:versions', { component: 'xray-pattn', prerelease: false });
  assert.equal(res.ok, true, JSON.stringify(res));
  assert.equal(res.installed, '26.9.1', 'what the core says (the fake answers 26.9.1 for the fork)');
  assert.equal(res.suggested, '26.9.22');
  assert.equal(res.latest, '26.10.3');
  assert.deepEqual(res.platform, { platform: 'linux', arch: 'arm', asset: 'Xray-linux-arm32-v7a.zip' });
  assert.equal(res.busy, false);
  assert.deepEqual(res.cards.map((c) => c.version), ['26.10.3', '26.9.27', '26.9.26', '26.9.24', '26.9.22', '26.9.13', '26.9.1']);
  assert.ok(res.cards.every((c) => c.asset === 'Xray-linux-arm32-v7a.zip'));
  assert.deepEqual(s.seen.sort(), [
    'api:https://api.github.com/repos/patterniha/Xray-core/releases/latest',
    'api:https://api.github.com/repos/patterniha/Xray-core/releases?per_page=30'
  ]);
});

test('router: cores:install puts the chosen core in the service’s bin, then the same refresh as a download', async (t) => {
  const s = start();
  t.after(() => s.service.shutdown());
  s.state.xray.binPath = '/srv/located/xray';
  const progress = [];
  s.service.onEvent((ch, p) => { if (ch === 'asset-progress') progress.push(p); });
  const res = await s.service.invoke('cores:install', { component: 'xray-pattn', tag: 'v26.9.22' });
  assert.equal(res.ok, true, JSON.stringify(res));
  assert.equal(res.version, '26.9.22');
  assert.ok(res.assets && typeof res.tunAvailable === 'boolean' && typeof res.xrayReady === 'boolean', JSON.stringify(res));
  assert.equal(fs.readFileSync(path.join(s.binDir, 'xray-pattn'), 'utf8'), 'CORE FROM Xray-linux-arm32-v7a.zip');
  assert.deepEqual(progress, [{ component: 'xray-pattn', pct: 55 }, { component: 'xray-pattn', pct: 100 }], 'the existing asset-progress event');
  assert.equal(s.state.xray.forgot, 1, 'the cached versions are forgotten');
  assert.equal(s.state.xray.binPath, '/srv/located/xray', 'the fork never clears the official core’s path');
  assert.ok(s.logs.some((l) => /Xray-PattN v26\.9\.22 installed/.test(l.line)), JSON.stringify(s.logs));
  // the official core: binPath is re-resolved, as after a download
  const off = await s.service.invoke('cores:install', { component: 'xray', tag: 'v26.3.27' });
  assert.equal(off.ok, true, JSON.stringify(off));
  assert.equal(s.state.xray.binPath, null);
  assert.equal(fs.readFileSync(path.join(s.binDir, 'xray'), 'utf8'), 'CORE FROM Xray-linux-arm32-v7a.zip');
  assert.equal(fs.existsSync(path.join(s.binDir, 'geoip.dat')), false, 'no geo files from a version install');
});

test('router: cores:install is refused while connected — nothing is fetched, nothing replaced', async (t) => {
  const s = start();
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  const res = await s.service.invoke('cores:install', { component: 'xray', tag: 'v26.3.27' });
  assert.deepEqual(res, { ok: false, refused: 'connected', component: 'xray', tag: 'v26.3.27' });
  assert.deepEqual(s.seen, []);
  assert.equal(fs.existsSync(path.join(s.binDir, 'xray')), false);
  assert.equal((await s.service.invoke('cores:versions', { component: 'xray' })).busy, true, 'the modal is told, to disable its actions');
  await s.service.invoke('disconnect');
  assert.equal((await s.service.invoke('cores:install', { component: 'xray', tag: 'v26.3.27' })).ok, true, 'and allowed once disconnected');
});

test('router: cores:install is refused while a connect is being built', async (t) => {
  const s = start();
  t.after(() => s.service.shutdown());
  let open;
  s.state.gatewayGate = new Promise((r) => { open = r; });
  const connecting = s.service.invoke('connect', SERVER.id);
  await until(() => s.state.events.includes('gateway:start'), 'the gateway starting');
  const res = await s.service.invoke('cores:install', { component: 'sing-box', tag: 'v1.13.14' });
  assert.equal(res.refused, 'connected');
  assert.deepEqual(s.seen, []);
  open();
  await connecting;
});

test('router: cores:install is refused while the boot connect waits for the WAN between its retries', async (t) => {
  const s = start({ connectIntent: SERVER.id, settings: { autoConnect: true } }, { timing: Object.assign({}, H.fakes.deps(H.fakes.makeState()).timing, { bootDelayMs: 5, bootEveryMs: 400, bootSlowAfter: 1000 }) });
  t.after(() => s.service.shutdown());
  s.state.gatewayFails = true;
  await until(() => s.service.connSnapshot().state === 'waiting' && !s.state.xray.running, 'waiting between two boot attempts', 10000);
  const res = await s.service.invoke('cores:install', { component: 'xray-pattn', tag: 'v26.9.22' });
  assert.equal(res.refused, 'connected', JSON.stringify(res));
  assert.equal(s.seen.filter((x) => x.startsWith('install-tag:')).length, 0);
});

test('router: the update button now forgets a sing-box version too — the row shows it', async (t) => {
  const s = start();
  t.after(() => s.service.shutdown());
  const res = await s.service.invoke('assets:download', 'sing-box');
  assert.equal(res.ok, true, JSON.stringify(res));
  assert.deepEqual(s.seen, ['update:sing-box']);
  assert.equal(s.state.xray.forgot, 1);
  // and geo still does not (it is no core)
  await s.service.invoke('assets:download', 'geo');
  assert.equal(s.state.xray.forgot, 1);
});

/* ------------------------------ main.js, as text ------------------------------ */

const MAIN = R('src', 'main', 'main.js');
/** A top-level function of main.js, as source. */
function mainFn(name) {
  const start = MAIN.indexOf(`\nfunction ${name}(`);
  assert.ok(start > -1, `main.js has no function ${name}`);
  let depth = 0, j = MAIN.indexOf('{', MAIN.indexOf(')', start));
  for (; j < MAIN.length; j++) {
    if (MAIN[j] === '{') depth++;
    else if (MAIN[j] === '}' && --depth === 0) break;
  }
  return MAIN.slice(start, j + 1);
}

test('desktop: main registers both channels on the shared handlers, refusing while connected, connecting or rebuilding', () => {
  assert.match(MAIN, /require\('\.\/coreVersions'\)/);
  const blocked = mainFn('coreChangeBlocked');
  for (const part of [/connectsInFlight\.size > 0/, /recovering/, /recoverTimer/, /store\.get\('activeServerId', null\)/, /xray && xray\.running/, /tun && tun\.active/, /\['connecting', 'reconnecting', 'connected'\]\.includes\(conn\.state\)/]) {
    assert.match(blocked, part);
  }
  const reg = mainFn('registerIpc');
  assert.match(reg, /createCoreVersionsApi\(\{\s*downloader,\s*installedVersion: \(id\) => xray\.version\(id\),\s*busy: coreChangeBlocked,\s*afterInstall: afterCoreChanged,/);
  assert.match(reg, /ipcMain\.handle\('cores:versions', \(e, arg\) => coreVersions\.versions\(arg\)\);/);
  assert.match(reg, /ipcMain\.handle\('cores:install', \(e, arg\) => coreVersions\.install\(arg\)\);/);
  // the same answer a download gives
  assert.match(reg, /result: \(\) => \(\{ assets: assetStatus\(\), tunAvailable: makeTun\(getSettings\(\), \{ quiet: true \}\)\.isAvailable\(\), xrayReady: xray\.binExists\(\) \}\)/);
});

test('desktop: after a core changed — a download or a chosen version — the same refresh, sing-box included', () => {
  const after = mainFn('afterCoreChanged');
  assert.match(after, /if \(component === 'xray'\) xray\.binPath = null;\s*xray\.forgetVersions\(\);\s*stats\.setBin\(xray\.anyBin\(\)\);/);
  const dl = MAIN.slice(MAIN.indexOf("ipcMain.handle('assets:download'"), MAIN.indexOf("ipcMain.handle('xray:locate'"));
  assert.match(dl, /if \(CORE_IDS\.includes\(component\)\) afterCoreChanged\(component\);/);
  assert.doesNotMatch(dl, /xray\.binPath = null/, 'one place says what a core change clears');
});

test('the router’s service wires the same shared handlers', () => {
  const svc = R('src', 'server', 'service.js');
  assert.match(svc, /const downloader = deps\.downloader \? deps\.downloader\(downloaderOpts\) : new Downloader\(downloaderOpts\);/);
  assert.match(svc, /'cores:versions': \(arg\) => coreVersions\.versions\(arg\),/);
  assert.match(svc, /'cores:install': \(arg\) => coreVersions\.install\(arg\),/);
});

/* ------------------------------ the two bridges ------------------------------ */

test('both bridges expose the picker the same way: (component, { prerelease, force }) and (component, tag)', () => {
  const preload = R('src', 'preload', 'preload.js');
  const web = R('src', 'server', 'web-api.js');
  assert.match(preload, /coreVersions: \(component, opts\) => ipcRenderer\.invoke\('cores:versions', Object\.assign\(\{\}, opts, \{ component \}\)\),/);
  assert.match(preload, /installCoreVersion: \(component, tag\) => ipcRenderer\.invoke\('cores:install', \{ component, tag \}\),/);
  assert.match(web, /coreVersions: \(component, opts\) => invoke\('cores:versions', Object\.assign\(\{\}, opts, \{ component \}\)\),/);
  assert.match(web, /installCoreVersion: \(component, tag\) => invoke\('cores:install', \{ component, tag \}\),/);
});
