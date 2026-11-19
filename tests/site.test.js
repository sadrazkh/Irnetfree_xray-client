'use strict';
/**
 * The GitHub Pages site (site/, scripts/build-site.js, .github/workflows/pages.yml).
 *
 * Built into a temp folder with a made-up release, no network: every local link and image resolves, the Persian
 * and English pages keep the same sections, nothing loads from another host, the download buttons find their
 * files among a release's real asset names, and the guide anchors are ones the README already uses.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const site = require('../scripts/build-site.js');
const page = require('../site/assets/site.js');

const ROOT = path.join(__dirname, '..');
const BASE = '/Irnetfree_xray-client/';

// The asset names of v1.47.4, as release.yml publishes them.
const ASSETS = [
  'build-log.txt', 'hev-build.txt', 'IRNetFree-1.47.4-amd64.deb', 'IRNetFree-1.47.4-arm64-mac.zip',
  'IRNetFree-1.47.4-arm64.dmg', 'IRNetFree-1.47.4-mac.zip', 'IRNetFree-1.47.4-x64.dmg', 'IRNetFree-1.47.4-x86_64.AppImage',
  'IRNetFree-1.47.4.apk', 'IRNetFree-Portable-1.47.4.exe', 'IRNetFree-Setup-1.47.4.exe', 'irnetfree_1.47.4_all.ipk',
  'SHA256SUMS-macos-latest.txt', 'SHA256SUMS-openwrt.txt', 'SHA256SUMS-ubuntu-latest.txt', 'SHA256SUMS-windows-latest.txt',
];
const API_BODY = {
  tag_name: 'v1.47.4', published_at: '2026-11-17T14:18:02Z', html_url: 'https://github.com/sadrazkh/Irnetfree_xray-client/releases/tag/v1.47.4',
  assets: ASSETS.map((name, i) => ({ name, size: 1000 + i, browser_download_url: `https://github.com/sadrazkh/Irnetfree_xray-client/releases/download/v1.47.4/${name}` })),
};

let out;
let files;
test.before(() => {
  out = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-site-'));
  files = site.build(out, page.slimRelease(API_BODY));
});
test.after(() => { fs.rmSync(out, { recursive: true, force: true }); });

const read = (p) => fs.readFileSync(path.join(out, p), 'utf8');
const HTML = ['index.html', 'en/index.html', '404.html'];
const attrs = (html, name) => [...html.matchAll(new RegExp(`\\s${name}="([^"]*)"`, 'g'))].map((m) => m[1]);
const ids = (html) => new Set(attrs(html, 'id'));

test('the build holds the pages, the assets, the screenshots and the generated files', () => {
  for (const f of [...HTML, 'assets/site.css', 'assets/site.js', 'assets/icons.svg', 'assets/og.png', 'assets/logo.svg',
    'assets/icon.png', 'release.json', 'robots.txt', 'sitemap.xml',
    'shots/home.png', 'shots/servers.png', 'shots/routing.png', 'shots/sites.png', 'shots/subs.png', 'shots/extensions.png']) {
    assert.ok(files.includes(f), `${f} is not in the build`);
  }
  assert.ok(!files.some((f) => /(^|\/)_/.test(f)), 'a source file starting with "_" was published');
  const rel = JSON.parse(read('release.json'));
  assert.equal(rel.tag, 'v1.47.4');
  assert.equal(rel.version, '1.47.4');
  assert.equal(rel.assets.length, ASSETS.length);
  assert.match(read('sitemap.xml'), /https:\/\/sadrazkh\.github\.io\/Irnetfree_xray-client\/en\//);
});

test('every local link, image, script and stylesheet resolves inside the build', () => {
  for (const p of HTML) {
    const html = read(p);
    const dir = path.posix.dirname(p);
    for (const ref of [...attrs(html, 'href'), ...attrs(html, 'src')]) {
      if (/^(https?:|mailto:)/.test(ref)) continue;
      const [file, frag] = ref.split('#');
      if (!file) { // a link inside the page
        if (frag) assert.ok(ids(html).has(frag), `${p}: #${frag} has no element`);
        continue;
      }
      let target = file.startsWith(BASE) ? file.slice(BASE.length) : path.posix.normalize(path.posix.join(dir, file));
      if (target === '.' || target === '') target = 'index.html';
      if (target.endsWith('/')) target += 'index.html';
      if (!path.posix.extname(target)) target += '/index.html';
      target = path.posix.normalize(target).replace(/^\.\//, '');
      assert.ok(files.includes(target), `${p}: ${ref} → ${target} is not in the build`);
      if (frag && target.endsWith('.svg')) assert.match(read(target), new RegExp(`id="${frag}"`), `${p}: ${ref} names no symbol`);
      else if (frag) assert.ok(ids(read(target)).has(frag), `${p}: ${ref} → no #${frag} there`);
    }
  }
});

test('nothing on the pages loads from another host (fonts, scripts, styles, images)', () => {
  for (const p of HTML) {
    const html = read(p);
    for (const m of html.matchAll(/<(script|img|link|iframe|source|video|audio)\b[^>]*>/g)) {
      const tag = m[0];
      if (/rel="(canonical|alternate)"/.test(tag)) continue; // addresses, not loads
      const ref = (/\s(?:src|href)="([^"]*)"/.exec(tag) || [])[1];
      if (ref) assert.ok(!/^(https?:)?\/\//.test(ref), `${p} loads ${ref}`);
    }
    assert.doesNotMatch(read('assets/site.css'), /@import|url\(\s*["']?https?:/, 'the stylesheet loads from another host');
  }
});

test('the Persian and English pages have the same sections, tabs and download buttons', () => {
  const fa = read('index.html');
  const en = read('en/index.html');
  assert.deepEqual([...ids(fa)].sort(), [...ids(en)].sort());
  assert.deepEqual(attrs(fa, 'data-asset'), attrs(en, 'data-asset'));
  assert.match(fa, /<html lang="fa" dir="rtl" data-root="\.">/);
  assert.match(en, /<html lang="en" dir="ltr" data-root="\.\.">/);
});

test('every download button finds its file among a release\'s asset names', () => {
  const slots = page.slotsOf(API_BODY.assets.map((a) => ({ name: a.name, size: a.size, url: a.browser_download_url })));
  const want = {
    'win-setup': 'IRNetFree-Setup-1.47.4.exe', 'win-portable': 'IRNetFree-Portable-1.47.4.exe',
    'mac-arm64': 'IRNetFree-1.47.4-arm64.dmg', 'mac-x64': 'IRNetFree-1.47.4-x64.dmg',
    'mac-arm64-zip': 'IRNetFree-1.47.4-arm64-mac.zip', 'mac-x64-zip': 'IRNetFree-1.47.4-mac.zip',
    deb: 'IRNetFree-1.47.4-amd64.deb', appimage: 'IRNetFree-1.47.4-x86_64.AppImage', apk: 'IRNetFree-1.47.4.apk',
    ipk: 'irnetfree_1.47.4_all.ipk',
  };
  for (const [slot, name] of Object.entries(want)) assert.equal(slots[slot] && slots[slot].name, name, slot);
  for (const slot of new Set(attrs(read('index.html'), 'data-asset'))) assert.ok(want[slot], `button ${slot} has no file pattern`);
  for (const slot of Object.values(page.HERO_SLOT)) assert.ok(want[slot], `the hero's ${slot} has no file pattern`);
});

test('electron-builder\'s and the router\'s artifact names still match the button patterns', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  assert.equal(pkg.build.portable.artifactName, 'IRNetFree-Portable-${version}.${ext}');
  assert.equal(pkg.build.linux.artifactName, 'IRNetFree-${version}-${arch}.${ext}');
});

test('the hero picks the right file for each system', () => {
  const cases = [
    ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/140 Safari/537.36', 'Win32', 0, 'windows'],
    ['Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/18.0 Safari/605.1.15', 'MacIntel', 0, 'mac'],
    ['Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/18.0 Safari/605.1.15', 'MacIntel', 5, 'ios'],
    ['Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148', 'iPhone', 5, 'ios'],
    ['Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/140 Mobile Safari/537.36', 'Linux armv8l', 5, 'android'],
    ['Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/140 Safari/537.36', 'Linux x86_64', 0, 'linux'],
    ['', '', 0, ''],
  ];
  for (const [ua, platform, touch, want] of cases) assert.equal(page.detectOS(ua, platform, touch), want, ua);
});

test('sizes and dates read the way each page writes numbers', () => {
  assert.equal(page.formatSize(82357451, 'en'), '79 MB');
  assert.equal(page.formatSize(82357451, 'fa'), '۷۹ مگابایت');
  assert.equal(page.formatSize(1390708, 'en'), '1.3 MB');
  assert.equal(page.formatSize(0, 'en'), '');
  assert.equal(page.formatDate('2026-11-17T14:18:02Z', 'en'), 'November 17, 2026');
  assert.equal(page.formatDate('not a date', 'en'), '');
  assert.equal(page.slimRelease(null), null);
  assert.equal(page.slimRelease({ message: 'Not Found' }), null);
});

test('links into GUIDE.md and docs/ use anchors the README already uses', () => {
  const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
  for (const p of ['index.html', 'en/index.html']) {
    for (const ref of attrs(read(p), 'href')) {
      const m = /^https:\/\/github\.com\/sadrazkh\/Irnetfree_xray-client\/blob\/main\/((?:GUIDE\.md|docs\/[^#]+))#(.+)$/.exec(ref);
      if (!m) continue;
      assert.ok(readme.includes(`(${m[1]}#${m[2]})`), `${p}: ${m[1]}#${m[2]} is not an anchor README.md links to`);
    }
  }
});

test('the Pages workflow builds after a site change and after every release, and deploys from Actions', () => {
  const wf = fs.readFileSync(path.join(ROOT, '.github/workflows/pages.yml'), 'utf8');
  assert.match(wf, /workflow_run:\s*\n\s*workflows: \['Build & Release'\]/);
  const rel = fs.readFileSync(path.join(ROOT, '.github/workflows/release.yml'), 'utf8');
  assert.match(rel, /^name: Build & Release$/m, 'pages.yml waits on a workflow by this name');
  assert.match(wf, /node scripts\/build-site\.js --out _site --require-release/);
  assert.match(wf, /actions\/upload-pages-artifact@/);
  assert.match(wf, /actions\/deploy-pages@/);
  assert.match(wf, /pages: write/);
  assert.match(wf, /id-token: write/);
});
