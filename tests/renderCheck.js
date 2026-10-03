'use strict';
/**
 * A real render of the window's own markup and CSS, for what a text test
 * cannot see: where things land on screen. From 52ac922 (the redesign) to
 * v1.16.3 the kill-switch, leak-guard, pending-settings and logon-task banners
 * were static blocks AFTER the full-height layout, in a window whose html/body
 * never scroll — so every one of them sat just below the viewport (top ==
 * innerHeight, 0 visible pixels) while every test that read `hidden === false`
 * passed. Only a layout engine says that; this module drives one.
 *
 *   serveRenderer(checkJs)  src/renderer on 127.0.0.1, index.html WITHOUT its
 *                           scripts (the app needs Electron's bridge) and WITH
 *                           `checkJs` run at the end of <body> — after every
 *                           stylesheet, so it measures the real layout
 *   bannerCheckJs(texts)    that check for the banners: each one alone, then
 *                           all at once, right-to-left and left-to-right
 *   renderInBrowser(...)    a headless Chromium (Chrome or Edge) at one window
 *                           size: the page's measurements, as an object
 *   findBrowser()           IRNF_RENDER_BROWSER, or on CI a known install path;
 *                           null elsewhere (the owner's daily PC: never launched)
 *
 * `node tests/renderCheck.js` serves the page and prints its URL, to look at
 * it in any browser.
 */
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const os = require('node:os');
const vm = require('node:vm');
const { spawn } = require('node:child_process');

const ROOT = path.join(__dirname, '..', 'src', 'renderer');
const TYPES = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon',
  '.woff2': 'font/woff2', '.woff': 'font/woff', '.ttf': 'font/ttf', '.otf': 'font/otf'
};
const CHECK_PATH = '/__render-check.js';
const BANNERS = ['killBanner', 'guardBanner', 'pendingBanner', 'autostartBanner'];

/** index.html without its <script> tags and with the check at the end of <body>. */
function checkPage() {
  const html = fs.readFileSync(path.join(ROOT, 'index.html'), 'utf8');
  return html
    .replace(/<script\b[^>]*><\/script>[ \t]*\r?\n?/g, '')
    .replace('</body>', `<script src="${CHECK_PATH}"></script>\n</body>`);
}

/** src/renderer on 127.0.0.1 (a free port): resolves { url, close }. */
function serveRenderer(checkJs) {
  const server = http.createServer((req, res) => {
    const send = (code, type, body) => { res.writeHead(code, { 'Content-Type': type, 'Cache-Control': 'no-store' }); res.end(body); };
    let p;
    try { p = decodeURIComponent(new URL(req.url, 'http://127.0.0.1').pathname); } catch { return send(400, 'text/plain', 'bad'); }
    // read on every request, like the stylesheets: the page as it is on disk now
    if (p === '/' || p === '/index.html') return send(200, TYPES['.html'], checkPage());
    if (p === CHECK_PATH) return send(200, TYPES['.js'], checkJs);
    const file = path.join(ROOT, path.normalize(p).replace(/^[\\/]+/, ''));
    if (file !== ROOT && !file.startsWith(ROOT + path.sep)) return send(404, 'text/plain', 'no');
    fs.readFile(file, (err, buf) => {
      if (err) return send(404, 'text/plain', 'no');
      send(200, TYPES[path.extname(file).toLowerCase()] || 'application/octet-stream', buf);
    });
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({ url: `http://127.0.0.1:${port}/`, close: () => new Promise((r) => server.close(() => r())) });
    });
  });
}

/**
 * The banners' check, as page script: fills the two banners whose text the app
 * sets (with `texts.pending` / `texts.autostart`), then shows each banner
 * alone and all four together, in both directions, and measures each: its box,
 * whether the point at its centre is the banner (not something over it), its
 * text's box and horizontal overflow, and each button's box and hit. The
 * result goes, URI-encoded JSON, into <pre id="render-result">.
 */
function bannerCheckJs(texts) {
  return `(function () {
  var TEXTS = ${JSON.stringify(texts || {})};
  var IDS = ${JSON.stringify(BANNERS)};
  var el = function (id) { return document.getElementById(id); };
  if (TEXTS.pending) el('pendingBannerText').textContent = TEXTS.pending;
  if (TEXTS.autostart) el('autostartBannerText').textContent = TEXTS.autostart;
  function box(e) { var r = e.getBoundingClientRect(); return { top: r.top, bottom: r.bottom, left: r.left, right: r.right, width: r.width, height: r.height }; }
  function hits(e) { var r = e.getBoundingClientRect(); var at = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2); return !!at && e.contains(at); }
  function measure(id) {
    var b = el(id);
    var text = b.querySelector('[class$="-banner-text"]');
    return {
      id: id, box: box(b), hit: hits(b),
      text: text ? box(text) : null, textOverflow: text ? text.scrollWidth - text.clientWidth : 0,
      buttons: Array.prototype.map.call(b.querySelectorAll('button'), function (x) { return { id: x.id, box: box(x), hit: hits(x) }; })
    };
  }
  var out = { width: window.innerWidth, height: window.innerHeight, runs: [] };
  ['rtl', 'ltr'].forEach(function (dir) {
    document.documentElement.dir = dir;
    IDS.forEach(function (id) {
      IDS.forEach(function (x) { el(x).hidden = x !== id; });
      out.runs.push({ dir: dir, shown: [id], banners: [measure(id)] });
    });
    IDS.forEach(function (x) { el(x).hidden = false; });
    out.runs.push({ dir: dir, shown: IDS.slice(), banners: IDS.map(measure) });
    IDS.forEach(function (x) { el(x).hidden = true; });
  });
  var pre = document.createElement('pre');
  pre.id = 'render-result';
  pre.textContent = encodeURIComponent(JSON.stringify(out));
  document.body.appendChild(pre);
})();
`;
}

/**
 * The texts the app puts into the two banners whose markup is empty, at their
 * longest: the renderer's own Persian strings, the logon-task one with two
 * Windows paths that have no space to break at.
 */
function bannerTexts() {
  const ctx = vm.createContext({ window: {}, document: { documentElement: {}, querySelectorAll: () => [] } });
  vm.runInContext(fs.readFileSync(path.join(ROOT, 'i18n.js'), 'utf8'), ctx);
  ctx.window.i18n.applyI18n('fa');
  const t = ctx.window.i18n.t;
  return {
    pending: t('apply.intro'),
    autostart: t('notice.autostartStale')
      .replace('{task}', 'C:\\Users\\someone-with-a-long-name\\Desktop\\Programs\\IRNetFree-Portable-1.13.0-x64-setup-copy.exe')
      .replace('{current}', 'C:\\Users\\someone-with-a-long-name\\AppData\\Local\\Programs\\IRNetFree\\IRNetFree.exe')
  };
}

/** A Chromium to render with: IRNF_RENDER_BROWSER, or — on CI only — a known install path. */
function findBrowser(env = process.env, platform = process.platform) {
  if (env.IRNF_RENDER_BROWSER) return env.IRNF_RENDER_BROWSER;
  if (!env.CI && !env.GITHUB_ACTIONS) return null;
  const pf = env.PROGRAMFILES || 'C:\\Program Files';
  const pf86 = env['PROGRAMFILES(X86)'] || 'C:\\Program Files (x86)';
  const candidates = platform === 'win32'
    ? [path.join(pf, 'Google', 'Chrome', 'Application', 'chrome.exe'), path.join(pf86, 'Google', 'Chrome', 'Application', 'chrome.exe'),
      path.join(pf86, 'Microsoft', 'Edge', 'Application', 'msedge.exe'), path.join(pf, 'Microsoft', 'Edge', 'Application', 'msedge.exe')]
    : platform === 'darwin'
      ? ['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', '/Applications/Chromium.app/Contents/MacOS/Chromium',
        '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge']
      : ['/usr/bin/google-chrome', '/usr/bin/google-chrome-stable', '/usr/bin/chromium', '/usr/bin/chromium-browser', '/snap/bin/chromium'];
  return candidates.find((p) => { try { return fs.statSync(p).isFile(); } catch { return false; } }) || null;
}

/**
 * Load `url` in a headless Chromium with a `width`×`height` window and a
 * throwaway profile, and return what the check wrote into #render-result.
 * Nothing is installed or kept: the profile is a temp dir, removed after.
 */
function renderInBrowser(browser, url, { width, height, timeoutMs = 60000 } = {}) {
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-render-'));
  const args = [
    '--headless=new', '--disable-gpu', '--no-sandbox', '--no-first-run', '--no-default-browser-check',
    '--disable-extensions', '--disable-background-networking', '--disable-component-update', '--disable-sync',
    '--disable-default-apps', '--mute-audio', '--hide-scrollbars', '--use-mock-keychain', '--password-store=basic',
    `--user-data-dir=${profile}`, `--window-size=${width},${height}`, '--virtual-time-budget=5000', '--dump-dom', url
  ];
  return new Promise((resolve, reject) => {
    let stdout = '', stderr = '', done = false;
    const child = spawn(browser, args, { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    const finish = (err, value) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try { fs.rmSync(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }); } catch { /* a temp dir */ }
      if (err) reject(err); else resolve(value);
    };
    const timer = setTimeout(() => { try { child.kill(); } catch { /* gone */ } finish(new Error(`no answer from ${browser} in ${timeoutMs} ms\n${stderr.slice(-2000)}`)); }, timeoutMs);
    child.stdout.on('data', (b) => { stdout += b; });
    child.stderr.on('data', (b) => { stderr += b; });
    child.on('error', (e) => finish(e));
    child.on('close', (code) => {
      const m = /<pre id="render-result">([^<]*)<\/pre>/.exec(stdout);
      if (!m) return finish(new Error(`${browser} exited ${code} without a result\n${stderr.slice(-2000)}\n${stdout.slice(-500)}`));
      try { finish(null, JSON.parse(decodeURIComponent(m[1]))); } catch (e) { finish(e); }
    });
  });
}

module.exports = { BANNERS, checkPage, serveRenderer, bannerCheckJs, bannerTexts, findBrowser, renderInBrowser };

if (require.main === module) {
  serveRenderer(bannerCheckJs(bannerTexts())).then(({ url }) => console.log(`serving the banner check at ${url} — Ctrl+C to stop`));
}
