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
 *   serveRenderer(checkJs)  src/renderer on 127.0.0.1: `/` is index.html
 *                           WITHOUT its scripts (the app needs Electron's
 *                           bridge) and WITH `checkJs` run at the end of <body>
 *                           — after every stylesheet, so it measures the real
 *                           layout. `/__harness.html?sizes=1080x720,…` holds
 *                           one iframe of exactly each size around that page
 *                           and POSTs what each measured back to the server.
 *   bannerCheckJs(texts)    that check for the banners: each one alone, then
 *                           all at once, right-to-left and left-to-right — and
 *                           #toast with each of `texts.toasts`, plain and with
 *                           its button, in both directions
 *   bannerTexts()           the app's own texts for the two banners it fills in,
 *                           and its longest notice (fa, en) for the toast
 *   renderInBrowser(...)    a headless Chromium (Chrome or Edge) on the
 *                           harness: the measurements per size
 *   findBrowser()           IRNF_RENDER_BROWSER, or on CI a known install path;
 *                           null elsewhere (the owner's daily PC: never launched)
 *
 * The sizes are iframes, not the browser's window: a headless window's size is
 * not the same on every OS (Windows CI gave 884x449 for --window-size=1080,720),
 * an iframe's viewport is exactly its CSS size. The answer comes back as a POST,
 * not from --dump-dom, which never returned on macOS CI.
 *
 * `node tests/renderCheck.js` serves both pages and prints their URLs, to look
 * at them in any browser.
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
const HARNESS_PATH = '/__harness.html';
const HARNESS_JS = '/__harness.js';
const RESULT_PATH = '/__result';
const BANNERS = ['killBanner', 'guardBanner', 'pendingBanner', 'autostartBanner'];

/** index.html without its <script> tags and with the check at the end of <body>. */
function checkPage() {
  const html = fs.readFileSync(path.join(ROOT, 'index.html'), 'utf8');
  return html
    .replace(/<script\b[^>]*><\/script>[ \t]*\r?\n?/g, '')
    .replace('</body>', `<script src="${CHECK_PATH}"></script>\n</body>`);
}

/** '1080x720,900x600' → [{ width, height }] (garbage dropped). */
function parseSizes(s) {
  return String(s || '').split(',').map((x) => /^(\d{2,4})x(\d{2,4})$/.exec(x.trim())).filter(Boolean)
    .map((m) => ({ width: Number(m[1]), height: Number(m[2]) }));
}

/** The harness: one iframe of exactly each size around the check page, scaled down so all of it is on screen. */
function harnessPage(sizes) {
  const frames = sizes.map((s, i) =>
    `<iframe id="f${i}" data-width="${s.width}" data-height="${s.height}" src="/?frame=${i}" style="width:${s.width}px;height:${s.height}px"></iframe>`);
  return `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>IRNetFree render check</title>
<style>body { margin: 0; } iframe { position: absolute; top: 0; left: 0; border: 0; transform-origin: 0 0; transform: scale(.25); }</style>
</head><body>
${frames.join('\n')}
<script src="${HARNESS_JS}"></script>
</body></html>
`;
}

/** Once every frame has loaded: what each measured, POSTed to the server. */
const HARNESS_SCRIPT = `window.addEventListener('load', function () {
  var out = Array.prototype.map.call(document.querySelectorAll('iframe'), function (f) {
    var size = { width: Number(f.dataset.width), height: Number(f.dataset.height) };
    try {
      var pre = f.contentDocument.getElementById('render-result');
      if (!pre) return { size: size, error: 'no #render-result in the frame' };
      var r = JSON.parse(decodeURIComponent(pre.textContent));
      r.size = size;
      return r;
    } catch (e) { return { size: size, error: String(e && e.message || e) }; }
  });
  fetch('${RESULT_PATH}', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(out) });
});
`;

/**
 * src/renderer on 127.0.0.1 (a free port). Resolves { url, harnessUrl(sizes),
 * nextResult(timeoutMs), close }: nextResult is the next POSTed result.
 */
function serveRenderer(checkJs) {
  const waiting = [];
  const server = http.createServer((req, res) => {
    const send = (code, type, body) => { res.writeHead(code, { 'Content-Type': type, 'Cache-Control': 'no-store' }); res.end(body); };
    let u;
    try { u = new URL(req.url, 'http://127.0.0.1'); } catch { return send(400, 'text/plain', 'bad'); }
    const p = u.pathname;
    if (req.method === 'POST' && p === RESULT_PATH) {
      let body = '';
      req.setEncoding('utf8');
      req.on('data', (c) => { body += c; });
      req.on('end', () => {
        send(204, 'text/plain', '');
        let value, error = null;
        try { value = JSON.parse(body); } catch (e) { error = e; }
        const w = waiting.shift();
        if (w) w(error, value);
      });
      return;
    }
    // read on every request, like the stylesheets: the page as it is on disk now
    if (p === '/' || p === '/index.html') return send(200, TYPES['.html'], checkPage());
    if (p === CHECK_PATH) return send(200, TYPES['.js'], checkJs);
    if (p === HARNESS_PATH) return send(200, TYPES['.html'], harnessPage(parseSizes(u.searchParams.get('sizes'))));
    if (p === HARNESS_JS) return send(200, TYPES['.js'], HARNESS_SCRIPT);
    let file;
    try { file = path.join(ROOT, path.normalize(decodeURIComponent(p)).replace(/^[\\/]+/, '')); } catch { return send(400, 'text/plain', 'bad'); }
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
      const url = `http://127.0.0.1:${port}/`;
      resolve({
        url,
        harnessUrl: (sizes) => `${url}${HARNESS_PATH.slice(1)}?sizes=${sizes.map((s) => `${s.width}x${s.height}`).join(',')}`,
        nextResult: (timeoutMs) => new Promise((ok, fail) => {
          const timer = setTimeout(() => { const i = waiting.indexOf(take); if (i > -1) waiting.splice(i, 1); fail(new Error(`no result in ${timeoutMs} ms`)); }, timeoutMs);
          const take = (err, value) => { clearTimeout(timer); if (err) fail(err); else ok(value); };
          waiting.push(take);
        }),
        close: () => new Promise((r) => { server.closeAllConnections && server.closeAllConnections(); server.close(() => r()); })
      });
    });
  });
}

/**
 * The banners' check, as page script: fills the two banners whose text the app
 * sets (with `texts.pending` / `texts.autostart`), then shows each banner
 * alone and all four together, in both directions, and measures each: its box,
 * whether the point at its centre is the banner (not something over it), its
 * text's box and horizontal overflow, and each button's box and hit. Then the
 * toast's box with each of `texts.toasts` in it. The result goes, URI-encoded
 * JSON, into <pre id="render-result">.
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
  // #toast showing a text, plain (toast()) or with its button (toastAction()), as app.js fills it;
  // no transition, so the box is where the toast rests
  function measureToast(dir, text, action) {
    var t = el('toast');
    t.style.transition = 'none';
    t.textContent = '';
    if (action) {
      var span = document.createElement('span');
      span.textContent = text;
      var btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'btn small toast-action';
      btn.textContent = 'OK';
      t.appendChild(span);
      t.appendChild(btn);
      t.className = 'toast show has-action warn';
    } else {
      t.textContent = text;
      t.className = 'toast show warn';
    }
    var r = { dir: dir, action: !!action, length: text.length, box: box(t) };
    t.className = 'toast';
    t.textContent = '';
    return r;
  }
  var out = { width: window.innerWidth, height: window.innerHeight, runs: [], toasts: [] };
  ['rtl', 'ltr'].forEach(function (dir) {
    document.documentElement.dir = dir;
    IDS.forEach(function (id) {
      IDS.forEach(function (x) { el(x).hidden = x !== id; });
      out.runs.push({ dir: dir, shown: [id], banners: [measure(id)] });
    });
    IDS.forEach(function (x) { el(x).hidden = false; });
    out.runs.push({ dir: dir, shown: IDS.slice(), banners: IDS.map(measure) });
    IDS.forEach(function (x) { el(x).hidden = true; });
    (TEXTS.toasts || []).forEach(function (text) {
      out.toasts.push(measureToast(dir, text, false));
      out.toasts.push(measureToast(dir, text, true));
    });
  });
  var pre = document.createElement('pre');
  pre.id = 'render-result';
  pre.hidden = true;
  pre.textContent = encodeURIComponent(JSON.stringify(out));
  document.body.appendChild(pre);
})();
`;
}

/** The renderer's real t(), in one language. */
function rendererT(lang) {
  const ctx = vm.createContext({ window: {}, document: { documentElement: {}, querySelectorAll: () => [] } });
  vm.runInContext(fs.readFileSync(path.join(ROOT, 'i18n.js'), 'utf8'), ctx);
  ctx.window.i18n.applyI18n(lang);
  return ctx.window.i18n.t;
}

/**
 * What a notice's {fields} are filled with in the render: values as long as
 * the owner's own (the subscription's group name, a sing-box error, two
 * Windows paths with no space to break at).
 */
const SAMPLE_FIELDS = {
  name: 'cobra.tes.ca', other: 'cobra.tes.ca', group: 'tes-vpn-service.platform.irnetfree.info', address: '10.10.10.42',
  lan: '192.168.60.0/24', iface: 'Ethernet 2', range: '192.168.0.0/16', target: 'Tes Chain', key: 'AllowedIPs', servers: '192.168.60.1, 192.168.60.2',
  reason: 'sing-box exited before the TUN adapter came up — FATAL[0000] start inbound/tun[tun-in]: configure tun interface: set ipv6 address: Element not found.',
  error: 'Access is denied.',
  task: 'C:\\Users\\someone-with-a-long-name\\Desktop\\Programs\\IRNetFree-Portable-1.13.0-x64-setup-copy.exe',
  current: 'C:\\Users\\someone-with-a-long-name\\AppData\\Local\\Programs\\IRNetFree\\IRNetFree.exe'
};

/**
 * The texts the app puts into the two banners whose markup is empty, at their
 * longest: the renderer's own Persian strings, the logon-task one with two
 * Windows paths that have no space to break at. `toasts`: the longest notice
 * the window can toast (every 'notice.*' string filled from SAMPLE_FIELDS), in
 * Persian and in English.
 */
function bannerTexts() {
  const t = rendererT('fa');
  return {
    pending: t('apply.intro'),
    autostart: t('notice.autostartStale')
      .replace('{task}', SAMPLE_FIELDS.task)
      .replace('{current}', SAMPLE_FIELDS.current),
    toasts: ['fa', 'en'].map(longestNotice)
  };
}

/** The longest 'notice.*' string of one language, every {field} filled. */
function longestNotice(lang) {
  const src = fs.readFileSync(path.join(ROOT, 'i18n.js'), 'utf8');
  const keys = [...new Set([...src.matchAll(/'(notice\.\w+)':/g)].map((m) => m[1]))];
  const t = rendererT(lang);
  return keys.map((k) => t(k).replace(/\{(\w+)\}/g, (m, f) => SAMPLE_FIELDS[f] || m))
    .reduce((a, b) => (b.length > a.length ? b : a), '');
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
 * Open the harness for `sizes` in a headless Chromium with a throwaway profile,
 * wait for its POST, then end the browser: the measurements, one per size
 * ({ size, width, height, runs } or { size, error }). Nothing is installed or
 * kept: the profile is a temp dir, removed after.
 */
async function renderInBrowser(browser, served, sizes, { timeoutMs = 90000 } = {}) {
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-render-'));
  const args = [
    '--headless=new', '--disable-gpu', '--no-sandbox', '--no-first-run', '--no-default-browser-check',
    '--disable-extensions', '--disable-background-networking', '--disable-component-update', '--disable-sync',
    '--disable-default-apps', '--mute-audio', '--hide-scrollbars', '--use-mock-keychain', '--password-store=basic',
    `--user-data-dir=${profile}`, '--window-size=1280,900', served.harnessUrl(sizes)
  ];
  const result = served.nextResult(timeoutMs);
  let stderr = '';
  const child = spawn(browser, args, { stdio: ['ignore', 'ignore', 'pipe'], windowsHide: true, detached: process.platform !== 'win32' });
  child.stderr.on('data', (b) => { stderr = (stderr + b).slice(-4000); });
  const exited = new Promise((resolve) => child.once('close', resolve));
  const failedToStart = new Promise((resolve, reject) => child.once('error', reject));
  const end = async () => {
    try {
      if (process.platform !== 'win32') process.kill(-child.pid, 'SIGKILL');
      else child.kill();
    } catch { /* already gone */ }
    await Promise.race([exited, new Promise((r) => setTimeout(r, 5000))]);
    try { fs.rmSync(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 300 }); } catch { /* a temp dir */ }
  };
  try {
    return await Promise.race([
      result,
      failedToStart,
      exited.then((code) => new Promise((resolve, reject) => setTimeout(() =>
        reject(new Error(`${browser} exited (${code}) before the page answered\n${stderr}`)), 2000)))
    ]);
  } catch (e) {
    e.message += stderr && !e.message.includes(stderr) ? `\n${stderr}` : '';
    throw e;
  } finally {
    await end();
  }
}

module.exports = { BANNERS, checkPage, harnessPage, parseSizes, serveRenderer, bannerCheckJs, bannerTexts, longestNotice, findBrowser, renderInBrowser };

if (require.main === module) {
  serveRenderer(bannerCheckJs(bannerTexts())).then((s) => {
    console.log(`the page:    ${s.url}`);
    console.log(`the harness: ${s.harnessUrl([{ width: 1080, height: 720 }, { width: 900, height: 600 }, { width: 390, height: 760 }])}`);
    console.log('Ctrl+C to stop');
  });
}
