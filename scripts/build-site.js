#!/usr/bin/env node
'use strict';
/**
 * The GitHub Pages site (https://sadrazkh.github.io/Irnetfree_xray-client/): site/ plus a few files that
 * already live elsewhere in the repo, and the latest release's downloads.
 *
 *   node scripts/build-site.js --out _site [--require-release]   build the folder Pages serves
 *   node scripts/build-site.js --serve [port]                    preview on 127.0.0.1 (default 4517), files read per request
 *   add --offline to either to skip the GitHub API
 *
 * - The README's screenshots (docs/readme/*.png) and the app's logo and icon are served from where they already
 *   are, not copied into site/ in git.
 * - release.json is the latest release (tag, date, assets with sizes and links), read from the GitHub API when the
 *   site is built. The page reads it from its own origin, so a visitor whose network blocks api.github.com still
 *   gets direct download links; the page asks the API itself only when release.json is missing or empty.
 * - .github/workflows/pages.yml runs this after a push that touches the site and after every Build & Release, so a
 *   new release reaches the page without a commit. --require-release makes a failed API call fail that build.
 */
const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const { slimRelease } = require('../site/assets/site.js');

const ROOT = path.join(__dirname, '..');
const REPO = 'sadrazkh/Irnetfree_xray-client';
const SITE_URL = 'https://sadrazkh.github.io/Irnetfree_xray-client/';
const PAGES = ['', 'en/'];

/** Every file the site serves: published path → source path, relative to the repo root. Names starting with
 *  "_" under site/ are sources (the link preview's _og.html) and are not published. */
function fileMap(root = ROOT) {
  const map = new Map();
  const walk = (dir) => {
    for (const e of fs.readdirSync(path.join(root, dir), { withFileTypes: true })) {
      const rel = `${dir}/${e.name}`;
      if (e.name.startsWith('_')) continue; // sources such as _og.html stay out
      if (e.isDirectory()) walk(rel);
      else if (e.isFile()) map.set(rel.slice('site/'.length), rel);
    }
  };
  walk('site');
  for (const f of fs.readdirSync(path.join(root, 'docs/readme')).sort()) {
    if (/\.png$/i.test(f)) map.set(`shots/${f}`, `docs/readme/${f}`);
  }
  map.set('assets/logo.svg', 'assets/logo.svg');
  map.set('assets/icon.png', 'assets/icon.png');
  return map;
}

function sitemap() {
  const alt = PAGES.map((p) => `    <xhtml:link rel="alternate" hreflang="${p ? 'en' : 'fa'}" href="${SITE_URL}${p}"/>`).join('\n');
  const urls = PAGES.map((p) => `  <url>\n    <loc>${SITE_URL}${p}</loc>\n${alt}\n  </url>`).join('\n');
  return `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">\n${urls}\n</urlset>\n`;
}

function robots() { return `User-agent: *\nAllow: /\nSitemap: ${SITE_URL}sitemap.xml\n`; }

/** Generated files: published path → content. */
function generated(release) {
  return new Map([
    ['release.json', JSON.stringify(release || {}, null, 1) + '\n'],
    ['sitemap.xml', sitemap()],
    ['robots.txt', robots()],
  ]);
}

/** The latest release from the GitHub API, slimmed; null when it cannot be read. */
function fetchLatest({ token, timeoutMs = 20000 } = {}) {
  return new Promise((resolve) => {
    const headers = { 'User-Agent': 'irnetfree-site-build', Accept: 'application/vnd.github+json' };
    if (token) headers.Authorization = `Bearer ${token}`;
    const req = https.get({ host: 'api.github.com', path: `/repos/${REPO}/releases/latest`, headers, timeout: timeoutMs }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (c) => { body += c; });
      res.on('end', () => {
        if (res.statusCode !== 200) { resolve(null); return; }
        try { resolve(slimRelease(JSON.parse(body))); } catch { resolve(null); }
      });
    });
    req.on('timeout', () => req.destroy());
    req.on('error', () => resolve(null));
  });
}

/** Writes the site into `out` (created if missing; nothing is deleted). Returns the published paths. */
function build(out, release, root = ROOT) {
  const written = [];
  for (const [pub, src] of fileMap(root)) {
    const dest = path.join(out, pub);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.copyFileSync(path.join(root, src), dest);
    written.push(pub);
  }
  for (const [pub, text] of generated(release)) {
    fs.writeFileSync(path.join(out, pub), text);
    written.push(pub);
  }
  return written.sort();
}

const TYPES = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.xml': 'application/xml',
  '.txt': 'text/plain; charset=utf-8', '.ico': 'image/x-icon',
};

function serve(port, release) {
  const server = http.createServer((req, res) => {
    let p = decodeURIComponent(new URL(req.url, 'http://x').pathname).replace(/^\/+/, '');
    if (p === '' || p.endsWith('/')) p += 'index.html';
    const gen = generated(release);
    const map = fileMap();
    let status = 200;
    let body = null;
    if (gen.has(p)) body = Buffer.from(gen.get(p));
    else if (map.has(p)) body = fs.readFileSync(path.join(ROOT, map.get(p)));
    else if (map.has(`${p}/index.html`)) { res.writeHead(301, { Location: `/${p}/` }); res.end(); return; }
    else { status = 404; p = '404.html'; body = fs.readFileSync(path.join(ROOT, 'site/404.html')); }
    res.writeHead(status, { 'Content-Type': TYPES[path.extname(p)] || 'application/octet-stream', 'Cache-Control': 'no-store' });
    res.end(body);
  });
  server.listen(port, '127.0.0.1', () => console.log(`site preview: http://127.0.0.1:${port}/`));
  return server;
}

async function main(argv) {
  const has = (f) => argv.includes(f);
  const val = (f) => { const i = argv.indexOf(f); return i >= 0 ? argv[i + 1] : undefined; };
  const release = has('--offline') ? null : await fetchLatest({ token: process.env.GITHUB_TOKEN });
  if (!release) {
    if (has('--require-release')) { console.error('build-site: the latest release could not be read from the GitHub API'); process.exit(1); }
    console.warn('build-site: no release data; the download buttons will point at the releases page');
  } else {
    console.log(`build-site: ${release.tag}, ${release.assets.length} assets`);
  }
  if (has('--serve')) {
    const n = Number(val('--serve'));
    serve(Number.isInteger(n) && n > 0 ? n : 4517, release);
    return;
  }
  const out = path.resolve(val('--out') || '_site');
  const files = build(out, release);
  console.log(`build-site: ${files.length} files in ${out}`);
}

if (require.main === module) main(process.argv.slice(2));

module.exports = { ROOT, REPO, SITE_URL, fileMap, generated, build, fetchLatest, sitemap };
