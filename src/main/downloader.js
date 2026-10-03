'use strict';
/**
 * Downloads / integrates / updates the runtime binaries the app needs, WITHOUT
 * rebuilding the installer. Everything lands in a writable directory
 * (userData/bin) which the managers check before the bundled bin/.
 *
 * Components:
 *   - xray      : XTLS/Xray-core (zip → xray.exe + geoip.dat + geosite.dat)
 *   - xray-pattn: patterniha/Xray-core fork — same asset names, placed as
 *                 xray-pattn.exe so it coexists with the official core
 *   - sing-box  : SagerNet/sing-box (zip/tar.gz → sing-box.exe) — alternate core
 *   - geo       : geoip.dat + geosite.dat only (Loyalsoldier rules, direct .dat)
 *   - tun2socks : xjasonlyu/tun2socks (zip → tun2socks.exe)
 *   - wintun    : wintun.dll (wintun.net zip, Windows only)
 *
 * The three cores can also be installed at a chosen release (the version
 * picker, coreVersions.js): listReleases() and installVersion() below.
 *
 * No external deps: Node https + PowerShell/unzip for extraction.
 */

const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { execFile, execFileSync } = require('child_process');
const { engine, engineExe } = require('./engines');
const { versionNumber } = require('./assetUpdater');
const { CORE_IDS, CORE_NAMES, SUGGESTED, TAG_RE, fullVersion } = require('./coreVersions');

const GEO_BASE = 'https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download';
const WINTUN_URL = 'https://www.wintun.net/builds/wintun-0.14.1.zip';

/** The picker's release list per core is kept this long (spec: ten minutes). */
const RELEASES_TTL_MS = 10 * 60 * 1000;
/** How many releases one listing asks GitHub for. */
const RELEASES_PER_PAGE = 30;
/** GitHub's API silent this long is an error the picker can show, not a spinner for ever. */
const API_IDLE_MS = 30000;
/** A version install's download with no data for this long is given up. */
const DOWNLOAD_IDLE_MS = 60000;
/** `<bin> version` of a freshly downloaded core: a router's Cortex-A7 included. */
const VERSION_RUN_MS = 20000;
/** The most JSON read in one answer: the 30 newest Xray releases are ~4 MB with every asset of each. */
const JSON_MAX_BYTES = 32 * 1024 * 1024;

function getJSON(url) {
  return new Promise((resolve, reject) => {
    https.get(url, { headers: { 'User-Agent': 'IRNetFree' } }, (res) => {
      if (res.statusCode >= 300 && res.headers.location) return resolve(getJSON(res.headers.location));
      let body = '';
      res.on('data', (c) => (body += c));
      res.on('end', () => { try { resolve(JSON.parse(body)); } catch (e) { reject(e); } });
    }).on('error', reject);
  });
}

/** The only hosts plain http:// is allowed for — the tests' local server. */
const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '::1']);

/**
 * Pick the transport for a download URL, refusing cleartext.
 * What lands here is an EXECUTABLE (xray / sing-box / tun2socks) that the app
 * then runs, so http:// is only a local-test seam. This is checked per hop:
 * a redirect onto a plain-http URL must not reopen it either.
 */
function pickModule(u) {
  let parsed;
  try { parsed = new URL(u); } catch { throw new Error('invalid download URL: ' + u); }
  if (parsed.protocol === 'https:') return https;
  if (parsed.protocol !== 'http:') throw new Error('unsupported download protocol: ' + parsed.protocol);
  // URL strips the brackets of an IPv6 literal, so [::1] arrives as ::1
  if (!LOOPBACK_HOSTS.has(parsed.hostname.toLowerCase())) {
    throw new Error('refusing to download over plain http: ' + u);
  }
  return http;
}

/**
 * GitHub's API for the version picker, stricter than getJSON (which the update
 * button and the weekly check keep using as they always did): an HTTP error is
 * an error carrying GitHub's own message — `status`, and `rateLimited` for the
 * unauthenticated 60-an-hour limit — not an object that looks like a release;
 * a server silent for `idleTimeoutMs` is ETIMEDOUT; an answer larger than
 * JSON_MAX_BYTES is refused (a router holds it in a 160 MB heap). https only,
 * per hop, like downloadFile (plain http to loopback is the tests' seam).
 */
function fetchJSON(url, { idleTimeoutMs = API_IDLE_MS } = {}, depth = 0) {
  return new Promise((resolve, reject) => {
    if (depth > 6) return reject(new Error('too many redirects'));
    let mod;
    try { mod = pickModule(url); } catch (e) { return reject(e); }
    const req = mod.get(url, { headers: { 'User-Agent': 'IRNetFree', Accept: 'application/vnd.github+json' } }, (res) => {
      const code = res.statusCode || 0;
      if (code >= 300 && code < 400 && res.headers.location) {
        res.resume();
        let next;
        try { next = new URL(res.headers.location, url).toString(); } catch { return reject(new Error('GitHub redirected to an invalid URL')); }
        return resolve(fetchJSON(next, { idleTimeoutMs }, depth + 1));
      }
      const chunks = [];
      let size = 0;
      res.on('data', (c) => {
        size += c.length;
        if (size > JSON_MAX_BYTES) { req.destroy(new Error('GitHub’s answer is too large')); return; }
        chunks.push(c);
      });
      res.on('error', reject);
      res.on('close', () => { if (!res.complete) reject(new Error('GitHub’s answer was cut off')); });
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        if (code < 200 || code >= 300) {
          let message = '';
          try { message = String((JSON.parse(text) || {}).message || ''); } catch { /* not JSON: the status says it */ }
          const rateLimited = (code === 403 || code === 429) && (res.headers['x-ratelimit-remaining'] === '0' || /rate limit/i.test(message));
          return reject(Object.assign(new Error(`GitHub: HTTP ${code}${message ? ' — ' + message : ''}`), { status: code, rateLimited }));
        }
        try { resolve(JSON.parse(text)); } catch (e) { reject(new Error('GitHub’s answer is not JSON: ' + e.message)); }
      });
    });
    req.on('error', reject);
    req.setTimeout(idleTimeoutMs, () => req.destroy(Object.assign(new Error('GitHub did not answer in time'), { code: 'ETIMEDOUT' })));
  });
}

/**
 * `opts.idleTimeoutMs`: give up when no data arrives for that long (the version
 * picker's installs). Without it — every other caller — a download waits as long
 * as it always did.
 */
function downloadFile(url, dest, onProgress, opts = {}) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(dest);
    let settled = false;
    let body = null;             // the response being written, dropped on a failure
    // Never leave a half-written (or empty, still-open) file behind: a 403 from
    // GitHub's rate limiter used to strand a zero-byte *.tmp with its handle open.
    const fail = (err) => {
      if (settled) return;
      settled = true;
      if (body) { try { body.destroy(); } catch {} }
      const drop = () => { try { fs.unlinkSync(dest); } catch {} reject(err); };
      if (file.closed) return drop();
      file.once('close', drop);
      file.destroy();
    };
    // ENOSPC / EIO / EACCES on the destination: without a listener an error on
    // the write stream is an uncaught exception — the whole process, and on a
    // router with it the gateway. It is a failed download like any other.
    file.on('error', fail);
    const req = (u, depth) => {
      if (depth > 6) return fail(new Error('too many redirects'));
      let mod;
      try { mod = pickModule(u); } catch (e) { return fail(e); }
      const hop = mod.get(u, { headers: { 'User-Agent': 'IRNetFree' } }, (res) => {
        if (settled) { res.resume(); return; }
        if (res.statusCode >= 300 && res.headers.location) { res.resume(); req(res.headers.location, depth + 1); return; }
        if (res.statusCode !== 200) { res.resume(); return fail(new Error('HTTP ' + res.statusCode)); }
        body = res;
        const total = parseInt(res.headers['content-length'] || '0', 10);
        let got = 0;
        res.on('data', (c) => {
          got += c.length;
          if (onProgress && total) onProgress(Math.min(100, Math.round((got / total) * 100)));
        });
        res.on('error', fail);
        // a connection that closes before the body is complete is a failure,
        // whether or not this Node reports it as an error on the response
        res.on('close', () => { if (!res.complete) fail(new Error('the download was cut off')); });
        res.pipe(file);
        file.on('finish', () => file.close(() => { if (!settled) { settled = true; resolve(dest); } }));
      }).on('error', fail);
      if (opts.idleTimeoutMs) {
        hop.setTimeout(opts.idleTimeoutMs, () => hop.destroy(new Error(`the download stalled — nothing arrived for ${Math.round(opts.idleTimeoutMs / 1000)} s`)));
      }
    };
    req(url, 0);
  });
}

/** Unpack a release archive into `dir`: .zip, or .tar.gz (sing-box off Windows). */
function extractArchive(archive, dir) {
  if (/\.zip$/i.test(archive)) unzip(archive, dir);
  else untar(archive, dir);
}

/**
 * `<bin> version` — stdout and stderr together. Rejects when the binary does
 * not start, exits with an error or hangs, with a short reason of its own:
 * execFile's message carries the binary's path, and nothing but the core's
 * own output may ever be read as its version.
 */
function runVersion(bin, timeoutMs = VERSION_RUN_MS) {
  return new Promise((resolve, reject) => {
    execFile(bin, ['version'], { cwd: path.dirname(bin), timeout: timeoutMs, windowsHide: true, maxBuffer: 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) {
        const why = err.killed ? `no answer in ${Math.round(timeoutMs / 1000)} s`
          : err.signal ? `killed by ${err.signal}`
            : typeof err.code === 'number' ? `exit code ${err.code}`
              : err.code ? String(err.code) : 'it exited with an error';
        return reject(new Error(why));
      }
      resolve(`${stdout || ''}${stderr || ''}`);
    });
  });
}

/**
 * A GitHub release as the picker keeps it: what it reads, and of the assets
 * only the ones `match` (this platform's build) — a release of Xray carries
 * ~70 of them, each with its uploader, and a router keeps this for ten minutes.
 * Drafts (and anything that is not a release object) are dropped.
 */
function trimRelease(r, match) {
  if (!r || typeof r !== 'object' || Array.isArray(r) || r.draft || typeof r.tag_name !== 'string') return null;
  return {
    tag_name: r.tag_name,
    name: typeof r.name === 'string' ? r.name : '',
    prerelease: !!r.prerelease,
    draft: false,
    published_at: r.published_at || r.created_at || null,
    assets: (Array.isArray(r.assets) ? r.assets : [])
      .filter((a) => a && typeof a.name === 'string' && match(a.name))
      .map((a) => ({ name: a.name, size: Number(a.size) || 0, browser_download_url: String(a.browser_download_url || '') }))
  };
}

/** A core the picker knows, or an error. */
function coreId(component) {
  if (!CORE_IDS.includes(component)) throw new Error('unknown core: ' + component);
  return component;
}

function tmpDir(tag) {
  const d = path.join(os.tmpdir(), `irnf-${tag}-${Date.now()}`);
  fs.mkdirSync(d, { recursive: true });
  return d;
}

function unzip(zipPath, destDir) {
  if (os.platform() === 'win32') {
    execFileSync('powershell', ['-NoProfile', '-NonInteractive', '-Command',
      `Expand-Archive -LiteralPath '${zipPath}' -DestinationPath '${destDir}' -Force`],
      { windowsHide: true });
  } else {
    execFileSync('unzip', ['-o', zipPath, '-d', destDir], { stdio: 'ignore' });
  }
}

/** Extract a .tar.gz (used by sing-box's non-Windows releases). */
function untar(tgzPath, destDir) {
  execFileSync('tar', ['-xzf', tgzPath, '-C', destDir], { stdio: 'ignore' });
}

/** Recursively find the first file whose basename matches (case-insensitive). */
function findFile(dir, name) {
  const want = name.toLowerCase();
  const stack = [dir];
  while (stack.length) {
    const cur = stack.pop();
    let entries;
    try { entries = fs.readdirSync(cur, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      const full = path.join(cur, e.name);
      if (e.isDirectory()) stack.push(full);
      else if (e.name.toLowerCase() === want) return full;
    }
  }
  return null;
}

/**
 * Linux release-asset arch tokens per Node `os.arch()`. Routers: the Google
 * Wifi AC-1304 (OpenWrt, see tunOpenwrt.js) is 32-bit ARMv7 — `arm` — and
 * the two mips rows are what the small routers would need; they are a
 * mapping, not a supported target. amd64/arm64 rows are what they always were.
 */
const LINUX_ARCH = {
  xray: { x64: '64', arm64: 'arm64-v8a', arm: 'arm32-v7a', mips: 'mips32', mipsel: 'mips32le' },
  singbox: { x64: 'amd64', arm64: 'arm64', arm: 'armv7', mips: 'mips', mipsel: 'mipsle' },
  tun2socks: { x64: 'amd64', arm64: 'arm64', arm: 'armv7', mips: 'mips', mipsel: 'mipsle' }
};

class Downloader {
  /**
   * @param {object} opts { destDir, onLog, onProgress(component, pct) }
   *   The version picker's seams, for the tests: fetchJSON(url), fetchFile(url,
   *   dest, onProgress, opts), extractArchive(archive, dir), runVersion(bin) →
   *   output, now() → ms, platform / arch (this machine's by default).
   */
  constructor(opts = {}) {
    this.destDir = opts.destDir;
    this.onLog = opts.onLog || (() => {});
    this.onProgress = opts.onProgress || (() => {});
    this.copyFile = opts.copyFile || fs.copyFileSync;   // a seam for the tests (a copy that fails half way)
    this.fetchJSON = opts.fetchJSON || fetchJSON;
    this.fetchFile = opts.fetchFile || downloadFile;
    this.extractArchive = opts.extractArchive || extractArchive;
    this.runVersion = opts.runVersion || runVersion;
    this.now = opts.now || Date.now;
    this.platform = opts.platform || os.platform();
    this.arch = opts.arch || os.arch();
    this.releaseCache = new Map();     // core → { at, value } (listReleases)
    this.releaseFetches = new Map();   // core → the listing in flight, shared by every caller
    this.coresBusy = new Set();        // cores whose file a download or a version install is writing now
    fs.mkdirSync(this.destDir, { recursive: true });
  }

  /**
   * One writer per core file: the update button (download), the weekly updater
   * and a version install of the same core never run at once — on the router two
   * browser tabs can ask for both. The second is refused (ECOREBUSY) rather than
   * racing the first to place(): the last writer would win, and the picker's card
   * would say "installed" for a core already overwritten. Returns the release.
   */
  holdCore(id) {
    if (this.coresBusy.has(id)) throw Object.assign(new Error('another download or install of this core is running'), { code: 'ECOREBUSY' });
    this.coresBusy.add(id);
    return () => this.coresBusy.delete(id);
  }

  log(msg, level = 'info') { this.onLog('[download] ' + msg, level); }

  /** GitHub "latest release" endpoint for an Xray-format engine. */
  static releaseApiUrl(engineId) {
    const e = engine(engineId);
    if (e.format !== 'xray' || e.id !== engineId) throw new Error('not an Xray-format engine: ' + engineId);
    return `https://api.github.com/repos/${e.repo}/releases/latest`;
  }

  /*
   * The three release-asset pickers take the platform and arch as parameters
   * (defaulting to this machine's) so the tests can pin the macOS names on any
   * CI box: an Xray release carries `Xray-macos-64.zip` and
   * `Xray-macos-arm64-v8a.zip`, tun2socks `tun2socks-darwin-{amd64,arm64}.zip`,
   * sing-box `sing-box-<ver>-darwin-{amd64,arm64}.tar.gz` — none of which any
   * developer here can download on the machine it is meant for.
   */
  xrayAssetName(platform = os.platform(), arch = os.arch()) {
    if (platform === 'win32') return arch === 'arm64' ? 'Xray-windows-arm64-v8a.zip' : 'Xray-windows-64.zip';
    if (platform === 'darwin') return arch === 'arm64' ? 'Xray-macos-arm64-v8a.zip' : 'Xray-macos-64.zip';
    return `Xray-linux-${LINUX_ARCH.xray[arch] || '64'}.zip`;
  }

  tun2socksAssetName(platform = os.platform(), arch = os.arch()) {
    const a = arch === 'arm64' ? 'arm64' : 'amd64';
    if (platform === 'win32') return `tun2socks-windows-${a}.zip`;
    if (platform === 'darwin') return `tun2socks-darwin-${a}.zip`;
    return `tun2socks-linux-${LINUX_ARCH.tun2socks[arch] || 'amd64'}.zip`;
  }

  /** Download + integrate one component. Returns { ok, files } or throws. A core is held while it runs (holdCore). */
  async download(component) {
    const release = CORE_IDS.includes(component) ? this.holdCore(component) : null;
    try {
      switch (component) {
        case 'xray': return await this.getXray('xray');
        case 'xray-pattn': return await this.getXray('xray-pattn');
        case 'sing-box': return await this.getSingbox();
        case 'geo': return await this.getGeo();
        case 'tun2socks': return await this.getTun2socks();
        case 'wintun': return await this.getWintun();
        default: throw new Error('unknown component: ' + component);
      }
    } finally {
      if (release) release();
    }
  }

  /** Regex matching a platform's sing-box release asset (version varies). */
  singboxAssetPattern(platform = os.platform(), arch = os.arch()) {
    const a = arch === 'arm64' ? 'arm64' : 'amd64';
    if (platform === 'win32') return new RegExp(`sing-box-.*-windows-${a}\\.zip$`, 'i');
    if (platform === 'darwin') return new RegExp(`sing-box-.*-darwin-${a}\\.tar\\.gz$`, 'i');
    return new RegExp(`sing-box-.*-linux-${LINUX_ARCH.singbox[arch] || 'amd64'}\\.tar\\.gz$`, 'i');
  }

  async getSingbox() {
    this.log('Fetching latest sing-box release info…');
    const rel = await getJSON('https://api.github.com/repos/SagerNet/sing-box/releases/latest');
    const pat = this.singboxAssetPattern();
    const asset = (rel.assets || []).find(a => pat.test(a.name));
    if (!asset) throw new Error('sing-box asset not found for this platform');
    const work = tmpDir('singbox');
    const archive = path.join(work, asset.name);
    this.log(`Downloading ${asset.name} (${rel.tag_name})…`);
    await downloadFile(asset.browser_download_url, archive, (p) => this.onProgress('sing-box', p));
    this.log('Extracting sing-box…');
    if (/\.zip$/i.test(asset.name)) unzip(archive, work); else untar(archive, work);
    const exeName = os.platform() === 'win32' ? 'sing-box.exe' : 'sing-box';
    const exe = findFile(work, exeName);
    if (!exe) throw new Error('sing-box binary not found in archive');
    const placed = this.place(exe, exeName, true);
    this.cleanup(work);
    this.log('✓ sing-box integrated: ' + placed);
    return { ok: true, files: [placed] };
  }

  /**
   * Download an Xray-format core. Both the official core and the patterniha fork
   * publish the same asset names; the binary is placed under the engine's own exe
   * name so they coexist. Geo files inside the archive are placed too.
   */
  async getXray(engineId = 'xray') {
    const eng = engine(engineId);
    this.log(`Fetching latest ${eng.label} release info…`);
    const rel = await getJSON(Downloader.releaseApiUrl(engineId));
    const want = this.xrayAssetName();
    const asset = (rel.assets || []).find(a => a.name === want);
    if (!asset) throw new Error('asset not found: ' + want);
    const work = tmpDir(engineId);
    const zip = path.join(work, want);
    this.log(`Downloading ${want} (${eng.label} ${rel.tag_name})…`);
    await downloadFile(asset.browser_download_url, zip, (p) => this.onProgress(engineId, p));
    this.log(`Extracting ${eng.label}…`);
    unzip(zip, work);
    const inArchive = os.platform() === 'win32' ? 'xray.exe' : 'xray';   // upstream's name inside the zip
    const exe = findFile(work, inArchive);
    if (!exe) throw new Error('xray binary not found in archive');
    const out = [];
    out.push(this.place(exe, engineExe(engineId), true));
    for (const dat of ['geoip.dat', 'geosite.dat']) {
      const f = findFile(work, dat);
      if (f) out.push(this.place(f, dat));
    }
    this.cleanup(work);
    this.log(`✓ ${eng.label} integrated: ` + out.join(', '));
    return { ok: true, files: out };
  }

  /** The latest release tag of an engine, without a leading v — for the weekly check (assetUpdater.js). */
  async latestVersion(engineId) {
    const url = engineId === 'sing-box'
      ? 'https://api.github.com/repos/SagerNet/sing-box/releases/latest'
      : Downloader.releaseApiUrl(engineId);
    const rel = await getJSON(url);
    return String(rel.tag_name || '').replace(/^v/i, '').trim();
  }

  /* ----------------------------- the version picker ----------------------------- */

  /** GitHub's releases endpoint of a core's own repo. */
  static releasesUrl(component) {
    return `https://api.github.com/repos/${engine(coreId(component)).repo}/releases`;
  }

  /** (assetName) → is this the platform's archive of the core — the one the update button would fetch? */
  assetMatcher(component, platform = this.platform, arch = this.arch) {
    if (coreId(component) === 'sing-box') {
      const re = this.singboxAssetPattern(platform, arch);
      return (name) => re.test(String(name));
    }
    const want = this.xrayAssetName(platform, arch);
    return (name) => String(name) === want;
  }

  /**
   * What the picker says it downloads for: { platform, arch, asset } — the
   * archive's name (sing-box's with `*` for the version, as its pattern has it).
   */
  target(component, platform = this.platform, arch = this.arch) {
    if (coreId(component) !== 'sing-box') return { platform, arch, asset: this.xrayAssetName(platform, arch) };
    const a = arch === 'arm64' ? 'arm64' : 'amd64';
    const tail = platform === 'win32' ? `windows-${a}.zip`
      : platform === 'darwin' ? `darwin-${a}.tar.gz`
        : `linux-${LINUX_ARCH.singbox[arch] || 'amd64'}.tar.gz`;
    return { platform, arch, asset: `sing-box-*-${tail}` };
  }

  /**
   * A core's releases for the picker: { releases, latestTag, fetchedAt } — the
   * RELEASES_PER_PAGE newest (trimRelease: this platform's archive only) and
   * GitHub's latest stable tag ('' if that request failed). The suggested
   * release (coreVersions.js) is fetched by its tag when it is older than those
   * — sing-box publishes alphas, betas and rcs between its stables, and the ⭐
   * card must be there to go back to. Cached RELEASES_TTL_MS per core; `force`
   * (the modal's Retry) asks again; callers asking at once share one request;
   * a failure is thrown and never cached.
   */
  async listReleases(component, { force = false } = {}) {
    const id = coreId(component);
    const hit = this.releaseCache.get(id);
    if (!force && hit && this.now() - hit.at < RELEASES_TTL_MS) return hit.value;
    if (!force && this.releaseFetches.has(id)) return this.releaseFetches.get(id);
    const run = this.fetchReleases(id).then((value) => {
      this.releaseCache.set(id, { at: this.now(), value });
      return value;
    });
    this.releaseFetches.set(id, run);
    try {
      return await run;
    } finally {
      if (this.releaseFetches.get(id) === run) this.releaseFetches.delete(id);
    }
  }

  async fetchReleases(id) {
    const base = Downloader.releasesUrl(id);
    const [list, latest] = await Promise.all([
      this.fetchJSON(`${base}?per_page=${RELEASES_PER_PAGE}`),
      Promise.resolve().then(() => this.fetchJSON(`${base}/latest`)).catch(() => null)
    ]);
    if (!Array.isArray(list)) {
      const said = list && typeof list === 'object' && list.message ? ` (${String(list.message).slice(0, 200)})` : '';
      throw new Error('GitHub did not answer with a list of releases' + said);
    }
    const match = this.assetMatcher(id);
    const releases = list.map((r) => trimRelease(r, match)).filter(Boolean);
    const suggested = SUGGESTED[id];
    if (suggested && !releases.some((r) => versionNumber(r.tag_name) === suggested && !/-/.test(fullVersion(r.tag_name)))) {
      const extra = await Promise.resolve().then(() => this.fetchJSON(`${base}/tags/v${suggested}`)).catch(() => null);
      const t = trimRelease(extra, match);
      if (t) releases.push(t);
    }
    return {
      releases,
      latestTag: latest && typeof latest.tag_name === 'string' && !latest.draft ? latest.tag_name : '',
      fetchedAt: this.now()
    };
  }

  /** One release by its tag: from the last listing when it is there, else from GitHub. */
  async releaseByTag(id, tag) {
    const hit = this.releaseCache.get(id);
    const known = hit && hit.value.releases.find((r) => r.tag_name === tag);
    if (known) return known;
    const r = trimRelease(await this.fetchJSON(`${Downloader.releasesUrl(id)}/tags/${encodeURIComponent(tag)}`), this.assetMatcher(id));
    if (!r) throw new Error(`no release ${tag}`);
    return r;
  }

  /**
   * Install one chosen release of a core: its archive for this platform is
   * downloaded and extracted into a work dir, the binary in it is made
   * runnable (a Mac: the quarantine strip and the ad-hoc signature, as place()
   * does) and run — `<bin> version` must name the tag's version — and only then
   * put in place under the engine's exe name, by the same atomic place() as a
   * download. `beforePlace` runs right before that (the IPC asks again whether a
   * connection started meanwhile, and throws). Any failure leaves the installed
   * binary as it was. The geo files in an Xray archive are NOT put in place:
   * a version install changes the core and nothing else. The core is held for
   * the whole install (holdCore): an Update of it meanwhile is refused, and so
   * is this install while an Update of it runs.
   * Returns { ok, component, tag, version, file }.
   */
  async installVersion(component, tag, opts = {}) {
    const id = coreId(component);
    const want = versionNumber(tag);
    if (!TAG_RE.test(String(tag || '')) || !want) throw new Error('not a release tag: ' + tag);
    const release = this.holdCore(id);
    try {
      return await this.installHeld(id, tag, want, opts);
    } finally {
      release();
    }
  }

  async installHeld(id, tag, want, { beforePlace } = {}) {
    const name = `${CORE_NAMES[id]} ${tag}`;
    const rel = await this.releaseByTag(id, tag);
    const match = this.assetMatcher(id);
    const asset = (rel.assets || []).find((a) => a && match(a.name) && a.browser_download_url);
    if (!asset) throw new Error(`${tag} has no build for this platform (${this.target(id).asset})`);
    const work = tmpDir(id);
    try {
      const archive = path.join(work, path.basename(asset.name));
      this.log(`Downloading ${asset.name} (${name})…`);
      await this.fetchFile(asset.browser_download_url, archive, (p) => this.onProgress(id, p), { idleTimeoutMs: DOWNLOAD_IDLE_MS });
      this.log(`Extracting ${name}…`);
      await this.extractArchive(archive, work);
      const win = this.platform === 'win32';
      const inArchive = (id === 'sing-box' ? 'sing-box' : 'xray') + (win ? '.exe' : '');   // upstream's name inside the archive
      const exe = findFile(work, inArchive);
      if (!exe) throw new Error(`${inArchive} not found in ${asset.name}`);
      if (!win) { try { fs.chmodSync(exe, 0o755); } catch { /* the run below says whether it can start */ } }
      if (this.platform === 'darwin') this.macPrepareBinary(exe, true);
      this.log(`Checking ${name}…`);
      let out;
      try { out = String(await this.runVersion(exe)); } catch (e) {
        throw new Error(`the downloaded ${CORE_NAMES[id]} did not run (${e.message}) — nothing was replaced`);
      }
      const got = versionNumber(out);
      if (!got) throw new Error(`the downloaded ${CORE_NAMES[id]} did not say its version (${JSON.stringify(out.trim().split(/\r?\n/)[0].slice(0, 120))}) — nothing was replaced`);
      if (got !== want) throw new Error(`the downloaded ${CORE_NAMES[id]} says it is ${got}, not ${want} — nothing was replaced`);
      if (beforePlace) await beforePlace();
      let placed;
      try {
        placed = this.place(exe, engineExe(id, this.platform), true);
      } catch (e) {
        // Windows: a core image that is running cannot be renamed over — a
        // latency test ("ping all") or a config check holds it for a few seconds,
        // and nothing else the IPC can see does. place() left it untouched.
        if (this.platform === 'win32' && ['EPERM', 'EBUSY', 'EACCES'].includes(e && e.code)) {
          throw Object.assign(new Error(`the ${CORE_NAMES[id]} file is in use (a latency test or a config check is running it) — close it and try again; nothing was replaced`), { code: 'ECOREINUSE', cause: e });
        }
        throw e;
      }
      this.log(`✓ ${name} integrated: ${placed}`);
      return { ok: true, component: id, tag, version: fullVersion(tag) || want, file: placed };
    } finally {
      this.cleanup(work);
    }
  }

  async getGeo() {
    const out = [];
    for (const dat of ['geoip.dat', 'geosite.dat']) {
      const dest = path.join(this.destDir, dat);
      this.log(`Downloading ${dat}…`);
      await downloadFile(`${GEO_BASE}/${dat}`, dest + '.tmp', (p) => this.onProgress('geo', p));
      fs.renameSync(dest + '.tmp', dest);
      out.push(dest);
    }
    this.log('✓ Geo files integrated.');
    return { ok: true, files: out };
  }

  async getTun2socks() {
    this.log('Fetching latest tun2socks release info…');
    const rel = await getJSON('https://api.github.com/repos/xjasonlyu/tun2socks/releases/latest');
    const want = this.tun2socksAssetName();
    const asset = (rel.assets || []).find(a => a.name === want);
    if (!asset) throw new Error('asset not found: ' + want);
    const work = tmpDir('t2s');
    const zip = path.join(work, want);
    this.log(`Downloading ${want} (${rel.tag_name})…`);
    await downloadFile(asset.browser_download_url, zip, (p) => this.onProgress('tun2socks', p));
    this.log('Extracting tun2socks…');
    unzip(zip, work);
    const exeName = os.platform() === 'win32' ? '.exe' : '';
    // archive names the binary like tun2socks-windows-amd64.exe
    let exe = findFile(work, this.tun2socksAssetName().replace('.zip', exeName));
    if (!exe) exe = findFile(work, os.platform() === 'win32' ? 'tun2socks.exe' : 'tun2socks');
    if (!exe) throw new Error('tun2socks binary not found in archive');
    const placed = this.place(exe, os.platform() === 'win32' ? 'tun2socks.exe' : 'tun2socks', true);
    this.cleanup(work);
    this.log('✓ tun2socks integrated: ' + placed);
    return { ok: true, files: [placed] };
  }

  async getWintun() {
    if (os.platform() !== 'win32') return { ok: true, files: [] };
    const work = tmpDir('wintun');
    const zip = path.join(work, 'wintun.zip');
    this.log('Downloading wintun.dll…');
    await downloadFile(WINTUN_URL, zip, (p) => this.onProgress('wintun', p));
    unzip(zip, work);
    const archDir = os.arch() === 'arm64' ? 'arm64' : 'amd64';
    let dll = findFile(path.join(work, 'wintun', 'bin', archDir), 'wintun.dll');
    if (!dll) dll = findFile(work, 'wintun.dll');
    if (!dll) throw new Error('wintun.dll not found in archive');
    const placed = this.place(dll, 'wintun.dll');
    this.cleanup(work);
    this.log('✓ wintun integrated: ' + placed);
    return { ok: true, files: [placed] };
  }

  /**
   * Copy a file into destDir; mark executable on unix. The copy goes to
   * `<name>.new` and is renamed over the old one, so a copy that fails half way
   * (a full flash on a router) never truncates — or, through libuv's cleanup of
   * a failed copy, deletes — the core that was working. The rename also works
   * under a running binary on Linux, where copying onto it is ETXTBSY.
   */
  place(src, name, exec = false) {
    const dest = path.join(this.destDir, name);
    const tmp = dest + '.new';
    try {
      this.copyFile(src, tmp);
      if (os.platform() !== 'win32') {
        if (exec) { try { fs.chmodSync(tmp, 0o755); } catch {} }
        if (os.platform() === 'darwin') this.macPrepareBinary(tmp, exec);
      }
      fs.renameSync(tmp, dest);
    } catch (e) {
      try { fs.rmSync(tmp, { force: true }); } catch {}
      throw e;
    }
    return dest;
  }

  /**
   * Make a downloaded file usable on macOS:
   *  - strip the quarantine attribute (harmless if absent)
   *  - ad-hoc codesign executables so Gatekeeper (esp. Apple Silicon, which
   *    refuses to run unsigned binaries) lets them launch.
   */
  macPrepareBinary(dest, exec) {
    try { execFileSync('xattr', ['-dr', 'com.apple.quarantine', dest]); } catch {}
    if (exec) {
      // Apple Silicon REFUSES to exec an unsigned binary (SIGKILL "Killed: 9")
      // with no useful error — which later masquerades as "tun2socks did not
      // create a utun device". An ad-hoc signature is enough to run a CLI
      // binary, so a codesign failure here must be fatal, not a warning.
      try { execFileSync('codesign', ['--force', '--sign', '-', dest]); }
      catch (e) {
        const isArm = os.arch() === 'arm64';
        const msg = 'codesign failed for ' + path.basename(dest) + ': ' + (e.message || e) +
          (isArm ? ' — on Apple Silicon the binary cannot run unsigned. Install Xcode Command Line Tools (xcode-select --install) and retry.' : '');
        if (isArm) { this.log(msg, 'error'); throw new Error(msg); }
        this.log(msg, 'warn');
      }
    }
  }

  cleanup(dir) { try { fs.rmSync(dir, { recursive: true, force: true }); } catch {} }
}

module.exports = { Downloader, downloadFile, fetchJSON, runVersion, RELEASES_TTL_MS };
