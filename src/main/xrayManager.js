'use strict';
/**
 * Manages the xray-core child process lifecycle:
 *  - locate the xray binary (bundled in /bin or via env)
 *  - write config.json, spawn, capture logs
 *  - stop / restart
 *  - run a short-lived instance to measure real proxy latency
 */

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { DEFAULT_ENGINE, engineExe, engineRunArgs, engineTestArgs, engineLabel, xrayEngines } = require('./engines');
const net = require('net');

/** Upstream's plaintext-outbound refusal (infra/conf/xray.go); the patterniha fork lifts it. */
const PLAINTEXT_REJECT = /without TLS.*prohibited/i;

class XrayManager {
  constructor(opts = {}) {
    this.binPath = opts.binPath || null;
    this.dataDir = opts.dataDir;          // where config.json and logs live
    // Writable dirs (e.g. userData/bin) checked BEFORE the bundled bin so the
    // user can download/update xray + geo files without rebuilding the app.
    this.extraBinDirs = (opts.extraBinDirs || []).filter(Boolean);
    this.onLog = opts.onLog || (() => {}); // (line, level)
    this.onStatus = opts.onStatus || (() => {}); // ('running'|'stopped'|'error', info)
    this.proc = null;
    this.running = false;
    this._versions = {};                  // engineId -> version string
    this.currentConfigPath = path.join(this.dataDir, 'config.json');
  }

  /** All directories that may contain xray / geo assets, in priority order. */
  binDirs() {
    return [
      ...this.extraBinDirs,
      path.join(this.dataDir || '', '..', 'bin'),
      path.join(process.resourcesPath || '', 'bin'),
      path.join(__dirname, '..', '..', 'bin')
    ].filter(Boolean);
  }

  /**
   * Find a core executable. With no engine (or the default 'xray') this resolves
   * the stock xray binary and caches it on `this.binPath`. For an alternate
   * engine it resolves that engine's binary from the bin dirs (no caching), and
   * returns null if it isn't installed — callers fall back to the default.
   */
  resolveBin(engineId = DEFAULT_ENGINE) {
    if (engineId !== DEFAULT_ENGINE) {
      const exe = engineExe(engineId);
      for (const d of this.binDirs()) {
        const c = path.join(d, exe);
        if (fs.existsSync(c)) return c;
      }
      return null;
    }

    if (this.binPath && fs.existsSync(this.binPath)) return this.binPath;

    const exe = engineExe(DEFAULT_ENGINE);
    const candidates = [
      process.env.XRAY_PATH,
      this.binPath,
      ...this.binDirs().map(d => path.join(d, exe))
    ].filter(Boolean);

    for (const c of candidates) {
      if (fs.existsSync(c)) { this.binPath = c; return c; }
    }
    return null;
  }

  /**
   * Resolve the effective engine to run a config on. The requested one if its
   * binary is installed; otherwise any other Xray-format core (they run the same
   * config — logged, so the user sees which one actually ran); otherwise the
   * default id with bin:null. Callers use the argv/format of the core returned.
   *
   * `opts.quiet` skips the fallback warning. Repeated lookups pass it, so a user
   * who installed only one core isn't told over and over that the other is
   * missing: the stats poller's binary (re-resolved on every connect / config
   * rebuild / asset change) and the latency test (once per server in "ping all").
   * The connect path stays loud — there, knowing which core ran is worth a line.
   */
  resolveEngine(engineId, opts = {}) {
    const wantId = engineId || DEFAULT_ENGINE;
    const wantBin = this.resolveBin(wantId);
    if (wantBin) return { id: wantId, bin: wantBin };
    for (const id of xrayEngines()) {
      if (id === wantId) continue;
      const bin = this.resolveBin(id);
      if (bin) {
        if (!opts.quiet) {
          this.onLog(`Engine '${wantId}' binary (${engineExe(wantId)}) not found in bin/ — using ${id}`, 'warn');
        }
        return { id, bin };
      }
    }
    return { id: DEFAULT_ENGINE, bin: null };
  }

  /**
   * Path of *any* installed Xray-format core, without logging a fallback —
   * for internal consumers (the stats poller) that just need an executable.
   */
  anyBin() {
    return this.resolveEngine(undefined, { quiet: true }).bin;
  }

  /** Directory that holds geoip.dat / geosite.dat (for XRAY_LOCATION_ASSET). */
  assetDir() {
    for (const d of this.binDirs()) {
      if (fs.existsSync(path.join(d, 'geoip.dat')) || fs.existsSync(path.join(d, 'geosite.dat'))) {
        return d;
      }
    }
    // fall back to the xray binary's own folder
    const bin = this.resolveBin();
    return bin ? path.dirname(bin) : null;
  }

  /** Build the spawn env, pinning the geo-asset path so routing rules work. */
  spawnEnv() {
    const env = Object.assign({}, process.env);
    const ad = this.assetDir();
    if (ad) {
      env.XRAY_LOCATION_ASSET = ad;
      env.V2RAY_LOCATION_ASSET = ad;
    }
    return env;
  }

  /** Is a core installed? With no id: any Xray-format core (they run the same config). */
  binExists(engineId) {
    if (engineId) return !!this.resolveBin(engineId);
    return xrayEngines().some(id => !!this.resolveBin(id));
  }

  /** Core version string (e.g. "26.9.1") for an engine, cached per engine. Empty if unavailable. */
  version(engineId = DEFAULT_ENGINE) {
    return new Promise((resolve) => {
      if (this._versions[engineId]) return resolve(this._versions[engineId]);
      const bin = this.resolveBin(engineId);
      if (!bin) return resolve('');
      let out = '';
      const proc = spawn(bin, ['version'], { cwd: path.dirname(bin), windowsHide: true, env: this.spawnEnv() });
      proc.stdout.on('data', d => { out += d.toString('utf8'); });
      proc.stderr.on('data', d => { out += d.toString('utf8'); });
      let done = false;
      const finish = () => {
        if (done) return; done = true;
        // first line looks like: "Xray 26.9.1 (Xray, Penetrates Everything.) ..."
        const m = out.match(/Xray[^\d]*(\d+\.\d+\.\d+)/i);
        this._versions[engineId] = m ? m[1] : (out.split(/\r?\n/)[0] || '').trim();
        resolve(this._versions[engineId]);
      };
      // mark done so the 4s timeout below can't run finish() after this and
      // cache a version parsed from output the failed spawn never produced
      proc.on('error', () => { done = true; resolve(''); });
      proc.on('exit', finish);
      setTimeout(() => { try { proc.kill(); } catch {} finish(); }, 4000);
    });
  }

  /** Forget cached versions (after a download / removal). */
  forgetVersions() { this._versions = {}; }

  /** Write config to disk. */
  writeConfig(config, file) {
    const target = file || this.currentConfigPath;
    fs.writeFileSync(target, JSON.stringify(config, null, 2), 'utf8');
    return target;
  }

  /**
   * Validate a config WITHOUT launching the server (xray run -test).
   * Returns { ok:true } or { ok:false, error } with the real core message,
   * so the UI can show *why* a chain / advanced-routing config was rejected.
   */
  validate(config, engineId) {
    return new Promise((resolve) => {
      const { id, bin } = this.resolveEngine(engineId);
      if (!bin) return resolve({ ok: false, error: 'core binary not found' });
      let cfgPath;
      try { cfgPath = path.join(this.dataDir, `test-cfg-${Date.now()}.json`); fs.writeFileSync(cfgPath, JSON.stringify(config, null, 2), 'utf8'); }
      catch (e) { return resolve({ ok: false, error: e.message }); }

      let out = '';
      const proc = spawn(bin, engineTestArgs(id, cfgPath), { cwd: path.dirname(bin), windowsHide: true, env: this.spawnEnv() });
      const grab = (d) => { out += d.toString('utf8'); };
      proc.stdout.on('data', grab);
      proc.stderr.on('data', grab);
      let settled = false;
      const finish = (res) => { if (settled) return; settled = true; try { fs.unlinkSync(cfgPath); } catch {} resolve(res); };
      proc.on('error', (err) => finish({ ok: false, error: err.message }));
      proc.on('exit', (code) => {
        if (code === 0) return finish({ ok: true });
        // Older xray builds may not know the -test flag; don't false-reject.
        if (/flag provided but not defined|not defined:.*test|unknown (flag|command)/i.test(out)) {
          return finish({ ok: true });
        }
        finish({ ok: false, error: extractXrayError(out) || `xray -test exited with code ${code}` });
      });
      // safety timeout — don't hang the UI if -test never returns
      setTimeout(() => { if (!settled) { try { proc.kill(); } catch {} finish({ ok: true }); } }, 6000);
    });
  }

  /**
   * Validate on the requested engine. If the OFFICIAL core rejects the config
   * only because it is plaintext VLESS/Trojan to a public address and the
   * patterniha fork is installed, validate on the fork instead — that is the one
   * thing the fork exists for. Returns { ok, engine, error?, fellBack?,
   * plaintextRejected? } so the caller knows which core to start and can tell
   * the user to install the fork when it is missing.
   */
  async validateWithFallback(config, engineId) {
    const first = this.resolveEngine(engineId);
    const r = await this.validate(config, first.id);
    if (r.ok) return { ok: true, engine: first.id };
    const plaintextRejected = PLAINTEXT_REJECT.test(r.error || '');
    if (first.id === 'xray' && plaintextRejected && this.resolveBin('xray-pattn')) {
      const again = await this.validate(config, 'xray-pattn');
      if (again.ok) {
        this.onLog(`Official core rejects this plaintext config — running it on ${engineLabel('xray-pattn')}`, 'warn');
        return { ok: true, engine: 'xray-pattn', fellBack: true };
      }
      return { ok: false, engine: 'xray-pattn', error: again.error, plaintextRejected: false };
    }
    return { ok: false, engine: first.id, error: r.error, plaintextRejected };
  }

  /** Start the core with the given config object, on the given engine. */
  async start(config, engineId) {
    if (this.running) await this.stop();

    const { id, bin } = this.resolveEngine(engineId);
    if (!bin) {
      this.onStatus('error', { message: 'xray binary not found. Put xray.exe in the bin/ folder.' });
      throw new Error('xray binary not found');
    }

    const cfgPath = this.writeConfig(config);
    this.onLog(`Starting ${path.basename(bin)} with ${path.basename(cfgPath)}`, 'info');

    this.proc = spawn(bin, engineRunArgs(id, cfgPath), {
      cwd: path.dirname(bin),
      windowsHide: true,
      env: this.spawnEnv()
    });

    this.running = true;
    // keep the most recent lines so a crash-on-start can report the real reason
    let recent = '';
    let earlyExit = null;

    const handleData = (buf, level) => {
      const text = buf.toString('utf8');
      recent = (recent + text).slice(-4000);
      for (const line of text.split(/\r?\n/)) {
        if (line.trim()) this.onLog(line.trim(), level);
      }
    };
    this.proc.stdout.on('data', (d) => handleData(d, 'log'));
    this.proc.stderr.on('data', (d) => handleData(d, 'warn'));

    this.proc.on('exit', (code, signal) => {
      this.running = false;
      this.proc = null;
      if (earlyExit) earlyExit({ code, signal });
      this.onLog(`xray exited (code=${code} signal=${signal || '-'})`, code === 0 ? 'info' : 'error');
      this.onStatus('stopped', { code, signal });
    });
    this.proc.on('error', (err) => {
      this.running = false;
      this.onLog('xray spawn error: ' + err.message, 'error');
      this.onStatus('error', { message: err.message });
    });

    // Grace period to detect an immediate crash (bad chain / routing config).
    // If xray dies within this window, throw the REAL core error so the UI can
    // show it instead of a silent "connected then dropped".
    const crashed = await new Promise((resolve) => {
      const timer = setTimeout(() => { earlyExit = null; resolve(null); }, 1200);
      earlyExit = (info) => { clearTimeout(timer); resolve(info); };
    });

    if (crashed) {
      const msg = extractXrayError(recent) || `xray exited on startup (code ${crashed.code})`;
      this.onStatus('error', { message: msg });
      throw new Error(msg);
    }

    if (this.running) this.onStatus('running', { pid: this.proc.pid });
    return this.running;
  }

  async stop() {
    if (!this.proc) { this.running = false; return; }
    const p = this.proc;
    return new Promise((resolve) => {
      const done = () => { resolve(); };
      p.once('exit', done);
      try {
        if (os.platform() === 'win32') {
          // graceful then forced
          spawn('taskkill', ['/pid', String(p.pid), '/t', '/f'], { windowsHide: true });
        } else {
          p.kill('SIGTERM');
        }
      } catch { done(); }
      setTimeout(done, 2500);
    });
  }

  /**
   * Spin up a throwaway xray instance on a free local SOCKS port to measure
   * real latency through the server, then kill it.
   * Returns the temp socks port (caller must measure & then call killTest).
   *
   * Resolves QUIETLY: "ping all" runs this once per server, so a fallback would
   * otherwise log the same warning dozens of times in a row.
   */
  async startTest(testConfig, engineId) {
    const { id, bin } = this.resolveEngine(engineId, { quiet: true });
    if (!bin) throw new Error('xray binary not found');
    const cfgPath = path.join(this.dataDir, `test-${Date.now()}.json`);
    fs.writeFileSync(cfgPath, JSON.stringify(testConfig, null, 2), 'utf8');

    const proc = spawn(bin, engineRunArgs(id, cfgPath), { cwd: path.dirname(bin), windowsHide: true, env: this.spawnEnv() });

    // A child that cannot be started emits 'error', and an 'error' with no
    // listener is re-thrown by Node as an uncaught exception — which killed the
    // whole app. A core that is missing, half-downloaded or not executable is
    // an ordinary thing (the user can delete it while we run), so it has to
    // come back as a rejected promise, like validate() already does.
    const failed = new Promise((_, reject) => {
      proc.once('error', (err) => {
        try { fs.unlinkSync(cfgPath); } catch { /* nothing to clean */ }
        reject(err);
      });
    });
    // If the child dies AFTER we have handed the caller its handle, nobody is
    // waiting on `failed` any more — mark it handled so a late failure is not
    // an unhandled rejection, which is the same crash by another route. The
    // caller finds out the ordinary way: the test through it times out.
    failed.catch(() => {});
    // give it a moment to bind — and lose the race if it never starts
    await Promise.race([delay(500), failed]);
    return {
      proc,
      cleanup: () => {
        try { proc.kill(); } catch {}
        try {
          if (os.platform() === 'win32' && proc.pid) spawn('taskkill', ['/pid', String(proc.pid), '/t', '/f'], { windowsHide: true });
        } catch {}
        try { fs.unlinkSync(cfgPath); } catch {}
      }
    };
  }
}

function delay(ms) { return new Promise(r => setTimeout(r, ms)); }

/**
 * Pull the meaningful line out of xray's (verbose) startup output.
 * xray prints failures like:
 *   "Failed to start: ... > infra/conf: <reason>"
 * We surface the deepest "> ..." segment, which is the actual reason.
 */
function extractXrayError(text) {
  if (!text) return null;
  const lines = text.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  // Prefer the line that mentions a failure
  const failLine = lines.reverse().find(l => /failed|error|panic|invalid|unknown|cannot|no such/i.test(l));
  const pick = failLine || lines[0];
  if (!pick) return null;
  // The most specific reason is usually after the last " > "
  const parts = pick.split(' > ');
  let msg = parts[parts.length - 1].trim();
  // strip a leading timestamp if present (e.g. "2024/01/01 00:00:00 ")
  msg = msg.replace(/^\d{4}\/\d{2}\/\d{2}\s+\d{2}:\d{2}:\d{2}\s*/, '');
  return msg || pick;
}

/** Find a free TCP port in the ephemeral range. */
function getFreePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.unref();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const port = srv.address().port;
      srv.close(() => resolve(port));
    });
  });
}

module.exports = { XrayManager, getFreePort, PLAINTEXT_REJECT };
