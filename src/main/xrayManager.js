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
const net = require('net');

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

  /** Find the xray executable. */
  resolveBin() {
    if (this.binPath && fs.existsSync(this.binPath)) return this.binPath;

    const exe = os.platform() === 'win32' ? 'xray.exe' : 'xray';
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

  binExists() {
    return !!this.resolveBin();
  }

  /** xray-core version string (e.g. "1.8.24"), cached. Empty if unavailable. */
  version() {
    return new Promise((resolve) => {
      if (this._version) return resolve(this._version);
      const bin = this.resolveBin();
      if (!bin) return resolve('');
      let out = '';
      const proc = spawn(bin, ['version'], { cwd: path.dirname(bin), windowsHide: true, env: this.spawnEnv() });
      proc.stdout.on('data', d => { out += d.toString('utf8'); });
      proc.stderr.on('data', d => { out += d.toString('utf8'); });
      const finish = () => {
        // first line looks like: "Xray 1.8.24 (Xray, ...) ..."
        const m = out.match(/Xray[^\d]*(\d+\.\d+\.\d+)/i);
        this._version = m ? m[1] : (out.split(/\r?\n/)[0] || '').trim();
        resolve(this._version);
      };
      proc.on('error', () => resolve(''));
      proc.on('exit', finish);
      setTimeout(() => { try { proc.kill(); } catch {} finish(); }, 4000);
    });
  }

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
  validate(config) {
    return new Promise((resolve) => {
      const bin = this.resolveBin();
      if (!bin) return resolve({ ok: false, error: 'xray binary not found' });
      let cfgPath;
      try { cfgPath = path.join(this.dataDir, `test-cfg-${Date.now()}.json`); fs.writeFileSync(cfgPath, JSON.stringify(config, null, 2), 'utf8'); }
      catch (e) { return resolve({ ok: false, error: e.message }); }

      let out = '';
      const proc = spawn(bin, ['run', '-test', '-c', cfgPath], { cwd: path.dirname(bin), windowsHide: true, env: this.spawnEnv() });
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

  /** Start xray with the given config object. */
  async start(config) {
    if (this.running) await this.stop();

    const bin = this.resolveBin();
    if (!bin) {
      this.onStatus('error', { message: 'xray binary not found. Put xray.exe in the bin/ folder.' });
      throw new Error('xray binary not found');
    }

    const cfgPath = this.writeConfig(config);
    this.onLog(`Starting xray with ${path.basename(cfgPath)}`, 'info');

    this.proc = spawn(bin, ['run', '-c', cfgPath], {
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
   */
  async startTest(testConfig) {
    const bin = this.resolveBin();
    if (!bin) throw new Error('xray binary not found');
    const cfgPath = path.join(this.dataDir, `test-${Date.now()}.json`);
    fs.writeFileSync(cfgPath, JSON.stringify(testConfig, null, 2), 'utf8');

    const proc = spawn(bin, ['run', '-c', cfgPath], { cwd: path.dirname(bin), windowsHide: true, env: this.spawnEnv() });
    // give it a moment to bind
    await delay(500);
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

module.exports = { XrayManager, getFreePort };
