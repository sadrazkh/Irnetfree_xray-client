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
const crypto = require('crypto');
const { DEFAULT_ENGINE, engineExe, engineRunArgs, engineTestArgs, engineLabel, xrayEngines, engineFormat } = require('./engines');
const { adaptForCore, needsCoreVersion } = require('./coreCompat');
const net = require('net');

/** Upstream's plaintext-outbound refusal (infra/conf/xray.go); the patterniha fork lifts it. */
const PLAINTEXT_REJECT = /without TLS.*prohibited/i;
/**
 * The official core refusing the fork's `finalmask` (measured on 26.3.27 over
 * all 44 of the owner's patterniha servers: "infra/conf: LengthMin can't be 0").
 * Only read for a config that carries a finalmask — a freedom fragment can say
 * the same words about itself (usesFinalmask).
 */
const FINALMASK_REJECT = /LengthMin can't be 0|finalmask/i;

/**
 * Go's own runtime out of memory: the heap ("fatal error: runtime: out of
 * memory", or "runtime: out of memory: cannot allocate …" then "fatal error:
 * out of memory") or a thread it could not create. Exit code 2 — the check
 * died of the router's memory, not of the config (a refusal is "Failed to
 * start: …", exit 23).
 */
const GO_OUT_OF_MEMORY = /\bruntime: (out of memory|cannot allocate memory|failed to create new OS thread)|\bfatal error: out of memory/;

/**
 * Does any outbound carry a (non-empty) `streamSettings.finalmask`? Not one on
 * Hysteria or mKCP: their masks (salamander, hopping, mKCP's header and seed)
 * are the official core's own, written for its version (coreCompat.js) — no
 * reason to move them onto the fork.
 */
function usesFinalmask(config) {
  return ((config && config.outbounds) || []).some((o) => {
    const ss = o && o.streamSettings;
    const fm = ss && ss.finalmask;
    if (/^(hysteria|kcp|mkcp)$/i.test(String((ss && ss.network) || ''))) return false;
    return !!fm && typeof fm === 'object' && Object.keys(fm).length > 0;
  });
}

/**
 * The first official release that knows `finalmask` at all. Before it the key
 * is ignored like any unknown one — `-test` says "Configuration OK." and the
 * server runs with its mask silently dropped (the OpenWrt 23.05 feed's
 * xray-core is 24.12.31).
 */
const FINALMASK_SINCE = '26.3.27';

/**
 * ECH from a link: the official core knows `echConfigList` from 25.7.26 and
 * `echSockopt` (the ECH query bound to the NIC under TUN) from 25.8.3. An older
 * one passes the config — unknown keys — and connects WITHOUT ECH, the very
 * thing the link asked to hide. The router's opkg fallback (24.12.31, 25.1.30)
 * is such a core.
 */
const ECH_SINCE = '25.8.3';

/** Does any outbound ask for ECH? */
function usesEch(config) {
  return ((config && config.outbounds) || []).some((o) => {
    const tls = o && o.streamSettings && o.streamSettings.tlsSettings;
    return !!tls && typeof tls.echConfigList === 'string' && tls.echConfigList.trim() !== '';
  });
}

/**
 * Core log flood control (spec 2026-10-05 §4). The router's field report:
 * hundreds of identical WebSocket dial errors within the same milliseconds,
 * each one a line through syslog and the window's log on a slow CPU, in the
 * very storm the core was trying to get out of. A line the core repeats is
 * forwarded at most FLOOD_MAX times per FLOOD_WINDOW_MS; the rest become one
 * "×N more" line, said when the window closes or as soon as a different line
 * is forwarded. The lines are compared without their timestamp and their
 * [connection id] — what makes every one of a storm's lines different.
 */
const FLOOD_MAX = 5;
const FLOOD_WINDOW_MS = 10000;
// "2026/10/05 12:34:56.123456 " (Xray); "+0330 2026-10-05 12:34:56 " (sing-box)
const LOG_TIMESTAMP = /^(?:[+-]\d{4} )?\d{4}[/-]\d{2}[/-]\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?\s*/;
// "[2394738294] " (Xray); "[3524466123 1.2s] " (sing-box)
const LOG_CONN_ID = /\[\d+(?: [^\]\s]+)?\]\s*/g;

/** A core line as the gate compares it: no timestamp, no connection id. */
function floodKey(line) {
  return String(line == null ? '' : line).trim().replace(LOG_TIMESTAMP, '').replace(LOG_CONN_ID, '').trim();
}

/**
 * The gate one running core's lines pass through: `line(text, level)` forwards
 * to `emit(text, level)` or holds it back; `flush()` says what is held (the
 * core exited). `opts.max` / `opts.windowMs` for a test.
 */
function floodGate(emit, opts = {}) {
  const max = opts.max || FLOOD_MAX;
  const windowMs = opts.windowMs || FLOOD_WINDOW_MS;
  // key → { start, sent, held, level, timer }, in the order the windows opened
  const windows = new Map();
  const pending = new Set();   // keys with lines held back
  const sayHeld = (key) => {
    const w = windows.get(key);
    pending.delete(key);
    if (!w || !w.held) return;
    const n = w.held;
    w.held = 0;
    if (w.timer) { clearTimeout(w.timer); w.timer = null; }
    emit(`×${n} more: ${key}`, w.level);
  };
  const close = (key) => { sayHeld(key); windows.delete(key); };
  function line(text, level) {
    const key = floodKey(text);
    const now = Date.now();
    let w = windows.get(key);
    if (w && now - w.start >= windowMs) { close(key); w = null; }
    if (!w) {
      // windows long closed, oldest first: a line the core printed once is not kept for ever
      for (const [k, old] of windows) {
        if (now - old.start < windowMs) break;
        if (!old.held) windows.delete(k);
      }
      w = { start: now, sent: 0, held: 0, level, timer: null };
      windows.set(key, w);
    }
    if (w.sent < max) {
      // a different line: what is held back is said first, in the order it happened
      for (const k of [...pending]) if (k !== key) sayHeld(k);
      w.sent++;
      emit(text, level);
      return;
    }
    w.held++;
    w.level = level;
    pending.add(key);
    if (!w.timer) {
      w.timer = setTimeout(() => close(key), Math.max(0, w.start + windowMs - now));
      if (w.timer.unref) w.timer.unref();
    }
  }
  return { line, flush: () => { for (const k of [...pending]) sayHeld(k); } };
}

/** "24.12.31" below "26.3.27", compared as numbers; a string with no x.y.z in it is never below anything. */
function versionBelow(v, min) {
  const parse = (s) => { const m = /(\d+)\.(\d+)\.(\d+)/.exec(String(s || '')); return m ? m.slice(1, 4).map(Number) : null; };
  const a = parse(v);
  const b = parse(min);
  if (!a || !b) return false;
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] < b[i];
  return false;
}

class XrayManager {
  constructor(opts = {}) {
    this.binPath = opts.binPath || null;
    this.dataDir = opts.dataDir;          // where config.json and logs live
    // Writable dirs (e.g. userData/bin) checked BEFORE the bundled bin so the
    // user can download/update xray + geo files without rebuilding the app.
    this.extraBinDirs = (opts.extraBinDirs || []).filter(Boolean);
    this.onLog = opts.onLog || (() => {}); // (line, level)
    this.onStatus = opts.onStatus || (() => {}); // ('running'|'stopped'|'error', info)
    // How long `-test` may take before the config counts as UNVERIFIED (and
    // starts anyway). 6 s on a desktop; the router asks for ~30 s — on a
    // Cortex-A7 a slow refusal used to pass as "unverified" and only show up
    // as a dead connection (field report S2, fix 20).
    this.testTimeoutMs = opts.testTimeoutMs || 6000;
    this.proc = null;
    this.running = false;
    this.recent = '';                     // the running core's last output (recentLines)
    this._versions = {};                  // engineId -> version string
    /** Validations that PASSED, keyed by core file + geo files + config bytes (see validationKey). */
    this._validated = new Map();
    /** Test cores started so far: each one's config file is its own (startTest). */
    this._testSeq = 0;
    this.currentConfigPath = path.join(this.dataDir, 'config.json');
  }

  /** All directories that may contain xray / geo assets, in priority order. */
  binDirs() {
    return [
      ...this.extraBinDirs,
      path.join(this.dataDir || '', '..', 'bin'),
      // Only under Electron. In plain Node (the headless server) resourcesPath
      // is undefined and this entry was the RELATIVE `bin` — which existsSync()
      // found from the repo root and spawn() then resolved against the child's
      // own cwd (`bin`), so every latency test died with ENOENT.
      ...(process.resourcesPath ? [path.join(process.resourcesPath, 'bin')] : []),
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
  forgetVersions() { this._versions = {}; this._validated.clear(); }

  /**
   * The config in the form THIS core's version takes (coreCompat.js: mKCP's
   * header and seed, hysteria's port hopping moved between 2026 releases).
   * Only a config holding such a transport costs the `version` call.
   */
  async forCore(config, engineId) {
    if (!needsCoreVersion(config)) return config;
    const { id } = this.resolveEngine(engineId, { quiet: true });
    if (engineFormat(id) !== 'xray') return config;
    return adaptForCore(config, await this.version(id));
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
  /**
   * What a validation is a fact about: this core file (path + mtime, so a core
   * re-downloaded in place is a new fact), the geo files it loads (a config
   * with geosite rules is refused without them and accepted once they arrive —
   * their mtimes, `0` when absent), and the config bytes.
   */
  validationKey(id, bin, config) {
    const mt = (p) => { try { return String(fs.statSync(p).mtimeMs); } catch { return '0'; } };
    const ad = this.assetDir();
    const geo = ad ? `${mt(path.join(ad, 'geoip.dat'))}/${mt(path.join(ad, 'geosite.dat'))}` : '0/0';
    const digest = crypto.createHash('sha256').update(JSON.stringify(config)).digest('hex');
    return `${id}|${bin}|${mt(bin)}|${geo}|${digest}`;
  }

  validate(config, engineId) {
    if (!needsCoreVersion(config)) return this._validate(config, engineId);
    return this.forCore(config, engineId).then(c => this._validate(c, engineId));
  }

  _validate(config, engineId) {
    return new Promise((resolve) => {
      const { id, bin } = this.resolveEngine(engineId);
      if (!bin) return resolve({ ok: false, error: 'core binary not found' });
      // A config the core already accepted, on this core file with these geo
      // files, is not run through -test again: a reconnect after a network
      // change rebuilds the identical config, and -test costs 1-6 s of the
      // connect each time. Only a real pass is remembered — never a rejection,
      // never the safety timeout, never an old core that does not know -test.
      const key = this.validationKey(id, bin, config);
      if (this._validated.has(key)) return resolve({ ok: true, cached: true });
      let cfgPath;
      try { cfgPath = path.join(this.dataDir, `test-cfg-${Date.now()}.json`); fs.writeFileSync(cfgPath, JSON.stringify(config, null, 2), 'utf8'); }
      catch (e) { return resolve({ ok: false, error: e.message }); }

      let out = '';
      const proc = spawn(bin, engineTestArgs(id, cfgPath), { cwd: path.dirname(bin), windowsHide: true, env: this.spawnEnv() });
      const grab = (d) => { out += d.toString('utf8'); };
      proc.stdout.on('data', grab);
      proc.stderr.on('data', grab);
      let settled = false;
      const finish = (res) => {
        if (settled) return;
        settled = true;
        try { fs.unlinkSync(cfgPath); } catch {}
        if (res.ok && !res.unverified) {
          this._validated.set(key, true);
          if (this._validated.size > 64) this._validated.delete(this._validated.keys().next().value);
        }
        resolve(res);
      };
      proc.on('error', (err) => finish({ ok: false, error: err.message }));
      proc.on('exit', (code, signal) => {
        if (code === 0) return finish({ ok: true });
        // Killed — the kernel's OOM killer on a 512 MB router, mostly — or
        // ended by Go's runtime out of memory: no verdict on the config at all.
        // Its banner ("… Reading config: …") is all it printed, and read as the
        // reason it made a refusal of a check that never finished (v1.16.1
        // re-review). `killed` says so to the caller, whatever the words.
        const oom = signal ? null : out.split(/\r?\n/).map(l => l.trim()).find(l => GO_OUT_OF_MEMORY.test(l));
        if (signal || oom) {
          const what = signal ? `was killed (${signal})` : `ran out of memory (${oom})`;
          return finish({ ok: false, killed: true, error: `${path.basename(bin)} -test ${what} — the config was not checked` });
        }
        // Older xray builds may not know the -test flag; don't false-reject.
        if (/flag provided but not defined|not defined:.*test|unknown (flag|command)/i.test(out)) {
          this.onLog(`${path.basename(bin)} does not know -test — the config was not verified before it starts`, 'warn');
          return finish({ ok: true, unverified: true });
        }
        finish({ ok: false, error: extractXrayError(out) || `xray -test exited with code ${code}` });
      });
      // safety timeout — don't hang the UI if -test never returns. Said out
      // loud: a config that is refused after this would otherwise look like a
      // connection that came up and carries nothing.
      const limit = this.testTimeoutMs;
      setTimeout(() => {
        if (settled) return;
        try { proc.kill(); } catch {}
        this.onLog(`${path.basename(bin)} did not finish its config check within ${limit / 1000} s — the config was not verified; starting it anyway`, 'warn');
        finish({ ok: true, unverified: true });
      }, limit);
    });
  }

  /**
   * Validate on the requested engine. If the OFFICIAL core rejects the config
   * only because it is plaintext VLESS/Trojan to a public address and the
   * patterniha fork is installed, validate on the fork instead; a config
   * carrying the fork's `finalmask` goes to the fork first (see below) —
   * those are the things the fork exists for. Returns { ok, engine, error?,
   * fellBack?, plaintextRejected?, pattnNeeded?, finalmaskIgnored?,
   * echUnsupported?, coreVersion? } so the caller knows which core to start and
   * can tell the user to install the fork when it is missing (`pattnNeeded`: a
   * finalmask the official core refuses — or, `finalmaskIgnored`, one it is too
   * old to know and would drop) or to update the official core
   * (`echUnsupported`: ECH on a core older than ECH_SINCE, no fork to run it).
   */
  async validateWithFallback(config, engineId) {
    const first = this.resolveEngine(engineId);
    // A config carrying the fork's `finalmask` runs on the fork when it is
    // there, and the official core is not asked: one older than 26.3.27
    // PASSES it (an unknown key) and runs the server unmasked; a newer one
    // refuses the fork's values — a failing -test, paid on every connect.
    if (first.id === 'xray' && usesFinalmask(config)) {
      if (this.resolveBin('xray-pattn')) {
        const onFork = await this.validate(config, 'xray-pattn');
        if (!onFork.ok) return { ok: false, engine: 'xray-pattn', error: onFork.error, plaintextRejected: false, ...killedOf(onFork) };
        this.onLog(`This config carries finalmask (the patterniha fork's transport mask) — running it on ${engineLabel('xray-pattn')}`, 'info');
        return { ok: true, engine: 'xray-pattn', fellBack: true };
      }
      const r = await this.validate(config, 'xray');
      if (!r.ok) {
        if (r.killed) return { ok: false, engine: 'xray', error: r.error, plaintextRejected: false, killed: true };
        return { ok: false, engine: 'xray', error: r.error, plaintextRejected: PLAINTEXT_REJECT.test(r.error || ''), ...(FINALMASK_REJECT.test(r.error || '') ? { pattnNeeded: true } : {}) };
      }
      const v = await this.version('xray');
      if (versionBelow(v, FINALMASK_SINCE)) {
        return {
          ok: false, engine: 'xray', pattnNeeded: true, finalmaskIgnored: true, coreVersion: v,
          error: `xray ${v} does not know finalmask (${FINALMASK_SINCE} and newer do) — it would run this server without its mask`
        };
      }
      return { ok: true, engine: 'xray' };
    }
    // ECH on an official core too old to know it: -test would say
    // "Configuration OK." and the core would connect without ECH. The fork
    // (built from upstream's main) runs it; without the fork the connect is
    // refused in plain words. A version that cannot be read takes the
    // ordinary path, as it does for finalmask.
    if (first.id === 'xray' && usesEch(config)) {
      const v = await this.version('xray');
      if (versionBelow(v, ECH_SINCE)) {
        if (this.resolveBin('xray-pattn')) {
          const onFork = await this.validate(config, 'xray-pattn');
          if (!onFork.ok) return { ok: false, engine: 'xray-pattn', error: onFork.error, plaintextRejected: false, ...killedOf(onFork) };
          this.onLog(`This config uses ECH, which xray ${v} does not know — running it on ${engineLabel('xray-pattn')}`, 'info');
          return { ok: true, engine: 'xray-pattn', fellBack: true };
        }
        return { ok: false, engine: 'xray', echUnsupported: true, coreVersion: v, plaintextRejected: false,
          error: `xray ${v} does not know ECH (${ECH_SINCE} and newer do) — it would connect without it` };
      }
    }
    const r = await this.validate(config, first.id);
    if (r.ok) return { ok: true, engine: first.id };
    const plaintextRejected = PLAINTEXT_REJECT.test(r.error || '');
    if (first.id === 'xray' && plaintextRejected && this.resolveBin('xray-pattn')) {
      const again = await this.validate(config, 'xray-pattn');
      if (again.ok) {
        this.onLog(`Official core rejects this plaintext config — running it on ${engineLabel('xray-pattn')}`, 'warn');
        return { ok: true, engine: 'xray-pattn', fellBack: true };
      }
      return { ok: false, engine: 'xray-pattn', error: again.error, plaintextRejected: false, ...killedOf(again) };
    }
    return { ok: false, engine: first.id, error: r.error, plaintextRejected, ...killedOf(r) };
  }

  /** Start the core with the given config object, on the given engine. */
  async start(config, engineId) {
    if (this.running) await this.stop();

    const { id, bin } = this.resolveEngine(engineId);
    if (!bin) {
      this.onStatus('error', { message: 'xray binary not found. Put xray.exe in the bin/ folder.' });
      throw new Error('xray binary not found');
    }

    // (awaited only when there is something to adapt: start() spawns in the
    // same tick it was called in otherwise, which the callers' ordering relies on)
    const cfgPath = this.writeConfig(needsCoreVersion(config) ? await this.forCore(config, id) : config);
    this.onLog(`Starting ${path.basename(bin)} with ${path.basename(cfgPath)}`, 'info');

    this.proc = spawn(bin, engineRunArgs(id, cfgPath), {
      cwd: path.dirname(bin),
      windowsHide: true,
      env: this.spawnEnv()
    });
    const proc = this.proc;

    this.running = true;
    // keep the most recent lines so a crash-on-start can report the real reason
    // — and, through recentLines(), a crash after the grace (the router's wait
    // for the SOCKS port). Only this start's output: a late line from the core
    // it replaced is not mixed in.
    let recent = '';
    let earlyExit = null;
    this.recent = '';
    this._recentOf = proc;

    // A storm of one line reaches the log five times per 10 s, then as a count
    // (floodGate); `recent` — what a crash is reported with — keeps every line.
    const gate = floodGate((line, level) => this.onLog(line, level));
    const handleData = (buf, level) => {
      const text = buf.toString('utf8');
      recent = (recent + text).slice(-4000);
      if (this._recentOf === proc) this.recent = recent;
      for (const line of text.split(/\r?\n/)) {
        if (line.trim()) gate.line(line.trim(), level);
      }
    };
    this.proc.stdout.on('data', (d) => handleData(d, 'log'));
    this.proc.stderr.on('data', (d) => handleData(d, 'warn'));

    this.proc.on('exit', (code, signal) => {
      gate.flush();   // what was held back is said before the exit is
      if (earlyExit) earlyExit({ code, signal });
      // stop() has a bounded wait. A late exit from the previous child must
      // never clear the replacement child or trigger its recovery callback.
      if (this.proc !== proc) return;
      this.running = false;
      this.proc = null;
      this.onLog(`xray exited (code=${code} signal=${signal || '-'})`, code === 0 ? 'info' : 'error');
      this.onStatus('stopped', { code, signal });
    });
    this.proc.on('error', (err) => {
      if (earlyExit) earlyExit({ code: null, error: err.message });
      if (this.proc !== proc) return;
      this.running = false;
      this.proc = null;
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
      const msg = crashed.error || extractXrayError(recent) || `xray exited on startup (code ${crashed.code})`;
      if (!this.proc || this.proc === proc) this.onStatus('error', { message: msg });
      throw new Error(msg);
    }

    if (this.running && this.proc === proc) this.onStatus('running', { pid: proc.pid });
    return this.running && this.proc === proc;
  }

  /** The last `n` non-empty lines the core started last printed (kept after it exited). */
  recentLines(n = 5) {
    return String(this.recent || '').split(/\r?\n/).map(l => l.trim()).filter(Boolean).slice(-n);
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
    // numbered as well: the mux probes start up to three at once, and two in
    // the same millisecond shared one file — and one's cleanup deleted both's
    const cfgPath = path.join(this.dataDir, `test-${Date.now()}-${++this._testSeq}.json`);
    fs.writeFileSync(cfgPath, JSON.stringify(needsCoreVersion(testConfig) ? await this.forCore(testConfig, id) : testConfig, null, 2), 'utf8');

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

/** A validation's `killed` (validate: its -test never gave a verdict), carried into validateWithFallback's answer. */
function killedOf(r) { return r && r.killed ? { killed: true } : {}; }

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

/**
 * n distinct free loopback ports, held open together until all are known —
 * asking getFreePort() n times can hand the same port back twice.
 */
function getFreePorts(n) {
  return new Promise((resolve, reject) => {
    const servers = [], ports = [];
    const closeAll = () => servers.forEach((s) => { try { s.close(); } catch { /* closing */ } });
    const next = () => {
      if (ports.length >= n) { closeAll(); return resolve(ports); }
      const srv = net.createServer();
      srv.once('error', (e) => { closeAll(); reject(e); });
      srv.listen(0, '127.0.0.1', () => { servers.push(srv); ports.push(srv.address().port); next(); });
    };
    next();
  });
}

module.exports = { XrayManager, getFreePort, getFreePorts, PLAINTEXT_REJECT, FINALMASK_SINCE, ECH_SINCE, usesEch, versionBelow, floodGate, floodKey };
