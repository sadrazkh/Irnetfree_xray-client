'use strict';
/**
 * Keep the geo files — and, if the user asks, the installed cores — fresh
 * without anyone remembering to. Once a week, never while a tunnel is up (a
 * core is never swapped under a running connection: the attempt is deferred
 * to the next tick), and a failure is a log line, not a stuck timer.
 *
 * The default is the geo files only. They are data — a fresh geoip.dat cannot
 * make a config stop working — while a new core release can change behaviour
 * under a config that works today, so cores update automatically only when
 * the user chooses `all`.
 *
 * Every dependency is injected, so the schedule and the choices are tested
 * without a clock, a network or a binary.
 */

const WEEK_MS = 7 * 24 * 3600 * 1000;
const CORES = ['xray', 'xray-pattn', 'sing-box'];

/** The first dotted version in a string ("Xray 26.9.1 (…)", "sing-box version 1.13.14"), or ''. */
function versionNumber(s) {
  const m = /(\d+)\.(\d+)\.(\d+)/.exec(String(s || ''));
  return m ? `${m[1]}.${m[2]}.${m[3]}` : '';
}

/**
 * Numeric dotted compare: 1 if a > b, -1 if a < b, 0 if equal. A leading v is
 * ignored. A pre-release part (`1.13.0-beta.3`, sing-box's tags) ranks the way
 * semver says: below its own release, identifiers dot by dot — numbers as
 * numbers and below words, words in ASCII order (alpha < beta < rc). Versions
 * without one compare exactly as they always did.
 */
function cmpVersion(a, b) {
  const split = (v) => {
    const s = String(v || '').trim().replace(/^v/i, '');
    const dash = s.indexOf('-');
    return dash < 0 ? [s, ''] : [s.slice(0, dash), s.slice(dash + 1).toLowerCase()];
  };
  const [ca, prea] = split(a);
  const [cb, preb] = split(b);
  const pa = ca.split('.').map(n => parseInt(n, 10) || 0);
  const pb = cb.split('.').map(n => parseInt(n, 10) || 0);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const x = pa[i] || 0, y = pb[i] || 0;
    if (x > y) return 1;
    if (x < y) return -1;
  }
  if (prea === preb) return 0;
  if (!prea) return 1;
  if (!preb) return -1;
  const ia = prea.split('.'), ib = preb.split('.');
  for (let i = 0; i < Math.max(ia.length, ib.length); i++) {
    if (i >= ia.length) return -1;
    if (i >= ib.length) return 1;
    const x = ia[i], y = ib[i];
    if (x === y) continue;
    const nx = /^\d+$/.test(x), ny = /^\d+$/.test(y);
    if (nx && ny) return Number(x) > Number(y) ? 1 : -1;
    if (nx !== ny) return nx ? -1 : 1;
    return x > y ? 1 : -1;
  }
  return 0;
}

class AssetUpdater {
  /**
   * @param {object} o
   *   getSettings()        → settings (reads `autoUpdateAssets`: 'off' | 'geo' | 'all')
   *   getCheckedAt()       → ms epoch of the last completed run, or 0
   *   setCheckedAt(ms)
   *   download(component)  → Promise (the Downloader)
   *   installed(id)        → boolean
   *   currentVersion(id)   → Promise<string> (any string; the version is extracted)
   *   latestVersion(id)    → Promise<string>
   *   busy()               → boolean: a tunnel is up, do nothing now
   *   onLog(line, level)
   *   now()                → ms epoch (injectable)
   */
  constructor(o) {
    this.o = o;
    this.now = o.now || (() => Date.now());
    this.timer = null;
    this.firstTimer = null;
    /**
     * Cores whose last download put back the version they had: { installed,
     * target } by id. The release the target names could not be fetched (a
     * 404, or the API's 60-an-hour limit) and the downloader installed the
     * latest stable again (downloader.defaultRelease). Not downloaded again
     * while the installed version and the target are the same — a restart, or
     * a newer target, tries again.
     */
    this.unmoved = {};
  }

  mode() {
    const m = this.o.getSettings().autoUpdateAssets;
    return m === 'geo' || m === 'all' ? m : 'off';
  }

  due(nowMs) {
    if (this.mode() === 'off') return false;
    return nowMs - (Number(this.o.getCheckedAt()) || 0) >= WEEK_MS;
  }

  async tick() {
    const nowMs = this.now();
    if (!this.due(nowMs)) return { ran: false };
    if (this.o.busy()) return { ran: false, deferred: true };
    const done = [];
    try { await this.o.download('geo'); done.push('geo'); }
    catch (e) { this.o.onLog('Geo update failed: ' + e.message, 'warn'); }
    if (this.mode() === 'all') {
      for (const id of CORES) {
        if (!this.o.installed(id)) continue;
        try {
          const cur = versionNumber(await this.o.currentVersion(id));
          const latest = versionNumber(await this.o.latestVersion(id));
          // An unreadable version on either side is not a reason to download.
          if (!(cur && latest && cmpVersion(latest, cur) > 0)) continue;
          const miss = this.unmoved[id];
          if (miss && miss.installed === cur && miss.target === latest) continue;   // the same miss as last time
          await this.o.download(id);
          // Updated is what the core says now — not that a download ran.
          const after = versionNumber(await this.o.currentVersion(id));
          if (after && after !== cur) { done.push(id); delete this.unmoved[id]; continue; }
          if (after) {
            this.unmoved[id] = { installed: cur, target: latest };
            this.o.onLog(`${id}: the update put ${cur} back (${latest} could not be fetched) — not downloaded again while ${latest} is the newest`, 'warn');
          } else {
            this.o.onLog(`${id}: downloaded, but its version cannot be read — not counted as updated`, 'warn');
          }
        } catch (e) { this.o.onLog(`Update check failed for ${id}: ` + e.message, 'warn'); }
      }
    }
    this.o.setCheckedAt(nowMs);
    if (done.length) this.o.onLog('Updated automatically: ' + done.join(', '), 'info');
    return { ran: true, done };
  }

  /** Every `everyMs`, plus once shortly after launch. Timers never keep the process alive. */
  start(everyMs = 6 * 3600 * 1000, firstMs = 30000) {
    this.stop();
    const run = () => this.tick().catch((e) => this.o.onLog('Asset update failed: ' + e.message, 'warn'));
    this.timer = setInterval(run, everyMs);
    if (this.timer.unref) this.timer.unref();
    this.firstTimer = setTimeout(run, firstMs);
    if (this.firstTimer.unref) this.firstTimer.unref();
  }

  stop() {
    if (this.timer) { clearInterval(this.timer); this.timer = null; }
    if (this.firstTimer) { clearTimeout(this.firstTimer); this.firstTimer = null; }
  }
}

module.exports = { AssetUpdater, cmpVersion, versionNumber, WEEK_MS, CORES };
