'use strict';
/**
 * Minimal JSON store persisted to disk (no external deps).
 *
 * Durability matters here: this one file holds every server, subscription,
 * chain, pool entry and setting the user has. Two things it therefore does NOT
 * do any more:
 *
 *  - write in place. `writeFileSync` truncates the target before writing, so a
 *    crash or power loss mid-write left a half-written file that the next launch
 *    could not parse. Writes now go to a sibling `.tmp`, get fsync'd, and are
 *    swapped in with a rename — the real file is only ever the old complete
 *    version or the new complete version.
 *  - fail silently. An unreadable file used to be swallowed by an empty catch
 *    and the app started from defaults, i.e. every saved server simply gone with
 *    no message. A bad file is now kept as `.corrupt-<timestamp>`, recovery from
 *    a leftover `.tmp` is attempted, and `loadError` / `saveError` are reported
 *    so the UI can say what happened.
 */

const fs = require('fs');
const path = require('path');

/** Sleep without going async — save() is synchronous by contract. */
function sleepSync(ms) {
  try { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); } catch { /* best effort */ }
}

/**
 * Rename with a short retry. On Windows a virus scanner or the search indexer
 * can hold the destination open for a moment and the swap fails with
 * EPERM/EACCES/EBUSY; the next attempt normally succeeds.
 */
function renameWithRetry(from, to, attempts = 5) {
  for (let i = 0; ; i++) {
    try { return fs.renameSync(from, to); } catch (e) {
      const transient = e && ['EPERM', 'EACCES', 'EBUSY'].includes(e.code);
      if (!transient || i >= attempts - 1) throw e;
      sleepSync(20 * (i + 1));
    }
  }
}

function isPlainObject(v) {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

class Store {
  /**
   * @param {string} filePath
   * @param {object} defaults
   * @param {{ onError?: (kind: 'load'|'save', info: object) => void }} [opts]
   */
  constructor(filePath, defaults = {}, opts = {}) {
    this.filePath = filePath;
    this.tmpPath = filePath + '.tmp';
    this.defaults = defaults;
    this.onError = opts.onError || (() => {});
    this.data = Object.assign({}, defaults);
    /** Set when the saved file could not be read: { reason, backup, recovered }. */
    this.loadError = null;
    /** Set when the last save failed: the error message. */
    this.saveError = null;
    this.load();
  }

  /** Read+parse a JSON file. Never throws. */
  readFile(file) {
    let raw;
    try {
      raw = fs.readFileSync(file, 'utf8');
    } catch (e) {
      if (e && e.code === 'ENOENT') return { ok: false, missing: true };
      return { ok: false, error: e.message };
    }
    let value;
    try {
      value = JSON.parse(raw);
    } catch (e) {
      return { ok: false, error: 'invalid JSON (' + e.message + ')' };
    }
    // A file holding `null`, a string or an array is not a store — treating it
    // as one would silently produce an empty store.
    if (!isPlainObject(value)) return { ok: false, error: 'not a JSON object' };
    return { ok: true, value };
  }

  /** Move an unreadable file aside so the user can still recover from it. */
  quarantine() {
    const backup = `${this.filePath}.corrupt-${Date.now()}`;
    try { fs.renameSync(this.filePath, backup); return backup; } catch { return null; }
  }

  load() {
    const main = this.readFile(this.filePath);
    if (main.ok) {
      this.data = Object.assign({}, this.defaults, main.value);
      return;
    }

    // A crash between the write and the rename leaves a complete `.tmp` behind
    // while the real file is still the previous good one — which is why the real
    // file is tried FIRST and `.tmp` only as a fallback.
    const tmp = this.readFile(this.tmpPath);

    if (main.missing) {
      // Nothing saved yet (first run) — unless a very first write never got
      // renamed, in which case the .tmp is the only copy there is.
      if (tmp.ok) this.data = Object.assign({}, this.defaults, tmp.value);
      return;
    }

    const backup = this.quarantine();
    if (tmp.ok) this.data = Object.assign({}, this.defaults, tmp.value);
    this.loadError = { reason: main.error, backup, recovered: tmp.ok };
    this.onError('load', this.loadError);
  }

  get(key, fallback) {
    return key in this.data ? this.data[key] : fallback;
  }
  set(key, value) {
    this.data[key] = value;
    return this.save();
  }
  assign(obj) {
    Object.assign(this.data, obj);
    return this.save();
  }
  all() { return this.data; }

  /**
   * Persist atomically: full write to `.tmp`, fsync, then rename over the real
   * file. Returns true on success; on failure the previously saved file is left
   * untouched and `saveError` is set.
   */
  save() {
    const json = JSON.stringify(this.data, null, 2);
    try {
      fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
      const fd = fs.openSync(this.tmpPath, 'w');
      try {
        fs.writeFileSync(fd, json, 'utf8');
        fs.fsyncSync(fd);          // on disk before the swap, not just in cache
      } finally {
        fs.closeSync(fd);
      }
      renameWithRetry(this.tmpPath, this.filePath);
      this.saveError = null;
      return true;
    } catch (e) {
      this.saveError = e.message;
      this.onError('save', { reason: e.message });
      try { fs.unlinkSync(this.tmpPath); } catch { /* nothing to clean up */ }
      return false;
    }
  }
}

module.exports = { Store };
