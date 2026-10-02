'use strict';
/**
 * The relay's data — routers (name, token hash, last seen) and sessions — in
 * one JSON file on the volume, plus the cookie-signing secret in a file of
 * its own.
 *
 * Written atomically (a temp file, fsync, rename) and never locked: Harbora's
 * start-first cutover runs the old and the new container on the same volume
 * for a while, and an exclusive lock held by one would keep the other from
 * starting. Every read compares the file's mtime and size with the copy in
 * memory, so a session the other container created is seen here on the next
 * request; writes start from what was last read. The secret is created with
 * O_EXCL, so two first starts at once still end up sharing one.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const fresh = () => ({ routers: {}, sessions: {} });

function openStore(dir) {
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, 'relay.json');
  // a tmp name of its own per write: in each container the relay is PID 1, so a per-process name would be the
  // SAME file in both during a cutover — one truncating the other's half-written bytes (review I3)
  const tmpName = () => file + '.' + process.pid + '.' + crypto.randomBytes(4).toString('hex') + '.tmp';
  let data = null;
  let stamp = null;
  const stampNow = () => {
    try { const s = fs.statSync(file); return s.mtimeMs + ':' + s.size; } catch { return 'none'; }
  };

  function get() {
    const s = stampNow();
    if (data && s === stamp) return data;
    let next = fresh();
    try {
      const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
      if (raw && typeof raw === 'object' && !Array.isArray(raw)) next = Object.assign(fresh(), raw);
    } catch {
      if (data) next = data;        // unreadable for a moment (the other container mid-rename): keep what we have
    }
    data = next;
    stamp = s;
    return data;
  }

  function save(next) {
    const json = JSON.stringify(next, null, 2);
    fs.mkdirSync(dir, { recursive: true });
    const tmp = tmpName();
    try {
      const fd = fs.openSync(tmp, 'w', 0o600);
      try { fs.writeFileSync(fd, json); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
      fs.renameSync(tmp, file);
    } catch (e) {
      try { fs.unlinkSync(tmp); } catch { /* never made, or gone */ }
      throw e;
    }
    data = next;
    stamp = stampNow();
  }

  /** Read the latest, let `fn` change it in place, write it back. Returns what `fn` returned. */
  function update(fn) {
    const next = get();
    const out = fn(next);
    save(next);
    return out;
  }

  return { get, update, file, dir };
}

/** 32 bytes, made once per data dir; two containers starting together share the first one written. */
function loadSecret(dir) {
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, 'secret.key');
  const read = () => {
    const s = Buffer.from(fs.readFileSync(file, 'utf8').trim(), 'hex');
    if (s.length < 32) throw new Error('secret.key is too short');
    return s;
  };
  try { return read(); } catch { /* made below */ }
  const s = crypto.randomBytes(32);
  try { fs.writeFileSync(file, s.toString('hex') + '\n', { flag: 'wx', mode: 0o600 }); return s; }
  catch (e) { if (e && e.code === 'EEXIST') return read(); throw e; }
}

module.exports = { openStore, loadSecret };
