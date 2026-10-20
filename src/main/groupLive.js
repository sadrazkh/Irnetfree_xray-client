'use strict';
/**
 * A group member set aside — or put back — in the RUNNING core, without a
 * restart (v1.28.3). A reload drops every connection, the corporate WireGuard
 * riding the base included; Xray's HandlerService removes one outbound and
 * adds one while everything else keeps flowing. Reached through the core's own
 * CLI (`xray api rmo|ado --server=127.0.0.1:<port>`) on the loopback port the
 * config's `api` listens on (configBuilder: only when the plan runs a group).
 *
 * Proven on both suggested cores at the time (Xray 26.3.27, PattN 26.9.1; the
 * session's api-probe.js): `rmo` of a dead member stops its probes — the leak
 * of a socket per failed TLS handshake stops growing (the sockets already
 * leaked stay until the core's next start); fetches through the others go on;
 * streams through other members, and through the removed one, complete;
 * `ado` of the same outbound (as the config built it, its tag unchanged)
 * brings it back to the balancer and the health check.
 *
 * The rules that came with it:
 *  - never `rmo` the balancer's fallbackTag (`T~gm0` when the group has no
 *    fallback of its own): with every other member dead its traffic would go
 *    nowhere — that one is left to the reload;
 *  - `ado` only what the app's own test found answering (groupEvict: two
 *    answers) — a re-added member counts as alive until its first probe;
 *  - `ado` of a tag already there fails ("existing tag found"): it is there;
 *  - anything that cannot be done live (a member the running config does not
 *    have, a fallback member, a failed call) → false, and the caller reloads,
 *    which makes the running config what the evictor holds.
 *
 *   memberTags(map)             groupTags → Map(key → { tag, isFallback })
 *   applyLive({ changes, map, outbounds, bin, port, run, write })
 *                               → { ok, done: [{ key, tag, how }] }
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFile } = require('child_process');
const { groupMemberKey } = require('./configBuilder');

/** Every running group's members by key: their tag (`T~gm<i>`), and whether it is the balancer's fallback (no fallback of the group's own: member 0). */
function memberTags(map) {
  const out = new Map();
  for (const g of Array.isArray(map) ? map : []) {
    if (!g || !Array.isArray(g.members)) continue;
    g.members.forEach((m, i) => {
      if (m) out.set(groupMemberKey(g.groupId, m), { tag: `${g.tag}~gm${i}`, isFallback: !g.fallback && i === 0 });
    });
  }
  return out;
}

/** The core's CLI, bounded in time: { ok, out }. */
function runCli(bin, args) {
  return new Promise((resolve) => {
    execFile(bin, args, { timeout: 8000, windowsHide: true }, (err, stdout, stderr) =>
      resolve({ ok: !err, out: String(stdout || '') + String(stderr || '') }));
  });
}

/**
 * `changes`: { out: [keys], back: [keys] } (GroupEvictor.takeChanges). Every
 * one or none: the first that cannot be done live stops it (false) — the
 * caller then reloads, which writes them all.
 */
async function applyLive({ changes, map, outbounds, bin, port, run = runCli, write = null }) {
  const done = [];
  const ch = changes || {};
  if (!bin || !port || !Array.isArray(map) || !Array.isArray(outbounds)) return { ok: false, done };
  const server = `--server=127.0.0.1:${port}`;
  const tags = memberTags(map);
  for (const key of ch.out || []) {
    const m = tags.get(key);
    if (!m || m.isFallback) return { ok: false, done };
    const r = await run(bin, ['api', 'rmo', server, m.tag]);
    if (!r.ok) return { ok: false, done };
    done.push({ key, tag: m.tag, how: 'out' });
  }
  for (const key of ch.back || []) {
    const m = tags.get(key);
    const ob = m && outbounds.find((o) => o && o.tag === m.tag);
    if (!ob) return { ok: false, done };
    const file = path.join(os.tmpdir(), `irnf-ado-${process.pid}-${Date.now()}.json`);
    try {
      (write || ((f, s) => fs.writeFileSync(f, s)))(file, JSON.stringify({ outbounds: [ob] }));
      const r = await run(bin, ['api', 'ado', server, file]);
      // already there is where it should be
      if (!r.ok && !/existing tag/i.test(r.out)) return { ok: false, done };
    } finally {
      if (!write) { try { fs.unlinkSync(file); } catch { /* gone */ } }
    }
    done.push({ key, tag: m.tag, how: 'back' });
  }
  return { ok: true, done };
}

module.exports = { memberTags, applyLive, runCli };
