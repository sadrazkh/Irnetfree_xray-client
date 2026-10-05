'use strict';
/**
 * Mux, decided per server by a test (spec 2026-10-05 §4).
 *
 * The router's field report: after two or three hours "it kept
 * disconnecting", and its log held hundreds of WebSocket dials to the ECH
 * server ending in EOF / broken pipe within the same milliseconds. A router
 * turns every LAN flow into its own TLS(+ECH)+WS handshake on a slow CPU;
 * when the line swings (0.6-3.7 s a handshake, measured) that becomes a storm
 * the core cannot get out of — and Xray leaves a failed handshake's socket
 * open until GC (XTLS/Xray-core#6813). With mux (concurrency 8) the same
 * server carried 30 connections at ~150 ms each over a handful of real ones.
 *
 * Not every server takes mux — one that reads `v1.mux.cool` as a destination
 * answers nothing through it — so `auto` asks each eligible server once,
 * before the connect that needs it: a throwaway core with mux makes two
 * requests through one mux connection; if one of them gets a definitive no
 * (closed, reset, refused, an error status — or the core did not start), a
 * control request without mux tells "does not take mux" (unsupported) from
 * "did not answer at all" (unknown). A TIMEOUT is no answer: on a slow moment
 * of the line the mux connection's first handshake alone can use up its share
 * (measured: 0.6-3.7 s each with ECH), and a control asked after it may well
 * answer — read as "refuses mux", that turned mux off for three days on the
 * owner's ECH server, exactly where it is needed (a live run on 26.3.27). So a
 * mux attempt that times out is `unknown`, whatever a control would say. The
 * verdict is remembered per server fingerprint — ok for 7 days, unsupported
 * for 1 — so an edited server, or a refreshed subscription with new
 * parameters, is tested again. An `unknown` — the control answered, only
 * the mux attempt ran out of time — never replaces an ok or unsupported
 * verdict: it keeps it and is not tried again for an hour (`retryAfter`);
 * with nothing before, it is remembered as unknown for that hour — a slow
 * line is not tested on every connect. When the control does not answer
 * either (`unreachable`: the WAN not up yet at a router's boot, the server
 * down) nothing at all is remembered, and the next connect tests again.
 *
 * Only a connect the user or the boot makes tests. A recovery's connect (a
 * rebuild after a drop or a network change) never does: it runs in the outage
 * — on a router with the LAN offline or going direct, on Windows behind the
 * kill switch's block-all rule, where no test can reach the server — and a
 * slow line there turned mux off in the very storm it was added for (final
 * review, I1). A drop therefore marks what it muxed for a re-test (`recheck`,
 * still ok): the rebuild muxes it as before, the next connect by the user or
 * the boot tests it again.
 *
 * Eligible: VLESS without `flow`, VMess and Trojan, over ws or httpupgrade.
 * gRPC, XHTTP and H2 multiplex already; Vision, REALITY-raw, mKCP, Hysteria,
 * WireGuard and Shadowsocks are never touched. Neither are a chain's hops nor
 * the sing-box engine (the callers' business), and latency tests stay without.
 *
 * Pure but for the probe, which is handed everything it runs (`deps`).
 */
const crypto = require('crypto');

/** The mux object an eligible outbound carries. UDP 443 (QUIC) keeps its own way. */
const MUX = Object.freeze({ enabled: true, concurrency: 8, xudpConcurrency: 16, xudpProxyUDP443: 'skip' });

const DAY_MS = 24 * 60 * 60 * 1000;
/** How long a verdict is trusted. */
const OK_TTL_MS = 7 * DAY_MS;
const UNSUPPORTED_TTL_MS = 1 * DAY_MS;
/** After an inconclusive test, how long the server is left alone: at most one test — and one store write — an hour. */
const RETRY_UNKNOWN_MS = 60 * 60 * 1000;
/** A probe's whole budget, both of its cores — and how many run at once (the callers may ask for fewer: the router, one). */
const PROBE_MS = 8000;
const PROBE_PARALLEL = 3;
/** The muxed core's share of the budget; a definitive no there leaves the control the rest. */
const MUX_SHARE = 5 / 8;
/** Remembered verdicts kept in the store (`muxProbes`); the oldest go first. */
const CACHE_MAX = 500;
/** What the requests ask for: what ping:real asks. */
const PROBE_TARGET = Object.freeze({ host: 'cp.cloudflare.com', port: 80, path: '/' });

const PROTOCOLS = new Set(['vless', 'vmess', 'trojan']);
// `websocket` is the core's other name for ws
const NETWORKS = new Set(['ws', 'websocket', 'httpupgrade']);

/** The setting, read: 'on' and 'off' as they are, anything else the default 'auto'. */
function muxMode(v) {
  return v === 'on' || v === 'off' ? v : 'auto';
}

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const own = (o, k) => (isObj(o) && Object.prototype.hasOwnProperty.call(o, k) ? o[k] : undefined);

/** The server an outbound dials and its credentials: vnext (vless, vmess), servers (trojan) or the flat form. */
function peerOf(o) {
  const st = (o && o.settings) || {};
  const first = (l) => (Array.isArray(l) && isObj(l[0]) ? l[0] : null);
  const peer = first(st.vnext) || first(st.servers) || st;
  const user = first(peer.users) || {};
  return { address: peer.address, port: peer.port, id: user.id || peer.id, password: peer.password, flow: user.flow || peer.flow || st.flow };
}

/** May this outbound carry mux? VLESS without flow, VMess or Trojan — over ws or httpupgrade. */
function muxEligible(outbound) {
  if (!isObj(outbound) || !PROTOCOLS.has(outbound.protocol)) return false;
  const ss = outbound.streamSettings;
  if (!isObj(ss) || !NETWORKS.has(ss.network)) return false;
  return !(outbound.protocol === 'vless' && String(peerOf(outbound).flow || '').trim());
}

/**
 * Who a server IS, for its remembered verdict: protocol, address, port,
 * id/password, network, the ws/httpupgrade path and host, security and SNI —
 * never the name (a label) or the record id (a subscription refresh hands out
 * new ones). A stable hash of those.
 */
function muxFingerprint(server) {
  const o = (server && server.outbound) || {};
  const peer = peerOf(o);
  const ss = isObj(o.streamSettings) ? o.streamSettings : {};
  const tr = (ss.network === 'httpupgrade' ? ss.httpupgradeSettings : ss.wsSettings) || {};
  const host = tr.host || (tr.headers && (tr.headers.Host || tr.headers.host)) || '';
  const tls = ss.tlsSettings || ss.realitySettings || {};
  const parts = [o.protocol, peer.address, peer.port, peer.id || peer.password, ss.network, tr.path, host, ss.security, tls.serverName]
    .map((v) => (v == null ? '' : String(v)));
  return crypto.createHash('sha256').update(JSON.stringify(parts)).digest('hex').slice(0, 32);
}

/**
 * A remembered { verdict, at } still to be trusted at `now`: 'ok' for 7 days,
 * 'unsupported' for 1, else null — as is anything from the future (a clock
 * set back, a router before its NTP) or anything that is not a verdict (an
 * inconclusive test's `unknown` included). Its age alone: a `recheck` mark or
 * a pending `retryAfter` is what judge() reads.
 */
function freshVerdict(entry, now) {
  if (!isObj(entry)) return null;
  const at = entry.at;
  if (typeof at !== 'number' || !Number.isFinite(at)) return null;
  const age = now - at;
  if (!(age >= 0)) return null;
  if (entry.verdict === 'ok') return age < OK_TTL_MS ? 'ok' : null;
  if (entry.verdict === 'unsupported') return age < UNSUPPORTED_TTL_MS ? 'unsupported' : null;
  return null;
}

/** Each eligible server once (by record id), in order. */
function eligibleOnce(servers) {
  const seen = new Set();
  const out = [];
  for (const s of Array.isArray(servers) ? servers : []) {
    if (!s || !s.id || seen.has(s.id) || !muxEligible(s.outbound)) continue;
    seen.add(s.id);
    out.push(s);
  }
  return out;
}

/** The verdict a remembered entry holds — 'ok' | 'unsupported' | 'unknown' — whatever its age; null when it holds none. */
function heldVerdict(entry) {
  const v = isObj(entry) ? entry.verdict : null;
  return v === 'ok' || v === 'unsupported' || v === 'unknown' ? v : null;
}

/**
 * One server, at one connect: what memory says (`verdict`, also what an
 * inconclusive test keeps) and whether to test it now (`probe`).
 *  - A recovery's connect never tests: a remembered ok — fresh, expired or
 *    marked for a re-test — is mux on; anything else, off.
 *  - Any other connect leaves a server alone before its `retryAfter` (the
 *    verdict it holds decides meanwhile), takes a fresh ok that is not marked
 *    and a fresh unsupported as they are, and tests the rest: no verdict, an
 *    expired one, a `recheck` mark, an inconclusive test whose hour is over.
 */
function judge(entry, now, recovery) {
  const verdict = heldVerdict(entry);
  if (recovery) return { verdict, probe: false };
  if (isObj(entry) && typeof entry.retryAfter === 'number' && now < entry.retryAfter) return { verdict, probe: false };
  const fresh = freshVerdict(entry, now);
  if (fresh === 'ok' && !entry.recheck) return { verdict: 'ok', probe: false };
  if (fresh === 'unsupported') return { verdict: 'unsupported', probe: false };
  return { verdict, probe: true };
}

/**
 * What a connect has to do about mux, before any probe:
 *   off  → nothing;
 *   on   → every eligible server, no probe;
 *   auto → the servers memory says ok (judge), and those to test in
 *          `toProbe` — never in a recovery's connect (`recovery`).
 * `cache`: the store's muxProbes ({ fingerprint: { verdict, at, recheck?, retryAfter? } }).
 */
function planMux({ mode, servers, cache, now, recovery = false } = {}) {
  const m = muxMode(mode);
  const muxIds = [];
  const toProbe = [];
  if (m === 'off') return { muxIds, toProbe };
  for (const s of eligibleOnce(servers)) {
    if (m === 'on') { muxIds.push(s.id); continue; }
    const j = judge(own(cache, muxFingerprint(s)), now, recovery);
    if (j.probe) toProbe.push(s);
    else if (j.verdict === 'ok') muxIds.push(s.id);
  }
  return { muxIds, toProbe };
}

/** A reply that ran out of time: the request's own timer, the SOCKS handshake's, the socket's (ETIMEDOUT). */
const TIMED_OUT = /timed?\s?out/i;
/** The throwaway core's own port refused the connection: a core not listening (yet, or any more). */
const PORT_REFUSED = /ECONNREFUSED/;
/** How often a core still starting is asked again. */
const RETRY_MS = 150;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
/** Has this test core's process exited — its config refused, its binary gone? */
const exited = (core) => !!(core && core.proc && (core.proc.exitCode != null || core.proc.signalCode != null));

/**
 * Does this server take mux? Within PROBE_MS (`deps.timeoutMs` in a test):
 *   1. a throwaway core whose proxy outbound carries MUX makes two requests,
 *      one after the other, through one mux connection, within its share of
 *      the budget (MUX_SHARE) — both answer: 'ok';
 *   2. otherwise one request through a core without mux, the control, in the
 *      rest of the budget — it tells a working line from nothing reachable:
 *      - it answers, and the mux attempt got a definitive no (closed, reset,
 *        refused, an error status, or the core did not start): 'unsupported';
 *      - it answers, and the mux attempt ran out of time: 'unknown' — a slow
 *        line says nothing about the server (see the top of this file);
 *      - it does not answer either: 'unreachable' — the WAN not up yet (a
 *        router's first boot connect), the server down. Nothing to learn:
 *        decideMux remembers nothing, the next connect tests again.
 * A refused port on a core that is still running is a core still starting,
 * not an answer: asked again while there is time. Every core it starts is
 * cleaned up, one that only comes up after the deadline included; nothing it
 * is handed can make it throw (anything that goes wrong is 'unreachable').
 *
 * deps = { buildTestConfig(server, port), startTest(config) → { proc, cleanup },
 *          getFreePort(), httpThroughProxy(port, opts) → { ok, error?, status? } }
 */
async function probeMux(server, deps = {}) {
  const { buildTestConfig, startTest, getFreePort, httpThroughProxy } = deps;
  const budget = deps.timeoutMs > 0 ? deps.timeoutMs : PROBE_MS;
  const t0 = Date.now();
  const live = new Set();
  let over = false;
  const clean = (core) => {
    if (!core || !live.delete(core)) return;
    try { core.cleanup(); } catch { /* a core already gone */ }
  };

  /**
   * One core, `requests` requests through it one after the other, before
   * `deadline`: 'ok' — every one answered; 'timeout' — the deadline, or the
   * whole budget, ran out first; 'failed' — a definitive no.
   */
  async function through(withMux, requests, deadline) {
    let core = null;
    try {
      if (over) return 'timeout';
      const port = await getFreePort();
      const config = buildTestConfig(server, port);
      if (withMux) {
        const proxy = ((config && config.outbounds) || []).find((o) => o && o.tag === 'proxy');
        if (!proxy) return 'failed';
        proxy.mux = Object.assign({}, MUX);
      }
      if (over) return 'timeout';
      try { core = await startTest(config); } catch { return over ? 'timeout' : 'failed'; }   // the core did not start
      if (core) live.add(core);
      if (over) return 'timeout';   // came up after the deadline: cleaned below, never used
      for (let i = 0; i < requests; i++) {
        for (;;) {
          const left = deadline - Date.now();
          if (over || left <= 0) return 'timeout';
          const r = await httpThroughProxy(port, Object.assign({}, PROBE_TARGET, { timeout: left }));
          if (over) return 'timeout';
          if (r && r.ok) break;
          const error = String((r && r.error) || '');
          if (TIMED_OUT.test(error)) return 'timeout';
          // startTest gives a core 500 ms; a router's first core after a boot
          // runs from a cold binary — not listening yet is no answer either
          if (PORT_REFUSED.test(error) && !exited(core)) {
            await sleep(Math.max(0, Math.min(RETRY_MS, deadline - Date.now())));
            continue;
          }
          return 'failed';
        }
      }
      return 'ok';
    } catch {
      return over ? 'timeout' : 'failed';
    } finally {
      clean(core);
    }
  }

  const run = (async () => {
    const muxed = await through(true, 2, t0 + Math.round(budget * MUX_SHARE));
    if (muxed === 'ok') return 'ok';
    if ((await through(false, 1, t0 + budget)) !== 'ok') return 'unreachable';   // nothing answered: nothing learnt
    // the line works: a definitive no is the server's; a timeout proves nothing
    return muxed === 'failed' ? 'unsupported' : 'unknown';
  })().catch(() => 'unreachable');
  let timer = null;
  const expired = new Promise((resolve) => { timer = setTimeout(() => resolve('unreachable'), budget); });
  try {
    return await Promise.race([run, expired]);
  } finally {
    over = true;
    clearTimeout(timer);
    for (const core of [...live]) clean(core);
  }
}

const VERDICTS = new Set(['ok', 'unsupported']);
/** What a probe can answer (probeMux); anything else — a throw, nonsense — counts as 'unreachable'. */
const PROBED = new Set(['ok', 'unsupported', 'unknown', 'unreachable']);
const nameOf = (s) => s.name || s.address || s.id;

/**
 * One connect's mux decision: planMux, then a probe (`probe(server)` →
 * verdict) for each server it asks about — each fingerprint once, at most
 * `parallel` at once (PROBE_PARALLEL; the router asks for 1) — and one log
 * line per server. A recovery's connect (`recovery`) probes nothing. An
 * inconclusive probe keeps the verdict the server had: an ok stays mux on.
 * Returns the ids to mux and what the probes `learnt` ([{ fp, verdict }] — ok,
 * unsupported or unknown; rememberVerdicts says what an unknown keeps). An
 * 'unreachable' (nothing answered, mux or not) teaches nothing and is not in
 * `learnt`: no store write, and the next connect tests again. `on` and `off`
 * probe nothing and say nothing.
 */
async function decideMux({ mode, servers, cache, now = Date.now(), probe, log = () => {}, recovery = false, parallel = PROBE_PARALLEL } = {}) {
  const m = muxMode(mode);
  const plan = planMux({ mode: m, servers, cache, now, recovery });
  if (m !== 'auto') return { muxIds: plan.muxIds, learnt: [] };

  const asked = new Map();   // fingerprint → the probe's verdict
  const queue = [];
  for (const s of plan.toProbe) {
    const fp = muxFingerprint(s);
    if (!queue.some((q) => q.fp === fp)) queue.push({ fp, server: s });
  }
  const worker = async () => {
    for (let job = queue.shift(); job; job = queue.shift()) {
      let v;
      try { v = await probe(job.server); } catch { v = 'unreachable'; }
      asked.set(job.fp, PROBED.has(v) ? v : 'unreachable');
    }
  };
  const lanes = Math.max(1, Math.floor(Number(parallel)) || PROBE_PARALLEL);
  await Promise.all(Array.from({ length: Math.min(lanes, queue.length) }, worker));

  const muxIds = [];
  const learnt = [];
  for (const s of eligibleOnce(servers)) {
    const fp = muxFingerprint(s);
    const name = nameOf(s);
    const held = judge(own(cache, fp), now, recovery).verdict;   // memory — also what an inconclusive test keeps
    const tested = asked.has(fp);
    const v = tested ? asked.get(fp) : held;
    if (tested && v !== 'unreachable' && !learnt.some((l) => l.fp === fp)) learnt.push({ fp, verdict: v });
    if (v === 'ok') {
      muxIds.push(s.id);
      log(`Mux on for ${name} (tested: works)`, 'info');
    } else if (v === 'unsupported') {
      log(`Mux off for ${name} (this server does not accept it)`, 'info');
    } else if (tested && held === 'ok') {
      muxIds.push(s.id);   // the test now did not answer: the ok from before stands
      log(`Mux on for ${name} (tested before: works — this test did not answer)`, 'info');
    } else if (tested && held === 'unsupported') {
      log(`Mux off for ${name} (this server does not accept it)`, 'info');
    } else if (v === 'unknown') {
      // the line works, mux ran out of time: said at warn when a test just
      // found it, a remembered one (its retry hour) again quietly
      log(`Mux: ${name} did not answer through mux in time — connecting without it`, tested ? 'warn' : 'info');
    } else if (v === 'unreachable') {
      log(`Mux: ${name} did not answer either way — connecting without it`, 'warn');
    } else {
      log(`Mux: ${name} not tested yet — connecting without it`, 'info');   // a recovery's connect, which never tests
    }
  }
  return { muxIds, learnt };
}

/**
 * The store's muxProbes with what the probes learnt, at `now` — a new object,
 * at most CACHE_MAX entries, the oldest dropped. An ok or unsupported is the
 * server's verdict from now on (any `recheck` mark or `retryAfter` gone). An
 * unknown never replaces an ok or unsupported — expired or marked included —
 * it keeps it and stamps `retryAfter` an hour on; with nothing before, it is
 * remembered as `{ verdict: 'unknown', retryAfter }`. Nothing else (an
 * 'unreachable', junk) is remembered; with nothing to remember the very same
 * object comes back — the caller writes nothing. A value that is not a map (a
 * store from before, a hand edit) starts over.
 */
function rememberVerdicts(cache, learnt, now) {
  const apply = (Array.isArray(learnt) ? learnt : []).filter((l) => l && l.fp && (VERDICTS.has(l.verdict) || l.verdict === 'unknown'));
  if (!apply.length) return cache;
  const next = Object.assign({}, isObj(cache) ? cache : {});
  for (const l of apply) {
    if (VERDICTS.has(l.verdict)) {
      delete next[l.fp];   // re-inserted: the newest last
      next[l.fp] = { verdict: l.verdict, at: now };
    } else if (l.verdict === 'unknown') {
      const before = own(next, l.fp);
      const kept = isObj(before) && VERDICTS.has(before.verdict);
      delete next[l.fp];
      next[l.fp] = kept
        ? Object.assign({}, before, { retryAfter: now + RETRY_UNKNOWN_MS })
        : { verdict: 'unknown', at: now, retryAfter: now + RETRY_UNKNOWN_MS };
    }
  }
  const keys = Object.keys(next);
  if (keys.length > CACHE_MAX) {
    const age = (k) => (isObj(next[k]) && Number.isFinite(next[k].at) ? next[k].at : -Infinity);
    keys.sort((a, b) => age(a) - age(b));
    for (const k of keys.slice(0, keys.length - CACHE_MAX)) delete next[k];
  }
  return next;
}

/**
 * A muxed connection dropped: the ok verdicts of these fingerprints are
 * marked for a re-test (`recheck`) — still ok, so the recovery's connect,
 * which never tests, muxes them as before; the next connect the user or the
 * boot makes tests them again. Only an ok is marked. The same object when
 * nothing changes (already marked, not an ok, not remembered), so the caller
 * has nothing to write — a core crashing over and over costs no store write
 * after the first.
 */
function markRecheck(cache, fps) {
  if (!isObj(cache)) return cache;
  const marks = [...new Set(Array.isArray(fps) ? fps : [])].filter((fp) => {
    const entry = own(cache, fp);
    return isObj(entry) && entry.verdict === 'ok' && !entry.recheck;
  });
  if (!marks.length) return cache;
  const next = Object.assign({}, cache);
  for (const fp of marks) next[fp] = Object.assign({}, cache[fp], { recheck: true });
  return next;
}

/**
 * The servers a plan dials as targets of their own: the single server; an
 * advanced plan's server targets and default; a pool's primary and entries.
 * Never a chain's hops, nor `direct` / `block` / a target that is gone.
 */
function muxCandidates(plan) {
  const out = [];
  if (!plan) return out;
  const byId = plan.serversById || {};
  const add = (s) => { if (s && s.id && s.outbound && !out.some((x) => x.id === s.id)) out.push(s); };
  const target = (tg) => {
    if (typeof tg !== 'string' || !tg || tg === 'direct' || tg === 'block' || tg === 'chain' || tg.startsWith('chain:')) return;
    add(own(byId, tg));
  };
  switch (plan.mode) {
    case 'single': add(plan.server); break;
    case 'advanced': for (const r of plan.rules || []) if (r) target(r.target); target(plan.def); break;
    case 'pool': target(plan.primary); for (const e of plan.entries || []) if (e) target(e.target); break;
    default: break;   // a chain: hops only
  }
  return out;
}

module.exports = {
  MUX, OK_TTL_MS, UNSUPPORTED_TTL_MS, RETRY_UNKNOWN_MS, PROBE_MS, PROBE_PARALLEL, CACHE_MAX,
  muxMode, muxEligible, muxFingerprint, freshVerdict, planMux, probeMux,
  decideMux, rememberVerdicts, markRecheck, muxCandidates
};
