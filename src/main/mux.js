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
 * for 3, unknown never — so an edited server, or a refreshed subscription with
 * new parameters, is tested again.
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
const UNSUPPORTED_TTL_MS = 3 * DAY_MS;
/** A probe's whole budget, both of its cores — and how many run at once. */
const PROBE_MS = 8000;
const PROBE_PARALLEL = 3;
/** The muxed core's share of the budget; a definitive no there leaves the control the rest. */
const MUX_SHARE = 5 / 8;
/** Remembered verdicts kept in the store (`muxProbes`); the oldest go first. */
const CACHE_MAX = 500;
/**
 * A drop forgets only a verdict at least this old. A core that keeps crashing
 * for a reason that has nothing to do with mux rewrote store.json — on a
 * router, its flash — twice per crash: the forget, then the probe learning the
 * same answer again. A server that really stopped taking mux is still caught,
 * on the first drop after these 10 minutes.
 */
const FORGET_MIN_AGE_MS = 10 * 60 * 1000;
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
 * 'unsupported' for 3, else null — as is anything from the future (a clock
 * set back, a router before its NTP) or anything that is not a verdict.
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

/**
 * What a connect has to do about mux, before any probe:
 *   off  → nothing;
 *   on   → every eligible server, no probe;
 *   auto → the ids with a fresh ok, and the eligible servers with no fresh
 *          verdict in `toProbe`.
 * `cache`: the store's muxProbes ({ fingerprint: { verdict, at } }).
 */
function planMux({ mode, servers, cache, now } = {}) {
  const m = muxMode(mode);
  const muxIds = [];
  const toProbe = [];
  if (m === 'off') return { muxIds, toProbe };
  for (const s of eligibleOnce(servers)) {
    if (m === 'on') { muxIds.push(s.id); continue; }
    const v = freshVerdict(own(cache, muxFingerprint(s)), now);
    if (v === 'ok') muxIds.push(s.id);
    else if (v == null) toProbe.push(s);
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
 *   2. it runs out of time instead: 'unknown' — a slow line says nothing about
 *      the server (see the top of this file), so no control is asked;
 *   3. it gets a definitive no — closed, reset, refused, an error status, or
 *      the core did not start — then one request through a core without mux:
 *      it answers: 'unsupported'; it does not: 'unknown'.
 * A refused port on a core that is still running is a core still starting,
 * not an answer: asked again while there is time. Every core it starts is
 * cleaned up, one that only comes up after the deadline included; nothing it
 * is handed can make it throw.
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
    if (muxed !== 'failed') return 'unknown';   // a timeout proves nothing, whatever a control would say
    return (await through(false, 1, t0 + budget)) === 'ok' ? 'unsupported' : 'unknown';
  })().catch(() => 'unknown');
  let timer = null;
  const expired = new Promise((resolve) => { timer = setTimeout(() => resolve('unknown'), budget); });
  try {
    return await Promise.race([run, expired]);
  } finally {
    over = true;
    clearTimeout(timer);
    for (const core of [...live]) clean(core);
  }
}

const VERDICTS = new Set(['ok', 'unsupported']);
const nameOf = (s) => s.name || s.address || s.id;

/**
 * One connect's mux decision: planMux, then a probe (`probe(server)` →
 * verdict) for each server it asks about — each fingerprint once, at most
 * PROBE_PARALLEL at once — and one log line per server: on, off, or "did not
 * answer either way". Returns the ids to mux and the verdicts `learnt` from
 * the probes ([{ fp, verdict }] — ok / unsupported; an unknown is never
 * remembered). `on` and `off` probe nothing and say nothing.
 */
async function decideMux({ mode, servers, cache, now = Date.now(), probe, log = () => {} } = {}) {
  const m = muxMode(mode);
  const plan = planMux({ mode: m, servers, cache, now });
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
      try { v = await probe(job.server); } catch { v = 'unknown'; }
      asked.set(job.fp, VERDICTS.has(v) ? v : 'unknown');
    }
  };
  await Promise.all(Array.from({ length: Math.min(PROBE_PARALLEL, queue.length) }, worker));

  const muxIds = [];
  const learnt = [];
  for (const s of eligibleOnce(servers)) {
    const fp = muxFingerprint(s);
    const tested = asked.has(fp);
    const v = tested ? asked.get(fp) : freshVerdict(own(cache, fp), now);
    if (tested && VERDICTS.has(v) && !learnt.some((l) => l.fp === fp)) learnt.push({ fp, verdict: v });
    if (v === 'ok') {
      muxIds.push(s.id);
      log(`Mux on for ${nameOf(s)} (tested: works)`, 'info');
    } else if (v === 'unsupported') {
      log(`Mux off for ${nameOf(s)} (this server does not accept it)`, 'info');
    } else {
      log(`Mux: ${nameOf(s)} did not answer either way — connecting without it`, 'warn');
    }
  }
  return { muxIds, learnt };
}

/**
 * The store's muxProbes with these verdicts remembered at `now` — a new
 * object, at most CACHE_MAX entries, the oldest dropped. A value that is not
 * a map (a store from before, a hand edit) starts over.
 */
function rememberVerdicts(cache, learnt, now) {
  const next = Object.assign({}, isObj(cache) ? cache : {});
  for (const l of Array.isArray(learnt) ? learnt : []) {
    if (!l || !l.fp || !VERDICTS.has(l.verdict)) continue;
    delete next[l.fp];   // re-inserted: the newest last
    next[l.fp] = { verdict: l.verdict, at: now };
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
 * The store's muxProbes without those of these fingerprints that are at least
 * FORGET_MIN_AGE_MS old at `now` (a drop's forgetting) — the same object when
 * none qualifies, so the caller has nothing to write.
 */
function forgetVerdicts(cache, fps, now = Date.now()) {
  if (!isObj(cache)) return cache;
  const gone = (Array.isArray(fps) ? fps : []).filter((fp) => {
    const entry = own(cache, fp);
    return isObj(entry) && now - entry.at >= FORGET_MIN_AGE_MS;
  });
  if (!gone.length) return cache;
  const next = Object.assign({}, cache);
  for (const fp of gone) delete next[fp];
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
  MUX, OK_TTL_MS, UNSUPPORTED_TTL_MS, PROBE_MS, PROBE_PARALLEL, CACHE_MAX, FORGET_MIN_AGE_MS,
  muxMode, muxEligible, muxFingerprint, freshVerdict, planMux, probeMux,
  decideMux, rememberVerdicts, forgetVerdicts, muxCandidates
};
