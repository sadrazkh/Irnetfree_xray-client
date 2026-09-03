'use strict';
/**
 * Certificate pinning on first use — what stands in for `allowInsecure` now.
 *
 * Both cores (Xray 26.3.27, PattN 26.9.1) refuse `tlsSettings.allowInsecure:
 * true` at config load: "removed and migrated to pinnedPeerCertSha256". That
 * key is the SHA-256 of the leaf certificate's DER, as hex. Iranian share links
 * carry allowInsecure=1 constantly, so the first time such a server is dialled
 * the app reads the certificate it presents, stores the hash on the server
 * record (`certPin`, `certPinAt`), and configBuilder emits it as
 * pinnedPeerCertSha256 from then on — the core then accepts that certificate
 * and no other, which is strictly more than allowInsecure ever checked.
 */
const tls = require('tls');
const net = require('net');
const crypto = require('crypto');
const { planServers } = require('./engineChoice');

/** SHA-256 (hex, lowercase) of a certificate's DER. */
function pinOf(der) {
  return crypto.createHash('sha256').update(der).digest('hex');
}

/**
 * The core accepts the hash in any case, with or without `:` separators; the
 * record keeps one canonical form. Anything that is not 64 hex digits is ''.
 */
function normalizePin(s) {
  const hex = String(s == null ? '' : s).replace(/[\s:]/g, '').toLowerCase();
  return /^[0-9a-f]{64}$/.test(hex) ? hex : '';
}

/**
 * The pin of the leaf certificate a TLS server presents. Verification is off
 * on purpose: this is the trust-on-first-use step, and the hash learnt here is
 * what the core will insist on from now on. A server behind uTLS-only DPI may
 * refuse Node's plain handshake — then this rejects and the caller leaves
 * verification to the core.
 */
function fetchLeafPin({ host, port, servername, timeoutMs = 5000 }) {
  return new Promise((resolve, reject) => {
    let done = false;
    let sock = null;
    const finish = (err, pin) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      if (sock) sock.destroy();
      if (err) reject(err); else resolve(pin);
    };
    const timer = setTimeout(() => finish(new Error(`no TLS handshake within ${timeoutMs} ms`)), timeoutMs);
    try {
      sock = tls.connect({
        host,
        port: parseInt(port, 10),
        // SNI carries host names only (RFC 6066) — Node warns about an IP
        servername: servername && !net.isIP(servername) ? servername : undefined,
        rejectUnauthorized: false
      });
    } catch (e) { return finish(e); }
    sock.once('secureConnect', () => {
      const cert = sock.getPeerCertificate(false);
      if (!cert || !cert.raw) return finish(new Error('the server presented no certificate'));
      finish(null, pinOf(cert.raw));
    });
    sock.once('error', finish);
    sock.once('close', () => finish(new Error('connection closed before the handshake')));
  });
}

/* ----------------------------- which servers a plan dials itself ----------------------------- */

function firstHop(list) {
  return (list || []).find(s => s && s.outbound) || null;
}

/**
 * The servers the machine dials directly: a single server, a chain's first hop,
 * and for advanced / pool plans each target's server or chain first hop. Same
 * member filter and target grammar as configBuilder's registry. Only these can
 * be probed from here — a later hop is reached through the previous one.
 */
function directServers(plan) {
  if (!plan) return [];
  const out = [];
  const add = (s) => { if (s && s.outbound && !out.includes(s)) out.push(s); };
  const target = (tg) => {
    if (!tg || tg === 'direct' || tg === 'block') return;
    if (tg === 'chain') return add(firstHop(plan.chain));
    if (String(tg).indexOf('chain:') === 0) return add(firstHop((plan.chainsById || {})[String(tg).slice('chain:'.length)]));
    add((plan.serversById || {})[tg]);
  };
  switch (plan.mode) {
    case 'single': add(plan.server); break;
    case 'chain': add(firstHop(plan.chain)); break;
    case 'pool': for (const e of plan.entries || []) if (e) target(e.target); break;
    case 'advanced': for (const r of plan.rules || []) if (r) target(r.target); target(plan.def); break;
    default: break;
  }
  return out;
}

/** The record asked for "allow insecure" (allowInsecure=1 in its link) over plain TLS. REALITY verifies its own way. */
function wantsPin(server) {
  const st = server && server.outbound && server.outbound.streamSettings;
  return !!(st && st.security === 'tls' && st.tlsSettings && st.tlsSettings.allowInsecure);
}

/**
 * Who needs a pin before this plan can run: `probe` = dialled directly, asked
 * for allowInsecure, no pin yet; `behind` = the same, but only reachable
 * through another hop — those the user pins by connecting to them directly once.
 */
function pinTargets(plan) {
  const direct = directServers(plan);
  const needs = (s) => wantsPin(s) && !normalizePin(s.certPin);
  const probe = direct.filter(needs);
  const behind = [];
  for (const s of planServers(plan)) {
    if (s && !direct.includes(s) && !behind.includes(s) && needs(s)) behind.push(s);
  }
  return { probe, behind };
}

/* ----------------------------- the core’s mismatch line ----------------------------- */

/**
 * What the core logs when a pinned server presents another certificate. Seen at
 * log level info only (nothing at warning), ~6 s into the first dial once the
 * retries are spent, on both cores:
 *   [Info] [<session>] app/proxyman/outbound: ... > common/retry: [transport/internet/tls:
 *   peer cert is unrecognized (against pinnedPeerCertSha256)] > common/retry: all retry attempts failed
 * The config-load rejection of allowInsecure names the key too — this must not match it.
 */
const PIN_MISMATCH = /peer cert is unrecognized \(against pinnedPeerCertSha256\)/;

/**
 * Watches the core's log for that line and names the server it belongs to.
 * The line carries no address — only the session id the core prints on every
 * line of one connection, and the dial line before it ("dialing TCP to
 * tcp:host:port") names the server. A hit is reported once per server: the
 * core repeats the line on every retry and the pin is already gone.
 */
class PinWatch {
  constructor() { this.live = []; this.sessions = new Map(); }

  /** The servers the live plan dials directly — only the pinned ones can mismatch. */
  setLive(servers) {
    this.live = (servers || []).filter(s => s && normalizePin(s.certPin));
    this.sessions = new Map();
  }

  clear() { this.setLive([]); }

  /** The pinned server(s) a mismatch line belongs to, or null for any other line. */
  onLine(line) {
    if (!this.live.length) return null;
    const m = /\[(\d+)\]/.exec(line);
    const id = m ? m[1] : null;
    if (!PIN_MISMATCH.test(line)) {
      if (id) {
        const s = this.live.find(x => line.indexOf(`tcp:${x.address}:${x.port}`) !== -1);
        if (s) {
          this.sessions.set(id, s);
          if (this.sessions.size > 64) this.sessions.delete(this.sessions.keys().next().value);
        }
      }
      return null;
    }
    // Unknown session with several candidates: all of them — a stale pin left
    // in place costs a dead tunnel, a cleared one costs a re-probe on the
    // next connect.
    const known = id ? this.sessions.get(id) : null;
    const hit = known ? [known] : this.live.slice();
    this.live = this.live.filter(s => !hit.includes(s));
    for (const [k, s] of this.sessions) if (hit.includes(s)) this.sessions.delete(k);
    return hit;
  }
}

module.exports = { fetchLeafPin, pinOf, normalizePin, directServers, wantsPin, pinTargets, PinWatch, PIN_MISMATCH };
