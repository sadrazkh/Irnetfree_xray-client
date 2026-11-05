'use strict';
/**
 * A server that sniffs without Route Only reads the name in a TLS hello and dials that name instead of the address it
 * was asked for. A tunnel does not stop it: the far end of a tunnel reads what comes out of it. So a VPN client whose
 * traffic passes through such a server (a VPN router in front of it, its exit server) reaches the real site its config
 * names, not its own server. A Reality or pinned config then fails, while one whose name is its own server survives,
 * and that difference looks like "advanced routing breaks it" when the two modes happen to use different configs.
 *
 * Xray's sniffer wants the whole hello in one TLS record. Cut into several it reads nothing and the address stands,
 * while the TLS stack on the far side takes the records as usual. Interval 0 writes them in one go, so a connection
 * opens no later for it. Measured on real servers behind a real VPN router, on both cores: every Reality and pinned
 * config that was dead came back with this and nothing else changed (scripts/probe-hello-cut.js does it in CI).
 *
 * Only on evidence. An ordinary internet connection keeps the bytes it always had, and so does any config that already
 * says how it dials: its own fragment or noise, a final mask, a dial mode, ECH, a hop in front of it. Those are the
 * owner's own tools, used on purpose, one config for one job; each keeps what it has, side by side in one plan.
 */
const tls = require('tls');

const HELLO_CUT = 'tlshello,100-200,0';
// a hello over TCP; QUIC, mKCP and the like have no such thing for a sniffer to read here
const TCP_TRANSPORTS = new Set(['tcp', 'raw', 'ws', 'grpc', 'httpupgrade', 'xhttp', 'splithttp', 'h2', 'http']);

function takesCut(o) {
  if (!o || o._fragment || o._noise) return false;
  const ss = o.streamSettings;
  if (!ss || (ss.security !== 'tls' && ss.security !== 'reality')) return false;
  if (!TCP_TRANSPORTS.has(ss.network || 'tcp')) return false;
  if (ss.finalmask || ss.finalMask) return false;
  const so = ss.sockopt || {};
  if (so.dialerProxy || so.dialMode) return false;
  const t = ss.tlsSettings || {};
  if (t.echOutbound || t.echConfigList || t.echServerKeys) return false;
  if (Array.isArray(t.alpn) && t.alpn.length && t.alpn.every((a) => a === 'h3')) return false;
  return true;
}

/** Marks what takes the cut; applyFragments writes the dialer. Runs on a config's own copies. */
function cutHellos(outbounds) {
  for (const o of outbounds || []) if (takesCut(o)) o._fragment = HELLO_CUT;
  return outbounds;
}

// A public address asked for another's name. Its own certificate says the address stood; one that names the site
// asked for can only have come from that site, so something on the way dialled the name.
const SAMPLES = [{ ip: '1.1.1.1', name: 'www.google.com' }, { ip: '8.8.8.8', name: 'www.cloudflare.com' }];

function certNames(cert, name) {
  const want = String(name).toLowerCase();
  return String((cert && cert.subjectaltname) || '').toLowerCase().split(/,\s*/)
    .map((x) => x.replace(/^dns:/, ''))
    .some((d) => d === want || (d.startsWith('*.') && want.endsWith(d.slice(1)) && !want.slice(0, -d.length + 1).includes('.')));
}

/**
 * Does the way out read names? true: proved. false: an address answered as itself. null: nothing answered, so nothing
 * is known and the last answer stands. Asked without a tunnel of ours up: through one it would be about our own server.
 */
function pathReadsHello({ samples = SAMPLES, timeoutMs = 2000, connect = tls.connect } = {}) {
  return new Promise((resolve) => {
    if (!samples.length) { resolve(null); return; }
    const open = new Set();
    let left = samples.length, kept = false, over = false;
    const finish = (v) => {
      if (over) return;
      over = true;
      clearTimeout(timer);
      for (const s of open) { try { s.destroy(); } catch { /* gone */ } }
      resolve(v);
    };
    const timer = setTimeout(() => finish(kept ? false : null), timeoutMs);
    for (const { ip, name } of samples) {
      let answered = false;
      const settle = (v) => {
        if (answered) return;
        answered = true;
        if (v === true) { finish(true); return; }
        if (v === false) kept = true;
        if (--left === 0) finish(kept ? false : null);
      };
      let sock;
      try {
        sock = connect({ host: ip, port: 443, servername: name, rejectUnauthorized: false, ALPNProtocols: ['http/1.1'] });
      } catch { settle(null); continue; }
      open.add(sock);
      sock.once('secureConnect', () => {
        let cert = null;
        try { cert = sock.getPeerCertificate(); } catch { /* gone */ }
        settle(cert ? certNames(cert, name) : null);
        open.delete(sock);
        try { sock.destroy(); } catch { /* gone */ }
      });
      sock.once('error', () => settle(null));
      sock.once('close', () => settle(null));
    }
  });
}

module.exports = { HELLO_CUT, cutHellos, takesCut, certNames, pathReadsHello };
