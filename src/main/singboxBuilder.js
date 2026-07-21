'use strict';
/**
 * Translate one server (our internal Xray-shaped model) into a sing-box config.
 *
 * Used only for configs whose per-config engine is 'sing-box'. sing-box is run
 * as an alternate core (see engines.js) for its stronger anti-DPI TLS stack:
 * uTLS (a realistic "fake" ClientHello fingerprint), TLS fragmentation, ECH,
 * Reality. To keep the rest of the app untouched, sing-box exposes the SAME
 * local SOCKS/HTTP inbounds on the SAME ports the Xray config would — so TUN
 * (tun2socks), the system proxy, the kill switch and entry-address logic all
 * keep working. (Live traffic stats come from Xray's API and are simply absent
 * for sing-box configs.)
 *
 * Scope: single-server proxying (vless/vmess/trojan/shadowsocks/socks/http)
 * with tcp/ws/grpc transport and tls/reality. WireGuard and chains stay on Xray
 * (the caller falls back). Throws `UnsupportedEngineConfig` when it can't
 * translate, so the caller can fall back to the default core.
 */

class UnsupportedEngineConfig extends Error {}

function buildSingboxConfig(server, settings) {
  const s = Object.assign({ socksPort: 10808, httpPort: 10809, allowLan: false, logLevel: 'warning' }, settings || {});
  const listen = s.allowLan ? '0.0.0.0' : '127.0.0.1';

  const outbound = translateOutbound(server, 'proxy');

  const inbounds = [
    { type: 'socks', tag: 'socks-in', listen, listen_port: s.socksPort },
    { type: 'http', tag: 'http-in', listen, listen_port: s.httpPort }
  ];

  return {
    log: { level: singboxLogLevel(s.logLevel), timestamp: false },
    inbounds,
    outbounds: [
      outbound,
      { type: 'direct', tag: 'direct' }
    ],
    route: { final: 'proxy' }
  };
}

function singboxLogLevel(x) {
  const v = String(x || 'warning').toLowerCase();
  if (v === 'warning') return 'warn';
  if (['trace', 'debug', 'info', 'warn', 'error', 'fatal', 'panic'].includes(v)) return v;
  return 'warn';
}

/** Our Xray-shaped server model -> one sing-box outbound object. */
function translateOutbound(server, tag) {
  const ob = server.outbound || {};
  const proto = server.protocol;
  const server_addr = server.address;
  const server_port = server.port;
  const ss = ob.streamSettings || {};

  const base = { tag, server: server_addr, server_port };
  let out;

  if (proto === 'vless') {
    const u = user(ob);
    out = Object.assign({ type: 'vless', uuid: u.id || '', flow: u.flow || undefined }, base);
    // sing-box needs packet_encoding for vless UDP; xrudp is the common default
    out.packet_encoding = 'xudp';
  } else if (proto === 'vmess') {
    const u = user(ob);
    out = Object.assign({ type: 'vmess', uuid: u.id || '', security: u.security || 'auto', alter_id: u.alterId || 0 }, base);
  } else if (proto === 'trojan') {
    const srv = firstServer(ob);
    out = Object.assign({ type: 'trojan', password: srv.password || '' }, base);
  } else if (proto === 'shadowsocks') {
    const srv = firstServer(ob);
    out = Object.assign({ type: 'shadowsocks', method: srv.method || '', password: srv.password || '' }, base);
  } else if (proto === 'socks') {
    const srv = firstServer(ob);
    const cred = (srv.users && srv.users[0]) || {};
    out = Object.assign({ type: 'socks', version: '5' }, base);
    if (cred.user) { out.username = cred.user; out.password = cred.pass || ''; }
  } else if (proto === 'http') {
    const srv = firstServer(ob);
    const cred = (srv.users && srv.users[0]) || {};
    out = Object.assign({ type: 'http' }, base);
    if (cred.user) { out.username = cred.user; out.password = cred.pass || ''; }
  } else {
    throw new UnsupportedEngineConfig(`sing-box: protocol '${proto}' not supported (use Xray)`);
  }

  const tls = translateTls(ss, server_addr);
  if (tls) out.tls = tls;

  const transport = translateTransport(ss);
  if (transport) out.transport = transport;

  // NOTE: mainline sing-box has no TLS-fragment option (that lives in forks), so
  // the `_fragment` marker is ignored here — sing-box's anti-DPI edge is uTLS
  // (a realistic/"fake" ClientHello). Fragment stays an Xray-only feature.

  // strip undefined keys so the JSON is clean
  return prune(out);
}

function translateTls(ss, addr) {
  const security = (ss.security || 'none').toLowerCase();
  if (security !== 'tls' && security !== 'reality') return null;

  const t = ss.tlsSettings || ss.realitySettings || {};
  const tls = { enabled: true };
  tls.server_name = t.serverName || addr;
  if (t.allowInsecure) tls.insecure = true;
  const alpn = normalizeAlpn(t.alpn);
  if (alpn.length) tls.alpn = alpn;

  // uTLS = a realistic (mimicked) ClientHello fingerprint.
  const fp = t.fingerprint || 'chrome';
  tls.utls = { enabled: true, fingerprint: fp };

  if (security === 'reality') {
    const r = ss.realitySettings || {};
    tls.reality = { enabled: true, public_key: r.publicKey || '', short_id: r.shortId || '' };
  }
  return tls;
}

function translateTransport(ss) {
  const net = (ss.network || 'tcp').toLowerCase();
  if (net === 'ws') {
    const w = ss.wsSettings || {};
    const tr = { type: 'ws' };
    if (w.path) tr.path = w.path;
    const host = w.headers && (w.headers.Host || w.headers.host);
    if (host) tr.headers = { Host: host };
    return tr;
  }
  if (net === 'grpc') {
    const g = ss.grpcSettings || {};
    return { type: 'grpc', service_name: g.serviceName || '' };
  }
  if (net === 'http' || net === 'h2') {
    const h = ss.httpSettings || {};
    const tr = { type: 'http' };
    if (h.path) tr.path = h.path;
    if (h.host) tr.host = Array.isArray(h.host) ? h.host : [h.host];
    return tr;
  }
  // tcp / raw -> no transport block
  return null;
}

/* --------------------------------- helpers --------------------------------- */
function user(ob) {
  return (ob.settings && ob.settings.vnext && ob.settings.vnext[0] && ob.settings.vnext[0].users && ob.settings.vnext[0].users[0]) || {};
}
function firstServer(ob) {
  return (ob.settings && ob.settings.servers && ob.settings.servers[0]) || {};
}
function normalizeAlpn(v) {
  if (!v) return [];
  if (Array.isArray(v)) return v.map(x => String(x).trim()).filter(Boolean);
  return String(v).split(',').map(x => x.trim()).filter(Boolean);
}
function prune(o) {
  for (const k of Object.keys(o)) if (o[k] === undefined) delete o[k];
  return o;
}

module.exports = { buildSingboxConfig, translateOutbound, UnsupportedEngineConfig };
