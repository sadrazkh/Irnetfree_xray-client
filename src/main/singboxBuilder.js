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
 * Scope: single-server proxying (vless/vmess/trojan/shadowsocks/socks/http,
 * hysteria2) with tcp/ws/grpc/http/httpupgrade transport and tls/reality (and
 * ECH). WireGuard, kcp/xhttp and chains stay on Xray (the caller falls back).
 * Throws `UnsupportedEngineConfig` when it can't translate, so the caller can
 * fall back to the default core.
 */

const { ssPluginOf } = require('./parser');

class UnsupportedEngineConfig extends Error {}

function buildSingboxConfig(server, settings) {
  const s = Object.assign({ socksPort: 10808, httpPort: 10809, allowLan: false, logLevel: 'warning' }, settings || {});
  const listen = s.allowLan ? '0.0.0.0' : '127.0.0.1';

  const outbound = translateOutbound(server, 'proxy');

  const inbounds = [{ type: 'socks', tag: 'socks-in', listen, listen_port: s.socksPort }];
  // a latency test asks for SOCKS alone (httpPort 0): the HTTP port is the live connection's
  if (s.httpPort) inbounds.push({ type: 'http', tag: 'http-in', listen, listen_port: s.httpPort });

  // Explicit DNS via the `direct` outbound. sing-box is a Go binary and on
  // Android can't read the system resolver, so without this the server domain
  // fails to resolve and nothing connects. Resolving through `direct` also keeps
  // the lookup off the tunnel (no chicken-and-egg with the proxy).
  // First remote resolver, in sing-box's own shape (DoH → https, IP → udp).
  const remote = Array.isArray(s.dnsRemote) ? s.dnsRemote : (Array.isArray(s.dns) ? s.dns : []);
  const first = String((remote.find(v => v && String(v).trim()) || '1.1.1.1')).trim();
  const dnsServer = singboxDnsServer(first);

  return {
    log: { level: singboxLogLevel(s.logLevel), timestamp: false },
    dns: {
      servers: [dnsServer],
      final: 'dns-direct'
    },
    inbounds,
    outbounds: [
      outbound,
      { type: 'direct', tag: 'direct' }
    ],
    // Resolve outbound server domains with dns-direct (an IP server, reached
    // without the proxy) so there's no resolve→proxy→resolve loop.
    route: { final: 'proxy', default_domain_resolver: 'dns-direct' }
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
    // A plugin's transport (parser.ssStream) goes back to being the plugin:
    // sing-box runs obfs-local and v2ray-plugin itself, and its Shadowsocks
    // takes no transport or TLS of its own.
    const plugin = ssPluginOf(ss);
    if (plugin) {
      const i = plugin.indexOf(';');
      out.plugin = i === -1 ? plugin : plugin.slice(0, i);
      if (i !== -1) out.plugin_opts = plugin.slice(i + 1);
    } else if ((ss.network && !['tcp', 'raw'].includes(String(ss.network).toLowerCase())) || (ss.security && ss.security !== 'none')) {
      throw new UnsupportedEngineConfig(`sing-box: Shadowsocks over '${ss.network}'/${ss.security || 'none'} is not supported (use Xray)`);
    }
    return prune(out);
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
  } else if (proto === 'hysteria2') {
    return translateHysteria2(server, tag);
  } else {
    throw new UnsupportedEngineConfig(`sing-box: protocol '${proto}' not supported (use Xray)`);
  }

  const tls = translateTls(ss, server_addr);
  if (tls) {
    // sing-box (1.12+) splits the ClientHello itself: the link's fragment
    // setting asks for exactly that. Its sizes and delays are Xray's knobs;
    // sing-box picks its own.
    if (ob._fragment) tls.fragment = true;
    out.tls = tls;
  }

  // Reject transports sing-box can't express so the caller falls back to Xray
  // instead of silently dialing plain TCP (which would just fail to connect).
  const net = (ss.network || 'tcp').toLowerCase();
  if (!['tcp', 'raw', 'ws', 'grpc', 'http', 'h2', 'httpupgrade'].includes(net)) {
    throw new UnsupportedEngineConfig(`sing-box: '${net}' transport not supported (use Xray)`);
  }
  // RAW's HTTP header obfuscation has no sing-box counterpart: dialled as
  // plain TCP it would only fail. Xray carries it.
  const hdr = ss.tcpSettings && ss.tcpSettings.header;
  if ((net === 'tcp' || net === 'raw') && hdr && hdr.type === 'http') {
    throw new UnsupportedEngineConfig('sing-box: the TCP HTTP header is not supported (use Xray)');
  }
  const transport = translateTransport(ss);
  if (transport) out.transport = transport;

  // strip undefined keys so the JSON is clean
  return prune(out);
}

/**
 * Hysteria2 — our record keeps it in the Xray core's shape (parser.js); this
 * is sing-box's: the password, the salamander obfuscation, port hopping as a
 * list of `from:to` ranges, the bandwidth in Mbps.
 */
function translateHysteria2(server, tag) {
  const ob = server.outbound || {};
  const ss = ob.streamSettings || {};
  const fm = ss.finalmask || {};
  const masks = Array.isArray(fm.udp) ? fm.udp : [];
  const sal = masks.find(m => m && m.type === 'salamander');
  const hop = masks.find(m => m && m.type === 'udphop');
  const qp = fm.quicParams || {};
  const out = {
    type: 'hysteria2', tag,
    server: server.address,
    server_port: server.port,
    password: (ss.hysteriaSettings && ss.hysteriaSettings.auth) || ''
  };
  const ports = hop && hop.settings ? String(hop.settings.remotePorts || '').split(',').map(p => p.trim()).filter(Boolean) : [];
  if (ports.length) {
    // sing-box takes `server_ports` instead of server_port, each a range
    out.server_ports = ports.map(p => (p.includes('-') ? p.replace('-', ':') : `${p}:${p}`));
    delete out.server_port;
    const iv = parseInt(String(hop.settings.interval || ''), 10);
    if (iv > 0) out.hop_interval = iv + 's';
  }
  if (sal && sal.settings && sal.settings.password) out.obfs = { type: 'salamander', password: sal.settings.password };
  const mbps = (v) => { const m = /^(\d+(?:\.\d+)?)\s*m/i.exec(String(v || '')); return m ? Math.round(Number(m[1])) : 0; };
  if (mbps(qp.brutalUp)) out.up_mbps = mbps(qp.brutalUp);
  if (mbps(qp.brutalDown)) out.down_mbps = mbps(qp.brutalDown);
  const tls = translateTls(ss, server.address) || { enabled: true, server_name: server.address };
  // QUIC: no uTLS fingerprint, and the ALPN is Hysteria's own unless the link named one
  delete tls.utls;
  out.tls = tls;
  return prune(out);
}

function translateTls(ss, addr) {
  const security = (ss.security || 'none').toLowerCase();
  if (security !== 'tls' && security !== 'reality') return null;

  const t = ss.tlsSettings || ss.realitySettings || {};
  const tls = { enabled: true };
  tls.server_name = t.serverName || addr;
  // sing-box can pin neither a certificate's hash (`pcs`: it pins a public
  // key) nor verify it against another name (`vcn`): a link that carries one
  // has a certificate the usual check refuses, so — as allowInsecure did —
  // the check is skipped. The Xray cores keep both checks.
  if (t.allowInsecure || (security === 'tls' && (t.pinnedPeerCertSha256 || t.verifyPeerCertByName))) tls.insecure = true;
  const alpn = normalizeAlpn(t.alpn);
  if (alpn.length) tls.alpn = alpn;

  // uTLS = a realistic (mimicked) ClientHello fingerprint.
  const fp = t.fingerprint || 'chrome';
  tls.utls = { enabled: true, fingerprint: fp };

  if (security === 'reality') {
    const r = ss.realitySettings || {};
    tls.reality = { enabled: true, public_key: r.publicKey || '', short_id: r.shortId || '' };
  }
  const ech = security === 'tls' ? singboxEch(t.echConfigList) : null;
  if (ech) tls.ech = ech;
  return tls;
}

/**
 * Encrypted Client Hello in sing-box's terms. A base64 ECHConfigList goes in
 * as the PEM block sing-box reads; the DNS form (`name+udp://1.1.1.1`) has
 * sing-box look the HTTPS record up itself — of `name` (query_server_name),
 * through its own resolver (the `dns-direct` server of this config): it has no
 * way to name a resolver per outbound.
 */
function singboxEch(list) {
  const s = String(list || '').trim();
  if (!s) return null;
  const sep = s.indexOf('://');
  if (sep === -1) {
    return { enabled: true, config: ['-----BEGIN ECH CONFIGS-----', s, '-----END ECH CONFIGS-----'] };
  }
  const plus = s.indexOf('+');
  const ech = { enabled: true };
  if (plus > 0 && plus < sep) ech.query_server_name = s.slice(0, plus);
  return ech;
}

function translateTransport(ss) {
  const net = (ss.network || 'tcp').toLowerCase();
  if (net === 'ws') {
    const w = ss.wsSettings || {};
    const tr = { type: 'ws' };
    // `/path?ed=2048` is Xray's early data: sing-box wants it spelt out
    let p = w.path || '';
    const ed = /[?&]ed=(\d+)/.exec(p);
    if (ed) {
      p = p.replace(/([?&])ed=\d+&?/, '$1').replace(/[?&]$/, '');
      tr.max_early_data = parseInt(ed[1], 10);
      tr.early_data_header_name = 'Sec-WebSocket-Protocol';
    }
    if (p) tr.path = p;
    const host = w.host || (w.headers && (w.headers.Host || w.headers.host));
    if (host) tr.headers = { Host: host };
    return tr;
  }
  if (net === 'httpupgrade') {
    const h = ss.httpupgradeSettings || {};
    const tr = { type: 'httpupgrade' };
    if (h.host) tr.host = h.host;
    if (h.path) tr.path = h.path;
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

/** One resolver entry → a sing-box 1.12+ DNS server object. */
function singboxDnsServer(entry) {
  const m = entry.match(/^https(?:\+local)?:\/\/([^/:?#]+)(?::(\d+))?(\/[^?#]*)?/i);
  if (m) {
    const srv = { type: 'https', tag: 'dns-direct', server: m[1] };
    if (m[2]) srv.server_port = parseInt(m[2], 10);
    if (m[3]) srv.path = m[3];
    return srv;
  }
  return { type: 'udp', tag: 'dns-direct', server: entry };
}

module.exports = { buildSingboxConfig, translateOutbound, UnsupportedEngineConfig };
