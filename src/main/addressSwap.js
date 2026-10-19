'use strict';
/**
 * A saved server dialled at another address — a clean CDN IP, another port —
 * as a group member asks for it (v1.27.0, groups.js). Ported from IRNetFree
 * Plus's scanner (src/main/scan/substitute.js `applyTarget`), less the SNI.
 * Pure: the stored record is never touched, a deep copy comes back.
 *
 * The address goes where the protocol keeps it: `vnext[0]` (vless, vmess),
 * `servers[0]` (trojan, shadowsocks), the flat `settings.address/port`
 * (hysteria, MASQUE, and any flat shape a JSON config uses), a WireGuard
 * peer's `endpoint`. The names the server hides behind — TLS SNI, the
 * WebSocket / HTTPUpgrade / XHTTP / h2 Host, the gRPC authority — stay on the
 * original host name, and are filled from it when the link left them empty:
 * the Cloudflare-fronting trick, any edge IP works as long as the handshake
 * still names the site. REALITY's serverName is the camouflage site, not
 * ours, so it is never touched.
 *
 *   withTarget(server, { address, port }) → the copy | throws (.code: unsupported | json-chain | invalid)
 *   dialOf(server) → { addr, port }   what it dials today
 */
const { isIP } = require('net');

/** jsonImport.js's list, written out here: configBuilder needs this module, and jsonImport needs configBuilder. */
const PROXY_PROTOCOLS = new Set(['vless', 'vmess', 'trojan', 'shadowsocks', 'socks', 'http', 'wireguard', 'hysteria', 'masque']);
const SUPPORTED = ['vless', 'vmess', 'trojan', 'shadowsocks', 'hysteria2', 'masque', 'wireguard'];

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const clone = (v) => JSON.parse(JSON.stringify(v));
const present = (v) => v != null && String(v).trim() !== '';
const fail = (code, msg) => Object.assign(new Error(msg), { code });
const isName = (a) => !!a && isIP(a) === 0;

/** 1–65535, or null. */
function toPort(v) {
  const n = Number(v);
  return Number.isInteger(n) && n >= 1 && n <= 65535 ? n : null;
}

/** `host:port`, a v6 host bracketed. */
function addrPort(addr, port) {
  const a = String(addr == null ? '' : addr);
  if (port == null || port === '') return a;
  return (a.includes(':') && !a.startsWith('[') ? `[${a}]` : a) + ':' + port;
}

/** The record's protocol in its own terms ('hysteria2' for a hysteria outbound); the outbound's protocol wins. */
function protocolOf(server) {
  const ob = server && server.outbound;
  const p = isObj(ob) && typeof ob.protocol === 'string' && ob.protocol ? ob.protocol : String((server && server.protocol) || '');
  return p === 'hysteria' ? 'hysteria2' : p;
}

/** The node that carries the dial address, or null for a shape this cannot rewrite. WireGuard: wgPeer. */
function dialNode(ob, proto) {
  const st = isObj(ob && ob.settings) ? ob.settings : null;
  if (!st) return null;
  const first = (l) => (Array.isArray(l) && isObj(l[0]) ? l[0] : null);
  const flat = typeof st.address === 'string' && st.address.trim() ? st : null;
  if (proto === 'vless' || proto === 'vmess') return first(st.vnext) || flat;
  if (proto === 'trojan' || proto === 'shadowsocks') return first(st.servers) || flat;
  if (proto === 'hysteria2' || proto === 'masque') return flat;
  return null;
}

function wgPeer(ob) {
  const st = isObj(ob && ob.settings) ? ob.settings : null;
  return st && Array.isArray(st.peers) && isObj(st.peers[0]) ? st.peers[0] : null;
}

/** 'host:port' / '[v6]:port' → { host, port }. */
function splitEndpoint(ep) {
  const e = String(ep == null ? '' : ep).trim();
  const m6 = /^\[([^\]]+)\](?::(\d*))?$/.exec(e);
  if (m6) return { host: m6[1], port: m6[2] || '' };
  const i = e.lastIndexOf(':');
  if (i === -1 || e.indexOf(':') !== i) return { host: e, port: '' };
  return { host: e.slice(0, i), port: e.slice(i + 1) };
}

/** dialOf(server) → { addr, port }: the server address and port the config dials today (`port` null when none). */
function dialOf(server) {
  const proto = protocolOf(server);
  const ob = server && isObj(server.outbound) ? server.outbound : {};
  let addr = '';
  let port = null;
  if (proto === 'wireguard') {
    const ep = splitEndpoint(wgPeer(ob) && wgPeer(ob).endpoint);
    addr = ep.host;
    port = toPort(ep.port);
  } else {
    const node = dialNode(ob, proto);
    if (node) { addr = String(node.address || '').trim(); port = toPort(node.port); }
  }
  if (!addr) addr = String((server && server.address) || '').trim();
  if (port == null) port = toPort(server && server.port);
  return { addr, port };
}

/** Fill the fronting names a link may have left empty. Only existing blocks are touched; REALITY never. */
function fillHostNames(stream, name) {
  const tls = stream.tlsSettings;
  if (isObj(tls) && !tls.serverName) tls.serverName = name;
  const ws = stream.wsSettings;
  if (isObj(ws) && !ws.host) {
    if (!isObj(ws.headers)) ws.headers = {};
    if (!ws.headers.Host && !ws.headers.host) ws.headers.Host = name;
  }
  const hu = stream.httpupgradeSettings;
  if (isObj(hu) && !hu.host) hu.host = name;
  const xh = stream.xhttpSettings;
  if (isObj(xh) && !xh.host) xh.host = name;
  const h2 = stream.httpSettings;
  if (isObj(h2)) {
    if (!Array.isArray(h2.host)) h2.host = h2.host ? [String(h2.host)] : [];
    if (!h2.host.length) h2.host.push(name);
  }
  const grpc = stream.grpcSettings;
  if (isObj(grpc) && !grpc.authority) grpc.authority = name;
}

/** The tags an outbound dials through: its dialerProxy and its proxySettings.tag. */
function refsOf(o) {
  const so = isObj(o.streamSettings) && isObj(o.streamSettings.sockopt) ? o.streamSettings.sockopt : {};
  return [so.dialerProxy, isObj(o.proxySettings) ? o.proxySettings.tag : null].filter((t) => typeof t === 'string' && t);
}

/**
 * Does a JSON server's main outbound reach its server through another proxy
 * (a chain)? Through a freedom helper (a fragment or noise dialer) it still
 * dials the address itself, so the walk goes on through those.
 */
function dialsThroughProxy(server) {
  const extras = Array.isArray(server.extraOutbounds) ? server.extraOutbounds.filter(isObj) : [];
  const byTag = new Map(extras.filter((o) => typeof o.tag === 'string' && o.tag).map((o) => [o.tag, o]));
  const visited = new Set();
  const queue = [server.outbound];
  while (queue.length) {
    const o = queue.shift();
    if (visited.has(o)) continue;
    visited.add(o);
    for (const t of refsOf(o)) {
      const h = byTag.get(t);
      if (!h) continue;
      if (PROXY_PROTOCOLS.has(h.protocol)) return true;
      queue.push(h);
    }
  }
  return false;
}

/** Key order aside, the same JSON. */
function canon(v) {
  const sort = (x) => (Array.isArray(x) ? x.map(sort)
    : (isObj(x) ? Object.keys(x).sort().reduce((o, k) => { o[k] = sort(x[k]); return o; }, {}) : x));
  return JSON.stringify(sort(v));
}

/** A JSON server's config gets the same outbound, so the record stays one config. */
function mirrorIntoJson(out, original) {
  const json = out.json;
  if (!isObj(json) || !Array.isArray(json.outbounds)) return;
  const want = canon(original);
  const i = json.outbounds.findIndex((o) => {
    if (!isObj(o)) return false;
    const c = Object.assign({}, o);
    delete c.tag;
    return canon(c) === want;
  });
  if (i === -1) return;
  const tag = json.outbounds[i].tag;
  json.outbounds[i] = tag === undefined ? clone(out.outbound) : Object.assign({ tag }, clone(out.outbound));
}

/**
 * withTarget(server, { address, port }) → a deep copy of `server` that dials
 * address:port, its fronting names kept on the original host. An absent
 * field keeps the config's own. Throws an Error with `.code`: 'unsupported'
 * (a protocol or record shape this cannot rewrite), 'json-chain' (a JSON
 * server that reaches its server through another proxy), 'invalid' (a port
 * outside 1–65535). `raw` is left as it was.
 */
function withTarget(server, target = {}) {
  const { address, port } = target || {};
  const proto = protocolOf(server);
  if (!server || !isObj(server.outbound) || !SUPPORTED.includes(proto)) {
    throw fail('unsupported', 'unsupported protocol' + (proto ? ': ' + proto : ''));
  }
  if (proto === 'wireguard' ? !wgPeer(server.outbound) : !dialNode(server.outbound, proto)) {
    throw fail('unsupported', `this ${proto} config names no server to dial`);
  }
  if (server.source === 'json' && dialsThroughProxy(server)) {
    throw fail('json-chain', 'this JSON config dials its server through another proxy (a chain)');
  }
  const newAddr = present(address) ? String(address).trim().replace(/^\[(.*)\]$/, '$1') : null;
  let newPort = null;
  if (port != null && port !== '') {
    newPort = toPort(port);
    if (newPort == null) throw fail('invalid', 'invalid port: ' + port);
  }

  const origin = dialOf(server).addr;
  const out = clone(server);
  const ob = out.outbound;
  if (proto === 'wireguard') {
    const peer = wgPeer(ob);
    const ep = splitEndpoint(peer.endpoint);
    const host = newAddr != null ? newAddr : ep.host;
    const p = newPort != null ? newPort : (toPort(ep.port) || toPort(server.port));
    peer.endpoint = addrPort(host, p);
  } else {
    const node = dialNode(ob, proto);
    if (newAddr != null) node.address = newAddr;
    if (newPort != null) node.port = newPort;
  }
  if (newAddr != null) out.address = newAddr;
  if (newPort != null) out.port = newPort;

  const st = ob.streamSettings;
  if (isObj(st) && newAddr != null && isName(origin)) fillHostNames(st, origin);
  if (out.source === 'json') mirrorIntoJson(out, server.outbound);
  return out;
}

module.exports = { SUPPORTED_PROTOCOLS: SUPPORTED.slice(), dialOf, withTarget, toPort, addrPort };
