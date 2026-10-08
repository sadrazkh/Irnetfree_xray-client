'use strict';
/**
 * JSON configs as servers (docs/superpowers/specs/2026-10-08-json-configs-design.md).
 *
 * A panel answers this app's User-Agent with JSON: one complete Xray config,
 * an array of them, or the same text base64-encoded — and other clients get
 * sing-box JSON. parser.parseMany hands every text here first; `null` means
 * "not JSON at all" and the link reader goes on as before.
 *
 *  - Xray JSON: each config becomes a server (a balancer: one per member).
 *    Its MAIN outbound is what the app dials everywhere (`outbound`, tag
 *    removed); the outbounds it dials THROUGH — a fragment freedom, a chain's
 *    hops — are kept verbatim beside it (`extraOutbounds`, original tags) and
 *    written next to it by configBuilder (full mode). The record carries the
 *    config itself (`json`), `source: 'json'`, `jsonMode` ('full' | 'raw') and
 *    `jsonInfo`, what full mode does not use. `raw` is the minified config.
 *  - sing-box JSON: each supported outbound becomes an ORDINARY server — the
 *    share link it stands for, written out and parsed as an import parses it.
 *  - Clash YAML is refused by name.
 *
 * Pure: nothing here touches the network, the disk or the store.
 */

const crypto = require('crypto');
const { isIP } = require('net');
const { serverAddressOf } = require('./configBuilder');

// parser.js requires this module at load; it is asked for lazily, when a
// sing-box outbound is turned into the server its link parses to.
const parser = () => require('./parser');

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const BOM = new RegExp('^' + String.fromCharCode(0xfeff));   // a byte-order mark some panels put first
const clone = (v) => JSON.parse(JSON.stringify(v));
function uid() { return crypto.randomBytes(8).toString('hex'); }

/** Key order aside: two configs that say the same thing compare equal. */
function canon(v) {
  const sort = (x) => (Array.isArray(x) ? x.map(sort)
    : (isObj(x) ? Object.keys(x).sort().reduce((o, k) => { o[k] = sort(x[k]); return o; }, {}) : x));
  return JSON.stringify(sort(v));
}

/** host:port for a name or a link, an IPv6 address in brackets. */
function joinHostPort(host, port) {
  const h = String(host == null ? '' : host);
  return (isIP(h) === 6 ? `[${h}]` : h) + ':' + port;
}

/** "host:port" / "[v6]:port" → { host, port }. */
function splitHostPort(ep) {
  const e = String(ep == null ? '' : ep).trim();
  const m6 = /^\[([^\]]+)\](?::(\d+))?$/.exec(e);
  if (m6) return { host: m6[1], port: m6[2] || '' };
  const i = e.lastIndexOf(':');
  return i === -1 ? { host: e, port: '' } : { host: e.slice(0, i), port: e.slice(i + 1) };
}

/* ------------------------------ detection ------------------------------ */

/**
 * Is this text JSON (an object or an array)? `[Interface]` — a WireGuard
 * .conf — is not: an array's first item is an object, an array, a string, or
 * nothing.
 */
function looksLikeJson(text) {
  const t = String(text == null ? '' : text).replace(BOM, '').trim();
  if (t[0] === '{') return true;
  return t[0] === '[' && /^\[\s*([{["\]]|$)/.test(t);
}

/** Base64 (standard or url-safe, padded or not, wrapped in lines) → text; '' when it is none. */
function b64text(s) {
  const t = String(s).replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
  if (!t || /[^A-Za-z0-9+/=]/.test(t)) return '';
  try { return Buffer.from(t + '='.repeat((4 - (t.length % 4)) % 4), 'base64').toString('utf8'); } catch { return ''; }
}

const CLASH = 'Clash YAML is not supported — use the subscription link';
function isClashYaml(text) {
  return /^proxies\s*:/m.test(text) || /^proxy-groups\s*:/m.test(text);
}

/** A sing-box config: its outbounds say `type`, an Xray config's say `protocol`. */
function isSingbox(c) {
  const outs = [].concat(Array.isArray(c.outbounds) ? c.outbounds : [], Array.isArray(c.endpoints) ? c.endpoints : []).filter(isObj);
  return outs.some((o) => typeof o.type === 'string') && !outs.some((o) => typeof o.protocol === 'string');
}

/* ------------------------------ Xray JSON ------------------------------ */

/** The protocols a server is made of; freedom, blackhole, dns, loopback… are not. */
const PROXY_PROTOCOLS = new Set(['vless', 'vmess', 'trojan', 'shadowsocks', 'socks', 'http', 'wireguard', 'hysteria']);
const isProxy = (o) => isObj(o) && PROXY_PROTOCOLS.has(o.protocol);

/** What a routing rule can match on — a rule with none of them catches everything left over. */
const MATCHERS = ['domain', 'ip', 'port', 'sourcePort', 'source', 'sourceIP', 'localIP', 'localPort', 'protocol', 'inboundTag', 'user', 'attrs', 'process', 'vlessRoute'];
const present = (v) => v != null && v !== '' && !(Array.isArray(v) && !v.length) && !(isObj(v) && !Object.keys(v).length);
/** A port condition that is every port (the app's own catch-all is `port: 0-65535`). */
const anyPort = (v) => /^\s*[01]\s*-\s*65535\s*$/.test(String(v));
/** `network` absent, or naming both TCP and UDP. */
function coversBoth(n) {
  if (!present(n)) return true;
  const set = new Set([].concat(n).join(',').toLowerCase().split(',').map((x) => x.trim()));
  return set.has('tcp') && set.has('udp');
}
function isCatchAll(r) {
  return isObj(r) && MATCHERS.every((k) => !present(r[k]) || (k === 'port' && anyPort(r[k])));
}

const outboundsOf = (c) => (isObj(c) && Array.isArray(c.outbounds) ? c.outbounds.filter(isObj) : []);
const rulesOf = (c) => (isObj(c) && isObj(c.routing) && Array.isArray(c.routing.rules) ? c.routing.rules.filter(isObj) : []);
const balancersOf = (c) => (isObj(c) && isObj(c.routing) && Array.isArray(c.routing.balancers) ? c.routing.balancers.filter(isObj) : []);

/** The rule that catches everything left over: the last one with no matcher (one for TCP and UDP both, first). */
function catchAllRule(config) {
  const all = rulesOf(config).filter(isCatchAll);
  return all.filter((r) => coversBoth(r.network)).at(-1) || all.at(-1) || null;
}

/**
 * The outbound(s) the config sends its traffic to: the catch-all rule's
 * outbound (a balancer's: every member its selector names), else the one
 * tagged `proxy`, else the first with a proxy protocol. { list, balancer }.
 */
function mainOutbounds(config) {
  const outs = outboundsOf(config);
  const byTag = (t) => outs.find((o) => o.tag === t);
  const r = catchAllRule(config);
  if (r && r.outboundTag) {
    const o = byTag(r.outboundTag);
    if (isProxy(o)) return { list: [o], balancer: false };
  } else if (r && r.balancerTag) {
    const b = balancersOf(config).find((x) => x.tag === r.balancerTag);
    const sel = (b && Array.isArray(b.selector) ? b.selector : []).map(String).filter(Boolean);
    const members = outs.filter((o) => isProxy(o) && typeof o.tag === 'string' && sel.some((p) => o.tag.startsWith(p)));
    if (members.length) return { list: members, balancer: true };
  }
  const proxy = byTag('proxy');
  if (isProxy(proxy)) return { list: [proxy], balancer: false };
  const first = outs.find(isProxy);
  return { list: first ? [first] : [], balancer: false };
}

/** The main outbound's tag; `{ balancer: [tags] }` for a balancer; null when there is no proxy outbound at all. */
function mainOutboundTag(config) {
  const m = mainOutbounds(config);
  if (!m.list.length) return null;
  return m.balancer ? { balancer: m.list.map((o) => o.tag) } : (m.list[0].tag || '');
}

/** The tags an outbound dials through: its dialerProxy and its proxySettings.tag. */
function refsOf(o) {
  const so = isObj(o.streamSettings) && isObj(o.streamSettings.sockopt) ? o.streamSettings.sockopt : {};
  return [so.dialerProxy, isObj(o.proxySettings) ? o.proxySettings.tag : null].filter((t) => typeof t === 'string' && t);
}

/** Every outbound `main` reaches through dialerProxy / proxySettings.tag, recursively, in the order reached — copies, tags kept. */
function helpersOf(config, main) {
  const outs = outboundsOf(config);
  const seen = new Set([main]);
  const result = [];
  const queue = [main];
  while (queue.length) {
    for (const t of refsOf(queue.shift())) {
      const h = outs.find((o) => o.tag === t);
      if (!h || seen.has(h)) continue;
      seen.add(h);
      result.push(clone(h));
      queue.push(h);
    }
  }
  return result;
}

/** helpersOf for the outbound tagged `tag`. */
function helperClosure(config, tag) {
  const main = outboundsOf(config).find((o) => (o.tag || '') === String(tag == null ? '' : tag));
  return main ? helpersOf(config, main) : [];
}

/** Where an outbound dials: { address, port }. WireGuard from its peer's endpoint. */
function endpointOf(o) {
  const st = isObj(o.settings) ? o.settings : {};
  if (o.protocol === 'wireguard') {
    const peer = Array.isArray(st.peers) && isObj(st.peers[0]) ? st.peers[0] : {};
    const ep = splitHostPort(peer.endpoint);
    return { address: ep.host, port: parseInt(ep.port, 10) || 0 };
  }
  const first = (l) => (Array.isArray(l) && isObj(l[0]) ? l[0] : null);
  const at = first(st.vnext) || first(st.servers) || st;
  return { address: serverAddressOf(o) || '', port: parseInt(at.port, 10) || 0 };
}

/** One routing rule as the edit view says it: its conditions (or `*`) → its outbound (or balancer). */
function ruleInfo(r) {
  const vals = (v) => [].concat(v).map((x) => String(x)).filter(Boolean);
  const short = (v) => { const l = vals(v); return l.length > 3 ? `${l.slice(0, 3).join(', ')} +${l.length - 3}` : l.join(', '); };
  const parts = [];
  if (present(r.domain)) parts.push(short(r.domain));
  if (present(r.ip)) parts.push(short(r.ip));
  if (present(r.port) && !anyPort(r.port)) parts.push('port ' + r.port);
  if (present(r.sourcePort)) parts.push('source port ' + r.sourcePort);
  if (present(r.source) || present(r.sourceIP)) parts.push('source ' + short(present(r.source) ? r.source : r.sourceIP));
  if (present(r.localIP)) parts.push('local ' + short(r.localIP));
  if (present(r.localPort)) parts.push('local port ' + r.localPort);
  if (present(r.protocol)) parts.push(short(r.protocol));
  if (present(r.inboundTag)) parts.push('inbound ' + short(r.inboundTag));
  if (present(r.user)) parts.push('user ' + short(r.user));
  if (present(r.process)) parts.push('process ' + short(r.process));
  if (present(r.vlessRoute)) parts.push('vlessRoute ' + r.vlessRoute);
  if (present(r.attrs)) parts.push('attrs');
  if (!coversBoth(r.network)) parts.push(vals(r.network).join(','));
  return { match: parts.length ? parts.join(' + ') : '*', to: r.outboundTag ? String(r.outboundTag) : (r.balancerTag ? 'balancer:' + r.balancerTag : '') };
}

/**
 * What full mode does not use, for the edit view: the config's own routing
 * rules, whether it has its own DNS, how many balancers, an observatory.
 */
function jsonInfo(config) {
  return {
    rules: rulesOf(config).map(ruleInfo),
    dns: isObj(config && config.dns) && Object.keys(config.dns).length > 0,
    balancers: balancersOf(config).length,
    observatory: !!(config && (config.observatory || config.burstObservatory))
  };
}

/** A server's name: remarks, else ps, else the main outbound's address:port; a balancer member's carries its tag. */
function nameFor(config, main, balancer) {
  const base = String((config && (config.remarks || config.ps)) || '').trim();
  const ep = endpointOf(main);
  if (!base) return joinHostPort(ep.address, ep.port);
  return balancer ? `${base} · ${main.tag}` : base;
}

/** The fields a JSON server derives from its config — re-derived on every edit. */
const DERIVED = ['protocol', 'address', 'port', 'raw', 'outbound', 'json', 'extraOutbounds', 'jsonInfo'];

/** The record for `main` of `config`: the link record's fields, then source/json/extraOutbounds/jsonMode/jsonInfo. */
function recordFor(config, main, balancer) {
  const outbound = clone(main);
  delete outbound.tag;
  const { address, port } = endpointOf(main);
  return {
    id: uid(),
    name: nameFor(config, main, balancer),
    protocol: main.protocol === 'hysteria' ? 'hysteria2' : main.protocol,
    address,
    port,
    raw: JSON.stringify(config),
    outbound,
    source: 'json',
    json: clone(config),
    extraOutbounds: helpersOf(config, main),
    jsonMode: 'full',
    jsonInfo: jsonInfo(config)
  };
}

/** One Xray config → its server(s). A config with no proxy outbound (an info row) → none. */
function serversFromXray(config) {
  if (!isObj(config)) return [];
  const m = mainOutbounds(config);
  return m.list.map((main) => recordFor(config, main, m.balancer));
}

/* ------------------------------ sing-box JSON ------------------------------ */

const enc = (v) => encodeURIComponent(String(v));
const qs = (o) => Object.keys(o).filter((k) => o[k] !== undefined && o[k] !== null && o[k] !== '').map((k) => `${k}=${enc(o[k])}`).join('&');
const SINGBOX_SKIP = new Set(['selector', 'urltest', 'direct', 'block', 'dns']);

/** sing-box `transport` → a link's type/path/host/serviceName. */
function transportQuery(t) {
  if (!isObj(t) || !t.type) return { type: 'tcp' };
  const type = String(t.type).toLowerCase();
  if (type === 'ws') {
    const h = isObj(t.headers) ? (t.headers.Host || t.headers.host) : '';
    let p = String(t.path || '/');
    const ed = parseInt(t.max_early_data, 10);
    if (ed > 0 && String(t.early_data_header_name || '') === 'Sec-WebSocket-Protocol') p += (p.includes('?') ? '&' : '?') + 'ed=' + ed;
    return { type: 'ws', path: p, host: [].concat(h || [])[0] || '' };
  }
  if (type === 'grpc') return { type: 'grpc', serviceName: t.service_name || '' };
  if (type === 'http') return { type: 'http', path: t.path || '/', host: [].concat(t.host || []).join(',') };
  if (type === 'httpupgrade') return { type: 'httpupgrade', path: t.path || '/', host: t.host || '' };
  throw new Error('unsupported transport: ' + type);
}

/** sing-box `tls` → a link's security/sni/fp/alpn/pbk/sid. */
function tlsQuery(tls) {
  if (!isObj(tls) || !tls.enabled) return { security: 'none' };
  const fp = isObj(tls.utls) && tls.utls.enabled !== false && tls.utls.fingerprint ? String(tls.utls.fingerprint) : '';
  const sni = tls.server_name || '';
  if (isObj(tls.reality) && tls.reality.enabled) {
    return { security: 'reality', sni, fp, pbk: tls.reality.public_key || '', sid: tls.reality.short_id || '' };
  }
  return { security: 'tls', sni, fp, alpn: [].concat(tls.alpn || []).join(','), allowInsecure: tls.insecure ? '1' : '' };
}

/** A WireGuard `reserved`: [0, 0, 0] or its base64 → "0,0,0". */
function reservedText(v) {
  if (Array.isArray(v)) return v.join(',');
  if (typeof v === 'string' && v) return /^\d+(,\d+)*$/.test(v) ? v : [...Buffer.from(v, 'base64')].join(',');
  return '';
}

/**
 * The share link a sing-box outbound stands for — the server is then exactly
 * what an import of that link gives. Throws, naming it, for what has no link
 * here (tuic, anytls, a QUIC transport…).
 */
function singboxLink(o, type) {
  const name = (o.tag ? String(o.tag) : type) + (o.detour ? ` (via ${o.detour})` : '');
  const frag = '#' + enc(name);
  const b64 = (s) => Buffer.from(s, 'utf8').toString('base64');
  if (type === 'wireguard') {
    const peer = Array.isArray(o.peers) && isObj(o.peers[0]) ? o.peers[0] : null;
    const host = peer ? (peer.address || peer.server) : o.server;
    const port = peer ? (peer.port || peer.server_port) : o.server_port;
    if (!host) throw new Error('wireguard: no server address');
    const q = {
      publickey: peer ? peer.public_key : o.peer_public_key,
      address: [].concat(o.local_address || o.address || []).join(','),
      allowedips: peer ? [].concat(peer.allowed_ips || []).join(',') : '',
      presharedkey: peer ? peer.pre_shared_key : o.pre_shared_key,
      mtu: o.mtu ? String(o.mtu) : '',
      reserved: reservedText((peer && peer.reserved) || o.reserved)
    };
    return `wireguard://${enc(o.private_key || '')}@${joinHostPort(host, port || 51820)}?${qs(q)}${frag}`;
  }
  if (!['vless', 'vmess', 'trojan', 'shadowsocks', 'hysteria2', 'socks', 'http'].includes(type)) throw new Error('unsupported protocol: ' + type);
  if (!o.server) throw new Error(type + ': no server address');
  const hp = joinHostPort(o.server, o.server_port);
  if (type === 'vless') {
    return `vless://${o.uuid || ''}@${hp}?${qs(Object.assign({ encryption: 'none', flow: o.flow }, transportQuery(o.transport), tlsQuery(o.tls)))}${frag}`;
  }
  if (type === 'trojan') return `trojan://${enc(o.password || '')}@${hp}?${qs(Object.assign({}, transportQuery(o.transport), tlsQuery(o.tls)))}${frag}`;
  if (type === 'vmess') {
    const t = transportQuery(o.transport), s = tlsQuery(o.tls);
    if (s.security === 'reality') throw new Error('unsupported protocol: vmess with reality');
    const v = {
      v: '2', ps: name, add: String(o.server), port: String(o.server_port), id: o.uuid || '', aid: String(o.alter_id || 0), scy: o.security || 'auto',
      net: t.type, type: 'none', host: t.host || '', path: t.type === 'grpc' ? t.serviceName : (t.path || ''),
      tls: s.security === 'tls' ? 'tls' : '', sni: s.sni || '', fp: s.fp || '', alpn: s.alpn || ''
    };
    if (s.allowInsecure) v.insecure = '1';
    return 'vmess://' + b64(JSON.stringify(v));
  }
  if (type === 'shadowsocks') {
    const plugin = o.plugin ? '/?plugin=' + enc([o.plugin, o.plugin_opts].filter(Boolean).join(';')) : '';
    return `ss://${b64(`${o.method || ''}:${o.password || ''}`)}@${hp}${plugin}${frag}`;
  }
  if (type === 'hysteria2') {
    const tls = isObj(o.tls) ? o.tls : {};
    const obfs = isObj(o.obfs) ? o.obfs : {};
    const q = {
      sni: tls.server_name, insecure: tls.insecure ? '1' : '', alpn: [].concat(tls.alpn || []).join(','),
      obfs: obfs.type, 'obfs-password': obfs.password, mport: [].concat(o.server_ports || []).join(','),
      hopInterval: o.hop_interval, up: o.up_mbps, down: o.down_mbps
    };
    return `hysteria2://${enc(o.password || '')}@${hp}/?${qs(q)}${frag}`;
  }
  // socks / http: the proxy link's base64 user:pass
  if (isObj(o.tls) && o.tls.enabled) throw new Error(`unsupported protocol: ${type} over TLS`);
  const auth = (o.username || o.password) ? b64(`${o.username || ''}:${o.password || ''}`) + '@' : '';
  return `${type}://${auth}${hp}${frag}`;
}

/** A sing-box config → { servers, errors }: one ordinary server per supported outbound (and WireGuard endpoint). */
function serversFromSingbox(config) {
  const servers = [], errors = [];
  const list = [].concat(Array.isArray(config && config.outbounds) ? config.outbounds : [], Array.isArray(config && config.endpoints) ? config.endpoints : []);
  for (const o of list) {
    if (!isObj(o)) continue;
    const type = String(o.type || '').trim().toLowerCase();
    if (SINGBOX_SKIP.has(type)) continue;
    try { servers.push(parser().parseLink(singboxLink(o, type))); }
    catch (e) { errors.push({ line: String(o.tag || type), error: e.message }); }
  }
  return { servers, errors };
}

/* ------------------------------ the reader ------------------------------ */

/**
 * JSON text → { servers, errors }; null when the text is not JSON at all (so
 * parseMany reads it as links). Base64 of JSON counts; Clash YAML is refused.
 */
function importJson(text) {
  const body = String(text == null ? '' : text).replace(BOM, '').trim();
  if (!body) return null;
  let json = looksLikeJson(body) ? body : null;
  if (!json && !body.includes('://')) {
    const decoded = b64text(body).replace(BOM, '').trim();
    if (looksLikeJson(decoded)) json = decoded;
  }
  if (!json) return isClashYaml(body) ? { servers: [], errors: [{ line: 'proxies:', error: CLASH }] } : null;

  let data;
  try { data = JSON.parse(json); } catch (e) {
    return { servers: [], errors: [{ line: json.split(/\r?\n/)[0].slice(0, 80), error: 'invalid JSON: ' + e.message }] };
  }
  const servers = [], errors = [];
  for (const [i, c] of (Array.isArray(data) ? data : [data]).entries()) {
    if (!isObj(c) || !Array.isArray(c.outbounds)) {
      const label = isObj(c) && (c.remarks || c.ps) ? String(c.remarks || c.ps) : `#${i + 1}`;
      errors.push({ line: label, error: 'not an Xray or sing-box config: no outbounds' });
      continue;
    }
    if (isSingbox(c)) {
      const r = serversFromSingbox(c);
      servers.push(...r.servers);
      errors.push(...r.errors);
    } else {
      servers.push(...serversFromXray(c));
    }
  }
  return { servers, errors };
}

/* ------------------------------ editing ------------------------------ */

const NO_PROXY = 'no proxy outbound in this config (vless, vmess, trojan, shadowsocks, socks, http, wireguard or hysteria)';

/** The config an edit sends — text or an object — or an Error saying why it is none. */
function configFromEdit(v) {
  let cfg = v;
  if (typeof v === 'string') {
    try { cfg = JSON.parse(v); } catch (e) { throw new Error('invalid JSON: ' + e.message); }
  }
  if (Array.isArray(cfg) && cfg.length === 1) cfg = cfg[0];
  if (!isObj(cfg)) throw new Error('the JSON must be one Xray config (an object with outbounds)');
  if (!Array.isArray(cfg.outbounds)) throw new Error('no outbounds in this config');
  if (isSingbox(cfg)) throw new Error('this is a sing-box config — add it as a new server instead');
  return clone(cfg);
}

/**
 * Which member of a balancer a record is: the outbound of its config that is
 * its main outbound, else the tag its name ends with. '' when it cannot say.
 */
function memberTag(server) {
  const want = canon(server.outbound || {});
  for (const o of outboundsOf(server.json)) {
    const c = Object.assign({}, o);
    delete c.tag;
    if (canon(c) === want) return o.tag || '';
  }
  const m = / · (.+)$/.exec(String(server.name || ''));
  return m ? m[1] : '';
}

/** The main outbound of `config` for this record: the one member of a balancer it was. */
function mainFor(config, server) {
  const m = mainOutbounds(config);
  if (!m.list.length) return null;
  const tag = m.list.length > 1 ? memberTag(server) : '';
  return { main: m.list.find((o) => o.tag === tag) || m.list[0], balancer: m.balancer };
}

/**
 * An edit of a JSON server — { name, jsonMode, json } — on a copy. `json` (text
 * or an object) re-derives the main outbound, the helpers, the protocol,
 * address, port, raw and jsonInfo; one with no proxy outbound left throws
 * with the reason. What the user changed is recorded in `_edited` (a union
 * over every edit), as for a link server's fields: a name back to the
 * config's own, or the mode back to full, is released.
 */
function applyJsonEdits(server, f) {
  f = f || {};
  const out = clone(server);
  const changed = [];
  const cfg = f.json != null ? configFromEdit(f.json) : null;
  // The same config, whatever its spacing or key order (the edit view sends
  // the object it parsed): nothing to re-derive, and nothing was edited — a
  // Save with nothing changed leaves the record exactly as it was.
  if (cfg && canon(cfg) !== canon(server.json)) {
    const pick = mainFor(cfg, server);
    if (!pick) throw new Error(NO_PROXY);
    const fresh = recordFor(cfg, pick.main, pick.balancer);
    for (const k of DERIVED) out[k] = fresh[k];
    changed.push('json');
  } else if (isObj(out.json)) {
    out.jsonInfo = jsonInfo(out.json);
  }
  if (f.name != null) {
    const n = String(f.name).trim();
    if (n) {
      if (n !== server.name) changed.push('name');
      out.name = n;
    }
  }
  if (f.jsonMode != null) {
    const mode = f.jsonMode === 'raw' ? 'raw' : 'full';
    if (mode !== (server.jsonMode || 'full')) changed.push('jsonMode');
    out.jsonMode = mode;
  }
  if (f.clearCertPin) { delete out.certPin; delete out.certPinAt; }

  if (changed.length) {
    const own = isObj(out.json) ? mainFor(out.json, out) : null;
    const released = (k) => (k === 'jsonMode' && out.jsonMode === 'full') ||
      (k === 'name' && !!own && out.name === nameFor(out.json, own.main, own.balancer));
    const edited = [...new Set([...(Array.isArray(server._edited) ? server._edited : []), ...changed])]
      .filter((k) => !(changed.includes(k) && released(k)))
      .sort();
    if (edited.length) out._edited = edited; else delete out._edited;
  }
  return out;
}

/** A JSON server's fields as its edit view shows them: the name, the mode, the config as pretty text. */
function jsonEditFields(server) {
  return { name: server.name, jsonMode: server.jsonMode || 'full', json: JSON.stringify(server.json, null, 2) };
}

module.exports = {
  looksLikeJson, importJson, serversFromXray, serversFromSingbox, mainOutboundTag, helperClosure, jsonInfo,
  applyJsonEdits, jsonEditFields, PROXY_PROTOCOLS, JSON_DERIVED: DERIVED
};
