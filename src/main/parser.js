'use strict';
/**
 * Share-link parser: converts vless:// vmess:// trojan:// ss:// links
 * into Xray outbound JSON objects (+ a normalized server record for the UI).
 *
 * Returns a "server" object:
 *   { id, name, protocol, address, port, raw, outbound }
 * where `outbound` is a ready-to-use Xray outbound (without tag; tag added later).
 */

const crypto = require('crypto');

function uid() {
  return crypto.randomBytes(8).toString('hex');
}

function safeDecodeURIComponent(s) {
  try { return decodeURIComponent(s); } catch { return s; }
}

// Base64 (both standard and url-safe), tolerant of missing padding.
function b64decode(str) {
  if (!str) return '';
  let s = String(str).trim().replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  try {
    return Buffer.from(s, 'base64').toString('utf8');
  } catch {
    return '';
  }
}

function parseQuery(qs) {
  const out = {};
  if (!qs) return out;
  for (const pair of qs.split('&')) {
    if (!pair) continue;
    const idx = pair.indexOf('=');
    const k = idx === -1 ? pair : pair.slice(0, idx);
    const v = idx === -1 ? '' : pair.slice(idx + 1);
    out[safeDecodeURIComponent(k)] = safeDecodeURIComponent(v);
  }
  return out;
}

/**
 * Build a streamSettings object shared by vless/trojan from query params.
 */
function buildStreamSettings(q) {
  const net = (q.type || q.network || 'tcp').toLowerCase();
  const security = (q.security || 'none').toLowerCase();

  const stream = { network: net, security };

  // --- transport specific ---
  if (net === 'ws') {
    stream.wsSettings = {
      path: q.path || '/',
      headers: q.host ? { Host: q.host } : {}
    };
  } else if (net === 'grpc') {
    stream.grpcSettings = {
      serviceName: q.serviceName || q.path || '',
      multiMode: (q.mode || '') === 'multi'
    };
  } else if (net === 'h2' || net === 'http') {
    stream.network = 'h2';
    stream.httpSettings = {
      path: q.path || '/',
      host: q.host ? q.host.split(',') : []
    };
  } else if (net === 'tcp') {
    if ((q.headerType || '') === 'http') {
      stream.tcpSettings = {
        header: {
          type: 'http',
          request: { path: [q.path || '/'], headers: q.host ? { Host: [q.host] } : {} }
        }
      };
    }
  } else if (net === 'xhttp' || net === 'splithttp') {
    stream.network = 'xhttp';
    stream.xhttpSettings = {
      path: q.path || '/',
      host: q.host || '',
      mode: q.mode || 'auto'
    };
  } else if (net === 'kcp' || net === 'mkcp') {
    stream.network = 'kcp';
    stream.kcpSettings = {
      header: { type: q.headerType || 'none' },
      seed: q.seed || ''
    };
  }

  // --- security specific ---
  if (security === 'tls') {
    stream.tlsSettings = {
      serverName: q.sni || q.host || '',
      allowInsecure: q.allowInsecure === '1' || q.allowInsecure === 'true',
      fingerprint: q.fp || 'chrome'
    };
    if (q.alpn) stream.tlsSettings.alpn = q.alpn.split(',');
  } else if (security === 'reality') {
    stream.realitySettings = {
      serverName: q.sni || '',
      fingerprint: q.fp || 'chrome',
      publicKey: q.pbk || '',
      shortId: q.sid || '',
      spiderX: q.spx || ''
    };
  }

  return stream;
}

/* ----------------------------- VLESS ----------------------------- */
function parseVless(link) {
  // vless://uuid@host:port?params#name
  const body = link.slice('vless://'.length);
  const hashIdx = body.indexOf('#');
  const name = hashIdx === -1 ? '' : safeDecodeURIComponent(body.slice(hashIdx + 1));
  const main = hashIdx === -1 ? body : body.slice(0, hashIdx);

  const qIdx = main.indexOf('?');
  const beforeQ = qIdx === -1 ? main : main.slice(0, qIdx);
  const q = parseQuery(qIdx === -1 ? '' : main.slice(qIdx + 1));

  const atIdx = beforeQ.lastIndexOf('@');
  const uuid = beforeQ.slice(0, atIdx);
  const hostPort = beforeQ.slice(atIdx + 1);
  const [address, portStr] = splitHostPort(hostPort);
  const port = parseInt(portStr, 10) || 443;

  const stream = buildStreamSettings(q);

  const outbound = {
    protocol: 'vless',
    settings: {
      vnext: [{
        address,
        port,
        users: [{
          id: uuid,
          encryption: q.encryption || 'none',
          flow: q.flow || ''
        }]
      }]
    },
    streamSettings: stream
  };

  return mkServer(name || address, 'vless', address, port, link, outbound);
}

/* ----------------------------- VMess ----------------------------- */
function parseVmess(link) {
  // vmess://<base64 of json>
  const raw = link.slice('vmess://'.length);
  const json = b64decode(raw);
  let v;
  try { v = JSON.parse(json); } catch { throw new Error('VMess: invalid base64/JSON'); }

  const address = v.add;
  const port = parseInt(v.port, 10) || 443;
  const net = (v.net || 'tcp').toLowerCase();
  const security = (v.tls || 'none').toLowerCase() === 'tls' ? 'tls' : (v.tls || 'none');

  const q = {
    type: net,
    security: security === 'tls' ? 'tls' : 'none',
    path: v.path || '/',
    host: v.host || '',
    sni: v.sni || v.host || '',
    fp: v.fp || 'chrome',
    alpn: v.alpn || '',
    serviceName: v.path || '',
    headerType: v.type || 'none'
  };
  const stream = buildStreamSettings(q);

  const outbound = {
    protocol: 'vmess',
    settings: {
      vnext: [{
        address,
        port,
        users: [{
          id: v.id,
          alterId: parseInt(v.aid, 10) || 0,
          security: v.scy || 'auto'
        }]
      }]
    },
    streamSettings: stream
  };

  return mkServer(v.ps || address, 'vmess', address, port, link, outbound);
}

/* ----------------------------- Trojan ----------------------------- */
function parseTrojan(link) {
  // trojan://password@host:port?params#name
  const body = link.slice('trojan://'.length);
  const hashIdx = body.indexOf('#');
  const name = hashIdx === -1 ? '' : safeDecodeURIComponent(body.slice(hashIdx + 1));
  const main = hashIdx === -1 ? body : body.slice(0, hashIdx);

  const qIdx = main.indexOf('?');
  const beforeQ = qIdx === -1 ? main : main.slice(0, qIdx);
  const q = parseQuery(qIdx === -1 ? '' : main.slice(qIdx + 1));

  const atIdx = beforeQ.lastIndexOf('@');
  const password = safeDecodeURIComponent(beforeQ.slice(0, atIdx));
  const [address, portStr] = splitHostPort(beforeQ.slice(atIdx + 1));
  const port = parseInt(portStr, 10) || 443;

  if (!q.security) q.security = 'tls'; // trojan defaults to tls
  const stream = buildStreamSettings(q);

  const outbound = {
    protocol: 'trojan',
    settings: {
      servers: [{ address, port, password }]
    },
    streamSettings: stream
  };

  return mkServer(name || address, 'trojan', address, port, link, outbound);
}

/* --------------------------- Shadowsocks --------------------------- */
function parseShadowsocks(link) {
  // ss://base64(method:password)@host:port#name
  //  or ss://base64(method:password@host:port)#name
  const body = link.slice('ss://'.length);
  const hashIdx = body.indexOf('#');
  const name = hashIdx === -1 ? '' : safeDecodeURIComponent(body.slice(hashIdx + 1));
  let main = hashIdx === -1 ? body : body.slice(0, hashIdx);

  // strip plugin query if present
  const qIdx = main.indexOf('?');
  if (qIdx !== -1) main = main.slice(0, qIdx);

  let method, password, address, port;

  if (main.includes('@')) {
    const atIdx = main.lastIndexOf('@');
    const userInfo = main.slice(0, atIdx);
    const hostPart = main.slice(atIdx + 1);
    const decoded = b64decode(userInfo) || safeDecodeURIComponent(userInfo);
    const ci = decoded.indexOf(':');
    method = decoded.slice(0, ci);
    password = decoded.slice(ci + 1);
    [address, port] = splitHostPort(hostPart);
  } else {
    const decoded = b64decode(main);
    const atIdx = decoded.lastIndexOf('@');
    const userInfo = decoded.slice(0, atIdx);
    const hostPart = decoded.slice(atIdx + 1);
    const ci = userInfo.indexOf(':');
    method = userInfo.slice(0, ci);
    password = userInfo.slice(ci + 1);
    [address, port] = splitHostPort(hostPart);
  }
  port = parseInt(port, 10) || 443;

  const outbound = {
    protocol: 'shadowsocks',
    settings: {
      servers: [{ address, port, method, password, uot: true }]
    },
    streamSettings: { network: 'tcp' }
  };

  return mkServer(name || address, 'shadowsocks', address, port, link, outbound);
}

/* --------------------------- WireGuard --------------------------- */
/**
 * Build a WireGuard outbound from plain fields.
 * fields: { privateKey, publicKey, endpoint(host:port) | address+port,
 *           addresses[] | address, presharedKey, mtu, reserved, dns, name }
 */
/**
 * Normalize WireGuard *interface* addresses. Xray REQUIRES the local interface
 * address to be /32 (IPv4) or /128 (IPv6); anything else (e.g. /16, /24) makes
 * xray fail to start ("interface address subnet should be /32..."). We coerce
 * the mask so a misconfigured value can't crash the whole VPN.
 */
function normalizeWgAddresses(list) {
  return (list || [])
    .map(a => String(a || '').trim())
    .filter(Boolean)
    .map(a => {
      const isV6 = a.includes(':');
      const host = a.indexOf('/') === -1 ? a : a.slice(0, a.indexOf('/'));
      return host + (isV6 ? '/128' : '/32');
    });
}

function buildWireguardOutbound(f) {
  const addrList = Array.isArray(f.addresses)
    ? f.addresses
    : splitCommas(f.address || f.addresses || '');
  let localAddrs = normalizeWgAddresses(addrList);
  if (!localAddrs.length) localAddrs = ['10.0.0.2/32'];

  let reserved;
  if (Array.isArray(f.reserved)) reserved = f.reserved;
  else if (f.reserved) reserved = splitCommas(f.reserved).map(n => parseInt(n, 10) || 0);

  // AllowedIPs decides which destination IPs are sent into the tunnel.
  const allowedRaw = f.allowedIPs != null
    ? (Array.isArray(f.allowedIPs) ? f.allowedIPs : splitCommas(f.allowedIPs))
    : null;
  const allowedIPs = (allowedRaw && allowedRaw.length) ? allowedRaw : ['0.0.0.0/0', '::/0'];

  const peer = {
    publicKey: (f.publicKey || '').trim(),
    endpoint: (f.endpoint || '').trim(),
    allowedIPs
  };
  if (f.presharedKey) peer.preSharedKey = f.presharedKey.trim();

  const settings = {
    secretKey: (f.privateKey || '').trim(),
    address: localAddrs,
    peers: [peer],
    mtu: parseInt(f.mtu, 10) || 1420
  };
  if (reserved && reserved.length) settings.reserved = reserved;

  return { protocol: 'wireguard', settings, streamSettings: { sockopt: {} } };
}

function splitCommas(v) {
  return String(v || '').split(/[,\s]+/).map(x => x.trim()).filter(Boolean);
}

/**
 * Parse a wireguard:// or wg:// share link. Tolerant of several variants:
 *   wireguard://<privkey>@host:port?publickey=..&address=..&presharedkey=..&mtu=..&reserved=..#name
 */
function parseWireguard(link) {
  const scheme = link.startsWith('wireguard://') ? 'wireguard://' : 'wg://';
  const body = link.slice(scheme.length);
  const hashIdx = body.indexOf('#');
  const name = hashIdx === -1 ? '' : safeDecodeURIComponent(body.slice(hashIdx + 1));
  const main = hashIdx === -1 ? body : body.slice(0, hashIdx);

  const qIdx = main.indexOf('?');
  const beforeQ = qIdx === -1 ? main : main.slice(0, qIdx);
  const q = parseQuery(qIdx === -1 ? '' : main.slice(qIdx + 1));

  const atIdx = beforeQ.lastIndexOf('@');
  const privateKey = safeDecodeURIComponent(atIdx === -1 ? '' : beforeQ.slice(0, atIdx));
  const hostPort = atIdx === -1 ? beforeQ : beforeQ.slice(atIdx + 1);
  const [address, portStr] = splitHostPort(hostPort);
  const port = parseInt(portStr, 10) || 51820;

  const outbound = buildWireguardOutbound({
    privateKey,
    publicKey: q.publickey || q.publicKey || q.peer || '',
    endpoint: `${address}:${port}`,
    address: q.address || q.ip || '',
    presharedKey: q.presharedkey || q.presharedKey || q.psk || '',
    mtu: q.mtu,
    reserved: q.reserved
  });

  return mkServer(name || address, 'wireguard', address, port, link, outbound);
}

/**
 * Create a WireGuard server record from a UI form (no share link).
 */
function makeWireguardServer(fields) {
  const [host, portStr] = splitHostPort(fields.endpoint || '');
  const port = parseInt(portStr, 10) || parseInt(fields.port, 10) || 51820;
  const endpoint = fields.endpoint || `${host}:${port}`;
  const outbound = buildWireguardOutbound(Object.assign({}, fields, { endpoint }));
  const raw = 'wireguard://' + (host || '') + ':' + port;
  return mkServer(fields.name || host || 'WireGuard', 'wireguard', host || '', port, raw, outbound);
}

/* ------------------------------ editing ------------------------------ */
/**
 * Apply edited fields to an existing server (mutates a clone, returns it).
 * Generic fields: name, address, port.
 * Credential/transport fields depend on protocol.
 */
function applyServerEdits(server, f) {
  const out = JSON.parse(JSON.stringify(server));
  if (f.name != null) out.name = String(f.name).trim() || out.name;
  const addr = f.address != null ? String(f.address).trim() : out.address;
  const port = f.port != null ? (parseInt(f.port, 10) || out.port) : out.port;
  out.address = addr;
  out.port = port;

  const ob = out.outbound;
  const proto = out.protocol;

  if (proto === 'vless' || proto === 'vmess') {
    const vnext = ob.settings && ob.settings.vnext && ob.settings.vnext[0];
    if (vnext) {
      vnext.address = addr;
      vnext.port = port;
      const u = vnext.users && vnext.users[0];
      if (u) {
        if (f.uuid) u.id = f.uuid.trim();
        if (proto === 'vless' && f.flow != null) u.flow = f.flow.trim();
      }
    }
    rebuildStream(ob, f);
  } else if (proto === 'trojan') {
    const srv = ob.settings && ob.settings.servers && ob.settings.servers[0];
    if (srv) {
      srv.address = addr; srv.port = port;
      if (f.password) srv.password = f.password;
    }
    rebuildStream(ob, f);
  } else if (proto === 'shadowsocks') {
    const srv = ob.settings && ob.settings.servers && ob.settings.servers[0];
    if (srv) {
      srv.address = addr; srv.port = port;
      if (f.password) srv.password = f.password;
      if (f.method) srv.method = f.method;
    }
  } else if (proto === 'wireguard') {
    const st = ob.settings;
    const peer = st && st.peers && st.peers[0];
    if (peer) {
      peer.endpoint = `${addr}:${port}`;
      if (f.publicKey) peer.publicKey = f.publicKey.trim();
      if (f.presharedKey != null) {
        if (f.presharedKey.trim()) peer.preSharedKey = f.presharedKey.trim();
        else delete peer.preSharedKey;
      }
      if (f.allowedIPs != null) {
        const a = splitCommas(f.allowedIPs);
        peer.allowedIPs = a.length ? a : ['0.0.0.0/0', '::/0'];
      }
    }
    if (f.privateKey) st.secretKey = f.privateKey.trim();
    if (f.address) st.address = normalizeWgAddresses(splitCommas(f.address));
    if (f.mtu) st.mtu = parseInt(f.mtu, 10) || st.mtu;
    if (f.reserved != null) {
      const r = splitCommas(f.reserved).map(n => parseInt(n, 10) || 0);
      if (r.length) st.reserved = r; else delete st.reserved;
    }
  }

  return out;
}

/** Rebuild streamSettings (transport/security) from edit fields, when supplied. */
function rebuildStream(ob, f) {
  if (!ob.streamSettings) return;
  const cur = ob.streamSettings;
  // Only rebuild if the user touched transport/security fields.
  const touched = ['network', 'security', 'sni', 'path', 'host', 'allowInsecure', 'fp', 'pbk', 'sid', 'serviceName', 'alpn']
    .some(k => f[k] != null && f[k] !== '');
  if (!touched) return;

  const q = {
    type: f.network || cur.network || 'tcp',
    security: f.security || cur.security || 'none',
    sni: f.sni,
    path: f.path,
    host: f.host,
    serviceName: f.serviceName,
    fp: f.fp,
    pbk: f.pbk,
    sid: f.sid,
    alpn: f.alpn,
    allowInsecure: f.allowInsecure ? '1' : '0'
  };
  ob.streamSettings = buildStreamSettings(q);
}

/* ------------------------------ helpers ------------------------------ */
function splitHostPort(hp) {
  // supports [ipv6]:port and host:port
  if (hp.startsWith('[')) {
    const close = hp.indexOf(']');
    const host = hp.slice(1, close);
    const port = hp.slice(close + 2);
    return [host, port];
  }
  const idx = hp.lastIndexOf(':');
  if (idx === -1) return [hp, ''];
  return [hp.slice(0, idx), hp.slice(idx + 1)];
}

function mkServer(name, protocol, address, port, raw, outbound) {
  return {
    id: uid(),
    name: name || `${protocol}-${address}`,
    protocol,
    address,
    port,
    raw,
    outbound
  };
}

/**
 * Parse a single share link into a server object. Throws on failure.
 */
function parseLink(link) {
  const l = String(link).trim();
  if (l.startsWith('vless://')) return parseVless(l);
  if (l.startsWith('vmess://')) return parseVmess(l);
  if (l.startsWith('trojan://')) return parseTrojan(l);
  if (l.startsWith('ss://')) return parseShadowsocks(l);
  if (l.startsWith('wireguard://') || l.startsWith('wg://')) return parseWireguard(l);
  throw new Error('Unsupported or invalid link: ' + l.slice(0, 12) + '...');
}

/**
 * Parse multiple links / a subscription blob. Accepts:
 *  - newline separated links
 *  - a base64 blob whose decoded body is newline separated links (subscription)
 * Returns { servers: [...], errors: [...] }
 */
function parseMany(text) {
  let body = String(text || '').trim();

  // If it has no scheme but decodes to links, treat as subscription base64.
  if (!/^(vless|vmess|trojan|ss|wireguard|wg):\/\//im.test(body)) {
    const decoded = b64decode(body);
    if (/^(vless|vmess|trojan|ss|wireguard|wg):\/\//im.test(decoded)) body = decoded;
  }

  const lines = body.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
  const servers = [];
  const errors = [];
  for (const line of lines) {
    if (!/^(vless|vmess|trojan|ss|wireguard|wg):\/\//i.test(line)) continue;
    try {
      servers.push(parseLink(line));
    } catch (e) {
      errors.push({ line, error: e.message });
    }
  }
  return { servers, errors };
}

module.exports = {
  parseLink, parseMany, b64decode,
  buildStreamSettings, buildWireguardOutbound, makeWireguardServer, applyServerEdits
};
