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
    // patterniha-style custom TLS: `unsafe` fingerprint lets you pin cipherSuites.
    if (q.cipherSuites) stream.tlsSettings.cipherSuites = String(q.cipherSuites).trim();
  } else if (security === 'reality') {
    stream.realitySettings = {
      serverName: q.sni || '',
      fingerprint: q.fp || 'chrome',
      publicKey: q.pbk || '',
      shortId: q.sid || '',
      spiderX: q.spx || ''
    };
  }

  // finalMask (ClientHello fragmentation / masking) — a raw JSON object the user
  // pastes; normalized so both the plural (lengths/delays arrays) and singular
  // forms work on the bundled core.
  if (q.finalMask) {
    const fm = normalizeFinalMask(q.finalMask);
    if (fm) stream.finalmask = fm;
  }

  return stream;
}

/**
 * Parse + normalize a finalMask JSON. The patterniha UI uses plural arrays
 * (`lengths`, `delays`) where the n-th element is the n-th fragment's size; the
 * bundled xray core wants the singular `length`/`delay` range, so we collapse
 * the array to its min-max range (still splits the ClientHello / hides the SNI).
 * Returns the normalized object, or null on invalid JSON.
 */
function normalizeFinalMask(raw) {
  let obj;
  try { obj = typeof raw === 'string' ? JSON.parse(raw) : raw; }
  catch { return null; }
  if (!obj || typeof obj !== 'object') return null;
  const rangeOf = (arr) => {
    let mn = Infinity, mx = -Infinity;
    for (const v of arr) { const p = String(v).split('-').map(n => parseInt(n, 10)); if (Number.isFinite(p[0])) mn = Math.min(mn, p[0]); mx = Math.max(mx, p[p.length - 1]); }
    if (!Number.isFinite(mn)) return null;
    mn = Math.max(1, mn); mx = Math.max(mn, mx);
    return mn === mx ? String(mn) : `${mn}-${mx}`;
  };
  const fixMasks = (a) => Array.isArray(a) ? a.map(m => {
    const s = m && m.settings;
    if (s) {
      if (Array.isArray(s.lengths)) { const r = rangeOf(s.lengths); if (r) s.length = r; delete s.lengths; }
      if (Array.isArray(s.delays)) { s.delay = String(s.delays[0] != null ? s.delays[0] : '0'); delete s.delays; }
    }
    return m;
  }) : a;
  if (obj.tcp) obj.tcp = fixMasks(obj.tcp);
  if (obj.udp) obj.udp = fixMasks(obj.udp);
  return obj;
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

  // TLS fragmentation, read straight from the share link (&fragment=p,l,i)
  if (q.fragment) outbound._fragment = q.fragment;
  // Anti-DPI noise / fake ClientHello injection (&noise=type:packet:delay;...)
  if (q.noise) outbound._noise = q.noise;
  if (q.fakeSni) outbound._fakesni = q.fakeSni;

  const srv = mkServer(name || address, 'vless', address, port, link, outbound);
  if (q.engine && q.engine !== 'xray') srv.engine = q.engine;
  return srv;
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
    headerType: v.type || 'none',
    cipherSuites: v.cipherSuites || '',
    finalMask: v.finalMask || v.finalmask || ''
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

  if (v.fragment) outbound._fragment = String(v.fragment);
  if (v.noise) outbound._noise = String(v.noise);
  if (v.fakesni) outbound._fakesni = String(v.fakesni);

  const srv = mkServer(v.ps || address, 'vmess', address, port, link, outbound);
  if (v.engine && v.engine !== 'xray') srv.engine = String(v.engine);
  return srv;
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

  if (q.fragment) outbound._fragment = q.fragment;
  if (q.noise) outbound._noise = q.noise;
  if (q.fakeSni) outbound._fakesni = q.fakeSni;

  const srv = mkServer(name || address, 'trojan', address, port, link, outbound);
  if (q.engine && q.engine !== 'xray') srv.engine = q.engine;
  return srv;
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

/* --------------------------- SOCKS / HTTP proxy --------------------------- */
/**
 * Build a SOCKS/HTTP proxy outbound. `proto` is 'socks' or 'http'.
 * Credentials are optional (many public SOCKS proxies are open).
 */
function buildProxyOutbound(proto, address, port, user, pass) {
  const server = { address, port: parseInt(port, 10) || (proto === 'http' ? 8080 : 1080) };
  if ((user && user.length) || (pass && pass.length)) {
    server.users = [{ user: user || '', pass: pass || '' }];
  }
  return {
    protocol: proto === 'http' ? 'http' : 'socks',
    settings: { servers: [server] },
    streamSettings: { network: 'tcp' }
  };
}

/**
 * v2rayN shares an HTTP proxy exactly like a SOCKS one —
 * `http://[b64(user:pass)@]host:port#name` — which is also the shape of a plain
 * subscription URL's origin. A proxy link therefore has NO path and NO query.
 * The userinfo is either a standard-alphabet base64 blob (which may contain '/')
 * or a plain `user:pass`; the host never contains a '/', so a subscription URL
 * with an '@' in its path still fails to match.
 * (Kept in sync with the copy in src/renderer/app.js smartImport.)
 */
const HTTP_PROXY_LINK = /^http:\/\/(?:(?:[A-Za-z0-9+/=]+|[^/?#\s@]+)@)?[^/?#\s@]+:\d{1,5}(?:#\S*)?$/i;
function isHttpProxyLink(s) { return HTTP_PROXY_LINK.test(String(s || '').trim()); }

/**
 * Parse a socks:// / socks5:// / http:// proxy link. Tolerant of several shapes:
 *   scheme://host:port#name
 *   scheme://user:pass@host:port#name
 *   scheme://base64(user:pass)@host:port#name
 *   scheme://base64(user:pass@host:port)#name
 */
function parseProxyLink(link, proto) {
  const scheme = link.slice(0, link.indexOf('://') + 3);
  const body = link.slice(scheme.length);
  const hashIdx = body.indexOf('#');
  const name = hashIdx === -1 ? '' : safeDecodeURIComponent(body.slice(hashIdx + 1));
  let main = hashIdx === -1 ? body : body.slice(0, hashIdx);
  const qIdx = main.indexOf('?');
  if (qIdx !== -1) main = main.slice(0, qIdx);   // ignore any query params

  let user = '', pass = '', address, portStr;

  const splitCreds = (raw) => {
    const ci = raw.indexOf(':');
    if (ci === -1) { user = raw; pass = ''; }
    else { user = raw.slice(0, ci); pass = raw.slice(ci + 1); }
  };

  if (main.includes('@')) {
    const atIdx = main.lastIndexOf('@');
    const userInfo = main.slice(0, atIdx);
    const hostPart = main.slice(atIdx + 1);
    // userInfo may be plain "user:pass" or a base64 of it
    const decoded = userInfo.includes(':') ? userInfo : (b64decode(userInfo) || userInfo);
    splitCreds(decoded);
    [address, portStr] = splitHostPort(hostPart);
  } else {
    // whole thing may be base64(user:pass@host:port) or just host:port
    const decoded = b64decode(main);
    if (decoded && decoded.includes('@')) {
      const atIdx = decoded.lastIndexOf('@');
      splitCreds(decoded.slice(0, atIdx));
      [address, portStr] = splitHostPort(decoded.slice(atIdx + 1));
    } else {
      [address, portStr] = splitHostPort(main);
    }
  }
  const port = parseInt(portStr, 10) || (proto === 'http' ? 8080 : 1080);
  const outbound = buildProxyOutbound(proto, address, port, safeDecodeURIComponent(user), safeDecodeURIComponent(pass));
  return mkServer(name || address, proto, address, port, link, outbound);
}

function parseSocks(link) { return parseProxyLink(link, 'socks'); }
function parseHttpProxy(link) { return parseProxyLink(link, 'http'); }

/**
 * Create a SOCKS/HTTP proxy server record from a UI form (no share link).
 * fields: { name, type:'socks'|'http', address, port, username, password }
 */
function makeProxyServer(fields) {
  const type = (fields.type === 'http') ? 'http' : 'socks';
  const address = String(fields.address || '').trim();
  const port = parseInt(fields.port, 10) || (type === 'http' ? 8080 : 1080);
  const user = String(fields.username || '').trim();
  const pass = String(fields.password || '').trim();
  const outbound = buildProxyOutbound(type, address, port, user, pass);
  const raw = `${type}://${address}:${port}`;
  return mkServer(fields.name || address || type.toUpperCase(), type, address, port, raw, outbound);
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
  } else if (proto === 'socks' || proto === 'http') {
    const srv = ob.settings && ob.settings.servers && ob.settings.servers[0];
    if (srv) {
      srv.address = addr; srv.port = port;
      if (f.username != null || f.password != null) {
        const u = (f.username || '').trim();
        const p = (f.password || '').trim();
        if (u || p) srv.users = [{ user: u, pass: p }];
        else delete srv.users;
      }
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

  // TLS fragmentation (packets,length,interval). Empty clears it.
  if (f.fragment != null) {
    const fr = String(f.fragment).trim();
    if (fr) ob._fragment = fr; else delete ob._fragment;
  }
  // Anti-DPI noise / fake ClientHello injection. Empty clears it.
  if (f.noise != null) {
    const nz = String(f.noise).trim();
    if (nz) ob._noise = nz; else delete ob._noise;
  }
  // Fake/decoy SNI domain injected as a fake ClientHello. Empty clears it.
  if (f.fakeSni != null) {
    const fs = String(f.fakeSni).trim();
    if (fs) ob._fakesni = fs; else delete ob._fakesni;
  }
  // Per-config core selection. 'xray' (default) or empty clears it.
  if (f.engine != null) {
    const eng = String(f.engine).trim();
    if (eng && eng !== 'xray') out.engine = eng; else delete out.engine;
  }

  return out;
}

/** Rebuild streamSettings (transport/security) from edit fields, when supplied. */
function rebuildStream(ob, f) {
  if (!ob.streamSettings) return;
  const cur = ob.streamSettings;
  // Only rebuild if the user touched transport/security fields.
  const touched = ['network', 'security', 'sni', 'path', 'host', 'allowInsecure', 'fp', 'pbk', 'sid', 'serviceName', 'alpn', 'cipherSuites', 'finalMask']
    .some(k => f[k] != null && f[k] !== '');
  if (!touched) return;

  // Fields the edit form doesn't expose but must survive a rebuild (otherwise
  // editing anything would silently break the config): reality spiderX, xhttp
  // mode, kcp seed/headerType, grpc multiMode.
  const rs = cur.realitySettings || {};
  const xs = cur.xhttpSettings || {};
  const ks = cur.kcpSettings || {};
  const gs = cur.grpcSettings || {};

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
    allowInsecure: f.allowInsecure ? '1' : '0',
    // preserved passthroughs
    spx: rs.spiderX || '',
    mode: xs.mode || (gs.multiMode ? 'multi' : ''),
    seed: ks.seed || '',
    headerType: (ks.header && ks.header.type) || '',
    // patterniha: cipherSuites (tls) + finalMask (stream). Edited value wins,
    // else keep whatever the config already had.
    cipherSuites: f.cipherSuites != null ? f.cipherSuites : ((cur.tlsSettings && cur.tlsSettings.cipherSuites) || ''),
    finalMask: f.finalMask != null ? f.finalMask : (cur.finalmask ? JSON.stringify(cur.finalmask) : '')
  };
  const rebuilt = buildStreamSettings(q);

  // Carry over any transport `extra`/advanced sub-keys the builder doesn't model
  // (e.g. xhttp scMaxEachPostBytes / uplink method / padding) so they persist.
  if (rebuilt.xhttpSettings && xs.extra) rebuilt.xhttpSettings.extra = xs.extra;

  ob.streamSettings = rebuilt;
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
  if (l.startsWith('socks://') || l.startsWith('socks5://')) return parseSocks(l);
  if (l.startsWith('wireguard://') || l.startsWith('wg://')) return parseWireguard(l);
  // case-insensitive to match HTTP_PROXY_LINK's /i (and parseMany's line filter),
  // so an uppercase scheme imports instead of being reported as an error
  if (/^http:\/\//i.test(l) && isHttpProxyLink(l)) return parseHttpProxy(l);
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
  if (!/^(vless|vmess|trojan|ss|socks|socks5|wireguard|wg):\/\//im.test(body)) {
    const decoded = b64decode(body);
    if (/^(vless|vmess|trojan|ss|socks|socks5|wireguard|wg):\/\//im.test(decoded)) body = decoded;
  }

  const lines = body.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
  const servers = [];
  const errors = [];
  for (const line of lines) {
    if (!/^(vless|vmess|trojan|ss|socks|socks5|wireguard|wg):\/\//i.test(line) && !isHttpProxyLink(line)) continue;
    try {
      servers.push(parseLink(line));
    } catch (e) {
      errors.push({ line, error: e.message });
    }
  }
  return { servers, errors };
}

/* ===================== build share link (export) ===================== */
const enc = (v) => encodeURIComponent(String(v));

// streamSettings -> flat query params (inverse of buildStreamSettings), so a
// copied/QR'd link carries EVERY setting (incl. patterniha finalMask/cipherSuites).
function streamToQuery(st) {
  const q = {};
  if (!st) return q;
  const net = st.network || 'tcp';
  q.type = net;
  q.security = st.security || 'none';
  if (net === 'ws' && st.wsSettings) { q.path = st.wsSettings.path || ''; q.host = (st.wsSettings.headers && (st.wsSettings.headers.Host || st.wsSettings.headers.host)) || ''; }
  else if (net === 'grpc' && st.grpcSettings) { q.serviceName = st.grpcSettings.serviceName || ''; if (st.grpcSettings.multiMode) q.mode = 'multi'; }
  else if ((net === 'h2' || net === 'http') && st.httpSettings) { q.path = st.httpSettings.path || ''; q.host = (st.httpSettings.host || []).join(','); }
  else if (net === 'xhttp' && st.xhttpSettings) { q.path = st.xhttpSettings.path || ''; q.host = st.xhttpSettings.host || ''; if (st.xhttpSettings.mode) q.mode = st.xhttpSettings.mode; }
  else if (net === 'kcp' && st.kcpSettings) { q.headerType = (st.kcpSettings.header && st.kcpSettings.header.type) || 'none'; if (st.kcpSettings.seed) q.seed = st.kcpSettings.seed; }
  else if (net === 'tcp' && st.tcpSettings && st.tcpSettings.header && st.tcpSettings.header.type === 'http') {
    q.headerType = 'http'; const rq = st.tcpSettings.header.request || {};
    q.path = (rq.path && rq.path[0]) || ''; q.host = (rq.headers && rq.headers.Host && rq.headers.Host[0]) || '';
  }
  const tls = st.tlsSettings, rl = st.realitySettings;
  if (tls) { q.sni = tls.serverName || ''; q.fp = tls.fingerprint || ''; if (tls.allowInsecure) q.allowInsecure = '1'; if (tls.alpn) q.alpn = Array.isArray(tls.alpn) ? tls.alpn.join(',') : tls.alpn; if (tls.cipherSuites) q.cipherSuites = tls.cipherSuites; }
  if (rl) { q.sni = rl.serverName || ''; q.fp = rl.fingerprint || ''; q.pbk = rl.publicKey || ''; q.sid = rl.shortId || ''; if (rl.spiderX) q.spx = rl.spiderX; }
  if (st.finalmask) q.finalMask = JSON.stringify(st.finalmask);
  return q;
}

const qs = (o) => Object.keys(o).filter(k => o[k] !== undefined && o[k] !== null && o[k] !== '').map(k => `${k}=${enc(o[k])}`).join('&');

/** Serialize a server (with ALL its settings) back into a shareable link. */
function buildShareLink(server) {
  const ob = server.outbound || {};
  const proto = server.protocol;
  const name = server.name ? '#' + enc(server.name) : '';
  const extras = {};
  if (ob._fragment) extras.fragment = ob._fragment;
  if (ob._noise) extras.noise = ob._noise;
  if (ob._fakesni) extras.fakeSni = ob._fakesni;
  if (server.engine && server.engine !== 'xray') extras.engine = server.engine;

  if (proto === 'vless') {
    const u = ob.settings.vnext[0].users[0];
    const q = Object.assign({ encryption: u.encryption || 'none' }, streamToQuery(ob.streamSettings), extras);
    if (u.flow) q.flow = u.flow;
    return `vless://${u.id}@${server.address}:${server.port}?${qs(q)}${name}`;
  }
  if (proto === 'trojan') {
    const srv = ob.settings.servers[0];
    const q = Object.assign({}, streamToQuery(ob.streamSettings), extras);
    return `trojan://${enc(srv.password)}@${server.address}:${server.port}?${qs(q)}${name}`;
  }
  if (proto === 'vmess') {
    const u = ob.settings.vnext[0].users[0]; const p = streamToQuery(ob.streamSettings);
    const v = { v: '2', ps: server.name || '', add: server.address, port: String(server.port), id: u.id, aid: String(u.alterId || 0), scy: u.security || 'auto',
      net: p.type || 'tcp', type: p.headerType || 'none', host: p.host || '', path: p.path || p.serviceName || '', tls: p.security === 'tls' ? 'tls' : '', sni: p.sni || '', fp: p.fp || '', alpn: p.alpn || '' };
    if (p.cipherSuites) v.cipherSuites = p.cipherSuites;
    if (p.finalMask) v.finalMask = p.finalMask;
    if (extras.fragment) v.fragment = extras.fragment;
    if (extras.noise) v.noise = extras.noise;
    if (extras.fakeSni) v.fakesni = extras.fakeSni;
    if (extras.engine) v.engine = extras.engine;
    return 'vmess://' + Buffer.from(JSON.stringify(v)).toString('base64');
  }
  if (proto === 'shadowsocks') {
    const srv = ob.settings.servers[0];
    return `ss://${Buffer.from(`${srv.method}:${srv.password}`).toString('base64')}@${server.address}:${server.port}${name}`;
  }
  if (proto === 'socks' || proto === 'http') {
    const srv = ob.settings.servers[0]; const c = srv.users && srv.users[0];
    const auth = c ? Buffer.from(`${c.user || ''}:${c.pass || ''}`).toString('base64') + '@' : '';
    return `${proto}://${auth}${server.address}:${server.port}${name}`;
  }
  return server.raw || '';   // wireguard / unknown: fall back to the imported link
}

module.exports = {
  parseLink, parseMany, b64decode, isHttpProxyLink,
  buildStreamSettings, buildWireguardOutbound, makeWireguardServer, makeProxyServer, applyServerEdits,
  buildShareLink
};
