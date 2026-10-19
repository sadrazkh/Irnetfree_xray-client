'use strict';
/**
 * Cloudflare WARP (v1.25.0 MASQUE, v1.26.0 WireGuard): a WARP device registered
 * from the app — or one brought in (usque's config.json or an Xray WARP
 * outbound for MASQUE; a WireGuard .conf or wireguard:// link) — and the
 * editor's fields for parser.createServer: one MASQUE server per HTTP version,
 * or one WireGuard server, alone or as the exit of a chain over a config the
 * user already has. Several accounts in one go, each with a WARP+ key or
 * none, and what Cloudflare says of each account kept on its servers
 * (`server.warp`). Desktop (main.js) and the router (service.js) share all of
 * it. .superpowers/sdd/masque/design.md §5 and warp-wg/design.md (git-ignored).
 *
 *   registerWarp({ license, request, now, log })    → reg (MASQUE, below)
 *   registerWarpWg({ license, request, now, log })  → reg (WireGuard)
 *   importWarp(text)                                → reg (MASQUE)
 *   warpServers(reg, { http, endpoint, address, cover, antiDpi, name }) → [fields]   (pure)
 *   wgServerFields(reg, opts, name)                 → fields                        (pure)
 *   warpHandler(deps)                               → the servers:addWarp handler
 *
 *   reg = { privateKey (MASQUE: PKCS#8 PEM; WireGuard: base64 X25519), publicKey,
 *           address: [v4/32, v6/128], endpoints, reserved (WireGuard),
 *           account: { id, type, warpPlus }, info (AccountInfo), warnings: [{ code, message }] }
 *
 * The device key is made HERE and never leaves the machine except to the core;
 * Cloudflare gets its public half. The API token is used for the calls of one
 * registration and then dropped. Neither is ever logged, nor put in an error,
 * nor is a WARP+ key: whatever Cloudflare says back is scrubbed of all three.
 */
const crypto = require('crypto');
const http = require('http');
const net = require('net');
const tls = require('tls');
const { socks5Connect } = require('./netutils');

/**
 * The API as the official Android client 6.38.9 speaks it — wgcf 2.3.0's values,
 * the release that got past the 429s on POST /reg: that refusal follows the TLS
 * ClientHello (wgcf #613/#626), and a TLS 1.2 hello with ALPN http/1.1 is the
 * shape that got through. One place, so the next client version is one edit.
 */
const API = {
  host: 'api.cloudflareclient.com',
  port: 443,
  version: 'v0a5641',
  clientVersion: 'a-6.38.9-5641',
  userAgent: '1.1.1.1/6.38.9-5641 (Android 16.0.0)',
  contentType: 'application/json; charset=UTF-8',
  tls: { minVersion: 'TLSv1.2', maxVersion: 'TLSv1.2', ALPNProtocols: ['http/1.1'] },
  timeoutMs: 20000
};
const MAX_ANSWER = 512 * 1024;

/**
 * usque's registration body (api/cloudflare.go): an X25519 key — a throwaway
 * one the MASQUE key replaces at once, or the WireGuard device's own (`key`) —,
 * `tos` the moment the user accepted the terms (pressing «ساختن» is that), a
 * random 16-hex serial.
 */
function regBody(now, key) {
  const x = key ? null : crypto.generateKeyPairSync('x25519').publicKey.export({ type: 'spki', format: 'der' });
  return {
    key: key || x.subarray(x.length - 32).toString('base64'),
    install_id: '',
    fcm_token: '',
    tos: new Date(now()).toISOString(),
    model: 'PC',
    serial_number: crypto.randomBytes(8).toString('hex'),
    os_version: '',
    key_type: 'curve25519',
    tunnel_type: 'wireguard',
    locale: 'en_US'
  };
}

/** Cloudflare's MASQUE edges when a record names none: H3 from the record, H2 the fixed .2 pair (.1 is a plain CDN edge on TCP). */
const DEFAULT_ENDPOINTS = { h3v4: '162.159.198.1', h3v6: '2606:4700:103::1', h2v4: '162.159.198.2', h2v6: '2606:4700:103::2' };
/** The name the official client sends; a cover domain replaces it. */
const WARP_SNI = 'consumer-masque.cloudflareclient.com';
/** Anti-DPI per HTTP version: the lightest noise preset for QUIC, the app's Hide-SNI fragment (app.js HIDE_SNI_FRAGMENT) for TCP. */
const ANTI_DPI = { noise: 'random', fragment: 'tlshello,100-200,10-20' };
/** A WARP+ key: three groups of eight. */
const LICENSE_RE = /^[A-Za-z0-9]{8}-[A-Za-z0-9]{8}-[A-Za-z0-9]{8}$/;
/** A domain name with a dot and a non-numeric last label (so no IP passes for one). */
const HOST_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;

/** Cloudflare's WireGuard edge when a record names none, and its port (2408; 500, 1701, 4500 answer too). */
const WG_ENDPOINTS = { v4: '162.159.192.1', v6: '2606:4700:d0::a29f:c001' };
const WG_PORT = 2408;
/** WARP's own MTU — and room for the hop a chained WARP rides inside. */
const WG_MTU = 1280;
/** Accounts in one go, and the pause between two sign-ups (they are rate-limited). */
const MAX_ACCOUNTS = 10;
const PAUSE_MS = 2000;
const ACCOUNT_TYPES = ['free', 'limited', 'unlimited', 'team'];
const BASE_NAME = '☁ WARP';

/** The codes the window translates (`warp.err.<code>`, `warp.warn.<code>` in i18n.js). */
const ERROR_CODES = ['rateLimited', 'blocked', 'rejected', 'notConnected', 'badLicense', 'badAnswer', 'badImport',
  'badCover', 'badAddress', 'busy', 'createFailed', 'failed', 'badHop', 'badConf'];
const WARNING_CODES = ['warpNotEnabled', 'licenseFailed', 'accountUnread'];

class WarpError extends Error {
  /** `detail`: Cloudflare's own words, already scrubbed — what the window shows in `{msg}`. */
  constructor(code, message, detail) {
    super(message);
    this.name = 'WarpError';
    this.code = code;
    if (detail) this.detail = detail;
  }
}

const isPlain = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const str = (v) => (v == null ? '' : String(v).trim());
const pemBody = (pem) => String(pem).replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');

/** `text` with every secret cut out (an answer that repeats the token, say). */
function scrub(text, secrets) {
  let s = String(text == null ? '' : text);
  for (const secret of secrets || []) {
    const v = str(secret);
    if (v.length < 8) continue;
    s = s.split(v).join('…');
  }
  return s;
}

/** A failure on the way to the API, in the window's terms. */
function netError(e, host) {
  if (e instanceof WarpError) return e;
  const why = (e && (e.code || e.message)) || 'unknown error';
  return new WarpError('blocked', `Could not reach ${host}: ${why}`, String(why));
}

/* --------------------------------- the transport --------------------------------- */
/**
 * The real request: HTTPS to the API with the ClientHello above, straight out
 * (`via: 'direct'`) or through the app's own running SOCKS inbound (`via:
 * 'proxy'`, `socksPort`) the way the remote agent and the IP check reach
 * through it (netutils.socks5Connect: the name goes to the proxy, nothing is
 * looked up here). The certificate is checked as any HTTPS client checks it.
 *
 * Returns request({ method, path, headers, body }) → { status, body }. A
 * connection refused by the local proxy is `notConnected`; everything else on
 * the way — refused, reset, a certificate that is not the API's, no answer in
 * time — is `blocked`. `host`, `port`, `connectHost` and `ca` are for tests
 * (a local fake API); the app passes none of them.
 */
function makeRequest(opts = {}) {
  const host = opts.host || API.host;
  const port = opts.port || API.port;
  const via = opts.via === 'proxy' ? 'proxy' : 'direct';
  const socksPort = parseInt(opts.socksPort, 10) || 0;
  const timeoutMs = opts.timeoutMs || API.timeoutMs;
  const tlsOpts = Object.assign({ servername: host }, API.tls, opts.ca ? { ca: opts.ca } : {});

  // `track` gets each socket as it is made, so a timeout can close one still shaking hands
  const secure = (sock, track) => new Promise((resolve, reject) => {
    track(sock);
    const onError = (e) => { sock.destroy(); reject(e); };
    sock.once('error', onError);
    sock.once('secureConnect', () => { sock.removeListener('error', onError); resolve(sock); });
  });
  function open(track) {
    if (via === 'direct') return secure(tls.connect(Object.assign({ host: opts.connectHost || host, port }, tlsOpts)), track);
    if (!socksPort) return Promise.reject(new WarpError('notConnected', 'The app has no local proxy port to register through'));
    return socks5Connect('127.0.0.1', socksPort, host, port, timeoutMs).then(
      (raw) => { track(raw); return secure(tls.connect(Object.assign({ socket: raw }, tlsOpts)), track); },
      (e) => {
        if (e && e.code === 'ECONNREFUSED') throw new WarpError('notConnected', `Nothing answers on the app's proxy port ${socksPort}: the app is not connected`);
        throw e;
      });
  }

  return function request({ method, path, headers, body }) {
    return new Promise((resolve, reject) => {
      const socks = [];
      let done = false;
      const finish = (err, val) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        for (const s of socks) s.destroy();
        if (err) reject(netError(err, host)); else resolve(val);
      };
      const track = (s) => { if (done) s.destroy(); else socks.push(s); };
      const after = timeoutMs >= 1000 ? Math.round(timeoutMs / 1000) + ' s' : timeoutMs + ' ms';
      const timer = setTimeout(() => finish(new WarpError('blocked', `No answer from ${host}: timed out after ${after}`, 'timed out after ' + after)), timeoutMs);
      let opening;
      try { opening = open(track); } catch (e) { opening = Promise.reject(e); }   // tls.connect can throw at once
      opening.then((s) => {
        if (done) { s.destroy(); return; }
        const payload = body == null ? null : Buffer.from(String(body), 'utf8');
        const h = Object.assign({ Host: host }, headers, { Connection: 'close' }, payload ? { 'Content-Length': payload.length } : {});
        const req = http.request({ method, path, headers: h, createConnection: () => s });
        req.on('error', (e) => finish(e));
        req.on('response', (res) => {
          const chunks = [];
          let size = 0;
          res.on('data', (c) => {
            size += c.length;
            if (size > MAX_ANSWER) finish(new WarpError('badAnswer', 'Cloudflare\'s answer is too large'));
            else chunks.push(c);
          });
          res.on('end', () => finish(null, { status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
          res.on('error', (e) => finish(e));
        });
        req.end(payload || undefined);
      }, (e) => finish(e));
    });
  };
}

/** What Cloudflare said in a refusal: its `errors[].message`, else a short line of plain text (an HTML page says nothing useful). */
function cfMessage(json, text) {
  if (isPlain(json)) {
    if (Array.isArray(json.errors) && json.errors.length) {
      const m = json.errors.map((e) => (isPlain(e) ? str(e.message) : str(e))).filter(Boolean).join('; ');
      if (m) return m.slice(0, 300);
    }
    if (typeof json.message === 'string' && json.message.trim()) return json.message.trim().slice(0, 300);
    if (typeof json.error === 'string' && json.error.trim()) return json.error.trim().slice(0, 300);
    if (isPlain(json.error) && str(json.error.message)) return str(json.error.message).slice(0, 300);
  }
  const t = str(text);
  if (!t || /^</.test(t)) return '';
  return t.replace(/\s+/g, ' ').slice(0, 200);
}

/**
 * One API call: the headers, the version prefix, the status mapped. Resolves
 * the answer's JSON object — `{}` for an empty one when `empty` allows it (PUT
 * …/account may answer 204), the array when `list` asks for one.
 */
async function call(request, method, path, { token, body, step, secrets, empty, list }) {
  const headers = { 'User-Agent': API.userAgent, 'CF-Client-Version': API.clientVersion, Accept: 'application/json', 'Accept-Encoding': 'identity' };
  if (body !== undefined) headers['Content-Type'] = API.contentType;
  if (token) headers.Authorization = 'Bearer ' + token;
  let res;
  try {
    res = await request({ method, path: `/${API.version}${path}`, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  } catch (e) {
    const err = netError(e, API.host);
    throw new WarpError(err.code, scrub(err.message, secrets), err.detail && scrub(err.detail, secrets));
  }
  const status = Number(res && res.status) || 0;
  const text = res && res.body != null ? String(res.body) : '';
  let json = null;
  try { json = JSON.parse(text); } catch { /* said below */ }
  if (status === 429) throw new WarpError('rateLimited', `Cloudflare answered 429 (too many requests) to the ${step}`);
  if (status < 200 || status > 299) {
    const detail = scrub(cfMessage(json, text), secrets);
    throw new WarpError('rejected', `Cloudflare refused the ${step} (${status || 'no status'})${detail ? ': ' + detail : ''}`, detail);
  }
  if (empty && (status === 204 || !text.trim())) return {};
  if (list) {
    if (!Array.isArray(json)) throw new WarpError('badAnswer', `Cloudflare's answer to the ${step} is not a list`);
    return json;
  }
  if (!isPlain(json)) throw new WarpError('badAnswer', `Cloudflare's answer to the ${step} is not JSON`);
  return json;
}

/* ---------------------------------- the account ---------------------------------- */
const numberOf = (v) => (typeof v === 'number' && Number.isFinite(v) && v >= 0 ? v
  : (typeof v === 'string' && /^\d{1,20}$/.test(v.trim()) ? Number(v) : null));

/**
 * What the window and the server's card show of an account (`server.warp`):
 * Cloudflare's account object, read as it is — premium_data, quota and usage
 * in bytes under their own names (their meaning is not documented) — plus how
 * the WARP+ key went and the devices it is on. Never the key itself: its last
 * four characters say which one it was.
 */
function accountInfo(kind, deviceId, acc, extra, now) {
  const a = isPlain(acc) ? acc : {};
  const type = str(a.account_type).toLowerCase();
  const role = str(a.role).toLowerCase();
  return Object.assign({
    kind,
    deviceId: str(deviceId),
    type: ACCOUNT_TYPES.includes(type) ? type : '',
    warpPlus: a.warp_plus === true,
    premiumData: numberOf(a.premium_data),
    quota: numberOf(a.quota),
    usage: numberOf(a.usage),
    role: role === 'parent' || role === 'child' ? role : '',
    referralCount: numberOf(a.referral_count),
    devices: null,
    license: 'none',
    licenseTail: '',
    licenseError: '',
    checkedAt: new Date((now || Date.now)()).toISOString()
  }, extra);
}

/**
 * A registered device's account, both kinds: the WARP+ key when there is one
 * (PUT …/account; a refusal is a warning — the device exists by then, and a
 * free account beats none), then the account and its devices read back. A
 * read that fails is a warning too: the servers work without it.
 */
async function accountStep({ request, dev, token, license, secrets, say, warnings, base, kind, id, now }) {
  let acc = isPlain(base) ? base : {};
  const extra = {};
  if (license) {
    extra.licenseTail = license.slice(-4);
    try {
      const put = await call(request, 'PUT', dev + '/account', { token, body: { license }, step: 'WARP+ license', secrets, empty: true });
      acc = Object.assign({}, acc, put);
      extra.license = 'applied';
      say(`WARP: the WARP+ key …${extra.licenseTail} is applied`);
    } catch (e) {
      const why = scrub(e.detail || e.message, secrets);
      extra.license = 'refused';
      extra.licenseError = why;
      warnings.push({ code: 'licenseFailed', cause: e.code, message: why });
      say(`WARP: the WARP+ key …${extra.licenseTail} was not applied — ` + why, 'warn');
    }
  }
  const unread = [];
  try {
    acc = Object.assign({}, acc, await call(request, 'GET', dev + '/account', { token, step: 'account', secrets }));
  } catch (e) { unread.push(scrub(e.detail || e.message, secrets)); }
  try {
    extra.devices = (await call(request, 'GET', dev + '/account/devices', { token, step: 'account devices', secrets, list: true })).length;
  } catch (e) { unread.push(scrub(e.detail || e.message, secrets)); }
  if (unread.length) {
    warnings.push({ code: 'accountUnread', message: unread.join('; ') });
    say('WARP: the account could not be read in full — ' + unread.join('; '), 'warn');
  }
  const info = accountInfo(kind, id, acc, extra, now);
  say(`WARP: the account is ${info.type || 'of an unknown type'}${info.warpPlus ? ' (WARP+)' : ''}`);
  return info;
}

/* ------------------------------ keys, addresses, endpoints ------------------------------ */
/** A P-256 private key (PEM or base64, PKCS#8 or SEC1) as PKCS#8 PEM; null when it is not one. */
function privatePem(v) {
  const s = str(v);
  if (!s) return null;
  let k = null;
  if (/-----BEGIN/.test(s)) {
    try { k = crypto.createPrivateKey(s); } catch { k = null; }
  } else {
    const der = Buffer.from(s.replace(/\s+/g, ''), 'base64');
    for (const type of ['pkcs8', 'sec1']) {
      try { k = crypto.createPrivateKey({ key: der, format: 'der', type }); break; } catch { k = null; }
    }
  }
  if (!k || k.asymmetricKeyType !== 'ec' || !k.asymmetricKeyDetails || k.asymmetricKeyDetails.namedCurve !== 'prime256v1') return null;
  return k.export({ type: 'pkcs8', format: 'pem' });
}

/** The edge's P-256 public key (PEM or base64 SPKI) as PEM; null when it is not one. */
function publicPem(v) {
  const s = str(v);
  if (!s) return null;
  try {
    const k = /-----BEGIN/.test(s)
      ? crypto.createPublicKey(s)
      : crypto.createPublicKey({ key: Buffer.from(s.replace(/\s+/g, ''), 'base64'), format: 'der', type: 'spki' });
    if (k.asymmetricKeyType !== 'ec' || !k.asymmetricKeyDetails || k.asymmetricKeyDetails.namedCurve !== 'prime256v1') return null;
    return k.export({ type: 'spki', format: 'pem' });
  } catch { return null; }
}

/** The device's addresses: at most one v4 (/32 unless given) and one v6 (/128); null when one is not an address. */
function addressList(values) {
  const out = { 4: null, 6: null };
  for (const v of values) {
    const s = str(v);
    if (!s) continue;
    const [ip, prefix] = s.split('/');
    const fam = net.isIP(ip);
    if (!fam) return null;
    const max = fam === 4 ? 32 : 128;
    if (prefix != null && !(/^\d+$/.test(prefix) && Number(prefix) <= max)) return null;
    if (!out[fam]) out[fam] = `${ip}/${prefix != null ? prefix : max}`;
  }
  return [out[4], out[6]].filter(Boolean);
}

/** `162.159.198.1:0`, `[2606:4700:103::1]:0` or a bare IP → the IP, when it is of `family`; else ''. */
function hostOf(value, family) {
  let s = str(value);
  if (!s) return '';
  if (s[0] === '[') {
    const end = s.indexOf(']');
    s = end > 0 ? s.slice(1, end) : '';
  } else if (net.isIP(s) !== 6) {
    const i = s.lastIndexOf(':');
    if (i > -1 && s.indexOf(':') === i) s = s.slice(0, i);
  }
  return net.isIP(s) === family ? s : '';
}

/** A device record (the enroll, activation or GET answer) → the registration's key, addresses, endpoints. */
function fromRecord(rec) {
  const cfg = isPlain(rec.config) ? rec.config : {};
  const peer = (Array.isArray(cfg.peers) && isPlain(cfg.peers[0])) ? cfg.peers[0] : null;
  if (!peer) throw new WarpError('badAnswer', 'Cloudflare\'s device record has no endpoint (config.peers is empty)');
  const publicKey = publicPem(peer.public_key);
  if (!publicKey) throw new WarpError('badAnswer', 'Cloudflare\'s device record has no readable endpoint key (config.peers[0].public_key)');
  const a = (isPlain(cfg.interface) && isPlain(cfg.interface.addresses)) ? cfg.interface.addresses : {};
  const address = addressList([a.v4, a.v6]);
  if (!address || !address.length) throw new WarpError('badAnswer', 'Cloudflare\'s device record has no usable address (config.interface.addresses)');
  const ep = isPlain(peer.endpoint) ? peer.endpoint : {};
  return {
    publicKey,
    address,
    endpoints: {
      h3v4: hostOf(ep.v4, 4) || DEFAULT_ENDPOINTS.h3v4,
      h3v6: hostOf(ep.v6, 6) || DEFAULT_ENDPOINTS.h3v6,
      h2v4: DEFAULT_ENDPOINTS.h2v4,
      h2v6: DEFAULT_ENDPOINTS.h2v6
    }
  };
}

const peersOf = (rec) => (isPlain(rec) && isPlain(rec.config) && Array.isArray(rec.config.peers) ? rec.config.peers : []);

/* --------------------------------- registering --------------------------------- */
/**
 * A new WARP device for MASQUE (design §5):
 *   1. a P-256 key pair, made here;
 *   2. POST /reg (usque's body) → the device id and its token;
 *   3. PATCH /reg/{id} { key: base64 SPKI, key_type secp256r1, tunnel_type masque };
 *   4. when the answer does not say warp_enabled: PATCH { warp_enabled: true }, and
 *      check it — a device left off is refused by the edge ("tls: access denied");
 *      an answer without peers is no failure (the key IS enrolled): GET the record;
 *   5. with a WARP+ license: PUT /reg/{id}/account { license };
 *   6. the record → the edge key, the addresses, the endpoints.
 * A device that stays off and a license Cloudflare refuses are warnings: the
 * device exists by then, and a free account beats none (another try costs a
 * registration, and those are rate-limited).
 */
async function registerWarp(opts = {}) {
  const request = opts.request || makeRequest();
  const now = opts.now || Date.now;
  const log = typeof opts.log === 'function' ? opts.log : () => {};
  const license = str(opts.license);
  if (license && !LICENSE_RE.test(license)) throw new WarpError('badLicense', 'A WARP+ license looks like xxxxxxxx-xxxxxxxx-xxxxxxxx');

  const secrets = license ? [license] : [];
  const say = (line, level) => { try { log(scrub(line, secrets), level || 'info'); } catch { /* a log never fails a sign-up */ } };

  const pair = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const privateKey = pair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  secrets.push(privateKey, pemBody(privateKey), pair.privateKey.export({ type: 'sec1', format: 'der' }).toString('base64'));
  const enrollKey = pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');

  say('WARP: registering a new device with Cloudflare…');
  const made = await call(request, 'POST', '/reg', { body: regBody(now), step: 'registration', secrets });
  const id = str(made.id);
  const token = str(made.token);
  if (!id || !token) throw new WarpError('badAnswer', 'Cloudflare\'s registration answer has no device id or token');
  secrets.push(token);
  const dev = '/reg/' + encodeURIComponent(id);
  say(`WARP: device ${id} registered`);

  let rec = await call(request, 'PATCH', dev, { token, body: { key: enrollKey, key_type: 'secp256r1', tunnel_type: 'masque' }, step: 'MASQUE key enrollment', secrets });
  say('WARP: the device\'s MASQUE key (secp256r1) is enrolled');

  const warnings = [];
  if (rec.warp_enabled !== true) {
    const on = await call(request, 'PATCH', dev, { token, body: { warp_enabled: true }, step: 'activation (warp_enabled)', secrets });
    if (on.warp_enabled === true) {
      rec = peersOf(on).length ? on : Object.assign({}, rec, { warp_enabled: true });
      say('WARP: switched on for the device (warp_enabled)');
    } else {
      warnings.push({ code: 'warpNotEnabled', message: 'Cloudflare still reports warp_enabled: false for this device; the edge may answer "access denied"' });
      say('WARP: Cloudflare did not switch the device on (warp_enabled stays false) — the edge may refuse it', 'warn');
    }
  }
  if (!peersOf(rec).length) {
    say('WARP: the answer names no endpoint — reading the device record');
    const got = await call(request, 'GET', dev, { token, step: 'device record', secrets });
    rec = Object.assign({}, got, { warp_enabled: rec.warp_enabled === true || got.warp_enabled === true });
  }

  const base = isPlain(rec.account) ? rec.account : (isPlain(made.account) ? made.account : {});
  const info = await accountStep({ request, dev, token, license, secrets, say, warnings, base, kind: 'masque', id, now });

  const mapped = fromRecord(rec);
  say(`WARP: the device's addresses ${mapped.address.join(', ')}; HTTP/3 edge ${mapped.endpoints.h3v4}`);
  return {
    privateKey,
    publicKey: mapped.publicKey,
    address: mapped.address,
    endpoints: mapped.endpoints,
    account: { id, type: info.type, warpPlus: info.warpPlus },
    info,
    warnings
  };
}

/* ------------------------------ WireGuard (v1.26.0) ------------------------------ */
/** A WireGuard key: 32 bytes, base64. */
const isWgKey = (v) => /^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/.test(str(v));

/** `config.client_id` (base64) → its bytes: Xray's `reserved`, the three Cloudflare reads off each packet. */
function clientIdBytes(v) {
  const s = str(v);
  if (!s || !/^[A-Za-z0-9+/_-]+={0,2}$/.test(s)) return [];
  const b = Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  return b.length >= 1 && b.length <= 8 ? Array.from(b) : [];
}

/** A WireGuard device record → the peer's key, the addresses, the endpoints, `reserved`. */
function fromWgRecord(rec) {
  const cfg = isPlain(rec.config) ? rec.config : {};
  const peer = (Array.isArray(cfg.peers) && isPlain(cfg.peers[0])) ? cfg.peers[0] : null;
  if (!peer) throw new WarpError('badAnswer', 'Cloudflare\'s device record has no endpoint (config.peers is empty)');
  const publicKey = str(peer.public_key);
  if (!isWgKey(publicKey)) throw new WarpError('badAnswer', 'Cloudflare\'s device record has no WireGuard key (config.peers[0].public_key)');
  const a = (isPlain(cfg.interface) && isPlain(cfg.interface.addresses)) ? cfg.interface.addresses : {};
  const address = addressList([a.v4, a.v6]);
  if (!address || !address.length) throw new WarpError('badAnswer', 'Cloudflare\'s device record has no usable address (config.interface.addresses)');
  const ep = isPlain(peer.endpoint) ? peer.endpoint : {};
  return {
    publicKey,
    address,
    endpoints: { v4: hostOf(ep.v4, 4) || WG_ENDPOINTS.v4, v6: hostOf(ep.v6, 6) || WG_ENDPOINTS.v6 },
    reserved: clientIdBytes(cfg.client_id)
  };
}

/**
 * A new WARP device for WireGuard (wgcf's way):
 *   1. an X25519 key pair, made here;
 *   2. POST /reg with its public half (key_type curve25519, tunnel_type wireguard);
 *   3. warp_enabled switched on when the answer does not say it is — as for MASQUE;
 *   4. the WARP+ key, the account and its devices (accountStep);
 *   5. the record → the peer's key, the addresses, the endpoints, `reserved`.
 */
async function registerWarpWg(opts = {}) {
  const request = opts.request || makeRequest();
  const now = opts.now || Date.now;
  const log = typeof opts.log === 'function' ? opts.log : () => {};
  const license = str(opts.license);
  if (license && !LICENSE_RE.test(license)) throw new WarpError('badLicense', 'A WARP+ license looks like xxxxxxxx-xxxxxxxx-xxxxxxxx');

  const secrets = license ? [license] : [];
  const say = (line, level) => { try { log(scrub(line, secrets), level || 'info'); } catch { /* a log never fails a sign-up */ } };

  const pair = crypto.generateKeyPairSync('x25519');
  const priv = pair.privateKey.export({ type: 'pkcs8', format: 'der' });
  const pub = pair.publicKey.export({ type: 'spki', format: 'der' });
  const privateKey = priv.subarray(priv.length - 32).toString('base64');
  secrets.push(privateKey);
  const ownKey = pub.subarray(pub.length - 32).toString('base64');

  say('WARP: registering a new WireGuard device with Cloudflare…');
  const made = await call(request, 'POST', '/reg', { body: regBody(now, ownKey), step: 'registration', secrets });
  const id = str(made.id);
  const token = str(made.token);
  if (!id || !token) throw new WarpError('badAnswer', 'Cloudflare\'s registration answer has no device id or token');
  secrets.push(token);
  const dev = '/reg/' + encodeURIComponent(id);
  say(`WARP: device ${id} registered (WireGuard)`);

  const warnings = [];
  let rec = made;
  if (rec.warp_enabled !== true) {
    const on = await call(request, 'PATCH', dev, { token, body: { warp_enabled: true }, step: 'activation (warp_enabled)', secrets });
    if (on.warp_enabled === true) {
      rec = peersOf(on).length ? on : Object.assign({}, rec, { warp_enabled: true });
      say('WARP: switched on for the device (warp_enabled)');
    } else {
      warnings.push({ code: 'warpNotEnabled', message: 'Cloudflare still reports warp_enabled: false for this device; the edge may not answer' });
      say('WARP: Cloudflare did not switch the device on (warp_enabled stays false) — the edge may not answer', 'warn');
    }
  }
  if (!peersOf(rec).length) {
    say('WARP: the answer names no endpoint — reading the device record');
    const got = await call(request, 'GET', dev, { token, step: 'device record', secrets });
    rec = Object.assign({}, got, { warp_enabled: rec.warp_enabled === true || got.warp_enabled === true });
  }

  const base = isPlain(rec.account) ? rec.account : (isPlain(made.account) ? made.account : {});
  const info = await accountStep({ request, dev, token, license, secrets, say, warnings, base, kind: 'wireguard', id, now });

  const mapped = fromWgRecord(rec);
  say(`WARP: the device's addresses ${mapped.address.join(', ')}; edge ${mapped.endpoints.v4}:${WG_PORT}`);
  return {
    kind: 'wireguard',
    privateKey,
    publicKey: mapped.publicKey,
    address: mapped.address,
    endpoints: mapped.endpoints,
    reserved: mapped.reserved,
    account: { id, type: info.type, warpPlus: info.warpPlus },
    info,
    warnings
  };
}

/* ---------------------------------- importing ---------------------------------- */
const badImport = (why) => new WarpError('badImport', why);

/** usque's config.json (or the same keys pasted alone; mihomo's dashed spellings too). Its token is not carried. */
function fromUsque(j) {
  const privateKey = privatePem(j.private_key != null ? j.private_key : j['private-key']);
  if (!privateKey) throw badImport('private_key is not a P-256 (secp256r1) private key');
  const publicKey = publicPem(j.endpoint_pub_key || j.public_key || j['public-key']);
  if (!publicKey) throw badImport('endpoint_pub_key is missing or not a P-256 public key');
  const address = addressList([j.ipv4 || j.ip, j.ipv6]);
  if (!address || !address.length) throw badImport('ipv4 / ipv6 are missing or not addresses');
  return {
    privateKey,
    publicKey,
    address,
    endpoints: {
      h3v4: hostOf(j.endpoint_v4, 4) || DEFAULT_ENDPOINTS.h3v4,
      h3v6: hostOf(j.endpoint_v6, 6) || DEFAULT_ENDPOINTS.h3v6,
      h2v4: hostOf(j.endpoint_h2_v4, 4) || DEFAULT_ENDPOINTS.h2v4,
      h2v6: hostOf(j.endpoint_h2_v6, 6) || DEFAULT_ENDPOINTS.h2v6
    },
    account: { id: str(j.id), type: '', warpPlus: false },
    warnings: []
  };
}

const warpOf = (o) => {
  const ms = isPlain(o) && o.protocol === 'masque' && isPlain(o.streamSettings) && o.streamSettings.masqueSettings;
  return isPlain(ms) && isPlain(ms.warp) ? ms.warp : null;
};

/**
 * An Xray WARP outbound — alone, in a list, in a whole config (an IRNetFree
 * share JSON is one) — or the warp object by itself, or 3x-ui's registration
 * answer { privateKey, publicKey, address, endpoint }. Each masque outbound of
 * the same device names an endpoint for its HTTP version and address family.
 */
function fromXray(j) {
  let list = null;
  let warp = null;
  let endpoint = '';
  if (Array.isArray(j)) list = j;
  else if (isPlain(j) && Array.isArray(j.outbounds)) list = j.outbounds;
  else if (isPlain(j) && j.protocol) list = [j];
  else if (isPlain(j) && isPlain(j.warp)) warp = j.warp;
  else if (isPlain(j) && j.privateKey != null && j.publicKey != null) { warp = j; endpoint = str(j.endpoint); }
  const outs = list ? list.filter(warpOf) : [];
  if (outs.length) warp = warpOf(outs[0]);
  if (!warp) throw badImport('No WARP account in it: neither usque\'s private_key nor a masque outbound with masqueSettings.warp');

  const privateKey = privatePem(warp.privateKey);
  if (!privateKey) throw badImport('warp.privateKey is not a P-256 (secp256r1) private key');
  const publicKey = publicPem(warp.publicKey);
  if (!publicKey) throw badImport('warp.publicKey is missing or not a P-256 public key');
  const address = addressList([].concat(warp.address == null ? [] : warp.address));
  if (!address || !address.length) throw badImport('warp.address is missing or not addresses');

  const endpoints = {};
  const h3 = hostOf(endpoint, 4);
  if (h3) endpoints.h3v4 = h3;
  for (const o of outs) {
    if (str(warpOf(o).privateKey) !== str(warp.privateKey)) continue;   // another device's
    const addr = str(isPlain(o.settings) ? o.settings.address : '');
    const fam = net.isIP(addr) === 6 ? 6 : (net.isIP(addr) === 4 || HOST_RE.test(addr) ? 4 : 0);
    if (!fam) continue;
    const alpn = [].concat((o.streamSettings.tlsSettings || {}).alpn || []).map((x) => String(x).toLowerCase());
    const slot = (alpn.includes('h2') && !alpn.includes('h3') ? 'h2' : 'h3') + (fam === 6 ? 'v6' : 'v4');
    if (!endpoints[slot]) endpoints[slot] = addr;
  }
  return {
    privateKey,
    publicKey,
    address,
    endpoints: Object.assign({}, DEFAULT_ENDPOINTS, endpoints),
    account: { id: '', type: '', warpPlus: false },
    warnings: []
  };
}

/** A WARP account pasted in «وارد کردن حساب موجود»: usque's config.json, or Xray's WARP outbound / config. */
function importWarp(text) {
  const s = str(text);
  if (!s) throw badImport('Nothing was pasted');
  let j;
  try { j = JSON.parse(s); } catch { throw badImport('It is not JSON: paste usque\'s config.json or an Xray WARP outbound'); }
  if (isPlain(j) && (j.private_key != null || j['private-key'] != null)) return fromUsque(j);
  return fromXray(j);
}

/* ---------------------------------- the servers ---------------------------------- */
/** `ip`, `ip:port`, `[v6]:port`, a bare v6 or a domain → { host, port } (443, or `defaultPort`, when none is given); null when it is none of them. */
function parseEndpoint(v, defaultPort) {
  const s = str(v);
  if (!s || /[\s/@]/.test(s)) return null;
  let host;
  let port = defaultPort || 443;
  if (s[0] === '[') {
    const m = /^\[([^\]]+)\](?::(\d+))?$/.exec(s);
    if (!m || net.isIP(m[1]) !== 6) return null;
    host = m[1];
    if (m[2] != null) port = Number(m[2]);
  } else if (net.isIP(s) === 6) {
    host = s;
  } else {
    const m = /^([^:]+)(?::(\d+))?$/.exec(s);
    if (!m || !(net.isIP(m[1]) === 4 || HOST_RE.test(m[1]))) return null;
    host = m[1].toLowerCase();
    if (m[2] != null) port = Number(m[2]);
  }
  return port >= 1 && port <= 65535 ? { host, port } : null;
}

/** A cover domain as typed (a URL is forgiven) → the bare name, '' for none; badCover when it is no domain. */
function coverOf(v) {
  let s = str(v).toLowerCase();
  if (!s) return '';
  s = s.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/\.$/, '');
  if (!HOST_RE.test(s)) throw new WarpError('badCover', 'The cover domain must be a domain name, like www.example.com');
  return s;
}

/** The dialog's step 2, checked — before a registration, so a typo costs no device. */
function warpOptions(opts) {
  const o = opts || {};
  const h = str(o.http).toLowerCase();
  const e = str(o.endpoint).toLowerCase();
  const out = {
    http: ['h3', 'h2', 'both'].includes(h) ? h : 'both',
    endpoint: ['auto', 'v6', 'custom'].includes(e) ? e : 'auto',
    custom: null,
    cover: coverOf(o.cover),
    antiDpi: o.antiDpi !== false && o.antiDpi !== 'false',
    name: str(o.name)
  };
  if (out.endpoint === 'custom') {
    out.custom = parseEndpoint(o.address);
    if (!out.custom) throw new WarpError('badAddress', 'The endpoint must be an IP or a domain, with an optional port');
  }
  return out;
}

/**
 * The editor's fields for parser.createServer, one server per HTTP version
 * (H3 first): «☁ WARP · H3» on the record's H3 edge, «☁ WARP · H2» on the .2
 * edge — or both on the IPv6 pair, or on the user's own clean IP. The edge's
 * certificate is pinned by the WARP key, so the SNI is free: the official
 * client's name, or a cover domain — then serverName AND verifyPeerCertByName
 * are that name (the edge serves that site's real certificate, checked against
 * the core's roots; from Xray 26.10.10 a vcn replaces the WARP key check). The
 * host and path stay unset: the core's WARP defaults. Anti-DPI goes per HTTP
 * version: noise for QUIC, the Hide-SNI fragment for TCP.
 */
function warpServers(reg, opts) {
  const o = warpOptions(opts);
  const r = reg || {};
  if (!str(r.privateKey) || !str(r.publicKey) || !Array.isArray(r.address) || !r.address.length) {
    throw new WarpError('badAnswer', 'The WARP account lacks its keys or its addresses');
  }
  const ep = Object.assign({}, DEFAULT_ENDPOINTS);
  for (const [k, v] of Object.entries(isPlain(r.endpoints) ? r.endpoints : {})) if (str(v) && k in ep) ep[k] = str(v);
  const base = o.name || '☁ WARP';
  return (o.http === 'both' ? ['h3', 'h2'] : [o.http]).map((v) => {
    const f = {
      protocol: 'masque',
      name: `${base} · ${v.toUpperCase()}`,
      address: o.custom ? o.custom.host : ep[v + (o.endpoint === 'v6' ? 'v6' : 'v4')],
      port: o.custom ? o.custom.port : 443,
      masqueHttp: v,
      warpPrivateKey: r.privateKey,
      warpPublicKey: r.publicKey,
      warpAddress: r.address.join(', '),
      sni: o.cover || WARP_SNI
    };
    if (o.cover) f.vcn = o.cover;
    if (o.antiDpi) { if (v === 'h3') f.noise = ANTI_DPI.noise; else f.fragment = ANTI_DPI.fragment; }
    return f;
  });
}

/* ------------------------------ WireGuard servers ------------------------------ */
/** The window's WireGuard choices, checked — before a registration, so a typo costs no device. */
function wgOptions(opts) {
  const o = opts || {};
  const use = str(o.use).toLowerCase() === 'direct' ? 'direct' : 'chain';
  const e = str(o.endpoint).toLowerCase();
  const out = {
    use,
    chainWith: str(o.chainWith),
    // a chained WARP is dialled from the hop's server: Cloudflare's own edge, no clean IP, no noise
    endpoint: use === 'direct' && ['auto', 'v6', 'custom'].includes(e) ? e : 'auto',
    custom: null,
    antiDpi: use === 'direct' && o.antiDpi !== false && o.antiDpi !== 'false',
    name: str(o.name)
  };
  if (out.endpoint === 'custom') {
    out.custom = parseEndpoint(o.address, WG_PORT);
    if (!out.custom) throw new WarpError('badAddress', 'The endpoint must be an IP or a domain, with an optional port');
  }
  return out;
}

/**
 * A WireGuard WARP device as the editor's fields for parser.createServer:
 * Cloudflare's edge (the record's v4, or its v6, or the user's clean IP) on
 * 2408, the device's own key, the peer's, the tunnel's addresses, `reserved`
 * from the client id, MTU 1280, everything through it. Noise only for a WARP
 * dialled from here; a chained one rides its hop.
 */
function wgServerFields(reg, opts, name) {
  const o = wgOptions(opts);
  const r = reg || {};
  if (!isWgKey(r.privateKey) || !isWgKey(r.publicKey) || !Array.isArray(r.address) || !r.address.length) {
    throw new WarpError('badAnswer', 'The WARP account lacks its keys or its addresses');
  }
  const ep = Object.assign({}, WG_ENDPOINTS);
  for (const k of ['v4', 'v6']) if (isPlain(r.endpoints) && str(r.endpoints[k])) ep[k] = str(r.endpoints[k]);
  const f = {
    protocol: 'wireguard',
    name: str(name) || o.name || BASE_NAME,
    address: o.custom ? o.custom.host : ep[o.endpoint === 'v6' ? 'v6' : 'v4'],
    port: o.custom ? o.custom.port : WG_PORT,
    privateKey: r.privateKey,
    publicKey: r.publicKey,
    localAddress: r.address.join(', '),
    mtu: String(WG_MTU),
    allowedIPs: '0.0.0.0/0, ::/0'
  };
  if (Array.isArray(r.reserved) && r.reserved.length) f.reserved = r.reserved.join(',');
  if (o.antiDpi) f.noise = ANTI_DPI.noise;
  return f;
}

/** A WireGuard .conf or a wireguard:// link pasted in «وارد کردن حساب موجود» → its server (parser.js, as + WireGuard makes it). */
function importWg(text) {
  const s = str(text);
  if (!s) throw new WarpError('badConf', 'Nothing was pasted');
  const P = require('./parser');
  let server = null;
  try {
    if (P.isWireguardConf(s)) server = P.makeWireguardServer(P.parseWireguardConf(s));
    else if (/^(wireguard|wg):\/\//i.test(s)) server = P.parseLink(s);
  } catch (e) {
    // the parser's own words say which line is missing; a message quoting a key is not repeated
    const why = (e && e.message) || '';
    throw new WarpError('badConf', 'The WireGuard config could not be read' + (why && !/[A-Za-z0-9+/]{20,}/.test(why) ? ': ' + why : ''));
  }
  if (!server || server.protocol !== 'wireguard') {
    throw new WarpError('badConf', 'Paste a WireGuard .conf ([Interface] and [Peer]) or a wireguard:// link');
  }
  return server;
}

/* ------------------------------ names, keys, the chain ------------------------------ */
/**
 * Each account's label: the base alone for one account no server uses yet
 * («☁ WARP», MASQUE «☁ WARP · H3»), else the next free numbers — «☁ WARP 2»
 * when the bare base is there already, «☁ WARP 1» … for a batch. A label is
 * taken by a server of that name, or of that name + « · …».
 */
function accountLabels(n, base, servers) {
  const names = (Array.isArray(servers) ? servers : []).map((s) => str(s && s.name));
  const taken = (label) => names.some((x) => x === label || x.startsWith(label + ' · '));
  if (n === 1 && !taken(base)) return [base];
  const out = [];
  for (let k = taken(base) ? 2 : 1; out.length < n; k++) if (!taken(`${base} ${k}`)) out.push(`${base} ${k}`);
  return out;
}

/**
 * The WARP+ keys and how many accounts: one key goes on every account, several
 * one each in order (the accounts past them free), more keys than accounts
 * raise the count. Every key is checked here — the message names the line,
 * never the key.
 */
function licensePlan(a) {
  const raw = Array.isArray(a.licenses) ? a.licenses : (a.license != null ? [a.license] : []);
  const keys = raw.map(str).filter(Boolean);
  if (keys.length > MAX_ACCOUNTS) throw new WarpError('badLicense', `At most ${MAX_ACCOUNTS} WARP+ keys at once`);
  keys.forEach((k, i) => {
    if (!LICENSE_RE.test(k)) {
      throw new WarpError('badLicense', (keys.length > 1 ? `Key ${i + 1} is not a WARP+ key: ` : '') + 'a WARP+ license looks like xxxxxxxx-xxxxxxxx-xxxxxxxx');
    }
  });
  const asked = parseInt(a.count, 10);
  const n = Math.min(MAX_ACCOUNTS, Math.max(1, Number.isFinite(asked) ? asked : 1, keys.length));
  return { count: n, keys: Array.from({ length: n }, (_, i) => (keys.length === 1 ? keys[0] : keys[i] || '')) };
}

/**
 * What a chained WARP rides: a server (`<id>`) or a chain (`chain:<id>`, its
 * members) — each still there, and none an HTTP proxy, which carries no UDP.
 */
function resolveHop(chainWith, servers, chains) {
  const v = str(chainWith);
  const bad = (why) => new WarpError('badHop', why);
  if (!v) throw bad('Choose the config WARP goes through');
  const byId = new Map((Array.isArray(servers) ? servers : []).filter(isPlain).map((s) => [s.id, s]));
  let members;
  let name;
  if (v.startsWith('chain:')) {
    const c = (Array.isArray(chains) ? chains : []).find((x) => isPlain(x) && x.id === v.slice(6));
    if (!c) throw bad('That chain is no longer there');
    members = (Array.isArray(c.members) ? c.members : []).filter(Boolean);
    if (!members.length) throw bad('That chain has no servers');
    name = str(c.name) || 'Chain';
  } else {
    if (!byId.has(v)) throw bad('That config is no longer there');
    members = [v];
    name = str(byId.get(v).name) || v;
  }
  for (const id of members) {
    const s = byId.get(id);
    if (!s) throw bad('A server of that chain is no longer there');
    if (s.protocol === 'http') throw bad(`${str(s.name) || id} is an HTTP proxy: it carries no UDP, so WireGuard cannot ride it`);
  }
  return { members, name };
}

/** A new chain id, as the window's own: `chain-<base36 time><4 hex>`. */
function chainId(now) {
  return 'chain-' + Number((now || Date.now)()).toString(36) + crypto.randomBytes(2).toString('hex');
}

/* -------------------------------- servers:addWarp -------------------------------- */
/**
 * servers:addWarp (warp-wg/design.md §1-2): { kind: 'masque'|'wireguard',
 * mode: 'new'|'import', via, count, licenses (or the older single license),
 * importText; MASQUE http, endpoint, address, cover, antiDpi, name; WireGuard
 * use: 'chain'|'direct', chainWith, endpoint, address, antiDpi, name }.
 * Every choice is checked before the first registration. The accounts are made
 * one after another, a pause between; the first failing fails the call, a
 * later one stops the batch and keeps what was made (`stopped`). Each
 * account's servers carry what Cloudflare said of it (`server.warp`); a
 * chained WireGuard gets its chain. deps: createServer, connected(),
 * socksPort(), getServers(), getChains(), log(line, level), and for tests
 * request / now / pause(ms).
 * → { ok: true, added, addedChains, accounts, account, warnings, stopped? }
 *   | { ok: false, code, error, detail }
 */
async function addWarp(args, deps = {}) {
  const a = args || {};
  const kind = str(a.kind).toLowerCase() === 'wireguard' ? 'wireguard' : 'masque';
  const log = typeof deps.log === 'function' ? deps.log : () => {};
  const pause = typeof deps.pause === 'function' ? deps.pause : (ms) => new Promise((r) => setTimeout(r, ms));
  const servers = typeof deps.getServers === 'function' ? deps.getServers() || [] : [];
  const chains = typeof deps.getChains === 'function' ? deps.getChains() || [] : [];
  const secrets = [];
  const accounts = [];
  let stopped = null;
  const hide = (reg) => (reg && reg.privateKey ? [reg.privateKey, pemBody(reg.privateKey)] : []);

  // one account's servers (and its chain): createServer for each, the account kept on them
  function build(reg, label, hop) {
    const fields = kind === 'wireguard' ? [wgServerFields(reg, a, label)] : warpServers(reg, Object.assign({}, a, { name: label }));
    let added;
    try { added = fields.map((f) => deps.createServer(f)); } catch (e) {
      const why = scrub((e && e.message) || String(e), secrets.concat(hide(reg)));
      throw new WarpError('createFailed', 'The servers could not be made: ' + why, why);
    }
    const info = reg.info || { kind, imported: true };
    for (const s of added) if (isPlain(s)) s.warp = Object.assign({}, info);
    const chain = hop ? { id: chainId(deps.now), name: `${hop.name} → ${label}`, members: hop.members.concat(added[0].id) } : null;
    log(`WARP: ${added.length === 1 ? 'one server' : added.length + ' servers'} added (${added.map((s) => s.name).join(', ')})${chain ? '; chain ' + chain.name : ''}`, 'info');
    return { name: label, added, chain, info, warnings: reg.warnings || [], account: reg.account };
  }

  try {
    // checked first, so a typo costs no device; warpServers / wgServerFields check the same raw args again
    // (they take the dialog's words, not this checked form: «IP تمیز خودم» is `address`, not `custom`)
    const opt = kind === 'wireguard' ? wgOptions(a) : warpOptions(a);
    const hop = kind === 'wireguard' && opt.use === 'chain' ? resolveHop(opt.chainWith, servers, chains) : null;
    const base = opt.name || BASE_NAME;
    if (a.mode === 'import') {
      const [label] = accountLabels(1, base, servers);
      if (kind === 'wireguard') {
        const server = importWg(a.importText);
        server.name = label;
        server.warp = { kind, imported: true };
        const chain = hop ? { id: chainId(deps.now), name: `${hop.name} → ${label}`, members: hop.members.concat(server.id) } : null;
        log(`WARP: a WireGuard account was imported (${label})${chain ? '; chain ' + chain.name : ''}`, 'info');
        accounts.push({ name: label, added: [server], chain, info: server.warp, warnings: [], account: { id: '', type: '', warpPlus: false } });
      } else {
        const reg = importWarp(a.importText);
        log('WARP: an existing account was imported', 'info');
        accounts.push(build(reg, label, null));
      }
    } else {
      const plan = licensePlan(a);
      for (const k of plan.keys) if (k && !secrets.includes(k)) secrets.push(k);
      const via = a.via === 'proxy' ? 'proxy' : 'direct';
      if (via === 'proxy' && !(deps.connected && deps.connected())) {
        throw new WarpError('notConnected', 'Registering through the app\'s connection needs one: connect to a server first');
      }
      const request = deps.request || makeRequest({ via, socksPort: via === 'proxy' && deps.socksPort ? deps.socksPort() : 0 });
      const labels = accountLabels(plan.count, base, servers);
      log(`WARP: signing up ${plan.count === 1 ? 'one account' : plan.count + ' accounts'} (${kind === 'wireguard' ? 'WireGuard' : 'MASQUE'}) ${via === 'proxy' ? 'through the app\'s connection' : 'directly'}`, 'info');
      const register = kind === 'wireguard' ? registerWarpWg : registerWarp;
      for (let i = 0; i < plan.count; i++) {
        if (i) await pause(PAUSE_MS);
        if (plan.count > 1) log(`WARP: account ${i + 1} of ${plan.count}`, 'info');
        let reg = null;
        try {
          reg = await register({ license: plan.keys[i], request, now: deps.now, log });
          accounts.push(build(reg, labels[i], hop));
        } catch (e) {
          if (!accounts.length) throw e;
          const err = e instanceof WarpError ? e : new WarpError('failed', (e && e.message) || String(e));
          const message = scrub(err.message, secrets.concat(hide(reg)));
          stopped = { code: err.code, error: message, detail: err.detail ? scrub(err.detail, secrets.concat(hide(reg))) : message, made: accounts.length, wanted: plan.count };
          log(`WARP: stopped after ${accounts.length} of ${plan.count} accounts — ${message}`, 'warn');
          break;
        }
      }
    }
    const out = {
      ok: true,
      added: accounts.flatMap((x) => x.added),
      addedChains: accounts.map((x) => x.chain).filter(Boolean),
      accounts: accounts.map((x) => ({
        name: x.name,
        serverIds: x.added.map((s) => s.id),
        chainId: x.chain ? x.chain.id : null,
        chainName: x.chain ? x.chain.name : null,
        info: x.info,
        warnings: x.warnings
      })),
      // the first account as before v1.26, and every account's warnings with its name
      account: accounts[0].account,
      warnings: accounts.flatMap((x) => x.warnings.map((w) => Object.assign({}, w, { name: x.name })))
    };
    if (stopped) out.stopped = stopped;
    return out;
  } catch (e) {
    const err = e instanceof WarpError ? e : new WarpError('failed', (e && e.message) || String(e));
    const message = scrub(err.message, secrets);
    log('WARP: ' + message, 'warn');
    const out = { ok: false, code: err.code, error: message };
    // what the window puts in {msg}: Cloudflare's words, the network error, or the reason
    out.detail = err.detail ? scrub(err.detail, secrets) : message;
    return out;
  }
}

/**
 * The servers:addWarp handler main.js and service.js both register: addWarp,
 * then the new servers saved after the existing ones, and the new chains after
 * theirs. One sign-up at a time — a second click would register more devices
 * (and spend a rate limit). deps: as addWarp, plus setServers(list) and
 * setChains(list).
 * → { ok, servers (the whole list), chains (the whole list, when any was made), …addWarp's answer } or the refusal.
 */
function warpHandler(deps) {
  let running = false;
  return async function addWarpIpc(args) {
    if (running) return { ok: false, code: 'busy', error: 'A WARP sign-up is already running' };
    running = true;
    try {
      const res = await addWarp(args, deps);
      if (!res.ok) return res;
      const servers = deps.getServers().concat(res.added);
      deps.setServers(servers);
      const out = Object.assign({ servers }, res);
      if (res.addedChains.length && typeof deps.setChains === 'function') {
        const chains = (typeof deps.getChains === 'function' ? deps.getChains() || [] : []).concat(res.addedChains);
        deps.setChains(chains);
        out.chains = chains;
      }
      return out;
    } finally {
      running = false;
    }
  };
}

module.exports = {
  API, DEFAULT_ENDPOINTS, WARP_SNI, ANTI_DPI, ERROR_CODES, WARNING_CODES, WarpError,
  WG_ENDPOINTS, WG_PORT, WG_MTU, MAX_ACCOUNTS, LICENSE_RE,
  makeRequest, registerWarp, registerWarpWg, importWarp, importWg, warpServers, warpOptions,
  wgOptions, wgServerFields, accountInfo, accountLabels, licensePlan, resolveHop, addWarp, warpHandler
};
