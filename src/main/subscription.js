'use strict';
/**
 * Subscription manager.
 *  - fetch a subscription URL (http/https), decode base64 if needed,
 *    parse into server objects, tag each with its subscription id.
 *  - supports auto-refresh on an interval.
 *
 * A subscription record:
 *   { id, name, url, lastUpdated, serverCount, autoUpdate }
 * Servers produced carry `subId` so they can be replaced on refresh.
 */

const https = require('https');
const http = require('http');
const crypto = require('crypto');
const { parseMany, parseLink, applyServerEdits, editFields } = require('./parser');

function uid() { return crypto.randomBytes(8).toString('hex'); }

/* ------------------------- a refresh keeps who a server is ------------------------- */

/** The share link without its `#remark` — panels rewrite the remark (traffic left, days left) on every fetch. */
function withoutRemark(raw) {
  const s = String(raw || '');
  const i = s.indexOf('#');
  return i === -1 ? s : s.slice(0, i);
}

/**
 * What a server connects to, as one string: protocol, address, port, its
 * credential (uuid / password / private key), the transport and its
 * path/serviceName/host. Two records with the same identity are the same
 * server even when the link around them changed (a vmess `ps`, an SNI, a
 * fingerprint). '' when the record is too odd to say.
 *
 * `strict` adds what tells a panel's VARIANTS of one server apart — the same
 * host, port and uuid offered with another SNI, REALITY key or flow — so a
 * reordered, retuned list does not swap their ids.
 */
function serverIdentity(s, strict) {
  const ob = s && s.outbound;
  if (!ob || typeof ob !== 'object') return '';
  const set = ob.settings || {};
  const st = ob.streamSettings || {};
  let cred = '';
  if (ob.protocol === 'vless' || ob.protocol === 'vmess') {
    const u = set.vnext && set.vnext[0] && set.vnext[0].users && set.vnext[0].users[0];
    cred = (u && u.id) || '';
  } else if (ob.protocol === 'trojan' || ob.protocol === 'shadowsocks') {
    const srv = set.servers && set.servers[0];
    cred = srv ? [srv.method || '', srv.password || ''].join(':') : '';
  } else if (ob.protocol === 'socks' || ob.protocol === 'http') {
    const u = set.servers && set.servers[0] && set.servers[0].users && set.servers[0].users[0];
    cred = u ? [u.user || '', u.pass || ''].join(':') : '';
  } else if (ob.protocol === 'wireguard') {
    cred = set.secretKey || '';
  }
  const net = st.network || 'tcp';
  let path = '', host = '';
  if (st.wsSettings) { path = st.wsSettings.path; host = st.wsSettings.headers && (st.wsSettings.headers.Host || st.wsSettings.headers.host); }
  else if (st.grpcSettings) path = st.grpcSettings.serviceName;
  else if (st.httpSettings) { path = st.httpSettings.path; host = [].concat(st.httpSettings.host || []).join(','); }
  else if (st.xhttpSettings) { path = st.xhttpSettings.path; host = st.xhttpSettings.host; }
  else if (st.httpupgradeSettings) { path = st.httpupgradeSettings.path; host = st.httpupgradeSettings.host; }
  else if (st.tcpSettings && st.tcpSettings.header && st.tcpSettings.header.request) {
    const rq = st.tcpSettings.header.request;
    path = [].concat(rq.path || []).join(',');
    host = [].concat((rq.headers && rq.headers.Host) || []).join(',');
  }
  const id = [ob.protocol || s.protocol || '', String(s.address || '').toLowerCase(), Number(s.port) || 0,
    cred, net, path || '', host || ''];
  if (strict) {
    const tls = st.tlsSettings || st.realitySettings || {};
    const rs = st.realitySettings || {};
    const u = set.vnext && set.vnext[0] && set.vnext[0].users && set.vnext[0].users[0];
    id.push(st.security || 'none', tls.serverName || '', rs.publicKey || '', rs.shortId || '', (u && u.flow) || '');
  }
  return JSON.stringify(id);
}

const streamOf = (s) => (s && s.outbound && s.outbound.streamSettings) || null;
function put(obj, key, v) {
  if (!obj) return;
  if (v === undefined) delete obj[key]; else obj[key] = v;
}

/**
 * What the user sets on a server that its link can ALSO carry: the edit form's
 * anti-DPI fields, the per-config engine, the patterniha TLS knobs, a
 * WireGuard's DNS line. `key` is the edit form's name for it (the name
 * applyServerEdits records in `_edited`).
 */
const USER_FIELDS = [
  { key: 'engine', get: (s) => s.engine, set: (s, v) => put(s, 'engine', v) },
  { key: 'fragment', get: (s) => s.outbound && s.outbound._fragment, set: (s, v) => put(s.outbound, '_fragment', v) },
  { key: 'noise', get: (s) => s.outbound && s.outbound._noise, set: (s, v) => put(s.outbound, '_noise', v) },
  { key: 'finalMask', get: (s) => { const st = streamOf(s); return st ? st.finalmask : undefined; }, set: (s, v) => put(streamOf(s), 'finalmask', v) },
  {
    key: 'cipherSuites',
    get: (s) => { const st = streamOf(s); return st && st.tlsSettings ? st.tlsSettings.cipherSuites : undefined; },
    set: (s, v) => { const st = streamOf(s); if (st && st.tlsSettings) put(st.tlsSettings, 'cipherSuites', v); }
  },
  { key: 'dns', get: (s) => s.dns, set: (s, v) => put(s, 'dns', v) },
  { key: 'dns', get: (s) => s.dnsDomains, set: (s, v) => put(s, 'dnsDomains', v) }
];

/** Values compared the way the edit form writes them: blank is absent, text is trimmed. */
function norm(v) {
  if (v == null || v === '') return '';
  return typeof v === 'string' ? v.trim() : JSON.stringify(v);
}
const clone = (v) => (v === undefined ? undefined : JSON.parse(JSON.stringify(v)));

/**
 * What the provider's link said the old server was: its `raw`, parsed again
 * (an edit never touches `raw`; every refresh replaces it). Used to FIND the
 * server — one whose address the user swapped is still the provider's server
 * — and to compare its handshake with the fresh one's. null when the link
 * cannot say: it does not parse, or it is the `wireguard://host:port` a .conf
 * import keeps, which has no keys in it.
 */
function linkOf(old) {
  let said;
  try { said = parseLink(old.raw); } catch { return null; }
  const set = said && said.outbound && said.outbound.settings;
  if (said.protocol === 'wireguard' && !(set && set.secretKey)) return null;
  return said;
}

/** The connection fields of the edit form (parser.editFields names). */
const CONNECTION_KEYS = ['address', 'port', 'uuid', 'password', 'username',
  'privateKey', 'publicKey', 'presharedKey', 'localAddress', 'mtu', 'reserved', 'allowedIPs',
  'network', 'security', 'sni', 'host', 'path', 'fp', 'pbk', 'sid', 'allowInsecure'];
/** The ones the stream is rebuilt from, as the form sends them all on a save. */
const STREAM_KEYS = ['network', 'security', 'sni', 'host', 'path', 'serviceName', 'fp', 'pbk', 'sid', 'allowInsecure', 'alpn'];

/** The field names applyServerEdits recorded as the user's edits. */
function recordedEdits(s) {
  return Array.isArray(s && s._edited) ? s._edited.filter(k => typeof k === 'string') : [];
}

/**
 * The connection fields the user edited (as recorded when they edited them),
 * as applyServerEdits() takes them, and their names — null when none carry.
 * Nothing is inferred: a record with no `_edited` is taken as the provider
 * sent it, so every parser fix reaches it on the next refresh. A field the
 * user CLEARED in the form is recorded like any other edit, so it is carried
 * as cleared — a removed PSK, an empty shortId, a path reset to `/` stay that
 * way across refreshes; nothing has to guess whether a blank was theirs. When the
 * provider moved the server to another handshake or transport (security or
 * network differs between the old link and the fresh server), only the
 * address and port go across: an SNI, a fingerprint or a REALITY key belong
 * to the handshake they were set for.
 */
function connectionEdits(old, said, fresh) {
  let keys = recordedEdits(old).filter(k => CONNECTION_KEYS.includes(k));
  if (!keys.length) return null;
  const was = said ? editFields(said) : null;
  const now = editFields(fresh);
  if (!was || was.security !== now.security || was.network !== now.network) {
    keys = keys.filter(k => k === 'address' || k === 'port');
  }
  const mine = editFields(old);
  keys = keys.filter(k => k in mine);
  if (!keys.length) return null;
  const fields = {};
  // The stream is rebuilt from every field, as the form sends them: the
  // fresh server's, with the user's changes over them.
  if (keys.some(k => STREAM_KEYS.includes(k))) {
    for (const k of STREAM_KEYS) if (k in now) fields[k] = now[k];
  }
  for (const k of keys) fields[k] = mine[k];
  if (keys.includes('path')) fields.serviceName = mine.path;
  // socks/http credentials go as a pair (applyServerEdits replaces both)
  if ('username' in mine && (keys.includes('username') || keys.includes('password'))) {
    fields.username = mine.username; fields.password = mine.password;
  }
  return { fields, keys };
}

/**
 * The fresh record, with the old one's id and everything that was the user's.
 *  - Connection fields (address — a clean CDN IP —, port, credential, SNI,
 *    Host, path, …): only those recorded in `_edited` when the user edited
 *    them (see connectionEdits).
 *  - The anti-DPI fields, the engine, a WireGuard's DNS: recorded ones, and —
 *    as before — any whose old value differs from what the old link said, so
 *    a value the provider retunes and the user never touched comes through.
 *  - The name: recorded, or a rename the old link proves.
 *  - The certificate pin is learnt by the app and never in a link: always kept.
 * `_edited` goes forward with what was carried, so it holds refresh after
 * refresh.
 */
function carryOver(old, fresh, said) {
  let out = Object.assign({}, fresh, { id: old.id });
  out.outbound = clone(fresh.outbound);
  delete out._edited;
  const recorded = recordedEdits(old);
  const kept = [];
  const conn = connectionEdits(old, said, fresh);
  if (conn) { out = applyServerEdits(out, conn.fields); kept.push(...conn.keys); }
  for (const f of USER_FIELDS) {
    const mine = f.get(old);
    const mineRecorded = recorded.includes(f.key);
    if (mineRecorded || !said || norm(mine) !== norm(f.get(said))) f.set(out, clone(mine));
    if (mineRecorded) kept.push(f.key);
  }
  // A rename when recorded, or when the old link proves one: otherwise the
  // provider's name (which often carries the traffic left) is the current one.
  if (recorded.includes('name')) { out.name = old.name; kept.push('name'); }
  else if (said && norm(old.name) !== norm(said.name) && norm(old.name)) out.name = old.name;
  for (const k of Object.keys(old)) if (/^certPin/.test(k)) out[k] = old[k];
  delete out._edited;
  if (kept.length) out._edited = [...new Set(kept)].sort();
  return out;
}

/**
 * Match a subscription's freshly parsed servers to the ones it had before.
 * Pure. Four passes, each over whatever is still unmatched: the identical
 * link, the link apart from its remark, the strict identity, the identity
 * above — so a tighter match always wins over a looser one. Within a pass the
 * old servers are taken in order, one each: duplicates in the fresh list never
 * share an id. Unmatched old servers are gone; unmatched fresh ones keep their
 * new id. An old server's identity is what its link said it was, so one whose
 * address the user swapped is still found.
 */
function reconcileServers(previous, fresh) {
  const old = Array.isArray(previous) ? previous.filter(s => s && s.id) : [];
  const said = old.map(linkOf);
  const list = Array.isArray(fresh) ? fresh : [];
  const taken = new Set();
  const match = new Array(list.length).fill(null);
  const passes = [(s) => String(s.raw || ''), (s) => withoutRemark(s.raw), (s) => serverIdentity(s, true), (s) => serverIdentity(s)];
  for (const [p, key] of passes.entries()) {
    const byKey = new Map();
    old.forEach((o, i) => {
      if (taken.has(i)) return;
      const k = key(p >= 2 && said[i] ? said[i] : o);
      if (!k) return;
      if (!byKey.has(k)) byKey.set(k, []);
      byKey.get(k).push(i);
    });
    list.forEach((f, j) => {
      if (match[j] !== null) return;
      const k = key(f);
      const q = k && byKey.get(k);
      if (!q || !q.length) return;
      const i = q.shift();
      taken.add(i);
      match[j] = i;
    });
  }
  return list.map((f, j) => (match[j] === null ? f : carryOver(old[match[j]], f, said[match[j]])));
}

/** No subscription comes near this; a portal, a mistake or a hostile server can. */
const MAX_BODY_BYTES = 8 * 1024 * 1024;
/**
 * The whole fetch — every redirect and every byte — against one clock. The
 * socket's idle timeout alone never fires for a server that trickles a byte at
 * a time, and the hourly refresh would wait on it for ever.
 */
const FETCH_DEADLINE_MS = 60000;

/**
 * Where a redirect leads, resolved against the URL that sent it. Refused when
 * it would leave https for plain http: whoever answered the TLS request with a
 * 302 (a captive portal, anyone on the path) must not get the next request —
 * the subscription's secret URL — in the clear.
 */
function redirectTarget(from, location) {
  const next = new URL(location, from);
  if (next.protocol !== 'http:' && next.protocol !== 'https:') throw new Error('refused redirect to ' + next.protocol);
  if (new URL(from).protocol === 'https:' && next.protocol === 'http:') throw new Error('refused redirect from https to http');
  return next.toString();
}

/**
 * Fetch a URL following redirects; resolves with { body, headers }.
 * opts: timeout (idle, ms), deadline (whole fetch, ms), maxBytes, redirects.
 */
function fetchUrl(url, opts = {}) {
  const timeout = opts.timeout || 15000;
  const maxBytes = opts.maxBytes || MAX_BODY_BYTES;
  const redirects = opts.redirects == null ? 5 : opts.redirects;
  const deadlineAt = opts.deadlineAt || Date.now() + (opts.deadline || FETCH_DEADLINE_MS);
  return new Promise((resolve, reject) => {
    let mod;
    try { mod = url.startsWith('https') ? https : http; }
    catch { return reject(new Error('invalid url')); }

    let req = null, done = false;
    const finish = (err, value) => {
      if (done) return;
      done = true;
      clearTimeout(clock);
      if (err) { if (req) req.destroy(); reject(err); } else resolve(value);
    };
    const clock = setTimeout(() => finish(new Error('the subscription took too long to download')),
      Math.max(0, deadlineAt - Date.now()));
    const tooLarge = () => new Error(`the subscription is too large (over ${Math.round(maxBytes / 1048576)} MB)`);

    req = mod.get(url, {
      timeout,
      headers: { 'User-Agent': 'XrayClient/1.0 (subscription)' }
    }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        if (redirects <= 0) return finish(new Error('too many redirects'));
        let next;
        try { next = redirectTarget(url, res.headers.location); } catch (e) { return finish(e); }
        return finish(null, fetchUrl(next, Object.assign({}, opts, { redirects: redirects - 1, deadlineAt })));
      }
      if (res.statusCode !== 200) {
        res.resume();
        return finish(new Error('HTTP ' + res.statusCode));
      }
      if (parseInt(res.headers['content-length'], 10) > maxBytes) return finish(tooLarge());
      const chunks = [];
      let size = 0;
      res.on('data', (c) => {
        size += c.length;
        if (size > maxBytes) return finish(tooLarge());
        chunks.push(c);
      });
      res.on('end', () => finish(null, { body: Buffer.concat(chunks).toString('utf8'), headers: res.headers }));
      res.on('error', (e) => finish(e));
    });
    req.on('timeout', () => finish(new Error('timeout')));
    req.on('error', (e) => finish(e));
  });
}

/**
 * Parse the standard `Subscription-Userinfo` header that many panels send:
 *   upload=455; download=1234; total=10737418240; expire=1700000000
 * Returns { upload, download, total, expire } (bytes / unix-seconds) or null.
 */
function parseUserinfo(h) {
  if (!h) return null;
  const out = {};
  for (const part of String(h).split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const k = part.slice(0, idx).trim().toLowerCase();
    const v = part.slice(idx + 1).trim();
    if (/^\d+$/.test(v)) out[k] = Number(v);
  }
  if (!('upload' in out || 'download' in out || 'total' in out || 'expire' in out)) return null;
  return { upload: out.upload || 0, download: out.download || 0, total: out.total || 0, expire: out.expire || 0 };
}

/**
 * Download + parse a subscription. Returns { servers, errors, usage }.
 * Each server gets subId attached.
 */
async function fetchSubscription(url, subId) {
  const { body, headers } = await fetchUrl(url);
  const { servers, errors } = parseMany(body);
  for (const s of servers) s.subId = subId;
  const usage = parseUserinfo(headers['subscription-userinfo']);
  return { servers, errors, usage };
}

class SubscriptionManager {
  /**
   * @param {object} opts
   *   getSubs()        -> array of sub records
   *   setSubs(arr)     -> persist sub records
   *   getServers()     -> array of all servers
   *   setServers(arr)  -> persist servers
   *   onUpdate(sub, info) -> notify renderer
   *   fetch(url, subId)   -> optional, fetchSubscription's shape (tests)
   */
  constructor(opts) {
    this.opts = opts;
    this.timer = null;
  }

  list() { return this.opts.getSubs(); }

  async add(url, name) {
    const subs = this.opts.getSubs();
    const id = uid();
    const sub = {
      id,
      name: name || hostnameOf(url) || 'Subscription',
      url,
      lastUpdated: null,
      serverCount: 0,
      autoUpdate: true
    };
    subs.push(sub);
    this.opts.setSubs(subs);
    const res = await this.refresh(id);
    return { sub: this.list().find(s => s.id === id), ...res };
  }

  /**
   * Replace the servers belonging to a sub with freshly fetched ones. A server
   * still in the subscription keeps its id and the user's own settings on it
   * (see reconcileServers).
   */
  async refresh(subId) {
    const before = this.opts.getSubs().find(s => s.id === subId);
    if (!before) throw new Error('subscription not found');

    const { servers: parsed, errors, usage } = await (this.opts.fetch || fetchSubscription)(before.url, subId);

    // Nothing usable came back — a captive portal's page, an empty body, a
    // panel's error, a format we do not read. That is a failed refresh, not a
    // subscription that has no servers: keep every server it had.
    if (!parsed.length) {
      const why = errors.length
        ? `${errors.length} line(s) not understood — ${errors[0].error}`
        : 'no server links in the response';
      throw new Error(`the subscription returned no usable servers (${why}); the servers you had are kept`);
    }

    // Read the store again: other refreshes, an edit or a removal may have
    // landed while this one was on the network. A subscription removed in the
    // meantime stays removed — its servers are not written back.
    const subs = this.opts.getSubs();
    const sub = subs.find(s => s.id === subId);
    if (!sub) throw new Error('subscription not found');

    // keep manually-added servers (no subId) + servers from OTHER subs
    const all = this.opts.getServers();
    const others = all.filter(s => s.subId !== subId);
    const fresh = reconcileServers(all.filter(s => s.subId === subId), parsed);
    this.opts.setServers(others.concat(fresh));

    sub.lastUpdated = Date.now();
    sub.serverCount = fresh.length;
    sub.usage = usage || null;   // { upload, download, total, expire } or null
    this.opts.setSubs(subs);

    if (this.opts.onUpdate) this.opts.onUpdate(sub, { added: fresh.length, errors: errors.length });
    return { added: fresh.length, errors };
  }

  async refreshAll() {
    const subs = this.opts.getSubs();
    const results = [];
    for (const sub of subs) {
      try {
        const r = await this.refresh(sub.id);
        results.push({ id: sub.id, ok: true, added: r.added });
      } catch (e) {
        results.push({ id: sub.id, ok: false, error: e.message });
      }
    }
    return results;
  }

  remove(subId) {
    const subs = this.opts.getSubs().filter(s => s.id !== subId);
    this.opts.setSubs(subs);
    // drop its servers too
    const servers = this.opts.getServers().filter(s => s.subId !== subId);
    this.opts.setServers(servers);
    return subs;
  }

  /** Start a periodic refresh for subs that have autoUpdate=true. */
  startAuto(intervalMinutes = 60) {
    this.stopAuto();
    const ms = Math.max(5, intervalMinutes) * 60 * 1000;
    this.timer = setInterval(() => {
      const subs = this.opts.getSubs().filter(s => s.autoUpdate);
      subs.forEach(s => this.refresh(s.id).catch(() => {}));
    }, ms);
    if (this.timer.unref) this.timer.unref();
  }

  stopAuto() {
    if (this.timer) { clearInterval(this.timer); this.timer = null; }
  }

  setAutoUpdate(subId, enabled) {
    const subs = this.opts.getSubs();
    const sub = subs.find(s => s.id === subId);
    if (sub) { sub.autoUpdate = enabled; this.opts.setSubs(subs); }
    return sub;
  }
}

function hostnameOf(url) {
  try { return new URL(url).hostname; } catch { return ''; }
}

module.exports = { SubscriptionManager, fetchSubscription, reconcileServers, fetchUrl, redirectTarget, MAX_BODY_BYTES };
