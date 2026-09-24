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
const { parseMany, parseLink } = require('./parser');

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
 */
function serverIdentity(s) {
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
  return JSON.stringify([ob.protocol || s.protocol || '', String(s.address || '').toLowerCase(), Number(s.port) || 0,
    cred, net, path || '', host || '']);
}

const streamOf = (s) => (s && s.outbound && s.outbound.streamSettings) || null;
function put(obj, key, v) {
  if (!obj) return;
  if (v === undefined) delete obj[key]; else obj[key] = v;
}

/**
 * What the user sets on a server that its link can ALSO carry: the edit form's
 * anti-DPI fields, the per-config engine, the patterniha TLS knobs, a
 * WireGuard's DNS line. Connection parameters (address, credentials, SNI,
 * keys…) are not here: they must match the server, and the provider is the one
 * who knows them.
 */
const USER_FIELDS = [
  { get: (s) => s.engine, set: (s, v) => put(s, 'engine', v) },
  { get: (s) => s.outbound && s.outbound._fragment, set: (s, v) => put(s.outbound, '_fragment', v) },
  { get: (s) => s.outbound && s.outbound._noise, set: (s, v) => put(s.outbound, '_noise', v) },
  { get: (s) => { const st = streamOf(s); return st ? st.finalmask : undefined; }, set: (s, v) => put(streamOf(s), 'finalmask', v) },
  {
    get: (s) => { const st = streamOf(s); return st && st.tlsSettings ? st.tlsSettings.cipherSuites : undefined; },
    set: (s, v) => { const st = streamOf(s); if (st && st.tlsSettings) put(st.tlsSettings, 'cipherSuites', v); }
  },
  { get: (s) => s.dns, set: (s, v) => put(s, 'dns', v) },
  { get: (s) => s.dnsDomains, set: (s, v) => put(s, 'dnsDomains', v) }
];

/** Values compared the way the edit form writes them: blank is absent, text is trimmed. */
function norm(v) {
  if (v == null || v === '') return '';
  return typeof v === 'string' ? v.trim() : JSON.stringify(v);
}
const clone = (v) => (v === undefined ? undefined : JSON.parse(JSON.stringify(v)));

/**
 * The fresh record, with the old one's id and everything that was the user's.
 * A field counts as the user's when the old record differs from what its own
 * link says (they edited it — or cleared it), so a value the provider changed
 * and the user never touched still comes through. The certificate pin is
 * learnt by the app on first use and never travels in a link: always kept.
 */
function carryOver(old, fresh) {
  const out = Object.assign({}, fresh, { id: old.id });
  out.outbound = clone(fresh.outbound);
  let said = null;
  try { said = parseLink(old.raw); } catch { said = null; }
  for (const f of USER_FIELDS) {
    const mine = f.get(old);
    if (!said || norm(mine) !== norm(f.get(said))) f.set(out, clone(mine));
  }
  // A rename only when it can be proven one: otherwise the provider's name
  // (which often carries the traffic left) is the current one.
  if (said && norm(old.name) !== norm(said.name) && norm(old.name)) out.name = old.name;
  for (const k of Object.keys(old)) if (/^certPin/.test(k)) out[k] = old[k];
  return out;
}

/**
 * Match a subscription's freshly parsed servers to the ones it had before.
 * Pure. Three passes, each over whatever is still unmatched: the identical
 * link, then the link apart from its remark, then the identity above — so an
 * exact match always wins over a looser one. Within a pass the old servers are
 * taken in order, one each: duplicates in the fresh list never share an id.
 * Unmatched old servers are gone; unmatched fresh ones keep their new id.
 */
function reconcileServers(previous, fresh) {
  const old = Array.isArray(previous) ? previous.filter(s => s && s.id) : [];
  const list = Array.isArray(fresh) ? fresh : [];
  const taken = new Set();
  const match = new Array(list.length).fill(null);
  for (const key of [(s) => String(s.raw || ''), (s) => withoutRemark(s.raw), serverIdentity]) {
    const byKey = new Map();
    old.forEach((o, i) => {
      if (taken.has(i)) return;
      const k = key(o);
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
  return list.map((f, j) => (match[j] === null ? f : carryOver(old[match[j]], f)));
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
