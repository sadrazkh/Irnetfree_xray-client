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
const { parseMany } = require('./parser');

function uid() { return crypto.randomBytes(8).toString('hex'); }

/** Fetch a URL following redirects; resolves with { body, headers }. */
function fetchUrl(url, timeout = 15000, redirects = 5) {
  return new Promise((resolve, reject) => {
    let mod;
    try { mod = url.startsWith('https') ? https : http; }
    catch { return reject(new Error('invalid url')); }

    const req = mod.get(url, {
      timeout,
      headers: { 'User-Agent': 'XrayClient/1.0 (subscription)' }
    }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        if (redirects <= 0) return reject(new Error('too many redirects'));
        res.resume();
        const next = res.headers.location.startsWith('http')
          ? res.headers.location
          : new URL(res.headers.location, url).toString();
        return resolve(fetchUrl(next, timeout, redirects - 1));
      }
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error('HTTP ' + res.statusCode));
      }
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (c) => (body += c));
      res.on('end', () => resolve({ body, headers: res.headers }));
    });
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    req.on('error', (e) => reject(e));
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

  /** Replace all servers belonging to a sub with freshly fetched ones. */
  async refresh(subId) {
    const subs = this.opts.getSubs();
    const sub = subs.find(s => s.id === subId);
    if (!sub) throw new Error('subscription not found');

    const { servers: fresh, errors, usage } = await fetchSubscription(sub.url, subId);

    // keep manually-added servers (no subId) + servers from OTHER subs
    const others = this.opts.getServers().filter(s => s.subId !== subId);
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

module.exports = { SubscriptionManager, fetchSubscription };
