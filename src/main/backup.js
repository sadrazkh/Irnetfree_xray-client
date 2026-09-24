'use strict';
/**
 * Backup and restore: everything the user has typed or collected, in one JSON.
 *
 * Export is a plain copy. Import is a MERGE by id — what is already there is
 * kept, what is new is added, settings are overlaid — so restoring on a machine
 * that has its own servers loses nothing, and restoring twice is the same as
 * restoring once. A file that is not ours is refused before anything is read
 * from it. Pure: the mirrors hand it the store's contents and write back what
 * it returns.
 */

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);

/*
 * A backup is a file someone can hand you, and its ids, protocols and ports end
 * up inside the renderer's markup and its CSS selectors. So what comes IN is
 * held to the shapes the app itself writes: ids of word characters and dashes
 * (every generator here makes those — hex, `chain-…`, `px-…`), a protocol the
 * builder knows, ports that are integers. A record with an id we would never
 * write is dropped, and so is any reference to one (a chain member, a pool
 * target), so the two stay consistent. What is already on the machine is ours
 * and is not re-checked.
 */
const ID = /^[\w-]+$/;
const PROTOCOLS = new Set(['vless', 'vmess', 'trojan', 'shadowsocks', 'socks', 'http', 'wireguard']);
const validId = (v) => typeof v === 'string' && ID.test(v);

/** A TCP port 1–65535 as a number, or null. */
function portOf(v) {
  if (typeof v !== 'number' && typeof v !== 'string') return null;
  const n = Number(v);
  return Number.isInteger(n) && n >= 1 && n <= 65535 ? n : null;
}

function cleanServer(s) {
  if (!isObj(s.outbound)) return null;
  // the outbound is the truth when the record lost its copy (configBuilder.isWgServer)
  const protocol = s.protocol == null || s.protocol === '' ? s.outbound.protocol : s.protocol;
  if (!PROTOCOLS.has(protocol)) return null;
  const out = Object.assign({}, s, { protocol });
  if ('port' in s) {
    const port = portOf(s.port);
    if (port === null) return null;
    out.port = port;
  }
  return out;
}

function cleanSubscription(s) {
  if (typeof s.url !== 'string') return null;
  const out = Object.assign({}, s);
  if ('serverCount' in s) { const n = Number(s.serverCount); out.serverCount = Number.isInteger(n) && n >= 0 ? n : 0; }
  return out;
}

function cleanChain(c) {
  return Array.isArray(c.members) ? Object.assign({}, c, { members: c.members.filter(validId) }) : c;
}

function cleanPoolEntry(e) {
  const out = Object.assign({}, e);
  for (const k of ['socksPort', 'httpPort']) if (k in e) out[k] = portOf(e[k]) || 0;
  if ('target' in e) {
    const t = typeof e.target === 'string' ? e.target : '';
    out.target = validId(t.indexOf('chain:') === 0 ? t.slice('chain:'.length) : t) ? t : '';
  }
  return out;
}

/** The settings overlay, with its ports as integers; a bad one leaves the current value. */
function cleanSettings(s) {
  const out = Object.assign({}, s);
  for (const k of ['socksPort', 'httpPort', 'apiPort']) {
    if (!(k in s)) continue;
    const p = portOf(s[k]);
    if (p === null) delete out[k]; else out[k] = p;
  }
  return out;
}

function exportBundle({ version, store, usage }) {
  const s = store || {};
  return {
    app: 'IRNetFree',
    format: 1,
    version: version || '',
    exportedAt: new Date().toISOString(),
    servers: Array.isArray(s.servers) ? s.servers : [],
    subscriptions: Array.isArray(s.subscriptions) ? s.subscriptions : [],
    chains: Array.isArray(s.chains) ? s.chains : [],
    pool: Array.isArray(s.pool) ? s.pool : [],
    settings: isObj(s.settings) ? s.settings : {},
    usage: isObj(usage) ? usage : {}
  };
}

/**
 * @returns {{ next: object, added: { servers, subscriptions, chains, pool } }}
 * @throws when the bundle is not an IRNetFree backup
 */
function importBundle(bundle, current) {
  if (!isObj(bundle) || bundle.app !== 'IRNetFree' || bundle.format !== 1) throw new Error('not an IRNetFree backup');
  const c = current || {};
  // `clean` returns the record as it may come in, or null to leave it out.
  const merge = (have, incoming, clean) => {
    const list = Array.isArray(have) ? have : [];
    const ids = new Set(list.map(x => x && x.id));
    const add = (Array.isArray(incoming) ? incoming : [])
      .filter(x => isObj(x) && validId(x.id) && !ids.has(x.id))
      .map(clean)
      .filter(Boolean);
    return { list: list.concat(add), n: add.length };
  };
  const servers = merge(c.servers, bundle.servers, cleanServer);
  const subscriptions = merge(c.subscriptions, bundle.subscriptions, cleanSubscription);
  const chains = merge(c.chains, bundle.chains, cleanChain);
  const pool = merge(c.pool, bundle.pool, cleanPoolEntry);
  return {
    next: {
      servers: servers.list,
      subscriptions: subscriptions.list,
      chains: chains.list,
      pool: pool.list,
      settings: Object.assign({}, isObj(c.settings) ? c.settings : {}, isObj(bundle.settings) ? cleanSettings(bundle.settings) : {}),
      usage: Object.assign({}, isObj(c.usage) ? c.usage : {}, isObj(bundle.usage) ? bundle.usage : {})
    },
    added: { servers: servers.n, subscriptions: subscriptions.n, chains: chains.n, pool: pool.n }
  };
}

module.exports = { exportBundle, importBundle };
