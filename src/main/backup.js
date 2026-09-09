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
  const merge = (have, incoming, keep) => {
    const list = Array.isArray(have) ? have : [];
    const ids = new Set(list.map(x => x && x.id));
    const add = (Array.isArray(incoming) ? incoming : []).filter(x => isObj(x) && x.id && !ids.has(x.id) && keep(x));
    return { list: list.concat(add), n: add.length };
  };
  const servers = merge(c.servers, bundle.servers, (s) => isObj(s.outbound));
  const subscriptions = merge(c.subscriptions, bundle.subscriptions, (s) => typeof s.url === 'string');
  const chains = merge(c.chains, bundle.chains, () => true);
  const pool = merge(c.pool, bundle.pool, () => true);
  return {
    next: {
      servers: servers.list,
      subscriptions: subscriptions.list,
      chains: chains.list,
      pool: pool.list,
      settings: Object.assign({}, isObj(c.settings) ? c.settings : {}, isObj(bundle.settings) ? bundle.settings : {}),
      usage: Object.assign({}, isObj(c.usage) ? c.usage : {}, isObj(bundle.usage) ? bundle.usage : {})
    },
    added: { servers: servers.n, subscriptions: subscriptions.n, chains: chains.n, pool: pool.n }
  };
}

module.exports = { exportBundle, importBundle };
