'use strict';
/**
 * Groups (v1.27.0, .superpowers/sdd/groups/design.md): several saved servers
 * used together as one config. Each new connection goes out through one
 * member — round-robin by default — and a member that stops answering is left
 * out until it answers again (Xray's balancer and observatory, written by
 * configBuilder.expandGroups). A group is used wherever a server is: selected,
 * a routing target, a routing profile's base, a pool entry, any hop of a chain.
 *
 * Stored under `groups`:
 *   { id: 'grp-…', name, strategy: 'roundRobin' | 'leastPing' | 'random',
 *     members: [{ id: '<serverId>', address?: '<ip or host>', port?: <n> }] }
 * A member is a server, dialled as it is or at an address of its own (a clean
 * CDN IP — addressSwap.withTarget keeps its SNI and Host on the original name).
 *
 * The plan carries a group as a RECORD beside the servers (groupRecord): a
 * `loopback` outbound marked `_group`, which configBuilder expands at the end
 * into the members, the balancer, its routing rule and the health check.
 *
 * Pure: no store, no electron — main.js and the router's service.js both use it.
 */
const crypto = require('crypto');
const { withTarget, toPort } = require('./addressSwap');

const STRATEGIES = ['roundRobin', 'leastPing', 'random'];
const DEFAULT_STRATEGY = 'roundRobin';
const ID = /^grp-[\w-]+$/;

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const str = (v) => (v == null ? '' : String(v).trim());

/** A new group id: `grp-<base36 time><4 hex>`. */
function newGroupId(now) {
  return 'grp-' + Number((now || Date.now)()).toString(36) + crypto.randomBytes(2).toString('hex');
}

/** Is this id a group's? */
function isGroupId(id) {
  return typeof id === 'string' && ID.test(id);
}

/** A member as stored: `{ id, address?, port? }`; null when it names no server. */
function normalizeMember(m) {
  const src = typeof m === 'string' ? { id: m } : m;
  if (!isObj(src)) return null;
  const id = str(src.id);
  if (!id || isGroupId(id)) return null;   // a member is a server — never a group
  const out = { id };
  const address = str(src.address).replace(/^\[(.*)\]$/, '$1');
  if (address && !/[\s/@]/.test(address)) out.address = address;
  const port = toPort(src.port);
  if (port != null) out.port = port;
  return out;
}

/** A group with only its own fields, each of its type; an id that is not `grp-…` a new one; not an object → null. */
function normalizeGroup(g, now) {
  if (!isObj(g)) return null;
  const strategy = STRATEGIES.includes(g.strategy) ? g.strategy : DEFAULT_STRATEGY;
  // the config the group's traffic takes when no member answers (a WARP, say); a server's id, never a group's
  const fallback = str(g.fallback);
  return Object.assign({
    id: isGroupId(g.id) ? g.id : newGroupId(now),
    name: str(g.name) || 'Group',
    strategy,
    members: (Array.isArray(g.members) ? g.members : []).map(normalizeMember).filter(Boolean)
  }, fallback && !isGroupId(fallback) ? { fallback } : {});
}

/** groups:set — the list as it is saved: each normalized, a repeated id dropped. */
function normalizeGroups(list, now) {
  const seen = new Set();
  const out = [];
  for (const g of Array.isArray(list) ? list : []) {
    const n = normalizeGroup(g, now);
    if (!n || seen.has(n.id)) continue;
    seen.add(n.id);
    out.push(n);
  }
  return out;
}

/** A member's server record: the saved server, or a copy dialling the member's own address (its id kept). */
function memberRecord(server, m) {
  if (!m.address && m.port == null) return server;
  try {
    return withTarget(server, { address: m.address, port: m.port });
  } catch {
    return null;   // a shape that cannot take another address: left out, as a server that is gone
  }
}

/**
 * The record a group is in a plan — null when none of its members is left:
 *   { id, name, protocol: 'group', address: '', port: 0, group: { strategy, size },
 *     outbound: { protocol: 'loopback', settings: {}, _group: { id, name, strategy, members: [records], fallback: record | null } } }
 * `serversById`: the saved servers (never other groups). The fallback — the
 * config taken when no member answers — is there only while it is saved.
 */
function groupRecord(group, serversById) {
  const g = normalizeGroup(group);
  if (!g) return null;
  const byId = isObj(serversById) ? serversById : {};
  const members = [];
  for (const m of g.members) {
    const s = byId[m.id];
    if (!s || !isObj(s.outbound) || s.protocol === 'group') continue;
    const rec = memberRecord(s, m);
    if (rec) members.push(rec);
  }
  if (!members.length) return null;
  const f = g.fallback ? byId[g.fallback] : null;
  const fallback = f && isObj(f.outbound) && f.protocol !== 'group' ? f : null;
  return {
    id: g.id,
    name: g.name,
    protocol: 'group',
    address: '',
    port: 0,
    group: { strategy: g.strategy, size: members.length },
    outbound: { protocol: 'loopback', settings: {}, _group: { id: g.id, name: g.name, strategy: g.strategy, members, fallback } }
  };
}

/** Is this record a group's (groupRecord)? */
function isGroupRecord(s) {
  return !!(s && s.outbound && s.outbound.protocol === 'loopback' && isObj(s.outbound._group));
}

/** The servers a record stands for: a group's members (and its fallback, which it dials too), else the record itself. */
function serversOf(s) {
  if (!s) return [];
  if (!isGroupRecord(s)) return [s];
  const g = s.outbound._group;
  return g.fallback ? g.members.concat(g.fallback) : g.members.slice();
}

/** Every saved group as a record, keyed by id — what main.js and service.js add to a plan's serversById. */
function groupRecordsById(groups, serversById) {
  const out = {};
  for (const g of Array.isArray(groups) ? groups : []) {
    const rec = groupRecord(g, serversById);
    if (rec) out[rec.id] = rec;
  }
  return out;
}

module.exports = {
  STRATEGIES, DEFAULT_STRATEGY,
  newGroupId, isGroupId, normalizeMember, normalizeGroup, normalizeGroups,
  groupRecord, groupRecordsById, isGroupRecord, serversOf
};
