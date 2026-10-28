'use strict';
/**
 * A config of someone's own choosing, ridden beside the connection: the
 * machinery the users module built for its users and the router's transparent
 * inbounds (src/modules/lanUsers/xray.js), shared since per-app configs
 * (tunAppTargets.js) ride the same way — a loopback SOCKS inbound per target,
 * routed to that target's outbounds, which are made where the plan's own are
 * (configBuilder.buildConfig / buildPoolConfig) so every pass after them
 * (multi-internet, groups, the WireGuard fixes, pinned names, the anti-DPI
 * dialers, ECH, the NIC binding under TUN, the chain relay) reaches them too.
 *
 * A target is what the pickers store: '' (the connection itself), 'direct',
 * 'block', a server's or a group's id, or 'chain:<id>'.
 *
 * Node core only (no electron): the headless service builds with it too.
 */
const { groupRecordsById } = require('./groups');

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);

/**
 * The outbounds `targets` need, and the tag each target is routed to:
 * → { outbounds, tags: { [target]: tag } }. Raw, as the plan's own are before
 * the builder's passes — the caller puts them beside those. `prefix` names the
 * ones made here (`<prefix><id>`, `<prefix>chain-<cid>`): each user of this
 * keeps its own, so a config read back by its tags (the users' meter) never
 * counts another's.
 *
 * `ctx` (configBuilder makes it): { exitTag, serversById, chainsById,
 *   existingTag(target) → a tag the config already has for exactly that target,
 *   server(record, tag) → outbounds, chain(records, tag) → outbounds,
 *   unsafe(record) → true when the core must not be handed it (a WireGuard
 *   endpoint name nobody resolved: a core left to resolve one can go down with
 *   it, taking the owner's own connection along) }.
 *
 *  - ''  → the plan's exit (whatever this machine is connected through now);
 *  - 'direct' / 'block' → those;
 *  - the server, chain or group the config already dials as that very target →
 *    its outbound, shared: a WireGuard dialled twice is two sessions on one
 *    key, and the peer keeps only the newest — each would cut the other off;
 *  - else its own `<prefix><id>` (`<prefix>chain-<cid>` for a chain);
 *  - a target that is gone, a chain that lost a member, an unsafe one →
 *    'block'. Traffic is never sent out unprotected because its config
 *    disappeared.
 */
function targetOutbounds(targets, ctx, prefix) {
  const c = ctx || {};
  const servers = isObj(c.serversById) ? c.serversById : {};
  const chains = isObj(c.chainsById) ? c.chainsById : {};
  const unsafe = (recs) => typeof c.unsafe === 'function' && recs.some((r) => c.unsafe(r));
  const outbounds = [];
  const seen = new Set();
  const push = (list) => { for (const o of list || []) if (o && o.tag && !seen.has(o.tag)) { seen.add(o.tag); outbounds.push(o); } };

  function tagOf(target) {
    if (!target) return c.exitTag || 'direct';
    if (target === 'direct' || target === 'block') return target;
    const reuse = typeof c.existingTag === 'function' ? c.existingTag(target) : null;
    if (reuse) return reuse;
    if (target.indexOf('chain:') === 0) {
      const cid = target.slice('chain:'.length);
      const list = chains[cid];
      if (!Array.isArray(list) || !list.length || list.some((x) => !x || !x.outbound) || unsafe(list) || typeof c.chain !== 'function') return 'block';
      const tag = prefix + 'chain-' + cid;
      push(c.chain(list, tag));
      return tag;
    }
    const srv = servers[target];
    if (!srv || !srv.outbound || unsafe([srv]) || typeof c.server !== 'function') return 'block';
    const tag = prefix + target;
    push(c.server(srv, tag));
    return tag;
  }

  const tags = {};
  for (const t of Array.isArray(targets) ? targets : []) tags[t] = tagOf(t);
  return { outbounds, tags };
}

/**
 * The loopback SOCKS inbound a target is reached through: 127.0.0.1 only (the
 * local sing-box TUN is what dials it), no account, UDP on — the router's
 * transparent inbounds (`lu-tp-<n>`) and the per-app ones (`pa-<n>`) alike.
 */
function loopbackSocksInbound(tag, port, sniffing) {
  return { tag, port, listen: '127.0.0.1', protocol: 'socks', settings: { auth: 'noauth', udp: true }, sniffing };
}

/**
 * The records `targets` name, as main.js buildPlan makes them: groups as
 * records beside the servers (a group's id is a target like a server's); a
 * chain that lost a member is null — blocked, never a shorter chain. A target
 * that names nothing is simply absent. `store`: { servers, groups, chains },
 * the store's lists as they are.
 * → { serversById, chainsById }
 */
function recordsForTargets(targets, store) {
  const st = isObj(store) ? store : {};
  const all = {};
  for (const s of Array.isArray(st.servers) ? st.servers : []) if (s && s.id) all[s.id] = s;
  Object.assign(all, groupRecordsById(Array.isArray(st.groups) ? st.groups : [], Object.assign({}, all)));
  const chains = Array.isArray(st.chains) ? st.chains : [];
  const serversById = {};
  const chainsById = {};
  for (const t of Array.isArray(targets) ? targets : []) {
    if (!t || t === 'direct' || t === 'block') continue;
    if (t.indexOf('chain:') === 0) {
      const cid = t.slice('chain:'.length);
      const c = chains.find((x) => x && x.id === cid);
      const ids = c && Array.isArray(c.members) ? c.members : [];
      chainsById[cid] = ids.length && ids.every((id) => all[id]) ? ids.map((id) => all[id]) : null;
      continue;
    }
    if (all[t]) serversById[t] = all[t];
  }
  return { serversById, chainsById };
}

/** A target these records cannot dial: a server or group that is not there, a chain that is null (lost a member) or missing. */
function targetGone(target, records) {
  const t = target;
  if (!t || t === 'direct' || t === 'block') return false;
  const r = isObj(records) ? records : {};
  if (t.indexOf('chain:') === 0) return !(r.chainsById || {})[t.slice('chain:'.length)];
  return !(r.serversById || {})[t];
}

module.exports = { targetOutbounds, loopbackSocksInbound, recordsForTargets, targetGone };
