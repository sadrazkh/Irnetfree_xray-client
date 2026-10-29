'use strict';
/**
 * Users on the router, transparent mode — the core's half. Every user whose
 * config is not "block" gets their own SOCKS inbound `lu-tp-<n>` on a free
 * loopback port (v1.39: per user, not per config — what each user sends
 * direct is counted on their own direct outbound `lu-d-<id>`, and their
 * routing and holds are theirs), routed to their config — the proxy pool's
 * way of giving many exits one core (configBuilder.buildPoolConfig). sing-box
 * sends each device there by its addresses (tunSingbox buildTunConfig's
 * `lanRoutes`).
 *
 * The config's outbound is the one the running config already has for it
 * when there is one — the selected server is `proxy`, an advanced or pool
 * target `out-<id>` / `out-chain-<cid>` — so a WireGuard is never dialled as
 * two sessions on one key (the peer keeps only the newest: configBuilder's
 * makeRegistry says why). Otherwise it is built here as the pool builds its
 * targets: a server or a chain through configBuilder.buildChainOutbounds (the
 * certificate pin, a JSON server's helpers, a group's members — expanded by
 * expandGroups with their balancer and health check), and each dial of its
 * own bound to the physical interface like every other dial on a router
 * (configBuilder.bindDirectDials): under the whole-LAN tunnel an unbound dial
 * would re-enter it. Not carried over for these: mux, the anti-DPI dialers
 * and multi-internet — they ride the server's plain outbound.
 *
 * A user's rules are the users module's own (xray.js userRouteRules, the
 * desktop's accounts' too), scoped by the inbound, placed by their routing:
 *   - '' / 'global' — the router's own routing, as before v1.39: its rules
 *     (the DNS hijack, ads, private ranges, the routing mode, advanced
 *     routing's rules) hold for every device; what none of them claims leaves
 *     through the user's config — that catch-all right before the router's.
 *     So their direct bytes are counted as theirs, every router rule to
 *     'direct' is repeated for the inbound → `lu-d-<id>`, right after the DNS
 *     rules, ahead of the router's own;
 *   - 'bypass-ir' / 'profile:<id>' — their own routing decides: its rules and
 *     their catch-all, all of it right after the DNS rules, ahead of the
 *     router's own.
 * A hold of one class (the meter's 'vpn' / 'direct', the build's
 * `lanUsers.holds`): every rule of theirs to that class goes to block; under
 * 'vpn' their catch-all — block — sits ahead of the router's rules too, so a
 * router rule to a server never carries a held user's traffic.
 *
 * `lu-d-<id>`: a copy of the config's own `direct` — bound to the WAN as it
 * is (configBuilder.bindDirectDials), and bound here when it is not — unless
 * the config already has one (the same user's proxy account, xray.js).
 *
 * `ctx.outboundFor(target, { tag, config })` may replace the lookup and the
 * build (USERS-CORE's per-target outbound builder, if it is to be shared):
 * it returns the outbound tag, or null for a config that cannot be built.
 */
const { buildChainOutbounds, expandGroups, entryAddressesOf } = require('../../../main/configBuilder');
const { userRouteRules, directTagOf } = require('../xray');
const { routingOf, profileIdOf } = require('../model');

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const clone = (v) => JSON.parse(JSON.stringify(v));
/** The DNS hijack's outbound (dnsBuilder.js HIJACK_TAG): the last of the DNS rules routes to it. */
const DNS_HIJACK = 'dns-out';
/** Stands for a balancer in userRouteRules' catch-all, which knows outbound tags only. */
const BALANCER = '\0balancer';

/** The outbound the running config already has for this target, or null. */
function existingTag(config, target, ctx) {
  const tags = new Set(((config && config.outbounds) || []).map(o => o && o.tag).filter(Boolean));
  const plan = (ctx && ctx.plan) || {};
  const sel = ctx && ctx.serverId;
  if (tags.has('proxy')) {
    if (plan.mode === 'single' && plan.server && plan.server.id === target) return 'proxy';
    if (plan.mode === 'chain' && sel && (target === 'chain:' + sel || (sel === '__chain__' && target === 'chain'))) return 'proxy';
  }
  const own = target.indexOf('chain:') === 0 ? 'out-chain-' + target.slice('chain:'.length) : 'out-' + target;
  return tags.has(own) ? own : null;
}

/** The records a target dials, first hop first: a chain's members, a server or a group; null when it names nothing. */
function membersOf(target, records) {
  const r = records || {};
  if (target.indexOf('chain:') === 0) {
    const list = (r.chainsById || {})[target.slice('chain:'.length)];
    const live = Array.isArray(list) ? list.filter(s => s && s.outbound) : [];
    return live.length ? live : null;
  }
  const s = (r.serversById || {})[target];
  return s && s.outbound ? [s] : null;
}

/** Each dial of its own bound to the physical interface (configBuilder.bindDirectDials' rule). */
function bindDials(outbounds, iface) {
  for (const o of outbounds) {
    if (!o) continue;
    const tls = o.streamSettings && o.streamSettings.tlsSettings;
    // the editor's ECH outbound is the app's own key (configBuilder.applyEchOutbounds), never the core's
    if (tls && Object.prototype.hasOwnProperty.call(tls, 'echOutbound')) delete tls.echOutbound;
    if (typeof iface !== 'string' || !iface.trim() || o.protocol === 'dns' || o.protocol === 'blackhole' || o.protocol === 'loopback') continue;
    const ss = o.streamSettings || (o.streamSettings = {});
    if (ss.sockopt && (ss.sockopt.dialerProxy || ss.sockopt.interface)) continue;
    ss.sockopt = Object.assign({}, ss.sockopt, { interface: iface });
  }
  return outbounds;
}

/** Built here: the target's outbounds under `<tag>-out`, merged into `config` (groups' rules first, balancers, health check). */
function buildTarget(config, entry, members, ctx) {
  const outTag = `${entry.tag}-out`;
  const grp = expandGroups(buildChainOutbounds(members, outTag), ctx.groupSkip);
  config.outbounds.push(...bindDials(grp.outbounds, ctx.directInterface));
  if (grp.rules.length) config.routing.rules.unshift(...grp.rules);
  if (grp.balancers.length) config.routing.balancers = [...(config.routing.balancers || []), ...grp.balancers];
  if (grp.observatory) {
    if (isObj(config.observatory) && Array.isArray(config.observatory.subjectSelector)) {
      config.observatory.subjectSelector = [...config.observatory.subjectSelector, ...grp.observatory.subjectSelector];
    } else config.observatory = grp.observatory;
  }
  return outTag;
}

/** Where the config's catch-all (`port 0-65535` and nothing else) sits; -1 when it has none. */
function catchAllIndex(rules) {
  for (let i = rules.length - 1; i >= 0; i--) {
    const r = rules[i];
    if (isObj(r) && r.port === '0-65535' && Object.keys(r).every(k => ['type', 'port', 'outboundTag', 'balancerTag'].includes(k))) return i;
  }
  return -1;
}

/**
 * Where the router's own rules begin: right after the DNS rules (the last one
 * routes to the hijack, dnsBuilder.js) — or, a config with no hijack, after
 * the leading rules of an inbound of their own (the groups' loopbacks).
 */
function ownRulesIndex(rules) {
  for (let i = rules.length - 1; i >= 0; i--) if (isObj(rules[i]) && rules[i].outboundTag === DNS_HIJACK) return i + 1;
  let i = 0;
  while (i < rules.length && isObj(rules[i]) && Array.isArray(rules[i].inboundTag) && rules[i].inboundTag.length) i++;
  return i;
}

/** The user's own direct outbound into `config` (a copy of its `direct`, bound like it), unless it has one. */
function ensureUserDirect(config, tag, iface) {
  if (config.outbounds.some(o => o && o.tag === tag)) return;
  const d = config.outbounds.find(o => o && o.tag === 'direct');
  const own = Object.assign(d ? clone(d) : { protocol: 'freedom', settings: {} }, { tag });
  config.outbounds.push(...bindDials([own], iface));
}

/**
 * Add the inbounds and their rules to `config` (in place). `tp`: [{ tag,
 * port, target, userId? }] — the target as it is now (router/index.js reads
 * it off the user). `ctx`: { serverId, plan, records, directInterface,
 * groupSkip, users ([user] — the store's), holds ({ [userId]: 'vpn' |
 * 'direct' }), profilesById, geo }. → { applied: [{ tag, port, target,
 * userId?, outboundTag, gone, entryAddrs }], skipped: [{ tag, target, why }] }.
 *
 * A config that no longer exists (deleted, replaced by a subscription
 * refresh — `gone`) keeps its inbound, routed where the catch-all goes: the
 * running tunnel may already send devices to that port (a reload happens
 * under it), and a closed port would cut them off. Its devices ride the
 * router's own connection until the user is given another config — as do a
 * user's whose config is the current connection (''). An entry whose user is
 * gone keeps its inbound the same way, with one rule to its config. Skipped —
 * no inbound, so no route in sing-box either — is only a port the config
 * already listens on, or a config with nowhere to send it.
 */
function applyTransparentTargets(config, tp, ctx = {}) {
  const applied = [], skipped = [];
  if (!isObj(config) || !Array.isArray(tp) || !tp.length) return { applied, skipped };
  config.inbounds = Array.isArray(config.inbounds) ? config.inbounds : [];
  config.outbounds = Array.isArray(config.outbounds) ? config.outbounds : [];
  config.routing = isObj(config.routing) ? config.routing : {};
  config.routing.rules = Array.isArray(config.routing.rules) ? config.routing.rules : [];
  const socksIn = config.inbounds.find(i => i && i.tag === 'socks-in');
  const sniffing = socksIn && isObj(socksIn.sniffing) ? clone(socksIn.sniffing) : { enabled: false };
  const taken = new Set(config.inbounds.map(i => i && Number(i.port)).filter(Boolean));
  const hasBlock = config.outbounds.some(o => o && o.tag === 'block');
  // where what no rule claims goes: a gone config's devices go there too (or nowhere, never direct)
  const tail = config.routing.rules[catchAllIndex(config.routing.rules)] || null;
  const fallback = tail ? (tail.balancerTag ? { balancerTag: tail.balancerTag } : { outboundTag: tail.outboundTag })
    : (hasBlock ? { outboundTag: 'block' } : null);
  const users = new Map((Array.isArray(ctx.users) ? ctx.users : []).filter(u => isObj(u) && u.id).map(u => [u.id, u]));
  const holds = isObj(ctx.holds) ? ctx.holds : {};
  const profilesById = isObj(ctx.profilesById) ? ctx.profilesById : {};
  const geo = ctx.geo === true;
  // each config once, whoever rides it (two users on one server: one outbound — a WireGuard is never two sessions)
  const outs = new Map();
  let extra = 0;
  const outFor = (target, tagBase) => {
    if (outs.has(target)) return outs.get(target);
    let r = null;
    if (typeof ctx.outboundFor === 'function') {
      const t = ctx.outboundFor(target, { tag: tagBase, config });
      r = t ? { outboundTag: t, entryAddrs: [] } : null;
    } else {
      const have = existingTag(config, target, ctx);
      const members = have ? null : membersOf(target, ctx.records);
      if (have) r = { outboundTag: have, entryAddrs: [] };
      else if (members) r = { outboundTag: buildTarget(config, { tag: tagBase }, members, ctx), entryAddrs: entryAddressesOf(members[0]).filter(Boolean) };
    }
    outs.set(target, r);
    return r;
  };
  const head = [];      // right after the DNS rules, ahead of the router's own
  const beforeTail = [];   // right before the router's catch-all
  const mirrors = [];      // '' routing: copies scoped to the inbound, each right before the router rule it copies
  for (const e of tp) {
    if (!e || typeof e.tag !== 'string' || typeof e.target !== 'string' || !Number.isInteger(e.port)) continue;
    if (taken.has(e.port)) { skipped.push({ tag: e.tag, target: e.target, why: 'port' }); continue; }
    const user = typeof e.userId === 'string' ? users.get(e.userId) || null : null;
    let route = null, gone = false, entryAddrs = [];
    if (e.target === '') route = fallback;
    else if (e.target === 'direct') route = { outboundTag: user ? directTagOf(user.id) : 'direct' };
    else if (e.target === 'block') route = hasBlock ? { outboundTag: 'block' } : fallback;
    else {
      const r = outFor(e.target, e.tag);
      if (r) { route = { outboundTag: r.outboundTag }; entryAddrs = r.entryAddrs; } else { route = fallback; gone = true; }
    }
    if (!route) { skipped.push({ tag: e.tag, target: e.target, why: 'gone' }); continue; }
    taken.add(e.port);
    config.inbounds.push({ tag: e.tag, port: e.port, listen: '127.0.0.1', protocol: 'socks', settings: { auth: 'noauth', udp: true }, sniffing: clone(sniffing) });
    applied.push(Object.assign({ tag: e.tag, port: e.port, target: e.target }, user ? { userId: user.id } : {},
      { outboundTag: route.outboundTag || route.balancerTag, gone, entryAddrs }));
    if (!user) { beforeTail.push(Object.assign({ type: 'field', inboundTag: [e.tag] }, route)); continue; }

    const directTag = directTagOf(user.id);
    ensureUserDirect(config, directTag, ctx.directInterface);
    const routing = routingOf(user.routing);
    const pid = profileIdOf(routing);
    // '' / 'global', or a profile that is gone (userRouteRules reads it as ''): the router's own routing
    const plain = !(routing === 'bypass-ir' || (pid && isObj(profilesById[pid])));
    const hold = holds[user.id] === 'vpn' || holds[user.id] === 'direct' ? holds[user.id] : null;
    // a profile's server, chain or group: its outbound, built once like the users' own; gone → the rule is left out
    const tagFor = (t) => { const r = outFor(t, `${e.tag}-r${++extra}`); return r ? r.outboundTag : null; };
    // '' routing: the router's own rules keep their order (mirrored below); the user's rules are the catch-all alone
    const rules = userRouteRules({
      user, routing, profilesById, geo, match: { inboundTag: [e.tag] }, directTag,
      targetTag: route.balancerTag ? BALANCER : route.outboundTag, hold, tagFor, baseDirect: []
    });
    for (const r of rules) if (r.outboundTag === BALANCER) { delete r.outboundTag; r.balancerTag = route.balancerTag; }
    const catchAll = rules.pop();
    if (plain) { mirrors.push({ tag: e.tag, directTag, hold }); beforeTail.push(catchAll); continue; }
    head.push(...rules, catchAll);
  }
  // each router rule that ends direct gets, right before it, a copy for each such inbound to the user's own direct
  // outbound (counted as theirs; under a hold of direct: block) — and, under a hold of the VPN, each that ends
  // anywhere but direct or block a copy to block. In place, not ahead of them all: a router rule before it (ads
  // blocked, a domain through the corporate WireGuard) still decides first, as it does for every other device.
  if (mirrors.length) {
    const from = ownRulesIndex(config.routing.rules);
    const to = catchAllIndex(config.routing.rules);
    const own = config.routing.rules.slice(from, to === -1 ? undefined : to);
    const out = [];
    for (const r of own) {
      const scoped = isObj(r) && ((Array.isArray(r.inboundTag) && r.inboundTag.length) || r.user);
      if (!scoped) {
        for (const m of mirrors) {
          const copy = (tag) => { const c = Object.assign(clone(r), { inboundTag: [m.tag], outboundTag: tag }); delete c.balancerTag; return c; };
          if (r.outboundTag === 'direct') out.push(copy(m.hold === 'direct' ? 'block' : m.directTag));
          else if (m.hold === 'vpn' && r.outboundTag !== 'block') out.push(copy('block'));
        }
      }
      out.push(r);
    }
    config.routing.rules.splice(from, own.length, ...out);
  }
  if (head.length) config.routing.rules.splice(ownRulesIndex(config.routing.rules), 0, ...head);
  if (beforeTail.length) {
    const at = catchAllIndex(config.routing.rules);
    if (at === -1) config.routing.rules.push(...beforeTail);
    else config.routing.rules.splice(at, 0, ...beforeTail);
  }
  return { applied, skipped };
}

module.exports = { applyTransparentTargets, existingTag, membersOf, catchAllIndex, ownRulesIndex, bindDials };
