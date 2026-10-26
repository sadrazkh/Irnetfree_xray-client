'use strict';
/**
 * Users on the router, transparent mode — the core's half. Every config a
 * user has (other than the current connection, "direct" and "block", which
 * the gateway does itself) gets its own SOCKS inbound `lu-tp-<n>` on a free
 * loopback port, routed to that config — the proxy pool's way of giving many
 * exits one core (configBuilder.buildPoolConfig). sing-box sends each device
 * there by its addresses (tunSingbox buildTunConfig's `lanRoutes`).
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
 * Its rule goes right before the config's catch-all: the router's own rules
 * — the DNS hijack, ads, private ranges, the routing mode, advanced routing's
 * rules — hold for every device; what none of them claims leaves through the
 * device's user's config instead of the router's default.
 *
 * `ctx.outboundFor(target, { tag, config })` may replace the lookup and the
 * build (USERS-CORE's per-target outbound builder, if it is to be shared):
 * it returns the outbound tag, or null for a config that cannot be built.
 */
const { buildChainOutbounds, expandGroups, entryAddressesOf } = require('../../../main/configBuilder');

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);

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
 * Add the inbounds and their rules to `config` (in place). `tp`: [{ tag,
 * port, target }]. → { applied: [{ tag, port, target, outboundTag, gone,
 * entryAddrs }], skipped: [{ tag, target, why }] }.
 *
 * A config that no longer exists (deleted, replaced by a subscription
 * refresh — `gone`) keeps its inbound, routed where the catch-all goes: the
 * running tunnel may already send devices to that port (a reload happens
 * under it), and a closed port would cut them off. Its devices ride the
 * router's own connection until the user is given another config. Skipped —
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
  const sniffing = socksIn && isObj(socksIn.sniffing) ? JSON.parse(JSON.stringify(socksIn.sniffing)) : { enabled: false };
  const taken = new Set(config.inbounds.map(i => i && Number(i.port)).filter(Boolean));
  // where what no rule claims goes: a gone config's devices go there too (or nowhere, never direct)
  const tail = config.routing.rules[catchAllIndex(config.routing.rules)] || null;
  const fallback = tail ? (tail.balancerTag ? { balancerTag: tail.balancerTag } : { outboundTag: tail.outboundTag })
    : (config.outbounds.some(o => o && o.tag === 'block') ? { outboundTag: 'block' } : null);
  const rules = [];
  for (const e of tp) {
    if (!e || typeof e.tag !== 'string' || typeof e.target !== 'string' || !Number.isInteger(e.port)) continue;
    if (taken.has(e.port)) { skipped.push({ tag: e.tag, target: e.target, why: 'port' }); continue; }
    let outboundTag = null;
    let entryAddrs = [];
    if (typeof ctx.outboundFor === 'function') {
      outboundTag = ctx.outboundFor(e.target, { tag: e.tag, config }) || null;
    } else {
      outboundTag = existingTag(config, e.target, ctx);
      if (!outboundTag) {
        const members = membersOf(e.target, ctx.records);
        if (members) {
          outboundTag = buildTarget(config, e, members, ctx);
          entryAddrs = entryAddressesOf(members[0]).filter(Boolean);
        }
      }
    }
    const route = outboundTag ? { outboundTag } : fallback;
    if (!route) { skipped.push({ tag: e.tag, target: e.target, why: 'gone' }); continue; }
    taken.add(e.port);
    config.inbounds.push({ tag: e.tag, port: e.port, listen: '127.0.0.1', protocol: 'socks', settings: { auth: 'noauth', udp: true }, sniffing: JSON.parse(JSON.stringify(sniffing)) });
    rules.push(Object.assign({ type: 'field', inboundTag: [e.tag] }, route));
    applied.push({ tag: e.tag, port: e.port, target: e.target, outboundTag: route.outboundTag || route.balancerTag, gone: !outboundTag, entryAddrs });
  }
  if (rules.length) {
    const at = catchAllIndex(config.routing.rules);
    if (at === -1) config.routing.rules.push(...rules);
    else config.routing.rules.splice(at, 0, ...rules);
  }
  return { applied, skipped };
}

module.exports = { applyTransparentTargets, existingTag, membersOf, catchAllIndex, bindDials };
