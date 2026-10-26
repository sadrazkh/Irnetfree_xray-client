'use strict';
/**
 * Users and devices (module `lanUsers`) in the Xray config: a username/password
 * SOCKS5 and HTTP proxy on the LAN, each user routed to a config of their own,
 * each user's bytes counted by the core.
 *
 * What the core does with a SOCKS or HTTP account — read in XTLS/Xray-core
 * v26.10.21 (the PattN fork's 26.10.22 is the same in every one of these files):
 *  - An account is `{ user, pass }` and nothing else: the server side keeps a
 *    username → password map, with no email or level of its own
 *    (infra/conf/socks.go:13-16 and 50-59, infra/conf/http.go:13-16 and 38-47).
 *  - A SOCKS5 login names the session's user by its USERNAME — `request.User =
 *    &protocol.MemoryUser{Email: username}` (proxy/socks/protocol.go:164-165),
 *    copied onto the inbound (proxy/socks/server.go:135-136); UDP ASSOCIATE
 *    keeps that inbound, so a user's UDP is theirs too (server.go:168-190).
 *    SOCKS4 is refused when a password is required (protocol.go:52-55).
 *  - HTTP checks Proxy-Authorization and does the same: `inbound.User.Email =
 *    user` (proxy/http/server.go:121-128) — but only when the inbound HAS
 *    accounts: with none it lets anyone through (server.go:121), and so does
 *    the HTTP a SOCKS inbound answers on its own port, which gets the SOCKS
 *    accounts handed on (proxy/socks/server.go:44-49). So no active user means
 *    no inbound at all, never an empty account list.
 *  - Routing's `user` matches that Email (app/router/condition.go:185-196, via
 *    features/routing/session/context.go:123-127).
 *  - Per-user stats are `user>>><Email>>>>traffic>>>uplink|downlink` when the
 *    user's level has statsUserUplink/Downlink (app/dispatcher/default.go:
 *    161-176) — level 0, every config this app builds — and /debug/vars
 *    reports them under stats.user[<Email>] (app/metrics/metrics.go:175-201).
 * So ONE SOCKS inbound (`lu-socks`) and ONE HTTP inbound (`lu-http`) carry
 * every user, and a user is known to routing and to the counters by their
 * username — unique, case aside (model.js). No port per user is needed.
 *
 * configBuilder.buildConfig and buildPoolConfig call in two places, only when
 * applies(settings): lanUsersOutbounds() where the plan's own outbounds are
 * made — so every pass after it (multi-internet, groups, the WireGuard fixes,
 * pinned names, anti-DPI dialers, ECH, the NIC binding under TUN) reaches a
 * user's config exactly as it reaches the plan's — and applyLanUsers() at the
 * end, for the inbounds and the rules. Off, neither runs: not a byte of the
 * config changes.
 *
 * `settings.lanUsers` — what ipc.js forBuild() hands the build (the store's
 * record plus what only the running app knows):
 *   { config, users, devices,        the store's record (model.js)
 *     over: [userId],                over their cap this period (meter.js)
 *     now,                           ms — expiry is judged at this moment
 *     listen,                        the LAN address the proxy binds: absent = '0.0.0.0'
 *                                    (the desktop, as LAN sharing binds); '' = none known (no proxy)
 *     serversById, chainsById,       the records the users' targets name (a chain that lost a
 *                                    member is null: blocked, never a shorter chain)
 *     wgEndpointIps,                 WireGuard endpoint names of those, resolved
 *     tp: [{ tag | n, port, target }] the router's transparent mode: one loopback SOCKS inbound
 *                                    `lu-tp-<n>` per distinct target, routed like a user }
 */
const net = require('net');
const { normalizeLanUsers, normalizeConfig, activeUsers, portOf, targetOk } = require('./model');

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);

const SOCKS_TAG = 'lu-socks';
const HTTP_TAG = 'lu-http';
const OUT_PREFIX = 'lu-out-';
const TP_PREFIX = 'lu-tp-';
/**
 * Where nobody on the LAN may get to THROUGH the proxy: this machine's own
 * loopback — the core's metrics and control API, the router's admin page and
 * anything else that trusts 127.0.0.1. The IPs as written; the name
 * `localhost` (and its subdomains) as a name, before anything resolves it.
 */
const LOOPBACK_IPS = ['127.0.0.0/8', '0.0.0.0/8', '::1/128', '::/128'];
const LOOPBACK_NAMES = ['domain:localhost'];

/** The module is installed and there is something for it to do: the users' proxy on, or the router's transparent inbounds. */
function applies(settings) {
  const s = settings || {};
  if (!(s.modules && s.modules.lanUsers) || !isObj(s.lanUsers)) return false;
  return normalizeConfig(s.lanUsers.config).proxy.enabled || tpOf(s.lanUsers).length > 0;
}

/** The address the users' proxy binds: '0.0.0.0' when the input names none, '' when it names none usable. */
function listenOf(lu) {
  if (!isObj(lu) || lu.listen === undefined) return '0.0.0.0';
  return typeof lu.listen === 'string' && net.isIP(lu.listen) ? lu.listen : '';
}

/** The router's transparent inbounds, each of a shape that can be written: [{ tag, port, target }]. */
function tpOf(lu) {
  const out = [];
  const tags = new Set();
  for (const e of isObj(lu) && Array.isArray(lu.tp) ? lu.tp : []) {
    if (!isObj(e)) continue;
    const tag = typeof e.tag === 'string' ? e.tag : (e.n != null ? TP_PREFIX + e.n : '');
    const port = portOf(e.port);
    const target = e.target == null ? '' : e.target;
    if (!/^lu-tp-[\w-]+$/.test(tag) || tags.has(tag) || !port || !targetOk(target)) continue;
    tags.add(tag);
    out.push({ tag, port, target });
  }
  return out;
}

/** Who may use the proxy in this build (model.activeUsers at the input's moment, less the ones over their cap). */
function activeOf(lu) {
  const now = isObj(lu) && typeof lu.now === 'number' ? lu.now : Date.now();
  return activeUsers(lu, { now, over: isObj(lu) ? lu.over : null, usage: isObj(lu) ? lu.usage : null });
}

/** Every target this build has to reach: the active users' (when the proxy is on) and the transparent inbounds', each once. */
function neededTargets(lu) {
  const out = [];
  const n = normalizeLanUsers(lu);
  if (n.config.proxy.enabled && listenOf(lu)) for (const u of activeOf(lu)) if (!out.includes(u.target)) out.push(u.target);
  for (const e of tpOf(lu)) if (!out.includes(e.target)) out.push(e.target);
  return out;
}

/**
 * The outbounds the users' targets need, and the tag each target is routed to:
 * → { outbounds, tags: { [target]: tag } }. Raw, as the plan's own are before
 * the builder's passes — the caller puts them beside those.
 *
 * `ctx` (configBuilder makes it): { exitTag, serversById, chainsById,
 *   existingTag(target) → a tag the plan already has for exactly that target,
 *   server(record, tag) → outbounds, chain(records, tag) → outbounds,
 *   unsafe(record) → true when the core must not be handed it (a WireGuard
 *   endpoint name nobody resolved: a core left to resolve one can go down with
 *   it, taking the owner's own connection along) }.
 *
 *  - ''  → the plan's exit (whatever this machine is connected through now);
 *  - 'direct' / 'block' → those;
 *  - the server, chain or group the plan already dials as that very target →
 *    its outbound, shared: a WireGuard dialled twice is two sessions on one
 *    key, and the peer keeps only the newest — each would cut the other off;
 *  - else its own `lu-out-<id>` (`lu-out-chain-<cid>` for a chain);
 *  - a target that is gone, a chain that lost a member, an unsafe one →
 *    'block'. A user's traffic is never sent out unprotected because their
 *    config disappeared.
 */
function lanUsersOutbounds(lu, ctx) {
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
      const tag = OUT_PREFIX + 'chain-' + cid;
      push(c.chain(list, tag));
      return tag;
    }
    const srv = servers[target];
    if (!srv || !srv.outbound || unsafe([srv]) || typeof c.server !== 'function') return 'block';
    const tag = OUT_PREFIX + target;
    push(c.server(srv, tag));
    return tag;
  }

  const tags = {};
  for (const t of neededTargets(lu)) tags[t] = tagOf(t);
  return { outbounds, tags };
}

/** The ports a config already holds: its inbounds', and the metrics and control API listeners'. */
function portsOf(config) {
  const used = new Set();
  for (const i of Array.isArray(config.inbounds) ? config.inbounds : []) { const p = portOf(i && i.port); if (p) used.add(p); }
  for (const k of ['metrics', 'api']) {
    const m = isObj(config[k]) && typeof config[k].listen === 'string' ? /:(\d+)$/.exec(config[k].listen) : null;
    if (m) used.add(Number(m[1]));
  }
  return used;
}

/** A target's tag when the caller did not resolve it (a config made outside configBuilder): what the config has for it, else block. */
function fallbackTag(target, config, c) {
  const have = new Set((Array.isArray(config.outbounds) ? config.outbounds : []).map((o) => o && o.tag));
  if (!target) return c.exitTag || (have.has('proxy') ? 'proxy' : 'direct');
  if (target === 'direct' || target === 'block') return target;
  const id = target.indexOf('chain:') === 0 ? 'chain-' + target.slice('chain:'.length) : target;
  return [OUT_PREFIX + id, 'out-' + id].find((t) => have.has(t)) || 'block';
}

/**
 * The users' inbounds and rules into a built config (mutated, and returned).
 * `ctx`: { tags (lanUsersOutbounds'), ruleAt (where the rules go: after the
 * groups' loopback rules and the DNS rules, so a user's port-53 query is
 * answered by the app's own resolver like everyone's — the in-country DNS
 * never sees it), sniffing, exitTag }.
 *
 * The inbounds listen on the LAN (listenOf): `lu-socks` (SOCKS5, password,
 * UDP) and `lu-http`, both with every active user's account — disabled,
 * expired and capped users are simply not in them, so the core refuses them
 * like a wrong password. None at all when no one is active (see the header). A
 * port another inbound, the metrics or the control API holds is left out — the
 * core would refuse to start over it, taking the owner's connection with it.
 *
 * The rules, ahead of the plan's own: this machine's loopback blocked for
 * anyone coming in on them; one rule per user — that inbound and that
 * username → their target; whatever is left on them (nothing should be)
 * blocked. So a user's traffic is decided by their own target alone — the
 * owner's advanced rules (a corporate WireGuard for a domain, say) never apply
 * to it. Then each transparent inbound (`lu-tp-<n>`, loopback only: sing-box
 * hands it the devices' traffic) → its target.
 */
function applyLanUsers(config, lu, ctx) {
  if (!isObj(config) || !isObj(lu)) return config;
  const c = ctx || {};
  const n = normalizeLanUsers(lu);
  const tags = isObj(c.tags) ? c.tags : {};
  const tagOf = (t) => (Object.prototype.hasOwnProperty.call(tags, t) ? tags[t] : fallbackTag(t, config, c));
  const sniffing = c.sniffing || { enabled: false };
  const used = portsOf(config);
  const take = (port) => { if (!port || used.has(port)) return false; used.add(port); return true; };
  const inbounds = [];
  const guarded = [];
  const userRules = [];
  const tail = [];

  const listen = listenOf(lu);
  const active = activeOf(lu);
  if (n.config.proxy.enabled && active.length && listen) {
    const accounts = () => active.map((u) => ({ user: u.username, pass: u.password }));
    const ins = [];
    if (take(n.config.proxy.port)) {
      inbounds.push({ tag: SOCKS_TAG, port: n.config.proxy.port, listen, protocol: 'socks', settings: { auth: 'password', accounts: accounts(), udp: true }, sniffing });
      ins.push(SOCKS_TAG);
    }
    if (n.config.proxy.httpPort && take(n.config.proxy.httpPort)) {
      inbounds.push({ tag: HTTP_TAG, port: n.config.proxy.httpPort, listen, protocol: 'http', settings: { accounts: accounts(), allowTransparent: false }, sniffing });
      ins.push(HTTP_TAG);
    }
    if (ins.length) {
      guarded.push(...ins);
      for (const u of active) userRules.push({ type: 'field', inboundTag: ins.slice(), user: [u.username], outboundTag: tagOf(u.target) });
      tail.push({ type: 'field', inboundTag: ins.slice(), outboundTag: 'block' });
    }
  }
  for (const e of tpOf(lu)) {
    if (!take(e.port)) continue;
    inbounds.push({ tag: e.tag, port: e.port, listen: '127.0.0.1', protocol: 'socks', settings: { auth: 'noauth', udp: true }, sniffing });
    guarded.push(e.tag);
    userRules.push({ type: 'field', inboundTag: [e.tag], outboundTag: tagOf(e.target) });
  }
  if (!inbounds.length) return config;

  const rules = [
    { type: 'field', inboundTag: guarded.slice(), ip: LOOPBACK_IPS.slice(), outboundTag: 'block' },
    { type: 'field', inboundTag: guarded.slice(), domain: LOOPBACK_NAMES.slice(), outboundTag: 'block' },
    ...userRules,
    ...tail
  ];
  config.inbounds = (Array.isArray(config.inbounds) ? config.inbounds : []).concat(inbounds);
  if (!isObj(config.routing)) config.routing = { rules: [] };
  if (!Array.isArray(config.routing.rules)) config.routing.rules = [];
  const at = Math.max(0, Math.min(Number.isInteger(c.ruleAt) ? c.ruleAt : 0, config.routing.rules.length));
  config.routing.rules.splice(at, 0, ...rules);
  // the per-user counters (configBuilder's level 0 has them on already; a config from elsewhere may not)
  if (!isObj(config.policy)) config.policy = {};
  if (!isObj(config.policy.levels)) config.policy.levels = {};
  config.policy.levels['0'] = Object.assign({}, config.policy.levels['0'], { statsUserUplink: true, statsUserDownlink: true });
  if (!isObj(config.stats)) config.stats = {};
  return config;
}

module.exports = {
  SOCKS_TAG, HTTP_TAG, OUT_PREFIX, TP_PREFIX, LOOPBACK_IPS, LOOPBACK_NAMES,
  applies, listenOf, tpOf, activeOf, neededTargets, lanUsersOutbounds, applyLanUsers
};
