'use strict';
/**
 * Per-app configs under the sing-box TUN: each listed app rides a config of
 * its own — a server, a chain, a group, the connection, direct or blocked —
 * while every other app rides the connection (`exclude`) or goes direct
 * (`only`). tunApps.js decides which app goes where; this is the rest.
 *
 * It is the users module's transparent mode turned around (ProxyDog's per-app
 * proxy, built on what the app already has). There, sing-box picks a device's
 * packets by a rule-set of source addresses and hands them to a loopback Xray
 * SOCKS inbound `lu-tp-<n>` of that device's config; here it picks an app's
 * packets by `process_name` and hands them to a loopback inbound `pa-<n>` of
 * that app's config. The Xray half is the same machinery
 * (targetOutbounds.js): the target's outbounds are made where the plan's own
 * are, so every pass after them reaches them, and a target the plan already
 * dials shares its outbound (a WireGuard dialled twice is two sessions on one
 * key, each cutting the other off).
 *
 *   sing-box TUN (tunSingbox.buildTunConfig `apps`)        Xray (configBuilder)
 *     port 53                  → socks-out                  (every app's DNS: the tunnel's resolver)
 *     process_name [Telegram]  → socks 127.0.0.1:<p0> ───→ pa-0 → pa-out-<server> (or `proxy`, shared)
 *     process_name [steam]     → reject
 *     process_name [chrome]    → direct
 *     final                    → socks-out ───────────────→ socks-in → the connection
 *
 * Only 'direct', 'block' and the connection never need an inbound: sing-box
 * does those itself. A target that is gone (a deleted server, a chain that
 * lost a member, one a subscription refresh replaced) is BLOCKED — said once
 * in the log — and never quietly put on the connection: an app the user sent
 * somewhere on purpose does not get to leave by the main exit because its
 * config disappeared. The same at a reload: the tunnel keeps its rules, the
 * gone target's inbound is routed to block.
 *
 * The ports: from getFreePorts at every connect, never one the config already
 * holds. A reload keeps the live ones: the running sing-box points at them,
 * and a reload does not rebuild the tunnel.
 *
 * Node core only (no electron): src/server/service.js runs this headless too.
 */
const { targetOutbounds, loopbackSocksInbound, recordsForTargets, targetGone } = require('./targetOutbounds');

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

/** The loopback inbounds' tags (`pa-<n>`), and the outbounds made for their targets (`pa-out-<id>`). */
const TAG_PREFIX = 'pa-';
const OUT_PREFIX = 'pa-out-';
const TAG_RE = /^pa-\d{1,4}$/;
const ID_RE = /^[\w-]+$/;

/** A target that needs an inbound of its own: a server's or a group's id, or 'chain:<id>' — never '', 'direct' or 'block'. */
function needsInbound(t) {
  if (typeof t !== 'string' || !t || t === 'direct' || t === 'block') return false;
  return t.indexOf('chain:') === 0 ? ID_RE.test(t.slice('chain:'.length)) : ID_RE.test(t);
}

/** A port as a whole number 1–65535, else null. */
function portOf(v) {
  return Number.isInteger(v) && v >= 1 && v <= 65535 ? v : null;
}

/**
 * The targets of `apps.to` (tunApps.appsForTun's) that need a loopback inbound,
 * each once, in the order the listed apps name them.
 */
function loopbackTargets(apps) {
  const out = [];
  const to = apps && isObj(apps.to) ? apps.to : {};
  for (const name of apps && Array.isArray(apps.names) ? apps.names : []) {
    if (!has(to, name)) continue;
    const t = to[name];
    if (needsInbound(t) && !out.includes(t)) out.push(t);
  }
  return out;
}

/**
 * The decision with its targets bound to loopback inbounds.
 *
 * `apps`: tunApps.appsForTun's (null: nothing). `ports`: one per
 * loopbackTargets(apps), in that order. `gone(target)`: true for a target the
 * store no longer has.
 *
 * → { apps, inbounds: [{ tag, port, target }], gone: [{ name, target }] }
 *   `apps` is what buildTunConfig takes: without `to` it is the decision
 *   itself, untouched (the config of before); with it `to` is rewritten to
 *   routes — 'tunnel' (the connection), 'direct', 'block' or a `pa-<n>` — and
 *   `loopbacks` [{ tag, port }] says where each `pa-<n>` listens. A target with
 *   no port, or one that is gone, is 'block'.
 */
function bindAppTargets(apps, opts) {
  const o = opts || {};
  if (!apps || !isObj(apps.to)) return { apps: apps || null, inbounds: [], gone: [] };
  const ports = Array.isArray(o.ports) ? o.ports : [];
  const isGone = typeof o.gone === 'function' ? o.gone : () => false;
  const inbounds = [];
  const byTarget = {};
  loopbackTargets(apps).forEach((target, i) => {
    const port = portOf(ports[i]);
    if (!port || isGone(target)) return;
    const tag = TAG_PREFIX + inbounds.length;
    inbounds.push({ tag, port, target });
    byTarget[target] = tag;
  });
  const to = {};
  const gone = [];
  for (const name of apps.names) {
    if (!has(apps.to, name)) continue;
    const t = apps.to[name];
    if (t === '') to[name] = 'tunnel';
    else if (t === 'direct' || t === 'block') to[name] = t;
    else {
      to[name] = byTarget[t] || 'block';
      if (!byTarget[t] && needsInbound(t) && isGone(t)) gone.push({ name, target: t });
    }
  }
  return {
    apps: { mode: apps.mode, names: apps.names.slice(), to, loopbacks: inbounds.map((e) => ({ tag: e.tag, port: e.port })) },
    inbounds, gone
  };
}

/** The line a gone target is said with: the app, and what to do about it. */
function goneLine(name, target) {
  return `Per-app routing: the config of ${name} (${target}) no longer exists (removed, or replaced by a subscription update) — ${name} is blocked until another is picked`;
}

/**
 * The ports a per-app inbound must never take: the config's own inbounds and
 * listeners (SOCKS, HTTP, the metrics, the control API, the chain relay) and
 * the users' proxy. getFreePorts answers ports nothing holds NOW — the app's
 * own ones are free whenever it is not connected.
 */
function reservedPorts(settings) {
  const s = isObj(settings) ? settings : {};
  const out = new Set();
  for (const k of ['socksPort', 'httpPort', 'apiPort', 'apiCtlPort', 'chainRelayPort']) {
    const p = portOf(Number(s[k]));
    if (p) out.add(p);
  }
  const proxy = isObj(s.lanUsers) && isObj(s.lanUsers.config) && isObj(s.lanUsers.config.proxy) ? s.lanUsers.config.proxy : null;
  if (proxy) for (const k of ['port', 'httpPort']) { const p = portOf(Number(proxy[k])); if (p) out.add(p); }
  for (const e of isObj(s.lanUsers) && Array.isArray(s.lanUsers.tp) ? s.lanUsers.tp : []) { const p = portOf(Number(e && e.port)); if (p) out.add(p); }
  return out;
}

/**
 * `count` free loopback ports, none of them `reserved`: asked for with room to
 * spare, as the router's transparent inbounds are (lanUsers/router).
 */
async function freePortsFor(count, getFreePorts, reserved) {
  if (!count) return [];
  const own = reserved instanceof Set ? reserved : new Set();
  const got = await getFreePorts(count + own.size);
  return [...new Set(got)].filter((p) => !own.has(p)).slice(0, count);
}

/**
 * Everything a connect needs, from the decision: the inbounds bound to free
 * ports, the records their targets name (`store`: { servers, groups, chains }),
 * those records' WireGuard endpoint names resolved (`resolveWg(hosts)` → { host:
 * ip }), and the addresses their configs dial directly — for the tunnel's
 * bypass and, under the strict guard, the firewall holes, exactly like the
 * connection's own entry servers.
 *
 * → { apps (for the TUN), appRoutes (the build's `settings.appRoutes`, null
 *   when no app has a config of its own), bypass: [address], gone: [{ name,
 *   target }], labels: { [pa-<n>]: the config's name, for the log } }
 */
async function connectAppRoutes({ apps, store, getFreePorts, reserved, resolveWg }) {
  const targets = loopbackTargets(apps);
  if (!targets.length) {
    const bound = bindAppTargets(apps, { ports: [] });
    return { apps: bound.apps, appRoutes: null, bypass: [], gone: bound.gone, labels: {} };
  }
  const records = recordsForTargets(targets, store);
  const live = targets.filter((t) => !targetGone(t, records));
  const ports = await freePortsFor(live.length, getFreePorts, reserved);
  // a port per target that is still there, in the order loopbackTargets lists them
  const portByTarget = {};
  live.forEach((t, i) => { if (ports[i]) portByTarget[t] = ports[i]; });
  const bound = bindAppTargets(apps, { ports: targets.map((t) => portByTarget[t] || null), gone: (t) => targetGone(t, records) });
  if (!bound.inbounds.length) return { apps: bound.apps, appRoutes: null, bypass: [], gone: bound.gone, labels: {} };
  const chains = isObj(store) && Array.isArray(store.chains) ? store.chains : [];
  const labels = {};
  for (const e of bound.inbounds) {
    const cid = e.target.indexOf('chain:') === 0 ? e.target.slice('chain:'.length) : null;
    const c = cid ? chains.find((x) => x && x.id === cid) : null;
    const rec = cid ? null : records.serversById[e.target];
    labels[e.tag] = String((c && c.name) || (rec && rec.name) || e.target);
  }
  const { wgEndpointHosts, entryAddressesOf } = require('./configBuilder');
  const used = recordsForTargets(bound.inbounds.map((e) => e.target), store);
  const hosts = wgEndpointHosts({ mode: 'pool', serversById: used.serversById, chainsById: used.chainsById });
  let wgEndpointIps = {};
  if (hosts.length && typeof resolveWg === 'function') {
    try { wgEndpointIps = (await resolveWg(hosts)) || {}; } catch { wgEndpointIps = {}; }
  }
  const bypass = [];
  for (const e of bound.inbounds) {
    const first = e.target.indexOf('chain:') === 0
      ? ((used.chainsById[e.target.slice('chain:'.length)] || []).filter((x) => x && x.outbound)[0] || null)
      : used.serversById[e.target];
    for (const a of entryAddressesOf(first)) if (a && !bypass.includes(a)) bypass.push(a);
  }
  for (const ip of Object.values(wgEndpointIps)) if (ip && !bypass.includes(ip)) bypass.push(ip);
  // which apps ride each inbound — for a reload's "gone" line (namesFor); the builder never reads it
  const names = {};
  for (const [name, r] of Object.entries(bound.apps.to)) if (TAG_RE.test(r)) (names[r] = names[r] || []).push(name);
  return {
    apps: bound.apps,
    appRoutes: { inbounds: bound.inbounds, serversById: used.serversById, chainsById: used.chainsById, wgEndpointIps, names },
    bypass, gone: bound.gone, labels
  };
}

/** The apps riding `target` in an `appRoutes` (connectAppRoutes' `names`). */
function namesFor(ar, target) {
  const names = isObj(ar) && isObj(ar.names) ? ar.names : {};
  const out = [];
  for (const e of appRoutesOf(ar)) if (e.target === target) for (const n of Array.isArray(names[e.tag]) ? names[e.tag] : []) if (!out.includes(n)) out.push(n);
  return out;
}

/**
 * A reload's `settings.appRoutes`: the live inbounds — the running sing-box
 * points at their ports — with their records read again (a target deleted
 * since the connect is now blocked, and said so) and the WireGuard addresses
 * the connect pinned (the tunnel's bypass was cut for exactly those).
 * → { appRoutes, gone: [target] }
 */
function reloadAppRoutes(live, store) {
  const inbounds = appRoutesOf(live);
  if (!inbounds.length) return { appRoutes: null, gone: [] };
  const records = recordsForTargets(inbounds.map((e) => e.target), store);
  const gone = [...new Set(inbounds.map((e) => e.target).filter((t) => targetGone(t, records)))];
  return {
    appRoutes: {
      inbounds, serversById: records.serversById, chainsById: records.chainsById,
      wgEndpointIps: isObj(live.wgEndpointIps) ? Object.assign({}, live.wgEndpointIps) : {},
      names: isObj(live.names) ? JSON.parse(JSON.stringify(live.names)) : {}
    },
    gone
  };
}

/* ------------------------------ the connect path ------------------------------ */

/**
 * The per-app step of a connect and of a reload, for main.js and the headless
 * service alike (both hand in their own store, resolver and log):
 *
 *   storeLists()          → { servers, groups, chains } as buildPlan reads them
 *   resolveHost(name, o)  trustedDns.resolveHost's shape → { ips }
 *   lastWg                the connect path's Map of WireGuard names → the last address
 *   getFreePorts(n)       xrayManager's
 *   log({ line, level })
 *
 * → { forConnect(settings, tun), forReload(live) }
 *
 * forConnect: null when no tunnel can run (not TUN mode, its backend not
 * installed); else { apps (the TUN's), warn (the decision's refusal or note,
 * said where the tunnel starts), appRoutes (the build's), bypass, labels }.
 * The decision is made HERE, before the build — an app with a config of its
 * own needs an inbound the core has to open — and told what the backend
 * really is: the native macOS service calls itself 'sing-box' (a sing-box is
 * what it runs) but is never given a process rule (tunApps.js).
 *
 * forReload: the build's `appRoutes` for the live inbounds (reloadAppRoutes),
 * a config gone since then said once.
 */
function createPerApp(o) {
  const deps = o || {};
  const log = typeof deps.log === 'function' ? deps.log : () => {};
  const lastWg = deps.lastWg instanceof Map ? deps.lastWg : new Map();
  const storeLists = typeof deps.storeLists === 'function' ? deps.storeLists : () => ({});
  const said = new Set();   // (app, target) said to be gone — once each, like the users' (lanUsers/ipc.js)
  const sayGone = (list) => {
    for (const { name, target } of list || []) {
      const key = name + '\n' + target;
      if (said.has(key)) continue;
      said.add(key);
      log({ line: goneLine(name, target), level: 'warn' });
    }
  };

  /**
   * The WireGuard names of the apps' configs, resolved as the connection's
   * are: the connect's own answer, trustedDns, then the last connect's
   * address. One that does not resolve is left out — configBuilder's `unsafe`
   * then keeps that config from the core, and its apps are blocked.
   */
  async function resolveWg(hosts, settings) {
    const known = isObj(settings.wgEndpointIps) ? settings.wgEndpointIps : {};
    const map = {};
    await Promise.all(hosts.map(async (h) => {
      if (known[h]) { map[h] = known[h]; return; }
      const r = typeof deps.resolveHost === 'function'
        ? await deps.resolveHost(h, { ipv6: !!settings.ipv6, doh: settings.dnsRemote }).catch(() => null) : null;
      if (r && Array.isArray(r.ips) && r.ips.length) { map[h] = r.ips[0]; lastWg.set(h, r.ips[0]); return; }
      const last = lastWg.get(h);
      if (last) { map[h] = last; return; }
      log({ line: `Per-app routing: the WireGuard endpoint ${h} does not resolve — the apps riding that config are blocked until it does`, level: 'warn' });
    }));
    return map;
  }

  async function forConnect(settings, tun) {
    const s = isObj(settings) ? settings : {};
    if (!s.tunMode || !tun || !tun.isAvailable()) return null;
    const { appsForTun } = require('./tunApps');
    const { apps, warn } = appsForTun(s, tun.native ? 'native-macos' : tun.backendId);
    if (!apps) return { apps: null, warn, appRoutes: null, bypass: [], labels: {} };
    const r = await connectAppRoutes({
      apps, store: storeLists(), getFreePorts: deps.getFreePorts, reserved: reservedPorts(s),
      resolveWg: (hosts) => resolveWg(hosts, s)
    });
    sayGone(r.gone);
    // TUIC / AnyTLS: no Xray core carries them, so an app sent to one is blocked (configBuilder's `unsafe`) — said by name
    const { isSingboxOnly } = require('./engineChoice');
    const { serversOf } = require('./groups');
    for (const e of r.appRoutes ? r.appRoutes.inbounds : []) {
      const recs = e.target.indexOf('chain:') === 0 ? (r.appRoutes.chainsById[e.target.slice('chain:'.length)] || []) : [r.appRoutes.serversById[e.target]];
      if (recs.some((rec) => rec && serversOf(rec).some(isSingboxOnly))) {
        log({ line: `Per-app routing: “${r.labels[e.tag]}” is TUIC / AnyTLS, which only runs as the connection itself — the apps riding it are blocked`, level: 'warn' });
      }
    }
    return { apps: r.apps, warn, appRoutes: r.appRoutes, bypass: r.bypass, labels: r.labels };
  }

  function forReload(live) {
    const r = reloadAppRoutes(live, storeLists());
    for (const t of r.gone) sayGone(namesFor(live, t).map((name) => ({ name, target: t })));
    return r.appRoutes;
  }

  return { forConnect, forReload };
}

/* ------------------------------ the Xray side ------------------------------ */

/**
 * `settings.appRoutes`'s inbounds, each of a shape that can be written:
 * [{ tag, port, target }] — a `pa-<n>` tag once, a port, a target that needs an
 * inbound. Anything else is left out rather than written into the core's config.
 */
function appRoutesOf(ar) {
  const out = [];
  for (const e of isObj(ar) && Array.isArray(ar.inbounds) ? ar.inbounds : []) {
    if (!isObj(e) || typeof e.tag !== 'string' || !TAG_RE.test(e.tag) || out.some((x) => x.tag === e.tag)) continue;
    const port = portOf(e.port);
    if (!port || !needsInbound(e.target)) continue;
    out.push({ tag: e.tag, port, target: e.target });
  }
  return out;
}

/** There is something to build: at least one app with a config of its own. */
function applies(settings) {
  return appRoutesOf(settings && settings.appRoutes).length > 0;
}

/**
 * The outbounds the apps' targets need, and the tag each is routed to
 * (targetOutbounds.js: `pa-out-<id>`, or the outbound the config already has
 * for that very target). `ctx` as configBuilder makes it for the users.
 */
function appRouteOutbounds(ar, ctx) {
  const targets = [];
  for (const e of appRoutesOf(ar)) if (!targets.includes(e.target)) targets.push(e.target);
  return targetOutbounds(targets, ctx, OUT_PREFIX);
}

/** The ports a config already holds: its inbounds', and the metrics and control API listeners'. */
function portsOf(config) {
  const used = new Set();
  for (const i of Array.isArray(config.inbounds) ? config.inbounds : []) { const p = portOf(i && Number(i.port)); if (p) used.add(p); }
  for (const k of ['metrics', 'api']) {
    const m = isObj(config[k]) && typeof config[k].listen === 'string' ? /:(\d+)$/.exec(config[k].listen) : null;
    if (m) used.add(Number(m[1]));
  }
  return used;
}

/**
 * The apps' inbounds and rules into a built config (mutated, and returned).
 * `ctx`: { tags (appRouteOutbounds'), ruleAt, sniffing }.
 *
 * One loopback SOCKS inbound per target (127.0.0.1: only the local sing-box
 * dials it), and one rule each — that inbound → its target — at `ruleAt`:
 * after the groups' loopback rules and the DNS rules, ahead of the plan's own,
 * so an app's traffic is decided by its own config alone (the owner's routing
 * rules are the connection's). A target the caller did not resolve, or one
 * that resolved to nothing, is 'block'. A port the config already holds is
 * left out — the core would refuse to start over it, taking the connection
 * with it (main.js never hands one: reservedPorts).
 */
function applyAppRoutes(config, ar, ctx) {
  if (!isObj(config)) return config;
  const c = ctx || {};
  const tags = isObj(c.tags) ? c.tags : {};
  const sniffing = c.sniffing || { enabled: false };
  const used = portsOf(config);
  const inbounds = [];
  const rules = [];
  for (const e of appRoutesOf(ar)) {
    if (used.has(e.port)) continue;
    used.add(e.port);
    inbounds.push(loopbackSocksInbound(e.tag, e.port, sniffing));
    rules.push({ type: 'field', inboundTag: [e.tag], outboundTag: has(tags, e.target) && tags[e.target] ? tags[e.target] : 'block' });
  }
  if (!inbounds.length) return config;
  config.inbounds = (Array.isArray(config.inbounds) ? config.inbounds : []).concat(inbounds);
  if (!isObj(config.routing)) config.routing = { rules: [] };
  if (!Array.isArray(config.routing.rules)) config.routing.rules = [];
  const at = Math.max(0, Math.min(Number.isInteger(c.ruleAt) ? c.ruleAt : 0, config.routing.rules.length));
  config.routing.rules.splice(at, 0, ...rules);
  return config;
}

/**
 * The live inbounds a built config does NOT carry — a config in sing-box's own
 * format (TUIC / AnyTLS), a raw JSON run as written: nothing there answers on
 * those ports. Their apps are blocked in the TUN rather than left to a port
 * nobody opens (main.js says so by name).
 */
function missingInbounds(config, inbounds) {
  const have = new Set((isObj(config) && Array.isArray(config.inbounds) ? config.inbounds : []).map((i) => i && i.tag));
  return (Array.isArray(inbounds) ? inbounds : []).filter((e) => !have.has(e.tag));
}

/** `apps` (bindAppTargets') with the apps routed to these `pa-<n>` tags blocked instead; the names that were. */
function blockRoutes(apps, tags) {
  if (!apps || !isObj(apps.to) || !tags.length) return { apps, names: [] };
  const to = Object.assign({}, apps.to);
  const names = [];
  for (const [name, r] of Object.entries(to)) if (tags.includes(r)) { to[name] = 'block'; names.push(name); }
  const loopbacks = (apps.loopbacks || []).filter((l) => !tags.includes(l.tag));
  return { apps: Object.assign({}, apps, { to, loopbacks }), names };
}

/**
 * The log line for a tunnel built with per-app rules. Without targets, the
 * line of before. `labelOf(target)` names a config ('' when it cannot).
 */
function describeApps(apps, labelOf) {
  if (!apps) return '';
  if (!isObj(apps.to)) {
    return `Per-app routing: ${apps.mode === 'exclude' ? 'these apps go around the tunnel' : 'only these apps use the tunnel'} — ${apps.names.join(', ')}`;
  }
  const def = apps.mode === 'exclude' ? 'direct' : 'tunnel';
  const word = { tunnel: 'the connection', direct: 'direct', block: 'blocked' };
  const parts = apps.names.map((n) => {
    const r = has(apps.to, n) ? apps.to[n] : def;
    return `${n} → ${word[r] || (typeof labelOf === 'function' && labelOf(r)) || r}`;
  });
  return `Per-app routing: ${parts.join(', ')}; every other app ${apps.mode === 'exclude' ? 'rides the connection' : 'goes direct'}`;
}

module.exports = {
  TAG_PREFIX, OUT_PREFIX,
  loopbackTargets, bindAppTargets, goneLine, reservedPorts, freePortsFor, connectAppRoutes, reloadAppRoutes, namesFor, createPerApp,
  appRoutesOf, applies, appRouteOutbounds, applyAppRoutes, missingInbounds, blockRoutes, describeApps
};
