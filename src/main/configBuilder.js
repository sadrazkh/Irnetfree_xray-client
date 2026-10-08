'use strict';
/**
 * Builds a complete Xray config.json.
 *
 * A "plan" describes what to connect through:
 *   { mode: 'single',   server }                       single proxy
 *   { mode: 'chain',    chain: [server,…] }            client → s0 → s1 → … → exit
 *   { mode: 'advanced', serversById, chain, rules, def } per-rule routing
 *     — a routing profile's plan also carries profileId, defVia, base and
 *       useMode (routingProfiles.js): a rule's `via` and the default's
 *       `defVia` send a target through a base (makeRegistry)
 *
 * Legacy callers may still pass a bare server object or an array of servers;
 * normalizePlan() converts those into the structured form above.
 */

const net = require('net');
const { buildDnsPlan, DNS_TAG } = require('./dnsBuilder');
const { normalizePin } = require('./certPin');
const { planServers } = require('./engineChoice');
const { MUX, muxEligible } = require('./mux');
const { effectiveVia, advancedTargets } = require('./routingProfiles');

/**
 * Private / reserved IPv4+IPv6 ranges. Used INSTEAD of `geoip:private` so that
 * LAN/loopback bypass works even when the geoip.dat file is missing (otherwise
 * xray refuses to load the whole config and every routing mode breaks).
 */
const PRIVATE_IPS = [
  '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
  '172.16.0.0/12', '192.168.0.0/16', '224.0.0.0/4', '240.0.0.0/4',
  '::1/128', 'fc00::/7', 'fe80::/10'
];

/**
 * Routing modes (simple mode only):
 *  - 'global'   : everything through proxy (except private/LAN)
 *  - 'bypass-ir': bypass Iran -> direct, rest -> proxy
 *  - 'bypass-cn': bypass China -> direct, rest -> proxy
 *  - 'direct'   : everything direct (for testing)
 *
 * `geo` = whether geoip.dat/geosite.dat are installed. When false we skip every
 * geosite:/geoip: rule (xray would otherwise fail to start) and fall back to
 * literal private-range bypass only.
 */
function buildRoutingRules(mode, blockAds, geo) {
  const rules = [];
  if (blockAds && geo) {
    rules.push({ type: 'field', domain: ['geosite:category-ads-all'], outboundTag: 'block' });
  }
  // private/LAN always direct — literal ranges, no geo file needed
  rules.push({ type: 'field', ip: PRIVATE_IPS.slice(), outboundTag: 'direct' });

  if (mode === 'bypass-ir' && geo) {
    rules.push({ type: 'field', domain: ['geosite:category-ir', 'regexp:.*\\.ir$'], outboundTag: 'direct' });
    rules.push({ type: 'field', ip: ['geoip:ir'], outboundTag: 'direct' });
    rules.push({ type: 'field', port: '0-65535', outboundTag: 'proxy' });
  } else if (mode === 'bypass-cn' && geo) {
    rules.push({ type: 'field', domain: ['geosite:cn'], outboundTag: 'direct' });
    rules.push({ type: 'field', ip: ['geoip:cn'], outboundTag: 'direct' });
    rules.push({ type: 'field', port: '0-65535', outboundTag: 'proxy' });
  } else if (mode === 'direct') {
    rules.push({ type: 'field', port: '0-65535', outboundTag: 'direct' });
  } else {
    rules.push({ type: 'field', port: '0-65535', outboundTag: 'proxy' });
  }
  return rules;
}

/**
 * The country-bypass part of a simple routing mode, on its own.
 *
 * Advanced routing lays its own private-range rule and ends with the user's own
 * default target, so a mode contributes only what sits between the two: the
 * "send this country direct" pair. `global` and `direct` contribute nothing —
 * their whole content IS the catch-all, which the advanced default owns.
 */
function modeBypassRules(mode, geo) {
  const base = buildRoutingRules(mode, false, geo);
  base.pop();     // the port:0-65535 catch-all — the advanced default owns it
  base.shift();   // the private-range bypass — the caller already laid one
  return base;
}

/**
 * A server's outbound as the config will carry it. `server` is the record the
 * outbound belongs to — its certificate pin, if any, goes into tlsSettings.
 */
function cloneOut(outbound, tag, server) {
  const o = JSON.parse(JSON.stringify(outbound));
  o.tag = tag;
  return applyCertPin(o, server);
}

/**
 * The mux object (mux.js) on the outbound of a server the connect chose it
 * for — `settings.muxServerIds`, decided per server by a test (auto) or for
 * every one (on). Only a server's OWN outbound, never a chain's hop, and only
 * one that can carry it; anything but a list leaves the outbound as it was.
 */
function applyMux(o, server, muxIds) {
  if (!Array.isArray(muxIds) || !muxIds.length || !server || !muxIds.includes(server.id) || !muxEligible(o)) return o;
  o.mux = Object.assign({}, MUX);
  return o;
}

/**
 * allowInsecure is gone from the core (both cores reject it at config load):
 * never emit it, true or false. A record that learnt its server's certificate
 * on first use (certPin.js) pins it instead — the core then accepts that
 * certificate and no other; without a pin it verifies the chain as usual and
 * its own error is the user's signal.
 */
function applyCertPin(o, server) {
  const tls = o && o.streamSettings && o.streamSettings.tlsSettings;
  if (!tls) return o;
  delete tls.allowInsecure;
  // The link's own pins (`pcs`) and the one learnt on first use, together:
  // the core accepts a certificate that matches any of them.
  const pins = [...String(tls.pinnedPeerCertSha256 || '').split(','), server && server.certPin]
    .map(normalizePin).filter(Boolean);
  if (pins.length) tls.pinnedPeerCertSha256 = [...new Set(pins)].join(',');
  else delete tls.pinnedPeerCertSha256;
  return o;
}

/**
 * An ECH config list that is a DNS QUERY rather than the config itself:
 * `name+udp://1.1.1.1`, `name+https://1.1.1.1/dns-query`, or the server alone
 * (the SNI is then the name asked for). { name, server, scheme, host, port } —
 * `host` the resolver's address or name; null for a base64 list (nothing to
 * dial) or anything unreadable. The `+` counts only before the `://`.
 */
function echQueryOf(list) {
  const s = String(list == null ? '' : list).trim();
  const sep = s.indexOf('://');
  if (sep === -1) return null;
  const plus = s.indexOf('+');
  const name = plus > -1 && plus < sep ? s.slice(0, plus) : '';
  const server = plus > -1 && plus < sep ? s.slice(plus + 1) : s;
  const m = /^([a-z0-9]+):\/\/(\[[^\]]+\]|[^/:?#]+)(?::(\d+))?/i.exec(server);
  if (!m) return null;
  return { name, server, scheme: m[1].toLowerCase(), host: m[2].replace(/^\[|\]$/g, ''), port: m[3] ? parseInt(m[3], 10) : null };
}

/** The TLS settings of every outbound whose ECH config is fetched from DNS. */
function echQueryTls(outbounds) {
  const out = [];
  for (const o of outbounds || []) {
    const tls = o && o.streamSettings && o.streamSettings.tlsSettings;
    if (tls && echQueryOf(tls.echConfigList)) out.push(tls);
  }
  return out;
}

/**
 * Public resolvers that answer DoH on the very address they answer port 53 on.
 * Under the strict leak guard nothing leaves for port 53 off the tunnel (see
 * dropsUdpDirect), so an ECH config asked of one of these over UDP is asked
 * over DoH instead — same resolver, same answer, port 443.
 */
const DOH_ON_SAME_IP = {
  '1.1.1.1': 'https://1.1.1.1/dns-query', '1.0.0.1': 'https://1.0.0.1/dns-query',
  '8.8.8.8': 'https://8.8.8.8/dns-query', '8.8.4.4': 'https://8.8.4.4/dns-query',
  '9.9.9.9': 'https://9.9.9.9/dns-query', '149.112.112.112': 'https://149.112.112.112/dns-query'
};

function echOverDoh(outbounds) {
  for (const tls of echQueryTls(outbounds)) {
    const q = echQueryOf(tls.echConfigList);
    if (q.scheme !== 'udp' || (q.port && q.port !== 53) || !DOH_ON_SAME_IP[q.host]) continue;
    tls.echConfigList = (q.name ? q.name + '+' : '') + DOH_ON_SAME_IP[q.host];
  }
  return outbounds;
}

/**
 * The resolver addresses the running config fetches ECH configs from — what
 * the strict leak guard has to leave a hole for (the query is the core's own,
 * from the physical adapter). A resolver given by name is resolved before the
 * connect (entryHosts) and its addresses travel with the entry servers'.
 */
function echResolverIpsOf(config) {
  const out = [];
  for (const tls of echQueryTls(config && config.outbounds)) {
    const q = echQueryOf(tls.echConfigList);
    if (q && net.isIP(q.host) && !out.includes(q.host)) out.push(q.host);
  }
  return out;
}

/** "host:port" / "[v6]:port" → { host, port }; anything else → null. */
function splitEndpoint(ep) {
  const e = String(ep == null ? '' : ep).trim();
  const m6 = e.match(/^\[([^\]]+)\]:(\d{1,5})$/);
  if (m6) return { host: m6[1], port: m6[2] };
  const m4 = e.match(/^([^:]+):(\d{1,5})$/);
  return m4 ? { host: m4[1], port: m4[2] } : null;
}

/**
 * The WireGuard peer endpoints in a plan that are names rather than addresses.
 *
 * They have to be resolved before the config is written, because the cores do
 * not agree on who resolves them. The official core asks its own DNS; the
 * patterniha fork does not — dialled directly it asks the OS resolver ("Unable
 * to update bind: lookup <host>: no such host") and through a chain it hands the
 * bare hostname to the next hop. So a `.conf`-imported corporate WireGuard,
 * whose endpoint is always a name, silently never comes up on that core: every
 * other route keeps working, only the tunnel is dead. Handing the core an
 * address makes both behave the same, and takes the tunnel's own bootstrap off
 * the DNS that tunnel is supposed to carry.
 */
function wgEndpointHosts(planArg) {
  const plan = normalizePlan(planArg);
  const out = [];
  const visit = (s) => {
    const ob = s && s.outbound;
    if (!ob || ob.protocol !== 'wireguard') return;
    for (const p of (ob.settings && ob.settings.peers) || []) {
      const ep = splitEndpoint(p && p.endpoint);
      if (!ep || net.isIP(ep.host) || out.includes(ep.host)) continue;
      out.push(ep.host);
    }
  };
  if (plan.server) visit(plan.server);
  for (const s of plan.chain || []) visit(s);
  for (const s of Object.values(plan.serversById || {})) visit(s);
  for (const list of Object.values(plan.chainsById || {})) for (const s of list || []) visit(s);
  return out;
}

/**
 * The server a proxy outbound dials: `vnext[0]` (vless, vmess), `servers[0]`
 * (trojan, shadowsocks, socks, http) or the flat `settings.address` newer
 * configs carry. Null for an outbound that names no server of its own, and for
 * WireGuard, whose peer endpoint has its own path (wgEndpointHosts).
 */
const NO_SERVER = new Set(['freedom', 'blackhole', 'dns', 'loopback', 'wireguard']);
function serverAddressOf(o) {
  if (!o || !o.settings || NO_SERVER.has(o.protocol)) return null;
  const st = o.settings;
  const first = (list) => (Array.isArray(list) && list[0] && list[0].address) || '';
  const a = String(first(st.vnext) || first(st.servers) || (typeof st.address === 'string' ? st.address : '')).trim();
  return a || null;
}

/** The protocols that carry traffic to a server; freedom, blackhole, dns, loopback do not. */
const PROXY_OUT = new Set(['vless', 'vmess', 'trojan', 'shadowsocks', 'socks', 'http', 'wireguard', 'hysteria']);

/** The tag an outbound dials through: its dialerProxy, else (a JSON config's older form) its proxySettings.tag. */
function dialsThrough(o) {
  const so = o && o.streamSettings && o.streamSettings.sockopt;
  if (so && so.dialerProxy) return String(so.dialerProxy);
  return o && o.proxySettings && o.proxySettings.tag ? String(o.proxySettings.tag) : '';
}

/**
 * The outbounds of a server that this machine dials ITSELF. A link server:
 * its outbound. A JSON server: every proxy outbound of [main, ...helpers] that
 * dials by itself — directly, or through a freedom helper (a fragment or noise
 * dialer dials the address of whoever dialled through it, so it adds nothing).
 * One that dials through another proxy (the exit behind a chain's hop) is
 * reached by that proxy, never from here. `whole`: a raw connect runs the
 * whole config, so every outbound in it is looked at.
 */
function entryOutbounds(server, whole) {
  if (!server || !server.outbound) return [];
  if (server.source !== 'json') return [server.outbound];
  const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
  const list = whole && isObj(server.json) && Array.isArray(server.json.outbounds)
    ? server.json.outbounds.filter(isObj)
    : [server.outbound, ...(Array.isArray(server.extraOutbounds) ? server.extraOutbounds.filter(isObj) : [])];
  const byTag = new Map(list.filter(o => typeof o.tag === 'string' && o.tag).map(o => [o.tag, o]));
  return list.filter(o => {
    if (!PROXY_OUT.has(o.protocol)) return false;
    const via = dialsThrough(o);
    const dialer = via ? byTag.get(via) : null;
    return !via || !dialer || !PROXY_OUT.has(dialer.protocol);
  });
}

/** Where an outbound dials: its server's address, a WireGuard's peer endpoint host. '' when it names none. */
function dialAddressOf(o) {
  if (o && o.protocol === 'wireguard') {
    const peer = o.settings && Array.isArray(o.settings.peers) && o.settings.peers[0];
    const ep = splitEndpoint(peer && peer.endpoint);
    return ep ? ep.host : '';
  }
  return serverAddressOf(o) || '';
}

/**
 * The addresses a connect to this server dials directly — what the tunnel's
 * bypass, the strict guard's firewall holes and the UDP block's exclusions
 * are cut for. A link server: its record's address, as always. A JSON server:
 * the address of each of its entry outbounds (entryOutbounds); `whole` for a
 * raw connect.
 */
function entryAddressesOf(server, whole) {
  if (!server) return [];
  if (server.source !== 'json') return [server.address];
  const out = [];
  for (const o of entryOutbounds(server, whole)) {
    const a = dialAddressOf(o);
    if (a && !out.includes(a)) out.push(a);
  }
  return out;
}

/**
 * The server a routing target is ENTERED through: a chain's first hop, a
 * server looked up by id. targetServer's twin, from the other end.
 */
function targetEntry(target, plan) {
  const first = (list) => (list || []).filter(s => s && s.outbound)[0] || null;
  if (!target || target === 'direct' || target === 'block') return null;
  if (Array.isArray(target)) return first(target);
  if (typeof target === 'object') return target;
  if (target === 'chain') return first(plan.chain);
  if (target.indexOf('chain:') === 0) return first((plan.chainsById || {})[target.slice('chain:'.length)]);
  return (plan.serversById || {})[target] || null;
}

/**
 * The names a connect has to resolve before it builds the config: the server
 * of every outbound that dials the network ITSELF — a single server, the first
 * hop of a chain, the entry of every target an advanced plan or a pool routes
 * to. A hop behind another hop is not one (its name travels through that hop
 * and is resolved at the far end), nor is a WireGuard, an address, or a server
 * the plan does not route to — the store behind an advanced plan holds every
 * server the user has. See pinEntryHosts for what the answers are for. A JSON
 * server's are its entry outbounds' (entryOutbounds): the chain fixture is
 * entered at its hop, never at the exit behind it.
 */
function entryHosts(planArg) {
  const plan = normalizePlan(planArg);
  const entries = [];
  if (plan.mode === 'advanced') {
    // a target through a base is entered at the base (routingProfiles.advancedTargets)
    for (const tg of advancedTargets(plan).entries) entries.push(targetEntry(tg, plan));
  } else if (plan.mode === 'pool') {
    entries.push(targetEntry(plan.primary, plan));
    for (const e of plan.entries || []) if (e) entries.push(targetEntry(e.target, plan));
  } else if (plan.mode === 'chain') {
    entries.push(targetEntry(plan.chain, plan));
  } else {
    entries.push(plan.server || null);
  }
  // Asked under TUN only (withEntryHostIps), where a raw server runs its full
  // form (rawApplies): a server's entries are its full form's.
  const out = [];
  for (const s of entries) {
    for (const o of entryOutbounds(s)) {
      const host = serverAddressOf(o);
      if (host && !net.isIP(host) && !out.includes(host)) out.push(host);
    }
  }
  // A DoH resolver an ECH config is fetched from, given by name: the core asks
  // it directly, before its tunnel exists — so its name must not wait on the
  // tunnel either. Any server of the plan, hops behind others included (the
  // query never rides the chain).
  for (const s of planServers(plan)) {
    const tls = s && s.outbound && s.outbound.streamSettings && s.outbound.streamSettings.tlsSettings;
    const q = tls && echQueryOf(tls.echConfigList);
    if (q && q.host && !net.isIP(q.host) && !out.includes(q.host)) out.push(q.host);
  }
  return out;
}

/**
 * The addresses a pinned name is answered with: its IPv4 ones when it has any —
 * the core picks one at random with no fallback, so never the family a network
 * is likelier to lack — else its IPv6 ones, but only with IPv6 on (the DNS then
 * asks for AAAA at all; see dnsBuilder's queryStrategy).
 */
function pinnable(list, ipv6) {
  const ips = [].concat(list == null ? [] : list).map(x => String(x == null ? '' : x).trim()).filter(x => net.isIP(x));
  const v4 = ips.filter(x => net.isIPv4(x));
  if (v4.length) return v4;
  return ipv6 ? ips.filter(x => net.isIPv6(x)) : [];
}

/**
 * Answer the entry servers' names from the config.
 *
 * With no `sockopt.domainStrategy`, xray hands a server it dials by NAME to the
 * system dialer — the OPERATING SYSTEM resolves it (transport/internet/
 * dialer.go). Under TUN that resolver is the tunnel: the Windows leak guard
 * holds every physical adapter on loopback, the router's dnsmasq forwards into
 * the gateway. So the core's question about its own server enters the tunnel
 * and waits on that very server — a recursion only the OS cache hid, and every
 * guard apply flushes the cache. `dns.hosts` answers the name from the config;
 * the strategy makes the dialer ask xray's DNS (hosts first) instead of the OS.
 * The NAME stays in the outbound: SNI, the Host header and REALITY's
 * serverName are read from their own fields, never from the address.
 *
 * `map` = { name: [addresses] }, what the connect resolved for entryHosts().
 * Only an outbound with no dialerProxy yet — a hop behind a hop hands its name
 * to that hop — and only a name with an address to give: a strategy with
 * nothing in hosts would ask xray's own resolvers, which sit behind the very
 * proxy. Runs before applyFragments: the lookup happens before the dialerProxy
 * redirect, so the dpi dialer is then handed the address — and it carries the
 * same strategy, for when it is handed the name. Returns the hosts table, or
 * null when nothing was pinned (the config is then as it was; see withHosts).
 *
 * A JSON server's outbound that already dials through a freedom helper of its
 * own (a fragment or noise dialer, helpersFor) still dials its server from
 * here: it is pinned, and that dialer carries the strategy as a dpi dialer
 * does (unless it names one of its own). One behind another proxy is not.
 */
function pinEntryHosts(outbounds, map, ipv6) {
  if (!map || typeof map !== 'object') return null;
  const hosts = {};
  const strategy = ipv6 ? 'UseIP' : 'UseIPv4';
  for (const o of outbounds) {
    const host = serverAddressOf(o);
    if (!host || net.isIP(host) || !Object.prototype.hasOwnProperty.call(map, host)) continue;
    const via = o.streamSettings && o.streamSettings.sockopt && o.streamSettings.sockopt.dialerProxy;
    const dialer = via ? outbounds.find(x => x && x.tag === via) : null;
    if (via && !(dialer && dialer.protocol === 'freedom')) continue;
    const ips = pinnable(map[host], ipv6);
    if (!ips.length) continue;
    const ss = o.streamSettings || (o.streamSettings = {});
    ss.sockopt = Object.assign({}, ss.sockopt, { domainStrategy: strategy });
    if (dialer && !(dialer.settings && dialer.settings.domainStrategy)) dialer.settings = Object.assign({}, dialer.settings, { domainStrategy: strategy });
    hosts[host] = ips;
  }
  // The ECH query's own dial (echSockopt) the same way: its resolver's name
  // answered from the config, never asked of the OS — under TUN that is the
  // tunnel, which is waiting on this very query.
  for (const tls of echQueryTls(outbounds)) {
    const q = echQueryOf(tls.echConfigList);
    if (!q.host || net.isIP(q.host) || !Object.prototype.hasOwnProperty.call(map, q.host)) continue;
    const ips = pinnable(map[q.host], ipv6);
    if (!ips.length) continue;
    tls.echSockopt = Object.assign({}, tls.echSockopt, { domainStrategy: ipv6 ? 'UseIP' : 'UseIPv4' });
    hosts[q.host] = ips;
  }
  return Object.keys(hosts).length ? hosts : null;
}

/**
 * The DNS plan with the pinned names (pinEntryHosts) in its hosts table —
 * JOINED to any hosts the plan carries itself, never in place of them, and
 * winning only for their own names (what the tunnel's bypass was cut for).
 * Nothing pinned: the plan as it is. `hosts` stays the first key.
 */
function withHosts(dns, pins) {
  if (!pins) return dns;
  const hosts = Object.assign({}, dns && dns.hosts, pins);
  return Object.assign({ hosts }, dns, { hosts });
}

/** Put the resolved address in the peer's endpoint, keeping its port. */
function applyWgEndpointIps(o, map) {
  if (!o || o.protocol !== 'wireguard' || !map || !o.settings) return o;
  for (const p of o.settings.peers || []) {
    const ep = splitEndpoint(p && p.endpoint);
    const ip = ep && map[ep.host];
    if (!ip) continue;
    p.endpoint = (net.isIPv6(ip) ? `[${ip}]` : ip) + ':' + ep.port;
  }
  return o;
}

/**
 * Coerce a WireGuard outbound's interface address to /32 (or /128 for IPv6).
 * xray refuses to start otherwise — this protects configs that were saved with
 * a wrong mask (e.g. someone put 192.168.x.0/16 in the Address field).
 */
/**
 * What a WireGuard peer in the CONFIG may carry: everything.
 *
 * The patterniha fork moves no traffic at all through a peer whose AllowedIPs
 * is a split list — the shape every corporate `.conf` has, and not so much as a
 * handshake leaves (measured against both cores; the official one carries it).
 * Widening costs nothing here: `allowedIPs` is not a firewall, it only says what
 * this outbound may carry, and what reaches it is decided by the routing rules —
 * which are built from the very same ranges. The stored record keeps them, so
 * the routing suggestion and the resolver's expectedIPs are unaffected.
 */
function widenWgAllowedIps(o) {
  if (!o || o.protocol !== 'wireguard' || !o.settings) return o;
  for (const p of o.settings.peers || []) {
    if (p) p.allowedIPs = ['0.0.0.0/0', '::/0'];
  }
  return o;
}

function sanitizeWgOutbound(o) {
  widenWgAllowedIps(o);
  if (!o || o.protocol !== 'wireguard' || !o.settings || !Array.isArray(o.settings.address)) return o;
  o.settings.address = o.settings.address
    .map(a => String(a || '').trim())
    .filter(Boolean)
    .map(a => {
      const v6 = a.includes(':');
      const host = a.indexOf('/') === -1 ? a : a.slice(0, a.indexOf('/'));
      return host + (v6 ? '/128' : '/32');
    });
  return o;
}

/**
 * Attach a dialerProxy to an outbound so it tunnels THROUGH `viaTag`.
 * Works for every protocol including WireGuard (its handshake/data then rides
 * the previous hop — this is what lets a WireGuard "server" reach a database
 * even when its own UDP endpoint is blocked: client → config → wireguard → DB).
 */
function dialThrough(outbound, viaTag) {
  outbound.streamSettings = outbound.streamSettings || {};
  outbound.streamSettings.sockopt = Object.assign(
    {},
    outbound.streamSettings.sockopt,
    { dialerProxy: viaTag }
  );
  return outbound;
}

/**
 * A JSON server's helper outbounds (jsonImport.js: what its main outbound
 * dials THROUGH — a fragment freedom, the hops of its own chain), for its
 * outbound `o` tagged `tag` in this config: each helper's tag becomes
 * `<tag>~<helperTag>`, and every dialerProxy / proxySettings.tag that named a
 * helper is rewritten — in `o` and in the helpers, a proxySettings as the
 * dialerProxy the cores now take (proxySettingsToDialer) — so two JSON servers
 * in one config never collide. Copies, `allowInsecure` handled as for every
 * outbound (applyCertPin). A link server has none: [] and `o` untouched.
 */
function helpersFor(server, o, tag) {
  if (!server || server.source !== 'json') return [];
  proxySettingsToDialer(o);
  const extra = Array.isArray(server.extraOutbounds)
    ? server.extraOutbounds.filter(h => h && typeof h.tag === 'string' && h.tag) : [];
  if (!extra.length) return [];
  const named = new Map(extra.map(h => [h.tag, `${tag}~${h.tag}`]));
  const helpers = extra.map(h => proxySettingsToDialer(applyCertPin(Object.assign(JSON.parse(JSON.stringify(h)), { tag: named.get(h.tag) }), null)));
  for (const x of [o, ...helpers]) {
    const so = x.streamSettings && x.streamSettings.sockopt;
    if (so && named.has(so.dialerProxy)) so.dialerProxy = named.get(so.dialerProxy);
  }
  return helpers;
}

/**
 * `proxySettings.tag` → `streamSettings.sockopt.dialerProxy`, in place. The
 * 2026 cores refuse proxySettings at config load — "has been removed and
 * migrated to streamSettings.sockopt.dialerProxy" — and a JSON config written
 * for an older one still carries it (a chain's hop). A dialerProxy the
 * outbound has already wins. Only a JSON server's outbounds ever carry it.
 */
function proxySettingsToDialer(o) {
  if (!o || !o.proxySettings || typeof o.proxySettings !== 'object') return o;
  const via = o.proxySettings.tag;
  delete o.proxySettings;
  if (typeof via === 'string' && via) {
    const ss = o.streamSettings || (o.streamSettings = {});
    if (!(ss.sockopt && ss.sockopt.dialerProxy)) ss.sockopt = Object.assign({}, ss.sockopt, { dialerProxy: via });
  }
  return o;
}

/** An outbound followed by the helpers its server dials through (helpersFor). */
function withHelpers(o, server) {
  return [o, ...helpersFor(server, o, o.tag)];
}

/**
 * Build chained outbounds. `servers` is ordered first-hop → exit.
 * Each hop after the first dials THROUGH the previous via sockopt.dialerProxy.
 * The exit gets `exitTag` (what routing targets); default 'proxy'.
 *
 * Inner hop tags are namespaced under `exitTag` (`<exitTag>-h<i>`) so multiple
 * chains can coexist in one config (advanced routing) without tag collisions.
 *
 * A JSON server dials the network through its helpers (helpersFor) only as
 * the FIRST hop. A later hop dials through the hop before it: its own way out
 * — the helper its dialerProxy or proxySettings named — goes, and with it
 * every helper (as a link's anti-DPI dialer does for a chained hop).
 *
 * `viaTag`: the chain itself rides a base (makeRegistry) — its first hop then
 * dials through that, exactly as a later hop dials the hop before it.
 */
function buildChainOutbounds(servers, exitTag, viaTag) {
  exitTag = exitTag || 'proxy';
  const list = (servers || []).filter(s => s && s.outbound);
  const last = list.length - 1;
  const outs = [];
  for (let i = 0; i <= last; i++) {
    const tag = i === last ? exitTag : `${exitTag}-h${i}`;
    const prev = i > 0 ? `${exitTag}-h${i - 1}` : (viaTag || null);
    outs.push(...(prev ? [behind(list[i], tag, prev)] : withHelpers(cloneOut(list[i].outbound, tag, list[i]), list[i])));
  }
  return outs;
}

/**
 * A server's outbound tagged `tag`, dialing THROUGH `viaTag` — a chain's later
 * hop, or a target riding a base: a JSON server's own way out (proxySettings,
 * or the dialerProxy that named its helper) is replaced, and its helpers are
 * left out.
 */
function behind(server, tag, viaTag) {
  const ob = cloneOut(server.outbound, tag, server);
  if (server.source === 'json') delete ob.proxySettings;
  return dialThrough(ob, viaTag);
}

/**
 * Registry that turns a routing "target" into an outbound tag, lazily
 * creating (and de-duplicating) the outbound(s) needed for it.
 * Targets:
 *   'direct' | 'block'
 *   '<serverId>'        a single config
 *   'chain'             the legacy single chain (plan.chain)
 *   'chain:<chainId>'   a named chain (plan.chainsById[chainId])
 * `muxIds`: settings.muxServerIds — a server target's own outbound carries
 * mux (applyMux); a chain target's hops never do.
 *
 * `tagFor(target, via)`: the target through a base (a routing profile's via,
 * routingProfiles.effectiveVia — a server id or `chain:<id>`). The base is one
 * outbound group shared by every target through it: `base-<id>`, a chain
 * `base-chain-<cid>` with its hops `base-chain-<cid>-h<i>`. The target is an
 * outbound of its own, `out-<id>@<baseKey>` (a chain `out-chain-<cid>@<baseKey>`,
 * hops `…-h<i>`), whose outbound that would dial by itself dials the base's
 * exit (behind); `<baseKey>` is the base's server id or `chain-<cid>`. Neither
 * ever carries mux. The caller checks exists(via) first: a base that is gone
 * is a refusal (buildConfig), never a silent direct.
 */
function makeRegistry(plan, muxIds) {
  const outs = [];
  const seen = new Set();
  const add = (o) => { if (o && !seen.has(o.tag)) { seen.add(o.tag); outs.push(o); } };

  function chainTag(list, tag, viaTag) {
    const arr = (list || []).filter(s => s && s.outbound);
    if (arr.length >= 2) { buildChainOutbounds(arr, tag, viaTag).forEach(add); return tag; }
    if (arr.length === 1) {
      (viaTag ? [behind(arr[0], tag, viaTag)] : withHelpers(cloneOut(arr[0].outbound, tag, arr[0]), arr[0])).forEach(add);
      return tag;
    }
    return 'direct';
  }

  /** A via's base group, registered once: { key, tag } — its exit tag and the key a target through it is named by. */
  function baseOf(via) {
    if (via === 'chain') return { key: 'chain', tag: chainTag(plan.chain, 'base-chain') };
    if (via.indexOf('chain:') === 0) {
      const cid = via.slice('chain:'.length);
      return { key: 'chain-' + cid, tag: chainTag((plan.chainsById || {})[cid], 'base-chain-' + cid) };
    }
    const s = (plan.serversById || {})[via];
    const tag = 'base-' + via;
    if (s && s.outbound) withHelpers(cloneOut(s.outbound, tag, s), s).forEach(add);
    return { key: via, tag };
  }

  function tagFor(target, via) {
    if (!target || target === 'direct') return 'direct';
    if (target === 'block') return 'block';
    if (typeof via === 'string' && via) return tagThrough(target, baseOf(via));
    if (target === 'chain') return chainTag(plan.chain, 'out-chain');
    if (typeof target === 'string' && target.indexOf('chain:') === 0) {
      const cid = target.slice('chain:'.length);
      const list = (plan.chainsById || {})[cid];
      return chainTag(list, 'out-chain-' + cid);
    }
    const s = (plan.serversById || {})[target];
    if (s && s.outbound) { const tag = 'out-' + target; withHelpers(applyMux(cloneOut(s.outbound, tag, s), s, muxIds), s).forEach(add); return tag; }
    return 'direct';
  }

  /** `target` riding `base` (baseOf): its own outbound(s), the one that would dial by itself dialing the base. */
  function tagThrough(target, base) {
    const at = '@' + base.key;
    if (target === 'chain') return chainTag(plan.chain, 'out-chain' + at, base.tag);
    if (typeof target === 'string' && target.indexOf('chain:') === 0) {
      const cid = target.slice('chain:'.length);
      return chainTag((plan.chainsById || {})[cid], 'out-chain-' + cid + at, base.tag);
    }
    const s = (plan.serversById || {})[target];
    if (s && s.outbound) { const tag = 'out-' + target + at; add(behind(s, tag, base.tag)); return tag; }
    return 'direct';
  }

  /**
   * Does the target still name something? A server deleted (or replaced by a
   * subscription refresh), a chain removed or left with no members: tagFor()
   * would send that `direct` — the traffic the rule was meant to protect,
   * leaving in the clear while the app says "connected". An empty target is
   * the user's own "not routed anywhere" and stays `direct`.
   */
  function exists(target) {
    if (!target || target === 'direct' || target === 'block') return true;
    const members = (list) => (list || []).filter(s => s && s.outbound).length > 0;
    if (target === 'chain') return members(plan.chain);
    if (typeof target === 'string' && target.indexOf('chain:') === 0) return members((plan.chainsById || {})[target.slice('chain:'.length)]);
    const s = (plan.serversById || {})[target];
    return !!(s && s.outbound);
  }

  return { outs, add, tagFor, exists };
}

/**
 * Is this stored record a WireGuard config? The OUTBOUND is the truth; the
 * record's top-level `protocol` is a copy kept for the list UI, and a record
 * that lost it (an old store, a hand-edited import) must not silently lose its
 * corporate resolver with it.
 */
function isWgServer(server) {
  return !!server && (server.protocol === 'wireguard' ||
    !!(server.outbound && server.outbound.protocol === 'wireguard'));
}

/**
 * Resolvers a routing target brings with it. A WireGuard server that names a
 * DNS in its config (a corporate VPN) can resolve names nobody else knows —
 * but only when asked THROUGH that tunnel. A chain contributes its last hop.
 * Shape: what buildDnsPlan's `targetResolvers` takes.
 */
function wgResolvers(server, outboundTag) {
  if (!isWgServer(server) || !Array.isArray(server.dns)) return [];
  const dns = server.dns.map(d => String(d == null ? '' : d).trim()).filter(Boolean);
  if (!dns.length) return [];
  const peer = server.outbound && server.outbound.settings && server.outbound.settings.peers && server.outbound.settings.peers[0];
  // AllowedIPs minus the full-tunnel entries; empty → any answer is acceptable
  const expectedIPs = ((peer && peer.allowedIPs) || []).map(a => String(a).trim()).filter(a => a && !/\/0$/.test(a));
  const domains = (Array.isArray(server.dnsDomains) ? server.dnsDomains : [])
    .map(d => String(d == null ? '' : d).trim().replace(/^\.+/, '')).filter(Boolean)
    .map(d => 'domain:' + d);
  return dns.slice(0, 2).map(address => ({ address, outboundTag, expectedIPs: expectedIPs.slice(), domains: domains.slice() }));
}

/**
 * Every resolver the WireGuard servers in a plan bring with them, whether or
 * not this config ends up using them. The connect path needs it to say why the
 * names inside a corporate network stopped resolving when managed DNS was
 * switched off: with `dnsManaged:false` buildDnsPlan returns the user's own
 * server list and nothing else, so these are silently absent.
 */
function wgResolverAddresses(planArg) {
  const plan = normalizePlan(planArg);
  const out = [];
  const visit = (s) => {
    if (!isWgServer(s) || !Array.isArray(s.dns)) return;
    for (const d of s.dns) {
      const v = String(d == null ? '' : d).trim();
      if (v && !out.includes(v)) out.push(v);
    }
  };
  if (plan.server) visit(plan.server);
  for (const s of plan.chain || []) visit(s);
  for (const s of Object.values(plan.serversById || {})) visit(s);
  for (const list of Object.values(plan.chainsById || {})) for (const s of list || []) visit(s);
  return out;
}

/** A WireGuard whose AllowedIPs is not the whole internet: it carries only those ranges. */
function isSplitTunnelWg(server) {
  if (!isWgServer(server)) return false;
  const peer = server.outbound && server.outbound.settings && server.outbound.settings.peers && server.outbound.settings.peers[0];
  const allowed = ((peer && peer.allowedIPs) || []).map(a => String(a).trim()).filter(Boolean);
  return allowed.length > 0 && !allowed.some(a => /\/0$/.test(a));
}

/**
 * The server a routing target ends at: a chain's last hop, a server looked up
 * by id, or the server object / chain array itself. `direct`, `block` and an
 * unknown target end nowhere. Same member filter as makeRegistry's chainTag.
 */
function targetServer(target, plan) {
  const last = (list) => (list || []).filter(s => s && s.outbound).at(-1) || null;
  if (!target || target === 'direct' || target === 'block') return null;
  if (Array.isArray(target)) return last(target);
  if (typeof target === 'object') return target;
  if (target === 'chain') return last(plan.chain);
  if (target.indexOf('chain:') === 0) return last((plan.chainsById || {})[target.slice('chain:'.length)]);
  return (plan.serversById || {})[target] || null;
}

/**
 * The target resolvers for `entries` = [{ target, tag }]: every outbound the
 * plan routes to, with the tag its outbound already got (reg.tagFor REGISTERS
 * outbounds, so the caller passes the tags it has rather than asking again).
 * Deduplicated by resolver address: first entry wins, except that a chain to
 * the same WireGuard replaces the direct dial — its UDP endpoint is what the
 * chain exists to avoid. So does the WireGuard through a base (`…@<base>`).
 */
function targetResolversFor(entries, plan) {
  const out = [];
  const at = new Map();   // address → index in out
  const viaChain = (tag) => /^out-chain|@/.test(String(tag));
  for (const e of entries || []) {
    if (!e) continue;
    for (const r of wgResolvers(targetServer(e.target, plan), e.tag)) {
      const i = at.get(r.address);
      if (i === undefined) { at.set(r.address, out.length); out.push(r); continue; }
      if (viaChain(r.outboundTag) && !viaChain(out[i].outboundTag)) out[i] = r;
    }
  }
  return out;
}

function normalizePlan(plan) {
  if (Array.isArray(plan)) return { mode: 'chain', chain: plan };
  if (plan && plan.mode) return plan;
  if (plan && plan.outbound) return { mode: 'single', server: plan };
  return plan || { mode: 'single' };
}

/**
 * The direct outbound. IPv4-only unless the user turned IPv6 on: with no v6
 * route in the tunnel, an AAAA answer would just make the app try an address
 * it cannot reach.
 */
function freedom(s) {
  return { tag: 'direct', protocol: 'freedom', settings: { domainStrategy: s.ipv6 ? 'UseIP' : 'UseIPv4' } };
}
const BLACKHOLE = { tag: 'block', protocol: 'blackhole', settings: { response: { type: 'http' } } };

/**
 * The settings buildDnsPlan should see for THIS plan. The store carries the
 * user's saved advanced rules whether or not the plan being built uses them —
 * main.js picks the mode from the connect target, not from `advancedRouting` —
 * so the plan, not the store, decides whether an in-country resolver is
 * wanted: an advanced plan contributes its own rules, every other plan follows
 * routingMode alone.
 */
/**
 * Under the STRICT leak guard the in-country resolver's plain-UDP query cannot
 * leave the machine: sing-box's `strict_route` blocks port 53 off the tunnel,
 * and a `direct` dial is exactly that — it leaves through the physical adapter.
 * Dropping the UDP entries at build time turns a timeout on every domestic name
 * into an immediate fall through to the DoH resolvers; a DoH direct resolver
 * rides port 443 and stays, and geoip still routes the answers, so `bypass-ir`
 * keeps working. Only under TUN — in proxy mode nothing blocks :53.
 */
function dropsUdpDirect(s) {
  return !!(s && s.tunMode && s.leakGuard === 'strict');
}

/**
 * Does this advanced plan apply the simple routing mode under its rules? A
 * routing profile's own `useMode`; a plan without one (today's), the setting.
 */
function useModeOf(s, plan) {
  return typeof plan.useMode === 'boolean' ? plan.useMode : s.advancedUseMode;
}

function dnsSettingsFor(s, plan) {
  if (plan.mode === 'advanced') {
    return Object.assign({}, s, { advancedRouting: true, routeRules: plan.rules || [] },
      typeof plan.useMode === 'boolean' ? { advancedUseMode: plan.useMode } : {});
  }
  // Pool emits no bypass rules, so an in-country resolver would only hand the
  // primary exit an Iranian IP to dial from abroad — routingMode is not its.
  if (plan.mode === 'pool') return Object.assign({}, s, { advancedRouting: false, routingMode: 'global' });
  return Object.assign({}, s, { advancedRouting: false });
}

/**
 * How the router treats a hostname destination. xray resolves it under
 * IPIfNonMatch only when NO rule matched on the first pass — and every plan
 * ends with a port:0-65535 catch-all, which always matches — so an `ip:` rule
 * (geoip:ir, the private-LAN bypass, a corporate range behind a WireGuard)
 * never fired for a browser connection carrying a name. IPOnDemand resolves
 * exactly when an ip condition is evaluated: one lookup per new name, through
 * the managed DoH, cached by the core; a failed lookup just leaves the rule
 * unmatched and the name intact for the exit. Not for the legacy DNS list —
 * a dead plain-UDP resolver there would make every connection wait it out.
 * The pool is the exception (see buildPoolConfig).
 */
function routingStrategy(s) {
  return s.dnsManaged === false ? 'IPIfNonMatch' : 'IPOnDemand';
}


const SETTINGS_DEFAULTS = {
  socksPort: 10808,
  httpPort: 10809,
  allowLan: false,
  routingMode: 'global',
  advancedUseMode: false,   // advanced routing also applies routingMode
  blockAds: true,
  enableSniffing: true,
  dnsManaged: true,
  dnsRemote: ['https://1.1.1.1/dns-query', 'https://8.8.8.8/dns-query'],
  dnsDirect: ['178.22.122.100', '185.51.200.2'],
  ipv6: false,
  logLevel: 'warning',
  apiPort: 10085,
  customRules: [],
  geoAssets: true   // geoip.dat/geosite.dat present? false -> skip geo rules
};

/**
 * The resolver addresses the TUN layer must route past the tunnel. Under TUN
 * every `direct` dial to a public address matches the split routes and
 * re-enters the tunnel, so the in-country resolver's UDP query would loop into
 * the hijack. Same defaults and plan view as buildConfig, so the two agree.
 */
function resolverBypassIps(planArg, settings) {
  const s = Object.assign({}, SETTINGS_DEFAULTS, settings || {});
  const plan = normalizePlan(planArg);
  // Same options as buildConfig, so the bypass list never names a resolver the
  // config no longer has — a stale entry here is a hole in the strict guard's
  // firewall (the TUN backend hands this list to it as an exclude).
  return buildDnsPlan(dnsSettingsFor(s, plan),
    { geoAssets: s.geoAssets !== false, dropUdpDirect: dropsUdpDirect(s) }).directResolverIps;
}

/**
 * The same list, read out of the config that is actually RUNNING.
 *
 * Rebuilding it from the plan can only be as truthful as the settings object it
 * is handed, and one input never travels in that object: `geoAssets`. main.js
 * (and service.js) compute it from the files on disk inside buildActive() and
 * pass it to buildConfig alone, so with the geo files missing the plan-derived
 * list still names an in-country resolver the config no longer builds — a route
 * exclusion, and at the strict level a firewall hole, for nothing. Reading the
 * config's own `dns-internal → direct` rule cannot drift: it is the rule the
 * core is obeying. A config in another core's format has no such rule and
 * bypasses nothing, which is also the truthful answer for it.
 */
function resolverBypassIpsOf(config) {
  const rules = (config && config.routing && config.routing.rules) || [];
  const out = [];
  for (const r of rules) {
    if (!r || r.outboundTag !== 'direct' || !Array.isArray(r.ip)) continue;
    if (!Array.isArray(r.inboundTag) || !r.inboundTag.includes(DNS_TAG)) continue;
    for (const ip of r.ip) if (!out.includes(ip)) out.push(ip);
  }
  return out;
}

function buildConfig(planArg, settings) {
  const s = Object.assign({}, SETTINGS_DEFAULTS, settings || {});
  const geo = s.geoAssets !== false;

  const plan = normalizePlan(planArg);
  const listen = s.allowLan ? '0.0.0.0' : '127.0.0.1';
  const sniffing = s.enableSniffing
    ? { enabled: true, destOverride: ['http', 'tls', 'quic'], routeOnly: false }
    : { enabled: false };

  // Proxy pool: many local inbounds, each on its own port, each routed to its
  // own config/chain. Handled separately (its own inbound set).
  if (plan.mode === 'pool') return buildPoolConfig(plan, s, listen, sniffing);

  let outbounds, rules, exitTag;
  // Every target the plan routes to, with its outbound tag — the resolver a
  // corporate WireGuard carries must be asked through THAT outbound.
  const targets = [];

  if (plan.mode === 'advanced') {
    const reg = makeRegistry(plan, s.muxServerIds);
    // The default carries everything no rule claims: gone, there is nothing
    // honest to send that traffic to. Refuse, rather than connect `direct`.
    if (!reg.exists(plan.def)) {
      throw new Error(s.lang === 'en'
        ? 'Advanced routing: the default target no longer exists (it was removed, or replaced by a subscription update) — choose a new default under Routing.'
        : 'روتینگ ویژه: مقصدِ پیش‌فرض دیگر وجود ندارد (حذف شده، یا با به‌روزرسانیِ اشتراک عوض شده) — در بخش روتینگ یک مقصدِ پیش‌فرضِ تازه انتخاب کن.');
    }
    // A base a target goes through (a routing profile's via) that is gone —
    // a deleted server, an emptied chain: the target would be dialled from
    // here, the very thing the base is there for. Refused the same way.
    const baseGone = () => new Error(s.lang === 'en'
      ? 'Advanced routing: a base that a target goes through no longer exists (it was removed, or replaced by a subscription update) — choose another base under Routing.'
      : 'روتینگ ویژه: پایه‌ای که یک مقصد از طریقِ آن می‌رود دیگر وجود ندارد (حذف شده، یا با به‌روزرسانیِ اشتراک عوض شده) — در بخش روتینگ پایهٔ دیگری انتخاب کن.');
    const defVia = effectiveVia('def', plan);
    if (defVia && !reg.exists(defVia)) throw baseGone();
    const advRules = [];
    for (const r of plan.rules || []) {
      if (!r) continue;
      let vals = splitList(r.value);
      if (!vals.length) continue;

      let field, value;
      if (r.type === 'ip') {
        // drop geoip:* tokens when geo files are absent (xray would crash)
        if (!geo) vals = vals.filter(v => !/^geoip:/i.test(v));
        if (!vals.length) continue;
        field = 'ip'; value = vals;
      } else if (r.type === 'domain') {
        if (!geo) vals = vals.filter(v => !/^geosite:/i.test(v));
        if (!vals.length) continue;
        field = 'domain'; value = vals;
      } else if (r.type === 'port') {
        field = 'port'; value = vals.join(',');
      } else continue;

      // A rule to a target that no longer exists is left out: its traffic
      // then follows the default like everything else no rule claims.
      if (!reg.exists(r.target)) continue;
      const via = effectiveVia(r, plan);
      if (via && !reg.exists(via)) throw baseGone();

      // Resolve the target only once the rule is known to survive: tagFor()
      // REGISTERS the outbound(s), so doing it earlier leaves a dead outbound
      // behind for every dropped rule — writing an unused server's address and
      // credentials into config.json (and materializing a whole chain for a
      // `chain:` target).
      const rule = { type: 'field', outboundTag: reg.tagFor(r.target, via) };
      rule[field] = value;
      advRules.push(rule);
      targets.push({ target: r.target, tag: rule.outboundTag });
    }
    const defTag = reg.tagFor(plan.def, defVia);
    targets.push({ target: plan.def, tag: defTag });
    // The resolver's exit. A `block` default is a legitimate allow-list, but
    // the blackhole can never answer a DoH query: use the first proxy the
    // rules name whose tunnel can carry it — a split-tunnel WireGuard drops
    // anything outside its AllowedIPs, so DoH to 1.1.1.1 would die inside it
    // — else direct.
    const carrier = targets.find(x => x.tag !== 'direct' && x.tag !== 'block' && !isSplitTunnelWg(targetServer(x.target, plan)));
    exitTag = defTag !== 'block' ? defTag : (carrier ? carrier.tag : 'direct');
    reg.add(freedom(s));
    reg.add(Object.assign({}, BLACKHOLE));
    outbounds = reg.outs;
    // NOTE: user rules come BEFORE the private-IP bypass on purpose. This is
    // "special routing" — explicit rules must win, otherwise a database on an
    // internal range (e.g. 10.20.0.0/16) would be caught by the private bypass
    // and go direct instead of through the chosen config/chain (e.g. WireGuard).
    // `advancedUseMode`: apply the simple routing mode UNDER the user's rules.
    // Without it an advanced plan has no way to say "…and bypass Iran too" —
    // the user had to hand-write geosite:category-ir rules or give up one of
    // the two features. Under the user's rules on purpose: an explicit
    // corporate rule must still win over a country bypass.
    rules = [
      ...(s.blockAds && geo ? [{ type: 'field', domain: ['geosite:category-ads-all'], outboundTag: 'block' }] : []),
      ...advRules,
      { type: 'field', ip: PRIVATE_IPS.slice(), outboundTag: 'direct' },
      ...(useModeOf(s, plan) ? modeBypassRules(s.routingMode, geo) : []),
      { type: 'field', port: '0-65535', outboundTag: defTag }
    ];
  } else {
    const proxyOutbounds = plan.mode === 'chain'
      ? buildChainOutbounds(plan.chain, 'proxy')
      : withHelpers(applyMux(cloneOut(plan.server.outbound, 'proxy', plan.server), plan.server, s.muxServerIds), plan.server);
    outbounds = [...proxyOutbounds, freedom(s), Object.assign({}, BLACKHOLE)];
    exitTag = s.routingMode === 'direct' ? 'direct' : 'proxy';
    // The exit carries the resolver — unless it is `direct` (routingMode
    // direct): a corporate resolver asked off its tunnel simply fails, so it
    // is not offered at all.
    if (exitTag !== 'direct') targets.push({ target: plan.mode === 'chain' ? plan.chain : plan.server, tag: exitTag });
    // custom rules go BEFORE the catch-all so they actually take effect
    const base = buildRoutingRules(s.routingMode, s.blockAds, geo);
    const tail = base.pop(); // the final port:0-65535 catch-all
    rules = [...base, ...normalizeCustomRules(s.customRules, geo), tail];
  }

  // Name resolution (see dnsBuilder.js). Its rules go FIRST: the port-53 hijack
  // must beat the private-IP bypass, or a query to the tunnel peer 10.255.0.1
  // would be sent "direct" into nowhere instead of being answered.
  const dnsPlan = buildDnsPlan(dnsSettingsFor(s, plan),
    { geoAssets: geo, exitTag, dropUdpDirect: dropsUdpDirect(s), targetResolvers: targetResolversFor(targets, plan) });
  if (dnsPlan.hijackOutbound) outbounds.push(dnsPlan.hijackOutbound);
  rules = [...dnsPlan.rules, ...rules];

  // Safety net: fix any WireGuard interface address that isn't /32 (/128).
  outbounds = (outbounds || []).map(sanitizeWgOutbound).map(o => applyWgEndpointIps(o, s.wgEndpointIps));
  const hosts = pinEntryHosts(outbounds, s.entryHostIps, s.ipv6);
  outbounds = applyFragments(outbounds);
  if (dropsUdpDirect(s)) echOverDoh(outbounds);
  bindDirectDials(outbounds, s.directInterface);

  // No `bufferSize: 0` any more. It was set whenever a WireGuard was dialled
  // through a chain (Xray-core #2850: the dialer pipe merged UDP packets and
  // the tunnel passed nothing) — but a policy level is everyone's: level 0 is
  // every connection of the config, and a pipe allowed to hold nothing makes
  // each write wait for its reader, so the whole plan ran lock-stepped, both
  // ways, for as long as the corporate chain was in it. Both cores carry the
  // chained WireGuard with the default buffer now (scripts/probe-wg-chain.js:
  // plain, TLS, 80 ms RTT, the fork's mask); IRNF_PROBE_BUF0=1 puts the old
  // line back for a comparison.
  const level0 = { statsUserUplink: true, statsUserDownlink: true };

  return {
    log: { loglevel: s.logLevel },
    // Live traffic counters over HTTP (GET /debug/vars) instead of the gRPC-only
    // StatsService: one cheap request per second instead of spawning `xray api
    // statsquery`, and it reports EVERY outbound tag — the pool and advanced
    // plans have no outbound called 'proxy', so the old query always read 0.
    metrics: { tag: 'metrics', listen: `127.0.0.1:${s.apiPort}` },
    stats: {},
    policy: {
      levels: { '0': level0 },
      system: { statsInboundUplink: true, statsInboundDownlink: true, statsOutboundUplink: true, statsOutboundDownlink: true }
    },
    dns: withHosts(dnsPlan.dns, hosts),
    inbounds: localInbounds(s, listen, sniffing),
    outbounds,
    routing: { domainStrategy: routingStrategy(s), rules }
  };
}

/** The app's own local inbounds: SOCKS and HTTP on the ports from Settings (what the system proxy and TUN reach). */
function localInbounds(s, listen, sniffing) {
  return [
    { tag: 'socks-in', port: s.socksPort, listen, protocol: 'socks', settings: { auth: 'noauth', udp: true }, sniffing },
    { tag: 'http-in', port: s.httpPort, listen, protocol: 'http', settings: {}, sniffing }
  ];
}

const isPlainObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);

/** Is config outbound `o` the record's outbound `stored` (stored without its tag; key order aside)? */
function sameOutbound(o, stored) {
  if (!isPlainObj(o) || !isPlainObj(stored)) return false;
  const canon = (v) => (Array.isArray(v) ? v.map(canon)
    : (isPlainObj(v) ? Object.keys(v).sort().reduce((x, k) => { x[k] = canon(v[k]); return x; }, {}) : v));
  const c = Object.assign({}, o);
  delete c.tag;
  return JSON.stringify(canon(c)) === JSON.stringify(canon(stored));
}

/** A JSON server set to run exactly as written (jsonMode 'raw'). */
function isRawJson(server) {
  return !!server && server.source === 'json' && server.jsonMode === 'raw' && isPlainObj(server.json);
}

/**
 * The tags a running config's outbounds dial THROUGH (sockopt.dialerProxy): a
 * raw config's fragment dialer, the hops of its own chain. Their bytes are the
 * ones the outbound dialling through them already counted — the traffic meter
 * leaves them out (stats.js), as it does `<tag>~<helper>` in the full form.
 */
function dialerTagsOf(config) {
  const out = new Set();
  for (const o of (config && Array.isArray(config.outbounds) ? config.outbounds : [])) {
    const via = o && o.streamSettings && o.streamSettings.sockopt && o.streamSettings.sockopt.dialerProxy;
    if (typeof via === 'string' && via) out.add(via);
  }
  return out;
}

/**
 * Does raw mode run for this server on this connect? A raw JSON server, in
 * proxy mode on the desktop only. Under TUN — and always on the router
 * (`opts.openwrt`) — names resolve only through the app's own DNS: the port-53
 * answer a router's LAN lives on, the entry names answered from the config
 * (pinEntryHosts) so the core never asks the OS resolver that is the tunnel
 * itself. A raw config carries neither, so there its full form runs.
 */
function rawApplies(server, settings, opts) {
  return isRawJson(server) && !(settings && settings.tunMode) && !(opts && opts.openwrt);
}

/**
 * The raw JSON server a plan runs as written — a single-server connect where
 * rawApplies; null for every other plan (a raw server in a chain, advanced
 * routing or the pool, under TUN or on the router is used in its full form:
 * buildConfig).
 */
function rawServerOf(planArg, settings, opts) {
  const plan = normalizePlan(planArg);
  return plan.mode === 'single' && rawApplies(plan.server, settings, opts) ? plan.server : null;
}

/**
 * What a connect says about raw mode, once: [{ line, level }]. A single raw
 * server runs as written — or, under TUN and on the router, in its full form;
 * one in any other plan is used in its full form.
 */
function rawModeNotes(planArg, settings, opts) {
  const plan = normalizePlan(planArg);
  const raw = rawServerOf(plan, settings, opts);
  if (raw) return [{ line: `Running "${raw.name}" exactly as written (raw JSON) — the app's DNS management, leak guard and routing mode do not apply`, level: 'info' }];
  if (plan.mode === 'single' && isRawJson(plan.server)) {
    return [{ line: `"${plan.server.name}" is set to run raw — under TUN (and on the router) its full form runs, so the app's DNS and tunnel rules apply`, level: 'warn' }];
  }
  const seen = new Set();
  const out = [];
  for (const s of planServers(plan)) {
    if (!isRawJson(s) || seen.has(s.id || s)) continue;
    seen.add(s.id || s);
    out.push({ line: `"${s.name}" is set to run raw, but a chain/routing target uses its full form`, level: 'warn' });
  }
  return out;
}

/**
 * Raw mode: a JSON server's own config, run exactly as written — its routing,
 * DNS, balancers, observatory, policy and fakedns — with only what the app
 * needs to reach it and to read it:
 *  - its `inbounds` are the app's own (localInbounds, as buildConfig makes
 *    them for these settings), so the system proxy and TUN reach it — with
 *    `fakedns` sniffed when the config keeps a fake-IP pool;
 *  - `log.loglevel` from Settings;
 *  - the traffic meter's metrics listener and the counters it reads;
 *  - under TUN (`directInterface`) every outbound that dials itself bound to
 *    the NIC (bindDirectDials) — a `direct` dial would otherwise re-enter the
 *    tunnel it is meant to go around;
 *  - what the cores refuse or trip over, written as full mode writes it: a
 *    `proxySettings` hop as the dialerProxy it was migrated to
 *    (proxySettingsToDialer); `allowInsecure` never — the certificate pin
 *    learnt for the record's server on its main outbound instead
 *    (applyCertPin); a WireGuard endpoint name as the address the connect
 *    resolved (applyWgEndpointIps — a failed lookup panics the handler).
 * The app's DNS plan, leak-guard rules and routing mode are not applied.
 * Never changes the record. (xrayManager still writes the result for the
 * core's version — coreCompat.adaptForCore — as it does every config.)
 */
function buildRawConfig(server, settings) {
  const s = Object.assign({}, SETTINGS_DEFAULTS, settings || {});
  const cfg = JSON.parse(JSON.stringify((server && server.json) || {}));
  const listen = s.allowLan ? '0.0.0.0' : '127.0.0.1';
  let sniffing = s.enableSniffing
    ? { enabled: true, destOverride: ['http', 'tls', 'quic'], routeOnly: false }
    : { enabled: false };
  if (cfg.fakedns) sniffing = { enabled: true, destOverride: [...(sniffing.destOverride || []), 'fakedns'], routeOnly: false };
  cfg.log = Object.assign({}, isPlainObj(cfg.log) ? cfg.log : {}, { loglevel: s.logLevel });
  cfg.inbounds = localInbounds(s, listen, sniffing);
  cfg.metrics = { tag: 'metrics', listen: `127.0.0.1:${s.apiPort}` };
  cfg.stats = {};
  const policy = isPlainObj(cfg.policy) ? cfg.policy : {};
  policy.system = Object.assign({}, isPlainObj(policy.system) ? policy.system : {},
    { statsInboundUplink: true, statsInboundDownlink: true, statsOutboundUplink: true, statsOutboundDownlink: true });
  cfg.policy = policy;
  if (Array.isArray(cfg.outbounds)) {
    const outs = cfg.outbounds.filter(isPlainObj);
    // the record's main outbound, found before anything is changed: the
    // certificate pin learnt for its server is that outbound's alone
    const main = outs.find(o => sameOutbound(o, server && server.outbound));
    for (const o of outs) {
      proxySettingsToDialer(o);
      applyCertPin(o, o === main ? server : null);
      applyWgEndpointIps(o, s.wgEndpointIps);
    }
    bindDirectDials(outs, s.directInterface);
  }
  return cfg;
}

/**
 * Build a "proxy pool" config: a single xray instance exposing MANY local
 * inbounds, each on its own SOCKS (and optional HTTP) port, each routed to its
 * own config/chain. This is what powers "run one exit on 60001, another on
 * 60002, …" — several proxies live at once.
 *
 * plan = {
 *   mode: 'pool',
 *   entries: [{ id, name, target, socksPort, httpPort }],  // target: serverId | 'chain:<id>'
 *   primary,                                                // target for the standard ports (system proxy / TUN)
 *   serversById, chainsById, chain
 * }
 *
 * The standard SOCKS/HTTP ports (settings.socksPort/httpPort) are ALSO opened and
 * routed to `primary`, so the system proxy, TUN and the IP check keep working
 * exactly as in single-config mode; the per-entry ports are extra exits on top.
 */
function buildPoolConfig(plan, s, listen, sniffing) {
  const reg = makeRegistry(plan, s.muxServerIds);
  const inbounds = [];
  // The metrics listener binds apiPort itself, outside the inbound list: reserve
  // it up front so a pool entry cannot take it (xray refuses to start on a
  // duplicate bind).
  const usedPorts = new Set([parseInt(s.apiPort, 10)]);

  const rules = [];

  const addInbound = (tag, port, proto) => {
    port = parseInt(port, 10);
    if (!port || port < 1 || port > 65535 || usedPorts.has(port)) return false;
    usedPorts.add(port);
    if (proto === 'http') {
      inbounds.push({ tag, port, listen, protocol: 'http', settings: {}, sniffing });
    } else {
      inbounds.push({ tag, port, listen, protocol: 'socks', settings: { auth: 'noauth', udp: true }, sniffing });
    }
    return true;
  };

  const perInboundRules = [];

  // 1) standard ports -> primary exit (system proxy / TUN / IP check use these)
  const primaryTag = reg.tagFor(plan.primary);
  const stdTags = [];
  if (addInbound('socks-in', s.socksPort, 'socks')) stdTags.push('socks-in');
  if (addInbound('http-in', s.httpPort, 'http')) stdTags.push('http-in');
  if (stdTags.length) perInboundRules.push({ type: 'field', inboundTag: stdTags, outboundTag: primaryTag });

  // 2) one inbound (socks + optional http) per pool entry -> its own exit
  for (const e of plan.entries || []) {
    if (!e) continue;
    const tag = reg.tagFor(e.target);
    const inTags = [];
    if (addInbound('ps-' + e.id, e.socksPort, 'socks')) inTags.push('ps-' + e.id);
    if (e.httpPort && addInbound('ph-' + e.id, e.httpPort, 'http')) inTags.push('ph-' + e.id);
    if (inTags.length) perInboundRules.push({ type: 'field', inboundTag: inTags, outboundTag: tag });
  }

  reg.add(freedom(s));
  reg.add(Object.assign({}, BLACKHOLE));
  const dnsPlan = buildDnsPlan(dnsSettingsFor(s, plan),
    { geoAssets: s.geoAssets !== false, exitTag: primaryTag, dropUdpDirect: dropsUdpDirect(s) });
  if (dnsPlan.hijackOutbound) reg.add(dnsPlan.hijackOutbound);
  const outs = (reg.outs || []).map(sanitizeWgOutbound).map(o => applyWgEndpointIps(o, s.wgEndpointIps));
  const hosts = pinEntryHosts(outs, s.entryHostIps, s.ipv6);   // see buildConfig
  const outbounds = applyFragments(outs);
  if (dropsUdpDirect(s)) echOverDoh(outbounds);
  bindDirectDials(outbounds, s.directInterface);

  // Resolver rules first (see buildConfig), then private/LAN direct, THEN
  // per-inbound routing, THEN a catch-all to the primary exit so nothing is
  // ever left unrouted.
  rules.push(...dnsPlan.rules);
  rules.push({ type: 'field', ip: PRIVATE_IPS.slice(), outboundTag: 'direct' });
  rules.push(...perInboundRules);
  rules.push({ type: 'field', port: '0-65535', outboundTag: primaryTag });

  // See buildConfig: no per-connection buffer cap for a chained WireGuard.
  const level0 = { statsUserUplink: true, statsUserDownlink: true };

  return {
    log: { loglevel: s.logLevel },
    // See buildConfig: the metrics endpoint reports every outbound tag, which is
    // what makes the traffic meter work for a pool (exits are 'out-<serverId>').
    metrics: { tag: 'metrics', listen: `127.0.0.1:${s.apiPort}` },
    stats: {},
    policy: {
      levels: { '0': level0 },
      system: { statsInboundUplink: true, statsInboundDownlink: true, statsOutboundUplink: true, statsOutboundDownlink: true }
    },
    dns: withHosts(dnsPlan.dns, hosts),
    inbounds,
    outbounds,
    // IPIfNonMatch on purpose: the pool emits no user ip rule (only the private
    // bypass), and on demand every entry's hostname connections would wait on
    // the PRIMARY's DoH — a dead primary costing the others ~8 s per new name.
    routing: { domainStrategy: 'IPIfNonMatch', rules }
  };
}

/**
 * Build a *test* config used only to measure real proxy latency.
 * `target` may be a single server object OR an array of servers (a chain).
 *
 * `opts` = { entryHostIps, ipv6 }: a mux probe (mux.js) runs inside a connect,
 * and is handed the names that connect already resolved — under TUN a
 * rebuild's held guard answers no name, so its core dials the address, as the
 * live core will (pinEntryHosts, before the dialers like there). A latency
 * test passes none, and its config is exactly as it was.
 */
function buildTestConfig(target, socksPort, opts) {
  const proxyOutbounds = Array.isArray(target)
    ? buildChainOutbounds(target, 'proxy')
    : withHelpers(cloneOut(target.outbound, 'proxy', target), target);
  const hosts = opts ? pinEntryHosts(proxyOutbounds, opts.entryHostIps, opts.ipv6) : null;
  // apply TLS fragment (if the config carries one) so the test matches reality
  const outbounds = applyFragments(proxyOutbounds).concat([{ tag: 'direct', protocol: 'freedom' }]);
  return {
    log: { loglevel: 'none' },
    ...(hosts ? { dns: { hosts } } : {}),
    inbounds: [{
      tag: 'socks-in',
      port: socksPort,
      listen: '127.0.0.1',
      protocol: 'socks',
      settings: { auth: 'noauth', udp: false }
    }],
    outbounds,
    // Unrouted traffic goes to the FIRST outbound — for a chain the entry hop
    // alone, so a dead exit measured green. Route the inbound to the exit.
    routing: { rules: [{ type: 'field', inboundTag: ['socks-in'], outboundTag: 'proxy' }] }
  };
}

/**
 * ONE throwaway core for MANY latency targets. Inbound i on ports[i] is routed
 * to target i by inboundTag; a target may be a server or a chain (an array).
 * "Test all" used to spawn a core per server, in sequence — sixty servers were
 * sixty process starts. Tags carry the index so a chain's hops
 * (`test-out-3-h0`) and the shared anti-DPI dialers cannot collide.
 * Same shape as buildTestConfig otherwise: no DNS plan, no interface binding
 * (a ping runs without TUN), fragments applied so the test matches reality.
 */
function buildMultiTestConfig(targets, ports) {
  const inbounds = [], outbounds = [], rules = [];
  (targets || []).forEach((target, i) => {
    const inTag = `test-in-${i}`, outTag = `test-out-${i}`;
    inbounds.push({ tag: inTag, port: ports[i], listen: '127.0.0.1', protocol: 'socks', settings: { auth: 'noauth', udp: false } });
    const outs = Array.isArray(target) ? buildChainOutbounds(target, outTag) : withHelpers(cloneOut(target.outbound, outTag, target), target);
    outbounds.push(...outs);
    rules.push({ type: 'field', inboundTag: [inTag], outboundTag: outTag });
  });
  return {
    log: { loglevel: 'none' },
    inbounds,
    outbounds: applyFragments(outbounds).concat([{ tag: 'direct', protocol: 'freedom' }]),
    routing: { rules }
  };
}

function normalizeCustomRules(custom, geo) {
  if (!Array.isArray(custom)) return [];
  const out = [];
  for (const r of custom) {
    if (!r || !r.outboundTag) continue;
    // custom outbound tags only ever target proxy/direct/block here
    const rule = { type: 'field', outboundTag: r.outboundTag };
    if (r.domain) {
      let d = splitList(r.domain);
      if (geo === false) d = d.filter(v => !/^geosite:/i.test(v));
      if (d.length) rule.domain = d;
    }
    if (r.ip) {
      let ip = splitList(r.ip);
      if (geo === false) ip = ip.filter(v => !/^geoip:/i.test(v));
      if (ip.length) rule.ip = ip;
    }
    if (r.port) rule.port = String(r.port);
    if (rule.domain || rule.ip || rule.port) out.push(rule);
  }
  return out;
}

/**
 * Split a rule value into tokens. Both `,` and `|` separate — the settings page
 * writes custom rules as `domain, a.com|b.com, proxy`, so a value that reaches
 * here as a raw string (headless RPC, a hand-edited store, an older save) must
 * split on `|` too. Neither character is legal inside a domain, an IP/CIDR or a
 * port range, so accepting both is a superset with no ambiguity.
 * ConfigBuilder.kt splits on the same pair.
 */
const SEPARATORS = /[|,]/;

function splitList(v) {
  if (Array.isArray(v)) return v.map(x => String(x).trim()).filter(Boolean);
  return String(v == null ? '' : v).split(SEPARATORS).map(x => x.trim()).filter(Boolean);
}

/**
 * DPI-evasion dialer: any outbound carrying a `_fragment` (TLS fragmentation)
 * and/or `_noise` (fake ClientHello / decoy packet injection) marker is made to
 * dial THROUGH a `freedom` outbound that carries the matching `fragment` and/or
 * `noises` settings. Outbounds that already dial through something (chain inner
 * hops) are left alone. Returns the outbound list with the extra freedom
 * outbounds appended; the markers are stripped.
 */
function applyFragments(outbounds) {
  const byKey = {};   // "frag|noise|strategy" -> tag
  const extra = [];
  for (const o of outbounds) {
    if (!o || (!o._fragment && !o._noise)) continue;
    const frag = o._fragment ? String(o._fragment) : '';
    const noise = o._noise ? String(o._noise) : '';
    delete o._fragment; delete o._noise;
    const ss = o.streamSettings || (o.streamSettings = {});
    const sockopt = ss.sockopt || (ss.sockopt = {});
    if (sockopt.dialerProxy) continue;   // chained hop — don't override
    // A pinned outbound (pinEntryHosts) hands its dialer the strategy too: the
    // name is normally resolved before the redirect, but a dialer handed the
    // NAME asks the OS when it is AsIs — the recursion the pin is there to
    // stop. So whichever resolves first, dns.hosts answers. Its own dialer:
    // one shared with an unpinned name would send that name to xray's DNS,
    // which sits behind the very proxy being dialled.
    const strategy = sockopt.domainStrategy || '';
    const key = frag + '|' + noise + '|' + strategy;
    let tag = byKey[key];
    if (!tag) {
      tag = 'dpi-' + (Object.keys(byKey).length + 1);
      byKey[key] = tag;
      extra.push(makeFragmentOutbound(tag, frag, noise, strategy));
    }
    sockopt.dialerProxy = tag;
  }
  return extra.length ? outbounds.concat(extra) : outbounds;
}

/**
 * Under TUN the OS default route IS the tunnel, so a dial Xray makes itself —
 * `direct` to a public address, the `dpi-*` dialers, a single proxy, the first
 * hop of a chain, a WireGuard endpoint — re-enters the TUN and loops back into
 * the SOCKS inbound (phase-2 review H1: why bypass-ir / bypass-cn / `direct`
 * routing never worked under TUN). `sockopt.interface` binds the socket to
 * the physical NIC instead (Windows IP_UNICAST_IF, macOS IP_BOUND_IF, Linux
 * SO_BINDTODEVICE); measured on this machine: a bound freedom dial left with
 * the ISP's public IP while the default route was the TUN.
 *
 * "Dials itself" = protocol not dns/blackhole AND no `sockopt.dialerProxy`:
 * a hop behind another hop dials through it, and binding it would be wrong.
 * Runs after applyFragments so the dpi dialers exist. `name` comes from
 * main.js (`settings.directInterface`, read from the OS before the tunnel is
 * up, only under tunMode); anything but a non-blank string leaves every
 * outbound exactly as it was, which the golden tests pin. Not applied to
 * buildTestConfig — a ping runs without TUN.
 */
function bindDirectDials(outbounds, name) {
  if (typeof name !== 'string' || !name.trim()) return outbounds;
  for (const o of outbounds) {
    if (!o || o.protocol === 'dns' || o.protocol === 'blackhole') continue;
    const ss = o.streamSettings || (o.streamSettings = {});
    if (ss.sockopt && ss.sockopt.dialerProxy) continue;
    ss.sockopt = Object.assign({}, ss.sockopt, { interface: name });
  }
  // An ECH config fetched from DNS is fetched by the core itself, with its own
  // socket options (echSockopt), for a hop behind another hop as much as for
  // the first: bound to the NIC like any direct dial, or the query enters the
  // tunnel that cannot come up without its answer.
  for (const tls of echQueryTls(outbounds)) {
    tls.echSockopt = Object.assign({}, tls.echSockopt, { interface: name });
  }
  return outbounds;
}

function makeFragmentOutbound(tag, fragStr, noiseStr, strategy) {
  const settings = { domainStrategy: strategy || 'AsIs' };
  if (fragStr) {
    const p = String(fragStr).split(',').map(s => s.trim());
    // xray rejects LengthMin=0, so clamp length min to >=1; keep packets/interval sane.
    settings.fragment = {
      packets: (p[0] && p[0].length) ? p[0] : 'tlshello',
      length: fragRange(p[1], '100-200', 1),
      interval: fragRange(p[2], '10-20', 0)
    };
  }
  const noises = noiseStr ? parseNoises(noiseStr) : [];
  if (noises.length) settings.noises = noises;
  return { tag, protocol: 'freedom', settings };
}

// Named presets (also accepted from the link's &noise= value).
const NOISE_PRESETS = {
  random: 'rand:50-100:0',
  // fake ClientHello: a ~handshake-sized decoy record, then jittered filler
  faketls: 'rand:100-200:0;rand:40-80:10-20',
  fakehello: 'rand:100-200:0;rand:40-80:10-20'
};

/**
 * Parse a noise spec into xray `noises` objects.
 * Spec: entries separated by `;`, each `type:packet:delay`.
 *   type   = rand | str | base64 | hex
 *   packet = length/length-range (rand/hex) | literal (str) | base64 (base64)
 *   delay  = ms number or range (optional, default "0")
 * A bare preset keyword (random/faketls/fakehello) is expanded first.
 */
function parseNoises(spec) {
  let s = String(spec == null ? '' : spec).trim();
  if (!s) return [];
  if (NOISE_PRESETS[s.toLowerCase()]) s = NOISE_PRESETS[s.toLowerCase()];
  const out = [];
  for (const entry of s.split(';')) {
    const e = entry.trim();
    if (!e) continue;
    const parts = e.split(':');
    const type = (parts[0] || '').trim().toLowerCase();
    const packet = (parts[1] || '').trim();
    const delay = (parts[2] || '0').trim() || '0';
    if (!['rand', 'str', 'base64', 'hex'].includes(type) || !packet) continue;
    out.push({ type, packet, delay });
  }
  return out;
}

// Normalize a "min-max" (or single) numeric range; clamp min to `floor`.
function fragRange(v, def, floor) {
  if (!v) return def;
  const parts = String(v).split('-').map(x => parseInt(x, 10));
  let min = parts[0];
  if (!Number.isFinite(min)) return def;
  let max = (parts.length > 1 && Number.isFinite(parts[1])) ? parts[1] : min;
  if (min < floor) min = floor;
  if (max < min) max = min;
  return min + '-' + max;
}

module.exports = { buildConfig, buildPoolConfig, buildTestConfig, buildMultiTestConfig, buildRoutingRules, buildChainOutbounds, resolverBypassIps, resolverBypassIpsOf, echResolverIpsOf, echQueryOf, wgResolvers, wgEndpointHosts, wgResolverAddresses, entryHosts, withHosts, serverAddressOf, buildRawConfig, rawServerOf, rawModeNotes, entryAddressesOf, isRawJson, rawApplies, dialerTagsOf };
