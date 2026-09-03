'use strict';
/**
 * Builds a complete Xray config.json.
 *
 * A "plan" describes what to connect through:
 *   { mode: 'single',   server }                       single proxy
 *   { mode: 'chain',    chain: [server,…] }            client → s0 → s1 → … → exit
 *   { mode: 'advanced', serversById, chain, rules, def } per-rule routing
 *
 * Legacy callers may still pass a bare server object or an array of servers;
 * normalizePlan() converts those into the structured form above.
 */

const { buildDnsPlan } = require('./dnsBuilder');

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

function cloneOut(outbound, tag) {
  const o = JSON.parse(JSON.stringify(outbound));
  o.tag = tag;
  return o;
}

/**
 * Coerce a WireGuard outbound's interface address to /32 (or /128 for IPv6).
 * xray refuses to start otherwise — this protects configs that were saved with
 * a wrong mask (e.g. someone put 192.168.x.0/16 in the Address field).
 */
function sanitizeWgOutbound(o) {
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
 * Build chained outbounds. `servers` is ordered first-hop → exit.
 * Each hop after the first dials THROUGH the previous via sockopt.dialerProxy.
 * The exit gets `exitTag` (what routing targets); default 'proxy'.
 *
 * Inner hop tags are namespaced under `exitTag` (`<exitTag>-h<i>`) so multiple
 * chains can coexist in one config (advanced routing) without tag collisions.
 */
function buildChainOutbounds(servers, exitTag) {
  exitTag = exitTag || 'proxy';
  const list = (servers || []).filter(s => s && s.outbound);
  const last = list.length - 1;
  const outs = [];
  for (let i = 0; i <= last; i++) {
    const tag = i === last ? exitTag : `${exitTag}-h${i}`;
    const ob = cloneOut(list[i].outbound, tag);
    if (i > 0) dialThrough(ob, `${exitTag}-h${i - 1}`);
    outs.push(ob);
  }
  return outs;
}

/**
 * Registry that turns a routing "target" into an outbound tag, lazily
 * creating (and de-duplicating) the outbound(s) needed for it.
 * Targets:
 *   'direct' | 'block'
 *   '<serverId>'        a single config
 *   'chain'             the legacy single chain (plan.chain)
 *   'chain:<chainId>'   a named chain (plan.chainsById[chainId])
 */
function makeRegistry(plan) {
  const outs = [];
  const seen = new Set();
  const add = (o) => { if (o && !seen.has(o.tag)) { seen.add(o.tag); outs.push(o); } };

  function chainTag(list, tag) {
    const arr = (list || []).filter(s => s && s.outbound);
    if (arr.length >= 2) { buildChainOutbounds(arr, tag).forEach(add); return tag; }
    if (arr.length === 1) { add(cloneOut(arr[0].outbound, tag)); return tag; }
    return 'direct';
  }

  function tagFor(target) {
    if (!target || target === 'direct') return 'direct';
    if (target === 'block') return 'block';
    if (target === 'chain') return chainTag(plan.chain, 'out-chain');
    if (typeof target === 'string' && target.indexOf('chain:') === 0) {
      const cid = target.slice('chain:'.length);
      const list = (plan.chainsById || {})[cid];
      return chainTag(list, 'out-chain-' + cid);
    }
    const s = (plan.serversById || {})[target];
    if (s && s.outbound) { const tag = 'out-' + target; add(cloneOut(s.outbound, tag)); return tag; }
    return 'direct';
  }

  return { outs, add, tagFor };
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
function dnsSettingsFor(s, plan) {
  return plan.mode === 'advanced'
    ? Object.assign({}, s, { advancedRouting: true, routeRules: plan.rules || [] })
    : Object.assign({}, s, { advancedRouting: false });
}

function buildConfig(planArg, settings) {
  const s = Object.assign({
    socksPort: 10808,
    httpPort: 10809,
    allowLan: false,
    routingMode: 'global',
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
  }, settings || {});
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

  if (plan.mode === 'advanced') {
    const reg = makeRegistry(plan);
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

      // Resolve the target only once the rule is known to survive: tagFor()
      // REGISTERS the outbound(s), so doing it earlier leaves a dead outbound
      // behind for every dropped rule — writing an unused server's address and
      // credentials into config.json (and materializing a whole chain for a
      // `chain:` target).
      const rule = { type: 'field', outboundTag: reg.tagFor(r.target) };
      rule[field] = value;
      advRules.push(rule);
    }
    const defTag = reg.tagFor(plan.def);
    exitTag = defTag;
    reg.add(freedom(s));
    reg.add(Object.assign({}, BLACKHOLE));
    outbounds = reg.outs;
    // NOTE: user rules come BEFORE the private-IP bypass on purpose. This is
    // "special routing" — explicit rules must win, otherwise a database on an
    // internal range (e.g. 10.20.0.0/16) would be caught by the private bypass
    // and go direct instead of through the chosen config/chain (e.g. WireGuard).
    rules = [
      ...(s.blockAds && geo ? [{ type: 'field', domain: ['geosite:category-ads-all'], outboundTag: 'block' }] : []),
      ...advRules,
      { type: 'field', ip: PRIVATE_IPS.slice(), outboundTag: 'direct' },
      { type: 'field', port: '0-65535', outboundTag: defTag }
    ];
  } else {
    const proxyOutbounds = plan.mode === 'chain'
      ? buildChainOutbounds(plan.chain, 'proxy')
      : [cloneOut(plan.server.outbound, 'proxy')];
    outbounds = [...proxyOutbounds, freedom(s), Object.assign({}, BLACKHOLE)];
    exitTag = s.routingMode === 'direct' ? 'direct' : 'proxy';
    // custom rules go BEFORE the catch-all so they actually take effect
    const base = buildRoutingRules(s.routingMode, s.blockAds, geo);
    const tail = base.pop(); // the final port:0-65535 catch-all
    rules = [...base, ...normalizeCustomRules(s.customRules, geo), tail];
  }

  // Name resolution (see dnsBuilder.js). Its rules go FIRST: the port-53 hijack
  // must beat the private-IP bypass, or a query to the tunnel peer 10.255.0.1
  // would be sent "direct" into nowhere instead of being answered.
  const dnsPlan = buildDnsPlan(dnsSettingsFor(s, plan), { geoAssets: geo, exitTag });
  if (dnsPlan.hijackOutbound) outbounds.push(dnsPlan.hijackOutbound);
  rules = [...dnsPlan.rules, ...rules];

  // Safety net: fix any WireGuard interface address that isn't /32 (/128).
  outbounds = (outbounds || []).map(sanitizeWgOutbound);
  outbounds = applyFragments(outbounds);

  // WireGuard dialed THROUGH another outbound (chain) needs the dialer pipe
  // buffer disabled, otherwise UDP/TCP conversion corrupts packets ("unknown
  // type packet") and the tunnel silently passes no data. See Xray-core #2850.
  const wgChained = outbounds.some(o =>
    o && o.protocol === 'wireguard' && o.streamSettings && o.streamSettings.sockopt && o.streamSettings.sockopt.dialerProxy);
  const level0 = { statsUserUplink: true, statsUserDownlink: true };
  if (wgChained) level0.bufferSize = 0;

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
    dns: dnsPlan.dns,
    inbounds: [
      { tag: 'socks-in', port: s.socksPort, listen, protocol: 'socks', settings: { auth: 'noauth', udp: true }, sniffing },
      { tag: 'http-in', port: s.httpPort, listen, protocol: 'http', settings: {}, sniffing }
    ],
    outbounds,
    routing: { domainStrategy: 'IPIfNonMatch', rules }
  };
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
  const reg = makeRegistry(plan);
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
  const dnsPlan = buildDnsPlan(dnsSettingsFor(s, plan), { geoAssets: s.geoAssets !== false, exitTag: primaryTag });
  if (dnsPlan.hijackOutbound) reg.add(dnsPlan.hijackOutbound);
  const outbounds = applyFragments((reg.outs || []).map(sanitizeWgOutbound));

  // Resolver rules first (see buildConfig), then private/LAN direct, THEN
  // per-inbound routing, THEN a catch-all to the primary exit so nothing is
  // ever left unrouted.
  rules.push(...dnsPlan.rules);
  rules.push({ type: 'field', ip: PRIVATE_IPS.slice(), outboundTag: 'direct' });
  rules.push(...perInboundRules);
  rules.push({ type: 'field', port: '0-65535', outboundTag: primaryTag });

  const wgChained = outbounds.some(o =>
    o && o.protocol === 'wireguard' && o.streamSettings && o.streamSettings.sockopt && o.streamSettings.sockopt.dialerProxy);
  const level0 = { statsUserUplink: true, statsUserDownlink: true };
  if (wgChained) level0.bufferSize = 0;

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
    dns: dnsPlan.dns,
    inbounds,
    outbounds,
    routing: { domainStrategy: 'IPIfNonMatch', rules }
  };
}

/**
 * Build a *test* config used only to measure real proxy latency.
 * `target` may be a single server object OR an array of servers (a chain).
 */
function buildTestConfig(target, socksPort) {
  const proxyOutbounds = Array.isArray(target)
    ? buildChainOutbounds(target, 'proxy')
    : [cloneOut(target.outbound, 'proxy')];
  // apply TLS fragment (if the config carries one) so the test matches reality
  const outbounds = applyFragments(proxyOutbounds).concat([{ tag: 'direct', protocol: 'freedom' }]);
  return {
    log: { loglevel: 'none' },
    inbounds: [{
      tag: 'socks-in',
      port: socksPort,
      listen: '127.0.0.1',
      protocol: 'socks',
      settings: { auth: 'noauth', udp: false }
    }],
    outbounds
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
  const byKey = {};   // "frag|noise" -> tag
  const extra = [];
  for (const o of outbounds) {
    if (!o || (!o._fragment && !o._noise)) continue;
    const frag = o._fragment ? String(o._fragment) : '';
    const noise = o._noise ? String(o._noise) : '';
    delete o._fragment; delete o._noise;
    const ss = o.streamSettings || (o.streamSettings = {});
    const sockopt = ss.sockopt || (ss.sockopt = {});
    if (sockopt.dialerProxy) continue;   // chained hop — don't override
    const key = frag + '|' + noise;
    let tag = byKey[key];
    if (!tag) {
      tag = 'dpi-' + (Object.keys(byKey).length + 1);
      byKey[key] = tag;
      extra.push(makeFragmentOutbound(tag, frag, noise));
    }
    sockopt.dialerProxy = tag;
  }
  return extra.length ? outbounds.concat(extra) : outbounds;
}

function makeFragmentOutbound(tag, fragStr, noiseStr) {
  const settings = { domainStrategy: 'AsIs' };
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

module.exports = { buildConfig, buildPoolConfig, buildTestConfig, buildRoutingRules, buildChainOutbounds };
