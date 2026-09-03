'use strict';
/**
 * The resolver plan: what Xray's built-in DNS looks like for a settings object,
 * plus the routing rules that make it safe.
 *
 * Why this exists. The old config listed plain UDP resolvers (1.1.1.1) and let
 * them ride through the proxy. When the server dropped UDP — common — every
 * lookup failed, `IPIfNonMatch` never produced an IP, `geoip:ir` never matched,
 * and "bypass Iran" silently became "everything through the proxy". In TUN mode
 * the whole system's DNS took the same doomed path.
 *
 * The plan, mirroring what v2rayN does:
 *   - remote lookups over DoH (TCP/443), routed to the tunnel exit;
 *   - in bypass modes, an in-country UDP resolver pinned to domestic domains,
 *     with `expectedIPs` so a poisoned answer is discarded, reached DIRECT;
 *   - a `dns` outbound that answers ANY port-53 packet entering the core, so
 *     system DNS in TUN mode never leaves the machine in plain text;
 *   - a resolver can also follow a routing target: a corporate WireGuard's
 *     internal DNS is asked through that WireGuard's own outbound.
 *
 * Everything here is pure; configBuilder splices the result into each plan.
 */

const DNS_DEFAULT_REMOTE = ['https://1.1.1.1/dns-query', 'https://8.8.8.8/dns-query'];
/** Shecan — the usual in-country resolver; a user can pick another preset. */
const DNS_DEFAULT_DIRECT_IR = ['178.22.122.100', '185.51.200.2'];
/** AliDNS for the China bypass — not user-configurable (the setting is Iran-centric). */
const DNS_DEFAULT_DIRECT_CN = ['223.5.5.5'];

const net = require('net');

const DNS_TAG = 'dns-internal';
const HIJACK_TAG = 'dns-out';
/** Refuse every query type except A (1) and AAAA (28). */
const HIJACK_REFUSE_NON_IP = { action: 'return', rCode: 5, qType: '0,2-27,29-65535' };

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
const URL_SCHEME = /^[a-z+]+:\/\//i;

function isDohUrl(s) {
  return /^https(\+local)?:\/\//i.test(String(s || '').trim());
}

/**
 * "host:port" / "[v6]:port" → { host, port }; anything else keeps port null.
 * A bare IPv6 address has more than one colon and is never split.
 */
function splitHostPort(e) {
  const m6 = e.match(/^\[([^\]]+)\]:(\d{1,5})$/);
  if (m6) return { host: m6[1], port: Number(m6[2]) };
  const m4 = e.match(/^([^:/]+):(\d{1,5})$/);
  if (m4) return { host: m4[1], port: Number(m4[2]) };
  return { host: e, port: null };
}

/**
 * The address the core will dial for an entry, if it is a literal IP:
 * "8.8.8.8" → "8.8.8.8"; "1.1.1.1:5353" → "1.1.1.1"; "https://1.1.1.1/dns-query"
 * → "1.1.1.1"; a hostname (bare or in a URL) → null.
 */
function resolverIp(entry) {
  const e = String(entry || '').trim();
  const m = e.match(/^[a-z+]+:\/\/(\[[^\]]+\]|[^/:?#]+)/i);
  const host = m ? m[1].replace(/^\[|\]$/g, '') : splitHostPort(e).host;
  return net.isIP(host) ? host : null;
}

/** RFC1918 / loopback / link-local / CGNAT v4, ULA / link-local / loopback v6. */
function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)
      || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127);
  }
  return /^(fc|fd|fe80:|::1$)/i.test(ip);
}

/**
 * A resolver entry in the shape the core accepts. A URL or a bare address is
 * a string; "host:port" must become { address, port } — 26.3.27 rejects the
 * string form ("first path segment in URL cannot contain colon").
 */
function serverEntry(entry) {
  const e = String(entry).trim();
  if (URL_SCHEME.test(e)) return e;
  const { host, port } = splitHostPort(e);
  return port ? { address: host, port } : e;
}

/** A CIDR that only an AAAA answer could ever fall in. */
function isV6Range(c) { return String(c).includes(':') && !/^geoip:/i.test(String(c)); }

/** A CIDR that only an AAAA answer could ever fall in. */
function isV6Range(c) { return String(c).includes(':') && !/^geoip:/i.test(String(c)); }

function cleanList(list) {
  const out = [];
  for (const raw of Array.isArray(list) ? list : []) {
    const v = String(raw == null ? '' : raw).trim();
    if (v && !out.includes(v)) out.push(v);
  }
  return out;
}

/**
 * Which in-country resolver set a plan needs, if any: 'ir' | 'cn' | null.
 * Simple modes follow routingMode; advanced routing needs one only when a
 * domain rule sends the matching geosite list DIRECT (a rule that sends
 * category-ir through a config wants the exit's view of DNS, not Iran's).
 */
function directRegion(s) {
  if (s.advancedRouting) {
    let region = null;
    for (const r of s.routeRules || []) {
      if (!r || r.type !== 'domain' || r.target !== 'direct') continue;
      const v = String(r.value || '').toLowerCase();
      if (v.includes('geosite:category-ir')) return 'ir';
      if (v.includes('geosite:cn')) region = region || 'cn';
    }
    return region;
  }
  if (s.routingMode === 'bypass-ir') return 'ir';
  if (s.routingMode === 'bypass-cn') return 'cn';
  return null;
}

/**
 * @param {object} settings  dnsManaged, dnsRemote, dnsDirect, ipv6, routingMode, advancedRouting, routeRules
 * @param {object} opts      geoAssets (bool), exitTag (string), dropUdpDirect (bool, phase-3 strict guard),
 *                           targetResolvers: [{ address, outboundTag, expectedIPs?, domains? }] — resolvers
 *                           that belong to a routing target (a corporate WireGuard's DNS) and must be asked
 *                           through that target's outbound; `address` takes the same forms as the lists,
 *                           `domains` is already in the core's rule syntax (`domain:tes.systems`).
 */
function buildDnsPlan(settings, opts) {
  const s = settings || {};
  const o = Object.assign({ geoAssets: true, exitTag: 'proxy', dropUdpDirect: false }, opts || {});
  const queryStrategy = s.ipv6 ? 'UseIP' : 'UseIPv4';

  // the remote list; a legacy `dns` array (pre-migration store) counts
  let remote = cleanList(s.dnsRemote != null ? s.dnsRemote : s.dns);
  if (!remote.length) remote = DNS_DEFAULT_REMOTE.slice();

  if (s.dnsManaged === false) {
    // Legacy behaviour: the user's servers as given, nothing intercepted.
    return { dns: { queryStrategy, servers: remote.map(serverEntry) }, hijackOutbound: null, rules: [], directResolverIps: [] };
  }

  const servers = [];
  const directResolverIps = [];

  const region = directRegion(s);
  if (region) {
    let direct = region === 'cn' ? DNS_DEFAULT_DIRECT_CN.slice() : cleanList(s.dnsDirect);
    if (!direct.length) direct = (region === 'cn' ? DNS_DEFAULT_DIRECT_CN : DNS_DEFAULT_DIRECT_IR).slice();
    // strict guard: plain UDP is blocked off the tunnel, keep DoH only
    if (o.dropUdpDirect) direct = direct.filter(isDohUrl);

    // Only the tokens the installed files can back. Without geo files the
    // literal TLD regexp is all that is safe; expectedIPs needs geoip.dat.
    const domains = region === 'ir'
      ? (o.geoAssets ? ['geosite:category-ir', 'regexp:.*\\.ir$'] : ['regexp:.*\\.ir$'])
      : (o.geoAssets ? ['geosite:cn'] : ['regexp:.*\\.cn$']);
    const expected = region === 'ir' ? ['geoip:ir'] : ['geoip:cn'];

    for (const address of direct.slice(0, 2)) {
      const ent = serverEntry(address);
      const srv = Object.assign(typeof ent === 'object' ? ent : { address: ent }, { domains: domains.slice() });
      if (o.geoAssets) srv.expectedIPs = expected.slice();
      srv.skipFallback = true;   // never ask the domestic resolver about the rest of the world
      servers.push(srv);
      const ip = resolverIp(address);
      if (ip && !directResolverIps.includes(ip)) directResolverIps.push(ip);
    }
  }

  for (const r of remote) {
    servers.push(serverEntry(r));
    // A LAN / private-range resolver (a router, a corporate DNS) is only
    // reachable off the tunnel; the exit rule below would send it nowhere.
    const ip = resolverIp(r);
    if (ip && isPrivateIp(ip) && !directResolverIps.includes(ip)) directResolverIps.push(ip);
  }

  // Resolvers that belong to a routing target (a corporate WireGuard's
  // internal DNS). They go LAST: the public resolver answers everything it
  // knows and only its NXDOMAIN falls through to the target's server, so
  // public names never travel through the tunnel to the company. `domains`
  // (the search domains) hands those names to the target's server FIRST —
  // no public round trip, and the internal name is never shown outside —
  // and `expectedIPs` (from AllowedIPs) discards an answer the tunnel could
  // not carry anyway. No skipFallback: unlike the in-country resolver, this
  // one must remain a fallback for every name nobody else knows.
  // Their queries must leave through the target — never `direct`, so they are
  // deliberately kept out of directResolverIps although they are private-range.
  const targetRules = [];
  for (const t of Array.isArray(o.targetResolvers) ? o.targetResolvers : []) {
    if (!t || !t.address || !t.outboundTag) continue;
    const ent = serverEntry(t.address);
    const srv = typeof ent === 'object' ? ent : { address: ent };
    if (Array.isArray(t.domains) && t.domains.length) srv.domains = t.domains.slice();
    if (Array.isArray(t.expectedIPs) && t.expectedIPs.length) {
      // while the core asks for A records only, an IPv6 range could never
      // match — left in, it would reject every answer the resolver gives
      const exp = s.ipv6 ? t.expectedIPs.slice() : t.expectedIPs.filter(c => !isV6Range(c));
      if (exp.length) srv.expectedIPs = exp;
    }
    servers.push(srv);
    // One rule per ip, the first target named wins. A hostname address has no
    // ip to route by: its query rides the exit like any other (and a corporate
    // hostname will not resolve there — an ip is what the .conf gives anyway).
    const ip = resolverIp(t.address);
    if (ip && !targetRules.some(r => r.ip[0] === ip)) {
      targetRules.push({ type: 'field', inboundTag: [DNS_TAG], ip: [ip], outboundTag: t.outboundTag });
    }
  }

  // Rule order matters: the resolver's own traffic is tagged with dns.tag and
  // must be decided BEFORE the port-53 hijack, or its UDP query to the
  // in-country server would be captured by dns-out and loop. Direct resolver
  // → target resolvers → everything else to the exit → the hijack.
  const rules = [];
  if (directResolverIps.length) rules.push({ type: 'field', inboundTag: [DNS_TAG], ip: directResolverIps.slice(), outboundTag: 'direct' });
  rules.push(...targetRules);
  rules.push({ type: 'field', inboundTag: [DNS_TAG], outboundTag: o.exitTag });
  rules.push({ type: 'field', port: '53', network: 'tcp,udp', outboundTag: HIJACK_TAG });

  return {
    dns: { tag: DNS_TAG, queryStrategy, servers },
    // Every non-A/AAAA query (PTR/SRV/TXT/HTTPS…) is answered REFUSED (rCode 5)
    // instead of being forwarded to its original destination through a direct
    // dial — under TUN that is the tunnel peer, so it would loop back into the
    // hijack. The `rules` form is what both cores accept without a deprecation
    // warning (26.3.27 and PattN 26.9.1 verified); `nonIPQuery` is being removed
    // on main and cannot be mixed with `rules`.
    hijackOutbound: { tag: HIJACK_TAG, protocol: 'dns', settings: { rules: [HIJACK_REFUSE_NON_IP] } },
    rules,
    directResolverIps
  };
}

/**
 * What the TUN adapter's DNS servers should be. Managed, with a peer to hand
 * the queries to: the tunnel's own address — every query then enters the TUN
 * and is hijacked by dns-out. Otherwise (unmanaged, or a config without the
 * hijack — the sing-box format has none — so `tunnelPeer` is null): the
 * plain-IP entries of the remote list (a URL or a host:port cannot be an
 * adapter DNS server), falling back to public resolvers the proxy can reach.
 */
function adapterDnsServers(settings, tunnelPeer) {
  const s = settings || {};
  if (s.dnsManaged !== false && tunnelPeer) return [tunnelPeer];
  const ips = cleanList(s.dnsRemote != null ? s.dnsRemote : s.dns).filter(v => IPV4.test(v));
  return ips.length ? ips.slice(0, 2) : ['1.1.1.1', '8.8.8.8'];
}

module.exports = {
  buildDnsPlan, adapterDnsServers, isDohUrl, resolverIp,
  DNS_DEFAULT_REMOTE, DNS_DEFAULT_DIRECT_IR, DNS_DEFAULT_DIRECT_CN, DNS_TAG, HIJACK_TAG
};
