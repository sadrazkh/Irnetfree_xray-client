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
 *     system DNS in TUN mode never leaves the machine in plain text.
 *
 * Everything here is pure; configBuilder splices the result into each plan.
 */

const DNS_DEFAULT_REMOTE = ['https://1.1.1.1/dns-query', 'https://8.8.8.8/dns-query'];
/** Shecan — the usual in-country resolver; a user can pick another preset. */
const DNS_DEFAULT_DIRECT_IR = ['178.22.122.100', '185.51.200.2'];
/** AliDNS for the China bypass — not user-configurable (the setting is Iran-centric). */
const DNS_DEFAULT_DIRECT_CN = ['223.5.5.5'];

const DNS_TAG = 'dns-internal';
const HIJACK_TAG = 'dns-out';

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

function isDohUrl(s) {
  return /^https(\+local)?:\/\//i.test(String(s || '').trim());
}

/** "8.8.8.8" → "8.8.8.8"; "https://1.1.1.1/dns-query" → "1.1.1.1"; a hostname → null. */
function resolverIp(entry) {
  const e = String(entry || '').trim();
  if (IPV4.test(e)) return e;
  const m = e.match(/^[a-z+]+:\/\/([^/:?#]+)/i);
  if (m && IPV4.test(m[1])) return m[1];
  return null;
}

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
 * @param {object} opts      geoAssets (bool), exitTag (string), dropUdpDirect (bool, phase-3 strict guard)
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
    return { dns: { queryStrategy, servers: remote }, hijackOutbound: null, rules: [], directResolverIps: [] };
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
      const srv = { address, domains: domains.slice() };
      if (o.geoAssets) srv.expectedIPs = expected.slice();
      srv.skipFallback = true;   // never ask the domestic resolver about the rest of the world
      servers.push(srv);
      const ip = resolverIp(address);
      if (ip && !directResolverIps.includes(ip)) directResolverIps.push(ip);
    }
  }

  for (const r of remote) servers.push(r);

  // Rule order matters: the resolver's own traffic is tagged with dns.tag and
  // must be decided BEFORE the port-53 hijack, or its UDP query to the
  // in-country server would be captured by dns-out and loop.
  const rules = [];
  if (directResolverIps.length) rules.push({ type: 'field', inboundTag: [DNS_TAG], ip: directResolverIps.slice(), outboundTag: 'direct' });
  rules.push({ type: 'field', inboundTag: [DNS_TAG], outboundTag: o.exitTag });
  rules.push({ type: 'field', port: '53', network: 'tcp,udp', outboundTag: HIJACK_TAG });

  return {
    dns: { tag: DNS_TAG, queryStrategy, servers },
    hijackOutbound: { tag: HIJACK_TAG, protocol: 'dns' },
    rules,
    directResolverIps
  };
}

/**
 * What the TUN adapter's DNS servers should be. Managed: the tunnel's own peer
 * address — every query then enters the TUN and is hijacked by dns-out.
 * Unmanaged: the plain-IP entries of the remote list (URLs cannot be adapter
 * DNS servers), falling back to public resolvers.
 */
function adapterDnsServers(settings, tunnelPeer) {
  const s = settings || {};
  if (s.dnsManaged !== false) return [tunnelPeer];
  const ips = cleanList(s.dnsRemote != null ? s.dnsRemote : s.dns).filter(v => IPV4.test(v));
  return ips.length ? ips.slice(0, 2) : ['1.1.1.1', '8.8.8.8'];
}

module.exports = {
  buildDnsPlan, adapterDnsServers, isDohUrl, resolverIp,
  DNS_DEFAULT_REMOTE, DNS_DEFAULT_DIRECT_IR, DNS_DEFAULT_DIRECT_CN, DNS_TAG, HIJACK_TAG
};
