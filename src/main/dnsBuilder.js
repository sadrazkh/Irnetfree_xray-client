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

/**
 * The port the core dials for an entry: the URL's or the host:port's own,
 * else the scheme's default — 443 for DoH, 853 for DNS over QUIC, 53 for
 * everything plain.
 */
function resolverPort(entry) {
  const e = String(entry || '').trim();
  const m = e.match(/^([a-z+]+):\/\/(\[[^\]]+\]|[^/:?#]+)(?::(\d{1,5}))?/i);
  if (m) {
    if (m[3]) return Number(m[3]);
    if (/^https/i.test(m[1])) return 443;
    if (/^quic/i.test(m[1])) return 853;
    return 53;
  }
  const { port } = splitHostPort(e);
  return port || 53;
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
 * category-ir through a config wants the exit's view of DNS, not Iran's) —
 * or when the plan applies a simple routing mode on top (`advancedUseMode`),
 * in which case it wants exactly what that mode wants.
 *
 * `geoAssets` is the veto. Every justification above is a geo token — the
 * routing mode's bypass pair, or a `geosite:` rule — and without geoip.dat /
 * geosite.dat the router emits none of them: bypass-ir IS global routing, every
 * byte goes through the proxy. Building the resolver anyway asked an Iranian
 * server, over cleartext UDP off the tunnel, for exactly the names the traffic
 * then hid — a leak with nothing bought for it, and one a fresh install (no geo
 * files downloaded yet) hit by default. Seen on both cores with
 * scripts/probe-dns-leak.js before this line existed.
 */
function directRegion(s, geoAssets) {
  if (!geoAssets) return null;
  if (s.advancedRouting) {
    let region = null;
    for (const r of s.routeRules || []) {
      if (!r || r.type !== 'domain' || r.target !== 'direct') continue;
      const v = String(r.value || '').toLowerCase();
      if (v.includes('geosite:category-ir')) return 'ir';
      if (v.includes('geosite:cn')) region = region || 'cn';
    }
    if (region || !s.advancedUseMode) return region;
    // else fall through to the routing mode the plan also applies
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
  // { ip, port } per resolver the core dials off the tunnel. The direct rule
  // below matches BOTH, so a public address that is also a remote DoH server
  // — 1.1.1.1 in the in-country list and https://1.1.1.1/dns-query in the
  // remote one, a real store — keeps its DoH on the exit: only the plain :53
  // query to it goes direct. Matched on ip alone, the DoH connection went off
  // the tunnel too, from the machine's own address.
  const directResolvers = [];
  const addDirect = (entry) => {
    const ip = resolverIp(entry);
    if (!ip) return;
    const port = resolverPort(entry);
    if (!directResolvers.some(d => d.ip === ip && d.port === port)) directResolvers.push({ ip, port });
    if (!directResolverIps.includes(ip)) directResolverIps.push(ip);
  };

  const region = directRegion(s, o.geoAssets);
  if (region) {
    let direct = region === 'cn' ? DNS_DEFAULT_DIRECT_CN.slice() : cleanList(s.dnsDirect);
    if (!direct.length) direct = (region === 'cn' ? DNS_DEFAULT_DIRECT_CN : DNS_DEFAULT_DIRECT_IR).slice();
    // strict guard: plain UDP is blocked off the tunnel, keep DoH only
    if (o.dropUdpDirect) direct = direct.filter(isDohUrl);

    // The tokens the installed files back. `directRegion` already refused the
    // whole resolver without them, so both lists are always available here.
    const domains = region === 'ir' ? ['geosite:category-ir', 'regexp:.*\\.ir$'] : ['geosite:cn'];
    const expected = region === 'ir' ? ['geoip:ir'] : ['geoip:cn'];

    for (const address of direct.slice(0, 2)) {
      const ent = serverEntry(address);
      const srv = Object.assign(typeof ent === 'object' ? ent : { address: ent }, { domains: domains.slice() });
      srv.expectedIPs = expected.slice();
      srv.skipFallback = true;   // never ask the domestic resolver about the rest of the world
      servers.push(srv);
      addDirect(address);
    }
  }

  for (const r of remote) {
    servers.push(serverEntry(r));
    // A LAN / private-range resolver (a router, a corporate DNS) is only
    // reachable off the tunnel; the exit rule below would send it nowhere.
    const ip = resolverIp(r);
    if (ip && isPrivateIp(ip)) addDirect(r);
  }

  // Resolvers that belong to a routing target (a corporate WireGuard's
  // internal DNS). They go LAST: the public resolver answers everything it
  // knows and only its NXDOMAIN falls through to the target's server, so
  // public names never travel through the tunnel to the company. `domains`
  // (the search domains) hands those names to the target's server FIRST —
  // no public round trip, and the internal name is never shown outside —
  // and `expectedIPs` (from AllowedIPs) discards an answer the tunnel could
  // not carry anyway.
  //
  // With search domains, `skipFallback` too, and that one is load-bearing. A
  // resolver reachable only THROUGH the tunnel must never be the fallback for
  // names the tunnel itself needs: on the owner's laptop the core asked the
  // corporate server for its own WireGuard endpoint (`cobra.tes.ca`) and for
  // `api.ipify.org` while the exit was down — each one a full round trip into
  // a tunnel that was not there, and the endpoint lookup then killed the core
  // outright (see engineChoice.js). Without search domains there is nothing
  // else to match on, so such a resolver stays a fallback and keeps working
  // the way it did.
  // Their queries must leave through the target — never `direct`, so they are
  // deliberately kept out of directResolverIps although they are private-range.
  const targetRules = [];
  for (const t of Array.isArray(o.targetResolvers) ? o.targetResolvers : []) {
    if (!t || !t.address || !t.outboundTag) continue;
    const ent = serverEntry(t.address);
    const srv = typeof ent === 'object' ? ent : { address: ent };
    if (Array.isArray(t.domains) && t.domains.length) {
      srv.domains = t.domains.slice();
      srv.skipFallback = true;
    }
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
  // A resolver imported from a routing target can also occur in the user's
  // remote/direct lists. Its explicit target owns that IP: otherwise the
  // earlier private-resolver exception sends corporate DNS onto the LAN.
  // Remove the bypass too, so the OS cannot route these packets around TUN.
  const targetIps = new Set(targetRules.flatMap(r => r.ip));
  for (let i = directResolverIps.length - 1; i >= 0; i--) {
    if (targetIps.has(directResolverIps[i])) directResolverIps.splice(i, 1);
  }
  // One direct rule per port, first port seen first: the in-country pair on
  // :53 is one rule, a `host:port` entry its own, a private DoH URL its :443.
  const directByPort = new Map();
  for (const d of directResolvers) {
    if (targetIps.has(d.ip)) continue;
    if (!directByPort.has(d.port)) directByPort.set(d.port, []);
    directByPort.get(d.port).push(d.ip);
  }
  for (const [port, ips] of directByPort) {
    rules.push({ type: 'field', inboundTag: [DNS_TAG], ip: ips, port: String(port), outboundTag: 'direct' });
  }
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

/**
 * What the leak guard must point the machine's PHYSICAL adapters at — on
 * macOS. On Windows the guard holds them on loopback instead whatever this
 * returns (see WIN_HOLD4 in leakGuard.js: Windows sends each adapter's queries
 * out of that adapter, and with the TUN adapter gone the peer routes out of
 * the physical NIC), and `peer4` only has to say that the tunnel has one.
 *
 * When the core hijacks port 53 the answer is the tunnel's own peer: every
 * query then enters the TUN, and if the tunnel goes, nothing resolves — closed,
 * which is the point of the guard.
 *
 * When it does NOT hijack — managed DNS switched off, or a sing-box-format
 * config, whose translator writes no hijack — that peer answers nothing at all.
 * Pointing the adapters at it left the machine with no name resolution on any
 * adapter but the tunnel's own, while the app reported it was protecting them:
 * every lookup that Windows sent to a physical adapter's resolver (it asks them
 * all) waited for a timeout. So they get exactly what the TUN adapter got —
 * the user's own resolvers, reached through the tunnel like everything else.
 *
 * @param {string[]} adapterDns  what adapterDnsServers() returned for this connect
 * @param {{peer4?: string, peer6?: string}} tunnel  the backend's own peers
 */
function guardPeers(adapterDns, tunnel) {
  const list = (Array.isArray(adapterDns) ? adapterDns : [adapterDns])
    .map(v => String(v == null ? '' : v).trim()).filter(Boolean);
  const peer4 = (tunnel && tunnel.peer4) || null;
  const peer6 = (tunnel && tunnel.peer6) || null;
  // The hijacked case: adapterDnsServers returns the peer and nothing else.
  if (!list.length || (list.length === 1 && list[0] === peer4)) return { peer4, peer6 };
  return {
    peer4: list.find(a => !a.includes(':')) || null,
    peer6: list.find(a => a.includes(':')) || null
  };
}

module.exports = {
  buildDnsPlan, adapterDnsServers, guardPeers, isDohUrl, resolverIp, resolverPort,
  DNS_DEFAULT_REMOTE, DNS_DEFAULT_DIRECT_IR, DNS_DEFAULT_DIRECT_CN, DNS_TAG, HIJACK_TAG
};
