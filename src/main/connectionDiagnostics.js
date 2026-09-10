'use strict';

// Diagnostics never rebuild or mutate a running configuration. Exported reports
// use an allow-list: even user-defined tags, names and error messages can carry
// private information, so none of those are copied to the result.
const net = require('net');
const { socks5Connect } = require('./netutils');
const PROTOCOLS = new Set(['vless', 'vmess', 'trojan', 'shadowsocks', 'socks', 'http', 'wireguard', 'hysteria', 'hysteria2', 'tuic', 'freedom', 'direct', 'blackhole', 'block', 'dns']);
const FIELDS = ['domain', 'ip', 'port', 'network', 'inboundTag', 'protocol', 'source', 'sourcePort', 'user', 'domain_suffix', 'domain_keyword', 'domain_regex', 'ip_cidr', 'port_range', 'inbound', 'process_name', 'process_path', 'rule_set'];

function explainRoutes(config, plan = {}) {
  plan = plan || {};
  if (!config || (!config.routing && !config.route)) return { status: 'unavailable', rules: [], paths: [] };
  const outbounds = Array.isArray(config.outbounds) ? config.outbounds : [];
  const byTag = new Map(outbounds.map(o => [o.tag, o]));
  const aliases = new Map();
  function target(tag) {
    const out = byTag.get(tag);
    const protocol = out && (out.protocol || out.type);
    if (protocol === 'freedom' || protocol === 'direct' || tag === 'direct') return 'direct';
    if (protocol === 'blackhole' || protocol === 'block' || tag === 'block') return 'block';
    if (protocol === 'dns') return 'dns';
    if (!out) return 'unknown';
    if (!aliases.has(tag)) aliases.set(tag, 'path-' + (aliases.size + 1));
    return aliases.get(tag);
  }
  const routing = config.routing || config.route;
  const rules = (Array.isArray(routing.rules) ? routing.rules : []).filter(r => r && typeof r === 'object').map((r, index) => ({
    priority: index + 1,
    // Criteria values are deliberately withheld from the shareable report.
    criteria: FIELDS.filter(f => r[f] != null).map(f => ({ field: f, count: Array.isArray(r[f]) ? r[f].length : 1 })),
    catchAll: r.port === '0-65535' && FIELDS.every(f => f === 'port' || r[f] == null),
    target: r.action === 'reject' ? 'block' : r.action === 'hijack-dns' ? 'dns' : r.balancerTag ? 'dynamic-selection' : target(r.outboundTag || r.outbound)
  }));
  const fallback = config.routing ? (outbounds[0] && target(outbounds[0].tag)) : target(routing.final);
  const paths = [];
  for (const [tag, alias] of aliases) {
    const hops = [];
    const seen = new Set();
    let cursor = tag;
    let complete = true;
    while (cursor) {
      if (seen.has(cursor)) { complete = false; break; }
      seen.add(cursor);
      const out = byTag.get(cursor);
      if (!out) { complete = false; break; }
      const protocol = out.protocol || out.type;
      hops.unshift(PROTOCOLS.has(protocol) ? protocol : 'other');
      cursor = (out.streamSettings && out.streamSettings.sockopt && out.streamSettings.sockopt.dialerProxy) || out.detour;
    }
    paths.push({ id: alias, hops, complete });
  }
  return {
    status: 'available',
    mode: ['single', 'chain', 'advanced', 'pool'].includes(plan.mode) ? plan.mode : 'unknown',
    semantics: 'First matching rule wins. Criteria values are withheld; this is rule order, not a prediction of a destination match. DNS, geo lists and sniffing may affect matching.',
    hopOrder: 'client to exit', rules, paths, fallback: fallback || 'unknown'
  };
}

function validPort(value) { return Number.isInteger(value) && value > 0 && value <= 65535; }
function validHost(host) {
  if (typeof host !== 'string' || !host || Buffer.byteLength(host, 'utf8') > 253) return false;
  if (net.isIP(host)) return true;
  return host.replace(/\.$/, '').split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label));
}

/** Explicit TCP-only check of a user-selected service (including private WG
 * destinations). Resolving a hostname is delegated to the running SOCKS/core;
 * there is never a direct fallback, HTTP request or automatic public probe.
 */
async function probeDestination(socksPort, target, deps = {}) {
  if (!validPort(socksPort) || !target || !validHost(target.host) || !validPort(target.port)) {
    return { status: 'invalid-input', via: 'local-socks', error: 'Use a hostname or IP and a port from 1 to 65535.' };
  }
  const connect = deps.socks5Connect || socks5Connect;
  const now = deps.now || Date.now;
  const started = now();
  let socket;
  try {
    socket = await connect('127.0.0.1', socksPort, target.host, target.port, 5000);
    return { status: 'reachable', via: 'local-socks', ms: Math.max(0, now() - started), scope: 'TCP connection only; does not verify application health or prove WireGuard was selected.' };
  } catch (e) {
    const message = String(e && e.message || '');
    return { status: 'unreachable', via: 'local-socks', reason: /timeout/i.test(message) ? 'timeout' : 'connection-failed' };
  } finally {
    if (socket) { try { socket.destroy(); } catch {} }
  }
}

async function collectDiagnostics(input = {}, deps = {}) {
  const running = input.coreRunning === true;
  const config = running ? input.config : null;
  const servers = config && config.dns && config.dns.servers;
  const report = {
    version: 1,
    core: { status: running ? 'running' : 'stopped', scope: 'Reported process state; traffic is checked separately.' },
    tun: { status: input.tunActive === true ? 'active' : input.tunRequested === true ? 'inactive' : 'not-requested', scope: 'Reported tunnel state; does not prove system traffic traverses it.' },
    dns: { status: Array.isArray(servers) && servers.length ? 'configured-unverified' : 'unknown', resolverCount: Array.isArray(servers) ? servers.length : 0, scope: 'No system DNS change or independent DNS-leak test is performed.' },
    connectivity: { status: 'not-tested', via: 'local-socks' },
    routes: explainRoutes(config, input.plan),
    privacy: 'Server names, addresses, keys, rule values, destination and raw errors are omitted.'
  };
  if (input.probe) report.connectivity = running
    ? await probeDestination(input.socksPort, input.probe, deps)
    : { status: 'core-stopped', via: 'local-socks' };
  return report;
}

module.exports = { collectDiagnostics, explainRoutes, probeDestination };
