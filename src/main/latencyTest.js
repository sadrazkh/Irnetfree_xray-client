'use strict';
/**
 * Which throwaway config a latency test runs, and on which core.
 *
 * A test measures the path the connection would take, so a single server whose
 * connection runs on sing-box — its own choice in the edit form, or a
 * Hysteria2 with a certificate only sing-box can accept (engineChoice
 * .needsInsecureCore) — is measured on sing-box when it is installed. On
 * Xray it would report an error for a server that connects fine. Everything
 * else (and a server sing-box cannot translate) is measured on an Xray-format
 * core, as before.
 *
 * TUIC and AnyTLS have no Xray at all (engineChoice.isSingboxOnly): measured
 * on sing-box or refused, saying why, as their connect is — sing-box not
 * installed, a router, a pinned certificate; inside a chain or a group the
 * Xray test config refuses them by name (configBuilder.cloneOut).
 */
const { chooseEngine, testEngineFor, planServers, isSingboxOnly, singboxOnlyError } = require('./engineChoice');
const { engineFormat } = require('./engines');
const { buildTestConfig } = require('./configBuilder');
const { buildSingboxConfig } = require('./singboxBuilder');
const { masqueHttpOf } = require('../renderer/serverFields');

/**
 * @param target  a server record, or a chain (an array of them)
 * @param port    the local SOCKS port the test listens on
 * @param opts    { defaultEngine, hasSingbox, dnsRemote, router, lang }
 * @returns { engine, config, single } — `single`: this target needs a core of its own (no batching)
 */
function latencyTest(target, port, opts = {}) {
  const isChain = Array.isArray(target);
  const plan = isChain ? { mode: 'chain', chain: target } : { mode: 'single', server: target };
  const engine = chooseEngine(plan, opts.defaultEngine);
  if (!isChain && isSingboxOnly(target)) {
    if (opts.router) throw new Error(singboxOnlyError(target, 'router', opts.lang));
    if (!opts.hasSingbox) throw new Error(singboxOnlyError(target, 'missing', opts.lang));
    try {
      return { engine: 'sing-box', config: buildSingboxConfig(target, { socksPort: port, httpPort: 0, dnsRemote: opts.dnsRemote, logLevel: 'error' }), single: true };
    } catch { throw new Error(singboxOnlyError(target, 'pin', opts.lang)); }
  }
  if (!isChain && opts.hasSingbox && engineFormat(engine) === 'sing-box') {
    try {
      const config = buildSingboxConfig(target, { socksPort: port, httpPort: 0, dnsRemote: opts.dnsRemote, logLevel: 'error' });
      return { engine: 'sing-box', config, single: true };
    } catch { /* a server sing-box cannot carry is measured on Xray */ }
  }
  return { engine: testEngineFor(engine), config: buildTestConfig(target, port), single: false };
}

/**
 * Does this target's test need a core of its own (see latencyTest)? Builds a
 * config only for a server that would run on sing-box. A TUIC / AnyTLS — or a
 * group holding one — always does: in a batch its refusal (latencyTest, or the
 * Xray test config's) would take every other target of the batch down with it.
 */
function testsAlone(target, opts = {}) {
  if (Array.isArray(target)) return false;
  if (planServers({ mode: 'single', server: target }).some(isSingboxOnly)) return true;
  if (!opts.hasSingbox) return false;
  return engineFormat(chooseEngine({ mode: 'single', server: target }, opts.defaultEngine)) === 'sing-box' &&
    latencyTest(target, 1, opts).single;
}

/**
 * A server that has no TCP port to knock on: WireGuard and Hysteria2 listen
 * on UDP only, so a TCP ping of them says nothing at all about the server
 * (it failed for every one of them). The real-delay test still measures them.
 * MASQUE likewise over HTTP/3 (QUIC); over HTTP/2 it is TCP like any other.
 * TUIC is QUIC too; AnyTLS is TLS over TCP, knocked on like any other.
 */
function udpOnly(server) {
  const ob = server && server.outbound;
  const p = server && ((ob && ob.protocol) || server.protocol);
  if (p === 'masque') return masqueHttpOf(ob && ob.streamSettings && ob.streamSettings.tlsSettings) !== 'h2';
  return p === 'wireguard' || p === 'hysteria' || p === 'hysteria2' || p === 'tuic';
}

module.exports = { latencyTest, testsAlone, udpOnly };
