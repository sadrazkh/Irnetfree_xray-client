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
 */
const { chooseEngine, testEngineFor } = require('./engineChoice');
const { engineFormat } = require('./engines');
const { buildTestConfig } = require('./configBuilder');
const { buildSingboxConfig } = require('./singboxBuilder');

/**
 * @param target  a server record, or a chain (an array of them)
 * @param port    the local SOCKS port the test listens on
 * @param opts    { defaultEngine, hasSingbox, dnsRemote }
 * @returns { engine, config, single } — `single`: this target needs a core of its own (no batching)
 */
function latencyTest(target, port, opts = {}) {
  const isChain = Array.isArray(target);
  const plan = isChain ? { mode: 'chain', chain: target } : { mode: 'single', server: target };
  const engine = chooseEngine(plan, opts.defaultEngine);
  if (!isChain && opts.hasSingbox && engineFormat(engine) === 'sing-box') {
    try {
      const config = buildSingboxConfig(target, { socksPort: port, httpPort: 0, dnsRemote: opts.dnsRemote, logLevel: 'error' });
      return { engine: 'sing-box', config, single: true };
    } catch { /* a server sing-box cannot carry is measured on Xray */ }
  }
  return { engine: testEngineFor(engine), config: buildTestConfig(target, port), single: false };
}

/** Does this target's test need a core of its own (see latencyTest)? Builds a config only for a server that would run on sing-box. */
function testsAlone(target, opts = {}) {
  if (Array.isArray(target) || !opts.hasSingbox) return false;
  return engineFormat(chooseEngine({ mode: 'single', server: target }, opts.defaultEngine)) === 'sing-box' &&
    latencyTest(target, 1, opts).single;
}

/**
 * A server that has no TCP port to knock on: WireGuard and Hysteria2 listen
 * on UDP only, so a TCP ping of them says nothing at all about the server
 * (it failed for every one of them). The real-delay test still measures them.
 */
function udpOnly(server) {
  const p = server && ((server.outbound && server.outbound.protocol) || server.protocol);
  return p === 'wireguard' || p === 'hysteria' || p === 'hysteria2';
}

module.exports = { latencyTest, testsAlone, udpOnly };
