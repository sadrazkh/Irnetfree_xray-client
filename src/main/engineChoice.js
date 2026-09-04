'use strict';
/**
 * Which core runs a connection plan.
 *
 *  - single:   the server's own choice (edit form), else the default engine
 *  - chain / pool / advanced: 'xray-pattn' if the default is PattN or ANY server
 *    that participates asks for it — PattN accepts everything the official core
 *    does plus plaintext VLESS/Trojan, so a chain with one plaintext hop must run
 *    on it. Otherwise the official core.
 *  - 'sing-box' is a single-config engine only (it has no chain/pool translator).
 */

/** Every server object a plan can dial (duplicates allowed). */
function planServers(plan) {
  if (!plan) return [];
  switch (plan.mode) {
    case 'single': return plan.server ? [plan.server] : [];
    case 'chain': return plan.chain || [];
    case 'pool': return targetsServers((plan.entries || []).map(e => e && e.target), plan);
    case 'advanced': return targetsServers([...(plan.rules || []).map(r => r && r.target), plan.def], plan);
    default: return [];
  }
}

function targetsServers(targets, plan) {
  const out = [];
  for (const tg of targets) {
    if (!tg || tg === 'direct' || tg === 'block') continue;
    if (tg === 'chain') out.push(...(plan.chain || []));
    else if (String(tg).startsWith('chain:')) out.push(...((plan.chainsById || {})[String(tg).slice('chain:'.length)] || []));
    else if (plan.serversById && plan.serversById[tg]) out.push(plan.serversById[tg]);
  }
  return out;
}

function chooseEngine(plan, defaultEngine = 'xray') {
  const def = defaultEngine === 'xray-pattn' ? 'xray-pattn' : 'xray';
  if (plan && plan.mode === 'single') return (plan.server && plan.server.engine) || def;
  const wantsPattn = planServers(plan).some(s => s && s.engine === 'xray-pattn');
  return wantsPattn ? 'xray-pattn' : def;
}

/** Throwaway latency tests use an Xray-format core (buildTestConfig is Xray JSON). */
function testEngineFor(engineId) {
  return engineId === 'xray-pattn' ? 'xray-pattn' : 'xray';
}

/**
 * Does this core have to be handed a WireGuard peer endpoint as an ADDRESS?
 *
 * The official core resolves a peer endpoint NAME with its own resolver — the
 * managed DoH one, reached through the tunnel. Substituting an address there
 * would swap a censorship-resistant lookup for whatever the machine's own
 * resolver answers, which on a filtered connection is exactly the wrong answer
 * and would break a tunnel that works today.
 *
 * The patterniha fork does not use Xray's DNS for that bind at all: dialled
 * directly it asks the OS resolver ("Unable to update bind: lookup <host>: no
 * such host") and through a chain it hands the bare name to the next hop. There
 * an address is the only thing that works, so it — and only it — gets one.
 */
function needsWgEndpointIp(engineId) {
  return engineId === 'xray-pattn';
}

module.exports = { chooseEngine, planServers, testEngineFor, needsWgEndpointIp };
