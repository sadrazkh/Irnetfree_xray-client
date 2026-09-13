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

/*
 * Which core has to be handed a WireGuard peer endpoint as an ADDRESS?
 *
 * Every core, so there is no longer a function here to ask.
 *
 * This used to be the patterniha fork's business only: the fork cannot resolve
 * a peer endpoint itself, while the official core asks its own DoH resolver,
 * which is the censorship-resistant lookup this app exists to prefer. What that
 * reasoning missed is the failure path. When the core's lookup does not answer
 * — the exit is not up yet, DoH is unreachable, or the plan's own corporate
 * resolver is asked for the endpoint of the tunnel that reaches it — Xray's
 * WireGuard handler panics (`close of closed channel`, proxy/wireguard/bind.go)
 * and the WHOLE core dies, taking every other route with it. Seen on the
 * owner's laptop: an advanced plan whose chain ends at a corporate WireGuard,
 * one connection to it, and the process was gone.
 *
 * So the app resolves the endpoint itself, before the core ever sees it, and
 * does it through src/main/trustedDns.js rather than the machine's resolver —
 * a DoH answer when the network's own is a fake-IP address. A name that cannot
 * be resolved at all is still left to the core.
 */
module.exports = { chooseEngine, planServers, testEngineFor };
