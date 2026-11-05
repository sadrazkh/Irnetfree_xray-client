'use strict';
/**
 * "Connected" says the core runs, not that anything passes. Under advanced routing
 * that hides the worst case: name resolution leaves through the default route, so
 * with a dead default no name is found, not even a site with a rule of its own, and
 * changing a rule's target changes nothing. It looks as if the rules do nothing.
 *
 * While connected, a small request goes through the local SOCKS inbound now and then.
 * Two misses in a row and the window is told, once, until it answers again. It asks
 * the running core, starts nothing, and changes no route. A site no rule names is what
 * it asks for, so it measures the default. A rule that names the test site makes it
 * measure that rule instead: a block rule would warn on a healthy server.
 *
 * While the warning stands it asks at the short interval, so a false one (a laptop
 * waking before its Wi-Fi is back) is gone within seconds.
 */
const { isSplitTunnelWg, targetServer } = require('./configBuilder');

const TIMING = { firstMs: 8000, everyMs: 120000, recheckMs: 20000 };

/**
 * What to say if this plan's way out stops answering, or null when there is nothing
 * to watch: no way out to judge (direct, block, a pool), or a split-tunnel WireGuard,
 * which carries only its own ranges and would never answer the test.
 */
function deadRouteNotice(plan, settings = {}, chains = []) {
  if (!plan) return null;
  if (plan.mode === 'advanced') {
    const target = plan.def;
    if (!target || target === 'direct' || target === 'block') return null;
    if (isSplitTunnelWg(targetServer(target, plan))) return null;
    const id = settings.dnsManaged === false ? 'routeDead' : 'routeDeadDns';
    if (String(target).startsWith('chain:')) {
      const chainId = String(target).slice('chain:'.length);
      const chain = (chains || []).find((c) => c && c.id === chainId);
      return { id, name: (chain && chain.name) || chainId };
    }
    const server = target === 'chain' ? targetServer(target, plan) : (plan.serversById || {})[target];
    return { id, name: (server && server.name) || String(target) };
  }
  if (settings.routingMode === 'direct') return null;
  if (plan.mode === 'single') {
    if (!plan.server || isSplitTunnelWg(plan.server)) return null;
    return { id: 'serverDead', name: plan.server.name || '' };
  }
  if (plan.mode === 'chain') {
    const hops = (plan.chain || []).filter((s) => s && s.outbound);
    if (!hops.length || isSplitTunnelWg(hops[hops.length - 1])) return null;
    return { id: 'serverDead', name: plan.name || hops[hops.length - 1].name || '' };
  }
  return null;
}

/**
 * createRouteWatch({ probe, onChange, busy, timing }):
 *   probe(port)       resolves to whether the way out answered
 *   onChange(notice)  the notice when it stops answering, null when it answers again
 *   busy()            a connect, a recovery or a reload under way: nothing is asked or counted
 * start(notice, port) a connection stands; start(null) watches nothing. stop() it is gone.
 * notice() what stands right now, for a window opened later.
 */
function createRouteWatch({ probe, onChange, busy = () => false, timing = {} }) {
  const T = Object.assign({}, TIMING, timing);
  let gen = 0, timer = null, watched = null, port = 0, misses = 0, dead = false;

  const arm = (ms, g) => {
    clearTimeout(timer);
    timer = setTimeout(() => { tick(g); }, ms);
    if (timer.unref) timer.unref();
  };
  async function tick(g) {
    if (g !== gen) return;
    if (busy()) { misses = 0; arm(T.recheckMs, g); return; }
    let ok;
    try { ok = !!(await probe(port)); } catch { ok = false; }
    if (g !== gen) return;
    if (busy()) { misses = 0; arm(T.recheckMs, g); return; }
    if (ok) {
      misses = 0;
      if (dead) { dead = false; onChange(null); }
      arm(T.everyMs, g);
      return;
    }
    misses++;
    if (misses >= 2 && !dead) { dead = true; onChange(watched); }
    arm(T.recheckMs, g);
  }
  function stop() {
    gen++;
    clearTimeout(timer);
    timer = null;
    watched = null;
    misses = 0;
    dead = false;
  }
  function start(notice, socksPort) {
    stop();
    if (!notice) return;
    watched = notice;
    port = socksPort;
    arm(T.firstMs, gen);
  }
  return { start, stop, notice: () => (dead ? watched : null) };
}

module.exports = { createRouteWatch, deadRouteNotice };
