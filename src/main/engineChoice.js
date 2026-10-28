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
 *    TUIC and AnyTLS are sing-box's alone: a single one always runs there
 *    (isSingboxOnly), and no other plan can hold one.
 */

const { advancedTargets } = require('./routingProfiles');
const { isGroupRecord, serversOf } = require('./groups');

/**
 * Every server object a plan can dial (duplicates allowed). An advanced plan:
 * every rule target and the default, then every base they go through
 * (a routing profile's via).
 */
function planServers(plan) {
  if (!plan) return [];
  return planRecords(plan).flatMap(serversOf);   // a group stands for its members
}

function planRecords(plan) {
  switch (plan.mode) {
    case 'single': return plan.server ? [plan.server] : [];
    case 'chain': return plan.chain || [];
    case 'pool': return targetsServers((plan.entries || []).map(e => e && e.target), plan);
    case 'advanced': return targetsServers([...(plan.rules || []).map(r => r && r.target), plan.def, ...advancedTargets(plan).vias], plan);
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

/**
 * A Hysteria2 server that asked for "allow insecure" and names no certificate:
 * the Xray cores have no way left to accept an unverified certificate
 * (allowInsecure is gone; certPin's trust-on-first-use is a TCP handshake,
 * and Hysteria is QUIC), sing-box still has one. Such links are common — a
 * self-signed certificate is how most Hysteria2 servers are set up.
 */
function needsInsecureCore(server) {
  const st = server && server.outbound && server.outbound.streamSettings;
  const tls = st && st.tlsSettings;
  return !!(st && st.network === 'hysteria' && tls && tls.allowInsecure &&
    !String(tls.pinnedPeerCertSha256 || '').trim() && !String(tls.verifyPeerCertByName || '').trim() &&
    !String(server.certPin || '').trim());
}

/**
 * A MASQUE server (a JSON one too): only the Xray cores run it — sing-box has
 * no MASQUE (1.15 alphas only) and no WARP at all — whatever the record says.
 */
function isMasque(server) {
  return !!server && (server.protocol === 'masque' || !!(server.outbound && server.outbound.protocol === 'masque'));
}

/**
 * TUIC and AnyTLS: sing-box has them, neither Xray core has either. The record
 * keeps an Xray-shaped outbound all the same (parser.js) — Xray never runs it.
 * Such a server runs on sing-box, on its own, or not at all: whatever its
 * record or the default engine says, and never inside a chain, a group, a
 * routing rule or the pool, which only an Xray config can hold
 * (configBuilder refuses them by name).
 */
const SINGBOX_ONLY = { tuic: 'TUIC', anytls: 'AnyTLS' };

/** The record's own protocol or its outbound's (a record that lost its copy, as configBuilder.isWgServer reads it). */
function isSingboxOnly(server) {
  if (!server) return false;
  const has = (p) => typeof p === 'string' && Object.prototype.hasOwnProperty.call(SINGBOX_ONLY, p);
  return has(server.protocol) || has(server.outbound && server.outbound.protocol);
}

/**
 * Why a TUIC / AnyTLS server cannot run, in the app's language — the line a
 * connect, a test or a config build refuses with:
 *  - 'missing': sing-box is not installed;
 *  - 'plan':    it was put in a chain, a group, a routing rule or the pool;
 *  - 'router':  the router runs every config on Xray (its LAN's DNS is Xray's);
 *  - 'pin':     its certificate is pinned, which sing-box cannot keep
 *               (singboxBuilder.pinnedTls) — and there is no Xray to fall back to.
 */
function singboxOnlyError(server, why, lang) {
  const kind = SINGBOX_ONLY[(server && server.outbound && server.outbound.protocol) || (server && server.protocol)] || 'TUIC';
  const name = String((server && server.name) || kind);
  const en = lang === 'en';
  if (why === 'missing') {
    return en
      ? `"${name}" is a ${kind} server: it runs only on the sing-box core, which is not installed — it needs the sing-box core (Settings → Required files).`
      : `«${name}» سرور ${kind} است و فقط با هستهٔ sing-box اجرا می‌شود، که نصب نیست — هستهٔ sing-box را از تنظیمات → فایل‌های موردنیاز نصب کن.`;
  }
  if (why === 'router') {
    return en
      ? `"${name}" is a ${kind} server: it runs only on the sing-box core, and the router runs every config on Xray (the LAN's DNS is Xray's) — it cannot run on the router.`
      : `«${name}» سرور ${kind} است و فقط با هستهٔ sing-box اجرا می‌شود، ولی روتر همهٔ کانفیگ‌ها را با Xray اجرا می‌کند (DNS شبکهٔ پشت روتر با Xray است) — روی روتر اجرا نمی‌شود.`;
  }
  if (why === 'pin') {
    return en
      ? `"${name}" is a ${kind} server with a pinned certificate (pcs, vcn or pinned on first use): sing-box, the only core it runs on, could check it only by accepting any certificate — remove the pin in its editor (Security) to connect.`
      : `«${name}» سرور ${kind} با گواهیِ پین‌شده است (pcs، vcn یا پین در اولین اتصال): sing-box، تنها هسته‌ای که آن را اجرا می‌کند، فقط با قبولِ هر گواهی‌ای می‌تواند بررسی‌اش کند — برای اتصال، پین را در ویرایشگرش (امنیت) پاک کن.`;
  }
  return en
    ? `"${name}" is a ${kind} server: it runs only on its own, on sing-box — not inside a chain, group or routing rule.`
    : `«${name}» سرور ${kind} است و فقط به‌تنهایی و با sing-box اجرا می‌شود — نه درون زنجیره، گروه یا قانونِ روتینگ.`;
}

function chooseEngine(plan, defaultEngine = 'xray') {
  const def = defaultEngine === 'xray-pattn' ? 'xray-pattn' : 'xray';
  if (plan && plan.mode === 'single' && !isGroupRecord(plan.server)) {
    const s = plan.server;
    if (isMasque(s)) return s.engine === 'xray-pattn' ? 'xray-pattn' : def;
    if (isSingboxOnly(s)) return 'sing-box';
    return (s && s.engine) || (needsInsecureCore(s) ? 'sing-box' : def);
  }
  // a group (groups.js) runs on an Xray core whatever its members ask: sing-box has no balancer
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
module.exports = { chooseEngine, planServers, testEngineFor, needsInsecureCore, isMasque, isSingboxOnly, singboxOnlyError };
