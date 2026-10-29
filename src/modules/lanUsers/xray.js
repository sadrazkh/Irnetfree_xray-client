'use strict';
/**
 * Users and devices (module `lanUsers`) in the Xray config: a username/password
 * SOCKS5 and HTTP proxy on the LAN, each user routed to a config of their own,
 * each user's bytes counted by the core.
 *
 * What the core does with a SOCKS or HTTP account — read in XTLS/Xray-core
 * v26.10.21 (the PattN fork's 26.10.22 is the same in every one of these files):
 *  - An account is `{ user, pass }` and nothing else: the server side keeps a
 *    username → password map, with no email or level of its own
 *    (infra/conf/socks.go:13-16 and 50-59, infra/conf/http.go:13-16 and 38-47).
 *  - A SOCKS5 login names the session's user by its USERNAME — `request.User =
 *    &protocol.MemoryUser{Email: username}` (proxy/socks/protocol.go:164-165),
 *    copied onto the inbound (proxy/socks/server.go:135-136); UDP ASSOCIATE
 *    keeps that inbound, so a user's UDP is theirs too (server.go:168-190).
 *    SOCKS4 is refused when a password is required (protocol.go:52-55).
 *  - HTTP checks Proxy-Authorization and does the same: `inbound.User.Email =
 *    user` (proxy/http/server.go:121-128) — but only when the inbound HAS
 *    accounts: with none it lets anyone through (server.go:121), and so does
 *    the HTTP a SOCKS inbound answers on its own port, which gets the SOCKS
 *    accounts handed on (proxy/socks/server.go:44-49). So no active user means
 *    no inbound at all, never an empty account list.
 *  - Routing's `user` matches that Email (app/router/condition.go:185-196, via
 *    features/routing/session/context.go:123-127).
 *  - Per-user stats are `user>>><Email>>>>traffic>>>uplink|downlink` when the
 *    user's level has statsUserUplink/Downlink (app/dispatcher/default.go:
 *    161-176) — level 0, every config this app builds — and /debug/vars
 *    reports them under stats.user[<Email>] (app/metrics/metrics.go:175-201).
 * So ONE SOCKS inbound (`lu-socks`) and ONE HTTP inbound (`lu-http`) carry
 * every user, and a user is known to routing and to the counters by their
 * username — unique, case aside (model.js). No port per user is needed.
 *
 * What a user sends direct leaves through a direct outbound of their own,
 * `lu-d-<userId>` — a copy of the plan's own `direct`, made beside it before
 * any pass, so every pass that binds the direct path (the NIC binding under
 * TUN above all: a freedom dial that is not bound loops back into the tunnel)
 * does the same to it — and its counter, stats.outbound['lu-d-<userId>']
 * (policy.system statsOutbound*, on in every config the builder makes), is
 * that user's direct bytes: meter.js counts them so. Everything else the
 * user carried is their VPN.
 *
 * configBuilder.buildConfig and buildPoolConfig call in two places, only when
 * applies(settings): lanUsersOutbounds() where the plan's own outbounds are
 * made — so every pass after it (multi-internet, groups, the WireGuard fixes,
 * pinned names, anti-DPI dialers, ECH, the NIC binding under TUN) reaches a
 * user's config and direct outbound exactly as it reaches the plan's — and
 * applyLanUsers() at the end, for the inbounds and the rules. Off, neither
 * runs: not a byte of the config changes.
 *
 * `settings.lanUsers` — what ipc.js forBuild() hands the build (the store's
 * record plus what only the running app knows):
 *   { config, users, devices,        the store's record (model.js)
 *     over: [userId],                held off entirely this period (meter.js holds 'all')
 *     holds: { [userId]: 'vpn'|'direct' }, held in part: only that class is blocked
 *     profilesById: { [id]: profile }, the app's routing profiles the users' routing names
 *     geo,                           whether geoip.dat / geosite.dat are there (absent: the builder's say)
 *     now,                           ms — expiry and the allowed hours are judged at this moment
 *     listen,                        the LAN address the proxy binds: absent = '0.0.0.0'
 *                                    (the desktop, as LAN sharing binds); '' = none known (no proxy)
 *     serversById, chainsById,       the records the users' targets (and their profiles' targets)
 *                                    name (a chain that lost a member is null: blocked, never a
 *                                    shorter chain)
 *     wgEndpointIps,                 WireGuard endpoint names of those, resolved
 *     tp: [{ tag | n, port, target, userId? }] the router's transparent mode: a loopback SOCKS
 *                                    inbound `lu-tp-<n>` routed like a user — that user's rules
 *                                    when it names one }
 *
 * The content filter (v1.40.0) — `user.filter`, null or { block, safeSearch,
 * domains } (model.js), first among that user's rules, scoped like the rest:
 *  - `block`: categories, each a geosite list the geosite.dat the app downloads
 *    carries (FILTER_GEOSITE). Loyalsoldier/v2ray-rules-dat builds it from
 *    v2fly/domain-list-community's `data/` (its run.yml: `go run ./
 *    --datapath=../community/data`), whose files were read by name on
 *    2026-10-29: category-porn, category-social-media-!cn, category-games and
 *    category-ads-all are there; NO gambling list is (only category-betting-ru,
 *    Russian bookmakers), so that key writes no rule and is said in the notes.
 *    Without the geo files the core would refuse the config over a geosite
 *    name: the categories are left out, and said once in the notes.
 *  - `domains`: 'example.com' (the domain and its subdomains), 'full:host',
 *    'keyword:word' → block.
 *  - `safeSearch`: each engine's search hosts on TCP 443 go to a freedom
 *    outbound of the user's own, `lu-ss-<id>-<engine>`, whose `redirect` is the
 *    engine's safe host:443 — the host each engine documents as the DNS CNAME
 *    for a network (SAFE_SEARCH cites them). The browser still sends the real
 *    name as SNI and Host; the safe host is the same front end, serves that
 *    name's certificate and answers with its strict results — exactly what the
 *    CNAME does, per user instead of per network. The outbound dials through
 *    the outbound the user's traffic rides (`sockopt.dialerProxy`; a copy of
 *    their own direct outbound when it rides direct), so the engine sees the
 *    user's exit, never this machine. UDP 443 to those hosts is blocked: QUIC
 *    would carry the search past the redirect, and a browser retries over TCP.
 *    Read in XTLS/Xray-core (main, 2026-10-29): infra/conf/freedom.go parses
 *    `redirect` with net.SplitHostPort + xnet.ParseAddress (a domain is
 *    accepted); proxy/freedom/freedom.go Process() replaces the destination's
 *    address and port and, with a dialerProxy, hands the domain unresolved to
 *    the dialer; transport/internet/dialer.go DialSystem() dials through the
 *    handler `sockopt.DialerProxy` names whatever the outbound's protocol — a
 *    freedom too. Not for a user whose traffic rides a balancer (no outbound
 *    to name) or a group's loopback outbound (a TCP stream dialled through a
 *    loopback can lose its tail — the groups round: nothing TCP dials a
 *    group): left out, and said in the notes.
 *  The rules match on names: an inbound whose sniffing is off gets it on
 *  (`routeOnly`, the dial unchanged) when a filtered user rides it. What the
 *  filter could not do is `config.lanUsersNotes` (not written to disk) and
 *  `ctx.log` when the caller gives one; the router gets `notes` back.
 */
const net = require('net');
const { normalizeLanUsers, normalizeConfig, activeUsers, portOf, targetOk, routingOf, profileIdOf, ID } = require('./model');
// a target's outbounds and its loopback inbound: shared with the per-app configs (src/main/tunAppTargets.js)
const { targetOutbounds, loopbackSocksInbound, targetGone } = require('../../main/targetOutbounds');
const { TARGET_BASE } = require('../../main/routingProfiles');

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const clone = (v) => JSON.parse(JSON.stringify(v));

const SOCKS_TAG = 'lu-socks';
const HTTP_TAG = 'lu-http';
const OUT_PREFIX = 'lu-out-';
const TP_PREFIX = 'lu-tp-';
/** A user's own direct outbound: `lu-d-<userId>` (meter.js reads its counter). */
const DIRECT_PREFIX = 'lu-d-';
/**
 * Where nobody on the LAN may get to THROUGH the proxy: this machine's own
 * loopback — the core's metrics and control API, the router's admin page and
 * anything else that trusts 127.0.0.1. The IPs as written; the name
 * `localhost` (and its subdomains) as a name, before anything resolves it.
 */
const LOOPBACK_IPS = ['127.0.0.0/8', '0.0.0.0/8', '::1/128', '::/128'];
const LOOPBACK_NAMES = ['domain:localhost'];
/** The private ranges the app's own routing sends direct (configBuilder's PRIVATE_IPS, the same list: no geo file needed). */
const PRIVATE_IPS = [
  '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
  '172.16.0.0/12', '192.168.0.0/16', '224.0.0.0/4', '240.0.0.0/4',
  '::1/128', 'fc00::/7', 'fe80::/10'
];
/** "Iranian sites direct" — configBuilder buildRoutingRules' bypass-ir, word for word (both need the geo files). */
const IR_DOMAINS = ['geosite:category-ir', 'regexp:.*\\.ir$'];
const IR_IPS = ['geoip:ir'];
/** A profile rule's value: a list split as the app splits it (configBuilder splitList). */
const SEPARATORS = /[|,]/;

/* ------------------------------ the content filter ------------------------------ */

/** The filter's category keys (model.js FILTER_CATEGORIES), in their order. */
const FILTER_CATEGORIES = ['adult', 'gambling', 'social', 'games', 'ads'];
/**
 * Each category's geosite list — only names READ in v2fly/domain-list-community's
 * `data/` (what Loyalsoldier's geosite.dat is built from) on 2026-10-29. No
 * key for 'gambling': that tree holds no gambling, casino, lottery or poker
 * list (category-betting-ru alone, Russian bookmakers), and a name the file
 * has not would stop the core.
 */
const FILTER_GEOSITE = Object.freeze({
  adult: 'geosite:category-porn',
  social: 'geosite:category-social-media-!cn',
  games: 'geosite:category-games',
  ads: 'geosite:category-ads-all'
});
/** Custom blocked domains kept at most (model.js FILTER_DOMAINS_MAX). */
const FILTER_DOMAINS_MAX = 200;
/** A domain or keyword after its prefix: letters, digits, '.', '-', '_' — nothing the core's matcher reads otherwise. */
const DOMAIN_TEXT = /^[a-z0-9._-]{1,253}$/;
/** A user's safe-search outbounds: `lu-ss-<userId>-<engine>`. */
const SS_PREFIX = 'lu-ss-';
/**
 * The engines' safe hosts, as each documents them for a network's DNS (the
 * search hosts as the core matches them: `full:` exact names, one regexp for
 * Google's country domains — www.google.de, www.google.co.uk, www.google.com.tr).
 *  - Google: support.google.com/websearch/answer/186669 — "Set the DNS entry
 *    for www.google.com (and any other Google country or region domains that
 *    your users may use) to be a CNAME for forcesafesearch.google.com".
 *  - Bing: support.microsoft.com, "Block adult content with SafeSearch" — "Set
 *    the DNS entry for www.bing.com to be a CNAME for strict.bing.com", and
 *    edgeservices.bing.com the same for the Edge sidebar.
 *  - DuckDuckGo: duckduckgo.com/duckduckgo-help-pages/features/safe-search —
 *    "Set the DNS entry for duckduckgo.com to the safe.duckduckgo.com CNAME".
 *  - YouTube: knowledge.workspace.google.com/admin/youtube/control-youtube-
 *    content-available-to-users — a CNAME to restrict.youtube.com for exactly
 *    www.youtube.com, m.youtube.com, youtubei.googleapis.com,
 *    youtube.googleapis.com and www.youtube-nocookie.com, and never youtube.com,
 *    youtu.be, s.ytimg.com or googleapis.com ("may stop YouTube from working").
 */
const SAFE_SEARCH = Object.freeze([
  { key: 'google', host: 'forcesafesearch.google.com', domains: ['full:www.google.com', 'regexp:^www\\.google\\.(com?\\.)?[a-z]{2,3}$'] },
  { key: 'bing', host: 'strict.bing.com', domains: ['full:www.bing.com', 'full:edgeservices.bing.com'] },
  { key: 'ddg', host: 'safe.duckduckgo.com', domains: ['full:duckduckgo.com'] },
  { key: 'youtube', host: 'restrict.youtube.com', domains: ['full:www.youtube.com', 'full:m.youtube.com', 'full:youtubei.googleapis.com', 'full:youtube.googleapis.com', 'full:www.youtube-nocookie.com'] }
]);

/** One custom blocked domain as stored — 'example.com', 'full:host', 'keyword:word', lowercase — or null for anything else. */
function filterDomainOf(v) {
  if (typeof v !== 'string') return null;
  const m = /^(full:|keyword:)?(.*)$/.exec(v.trim().toLowerCase());
  return m && DOMAIN_TEXT.test(m[2]) ? (m[1] || '') + m[2] : null;
}

/** A stored domain as the core's rule: 'example.com' → 'domain:example.com'; a prefixed one as it is. */
const domainRule = (d) => (/^(full|keyword):/.test(d) ? d : 'domain:' + d);

/**
 * A user's content filter as the build reads it — { block, safeSearch, domains }
 * or null — from whatever `user.filter` holds (the model's shape, or a record
 * of before, or junk): known categories once each in their order, domains in
 * their stored forms once each, at most FILTER_DOMAINS_MAX; null when there is
 * nothing to do.
 */
function filterOf(u) {
  const f = isObj(u) && isObj(u.filter) ? u.filter : null;
  if (!f) return null;
  const block = FILTER_CATEGORIES.filter((k) => Array.isArray(f.block) && f.block.includes(k));
  const domains = [];
  for (const d of Array.isArray(f.domains) ? f.domains : []) {
    const v = filterDomainOf(d);
    if (v && !domains.includes(v)) domains.push(v);
    if (domains.length >= FILTER_DOMAINS_MAX) break;
  }
  const safeSearch = f.safeSearch === true;
  return block.length || domains.length || safeSearch ? { block, safeSearch, domains } : null;
}

/**
 * A user's filter in a build: on the user as handed, else on the store's
 * record of the same id in `lu.users` — a model of before drops what it does
 * not know when it normalizes, and the record is still what the admin saved.
 */
function filterFor(lu, u) {
  const own = filterOf(u);
  if (own || !isObj(u)) return own;
  const raw = isObj(lu) && Array.isArray(lu.users) ? lu.users.find((x) => isObj(x) && x.id === u.id) : null;
  return filterOf(raw);
}

/**
 * The outbound a user's safe search may dial through — `tag`, their catch-all's
 * — or null when nothing can: a tag the config has not (a balancer's), a group's
 * loopback outbound (the tail of a TCP stream dialled through a loopback is
 * lost now and then, groups round fact 2), a blackhole (nothing of theirs goes
 * anywhere, nothing to redirect).
 */
function safeSearchVia(config, tag) {
  if (typeof tag !== 'string' || !tag) return null;
  const o = (isObj(config) && Array.isArray(config.outbounds) ? config.outbounds : []).find((x) => x && x.tag === tag);
  return o && o.protocol !== 'loopback' && o.protocol !== 'blackhole' ? tag : null;
}

/**
 * One user's safe-search outbounds, `lu-ss-<id>-<engine>`, each a freedom
 * whose `redirect` is the engine's safe host:443: dialled through `via` (the
 * outbound the user's traffic rides — `sockopt.dialerProxy`), or, when it
 * rides direct, a copy of `direct` (their own direct outbound, bound as it is)
 * with the redirect on. → { outbounds, tags: { [engine]: tag } }; nothing when
 * neither is given.
 */
function safeSearchOutbounds(u, o) {
  const a = isObj(o) ? o : {};
  const out = { outbounds: [], tags: {} };
  const direct = isObj(a.direct) ? a.direct : null;
  const via = typeof a.via === 'string' && a.via ? a.via : null;
  if (!isObj(u) || typeof u.id !== 'string' || (!direct && !via)) return out;
  for (const e of SAFE_SEARCH) {
    const tag = SS_PREFIX + u.id + '-' + e.key;
    const redirect = e.host + ':443';
    const ob = direct
      ? Object.assign(direct.protocol === 'freedom' ? clone(direct) : { protocol: 'freedom', streamSettings: clone(direct.streamSettings || {}) }, { tag })
      : { tag, protocol: 'freedom', settings: {}, streamSettings: { sockopt: { dialerProxy: via } } };
    ob.settings = Object.assign({}, isObj(ob.settings) ? ob.settings : {}, { redirect });
    out.outbounds.push(ob);
    out.tags[e.key] = tag;
  }
  return out;
}

/**
 * The sniffing the filter's name rules need, on an inbound whose sniffing is
 * off: on for every kind, `routeOnly` — the routing sees the name, the dial is
 * not changed. One already on is left as the owner set it.
 */
function ensureSniffing(inbound) {
  if (!isObj(inbound)) return inbound;
  if (!(isObj(inbound.sniffing) && inbound.sniffing.enabled === true)) inbound.sniffing = { enabled: true, destOverride: ['http', 'tls', 'quic'], routeOnly: true };
  return inbound;
}

/**
 * What a user's filter could not do in this build, one line each for the log:
 * `o.geo` the geo files are there, `o.safe` their safe-search outbounds were
 * made. [] for no filter, or one wholly applied.
 */
function filterNotes(u, f, o) {
  if (!f) return [];
  const a = isObj(o) ? o : {};
  const who = `"${(isObj(u) && (u.name || u.username || u.id)) || '?'}"`;
  const out = [];
  if (f.block.length && a.geo !== true) out.push(`Users: ${who}’s blocked categories (${f.block.join(', ')}) need the geo files (geoip.dat, geosite.dat) — left out until they are there`);
  for (const k of f.block) if (!FILTER_GEOSITE[k]) out.push(`Users: ${who}: geosite.dat has no list for the category "${k}" — left out`);
  if (f.safeSearch && a.safe !== true) out.push(`Users: ${who}: safe search needs a server, a chain or direct as the config — not a group, nor the router’s balancer — left out`);
  return out;
}

/** The direct outbound tag of a user. */
const directTagOf = (userId) => DIRECT_PREFIX + userId;

/** The module is installed and there is something for it to do: the users' proxy on, or the router's transparent inbounds. */
function applies(settings) {
  const s = settings || {};
  if (!(s.modules && s.modules.lanUsers) || !isObj(s.lanUsers)) return false;
  return normalizeConfig(s.lanUsers.config).proxy.enabled || tpOf(s.lanUsers).length > 0;
}

/** The address the users' proxy binds: '0.0.0.0' when the input names none, '' when it names none usable. */
function listenOf(lu) {
  if (!isObj(lu) || lu.listen === undefined) return '0.0.0.0';
  return typeof lu.listen === 'string' && net.isIP(lu.listen) ? lu.listen : '';
}

/** The router's transparent inbounds, each of a shape that can be written: [{ tag, port, target, userId? }]. */
function tpOf(lu) {
  const out = [];
  const tags = new Set();
  for (const e of isObj(lu) && Array.isArray(lu.tp) ? lu.tp : []) {
    if (!isObj(e)) continue;
    const tag = typeof e.tag === 'string' ? e.tag : (e.n != null ? TP_PREFIX + e.n : '');
    const port = portOf(e.port);
    const target = e.target == null ? '' : e.target;
    if (!/^lu-tp-[\w-]+$/.test(tag) || tags.has(tag) || !port || !targetOk(target)) continue;
    tags.add(tag);
    out.push(Object.assign({ tag, port, target }, typeof e.userId === 'string' && ID.test(e.userId) ? { userId: e.userId } : {}));
  }
  return out;
}

/** Who may use the proxy in this build (model.activeUsers at the input's moment, less the ones held off entirely). */
function activeOf(lu) {
  const now = isObj(lu) && typeof lu.now === 'number' ? lu.now : Date.now();
  return activeUsers(lu, { now, over: isObj(lu) ? lu.over : null, usage: isObj(lu) ? lu.usage : null });
}

/** The users whose rules this build writes: the active ones (proxy on, an address to bind), then the transparent inbounds' — each once. */
function routedUsers(lu) {
  const n = normalizeLanUsers(lu);
  const out = [];
  if (n.config.proxy.enabled && listenOf(lu)) out.push(...activeOf(lu));
  for (const e of tpOf(lu)) {
    const u = e.userId ? n.users.find((x) => x.id === e.userId) : null;
    if (u && !out.some((x) => x.id === u.id)) out.push(u);
  }
  return out;
}

/** A user's partial hold in the build input: 'vpn' | 'direct' | null. */
function holdOf(lu, id) {
  const h = isObj(lu) && isObj(lu.holds) ? lu.holds[id] : null;
  const v = isObj(h) ? h.hold : h;
  return v === 'vpn' || v === 'direct' ? v : null;
}

/** The profile a user's routing names in this build, or null (none named, or gone). */
function profileOf(lu, u) {
  const id = profileIdOf(u && u.routing);
  const p = id && isObj(lu) && isObj(lu.profilesById) ? lu.profilesById[id] : null;
  return isObj(p) ? p : null;
}

/** A profile rule's value as a list: an array as it is, a string split at `|` and `,`. */
function splitValues(v) {
  if (Array.isArray(v)) return v.map((x) => String(x).trim()).filter(Boolean);
  return String(v == null ? '' : v).split(SEPARATORS).map((x) => x.trim()).filter(Boolean);
}

/**
 * The fields a profile rule matches on — { domain } | { ip } | { port } — or
 * null: a geo name without the geo files (the core would refuse the whole
 * config), a process rule (this machine's own programs, never a LAN user's),
 * a type the core has not.
 */
function profileCondition(r, geo) {
  const vals = splitValues(r.value);
  if (r.type === 'domain') { const d = geo ? vals : vals.filter((v) => !/^geosite:/i.test(v)); return d.length ? { domain: d } : null; }
  if (r.type === 'ip') { const ip = geo ? vals : vals.filter((v) => !/^geoip:/i.test(v)); return ip.length ? { ip } : null; }
  if (r.type === 'port') return vals.length ? { port: vals.join(',') } : null;
  return null;
}

/** A profile rule's target, "exit at the base" as the profile's base (routingProfiles.resolveBaseTargets); null when it names nothing. */
function ruleTarget(r, profile) {
  const t = r.target === TARGET_BASE ? profile.base : r.target;
  return typeof t === 'string' && t && t !== TARGET_BASE && targetOk(t) ? t : null;
}

/** The targets a profile's rules name — server, group or chain, each once: what the build must reach for the users riding it. */
function profileTargets(profile) {
  const out = [];
  if (!isObj(profile)) return out;
  for (const r of Array.isArray(profile.rules) ? profile.rules : []) {
    const t = isObj(r) ? ruleTarget(r, profile) : null;
    if (t && t !== 'direct' && t !== 'block' && !out.includes(t)) out.push(t);
  }
  return out;
}

/** The rule fields of the platform's that a user's copy keeps: everything it matches on, none of where or whom. */
const NOT_CONDITION = new Set(['type', 'outboundTag', 'balancerTag', 'ruleTag']);

/**
 * One user's rules, in order: their routing's, then the catch-all — every one
 * scoped by `match` — with the hold applied. Shared by the desktop's accounts
 * (applyLanUsers) and the router's transparent inbounds (router/xrayTargets).
 *
 *   user        the user (model.js) — their target 'direct' sends the catch-all to `directTag` too
 *   routing     their routing (default: user.routing):
 *                 '' / 'global'  everything to the target — and `baseDirect`, the rules the
 *                                platform already sends direct for everyone (the router's own:
 *                                private ranges, its routing mode, advanced routing's direct
 *                                ones), repeated for this user to `directTag` so their bytes are
 *                                counted as theirs ([] on the desktop: there the owner's rules
 *                                never apply to a user);
 *                 'bypass-ir'    private ranges, and with the geo files geosite:category-ir +
 *                                regexp:.*\.ir$ and geoip:ir, to `directTag`; the rest to the target;
 *                 'profile:<id>' the profile's rules in order (profilesById[id]) — 'direct' to
 *                                `directTag`, 'block' to block, anything else to tagFor(target)
 *                                (null: the target is gone — the rule is left out and its
 *                                traffic follows the catch-all, as the app's own routing does);
 *                                its default and every via are not used — the user's target is
 *                                the default. A profile not in profilesById is '' (the caller
 *                                says so in the log).
 *   geo         the geo files are there (false: no geosite: / geoip: name is written)
 *   match       the fields that scope a rule to this user — { inboundTag: [...], user: [name] }
 *               for an account, { inboundTag: [tag] } for a transparent inbound
 *   directTag   the user's own direct outbound (default lu-d-<id>)
 *   targetTag   the outbound of the user's target (the catch-all's)
 *   hold        'vpn': every rule to anything but `directTag` (and block) is blocked;
 *               'direct': every rule to `directTag` is blocked; else none —
 *               a safe-search outbound counts as the class the catch-all rides
 *   filter      the user's content filter (filterOf's shape; default filterOf(user)):
 *               its rules come FIRST — the custom domains → block, the categories
 *               (with the geo files) → block, then with safeSearch the engines'
 *               hosts on UDP 443 → block and on TCP 443 → `safeSearchTag(engine)`,
 *               the outbound the caller made (null: that engine is left out)
 * → [rule]; the last one is always the catch-all, so a caller that places the
 * user's routing and their catch-all apart (the router) can.
 */
function userRouteRules(o) {
  const a = isObj(o) ? o : {};
  const u = isObj(a.user) ? a.user : {};
  const match = isObj(a.match) ? a.match : {};
  const directTag = typeof a.directTag === 'string' && a.directTag ? a.directTag : directTagOf(u.id);
  const geo = a.geo === true;
  const routing = routingOf(a.routing != null ? a.routing : u.routing);
  const pid = profileIdOf(routing);
  const profile = pid && isObj(a.profilesById) && isObj(a.profilesById[pid]) ? a.profilesById[pid] : null;
  const rule = (cond, outboundTag) => Object.assign({ type: 'field' }, clone(match), cond, { outboundTag });
  const rules = [];
  // the filter first: a block wins over every route of theirs, the redirect over their catch-all
  const filter = a.filter === undefined ? filterOf(u) : (isObj(a.filter) ? a.filter : null);
  const ssTags = new Set();
  if (filter) {
    if (filter.domains.length) rules.push(rule({ domain: filter.domains.map(domainRule) }, 'block'));
    const sites = geo ? filter.block.map((k) => FILTER_GEOSITE[k]).filter(Boolean) : [];
    if (sites.length) rules.push(rule({ domain: sites }, 'block'));
    if (filter.safeSearch && typeof a.safeSearchTag === 'function') {
      const made = SAFE_SEARCH.map((e) => [e, a.safeSearchTag(e.key)]).filter(([, t]) => typeof t === 'string' && t);
      if (made.length) {
        rules.push(rule({ domain: made.flatMap(([e]) => e.domains.slice()), port: '443', network: 'udp' }, 'block'));
        for (const [e, t] of made) { rules.push(rule({ domain: e.domains.slice(), port: '443', network: 'tcp' }, t)); ssTags.add(t); }
      }
    }
  }
  if (routing === 'bypass-ir') {
    rules.push(rule({ ip: PRIVATE_IPS.slice() }, directTag));
    if (geo) {
      rules.push(rule({ domain: IR_DOMAINS.slice() }, directTag));
      rules.push(rule({ ip: IR_IPS.slice() }, directTag));
    }
  } else if (profile) {
    for (const r of Array.isArray(profile.rules) ? profile.rules : []) {
      if (!isObj(r)) continue;
      const cond = profileCondition(r, geo);
      const target = ruleTarget(r, profile);
      if (!cond || !target) continue;
      const tag = target === 'direct' ? directTag : (target === 'block' ? 'block' : (typeof a.tagFor === 'function' ? a.tagFor(target) : null));
      if (tag) rules.push(rule(cond, tag));
    }
  } else {
    for (const b of Array.isArray(a.baseDirect) ? a.baseDirect : []) {
      // a rule of another inbound's or another user's (the DNS ones, an account's) is not this user's
      if (!isObj(b) || b.balancerTag || (Array.isArray(b.inboundTag) && b.inboundTag.length) || b.user) continue;
      const cond = {};
      for (const [k, v] of Object.entries(b)) if (!NOT_CONDITION.has(k) && k !== 'inboundTag') cond[k] = clone(v);
      if (Object.keys(cond).length) rules.push(rule(cond, directTag));
    }
  }
  const targetTag = typeof a.targetTag === 'string' && a.targetTag ? a.targetTag : 'block';
  const catchTag = u.target === 'direct' || targetTag === 'direct' ? directTag : targetTag;
  rules.push(rule({}, catchTag));
  // a safe-search outbound rides what the catch-all rides: held with that class
  const ridesDirect = (tag) => tag === directTag || (catchTag === directTag && ssTags.has(tag));
  if (a.hold === 'vpn') for (const r of rules) { if (!ridesDirect(r.outboundTag)) r.outboundTag = 'block'; }
  if (a.hold === 'direct') for (const r of rules) { if (ridesDirect(r.outboundTag)) r.outboundTag = 'block'; }
  return rules;
}

/**
 * Every target this build has to reach: the active users' (when the proxy is
 * on) and the transparent inbounds', and every target a profile they ride
 * names — each once.
 */
function neededTargets(lu) {
  const out = [];
  const put = (t) => { if (!out.includes(t)) out.push(t); };
  const n = normalizeLanUsers(lu);
  if (n.config.proxy.enabled && listenOf(lu)) for (const u of activeOf(lu)) put(u.target);
  for (const e of tpOf(lu)) put(e.target);
  for (const u of routedUsers(lu)) profileTargets(profileOf(lu, u)).forEach(put);
  return out;
}

/**
 * The outbounds the users' targets need, and the tag each target is routed to:
 * → { outbounds, tags: { [target]: tag } }. Raw, as the plan's own are before
 * the builder's passes — the caller puts them beside those.
 *
 * `ctx` (configBuilder makes it): { exitTag, serversById, chainsById,
 *   existingTag(target), server(record, tag), chain(records, tag), unsafe(record),
 *   direct (the plan's own `direct` outbound, before any pass) }
 * — src/main/targetOutbounds.js says what each is for, and what each target
 * becomes: '' the plan's exit, 'direct' / 'block' those, the server, chain or
 * group the plan already dials as that very target its outbound (shared: a
 * WireGuard dialled twice is two sessions on one key), else its own
 * `lu-out-<id>` (`lu-out-chain-<cid>` for a chain); a target that is gone, a
 * chain that lost a member, an unsafe one 'block'. A user's traffic is never
 * sent out unprotected because their config disappeared. And for every user
 * whose rules the build writes, their own direct outbound (`lu-d-<id>`): a copy
 * of `ctx.direct`.
 */
function lanUsersOutbounds(lu, ctx) {
  const r = targetOutbounds(neededTargets(lu), ctx, OUT_PREFIX);
  const base = ctx && isObj(ctx.direct) ? ctx.direct : null;
  for (const u of routedUsers(lu)) r.outbounds.push(Object.assign(base ? clone(base) : { protocol: 'freedom', settings: {} }, { tag: directTagOf(u.id) }));
  return r;
}

/** The ports a config already holds: its inbounds', and the metrics and control API listeners'. */
function portsOf(config) {
  const used = new Set();
  for (const i of Array.isArray(config.inbounds) ? config.inbounds : []) { const p = portOf(i && i.port); if (p) used.add(p); }
  for (const k of ['metrics', 'api']) {
    const m = isObj(config[k]) && typeof config[k].listen === 'string' ? /:(\d+)$/.exec(config[k].listen) : null;
    if (m) used.add(Number(m[1]));
  }
  return used;
}

/** A target's tag when the caller did not resolve it (a config made outside configBuilder): what the config has for it, else block. */
function fallbackTag(target, config, c) {
  const have = new Set((Array.isArray(config.outbounds) ? config.outbounds : []).map((o) => o && o.tag));
  if (!target) return c.exitTag || (have.has('proxy') ? 'proxy' : 'direct');
  if (target === 'direct' || target === 'block') return target;
  const id = target.indexOf('chain:') === 0 ? 'chain-' + target.slice('chain:'.length) : target;
  return [OUT_PREFIX + id, 'out-' + id].find((t) => have.has(t)) || 'block';
}

/**
 * A user's direct outbound in a config made outside configBuilder (no
 * lanUsersOutbounds): a copy of the config's own `direct` as it stands — bound
 * as it is bound — so a rule never names an outbound the config has not.
 */
function ensureDirect(config, tag) {
  const outs = Array.isArray(config.outbounds) ? config.outbounds : (config.outbounds = []);
  if (outs.some((o) => o && o.tag === tag)) return;
  const d = outs.find((o) => o && o.tag === 'direct');
  outs.push(Object.assign(d ? clone(d) : { protocol: 'freedom', settings: {} }, { tag }));
}

/**
 * The users' inbounds and rules into a built config (mutated, and returned).
 * `ctx`: { tags (lanUsersOutbounds'), ruleAt (where the rules go: after the
 * groups' loopback rules and the DNS rules, so a user's port-53 query is
 * answered by the app's own resolver like everyone's — the in-country DNS
 * never sees it), sniffing, exitTag, geo (the builder's: the geo files are
 * there) }.
 *
 * The inbounds listen on the LAN (listenOf): `lu-socks` (SOCKS5, password,
 * UDP) and `lu-http`, both with every active user's account — disabled,
 * expired, out-of-hours and held users are simply not in them, so the core
 * refuses them like a wrong password. None at all when no one is active (see
 * the header). A port another inbound, the metrics or the control API holds is
 * left out — the core would refuse to start over it, taking the owner's
 * connection with it.
 *
 * The rules, ahead of the plan's own: this machine's loopback blocked for
 * anyone coming in on them; each user's (userRouteRules: that inbound and that
 * username, their routing, then their target, their hold applied); whatever is
 * left on them (nothing should be) blocked. So a user's traffic is decided by
 * their own routing and target alone — the owner's advanced rules (a corporate
 * WireGuard for a domain, say) never apply to it. Then each transparent
 * inbound (`lu-tp-<n>`, loopback only: sing-box hands it the devices'
 * traffic) → its user's rules, or its target.
 */
function applyLanUsers(config, lu, ctx) {
  if (!isObj(config) || !isObj(lu)) return config;
  const c = ctx || {};
  const n = normalizeLanUsers(lu);
  const tags = isObj(c.tags) ? c.tags : {};
  const tagOf = (t) => (Object.prototype.hasOwnProperty.call(tags, t) ? tags[t] : fallbackTag(t, config, c));
  const geo = c.geo === false ? false : (typeof lu.geo === 'boolean' ? lu.geo : true);
  const profilesById = isObj(lu.profilesById) ? lu.profilesById : {};
  const records = { serversById: isObj(lu.serversById) ? lu.serversById : {}, chainsById: isObj(lu.chainsById) ? lu.chainsById : {} };
  // a profile's target that is gone: its rule is left out (the user's target carries it); one that cannot be dialled safely: block
  const tagFor = (t) => { const tag = tagOf(t); return tag === 'block' && targetGone(t, records) ? null : tag; };
  const notes = [];
  // a filtered user's safe-search outbounds into the config (once each) → { [engine]: tag }: through the outbound
  // their catch-all rides, or a copy of their own direct outbound (already there, bound as direct is) when that is direct
  const safeFor = (u, f, target) => {
    if (!f || !f.safeSearch) return {};
    const tt = tagOf(target);
    const direct = u.target === 'direct' || tt === 'direct' ? config.outbounds.find((o) => o && o.tag === directTagOf(u.id)) : null;
    const made = safeSearchOutbounds(u, direct ? { direct } : { via: safeSearchVia(config, tt) });
    for (const o of made.outbounds) if (!config.outbounds.some((x) => x && x.tag === o.tag)) config.outbounds.push(o);
    return made.tags;
  };
  const rulesOf = (u, match, target) => {
    ensureDirect(config, directTagOf(u.id));
    const f = filterFor(lu, u);
    const ssTags = safeFor(u, f, target);
    for (const line of filterNotes(u, f, { geo, safe: Object.keys(ssTags).length > 0 })) if (!notes.includes(line)) notes.push(line);
    return userRouteRules({
      user: u, filter: f, safeSearchTag: (k) => ssTags[k] || null, profilesById, geo, match,
      directTag: directTagOf(u.id), targetTag: tagOf(target), hold: holdOf(lu, u.id), tagFor, baseDirect: []
    });
  };
  const sniffing = c.sniffing || { enabled: false };
  const used = portsOf(config);
  const take = (port) => { if (!port || used.has(port)) return false; used.add(port); return true; };
  const inbounds = [];
  const guarded = [];
  const userRules = [];
  const tail = [];

  const listen = listenOf(lu);
  const active = activeOf(lu);
  if (n.config.proxy.enabled && active.length && listen) {
    const accounts = () => active.map((u) => ({ user: u.username, pass: u.password }));
    const ins = [];
    if (take(n.config.proxy.port)) {
      inbounds.push({ tag: SOCKS_TAG, port: n.config.proxy.port, listen, protocol: 'socks', settings: { auth: 'password', accounts: accounts(), udp: true }, sniffing });
      ins.push(SOCKS_TAG);
    }
    if (n.config.proxy.httpPort && take(n.config.proxy.httpPort)) {
      inbounds.push({ tag: HTTP_TAG, port: n.config.proxy.httpPort, listen, protocol: 'http', settings: { accounts: accounts(), allowTransparent: false }, sniffing });
      ins.push(HTTP_TAG);
    }
    if (ins.length) {
      guarded.push(...ins);
      for (const u of active) userRules.push(...rulesOf(u, { inboundTag: ins.slice(), user: [u.username] }, u.target));
      tail.push({ type: 'field', inboundTag: ins.slice(), outboundTag: 'block' });
      // a filtered account's names must be seen: the shared inbounds sniff (routeOnly) if they did not
      if (active.some((u) => filterFor(lu, u))) for (const i of inbounds) if (ins.includes(i.tag)) ensureSniffing(i);
    }
  }
  for (const e of tpOf(lu)) {
    if (!take(e.port)) continue;
    const ib = loopbackSocksInbound(e.tag, e.port, sniffing);
    inbounds.push(ib);
    guarded.push(e.tag);
    const u = e.userId ? n.users.find((x) => x.id === e.userId) : null;
    if (u) {
      userRules.push(...rulesOf(u, { inboundTag: [e.tag] }, e.target));
      if (filterFor(lu, u)) ensureSniffing(ib);
    } else userRules.push({ type: 'field', inboundTag: [e.tag], outboundTag: tagOf(e.target) });
  }
  // what the filters could not do: for the caller's log, never into the file the core reads
  Object.defineProperty(config, 'lanUsersNotes', { value: notes, enumerable: false, configurable: true, writable: true });
  if (typeof c.log === 'function') for (const line of notes) c.log(line, 'warn');
  if (!inbounds.length) return config;

  const rules = [
    { type: 'field', inboundTag: guarded.slice(), ip: LOOPBACK_IPS.slice(), outboundTag: 'block' },
    { type: 'field', inboundTag: guarded.slice(), domain: LOOPBACK_NAMES.slice(), outboundTag: 'block' },
    ...userRules,
    ...tail
  ];
  config.inbounds = (Array.isArray(config.inbounds) ? config.inbounds : []).concat(inbounds);
  if (!isObj(config.routing)) config.routing = { rules: [] };
  if (!Array.isArray(config.routing.rules)) config.routing.rules = [];
  const at = Math.max(0, Math.min(Number.isInteger(c.ruleAt) ? c.ruleAt : 0, config.routing.rules.length));
  config.routing.rules.splice(at, 0, ...rules);
  // the per-user counters (configBuilder's level 0 has them on already; a config from elsewhere may not)
  if (!isObj(config.policy)) config.policy = {};
  if (!isObj(config.policy.levels)) config.policy.levels = {};
  config.policy.levels['0'] = Object.assign({}, config.policy.levels['0'], { statsUserUplink: true, statsUserDownlink: true });
  // …and the per-outbound ones: a user's direct bytes are their lu-d-<id>'s
  config.policy.system = Object.assign({}, config.policy.system, { statsOutboundUplink: true, statsOutboundDownlink: true });
  if (!isObj(config.stats)) config.stats = {};
  return config;
}

module.exports = {
  SOCKS_TAG, HTTP_TAG, OUT_PREFIX, TP_PREFIX, DIRECT_PREFIX, LOOPBACK_IPS, LOOPBACK_NAMES, PRIVATE_IPS, IR_DOMAINS, IR_IPS,
  FILTER_CATEGORIES, FILTER_GEOSITE, FILTER_DOMAINS_MAX, SS_PREFIX, SAFE_SEARCH,
  applies, listenOf, tpOf, activeOf, routedUsers, neededTargets, lanUsersOutbounds, applyLanUsers,
  userRouteRules, profileTargets, directTagOf,
  filterOf, filterFor, filterDomainOf, domainRule, safeSearchVia, safeSearchOutbounds, ensureSniffing, filterNotes
};
