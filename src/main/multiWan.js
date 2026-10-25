'use strict';
/**
 * Multi-internet («ترکیب اینترنت‌ها», v1.32.0): two or more connected
 * internets used together — one with good upload and one with good download,
 * say — for speed and for staying up when one drops.
 *
 * Every outbound's `streamSettings.sockopt.interface` binds its sockets to one
 * NIC (Windows IP_UNICAST_IF, macOS IP_BOUND_IF, Linux SO_BINDTODEVICE — the
 * very field bindDirectDials uses under TUN), so a server dialled once per
 * link is a server reachable over each of them. What this module writes on
 * top of that is an ordinary group (groups.js, configBuilder.expandGroups):
 *  - balance: a copy of the server per 'use' link — `weight` copies, so the
 *    round robin hands a link a share of the new connections; a 'backup' link
 *    is the group's fallback, taken only when no 'use' link answers;
 *  - failover: the first link alone, the next one as the fallback;
 *  - split: an XHTTP server uploads on one link and downloads on the other
 *    (xhttpSettings.extra.downloadSettings, a full stream config with its own
 *    sockopt: the core keys a session by its id, never the source address).
 * One flow is never faster than its own link — the server sees two clients,
 * not one fat pipe; the gain is many connections spread over both, and a
 * link that drops costing only the connections that were on it.
 *
 * Settings (`settings.multiWan`, persisted; normalizeMultiWan):
 *   { enabled, mode: 'balance'|'failover'|'split',
 *     links: [{ id, iface, name, role: 'use'|'backup'|'off', weight: 1..3, quotaGb, quotaPeriod: 'day'|'month'|'none' }],
 *     split: { up: <link id>, down: <link id> } }
 * `settings.multiWanSkip` (runtime only): the ids of the links over their cap,
 * left out of the build.
 *
 * What is never touched: a chain's hops (a TCP hop must never dial a
 * loopback — groups-round fact 2 — so a chain plan stays as it was), anything
 * that dials through another outbound, a member or helper (`~` in its tag),
 * an outbound that names its own interface, and every WireGuard: one key is
 * one session, and the peer keeps only the newest handshake — a copy per link
 * (or per weight) would cut the others off, and the group's health probe
 * through a split-tunnel corporate WireGuard never answers, so it would flap.
 * A WireGuard keeps dialling by the system's default route, which the OS
 * itself moves to the link still up.
 *
 * Pure: no store, no electron — main.js and the router's service.js both use it.
 */

const MODES = ['balance', 'failover', 'split'];
const ROLES = ['use', 'backup', 'off'];
const PERIODS = ['day', 'month', 'none'];
const WEIGHT_MIN = 1, WEIGHT_MAX = 3, WEIGHT_DEFAULT = 2;

/** The protocols a link can carry a copy of. Not WireGuard (see above), not freedom/blackhole/dns/loopback. */
const LINKABLE = new Set(['vless', 'vmess', 'trojan', 'shadowsocks', 'socks', 'http', 'hysteria', 'masque']);

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const str = (v) => (v == null ? '' : String(v).trim());
const clone = (v) => JSON.parse(JSON.stringify(v));

/* --------------------------------- settings --------------------------------- */

/** A link as it is saved; null when it names no interface. */
function normalizeLink(raw) {
  if (!isObj(raw)) return null;
  // the id IS the interface's name — what the OS calls the adapter
  const id = str(raw.id) || str(raw.iface);
  if (!id) return null;
  const w = Math.round(Number(raw.weight));
  const q = Number(raw.quotaGb);
  return {
    id,
    iface: str(raw.iface) || id,
    name: str(raw.name) || str(raw.iface) || id,
    role: ROLES.includes(raw.role) ? raw.role : 'use',
    weight: Number.isFinite(w) ? Math.min(WEIGHT_MAX, Math.max(WEIGHT_MIN, w)) : WEIGHT_DEFAULT,
    quotaGb: Number.isFinite(q) && q > 0 ? q : 0,
    quotaPeriod: PERIODS.includes(raw.quotaPeriod) ? raw.quotaPeriod : 'none'
  };
}

/** The settings, always the full shape: junk dropped, a repeated link id dropped (the first wins). */
function normalizeMultiWan(raw) {
  const r = isObj(raw) ? raw : {};
  const seen = new Set();
  const links = [];
  for (const l of Array.isArray(r.links) ? r.links : []) {
    const n = normalizeLink(l);
    if (!n || seen.has(n.id)) continue;
    seen.add(n.id);
    links.push(n);
  }
  const sp = isObj(r.split) ? r.split : {};
  return {
    enabled: r.enabled === true,
    mode: MODES.includes(r.mode) ? r.mode : 'balance',
    links,
    split: { up: str(sp.up), down: str(sp.down) }
  };
}

/** `skip` (settings.multiWanSkip) as a set of link ids, whatever it came as. */
function skipSet(skip) {
  if (skip instanceof Set) return skip;
  return new Set((Array.isArray(skip) ? skip : []).map(str).filter(Boolean));
}

/** The links a build may use: not off, an interface to bind, not set aside for its cap — in the order configured. */
function usableLinks(mw, skip) {
  const out = skipSet(skip);
  return normalizeMultiWan(mw).links.filter((l) => l.role !== 'off' && l.iface && !out.has(l.id));
}

/**
 * What a build does with the links, or null when it leaves the config alone:
 * { mode, usable, up?, down? }. Balance and failover want two links, split an
 * up and a down that are both there and not the same one.
 *
 * One more case keeps the cap honest: a link set aside for its cap while one
 * link is left. Left alone, the config would dial by the default route — the
 * capped link, as likely as not — so the build balances over what is left
 * instead (one link: a group of one), and the capped one carries none of the
 * proxied traffic. A split whose up or down is capped does the same.
 */
function planOf(mw, skip) {
  const n = normalizeMultiWan(mw);
  if (!n.enabled) return null;
  const usable = usableLinks(n, skip);
  if (n.mode === 'split') {
    const up = usable.find((l) => l.id === n.split.up);
    const down = usable.find((l) => l.id === n.split.down);
    if (up && down && up.id !== down.id) return { mode: 'split', usable, up, down };
  } else if (usable.length >= 2) {
    return { mode: n.mode, usable };
  }
  const out = skipSet(skip);
  const capped = n.links.some((l) => l.role !== 'off' && l.iface && out.has(l.id));
  return capped && usable.length ? { mode: 'balance', usable } : null;
}

/** Does multi-internet change this build? (configBuilder calls applyMultiWan only then.) */
function applies(mw, skip) {
  return planOf(mw, skip) !== null;
}

/* ------------------------------ which outbounds ------------------------------ */

/** The tag an outbound dials through: its dialerProxy, else (a JSON config's older form) its proxySettings.tag. */
function dialsThrough(o) {
  const so = o && o.streamSettings && o.streamSettings.sockopt;
  if (so && so.dialerProxy) return String(so.dialerProxy);
  return o && o.proxySettings && o.proxySettings.tag ? String(o.proxySettings.tag) : '';
}

/** An outbound a link can carry a copy of: a proxy that dials by itself and names no interface of its own. */
function linkable(o) {
  if (!isObj(o) || !LINKABLE.has(o.protocol) || dialsThrough(o)) return false;
  const so = o.streamSettings && o.streamSettings.sockopt;
  return !(so && so.interface);
}

/** Every tag some outbound dials through — a chain's hops, a base, a JSON server's helpers. */
function dialedTags(outbounds) {
  const out = new Set();
  for (const o of outbounds) { const via = dialsThrough(o); if (via) out.add(via); }
  return out;
}

const isGroupLoopback = (o) => isObj(o) && o.protocol === 'loopback' && isObj(o._group);

/** Where an outbound dials: { address, port } of vnext[0] / servers[0] / the flat settings. */
function dialTarget(o) {
  const st = (o && o.settings) || {};
  const first = (l) => (Array.isArray(l) && isObj(l[0]) ? l[0] : null);
  const s = first(st.vnext) || first(st.servers) || (typeof st.address === 'string' ? st : null);
  const port = s ? Number(s.port) : 0;
  return { address: s ? str(s.address) : '', port: Number.isInteger(port) && port > 0 && port <= 65535 ? port : 0 };
}

/* --------------------------------- the copies --------------------------------- */

/** `outbound` as a link carries it: a copy whose sockets are bound to the link's interface. */
function onLink(outbound, link) {
  const o = clone(outbound);
  delete o.tag;
  const ss = isObj(o.streamSettings) ? o.streamSettings : (o.streamSettings = {});
  ss.sockopt = Object.assign({}, ss.sockopt, { interface: link.iface });
  return o;
}

/**
 * A member record (what expandGroups dials as `T~gm<i>`) for `rec` on `link`:
 * `<id>#<link id>` — copies of one link share it, so whatever sets a member
 * aside sets the whole link aside together, and linkOfMemberId reads the link
 * back — named "<server> · <link>". The certificate pin travels with it
 * (expandGroups applies it as it does for every member).
 */
function memberOn(rec, link) {
  return Object.assign({
    id: rec.id + '#' + link.id,
    name: rec.name + ' · ' + link.name,
    address: rec.address,
    port: rec.port,
    outbound: onLink(rec.outbound, link)
  }, rec.certPin ? { certPin: rec.certPin } : {});
}

/**
 * The links of one group, in the order its members are written:
 * { members: [link…] (a link repeated `weight` times, interleaved), fallback: link | null }.
 * `split`: the up and the down, both used (a server that cannot split is balanced over the two).
 */
function linkSpec(p) {
  const uses = p.mode === 'split' ? [p.up, p.down] : p.usable.filter((l) => l.role === 'use');
  const backups = p.mode === 'split' ? [] : p.usable.filter((l) => l.role === 'backup');
  if (p.mode === 'failover') {
    const order = uses.concat(backups);
    return { members: [order[0]], fallback: order[1] || null };
  }
  if (!uses.length) return { members: [backups[0]], fallback: backups[1] || null };
  // interleaved, so a 2:1 share is A B A rather than A A B: the next few connections already spread
  const members = [];
  const most = Math.max(...uses.map((l) => l.weight));
  for (let r = 0; r < most; r++) for (const l of uses) if (l.weight > r) members.push(l);
  return { members, fallback: backups[0] || null };
}

/* ------------------------------------ split ------------------------------------ */

/**
 * An XHTTP outbound's stream: { ss, xs } (xs the object its settings key
 * holds — written in when `create` and it has none); null for any other transport.
 */
function xhttpOf(o, create) {
  const ss = o && o.streamSettings;
  if (!isObj(ss) || !['xhttp', 'splithttp'].includes(String(ss.network || '').toLowerCase())) return null;
  const key = isObj(ss.xhttpSettings) || !isObj(ss.splithttpSettings) ? 'xhttpSettings' : 'splithttpSettings';
  if (!isObj(ss[key])) {
    if (!create) return { ss, xs: {} };
    ss[key] = {};
  }
  return { ss, xs: ss[key] };
}

/** The download settings an XHTTP stream already has: `extra`'s — the only ones the core reads once `extra` exists. */
function ownDownload(xs) {
  if (isObj(xs.extra)) return isObj(xs.extra.downloadSettings) ? xs.extra.downloadSettings : null;
  return isObj(xs.downloadSettings) ? xs.downloadSettings : null;
}

/**
 * Can this outbound upload on one link and download on another? XHTTP in any
 * mode but `stream-one` (the one mode that refuses a separate download; `auto`
 * becomes packet-up with TLS and stream-up with REALITY once there is one),
 * with a server to dial the download at — its own downloadSettings, or the
 * address it dials itself.
 */
function splittable(o) {
  const x = xhttpOf(o);
  if (!x || String(x.xs.mode || 'auto') === 'stream-one') return false;
  return !!ownDownload(x.xs) || !!dialTarget(o).address;
}

/** TLS for a download leg the app writes: the upload's own, less the ECH outbound (the app's key, never the core's). */
function legTls(tls, down) {
  const t = clone(tls);
  delete t.echOutbound;
  // an ECH config asked of DNS: asked over the leg's own link
  if (String(t.echConfigList || '').includes('://') && !(isObj(t.echSockopt) && t.echSockopt.dialerProxy)) {
    t.echSockopt = Object.assign({}, t.echSockopt, { interface: down.iface });
  }
  return t;
}

/**
 * `o` (a copy is made) uploading on `up` and downloading on `down`: its own
 * sockets bound to the up link; `extra.downloadSettings` — its own, or one
 * written here for the same server (address, port, the same security and the
 * path and Host) — bound to the down link. Without an `extra` the stream's
 * other keys move into one: once `extra` exists the core reads every key from
 * it but host, path and mode. Marked `_mwSplit` for finishSplit.
 */
function splitOut(o, up, down) {
  const c = clone(o);
  const { ss, xs } = xhttpOf(c, true);
  ss.sockopt = Object.assign({}, ss.sockopt, { interface: up.iface });
  if (!isObj(xs.extra)) {
    const extra = {};
    for (const k of Object.keys(xs)) if (!['host', 'path', 'mode', 'extra'].includes(k)) { extra[k] = xs[k]; delete xs[k]; }
    xs.extra = extra;
  }
  const built = !isObj(xs.extra.downloadSettings);
  let ds = xs.extra.downloadSettings;
  if (built) {
    const t = dialTarget(c);
    const sec = str(ss.security) || 'none';
    ds = { address: t.address, port: t.port, network: 'xhttp', security: sec };
    if (sec === 'tls' && isObj(ss.tlsSettings)) ds.tlsSettings = legTls(ss.tlsSettings, down);
    if (sec === 'reality' && isObj(ss.realitySettings)) ds.realitySettings = clone(ss.realitySettings);
    ds.xhttpSettings = { path: xs.path || '/', host: xs.host || '' };
  }
  ds.sockopt = Object.assign({}, ds.sockopt, { interface: down.iface });
  xs.extra.downloadSettings = ds;
  c._mwSplit = { up: up.id, down: down.id, built };
  return c;
}

/**
 * After pinEntryHosts, before the dialers (configBuilder): every outbound
 * splitOut marked — the marker taken off (never the core's), and a download
 * leg the app wrote for the same server given the strategy its upload was
 * pinned with, so its name is answered from dns.hosts too and never asked of
 * the OS (under TUN that is the tunnel, waiting on this very server).
 * → [{ tag, up, down }] (the link ids), or null: what linkUsage needs to
 * count a split's bytes by link (its uplink on `up`, its downlink on `down`).
 */
function finishSplit(outbounds) {
  const out = [];
  for (const o of outbounds || []) {
    const mark = o && o._mwSplit;
    if (!mark) continue;
    delete o._mwSplit;
    out.push({ tag: o.tag, up: mark.up, down: mark.down });
    if (!mark.built) continue;
    const so = o.streamSettings && o.streamSettings.sockopt;
    const x = xhttpOf(o);
    const ds = x && isObj(x.xs.extra) && x.xs.extra.downloadSettings;
    if (ds && so && so.domainStrategy && !(ds.sockopt && ds.sockopt.domainStrategy)) {
      ds.sockopt = Object.assign({}, ds.sockopt, { domainStrategy: so.domainStrategy });
    }
  }
  return out.length ? out : null;
}

/* ----------------------------------- the build ----------------------------------- */

/** One server's outbound `o` (tagged T, from the record `rec` when the plan has it) over the links. */
function serverOnLinks(o, rec, p) {
  if (p.mode === 'split' && splittable(o)) return splitOut(o, p.up, p.down);
  const T = o.tag;
  const t = dialTarget(o);
  const me = {
    id: str(rec && rec.id) || T,
    name: str(rec && rec.name) || T,
    address: str(rec && rec.address) || t.address,
    port: Number(rec && rec.port) || t.port,
    outbound: o
  };
  const spec = linkSpec(p);
  return {
    tag: T, protocol: 'loopback', settings: {},
    _group: {
      id: 'mw:' + T, name: me.name, strategy: 'roundRobin',
      members: spec.members.map((l) => memberOn(me, l)),
      fallback: spec.fallback ? memberOn(me, spec.fallback) : null
    }
  };
}

/** A member record a link can carry: a server that dials by itself (not a chain variant, not a WireGuard). */
const linkableMember = (m) => isObj(m) && !Array.isArray(m.chain) && linkable(m.outbound);

/** A member record as memberOn takes it: its id, a name, the address it dials. */
function memberBase(m) {
  const t = dialTarget(m.outbound);
  return Object.assign({
    id: str(m.id), name: str(m.name) || str(m.id), address: str(m.address) || t.address, port: Number(m.port) || t.port, outbound: m.outbound
  }, m.certPin ? { certPin: m.certPin } : {});
}

/** configBuilder.groupMemberKey's form (that module requires this one): a member as the app sets it aside. */
const memberKey = (groupId, m) => [groupId || '', (m && m.id) || '', (m && m.address) || '', (m && m.port) || 0].join('|');

/**
 * A group the plan already runs (a group selected, a rule's target, a pool
 * entry), over the links: each member a copy per link of the spec — `<member
 * id>#<link id>` — or, in split, an XHTTP member split as a server is. Its own
 * fallback stays; one it does not have is its first member on the fallback
 * link. A member the links cannot carry (a WireGuard, one dialling through
 * its own helper) stays as it is. A group behind a hop, a chain hop itself
 * (a WireGuard after it dials its loopback) or a group of chain variants is
 * left exactly as it was.
 *
 * `groupSkip` (settings.groupSkip, groupEvict.js): a member the app set aside
 * for not answering stays out — copied per link under new ids it would be
 * back N times over, each copy probed (the very socket leak it was set aside
 * for). Unless that would leave the group empty, as expandGroups does.
 */
function groupOnLinks(o, p, dialed, groupSkip) {
  const g = o._group;
  const all = Array.isArray(g.members) ? g.members : [];
  if (dialsThrough(o) || dialed.has(o.tag) || all.some((m) => m && Array.isArray(m.chain))) return o;
  if (!all.some(linkableMember)) return o;
  const kept = groupSkip.size ? all.filter((m) => !groupSkip.has(memberKey(g.id, m))) : all;
  const members = kept.length ? kept : all;
  const spec = linkSpec(p);
  const next = members.flatMap((m) => {
    if (!linkableMember(m)) return [m];
    if (p.mode === 'split' && splittable(m.outbound)) return [Object.assign({}, m, { outbound: splitOut(m.outbound, p.up, p.down) })];
    const base = memberBase(m);
    return spec.members.map((l) => memberOn(base, l));
  });
  let fallback = g.fallback || null;
  const first = members.find(linkableMember);
  if (!fallback && spec.fallback && first) fallback = memberOn(memberBase(first), spec.fallback);
  return Object.assign({}, o, { _group: Object.assign({}, g, { members: next, fallback }) });
}

/**
 * The outbounds with multi-internet applied — configBuilder.buildConfig and
 * buildPoolConfig call it right before expandGroups, only when applies(). A
 * server that dials by itself becomes a group over the links (`mw:<tag>`,
 * its tag kept, so every rule, the DNS exit and the pool's inbounds that
 * name it reach its balancer); a group the plan runs gets its members
 * multiplied over the links; an XHTTP server in split mode stays one
 * outbound with its two legs bound. Everything else is passed through as it
 * was. `opts.servers`: { [tag]: the server record behind that outbound } —
 * its id and name for the copies (configBuilder.serversByTag); a tag without
 * one is named by the tag itself. `opts.groupSkip`: settings.groupSkip (see
 * groupOnLinks).
 */
function applyMultiWan(outbounds, mw, skip, opts) {
  const list = Array.isArray(outbounds) ? outbounds : [];
  const p = planOf(mw, skip);
  if (!p) return list;
  const servers = (opts && isObj(opts.servers)) ? opts.servers : {};
  const groupSkip = skipSet(opts && opts.groupSkip);
  const dialed = dialedTags(list);
  return list.map((o) => {
    if (isGroupLoopback(o)) return groupOnLinks(o, p, dialed, groupSkip);
    if (!linkable(o) || typeof o.tag !== 'string' || !o.tag || o.tag.includes('~') || dialed.has(o.tag)) return o;
    return serverOnLinks(o, servers[o.tag] || null, p);
  });
}

/* ------------------------------------ counting ------------------------------------ */

/**
 * The link a member's id names: what follows the `#` ('' for any other
 * member). The FIRST `#`: a server's id never holds one (hex, `grp-…`, a tag),
 * while an adapter may be renamed "Ethernet #2" — with one `#` it is the last
 * one as well.
 */
function linkOfMemberId(id) {
  const s = id == null ? '' : String(id);
  const i = s.indexOf('#');
  return i < 0 ? '' : s.slice(i + 1);
}

const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : 0);

/**
 * The bytes each link carried: { [linkId]: { up, down } }, from /debug/vars'
 * `stats.outbound` as read (before stats.foldGroups) and the running groups
 * (expandGroups' map, config.groupTags — member i is `<tag>~gm<i>`, the
 * fallback `<tag>~fb`, a link's copy known by the `#<link id>` its id ends
 * in). `split`: config.multiWanSplit — each split outbound's uplink went out
 * on its up link and its downlink came in on its down link. A link a group
 * dials gets an entry even before it has carried a byte.
 */
function linkUsage(rawOutboundCounters, groupMap, split) {
  const raw = isObj(rawOutboundCounters) ? rawOutboundCounters : {};
  const out = {};
  const add = (link, up, down) => {
    if (!link) return;
    const r = out[link] || (out[link] = { up: 0, down: 0 });
    r.up += up;
    r.down += down;
  };
  const count = (link, tag) => { const c = raw[tag]; add(link, num(c && c.uplink), num(c && c.downlink)); };
  for (const g of Array.isArray(groupMap) ? groupMap : []) {
    if (!g || !g.tag) continue;
    (Array.isArray(g.members) ? g.members : []).forEach((m, i) => count(linkOfMemberId(m && m.id), `${g.tag}~gm${i}`));
    if (g.fallback) count(linkOfMemberId(g.fallback.id), `${g.tag}~fb`);
  }
  for (const sp of Array.isArray(split) ? split : []) {
    if (!sp || !sp.tag) continue;
    const c = raw[sp.tag];
    add(str(sp.up), num(c && c.uplink), 0);
    add(str(sp.down), 0, num(c && c.downlink));
  }
  return out;
}

module.exports = {
  MODES, ROLES, PERIODS, WEIGHT_MIN, WEIGHT_MAX, WEIGHT_DEFAULT,
  normalizeMultiWan, usableLinks, applies, applyMultiWan, finishSplit, linkOfMemberId, linkUsage, splittable
};
