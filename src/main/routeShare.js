'use strict';
/**
 * Routing share links (docs/superpowers/specs/2026-10-09-routing-profiles-design.md §4):
 * a routing profile — or a chain — with every server and chain it needs, as
 * one line of text:
 *
 *   irnetfree://routing/<base64url(deflate-raw(JSON))>
 *
 * The JSON is `{ v: 1, kind: 'profile'|'chain', servers, chains, profile? }`:
 *   - servers `{ key: 's<n>', name, link }` — `link` is what Copy gives for that
 *     server (buildShareLink: a share link, or the JSON text of a JSON server);
 *   - chains `{ key: 'c<n>', name, members: [serverKey] }`;
 *   - profile `{ name, useMode, base, def, defVia, rules: [{ type, value, target, via? }] }`
 *     with every target, via and base written as `s<n>` / `chain:c<n>` — never
 *     the sender's ids. `useMode` is the only setting it carries.
 *
 * Everything but createRouteShareApi() is pure: lists in, new lists out.
 * createRouteShareApi() is the four IPC handlers main.js and the router's
 * service.js share (`routing:shareProfile`, `routing:shareChain`,
 * `routing:importPreview`, `routing:import`); every effect it has goes through
 * what they hand in. Android reads and writes the same text (RouteShare.kt);
 * tests/fixtures/routing/ holds one payload and its link for both.
 */
const zlib = require('zlib');
const crypto = require('crypto');

const SHARE_PREFIX = 'irnetfree://routing/';
/** The decoded JSON may be at most this long — larger is refused, both ways. */
const MAX_DECODED = 65536;
/** A QR is offered up to this many bytes of text; larger: "use Copy". */
const QR_MAX_BYTES = 1700;
/** The longest body worth decoding: raw deflate of MAX_DECODED never needs more (stored blocks, + slack). */
const MAX_BODY_CHARS = Math.ceil((MAX_DECODED + 1024) / 3) * 4;

const RULE_TYPES = ['ip', 'domain', 'port', 'process'];
const VIA_INHERIT = 'inherit';
const VIA_NONE = 'none';
const SERVER_KEY = /^s[1-9]\d*$/;
const CHAIN_KEY = /^c[1-9]\d*$/;

/* ------------------------------ reasons ------------------------------ */

const faDigits = (v) => String(v).replace(/\d/g, (d) => '۰۱۲۳۴۵۶۷۸۹'[d]);

const REASONS = {
  prefix: {
    en: () => 'Not a routing link — it should start with irnetfree://routing/.',
    fa: () => 'این متن لینکِ روتینگ نیست — باید با irnetfree://routing/ شروع شود.'
  },
  base64: {
    en: () => 'The routing link is damaged (not base64url text) — copy it again in full.',
    fa: () => 'لینکِ روتینگ خراب است (متنِ base64url نیست) — دوباره کاملش را کپی کن.'
  },
  deflate: {
    en: () => 'The routing link is damaged or cut short — copy it again in full.',
    fa: () => 'لینکِ روتینگ خراب یا ناقص است — دوباره کاملش را کپی کن.'
  },
  size: {
    en: () => 'The routing link is too large (over 64 KB once unpacked).',
    fa: () => 'لینکِ روتینگ بیش از حد بزرگ است (بازشده‌اش بیش از ۶۴ کیلوبایت).'
  },
  json: {
    en: () => 'The routing link is damaged — what it carries is not readable.',
    fa: () => 'لینکِ روتینگ خراب است — محتوایش خوانا نیست.'
  },
  version: {
    en: (x) => `This routing link is in a format this version of IRNetFree does not read (v${x.v}) — update the app.`,
    fa: (x) => `این لینکِ روتینگ قالبی دارد که این نسخهٔ IRNetFree نمی‌خواند (v${x.v}) — برنامه را به‌روز کن.`
  },
  kind: {
    en: (x) => `Unknown kind of routing link: ${x.kind}.`,
    fa: (x) => `نوعِ ناشناختهٔ لینکِ روتینگ: ${x.kind}.`
  },
  shape: {
    en: (x) => `The routing link is malformed: ${x.detail}.`,
    fa: (x) => `لینکِ روتینگ نادرست ساخته شده: ${x.detail}.`
  },
  missing: {
    en: (x) => `The routing link names “${x.ref}”, which it does not carry.`,
    fa: (x) => `لینکِ روتینگ به «${x.ref}» اشاره می‌کند که خودش آن را ندارد.`
  },
  gone: {
    en: (x) => `${x.where} names a server or chain that no longer exists — fix it under Routing, then copy again.`,
    fa: (x) => `${x.where} به سرور یا زنجیره‌ای اشاره می‌کند که دیگر وجود ندارد — اول در بخشِ روتینگ درستش کن، بعد دوباره کپی کن.`
  },
  chainLost: {
    en: (x) => `The chain “${x.name}” lost a server (it was removed, or replaced by a subscription update) — put it back under Chain, then copy again.`,
    fa: (x) => `زنجیرهٔ «${x.name}» یکی از سرورهایش را از دست داده (حذف شده، یا با به‌روزرسانیِ اشتراک عوض شده) — اول در بخشِ زنجیره سرور را برگردان، بعد دوباره کپی کن.`
  },
  notFound: {
    en: () => 'Not found — it may have been deleted.',
    fa: () => 'پیدا نشد — شاید حذف شده باشد.'
  }
};

/** An Error with a stable `code` and a reason in the app's language ('en', else Persian when 'fa'; English by default). */
function fail(code, lang, vars = {}) {
  const r = REASONS[code];
  const e = new Error(r[lang === 'fa' ? 'fa' : 'en'](vars));
  e.code = code;
  return e;
}

/** Where in a profile a reference sits, for the 'gone' reason. */
function whereLabel(lang, at = {}) {
  const fa = lang === 'fa';
  if (at.rule) {
    const n = at.rule;
    if (at.via) return fa ? `مسیرِ واسطِ قانونِ ${faDigits(n)}` : `Rule ${n}’s via`;
    return fa ? `قانونِ ${faDigits(n)}` : `Rule ${n}`;
  }
  if (at.what === 'base') return fa ? 'پایهٔ این روتینگ' : 'The profile’s base';
  if (at.what === 'defVia') return fa ? 'مسیرِ واسطِ پیش‌فرض' : 'The default’s via';
  return fa ? 'مقصدِ پیش‌فرض' : 'The default';
}

/* ------------------------------ text ------------------------------ */

/** The payload as one line of text. Refuses one the receiver would refuse (> MAX_DECODED). */
function encodeShare(payload, { lang } = {}) {
  const json = Buffer.from(JSON.stringify(payload), 'utf8');
  if (json.length > MAX_DECODED) throw fail('size', lang);
  return SHARE_PREFIX + zlib.deflateRawSync(json).toString('base64url');
}

/**
 * The payload of a share text — or an Error whose `code` says why not:
 * 'prefix', 'base64', 'deflate', 'size', 'json', 'version', 'kind', 'shape',
 * 'missing'. Surrounding whitespace (a paste, a CRLF) is fine; nothing is
 * inflated past MAX_DECODED bytes.
 */
function decodeShare(text, { lang } = {}) {
  const s = String(text == null ? '' : text).trim();
  if (s.slice(0, SHARE_PREFIX.length).toLowerCase() !== SHARE_PREFIX) throw fail('prefix', lang);
  const body = s.slice(SHARE_PREFIX.length).replace(/\s+/g, '');
  if (body.length > MAX_BODY_CHARS) throw fail('size', lang);
  const bare = body.replace(/={1,2}$/, '');
  if (!bare || !/^[A-Za-z0-9_+/-]+$/.test(bare) || bare.length % 4 === 1) throw fail('base64', lang);
  let raw;
  try { raw = zlib.inflateRawSync(Buffer.from(bare, 'base64url'), { maxOutputLength: MAX_DECODED }); }
  catch (e) { throw fail(e && (e.code === 'ERR_BUFFER_TOO_LARGE' || e instanceof RangeError) ? 'size' : 'deflate', lang); }
  if (raw.length > MAX_DECODED) throw fail('size', lang);
  let payload;
  try { payload = JSON.parse(raw.toString('utf8')); } catch { throw fail('json', lang); }
  validatePayload(payload, lang);
  return payload;
}

/** Is this text small enough for a QR (bytes, not characters)? */
function fitsQr(text) {
  return Buffer.byteLength(String(text || ''), 'utf8') <= QR_MAX_BYTES;
}

/* ------------------------------ validation ------------------------------ */

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const isText = (v) => typeof v === 'string';

/**
 * Throws unless `p` is a payload this version can import whole: v 1, a known
 * kind, unique keys, a link per server, and every reference — a chain member,
 * a rule's target and via, the default and its via, the base — naming a key
 * the payload carries (or direct / block / inherit / none where those apply).
 */
function validatePayload(p, lang) {
  const shape = (detail) => fail('shape', lang, { detail });
  if (!isObj(p)) throw fail('json', lang);
  if (p.v !== 1) throw fail('version', lang, { v: p.v === undefined ? '?' : String(p.v).slice(0, 12) });
  if (p.kind !== 'profile' && p.kind !== 'chain') throw fail('kind', lang, { kind: String(p.kind).slice(0, 24) });
  if (!Array.isArray(p.servers)) throw shape('no server list');
  if (p.chains !== undefined && !Array.isArray(p.chains)) throw shape('the chain list is not a list');
  const serverKeys = new Set();
  for (const s of p.servers) {
    if (!isObj(s) || !isText(s.key) || !SERVER_KEY.test(s.key)) throw shape('a server without a key s1, s2, …');
    if (serverKeys.has(s.key)) throw shape('two servers named ' + s.key);
    if (!isText(s.link) || !s.link.trim()) throw shape('server ' + s.key + ' has no link');
    if (s.name !== undefined && !isText(s.name)) throw shape('server ' + s.key + ' has an odd name');
    serverKeys.add(s.key);
  }
  const chains = p.chains || [];
  const chainKeys = new Set();
  for (const c of chains) {
    if (!isObj(c) || !isText(c.key) || !CHAIN_KEY.test(c.key)) throw shape('a chain without a key c1, c2, …');
    if (chainKeys.has(c.key)) throw shape('two chains named ' + c.key);
    if (c.name !== undefined && !isText(c.name)) throw shape('chain ' + c.key + ' has an odd name');
    if (!Array.isArray(c.members) || !c.members.length) throw shape('chain ' + c.key + ' has no servers');
    for (const m of c.members) if (!isText(m) || !serverKeys.has(m)) throw fail('missing', lang, { ref: String(m).slice(0, 40) });
    chainKeys.add(c.key);
  }
  const target = (t) => {
    if (t === 'direct' || t === 'block') return;
    const ok = isText(t) && (t.startsWith('chain:') ? chainKeys.has(t.slice(6)) : serverKeys.has(t));
    if (!ok) throw fail('missing', lang, { ref: String(t).slice(0, 40) });
  };
  const proxy = (t) => {   // a via or a base: a server or a chain, never direct/block
    if (t === 'direct' || t === 'block') throw fail('missing', lang, { ref: t });
    target(t);
  };
  const via = (v) => { if (v !== undefined && v !== null && v !== VIA_INHERIT && v !== VIA_NONE) proxy(v); };
  if (p.kind === 'chain') {
    if (!chains.length) throw shape('a chain link without a chain');
    return;
  }
  const pr = p.profile;
  if (!isObj(pr)) throw shape('a profile link without a profile');
  if (pr.name !== undefined && !isText(pr.name)) throw shape('the profile has an odd name');
  if (!Array.isArray(pr.rules)) throw shape('the profile has no rule list');
  for (const r of pr.rules) {
    if (!isObj(r)) throw shape('a rule that is not a rule');
    if (!RULE_TYPES.includes(r.type)) throw shape('a rule of an unknown kind: ' + String(r.type).slice(0, 24));
    if (r.value !== undefined && !isText(r.value)) throw shape('a rule with an odd value');
    target(r.target);
    via(r.via);
  }
  if (pr.def !== undefined && pr.def !== null && pr.def !== '') target(pr.def);
  via(pr.defVia);
  if (pr.base !== undefined && pr.base !== null && pr.base !== '') proxy(pr.base);
}

/* ------------------------------ building a payload ------------------------------ */

/**
 * Keys for what a payload carries, handed out in the order they are first
 * used: `server(id)` → 's<n>', `chain(id)` → 'c<n>' (its members first get
 * theirs). Throws 'gone' / 'chainLost' for what no longer exists.
 */
function makeKeys({ servers, chains, linkOf, legacyChain, lang }) {
  const serverById = new Map((servers || []).filter(Boolean).map((s) => [s.id, s]));
  const chainById = new Map((chains || []).filter(Boolean).map((c) => [c.id, c]));
  const sKeys = new Map();
  const cKeys = new Map();
  const outServers = [];
  const outChains = [];
  const server = (id, at) => {
    if (sKeys.has(id)) return sKeys.get(id);
    const s = serverById.get(id);
    if (!s) throw fail('gone', lang, { where: whereLabel(lang, at) });
    const key = 's' + (outServers.length + 1);
    sKeys.set(id, key);
    outServers.push({ key, name: String(s.name || ''), link: String(linkOf(s) || '') });
    return key;
  };
  const chainOf = (c) => {
    if (cKeys.has(c.id)) return cKeys.get(c.id);
    const ids = Array.isArray(c.members) ? c.members.filter(Boolean) : [];
    if (!ids.length || ids.some((id) => !serverById.has(id))) throw fail('chainLost', lang, { name: c.name || c.id });
    const key = 'c' + (outChains.length + 1);
    cKeys.set(c.id, key);
    const entry = { key, name: String(c.name || ''), members: [] };
    outChains.push(entry);
    entry.members = ids.map((id) => server(id));
    return key;
  };
  // the old single global chain (a rule target 'chain'): carried as a named chain
  const legacy = () => {
    const ids = Array.isArray(legacyChain) ? legacyChain.filter(Boolean) : [];
    const name = ids.map((id) => (serverById.get(id) || {}).name || id).join(' → ');
    return { id: '\u0000legacy', name, members: ids };
  };
  const ref = (t, at) => {
    if (t === 'direct' || t === 'block') return t;
    if (t === 'chain') {
      const c = legacy();
      if (!c.members.length) throw fail('gone', lang, { where: whereLabel(lang, at) });
      return 'chain:' + chainOf(c);
    }
    if (isText(t) && t.startsWith('chain:')) {
      const c = chainById.get(t.slice(6));
      if (!c) throw fail('gone', lang, { where: whereLabel(lang, at) });
      return 'chain:' + chainOf(c);
    }
    return server(t, at);
  };
  return { ref, chainOf, servers: outServers, chains: outChains };
}

/** A via as the payload carries it: inherit / none as they are, a target as its key. direct/block are not vias. */
function viaRef(v, keys, at) {
  if (v === undefined || v === null || v === '') return undefined;
  if (v === VIA_INHERIT || v === VIA_NONE) return v;
  if (v === 'direct' || v === 'block') return undefined;
  return keys.ref(v, at);
}

/**
 * The payload for a profile: only the servers and chains it uses, keyed in the
 * order it uses them (base, default, the default's via, then each rule's target
 * and via). An empty default is the store's first server — what a connect uses.
 * `legacyChain` (store `chain`, ids) stands in for a rule target 'chain'.
 */
function profilePayload({ profile, servers, chains, linkOf, legacyChain, lang }) {
  const keys = makeKeys({ servers, chains, linkOf, legacyChain, lang });
  const p = profile || {};
  const base = p.base ? keys.ref(p.base, { what: 'base' }) : null;
  const rawDef = p.def || ((servers || [])[0] && servers[0].id) || 'direct';
  const def = keys.ref(rawDef, { what: 'def' });
  const defVia = (def === 'direct' || def === 'block') ? VIA_INHERIT : (viaRef(p.defVia, keys, { what: 'defVia' }) || VIA_INHERIT);
  const rules = (Array.isArray(p.rules) ? p.rules : []).filter(Boolean).map((r, i) => {
    const out = { type: r.type, value: String(r.value == null ? '' : r.value), target: keys.ref(r.target, { rule: i + 1 }) };
    if (out.target !== 'direct' && out.target !== 'block') {
      const v = viaRef(r.via, keys, { rule: i + 1, via: true });
      if (v !== undefined) out.via = v;
    }
    return out;
  });
  return {
    v: 1, kind: 'profile',
    servers: keys.servers,
    chains: keys.chains,
    profile: { name: String(p.name || ''), useMode: !!p.useMode, base, def, defVia, rules }
  };
}

/** The payload for a chain: the chain (c1) and its servers. */
function chainPayload({ chain, servers, linkOf, lang }) {
  const keys = makeKeys({ servers, chains: [chain], linkOf, lang });
  keys.chainOf(chain || {});
  return { v: 1, kind: 'chain', servers: keys.servers, chains: keys.chains };
}

/* ------------------------------ importing ------------------------------ */

/**
 * What each server of the payload becomes here: `{ key → { state, id?, server?, error? } }`
 *   - 'existing': a saved server with the same strict identity (reused, untouched);
 *   - 'new': read from its link (`server`, named as the link says);
 *   - 'same': the same identity as an earlier key of this payload (one record);
 *   - 'unreadable': the link does not parse (`error`).
 */
function matchServers(payload, { servers, parse, identityOf }) {
  const have = new Map();
  for (const s of servers || []) {
    const id = s ? identityOf(s) : '';
    if (id && !have.has(id)) have.set(id, s.id);
  }
  const seen = new Map();
  const out = new Map();
  for (const e of payload.servers) {
    let server;
    try { server = parse(e.link, e.name); }
    catch (err) { out.set(e.key, { state: 'unreadable', error: (err && err.message) || String(err) }); continue; }
    if (!server || typeof server !== 'object') { out.set(e.key, { state: 'unreadable', error: 'unreadable' }); continue; }
    const ident = identityOf(server);
    if (ident && have.has(ident)) { out.set(e.key, { state: 'existing', id: have.get(ident) }); continue; }
    if (ident && seen.has(ident)) { out.set(e.key, { state: 'same', key: seen.get(ident) }); continue; }
    if (ident) seen.set(ident, e.key);
    out.set(e.key, { state: 'new', server: Object.assign({}, server, { name: isText(e.name) && e.name.trim() ? e.name : server.name }) });
  }
  return out;
}

const unreadableLine = (e, m) => `${(e.name || e.key)}: ${m.error}`;

/**
 * What an import would do, for the preview:
 * `{ kind, name, rules, chains, serversNew, serversExisting, unreadable: ['<name>: <reason>'] }`.
 */
function previewImport(payload, { servers = [], parse, identityOf, lang } = {}) {
  validatePayload(payload, lang);
  const m = matchServers(payload, { servers, parse, identityOf });
  let serversNew = 0, serversExisting = 0;
  const unreadable = [];
  for (const e of payload.servers) {
    const x = m.get(e.key);
    if (x.state === 'new') serversNew++;
    else if (x.state === 'existing') serversExisting++;
    else if (x.state === 'unreadable') unreadable.push(unreadableLine(e, x));
  }
  const chains = payload.chains || [];
  const profile = payload.kind === 'profile' ? payload.profile : null;
  return {
    kind: payload.kind,
    name: profile ? String(profile.name || '') : String((chains[0] && chains[0].name) || ''),
    rules: profile ? profile.rules.length : 0,
    chains: chains.length,
    serversNew, serversExisting, unreadable
  };
}

/** `name`, or `name (2)`, `name (3)`, … — the first one none of `taken` has. */
function uniqueName(name, taken) {
  const set = new Set(taken);
  if (!set.has(name)) return name;
  for (let n = 2; ; n++) if (!set.has(`${name} (${n})`)) return `${name} (${n})`;
}

const rand4 = () => crypto.randomBytes(3).toString('hex').slice(0, 4);
/** ids as the app makes them: chain-<base36 time><rand>, rp-<base36 time><rand>, a server's 16 hex digits. */
function defaultNewId(kind) {
  if (kind === 'chain') return 'chain-' + Date.now().toString(36) + rand4();
  if (kind === 'profile') return 'rp-' + Date.now().toString(36) + rand4();
  return crypto.randomBytes(8).toString('hex');
}

/**
 * The import itself, pure: `{ servers, chains, profiles, added: { servers, chains, profiles },
 * unreadable, profileId?, chainId? }` — new lists, the given ones untouched.
 *   - a server with the same strict identity as a saved one is reused; others are added (no subscription);
 *   - a chain with the same name and (mapped) members is reused, else added (its name made unique);
 *   - a profile is always added, at the end, its name made unique ("Work (2)");
 *   - an unreadable server stays a reference to nothing — the builder refuses
 *     a chain or default that names it and skips a rule to it — never a shorter chain.
 * `newId(kind)` makes the ids ('server' | 'chain' | 'profile').
 */
function applyImport(payload, { servers = [], chains = [], profiles = [], parse, identityOf, newId, lang } = {}) {
  validatePayload(payload, lang);
  const makeId = typeof newId === 'function' ? newId : defaultNewId;
  const fresh = (kind, taken) => {
    for (let i = 0; i < 100; i++) {
      const id = makeId(kind);
      if (id && !taken.has(id)) { taken.add(id); return id; }
    }
    const id = defaultNewId(kind) + crypto.randomBytes(4).toString('hex');
    taken.add(id);
    return id;
  };
  const m = matchServers(payload, { servers, parse, identityOf });
  const outServers = servers.slice();
  const serverIds = new Set(servers.map((s) => s && s.id));
  const added = { servers: 0, chains: 0, profiles: 0 };
  const unreadable = [];
  const idOfKey = {};
  for (const e of payload.servers) {
    const x = m.get(e.key);
    if (x.state === 'existing') idOfKey[e.key] = x.id;
    else if (x.state === 'same') idOfKey[e.key] = idOfKey[x.key];
    else if (x.state === 'unreadable') { idOfKey[e.key] = 'unreadable-' + e.key; unreadable.push(unreadableLine(e, x)); }
    else {
      const rec = x.server;
      const id = rec.id && !serverIds.has(rec.id) ? (serverIds.add(rec.id), rec.id) : fresh('server', serverIds);
      outServers.push(Object.assign({}, rec, { id }));
      idOfKey[e.key] = id;
      added.servers++;
    }
  }

  const outChains = chains.slice();
  const chainIds = new Set(chains.map((c) => c && c.id));
  const chainOfKey = {};
  for (const c of payload.chains || []) {
    const members = c.members.map((k) => idOfKey[k]);
    const name = (isText(c.name) && c.name.trim()) || 'Chain';
    const same = outChains.find((x) => x && x.name === name && Array.isArray(x.members)
      && x.members.length === members.length && x.members.every((id, i) => id === members[i]));
    if (same) { chainOfKey[c.key] = same.id; continue; }
    const id = fresh('chain', chainIds);
    outChains.push({ id, name: uniqueName(name, outChains.map((x) => x && x.name)), members });
    chainOfKey[c.key] = id;
    added.chains++;
  }

  const res = { servers: outServers, chains: outChains, profiles: profiles.slice(), added, unreadable };
  if (payload.kind === 'chain') {
    res.chainId = chainOfKey[payload.chains[0].key];
    return res;
  }
  const ref = (t) => (t === 'direct' || t === 'block' ? t : t.startsWith('chain:') ? 'chain:' + chainOfKey[t.slice(6)] : idOfKey[t]);
  const via = (v) => (v === undefined || v === null || v === '' ? undefined : v === VIA_INHERIT || v === VIA_NONE ? v : ref(v));
  const p = payload.profile;
  const profileIds = new Set(profiles.map((x) => x && x.id));
  const profile = {
    id: fresh('profile', profileIds),
    name: uniqueName((isText(p.name) && p.name.trim()) || 'Routing', profiles.map((x) => x && x.name)),
    rules: p.rules.map((r) => {
      const out = { type: r.type, value: String(r.value == null ? '' : r.value), target: ref(r.target) };
      const v = out.target === 'direct' || out.target === 'block' ? undefined : via(r.via);
      if (v !== undefined) out.via = v;
      return out;
    }),
    def: p.def ? ref(p.def) : '',
    defVia: via(p.defVia) || VIA_INHERIT,
    useMode: !!p.useMode,
    base: p.base ? ref(p.base) : null
  };
  res.profiles.push(profile);
  res.profileId = profile.id;
  added.profiles++;
  return res;
}

/* ------------------------------ the store's profiles ------------------------------ */

/** R1's profile module when it is there (src/main/routingProfiles.js); null before it lands. */
function loadRoutingProfiles() {
  try { return require('./routingProfiles'); }
  catch (e) {
    if (e && e.code === 'MODULE_NOT_FOUND' && /routingProfiles/.test(e.message)) return null;
    throw e;
  }
}

/**
 * The saved routing profiles: the stored list; with none stored, what R1's
 * migration makes of today's settings — or, without R1, the same `rp-default`.
 */
function storedProfiles({ stored, settings, rp, lang }) {
  if (Array.isArray(stored)) return stored.filter(isObj);
  const s = settings || {};
  if (rp && typeof rp.migrateProfiles === 'function') {
    const r = rp.migrateProfiles({ stored: null, settings: s });
    if (r && Array.isArray(r.profiles)) return r.profiles;
  }
  return [{
    id: 'rp-default',
    name: lang === 'en' ? 'Advanced routing' : 'روتینگ ویژه',
    rules: Array.isArray(s.routeRules) ? s.routeRules.filter(isObj).map((r) => ({ type: r.type, value: r.value, target: r.target })) : [],
    def: s.routeDefault || '',
    defVia: VIA_INHERIT,
    useMode: !!s.advancedUseMode,
    base: null
  }];
}

/** The profile a selection connects: `__advanced__` = the first, `__advanced__:<id>` = that one (R1's profileIdOf when present). */
function profileIdOf(sel, profiles, rp) {
  if (rp && typeof rp.profileIdOf === 'function') return rp.profileIdOf(sel, profiles);
  if (sel === '__advanced__') return (profiles[0] && profiles[0].id) || null;
  if (isText(sel) && sel.startsWith('__advanced__:')) {
    const id = sel.slice('__advanced__:'.length);
    return profiles.some((p) => p.id === id) ? id : null;
  }
  return null;
}

/* ------------------------------ the IPC handlers ------------------------------ */

/**
 * The four channels main.js and the router's service register:
 *   shareProfile(id) / shareChain(id) → { ok, link, bytes, servers, qr, error? }
 *   importPreview(text)              → { ok, summary, error? }
 *   importShare(text)                → { ok, profileId?, chainId?, added, servers, chains, profiles, unreadable, live, pendingReconnect, error? }
 *
 * deps:
 *   store        get / assign (one atomic write of every list an import changes)
 *   getSettings  the settings (lang, and the routing keys rp-default mirrors)
 *   getChains    the named chains (the legacy migration included)
 *   linkOf       buildShareLink
 *   parseMany    parser's parseMany: a payload's link → its server
 *   identityOf   serverIdentity(s, true)
 *   afterWrite   called after an import wrote (main.js: the tray follows the servers)
 *   liveSelection  the live connection's selection id, or null when nothing is live
 *   markLive     raises the "reconnect needed" state
 *   pendingKeys  the reconnect state, for the answer
 *   rp           R1's module (default: loaded lazily; null = without it)
 *   newId        ids for tests (default: the app's forms; a profile id from R1 when present)
 */
function createRouteShareApi(d) {
  const lang = () => ((d.getSettings() || {}).lang === 'en' ? 'en' : 'fa');
  const rp = () => (d.rp !== undefined ? d.rp : loadRoutingProfiles());
  const newIdWith = (R) => d.newId || ((kind) => (kind === 'profile' && R && typeof R.newProfileId === 'function' ? R.newProfileId() : defaultNewId(kind)));
  const parse = (link, name) => {
    const r = d.parseMany(link);
    const list = (r && r.servers) || [];
    if (!list.length) throw new Error((r && r.errors && r.errors[0] && r.errors[0].error) || 'unreadable');
    // a JSON config can hold several proxies: the one this entry was named for, else the first
    return list.find((s) => s && s.name === name) || list[0];
  };
  const errorOf = (e) => ({ ok: false, error: (e && e.message) || String(e) });
  const answerLink = (payload, L) => {
    const link = encodeShare(payload, { lang: L });
    const bytes = Buffer.byteLength(link, 'utf8');
    return { ok: true, link, bytes, servers: payload.servers.length, qr: bytes <= QR_MAX_BYTES };
  };
  const pending = () => (typeof d.pendingKeys === 'function' ? d.pendingKeys() : []);

  function shareProfile(id) {
    const L = lang();
    try {
      const settings = d.getSettings();
      const profiles = storedProfiles({ stored: d.store.get('routingProfiles', null), settings, rp: rp(), lang: L });
      const profile = profiles.find((p) => p.id === id);
      if (!profile) throw fail('notFound', L);
      return answerLink(profilePayload({
        profile, servers: d.store.get('servers', []), chains: d.getChains(), linkOf: d.linkOf,
        legacyChain: d.store.get('chain', []), lang: L
      }), L);
    } catch (e) { return errorOf(e); }
  }

  function shareChain(id) {
    const L = lang();
    try {
      const chain = (d.getChains() || []).find((c) => c && c.id === id);
      if (!chain) throw fail('notFound', L);
      return answerLink(chainPayload({ chain, servers: d.store.get('servers', []), linkOf: d.linkOf, lang: L }), L);
    } catch (e) { return errorOf(e); }
  }

  function importPreview(text) {
    const L = lang();
    try {
      const payload = decodeShare(text, { lang: L });
      return { ok: true, summary: previewImport(payload, { servers: d.store.get('servers', []), parse, identityOf: d.identityOf, lang: L }) };
    } catch (e) { return errorOf(e); }
  }

  function importShare(text) {
    const L = lang();
    let payload, res, profilesBefore, R;
    try {
      payload = decodeShare(text, { lang: L });
      R = rp();
      const settings = d.getSettings();
      profilesBefore = storedProfiles({ stored: d.store.get('routingProfiles', null), settings, rp: R, lang: L });
      res = applyImport(payload, {
        servers: d.store.get('servers', []), chains: d.getChains(), profiles: profilesBefore,
        parse, identityOf: d.identityOf, newId: newIdWith(R), lang: L
      });
    } catch (e) { return errorOf(e); }

    // one write: the lists, and (a profile) the settings rp-default mirrors when R1 says they changed
    const write = { servers: res.servers, chains: res.chains };
    if (payload.kind === 'profile') {
      write.routingProfiles = res.profiles;
      if (R && typeof R.mirrorToSettings === 'function') {
        const now = d.getSettings();
        const mirrored = R.mirrorToSettings(res.profiles, Object.assign({}, now)) || now;
        const changed = ['routeRules', 'routeDefault', 'advancedUseMode']
          .filter((k) => k in mirrored && JSON.stringify(mirrored[k]) !== JSON.stringify(now[k]));
        if (changed.length) {
          const raw = Object.assign({}, d.store.get('settings', {}));
          for (const k of changed) raw[k] = mirrored[k];
          write.settings = raw;
        }
      }
    }
    // An import only adds: the live connection is touched only when what its
    // selection resolves to moved — plain __advanced__ with no profile before.
    const sel = typeof d.liveSelection === 'function' ? d.liveSelection() : null;
    const live = payload.kind === 'profile' && isText(sel) && sel.startsWith('__advanced__')
      && profileIdOf(sel, profilesBefore, R) !== profileIdOf(sel, res.profiles, R);
    d.store.assign(write);
    if (typeof d.afterWrite === 'function') d.afterWrite(write);
    if (live && typeof d.markLive === 'function') d.markLive();
    const out = { ok: true, added: res.added, servers: res.servers, chains: res.chains, profiles: res.profiles, unreadable: res.unreadable, live, pendingReconnect: pending() };
    if (res.profileId) out.profileId = res.profileId;
    if (res.chainId) out.chainId = res.chainId;
    return out;
  }

  return { shareProfile, shareChain, importPreview, importShare };
}

module.exports = {
  SHARE_PREFIX, MAX_DECODED, QR_MAX_BYTES,
  encodeShare, decodeShare, fitsQr, validatePayload,
  profilePayload, chainPayload, previewImport, applyImport,
  storedProfiles, profileIdOf, uniqueName,
  createRouteShareApi
};
