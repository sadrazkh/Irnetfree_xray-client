'use strict';
/**
 * Routing profiles — several saved advanced routings, and "via a base"
 * (docs/superpowers/specs/2026-10-09-routing-profiles-design.md §1-2).
 *
 * A profile is `{ id, name, rules, def, defVia, useMode, base }`:
 *  - `rules`: today's advanced rules (`{ type, value, target }`) with an
 *    optional `via`;
 *  - `def` / `useMode`: today's `routeDefault` / `advancedUseMode`;
 *  - `defVia`: the default's via;
 *  - `base`: the profile's base — a server id or `chain:<id>` — or null.
 * A via is 'inherit' (the profile's base, if any), 'none', or a target.
 * `direct` and `block` never take one.
 *
 * Stored under `routingProfiles`. Today's settings become profile
 * `rp-default` once, and stay its mirror both ways: an old backup, an older
 * app on the same store and Android's legacy reader still see them.
 *
 * Selections: `__advanced__:<profileId>`; plain `__advanced__` (LuCI, old
 * stores, old selections) is the first profile.
 *
 * Pure: no store, no electron — main.js and the router's service.js both use it.
 */
const crypto = require('crypto');

const VIA_INHERIT = 'inherit';
const VIA_NONE = 'none';
const DEFAULT_PROFILE_ID = 'rp-default';
const ADVANCED = '__advanced__';
const ID = /^[\w-]+$/;

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const str = (v) => (v == null ? '' : String(v));
const clone = (v) => JSON.parse(JSON.stringify(v));
/** Targets that name no outbound of a server or a chain. */
const LOCAL = new Set(['direct', 'block']);

/** A new profile id: `rp-<base36 time><rand>`. */
function newProfileId() {
  return 'rp-' + Date.now().toString(36) + crypto.randomBytes(3).toString('hex');
}

/** The migrated profile's name, in the language the app speaks. */
function defaultName(lang) {
  return lang === 'en' ? 'Advanced routing' : 'روتینگ پیشرفته';
}

/** A rule as a profile keeps it: `{ id?, type, value, target, via? }`, strings. */
function normalizeRule(r) {
  if (!isObj(r)) return null;
  const out = {};
  if (typeof r.id === 'string' && r.id) out.id = r.id;
  out.type = str(r.type);
  out.value = str(r.value);
  out.target = str(r.target);
  if (r.via != null && str(r.via).trim()) out.via = str(r.via).trim();
  return out;
}

/**
 * A profile with only its own fields, each of its type: an unknown field is
 * dropped, a missing one takes its default, an id that is not `[\w-]+` a new
 * one. Not an object → null.
 */
function normalizeProfile(p) {
  if (!isObj(p)) return null;
  const base = p.base == null ? '' : str(p.base).trim();
  const defVia = p.defVia == null ? '' : str(p.defVia).trim();
  return {
    id: typeof p.id === 'string' && ID.test(p.id) ? p.id : newProfileId(),
    name: str(p.name).trim() || 'Routing profile',
    rules: Array.isArray(p.rules) ? p.rules.map(normalizeRule).filter(Boolean) : [],
    def: str(p.def),
    defVia: defVia || VIA_INHERIT,
    useMode: !!p.useMode,
    base: !base || LOCAL.has(base) || base === VIA_INHERIT || base === VIA_NONE ? null : base
  };
}

/**
 * Today's settings as profile `rp-default`: the rules as they are (a copy),
 * the default, useMode; no via, no base.
 */
function profileFromSettings(settings) {
  const s = isObj(settings) ? settings : {};
  return {
    id: DEFAULT_PROFILE_ID,
    name: defaultName(s.lang),
    rules: Array.isArray(s.routeRules) ? clone(s.routeRules.filter(isObj)) : [],
    def: s.routeDefault ? str(s.routeDefault) : '',
    defVia: VIA_INHERIT,
    useMode: !!s.advancedUseMode,
    base: null
  };
}

/**
 * The stored profiles, migrated: none stored yet (not a list) → today's
 * settings as `rp-default`; a list → each normalized, a duplicate id once.
 * `changed`: what is returned differs from what is stored — write it.
 */
function migrateProfiles({ stored, settings } = {}) {
  if (!Array.isArray(stored)) return { profiles: [profileFromSettings(settings)], changed: true };
  const seen = new Set();
  const profiles = [];
  for (const p of stored) {
    const n = normalizeProfile(p);
    if (!n || seen.has(n.id)) continue;
    seen.add(n.id);
    profiles.push(n);
  }
  return { profiles, changed: JSON.stringify(profiles) !== JSON.stringify(stored) };
}

const mirrored = (s) => JSON.stringify([s.routeRules || [], s.routeDefault || '', !!s.advancedUseMode]);

/**
 * rp-default → the settings' `routeRules` / `routeDefault` / `advancedUseMode`.
 * The very same settings object when there is nothing to change (no rp-default,
 * or already equal), so the caller knows there is nothing to write.
 */
function mirrorToSettings(profiles, settings) {
  const d = (Array.isArray(profiles) ? profiles : []).find((p) => p && p.id === DEFAULT_PROFILE_ID);
  const s = isObj(settings) ? settings : {};
  if (!d) return settings;
  const next = Object.assign({}, s, { routeRules: clone(Array.isArray(d.rules) ? d.rules : []), routeDefault: str(d.def), advancedUseMode: !!d.useMode });
  return mirrored(next) === mirrored(s) ? settings : next;
}

/**
 * The other way: the settings' three keys into rp-default — its name, base and
 * default via kept. The very same list when nothing changes (no rp-default,
 * or already equal).
 */
function mirrorFromSettings(profiles, settings) {
  const list = Array.isArray(profiles) ? profiles : [];
  const i = list.findIndex((p) => p && p.id === DEFAULT_PROFILE_ID);
  if (i === -1) return profiles;
  const from = profileFromSettings(settings);
  const next = Object.assign({}, list[i], { rules: from.rules, def: from.def, useMode: from.useMode });
  if (JSON.stringify(next) === JSON.stringify(list[i])) return profiles;
  return list.map((p, j) => (j === i ? next : p));
}

/** Is this connect id advanced routing: `__advanced__` or `__advanced__:<profileId>`? */
function isAdvancedSelection(id) {
  return typeof id === 'string' && (id === ADVANCED || id.indexOf(ADVANCED + ':') === 0);
}

/** The selection id that connects a profile. */
function selectionIdOf(profileId) {
  return ADVANCED + ':' + profileId;
}

/**
 * The profile a selection connects: plain `__advanced__` → the first;
 * `__advanced__:<id>` → that one, when it exists. Anything else → null.
 */
function profileIdOf(selectionId, profiles) {
  if (!isAdvancedSelection(selectionId)) return null;
  const list = (Array.isArray(profiles) ? profiles : []).filter((p) => p && p.id);
  if (selectionId === ADVANCED) return list.length ? list[0].id : null;
  const id = selectionId.slice(ADVANCED.length + 1);
  return id && list.some((p) => p.id === id) ? id : null;
}

/**
 * The base a rule (or, with `'def'`, the default) goes through: its via, or
 * the profile's base for 'inherit' (no via is 'inherit'); null for 'none', for
 * `direct` / `block` / an empty target, and for a target that would be its own
 * base. `profile` may be an advanced plan — it carries the same fields.
 */
function effectiveVia(ruleOrDef, profile) {
  const p = isObj(profile) ? profile : {};
  const isDef = ruleOrDef === 'def';
  const target = isDef ? p.def : (isObj(ruleOrDef) ? ruleOrDef.target : null);
  const via = isDef ? p.defVia : (isObj(ruleOrDef) ? ruleOrDef.via : null);
  if (!target || LOCAL.has(target)) return null;
  const v = via == null || via === '' || via === VIA_INHERIT ? (p.base || null) : (via === VIA_NONE ? null : str(via));
  if (!v || LOCAL.has(v) || v === VIA_INHERIT || v === VIA_NONE || v === target) return null;
  return v;
}

/**
 * What an advanced plan uses, each once and in order: `targets` (every rule
 * target, then the default), `vias` (the bases they go through) and `entries`
 * (what the machine dials ITSELF: a target without a via, else its base).
 * Without a via, `entries` are `targets` in the same order.
 */
function advancedTargets(plan) {
  const p = isObj(plan) ? plan : {};
  const targets = [], vias = [], entries = [];
  const put = (list, v) => { if (!list.includes(v)) list.push(v); };
  const visit = (target, via) => {
    put(targets, target);
    if (via) put(vias, via);
    put(entries, via || target);
  };
  for (const r of Array.isArray(p.rules) ? p.rules : []) if (r) visit(r.target, effectiveVia(r, p));
  visit(p.def, effectiveVia('def', p));
  return { targets, vias, entries };
}

/**
 * Process rules as the ip rules of the addresses each process uses right now
 * (`procIps`: name → [address]); the stored rules keep `type: 'process'`. No
 * `procIps` (process routing not resolved) → the rules as they are.
 */
function resolveProcessRules(rules, procIps) {
  if (!isObj(procIps)) return rules;
  return (Array.isArray(rules) ? rules : []).map((r) => {
    if (!r || r.type !== 'process' || !r.value) return r;
    const out = { type: 'ip', value: (procIps[r.value] || []).join(','), target: r.target };
    if (r.via != null) out.via = r.via;
    return out;
  });
}

/* ------------------------------ reconnect state ------------------------------ */

const profileState = (p) => (p ? JSON.stringify(Object.assign({}, p, { name: null })) : null);
const chainState = (c) => (c ? JSON.stringify(Array.isArray(c.members) ? c.members : []) : null);

/**
 * What a live connection's routing is made of: its profile (an advanced plan)
 * and the chains it uses — as targets, as bases, the pool's, or the chain it
 * was connected to directly (a chain plan carries no id: the connect's id is
 * it). Names are left out: a rename changes no config.
 */
function liveRoutingOf({ serverId, plan, profiles, chains } = {}) {
  const p = isObj(plan) ? plan : {};
  const ids = new Set();
  const visit = (tg) => { if (typeof tg === 'string' && tg.indexOf('chain:') === 0) ids.add(tg.slice('chain:'.length)); };
  let profileId = null;
  if (p.mode === 'advanced') {
    profileId = p.profileId || null;
    const t = advancedTargets(p);
    t.targets.forEach(visit);
    t.vias.forEach(visit);
  } else if (p.mode === 'pool') {
    for (const e of p.entries || []) if (e) visit(e.target);
    visit(p.primary);
  } else if (p.mode === 'chain' && typeof serverId === 'string' && serverId) {
    ids.add(serverId);
  }
  const byId = new Map((Array.isArray(chains) ? chains : []).filter((c) => c && c.id).map((c) => [c.id, c]));
  const state = {};
  for (const id of ids) state[id] = chainState(byId.get(id));
  const profile = profileId ? (Array.isArray(profiles) ? profiles : []).find((x) => x && x.id === profileId) : null;
  return { profileId, profile: profileState(profile), chains: state };
}

/**
 * The pending-reconnect keys an edit since `live` (liveRoutingOf) raises:
 * 'routingProfiles' — the live profile changed or is gone; 'chains' — a chain the
 * connection uses changed or is gone.
 */
function routingPendingKeys(live, profiles, chains) {
  if (!isObj(live)) return [];
  const keys = [];
  if (live.profileId) {
    const now = (Array.isArray(profiles) ? profiles : []).find((x) => x && x.id === live.profileId);
    if (profileState(now) !== live.profile) keys.push('routingProfiles');
  }
  const byId = new Map((Array.isArray(chains) ? chains : []).filter((c) => c && c.id).map((c) => [c.id, c]));
  if (Object.keys(live.chains || {}).some((id) => chainState(byId.get(id)) !== live.chains[id])) keys.push('chains');
  return keys;
}

module.exports = {
  VIA_INHERIT, VIA_NONE, DEFAULT_PROFILE_ID, ADVANCED,
  newProfileId, normalizeProfile, migrateProfiles, mirrorToSettings, mirrorFromSettings, profileFromSettings,
  isAdvancedSelection, selectionIdOf, profileIdOf, effectiveVia, advancedTargets, resolveProcessRules,
  liveRoutingOf, routingPendingKeys
};
