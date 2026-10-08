# Routing profiles, "via a base", the flow tree and share links — design (sub-projects 2 + 3)

Owner's request, 2026-10-08:
- one config that reaches everywhere, with other targets riding on it (for example two chains that both leave through
  one config — "but it may not be");
- several advanced routings;
- the traffic and routing shown clearly enough for anyone to understand and change;
- advanced routing, chains and their combination copyable as a link that carries everything needed;
- "without breaking anything".

His choices (2026-10-09):
- **"via" per target**, as an option — today's chains stay exactly as they are and usable;
- **profiles with their own rules, chains and bases shared**;
- **the share link carries everything, with a warning**;
- **an interactive tree view**;
- the design was approved as written, on every platform (desktop, the router's web UI + LuCI's picker, Android).

## 1. Routing profiles

- **Store key** `routingProfiles: [{ id, name, rules, def, defVia, useMode, base }]`:
  - `id`: `rp-<base36 time><rand>`, matching `/^[\w-]+$/`.
  - `rules`: today's `routeRules` items (`{ type: 'ip'|'domain'|'port'|'process', value, target }`) plus an optional
    `via`.
  - `def`: today's `routeDefault`.
  - `defVia`: the via of the default.
  - `useMode`: today's `advancedUseMode`.
  - `base`: an optional profile base — a server id or `chain:<id>`; `null` = none.
- **Migration**:
  - On first start with no `routingProfiles`, today's settings become profile `rp-default`, named "Advanced routing"
    / «روتینگ پیشرفته»: `rules` = `routeRules`, `def` = `routeDefault`, `useMode` = `advancedUseMode`, no vias, no
    base.
  - The settings keys stay and mirror profile `rp-default`: an old backup, an older app on the same store and
    Android's legacy reader still see them.
- **Selection ids**:
  - `__advanced__:<profileId>` connects that profile.
  - Plain `__advanced__` (LuCI, old stores, old selections) = the first profile.
  - The home picker has one "🧭 <name>" row per profile that has rules or a default.
  - LuCI's connect list has one item per profile.
  - The router's boot intent keeps working with either form.
- `advancedRouting` stays the "show advanced routing" switch.
- **Reconnect**: editing the profile, a chain or a base that the live connection uses raises the existing
  "reconnect needed" state, exactly as a server edit does today. Today a chain or pool edit raises nothing; this fixes
  it for chains and profiles.

## 2. "Via a base"

- **Values**: a rule's `via` and a profile's `defVia` take `'inherit'` (default; the profile's `base` if set, else
  none), `'none'`, or a target (a server id or `chain:<id>`). `direct` and `block` never take a via.
- **Builder** (configBuilder's registry):
  - A base becomes one outbound group, tagged `base-<id>` (a chain base: its hops `base-chain-<cid>-h<i>`, exit
    `base-chain-<cid>`). It is shared by every target that goes through it.
  - A target through a base gets its own outbound, `out-<id>@<baseKey>` (a chain: `out-chain-<cid>@<baseKey>`, hops
    `…-h<i>`). The outbound that would dial by itself — a server's own, a chain's first hop — dials through the base
    (`sockopt.dialerProxy = <base exit tag>`).
  - A JSON server's own helper dialer is replaced and its helpers left out, as for a chain's later hop.
  - The same target used without a via keeps today's `out-<id>`.
- **Mux** stays on direct server targets only. A base and anything through it never get mux.
- **Entry addresses** (TUN bypass, the strict guard's holes, name pinning): a via target is not an entry; its base's
  entry is. `planServers` includes bases.
- **Unchanged when no via is set** (every profile migrated from today): the config is byte-identical — the golden
  check proves it.
- **A base that no longer exists** (a deleted server, an emptied chain) makes the connect refuse with a plain message,
  as a missing default does today. The UI marks the rule.

## 3. The flow tree (routing page)

- **Per profile**, left to right (RTL mirrored): the rules (type icon and a short value summary; consecutive rules to
  the same target grouped) → the targets (server, chain, direct, block) → the bases (each drawn once, with every
  target through it pointing at it).
- **Default**: the default rule is "everything else".
- **Live traffic**: while that profile is connected, each branch shows its live speed — the per-outbound stats the home
  path already reads.
- **Clicks**:
  - a rule opens its editor row;
  - a target or base opens that server's or chain's editor;
  - a dangling reference is drawn in the danger colour with its reason.
- **Rendering**: HTML/SVG in the renderer, responsive, keyboard-reachable, no new dependency.
- **The home screen's small path** shows "via <base>" where it applies.
- **Android**: the same tree as a vertical list (rule → target → base), in the app's Compose style.

## 4. Share links

- **Text format**: `irnetfree://routing/<base64url(deflate-raw(JSON))>`, one line.
- **Payload**: `{ v: 1, kind: 'profile'|'chain', profile?, chains: [...], servers: [...] }`:
  - Inside the payload, servers and chains are named by local keys (`s1…`, `c1…`), never by the sender's ids.
  - `servers`: `{ key, name, link }`, where `link` is what Copy gives for that server — a share link, or the JSON text
    for a JSON server.
  - `chains`: `{ key, name, members: [serverKey] }`.
  - `profile`: the profile with every target, via and base rewritten to those keys. Its `useMode` is the only setting
    carried; the receiver's own routing mode, DNS and the rest stay theirs.
- **Copy**:
  - "Copy link" on each profile and each chain card. It warns once per copy that server details are inside.
  - QR when the text is ≤ 1,700 bytes, else "too large for a QR — use Copy".
- **Import**:
  - The add box and paste recognise `irnetfree://routing/`. A preview shows the name, rules, chains, servers already
    here, new servers and anything unreadable, then Import.
  - Servers match existing ones by their strict identity and are reused; new ones are added by hand (no subscription).
  - Chains with the same members (after mapping) and name are reused, else created.
  - The profile is added as new, its name de-duplicated ("Work (2)"). A chain link imports its chain and servers only.
  - Malformed, oversized (> 64 KB decoded) or unknown-version text is refused with the reason, and nothing is written.
- **Android** reads and writes the same format (java.util.zip raw deflate + base64url) with the same preview.

## Unchanged

Servers, subscriptions, simple routing modes, the pool, chains used as targets without a via, JSON servers, mux.
Configs built from today's settings are byte-identical.

## Tests

- Migration (settings → `rp-default`, mirror both ways) and selection ids (`__advanced__`, `__advanced__:<id>`).
- Builder outputs for via:
  - a server through a server base;
  - a chain through a chain base;
  - two targets sharing one base (one base outbound);
  - a JSON server through a base;
  - inherit / none / explicit;
  - a dangling base → refusal.
- Golden byte-identity for every existing shape.
- Share:
  - encode → decode round trip;
  - import into an empty and a populated store (dedupe, name suffix);
  - hostile input (truncated, huge, bad base64, a wrong `v`) refused;
  - a QR-size decision.
- The CI `cores` job: via configs accepted by Xray and PattN.
- Renderer: the profile list, via pickers, tree nodes and edges for the fixtures, share and import dialogs, fa + en.
- Android JVM tests mirror the desktop's (the same payloads round-trip across platforms: a desktop-made link imports on
  Android and back — shared fixture text in `tests/fixtures/routing/`).
