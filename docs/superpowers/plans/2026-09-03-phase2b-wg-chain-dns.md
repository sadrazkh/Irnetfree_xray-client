# Phase 2b — Corporate WireGuard through a chain: DNS follows the target, AllowedIPs suggestions

Branch: `feature/phase2b-wg-dns` (base: `main` at v0.12.0). Models: T1 and T3 Opus, T2 Fable; Fable
reviews the branch before merge.

## The scenario (owner's report, 2026-09-03)

`Client → VLESS (intermediate) → WireGuard (company)` as a chain, plus one advanced-routing rule
`ip: 192.168.0.0/16, 10.0.0.0/8 → chain`, default → VLESS. The owner expects
`https://gitlab.hawk.tes.systems` (an internal name, resolvable only by the company's resolver
`192.168.60.1` that the `.conf` names in its `DNS =` line) to open with no hosts-file edits and no list
of domains to type.

## What is true in the code today (verified)

1. **The WireGuard edit form corrupts the server.** `src/renderer/app.js` `#editSave` sets
   `fields.address = $('#edWgAddr')` (the *interface* address, e.g. `10.10.10.42/32`) on top of
   `fields.address = $('#edAddress')` (the *endpoint host*). `applyServerEdits` then writes both
   `out.address` and `peer.endpoint = ${addr}:${port}` from that one key → `10.10.10.42/32:42421`,
   and the core fails with `failed to set endpoint … no such host`. Every save of the WG edit form
   does this. The original host survives only in `server.raw` (`wireguard://host:port` from a `.conf`
   import, or the share link).
2. **`DNS =` from the `.conf` is parsed and dropped** (`parser.js` `parseWireguardConf` → `dns`,
   never stored; ledger carried this since plan 2).
3. **Every resolver query goes to the exit.** `dnsBuilder.js` routes `inboundTag: dns-internal` to
   `exitTag`; a query to `192.168.60.1` would leave through the VLESS, not the WireGuard. And the
   resolver list has no server that knows the internal names, so the browser gets NXDOMAIN before any
   IP rule can match.

The owner's document also proposes putting the company DNS **first** in `dns.servers`. Rejected: a
server without `domains` is consulted for every lookup in list order, so every public name on the
machine would travel through the chain to the company resolver (slow, and it hands the company the
browsing history). The design below puts it **last** and lets `expectedIPs` (from AllowedIPs) and
optional search domains decide.

## Data model (T1 defines, T2/T3 consume)

On a WireGuard server record (`store.servers[]`):
- `dns: string[]` — resolver IPs from the `.conf` `DNS =` line / the form (`[]` when none).
- `dnsDomains: string[]` — search domains: the non-IP entries of the same `DNS =` line (wg-quick
  semantics) or typed by the user (`tes.systems, hawk.local`).
- `outbound.settings.peers[0].allowedIPs` — already present.

Share link: `wireguard://…?dns=192.168.60.1,tes.systems` round-trips both (IPs and names split by
`net.isIP`). `.conf` export (if present) writes `DNS = <ips>, <domains>`.

---

### Task 1 (Opus, ★★): WireGuard edit form, DNS field, store repair

**Files:** `src/renderer/app.js` (`readServerFields`, `openEdit`, `#editSave`, WG add form),
`src/renderer/index.html` (`#edWgDns` in `#edWgExtra`, `#wgDns` in the add form), `src/renderer/i18n.js`
(`wg.dns`, `wg.dnsHint` both languages), `src/main/parser.js` (`applyServerEdits`, `makeWireguardServer`,
`parseWireguard`, `parseWireguardConf`, `buildShareLink`, `migrateStoredServer`), `tests/parser.test.js`.

- `#editSave` for wireguard: `fields.localAddress = $('#edWgAddr')`, `fields.dns = $('#edWgDns')`;
  **never touch `fields.address`** (it stays the endpoint host from `#edAddress`).
- `applyServerEdits` wireguard branch: `st.address` from `f.localAddress` (accept the old key only
  if `f.localAddress` is undefined AND `f.address` is not the endpoint host — no: drop the old
  behaviour entirely; the test pins that editing the interface address leaves `peer.endpoint` alone).
  `f.dns != null` → split on commas → IPs to `out.dns`, names to `out.dnsDomains`.
- `parseWireguardConf`: split `DNS =` into `dns: string[]` / `dnsDomains: string[]`.
  `makeWireguardServer` stores both on the record. `parseWireguard` reads `dns=`; `buildShareLink`
  writes it.
- `migrateStoredServer` (runs at boot, idempotent): a wireguard record whose `address` is not a
  host (contains `/`, or is one of `outbound.settings.address`, or is a private IP equal to the
  interface IP) is repaired from `raw`: host/port from `wireguard://host:port` or the link;
  `address`, `port`, `peer.endpoint` rewritten. Unrepairable (no raw host) → left as is, logged once.
  Pin with the owner's exact record: `address: '10.10.10.42/32'`, `port: 42421`, `raw:
  'wireguard://cobra.tes.ca:42421'` → `cobra.tes.ca` / `cobra.tes.ca:42421`.
- Browser check on the headless server (port 7825): edit a WG server's interface address → `store.json`
  endpoint unchanged; type a DNS → `dns`/`dnsDomains` persisted; both languages.

### Task 2 (Fable, ★★★★): the resolver follows the target

**Files:** `src/main/dnsBuilder.js`, `src/main/configBuilder.js`, `tests/dnsBuilder.test.js`,
`tests/configBuilder.test.js`, `scripts/validate-configs.js`.

- `buildDnsPlan(settings, opts)` gains `opts.targetResolvers: [{ address, outboundTag, expectedIPs,
  domains }]`. For each: a server object **appended after the remote list** —
  `{ address, expectedIPs? , domains? (as `domain:<suffix>`), skipFallback: false }` — and a rule
  `{ inboundTag: ['dns-internal'], ip: [address], outboundTag }` placed **before the exit rule** and
  after the direct-resolver rule. Target resolvers never enter `directResolverIps` (they ride the
  target, not `direct`; the private-range rule from the review must not catch them).
  `expectedIPs` = AllowedIPs minus `0.0.0.0/0` / `::/0`; a full-tunnel list → no `expectedIPs`.
  `domains` given → the server is asked first for those names (no DoH round trip, no leak of the
  internal name to the public resolver); without them the DoH NXDOMAIN falls through to it.
- `configBuilder`: `targetResolversFor(plan, reg)` — advanced: every rule target and the default;
  single/chain: the exit; pool: none. A target contributes when it is a WireGuard server with `dns`,
  or a chain whose **last** hop is one. `outboundTag` = `reg.tagFor(target)` (advanced) / the exit tag.
  Dedupe by address.
- Tests: placement (after remote, before nothing else), rule order (direct-resolver → target →
  exit → hijack), `expectedIPs` from AllowedIPs, full tunnel → none, search domains → `domain:` form,
  not in `directResolverIps`/`resolverBypassIps`, advanced `chain:c1` with WG last hop → `out-chain-c1`,
  single WG → `proxy`, pool → nothing, unmanaged → nothing. `validate`: two shapes (advanced chain with
  WG dns + expectedIPs; single WG dns with domains).
- **Owner-run live check** (the only real proof; needs their `.conf`): rule `192.168.0.0/16,
  10.0.0.0/8 → chain`, open the GitLab URL; the log should show the query to `192.168.60.1` leaving
  through the chain tag and the site loading. If the DoH negative answer does not fall through on the
  installed core, the search-domain path is the fallback the UI must nudge toward (T3's note).

### Task 3 (Opus, ★★): suggestions in advanced routing

**Files:** `src/renderer/app.js` (rules editor near `renderRouteRules`/`targetOptionList`),
`src/renderer/index.html` (chip styles if needed), `src/renderer/i18n.js`.

- When a rule's target (or the default) is a WireGuard server, or a chain whose last hop is one:
  under the row a chip **"Suggested from AllowedIPs: 192.168.0.0/16, 10.0.0.0/8 — use"**; clicking
  sets the row's type to `ip` and its value. No chip for a full-tunnel AllowedIPs (say why in a hint).
- If that server has `dns`, an informational line: "Internal names resolve through this target via
  192.168.60.1" and, when `dnsDomains` is empty, "add search domains on the server (tes.systems) to
  resolve them without asking the public DNS first".
- Same for the WG add/edit forms? No — the chip lives in routing only.
- Browser-verified on the headless server (port 7826), both languages, i18n parity count reported.

### Order and review

T1 first (defines the fields). Then T2 ∥ T3. Fable whole-branch review, fix round, merge to `main`,
tag v0.13.0, push.

## Recorded trade-offs (from the branch review, 2026-09-03)

- **`IPOnDemand` under managed DNS** (`routingStrategy`). Every hostname connection that reaches an
  `ip` rule (the private-LAN bypass is in every plan) is resolved through the managed list before it is
  routed. Measured on the real core: when the DoH path through the exit is dead, that is 4 s per server ×
  2 = ~8 s per new name, after which the name still reaches the catch-all intact (correct, just slow).
  Before this branch the connection went to the exit immediately — and `geoip:ir`, the private bypass and
  the corporate range never matched a browser connection at all. Pool mode keeps `IPIfNonMatch` so its
  entries do not wait on the primary's DoH. TUN mode is not newly affected (the OS lookup already went
  through the hijack; the router's lookup hits the cache).
- **Process rules widen.** A `process` rule is rewritten into learned-IP `ip` rules; on demand, a browser
  connection whose name resolves to one of those IPs now takes the process rule's target too (TUN mode
  already did this for IP destinations). Release-note item.
- **`expectedIPs` from AllowedIPs** rejects a split-horizon name the corporate resolver answers with a
  PUBLIC address; such a name then gets no answer rather than the default target. By design.
