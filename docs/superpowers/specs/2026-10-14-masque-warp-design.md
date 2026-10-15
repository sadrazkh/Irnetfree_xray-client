# MASQUE + WARP — design (v1.25.0)

Owner: «الف و ب رو شروع کن» (2026-10-14); sample `.superpowers/mockups/masque.html` shown and approved with the three
recommendations: (1) a «ساختن حساب تازه» button that registers a WARP device from the app; (2) «هر دو» (one H3 + one
H2 server) is the default; (3) a MASQUE server is shared as JSON (no invented `masque://`). Added after the owner asked
about domain fronting: an optional cover domain (SNI) in the WARP dialog.
Facts: `research.md` (same folder). Touch-points: `integration-map.md`. Core: Xray ≥ 26.9.30 (plain), ≥ 26.10.10 (WARP);
suggested Xray 26.10.10 / PattN 26.10.13 since v1.24.1.

## 1. The record
A native protocol, like hysteria2 — not a `source:'json'` server — so the field editor works:
```
{ id, name, protocol: 'masque', address, port,
  outbound: { protocol: 'masque', settings: { address, port, remoteDNS? },
              streamSettings: { network: 'masque', masqueSettings: { host?, path?, user?, pass?, headers?, warp? },
                                security: 'tls', tlsSettings: { serverName?, alpn?, fingerprint?, pinnedPeerCertSha256?,
                                verifyPeerCertByName?, echConfigList?, useSystemCA?, … }, finalmask? } },
  raw: <the share JSON, §3> }
```
- `alpn: ["h2"]` = HTTP/2 over TCP; no alpn (or ["h3"]) = HTTP/3 over QUIC. The editor shows it as one seg `masqueHttp`.
- `warp: { privateKey, publicKey, address: [v4/32, v6/128] }` — all three or none; with warp, no user/pass/headers
  Authorization; host/path left unset (the core defaults them for WARP).
- Never: `allowInsecure`, REALITY, `mux.enabled`, sing-box. The WARP private key is a secret like a WireGuard key (kept
  in the store and backups like every other credential; never logged).
- Card tags derived, not stored: `WARP` when `masqueSettings.warp` exists, `h3`/`h2` from alpn.

## 2. Fields (serverFields.js — the one table; Android's copy regenerated)
New ids (all `when: { protocols: ['masque'] }` unless said):
| id | kind | path / special | notes |
|---|---|---|---|
| masqueHttp | seg h3/h2 | special → tlsSettings.alpn (h2 → ["h2"], h3 → delete) | simple; tab protocol |
| masqueHost | text | streamSettings.masqueSettings.host | |
| masquePath | text | streamSettings.masqueSettings.path | placeholder `/.well-known/masque/ip/*/*/` |
| masqueUser / masquePass | text | …masqueSettings.user / .pass | simple (not with WARP) |
| masqueHeaders | json | …masqueSettings.headers | local |
| warpPrivateKey | text (area) | …masqueSettings.warp.privateKey | group warp; simple shows a summary |
| warpPublicKey | text (area) | …masqueSettings.warp.publicKey | group warp |
| warpAddress | list | …masqueSettings.warp.address | group warp |
| remoteDNS | list | settings.remoteDNS | local; advanced |
| useSystemCA | switch | streamSettings.tlsSettings.useSystemCA | local; EVERY TLS protocol (STREAM + hysteria2 + masque), security tls only |
Existing fields extended to masque: sni (serverName), fp (fingerprint — hint: HTTP/2 only), pcs, vcn, ech, echForceQuery,
min/maxVersion, curves, finalMask, engine (options Xray / Xray-PattN only for masque). Not for masque: allowInsecure,
REALITY fields, mux fields, transport fields, cipherSuites. Anti-DPI: `fragment` (TCP) only with HTTP/2, `noise` (UDP)
only with HTTP/3 — through the app's existing dpi-* freedom dialer (applyFragments), proven by validate-configs + probe.
`securitiesOf('masque') = ['tls']`, `hasTransport('masque') = false`, `contextOf` network 'masque', tls forced like hy2.
`createServer` needs: name optional, address, port; WARP: all three warp fields; plain: nothing else (auth optional).
Validation: warp all-or-none; warp excludes user/pass; user has no ':'; warpAddress ≤ 1 v4 + ≤ 1 v6 (bare IPs → /32,/128);
headers JSON object without Host / Capsule-Protocol.

## 3. Sharing — JSON
`buildShareLink(masque)` = one-line JSON: `{"remarks": name, "outbounds": [<outbound without local-only fields>]}`.
- So Copy, QR, routeShare and `raw` all carry it (raw = the share JSON; `parseLink(raw)` failing is tolerated as today).
- jsonImport: a config whose proxy outbounds are exactly ONE `masque` outbound (besides freedom/blackhole/dns) becomes a
  NATIVE masque server (name from `remarks`), so a copy pasted into another IRNetFree is field-editable. Anything else
  with a masque outbound (e.g. a 3x-ui JSON subscription's full configs) becomes a `source:'json'` server as today —
  PROXY_PROTOCOLS gains `masque` so it is no longer silently dropped.
- Desktop and Android the same.

## 4. Running it
- configBuilder: PROXY_OUT += masque; never write mux for it; anti-DPI per HTTP version; no allowInsecure.
- engine: always Xray (or PattN when chosen); sing-box refuses (already: UnsupportedEngineConfig → Xray fallback);
  engineChoice forces Xray for masque; certPin.wantsPin excludes masque; staleCertPins skips h3.
- Version gate (xrayManager, like ECH_SINCE): `MASQUE_SINCE = '26.9.30'`, `MASQUE_WARP_SINCE = '26.10.10'`;
  `usesMasque(config)`, `usesMasqueWarp(config)`; validateWithFallback returns `{ ok:false, masqueUnsupported, coreVersion,
  need }` → main.js / service.js refusal text, both languages: «این سرور MASQUE است و به Xray نسخهٔ ≥ X نیاز دارد —
  از تنظیمات ← فایل‌های موردنیاز به‌روزش کن» / "This MASQUE server needs Xray X or newer — update it under Settings →
  Required files". usesFinalmask exempts network masque.
- latencyTest.udpOnly: masque without h2 (QUIC) → TCP ping refused as for hysteria2; real ping as usual.
- mux: allowlist already excludes; negative tests. Chains / via base / pools: allowed (dialerProxy works).
- backup PROTOCOLS, connectionDiagnostics PROTOCOLS, subscription.serverIdentity (user/pass or warp private key,
  host/path) gain masque.

## 5. WARP («+ WARP»)
Module `src/main/warp.js` (desktop + router):
- `registerWarp({ license, request })` → `{ privateKey, publicKey, address:[v4/32, v6/128], endpoints:{ h3v4, h3v6,
  h2v4, h2v6 }, account:{ id, type, warpPlus } }`:
  1. P-256 key pair locally (`crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' })`); privateKey written as
     PKCS#8 PEM (Xray accepts PEM or base64, PKCS#8 or SEC1).
  2. `POST https://api.cloudflareclient.com/v0a<ver>/reg` (usque body; a throwaway X25519 key, tunnel_type wireguard,
     tos = now) → id, token.
  3. `PATCH /reg/{id}` Bearer token `{ key: base64 SPKI DER, key_type: 'secp256r1', tunnel_type: 'masque' }`.
  4. If `warp_enabled` is not true in the answer: `PATCH /reg/{id}` `{ warp_enabled: true }` and check it.
  5. With a license: `PUT /reg/{id}/account { license }`.
  6. publicKey = `config.peers[0].public_key` (PEM); address = `config.interface.addresses.v4/.v6`; H3 endpoint =
     `peers[0].endpoint.v4` without ":0" (fallback 162.159.198.1), v6 likewise (fallback 2606:4700:103::1); H2 =
     162.159.198.2 / 2606:4700:103::2.
  - API version + headers as constants in one place (wgcf 2.3.0's v0a5641 / `CF-Client-Version: a-6.38.9-5641` /
    `User-Agent: 1.1.1.1/6.38.9-5641 (Android 16.0.0)`, TLS 1.2 + ALPN http/1.1 — the form that avoided 429s).
  - `request` is injectable (tests use a local fake API); the real one goes direct, or through the app's own running
    proxy (the local SOCKS/HTTP inbound) when the user picks «از اتصال روشن برنامه» — refuse that choice when not
    connected. Errors mapped to clear messages (429 rate limit, network/blocked, 4xx) in both languages. The token and
    private key are never logged.
- `warpServers(reg, { http: 'h3'|'h2'|'both', endpoint: 'auto'|'v6'|'custom', address, cover, antiDpi })` → field
  objects for `parser.createServer` (pure). Names «☁ WARP · H3» / «☁ WARP · H2». `cover` (a domain behind Cloudflare,
  e.g. a whitelisted site): serverName = cover, verifyPeerCertByName = cover (the edge then serves that site's real
  certificate, checked against the core's roots; aa7aa9ad makes pcs/vcn replace the WARP key check), host left to the
  WARP default. Without cover: serverName `consumer-masque.cloudflareclient.com`. antiDpi: H3 → noise (light preset),
  H2 → fragment tlshello (the app's Hide-SNI preset).
- `importUsque(json)` → the same `reg` shape from usque's config.json (private_key SEC1 base64, endpoint_v4,
  endpoint_h2_v4, endpoint_v6, endpoint_pub_key PEM, ipv4, ipv6) for «وارد کردن حساب موجود»; also accepts a pasted
  Xray WARP outbound.
- IPC `servers:addWarp({ mode: 'new'|'import', license, via: 'direct'|'proxy', importText, http, endpoint, address,
  cover, antiDpi })` → `{ ok, servers:[…] , account }` (main.js, service.js, preload.js, web-api.js).

## 6. UI (desktop + router web UI) — as the approved sample
- «+ WARP» button beside «+ WireGuard»; its box joins the mutual hiding of the add boxes. Dialog: step 1 account
  (new: route direct / through the connection, ToS line, optional WARP+ license; import: usque config.json or keys);
  step 2 HTTP version (H3 / H2 / both — default both), endpoint (auto / IPv6 / my clean IP), cover domain (optional,
  with the note that the IP must still be WARP's), anti-DPI switch (on). Progress list, then «دیدن در فهرست».
- Editor: MASQUE in the protocol picker (Pro basics, + Manual); Pro tabs per sample (transport tab disabled with its
  message; security TLS only; advanced: engine Xray/PattN, no Mux, remoteDNS, anti-DPI per HTTP version); Simple view:
  name/address/port, HTTP version, SNI, user/pass or the WARP summary chips, anti-DPI, engine.
- Card: badge `.proto-masque`, tags WARP / h3 / h2. Copy/QR give the JSON (button titles say so).
- Persian and English for every string.

## 7. Android
Mirror §1-5: ServerFields.kt + regenerated table, LinkParser.buildShareLink → JSON, JsonImport masque → native,
ServerEditor create/read/apply masque, EngineChoice forces Xray, CertPin excludes, WARP registration in Kotlin
(KeyPairGenerator EC secp256r1, HttpsURLConnection; «through the connection» via the running core's local proxy), add menu
«WARP (MASQUE)» sheet, edit sheet/Pro fields. Bundled cores already new enough (libv2ray 26.10.10, PattN 26.10.13).

## 8. Proof
- validate-configs: MASQUE plain H3/H2 (user/pass), WARP H3/H2, WARP + cover, with noise / fragment, through the
  suggested Xray and PattN (`xray run -test`).
- probe-masque.js (CI, both cores): a local Xray MASQUE server; the client config from the app's own builder (after
  §1-4 land); H3, H2, wrong password, UDP.
- WARP registration: unit tests against a local fake API (request shapes, warp_enabled, license, errors, the token
  never in logs). The real Cloudflare API is NOT called in tests or by the agents — the owner tests sign-up and
  connecting (direct, cover domain) on a real network.
- Device checks owed: Android WARP sheet; router web UI.
