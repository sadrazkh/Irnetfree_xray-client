# JSON configs and JSON subscriptions — design (sub-project 1 of 3)

Owner's request, 2026-10-08: "support JSON for links or subscriptions like this one — it must support everything". The
example `https://panel.zynalo.ir/sub/…` answers this app's User-Agent (`XrayClient/1.0 (subscription)`) with
`application/json`. That response is an array of 40 complete Xray configs:
- 38 are servers: `vless` + `ws` + `tls`, tagged `proxy`, with `direct`/`block` and three routing rules.
- 2 are info rows, holding only `freedom` (`remarks` "📅 انقضا…", "📦 حجم باقی مانده…").

It answers v2rayN with base64 links, sing-box with sing-box JSON, and Clash with YAML. Today `parseMany` reads none
of this JSON.

The owner's choices:
- order: JSON first and released, then routing profiles + shared-hop chains + flow view (2) with shareable bundles
  (3);
- model: **full by default, a per-server "run raw" switch**;
- sing-box JSON is included.

Every platform: Windows, macOS, Linux and the router (shared `src/main`, the router's web UI is `src/renderer`) and
Android.

## What is read

- **Xray JSON**:
  - one config object (it has `outbounds`), or an array of them;
  - the same text base64-encoded (a subscription body that decodes to `[`/`{`);
  - pasted into the add box, or answered by a subscription. Detected before the link parser runs.
- **sing-box JSON**: an object whose `outbounds` carry `type` (vless, vmess, trojan, shadowsocks, hysteria2,
  wireguard, socks, http).
  - Each one becomes an ordinary server, as if imported from its link.
  - `selector`, `urltest`, `direct`, `block` and `dns` are skipped. A `detour` is noted in the name ("via <tag>"), not
    chained.
  - tuic, anytls and the rest are reported by name, as unsupported links are today.
- **Clash YAML** is not read: "Clash YAML is not supported — use the subscription link". This app's User-Agent
  already gets JSON or links.

## One Xray config → one server (or several)

- **Name**: `remarks`; else `ps`; else the main outbound's address:port.
- **Main outbound**:
  1. the outbound of the routing rule that catches everything left over — the last rule with no `domain`, `ip`,
     `port`, `protocol` or `inboundTag`, or the one with `network: "tcp,udp"`;
  2. else the outbound tagged `proxy`;
  3. else the first outbound whose protocol is a proxy protocol (vless, vmess, trojan, shadowsocks, socks, http,
     wireguard, hysteria).
- **Balancer**: when the catch-all names a `balancerTag`, every outbound the balancer's `selector` matches becomes
  its own server, named `<remarks> · <tag>`.
- **Helper outbounds** (`extraOutbounds`): every outbound the main one reaches through `streamSettings.sockopt.dialerProxy`
  or `proxySettings.tag`, recursively, kept verbatim. Examples: a `freedom` with `fragment` or `noises`, the hops of a
  chain.
  - `mux`, `finalmask`, `sockopt` and everything else on the main outbound are kept verbatim.
- **Info rows**: a config with no proxy outbound at all (only freedom, blackhole or dns) is not a server, and is not an
  error. The subscription's usage header already carries volume and expiry.
- **Record**: the record is what a link produces — `id`, `name`, `protocol`, `address`, `port`, `outbound` (the main
  outbound, tag removed) — plus four fields:
  - `source: 'json'`;
  - `json` — that one config, as an object;
  - `extraOutbounds` — the helpers, with their original tags;
  - `jsonMode: 'full' | 'raw'` — default `'full'`.

  `raw` is the config's canonical minified JSON text, so a subscription refresh matches it: same text → same server,
  then the existing identity passes on the main outbound. User edits survive a refresh as they do for links.

## Full mode (default): inside the app

- The main outbound is the server's outbound everywhere: ping, ⚡/📶, chains, advanced routing, pool, mux probe and
  the sing-box translation.
- `buildConfig` writes the helpers next to it:
  - Each helper's tag becomes `<outboundTag>~<helperTag>`.
  - Every `dialerProxy` / `proxySettings.tag` that pointed at a helper is rewritten to match.
  - So two JSON servers in one advanced-routing config never collide.
  - TUN binding (`bindDirectDials`), entry-host pinning and fragments see the helpers like any other outbound.
- **In a chain**, a JSON server that is not the first hop dials through the hop before it. Its own `dialerProxy` to a
  helper is then replaced, and the helpers it no longer uses are left out (as `applyFragments` already does for
  chained hops).
- The config's own `routing`, `dns`, `inbounds`, `policy`, `observatory`, `log` and `stats` are not used: the app's
  routing mode, DNS plan, leak guard and TUN apply. The edit view says what they were (for example "its own routing: 3
  rules — geosite:private → direct, geoip:ir → direct, everything else → proxy").

## Raw mode (per server): exactly as written

- Connecting runs `json` itself, with two changes:
  - its `inbounds` are replaced by the app's own local ones (the SOCKS/HTTP ports from Settings, plus what the app's
    stats need), so the system proxy and TUN reach it;
  - `log.loglevel` comes from Settings.

  Its routing, DNS, balancers, observatory, policy and fakedns run as written.
- Only for a single-server connect. In a chain, advanced routing or the pool, a raw-mode server is used in its full
  form, and the log says so once.
- The app's DNS management, leak guard and routing modes do not apply. The switch says so in one line.
- Ping/⚡ measure the main outbound, as in full mode.

## The UI (desktop and the router's web UI; Android the same in its own style)

- A small `JSON` badge on the server's card.
- The edit view of a JSON server:
  - the name;
  - the mode switch, Full / Raw, with its one line;
  - the config itself in a monospace editor, validated on save. A config that no longer has a proxy outbound is
    refused with the reason; saving re-derives the main outbound and helpers;
  - "Copy JSON";
  - the not-applied summary (full mode).

  The link fields are not shown for a JSON server, so the JSON stays the one source.
- Copy gives the config's JSON (pretty). QR shows the minified JSON when it fits, else says "too large for a QR — use
  Copy".
- The add box takes pasted JSON as it takes links. fa + en.

## Unchanged

Links, base64 subscriptions, the configs every existing server builds (byte-identical — the before/after golden
check), engine choice, mux, chains and advanced routing for non-JSON servers.

## Tests and checks

- **Sanitized fixtures** in `tests/fixtures/json/`, shared by the JVM tests through `../../tests/fixtures/json/`:
  - a sanitized excerpt of the owner's subscription (2 info rows + 5 servers, fake ids and example.com hosts);
  - a fragment helper through `dialerProxy`;
  - a 2-hop chain through `proxySettings`;
  - a balancer;
  - an info row;
  - a sing-box config.
- Builder output for each, both modes.
- `scripts/validate-configs.js` hands the full- and raw-mode configs to the cores in the CI `cores` job.
- Live import of the owner's subscription; one connect in each mode on this machine's line (core bound to Wi-Fi, the
  owner's running app untouched).
