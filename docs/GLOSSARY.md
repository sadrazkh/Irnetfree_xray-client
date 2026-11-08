Last verified: 2026-11-08
Scope: terms as used in `src/`, `android/`, `openwrt/` and `docs/releases/`, at commit 3e5b74d. Each entry names where the term is defined or used; entries are [V] unless tagged otherwise.

# Glossary

| Term | Meaning | Where |
|---|---|---|
| Advanced routing | Rule-based routing per target, stored as routing profiles | `routingProfiles.js` |
| AnyTLS, TUIC | Protocols only sing-box runs here | `engineChoice.js` `SINGBOX_ONLY` |
| Anti-DPI | Fragment, noise and mask options | `applyFragments`; module `antiDpi` |
| Base (via) | A server or chain a routing target rides on | `routingProfiles.js` |
| `bypass-ir`, `bypass-cn` | Routing modes that send that country's sites direct | `buildRoutingRules` |
| Chain | Ordered hops, the last is the exit | `buildChainOutbounds` |
| Chain relay | Loopback SOCKS that carries TCP hop dials, so the end of a closed connection is not lost | `relayHopDials`; D-017 |
| ConnGen | Generation counter that lets a newer connect or a disconnect overtake a connect in progress | `connectOnce` |
| Core / engine | The proxy binary running a config: Xray, Xray-PattN, sing-box | `engines.js` |
| Corporate WireGuard | A WireGuard peer with its own resolvers and split `AllowedIPs`, often behind a chain | `wgResolvers`, `isSplitTunnelWg` |
| Cut hello | TLS ClientHello split into several records so a name-reading server cannot read it | `helloCut.js` |
| Dead route | The way out stopped answering | `routeWatch.js` |
| Direct ports | Local ports that leave outside the VPN | `directPorts.js` |
| `dialMode` | Xray-PattN socket option; `oob` sends out-of-band bytes | `pattnOobNeeds` |
| dns-out | Xray outbound that answers every port-53 packet | `dnsBuilder.js` |
| ECH / ECH outbound | Encrypted ClientHello; fetching the ECH key through an outbound | `applyEchOutbounds` |
| Entry address | An address the machine itself dials, which must bypass the tunnel | `entryAddressesOf` |
| Exit at the base | A routing target that means leaving from the base itself | `TARGET_BASE` |
| Extensions / modules | Built-in optional features behind a flag | `modules.js` |
| finalmask | Xray option that transforms bytes on the wire | `FINALMASK_SINCE` |
| fw4 | OpenWrt's nftables firewall | `tunOpenwrt.js` |
| Gateway | The router acting as the tunnel for the LAN | `tunOpenwrt.js` |
| Geo files | `geoip.dat`, `geosite.dat` | `assets.js` |
| Group | Several configs used as one, by a balancer | `groups.js` |
| Group eviction | App setting a dead member aside; reloaded or removed live | `groupEvict.js`, `groupLive.js` |
| hev | `hev-socks5-tunnel`, TUN-to-SOCKS on Android | `TProxyService.kt` |
| Hijack (DNS) | Capturing port-53 traffic into the core | `dnsBuilder.js` |
| Hotspot check | Whether a device on the Windows hotspot rides the VPN | `lanUsers/hotspot.js` |
| IRNetFree Plus | A separate tools app, not in this repo | `README.en.md` |
| Kill switch | Blocks internet when the tunnel is down | `armKillSwitch`; `killSwitchOpenwrt.js` |
| LAN user | A person with a login, limits and a config | `lanUsers/model.js` |
| Leak guard | Holding physical adapters' DNS, optionally a firewall | `leakGuard.js` |
| libv2ray | Android Xray library used in-process | `XrayCore.kt` |
| LuCI / rpcd | OpenWrt web admin and its RPC daemon | `openwrt/files/luci`, `rpcd` |
| MASQUE | CONNECT-IP over HTTP/3 or HTTP/2 | `parser.js` `checkMasque` |
| Mux | Multiplexing streams over one connection, decided per server | `mux.js` |
| Multi-internet | Several local links used together | `multiWan.js` |
| Observatory | Xray's outbound health checker | `expandGroups` |
| Owed | Release-notes term: checks a person must still run on a device | `docs/releases/` |
| Path reads names | A way out whose server sniffs TLS names and dials them | `pathReadsHello` |
| PattN | patterniha's Xray fork, `xray-pattn` here | `engines.js` |
| Pin (certificate) | SHA-256 of a leaf, learnt on first use | `certPin.js` |
| Pool | Several exits, each on its own local port | `buildPoolConfig` |
| Probe | A script running real cores to prove behaviour | `scripts/probe-*.js` |
| Raw (JSON server) | A JSON config run exactly as written | `buildRawConfig` |
| Reality | Xray's TLS camouflage transport security | `translateTls` |
| Receipt (guard) | Token that lets a connect release only its own guard | `leakGuard.js` |
| Relay | Self-hosted server carrying requests to a router over its outbound link | `relay/server.js` |
| Reconnect key | A setting baked into a running config | `RECONNECT_KEYS` |
| Skin | One of three looks: console, cockpit, legacy | `skins.css`, `applySkin` |
| Sniffing | The core reading a name from a connection's first bytes | `sniffRules.js` |
| SNI spoof | A forged ClientHello with an allowed name sent before the real one | `sniSpoof.js` |
| Subscription | A URL returning many configs | `subscription.js` |
| Suggested core | The version each app release is verified with | `SUGGESTED` |
| TUN | System-wide virtual adapter | `tunSingbox.js` |
| Transparent mode | Router users identified by device, no proxy setting | `lanUsers/router` |
| uTLS | TLS fingerprint imitation | server editor fields |
| Voucher (card) | A one-time login in a batch | `luVouchers.js`, `model.js` |
| WARP | Cloudflare's service, used as a server over MASQUE or WireGuard | `warp.js` |
| Xray-PattN | See PattN | |
