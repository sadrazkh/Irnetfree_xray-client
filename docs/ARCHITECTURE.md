Last verified: 2026-11-08
Scope: `src/main`, `src/server`, `src/preload`, `src/renderer` (structure), `src/modules/lanUsers`, `openwrt/`, `android/app/src/main`, `native/macos`, `relay/`, at commit 3e5b74d. Read only.

# Architecture

Labels: **[V]** Verified (evidence named), **[A]** Assumption, **[R]** Recommendation.

## 1. Component map

```mermaid
flowchart TB
  subgraph Desktop["Desktop: Electron"]
    R1["Renderer<br/>src/renderer (index.html, app.js)"]
    P["Preload<br/>src/preload/preload.js"]
    M["Main process<br/>src/main/main.js"]
    R1 -- "window.api" --> P
    P -- "IPC invoke" --> M
    M -- "log, status, stats, ..." --> P
  end

  subgraph Shared["Shared pure logic and managers: src/main/*, src/modules/lanUsers"]
    L1["parser, jsonImport, subscription"]
    L2["configBuilder, dnsBuilder, singboxBuilder, coreCompat"]
    L3["engineChoice, xrayManager, downloader"]
    L4["tunSingbox, tunManager, nativeMacTun, tunOpenwrt"]
    L5["leakGuard, sysproxy, stats, usage"]
  end

  subgraph Headless["Headless: Node, Linux server or OpenWrt"]
    R2["Same renderer in a browser<br/>+ src/server/web-api.js"]
    SRV["src/server/server.js<br/>POST /rpc, GET /events, POST /luci/*"]
    SVC["src/server/service.js<br/>createService().invoke"]
    LUCI["LuCI views + rpcd plugin<br/>openwrt/files"]
    AG["Remote agent<br/>src/server/remote"]
    R2 --> SRV --> SVC
    LUCI -- "loopback, token in body" --> SRV
    AG --> SRV
  end

  subgraph Cores["Core processes"]
    X["xray / xray-pattn<br/>proxy core"]
    SB["sing-box<br/>TUN forwarder or per-config core"]
  end

  subgraph Android["Android: Kotlin + Compose"]
    UI["ui/MainActivity.kt"]
    VS["vpn/XrayVpnService.kt"]
    KC["core/* port of parser and builders"]
    LV["libv2ray in-process Xray"]
    SP["Subprocess cores<br/>libxraypattn.so, libsingbox.so"]
    HEV["hev-socks5-tunnel<br/>TUN to local SOCKS"]
    UI --> VS --> KC
    VS --> LV
    VS --> SP
    VS --> HEV
  end

  MN["Native macOS LaunchDaemon<br/>native/macos, opt-in"]
  REL["Relay<br/>relay/server.js"]

  M --> Shared
  SVC --> Shared
  L3 --> X
  L3 --> SB
  L4 --> SB
  L4 -. "tunBackend native-macos" .-> MN
  AG -- "outbound WebSocket" --> REL
```

Evidence [V]: requires at the top of `main.js` and `service.js`; `server.js` `handle`; `openwrt/files/rpcd/luci.irnetfree` (POST to `/luci/<method>`); `XrayVpnService.startCore`; `native/macos/Bridge.swift` (`SMAppService.daemon`); `src/server/remote/agent.js`.

| Boundary | Mechanism | Evidence [V] |
|---|---|---|
| Renderer to main | `contextBridge` `window.api`, `ipcRenderer.invoke`; `contextIsolation: true`, `nodeIntegration: false`, `sandbox: false` | `preload.js`; `createWindow` in `main.js` |
| Browser to headless | `POST /rpc {channel,arg}`, `GET /events` SSE, same channel names | `web-api.js`; `server.js` `handle`; `service.js` `handlers` |
| LuCI to service | rpcd plugin posts to `/luci/<method>` from loopback, token in body | `src/server/luciApi.js`; `isLoopbackPeer` |
| Router to relay | Outbound WebSocket, binary frames, device token | `src/server/remote/agent.js`, `frames.js` |
| App to core | Spawned process, JSON config file, `xray run -test` first; live counters over HTTP `/debug/vars` | `xrayManager.js` `validateWithFallback`, `start`; `stats.js` |

## 2. Connect path (desktop)

`service.js` follows the same steps in its own `connectOnce`, plus router gates. Android's path is in section 5.

```mermaid
sequenceDiagram
  participant UI as Renderer
  participant Main as main.js doConnect/connectOnce
  participant B as buildActive
  participant XM as XrayManager
  participant T as TUN backend
  participant G as LeakGuard
  UI->>Main: connect(serverId)
  Main->>Main: connGen token, disarm kill switch
  Main->>Main: effectiveSettings (process IPs)
  Main->>Main: pathReadsHello (does the way out read names)
  Main->>Main: ensureCertPins (first-use TLS pin)
  Main->>Main: withWgEndpointIps + withEntryHostIps
  Main->>Main: muxFor (auto mode tests a server)
  Main->>T: makeTun, prepare, physicalInterface
  Main->>B: buildPlan, chooseEngine, buildConfig or buildSingboxConfig
  B-->>Main: plan, config, engine, entryAddrs
  Main->>UI: status connecting
  Main->>XM: validateWithFallback (core -test, version gates)
  XM-->>Main: runEngine or refusal
  Main->>XM: start(config, runEngine)
  Main->>Main: systemProxy if set
  Main->>T: start(socksPort, bypass list, dns, opts)
  Main->>G: engage (standard or strict) if the tunnel is up
  Main->>Main: firewall for LAN sharing
  Main->>Main: stats, watchers (net, route, proc)
  Main->>UI: status connected (tun, tunError, guardError, notices)
```

Rules that shape this path [V: all in `connectOnce`, `main.js`]:

- Every `await` is followed by `stale()`: a newer connect or a disconnect overtakes the call through `connGen`, and `giveWay` undoes what this call started.
- TUN failure is **not** a connect failure. The call stays connected proxy-only and returns `tunError`. See KI-004 for the comment that says otherwise.
- A failure on the core's `-test` becomes a named error (ECH, MASQUE, PattN OOB, plaintext).
- `startedTuns` tracks every backend a connect started, so a replaced `tun` can still be torn down.

## 3. How a config is built

```mermaid
flowchart TD
  ID["Target id: server, group, chain id,<br/>__chain__, __pool__, __advanced__:profile"] --> PLAN["buildPlan<br/>mode: single, chain, pool, advanced<br/>entryAddrs, refuses broken chains"]
  PLAN --> RAW{"JSON server<br/>set to raw?"}
  RAW -- yes --> RC["buildRawConfig<br/>Xray format, as written"]
  RAW -- no --> ENG["chooseEngine + resolveEngine"]
  ENG --> F{"Engine format"}
  F -- sing-box --> SBB["buildSingboxConfig<br/>single server only<br/>no routing rules"]
  SBB -. "cannot carry it" .-> XBB
  F -- xray --> XBB["buildConfig"]
  XBB --> POOL{"mode pool?"}
  POOL -- yes --> BP["buildPoolConfig<br/>one inbound pair per entry"]
  POOL -- no --> O["Outbounds and routing rules<br/>makeRegistry or buildChainOutbounds<br/>custom rules, geo rules"]
  O --> LU["lanUsers and per-app outbounds"]
  LU --> DNS["buildDnsPlan: rules first, port-53 hijack"]
  DNS --> MW["applyMultiWan"]
  MW --> GR["expandGroups: members, balancer, observatory"]
  GR --> WG["WireGuard sanitize, endpoint IPs, pinEntryHosts"]
  WG --> CUT["cutHellos if the path reads names<br/>applyFragments, applyEchOutbounds"]
  CUT --> BIND["bindDirectDials under TUN"]
  BIND --> FIN["inbounds, metrics, policy, routing<br/>applyLanUsers, applyAppRoutes<br/>applyDirectPorts, relayHopDials"]
  FIN --> CC["At start: xrayManager.forCore<br/>coreCompat.adaptForCore by core version"]
```

Evidence [V]: `buildPlan`, `buildActive` in `main.js`; `buildConfig`, `buildPoolConfig`, `buildRawConfig`, `expandGroups`, `relayHopDials` in `configBuilder.js`; `buildSingboxConfig` in `singboxBuilder.js`; `forCore` in `xrayManager.js`.

Order is load-bearing: the DNS rules go ahead of the private-IP bypass, group rules ahead of the DNS rules, and `relayHopDials` runs last (comments inside `buildConfig`) [V].

## 4. TUN backends

| Backend | File | Chosen when | Traffic path | Evidence [V] |
|---|---|---|---|---|
| sing-box | `tunSingbox.js` | Default on desktop when installed | sing-box `tun` inbound with `auto_route`, forwarding to the core's SOCKS inbound | `makeTun`; file header |
| tun2socks | `tunManager.js` | `tunBackend` set to it, or sing-box missing | wintun or utun, manual routes | `makeTun` |
| Native macOS | `nativeMacTun.js` + `native/macos` | darwin and `tunBackend: 'native-macos'` only | Root LaunchDaemon runs sing-box | `makeTun`; `TunnelService.swift` |
| OpenWrt gateway | `tunOpenwrt.js` | Always on a router | Composes sing-box, adds an nft table and `ip rule` entries | `service.js` `makeTun`; file header |

Under any backend Xray stays the proxy core and the TUN only feeds its SOCKS inbound, except a server running on the sing-box engine, where sing-box's own config serves SOCKS instead [V: `tunSingbox.js` header; `buildActive`].

```mermaid
flowchart LR
  LAN["LAN devices"] --> NFT["nft table inet irnetfree<br/>excluded MACs, users' gates"]
  NFT --> RULE["ip rule before sing-box's own"]
  RULE -- "excluded" --> WAN["WAN via fw4"]
  RULE -- "everything else" --> TUN["sing-box TUN auto_route"]
  TUN --> XR["Xray SOCKS inbound, port-53 hijack"]
  XR --> OUT["Server outbound"]
  KS["nft table inet irnetfree_ks<br/>kill switch, replayed at boot"] -. "rejects forwarded traffic while down" .-> LAN
```

Evidence [V]: header and `setLanUsers` in `tunOpenwrt.js`; header of `killSwitchOpenwrt.js`; `openwrt/files/irnetfree-ks.init`. On a router `managesDns` is true, so the leak guard stays out and dnsmasq is untouched.

## 5. Android session

```mermaid
flowchart TD
  A["connect: MainActivity, Quick Settings tile, Always-on"] --> B["XrayVpnService.prepare<br/>CertPin, DNS, Mux, HelloCut, plan"]
  B --> C["EngineChoice"]
  C --> D["startCore"]
  D --> D1["XrayCore libv2ray in-process, tunFd 0"]
  D --> D2["XrayPattnCore subprocess, arm64 by default"]
  D --> D3["SingboxCore subprocess, arm64 by default"]
  D1 & D2 & D3 --> E["VpnService.Builder establishes TUN<br/>own package excluded"]
  E --> F["hev-socks5-tunnel: TUN to local SOCKS with session credentials"]
  F --> G["Watchers: NetWatch, StallWatch, group watch"]
```

Evidence [V]: `XrayVpnService.kt` class comment, `prepare`, `startCore`; `TunnelSetup.kt`; `core/LocalAuth.kt`; `android/scripts/fetch-libs.sh`. Commands run on one worker thread with a generation number; native stops are bounded (`EngineReset.bounded`).

Cores ship inside the APK, because Android 10 and newer will not execute files an app downloaded [V: comment in `android/scripts/fetch-libs.sh`].

## 6. Failure and recovery

| Concern | Desktop | Router | Android | Evidence [V] |
|---|---|---|---|---|
| Network moved | `netWatcher.js`, `recoverFromNetworkChange` | `wanWatch.js`, `judgeWanChange`: a probe decides before any rebuild | `NetWatch` | those files |
| Core died | `onConnectionDrop`, `runRecovery`, `DropBudget` | `recoverFromDrop`, `backoffAfter`, tunnel watch | restart once, then fail (`onCoreExit`) | `main.js`, `service.js`, `XrayVpnService.kt` |
| Kill switch | Windows firewall rule only (`armKillSwitch`) | nft table `inet irnetfree_ks`, armed from boot | system Always-on / lockdown | `main.js`; `killSwitchOpenwrt.js`; manifest `SUPPORTS_ALWAYS_ON` |
| DNS held across rebuild | `leakGuard.holdForReconnect`, receipt tokens, `tun-state.json` crash record | not used, gateway owns DNS | not applicable | `leakGuard.js` header |
| System proxy recovery | `proxy-journal.json` | same file logic on headless | not applicable | `sysproxy.js` `useProxyJournal` |

## 7. Remote access

```mermaid
sequenceDiagram
  participant Browser
  participant Relay as relay/server.js
  participant Agent as Router agent
  participant UI as Router web UI (loopback)
  Agent->>Relay: WebSocket /_relay/agent, Bearer device token, HELLO
  Browser->>Relay: GET / (session cookie)
  Relay->>Agent: REQ_HEAD, REQ_BODY, REQ_END
  Agent->>UI: HTTP, UI token added on the router
  UI-->>Agent: response
  Agent-->>Relay: RES_HEAD, RES_BODY, RES_END
  Relay-->>Browser: response
```

Evidence [V]: `relay/server.js`, `src/server/remote/agent.js`, `frames.js`. The relay sees plaintext by design (`relay/server.js` header). The Cloudflare Tunnel alternative is `src/server/remote/cloudflared.js`. Details: [docs/remote.md](remote.md).

## 8. Size and shape

Largest files [V: `wc -l`]: `src/renderer/app.js` 11,112; `android/.../ui/MainActivity.kt` 5,185; `src/server/service.js` 4,675; `src/main/main.js` 4,607; `src/renderer/i18n.js` 3,432; `src/renderer/lanUsers.js` 3,349. Pure modules (`parser`, `configBuilder`, `groups`, `routingProfiles`, ...) take no store or Electron, which is what makes the test suite possible [V: headers of those files].
