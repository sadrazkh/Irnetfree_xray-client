Last verified: 2026-11-08
Scope: "Owed" and "Not proven" sections of `docs/releases/`, `docs/superpowers/plans/`, and the findings in [KNOWN_ISSUES_AND_TECH_DEBT.md](KNOWN_ISSUES_AND_TECH_DEBT.md), at commit 3e5b74d.

# Roadmap

No roadmap document exists in the repo. Everything here is **derived**: owed items are [V] as quoted from the named release note; the priority order is a **[R]** proposal for the owner to confirm (OQ-1).

## P0: Acceptance owed on real hardware

The largest gap in the project. Each row needs the owner's device.

| Target | Run | Source note |
|---|---|---|
| Android | Connect, disconnect, cancel, server switch; stall recovery; deep links and Share; groups set-aside rebuild; Persian RTL | v1.29.1, v1.30.0, v1.40.1, v1.44.1, v1.45.0, v1.45.5 |
| Router | Current build after updating; sniffing behaviour on advanced profiles; captive sign-in on real phones; shaper with `tc`; site-usage CPU load | v1.33.0, v1.38.1, v1.40.0, v1.44.0, v1.45.2 |
| Windows real TUN | Domain rules through Connections tab; per-app targets; SNI spoof; hello cut on real chains; link handler when elevated | v1.38.0, v1.45.1, v1.45.3, v1.45.5, v1.47.0 |
| macOS | Connect, sleep and wake, quit; native service | v1.7.1, v1.14.0 |
| Network | WARP sign-up and WARP+; two real internets over a real period; a real TUIC or AnyTLS server | v1.25.0, v1.32.0, v1.36.0 |

## P1: Integrity and safety

| Item | Ref | Why first |
|---|---|---|
| Verify downloaded cores | KI-005 | Elevated code from the network |
| Fail a release whose APK lacks `libv2ray` or hev | KI-020 | A silently broken tunnel in a tag |
| Router UI token and exposure | KI-012 | LAN-reachable control of the gateway |
| Credentials at rest, Android backup flag | KI-013, KI-014 | Depends on OQ-10 |
| Electron upgrade | KI-015 | Depends on a support check [A] |
| Add root licence file | KI-010 | Public repo; depends on OQ-12 |

## P2: Finish what is half-built

| Item | Ref |
|---|---|
| Decide SNI spoof on the router: implement, or remove from the router's lists | KI-007, OQ-4 |
| Android sing-box pin, and Android's later-hop hello cut | KI-008, KI-030 |
| hev 2.17+ on Android | KI-036, OQ-8 |
| Say on screen when advanced routing's default is dead | KI-028 |
| Pinned TUIC and AnyTLS | KI-032, OQ-6 |
| Windows hotspot sign-in, "step 2" | v1.35.0, OQ-15 |
| dialMode with fragment or noise | KI-033 |

## P3: Reduce drift

| Item | Ref |
|---|---|
| One connect sequence for `main.js` and `service.js` | KI-001, OQ-3 |
| More shared fixtures for the Android port | KI-002 |
| Split `app.js` and `MainActivity.kt` as touched | KI-003 |
| Fix stale comments and pointers | KI-004, KI-009, KI-011, KI-019 |
| Retire legacy chain and tun2socks when a migration is agreed | KI-018 |

## Not on this list

Anything not in the repo. Plans in `docs/superpowers/plans/` describe completed rounds, so they are history, not backlog [V: each matches a shipped tag].
