# Model assignment — which model implements what

Cost tiers (Agent tool `model` values): **haiku** < **sonnet** < **opus** < **fable**.
The rule: the more a mistake would be *invisible* (a leak, a routing order that silently
sends traffic the wrong way, a privileged system change that survives a crash), the more
expensive the implementer — and the reviewer is never cheaper than the implementer.

Roles per task in subagent-driven execution:

| Role | Who |
|---|---|
| Orchestrator (reads plan, dispatches, gates) | the current session (fable) |
| Implementer | per the tables below |
| Spec-compliance review | sonnet (for tiers ★/★★) · opus (for ★★★/★★★★) |
| Code-quality review | one tier above the implementer, capped at opus |

Tier legend: ★ cheap/mechanical · ★★ ordinary logic with tests · ★★★ protocol/precision or
touches the connect path · ★★★★ privileged system changes, leak-relevant, unverifiable locally.

## Plan A — phases 0 + 1 (this plan), per task

| Task | What | Tier | Implementer | Why |
|---|---|---|---|---|
| 1 | CSS flex fix | ★ | haiku | two lines, visually verified |
| 2 | `guard.js` + server wiring, `allowLan` | ★★ | sonnet | security-relevant but small and fully unit-tested |
| 3 | pool `apiPort` reservation | ★ | haiku | one line + one test |
| 4 | shared `assets.js`, `engineExe(platform)` | ★★ | sonnet | touches main + service, tests cover it |
| 5 | `http://` proxy links (parser + smartImport) | ★★ | sonnet | regex must reject subscription URLs; tests pin it |
| 6 | `saveSettings` partials (every caller) | ★★ | sonnet | mechanical but easy to miss a caller; browser-verified |
| 7 | hide custom-rules card | ★ | haiku | |
| 8 | downloader temp cleanup + http for tests | ★★ | sonnet | |
| 9 | SOCKS5 reply buffering | ★★★ | opus | protocol state machine; `unshift` of leftover bytes is subtle |
| 10 | geo note | ★ | haiku | |
| 11 | engines registry | ★★ | sonnet | data + tests |
| 12 | per-engine download | ★★ | sonnet | |
| 13 | `XrayManager` fallback + `validateWithFallback` | ★★★ | opus | decides which core runs; both directions of fallback; tested with monkeypatched validate |
| 14 | `engineChoice.js` + `doConnect`/`rebuildActiveConfig`/ping wiring in main **and** service | ★★★ | opus | touches the connect path in two files that must stay identical |
| 15 | settings/IPC/i18n/UI for two cores | ★★ | sonnet | many files, all mechanical; settingsMeta test guards the strings |
| 16 | README + CI | ★ | haiku | |

Batches that can run in parallel (no shared files): {1, 3, 7, 10} · {2, 8} · {4, 5} · {11 → 12}.
Serial: 13 → 14 → 15 → 16.

## Phases 2–8 (future plans), per phase

| Phase | Tier | Implementer | Reviewer | Why |
|---|---|---|---|---|
| 2 — DNS + routing (DoH, `:53` hijack, direct resolvers, `dnsManaged`, `ipv6`, live repro) | ★★★★ | **fable** | opus | rule order and DNS server selection decide whether traffic leaks or bypass works at all; the repro with a real config needs judgement, not just tests |
| 3 — sing-box TUN + leak guard (Windows firewall, adapter-DNS override + crash repair, mac pf/`networksetup`, server switch) | ★★★★ | **fable** | opus | privileged, persistent side effects; mac path written blind; the whole "no leak" promise lives here |
| 4 — standard finalmask / `fm` / `cs` / `fp=unsafe` (parser + config builder + core-version gate) | ★★★ | opus | opus | exact upstream JSON shapes; a wrong key makes the core refuse the config. The edit-form UI part of phase 4 can go to **sonnet** as a separate task |
| 5 — stats via `metrics.listen` | ★★ | sonnet | sonnet | small, fixture-tested |
| 6 — WireGuard `.conf` import + real `wireguard://` export | ★★ | sonnet | sonnet | INI parser with tests |
| 7 — light theme | ★ | haiku (CSS) + sonnet (nativeTheme wiring) | sonnet | verified by screenshots |
| 8 — Android sync (Kotlin parser/builder parity, Compose focus bugs) | ★★★ | opus | opus | no local test harness for Kotlin; parity with JS tests must be reasoned, not run |

Rule of thumb when a task is split further later: anything under `src/main/tun*`, `leakGuard`,
`dnsBuilder`, `configBuilder` routing order, or `parser.js` link semantics is ★★★ or above;
anything under `src/renderer` that only renders state, and any docs/i18n/CSS, is ★ or ★★.
