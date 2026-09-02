# Model assignment — which model implements what

Two models are available: **Opus 5** (the cheap one) and **Fable 5.1** (expensive, strongest).

The rule: the more a mistake would be *invisible* (a leak, a routing order that silently sends
traffic the wrong way, a privileged system change that survives a crash), the more it earns Fable.
Everything else is Opus. A Fable **review** of Opus work is far cheaper than a Fable implementation,
so ★★★ tasks are built by Opus and reviewed by Fable.

Tier legend: ★ mechanical · ★★ ordinary logic with tests · ★★★ protocol/precision or touches the
connect path · ★★★★ privileged system changes, leak-relevant, unverifiable locally.

| Tier | Implementer | Spec review | Code-quality review |
|---|---|---|---|
| ★ / ★★ | Opus | Opus | Opus |
| ★★★ | Opus | Opus | **Fable** (one pass, findings only) |
| ★★★★ | **Fable** | Opus | Fable |

Orchestration: the session that reads the plan and dispatches subagents should run on **Opus** for
plans that contain no ★★★★ task (plan A below) — switch the session model before starting — and on
Fable for phases 2 and 3.

## Plan A — phases 0 + 1, per task

Every task is Opus-implemented. Only the Fable review differs.

| Task | What | Tier | Fable review? | Why |
|---|---|---|---|---|
| 1 | CSS flex fix | ★ | no | |
| 2 | `guard.js` + server wiring, `allowLan` | ★★ | no | small, fully unit-tested |
| 3 | pool `apiPort` reservation | ★ | no | |
| 4 | shared `assets.js`, `engineExe(platform)` | ★★ | no | |
| 5 | `http://` proxy links | ★★ | no | tests pin the regex |
| 6 | `saveSettings` partials | ★★ | no | browser-verified |
| 7 | hide custom-rules card | ★ | no | |
| 8 | downloader temp cleanup | ★★ | no | |
| 9 | SOCKS5 reply buffering | ★★★ | **yes** | protocol state machine; `unshift` of leftover bytes |
| 10 | geo note | ★ | no | |
| 11 | engines registry | ★★ | no | |
| 12 | per-engine download | ★★ | no | |
| 13 | `XrayManager` fallback + `validateWithFallback` | ★★★ | **yes** | decides which core runs |
| 14 | `engineChoice.js` + connect-path wiring in main **and** service | ★★★ | **yes** | two files that must stay identical |
| 15 | settings/IPC/i18n/UI for two cores | ★★ | no | mechanical; settingsMeta test guards strings |
| 16 | README + CI | ★ | no | |

Cheapest execution: one Opus session runs tasks 1–16 (parallel batches {1,3,7,10} · {2,8} · {4,5} ·
{11→12}; serial 13→14→15→16), then **one** Fable pass reviews the diffs of 9, 13, 14 together.

## Phases 2–8, per phase

| Phase | Tier | Implementer | Review | Why |
|---|---|---|---|---|
| 2 — DNS + routing (DoH, `:53` hijack, direct resolvers, `dnsManaged`, `ipv6`, live repro with a real config) | ★★★★ | **Fable** | Opus spec / Fable code | rule order and resolver choice decide whether traffic leaks or bypass works; the repro needs judgement |
| 3 — sing-box TUN + leak guard (firewall, adapter-DNS override + crash repair, mac pf/`networksetup`, server switch) | ★★★★ | **Fable** | Opus spec / Fable code | privileged, persistent side effects; mac written blind; the "no leak" promise lives here |
| 4 — standard finalmask / `fm` / `cs` / `fp=unsafe` | ★★★ (parser + builder) · ★★ (edit form) | Opus | **Fable** on parser/builder only | exact upstream JSON; a wrong key makes the core refuse the config — but the shapes are pinned verbatim in the spec, so Opus + Fable review is enough |
| 5 — stats via `metrics.listen` | ★★ | Opus | Opus | |
| 6 — WireGuard `.conf` import / export | ★★ | Opus | Opus | |
| 7 — light theme | ★ | Opus | Opus | screenshots verify |
| 8 — Android sync | ★★★ | Opus | **Fable** on `ConfigBuilder.kt` / `LinkParser.kt` parity | no local Kotlin test harness; parity must be reasoned |

Rule of thumb for tasks split later: anything under `src/main/tun*`, `leakGuard`, `dnsBuilder`,
`configBuilder` routing order → Fable implements; `parser.js` link semantics and the connect path →
Opus implements, Fable reviews; renderer-only, docs, i18n, CSS → Opus, no Fable.
