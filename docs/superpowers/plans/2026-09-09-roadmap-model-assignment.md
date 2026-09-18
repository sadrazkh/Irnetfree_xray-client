# Roadmap after v1.3.0 — phases A–E, and which model implements what

Base: `main` at v1.3.0 (`ede8be0`). Five plans, one per phase, each self-contained so a fresh
session on ANY model can execute it without this conversation:

| Phase | Plan file | Theme | Tag when merged |
|---|---|---|---|
| A | `2026-09-09-phase-A-gaps.md` | close the gaps v1.3.0 left open, clean-ups | v1.3.1 |
| B | `2026-09-09-phase-B-performance.md` | speed: list rendering, ping-all, validate cache, poll cadence | v1.4.0 |
| C | `2026-09-09-phase-C-reliability.md` | leak self-test, health watch, DoH bootstrap, gateway watch, firewall holes, sing-box DNS, two-core chains, Linux/mac guard | v1.10.0 (was v1.8.0; E shipped as v1.8.0 and F as v1.9.0) |
| D | `2026-09-09-phase-D-features.md` | autostart, auto server, notifications, tray switch, self-update, scheduled asset updates, backup, sparkline, per-app TUN | v1.5.0 — shipped 2026-09-09; D10 shipped 2026-09-10 as v1.6.0 |
| E | `2026-09-09-phase-E-android.md` | Android parity: managed DNS, `dns=` links, advancedUseMode — and, by the time it ran, cert pinning, endpoint resolution, geo data, JVM tests | v1.8.0 — shipped 2026-09-17 (tags follow shipping order, so C moves to v1.9.0) |
| F | (no plan file — asked for directly) | Android: the design doc applied, Xray-PattN as a second core, the share QR fixed on both clients | v1.9.0 — shipped 2026-09-18 |

خلاصهٔ فارسی: هر فاز یک فایل پلن جداست با تسک‌های کوچک، کدِ کامل، تست و کامیت. مدلِ هر تسک در جدول
پایین آمده؛ جلسه‌ای که پلن را اجرا می‌کند باید روی همان مدل باشد و برای تسک‌های ★★★ بعد از پیاده‌سازی
یک بازبینی Fable بگیرد. ترتیب پیشنهادی: A کامل → از B فقط B1/B2/B3 → C1 → بقیهٔ C → D به انتخاب شما → E.

## Tier legend (unchanged from `2026-09-02-model-assignment.md`)

★ mechanical · ★★ ordinary logic with tests · ★★★ protocol/precision or touches the connect path ·
★★★★ privileged system changes, leak-relevant, unverifiable locally.

| Tier | Implementer | Spec review | Code-quality review |
|---|---|---|---|
| ★ / ★★ | Opus (Sonnet is fine for ★) | Opus | Opus |
| ★★★ | Opus | Opus | **Fable** (one pass, findings only) |
| ★★★★ | **Fable** | Opus | Fable |

The orchestrating session (the one that reads a plan and dispatches subagents) runs on Opus for
plans A, B, D, E and on **Fable for plan C** (it contains ★★★★ tasks C5, C6, C8, C9).

## Every task, its tier, and who does it

| Task | What | Tier | Implementer | Fable review? |
|---|---|---|---|---|
| A1 | README for the v1.3.0 batch | ★ | Opus/Sonnet | no |
| A2 | parser.js duplicate declarations + guard test | ★ | Opus/Sonnet | no |
| A3 | network change during the FIRST connect | ★★★ | Opus | **yes** (connect path, both mirrors) |
| A4 | subscription usage bar colour by percentage | ★ | Opus/Sonnet | no |
| A5 | clear usage history (all / one config) | ★★ | Opus | no |
| A6 | inline `style=` out of index.html + guard test | ★ | Opus/Sonnet | no |
| A7 | `assets:remove` forgets sing-box → shared file list | ★★ | Opus | no |
| B1 | in-place list updates (selection, usage) instead of full re-render | ★★ | Opus | no |
| B2 | one throwaway core for "ping all" | ★★★ | Opus | **yes** (spawns cores per engine) |
| B3 | validation cache keyed by core+geo+config | ★★★ | Opus | **yes** (decides whether a config is checked) |
| B4 | certificate re-check throttle | ★★ | Opus | no |
| B5 | coalesced store writes for the process-IP cache | ★★ | Opus | no |
| B6 | slower stats poll while the window is hidden | ★★ | Opus | no |
| C1 | in-app leak self-test | ★★★ | Opus | **yes** (a wrong "no leak" verdict is the worst bug) |
| C2 | health watch + auto reconnect / next server | ★★★ | Opus | **yes** (drives the recovery path) |
| C3 | DoH bootstrap for server-name resolution | ★★★ | Opus | **yes** (what the ISP sees before the tunnel) |
| C4 | default-gateway change detection | ★★ pure / ★★★ wiring | Opus | **yes** on the wiring |
| C5 | strict-guard holes narrowed to port 53 | ★★★★ | **Fable** | Fable |
| C6 | sing-box-format configs: remote DNS through the tunnel + hijack | ★★★★ | **Fable** | Fable |
| C7 | sniffing `routeOnly` option | ★★ | Opus | no |
| C8 | two-core chains (PattN hops in front of an official-core exit) | ★★★★ | **Fable** | Fable |
| C9 | Linux strict guard (nftables) + macOS guard snapshot order | ★★★★ | **Fable** | Fable |
| D1 | start with the OS (scheduled task on Windows) + auto-connect | ★★★ | Opus | **yes** (persistent system change) |
| D2 | "Auto" target = fastest tested server | ★★ | Opus | no |
| D3 | system notifications | ★ | Opus/Sonnet | no |
| D4 | server switch from the tray | ★★ | Opus | no |
| D5 | in-app update download with checksum | ★★★ | Opus | **yes** (downloads and runs an installer) |
| D6 | scheduled geo/core updates | ★★ | Opus | no |
| D7 | backup / restore | ★★ | Opus | no |
| D8 | speed sparkline on the home page | ★ | Opus/Sonnet | no |
| D9 | usage figures on chain and pool cards | ★ | Opus/Sonnet | no |
| D10 | per-app split under the sing-box TUN | ★★★★ | **Fable** | Fable |
| E1 | Kotlin: managed DNS plan | ★★★ | Opus | **yes** (parity by reasoning; no local Kotlin) |
| E2 | Kotlin: `dns=` on WireGuard links | ★★ | Opus | no |
| E3 | Kotlin: `advancedUseMode` | ★★★ | Opus | **yes** (rule order) |

## Dependencies and order

- Inside a phase the tasks are independent unless the plan says otherwise. Parallel batches are
  listed at the top of each plan.
- **B1 before D9** (D9 hangs its usage spans on B1's `data-usage` hook).
- **C7 before C8**: C8 is gated on the owner confirming that the PattN failure on
  `gitlab.hawk.tes.systems` survives `routeOnly` and Sniffing-off. Do not start C8 otherwise.
- **C5 and C6 together** (C6 changes what `resolverBypassIpsOf` returns for sing-box configs; C5
  passes that list to the guard).
- D3 is used by C2 and D1 for the messages they raise; implement D3 first if C2/D1 run in the same
  session, otherwise leave their `notify()` calls behind a `typeof notify === 'function'` check as
  the plans instruct.
- E depends on nothing on the desktop side; it can run any time after A.

## How to run a phase

1. `git worktree add ../irnf-phase-<X> -b feature/phase-<X> main` (v1.3.0 tag as base).
2. Switch the session model per the table (Fable for plan C). Read the plan's **Global
   Constraints** first; every task implicitly includes them.
3. Execute with `superpowers:subagent-driven-development`: one fresh subagent per task, the plan's
   own test steps as the gate, a Fable review for the tasks marked "yes".
4. After the phase: `npm test`, `npm run validate` (set `IRNF_XRAY_EXE` to the PattN binary for a
   second run), `node scripts/probe-dns-leak.js`, `npm run probe:wg`. The owner merges and tags.

The cheapest total: one Opus session runs A1–A7 (batches {A1,A2,A4,A6} · {A5,A7} · A3), then one
Fable pass reviews A3's diff. Same shape for B (Fable reviews B2+B3 together) and D (Fable reviews
D1+D5 together; D10 is Fable-implemented in its own session).
