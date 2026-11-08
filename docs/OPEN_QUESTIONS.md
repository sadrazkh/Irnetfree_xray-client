Last verified: 2026-11-08
Scope: questions only the owner can answer, raised by reading the code and release notes at commit 3e5b74d. Ranked by consequence; the first ten are the most important.

# Open questions

Evidence is named in each row. The ranking itself is a **[R]** proposal.

## Top ten

| ID | Question | Why it matters | Evidence |
|---|---|---|---|
| OQ-1 | What is the bar for "done" on Android, the router and a real TUN, and who runs the owed checks? | Almost every round since v1.25 ships with device checks owed; without a bar, IMPLEMENTATION_STATUS stays Partial for nearly everything | `docs/releases/` "Owed" and "Not proven"; ROADMAP P0 |
| OQ-2 | Should core and geo downloads be verified, knowing a stricter check can block updates on filtered networks? | Binaries run elevated | KI-005; `downloader.js` |
| OQ-3 | Unify `main.js` and `service.js`, or keep the mirror as a deliberate cost? | Sets how every future feature is built | KI-001 |
| OQ-4 | SNI spoof on the router: build it, or take it off the router's list? | The router offers it and refuses at connect | KI-007 |
| OQ-5 | Android's sing-box stays at 1.13.14 while the desktop suggests 1.14.3. Intentional? | Behaviour differs (`dns_mode`, spoof, hello cut) | KI-008; `fetch-libs.sh` |
| OQ-6 | Pinned TUIC/AnyTLS and pinned records Xray cannot run: keep refusing, or allow unverified with a warning? | v1.35.1 and v1.36.0 leave this to you | `docs/releases/v1.35.1.md`, `v1.36.0.md` |
| OQ-7 | How far is macOS supported, given nobody on the project has a Mac? Does `native-macos` ever become default? | Support promise vs. no way to test | `scripts/mac-selfcheck.sh` header; `tunSingbox.js` header; D-024 |
| OQ-8 | Can you test the hev 2.17+ upgrade on a phone? | Known fix for a stop that can spin, blocked only on a device | `docs/releases/v1.40.1.md`, `v1.44.1.md` |
| OQ-9 | Should the router's web UI stay plain HTTP on the LAN with a token in the URL? Is the LAN trusted? | Control of the gateway | KI-012 |
| OQ-10 | What is the threat model for plain JSON credentials, plain backups and Android `allowBackup`? | Decides whether to add encryption | KI-013, KI-014 |

## Others

| ID | Question | Evidence |
|---|---|---|
| OQ-11 | When TUN cannot start, should the connect refuse (as the comment says) or stay proxy-only (as the code does)? | KI-004 |
| OQ-12 | `package.json` says MIT. Do you want a root `LICENSE` file, and is MIT the intended licence? | KI-010 |
| OQ-13 | What is the policy for upgrading Electron and Android `targetSdk`? | KI-015, KI-022 |
| OQ-14 | Is Android distribution GitHub APK only, or is a store planned? | `release.yml`; `usesCleartextTraffic` |
| OQ-15 | Should the Windows hotspot get its sign-in page ("step 2")? It waited on your test | `docs/releases/v1.35.0.md` |
| OQ-16 | Reality on the sing-box engine: does it need to work, or stay unsupported? | KI-025 |
| OQ-17 | Should `probe-dns-leak.js` and `probe-wg-chain.js` join CI, or be retired? | KI-023 |
| OQ-18 | Is Linux desktop a supported target? It has no kill switch or adapter DNS guard | KI-026 |
| OQ-19 | When may the legacy chain and tun2socks go? | KI-018 |
| OQ-20 | Should sing-box configs honour routing modes, or is it acceptable that they do not? | KI-006 |
