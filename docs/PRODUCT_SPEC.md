Last verified: 2026-11-08
Scope: behaviour readable in `src/`, `android/`, `openwrt/`, and the feature lists in `README.en.md`, at commit 3e5b74d. The detailed user guide is [GUIDE.md](../GUIDE.md); this file records rules and intent, not how-to steps.

# Product specification

Labels: **[V]** Verified (evidence named), **[A]** Assumption, **[R]** Recommendation.

## Vision

"One app for every device: paste your subscription, press the button, you're connected." [V: `README.en.md`]

A client for people whose internet is filtered or inspected: it imports whatever configs they already have, finds a way past filtering, and tells the truth about what the connection is doing. [A: inferred from the README and feature set; no product brief exists.]

Audience [A]: Persian-speaking users of Xray subscriptions (Persian is the default UI language: `currentLang = 'fa'` in `i18n.js`), and owners who run a router or machine for their household or office.

Stated principles, as the code applies them:

| Principle | Evidence [V] |
|---|---|
| A connection does what the screen says, or says why not | `settingsMeta.js` header; `sniSpoofError`; `tunError` shown as `proxyOnly` in `app.js` |
| Nothing changes by itself | `modules.js` header: the selected item stays in a picker; `deepLink.js`: asks first, never connects |
| Features are extras: a user who wants none sees a simple app | `modules` default `{}`; `uiMode` `simple` when nothing advanced exists |

## Platforms

| Capability | Desktop | Router | Android | Evidence [V] |
|---|---|---|---|---|
| Chains, groups, pool, advanced routing | Yes | Yes | Yes | `modules.js` `platforms` |
| WARP, MASQUE, ECH outbound, anti-DPI | Yes | Yes | Yes | `modules.js` |
| TUIC, AnyTLS | Yes | Refused | Yes | `singboxOnlyError` `'router'` |
| SNI spoof | Windows, elevated | Listed, refused | No | KI-007; `modules.js` |
| LAN sharing | Yes | Always | Yes | `lanShare` platforms; `README.en.md` |
| Users with passwords and limits | Yes | Yes, plus captive portal | No | `lanUsers` platforms |
| Multi-internet | Yes | Yes | No | `multiWan` platforms |
| Traffic by site | Sing-box TUN | Per device | No | `siteUsage.js` |
| Per-app | Config per app under sing-box TUN | Refused | App selection | `tunAppTargets.js`; `service.js`; `applyPerApp` |
| Direct ports | Yes | Not in README; setting exists in `service.js` | No | `directPorts.js` |
| Kill switch | Windows | Yes, from boot | System Always-on | `armKillSwitch`; `killSwitchOpenwrt.js`; manifest |
| Remote access | No | Yes | No | `remoteRelay` platforms |

## Features and rules

### Configs and subscriptions

- Import: links, many at once, base64, subscription URL, WireGuard `.conf`, Xray or sing-box JSON, manual form; QR and Share on Android. Clash YAML is refused by name [V: `parser.js`, `jsonImport.js`].
- A key the app does not understand in a link is logged rather than silently dropped [V: `unreadLinkKeys`].
- A refresh keeps a server's identity, the user's edits, selection, chains, routing and groups even when a panel rotates addresses [V: `subscription.js`; A: "even when" is scoped by the tests in `tests/subscription.test.js`, not by real panels].
- Deleting has Undo; a failed connect offers the next config: same subscription first, fastest measured, then untested, then failed [V: `docs/releases/v1.45.0.md`; `renderTryNext` in `app.js`].

### Cores

- Three cores per config, version chosen in Settings. Fixed exceptions: section 3 of [TECHNICAL_SPEC.md](TECHNICAL_SPEC.md).
- The app writes each config in the shape the running core version accepts [V: `coreCompat.adaptForCore`].
- Weekly geo refresh by default; cores only if asked; never under a live tunnel, except a router's quiet hours [V: `assetUpdater.js`].

### Connecting

- A connect can be cancelled at any point; every control that would start one becomes Cancel [V: `connect` in `app.js`, `connGen`].
- A change to a baked-in setting shows as pending until Reconnect [V: `RECONNECT_KEYS`].
- If TUN cannot start the app stays connected proxy-only and says so (KI-004).
- Modes: global, bypass Iran, bypass China, direct; block ads; custom rules [V: `buildRoutingRules`].

### Advanced routing

Profiles of rules by IP, domain, port, process; each target through an optional base (`via`); "exit at the base"; a default target that must exist. Rules with a gone target fall through to the default; a gone default or base refuses the connect [V: `buildConfig`, `baseHere`].

### Protection

| Feature | Rule | Evidence [V] |
|---|---|---|
| Leak guard | `off`, `standard` (physical adapters' DNS held), `strict` (plus firewall and strict route) | `leakGuard.js` |
| Kill switch | Armed on an unexpected drop or a server switch; off by default | `armKillSwitch`, `killSwitch: false` |
| Certificate pin | On first use when a link asks for `allowInsecure` | `certPin.js` |
| Hello cut | Only when the path is seen to read names | `helloCut.js` |

### Extensions

Twelve built-in modules, installed by a flag [V: `modules.js`]: chains, groups, WARP, pool, advanced routing, ECH outbound, anti-DPI, SNI spoof, LAN share, multi-internet, remote relay, LAN users. Off hides entry points, records keep working. A store from before keeps what it uses (`migrateModules`).

### Users and limits

- Limits by kind (total, VPN, direct), period (day, month, one-off), action (cut, slow), allowed hours, top-up, Persian-calendar month option [V: `src/modules/lanUsers/model.js` header; `capPeriods.js`].
- On a router: transparent mode by device, captive sign-in, internet cards in batches, remembered devices, content filter, shaping [V: `src/modules/lanUsers/router`, `luVouchers.js`].
- Passwords are visible to the admin by design (D-022).

### Non-goals visible in code

- Sing-box as a chain or routing engine: no translator (`engineChoice.js`).
- Links on the router or headless server: no OS handler (`docs/releases/v1.45.0.md`).
- Downloaded plugins (D-021).

## Product gaps

See [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) for what is unproven and [OPEN_QUESTIONS.md](OPEN_QUESTIONS.md) for what needs the owner.
