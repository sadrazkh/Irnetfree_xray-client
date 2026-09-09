# macOS reliability and connection diagnostics

This change keeps the Xray/PattN configuration builders, WireGuard chain
translation, Advanced Routing precedence, DNS configuration builder, parser,
engine selection and Windows networking policy unchanged.

## Implemented

- Journal the original macOS DNS and process identity before starting either
  sing-box or legacy tun2socks. Recover these sessions at launch or on explicit
  network recovery, including when LeakGuard was disabled.
- Roll back failed privileged setup, retain unsuccessful cleanup for retry,
  identify processes by full command and birth time, wait after TERM and use
  bounded KILL only for the owned process. Never use a broad utun/pkill sweep.
- Serialize a pending administrator prompt against disconnect; prevent another
  backend instance in this application from treating a live setup as an orphan.
- Check a new sing-box interface's expected IPv4/IPv6 addresses before declaring
  setup complete. Treat failed DNS configuration as setup failure.
- Monitor the macOS sing-box process after startup and enter the existing
  reconnect path when it exits. Bound each log read and process-status command.
- Pass pre-TUN DNS originals into LeakGuard instead of persisting a snapshot
  already overwritten with the tunnel peer. Preserve previous live originals.
- Expose read-only diagnostics for core, TUN, configured DNS, actual running
  routing rule order and anonymized chain hop order. An explicit destination
  test connects through the existing local SOCKS listener, never directly.
- Export an allow-listed report that omits server names, addresses, rule values,
  keys and raw errors. Report configured DNS as unverified; a TCP success alone
  is not proof of a particular routing match or a DNS-leak test.

## Validation and release gate

Local validation uses Windows, mocked macOS commands, Bash syntax checks, and
the repository's core config validation / loopback corporate WireGuard probe.
These are not substitutes for real macOS integration testing. Keep the PR draft
until the owner has reviewed it and real Mac acceptance is recorded.

Run this matrix on both Intel and Apple Silicon using the packaged app and an
ordinary user account. Record OS, app and core versions; avoid recording keys.

| Scenario | Required observation |
| --- | --- |
| Fresh connect, each backend | Owned process and interface; expected DNS; destination traffic works |
| Missing/wrong-architecture/blocked binary | Actionable failure; no owned process, route or DNS override left |
| Cancel connect password prompt | No successful connection; no unrecoverable empty session |
| Fail after child launch / DNS write | Rollback or persistent recoverable journal |
| Disconnect and Cmd+Q | Process gone, original DHCP/static DNS restored, routes removed |
| Cancel disconnect password prompt | No false disconnected result; journal retained; retry succeeds |
| Child ignores TERM | Owned child receives KILL; unrelated VPN process survives |
| Force Quit app, relaunch | Recover both backend journals before a new connect |
| Kill sing-box only | Health callback detects drop; existing recovery handles it |
| Switch Wi-Fi / Ethernet, sleep / wake | Reconnect does not loop or retain a stale adapter |
| Existing other VPN / Private Relay | Never kill its process or delete routes by recycled utun name |
| Static IPv4/IPv6 DNS | Original exact server list restored after normal and crash recovery |
| Chain -> WireGuard -> private HTTP/HTTPS | Corporate DNS and content work through intended chain |
| Advanced direct/block/default/chain rules | Same precedence and destinations as the baseline |
| Windows regression | Existing chain, WireGuard, pool, fragmentation and advanced-routing suite passes |

Legacy tun2socks still discovers utun by the existing before/after interface
list; it cannot check a preconfigured address because this backend assigns the
address afterwards. Test concurrent creation by other VPNs explicitly. The
macOS strict PF guard remains experimental. Existing pre-journal versions do
not have enough process identity to safely kill their orphan children
automatically; inspect them rather than restoring broad process matching.

## Separate native macOS phase

A native helper / NetworkExtension migration is deliberately not implemented
in this cross-platform maintenance PR. It needs a Mac build environment,
Developer ID signing, entitlements, notarization and real lifecycle tests.

1. Prototype a narrow helper managed by SMAppService on supported macOS versions.
   Use authenticated IPC for session start/stop/status, constrained executable
   locations and validated configurations; never expose arbitrary root commands.
   The helper owns cleanup even if the Electron UI is killed. Test install,
   upgrade, uninstall, authorization cancellation and user-session boundaries.
2. Independently evaluate NEPacketTunnelProvider for OS-managed VPN status and
   lifecycle. Preserve the existing Xray/PattN plan semantics behind a defined
   packet/core boundary; do not assume that sing-box translates multi-core
   chains, WireGuard or per-process routing identically.
3. Gate adoption on the same corporate-DNS, chain, routing and crash matrix,
   packaged on both architectures. Keep the existing backend available until
   that parity is demonstrated; make no Windows migration as part of this work.

Primary references:
- [Apple SMAppService](https://developer.apple.com/documentation/servicemanagement/smappservice)
- [Apple packet tunnel provider](https://developer.apple.com/documentation/networkextension/packet-tunnel-provider)
- [sing-box TUN configuration](https://sing-box.sagernet.org/configuration/inbound/tun/)
