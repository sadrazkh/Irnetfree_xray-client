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

## Native macOS beta implementation

The packaged macOS 13+ app now includes an SMAppService LaunchDaemon and a
narrow Swift XPC bridge. The native backend is opt-in: the default TUN backend
stays sing-box on every platform and in every build, the service is registered
only from Settings > TUN > macOS tunnel service > Enable service, and a connect
against an unregistered service refuses and names that switch instead of
registering a root daemon on the user's behalf. Windows defaults are unchanged.
This is a native background service with a sing-box TUN, not a NetworkExtension
packet-tunnel provider or an entry in the system VPN configuration panel.
The compatibility (sing-box) backend keeps working below macOS 13; only the
native backend requires 13 or later.

The service validates network inputs, authenticates the pinned bridge code
signature, and executes only a checksum-pinned bundled sing-box copied into a
root-owned directory. It journals DNS before changing it, restores DNS on stop,
and expires the session after missing heartbeats from the app. A daemon restart
recovers the journal. Failed cleanup retains state for a later retry.
Xray/PattN still processes chain, WireGuard and advanced routing through the
existing local SOCKS listener; their configuration builders are unchanged.
Native mode explicitly rejects strict PF protection before starting the core.
DNS restoration during reconnect is not a firewall kill switch.

Settings provide status, registration, background-permission settings and
unregistration. Unregistration stops and recovers the tunnel first. Manual
network recovery also checks an already registered native service without
registering a new one. Missing helpers or pending approval do not silently
select another backend.

### Install and test

Download the architecture-specific DMG or ZIP from the Native macOS beta CI
artifacts for this PR. These are ad-hoc signed test builds, not notarized public
releases. Move IRNetFree.app to Applications before enabling its service. On
macOS 13+, allow IRNetFree under System Settings > General > Login Items (the
exact section name varies by macOS release), then connect using Native macOS.
Developer ID signing/notarization remains a separate release requirement.

Run the acceptance matrix above, especially Force Quit with a live tunnel,
service disable/enable, sleep/wake, static DNS restore and corporate chain
traffic. CI compile/package and mocked lifecycle tests cannot establish real
network behavior on a Mac. Record failures with the sanitized diagnostics
export; never include subscription credentials or WireGuard private keys.

Primary references:
- [Apple SMAppService](https://developer.apple.com/documentation/servicemanagement/smappservice)
- [Apple packet tunnel provider](https://developer.apple.com/documentation/networkextension/packet-tunnel-provider)
- [sing-box TUN configuration](https://sing-box.sagernet.org/configuration/inbound/tun/)
