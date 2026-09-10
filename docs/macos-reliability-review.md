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
select another backend, and a connect against an unregistered service refuses
rather than registering it.

Per-app routing (the sing-box `process_name` split added in v1.6.0) is not
available on this backend: the app does not write the daemon's configuration,
it hands it a fixed request, so the rule is refused at connect time with a line
naming the compatibility backend rather than accepted and dropped.

### Trust model

Any process running as the console user can ask the daemon to route all traffic
to a local SOCKS port and to set system DNS, and it will do so without a
prompt. That is the accepted model for a VPN helper — the alternative, an
authorization prompt per connect, is what the helper exists to remove — and it
is the same authority the user already grants the app itself. The bound on it
is the shape of the request: the daemon accepts a SOCKS port, an exclusion list,
DNS server addresses and two booleans, executes only a checksum-pinned bundled
sing-box from a root-owned directory, and authenticates the pinned bridge code
signature. No request can reach code execution, an arbitrary binary path, an
arbitrary file write or a shell.

### Install and test

Download the architecture-specific DMG or ZIP from the Native macOS beta CI
artifacts for this PR. These are ad-hoc signed test builds, not notarized public
releases. The CI artifact is quarantined, so clear it before the first launch:

    xattr -dr com.apple.quarantine IRNetFree.app

Launch it from /Applications, never from the DMG or from Downloads: App
Translocation runs the app from a randomised read-only path, and SMAppService
registration fails from there. On macOS 13+, allow IRNetFree under System
Settings > General > Login Items (the exact section name varies by macOS
release), then connect using Native macOS. Developer ID signing/notarization
remains a separate release requirement.

Run the acceptance matrix above, especially Force Quit with a live tunnel,
service disable/enable, sleep/wake, static DNS restore and corporate chain
traffic. CI compile/package and mocked lifecycle tests cannot establish real
network behavior on a Mac. Record failures with the sanitized diagnostics
export; never include subscription credentials or WireGuard private keys.

### Known items for the Mac iteration (Swift, not changed on Windows)

Found in review; each needs a Mac to compile and test, so none of them was
touched in the Windows fix wave. In rough order of consequence:

- The restore loop stops at the first `networksetup` service that fails, so one
  bad service leaves every later one still pointing at the tunnel. Attempt them
  all, collect the failures, and back off rather than abandoning the sweep.
- The heartbeat lease is measured with wall-clock `Date`. A sleep/wake or a
  clock change can expire a live session or keep a dead one; use an uptime
  clock (`mach_continuous_time` / `CLOCK_MONOTONIC`).
- After an app upgrade the running daemon still pins the previous bridge's
  cdhash, so the new bridge cannot talk to it. Compare `NativeBuild.bridgeSHA256`
  against the bridge on disk and exit when idle — and let `unregister` through
  when the daemon is unreachable, or the user cannot undo the install.
- DNS is set on every enabled network service, not only the one carrying the
  default route. Verify with a system VPN present before shipping.
- `proc_listallpids` returns a byte count, not a number of pids; the result is
  divided as though it were a count.
- `ipv6` is accepted in the start request and never used.
- `startupError` surfaces to the app as "existing session", which sends the user
  to recovery for a failure that has nothing to do with a stale session.
- The LaunchDaemon declares `ProcessType Interactive` for a root daemon.
- `signingOptions` forces ad-hoc signing even when a Developer ID identity is
  present, so a release build cannot be signed without editing the script.
- A journaled "original" DNS equal to the tunnel peer is residue from a previous
  session, not a user setting, and must not be restored as one.
- The Mac release job now depends on a live download of the pinned sing-box
  archive; a network hiccup or a moved asset breaks the release build.

Primary references:
- [Apple SMAppService](https://developer.apple.com/documentation/servicemanagement/smappservice)
- [Apple packet tunnel provider](https://developer.apple.com/documentation/networkextension/packet-tunnel-provider)
- [sing-box TUN configuration](https://sing-box.sagernet.org/configuration/inbound/tun/)
