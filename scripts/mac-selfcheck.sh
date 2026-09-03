#!/bin/bash
#
# IRNetFree — macOS self-check.
#
# Nobody on this project has a Mac: the macOS half of TUN mode (src/main/tunSingbox.js),
# of the leak guard (src/main/leakGuard.js) and of the binary preparation
# (src/main/downloader.js) was written blind. This script is what you run when
# something on macOS does not work, so the output can be pasted into an issue.
#
# READ-ONLY BY CONSTRUCTION. It starts no tunnel, changes no setting, kills no
# process. The only thing it writes is one sing-box config inside a fresh temp
# directory, which it deletes again on exit.
#
# Every check prints exactly one line, tagged OK / WARN / FAIL.
#
#   bash scripts/mac-selfcheck.sh                          # or: npm run selfcheck:mac
#   bash scripts/mac-selfcheck.sh /Applications/IRNetFree.app   # also check the bundle's bin
#   sudo bash scripts/mac-selfcheck.sh                     # adds the pf (firewall) answers
#
# Exit status: 1 when at least one check FAILed on a Mac; 0 otherwise (off macOS
# nothing it sees is a verdict, so it always exits 0 there).
#
# Stock macOS ships bash 3.2, so: no associative arrays, no mapfile/readarray,
# no `${var^^}`. `set -u` is on; `set -e` deliberately is NOT — a failing check
# is a result to print, never a reason to stop the run.

set -u

# ---------------------------------------------------------------- constants --
# Kept in sync by hand with src/main/tunSingbox.js (TUN_PEER4 / TUN_PEER6).
PEER4='172.19.0.2'
PEER6='fdfe:dcba:9876::2'
APP_SUPPORT="$HOME/Library/Application Support/IRNetFree"
USER_BIN="$APP_SUPPORT/bin"
STATE_FILE="$APP_SUPPORT/tun-state.json"
ISSUES='https://github.com/sadrazkh/Irnetfree_xray-client/issues'

TMP_BASE="${TMPDIR:-/tmp}"
TMP_BASE="${TMP_BASE%/}"

ARG="${1:-}"
case "$ARG" in
  -h|--help)
    sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
    ;;
esac

# The app bundle's read-only bin, when a path was given. Accept either the .app
# itself or a bin directory.
APP_BIN=''
if [ -n "$ARG" ]; then
  if [ -d "$ARG/Contents/Resources/bin" ]; then APP_BIN="$ARG/Contents/Resources/bin"; else APP_BIN="$ARG"; fi
fi

# ------------------------------------------------------------------ helpers --
OK_N=0
WARN_N=0
FAIL_N=0
SB=''          # the first sing-box binary we found (used by the config check)

ok()   { OK_N=$((OK_N + 1));     printf 'OK    %s\n' "$*"; }
warn() { WARN_N=$((WARN_N + 1)); printf 'WARN  %s\n' "$*"; }
fail() { FAIL_N=$((FAIL_N + 1)); printf 'FAIL  %s\n' "$*"; }
note() { printf '      %s\n' "$*"; }
section() { printf '\n-- %s --\n' "$*"; }

have() { command -v "$1" >/dev/null 2>&1; }

# First line of a blob, or a placeholder when it is empty.
first_line() {
  line1="$(printf '%s\n' "$1" | head -n 1)"
  if [ -n "$line1" ]; then printf '%s' "$line1"; else printf '%s' '(no output)'; fi
}

WORK=''
cleanup() { if [ -n "$WORK" ] && [ -d "$WORK" ]; then rm -rf "$WORK"; fi; }
trap cleanup EXIT

# -------------------------------------------------------------------- header --
UNAME_S="$(uname -s 2>/dev/null || echo unknown)"
ARCH="$(uname -m 2>/dev/null || echo unknown)"

printf 'IRNetFree — macOS self-check (read-only)\n'
printf 'date  : %s\n' "$(date 2>/dev/null || echo '?')"
printf 'system: %s %s (%s)\n' "$UNAME_S" "$(uname -r 2>/dev/null || echo '?')" "$ARCH"
printf 'user  : %s (uid %s)\n' "${USER:-?}" "$(id -u 2>/dev/null || echo '?')"
printf 'data  : %s\n' "$APP_SUPPORT"

section 'platform'
case "$UNAME_S" in
  Darwin)
    ok "running on macOS ($ARCH)"
    ;;
  *)
    warn "this script is for macOS — here uname says '$UNAME_S', so every check below degrades"
    note "run it on the Mac itself; on Windows/Linux it only proves the script does not crash"
    ;;
esac

# ============================================================== 1. binaries ==
# The three cores the app can run. `xray` / `xray-pattn` proxy, `sing-box` is
# the TUN backend. Missing is a WARN (not everyone installs all three); present
# but unrunnable is a FAIL, because that is the failure that looks like
# "sing-box did not create a utun device".
check_bins_in_dir() {
  local dir label name bin cs_out cs_rc v_out v_rc
  dir="$1"
  label="$2"
  if [ ! -d "$dir" ]; then
    warn "$label bin directory not found: $dir"
    return 0
  fi
  note "$label: $dir"
  for name in xray xray-pattn sing-box; do
    bin="$dir/$name"
    if [ ! -e "$bin" ]; then
      warn "$name: not in $label bin (Settings → Required files → download)"
      continue
    fi
    if [ ! -x "$bin" ]; then
      fail "$name: present but not executable (chmod +x '$bin')"
      continue
    fi
    ok "$name: present and executable"

    # Gatekeeper: Apple Silicon SIGKILLs an unsigned binary ("Killed: 9") with
    # no useful error. The downloader ad-hoc signs on download (downloader.js
    # macPrepareBinary), and tunSingbox.startMac re-signs sing-box before use.
    if have codesign; then
      cs_out="$(codesign -dv "$bin" 2>&1)"
      cs_rc=$?
      if [ $cs_rc -eq 0 ]; then
        case "$cs_out" in
          *adhoc*) ok "$name: codesign OK (ad-hoc signature)" ;;
          *)       ok "$name: codesign OK (signed)" ;;
        esac
      elif [ "$ARCH" = 'arm64' ]; then
        fail "$name: NOT signed — Apple Silicon refuses to exec it; run: codesign --force --sign - '$bin'"
      else
        warn "$name: not signed (Intel usually still runs it): $(first_line "$cs_out")"
      fi
    else
      warn "$name: codesign not available, signature unknown"
    fi

    # Quarantine: set by the browser/curl on anything downloaded; Gatekeeper
    # then blocks the exec. The app strips it, an unpacked-by-hand copy has it.
    if have xattr; then
      if xattr -p com.apple.quarantine "$bin" >/dev/null 2>&1; then
        fail "$name: quarantined — run: xattr -dr com.apple.quarantine '$bin'"
      else
        ok "$name: no quarantine attribute"
      fi
    else
      warn "$name: xattr not available, quarantine state unknown"
    fi

    # Does it actually run? This is the check the other three exist to explain.
    v_out="$("$bin" version 2>&1)"
    v_rc=$?
    if [ $v_rc -eq 0 ]; then
      ok "$name: $(first_line "$v_out")"
    else
      fail "$name: does not run (exit $v_rc): $(first_line "$v_out")"
      if [ $v_rc -gt 128 ]; then
        note "killed by a signal — on Apple Silicon that is the unsigned-binary case above"
      fi
    fi

    if [ "$name" = 'sing-box' ] && [ -z "$SB" ]; then SB="$bin"; fi
  done
}

section 'binaries'
check_bins_in_dir "$USER_BIN" 'downloaded'
if [ -n "$APP_BIN" ]; then
  check_bins_in_dir "$APP_BIN" 'bundled'
else
  note "no app path given — pass /Applications/IRNetFree.app to check the bundle's bin too"
fi

# =============================================================== 2. network ==
section 'network'
GW=''
DEV=''
if have route; then
  route_out="$(route -n get default 2>&1)"
  GW="$(printf '%s\n' "$route_out" | sed -n 's/.*gateway:[[:space:]]*\([^[:space:]]*\).*/\1/p' | head -n 1)"
  DEV="$(printf '%s\n' "$route_out" | sed -n 's/.*interface:[[:space:]]*\([^[:space:]]*\).*/\1/p' | head -n 1)"
  if [ -n "$GW" ] && [ -n "$DEV" ]; then
    ok "default route: gateway $GW via $DEV"
    case "$DEV" in
      utun*) warn "the default route already runs through a tunnel ($DEV) — a TUN session may be live" ;;
    esac
  else
    fail "default route not found — 'route -n get default' said: $(first_line "$route_out")"
    note 'without it TUN mode refuses to start (tunSingbox.startMac)'
  fi
else
  warn "route not available — cannot read the default gateway/interface"
fi

SVC=''
if have networksetup; then
  if [ -n "$DEV" ]; then
    # networksetup -listnetworkserviceorder prints, per service:
    #   (1) Wi-Fi
    #   (Hardware Port: Wi-Fi, Device: en0)
    # so the service name is the line BEFORE the one naming our device. Same
    # parsing as tunPlatform.serviceForDeviceMac; the `(*N)` of a DISABLED
    # service is stripped too, so the name printed is the one you can type.
    prev=''
    while IFS= read -r line; do
      case "$line" in
        *"Device: $DEV)"*) SVC="$(printf '%s' "$prev" | sed 's/^([*]*[0-9]*)[[:space:]]*//')" ;;
      esac
      prev="$line"
    done <<EOF
$(networksetup -listnetworkserviceorder 2>/dev/null)
EOF
  fi
  if [ -n "$SVC" ]; then
    ok "network service for $DEV: $SVC"
  elif [ -n "$DEV" ]; then
    fail "no networksetup service maps to $DEV — the DNS override has nothing to write to"
  else
    warn 'no default interface, so no network service to look up'
  fi

  if [ -n "$SVC" ]; then
    dns_out="$(networksetup -getdnsservers "$SVC" 2>&1)"
    case "$dns_out" in
      *"aren't any"*|*"any DNS Servers"*)
        ok "DNS of $SVC: automatic (DHCP)"
        ;;
      *)
        dns_one="$(printf '%s\n' "$dns_out" | tr '\n' ' ')"
        case " $dns_one " in
          *" $PEER4 "*|*" $PEER6 "*)
            warn "DNS of $SVC still points at the tunnel ($dns_one) — a session did not put it back"
            note 'launch IRNetFree once: the leak guard restores it from tun-state.json'
            ;;
          *)
            ok "DNS of $SVC: $dns_one"
            ;;
        esac
        ;;
    esac
  fi
else
  warn 'networksetup not available — cannot read the service name or its DNS'
fi

if have ifconfig; then
  utuns=''
  for u in $(ifconfig -l 2>/dev/null); do
    case "$u" in utun*) utuns="$utuns $u" ;; esac
  done
  if [ -n "$utuns" ]; then
    ok "utun devices:$utuns"
    note 'other VPNs and iCloud Private Relay use utun too — ours is whichever appeared last'
  else
    ok 'utun devices: none (no tunnel is up)'
  fi
else
  warn 'ifconfig not available — cannot list utun devices'
fi

# pf: the strict guard's firewall. /dev/pf needs root, so without sudo this
# section can only say "unknown" — that is a WARN, not a failure of the app.
if have pfctl; then
  pf_out="$(pfctl -s info 2>&1)"
  pf_rc=$?
  case "$pf_out" in
    *"Permission denied"*|*"Operation not permitted"*)
      warn 'pfctl needs root — re-run with: sudo bash scripts/mac-selfcheck.sh'
      ;;
    *)
      if [ $pf_rc -ne 0 ]; then
        warn "pfctl -s info failed: $(first_line "$pf_out")"
      else
        case "$pf_out" in
          *Enabled*) ok  'pf firewall: Enabled' ;;
          *)         ok  'pf firewall: Disabled (normal unless the strict guard is on)' ;;
        esac
        anchor_out="$(pfctl -a irnetfree -s rules 2>&1)"
        anchor_rc=$?
        anchor_txt="$(printf '%s\n' "$anchor_out" | sed '/^[[:space:]]*$/d')"
        # A missing anchor and an empty one look the same from here, and mean
        # the same thing: nothing of ours is loaded into pf.
        if [ $anchor_rc -ne 0 ] || [ -z "$anchor_txt" ]; then
          ok 'pf anchor "irnetfree": no rules loaded'
        else
          warn 'pf anchor "irnetfree" holds rules — a strict-guard session did not clean up:'
          printf '%s\n' "$anchor_txt" | sed 's/^/        /'
          note 'flush it with: sudo pfctl -a irnetfree -F all'
        fi
      fi
      ;;
  esac
else
  warn 'pfctl not available — cannot read the firewall state'
fi

# ======================================================== 3. sing-box config ==
section 'sing-box TUN config'
if [ -z "$SB" ] && have sing-box; then
  SB="$(command -v sing-box)"
  warn "using the sing-box on PATH ($SB) — the app uses its own copy in $USER_BIN"
fi

if [ -z "$SB" ]; then
  warn 'no sing-box binary to check the TUN config with'
else
  WORK="$(mktemp -d "$TMP_BASE/irnf-selfcheck-XXXXXX" 2>/dev/null)"
  if [ -z "$WORK" ] || [ ! -d "$WORK" ]; then
    fail "could not create a temp directory under $TMP_BASE"
  else
    CFG="$WORK/sing-box.json"
    # ------------------------------------------------------------------------
    # THE SHAPE BELOW IS A LITERAL COPY of what buildTunConfig() produces in
    #   src/main/tunSingbox.js
    # for macOS: socksPort 10808 (the app default — `check` validates the shape,
    # not the port), no exclusions, ipv6 off, strict off.
    #
    # Keep these in sync with the constants at the top of that file:
    #   TUN_ADDR4 '172.19.0.1/30'   TUN_ADDR6 'fdfe:dcba:9876::1/126'
    #   mtu 1500   stack 'system'   auto_route true
    # The v6 address is ALWAYS present even with ipv6 off: it is what puts a v6
    # default route on the tunnel so the physical adapter's v6 cannot leak.
    #
    # `interface_name` is deliberately ABSENT on darwin: sing-tun only accepts
    # `utun<N>` there and picks the next free unit itself, so the app passes
    # interfaceName=null and reads back the device that appeared. A config with
    # `"interface_name": "IRNetFree"` is the Windows/Linux one and would fail here.
    # ------------------------------------------------------------------------
    cat > "$CFG" <<'JSON'
{
  "log": {
    "level": "warn",
    "timestamp": false
  },
  "inbounds": [
    {
      "type": "tun",
      "tag": "tun-in",
      "address": [
        "172.19.0.1/30",
        "fdfe:dcba:9876::1/126"
      ],
      "mtu": 1500,
      "auto_route": true,
      "strict_route": false,
      "stack": "system",
      "route_exclude_address": []
    }
  ],
  "outbounds": [
    {
      "type": "socks",
      "tag": "socks-out",
      "server": "127.0.0.1",
      "server_port": 10808,
      "version": "5"
    }
  ],
  "route": {
    "final": "socks-out",
    "auto_detect_interface": true
  }
}
JSON
    chk_out="$("$SB" check -c "$CFG" 2>&1)"
    chk_rc=$?
    if [ $chk_rc -eq 0 ]; then
      ok 'sing-box check: the TUN config this app writes is accepted'
    else
      fail "sing-box check rejected the TUN config: $(first_line "$chk_out")"
      note 'that means this sing-box version wants a different shape — report the line above'
    fi
  fi
fi

# ============================================================= 4. leftovers ==
section 'leftovers from earlier sessions'
if [ -f "$STATE_FILE" ]; then
  warn "tun-state.json exists — the last session did not shut down cleanly"
  note "$STATE_FILE"
  note 'not a problem by itself: the next launch restores the DNS it records and deletes it'
else
  ok 'no tun-state.json (the last session shut down cleanly)'
fi

stale=0
stale_list=''
for d in "$TMP_BASE"/irnf-sb-* "$TMP_BASE"/irnf-tun-* "$TMP_BASE"/irnf-lg-*; do
  [ -d "$d" ] || continue
  stale=$((stale + 1))
  if [ $stale -le 10 ]; then stale_list="$stale_list$d
"; fi
done
if [ $stale -eq 0 ]; then
  ok "no stale irnf-* work directories in $TMP_BASE"
else
  warn "$stale stale irnf-* work directory/ies in $TMP_BASE — safe to delete"
  printf '%s' "$stale_list" | sed 's/^/        /'
  if [ $stale -gt 10 ]; then note "… and $((stale - 10)) more"; fi
fi

# Report only. This script never kills a process it did not start.
if have pgrep; then
  # `[s]` keeps pgrep from matching a shell that merely carries the pattern.
  procs="$(pgrep -fl '[s]ing-box run' 2>/dev/null; pgrep -fl '[t]un2socks' 2>/dev/null)"
  if [ -n "$procs" ]; then
    warn 'a tunnel process is running:'
    printf '%s\n' "$procs" | sed 's/^/        /'
    note 'expected while connected; after a disconnect it is an orphan — the next launch kills it'
  else
    ok 'no sing-box / tun2socks process is running'
  fi
else
  warn 'pgrep not available — cannot look for orphaned tunnel processes'
fi

# =============================================================== 5. summary ==
section 'summary'
printf 'OK %s · WARN %s · FAIL %s\n' "$OK_N" "$WARN_N" "$FAIL_N"
if [ "$UNAME_S" != 'Darwin' ]; then
  printf 'Not macOS: the lines above only show that this script runs — none of them is a\n'
  printf 'verdict about a Mac. Run it on the Mac itself.\n'
  exit 0
fi
if [ $FAIL_N -gt 0 ]; then
  printf 'Something above is broken. Paste this WHOLE output into %s\n' "$ISSUES"
  exit 1
fi
if [ $WARN_N -gt 0 ]; then
  printf 'No hard failure. If the app still misbehaves, paste this whole output into %s\n' "$ISSUES"
else
  printf 'Everything checked out. If the app still misbehaves, paste this whole output into %s\n' "$ISSUES"
fi
exit 0
