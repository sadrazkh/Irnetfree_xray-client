'use strict';
const { sh } = require('./tunPlatform');
const dnsArgs = values => (values && values.length ? values : ['Empty']).map(sh).join(' ');
function buildMacTeardownScript({ pid, bin, cfgFile, pidFile = cfgFile + '.pid', identityFile = cfgFile + '.identity', dnsFile = cfgFile + '.dns', service, savedDns }) {
  return `#!/bin/bash
PIDFILE=${sh(pidFile)}
IDENTITY=${sh(identityFile)}
DNSFILE=${sh(dnsFile)}
PID=${sh(String(Number.isSafeInteger(Number(pid)) && Number(pid) > 1 ? Number(pid) : ''))}
[ -s "$PIDFILE" ] && PID=$(cat "$PIDFILE")
case "$PID" in ''|*[!0-9]*) PID='';; esac
EXPECTED=${sh(`${bin || ''} run -c ${cfgFile}`)}
owned() {
  [ -n "$PID" ] && [ "$PID" -gt 1 ] && [ -s "$IDENTITY" ] || return 1
  [ "$(ps -ww -p "$PID" -o command= 2>/dev/null)" = "$EXPECTED" ] || return 1
  [ "$(ps -ww -p "$PID" -o lstart= 2>/dev/null)" = "$(cat "$IDENTITY")" ]
}
if owned; then
  kill -TERM "$PID" || exit 21
  i=0
  while owned && [ $i -lt 20 ]; do sleep 0.2; i=$((i+1)); done
  if owned; then kill -KILL "$PID" || exit 22; fi
  i=0
  while owned && [ $i -lt 20 ]; do sleep 0.2; i=$((i+1)); done
  if owned; then echo 'Owned tunnel process still running' >&2; exit 23; fi
elif [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null && [ ! -s "$IDENTITY" ]; then
  echo 'Missing tunnel process identity; recovery retained' >&2
  exit 24
fi
${service ? `if [ -f "$DNSFILE" ]; then
  networksetup -setdnsservers ${sh(service)} ${dnsArgs(savedDns)} || exit 25
  rm -f "$DNSFILE"
fi` : 'true'}
exit 0
`;
}
function buildMacSetupScript({ bin, cfgFile, logFile, pidFile, devFile, identityFile = cfgFile + '.identity', dnsFile = cfgFile + '.dns', teardownPath = cfgFile + '.teardown', service, dnsServers = [] }) {
 return `#!/bin/bash
trap '' HUP
BIN=${sh(bin)}
CFG=${sh(cfgFile)}
LOG=${sh(logFile)}
PIDFILE=${sh(pidFile)}
DEVFILE=${sh(devFile)}
IDENTITY=${sh(identityFile)}
DNSFILE=${sh(dnsFile)}
rollback() {
  code=$?
  trap - EXIT
  if [ "$code" -ne 0 ]; then
    /bin/bash ${sh(teardownPath)} || echo 'Tunnel rollback failed; recovery required' >&2
    tail -c 4096 "$LOG" >&2 2>/dev/null
  fi
  exit "$code"
}
trap rollback EXIT
BEFORE=" $(ifconfig -l 2>/dev/null) "
"$BIN" run -c "$CFG" >"$LOG" 2>&1 </dev/null &
SBPID=$!
echo "$SBPID" > "$PIDFILE" || exit 10
ps -ww -p "$SBPID" -o lstart= > "$IDENTITY" || exit 10
ACTUAL=""
i=0
while [ $i -lt 50 ]; do
  kill -0 "$SBPID" 2>/dev/null || break
  ACTUAL=""
  count=0
  for u in $(ifconfig -l 2>/dev/null); do
    case "$u" in
      utun[0-9]*)
        case "$BEFORE" in
          *" $u "*) ;;
          *)
            info=$(ifconfig "$u" 2>/dev/null)
            if echo "$info" | grep -Eq 'inet 172\\.19\\.0\\.1( |$)' && echo "$info" | grep -Eq 'inet6 fdfe:dcba:9876::1( |%)'; then
              ACTUAL="$u"; count=$((count+1))
            fi;;
        esac;;
    esac
  done
  [ "$count" -eq 1 ] && break
  ACTUAL=""
  i=$((i+1)); sleep 0.3
 done
if [ -z "$ACTUAL" ] || ! kill -0 "$SBPID" 2>/dev/null; then
  echo 'ERR: sing-box did not create a unique ready utun device' >&2
  exit 11
fi
echo "$ACTUAL" > "$DEVFILE" || exit 12
${service && dnsServers.length ? `touch "$DNSFILE" || exit 13
networksetup -setdnsservers ${sh(service)} ${dnsArgs(dnsServers)} || exit 14` : 'true'}
kill -0 "$SBPID" 2>/dev/null || exit 15
exit 0
`;
}
module.exports = { buildMacSetupScript, buildMacTeardownScript };
