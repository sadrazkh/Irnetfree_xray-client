#!/bin/sh
# Runs INSIDE the OpenWrt guest (busybox ash), started by qemu-smoke.js after
# it has put the ipk, this file and install.sh in /tmp. Installs the package
# the way a user would, then asks the gateway to come up against a SOCKS
# upstream that runs in this same guest (a second sing-box, bound to the LAN
# device so it can never loop into the tunnel) and goes to the internet
# through it: the TUN device, sing-box's policy route, our rules and table,
# the fw4 zone, WHERE PACKETS GO (five route lookups), a TCP fetch and a DNS
# query from the router through the tunnel, a live change of the exclusion
# list; then what keeps a router online with nobody there: a request that used
# to kill the service, sing-box and xray each killed, the service restarted and
# killed outright — the gateway must come back every time — and nothing of the
# token in syslog; and a clean teardown. Prints SMOKE OK last.
set -eu
say() { echo; echo "== $*"; }

say "a second LAN-side zone (a guest Wi-Fi) that forwards to wan — it must get the tunnel too"
uci -q batch <<'EOF'
set firewall.ci_guest=zone
set firewall.ci_guest.name='guest'
set firewall.ci_guest.input='REJECT'
set firewall.ci_guest.output='ACCEPT'
set firewall.ci_guest.forward='REJECT'
set firewall.ci_guest_wan=forwarding
set firewall.ci_guest_wan.src='guest'
set firewall.ci_guest_wan.dest='wan'
commit firewall
EOF

say "the installer, with the package it was given (feeds, node, the ipk)"
sh /tmp/install.sh /tmp/irnetfree.ipk
/etc/init.d/irnetfree enabled || { echo "postinst did not enable the service"; exit 1; }
uci -q get firewall.irnetfree.name | grep -qx irnetfree || { echo "uci-defaults did not add the firewall zone"; exit 1; }
[ "$(uci -q get firewall.irnetfree.input)" = "ACCEPT" ] || { echo "the zone's input is not ACCEPT — sing-box's system stack delivers LAN TCP as INPUT on the tun"; exit 1; }
[ -s /etc/irnetfree/token ] || { echo "no token was generated"; exit 1; }
uci show firewall | grep -E "^firewall\.irnetfree_(lan|guest)\." || true
[ "$(uci -q get firewall.irnetfree_lan.dest)" = irnetfree ] || { echo "lan does not forward to the tunnel zone"; exit 1; }
[ "$(uci -q get firewall.irnetfree_guest.src)" = guest ] && [ "$(uci -q get firewall.irnetfree_guest.dest)" = irnetfree ] \
	|| { echo "the guest zone forwards to wan but not to the tunnel zone — no internet for it while connected"; exit 1; }
[ "$(uci show firewall | grep -c "\.dest='irnetfree'")" = 2 ] || { echo "a forwarding to the tunnel zone is missing or doubled"; uci show firewall | grep irnetfree; exit 1; }

say "test tools and the feed cores"
opkg install sing-box xray-core curl jq >/dev/null

say "service up"
i=0
until curl -fs -o /dev/null http://127.0.0.1:6969/web-api.js; do
	i=$((i+1))
	[ $i -lt 150 ] || { echo "the UI did not come up"; logread | tail -60; exit 1; }
	sleep 2
done
TOKEN="$(cat /etc/irnetfree/token)"
rpc() { curl -fs -X POST "http://127.0.0.1:6969/rpc?token=$TOKEN" -H 'Content-Type: application/json' -d "$1"; }

say "flavor, backend, the router's defaults"
rpc '{"channel":"app:init"}' | jq -e '.result.flavor == "openwrt" and .result.tunBackendId == "openwrt"' >/dev/null
rpc '{"channel":"settings:get"}' | jq -c '.result | {autoConnect, lanBlockQuic, dnsManaged, tunMode}'
rpc '{"channel":"settings:get"}' | jq -e '.result.autoConnect == true and .result.lanBlockQuic == true and .result.dnsManaged == true' >/dev/null \
	|| { echo "the router defaults were not applied to a fresh store"; exit 1; }

say "an upstream: a SOCKS server in this guest, bound to the LAN device so it cannot loop into the tunnel"
cat > /tmp/upstream.json <<'EOF'
{"log":{"level":"warn"},"inbounds":[{"type":"socks","tag":"in","listen":"192.168.1.1","listen_port":1081}],"outbounds":[{"type":"direct","tag":"out","bind_interface":"br-lan"}]}
EOF
sing-box run -c /tmp/upstream.json > /tmp/upstream.log 2>&1 &
i=0
until netstat -tln 2>/dev/null | grep -q ':1081 '; do
	i=$((i+1))
	[ $i -lt 30 ] || { echo "the upstream SOCKS never listened"; cat /tmp/upstream.log; exit 1; }
	sleep 1
done
ID="$(rpc '{"channel":"servers:addProxy","arg":{"type":"socks","address":"192.168.1.1","port":1081,"name":"ci-upstream"}}' | jq -r '.result.server.id')"
[ -n "$ID" ] && [ "$ID" != null ] || { echo "servers:addProxy returned no id"; exit 1; }
# dnsManaged:false is ignored on a router (forced on) — the answer must say so
rpc '{"channel":"settings:set","arg":{"tunMode":true,"routingMode":"global","blockAds":false,"dnsManaged":false,"lanBypassMacs":["02:00:00:00:00:01"]}}' \
	| jq -e '.result.settings.lanBypassMacs == ["02:00:00:00:00:01"] and .result.settings.dnsManaged == true' >/dev/null

# The WAN as this guest has it: the slirp gateway, which sits on br-lan (one
# NIC). "Out the WAN" below means "via that gateway", not a device name.
GW="$(ip route show default | sed -n 's/.*via \([0-9.]*\).*/\1/p' | head -n 1)"
[ -n "$GW" ] || { echo "no default gateway before connect"; ip route; exit 1; }
echo "WAN gateway: $GW"

say "connect"
rpc "{\"channel\":\"connect\",\"arg\":\"$ID\"}" > /tmp/connect.json || true
cat /tmp/connect.json; echo
jq -e '.result.tunError == null' /tmp/connect.json >/dev/null || { echo "the gateway reported an error"; logread | tail -60; exit 1; }
i=0
until ip link show IRNetFree >/dev/null 2>&1; do
	i=$((i+1))
	[ $i -lt 90 ] || { echo "no TUN device after connect"; logread | tail -80; exit 1; }
	sleep 1
done

say "assert: sing-box routes, our rules, our table, the zone"
ip rule show
ip rule show | grep -q 'lookup 2022' || { echo "sing-box laid no policy route"; exit 1; }
ip rule show | grep -q '^8998:.*lookup main suppress_prefixlength 0' || { echo "the main-first rule is missing"; exit 1; }
ip rule show | grep -q '^8999:' || { echo "the bypass rule is missing"; exit 1; }
nft list table inet irnetfree
nft list table inet irnetfree | grep -q '02:00:00:00:00:01' || { echo "the excluded MAC is not in the set"; exit 1; }
nft list ruleset | grep -q 'oifname "IRNetFree"' || { echo "fw4 has no rule for the IRNetFree device"; exit 1; }

say "assert: where packets actually go (the v1.13.2 outage: the router's own LAN replies entered the tunnel)"
ip route show table 2022
r="$(ip route get 192.168.1.50)"; echo "router -> LAN client:      $r"
echo "$r" | grep -q 'dev br-lan' || { echo "the router's own packets to a LAN client would enter the tunnel"; exit 1; }
r="$(ip route get 8.8.8.8)"; echo "router -> internet:        $r"
echo "$r" | grep -q 'dev IRNetFree' || { echo "the router's own internet traffic is not tunnelled"; exit 1; }
r="$(ip route get 8.8.8.8 from 192.168.1.50 iif br-lan)"; echo "LAN client -> internet:    $r"
echo "$r" | grep -q 'dev IRNetFree' || { echo "a LAN client's internet traffic is not tunnelled"; exit 1; }
r="$(ip route get 192.168.1.60 from 192.168.1.50 iif br-lan)"; echo "LAN client -> LAN client:  $r"
echo "$r" | grep -q 'dev br-lan' || { echo "LAN-to-LAN would enter the tunnel"; exit 1; }
r="$(ip route get 8.8.8.8 from 192.168.1.50 iif br-lan mark 0x1f1e)"; echo "excluded device -> internet: $r"
echo "$r" | grep -q "via $GW" || { echo "an excluded device's traffic is not going out the WAN"; exit 1; }
if echo "$r" | grep -q 'dev IRNetFree'; then echo "an excluded device's traffic entered the tunnel"; exit 1; fi
# the DNS leak: a resolver on a CONNECTED subnet (an ISP modem on the WAN's own
# net is the usual one) must still be reached through the tunnel — only DNS;
# anything else on that subnet stays local
r="$(ip route get $GW ipproto udp dport 53)"; echo "router -> DNS on a connected subnet: $r"
echo "$r" | grep -q 'dev IRNetFree' || { echo "a DNS query to a resolver on a connected subnet would leak"; exit 1; }
r="$(ip route get $GW ipproto udp dport 123)"; echo "router -> NTP on a connected subnet: $r"
echo "$r" | grep -q 'dev br-lan' || { echo "non-DNS traffic to a connected subnet left the LAN"; exit 1; }
nft list table inet irnetfree | grep -q 'udp dport 443 counter.*reject' || { echo "the QUIC refusal is missing (on by default on a router)"; exit 1; }

say "assert: traffic really passes through the tunnel (the v1.13.3 outage: TCP died at the zone's INPUT)"
# the router's own unbound sockets go to the tunnel (rule 9003), so this curl
# is: tun -> sing-box -> socks -> xray -> the upstream -> the internet
code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 60 http://1.1.1.1/ || true)"
echo "TCP through the tunnel: HTTP $code"
[ -n "$code" ] && [ "$code" != "000" ] || { echo "no TCP through the tunnel"; logread | tail -40; cat /tmp/upstream.log; exit 1; }
# a plain UDP query to a public resolver: port 53 must be answered by the core (dns-out), never ride the proxy as UDP
out="$(nslookup example.com 1.1.1.1 2>&1 || true)"; echo "$out" | tail -4
echo "$out" | grep -qi 'address' || { echo "no DNS through the tunnel"; exit 1; }

say "the exclusion list changes live"
PIDS="$(pidof sing-box | tr ' ' '\n' | sort | tr '\n' ' ')"
rpc '{"channel":"settings:set","arg":{"lanBypassMacs":["02:00:00:00:00:02"]}}' >/dev/null
sleep 2
nft list table inet irnetfree | grep -q '02:00:00:00:00:02' || { echo "the new MAC is missing"; exit 1; }
if nft list table inet irnetfree | grep -q '02:00:00:00:00:01'; then echo "the old MAC is still there"; exit 1; fi
[ "$(pidof sing-box | tr ' ' '\n' | sort | tr '\n' ' ')" = "$PIDS" ] || { echo "the tunnel was restarted for a set change"; exit 1; }

# --- what keeps a router online with nobody there to press a button ---
# The gateway's own sing-box (its config is irnf-sb-…) and core (config in
# /etc/irnetfree), told apart from the upstream sing-box this script runs.
cmdline() { tr '\0' ' ' < "/proc/$1/cmdline" 2>/dev/null || true; }
gw_singbox() { for p in $(pidof sing-box || true); do cmdline "$p" | grep -q 'irnf-sb-' && echo "$p"; done; return 0; }
core_xray() { for p in $(pidof xray || true); do cmdline "$p" | grep -q '/etc/irnetfree/' && echo "$p"; done; return 0; }
upstream_pid() { for p in $(pidof sing-box || true); do cmdline "$p" | grep -q 'upstream\.json' && echo "$p"; done; return 0; }
gateway_up() {
	ip link show IRNetFree >/dev/null 2>&1 && ip rule show | grep -q 'lookup 2022' \
		&& ip rule show | grep -q '^8998:' && ip rule show | grep -q '^8999:'
}
# syslog since a marker: the service mirrors its state changes there ("irnetfree: connected — …")
mark() { MARK="irnf-smoke-$1-$$"; logger -t irnf-smoke "$MARK"; }
since_mark() { logread | sed -n "/$MARK/,\$p"; }
# wait_back <what> <seconds>: a new "connected" since the marker, the device and every rule
wait_back() {
	i=0
	until since_mark | grep -q 'irnetfree: connected' && gateway_up; do
		i=$((i+1))
		[ "$i" -lt "$2" ] || { echo "$1: the gateway did not come back within $2s"; ip rule show; since_mark | tail -60; exit 1; }
		sleep 1
	done
	echo "$1: back after ${i}s — sing-box $(gw_singbox | tr '\n' ' ')xray $(core_xray | tr '\n' ' ')"
	since_mark | grep 'irnetfree:' | tail -8
}
one_each() {
	[ "$(gw_singbox | wc -l)" = 1 ] || { echo "$1: not exactly one gateway sing-box: $(gw_singbox | tr '\n' ' ')"; exit 1; }
	[ "$(core_xray | wc -l)" = 1 ] || { echo "$1: not exactly one core: $(core_xray | tr '\n' ' ')"; exit 1; }
}
UPSTREAM="$(upstream_pid)"

say "memory while connected: MemAvailable and the RSS of node, xray and sing-box (S6 — the numbers behind any GOMEMLIMIT)"
grep -E '^(MemTotal|MemAvailable):' /proc/meminfo
for p in $(pidof node) $(gw_singbox) $(core_xray); do
	printf 'pid %s %s: %s\n' "$p" "$(cat "/proc/$p/comm")" "$(grep VmRSS "/proc/$p/status" | tr -s ' \t' ' ')"
done

say "a request target the URL parser refuses is a 400 — it used to end the service (and the gateway) with no token"
NODE="$(pidof node || true)"
code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 'http://127.0.0.1:6969//x:99999/' || true)"
echo "GET //x:99999/ -> HTTP $code"
[ "$code" = 400 ] || { echo "expected 400"; logread | tail -30; exit 1; }
sleep 3
[ "$(pidof node || true)" = "$NODE" ] || { echo "the service died or restarted: '$NODE' -> '$(pidof node || true)'"; logread | tail -40; exit 1; }
gateway_up || { echo "the gateway went down"; exit 1; }

say "kill -9 the gateway's sing-box: the service sees it and rebuilds the gateway"
OLD="$(gw_singbox)"; echo "sing-box $OLD"
mark singbox
kill -9 $OLD
wait_back "sing-box killed" 180
[ "$(gw_singbox)" != "$OLD" ] || { echo "still the old sing-box"; exit 1; }
since_mark | grep -q 'irnetfree: \[error\] Gateway down: sing-box exited on its own' || { echo "the exit did not reach syslog"; exit 1; }
one_each "after the sing-box kill"

say "kill -9 the core: the service sees it and rebuilds (sing-box would route the LAN into a dead SOCKS port)"
OLD="$(core_xray)"; echo "xray $OLD"
mark xray
kill -9 $OLD
wait_back "xray killed" 180
[ "$(core_xray)" != "$OLD" ] || { echo "still the old core"; exit 1; }
since_mark | grep -q 'irnetfree: \[error\] The core exited on its own' || { echo "the exit did not reach syslog"; exit 1; }
one_each "after the core kill"

say "a crash loop: the core killed three more times, each soon after its rebuild — the waits grow, no rebuild every few seconds"
mark loop; LOOP="$MARK"
for n in 1 2 3; do
	OLD="$(core_xray)"
	mark "loop$n"
	kill -9 $OLD
	wait_back "crash $n of 3" 240
	[ "$(core_xray)" != "$OLD" ] || { echo "still the old core"; exit 1; }
done
WAITS="$(logread | sed -n "/$LOOP/,\$p" | sed -n 's/.*dropped again [0-9]*s after it was rebuilt.*waiting \([0-9.]*\)s before the next rebuild.*/\1/p' | tr '\n' ' ')"
echo "waits before each rebuild (s): $WAITS"
echo "$WAITS" | awk '{ if (NF < 3) exit 1; for (i = 2; i <= NF; i++) if ($i + 0 <= $(i - 1) + 0) exit 1 }' \
	|| { echo "the waits did not grow across the crash loop"; exit 1; }
one_each "after the crash loop"

say "restart the service while connected: the boot connect brings the gateway back (a stale activeServerId used to stop it)"
NODE="$(pidof node || true)"
mark restart
/etc/init.d/irnetfree restart
wait_back "service restarted" 300
[ "$(pidof node || true)" != "$NODE" ] || { echo "the service was not restarted"; exit 1; }
one_each "after the restart"

say "kill -9 the service: procd respawns it; the new one ends the cores the old one left and brings the gateway back"
NODE="$(pidof node)"; OLD_SB="$(gw_singbox)"; OLD_X="$(core_xray)"
echo "node $NODE, sing-box $OLD_SB, xray $OLD_X (left running when node dies without its exit hook)"
mark respawn
kill -9 "$NODE"
wait_back "service killed and respawned" 300
for p in $OLD_SB $OLD_X; do [ ! -d "/proc/$p" ] || { echo "the orphan $p ($(cmdline "$p")) survived"; exit 1; }; done
since_mark | grep -q 'a previous run left behind' || { echo "the new service did not say it ended the orphans"; exit 1; }
one_each "after the respawn"
[ "$(upstream_pid)" = "$UPSTREAM" ] || { echo "the sweep touched a sing-box that is not the service's own"; exit 1; }

say "the recovered gateway carries traffic"
code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 60 http://1.1.1.1/ || true)"
echo "TCP through the tunnel: HTTP $code"
[ -n "$code" ] && [ "$code" != "000" ] || { echo "no TCP through the recovered tunnel"; logread | tail -40; exit 1; }

say "syslog: the gateway's story is there, the token is not"
logread -e irnetfree | grep 'irnetfree:' | tail -12
logread | grep -q 'Token    : /etc/irnetfree/token' || { echo "the banner does not say where the token is"; exit 1; }
if logread | grep -q "$TOKEN"; then echo "the token is in the system log"; exit 1; fi
if cmdline "$(pidof node)" | grep -q "$TOKEN"; then echo "the token is on the service's command line"; exit 1; fi

# --- v1.16: the connection as one fact, the LuCI facade, the remote bypass, the WAN watcher, the kill switch ---

say "the connection as one fact (S1/S2): app:init.conn says connected with its uptime source; a Connect on the live connection is a no-op"
rpc '{"channel":"app:init"}' | jq -e '.result.conn.state == "connected" and .result.conn.since != null and .result.conn.tun == true and .result.conn.serverId != null' >/dev/null \
	|| { echo "app:init.conn does not say connected"; rpc '{"channel":"app:init"}' | jq '.result.conn'; exit 1; }
PIDS="$(gw_singbox)"
rpc "{\"channel\":\"connect\",\"arg\":\"$ID\"}" | jq -e '.result.already == true' >/dev/null || { echo "a second Connect on the live connection was not a no-op"; exit 1; }
[ "$(gw_singbox)" = "$PIDS" ] || { echo "the gateway was rebuilt for a Connect on the live connection"; exit 1; }

say "the LuCI facade (A9): loopback only, the token in the body, the live state"
luci() { uclient-fetch -q -O - --post-data="{\"token\":\"$TOKEN\",\"arg\":$2}" "http://127.0.0.1:6969/luci/$1"; }
luci status '{}' > /tmp/luci-status.json
jq -e '.state == "connected" and .version != null and .traffic.up >= 0 and .killSwitch.enabled == false' /tmp/luci-status.json >/dev/null || { echo "luci/status is wrong"; cat /tmp/luci-status.json; exit 1; }
jq -c '{state, since, memAvailableKb, traffic}' /tmp/luci-status.json
luci configs '{}' | jq -e '(.groups | length) >= 1 and .activeId != null' >/dev/null || { echo "luci/configs is wrong"; exit 1; }
luci log '{"lines":5}' | jq -e '(.lines | length) <= 5 and (.lines | length) >= 1' >/dev/null || { echo "luci/log is wrong"; exit 1; }
luci diagnostics '{}' > /tmp/diag.json
jq -r '.text' /tmp/diag.json | grep -E '^(MemAvailable|RSS):' || { echo "the diagnostics carry no memory lines"; jq -r '.text' /tmp/diag.json | head -20; exit 1; }
if jq -r '.text' /tmp/diag.json | grep -q "$TOKEN"; then echo "the token is in the diagnostics"; exit 1; fi
echo "luci/test: $(luci test '{}')"
code="$(curl -s -o /dev/null -w '%{http_code}' -X POST --data '{"token":"nope","arg":{}}' http://127.0.0.1:6969/luci/status)"; [ "$code" = 401 ] || { echo "a wrong token got $code"; exit 1; }
code="$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:6969/luci/status)"; [ "$code" = 405 ] || { echo "a GET got $code"; exit 1; }
code="$(curl -s -o /dev/null -w '%{http_code}' -X POST --data "{\"token\":\"$TOKEN\",\"arg\":{}}" http://192.168.1.1:6969/luci/status)"; [ "$code" = 403 ] || { echo "a LAN-address peer got $code (loopback only)"; exit 1; }
luci settings_set '{"lanBlockQuic":false}' | jq -e '.ok == true and .settings.lanBlockQuic == false' >/dev/null || { echo "settings_set failed"; exit 1; }
sleep 2
if nft list table inet irnetfree | grep -q 'udp dport 443'; then echo "settings_set did not apply live"; exit 1; fi
luci settings_set '{"lanBlockQuic":true}' >/dev/null

say "destinations the remote control uses never ride the tunnel (A10)"
rpc '{"channel":"remote:bypass","arg":{"owner":"relay","hosts":["relay.example"],"cidrs":["198.51.100.1/32"]}}' | jq -e '.result.ok == true' >/dev/null
ip rule show | grep '^8997:' || { echo "no 8997 rule"; ip rule show; exit 1; }
r="$(ip route get 198.51.100.1)"; echo "router -> the relay's address: $r"
echo "$r" | grep -q "via $GW" || { echo "the relay's address does not leave by the WAN"; exit 1; }
if echo "$r" | grep -q 'dev IRNetFree'; then echo "the relay's address entered the tunnel"; exit 1; fi
ip route get 8.8.8.8 | grep -q 'dev IRNetFree' || { echo "everything else is no longer tunnelled"; exit 1; }
rpc '{"channel":"remote:bypass","arg":{"owner":"relay","hosts":[],"cidrs":[]}}' >/dev/null
if ip rule show | grep -q '^8997:'; then echo "the 8997 rule did not go"; exit 1; fi

say "a network change judged by a probe (S3): a second default route appears through netifd — the tunnel answers, kept"
uci -q batch <<'EOF'
set network.wtest=interface
set network.wtest.proto='static'
set network.wtest.device='br-lan'
set network.wtest.ipaddr='192.168.1.9'
set network.wtest.netmask='255.255.255.0'
set network.wtest.gateway='192.168.1.2'
set network.wtest.metric='50'
commit network
EOF
PIDS="$(gw_singbox)"
ifup wtest
judged() { luci log '{"lines":80}' | jq -r '.lines[]' | grep -q "$1"; }
i=0
until judged 'Network changed (wtest: default v4 route appeared'; do
	i=$((i+1)); [ $i -lt 60 ] || { echo "the watcher never judged the change"; luci log '{"lines":40}' | jq -r '.lines[]' | tail -20; exit 1; }; sleep 1
done
luci log '{"lines":80}' | jq -r '.lines[]' | grep 'Network changed' | tail -1
judged 'Network changed (wtest: default v4 route appeared.*— the tunnel answers, kept' || { echo "the change was not kept"; luci log '{"lines":40}' | jq -r '.lines[]' | tail -20; exit 1; }
ifdown wtest; uci -q delete network.wtest; uci commit network
i=0
until judged 'Network changed (wtest: default v4 route gone) — the tunnel answers, kept'; do
	i=$((i+1)); [ $i -lt 60 ] || { echo "the route leaving was not judged"; luci log '{"lines":40}' | jq -r '.lines[]' | tail -20; exit 1; }; sleep 1
done
[ "$(gw_singbox)" = "$PIDS" ] || { echo "the gateway was rebuilt for a change the tunnel survived"; exit 1; }

# --- the kill switch (K1–K6): armed while the VPN is meant to be on; the LAN has no internet while the tunnel is down ---
say "kill switch on: the table is in the kernel, the snippet on disk, status says armed and not blocking"
luci settings_set '{"killSwitch":true}' | jq -e '.ok == true and .settings.killSwitch == true' >/dev/null || { echo "settings_set killSwitch failed"; exit 1; }
i=0; until nft list table inet irnetfree_ks >/dev/null 2>&1; do i=$((i+1)); [ $i -lt 20 ] || { echo "no kill switch table"; logread -e irnetfree | tail -20; exit 1; }; sleep 1; done
nft list table inet irnetfree_ks
[ -s /etc/irnetfree/killswitch.nft ] || { echo "no boot snippet"; exit 1; }
nft -c -f /etc/irnetfree/killswitch.nft || { echo "the snippet does not validate"; exit 1; }
rpc '{"channel":"app:init"}' | jq -e '.result.conn.killSwitch == {"enabled":true,"armed":true,"blocking":false}' >/dev/null || { echo "status does not say armed"; rpc '{"channel":"app:init"}' | jq '.result.conn.killSwitch'; exit 1; }
[ -L /etc/rc.d/S19irnetfree-ks ] || { echo "irnetfree-ks is not enabled at boot"; ls /etc/rc.d | grep irnetfree; exit 1; }

say "a LAN-side network namespace: packets the router FORWARDS (a probe from 127.0.0.1 proves nothing about the LAN)"
# Two ways to put a peer behind the router. A: a veth whose other end is a port
# of br-lan — the peer is a station on the LAN (192.168.1.77). B: a routed
# veth on its own /30 (192.168.77.2 behind veth0), veth0 added to the lan
# zone, which is what fw4 needs to forward it like the LAN. Whichever pings
# the router first is used; neither → the forward chain is checked by its
# rules alone and the job says so.
LANNS=0; LANIP=; LANIF=; LANMAC=; LANZONE=
lanping() { ip netns exec lan0 ping -c 1 -W 3 "$1" >/dev/null 2>&1; }
lanwhy() {
	echo "-- lan0: addresses, routes, neighbours"
	ip netns exec lan0 ip -4 addr show veth1 | grep inet || true
	ip netns exec lan0 ip route || true
	ip netns exec lan0 ip neigh || true
	echo "-- the router: neighbours on $1, the bridge's ports, a ping back, rp_filter, fw4's input chain"
	ip neigh show dev "$1" || true
	bridge link show 2>/dev/null || true
	ping -c 1 -W 3 "$2" >/dev/null 2>&1 && echo "router -> lan0: ping ok" || echo "router -> lan0: no ping"
	echo "rp_filter: all=$(cat /proc/sys/net/ipv4/conf/all/rp_filter) $1=$(cat "/proc/sys/net/ipv4/conf/$1/rp_filter" 2>/dev/null)"
	nft list chain inet fw4 input 2>/dev/null | head -12 || true
}
if ip netns add lan0 2>/dev/null; then
	opkg install kmod-veth >/dev/null 2>&1 || true
	if ip link add veth0 type veth peer name veth1 2>/dev/null; then
		ip link set veth1 netns lan0
		ip netns exec lan0 ip link set lo up
		ip netns exec lan0 ip link set veth1 up
		LANMAC="$(ip netns exec lan0 cat /sys/class/net/veth1/address)"
		# A: a port of br-lan
		ip link set veth0 master br-lan up
		ip netns exec lan0 ip addr add 192.168.1.77/24 dev veth1
		ip netns exec lan0 ip route add default via 192.168.1.1
		sleep 1
		if lanping 192.168.1.1; then
			LANNS=1; LANIP=192.168.1.77; LANIF=br-lan
			echo "lan0: $LANIP ($LANMAC) as a port of br-lan — pings the router"
		else
			echo "A: a veth port of br-lan does not reach the router — why:"
			lanwhy br-lan 192.168.1.77
			# B: routed, on its own /30, veth0 in the lan zone
			ip link set veth0 nomaster
			ip addr add 192.168.77.1/30 dev veth0
			ip link set veth0 up
			ip netns exec lan0 ip addr flush dev veth1
			ip netns exec lan0 ip addr add 192.168.77.2/30 dev veth1
			ip netns exec lan0 ip route replace default via 192.168.77.1
			for z in $(uci show firewall | sed -n 's/^firewall\.\([^.=]*\)=zone$/\1/p'); do
				[ "$(uci -q get firewall.$z.name)" = lan ] || continue
				uci add_list firewall.$z.device='veth0'; LANZONE="$z"
			done
			uci commit firewall; fw4 reload >/dev/null 2>&1 || true
			sleep 2
			if lanping 192.168.77.1; then
				LANNS=1; LANIP=192.168.77.2; LANIF=veth0
				echo "lan0: $LANIP ($LANMAC) behind a routed veth0 in the lan zone — pings the router"
			else
				echo "B: a routed veth does not reach the router either — why:"
				lanwhy veth0 192.168.77.2
				echo "no working LAN-side namespace — the forward chain is checked by its rules only"
				ip link delete veth0 2>/dev/null || true
				ip netns delete lan0
			fi
		fi
	else
		echo "no veth in this image — the forward chain is checked by its rules only"
		ip netns delete lan0
	fi
else
	echo "no network namespaces in this image — the forward chain is checked by its rules only"
fi
# an HTTP code of any kind is "the internet answers" (1.1.1.1 answers 301 — which wget would follow to https and fail on);
# a rejected connection is an immediate 000
lanprobe() {
	local c
	c="$(ip netns exec lan0 curl -s -o /dev/null -w '%{http_code}' --max-time 15 http://1.1.1.1/ 2>/dev/null || true)"
	[ -n "$c" ] && [ "$c" != "000" ]
}
rejects() { nft list chain inet irnetfree_ks lanblock | sed -n 's/.*counter packets \([0-9]*\) bytes [0-9]* reject.*/\1/p'; }
if [ "$LANNS" = 1 ]; then
	if lanprobe; then echo "lan0 reaches the internet through the tunnel"; else
		echo "lan0 has no internet with the tunnel up (the kill switch must not block a working tunnel)"
		ip route get 1.1.1.1 from "$LANIP" iif "$LANIF" || true
		nft list chain inet irnetfree_ks lanblock || true
		logread | tail -15
		exit 1
	fi
fi

say "sing-box dies and cannot come back (its binary held): the LAN is blocked and the reject counter moves; an excluded device passes; the router itself stays free"
mv /usr/bin/sing-box /usr/bin/sing-box.held
unhold() { [ -e /usr/bin/sing-box.held ] && mv /usr/bin/sing-box.held /usr/bin/sing-box; return 0; }
OLD="$(gw_singbox)"; mark ks
kill -9 $OLD
i=0; until rpc '{"channel":"app:init"}' | jq -e '.result.conn.killSwitch.blocking == true' >/dev/null; do i=$((i+1)); [ $i -lt 30 ] || { echo "status never said blocking"; rpc '{"channel":"app:init"}' | jq '.result.conn'; unhold; exit 1; }; sleep 1; done
nft list table inet irnetfree_ks >/dev/null || { echo "the table went with the gateway"; unhold; exit 1; }
since_mark | grep -q 'Kill switch: the tunnel is down' || { echo "the block did not reach syslog"; since_mark | tail; unhold; exit 1; }
r="$(ip route get 1.1.1.1 from 192.168.1.50 iif br-lan)"; echo "LAN client -> internet with the tunnel down (routing): $r — the firewall says no"
code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 http://1.1.1.1/ || true)"; echo "the router itself -> internet: HTTP $code"
[ -n "$code" ] && [ "$code" != "000" ] || { echo "the router's own traffic is blocked — it must stay free (NTP, opkg, the relay)"; unhold; exit 1; }
before="$(rejects)"; before="${before:-0}"
if [ "$LANNS" = 1 ]; then
	if lanprobe; then echo "lan0 still reaches the internet with the tunnel down"; unhold; exit 1; fi
	after="$(rejects)"; after="${after:-0}"
	echo "reject counter: $before -> $after"
	[ "$after" -gt "$before" ] || { echo "the reject counter did not move"; nft list chain inet irnetfree_ks lanblock; unhold; exit 1; }
	echo "-- the namespace's MAC excluded: marked by the kill switch's own chain, it passes"
	luci settings_set "{\"lanBypassMacs\":[\"$LANMAC\"]}" | jq -e '.ok == true' >/dev/null
	sleep 2
	nft list table inet irnetfree_ks | grep -q "$LANMAC" || { echo "the excluded MAC is not in the kill switch's set"; nft list table inet irnetfree_ks; unhold; exit 1; }
	lanprobe || { echo "an excluded device has no internet while the tunnel is down"; nft list chain inet irnetfree_ks lanblock; unhold; exit 1; }
	r="$(ip route get 1.1.1.1 from "$LANIP" iif "$LANIF" mark 0x1f1e)"; echo "excluded device -> internet: $r"
	echo "$r" | grep -q "via $GW" || { echo "an excluded device's traffic does not leave by the WAN"; unhold; exit 1; }
	luci settings_set '{"lanBypassMacs":[]}' >/dev/null
	sleep 2
	if lanprobe; then echo "lan0 reaches the internet after its exclusion was removed"; unhold; exit 1; fi
else
	nft list chain inet irnetfree_ks lanblock | grep -q 'reject with icmpx.*admin-prohibited' || { echo "no reject rule"; unhold; exit 1; }
	nft list chain inet irnetfree_ks lanblock | grep -q 'meta mark 0x00001f1e accept' || { echo "no accept for excluded devices"; nft list chain inet irnetfree_ks lanblock; unhold; exit 1; }
fi

say "the binary back: the gateway recovers by itself, the block lifts, the table stays (the VPN is still meant to be on)"
unhold
wait_back "kill switch recovery" 300
rpc '{"channel":"app:init"}' | jq -e '.result.conn.killSwitch == {"enabled":true,"armed":true,"blocking":false}' >/dev/null || { echo "status after the recovery is wrong"; rpc '{"channel":"app:init"}' | jq '.result.conn.killSwitch'; exit 1; }
nft list table inet irnetfree_ks >/dev/null || { echo "the table went with the rebuild"; exit 1; }
judged 'Kill switch: the tunnel is back' || { echo "the lift is not in the log"; luci log '{"lines":30}' | jq -r '.lines[]' | tail -10; exit 1; }
if [ "$LANNS" = 1 ]; then lanprobe || { echo "lan0 has no internet after the recovery"; exit 1; }; fi
one_each "after the kill switch recovery"

say "a reboot-equivalent: the table deleted by hand, /etc/init.d/irnetfree-ks start replays the snippet; stop lifts it"
nft delete table inet irnetfree_ks
/etc/init.d/irnetfree-ks start
nft list table inet irnetfree_ks >/dev/null || { echo "the boot script did not replay the snippet"; exit 1; }
/etc/init.d/irnetfree-ks stop
if nft list table inet irnetfree_ks >/dev/null 2>&1; then echo "stop did not lift the table"; exit 1; fi
/etc/init.d/irnetfree-ks start
nft list table inet irnetfree_ks >/dev/null || { echo "start did not bring it back"; exit 1; }

say "disconnect"
rpc '{"channel":"disconnect"}' >/dev/null
sleep 3
if ip link show IRNetFree >/dev/null 2>&1; then echo "the TUN device is still there"; exit 1; fi
if nft list table inet irnetfree >/dev/null 2>&1; then echo "the nft table is still there"; exit 1; fi
# the user's disconnect disarms the kill switch: table and snippet gone, the LAN direct
if nft list table inet irnetfree_ks >/dev/null 2>&1; then echo "the kill switch table outlived the user's disconnect"; exit 1; fi
[ ! -e /etc/irnetfree/killswitch.nft ] || { echo "the boot snippet outlived the disconnect"; exit 1; }
rpc '{"channel":"app:init"}' | jq -e '.result.conn.state == "disconnected" and .result.conn.killSwitch.armed == false' >/dev/null || { echo "the snapshot after the disconnect is wrong"; exit 1; }
if [ "$LANNS" = 1 ]; then
	lanprobe || { echo "lan0 has no internet after the VPN was turned off"; exit 1; }
	echo "lan0 goes direct with the VPN off"
	ip netns delete lan0   # takes the veth pair with it
	if [ -n "$LANZONE" ]; then uci del_list firewall.$LANZONE.device='veth0'; uci commit firewall; fw4 reload >/dev/null 2>&1 || true; fi
fi
if ip rule show | grep -q '^8999:'; then echo "the bypass rule is still there"; exit 1; fi
if ip rule show | grep -q '^8998:'; then echo "the main-first rule is still there"; exit 1; fi
r="$(ip route get 8.8.8.8)"; echo "router -> internet after disconnect: $r"
echo "$r" | grep -q "via $GW" || { echo "after disconnect the router does not go out the WAN"; exit 1; }

say "a disconnect by hand survives a restart: the router stays the way the user left it"
mark stay
/etc/init.d/irnetfree restart
i=0
until curl -fs -o /dev/null http://127.0.0.1:6969/web-api.js; do
	i=$((i+1))
	[ $i -lt 150 ] || { echo "the UI did not come back"; exit 1; }
	sleep 2
done
sleep 30   # longer than a boot connect takes here (6-12s above): one would have shown by now
if ip link show IRNetFree >/dev/null 2>&1 || since_mark | grep -q 'irnetfree: connected'; then
	echo "the router reconnected after a disconnect by hand"; since_mark | tail -20; exit 1
fi
echo "still disconnected after the restart"

say "SMOKE OK"
