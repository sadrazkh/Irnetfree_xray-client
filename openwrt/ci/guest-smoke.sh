#!/bin/sh
# Runs INSIDE the OpenWrt guest (busybox ash), started by qemu-smoke.js after
# it has put the ipk, this file and install.sh in /tmp. Installs the package
# the way a user would, then asks the gateway to come up against a SOCKS
# upstream that runs in this same guest (a second sing-box, bound to the LAN
# device so it can never loop into the tunnel) and goes to the internet
# through it: the TUN device, sing-box's policy route, our rules and table,
# the fw4 zone, WHERE PACKETS GO (five route lookups), a TCP fetch and a DNS
# query from the router through the tunnel, a live change of the exclusion
# list, and a clean teardown. Prints SMOKE OK last.
set -eu
say() { echo; echo "== $*"; }

say "the installer, with the package it was given (feeds, node, the ipk)"
sh /tmp/install.sh /tmp/irnetfree.ipk
/etc/init.d/irnetfree enabled || { echo "postinst did not enable the service"; exit 1; }
uci -q get firewall.irnetfree.name | grep -qx irnetfree || { echo "uci-defaults did not add the firewall zone"; exit 1; }
[ "$(uci -q get firewall.irnetfree.input)" = "ACCEPT" ] || { echo "the zone's input is not ACCEPT — sing-box's system stack delivers LAN TCP as INPUT on the tun"; exit 1; }
[ -s /etc/irnetfree/token ] || { echo "no token was generated"; exit 1; }

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

say "disconnect"
rpc '{"channel":"disconnect"}' >/dev/null
sleep 3
if ip link show IRNetFree >/dev/null 2>&1; then echo "the TUN device is still there"; exit 1; fi
if nft list table inet irnetfree >/dev/null 2>&1; then echo "the nft table is still there"; exit 1; fi
if ip rule show | grep -q '^8999:'; then echo "the bypass rule is still there"; exit 1; fi
if ip rule show | grep -q '^8998:'; then echo "the main-first rule is still there"; exit 1; fi
r="$(ip route get 8.8.8.8)"; echo "router -> internet after disconnect: $r"
echo "$r" | grep -q "via $GW" || { echo "after disconnect the router does not go out the WAN"; exit 1; }

say "SMOKE OK"
