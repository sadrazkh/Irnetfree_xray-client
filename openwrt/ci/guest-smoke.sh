#!/bin/sh
# Runs INSIDE the OpenWrt guest (busybox ash), started by qemu-smoke.js after
# it has put the ipk and this file in /tmp. Installs the package the way a user
# would, then asks the gateway to come up against a SOCKS upstream that does not
# exist — no internet is needed for what is asserted: the TUN device, sing-box's
# policy route, our nft table with the excluded MAC, the fw4 zone, and that a
# change of the exclusion list does not restart the tunnel. Prints SMOKE OK last.
set -eu
say() { echo; echo "== $*"; }

say "the installer, with the package it was given (feeds, node, the ipk)"
sh /tmp/install.sh /tmp/irnetfree.ipk
/etc/init.d/irnetfree enabled || { echo "postinst did not enable the service"; exit 1; }

say "test tools and the feed cores"
opkg install sing-box xray-core curl jq >/dev/null
uci -q get firewall.irnetfree.name | grep -qx irnetfree || { echo "uci-defaults did not add the firewall zone"; exit 1; }
[ -s /etc/irnetfree/token ] || { echo "no token was generated"; exit 1; }

say "service up"
i=0
until curl -fs -o /dev/null http://127.0.0.1:6969/web-api.js; do
	i=$((i+1))
	[ $i -lt 150 ] || { echo "the UI did not come up"; logread | tail -60; exit 1; }
	sleep 2
done
TOKEN="$(cat /etc/irnetfree/token)"
rpc() { curl -fs -X POST "http://127.0.0.1:6969/rpc?token=$TOKEN" -H 'Content-Type: application/json' -d "$1"; }

say "flavor and backend"
rpc '{"channel":"app:init"}' | jq -e '.result.flavor == "openwrt" and .result.tunBackendId == "openwrt"' >/dev/null

say "a server that needs no internet"
ID="$(rpc '{"channel":"servers:addProxy","arg":{"type":"socks","address":"127.0.0.1","port":1,"name":"ci-dummy"}}' | jq -r '.result.server.id')"
[ -n "$ID" ] && [ "$ID" != null ] || { echo "servers:addProxy returned no id"; exit 1; }
rpc '{"channel":"settings:set","arg":{"tunMode":true,"routingMode":"global","blockAds":false,"dnsManaged":false,"lanBypassMacs":["02:00:00:00:00:01"]}}' \
	| jq -e '.result.settings.lanBypassMacs == ["02:00:00:00:00:01"]' >/dev/null

say "connect"
rpc "{\"channel\":\"connect\",\"arg\":\"$ID\"}" > /tmp/connect.json || true
cat /tmp/connect.json; echo
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
echo "$r" | grep -q 'dev eth0' || { echo "an excluded device's traffic is not going out the WAN"; exit 1; }
nft list table inet irnetfree
nft list table inet irnetfree | grep -q '02:00:00:00:00:01' || { echo "the excluded MAC is not in the set"; exit 1; }
nft list ruleset | grep -q 'oifname "IRNetFree"' || { echo "fw4 has no rule for the IRNetFree device"; exit 1; }

say "the exclusion list changes live"
PID="$(pidof sing-box)"
rpc '{"channel":"settings:set","arg":{"lanBypassMacs":["02:00:00:00:00:02"]}}' >/dev/null
sleep 2
nft list table inet irnetfree | grep -q '02:00:00:00:00:02' || { echo "the new MAC is missing"; exit 1; }
if nft list table inet irnetfree | grep -q '02:00:00:00:00:01'; then echo "the old MAC is still there"; exit 1; fi
[ "$(pidof sing-box)" = "$PID" ] || { echo "the tunnel was restarted for a set change"; exit 1; }

say "disconnect"
rpc '{"channel":"disconnect"}' >/dev/null
sleep 3
if ip link show IRNetFree >/dev/null 2>&1; then echo "the TUN device is still there"; exit 1; fi
if nft list table inet irnetfree >/dev/null 2>&1; then echo "the nft table is still there"; exit 1; fi
if ip rule show | grep -q '^8999:'; then echo "the bypass rule is still there"; exit 1; fi
if ip rule show | grep -q '^8998:'; then echo "the main-first rule is still there"; exit 1; fi
r="$(ip route get 8.8.8.8)"; echo "router -> internet after disconnect: $r"
echo "$r" | grep -q 'dev eth0' || { echo "after disconnect the router does not go out the WAN"; exit 1; }

say "SMOKE OK"
