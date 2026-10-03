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
# the installed files are not dated 1970 (build-ipk stamps the commit's time): uhttpd hands a view's mtime to the
# browser as Last-Modified, and a 1970 view stayed "fresh" in the browser for years after an upgrade
m="$(date -r /www/luci-static/resources/view/irnetfree/overview.js +%s 2>/dev/null || echo '?')"
echo "LuCI overview.js mtime: $m ($(date -u -r /www/luci-static/resources/view/irnetfree/overview.js 2>/dev/null || echo '?'))"
case "$m" in ''|*[!0-9]*) echo "(date -r cannot read it on this image: not asserted)" ;; *) [ "$m" -gt 31536000 ] || { echo "the LuCI views landed dated 1970: browsers keep the old ones after an upgrade"; exit 1; } ;; esac

say "test tools and the feed cores (kmod-veth: the WAN-change interface and the LAN-side namespace below)"
opkg install sing-box xray-core curl jq kmod-veth >/dev/null

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

# ---- remote control (feat/remote): the relay link's building blocks on this node, cloudflared from the feed ----
say "remote: the WebSocket, frame, token, agent and api modules run on this node (the relay link's building blocks)"
cat > /tmp/remote-selftest.js <<'EOF'
const http = require('http');
const { wsConnect, wsAccept } = require('/usr/lib/irnetfree/src/server/remote/ws');
const { T, encode, decode } = require('/usr/lib/irnetfree/src/server/remote/frames');
const { mintToken, isToken } = require('/usr/lib/irnetfree/src/server/remote/token');
const { forbiddenPath } = require('/usr/lib/irnetfree/src/server/remote/agent');
const api = require('/usr/lib/irnetfree/src/server/remote/api');
const srv = http.createServer();
srv.on('upgrade', (req, socket, head) => {
  const c = wsAccept(req, socket, head);
  c.on('message', (m) => { const f = decode(m); c.send(encode(T.RES_HEAD, f.stream, { status: 200, echo: f.json(), auth: req.headers.authorization })); });
});
srv.listen(0, '127.0.0.1', async () => {
  const token = mintToken();
  const c = await wsConnect('ws://127.0.0.1:' + srv.address().port + '/_relay/agent', { headers: { Authorization: 'Bearer ' + token } });
  c.on('message', (m) => {
    const f = decode(m);
    const j = f.json();
    const ok = f.type === T.RES_HEAD && f.stream === 7 && j.echo.hello === 'router' && j.auth === 'Bearer ' + token && isToken(token)
      && forbiddenPath('/luci/x') && forbiddenPath('/_relay/agent') && !forbiddenPath('/rpc') && api.METHODS.length === 4;
    console.log(ok ? 'REMOTE SELFTEST OK on node ' + process.version : 'REMOTE SELFTEST FAILED ' + JSON.stringify(j));
    c.close(1000); srv.close(); process.exit(ok ? 0 : 1);
  });
  c.send(encode(T.REQ_HEAD, 7, { hello: 'router' }));
});
setTimeout(() => { console.log('REMOTE SELFTEST TIMEOUT'); process.exit(1); }, 30000);
EOF
node /tmp/remote-selftest.js | tee /tmp/remote-selftest.log
grep -q 'REMOTE SELFTEST OK' /tmp/remote-selftest.log || { echo "the remote modules do not run on this node"; exit 1; }

say "remote: the service started remote access without an error (nothing enabled yet — no link, no dial)"
if logread | grep -q 'remote: not started'; then echo "the remote api did not start"; logread | grep 'remote' | tail -n 5; exit 1; fi
if logread | grep -qi 'remote:.*dialing'; then echo "the agent dialed although nothing is enabled"; exit 1; fi
echo "remote access idle, as configured"

say "remote: cloudflared in this release's feed — package, version, its UCI config and init script, dnsmasq's drop-in dir"
if opkg install cloudflared > /tmp/cf-install.log 2>&1; then
	echo "cloudflared: installed from the feed"
	opkg status cloudflared | grep -E '^(Version|Architecture|Installed-Size):'
	cloudflared --version 2>&1 | head -n 1 || true
	[ -x /etc/init.d/cloudflared ] || { echo "the package ships no init script"; exit 1; }
	echo "--- /etc/config/cloudflared"; cat /etc/config/cloudflared
	echo "--- /etc/init.d/cloudflared: how it reads enabled / token / protocol"
	grep -n 'config_get\|procd_set_param command\|procd_append_param\|token\|protocol' /etc/init.d/cloudflared || true
	# the default config file may not list `token` (24.10's does not); what matters is that the init reads it
	grep -q 'token' /etc/init.d/cloudflared || { echo "the package's init script does not read a token option — the spec's fallback (TUNNEL_TOKEN in the env) would be needed"; exit 1; }
	uci -q show cloudflared | grep -q '^cloudflared\.[A-Za-z0-9_]*=cloudflared' || { echo "no section of type cloudflared"; exit 1; }
	node -e "require('/usr/lib/irnetfree/src/server/remote/cloudflared').createCloudflared().status().then(s => { console.log('cloudflared status: ' + JSON.stringify(s)); process.exit(s.installed ? 0 : 1); })" \
		|| { echo "status does not report installed"; exit 1; }
	# the real apply path, on then off, with a token that cannot work (base64 of a made-up JSON): the UCI
	# write through uci batch on stdin, protocol pinned to http2, the service enabled/started, the dnsmasq
	# drop-in written into the dir dnsmasq really reads (23.05: /tmp/dnsmasq.d; 24.10: /tmp/dnsmasq.<cfg>.d)
	# and READ by dnsmasq — apply restarts it (a reload is a SIGHUP: dnsmasq re-reads no config on one)
	# — then everything undone
	CF_DIRS="$(grep -h '^conf-dir=' /var/etc/dnsmasq.conf.* 2>/dev/null | cut -d= -f2 | cut -d, -f1 | sort -u | tr '\n' ' ')"
	echo "dnsmasq conf-dir(s): ${CF_DIRS:-none}"
	[ -n "$CF_DIRS" ] || { echo "dnsmasq's generated config names no conf-dir"; grep -hs 'conf-dir\|conf-file' /var/etc/dnsmasq.conf.* || true; exit 1; }
	CF_MARK="irnf-smoke-cf-on-$$"; logger -t irnf-smoke "$CF_MARK"
	node -e "const c = require('/usr/lib/irnetfree/src/server/remote/cloudflared').createCloudflared({ log: (l) => console.log('  ' + l) }); c.apply({ enabled: true, token: 'eyJhIjoiMDAwIiwidCI6IjAwMCIsInMiOiIwMDAifQ==' }).then((r) => { console.log('apply on: ' + JSON.stringify(r)); return c.status(); }).then((s) => { console.log('status while on: ' + JSON.stringify(s)); process.exit(0); }).catch((e) => { console.log('apply failed: ' + e.message); process.exit(1); })" \
		|| { echo "apply on failed"; exit 1; }
	[ "$(uci -q get cloudflared.config.protocol)" = http2 ] || { echo "protocol was not pinned to http2 in UCI"; uci show cloudflared; exit 1; }
	[ "$(uci -q get cloudflared.config.enabled)" = 1 ] || { echo "apply on did not write enabled=1"; uci show cloudflared; exit 1; }
	for d in $CF_DIRS; do
		[ -s "$d/irnetfree-cloudflared.conf" ] || { echo "no drop-in in $d (where dnsmasq reads) after apply on + dnsmasq restart"; ls -la "$d" 2>&1 || true; exit 1; }
	done
	echo "--- the drop-in, as written"; cat "${CF_DIRS%% *}/irnetfree-cloudflared.conf"
	grep -q '^server=/argotunnel.com/' "${CF_DIRS%% *}/irnetfree-cloudflared.conf" || { echo "the drop-in does not name argotunnel.com"; exit 1; }
	i=0
	until logread | sed -n "/$CF_MARK/,\$p" | grep -q 'for domain argotunnel\.com'; do
		i=$((i+1))
		[ $i -lt 10 ] || { echo "dnsmasq did not read the drop-in after apply on (no 'for domain argotunnel.com' since it)"; logread | sed -n "/$CF_MARK/,\$p" | grep -i dnsmasq | tail -n 10; exit 1; }
		sleep 1
	done
	echo "dnsmasq read it: $(logread | sed -n "/$CF_MARK/,\$p" | grep 'for domain argotunnel\.com' | tail -n 1)"
	node -e "require('/usr/lib/irnetfree/src/server/remote/cloudflared').createCloudflared({ log: (l) => console.log('  ' + l) }).apply({ enabled: false, token: '' }).then((r) => { console.log('apply off: ' + JSON.stringify(r)); process.exit(0); }).catch((e) => { console.log('apply off failed: ' + e.message); process.exit(1); })" \
		|| { echo "apply off failed"; exit 1; }
	[ "$(uci -q get cloudflared.config.enabled)" = 0 ] || { echo "apply off did not write enabled=0"; uci show cloudflared; exit 1; }
	for d in $CF_DIRS /tmp/dnsmasq.d; do
		[ ! -e "$d/irnetfree-cloudflared.conf" ] || { echo "the dnsmasq drop-in in $d was not removed when off"; exit 1; }
	done
	if pidof cloudflared >/dev/null; then echo "cloudflared still runs after apply off"; exit 1; fi
	echo "cloudflared: UCI written, http2 pinned, started and stopped through its own init, drop-in written where dnsmasq reads and cleaned"
else
	echo "cloudflared: NOT installable from this feed:"; tail -n 5 /tmp/cf-install.log
	node -e "require('/usr/lib/irnetfree/src/server/remote/cloudflared').createCloudflared().status().then(s => { console.log('cloudflared status: ' + JSON.stringify(s)); process.exit(s.installed ? 1 : 0); })" \
		|| { echo "status claims installed without the binary"; exit 1; }
fi
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
# On its own link (a veth pair), never as an alias of br-lan: on 23.05 netifd
# took the LAN's shared connected route away with the alias (run #209), and
# every rebuild after that refused the gateway — rightly — for a LAN without
# its route. The gateway on that link is nobody; the route's metric keeps it
# behind the real default, and only its existence is what the watcher sees.
ip link add wt0 type veth peer name wt1
ip link set wt1 up
ip link set wt0 up
uci -q batch <<'EOF'
set network.wtest=interface
set network.wtest.proto='static'
set network.wtest.device='wt0'
set network.wtest.ipaddr='192.168.78.1'
set network.wtest.netmask='255.255.255.0'
set network.wtest.gateway='192.168.78.2'
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
ip link del wt0
# the LAN's own route must have survived all of the above (a rebuild's verify needs it)
ip route show | grep -q '^192.168.1.0/24 dev br-lan' || { echo "the LAN's connected route is gone from main"; ip route; exit 1; }

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
	lanping 192.168.1.2 && echo "lan0 -> slirp (192.168.1.2): ping ok" || echo "lan0 -> slirp (192.168.1.2): no ping"
	echo "-- the router: neighbours on $1, the bridge's ports, a ping back, rp_filter, fw4's input chain"
	ip neigh show dev "$1" || true
	bridge link show 2>/dev/null || true
	[ -e /sys/class/net/br-lan/brif/veth0/state ] && echo "veth0 port state: $(cat /sys/class/net/br-lan/brif/veth0/state) (3 = forwarding)"
	bridge fdb show br br-lan 2>/dev/null | grep -i "$LANMAC" || echo "no fdb entry for $LANMAC"
	ping -c 1 -W 3 "$2" >/dev/null 2>&1 && echo "router -> lan0: ping ok" || echo "router -> lan0: no ping"
	echo "rp_filter: all=$(cat /proc/sys/net/ipv4/conf/all/rp_filter) $1=$(cat "/proc/sys/net/ipv4/conf/$1/rp_filter" 2>/dev/null)"
	nft list chain inet fw4 input 2>/dev/null | head -12 || true
	nft list chain inet fw4 input_lan 2>/dev/null || true
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
			# slirp (this guest's "WAN") answers a direct packet by ARPing its source on the
			# virtual link; an address behind a routed veth needs the router to answer for it
			ip neigh add proxy 192.168.77.2 dev br-lan
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
# a tunnel that just came up carries traffic a moment later on an emulated CPU: up to ten tries, 3 s apart
lanprobe_soon() {
	local i=0
	until lanprobe; do
		i=$((i+1)); [ $i -lt 10 ] || return 1
		sleep 3
	done
	[ $i = 0 ] || echo "(lan0 reached the internet after $i retries)"
}
lantunnelwhy() {
	ip route get 1.1.1.1 from "$LANIP" iif "$LANIF" || true
	ip rule show || true
	nft list chain inet irnetfree_ks lanblock || true
	logread | tail -15
}
if [ "$LANNS" = 1 ]; then
	if lanprobe_soon; then echo "lan0 reaches the internet through the tunnel"; else
		echo "lan0 has no internet with the tunnel up (the kill switch must not block a working tunnel)"
		lantunnelwhy
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
if [ "$LANNS" = 1 ]; then lanprobe_soon || { echo "lan0 has no internet after the recovery"; lantunnelwhy; exit 1; }; fi
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
	if [ -n "$LANZONE" ]; then
		ip neigh del proxy 192.168.77.2 dev br-lan 2>/dev/null || true
		uci del_list firewall.$LANZONE.device='veth0'; uci commit firewall; fw4 reload >/dev/null 2>&1 || true
	fi
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

# ===========================================================================
# LuCI (feat/router-luci): the rpcd plugin, the ubus API the pages call, and
# the pages as LuCI serves them to a browser, all through the service's own
# /luci API (the facade) — strict: a facade that does not answer fails here.
# ===========================================================================
say "LuCI: what this image has (the armsr initramfs may come without LuCI or rpcd)"
for p in rpcd uhttpd uhttpd-mod-ubus luci-base luci-mod-admin-full luci-theme-bootstrap; do
	if opkg list-installed | grep -q "^$p "; then echo "  $p: in the image"; else echo "  $p: not in the image"; fi
done
if ! opkg list-installed | grep -q '^luci-base ' || ! opkg list-installed | grep -q '^rpcd '; then
	echo "installing LuCI from the feed (opkg install luci: luci-base, the admin pages, the theme, uhttpd, rpcd)"
	opkg install luci >/dev/null || { echo "could not install LuCI from the feed"; exit 1; }
	/etc/init.d/rpcd restart >/dev/null 2>&1 || true
	/etc/init.d/uhttpd enable >/dev/null 2>&1 || true
	/etc/init.d/uhttpd restart >/dev/null 2>&1 || true
	sleep 3
fi

say "LuCI: the package's pieces are where rpcd and LuCI look for them"
for f in /usr/libexec/rpcd/luci.irnetfree /usr/share/rpcd/acl.d/luci-app-irnetfree.json /usr/share/luci/menu.d/luci-app-irnetfree.json \
	/www/luci-static/resources/view/irnetfree/overview.js /www/luci-static/resources/view/irnetfree/settings.js \
	/www/luci-static/resources/view/irnetfree/remote.js /www/luci-static/resources/view/irnetfree/log.js \
	/www/luci-static/resources/irnetfree/common.js /usr/lib/lua/luci/i18n/irnetfree.fa.lmo; do
	[ -s "$f" ] || { echo "missing: $f"; exit 1; }
done
[ -x /usr/libexec/rpcd/luci.irnetfree ] || { echo "the rpcd plugin is not executable"; exit 1; }

say "LuCI: rpcd lists luci.irnetfree with every method (postinst reloads rpcd)"
i=0
until ubus -v list luci.irnetfree > /tmp/luci-ubus.txt 2>/dev/null; do
	i=$((i+1))
	[ $i -lt 15 ] || { echo "rpcd does not know luci.irnetfree"; ubus list | head -40; exit 1; }
	sleep 1
done
cat /tmp/luci-ubus.txt
for m in status configs connect select disconnect reconnect test subs_update settings_get settings_set devices log \
	diagnostics remote_get remote_set remote_status cloudflared_install service; do
	grep -q "\"$m\":" /tmp/luci-ubus.txt || { echo "luci.irnetfree has no method $m"; exit 1; }
done

lu() { ubus call luci.irnetfree "$@" 2>&1 || true; }

say "LuCI: status through the plugin"
r="$(lu status)"; echo "$r" | head -30
echo "$r" | grep -q '"state": "' || { echo "status through LuCI gave no state — the facade must answer here"; exit 1; }

say "LuCI: a stopped service reads as not-running, and the plugin's own service call starts it"
/etc/init.d/irnetfree stop
# the service closes its port only after its shutdown (the gateway first): wait for it
i=0
until lu status | grep -q '"error": "not-running"'; do
	i=$((i+1))
	[ $i -lt 30 ] || { echo "a stopped service did not read as not-running within 30s"; lu status; exit 1; }
	sleep 1
done
echo "stopped: status reads not-running after ${i}s"
r="$(lu service '{"action":"halt"}')"
echo "$r" | grep -q '"error": "bad action"' || { echo "the service call took an action it should refuse: $r"; exit 1; }
r="$(lu service '{"action":"start"}')"; echo "$r"
echo "$r" | grep -q '"ok": true' || { echo "service start through LuCI failed"; exit 1; }
i=0
until curl -fs -o /dev/null http://127.0.0.1:6969/web-api.js; do
	i=$((i+1))
	[ $i -lt 150 ] || { echo "the service did not come back after a start from LuCI"; logread | tail -30; exit 1; }
	sleep 2
done
r="$(lu status)"
case "$r" in *'"error": "not-running"'*) echo "still not-running after the start"; exit 1 ;; esac
echo "started from LuCI, answering again"

say "LuCI: the VPN switch on (connect from the Overview's API) — the status says connected"
mark luci
r="$(lu connect "{\"id\":\"$ID\"}")"; echo "$r"
echo "$r" | grep -q '"accepted": true' || { echo "connect through LuCI was not accepted"; exit 1; }
wait_back "LuCI connect" 180
r="$(lu status)"; echo "$r" | head -24
echo "$r" | grep -q '"state": "connected"' || { echo "status through LuCI does not say connected while the gateway is up"; exit 1; }

say "LuCI: the kill switch from Settings arms its table at once, and the table goes when it is turned off"
r="$(lu settings_set '{"killSwitch":true}')"; echo "$r" | head -12
echo "$r" | grep -q '"ok": true' || { echo "settings_set {killSwitch:true} was refused"; exit 1; }
i=0
until nft list table inet irnetfree_ks >/dev/null 2>&1; do
	i=$((i+1))
	[ $i -lt 15 ] || { echo "settings_set {killSwitch:true} did not arm the kill switch (no table inet irnetfree_ks)"; exit 1; }
	sleep 1
done
nft list table inet irnetfree_ks | head -24
lu settings_set '{"killSwitch":false}' | grep -q '"ok": true' || { echo "settings_set {killSwitch:false} was refused"; exit 1; }
i=0
while nft list table inet irnetfree_ks >/dev/null 2>&1; do
	i=$((i+1))
	[ $i -lt 15 ] || { echo "the kill switch table stayed after it was turned off"; exit 1; }
	sleep 1
done

say "LuCI: the VPN switch off"
lu disconnect | grep -q '"accepted": true' || { echo "disconnect through LuCI was not accepted"; exit 1; }
i=0
while ip link show IRNetFree >/dev/null 2>&1; do
	i=$((i+1))
	[ $i -lt 60 ] || { echo "the TUN device stayed after a disconnect from LuCI"; exit 1; }
	sleep 1
done
lu status | grep -q '"state": "disconnected"' || { echo "status does not say disconnected after the switch went off"; exit 1; }

say "LuCI: the rest of the API answers in the shapes the pages read"
lu configs | grep -q '"groups"' || { echo "configs has no groups"; exit 1; }
lu settings_get | grep -q '"killSwitch": false' || { echo "settings_get does not show the kill switch off"; exit 1; }
lu devices | grep -q '"result"' || { echo "devices did not come back as {result: [...]}"; exit 1; }
lu log '{"lines":20}' | grep -q '"lines"' || { echo "log has no lines"; exit 1; }
lu diagnostics | grep -q '"text"' || { echo "diagnostics has no text"; exit 1; }
lu remote_get | grep -q '"relay"' || { echo "remote_get through LuCI has no relay settings"; exit 1; }

say "LuCI over HTTP: a browser's login, the menu with the four tabs, the pages, the ubus calls through the ACL"
code="$(curl -s -o /dev/null -w '%{http_code}' -c /tmp/luci.jar -d 'luci_username=root&luci_password=' http://127.0.0.1/cgi-bin/luci/ || true)"
SID="$(awk '$6 ~ /^sysauth/ { print $7 }' /tmp/luci.jar 2>/dev/null | head -n 1)"
echo "login: HTTP $code, session ${SID:+(set)}"
[ -n "$SID" ] || { echo "no LuCI session after the login"; exit 1; }
curl -s -b /tmp/luci.jar -o /tmp/luci-menu.json http://127.0.0.1/cgi-bin/luci/admin/menu
jq -M -c '.children.admin.children.services.children.irnetfree | {title, satisfied, tabs: (.children | keys)}' /tmp/luci-menu.json || true
jq -e '.children.admin.children.services.children.irnetfree | (.satisfied != false) and (.children | has("overview") and has("settings") and has("remote") and has("log"))' /tmp/luci-menu.json >/dev/null \
	|| { echo "the LuCI menu has no Services -> IRNetFree with its four tabs (or the ACL is not granted)"; jq -M -c '.children.admin.children.services.children | keys' /tmp/luci-menu.json; exit 1; }
for p in overview settings remote log; do
	code="$(curl -s -b /tmp/luci.jar -o /tmp/luci-page.html -w '%{http_code}' "http://127.0.0.1/cgi-bin/luci/admin/services/irnetfree/$p" || true)"
	grep -q "irnetfree/$p" /tmp/luci-page.html || { echo "the $p tab (HTTP $code) does not load the view irnetfree/$p"; head -c 600 /tmp/luci-page.html; exit 1; }
	code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1/luci-static/resources/view/irnetfree/$p.js" || true)"
	[ "$code" = 200 ] || { echo "/luci-static/resources/view/irnetfree/$p.js: HTTP $code"; exit 1; }
	echo "  $p: the page and its view are served"
done
code="$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1/luci-static/resources/irnetfree/common.js || true)"
[ "$code" = 200 ] || { echo "/luci-static/resources/irnetfree/common.js: HTTP $code"; exit 1; }
# the call a page makes, with the page's session: rpcd must grant it through the ACL
luci_rpc() { curl -s -H 'Content-Type: application/json' -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"call\",\"params\":[\"$SID\",$1]}" http://127.0.0.1/ubus/; }
r="$(luci_rpc '"luci.irnetfree","status",{}')"
echo "ubus over HTTP, luci.irnetfree status: $(echo "$r" | cut -c1-160)"
echo "$r" | jq -e '.result[0] == 0 and (.result[1].state | type) == "string"' >/dev/null || { echo "the LuCI session gets no status through luci.irnetfree (the ACL or the facade)"; exit 1; }
luci_rpc '"file","read",{"path":"/etc/irnetfree/token"}' | jq -e '.result[0] == 0 and (.result[1].data | length) > 0' >/dev/null \
	|| { echo "the LuCI session may not read the token file for the web UI link (the ACL)"; exit 1; }
# the tab names in Persian: LuCI's fa catalog has them, under the hash the browser computes (sfh "Remote access")
curl -s -b /tmp/luci.jar -o /tmp/luci-fa.js http://127.0.0.1/cgi-bin/luci/admin/translations/fa
grep -qF '"45517f0a":"دسترسی از راه دور"' /tmp/luci-fa.js \
	|| { echo "the Persian tab names are not in LuCI's fa catalog"; head -c 300 /tmp/luci-fa.js; echo; exit 1; }
echo "LuCI's fa catalog has the IRNetFree tab names ($(grep -o '"[0-9a-f]\{8\}":' /tmp/luci-fa.js | wc -l) strings in all)"

# ===========================================================================
# v1.16.1 LuCI (fix/v1161-luci) — the owner's first install: «فعال» on Remote
# access must be honest (a setting that cannot work is refused with the reason,
# and the refusal is a warn line in syslog), the status carries what the
# Overview's "Whole-network tunnel" row and the Cloudflare state line read,
# and a Connect on the config that is already up answers already:true (the
# page then says: press Reconnect to apply changes).
# ===========================================================================
say "LuCI v1.16.1: Remote access refuses an «Enabled» that cannot work, says why, and syslog has it"
mark luci161
r="$(lu remote_set '{"relay":{"enabled":true}}')"; echo "$r"
echo "$r" | jq -e '.error == "enabling needs the relay URL and the device token"' >/dev/null \
	|| { echo "remote_set took the relay enabled without its URL and device token"; exit 1; }
if [ -x /usr/bin/cloudflared ]; then want='enabling needs the Cloudflare tunnel token'; else want='enabling needs cloudflared'; fi
r="$(lu remote_set '{"cloudflared":{"enabled":true}}')"; echo "$r"
echo "$r" | jq -e --arg w "$want" '.error | startswith($w)' >/dev/null \
	|| { echo "remote_set took Cloudflare enabled (cloudflared $([ -x /usr/bin/cloudflared ] && echo installed || echo 'not installed'), no token) — expected: $want"; exit 1; }
lu remote_get | jq -e '.relay.enabled == false and .cloudflared.enabled == false' >/dev/null || { echo "a refused remote_set saved something"; lu remote_get; exit 1; }
i=0
until since_mark | grep -q 'LuCI: remote_set refused: enabling needs the relay URL and the device token'; do
	i=$((i+1))
	[ $i -lt 10 ] || { echo "the refusal is not in syslog (warn)"; since_mark | tail -10; exit 1; }
	sleep 1
done
since_mark | grep 'LuCI: remote_set refused' | tail -2
r="$(lu remote_status)"; echo "$r" | jq -c '.cloudflared | {installed, running, enabled, tokenSet, applying, apply}'
echo "$r" | jq -e '.cloudflared | (.enabled == false) and (.tokenSet == false) and (.applying == false) and has("apply")' >/dev/null \
	|| { echo "remote_status does not say whether Cloudflare is meant to run (the page's «Enabled but not running» line)"; exit 1; }

say "LuCI v1.16.1: the Overview's whole-network row (tun), and Connect on the live config answers already:true without a rebuild"
r="$(lu connect "{\"id\":\"$ID\"}")"; echo "$r"
echo "$r" | jq -e '.accepted == true and .already != true' >/dev/null || { echo "a connect from disconnected was not accepted as a real connect"; exit 1; }
wait_back "LuCI v1.16.1 connect" 180
lu status | jq -e '.state == "connected" and .tun == true' >/dev/null || { echo "status does not say tun:true while the gateway is up"; lu status | head -30; exit 1; }
sleep 3   # the connect's own bookkeeping ends just after "connected"
GW="$(gw_singbox | tr '\n' ' ')"; CORE="$(core_xray | tr '\n' ' ')"
r="$(lu connect "{\"id\":\"$ID\"}")"; echo "$r"
echo "$r" | jq -e '.accepted == true and .already == true' >/dev/null || { echo "a Connect on the config that is already up did not answer already:true"; exit 1; }
sleep 5
[ "$(gw_singbox | tr '\n' ' ')" = "$GW" ] && [ "$(core_xray | tr '\n' ' ')" = "$CORE" ] \
	|| { echo "the Connect on the live config rebuilt the gateway (sing-box $GW -> $(gw_singbox | tr '\n' ' '), xray $CORE -> $(core_xray | tr '\n' ' '))"; exit 1; }
gateway_up || { echo "the gateway is not up after the Connect on the live config"; exit 1; }
echo "already:true — the same sing-box ($GW) and xray ($CORE), nothing rebuilt"
lu disconnect | jq -e '.accepted == true' >/dev/null || { echo "disconnect through LuCI was not accepted"; exit 1; }
i=0
while ip link show IRNetFree >/dev/null 2>&1; do
	i=$((i+1))
	[ $i -lt 60 ] || { echo "the TUN device stayed after the disconnect"; exit 1; }
	sleep 1
done
lu status | jq -e '.tun == false' >/dev/null || { echo "status says tun while disconnected"; exit 1; }

# v1.16.1 core (fix/v1161-core, field report D3): in bypass-ir the in-country
# resolvers the core dials `direct` stay IN the whole-LAN tunnel. v1.16.0 cut
# them out of sing-box's table for every device and every port — dnsmasq's
# upstream (or a phone's hard-coded resolver) then left in plain text by the
# ISP. Only the core's own query to them leaves direct, its socket bound to
# the WAN device — and the router's own control path (review of v1.16.1):
# the service's UDP 53 to them by a rule for its user alone, cloudflared's
# edge discovery by dnsmasq server lines bound to the WAN device.
# The router is disconnected here (the LuCI section ends so).
# Quad9 stands in for the in-country pair: CI can reach it, Iran's cannot be
# relied on from a runner; "Iranian names" come from hand-made geo files
# (geosite CATEGORY-IR = digikala.com, aparat.com; geoip IR = all of IPv4 —
# the only codes bypass-ir loads), so nothing is downloaded.
# ===========================================================================
say "D3: bypass-ir with hand-made geo files and Quad9 as the in-country resolvers"
WANDEV="$(ip route show default | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -n 1)"
WANIP="$(ip -4 addr show dev "$WANDEV" | sed -n 's/.*inet \([0-9.]*\)\/.*/\1/p' | head -n 1)"
echo "WAN device: $WANDEV ($WANIP)"
[ -n "$WANDEV" ] && [ -n "$WANIP" ] || { echo "no WAN device/address before the D3 connect"; ip route; exit 1; }
# (the service's weekly geo refresh may have put real ones there already while
# it sat disconnected — those are used as they are; only a missing one is made)
cat > /tmp/irnf-mkgeo.js <<'EOF'
// protobuf by hand (xray's routercommon): GeoIPList{entry=1} GeoIP{country_code=1, cidr=2} CIDR{ip=1, prefix=2};
// GeoSiteList{entry=1} GeoSite{country_code=1, domain=2} Domain{type=1 (2: a domain and its subdomains), value=2}
const fs = require('fs');
fs.mkdirSync('/tmp/irnf-geo', { recursive: true });
const varint = (n) => { const b = []; while (n > 127) { b.push((n & 127) | 128); n >>>= 7; } b.push(n); return Buffer.from(b); };
const bytes = (no, buf) => Buffer.concat([varint((no << 3) | 2), varint(buf.length), buf]);
const str = (no, s) => bytes(no, Buffer.from(s, 'utf8'));
const num = (no, n) => Buffer.concat([varint(no << 3), varint(n)]);
const cidr = (ip, prefix) => bytes(2, Buffer.concat([bytes(1, Buffer.from(ip.split('.').map(Number))), num(2, prefix)]));
const domain = (v) => bytes(2, Buffer.concat([num(1, 2), str(2, v)]));
fs.writeFileSync('/tmp/irnf-geo/geoip.dat', bytes(1, Buffer.concat([str(1, 'IR'), cidr('0.0.0.0', 1), cidr('128.0.0.0', 1)])));
fs.writeFileSync('/tmp/irnf-geo/geosite.dat', bytes(1, Buffer.concat([str(1, 'CATEGORY-IR'), domain('digikala.com'), domain('aparat.com')])));
EOF
node /tmp/irnf-mkgeo.js
D3_GEO=
for f in geoip.dat geosite.dat; do
	if [ -s "/etc/irnetfree/bin/$f" ]; then echo "$f: the service's own ($(wc -c < "/etc/irnetfree/bin/$f") bytes)"
	else cp "/tmp/irnf-geo/$f" "/etc/irnetfree/bin/$f"; D3_GEO="$D3_GEO $f"; echo "$f: hand-made"; fi
done
rpc '{"channel":"assets:status"}' | jq -e '.result.geoip == true and .result.geosite == true' >/dev/null || { echo "the service does not see the geo files"; ls -la /etc/irnetfree/bin; exit 1; }
D3_DIRECT_WAS="$(rpc '{"channel":"settings:get"}' | jq -c '.result.dnsDirect')"
rpc '{"channel":"settings:set","arg":{"routingMode":"bypass-ir","dnsDirect":["9.9.9.9","149.112.112.112"]}}' \
	| jq -e '.result.settings.routingMode == "bypass-ir"' >/dev/null || { echo "settings:set bypass-ir failed"; exit 1; }
mark d3
rpc "{\"channel\":\"connect\",\"arg\":\"$ID\"}" > /tmp/connect-d3.json || true
jq -c '.result // .error' /tmp/connect-d3.json
wait_back "D3 connect (bypass-ir)" 180
# Quad9 is no in-country resolver, and the service says so for a real router (field report D3)
since_mark | grep -E '(holds public resolvers|رزولورهای عمومی دارد) \(9\.9\.9\.9, 149\.112\.112\.112\)' || { echo "no warning that the in-country DNS holds public resolvers"; exit 1; }

say "D3: the core's config — the DNS module asks the in-country pair direct, the direct dial bound to the WAN device"
C=/etc/irnetfree/config.json
jq -c '.routing.rules[] | select((.inboundTag // []) | index("dns-internal"))' "$C"
jq -e '[.routing.rules[] | select(((.inboundTag // []) | index("dns-internal")) and .outboundTag == "direct" and .port == "53" and .ip == ["9.9.9.9","149.112.112.112"])] | length == 1' "$C" >/dev/null \
	|| { echo "no dns-internal -> direct rule for the in-country resolvers on :53"; exit 1; }
jq -e --arg dev "$WANDEV" '[.outbounds[] | select(.tag == "direct")][0].streamSettings.sockopt.interface == $dev' "$C" >/dev/null \
	|| { echo "the direct outbound is not bound to the WAN device $WANDEV"; jq -c '.outbounds[] | select(.tag == "direct")' "$C"; exit 1; }
SB_CFG="$(cmdline "$(gw_singbox | head -n 1)" | grep -o '/[^ ]*irnf-sb-[^ ]*/sing-box\.json' | head -n 1)"
[ -s "$SB_CFG" ] || { echo "the gateway's sing-box config was not found ($SB_CFG)"; exit 1; }
echo "sing-box route_exclude_address: $(jq -c '.inbounds[0].route_exclude_address' "$SB_CFG")"
jq -e '.inbounds[0].route_exclude_address | index("192.168.1.1/32")' "$SB_CFG" >/dev/null || { echo "the entry server is no longer kept off the tunnel"; exit 1; }
for ip in 9.9.9.9 149.112.112.112; do
	if jq -e --arg c "$ip/32" '.inbounds[0].route_exclude_address | index($c)' "$SB_CFG" >/dev/null; then echo "$ip is cut out of the whole-LAN tunnel again (D3)"; exit 1; fi
done

say "D3: where packets to the in-country resolvers go — a LAN device's DNS and HTTPS and dnsmasq's upstream in the tunnel; only the service's own UDP 53 out the WAN"
# The service's own lookups through them (the relay link resolves its relay
# there) must not need the tunnel: one rule per resolver at pref 8997,
# `iif lo uidrange <service uid> … ipproto udp dport 53 lookup main`
# (TunOpenwrt.layOwnDirect). `iif lo` because the kernel looks up a FORWARDED
# packet's route with uid 0 — without it the rule would take every LAN
# device's DNS to them out again (the `from 192.168.1.50 iif br-lan` lookups
# below are such packets). dnsmasq must run as a user of its own (OpenWrt
# starts it --user=dnsmasq), or the rule would take its upstream out too.
# (procd jails dnsmasq: the jail, named after it, stays root as the parent of
# the dnsmasq that forwards, which runs as its own user — run 37067447979)
DNSMASQ_PID=; DNSMASQ_UID=
for p in $(pidof dnsmasq); do
	pp="$(awk '/^PPid:/{print $2}' "/proc/$p/status" 2>/dev/null)"
	u="$(awk '/^Uid:/{print $2}' "/proc/$p/status" 2>/dev/null)"
	echo "dnsmasq: pid $p, parent $pp ($(cat "/proc/$pp/comm" 2>/dev/null)), uid $u"
	[ -n "$u" ] && [ "$u" != 0 ] && { DNSMASQ_PID=$p; DNSMASQ_UID=$u; }
done
echo "the dnsmasq that forwards: pid ${DNSMASQ_PID:-?}, uid ${DNSMASQ_UID:-?}"
[ -n "$DNSMASQ_UID" ] && [ "$DNSMASQ_UID" != 0 ] || { echo "dnsmasq runs as root here — the own-lookup rule cannot tell it from the service"; exit 1; }
echo "own-lookup rules:"; ip rule show | grep -F 'uidrange' || true
for ip in 9.9.9.9 149.112.112.112; do
	ip rule show | grep '^8997:' | grep -F "to $ip " | grep -F 'iif lo' | grep -F 'uidrange 0-0' | grep -qE 'ipproto (udp|17) dport 53' \
		|| { echo "no own-lookup rule for $ip"; ip rule show; exit 1; }
	r="$(ip route get "$ip" from 192.168.1.50 iif br-lan ipproto udp dport 53)"; echo "LAN client -> $ip:53/udp:  $r"
	echo "$r" | grep -q 'dev IRNetFree' || { echo "a LAN device's DNS to $ip leaves outside the tunnel"; exit 1; }
	r="$(ip route get "$ip" from 192.168.1.50 iif br-lan ipproto tcp dport 443)"; echo "LAN client -> $ip:443/tcp: $r"
	echo "$r" | grep -q 'dev IRNetFree' || { echo "a LAN device's HTTPS to $ip leaves outside the tunnel"; exit 1; }
	r="$(ip route get "$ip" ipproto udp dport 53 uid "$DNSMASQ_UID")"; echo "dnsmasq -> $ip:53/udp:     $r"
	echo "$r" | grep -q 'dev IRNetFree' || { echo "dnsmasq's upstream to $ip leaves outside the tunnel"; exit 1; }
	r="$(ip route get "$ip" ipproto udp dport 53 uid 0)"; echo "service -> $ip:53/udp:     $r"
	if echo "$r" | grep -q 'dev IRNetFree'; then echo "the service's own DNS to $ip (the relay link's lookup) rides the tunnel"; exit 1; fi
	echo "$r" | grep -q "dev $WANDEV" || { echo "the service's own DNS to $ip does not leave by the WAN device $WANDEV"; exit 1; }
	r="$(ip route get "$ip" ipproto tcp dport 443 uid 0)"; echo "service -> $ip:443/tcp:    $r"
	echo "$r" | grep -q 'dev IRNetFree' || { echo "the own-lookup rule let more than UDP 53 to $ip out"; exit 1; }
	r="$(ip route get "$ip" ipproto udp dport 53 uid 65534)"; echo "nobody -> $ip:53/udp:      $r"
	echo "$r" | grep -q 'dev IRNetFree' || { echo "another user's DNS to $ip leaves outside the tunnel — the rule is wider than the service's user"; exit 1; }
done

say "D3: the router still resolves an Iranian name — through the core's direct resolver path, out the WAN"
out=; i=0
until echo "$out" | sed -n '/^Name:/,$p' | grep -q '^Address'; do
	i=$((i+1))
	[ $i -le 6 ] || { echo "www.digikala.com did not resolve through the hijack"; echo "$out"; logread | tail -20; exit 1; }
	out="$(nslookup www.digikala.com 1.1.1.1 2>&1 || true)"
	echo "$out" | sed -n '/^Name:/,$p' | grep -q '^Address' || sleep 5
done
echo "$out" | sed -n '/^Name:/,$p'
if [ -r /proc/net/nf_conntrack ]; then
	# (run 37068874055: the answer above came before the core's query showed up
	# here — it asked a moment later — so a few looks, each after a name the core
	# has not cached: its own query to the in-country pair, then)
	ct=; i=0
	while :; do
		ct="$(grep -E "src=$WANIP dst=(9\.9\.9\.9|149\.112\.112\.112) sport=[0-9]+ dport=53 " /proc/net/nf_conntrack | head -n 2 || true)"
		[ -n "$ct" ] && break
		i=$((i+1)); [ $i -le 5 ] || break
		nslookup "ci$i.digikala.com" 1.1.1.1 >/dev/null 2>&1 || true
		sleep 1
	done
	echo "conntrack, the core's own query: ${ct:-none}"
	[ -n "$ct" ] || { echo "no query from the WAN address ($WANIP) to the in-country resolvers — the core's direct path did not leave by the WAN"; grep -E 'dport=53 ' /proc/net/nf_conntrack | head -n 10 || true; exit 1; }
	if grep -qE "src=172\.19\.0\.1 dst=(9\.9\.9\.9|149\.112\.112\.112) .*dport=53 " /proc/net/nf_conntrack; then echo "the core's query to the in-country resolvers looped into the tunnel"; exit 1; fi
else
	echo "no /proc/net/nf_conntrack in this image — the config's direct rule and its WAN binding (above) are the proof"
fi

say "D3: real packets — the service's user's query to an in-country resolver leaves from the WAN address, another user's enters the tunnel"
# (after the conntrack check above: the second query leaves a tunnel-side entry)
if [ -r /proc/net/nf_conntrack ]; then
	cat > /tmp/irnf-own-dns.js <<'EOF'
// one A query (example.com) to <ip>:53 from a fixed source port — as this user, or as <uid>, set BEFORE
// the socket exists: the kernel routes by the socket's owner, fixed when the socket is made
const [ip, port, uid] = process.argv.slice(2);
if (uid) process.setuid(Number(uid));
const s = require('dgram').createSocket('udp4');
const q = Buffer.from('123401000001000000000000076578616d706c6503636f6d0000010001', 'hex');
s.bind(Number(port), () => s.send(q, 53, ip));
s.on('message', () => { console.log(`uid ${process.getuid()} -> ${ip}:53 from :${port}: answered`); process.exit(0); });
setTimeout(() => { console.log(`uid ${process.getuid()} -> ${ip}:53 from :${port}: no answer in 5 s`); process.exit(0); }, 5000);
EOF
	# one query from <port> [as <uid>], then its conntrack entry — asked again from a new port when
	# none is there: run 37071843770 answered the query and then had no entry for it (one gone
	# between the two, as the core's own query above went missing once; the next entry was there)
	own_ct() {
		node /tmp/irnf-own-dns.js 9.9.9.9 "$1" ${2:-} >&2
		grep -E "dst=9\.9\.9\.9 sport=$1 dport=53 " /proc/net/nf_conntrack | head -n 1 || true
	}
	ct1=; for port in 53531 53533 53535 53537; do ct1="$(own_ct "$port")"; [ -n "$ct1" ] && break; done
	ct2=; for port in 53532 53534 53536 53538; do ct2="$(own_ct "$port" 65534)"; [ -n "$ct2" ] && break; done
	echo "conntrack, uid 0:     ${ct1:-none}"
	echo "conntrack, uid 65534: ${ct2:-none}"
	echo "$ct1" | grep -q "src=$WANIP " || { echo "the service's own query to 9.9.9.9 did not leave from the WAN address $WANIP"; exit 1; }
	[ -n "$ct2" ] || { echo "the other user's query left no conntrack entry at all"; exit 1; }
	if echo "$ct2" | grep -q "src=$WANIP "; then echo "another user's query to 9.9.9.9 left from the WAN address — the rule is wider than the service's user"; exit 1; fi
else
	echo "no /proc/net/nf_conntrack in this image — the route lookups above are the proof"
fi

say "D3: cloudflared's edge discovery (an SRV lookup through dnsmasq) — answered with the drop-in's lines bound to the WAN device, refused without the binding"
# dnsmasq (its own user) has no way around the tunnel but SO_BINDTODEVICE:
# `server=/<domain>/<resolver>@<WAN device>` (cloudflared.dnsmasqDropIn, the
# device from service.directDevice()). The control first: the same lines
# unbound enter the tunnel, where SRV gets no answer (the hijack refuses it;
# the feed's older cores leave it unanswered — ETIMEOUT on 24.10, run 37068874055).
CF_JS=/usr/lib/irnetfree/src/server/remote/cloudflared
cf_dirs() { node -e "process.stdout.write(require('$CF_JS').dnsmasqConfDirs().join(' '))"; }
# cloudflared's own question, asked of dnsmasq the way it asks it (node's resolver: busybox nslookup's -type is optional)
srv_lookup() {
	node -e "const d = require('dns'); d.setServers(['127.0.0.1']); d.resolveSrv('_v2-origintunneld._tcp.argotunnel.com', (e, a) => console.log(e ? 'SRV error ' + e.code : 'SRV ' + JSON.stringify(a)));" 2>&1 || true
}
node -e "
const fs = require('fs');
const cf = require('$CF_JS');
const text = cf.dnsmasqDropIn(['9.9.9.9', '149.112.112.112']);
for (const d of cf.dnsmasqConfDirs()) { fs.mkdirSync(d, { recursive: true }); fs.writeFileSync(d + '/irnf-smoke-srv.conf', text); }
process.stdout.write(text);
"
/etc/init.d/dnsmasq restart; sleep 3
out="$(srv_lookup)"; echo "unbound: $out"
if echo "$out" | grep -q '"port":7844'; then echo "the UNBOUND lines answered SRV — the tunnel did not refuse it, so the binding below would prove nothing"; exit 1; fi
for d in $(cf_dirs); do rm -f "$d/irnf-smoke-srv.conf"; done
CF_REAL=
if [ -x /usr/bin/cloudflared ]; then
	# the real path: the service's own remote api (LuCI's remote_set) — its drop-in names what
	# service.directDevice() and service.directResolvers() say now, and apply restarts dnsmasq
	CF_REAL=1
	luci remote_set '{"cloudflared":{"enabled":true,"token":"eyJhIjoiMDAwIiwidCI6IjAwMCIsInMiOiIwMDAifQ=="}}' | jq -e '.ok == true' >/dev/null \
		|| { echo "remote_set (cloudflared on) was refused"; exit 1; }
	for d in $(cf_dirs); do
		i=0
		until grep -q "^server=/argotunnel.com/9.9.9.9@$WANDEV\$" "$d/irnetfree-cloudflared.conf" 2>/dev/null; do
			i=$((i+1))
			[ $i -lt 30 ] || { echo "the service's drop-in in $d is not bound to $WANDEV"; cat "$d/irnetfree-cloudflared.conf" 2>&1; logread | grep -i cloudflared | tail -n 5; exit 1; }
			sleep 1
		done
	done
	echo "--- the service's drop-in"; cat "$(cf_dirs | cut -d' ' -f1)/irnetfree-cloudflared.conf"
else
	echo "cloudflared is not installed in this image — the drop-in text with the WAN device, written here"
	node -e "
const cf = require('$CF_JS');
const text = cf.dnsmasqDropIn(['9.9.9.9', '149.112.112.112'], process.argv[1]);
for (const d of cf.dnsmasqConfDirs()) require('fs').writeFileSync(d + '/irnf-smoke-srv.conf', text);
process.stdout.write(text);
" "$WANDEV"
	/etc/init.d/dnsmasq restart
fi
out=; i=0
until echo "$out" | grep -q '"port":7844'; do
	i=$((i+1))
	[ $i -le 8 ] || { echo "no SRV answer for _v2-origintunneld._tcp.argotunnel.com through the bound drop-in"; echo "$out"; logread | grep -i dnsmasq | tail -10; exit 1; }
	sleep 3
	out="$(srv_lookup)"
done
echo "bound: $out" | cut -c1-300
logread | grep 'for domain argotunnel\.com' | tail -n 2
if [ -n "$CF_REAL" ]; then
	luci remote_set '{"cloudflared":{"enabled":false}}' | jq -e '.ok == true' >/dev/null || { echo "remote_set (cloudflared off) was refused"; exit 1; }
	for d in $(cf_dirs); do
		i=0
		while [ -e "$d/irnetfree-cloudflared.conf" ]; do i=$((i+1)); [ $i -lt 30 ] || { echo "the drop-in in $d stayed after cloudflared off"; exit 1; }; sleep 1; done
	done
	i=0
	while pidof cloudflared >/dev/null; do i=$((i+1)); [ $i -lt 20 ] || { echo "cloudflared still runs after off"; exit 1; }; sleep 1; done
else
	for d in $(cf_dirs); do rm -f "$d/irnf-smoke-srv.conf"; done
	/etc/init.d/dnsmasq restart; sleep 2
fi

say "D3: back to global, disconnected, the hand-made geo files gone"
rpc '{"channel":"disconnect"}' >/dev/null
i=0
while ip link show IRNetFree >/dev/null 2>&1; do i=$((i+1)); [ $i -lt 60 ] || { echo "the TUN device stayed after the D3 disconnect"; exit 1; }; sleep 1; done
i=0
while ip rule show | grep -q 'uidrange'; do i=$((i+1)); [ $i -lt 15 ] || { echo "the own-lookup rules stayed after the D3 disconnect"; ip rule show; exit 1; }; sleep 1; done
rpc "{\"channel\":\"settings:set\",\"arg\":{\"routingMode\":\"global\",\"dnsDirect\":$D3_DIRECT_WAS}}" | jq -e '.result.settings.routingMode == "global"' >/dev/null
for f in $D3_GEO; do rm -f "/etc/irnetfree/bin/$f"; done

# ===========================================================================
# v1.16.2 (fix/v1162-router) — the owner's AC-1304 (OpenWrt 23.05.4, v1.16.1):
# the exit's DoH timed out ("failed to retrieve response … context deadline
# exceeded"), the core answered the LAN nothing, every client and dnsmasq
# retried, and 49-90 s after the gateway came up sing-box said "socket: too
# many open files" hundreds of times — no device could browse. Here: the
# limits procd now gives node, sing-box and xray (65536, from irnetfree.init),
# the gateway's UDP session lifetime (udp_timeout 120) and the core's DNS
# block; then a DNS flood from a LAN-side namespace through dnsmasq (each
# upstream query a new port — a new UDP session in sing-box) and a few hundred
# UDP flows to distinct ports, with sing-box's and xray's open files sampled
# every second; the flood drained by the 120 s lifetime; and the owner's very
# failure — the DoH black-holed, every name asked three times — with names
# resolving through the tunnel again once it is back. The router is
# disconnected here (D3 ends so).
# ===========================================================================
say "v1.16.2: connect; node, sing-box and xray have 65536 open files (procd limits), the gateway's UDP sessions last 120 s, the core runs the router's DNS block"
fdn() { ls "/proc/$1/fd" 2>/dev/null | wc -l; }
nofile() { awk '/^Max open files/ { print $4 " " $5 }' "/proc/$1/limits"; }
fd_pids() { FD_SB="$(gw_singbox | head -n 1)"; FD_X="$(core_xray | head -n 1)"; }
mark fd
rpc "{\"channel\":\"connect\",\"arg\":\"$ID\"}" > /tmp/connect-fd.json || true
jq -c '.result // .error' /tmp/connect-fd.json
wait_back "v1.16.2 connect" 180
fd_pids
echo "cores: $(sing-box version 2>/dev/null | head -n 1); xray $(cmdline "$FD_X" | cut -d' ' -f1) $("$(cmdline "$FD_X" | cut -d' ' -f1)" version 2>/dev/null | head -n 1)"
for p in $(pidof node) $FD_SB $FD_X; do
	l="$(nofile "$p")"
	echo "pid $p $(cat "/proc/$p/comm"): Max open files $l, $(fdn "$p") in use"
	[ "$l" = "65536 65536" ] || { echo "pid $p ($(cat "/proc/$p/comm")) does not have the init's 65536 open files"; cat "/proc/$p/limits"; exit 1; }
done
judged 'Open files at connect: node [0-9]* of 65536, xray [0-9]* of 65536, sing-box [0-9]* of 65536' \
	|| { echo "the service did not say the open files at connect"; luci log '{"lines":40}' | jq -r '.lines[]' | tail -20; exit 1; }
luci log '{"lines":80}' | jq -r '.lines[]' | grep 'Open files at connect' | tail -n 1
luci diagnostics '{}' | jq -r '.text' | grep '^open files' || { echo "the diagnostics carry no open-files line"; exit 1; }
luci diagnostics '{}' | jq -r '.text' | grep -q '^open files (in use/Max open files): node=[0-9]*/65536 xray=[0-9]*/65536 sing-box=[0-9]*/65536' \
	|| { echo "the diagnostics' open-files line is not node, xray and sing-box at 65536"; exit 1; }
SB_CFG="$(cmdline "$FD_SB" | grep -o '/[^ ]*irnf-sb-[^ ]*/sing-box\.json' | head -n 1)"
echo "sing-box tun inbound: $(jq -c '.inbounds[0] | {stack, udp_timeout}' "$SB_CFG")"
jq -e '.inbounds[0].udp_timeout == 120' "$SB_CFG" >/dev/null || { echo "the gateway's sing-box has no udp_timeout 120"; exit 1; }
C=/etc/irnetfree/config.json
echo "the core's DNS block: $(jq -c '.dns | del(.hosts)' "$C")"
jq -e '.dns.enableParallelQuery == true and .dns.serveStale == true and .dns.serveExpiredTTL == 86400' "$C" >/dev/null || { echo "the core's DNS block is not the router's"; exit 1; }
jq -e '.dns.servers | map(select(type == "object" and (.address | tostring | startswith("https://")))) | length > 0 and all(.timeoutMs == 8000)' "$C" >/dev/null \
	|| { echo "a DoH server of the core has no 8 s budget"; exit 1; }

say "v1.16.2: a LAN-side namespace again (lan0, a port of br-lan) to flood from"
FLOODNS=
if ip netns add lan0 2>/dev/null; then
	if ip link add veth0 type veth peer name veth1 2>/dev/null; then
		ip link set veth1 netns lan0
		ip netns exec lan0 ip link set lo up
		ip netns exec lan0 ip link set veth1 up
		ip link set veth0 master br-lan up
		ip netns exec lan0 ip addr add 192.168.1.77/24 dev veth1
		ip netns exec lan0 ip route add default via 192.168.1.1
		sleep 1
		if lanping 192.168.1.1; then FLOODNS=1; echo "lan0: 192.168.1.77 — pings the router"; else echo "lan0 does not reach the router — why:"; lanwhy br-lan 192.168.1.77; fi
	fi
	[ -n "$FLOODNS" ] || ip netns delete lan0
fi
[ -n "$FLOODNS" ] || echo "no LAN-side namespace: the flood runs from the router itself (dnsmasq's upstream and the router's own UDP enter the same sing-box)"
inlan() { if [ -n "$FLOODNS" ]; then ip netns exec lan0 "$@"; else "$@"; fi; }
# node in the namespace: one A query per name, each from a socket of its own, asked again from that
# socket every <gap> ms up to <tries> times (a stub resolver's retry); UDP flows, one socket each
cat > /tmp/irnf-flood.js <<'EOF'
const dgram = require('dgram');
const [mode, ...a] = process.argv.slice(2);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const query = (id, name) => Buffer.concat([
  Buffer.from([id >> 8, id & 255, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]),
  ...name.split('.').map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l)])),
  Buffer.from([0, 0, 1, 0, 1])
]);
const ask = (server, name, tries, gapMs) => new Promise((resolve) => {
  const s = dgram.createSocket('udp4');
  const id = Math.floor(Math.random() * 65536);
  const q = query(id, name);
  let n = 0;
  let done = false;
  let timer = null;
  const finish = (r) => { if (done) return; done = true; clearTimeout(timer); try { s.close(); } catch (e) { /* closed */ } resolve(r); };
  const send = () => { n++; s.send(q, 53, server, () => {}); timer = setTimeout(() => (n < tries ? send() : finish({ timeout: true })), gapMs); };
  s.on('message', (m) => { if (m.length > 3 && m.readUInt16BE(0) === id) finish({ rcode: m[3] & 15 }); });
  s.on('error', () => finish({ error: true }));
  s.bind(0, send);
});
(async () => {
  if (mode === 'dns') {
    const server = a[0], count = Number(a[1]), tag = a[2], tries = Number(a[3]), gapMs = Number(a[4]), wave = Number(a[5]);
    const r = { sent: count, answered: 0, noerror: 0, nxdomain: 0, servfail: 0, refused: 0, other: 0, unanswered: 0, seconds: 0 };
    const t0 = Date.now();
    for (let i = 0; i < count; i += wave) {
      const batch = [];
      for (let j = i; j < Math.min(count, i + wave); j++) batch.push(ask(server, 'irnf-' + tag + '-' + j + '.example.com', tries, gapMs));
      for (const x of await Promise.all(batch)) {
        if (x.timeout || x.error) { r.unanswered++; continue; }
        r.answered++;
        if (x.rcode === 0) r.noerror++; else if (x.rcode === 3) r.nxdomain++; else if (x.rcode === 2) r.servfail++; else if (x.rcode === 5) r.refused++; else r.other++;
      }
    }
    r.seconds = Math.round((Date.now() - t0) / 1000);
    console.log('FLOOD DNS ' + JSON.stringify(r));
  } else if (mode === 'udp') {
    const target = a[0], base = Number(a[1]), count = Number(a[2]);
    for (let i = 0; i < count; i++) {
      const s = dgram.createSocket('udp4');
      await new Promise((r) => s.bind(0, r));
      for (let k = 0; k < 2; k++) await new Promise((r) => s.send(Buffer.from('irnf-flood ' + i), base + i, target, () => r()));
      s.close();
      if (i % 50 === 49) await sleep(100);
    }
    console.log('FLOOD UDP ' + JSON.stringify({ flows: count, to: target + ':' + base + '-' + (base + count - 1) }));
  }
})();
EOF
SAMPLER=
fd_sample_start() {
	rm -f /tmp/irnf-fd.stop /tmp/irnf-fd.samples
	( while [ ! -e /tmp/irnf-fd.stop ]; do echo "$(fdn "$FD_SB") $(fdn "$FD_X")" >> /tmp/irnf-fd.samples; sleep 1; done ) &
	SAMPLER=$!
}
fd_sample_stop() { touch /tmp/irnf-fd.stop; wait "$SAMPLER" 2>/dev/null || true; }
fd_peak() { awk -v c="$1" 'BEGIN { m = 0 } { if ($c + 0 > m) m = $c + 0 } END { print m }' /tmp/irnf-fd.samples 2>/dev/null || echo 0; }
# a name nobody asked before (dnsmasq caches): through dnsmasq, its upstream in the tunnel
resolves() {
	out=; i=0
	until echo "$out" | sed -n '/^Name:/,$p' | grep -q '^Address'; do
		i=$((i+1))
		[ $i -le 8 ] || { echo "$1 did not resolve from the LAN through the tunnel"; echo "$out"; logread | tail -20; exit 1; }
		out="$(inlan nslookup "$1" 192.168.1.1 2>&1 || true)"
		echo "$out" | sed -n '/^Name:/,$p' | grep -q '^Address' || sleep 5
	done
	echo "$1 from the LAN through dnsmasq and the tunnel: $(echo "$out" | sed -n '/^Name:/,$p' | grep '^Address' | head -n 2 | tr '\n' ' ')"
}

say "v1.16.2: 1500 names nobody asked before through dnsmasq (100 at a time), then 300 UDP flows to distinct ports — sing-box's and xray's open files every second"
# The names do not exist. The feeds' cores (24.12.31, 25.1.30) send nothing back for such a name, as
# the owner's core sent nothing when its DoH timed out; dnsmasq then holds each query for a while and,
# with 150 in flight, refuses the rest itself (REFUSED) — the storm the owner's dnsmasq made, bounded
# the same way. What counts here is the gateway under it, not the answers.
BASE_SB="$(fdn "$FD_SB")"; BASE_X="$(fdn "$FD_X")"
echo "before the flood: sing-box $BASE_SB open files, xray $BASE_X"
logread -f > /tmp/irnf-flood-a.log 2>&1 &
LOGF=$!
sleep 1; logger -t irnf-smoke "irnf-flood-a-start-$$"
fd_sample_start
inlan node /tmp/irnf-flood.js dns 192.168.1.1 1500 "a$$" 1 3000 100 | tee /tmp/irnf-flood-a.txt
DNS_PEAK_SB="$(fd_peak 1)"
inlan node /tmp/irnf-flood.js udp 198.51.100.1 30000 300 | tee -a /tmp/irnf-flood-a.txt
UDP_DONE="$(date +%s)"
sleep 3
fd_sample_stop
logger -t irnf-smoke "irnf-flood-a-end-$$"; sleep 1
kill "$LOGF" 2>/dev/null || true
grep -q "irnf-flood-a-end-$$" /tmp/irnf-flood-a.log || { echo "logread -f captured nothing: the log check below would prove nothing"; head -n 5 /tmp/irnf-flood-a.log; exit 1; }
PEAK_SB="$(fd_peak 1)"; PEAK_X="$(fd_peak 2)"; NOW_SB="$(fdn "$FD_SB")"; NOW_X="$(fdn "$FD_X")"
# (an emulated CPU opens the last associations after the sampler stopped: the later reading counts too)
if [ "$NOW_SB" -gt "$PEAK_SB" ]; then PEAK_SB="$NOW_SB"; fi
if [ "$NOW_X" -gt "$PEAK_X" ]; then PEAK_X="$NOW_X"; fi
echo "sing-box open files: before $BASE_SB, peak $DNS_PEAK_SB during the names, $PEAK_SB with the UDP flows, after $NOW_SB — limit 65536 (the kernel's 4096 before v1.16.2)"
echo "xray open files: before $BASE_X, peak $PEAK_X — limit 65536"
EMFILE="$(grep -ci 'too many open files' /tmp/irnf-flood-a.log || true)"
echo "\"too many open files\" in the log during the flood: ${EMFILE:-0}"
[ "${EMFILE:-0}" = 0 ] || { grep -i 'too many open files' /tmp/irnf-flood-a.log | head -n 5; exit 1; }
[ "$PEAK_SB" -lt 32768 ] || { echo "sing-box reached $PEAK_SB open files — not well under its 65536"; exit 1; }
[ "$PEAK_X" -lt 32768 ] || { echo "xray reached $PEAK_X open files — not well under its 65536"; exit 1; }
[ "$NOW_SB" -ge $((BASE_SB + 300)) ] || { echo "the 300 UDP flows hold no sessions in sing-box ($BASE_SB -> $NOW_SB) — the drain below would prove nothing"; exit 1; }
resolves example.net
if [ -n "$FLOODNS" ]; then lanprobe_soon || { echo "lan0 has no TCP through the tunnel after the flood"; lantunnelwhy; exit 1; }; echo "lan0: TCP through the tunnel after the flood"; fi

say "v1.16.2: the flood's sessions are gone 120 s after their last packet (udp_timeout) — sing-box's default 300 s would still hold every one of them"
# sing-box up to 1.13 drops expired NAT sessions when a new one is added: a fresh flow each look
while [ $(( $(date +%s) - UDP_DONE )) -lt 125 ]; do sleep 5; done
DRAINED=; el=0
while [ "$el" -lt 200 ]; do
	inlan node /tmp/irnf-flood.js udp 198.51.100.2 40000 1 >/dev/null
	sleep 3
	NOW_SB="$(fdn "$FD_SB")"; el=$(( $(date +%s) - UDP_DONE ))
	echo "${el}s after the flood: sing-box $NOW_SB open files (before $BASE_SB, peak $PEAK_SB)"
	if [ "$NOW_SB" -le $((BASE_SB + 60)) ]; then DRAINED=1; break; fi
	sleep 5
done
[ -n "$DRAINED" ] || { echo "the flood's UDP sessions were still open ${el}s after it — the 120 s lifetime did not take"; exit 1; }

say "v1.16.2: the owner's failure — the exit's DoH black-holed (no answer: the LAN gets none and retries), 400 new names asked three times each"
DNS_REMOTE_WAS="$(rpc '{"channel":"settings:get"}' | jq -c '.result.dnsRemote')"
rpc '{"channel":"settings:set","arg":{"dnsRemote":["https://192.0.2.1/dns-query"]}}' | jq -e '.result.settings.dnsRemote == ["https://192.0.2.1/dns-query"]' >/dev/null \
	|| { echo "settings:set dnsRemote failed"; exit 1; }
mark fdb
rpc "{\"channel\":\"connect\",\"arg\":\"$ID\"}" > /tmp/connect-fdb.json || true
jq -c '.result // .error' /tmp/connect-fdb.json
wait_back "connect with the DoH black-holed" 180
fd_pids
jq -c '.dns.servers' /etc/irnetfree/config.json
BASE_SB="$(fdn "$FD_SB")"; BASE_X="$(fdn "$FD_X")"
echo "before: sing-box $BASE_SB open files, xray $BASE_X"
logread -f > /tmp/irnf-flood-b.log 2>&1 &
LOGF=$!
sleep 1
fd_sample_start
inlan node /tmp/irnf-flood.js dns 192.168.1.1 400 "b$$" 3 2000 100 | tee /tmp/irnf-flood-b.txt
sleep 3
fd_sample_stop
logger -t irnf-smoke "irnf-flood-b-end-$$"; sleep 1
kill "$LOGF" 2>/dev/null || true
grep -q "irnf-flood-b-end-$$" /tmp/irnf-flood-b.log || { echo "logread -f captured nothing during the outage"; exit 1; }
PEAK_SB="$(fd_peak 1)"; PEAK_X="$(fd_peak 2)"; NOW_SB="$(fdn "$FD_SB")"; NOW_X="$(fdn "$FD_X")"
if [ "$NOW_SB" -gt "$PEAK_SB" ]; then PEAK_SB="$NOW_SB"; fi
if [ "$NOW_X" -gt "$PEAK_X" ]; then PEAK_X="$NOW_X"; fi
echo "sing-box open files: before $BASE_SB, peak $PEAK_SB, after $NOW_SB — limit 65536"
echo "xray open files: before $BASE_X, peak $PEAK_X — limit 65536"
echo "the core's DoH failures logged meanwhile: $(grep -Ec 'failed to retrieve response|context deadline exceeded|192\.0\.2\.1' /tmp/irnf-flood-b.log || true)"
grep -E 'failed to retrieve response|192\.0\.2\.1' /tmp/irnf-flood-b.log | head -n 2 || true
# the outage is real: a name that exists, asked once dnsmasq has let go of the flood's queries, gets no address
sleep 10
out="$(inlan nslookup www.example.com 192.168.1.1 2>&1 || true)"
echo "www.example.com with the DoH black-holed: $(echo "$out" | sed -n '/^Name:/,$p' | tr '\n' ' ' | cut -c1-160)$(echo "$out" | grep -Ei "can't find|timed out|no answer" | head -n 1)"
if echo "$out" | sed -n '/^Name:/,$p' | grep -q '^Address'; then echo "a name resolved with the DoH black-holed — the outage was not simulated"; exit 1; fi
EMFILE="$(grep -ci 'too many open files' /tmp/irnf-flood-b.log || true)"
echo "\"too many open files\" in the log during the outage: ${EMFILE:-0}"
[ "${EMFILE:-0}" = 0 ] || { grep -i 'too many open files' /tmp/irnf-flood-b.log | head -n 5; exit 1; }
[ "$PEAK_SB" -lt 32768 ] && [ "$PEAK_X" -lt 32768 ] || { echo "open files not well under 65536 during the outage (sing-box $PEAK_SB, xray $PEAK_X)"; exit 1; }

say "v1.16.2: the DoH back — names resolve through the tunnel again (the owner's \"then it suddenly works\")"
rpc "{\"channel\":\"settings:set\",\"arg\":{\"dnsRemote\":$DNS_REMOTE_WAS}}" | jq -e '.result.settings.dnsRemote | tostring | contains("192.0.2.1") | not' >/dev/null \
	|| { echo "settings:set could not put the DoH list back"; exit 1; }
mark fdc
rpc "{\"channel\":\"connect\",\"arg\":\"$ID\"}" > /tmp/connect-fdc.json || true
wait_back "connect with the DoH back" 180
resolves example.org
rpc '{"channel":"disconnect"}' >/dev/null
i=0
while ip link show IRNetFree >/dev/null 2>&1; do i=$((i+1)); [ $i -lt 60 ] || { echo "the TUN device stayed after the v1.16.2 disconnect"; exit 1; }; sleep 1; done
if [ -n "$FLOODNS" ]; then ip netns delete lan0; fi

say "SMOKE OK"
