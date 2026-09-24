#!/bin/sh
# Every firewall zone that forwards to wan also forwards to irnetfree, the
# tunnel's zone. sing-box routes EVERY forwarded packet into the tun (its rule
# `not iif lo -> lookup 2022`), so a zone that may reach the internet but not
# the irnetfree zone - a guest Wi-Fi, an IoT VLAN - is refused by fw4 at the tun
# and has no internet at all while the gateway is up. A zone that may not reach
# wan does not get the tunnel either.
#
# Idempotent: an existing forwarding to irnetfree is left alone, nothing is
# committed when nothing changed. Run by the uci-defaults script (install and
# every upgrade) and by the init script at every start, which picks up a zone
# added since. Installed as /usr/lib/irnetfree/fw-forwardings.sh.
# POSIX sh (busybox ash) - this runs on the router.
set -f   # no globbing: an anonymous section is @forwarding[0]

uci -q get firewall.irnetfree >/dev/null || exit 0

# the names of the forwarding sections whose option $1 is $2
forwardings() {
	uci -q show firewall | sed -n "s/^firewall\.\([^.=]*\)\.$1='$2'\$/\1/p" | while read -r sec; do
		[ "$(uci -q get "firewall.$sec")" = forwarding ] && echo "$sec"
	done
}

added=0
for src in $(forwardings dest wan | while read -r sec; do uci -q get "firewall.$sec.src"; done | sort -u); do
	case "$src" in
		irnetfree|*[!A-Za-z0-9_-]*) continue ;;
	esac
	have=0
	for sec in $(forwardings src "$src"); do
		[ "$(uci -q get "firewall.$sec.dest")" = irnetfree ] && have=1
	done
	[ "$have" = 1 ] && continue
	name="irnetfree_$(echo "$src" | tr '-' '_')"
	uci -q batch <<-EOF
		set firewall.$name=forwarding
		set firewall.$name.src='$src'
		set firewall.$name.dest='irnetfree'
	EOF
	echo "irnetfree: the $src zone now forwards to the tunnel zone"
	added=1
done

[ "$added" = 1 ] || exit 0
uci commit firewall
[ -x /etc/init.d/firewall ] && /etc/init.d/firewall reload >/dev/null 2>&1
exit 0
