#!/bin/sh
# IRNetFree on OpenWrt — the one-line installer.
#
#   sh -c "$(wget -q -O - https://raw.githubusercontent.com/sadrazkh/Irnetfree_xray-client/main/openwrt/install.sh)"
#   sh install.sh /tmp/irnetfree_1.13.1_all.ipk        (a package you already have)
#
# Installs what IRNetFree depends on, the newest release's package (or the one
# given), and prints the link with the router's token. Re-running it upgrades.
# POSIX sh (busybox ash) — this runs on the router.
set -eu
REPO=sadrazkh/Irnetfree_xray-client
IPK="${1:-}"
say() { echo; echo "== $*"; }

[ "$(id -u)" = 0 ] || { echo "run this as root"; exit 1; }
[ -f /etc/openwrt_release ] || { echo "this is not OpenWrt"; exit 1; }
. /etc/openwrt_release
say "OpenWrt ${DISTRIB_RELEASE:-?} (${DISTRIB_ARCH:-?})"
# 24.10's feed has node 20, 23.05's has node 18 — both run IRNetFree (the 23.05
# one is exercised in CI too). 22.03 and older have node 16 or none; 25 and
# SNAPSHOT install packages with apk, not opkg, so this script does not fit.
case "${DISTRIB_RELEASE:-}" in
	24.*|23.05*) ;;
	*) echo "IRNetFree needs OpenWrt 23.05 or 24.10 (node 18 / 20 in their feeds); 25 and SNAPSHOT use apk instead of opkg, older releases have no usable node"; exit 1 ;;
esac

say "packages IRNetFree needs"
opkg update >/dev/null
opkg install node kmod-tun nftables ip-full unzip ca-bundle
NODE_MAJOR="$(node -v 2>/dev/null | sed 's/^v//' | cut -d. -f1)"
[ "${NODE_MAJOR:-0}" -ge 18 ] || { echo "node $(node -v 2>/dev/null || echo missing) is too old: IRNetFree needs 18 or newer"; exit 1; }
echo "node $(node -v)"

if [ -z "$IPK" ]; then
	say "the newest release"
	URL="$(wget -q -O - "https://api.github.com/repos/$REPO/releases/latest" | grep -o 'https://[^"]*_all\.ipk' | head -n 1)"
	[ -n "$URL" ] || { echo "could not find the package in the latest release (no internet from the router, or GitHub unreachable) — download the ipk on a PC and run: sh install.sh /tmp/<file>.ipk"; exit 1; }
	IPK=/tmp/irnetfree.ipk
	echo "$URL"
	wget -q -O "$IPK" "$URL"
fi

say "install"
opkg install "$IPK"

say "service"
i=0
until [ -s /etc/irnetfree/token ]; do
	i=$((i+1))
	[ $i -lt 30 ] || break
	sleep 1
done
LAN="$(uci -q get network.lan.ipaddr || echo 192.168.1.1)"
PORT="$(uci -q get irnetfree.main.port || echo 6969)"
echo
echo "IRNetFree is installed and running. Open it here:"
echo "  http://$LAN:$PORT/?token=$(cat /etc/irnetfree/token 2>/dev/null)"
echo "or LuCI -> Services -> IRNetFree. The token lives in /etc/irnetfree/token"
echo "(cat it any time); it is never written to the system log."
echo "Cores: Settings -> Required files (downloads the ARM/MIPS build), or: opkg install xray-core sing-box"
echo "Log:   logread -e irnetfree"
