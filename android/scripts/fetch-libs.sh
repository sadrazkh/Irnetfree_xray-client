#!/usr/bin/env bash
# Fetch the two native components the Android app needs. Neither is committed to
# git (see app/libs/.gitignore) — they are pulled here and by CI.
#
#   1) libv2ray.aar  (AndroidLibXrayLite = Xray core)  -> REQUIRED to compile.
#   2) libhev-socks5-tunnel.so per ABI (tun2socks)     -> REQUIRED at runtime for
#      the TUN tunnel. Provide via HEV_SO_URL_<ABI> env vars, else skipped (the
#      app still builds; the tunnel just won't start until the .so is present).
#
# Env overrides:
#   LIBV2RAY_TAG            pin a specific AndroidLibXrayLite tag (default: latest)
#   PATTN_TAG               pin the patterniha/Xray-core release (default: pinned below)
#   PATTN_ABIS              "<abi>:<asset.zip> ..." (default: arm64-v8a only)
#   HEV_SO_URL_ARM64_V8A   URL to libhev-socks5-tunnel.so for arm64-v8a
#   HEV_SO_URL_ARMEABI_V7A URL for armeabi-v7a
#   HEV_SO_URL_X86_64      URL for x86_64
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
libs="$here/app/libs"
jni="$here/app/src/main/jniLibs"
mkdir -p "$libs"

# Download libv2ray.aar directly from a pinned release asset. We deliberately do
# NOT hit the GitHub API (unauthenticated API is rate-limited to 60/h per IP and
# CI runners share IPs, which was killing the build with a 403). A release-asset
# download redirects to a CDN and is not rate-limited. Override the tag with
# LIBV2RAY_TAG=vX.Y.Z if you want a different core version.
TAG="${LIBV2RAY_TAG:-v26.7.11}"
url="https://github.com/2dust/AndroidLibXrayLite/releases/download/${TAG}/libv2ray.aar"
echo "==> Fetching libv2ray.aar (Xray core, $TAG)"
if curl -fSL --retry 3 --retry-delay 2 "$url" -o "$libs/libv2ray.aar"; then
  echo "    saved -> app/libs/libv2ray.aar"
else
  # Non-fatal: the app is built against the core via reflection, so a failed
  # download still yields an installable APK (tunnel won't start without it).
  echo "WARN: failed to download libv2ray.aar from $url — building without the core." >&2
  rm -f "$libs/libv2ray.aar"
fi

fetch_so() {
  local abi="$1" var="$2"
  local u="${!var:-}"
  if [ -z "$u" ]; then
    echo "    (skip $abi: set $var to a libhev-socks5-tunnel.so URL to include it)"
    return
  fi
  mkdir -p "$jni/$abi"
  curl -fSL "$u" -o "$jni/$abi/libhev-socks5-tunnel.so"
  echo "    saved -> jniLibs/$abi/libhev-socks5-tunnel.so"
}

echo "==> Fetching libhev-socks5-tunnel.so (tun2socks)"
fetch_so "arm64-v8a"   "HEV_SO_URL_ARM64_V8A"
fetch_so "armeabi-v7a" "HEV_SO_URL_ARMEABI_V7A"
fetch_so "x86_64"      "HEV_SO_URL_X86_64"

# sing-box CLI (the optional alternate per-config core). The official release
# ships an Android-built `sing-box` ELF; we bundle it as libsingbox.so so Android
# will extract it to the (executable) nativeLibraryDir and the app can exec it.
# arm64 only by default (each binary is ~58 MB — bundling all ABIs would bloat
# the APK); other ABIs simply fall back to Xray. Override the version with
# SINGBOX_TAG, or add ABIs via SINGBOX_ABIS="arm64-v8a:arm64 x86_64:amd64 ...".
fetch_singbox() {
  local abi="$1" goarch="$2" tag="$3"
  local ver="${tag#v}"
  local name="sing-box-${ver}-android-${goarch}"
  local url="https://github.com/SagerNet/sing-box/releases/download/${tag}/${name}.tar.gz"
  local tmp; tmp="$(mktemp -d)"
  echo "    $abi <- $name.tar.gz"
  if curl -fSL --retry 3 --retry-delay 2 "$url" -o "$tmp/sb.tar.gz" && tar -xzf "$tmp/sb.tar.gz" -C "$tmp"; then
    mkdir -p "$jni/$abi"
    cp "$tmp/$name/sing-box" "$jni/$abi/libsingbox.so"
    echo "    saved -> jniLibs/$abi/libsingbox.so"
  else
    echo "    (skip $abi: sing-box download failed — engine falls back to Xray)"
  fi
  rm -rf "$tmp"
}

echo "==> Fetching sing-box (optional alternate core)"
# Pinned (like libv2ray) so we never hit the rate-limited GitHub API on shared CI
# runners. Bump SINGBOX_TAG to update the bundled sing-box.
SINGBOX_TAG="${SINGBOX_TAG:-v1.13.14}"
echo "    sing-box $SINGBOX_TAG"
for pair in ${SINGBOX_ABIS:-"arm64-v8a:arm64"}; do
  fetch_singbox "${pair%%:*}" "${pair##*:}" "$SINGBOX_TAG"
done

# Xray-PattN (patterniha/Xray-core): the second Xray-format core, the one the
# desktop offers per config. Same JSON, same argv as upstream — its one change
# is that it does not refuse plaintext VLESS/Trojan to a public address, which
# is why an Iranian config or a chain with one plaintext hop needs it. The fork
# publishes an Android ELF in `Xray-android-<abi>.zip`, so it is bundled the
# same way sing-box is: as a jniLib, the only place Android will execute a file
# from. arm64 only by default (~40 MB each); other ABIs fall back to the
# in-process core. Override with PATTN_TAG / PATTN_ABIS.
fetch_pattn() {
  local abi="$1" asset="$2" tag="$3" bin=""
  local url="https://github.com/patterniha/Xray-core/releases/download/${tag}/${asset}"
  local tmp; tmp="$(mktemp -d)"
  echo "    $abi <- $asset"
  if curl -fSL --retry 3 --retry-delay 2 "$url" -o "$tmp/xray.zip" && unzip -q -o "$tmp/xray.zip" -d "$tmp"; then
    # The archive carries geo files and licences too; take the binary wherever
    # upstream puts it (the desktop downloader searches for it the same way).
    bin="$(find "$tmp" -type f -name xray | head -n1)"
  fi
  if [ -n "$bin" ]; then
    mkdir -p "$jni/$abi"
    cp "$bin" "$jni/$abi/libxraypattn.so"
    echo "    saved -> jniLibs/$abi/libxraypattn.so"
  else
    echo "    (skip $abi: Xray-PattN download failed — configs asking for it fall back to the in-process core)"
  fi
  rm -rf "$tmp"
}

echo "==> Fetching Xray-PattN (the second Xray-format core)"
# Pinned like the others so a shared CI runner never hits the rate-limited API.
PATTN_TAG="${PATTN_TAG:-v26.9.13}"
echo "    Xray-PattN $PATTN_TAG"
for pair in ${PATTN_ABIS:-"arm64-v8a:Xray-android-arm64-v8a.zip"}; do
  fetch_pattn "${pair%%:*}" "${pair##*:}" "$PATTN_TAG"
done

# The routing data files (geoip.dat / geosite.dat), the same Loyalsoldier build
# the desktop downloader uses. Bundled as APK assets: without them every
# geosite:/geoip: rule is dropped and "Bypass Iran", "Block ads" and the
# in-country resolver silently do nothing (GeoAssets / XrayCore.prepareAssets).
# Pinned to a release tag like the cores; bump GEO_TAG to refresh. A failed
# download is non-fatal — the app then runs without geo rules, and says so.
assets="$here/app/src/main/assets"
mkdir -p "$assets"
GEO_TAG="${GEO_TAG:-202609152354}"
echo "==> Fetching geoip.dat / geosite.dat (Loyalsoldier/v2ray-rules-dat $GEO_TAG)"
for dat in geoip.dat geosite.dat; do
  url="https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/${GEO_TAG}/${dat}"
  if curl -fSL --retry 3 --retry-delay 2 "$url" -o "$assets/$dat"; then
    echo "    saved -> app/src/main/assets/$dat ($(wc -c < "$assets/$dat") bytes)"
  else
    echo "WARN: failed to download $dat from $url — building without it (geo rules off)." >&2
    rm -f "$assets/$dat"
  fi
done

echo "Done."
