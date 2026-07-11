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
#   HEV_SO_URL_ARM64_V8A   URL to libhev-socks5-tunnel.so for arm64-v8a
#   HEV_SO_URL_ARMEABI_V7A URL for armeabi-v7a
#   HEV_SO_URL_X86_64      URL for x86_64
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
libs="$here/app/libs"
jni="$here/app/src/main/jniLibs"
mkdir -p "$libs"

echo "==> Fetching libv2ray.aar (Xray core)"
tag="${LIBV2RAY_TAG:-}"
api="https://api.github.com/repos/2dust/AndroidLibXrayLite/releases"
if [ -z "$tag" ]; then
  url="$(curl -fsSL "$api/latest" | grep -oE '"browser_download_url": *"[^"]*\.aar"' | head -n1 | cut -d'"' -f4)"
else
  url="$(curl -fsSL "$api/tags/$tag" | grep -oE '"browser_download_url": *"[^"]*\.aar"' | head -n1 | cut -d'"' -f4)"
fi
if [ -z "$url" ]; then
  echo "ERROR: could not find libv2ray.aar asset in AndroidLibXrayLite releases." >&2
  exit 1
fi
echo "    $url"
curl -fSL "$url" -o "$libs/libv2ray.aar"
echo "    saved -> app/libs/libv2ray.aar"

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

echo "Done."
