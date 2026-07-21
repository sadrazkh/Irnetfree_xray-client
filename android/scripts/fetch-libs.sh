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

echo "Done."
