#!/usr/bin/env bash
# check-version-code.sh <apk> [version]
#
# Reads the versionCode and the versionName an APK really carries (aapt2 dump badging) and
# fails unless the code is the one made of the name: major*1000000 + minor*1000 + patch
# (1.47.3 -> 1047003, the rule of app/build.gradle.kts). With [version], the name must be it.
#
# Why: Android refuses an APK whose versionCode is lower than the installed one, and all the
# phone says is "App not installed as package appears to be invalid". Until v1.47.2 the code
# was the release workflow's run number. The repository was recreated on 2026-11-08, the
# number began again at 1, and v1.47.1 and v1.47.2 went out as 11 and 12 to phones that held
# up to 155. Both workflows run this on the APK they built, before anything is published.
set -euo pipefail

apk="${1:?usage: check-version-code.sh <apk> [version]}"
want_name="${2:-}"

sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
aapt2="$(ls -d "$sdk"/build-tools/*/ 2>/dev/null | sort -V | tail -n1)aapt2"
[ -x "$aapt2" ] || { echo "::error::aapt2 not found under $sdk/build-tools"; exit 1; }
[ -f "$apk" ] || { echo "::error::no APK at $apk"; exit 1; }

out="$("$aapt2" dump badging "$apk" 2>&1)" || { printf '%s\n' "$out" | head -n 20; echo "::error::aapt2 could not read $apk"; exit 1; }
badge="$(printf '%s\n' "$out" | grep '^package:' || true)"
echo "$badge"
code="$(printf '%s\n' "$badge" | sed -n "s/.*versionCode='\([0-9]*\)'.*/\1/p")"
name="$(printf '%s\n' "$badge" | sed -n "s/.*versionName='\([^']*\)'.*/\1/p")"
if [ -z "$code" ] || [ -z "$name" ]; then
  echo "::error::aapt2's answer names no versionCode or no versionName"
  exit 1
fi

if [ -n "$want_name" ] && [ "$name" != "$want_name" ]; then
  echo "::error::the APK says it is version $name, not $want_name"
  exit 1
fi

nums="$(printf '%s\n' "$name" | sed -n 's/^\([0-9][0-9]*\)\.\([0-9][0-9]*\)\.\([0-9][0-9]*\).*$/\1 \2 \3/p')"
if [ -z "$nums" ]; then
  echo "::error::versionName $name does not begin with x.y.z"
  exit 1
fi
read -r major minor patch <<EOF
$nums
EOF
want=$((10#$major * 1000000 + 10#$minor * 1000 + 10#$patch))

if [ "$code" != "$want" ]; then
  echo "::error::the APK's versionCode is $code, and version $name must carry $want: a phone that holds an earlier release would refuse it (\"App not installed as package appears to be invalid\")"
  exit 1
fi

echo "versionCode $code is the one made of version $name"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  echo "APK versionCode $code (version $name)" >> "$GITHUB_STEP_SUMMARY"
fi
