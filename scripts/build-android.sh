#!/usr/bin/env bash
set -euo pipefail
client_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export ANDROID_HOME="${ANDROID_HOME:-$HOME/android-sdk}"
export ANDROID_USER_HOME="$ANDROID_HOME/.android"
export GRADLE_USER_HOME="$ANDROID_HOME/.gradle"
export TMPDIR="$ANDROID_HOME/tmp"
export JAVA_TOOL_OPTIONS="-Duser.home=$ANDROID_HOME -Djava.io.tmpdir=$TMPDIR"
mkdir -p "$ANDROID_USER_HOME" "$GRADLE_USER_HOME" "$TMPDIR"
cd "$client_root"
npm ci
npm run check
mkdir -p mobile/android/app/src/main/assets
npm run android:sync
cd mobile/android
printf 'sdk.dir=%s\n' "$ANDROID_HOME" > local.properties
./gradlew --no-daemon assembleDebug
