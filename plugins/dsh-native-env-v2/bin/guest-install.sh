#!/usr/bin/env bash
# dsh-native-env-v2 / guest-install — install, verify, or remove the REMOTE half on a
# POSIX guest (the Ubuntu VM), where the host reaches it over ssh.
#
#   ./guest-install.sh              # install + verify
#   ./guest-install.sh --verify     # install, then show the row and the runtime
#   ./guest-install.sh --remove     # remove the profile row
#
# Expected layout (pushed from the host beforehand):
#   ~/dsh-native-env-v2/lib/{guest.js,guest-transport.js,env-protocol.js,handshake.js,wire.js}
#
# Unlike the Windows guest, this one needs NO token and NO address: the host
# spawns it over ssh and speaks the env wire on its stdin/stdout, so the channel is
# already authenticated and encrypted by ssh.
#
# It DOES need a profile of its own. `dsh-base` alone, with no other stdio server:
# the `acp` profile would put the ACP JSON-RPC server on the same stdout and the
# two protocols would interleave.

set -euo pipefail

PLUGIN_DIR="${DSH_NATIVE_ENV_DIR:-$HOME/dsh-native-env-v2}"
AGENT_PROFILE="${DSH_NATIVE_ENV_PROFILE:-env}"
CWD_VALUE="${DSH_NATIVE_ENV_CWD:-$HOME}"
MAX_RESULT_BYTES="${DSH_NATIVE_ENV_MAX_RESULT_BYTES:-262144}"
DSH_BIN="${DSH_NATIVE_ENV_DSH:-dsh}"

MARKER='native-env-guest-v2'
BEGIN_MARKER='# >>> dsh-native-env-v2 (managed) >>>'
END_MARKER='# <<< dsh-native-env-v2 (managed) <<<'

REMOVE=0
VERIFY=0
for arg in "$@"; do
  case "$arg" in
    --remove) REMOVE=1 ;;
    --verify) VERIFY=1 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "[guest-install] unknown argument: $arg" >&2; exit 2 ;;
  esac
done

say() { echo "[guest-install] $*"; }

DSH_HOME_DIR="${DSH_HOME:-$HOME/.dsh}"
PROFILE_DIR="$DSH_HOME_DIR/profiles/$AGENT_PROFILE"
PATCH_PATH="$PROFILE_DIR/cordis.patch.yml"

# ── remove ────────────────────────────────────────────────────────────────────
if [ "$REMOVE" -eq 1 ]; then
  if [ ! -f "$PATCH_PATH" ]; then say "no patch file at $PATCH_PATH; nothing to do"; exit 0; fi
  if ! grep -qF "$BEGIN_MARKER" "$PATCH_PATH"; then say "no managed block in $PATCH_PATH; nothing to do"; exit 0; fi
  cp "$PATCH_PATH" "$PATCH_PATH.bak-native-env"
  awk -v b="$BEGIN_MARKER" -v e="$END_MARKER" '
    index($0, b) { skip = 1; next }
    index($0, e) { skip = 0; next }
    !skip { print }
  ' "$PATCH_PATH.bak-native-env" > "$PATCH_PATH"
  say "removed the managed block from $PATCH_PATH (backup: $PATCH_PATH.bak-native-env)"
  exit 0
fi

# ── prerequisites ─────────────────────────────────────────────────────────────
# This list is the guest half's IMPORT CLOSURE and must match it exactly — the
# closure guard in tests/guest-closure.test.mjs derives the set from the source and
# compares it against these three installers, so a module added to the pairing
# transport without being added here fails the suite rather than failing on the
# guest, where it is far more annoying to debug.
missing=0
for name in \
  device-code.js \
  e2ee.js \
  e2ee-channel.js \
  env-protocol.js \
  guest-transport.js \
  guest.js \
  handshake.js \
  host-api.js \
  pairing-guest.js \
  pairing-session.js \
  pairing.js \
  protocol-v2.js \
  relay-client.js \
  relay-protocol.js \
  state-store.js \
  terms.js \
  wire.js \
  ws.js
do
  if [ ! -f "$PLUGIN_DIR/lib/$name" ]; then say "missing: $PLUGIN_DIR/lib/$name"; missing=1; fi
done
if [ "$missing" -eq 1 ]; then
  say "copy them from the host first: <repo>/plugins/dsh-native-env-v2/lib/*.js -> $PLUGIN_DIR/lib/"
  exit 2
fi
say "plugin files present in $PLUGIN_DIR/lib"

# ── the profile (dsh-base only, so stdout belongs to the env wire) ────────────
if [ ! -d "$PROFILE_DIR" ]; then
  say "creating the '$AGENT_PROFILE' profile at $PROFILE_DIR"
  mkdir -p "$PROFILE_DIR/node_modules" "$PROFILE_DIR/.dsh-module-fallback/node_modules"
  cat > "$PROFILE_DIR/package.json" <<JSON
{
  "name": "dsh-profile-$AGENT_PROFILE",
  "private": true,
  "dependencies": {},
  "dsh": {
    "profile": {
      "bundles": [
        "@deepseek-ai/dsh-base"
      ],
      "patchReload": "startup"
    }
  }
}
JSON
  cat > "$PROFILE_DIR/cordis.yml" <<'YAML'
# dsh profile root — an empty entry list. The tree is composed as patches: each
# bundle in package.json's dsh.profile.bundles, then cordis.patch.yml, then any
# --patch overlays. Edit cordis.patch.yml, not this file.
[]
YAML
  cat > "$PROFILE_DIR/pnpm-workspace.yaml" <<'YAML'
packages:
  - .

nodeLinker: hoisted
autoInstallPeers: false
YAML
  : > "$PROFILE_DIR/cordis.patch.yml"
fi

# ── the profile row ───────────────────────────────────────────────────────────
if grep -qF "$MARKER" "$PATCH_PATH" 2>/dev/null; then
  say "a '$MARKER' row is already present in $PATCH_PATH; leaving it alone"
  say "run with --remove first if you need to change the settings"
else
  [ -f "$PATCH_PATH" ] && cp "$PATCH_PATH" "$PATCH_PATH.bak-native-env"
  # A fresh profile's patch file is the empty entry list `[]`. Appending a block
  # sequence AFTER that flow sequence is a YAML error, so a standalone `[]` line
  # is dropped first. Comments are kept, preserving the stock header.
  if [ -f "$PATCH_PATH" ]; then
    grep -v '^[[:space:]]*\[\][[:space:]]*$' "$PATCH_PATH" > "$PATCH_PATH.tmp" || true
    mv "$PATCH_PATH.tmp" "$PATCH_PATH"
  fi
  cat >> "$PATCH_PATH" <<YAML

$BEGIN_MARKER
# Written by dsh-native-env-v2/bin/guest-install.sh — re-run with --remove to delete.
- insert:
    - id: $MARKER
      name: '$PLUGIN_DIR/lib/guest.js'
      config:
        transport: stdio
        cwd: '$CWD_VALUE'
        maxResultBytes: $MAX_RESULT_BYTES
$END_MARKER
YAML
  say "appended the managed block to $PATCH_PATH"
fi

# ── verify ────────────────────────────────────────────────────────────────────
if [ "$VERIFY" -eq 1 ]; then
  say "--- profile ---"
  "$DSH_BIN" --profile "$AGENT_PROFILE" --dump-config 2>&1 | grep -E 'native-env|dsh-base' || {
    say "the profile did not compose; run: $DSH_BIN --profile $AGENT_PROFILE --dump-config"
    exit 1
  }
  say "--- current row ---"
  tail -n 12 "$PATCH_PATH"
fi

say 'done'
say "the host row must name this peer with transport: ssh, and its args must run:"
say "  $DSH_BIN --profile $AGENT_PROFILE"
