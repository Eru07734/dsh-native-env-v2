#!/usr/bin/env bash
# dsh-native-env-v2 / guest-env-profile.sh — run the REMOTE half on a POSIX guest.
#
# The POSIX counterpart of bin/guest-run-standalone.ps1, and the missing half of
# the Ubuntu deployment: it creates the guest's own `env` profile (dsh-base only,
# so NOTHING else owns stdout — the env wire does) and points it at this plugin.
#
# Why a separate profile instead of reusing `acp` or `web`: both of those mount
# an app bundle that writes its own protocol to stdout, and the env wire would
# interleave with it. `dsh-base` plus this plugin is the whole tree.
#
# The profile needs no install step: `~/.dsh/profiles/node_modules/@deepseek-ai/*`
# are already symlinks into the global DSH install (pnpm hoisted linker), and this
# plugin is zero-dependency (node: builtins only).
#
# Usage:
#   bash guest-env-profile.sh [--plugin-dir DIR] [--dsh-home DIR] [--profile NAME]
#                             [--cwd DIR] [--transport stdio|tcp] [--host H] [--port N]
#                             [--peer NAME] [--token-file PATH] [--dump] [--rewrite] [--start]
#
#   --dump     compose the profile and show the resolved config (no runtime started)
#   --rewrite  re-create the profile's cordis.patch.yml even when it already exists.
#              WITHOUT it the patch file is only written for a profile that does not
#              exist yet, so rows added by hand on the guest — a guest-side plugin, an
#              extra hook — SURVIVE every reconnect. Rewriting unconditionally would
#              delete them silently, and since the host runs this same command to
#              start the runtime, that is the normal path and not an edge case.
#   --start  exec the runtime in the FOREGROUND, so the caller owns its lifetime
#            (this is what the host's `ssh` peer row runs)
set -euo pipefail

PLUGIN_DIR="${PLUGIN_DIR:-$HOME/dsh-native-env-v2}"
DSH_HOME="${DSH_HOME:-$HOME/.dsh}"
AGENT_PROFILE="${AGENT_PROFILE:-env}"
CWD_DIR="${CWD_DIR:-$HOME}"
TRANSPORT="${TRANSPORT:-stdio}"
# Set --host (or SERVER_HOST) to the controller address for cross-machine TCP.
SERVER_HOST="${SERVER_HOST:-127.0.0.1}"
PORT="${PORT:-8912}"
PEER="${PEER:-ubuntu}"
TOKEN_FILE="${TOKEN_FILE:-$HOME/.dsh-net-bridge-token}"
# Optional fallback directory for a dsh installation outside PATH.
NODE_BIN="${NODE_BIN:-$HOME/.local/bin}"
DO_DUMP=0
DO_START=0
DO_REWRITE=0

while [ $# -gt 0 ]; do
  case "$1" in
    --plugin-dir) PLUGIN_DIR="$2"; shift 2 ;;
    --dsh-home)   DSH_HOME="$2"; shift 2 ;;
    --profile)    AGENT_PROFILE="$2"; shift 2 ;;
    --cwd)        CWD_DIR="$2"; shift 2 ;;
    --transport)  TRANSPORT="$2"; shift 2 ;;
    --host)       SERVER_HOST="$2"; shift 2 ;;
    --port)       PORT="$2"; shift 2 ;;
    --peer)       PEER="$2"; shift 2 ;;
    --token-file) TOKEN_FILE="$2"; shift 2 ;;
    --dump)       DO_DUMP=1; shift ;;
    --rewrite)    DO_REWRITE=1; shift ;;
    --start)      DO_START=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

say() { printf '[guest-env] %s\n' "$*"; }

PROFILE_DIR="$DSH_HOME/profiles/$AGENT_PROFILE"
PATCH="$PROFILE_DIR/cordis.patch.yml"

# ── prerequisites ─────────────────────────────────────────────────────────────
missing=0
for f in guest.js guest-transport.js env-protocol.js handshake.js wire.js; do
  if [ ! -f "$PLUGIN_DIR/lib/$f" ]; then say "missing $PLUGIN_DIR/lib/$f"; missing=1; fi
done
[ "$missing" -eq 0 ] || exit 2

if ! command -v dsh >/dev/null 2>&1; then
  export PATH="$NODE_BIN:$PATH"
fi
if ! command -v dsh >/dev/null 2>&1; then say "dsh is not on PATH (looked in $NODE_BIN too)"; exit 2; fi
say "dsh: $(command -v dsh)"

if [ "$TRANSPORT" = "tcp" ] && [ ! -f "$TOKEN_FILE" ]; then
  say "the shared token is missing: $TOKEN_FILE"; exit 2
fi

# ── the profile (dsh-base only: no other stdio server) ────────────────────────
if [ ! -f "$PROFILE_DIR/package.json" ]; then
  say "creating the '$AGENT_PROFILE' profile at $PROFILE_DIR"
  mkdir -p "$PROFILE_DIR/node_modules"
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
fi

# The row itself is only written when the profile is new (or when --rewrite is
# given). An operator's own rows live in this same file, and the host runs this
# command on every connect — so rewriting here would delete them on the next
# reconnect, silently.
if [ -f "$PATCH" ] && [ "$DO_REWRITE" -ne 1 ]; then
  say "keeping the existing $PATCH (pass --rewrite to regenerate it)"
else
  {
    echo "# Written by dsh-native-env-v2/bin/guest-env-profile.sh."
    echo "# This profile exists to be one thing only: a DSH runtime whose stdout belongs"
    echo "# to the env wire and to nothing else (dsh-base alone — no app bundle)."
    echo "# Rows appended below this block are kept across reconnects: the helper only"
    echo "# rewrites this file for a new profile, or with --rewrite."
    echo "- insert:"
    echo "    - id: native-env-guest-v2"
    echo "      name: '$PLUGIN_DIR/lib/guest.js'"
    echo "      config:"
    echo "        transport: $TRANSPORT"
    if [ "$TRANSPORT" = "tcp" ]; then
      echo "        host: '$SERVER_HOST'"
      echo "        port: $PORT"
      echo "        peer: $PEER"
      echo "        tokenFile: '$TOKEN_FILE'"
    fi
    echo "        cwd: '$CWD_DIR'"
    echo "        maxResultBytes: 262144"
  } > "$PATCH"
  say "wrote $PATCH"
fi

# ── compose BEFORE starting anything ──────────────────────────────────────────
dump="$(dsh --profile "$AGENT_PROFILE" --dump-config 2>&1 || true)"
if ! printf '%s' "$dump" | grep -q 'native-env-guest-v2'; then
  say 'the profile did NOT compose; refusing to start the runtime'
  printf '%s\n' "$dump" | tail -n 12
  exit 1
fi
say 'profile composes (native-env-guest-v2 present)'

if [ "$DO_DUMP" -eq 1 ]; then
  printf '%s\n' "$dump"
  exit 0
fi

if [ "$DO_START" -ne 1 ]; then
  say "done (pass --start to run the runtime in the foreground)"
  exit 0
fi

# ── run in the FOREGROUND ─────────────────────────────────────────────────────
# Under the stdio transport the host's ssh channel IS this process's stdin/stdout,
# so the runtime must not fork into the background: when ssh closes, stdin ends and
# the runtime exits with it, leaving nothing behind on the guest.
say "starting: profile $AGENT_PROFILE transport=$TRANSPORT cwd=$CWD_DIR"
exec dsh --profile "$AGENT_PROFILE"
