# dsh-native-env-v2 / guest-install — install, verify, or remove the REMOTE half on a
# WINDOWS guest.
#
# Runs INSIDE the guest. The plugin files and the shared token are pushed next to
# this script beforehand; this script never handles the token VALUE, only its path.
#
#   pwsh -File guest-install.ps1                 # install + verify
#   pwsh -File guest-install.ps1 -Remove         # remove the profile row
#
# Expected layout (created by the host-side deployment):
#   %USERPROFILE%\dsh-native-env-v2\lib\guest.js
#   %USERPROFILE%\dsh-native-env-v2\lib\guest-transport.js
#   %USERPROFILE%\dsh-native-env-v2\lib\env-protocol.js
#   %USERPROFILE%\dsh-native-env-v2\lib\handshake.js
#   %USERPROFILE%\dsh-native-env-v2\lib\wire.js
#   %USERPROFILE%\.dsh-net-bridge-token
#
# The five lib files are exactly the guest half's transitive closure; the host
# half (host.js, hub.js, client.js, binding.js, netaddr.js, tool-def.js) is NOT
# needed here and is not pushed.
#
# Parameter names avoid PowerShell's read-only automatic variables: `$Host` and
# `$Profile` cannot be assigned, so they are -ServerHost and -AgentProfile.

param(
    [string]$PluginDir = "$env:USERPROFILE\dsh-native-env-v2",
    # Set -ServerHost to the controller address for cross-machine TCP.
    [string]$ServerHost = '127.0.0.1',
    [int]$Port = 8912,
    [string]$Peer = 'win10',
    [string]$TokenFile = "$env:USERPROFILE\.dsh-net-bridge-token",
    [string]$AgentProfile = 'sdk',
    [string]$Cwd = "$env:USERPROFILE\dsh-native-env-v2-workspace",
    [int]$MaxResultBytes = 262144,
    [switch]$Remove,
    [switch]$Verify
)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

$Marker = 'native-env-guest-v2'
$BeginMarker = '# >>> dsh-native-env-v2 (managed) >>>'
$EndMarker = '# <<< dsh-native-env-v2 (managed) <<<'

function Say([string]$Message) { Write-Output ("[guest-install] " + $Message) }

$DshHome = if ($env:DSH_HOME) { $env:DSH_HOME } else { Join-Path $env:USERPROFILE '.dsh' }
$PatchPath = Join-Path $DshHome "profiles\$AgentProfile\cordis.patch.yml"

# ── remove ────────────────────────────────────────────────────────────────────
if ($Remove) {
    if (-not (Test-Path -LiteralPath $PatchPath)) { Say "no patch file at $PatchPath; nothing to do"; exit 0 }
    $lines = Get-Content -LiteralPath $PatchPath
    if (-not ($lines -match [regex]::Escape($BeginMarker))) { Say "no managed block in $PatchPath; nothing to do"; exit 0 }
    $kept = New-Object System.Collections.Generic.List[string]
    $inside = $false
    foreach ($line in $lines) {
        if ($line -match [regex]::Escape($BeginMarker)) { $inside = $true; continue }
        if ($line -match [regex]::Escape($EndMarker)) { $inside = $false; continue }
        if (-not $inside) { $kept.Add($line) }
    }
    Copy-Item -LiteralPath $PatchPath -Destination "$PatchPath.bak-native-env" -Force
    Set-Content -LiteralPath $PatchPath -Value $kept -Encoding UTF8
    Say "removed the managed block from $PatchPath (backup: $PatchPath.bak-native-env)"
    Say 'restart the guest runtime for it to take effect (the keeper respawns it on exit)'
    exit 0
}

# ── prerequisites ─────────────────────────────────────────────────────────────
# This list is the guest half's IMPORT CLOSURE and must match it exactly — the
# closure guard in tests/guest-closure.test.mjs derives the set from the source and
# compares it against these three installers. The launcher is listed too because
# `guest-run-standalone.ps1` — the documented way to start this half WITHOUT
# touching the keeper's `sdk` profile — refuses to start without it, and discovering
# that after a push is a wasted round trip.
$required = @(
    'lib\e2ee.js',
    'lib\device-code.js',
    'lib\e2ee-channel.js',
    'lib\env-protocol.js',
    'lib\guest-transport.js',
    'lib\guest.js',
    'lib\handshake.js',
    'lib\host-api.js',
    'lib\pairing-guest.js',
    'lib\pairing-session.js',
    'lib\pairing.js',
    'lib\protocol-v2.js',
    'lib\relay-client.js',
    'lib\relay-protocol.js',
    'lib\state-store.js',
    'lib\terms.js',
    'lib\wire.js',
    'lib\ws.js',
    'bin\guest-runtime-launcher.mjs'
)
$missing = @()
foreach ($name in $required) {
    $path = Join-Path $PluginDir $name
    if (-not (Test-Path -LiteralPath $path)) { $missing += $path }
}
if ($missing.Count -gt 0) {
    Say 'the plugin files are missing:'
    foreach ($path in $missing) { Say "  $path" }
    Say "copy them from the host first: <repo>\plugins\dsh-native-env-v2\{lib,bin}\* -> `"$PluginDir`""
    exit 2
}
if (-not (Test-Path -LiteralPath $TokenFile)) {
    Say "the shared token is missing: $TokenFile"
    Say 'copy it from the host first (it must be the same file the host row names)'
    exit 2
}
Say "plugin files present in $PluginDir (lib + bin)"
Say "token present at $TokenFile"

# ── the profile row ───────────────────────────────────────────────────────────
if (-not (Test-Path -LiteralPath (Split-Path $PatchPath -Parent))) {
    Say "the profile directory does not exist: $(Split-Path $PatchPath -Parent)"
    Say "boot the profile once (dsh --profile $AgentProfile) so it is created, then re-run this script"
    exit 2
}

$pluginEntry = ($PluginDir -replace '\\', '/') + '/lib/guest.js'
$tokenEntry = ($TokenFile -replace '\\', '/')

$block = @(
    $BeginMarker,
    '# Written by dsh-native-env-v2/bin/guest-install.ps1 — re-run with -Remove to delete.',
    '- insert:',
    "    - id: $Marker",
    "      name: '$pluginEntry'",
    '      config:',
    '        transport: tcp',
    "        host: '$ServerHost'",
    "        port: $Port",
    "        peer: $Peer",
    "        tokenFile: '$tokenEntry'",
    "        cwd: '$Cwd'",
    "        maxResultBytes: $MaxResultBytes",
    $EndMarker
)

$existing = if (Test-Path -LiteralPath $PatchPath) { Get-Content -LiteralPath $PatchPath -Raw } else { '' }
if ($existing -match [regex]::Escape($Marker)) {
    Say "a '$Marker' row is already present in $PatchPath; leaving it alone"
    Say "run with -Remove first if you need to change the settings"
} else {
    if (Test-Path -LiteralPath $PatchPath) { Copy-Item -LiteralPath $PatchPath -Destination "$PatchPath.bak-native-env" -Force }
    # A fresh profile's patch file is the empty entry list `[]`. Appending a block
    # sequence AFTER that flow sequence is a YAML error ("expected <block end>,
    # but found '-'"), so a standalone `[]` line is dropped first. Comments are
    # kept, which is what preserves the stock header.
    $kept = @()
    if (Test-Path -LiteralPath $PatchPath) {
        $kept = @(Get-Content -LiteralPath $PatchPath | Where-Object { $_.Trim() -ne '[]' })
    }
    Set-Content -LiteralPath $PatchPath -Value ($kept + @('') + $block) -Encoding UTF8
    Say "wrote the managed block into $PatchPath"
    Say 'restart the guest runtime for it to take effect (the keeper respawns it on exit)'
}

if ($Verify) {
    Start-Sleep -Seconds 2
    Say '--- current profile row ---'
    Get-Content -LiteralPath $PatchPath -Tail 14 | ForEach-Object { Write-Output $_ }
    Say '--- connection to the host env listener ---'
    $conn = @(Get-NetTCPConnection -RemotePort $Port -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Established' })
    Say "established connections to port ${Port}: $($conn.Count)"
}

Say 'done'
