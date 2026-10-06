# dsh-native-env-v2 / guest-run-standalone — run the REMOTE half on a guest WITHOUT
# touching the runtime the net-bridge keeper already owns.
#
# Why this exists next to guest-install.ps1: the installer adds a row to the
# guest's `sdk` profile, which is the profile the keeper's `dsh --profile sdk`
# child is running. That row is only read at startup, so picking it up means
# restarting that child — and the keeper gives up after five restarts, so a bad
# patch costs the guest its runtime and the only channel back to it.
#
# This script takes the other road: it creates a SEPARATE `env` profile and runs
# it as its own detached process. Nothing the keeper owns is read, written, or
# restarted, and the whole thing is undone by -Stop plus deleting the profile.
#
# It is reachable over the vm-cu bridge (dsh-computer-use-vm), which serves
# `run`/`push`/`pull` on the host's 8899 listener — so a host session can deploy
# and start this without a harness restart.
#
#   pwsh -File guest-run-standalone.ps1            # create the profile + start
#   pwsh -File guest-run-standalone.ps1 -Verify    # ... and show the config + log
#   pwsh -File guest-run-standalone.ps1 -Stop      # stop the runtime
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
    [string]$AgentProfile = 'env',
    [string]$Cwd = "$env:USERPROFILE\dsh-net-bridge-workspace",
    [int]$MaxResultBytes = 262144,
    [switch]$Stop,
    [switch]$Verify
)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

function Say([string]$Message) { Write-Output ("[guest-run] " + $Message) }

$DshHome = if ($env:DSH_HOME) { $env:DSH_HOME } else { Join-Path $env:USERPROFILE '.dsh' }
$ProfileDir = Join-Path $DshHome "profiles\$AgentProfile"
$PatchPath = Join-Path $ProfileDir 'cordis.patch.yml'
$LogPath = Join-Path $PluginDir "$AgentProfile.log"
$PidPath = Join-Path $PluginDir "$AgentProfile.pid"

function Get-RuntimeProcess {
    Get-CimInstance Win32_Process -Filter "Name = 'node.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -and $_.CommandLine -match "--profile\s+$AgentProfile\b" -and $_.CommandLine -match 'dsh' }
}

# ── stop ──────────────────────────────────────────────────────────────────────
if ($Stop) {
    $killed = 0
    foreach ($proc in @(Get-RuntimeProcess)) {
        Say "stopping pid $($proc.ProcessId)"
        try { Stop-Process -Id $proc.ProcessId -Force -ErrorAction Stop; $killed++ } catch { Say "stop failed: $($_.Exception.Message)" }
    }
    if (Test-Path -LiteralPath $PidPath) { Remove-Item -LiteralPath $PidPath -Force -ErrorAction SilentlyContinue }
    Say "stopped $killed process(es); the profile was left in place (delete $ProfileDir to remove it)"
    exit 0
}

# ── prerequisites ─────────────────────────────────────────────────────────────
# Paths are relative to $PluginDir and carry their own directory. They used to be
# a bare-name list joined onto `lib\`, which demanded `lib\guest-runtime-launcher.mjs`
# — a file that ships in `bin\`. On a pristine deployment the check therefore never
# passed and this script exited 2 before starting anything.
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
    exit 2
}
if (-not (Test-Path -LiteralPath $TokenFile)) { Say "the shared token is missing: $TokenFile"; exit 2 }
$dsh = (Get-Command dsh -ErrorAction SilentlyContinue)
if (-not $dsh) { Say 'dsh is not on PATH in this session'; exit 2 }
Say "dsh: $($dsh.Source)"

# ── the standalone profile (dsh-base only: no other stdio server) ─────────────
# Keyed on the MANIFEST, not the directory. A partially removed profile leaves an
# empty directory behind, and a directory without package.json is not a profile —
# dsh then refuses it with "profile does not exist", which is a confusing way to
# say "the manifest is missing".
if (-not (Test-Path -LiteralPath (Join-Path $ProfileDir 'package.json'))) {
    Say "creating the '$AgentProfile' profile at $ProfileDir"
    New-Item -ItemType Directory -Force -Path $ProfileDir | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $ProfileDir 'node_modules') | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $ProfileDir '.dsh-module-fallback\node_modules') | Out-Null
    Set-Content -LiteralPath (Join-Path $ProfileDir 'cordis.yml') -Encoding UTF8 -Value @(
        '# dsh profile root — an empty entry list. The tree is composed as patches: each',
        "# bundle in package.json's dsh.profile.bundles, then cordis.patch.yml, then any",
        '# --patch overlays. Edit cordis.patch.yml, not this file.',
        '[]'
    )
    Set-Content -LiteralPath (Join-Path $ProfileDir 'pnpm-workspace.yaml') -Encoding UTF8 -Value @(
        'packages:',
        '  - .',
        '',
        'nodeLinker: hoisted',
        'autoInstallPeers: false'
    )
    # Literal JSON rather than ConvertTo-Json: PowerShell unwraps a single-element
    # array into a scalar, and `bundles` must stay a list.
    #
    # `dsh-sdk-app` is here for the same reason the keeper's `sdk` profile carries
    # it: a bare `dsh-base` tree has nothing owning the process lifetime. It is
    # inert for this plugin — the env wire is its own socket, not stdio — but it is
    # what makes the runtime a runtime.
    $manifest = @"
{
  "name": "dsh-profile-$AgentProfile",
  "private": true,
  "dependencies": {},
  "dsh": {
    "profile": {
      "bundles": [
        "@deepseek-ai/dsh-base",
        "@deepseek-ai/dsh-sdk-app"
      ],
      "patchReload": "startup"
    }
  }
}
"@
    Set-Content -LiteralPath (Join-Path $ProfileDir 'package.json') -Encoding UTF8 -Value $manifest
}

$pluginEntry = ($PluginDir -replace '\\', '/') + '/lib/guest.js'
$tokenEntry = ($TokenFile -replace '\\', '/')
Set-Content -LiteralPath $PatchPath -Encoding UTF8 -Value @(
    '# Written by dsh-native-env-v2/bin/guest-run-standalone.ps1.',
    '# This profile exists to be one thing only: a DSH runtime whose stdout belongs',
    '# to the env wire and to nothing else, started separately from the keeper''s',
    '# `sdk` runtime so nothing the net-bridge depends on is touched.',
    '- insert:',
    '    - id: native-env-guest-v2',
    "      name: '$pluginEntry'",
    '      config:',
    '        transport: tcp',
    "        host: '$ServerHost'",
    "        port: $Port",
    "        peer: $Peer",
    "        tokenFile: '$tokenEntry'",
    "        cwd: '$Cwd'",
    "        maxResultBytes: $MaxResultBytes"
)
Say "wrote $PatchPath"

# ── validate BEFORE starting anything ─────────────────────────────────────────
$dump = & $dsh.Source --profile $AgentProfile --dump-config 2>&1 | Out-String
if ($LASTEXITCODE -ne 0 -or $dump -notmatch 'native-env-guest-v2') {
    Say 'the profile did NOT compose; refusing to start the runtime'
    Say ($dump -split "`n" | Select-Object -Last 8 | Out-String)
    exit 1
}
Say 'profile composes (native-env-guest-v2 present)'

# ── start ─────────────────────────────────────────────────────────────────────
foreach ($proc in @(Get-RuntimeProcess)) {
    Say "an '$AgentProfile' runtime is already running (pid $($proc.ProcessId)); leaving it"
    exit 0
}

$node = (Get-Command node -ErrorAction SilentlyContinue).Source
if (-not $node) { $node = 'C:\Program Files\nodejs\node.exe' }
$bin = Join-Path (Split-Path $dsh.Source -Parent) 'node_modules\@deepseek-ai\dsh\lib\bin.js'
if (-not (Test-Path -LiteralPath $bin)) { Say "cannot locate the dsh entry point (tried $bin)"; exit 2 }

# WMI process creation, deliberately NOT Start-Process.
#
# This script is normally invoked through the vm-cu bridge, whose runner owns the
# command it executes. A Start-Process child inherits that runner's job object and
# is killed the instant the runner exits — which is exactly what happened: the
# runtime started, wrote nothing, and was gone by the time the next command
# looked for it. Win32_Process.Create is detached from the caller's job, and it is
# the same mechanism dsh-net-bridge's restart-harness.ps1 uses to start a
# replacement host for the same reason.
$launcher = Join-Path $PluginDir 'lib\guest-runtime-launcher.mjs'
if (-not (Test-Path -LiteralPath $launcher)) { Say "the launcher is missing: $launcher"; exit 2 }

Say "starting via the launcher: profile $AgentProfile"
$launch = '"{0}" "{1}" {2} "{3}" "{4}"' -f $node, $launcher, $AgentProfile, $LogPath, $PidPath
$created = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $launch }
if ($created.ReturnValue -ne 0) {
    Say "Win32_Process.Create failed with return value $($created.ReturnValue)"
    exit 1
}
Say "started launcher pid $($created.ProcessId) (detached); log: $LogPath"

if ($Verify) {
    Start-Sleep -Seconds 8
    Say '--- log ---'
    Get-Content -LiteralPath $LogPath -Tail 20 -ErrorAction SilentlyContinue
    Say "runtime processes matching --profile $AgentProfile : $(@(Get-RuntimeProcess).Count)"
    $conn = @(Get-NetTCPConnection -RemotePort $Port -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Established' })
    Say "established connections to the host's port ${Port}: $($conn.Count)"
}

Say 'done'
