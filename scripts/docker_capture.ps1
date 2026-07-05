# Live capture — only Docker required (no Poetry/Python on host).
# Usage: .\scripts\docker_capture.ps1 [profile] [timeout_sec]
$ErrorActionPreference = "Stop"
$Root = Split-Path $PSScriptRoot -Parent
Set-Location $Root

function Invoke-Docker {
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & docker @args
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    } finally {
        $ErrorActionPreference = $prev
    }
}

$Profile = if ($args[0]) { $args[0] } else { "dns" }
$Timeout = $args[1]
$Image = "capture-udp-sig"
$BrowserProfiles = @("quic", "quic_browser", "quic_tls_browser", "stun", "stun_browser", "webrtc")
$Dockerfile = if ($BrowserProfiles -contains $Profile) { "Dockerfile.capture" } else { "Dockerfile.capture-lite" }

New-Item -ItemType Directory -Force -Path "$Root\output" | Out-Null

$env:DOCKER_BUILDKIT = "1"
Write-Host "=== docker build $Image ($Dockerfile) ==="
Invoke-Docker build -f $Dockerfile -t $Image .

$runArgs = @(
    "run", "--rm",
    "--cap-add=NET_RAW",
    "--cap-add=NET_ADMIN",
    "-v", "${Root}/output:/lab/output",
    $Image,
    $Profile
)
if ($Timeout) { $runArgs += $Timeout }

Write-Host "=== capture profile=$Profile ==="
Invoke-Docker @runArgs

$out = Join-Path $Root "output\live_${Profile}.json"
if (-not (Test-Path $out)) {
    Write-Error "Missing $out"
    exit 1
}

Write-Host "`n=== result ($out) ==="
Get-Content $out -Raw
