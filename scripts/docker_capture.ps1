# Live capture — only Docker required (no Poetry/Python on host).
# Usage: .\scripts\docker_capture.ps1 [profile] [timeout_sec]
# Example: .\scripts\docker_capture.ps1 dns
$ErrorActionPreference = "Stop"
$Root = Split-Path $PSScriptRoot -Parent
Set-Location $Root

function Invoke-Docker {
    & docker @args 2>&1 | ForEach-Object { Write-Host $_ }
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

$Profile = if ($args[0]) { $args[0] } else { "dns" }
$Timeout = $args[1]
$Image = "capture-udp-sig"

New-Item -ItemType Directory -Force -Path "$Root\output" | Out-Null

$env:DOCKER_BUILDKIT = "1"
Write-Host "=== docker build $Image ==="
Invoke-Docker build -f Dockerfile.capture -t $Image .

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
