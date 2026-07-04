# Live capture via unified siglab CLI (Docker Desktop on Windows/Linux).
$ErrorActionPreference = "Stop"
$Lab = Split-Path $PSScriptRoot -Parent
Set-Location $Lab

$Profile = if ($args[0]) { $args[0] } else { "dns" }
$Extra = @()
if ($args.Count -gt 1) {
    $Extra += "--timeout"
    $Extra += $args[1]
}

$py = if ($env:PYTHON) { $env:PYTHON } else { "python" }
& $py -m siglab capture --docker --profile $Profile --format prod --out "output/live_${Profile}.json" @Extra
exit $LASTEXITCODE
