#!/usr/bin/env pwsh
# Удобная обёртка: python -m siglab ...
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Args
)
$py = if ($env:PYTHON) { $env:PYTHON } else { "python" }
& $py -m siglab @Args
exit $LASTEXITCODE
