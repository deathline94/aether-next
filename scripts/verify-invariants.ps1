# Windows entry point for the invariant gate harness.
# The gate logic lives in exactly one place (scripts/verify-invariants.mjs);
# this wrapper only forwards arguments. Two implementations of the same rule is
# how drift happens, which is one of the defect classes this feature removes.
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Args2
)
$ErrorActionPreference = 'Stop'
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
& node (Join-Path $scriptDir 'verify-invariants.mjs') @Args2
exit $LASTEXITCODE
