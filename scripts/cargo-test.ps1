$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$tempDir = Join-Path $repoRoot ".tmp"

if (-not (Test-Path -LiteralPath $tempDir)) {
    New-Item -ItemType Directory -Path $tempDir | Out-Null
}

$env:TMP = $tempDir
$env:TEMP = $tempDir

Write-Host "TMP=$env:TMP"
Write-Host "TEMP=$env:TEMP"

$nativeErrorPreference = $null
if (Get-Variable -Name PSNativeCommandUseErrorActionPreference -ErrorAction SilentlyContinue) {
    $nativeErrorPreference = $PSNativeCommandUseErrorActionPreference
    $PSNativeCommandUseErrorActionPreference = $false
}

try {
    Push-Location $repoRoot
    try {
        cargo test @args
        $exitCode = $LASTEXITCODE
    } finally {
        Pop-Location
    }
} finally {
    if ($null -ne $nativeErrorPreference) {
        $PSNativeCommandUseErrorActionPreference = $nativeErrorPreference
    }
}

exit $exitCode
