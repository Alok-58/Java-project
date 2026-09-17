# PowerShell Build Script for Smart Log Analyzer
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host " Compiling Smart Log Analyzer (Java 17+)" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan

if (-not (Test-Path "bin")) {
    New-Item -ItemType Directory -Path "bin" | Out-Null
}

$sources = Get-ChildItem -Path "src" -Recurse -Filter "*.java" | ForEach-Object { $_.FullName }
if ($sources.Count -eq 0) {
    Write-Host "[ERROR] No Java source files found in src/" -ForegroundColor Red
    exit 1
}

$sourcesFile = [System.IO.Path]::GetTempFileName()
$sources | Set-Content -Path $sourcesFile -Encoding UTF8

javac -encoding UTF-8 -d bin "@$sourcesFile"
$exitCode = $LASTEXITCODE
Remove-Item -Path $sourcesFile -Force -ErrorAction SilentlyContinue

if ($exitCode -eq 0) {
    Write-Host "[OK] Compilation successful! Classes stored in bin/" -ForegroundColor Green
} else {
    Write-Host "[ERROR] Compilation failed with code $exitCode" -ForegroundColor Red
    exit $exitCode
}
