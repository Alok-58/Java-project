# PowerShell Run Script for Smart Log Analyzer
if (-not (Test-Path "bin\com\smartlog\analyzer\Main.class")) {
    Write-Host "[INFO] Classes not compiled yet. Compiling now..." -ForegroundColor Yellow
    & ".\build.ps1"
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

java -cp bin com.smartlog.analyzer.Main $args
