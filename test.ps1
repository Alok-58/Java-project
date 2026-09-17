# PowerShell Test Runner
if (-not (Test-Path "bin\com\smartlog\analyzer\AnalyzerTestSuite.class")) {
    & ".\build.ps1"
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

java -cp bin com.smartlog.analyzer.AnalyzerTestSuite
