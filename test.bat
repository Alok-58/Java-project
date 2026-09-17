@echo off
if not exist "bin\com\smartlog\analyzer\AnalyzerTestSuite.class" (
    echo [INFO] Compiling project test suite...
    call build.bat
    if %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL%
)

java -cp bin com.smartlog.analyzer.AnalyzerTestSuite
