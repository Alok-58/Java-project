@echo off
if not exist "bin\com\smartlog\analyzer\Main.class" (
    echo [INFO] Project not yet compiled. Running build.bat first...
    call build.bat
    if %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL%
)

java -cp bin com.smartlog.analyzer.Main %*
