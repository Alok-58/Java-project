@echo off
setlocal enabledelayedexpansion

echo ========================================================
echo  Compiling Smart Log Analyzer (Java 17+)
echo ========================================================

if not exist bin mkdir bin

dir /s /b src\main\java\*.java > sources.txt
dir /s /b src\test\java\*.java >> sources.txt

javac -encoding UTF-8 -d bin @sources.txt
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Compilation failed!
    del sources.txt
    exit /b 1
)

del sources.txt
echo [OK] Compilation successful! Output stored in bin/
