@echo off

setlocal

echo ========================================
echo Deep AI Digital Forensics Test Scenario
echo ========================================
echo.

if not exist build mkdir build

echo [1/2] Compiling test scenario...

g++ RiskScenario.cpp -o build\RiskScenario.exe -lwinhttp

if errorlevel 1 (
    echo.
    echo Compilation failed.
    exit /b 1
)

echo.
echo [2/2] Running test scenario...
echo.

build\RiskScenario.exe

echo.
echo ========================================
echo Test scenario finished
echo ========================================

endlocal