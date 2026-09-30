@echo off

set TEST_DIR=%TEMP%\DeepForensicsTest

echo Removing forensic test artifacts...

if exist "%TEST_DIR%" (
    rmdir /s /q "%TEST_DIR%"
    echo Removed: %TEST_DIR%
) else (
    echo Nothing to clean.
)

echo Done.