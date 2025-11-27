@echo off
REM Check if the Ultimate Performance power plan is available
powercfg /L | findstr /I "Ultimate"
IF ERRORLEVEL 1 (
    echo Ultimate Performance power plan not found. Attempting to add it...
    powercfg /duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61
)

REM Set the Ultimate Performance power plan
echo Setting Ultimate Performance power plan...
powercfg /S e9a42b02-d5df-448d-aa00-03f14749eb61

echo Ultimate Performance power plan is now active.
pause