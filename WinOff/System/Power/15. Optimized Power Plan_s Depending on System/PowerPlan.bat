@echo off
setlocal

:: Check if the system supports Ultimate Performance
for /f "tokens=3" %%i in ('wmic computersystem get totalphysicalmemory') do set totalmem=%%i

if %totalmem% GEQ 17179869184 (
    :: Enable Ultimate Performance
    powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61
    powercfg /setactive e9a42b02-d5df-448d-aa00-03f14749eb61
    echo Ultimate Performance power plan has been enabled and set as active.
) else (
    :: Set High Performance power plan
    powercfg /setactive SCHEME_MIN
    echo High Performance power plan has been set as active.
)

pause

endlocal