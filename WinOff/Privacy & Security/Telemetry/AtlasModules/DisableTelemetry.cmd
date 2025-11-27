@echo off
set "script=%~dp0Scripts\ScriptWrappers\DisableTelemetry.ps1"
if not exist "%script%" (
    echo Script not found: "%script%"
    pause
    exit /b 1
)

whoami /user | find /i "S-1-5-18" >nul 2>&1 || (
    call "%~dp0Scripts\RunAsTI.cmd" "%~f0" %*
    exit /b
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%script%" %*