@echo off
cd /d "%~dp0"
"Windows X Post Install.cmd" -both %*

if errorlevel 1 (
    echo LAUNCHER: Script failed with errorlevel %errorlevel%
) else (
    echo LAUNCHER: Script completed successfully
)

pause