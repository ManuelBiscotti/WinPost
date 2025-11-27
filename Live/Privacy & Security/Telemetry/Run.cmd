@echo off & setlocal EnableDelayedExpansion

:: Admin check
>nul 2>&1 fltmc || (
    if not defined _elev (
        set "_elev=1"
        set "_PSarg=%~f0"
        powershell -NoProfile "Start-Process cmd.exe -ArgumentList '/c', '""!_PSarg!' -Verb RunAs" && exit /b
    )
    echo.
    echo Right-click and select "Run as administrator"
    pause & exit /b 1
)

CD /d "%~dp0" 
Color 0F

:: Run scripts with error handling
for %%I in (
    "WindowsSpyBlocker.ps1"
    "Win11Debloat.ps1" 
    "winutil.ps1"
    "WPD.ps1"
    "ShutUp10.ps1"
) do (
    echo Running %%~I...
    PowerShell -ExecutionPolicy Bypass -File "%%~I"
    if errorlevel 1 (
        echo ERROR: %%~I failed!
        pause
        exit /b 1
    )
)

echo All scripts completed successfully!
pause
