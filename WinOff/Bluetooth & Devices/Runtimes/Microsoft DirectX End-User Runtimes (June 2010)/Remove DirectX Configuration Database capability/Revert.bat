@echo off
:: https://privacy.sexy — v0.13.8 — Thu, 06 Nov 2025 15:23:51 GMT
:: Ensure PowerShell is available
where PowerShell >nul 2>&1 || (
    echo PowerShell is not available. Please install or enable PowerShell.
    pause & exit 1
)
:: Ensure admin privileges
fltmc >nul 2>&1 || (
    echo Administrator privileges are required.
    PowerShell Start -Verb RunAs '%0' 2> nul || (
        echo Right-click on the script and select "Run as administrator".
        pause & exit 1
    )
    exit 0
)
:: Initialize environment
setlocal EnableExtensions DisableDelayedExpansion


:: Remove "DirectX Configuration Database" capability (revert)
echo --- Remove "DirectX Configuration Database" capability (revert)
PowerShell -ExecutionPolicy Unrestricted -Command "$capability = Get-WindowsCapability -Online -Name 'DirectX.Configuration.Database*'; Add-WindowsCapability -Name "^""$capability.Name"^"" -Online"
:: ----------------------------------------------------------


:: Pause the script to view the final state
pause
:: Restore previous environment settings
endlocal
:: Exit the script successfully
exit /b 0