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


:: ----------------------------------------------------------
:: --------Disable Edge WebView and WebView2 updates---------
:: ----------------------------------------------------------
echo --- Disable Edge WebView and WebView2 updates
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate!Update{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate' /v 'Update{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: Pause the script to view the final state
:: pause
:: Restore previous environment settings
endlocal
:: Exit the script successfully
:: exit /b 0