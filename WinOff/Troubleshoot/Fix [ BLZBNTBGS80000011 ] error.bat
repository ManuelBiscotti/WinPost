@echo off
:: https://privacy.sexy — v0.13.8 — Sat, 27 Sep 2025 11:01:38 GMT
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
:: ----------Disable insecure "SHA-1" hash (revert)----------
:: ----------------------------------------------------------
echo --- Disable insecure "SHA-1" hash (revert)
:: Restore usage of "SHA" hash algorithm for TLS/SSL connections
:: Delete the registry value "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "reg delete 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA' /v 'Enabled' /f 2>$null"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Disable insecure "SSL 2.0" protocol (revert)-------
:: ----------------------------------------------------------
echo --- Disable insecure "SSL 2.0" protocol (revert)
:: Restore usage of "SSL 2.0" protocol for TLS/SSL connections
:: Delete the registry value "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "reg delete 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' /v 'Enabled' /f 2>$null"
:: Delete the registry value "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server!DisabledByDefault"
PowerShell -ExecutionPolicy Unrestricted -Command "reg delete 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' /v 'DisabledByDefault' /f 2>$null"
:: Delete the registry value "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "reg delete 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' /v 'Enabled' /f 2>$null"
:: Delete the registry value "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client!DisabledByDefault"
PowerShell -ExecutionPolicy Unrestricted -Command "reg delete 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' /v 'DisabledByDefault' /f 2>$null"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Disable insecure "SSL 3.0" protocol (revert)-------
:: ----------------------------------------------------------
echo --- Disable insecure "SSL 3.0" protocol (revert)
:: Restore usage of "SSL 3.0" protocol for TLS/SSL connections
:: Delete the registry value "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "reg delete 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' /v 'Enabled' /f 2>$null"
:: Delete the registry value "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server!DisabledByDefault"
PowerShell -ExecutionPolicy Unrestricted -Command "reg delete 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' /v 'DisabledByDefault' /f 2>$null"
:: Delete the registry value "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "reg delete 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' /v 'Enabled' /f 2>$null"
:: Delete the registry value "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client!DisabledByDefault"
PowerShell -ExecutionPolicy Unrestricted -Command "reg delete 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' /v 'DisabledByDefault' /f 2>$null"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Disable insecure "TLS 1.0" protocol (revert)-------
:: ----------------------------------------------------------
echo --- Disable insecure "TLS 1.0" protocol (revert)
:: Restore usage of "TLS 1.0" protocol for TLS/SSL connections
:: Delete the registry value "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "reg delete 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' /v 'Enabled' /f 2>$null"
:: Delete the registry value "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server!DisabledByDefault"
PowerShell -ExecutionPolicy Unrestricted -Command "reg delete 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' /v 'DisabledByDefault' /f 2>$null"
:: Delete the registry value "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "reg delete 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' /v 'Enabled' /f 2>$null"
:: Delete the registry value "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client!DisabledByDefault"
PowerShell -ExecutionPolicy Unrestricted -Command "reg delete 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' /v 'DisabledByDefault' /f 2>$null"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Disable insecure "TLS 1.1" protocol (revert)-------
:: ----------------------------------------------------------
echo --- Disable insecure "TLS 1.1" protocol (revert)
:: Restore usage of "TLS 1.1" protocol for TLS/SSL connections
:: Delete the registry value "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "reg delete 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' /v 'Enabled' /f 2>$null"
:: Delete the registry value "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server!DisabledByDefault"
PowerShell -ExecutionPolicy Unrestricted -Command "reg delete 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' /v 'DisabledByDefault' /f 2>$null"
:: Delete the registry value "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "reg delete 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' /v 'Enabled' /f 2>$null"
:: Delete the registry value "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client!DisabledByDefault"
PowerShell -ExecutionPolicy Unrestricted -Command "reg delete 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' /v 'DisabledByDefault' /f 2>$null"
:: ----------------------------------------------------------


:: Pause the script to view the final state
pause
:: Restore previous environment settings
endlocal
:: Exit the script successfully
exit /b 0