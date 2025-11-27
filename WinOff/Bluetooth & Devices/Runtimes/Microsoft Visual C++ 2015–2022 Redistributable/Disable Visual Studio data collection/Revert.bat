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


:: Disable participation in Visual Studio Customer Experience Improvement Program (VSCEIP) (revert)
echo --- Disable participation in Visual Studio Customer Experience Improvement Program (VSCEIP) (revert)
:: Delete the registry value "HKLM\Software\Policies\Microsoft\VisualStudio\SQM!OptIn"
PowerShell -ExecutionPolicy Unrestricted -Command "reg delete 'HKLM\Software\Policies\Microsoft\VisualStudio\SQM' /v 'OptIn' /f 2>$null"
:: Set the registry value "HKLM\SOFTWARE\Microsoft\VSCommon\14.0\SQM!OptIn"
PowerShell -ExecutionPolicy Unrestricted -Command "$revertData =  '1'; reg add 'HKLM\SOFTWARE\Microsoft\VSCommon\14.0\SQM' /v 'OptIn' /t 'REG_DWORD' /d "^""$revertData"^"" /f"
:: Set the registry value "HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\14.0\SQM!OptIn"
PowerShell -ExecutionPolicy Unrestricted -Command "$revertData =  '1'; reg add 'HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\14.0\SQM' /v 'OptIn' /t 'REG_DWORD' /d "^""$revertData"^"" /f"
:: Set the registry value "HKLM\SOFTWARE\Microsoft\VSCommon\15.0\SQM!OptIn"
PowerShell -ExecutionPolicy Unrestricted -Command "$revertData =  '1'; reg add 'HKLM\SOFTWARE\Microsoft\VSCommon\15.0\SQM' /v 'OptIn' /t 'REG_DWORD' /d "^""$revertData"^"" /f"
:: Set the registry value "HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\15.0\SQM!OptIn"
PowerShell -ExecutionPolicy Unrestricted -Command "$revertData =  '1'; reg add 'HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\15.0\SQM' /v 'OptIn' /t 'REG_DWORD' /d "^""$revertData"^"" /f"
:: Set the registry value "HKLM\SOFTWARE\Microsoft\VSCommon\16.0\SQM!OptIn"
PowerShell -ExecutionPolicy Unrestricted -Command "$revertData =  '1'; reg add 'HKLM\SOFTWARE\Microsoft\VSCommon\16.0\SQM' /v 'OptIn' /t 'REG_DWORD' /d "^""$revertData"^"" /f"
:: Set the registry value "HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\16.0\SQM!OptIn"
PowerShell -ExecutionPolicy Unrestricted -Command "$revertData =  '1'; reg add 'HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\16.0\SQM' /v 'OptIn' /t 'REG_DWORD' /d "^""$revertData"^"" /f"
:: Set the registry value "HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\17.0\SQM!OptIn"
PowerShell -ExecutionPolicy Unrestricted -Command "$revertData =  '1'; reg add 'HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\17.0\SQM' /v 'OptIn' /t 'REG_DWORD' /d "^""$revertData"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Disable Visual Studio telemetry (revert)---------
:: ----------------------------------------------------------
echo --- Disable Visual Studio telemetry (revert)
:: Delete the registry value "HKCU\Software\Microsoft\VisualStudio\Telemetry!TurnOffSwitch"
PowerShell -ExecutionPolicy Unrestricted -Command "reg delete 'HKCU\Software\Microsoft\VisualStudio\Telemetry' /v 'TurnOffSwitch' /f 2>$null"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Disable Visual Studio feedback (revert)----------
:: ----------------------------------------------------------
echo --- Disable Visual Studio feedback (revert)
:: Delete the registry value "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback!DisableFeedbackDialog"
PowerShell -ExecutionPolicy Unrestricted -Command "reg delete 'HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback' /v 'DisableFeedbackDialog' /f 2>$null"
:: Delete the registry value "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback!DisableEmailInput"
PowerShell -ExecutionPolicy Unrestricted -Command "reg delete 'HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback' /v 'DisableEmailInput' /f 2>$null"
:: Delete the registry value "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback!DisableScreenshotCapture"
PowerShell -ExecutionPolicy Unrestricted -Command "reg delete 'HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback' /v 'DisableScreenshotCapture' /f 2>$null"
:: ----------------------------------------------------------


:: Disable "Visual Studio Standard Collector Service" (revert)
echo --- Disable "Visual Studio Standard Collector Service" (revert)
:: Restore service(s) to default state: `VSStandardCollectorService150`
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'VSStandardCollectorService150'; $defaultStartupMode = 'Manual'; $ignoreMissingOnRevert =  $false; Write-Host "^""Reverting service `"^""$serviceName`"^"" start to `"^""$defaultStartupMode`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if (!$service) { if ($ignoreMissingOnRevert) { Write-Output "^""Skipping: The service `"^""$serviceName`"^"" is not found. No action required."^""; Exit 0; }; Write-Warning "^""Failed to revert changes to the service `"^""$serviceName`"^"". The service is not found."^""; Exit 1; }; <# -- 2. Enable or skip if already enabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if (!$startupType) { $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if (!$startupType) { $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if ($startupType -eq "^""$defaultStartupMode"^"") { Write-Host "^""`"^""$serviceName`"^"" has already expected startup mode: `"^""$defaultStartupMode`"^"". No action required."^""; } else { try { Set-Service -Name "^""$serviceName"^"" -StartupType "^""$defaultStartupMode"^"" -Confirm:$false -ErrorAction Stop; Write-Host "^""Reverted `"^""$serviceName`"^"" with `"^""$defaultStartupMode`"^"" start, this may require restarting your computer."^""; } catch { Write-Error "^""Failed to enable `"^""$serviceName`"^"": $_"^""; Exit 1; }; }; <# -- 4. Start if not running (must be enabled first) #>; if ($defaultStartupMode -eq 'Automatic' -or $defaultStartupMode -eq 'Boot' -or $defaultStartupMode -eq 'System') { if ($service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running) { Write-Host "^""`"^""$serviceName`"^"" is not running, starting it."^""; try { Start-Service $serviceName -ErrorAction Stop; Write-Host "^""Started `"^""$serviceName`"^"" successfully."^""; } catch { Write-Warning "^""Failed to start `"^""$serviceName`"^"", requires restart, it will be started after reboot.`r`n$_"^""; }; } else { Write-Host "^""`"^""$serviceName`"^"" is already running, no need to start."^""; }; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----Disable Diagnostics Hub log collection (revert)------
:: ----------------------------------------------------------
echo --- Disable Diagnostics Hub log collection (revert)
:: Remove the registry value "LogLevel" from key "HKLM\Software\Microsoft\VisualStudio\DiagnosticsHub" to restore its original state 
PowerShell -ExecutionPolicy Unrestricted -Command "$keyName = 'HKLM\Software\Microsoft\VisualStudio\DiagnosticsHub'; $valueName = 'LogLevel'; $hive = $keyName.Split('\')[0]; $path = "^""$($hive):$($keyName.Substring($hive.Length))"^""; Write-Host "^""Removing the registry value '$valueName' from '$path'."^""; if (-Not (Test-Path -LiteralPath $path)) { Write-Host 'Skipping, no action needed, registry key does not exist.'; Exit 0; }; $existingValueNames = (Get-ItemProperty -LiteralPath $path).PSObject.Properties.Name; if (-Not ($existingValueNames -Contains $valueName)) { Write-Host 'Skipping, no action needed, registry value does not exist.'; Exit 0; }; try { if ($valueName -ieq '(default)') { Write-Host 'Removing the default value.'; $(Get-Item -LiteralPath $path).OpenSubKey('', $true).DeleteValue(''); } else { Remove-ItemProperty -LiteralPath $path -Name $valueName -Force -ErrorAction Stop; }; Write-Host 'Successfully removed the registry value.'; } catch { Write-Error "^""Failed to remove the registry value: $($_.Exception.Message)"^""; }"
:: ----------------------------------------------------------


:: Disable participation in IntelliCode data collection (revert)
echo --- Disable participation in IntelliCode data collection (revert)
:: Delete the registry value "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\IntelliCode!DisableRemoteAnalysis"
PowerShell -ExecutionPolicy Unrestricted -Command "reg delete 'HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\IntelliCode' /v 'DisableRemoteAnalysis' /f 2>$null"
:: Delete the registry value "HKCU\SOFTWARE\Microsoft\VSCommon\16.0\IntelliCode!DisableRemoteAnalysis"
PowerShell -ExecutionPolicy Unrestricted -Command "reg delete 'HKCU\SOFTWARE\Microsoft\VSCommon\16.0\IntelliCode' /v 'DisableRemoteAnalysis' /f 2>$null"
:: Delete the registry value "HKCU\SOFTWARE\Microsoft\VSCommon\17.0\IntelliCode!DisableRemoteAnalysis"
PowerShell -ExecutionPolicy Unrestricted -Command "reg delete 'HKCU\SOFTWARE\Microsoft\VSCommon\17.0\IntelliCode' /v 'DisableRemoteAnalysis' /f 2>$null"
:: ----------------------------------------------------------


:: Pause the script to view the final state
pause
:: Restore previous environment settings
endlocal
:: Exit the script successfully
exit /b 0