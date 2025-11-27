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


:: Disable participation in Visual Studio Customer Experience Improvement Program (VSCEIP)
echo --- Disable participation in Visual Studio Customer Experience Improvement Program (VSCEIP)
:: Set the registry value: "HKLM\Software\Policies\Microsoft\VisualStudio\SQM!OptIn"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\Software\Policies\Microsoft\VisualStudio\SQM'; $data =  '0'; reg add 'HKLM\Software\Policies\Microsoft\VisualStudio\SQM' /v 'OptIn' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Microsoft\VSCommon\14.0\SQM!OptIn"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Microsoft\VSCommon\14.0\SQM'; $data =  '0'; reg add 'HKLM\SOFTWARE\Microsoft\VSCommon\14.0\SQM' /v 'OptIn' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\14.0\SQM!OptIn"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\14.0\SQM'; $data =  '0'; reg add 'HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\14.0\SQM' /v 'OptIn' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Microsoft\VSCommon\15.0\SQM!OptIn"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Microsoft\VSCommon\15.0\SQM'; $data =  '0'; reg add 'HKLM\SOFTWARE\Microsoft\VSCommon\15.0\SQM' /v 'OptIn' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\15.0\SQM!OptIn"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\15.0\SQM'; $data =  '0'; reg add 'HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\15.0\SQM' /v 'OptIn' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Microsoft\VSCommon\16.0\SQM!OptIn"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Microsoft\VSCommon\16.0\SQM'; $data =  '0'; reg add 'HKLM\SOFTWARE\Microsoft\VSCommon\16.0\SQM' /v 'OptIn' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\16.0\SQM!OptIn"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\16.0\SQM'; $data =  '0'; reg add 'HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\16.0\SQM' /v 'OptIn' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\17.0\SQM!OptIn"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\17.0\SQM'; $data =  '0'; reg add 'HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\17.0\SQM' /v 'OptIn' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable Visual Studio telemetry--------------
:: ----------------------------------------------------------
echo --- Disable Visual Studio telemetry
:: Set the registry value: "HKCU\Software\Microsoft\VisualStudio\Telemetry!TurnOffSwitch"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\Software\Microsoft\VisualStudio\Telemetry'; $data =  '1'; reg add 'HKCU\Software\Microsoft\VisualStudio\Telemetry' /v 'TurnOffSwitch' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable Visual Studio feedback--------------
:: ----------------------------------------------------------
echo --- Disable Visual Studio feedback
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback!DisableFeedbackDialog"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback'; $data =  '1'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback' /v 'DisableFeedbackDialog' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback!DisableEmailInput"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback'; $data =  '1'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback' /v 'DisableEmailInput' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback!DisableScreenshotCapture"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback'; $data =  '1'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback' /v 'DisableScreenshotCapture' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----Disable "Visual Studio Standard Collector Service"----
:: ----------------------------------------------------------
echo --- Disable "Visual Studio Standard Collector Service"
:: Disable service(s): `VSStandardCollectorService150`
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'VSStandardCollectorService150'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) { Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) { Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try { Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch { Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else { Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if (!$startupType) { $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) { $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if ($startupType -eq 'Disabled') { Write-Host "^""$serviceName is already disabled, no further action is needed"^""; Exit 0; }; <# -- 4. Disable service #>; try { Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch { Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Disable Diagnostics Hub log collection----------
:: ----------------------------------------------------------
echo --- Disable Diagnostics Hub log collection
:: Delete the registry value "LogLevel" from the key "HKLM\Software\Microsoft\VisualStudio\DiagnosticsHub" 
PowerShell -ExecutionPolicy Unrestricted -Command "$keyName = 'HKLM\Software\Microsoft\VisualStudio\DiagnosticsHub'; $valueName = 'LogLevel'; $hive = $keyName.Split('\')[0]; $path = "^""$($hive):$($keyName.Substring($hive.Length))"^""; Write-Host "^""Removing the registry value '$valueName' from '$path'."^""; if (-Not (Test-Path -LiteralPath $path)) { Write-Host 'Skipping, no action needed, registry key does not exist.'; Exit 0; }; $existingValueNames = (Get-ItemProperty -LiteralPath $path).PSObject.Properties.Name; if (-Not ($existingValueNames -Contains $valueName)) { Write-Host 'Skipping, no action needed, registry value does not exist.'; Exit 0; }; try { if ($valueName -ieq '(default)') { Write-Host 'Removing the default value.'; $(Get-Item -LiteralPath $path).OpenSubKey('', $true).DeleteValue(''); } else { Remove-ItemProperty -LiteralPath $path -Name $valueName -Force -ErrorAction Stop; }; Write-Host 'Successfully removed the registry value.'; } catch { Write-Error "^""Failed to remove the registry value: $($_.Exception.Message)"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---Disable participation in IntelliCode data collection---
:: ----------------------------------------------------------
echo --- Disable participation in IntelliCode data collection
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\IntelliCode!DisableRemoteAnalysis"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\IntelliCode'; $data =  '1'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\IntelliCode' /v 'DisableRemoteAnalysis' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKCU\SOFTWARE\Microsoft\VSCommon\16.0\IntelliCode!DisableRemoteAnalysis"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\SOFTWARE\Microsoft\VSCommon\16.0\IntelliCode'; $data =  '1'; reg add 'HKCU\SOFTWARE\Microsoft\VSCommon\16.0\IntelliCode' /v 'DisableRemoteAnalysis' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKCU\SOFTWARE\Microsoft\VSCommon\17.0\IntelliCode!DisableRemoteAnalysis"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\SOFTWARE\Microsoft\VSCommon\17.0\IntelliCode'; $data =  '1'; reg add 'HKCU\SOFTWARE\Microsoft\VSCommon\17.0\IntelliCode' /v 'DisableRemoteAnalysis' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: Pause the script to view the final state
:: pause
:: Restore previous environment settings
endlocal
:: Exit the script successfully
:: exit /b 0