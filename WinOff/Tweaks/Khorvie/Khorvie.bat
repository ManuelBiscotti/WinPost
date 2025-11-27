@Echo Off & Set "_F0=%~f0" & Title Uninstall Apps

PowerShell.exe -NoProfile -Command "Set-Content -LiteralPath $Env:Temp\_.ps1 -Value ([RegEx]::Matches([System.IO.File]::ReadAllText($Env:_F0), '(?smi)^(Pause|Exit)(.*)$').Groups[2].Value) -Encoding Unicode -Force"
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%Temp%\_.ps1"
exit

function Del-PS1 {Remove-Item -LiteralPath $Env:Temp\_.ps1 -Force}

if ((Get-Item -LiteralPath 'Registry::HKU\S-1-5-19' -ErrorAction SilentlyContinue)) {Del-PS1} Else {
    try {Start-Process -FilePath PowerShell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$Env:Temp\_.ps1`"" -Verb RunAs} Catch {Del-PS1}
    exit
}

# Khorvie Tech mmm pain v3
$batchCode = @"
@echo off

:: bcdedit
bcdedit /set bootux disabled
bcdedit /set tscsyncpolicy enhanced
bcdedit /set uselegacyapicmode No
echo All commands executed successfully.

goto :TSC

one user claimed issues with applying this setting that resulted in the need to restore via a separate usb

to ensure this works properly, check your bios for this setting and make sure it is set to on from within the bios, then it should be safe to apply this batch file; if you are too lazy to go into the bios, then skip this step

bcdedit /set x2apicpolicy Enable

:TSC

bcdedit /deletevalue useplatformclock
bcdedit /deletevalue useplatformtick

:: adjust appearance
REM Set the performance settings to Custom
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d 2 /f

REM Disable animations in the taskbar and window titles
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "TaskbarAnimations" /t REG_DWORD /d 0 /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "WindowAnimations" /t REG_DWORD /d 0 /f

REM Ensure thumbnails previews are enabled
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconsOnly" /t REG_DWORD /d 0 /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ThumbnailCacheSize" /t REG_DWORD /d 0 /f

REM Ensure smooth edges of screen fonts are enabled
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "FontSmoothing" /t REG_DWORD /d 1 /f

REM Disable desktop composition (Aero Glass)
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Desktop" /v "VisualFXSetting" /t REG_DWORD /d 2 /f

REM Disable fading and sliding menus
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "MenuAnimations" /t REG_DWORD /d 0 /f

echo Performance settings have been adjusted

:: timeout
Reg.exe add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "1000" /f

:: tcpip tweaks
netsh int tcp set global dca=enabled
netsh int tcp set global netdma=enabled
netsh interface isatap set state disabled
netsh int tcp set global timestamps=disabled


reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "30" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxConnectRetransmissions" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DelayedAckFrequency" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DelayedAckTicks" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MultihopSets" /t REG_DWORD /d "15" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "50" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "SizReqBuf" /t REG_DWORD /d "17424" /f
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\QoS" /v "Do not use NLA" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NegativeCacheTime" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NegativeSOACacheTime" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NetFailureCacheTime" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "EnableAutoDoh" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "NonBlockingSendSpecialBuffering" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v NetworkThrottlingIndex /t REG_DWORD /d 0xFFFFFFFF /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v NonBestEffortLimit /t REG_DWORD /d 0 /f >nul 2>&1

:: Disable Event Trace Sessions (ETS)
for %%X in (
    "NTFSLog"
    "WiFiDriverIHVSession"
    "WiFiDriverSession"
    "WiFiSession"
    "SleepStudyTraceSession"
    "1DSListener"
    "MpWppTracing"
    "NVIDIA-NVTOPPS-NoCat"
    "NVIDIA-NVTOPPS-Filter"
    "Circular Kernel Context Logger"
    "DiagLog"
    "LwtNetLog"
    "Microsoft-Windows-Rdp-Graphics-RdpIdd-Trace"
    "NetCore"
    "RadioMgr"
    "ReFSLog"
    "WdiContextLog"
    "ShadowPlay"

) do (
    logman stop %%X -ets
)

:: DWM Schedule MASTER VALUES
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v WindowedGsyncGeforceFlag /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v FrameRateMin /t REG_DWORD /d 0xFFFFFFFF /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v IgnoreDisplayChangeDuration /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v LingerInterval /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v LicenseInterval /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v RestrictedNvcplUIMode /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v DisableSpecificPopups /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v DisableExpirationPopups /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v EnableForceIgpuDgpuFromUI /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v HideXGpuTrayIcon /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v ShowTrayIcon /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v HideBalloonNotification /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v PerformanceState /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v Gc6State /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v FrameDisplayBaseNegOffsetNS /t REG_DWORD /d 0xFFE17B80 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v FrameDisplayResDivValue /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v IgnoreNodeLocked /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v IgnoreSP /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v DontAskAgain /t REG_DWORD /d 1 /f

:: Kernel New Kizzimo
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v KiClockTimerPerCpu /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v KiClockTimerHighLatency /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v KiClockTimerAlwaysOnPresent /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v ClockTimerPerCpu /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v ClockTimerHighLatency /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v ClockTimerAlwaysOnPresent /t REG_DWORD /d 1 /f

bcdedit /set disabledynamictick No

echo All commands executed successfully.
"@

$batPath = "$env:TEMP\KhorvieTweaks.bat"
Set-Content -Path $batPath -Value $batchCode -Encoding ASCII
Start-Process -FilePath $batPath -Wait
Remove-Item $batPath -Force -ErrorAction SilentlyContinue

clear-host
write-host "Press any key to continue . . ."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
exit