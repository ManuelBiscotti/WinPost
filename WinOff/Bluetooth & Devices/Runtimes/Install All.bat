<# : batch portion
@echo off
fltmc >nul || (powershell "Start -Verb RunAs '%~f0'" & exit) & cd /D "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "[scriptblock]::Create((Get-Content -LiteralPath '%~f0' -Raw -Encoding UTF8)).Invoke(@(&{$args}%*))"
: end batch / begin powershell #>

# Microsoft .NET Desktop Runtimes
Write-Host "Microsoft .NET Desktop Runtimes"
Start-Process ".\Microsoft .NET Desktop Runtimes\windowsdesktop-runtime-5.0.17-win-x64.exe" -ArgumentList "/install /quiet /norestart" -Wait
Start-Process ".\Microsoft .NET Desktop Runtimes\windowsdesktop-runtime-6.0.36-win-x64.exe" -ArgumentList "/install /quiet /norestart" -Wait
Start-Process ".\Microsoft .NET Desktop Runtimes\windowsdesktop-runtime-7.0.20-win-x64.exe" -ArgumentList "/install /quiet /norestart" -Wait
Start-Process ".\Microsoft .NET Desktop Runtimes\windowsdesktop-runtime-8.0.21-win-x64.exe" -ArgumentList "/install /quiet /norestart" -Wait
Start-Process ".\Microsoft .NET Desktop Runtimes\windowsdesktop-runtime-9.0.10-win-x64.exe" -ArgumentList "/install /quiet /norestart" -Wait

# Microsoft DirectX End-User Runtimes (June 2010)
Write-Host "Microsoft DirectX End-User Runtimes (June 2010)"
Start-Process ".\Microsoft DirectX End-User Runtimes (June 2010)\directx_Jun2010_redist\DXSETUP.exe" -ArgumentList "/silent" -Wait
regedit /s ".\Microsoft DirectX End-User Runtimes (June 2010)\DirectX Tweaks\D3D11 - D3D12 Tweaks.reg"
regedit /s ".\Microsoft DirectX End-User Runtimes (June 2010)\DirectX Tweaks\DirectX Driver DXGKrnl Advanced Tweaks (2).reg"
Start-Process ".\Microsoft DirectX End-User Runtimes (June 2010)\Remove DirectX Configuration Database capability\Remove DirectX Configuration Database capability.bat" -NoNewWindow -Wait *>$null
Start-Process ".\Microsoft DirectX End-User Runtimes (June 2010)\Clear DirectX recent application history.bat" -NoNewWindow -Wait *>$null

# Microsoft Edge WebView2 Runtime
Write-Host "Microsoft Edge WebView2 Runtime"
Start-Process ".\Microsoft Edge WebView2 Runtime\MicrosoftEdgeWebView2RuntimeInstallerX64.exe" -Wait
Start-Process ".\Microsoft Edge WebView2 Runtime\Disable Edge WebView and WebView2 updates\Disable Edge WebView and WebView2 updates.bat" -NoNewWindow -Wait *>$null
Start-Process ".\Microsoft Edge WebView2 Runtime\Remove Win32 Web View Host  Desktop App Web Viewer app\Remove Win32 Web View Host  Desktop App Web Viewer app.bat" -NoNewWindow -Wait *>$null

# Microsoft Visual C++ 2015–2022 Redistributable
Write-Host "Microsoft Visual C++ 2015–2022 Redistributable"
Start-Process ".\Microsoft Visual C++ 2015–2022 Redistributable\VC_redist.x86.exe" -ArgumentList "/passive /norestart" -Wait
Start-Process ".\Microsoft Visual C++ 2015–2022 Redistributable\VC_redist.x64.exe" -ArgumentList "/passive /norestart" -Wait
Start-Process ".\Microsoft Visual C++ 2015–2022 Redistributable\Disable Visual Studio data collection\Disable Visual Studio data collection.bat" -NoNewWindow -Wait *>$null
Start-Process ".\Microsoft Visual C++ 2015–2022 Redistributable\Clear Visual Studio usage data.bat" -NoNewWindow -Wait *>$null

# LEGACY

# Microsoft Visual C++ Redistributables
Write-Host "Microsoft Visual C++ Redistributables"
Start-Process ".\Legacy\Microsoft Visual C++ Redistributables\vcredist2005_x86.exe" -ArgumentList "/q" -Wait
Start-Process ".\Legacy\Microsoft Visual C++ Redistributables\vcredist2005_x64.exe" -ArgumentList "/q" -Wait
Start-Process ".\Legacy\Microsoft Visual C++ Redistributables\vcredist2008_x86.exe" -ArgumentList "/qb" -Wait
Start-Process ".\Legacy\Microsoft Visual C++ Redistributables\vcredist2008_x64.exe" -ArgumentList "/qb" -Wait
Start-Process ".\Legacy\Microsoft Visual C++ Redistributables\vcredist2010_x86.exe" -ArgumentList "/passive /norestart" -Wait
Start-Process ".\Legacy\Microsoft Visual C++ Redistributables\vcredist2010_x64.exe" -ArgumentList "/passive /norestart" -Wait
Start-Process ".\Legacy\Microsoft Visual C++ Redistributables\vcredist2012_x86.exe" -ArgumentList "/passive /norestart" -Wait
Start-Process ".\Legacy\Microsoft Visual C++ Redistributables\vcredist2012_x64.exe" -ArgumentList "/passive /norestart" -Wait
Start-Process ".\Legacy\Microsoft Visual C++ Redistributables\vcredist2013_x86.exe" -ArgumentList "/passive /norestart" -Wait
Start-Process ".\Legacy\Microsoft Visual C++ Redistributables\vcredist2013_x64.exe" -ArgumentList "/passive /norestart" -Wait

# Java Runtime Environment
# Write-Host "Java Runtime Environment (JRE 8 Update 471)"
# Start-Process ".\Legacy\Java Runtime Environment\jre-8u471-windows-x64.exe" -ArgumentList "/s","REBOOT=Suppress","AUTO_UPDATE=0" -Wait

# Microsoft .NET Framework 3.5
Write-Host "Microsoft .NET Framework 3.5"
$build = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild
# Windows 10
if ($build -le 19045) {Start-Process ".\Legacy\Microsoft .NET Framework 3.5\dotNetFx35_WX_9_x86_x64.exe" -ArgumentList "/ais /gm2" -Wait }
# Windows 11
elseif ($build -ge 22000) { Start-Process ".\Legacy\Microsoft .NET Framework 3.5\dotNet2035_W11.exe" -ArgumentList "/ais /gm2" -Wait }

Write-Host "Microsoft XNA Framework Redistributable 4.0"
Start-Process ".\Legacy\Microsoft XNA Framework Redistributable 4.0\xnafx40_redist.msi" -ArgumentList "/qn /norestart" -Wait

# Write-Host "NVIDIA PhysX System Software"
# Start-Process ".\Legacy\NVIDIA PhysX System Software\PhysX_9.23.1019_SystemSoftware.exe" -ArgumentList "/s /noreboot" -Wait

Write-Host "OpenAL"
Start-Process ".\Legacy\OpenAL\oalinst.exe" -ArgumentList "/silent" -Wait




