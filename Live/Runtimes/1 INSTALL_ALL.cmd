<# : batch portion
@echo off
fltmc >nul || (powershell "Start -Verb RunAs '%~f0'" & exit) & cd /D "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "[scriptblock]::Create((Get-Content -LiteralPath '%~f0' -Raw -Encoding UTF8)).Invoke(@(&{$args}%*))"
: end batch / begin powershell #>

# Microsoft Edge WebView2 Runtime
Start-Process ".\Microsoft Edge WebView2 Runtime.bat" -NoNewWindow -Wait
Clear-Host
# Web Installer DirectX End-User Runtime
Start-Process ".\Web Installer DirectX End-User Runtime.bat" -NoNewWindow -Wait
Clear-Host
# Microsoft .NET Desktop Runtimes
Start-Process ".\Microsoft .NET Desktop Runtimes" -NoNewWindow -Wait
Clear-Host
Clear-Host
# Microsoft Visual C++ 2015–2022 Redistributable
Start-Process ".\Microsoft Visual C++ 2015–2022 Redistributable.bat" -NoNewWindow -Wait
Clear-Host

# LEGACY 

# Microsoft Visual C++ Redistributables
Start-Process ".\Legacy\Microsoft Visual C++ Redistributables.bat" -NoNewWindow -Wait
# Microsoft .NET Framework 3.5
Start-Process ".\Legacy\Microsoft .NET Framework 3.5" -NoNewWindow -Wait
Clear-Host
# Microsoft XNA Framework Redistributable 4.0
Start-Process ".\Legacy\Microsoft XNA Framework Redistributable 4.0" -NoNewWindow -Wait
Clear-Host
# NVIDIA PhysX System Software
# Start-Process ".\Legacy\NVIDIA PhysX System Software" -NoNewWindow -Wait
Clear-Host
# OpenAL
Start-Process ".\Legacy\OpenAL.bat" -NoNewWindow -Wait