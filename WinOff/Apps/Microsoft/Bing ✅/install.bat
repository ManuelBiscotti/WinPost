<# : batch portion
@echo off
fltmc >nul || (powershell "Start -Verb RunAs '%~f0'" & exit) & cd /D "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command "[scriptblock]::Create((Get-Content -LiteralPath '%~f0' -Raw)).Invoke()"
exit /b %ERRORLEVEL%
: end batch / begin powershell #>

# enable search indexing
Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows Search" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
Set-Service -Name WSearch -StartupType Automatic | Out-Null
Start-Service -Name WSearch | Out-Null

# enable web search
Remove-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableSearchBoxSuggestions" -ErrorAction SilentlyContinue | Out-Null

# install bing
$ProgressPreference = 'SilentlyContinue'
Get-AppXPackage -AllUsers *Microsoft.BingSearch* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}

# install WebView2
Start-Process ".\MicrosoftEdgeWebview2Setup.exe" -Wait

# restart explorer
Stop-Process -name explorer -force -ErrorAction SilentlyContinue | Out-Null
