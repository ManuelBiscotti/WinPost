<# : batch portion
@echo off
fltmc >nul || (powershell "Start -Verb RunAs '%~f0'" & exit) & cd /D "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command "[scriptblock]::Create((Get-Content -LiteralPath '%~f0' -Raw)).Invoke()"
exit /b %ERRORLEVEL%
: end batch / begin powershell #>

$ProgressPreference = 'SilentlyContinue'
# uninstall all uwp features			
# network drivers, media player & notepad left out					
Remove-WindowsCapability -Online -Name "App.StepsRecorder~~~~0.0.1.0" | Out-Null					
Remove-WindowsCapability -Online -Name "App.Support.QuickAssist~~~~0.0.1.0" | Out-Null					
Remove-WindowsCapability -Online -Name "Browser.InternetExplorer~~~~0.0.11.0" | Out-Null					
Remove-WindowsCapability -Online -Name "DirectX.Configuration.Database~~~~0.0.1.0" | Out-Null					
Remove-WindowsCapability -Online -Name "Hello.Face.18967~~~~0.0.1.0" | Out-Null					
Remove-WindowsCapability -Online -Name "Hello.Face.20134~~~~0.0.1.0" | Out-Null					
Remove-WindowsCapability -Online -Name "MathRecognizer~~~~0.0.1.0" | Out-Null					
# Remove-WindowsCapability -Online -Name "Media.WindowsMediaPlayer~~~~0.0.12.0" | Out-Null					
Remove-WindowsCapability -Online -Name "Microsoft.Wallpapers.Extended~~~~0.0.1.0" | Out-Null					
Remove-WindowsCapability -Online -Name "Microsoft.Windows.MSPaint~~~~0.0.1.0" | Out-Null					
# Remove-WindowsCapability -Online -Name "Microsoft.Windows.Notepad.System~~~~0.0.1.0" | Out-Null					
# Remove-WindowsCapability -Online -Name "Microsoft.Windows.Notepad~~~~0.0.1.0" | Out-Null					
Remove-WindowsCapability -Online -Name "Microsoft.Windows.PowerShell.ISE~~~~0.0.1.0" | Out-Null					
Remove-WindowsCapability -Online -Name "Microsoft.Windows.WordPad~~~~0.0.1.0" | Out-Null					
Remove-WindowsCapability -Online -Name "OneCoreUAP.OneSync~~~~0.0.1.0" | Out-Null					
Remove-WindowsCapability -Online -Name "OpenSSH.Client~~~~0.0.1.0" | Out-Null					
Remove-WindowsCapability -Online -Name "Print.Fax.Scan~~~~0.0.1.0" | Out-Null					
Remove-WindowsCapability -Online -Name "Print.Management.Console~~~~0.0.1.0" | Out-Null					
# breaks installer & uninstaller programs	
# Remove-WindowsCapability -Online -Name "VBSCRIPT~~~~" | Out-Null					
Remove-WindowsCapability -Online -Name "WMIC~~~~" | Out-Null					
# breaks uwp snippingtool w10					
# Remove-WindowsCapability -Online -Name "Windows.Client.ShellComponents~~~~0.0.1.0" | Out-Null					
Remove-WindowsCapability -Online -Name "Windows.Kernel.LA57~~~~0.0.1.0" | Out-Null