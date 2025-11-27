<# : batch portion
@echo off
fltmc >nul || (powershell "Start -Verb RunAs '%~f0'" & exit) & cd /D "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command "[scriptblock]::Create((Get-Content -LiteralPath '%~f0' -Raw)).Invoke()"
exit /b %ERRORLEVEL%
: end batch / begin powershell #>

# Windows 10				
if ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild -le 19045) {					
				
	# Disable News and interests (Win 10)				
	New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds' -Force | Out-Null				
	Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds' -Name 'EnableFeeds' -Value 0 -Type DWord | Out-Null				
					
}				
	
# Windows 11				
elseif ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild -ge 22000) {				
				
	# Remove Widgets related apps				
	Get-AppxPackage -allusers *Microsoft.WidgetsPlatformRuntime* | Remove-AppxPackage				
	Get-AppxPackage -allusers *MicrosoftWindows.Client.WebExperience* | Remove-AppxPackage				
	Get-AppxPackage -allusers *Microsoft.StartExperiencesApp* | Remove-AppxPackage				
	# Disable Widgets				
	reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\NewsAndInterests\AllowNewsAndInterests" /v "value" /t REG_DWORD /d "0" /f | Out-Null				
	# remove windows widgets from taskbar regedit				
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Dsh" /v "AllowNewsAndInterests" /t REG_DWORD /d "0" /f | Out-Null				
					
} else { Write-Host $_.Exception.Message -ForegroundColor Red }				