<# : batch portion
@echo off
fltmc >nul || (powershell "Start -Verb RunAs '%~f0'" & exit) & cd /D "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command "[scriptblock]::Create((Get-Content -LiteralPath '%~f0' -Raw)).Invoke()"
exit /b %ERRORLEVEL%
: end batch / begin powershell #>

# Windows 10
if ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild -le 19045) {				
					
	# fix edge blocks				
	. ([ScriptBlock]::Create((Invoke-RestMethod 'https://github.com/ManuelBiscotti/test/raw/refs/heads/main/functions/Invoke-EdgeFix.ps1')))				
	Invoke-EdgeFix				
	# Install Edge				
	# enable edge updates regedit				
	cmd /c "reg delete `"HKLM\SOFTWARE\Microsoft\EdgeUpdate`" /f >nul 2>&1"				
	# download edge webview installer				
	Get-FileFromWeb -URL "https://msedge.sf.dl.delivery.mp.microsoft.com/filestreamingservice/files/304fddef-b073-4e0a-b1ff-c2ea02584017/MicrosoftEdgeWebview2Setup.exe" -File "$env:TEMP\EdgeWebView.exe"				
	Clear-Host				
	# start edge webview installer				
	Start-Process -wait "$env:TEMP\EdgeWebView.exe"					
	# download edge installer				
	Get-FileFromWeb -URL "https://go.microsoft.com/fwlink/?linkid=2109047&Channel=Stable&language=en&brand=M100" -File "$env:TEMP\Edge.exe"				
	Clear-Host				
	# start edge installer				
	Start-Process -wait "$env:TEMP\Edge.exe"				
	# install uwp edge				
	# Get-AppXPackage -AllUsers *Microsoft.MicrosoftEdge.Stable* | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}								
	# Re-enable News and interests				
	Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds' -Name 'EnableFeeds' -ErrorAction SilentlyContinue				
	Remove-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds' -ErrorAction SilentlyContinue				
				
}				
			
# Windows 11	
elseif ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild -ge 22000) {				
					
	# widgets regedit				
	reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\NewsAndInterests\AllowNewsAndInterests" /v "value" /t REG_DWORD /d "1" /f | Out-Null				
	# windows widgets from taskbar regedit				
	cmd /c "reg delete `"HKLM\SOFTWARE\Policies\Microsoft\Dsh`" /f >nul 2>&1"				
					
	# fix edge blocks    			
	. ([ScriptBlock]::Create((Invoke-RestMethod 'https://github.com/ManuelBiscotti/test/raw/refs/heads/main/functions/Invoke-EdgeFix.ps1')))				
	Invoke-EdgeFix				
	# download edge webview installer				
	Get-FileFromWeb -URL "https://msedge.sf.dl.delivery.mp.microsoft.com/filestreamingservice/files/304fddef-b073-4e0a-b1ff-c2ea02584017/MicrosoftEdgeWebview2Setup.exe" -File "$env:TEMP\EdgeWebView.exe"				
	Clear-Host				
	# start edge webview installer				
	Start-Process -wait "$env:TEMP\EdgeWebView.exe"				
				
	# Widgets Platform Runtime		
	Get-AppXPackage -AllUsers *Microsoft.WidgetsPlatformRuntime* | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}				
	# Windows Web Experience App				
	Get-AppXPackage -AllUsers *MicrosoftWindows.Client.WebExperience* | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}				
	# Start Experiences App				
	if (Get-Command winget -ErrorAction SilentlyContinue) {				
						
		winget.exe install --id "9PC1H9VN18CM" --exact --source msstore --accept-source-agreements --disable-interactivity --silent --accept-package-agreements --force				
					
	} else {				
				
		[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
		Invoke-Expression ((New-Object Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1')) | Out-Null    			
		choco.exe install winget -y --force --ignore-checksums --quiet | Out-Null    			
    			
		winget.exe install --id "9PC1H9VN18CM" --exact --source msstore --accept-source-agreements --disable-interactivity --silent --accept-package-agreements --force
				
	}
					
	# Update all Apps   		 		
	winget upgrade --all --accept-source-agreements --no-progress --accept-package-agreements | Out-Null				
	Clear-Host				
				
	# STORE
	Write-Host "Installing: Store. Please wait . . ."				
	# install store				
	Get-AppXPackage -AllUsers *Microsoft.WindowsStore* | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}				
	Get-AppXPackage -AllUsers *Microsoft.Microsoft.StorePurchaseApp * | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}				
				
	# Fix PUR-AuthenticationFailure	    
	# Enable Microsoft Account Sign-in Assistant				
	$batchCode = @'							
@echo off
:: https://privacy.sexy — v0.13.8 — Sun, 19 Oct 2025 08:43:23 GMT
:: Initialize environment
setlocal EnableExtensions DisableDelayedExpansion


:: Disable Microsoft Account Sign-in Assistant (breaks Microsoft Store and Microsoft Account sign-in) (revert)
echo --- Disable Microsoft Account Sign-in Assistant (breaks Microsoft Store and Microsoft Account sign-in) (revert)
:: Restore service(s) to default state: `wlidsvc`
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'wlidsvc'; $defaultStartupMode = 'Manual'; $ignoreMissingOnRevert =  $false; Write-Host "^""Reverting service `"^""$serviceName`"^"" start to `"^""$defaultStartupMode`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if (!$service) { if ($ignoreMissingOnRevert) { Write-Output "^""Skipping: The service `"^""$serviceName`"^"" is not found. No action required."^""; Exit 0; }; Write-Warning "^""Failed to revert changes to the service `"^""$serviceName`"^"". The service is not found."^""; Exit 1; }; <# -- 2. Enable or skip if already enabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if (!$startupType) { $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if (!$startupType) { $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if ($startupType -eq "^""$defaultStartupMode"^"") { Write-Host "^""`"^""$serviceName`"^"" has already expected startup mode: `"^""$defaultStartupMode`"^"". No action required."^""; } else { try { Set-Service -Name "^""$serviceName"^"" -StartupType "^""$defaultStartupMode"^"" -Confirm:$false -ErrorAction Stop; Write-Host "^""Reverted `"^""$serviceName`"^"" with `"^""$defaultStartupMode`"^"" start, this may require restarting your computer."^""; } catch { Write-Error "^""Failed to enable `"^""$serviceName`"^"": $_"^""; Exit 1; }; }; <# -- 4. Start if not running (must be enabled first) #>; if ($defaultStartupMode -eq 'Automatic' -or $defaultStartupMode -eq 'Boot' -or $defaultStartupMode -eq 'System') { if ($service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running) { Write-Host "^""`"^""$serviceName`"^"" is not running, starting it."^""; try { Start-Service $serviceName -ErrorAction Stop; Write-Host "^""Started `"^""$serviceName`"^"" successfully."^""; } catch { Write-Warning "^""Failed to start `"^""$serviceName`"^"", requires restart, it will be started after reboot.`r`n$_"^""; }; } else { Write-Host "^""`"^""$serviceName`"^"" is already running, no need to start."^""; }; }"
:: ----------------------------------------------------------


:: Restore previous environment settings
endlocal
exit
'@
	$batPath = "$env:TEMP\EnableMSAccountSignInAssistant.bat"
	Set-Content -Path $batPath -Value $batchCode -Encoding ASCII
	Start-Process -FilePath $batPath -WindowStyle Hidden -Wait
	    	
	try {
		
		# Downloads and Updates
		Start-Process "ms-windows-store://downloadsandupdates"
		
	} catch {
		
		# Install Store with a different method
    	Get-FileFromWeb -URL "https://github.com/ManuelBiscotti/test/raw/refs/heads/main/tools/MS_Store.msix" -File "$env:TEMP\MS_Store.msix"
    	Clear-Host
    	Start-Process "$env:TEMP\MS_Store.msix" -Wait
		
		# Downloads and Updates
		Start-Process "ms-windows-store://downloadsandupdates"
		
	}
										
}else{Write-Host $_.Exception.Message -ForegroundColor Red}

Clear-Host
Write-Host "Restart to apply . . ."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
exit