<# : batch portion
@echo off
setlocal DisableDelayedExpansion
echo "%*"|find /i "-el">nul && set _elev=1
set _PSarg="""%~f0""" -el
setlocal EnableDelayedExpansion
>nul 2>&1 fltmc || >nul 2>&1 net session || (
    if not defined _elev (
        powershell -NoProfile -Command "Start-Process cmd.exe -ArgumentList '/c', '!_PSarg!' -Verb RunAs" && exit /b 0
        exit /b 1
    )
)
where pwsh.exe>nul 2>&1 && set "PS1=pwsh" || set "PS1=powershell"
%PS1% -nop -c "Get-Content '%~f0' -Raw | iex"
Color 0F
goto :eof
: end batch / begin powershell #>

$Host.UI.RawUI.WindowTitle = "Microsoft Edge"
$Host.UI.RawUI.BackgroundColor = "Black"
$Host.PrivateData.ProgressBackgroundColor = "Black"
$Host.PrivateData.ProgressForegroundColor = "White"
Clear-Host

function Get-FileFromWeb {
	param([string]$URL, [string]$File)
 	try{if(Get-Command curl.exe -ErrorAction SilentlyContinue){curl.exe -L $URL -o $File -s}
 	elseif((Get-Service BITS -ErrorAction SilentlyContinue).Status -eq 'Running'){
 	Start-BitsTransfer -Source $URL -Destination $File -ErrorAction Stop
 	}else{Invoke-WebRequest -Uri $URL -OutFile $File -UseBasicParsing -ErrorAction Stop}
	}catch{throw $_}
}

function EdgeInstalled {
    $msedgeExe = "$([Environment]::GetFolderPath('ProgramFilesx86'))\Microsoft\Edge\Application\msedge.exe"
    Test-Path $msedgeExe
}

if (-not (EdgeInstalled)) {
	
	Write-Host "Installing Microsoft Edge..."
	# stop edge running
	$stop = "MicrosoftEdgeUpdate", "msedge"
	$stop | ForEach-Object { Stop-Process -Name $_ -Force -ErrorAction SilentlyContinue }
	
	<#
		.LINK
		https://privacy.sexy
	#>
	
	# Configure Edge
	$batchCode = @'
@echo off
:: https://privacy.sexy — v0.13.8 — Tue, 25 Nov 2025 23:03:59 GMT
:: Ensure PowerShell is available
where PowerShell >nul 2>&1 || (
    echo PowerShell is not available. Please install or enable PowerShell.
    pause & exit 1
)
:: Ensure admin privileges
echo "%*" | find /i "-el" >nul && set _elev=1
set _PSarg="""%~f0""" -el
setlocal EnableDelayedExpansion
>nul 2>&1 fltmc || (
    if not defined _elev powershell -NoProfile "start cmd.exe -arg '/c \"!_PSarg:'=''!\"' -verb runas" && exit /b
    echo.
    echo Right-click on the script and select "Run as administrator".
    pause & exit 1
)


:: ----------------------------------------------------------
:: ---------Disable Edge update executable (revert)----------
:: ----------------------------------------------------------
echo --- Disable Edge update executable (revert)
:: Remove configuration preventing "MicrosoftEdgeUpdate.exe" from starting
:: Delete the registry value "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MicrosoftEdgeUpdate.exe!Debugger"
PowerShell -ExecutionPolicy Unrestricted -Command "reg delete 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MicrosoftEdgeUpdate.exe' /v 'Debugger' /f 2>$null"
:: Remove the rule that prevents the executable "MicrosoftEdgeUpdate.exe" from running via File Explorer
PowerShell -ExecutionPolicy Unrestricted -Command "$executableFilename='MicrosoftEdgeUpdate.exe'; try { $blockEntries = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun' -ErrorAction Ignore; if (-Not $blockEntries) { Write-Output "^""Skipping, no action needed: No block rules exist, `"^""$executableFilename`"^"" is not blocked."^""; exit 0; }; $blockingRulesForExecutable = @(; $blockEntries.PSObject.Properties | Where-Object { $_.Value -eq $executableFilename }; ); if (-Not $blockingRulesForExecutable) { Write-Output "^""Skipping, no action needed: `"^""$executableFilename`"^"" is not currently blocked."^""; exit 0; }; foreach ($blockingRuleForExecutable in $blockingRulesForExecutable) { $blockingRuleIndexForExecutable = $blockingRuleForExecutable.Name; Write-Output "^""Removing rule `"^""$blockingRuleIndexForExecutable`"^"" that blocks `"^""$executableFilename`"^""."^""; Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun' -Name "^""$blockingRuleIndexForExecutable"^"" -Force -ErrorAction Stop; Write-Output "^""Successfully revoked blocking of `$executableFilename` under rule `"^""$blockingRuleIndexForExecutable`"^""."^""; }; } catch { Write-Error "^""Failed to revoke blocking of `"^""$executableFilename`"^"": $_"^""; Exit 1; }"
:: Restore the File Explorer DisallowRun policy if no other blocks are active
PowerShell -ExecutionPolicy Unrestricted -Command "try { $currentDisallowRunPolicyValue = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'DisallowRun' -ErrorAction Ignore | Select-Object -ExpandProperty 'DisallowRun'; if ([string]::IsNullOrEmpty($currentDisallowRunPolicyValue)) { Write-Output 'Skipping, no action needed: DisallowRun policy is not active.'; Exit 0; }; if ($currentDisallowRunPolicyValue -ne 1) { Write-Output "^""Skipping, DisallowRun policy is not configured by privacy.sexy, unexpected value: `"^""$currentDisallowRunPolicyValue`"^""."^""; Exit 0; }; $remainingBlockingRules = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun' -ErrorAction Ignore; if ($remainingBlockingRules) { Write-Output 'Skipping deactivating DisallowRun policy, there are still active rules.'; Exit 0; }; Write-Output 'No remaining rules, deleting DisallowRun policy.'; Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'DisallowRun' -Force -ErrorAction Stop; Write-Output 'Successfully restored DisallowRun policy.'; } catch { Write-Error "^""Failed to restore DisallowRun policy: $_"^""; Exit 1; }"
:: Restore files matching pattern: "%PROGRAMFILES(x86)%\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe" 
PowerShell -ExecutionPolicy Unrestricted -Command "$revert=$true; $p='%PROGRAMFILES(x86)%\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe.OLD'; $e=[Environment]::ExpandEnvironmentVariables($p); if(Test-Path $e){Move-Item $e ($e-replace'.OLD$','')-Force;'Restored'}else{'No files found'}"
:: Restore files matching pattern: "%PROGRAMFILES(x86)%\Microsoft\EdgeUpdate\*\MicrosoftEdgeUpdate.exe" 
PowerShell -ExecutionPolicy Unrestricted -Command "$revert=$true; $p='%PROGRAMFILES(x86)%\Microsoft\EdgeUpdate\*\MicrosoftEdgeUpdate.exe.OLD'; $e=[Environment]::ExpandEnvironmentVariables($p); Get-Item $e -ErrorAction 0|%%{Move-Item $_.FullName ($_.FullName-replace'.OLD$','')-Force;'Restored '+$_.Name}"
:: ----------------------------------------------------------


:: Disable Edge automatic updates across all channels (revert)
echo --- Disable Edge automatic updates across all channels (revert)
:: Delete the registry value "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate!UpdateDefault"
PowerShell -ExecutionPolicy Unrestricted -Command "reg delete 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate' /v 'UpdateDefault' /f 2>$null"
:: Delete the registry value "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate!Update{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}"
PowerShell -ExecutionPolicy Unrestricted -Command "reg delete 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate' /v 'Update{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}' /f 2>$null"
:: Delete the registry value "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate!Update{2CD8A007-E189-409D-A2C8-9AF4EF3C72AA}"
PowerShell -ExecutionPolicy Unrestricted -Command "reg delete 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate' /v 'Update{2CD8A007-E189-409D-A2C8-9AF4EF3C72AA}' /f 2>$null"
:: Delete the registry value "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate!Update{65C35B14-6C1D-4122-AC46-7148CC9D6497}"
PowerShell -ExecutionPolicy Unrestricted -Command "reg delete 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate' /v 'Update{65C35B14-6C1D-4122-AC46-7148CC9D6497}' /f 2>$null"
:: Delete the registry value "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate!Update{0D50BFEC-CD6A-4F9A-964C-C7416E3ACB10}"
PowerShell -ExecutionPolicy Unrestricted -Command "reg delete 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate' /v 'Update{0D50BFEC-CD6A-4F9A-964C-C7416E3ACB10}' /f 2>$null"
:: Delete the registry value "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate!Update{F3C4FE00-EFD5-403B-9569-398A20F1BA4A}"
PowerShell -ExecutionPolicy Unrestricted -Command "reg delete 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate' /v 'Update{F3C4FE00-EFD5-403B-9569-398A20F1BA4A}' /f 2>$null"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----Disable Edge WebView and WebView2 updates (revert)----
:: ----------------------------------------------------------
echo --- Disable Edge WebView and WebView2 updates (revert)
:: Delete the registry value "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate!Update{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
PowerShell -ExecutionPolicy Unrestricted -Command "reg delete 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate' /v 'Update{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}' /f 2>$null"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----Disable automatic installation of Edge (revert)------
:: ----------------------------------------------------------
echo --- Disable automatic installation of Edge (revert)
:: Delete the registry value "HKLM\SOFTWARE\Microsoft\EdgeUpdate!DoNotUpdateToEdgeWithChromium"
PowerShell -ExecutionPolicy Unrestricted -Command "reg delete 'HKLM\SOFTWARE\Microsoft\EdgeUpdate' /v 'DoNotUpdateToEdgeWithChromium' /f 2>$null"
:: ----------------------------------------------------------


:: Disable automatic installation of Edge across all channels (revert)
echo --- Disable automatic installation of Edge across all channels (revert)
:: Delete the registry value "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate!InstallDefault"
PowerShell -ExecutionPolicy Unrestricted -Command "reg delete 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate' /v 'InstallDefault' /f 2>$null"
:: Delete the registry value "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate!Install{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}"
PowerShell -ExecutionPolicy Unrestricted -Command "reg delete 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate' /v 'Install{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}' /f 2>$null"
:: Delete the registry value "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate!Install{2CD8A007-E189-409D-A2C8-9AF4EF3C72AA}"
PowerShell -ExecutionPolicy Unrestricted -Command "reg delete 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate' /v 'Install{2CD8A007-E189-409D-A2C8-9AF4EF3C72AA}' /f 2>$null"
:: Delete the registry value "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate!Install{65C35B14-6C1D-4122-AC46-7148CC9D6497}"
PowerShell -ExecutionPolicy Unrestricted -Command "reg delete 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate' /v 'Install{65C35B14-6C1D-4122-AC46-7148CC9D6497}' /f 2>$null"
:: Delete the registry value "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate!Install{0D50BFEC-CD6A-4F9A-964C-C7416E3ACB10}"
PowerShell -ExecutionPolicy Unrestricted -Command "reg delete 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate' /v 'Install{0D50BFEC-CD6A-4F9A-964C-C7416E3ACB10}' /f 2>$null"
:: ----------------------------------------------------------


:: Disable automatic installation of WebView and WebView2 (revert)
echo --- Disable automatic installation of WebView and WebView2 (revert)
:: Delete the registry value "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate!Install{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
PowerShell -ExecutionPolicy Unrestricted -Command "reg delete 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate' /v 'Install{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}' /f 2>$null"
:: ----------------------------------------------------------


:: Restore previous environment settings
endlocal
:: Exit the script successfully
exit /b 0
'@
	
	$batPath = "$env:TEMP\Configure Edge.bat"
	Set-Content -Path $batPath -Value $batchCode -Encoding ASCII
	Start-Process -FilePath $batPath -Wait -WindowStyle Hidden
	# Start-Process -FilePath $batPath -Wait -NoNewWindow *>$null
	
	<#
		.LINK
		https://github.com/he3als/EdgeRemover
	#>
	
	# Clear Edge Blocks
	try {
		Invoke-Expression "&{$(Invoke-RestMethod https://cdn.jsdelivr.net/gh/he3als/EdgeRemover@main/get.ps1)} -ClearUpdateBlocks -Silent"
	} catch {
	    Write-Host "$($_.Exception.Message)" -ForegroundColor Red
	    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
	    exit 1
	}
	
	# EDGE
	try {
		
		# download edge installer
		Get-FileFromWeb "http://go.microsoft.com/fwlink/?LinkID=2093437" "$env:TEMP\MicrosoftEdgeEnterpriseX64.msi"
		# start edge installer
		Start-Process msiexec.exe -ArgumentList "/i `"$env:TEMP\MicrosoftEdgeEnterpriseX64.msi`" /qb /norestart" -Wait -ErrorAction Stop
		
	} catch {
		try {
			
			# download edge installer
			Get-FileFromWeb "https://go.microsoft.com/fwlink/?linkid=2109047&Channel=Stable&language=en&brand=M100" "$env:TEMP\MicrosoftEdgeSetup.exe"		    
			# start edge installer
			Start-Process -Wait "$env:TEMP\MicrosoftEdge4Setup.exe" -ErrorAction Stop
		    
			# stop edge running
			$stop = "MicrosoftEdgeUpdate", "OneDrive", "WidgetService", "Widgets", "msedge", "Resume", "CrossDeviceResume", "msedgewebview2"		    
			$stop | ForEach-Object { Stop-Process -Name $_ -Force -ErrorAction SilentlyContinue }
			
			# add edge shortcuts
			$WshShell = New-Object -comObject WScript.Shell
			$Shortcut = $WshShell.CreateShortcut("$env:SystemDrive\Windows\System32\config\systemprofile\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\Microsoft Edge.lnk")
			$Shortcut.TargetPath = "$env:SystemDrive\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
			$Shortcut.Save()
			$WshShell = New-Object -comObject WScript.Shell
			$Shortcut = $WshShell.CreateShortcut("$env:USERPROFILE\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\Microsoft Edge.lnk")
			$Shortcut.TargetPath = "$env:SystemDrive\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
			$Shortcut.Save()
			$WshShell = New-Object -comObject WScript.Shell
			$Shortcut = $WshShell.CreateShortcut("$env:USERPROFILE\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Microsoft Edge.lnk")
			$Shortcut.TargetPath = "$env:SystemDrive\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
			$Shortcut.Save()
			$WshShell = New-Object -comObject WScript.Shell
			$Shortcut = $WshShell.CreateShortcut("$env:USERPROFILE\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Tombstones\Microsoft Edge.lnk")
			$Shortcut.TargetPath = "$env:SystemDrive\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
			$Shortcut.Save()
			$WshShell = New-Object -comObject WScript.Shell
			$Shortcut = $WshShell.CreateShortcut("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk")
			$Shortcut.TargetPath = "$env:SystemDrive\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
			$Shortcut.Save()
			$WshShell = New-Object -comObject WScript.Shell
			$Shortcut = $WshShell.CreateShortcut("$env:SystemDrive\Users\Public\Desktop\Microsoft Edge.lnk")
			$Shortcut.TargetPath = "$env:SystemDrive\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
			$Shortcut.Save()
			
		} catch {
			
	    	Write-Host "$($_.Exception.Message)" -ForegroundColor Red
	    	$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
	    	exit 1
			
		}
	}
	
} else { Write-Host "Microsoft Edge is already installed." -ForegroundColor Green }

Write-Host "Debloating Microsoft Edge..."
# DEBLOAT EDGE
# Win11Debloat
& ([scriptblock]::Create((Invoke-RestMethod "https://debloat.raphi.re/"))) -Silent -DisableEdgeAds -DisableEdgeAI	*>$null
# download microsoft-edge-debloater
Get-FileFromWeb "https://github.com/bibicadotnet/microsoft-edge-debloater/archive/refs/heads/main.zip" "$env:TEMP\main.zip"
Expand-Archive "$env:TEMP\main.zip" -DestinationPath "$env:TEMP" -Force
# download edge-debloat
Get-FileFromWeb "https://github.com/marlock9/edge-debloat/raw/refs/heads/main/edge-debloat.reg" "$env:TEMP\edge-debloat.reg"
# download msedge-debloat
Get-FileFromWeb "https://gist.github.com/yashgorana/83a2939d739e312820f39703fe991412/raw/f93921f5887b3c7f443bfac35b573e0dc085ad03/msedge-debloat.reg" "$env:TEMP\msedge-debloat.reg"
# import reg files
Regedit.exe /S "$env:TEMP\microsoft-edge-debloater-main\vi.edge.reg"		
Start-Sleep -Seconds 2
Regedit.exe /S "$env:TEMP\msedge-debloat.reg"	
Start-Sleep -Seconds 2
Regedit.exe /S "$env:TEMP\edge-debloat.reg"		
Start-Sleep -Seconds 1
# remove extensions
Remove-Item -Path "HKLM:\Software\Policies\Microsoft\Edge\ExtensionInstallForcelist" -Recurse -Force -ErrorAction SilentlyContinue
# create reg file
$MultilineComment = @'
Windows Registry Editor Version 5.00

; Force install uBlock origin and webrtc control extensions
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist]
"1"="odfafepnkmbhccpbejgmiehpchacaeak;https://edge.microsoft.com/extensionwebstorebase/v1/crx" ; ublock origin
; "2"="eepeadgljpkkjpbfecfkijnnliikglpl;https://edge.microsoft.com/extensionwebstorebase/v1/crx" ; webrtc control

; Set Brave as default search engine
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge]
"DefaultSearchProviderEnabled"=dword:00000001
"DefaultSearchProviderName"="Brave"
"DefaultSearchProviderSearchURL"="https://search.brave.com/search?q={searchTerms}"
"DefaultSearchProviderSuggestURL"="https://search.brave.com/api/suggest?q={searchTerms}"

; Set Blank New Tab
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments\FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF] 
"EnrollmentState"=dword:00000001 
"EnrollmentType"=dword:00000000 
"IsFederated"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF]
"Flags"=dword:00d6fb7f
"AcctUId"="0x000000000000000000000000000000000000000000000000000000000000000000000000"
"RoamingCount"=dword:00000000
"SslClientCertReference"="MY;User;0000000000000000000000000000000000000000"
"ProtoVer"="1.2"

; Black new tab page (pure dark)
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge]
"NewTabPageLocation"="data:text/html,<html><head><title>New tab</title><meta name='color-scheme' content='dark'><style>html,body{margin:0;background:#000;height:100%;}</style></head><body></body></html>"

; Toolbar fixes
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge]
"FavoritesBarEnabled"=- ; enable "Favorites bar"
"WebCaptureEnabled"=dword:00000001 ; Enable "Screenshots"
"DownloadRestrictions"=- ; restore download restrictions
"ShowDownloadsToolbarButton"=dword:00000000 ; unpin "Downloads"
"SplitScreenEnabled"=dword:00000001; enable "Split screen"

; remove logon edge
[-HKEY_LOCAL_MACHINE\Software\Microsoft\Active Setup\Installed Components\{9459C573-B17A-45AE-9F64-1857B5D58CEE}]

; edge services manual startup
[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\MicrosoftEdgeElevationService]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\edgeupdate]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\edgeupdatem]
"Start"=dword:00000003

; block desktop shortcut for all edge channels
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\EdgeUpdate]
"CreateDesktopShortcutDefault"=dword:00000000

; enable edge updates
[HKEY_CURRENT_USER\Software\Policies\Microsoft\EdgeUpdate]
"UpdateDefault"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\EdgeUpdate]
"UpdateDefault"=dword:00000001

; disable auto-updates for all users
; prevent edge from staying up-to-date automatically
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\EdgeUpdate]
"AutoUpdateCheckPeriodMinutes"=dword:00000000

; unblock all update channels
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\EdgeUpdate]
"Update{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}"=dword:00000001
"Update{2CD8A007-E189-4D47-B5A4-DD5A7A6D2766}"=dword:00000001
"Update{65C35B14-6C1D-4122-AC46-7148CC9D6497}"=dword:00000001

; disable Edge as default PDF viewer
[HKEY_CLASSES_ROOT\.pdf]
@="AcroExch.Document.DC"

[HKEY_CLASSES_ROOT\.pdf\OpenWithProgids]
"AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723"=-

; edge telemetry
[-HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run]
[-HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker]

[HKEY_CURRENT_USER\Software\Policies\Microsoft\MicrosoftEdge\BooksLibrary]
"EnableExtendedBooksTelemetry"=dword:00000000

[HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\MicrosoftEdge\BooksLibrary]
"EnableExtendedBooksTelemetry"=dword:00000000

; dont send edge data
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection]
"MicrosoftEdgeDataOptIn"=dword:00000000

; edge preload
[HKEY_CURRENT_USER\Software\Policies\Microsoft\MicrosoftEdge\TabPreloader]
"AllowTabPreloading"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader]
"AllowTabPreloading"=dword:00000000

; disable smartscreen in edge
[HKEY_CURRENT_USER\Software\Microsoft\Edge\SmartScreenEnabled]
"(Default)"="0"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Edge\SmartScreenEnabled]
@=dword:00000000

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Edge\SmartScreenPuaEnabled]
@=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter]
"EnabledV9"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\MicrosoftEdge\PhishingFilter]
"EnabledV9"=dword:00000000
'@

# import reg file	            
Set-Content -Path "$env:TEMP\Edge.reg" -Value $MultilineComment -Force -Encoding ASCII
# import reg file           
Regedit.exe /S "$env:TEMP\Edge.reg"
Start-Sleep -Seconds 1
# disable edge tasks
Get-ScheduledTask | Where-Object { $_.TaskName -like "*Edge*" } | ForEach-Object { Disable-ScheduledTask -TaskName $_.TaskName | Out-Null }

