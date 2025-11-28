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
Color 0F
%PS1% -nop -c "Get-Content '%~f0' -Raw | iex"
goto :eof
: end batch / begin powershell #>

#Requires -RunAsAdministrator

$Host.UI.RawUI.WindowTitle = "Bloatware"
$Host.UI.RawUI.BackgroundColor = "Black"
$Host.PrivateData.ProgressBackgroundColor = "Black"
$Host.PrivateData.ProgressForegroundColor = "White"
Clear-Host
$ProgressPreference = 'SilentlyContinue'

function Get-FileFromWeb {
	param([string]$URL, [string]$File)
 	try{if(Get-Command curl.exe -ErrorAction SilentlyContinue){curl.exe -L $URL -o $File -s}
 	elseif((Get-Service BITS -ErrorAction SilentlyContinue).Status -eq 'Running'){
 	Start-BitsTransfer -Source $URL -Destination $File -ErrorAction Stop
 	}else{Invoke-WebRequest -Uri $URL -OutFile $File -UseBasicParsing -ErrorAction Stop}
	}catch{throw $_}
}

# FR33THY BLOATWARE SCRIPT
$scriptContent = (Invoke-WebRequest "https://raw.githubusercontent.com/FR33THYFR33THY/Ultimate-Windows-Optimization-Guide/main/6%20Windows/15%20Bloatware.ps1" -UseBasicParsing).Content   
# Remove media features - FIXED (keep the pipes!)
$scriptContent = $scriptContent -replace 'Remove-WindowsCapability -Online -Name "Media\.WindowsMediaPlayer~~~~0\.0\.12\.0" \| Out-Null', ''	
$scriptContent = $scriptContent -replace 'Dism /Online /NoRestart /Disable-Feature /FeatureName:MediaPlayback \| Out-Null', ''
# Remove the restart prompt from ALL options
$scriptContent = $scriptContent -replace 'Write-Host "Restart to apply \. \. \."\s*\$\w+ = \$Host\.UI\.RawUI\.ReadKey\("NoEcho,IncludeKeyDown"\)', '' 
# Remove the show-menu calls that cause looping
$scriptContent = $scriptContent -replace 'show-menu', ''
# Extract and run just the option 2 code
if ($scriptContent -match '2 \{\s*([\s\S]*?)\s*\}\s*3 \{') {
    $option2Code = $matches[1]
    # Run the extracted option 2 code
    Invoke-Expression $option2Code
} else {
    Write-Host "Failed run FR33THY Bloatware script" -ForegroundColor Red; Start-Sleep -Seconds 2
    # Win11Debloat
    Write-Output "Running Win11Debloat as fallback..."
    & ([scriptblock]::Create((Invoke-RestMethod "https://debloat.raphi.re/"))) -NoRestartExplorer -Silent -RunDefaults
}

# UWP APPS
# remove hevc, heif, paint, photos, notepad
Get-AppxPackage -allusers *Microsoft.HEVCVideoExtension* | Remove-AppxPackage -ErrorAction SilentlyContinue
Get-AppxPackage -allusers *Microsoft.HEIFImageExtension* | Remove-AppxPackage -ErrorAction SilentlyContinue
Get-AppxPackage -allusers *Microsoft.Paint* | Remove-AppxPackage -ErrorAction SilentlyContinue
Get-AppxPackage -allusers *Microsoft.Windows.Photos* | Remove-AppxPackage -ErrorAction SilentlyContinue
Get-AppxPackage -allusers *Microsoft.WindowsNotepad* | Remove-AppxPackage -ErrorAction SilentlyContinue # notepad
# reinstall winget
Get-AppXPackage -AllUsers *Microsoft.DesktopAppInstaller* | Foreach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
Get-AppXPackage -AllUsers *Microsoft.Winget* | Foreach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
# restore photo viewer
Write-Output "installing: Photo Viewer . . ."
'tif','tiff','bmp','dib','gif','jfif','jpe','jpeg','jpg','jxr','png','ico'|ForEach-Object {
	reg add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".${_}" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f >$null 2>&1
	reg add "HKCU\SOFTWARE\Classes\.${_}" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f >$null 2>&1
}

# RESTORE LEGACY NOTEPAD FOR WINDOWS 11
if ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild -ge 22000) { 
    # Create "Notepad" shortcut
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Notepad.lnk")
    $shortcut.TargetPath = "$env:SystemRoot\System32\notepad.exe"
    $shortcut.Save()
    # Restore "New Text Document" context menu
    $reg = "$env:TEMP\Restore_New_Text_Document.reg"
    Invoke-WebRequest "https://github.com/vishnusai-karumuri/Registry-Fixes/raw/master/Restore_New_Text_Document_context_menu_item.reg" -OutFile $reg
    & regedit.exe /s $reg; Start-Sleep -seconds 1
}

# MEDIA PLAYER
# rename Windows Media Player Legacy shortcut to Windows Media Player
Rename-Item "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Windows Media Player Legacy.lnk" "Windows Media Player.lnk" -ErrorAction SilentlyContinue
# imribiy
# This reg file automatically applies Media Player setup phase as you would like to complete, no document history, no data sharing.
Get-FileFromWeb "https://github.com/imribiy/useful-regs-bats/raw/refs/heads/main/MediaPlayer.reg" "$env:TEMP\MediaPlayer.reg"
Regedit.exe /S "$env:TEMP\MediaPlayer.reg"; Start-Sleep -seconds 1

<#
# WINDOWS AI
# run "Remove Windows AI" script
$aiScriptContent = Invoke-RestMethod "https://raw.githubusercontent.com/zoicware/RemoveWindowsAI/main/RemoveWindowsAi.ps1"
$aiScriptContent = $aiScriptContent -replace '^\s*exit\s*$', '' -replace '^\s*Exit\s*$', ''
& ([scriptblock]::Create($aiScriptContent)) -nonInteractive -backupMode -AllOptions
#>
# UPDATES
# uninstall update for windows 10 for x64-based systems (KB5001716)	
cmd /c "MsiExec.exe /X{B8D93870-98D1-4980-AFCA-E26563CDFB79} /qn >nul 2>&1"

# GAMEINPUT
# stop GameInputSvc service
Stop-Service -Name "GameInputSvc" -Force -ErrorAction SilentlyContinue
# disable GameInputSvc service
Set-Service -Name "GameInputSvc" -StartupType Disabled -ErrorAction SilentlyContinue
# uninstall microsoft gameinput
# Current: PowerShell fallback might not trigger if winget fails
# Better: Explicit check
if (Get-Command winget -ErrorAction SilentlyContinue) {
    winget uninstall --name "Microsoft GameInput" --silent --accept-source-agreements 2>&1 | Out-Null
} else {
    $gameInput = Get-Package -Name "*GameInput*" -ErrorAction SilentlyContinue
    if ($gameInput) { $gameInput | Uninstall-Package -Force | Out-Null }
}

# MICROSOFT TEXT INPUT APPLICATION
# kill Microsoft Text Input Application
cmd /c "taskkill /F /IM TextInputHost.exe >nul 2>&1"	
$d=Get-ChildItem "$env:SystemRoot\SystemApps" -Dir -Filter "MicrosoftWindows.Client.CBS_*"|Select-Object -First 1 -ExpandProperty FullName
if($d){
	$x=Join-Path $d "TextInputHost.exe"	
	if(Test-Path $x){cmd /c "takeown /f `"$x`" >nul 2>&1 & icacls `"$x`" /grant *S-1-3-4:F >nul 2>&1 & move /y `"$x`" `"$env:SystemRoot\TextInputHost.exe.bak`" >nul 2>&1"}	
}

# CLEANUP
# remove character map start shortcut
Remove-Item "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\System Tools\Character Map.lnk" -Force -ErrorAction SilentlyContinue | Out-Null
# delete internet explorer shortcuts
Remove-Item "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Accessories\Internet Explorer.lnk" -Force -ErrorAction SilentlyContinue
Remove-Item "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Internet Explorer.lnk" -Force -ErrorAction SilentlyContinue
Remove-Item "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Internet Explorer.lnk" -Force -ErrorAction SilentlyContinue
Remove-Item "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Internet Explorer.lnk" -Force -ErrorAction SilentlyContinue
# Start Menu Taskbar Clean
$scriptContent = (Invoke-WebRequest "https://github.com/FR33THYFR33THY/Ultimate-Windows-Optimization-Guide/raw/refs/heads/main/6%20Windows/1%20Start%20Menu%20Taskbar%20Clean.ps1" -UseBasicParsing).Content
$scriptContent = $scriptContent -replace 'Write-Host "Restart to apply \. \. \."\s*\$\w+ = \$Host\.UI\.RawUI\.ReadKey\("NoEcho,IncludeKeyDown"\)', '' 
$scriptContent = $scriptContent -replace 'exit', ''
$scriptContent = $scriptContent -replace 'show-menu', ''
if ($scriptContent -match '1 \{\s*([\s\S]*?)\s*\}\s*2 \{') {
    $option1Code = $matches[1]
    Invoke-Expression $option1Code
}
