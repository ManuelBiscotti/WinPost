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

$Host.UI.RawUI.WindowTitle = "Bloatware"
$Host.UI.RawUI.BackgroundColor = "Black"
$Host.PrivateData.ProgressBackgroundColor = "Black"
$Host.PrivateData.ProgressForegroundColor = "White"
Clear-Host
Write-Host "Uninstalling Bloatware..."
$ProgressPreference = 'SilentlyContinue'
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
    Write-Host "Failed to extract option 2 code" -ForegroundColor Red
}
# delete internet explorer shortcuts
Remove-Item "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Accessories\Internet Explorer.lnk" -Force -ErrorAction SilentlyContinue
Remove-Item "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Internet Explorer.lnk" -Force -ErrorAction SilentlyContinue
Remove-Item "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Internet Explorer.lnk" -Force -ErrorAction SilentlyContinue
Remove-Item "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Internet Explorer.lnk" -Force -ErrorAction SilentlyContinue
# reinstall essential apps
Get-AppXPackage -AllUsers *Microsoft.DesktopAppInstaller* | Foreach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
Get-AppXPackage -AllUsers *Microsoft.Winget* | Foreach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
Get-AppxPackage -allusers *Microsoft.HEVCVideoExtension* | Remove-AppxPackage -ErrorAction SilentlyContinue
Get-AppxPackage -allusers *Microsoft.HEIFImageExtension* | Remove-AppxPackage -ErrorAction SilentlyContinue
Get-AppxPackage -allusers *Microsoft.Paint* | Remove-AppxPackage -ErrorAction SilentlyContinue
Get-AppxPackage -allusers *Microsoft.Windows.Photos* | Remove-AppxPackage -ErrorAction SilentlyContinue
# Get-AppxPackage -allusers *Microsoft.WindowsNotepad* | Remove-AppxPackage -ErrorAction SilentlyContinue # notepad
# restore photo viewer
Write-Output "installing: Photo Viewer . . ."
'tif','tiff','bmp','dib','gif','jfif','jpe','jpeg','jpg','jxr','png','ico'|ForEach-Object {
	reg add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".${_}" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f >$null 2>&1
	reg add "HKCU\SOFTWARE\Classes\.${_}" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f >$null 2>&1
}
<#
# install notepad w11
if ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild -ge 22000){
# create notepad start menu shortcut
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut("C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Notepad.lnk")
$shortcut.TargetPath = "$env:SystemRoot\System32\notepad.exe"
$shortcut.Save()
# restore new text document context menu item
$reg = "$env:TEMP\Restore_New_Text_Document_context_menu_item.reg"
Invoke-WebRequest -Uri "https://github.com/vishnusai-karumuri/Registry-Fixes/raw/refs/heads/master/Restore_New_Text_Document_context_menu_item.reg" -OutFile "$reg"
& regedit.exe /s $reg
}else{$null}
#>
# remove character map start shortcut
Remove-Item "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\System Tools\Character Map.lnk" -Force -ErrorAction SilentlyContinue | Out-Null	
# uninstall update for windows 10 for x64-based systems (KB5001716)	
cmd /c "MsiExec.exe /X{B8D93870-98D1-4980-AFCA-E26563CDFB79} /qn >nul 2>&1"
# uninstall microsoft gameinput
Start-Process "msiexec.exe" -ArgumentList "/x `"$((Get-ChildItem 'C:\Program Files\WindowsApps' -Recurse -Filter GameInputRedist.msi -ErrorAction SilentlyContinue | Select-Object -First 1).FullName)`" /quiet /norestart" -Wait
# disable GameInput service
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\GameInputSvc" /v Start /t REG_DWORD /d 4 /f | Out-Null		
# kill Microsoft Text Input Application
cmd /c "taskkill /F /IM TextInputHost.exe >nul 2>&1"	
$d=Get-ChildItem "$env:SystemRoot\SystemApps" -Dir -Filter "MicrosoftWindows.Client.CBS_*"|Select-Object -First 1 -ExpandProperty FullName
if($d){
	$x=Join-Path $d "TextInputHost.exe"	
	if(Test-Path $x){cmd /c "takeown /f `"$x`" >nul 2>&1 & icacls `"$x`" /grant *S-1-3-4:F >nul 2>&1 & move /y `"$x`" `"$env:SystemRoot\TextInputHost.exe.bak`" >nul 2>&1"}	
}

