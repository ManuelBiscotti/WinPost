<# : batch portion
@echo off & setlocal DisableDelayedExpansion
echo "%*"|find /i "-el">nul && set _elev=1
set _PSarg="""%~f0""" -el
setlocal EnableDelayedExpansion
>nul 2>&1 fltmc || (if not defined _elev powershell -NoProfile "start cmd.exe -arg '/c \"!_PSarg:'=''!\"' -verb runas" & exit /b)
set "PS1=powershell"
where pwsh.exe>nul 2>&1 && set "PS1=pwsh"
Color 0F
%PS1% -nop -c "Get-Content '%~f0' -Raw | iex"
goto :eof
: end batch / begin powershell #>

#Requires -RunAsAdministrator

$Host.UI.RawUI.WindowTitle = 'simplewall'
$ProgressPreference = 'SilentlyContinue'  
$ErrorActionPreference = 'SilentlyContinue'
Clear-Host

# install simplewall
$release = Invoke-RestMethod -Uri "https://api.github.com/repos/henrypp/simplewall/releases/latest" -Headers @{ "User-Agent" = "powershell" }
$asset = $release.assets | Where-Object { $_.name -like '*.exe' } | Select-Object -First 1
curl.exe -L $asset.browser_download_url -o "$env:TEMP\$($asset.name)"
Start-Process -FilePath "$env:TEMP\$($asset.name)" -ArgumentList "/S" -Wait
Clear-Host

if (Test-Path "$env:ProgramFiles\simplewall\simplewall.exe") {

    # start shortcut
    $WScriptShell = New-Object -ComObject WScript.Shell
    $startMenuPath = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\simplewall.lnk"
    $lnk = $WScriptShell.CreateShortcut($startMenuPath)
    $lnk.TargetPath = "C:\Program Files\simplewall\simplewall.exe"
    $lnk.WorkingDirectory = "C:\Program Files\simplewall"
    $lnk.IconLocation = "C:\Program Files\simplewall\simplewall.exe,0"
    $lnk.Save()

    # enable filters
    Start-Process -FilePath "$env:ProgramFiles\simplewall\simplewall.exe" -ArgumentList "-install -silent" -Wait

    # skip uac task
    $taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.6" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>simplewall</Author>
    <URI>\simplewallTask</URI>
  </RegistrationInfo>
  <Triggers/>
  <Principals>
    <Principal id="Author">
      <RunLevel>HighestAvailable</RunLevel>
      <UserId>$env:USERDOMAIN\$env:USERNAME</UserId>
      <LogonType>InteractiveToken</LogonType>
    </Principal>
  </Principals>
  <Settings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Program Files\simplewall\simplewall.exe</Command>
      <Arguments>$(Arg0) -minimized</Arguments>
      <WorkingDirectory>C:\Program Files\simplewall</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"@
	
    Set-Content -Path "$env:TEMP\simplewallTask.xml" -Encoding Unicode -Value $taskXml -Force
    schtasks.exe /Create /TN "simplewallTask" /XML "$env:TEMP\simplewallTask.xml" /F | Out-Null
}

Start-Process "$env:ProgramFiles\simplewall\simplewall.exe"
