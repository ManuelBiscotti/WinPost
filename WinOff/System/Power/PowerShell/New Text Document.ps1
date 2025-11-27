    If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator"))
    {Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit}
    $Host.UI.RawUI.WindowTitle = $myInvocation.MyCommand.Definition + " (Administrator)"
    $Host.UI.RawUI.BackgroundColor = "Black"
	$Host.PrivateData.ProgressBackgroundColor = "Black"
    $Host.PrivateData.ProgressForegroundColor = "White"
    Clear-Host

function Get-FileFromWeb {
    param($URL, $File)
    $resp = [System.Net.HttpWebRequest]::Create($URL).GetResponse()
    if ($resp.StatusCode -in 401, 403, 404) { return }
    if (!(Split-Path $File)) { $File = Join-Path (Get-Location) $File }
    $dir = [System.IO.Path]::GetDirectoryName($File)
    if (!(Test-Path $dir)) { [void][System.IO.Directory]::CreateDirectory($dir) }
    $buf = [byte[]]::new(1MB)
    $r = $resp.GetResponseStream()
    $w = [System.IO.File]::Open($File, 'Create')
    while (($cnt = $r.Read($buf, 0, $buf.Length)) -gt 0) { $w.Write($buf, 0, $cnt) }
    $r.Close(); $w.Close(); $resp.Close()
}


$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'SilentlyContinue'

# ----------Pause Windows updates until 7/11/3000-----------
Write-Host "--- Pausing Windows updates until 7/11/3000"
$pauseExpiry="3000-07-11T12:00:00Z"; $pauseStart=(Get-Date).ToString("yyyy-MM-ddT00:00:00Z")
$updateKeys=@("PauseUpdatesExpiryTime",$pauseExpiry),("PauseUpdatesStartTime",$pauseStart),("PauseFeatureUpdatesStartTime",$pauseStart),("PauseFeatureUpdatesEndTime",$pauseExpiry),("PauseQualityUpdatesStartTime",$pauseStart),("PauseQualityUpdatesEndTime",$pauseExpiry)
$path="HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"; if(!(Test-Path $path)){New-Item $path -Force|Out-Null}; $updateKeys|%{Set-ItemProperty -Path $path -Name $_[0] -Value $_[1] -Type String}  ; Start-Sleep -Seconds 3


# -----------------Remove Windows apps----------------------
#Write-Host "--- Removing Windows apps"
#Get-AppXPackage -AllUsers | Where-Object { $_.Name -notlike '*NVIDIA*' -and $_.Name -notlike '*CBS*' } | Remove-AppxPackage




$f = "$env:TEMP\StartAllBack_setup.exe"
Get-FileFromWeb "https://www.startallback.com/files/StartAllBackSetup.exe" $f
Start-Process $f -ArgumentList "/elevated /silent" -Wait
Remove-Item $f -Force


pause