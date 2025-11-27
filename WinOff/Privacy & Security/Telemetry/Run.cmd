<# : batch portion
@echo off
fltmc >nul || (powershell "Start -Verb RunAs '%~f0'" & exit) & cd /D "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "[scriptblock]::Create((Get-Content -LiteralPath '%~f0' -Raw -Encoding UTF8)).Invoke(@(&{$args}%*))"
: end batch / begin powershell #>

# privacy.sexy
Start-Process ".\privacy.sexy\privacy-script.bat" -NoNewWindow -Wait
Clear-Host

# WPD
netsh advfirewall set allprofiles state off | Out-Null	
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v "Enabled" /t REG_DWORD /d 0 /f > $null 2>&1
Start-Process ".\WPD\WPD.exe" -ArgumentList "-wfpOnly","-wfp on","-recommended","-close" -Wait 

# O&O ShutUp10++   
Start-Process ".\O&O ShutUp10++\OOSU10.exe" -ArgumentList "ooshutup10.cfg","/quiet" -WorkingDirectory ".\O&O ShutUp10++" -Wait

# Chris Titus Tech's Windows Utility
$config = ".\Chris Titus Tech's Windows Utility\tweaks.json"	
$ps1 = ".\Chris Titus Tech's Windows Utility\winutil.ps1"	
# Use Start-Process with redirected output	
$psi = New-Object System.Diagnostics.ProcessStartInfo	
$psi.FileName = "powershell.exe"	
$psi.Arguments = "-NoProfile -Sta -ExecutionPolicy Bypass -File `"$ps1`" -Config `"$config`" -Run"	
$psi.RedirectStandardOutput = $true	
$psi.RedirectStandardError  = $true	
$psi.UseShellExecute = $false	
$psi.CreateNoWindow = $true	
$p = New-Object System.Diagnostics.Process	
$p.StartInfo = $psi	
$p.Start() | Out-Null	
$reader = $p.StandardOutput	
while (-not $p.HasExited) {	
    $line = $reader.ReadLine()	
    if ($null -ne $line) {	
        Write-Host $line	
        if ($line -match "Tweaks are Finished") {	
            $p.Kill()	
            break	
        }	
    } else {	
    }	
}
Clear-Host

# Win11Debloat
regedit /s ".\Win11Debloat\Disable_Bing_Cortana_In_Search.reg"
regedit /s ".\Win11Debloat\Disable_Chat_Taskbar.reg"
regedit /s ".\Win11Debloat\Disable_Click_to_Do.reg"
regedit /s ".\Win11Debloat\Disable_Desktop_Spotlight.reg"
regedit /s ".\Win11Debloat\Disable_Edge_Ads_And_Suggestions.reg"
regedit /s ".\Win11Debloat\Disable_Lockscreen_Tips.reg"
regedit /s ".\Win11Debloat\Disable_Modern_Standby_Networking.reg"
regedit /s ".\Win11Debloat\Disable_Settings_365_Ads.reg"
regedit /s ".\Win11Debloat\Disable_Start_Recommended.reg"
regedit /s ".\Win11Debloat\Disable_Telemetry.reg"
regedit /s ".\Win11Debloat\Disable_Windows_Suggestions.reg"

# simplewall
Start-Process ".\simplewall\simplewall-3.8.7-setup.exe" -ArgumentList '/S' -Wait
Start-Process "$env:ProgramFiles\simplewall\simplewall.exe" -ArgumentList "-install -silent" -Wait	
$WshShell = New-Object -ComObject WScript.Shell	
$Shortcut = $WshShell.CreateShortcut("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\simplewall.lnk")	
$Shortcut.TargetPath = "$env:ProgramFiles\simplewall\simplewall.exe"	
$Shortcut.WorkingDirectory = "C:\Program Files\simplewall"	
$Shortcut.Save()

# WindowsSpyBlocker
Start-Process cmd.exe -ArgumentList '/c', '(echo 1 & timeout /t 1 >nul & echo 1 & timeout /t 1 >nul & echo 1 & timeout /t 1 >nul & echo exit) | ".\WindowsSpyBlocker\WindowsSpyBlocker.exe"' -NoNewWindow -Wait
Clear-Host

# Add NoTelemetry package
if (Test-Path "C:\Windows\AtlasModules") { Start-Process -FilePath 'C:\Windows\AtlasModules\DisableTelemetry.cmd' -NoNewWindow -Wait } else {    	
	Move-Item ".\AtlasModules" "C:\Windows" -Force
	Start-Process -FilePath 'C:\Windows\AtlasModules\DisableTelemetry.cmd' -NoNewWindow -Wait
}

