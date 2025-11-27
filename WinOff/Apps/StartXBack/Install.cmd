<# : batch portion
@echo off
fltmc >nul || (powershell "Start -Verb RunAs '%~f0'" & exit) & cd /D "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "[scriptblock]::Create((Get-Content -LiteralPath '%~f0' -Raw -Encoding UTF8)).Invoke(@(&{$args}%*))"
: end batch / begin powershell #>

$ProgressPreference = 'SilentlyContinue'
if ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild -le 19045) {
		
	# install startisback
	Start-Process ".\StartIsBack\StartIsBackPlusPlus_setup.exe" -ArgumentList "/elevated /silent" -Wait
	# run startxback
	& ".\StartIsBack\StartXBack.cmd" -Wait *>$null
	Copy-Item ".\StartIsBack\version.dll" -Destination "${env:ProgramFiles(x86)}\StartIsBack\version.dll" -Force -ErrorAction SilentlyContinue
	# import reg
	Regedit.exe /S ".\StartIsBack\StartIsBack.reg"	
	Timeout /T 1 | Out-Null
	# orb
	Copy-Item ".\StartIsBack\Orbs\6801-6009.bmp" -Destination "${env:ProgramFiles(x86)}\StartIsBack\Orbs\6801-6009.bmp" -Force -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "HKCU:\Software\StartIsBack" -Name "OrbBitmap" -Value "C:\Program Files (x86)\StartIsBack\Orbs\6801-6009.bmp" | Out-Null	

} elseif ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild -ge 22000) {
		
	# install startallback
	Start-Process -FilePath ".\StartAllBack\StartAllBack_setup.exe" -ArgumentList "/elevated /silent" -Wait	
	# run StartAllBack activator (for educational purpose only)
	& ".\StartAllBack\SAB.ps1" -Wait *>$null		
	# import reg
	Regedit.exe /S ".\StartAllBack\StartAllBack.reg"
	Timeout /T 1 | Out-Null
	# orb
	Copy-Item ".\StartAllBack\Orbs\rog.png" -Destination "C:\Program Files\StartAllBack\Orbs\rog.png" -Force -ErrorAction SilentlyContinue
	# Set-ItemProperty -Path "HKCU:\Software\StartIsBack" -Name "OrbBitmap" -Value "C:\Program Files\StartAllBack\Orbs\rog.png" | Out-Null	

} else {
}
