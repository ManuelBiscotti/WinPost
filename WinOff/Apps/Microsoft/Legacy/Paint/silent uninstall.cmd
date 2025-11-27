<# : batch portion
@echo off
fltmc >nul || (powershell "Start -Verb RunAs '%~f0'" & exit) & cd /D "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "[scriptblock]::Create((Get-Content -LiteralPath '%~f0' -Raw -Encoding UTF8)).Invoke(@(&{$args}%*))" 2>nul
exit /b
: end batch / begin powershell #>

if ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild -ge 22000){				

	# remove paint files and shortcuts
	Remove-Item "C:\Program Files\Windows NT\Accessories\Paint.exe" -Force -ErrorAction SilentlyContinue
	Remove-Item "C:\Program Files\Windows NT\Accessories\en-US\mspaint1.exe.mui" -Recurse -Force -ErrorAction SilentlyContinue
	Remove-Item "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Paint.lnk" -Force -ErrorAction SilentlyContinue

} elseif ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild -le 19045) {	

	#
	$ProgressPreference = 'SilentlyContinue'
	Remove-WindowsCapability -Online -Name "Microsoft.Windows.MSPaint~~~~0.0.1.0" -ErrorAction SilentlyContinue | Out-Null 2>&1	
	
} else {
}