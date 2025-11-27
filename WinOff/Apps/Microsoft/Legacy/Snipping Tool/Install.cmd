<# : batch portion
@echo off
fltmc >nul || (powershell "Start -Verb RunAs '%~f0'" & exit) & cd /D "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "[scriptblock]::Create((Get-Content -LiteralPath '%~f0' -Raw -Encoding UTF8)).Invoke(@(&{$args}%*))"
: end batch / begin powershell #>

if ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild -ge 22000){				

	# Ensure target directories
	New-Item -Path "C:\Program Files\Windows NT\Accessories" -ItemType Directory -Force | Out-Null
	New-Item -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories" -ItemType Directory -Force | Out-Null
	
	# Copy Paint files
	Copy-Item ".\Portable\Snipping Tool\en-US" "C:\Program Files\Windows NT\Accessories" -Recurse -Force
	Copy-Item ".\Portable\Snipping Tool\SnippingTool.exe" "C:\Program Files\Windows NT\Accessories" -Force
	
	# Create Paint Start Menu shortcut
	$shell = New-Object -ComObject WScript.Shell
	$shortcut = $shell.CreateShortcut("C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\SnippingTool.lnk")
	$shortcut.TargetPath = "C:\Program Files\Windows NT\Accessories\SnippingTool.exe"
	$shortcut.Save()

} elseif ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild -le 19045) {	

	# install snipping tool
	cmd /c ".\snippingtool_setup_x64.exe >nul 2>&1"
	
} else {
}
