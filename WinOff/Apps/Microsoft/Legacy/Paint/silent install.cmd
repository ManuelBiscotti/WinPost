<# : batch portion
@echo off
fltmc >nul || (powershell "Start -Verb RunAs '%~f0'" & exit) & cd /D "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "[scriptblock]::Create((Get-Content -LiteralPath '%~f0' -Raw -Encoding UTF8)).Invoke(@(&{$args}%*))" 2>nul
exit /b
: end batch / begin powershell #>

function Invoke-PaintPortable {
	
	# Ensure target directories
	New-Item -Path "C:\Program Files\Windows NT\Accessories" -ItemType Directory -Force| Out-Null 2>&1
	New-Item -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories" -ItemType Directory -Force| Out-Null 2>&1
	
	# Copy Paint files
	Copy-Item ".\Portable\Paint\en-US" "C:\Program Files\Windows NT\Accessories" -Recurse -Force -ErrorAction SilentlyContinue
	Copy-Item ".\Portable\Paint\mspaint1.exe" "C:\Program Files\Windows NT\Accessories" -Force -ErrorAction SilentlyContinue
	
	# Create Paint Start Menu shortcut
	$shell = New-Object -ComObject WScript.Shell
	$shortcut = $shell.CreateShortcut("C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Paint.lnk")
	$shortcut.TargetPath = "C:\Program Files\Windows NT\Accessories\mspaint1.exe"
	$shortcut.Save()
	
}

if ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild -ge 22000){				
	
	try {
	
		Start-Process ".\setup\ClassicPaint-setup.exe" -Argumentlist "/SILENT" -Wait
		Remove-Item "$env:Public\Desktop\Paint (classic).lnk" -Force -ErrorAction SilentlyContinue
		Rename-Item "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Paint (classic).lnk" "Paint.lnk" -Force -ErrorAction SilentlyContinue
	
	} catch {
		Invoke-PaintPortable
	}

} elseif ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild -le 19045) {	

	try {
		# install paint W10
		$ProgressPreference = 'SilentlyContinue'
		Add-WindowsCapability -Online -Name "Microsoft.Windows.MSPaint~~~~0.0.1.0" -ErrorAction SilentlyContinue | Out-Null 2>&1	

	} catch {
		Invoke-PaintPortable
	}
	
} else {
}

