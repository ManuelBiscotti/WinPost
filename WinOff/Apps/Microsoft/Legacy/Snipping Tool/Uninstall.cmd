<# : batch portion
@echo off
fltmc >nul || (powershell "Start -Verb RunAs '%~f0'" & exit) & cd /D "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "[scriptblock]::Create((Get-Content -LiteralPath '%~f0' -Raw -Encoding UTF8)).Invoke(@(&{$args}%*))"
: end batch / begin powershell #>

if ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild -ge 22000){				

	# Remove Snipping Tool files and shortcut
	Remove-Item "C:\Program Files\Windows NT\Accessories\SnippingTool.exe" -Force -ErrorAction SilentlyContinue
	Remove-Item "C:\Program Files\Windows NT\Accessories\en-US\SnippingTool.exe.mui" -Recurse -Force -ErrorAction SilentlyContinue
	Remove-Item "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\SnippingTool.lnk" -Force -ErrorAction SilentlyContinue

} elseif ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild -le 19045) {	

	# uninstall old snippingtool w10						
	if (Test-Path "C:\Windows\System32\SnippingTool.exe") {			
	    Start-Process "C:\Windows\System32\SnippingTool.exe" -ArgumentList "/Uninstall"			
	    $processExists = Get-Process -Name SnippingTool -ErrorAction SilentlyContinue			
	    if ($processExists) {			
	        do {			
	            $openWindows = Get-Process | Where-Object { $_.MainWindowTitle -ne '' } | Select-Object -ExpandProperty MainWindowTitle			
	            if ($openWindows -contains 'Snipping Tool') {			
	                Stop-Process -Name SnippingTool -Force -ErrorAction SilentlyContinue			
	                break			
	            }			
	        } while ($true)			
	    }			
	}			
	
} else {
}