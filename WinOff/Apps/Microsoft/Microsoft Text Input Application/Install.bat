<# : batch portion
@echo off
fltmc >nul || (powershell "Start -Verb RunAs '%~f0'" & exit) & cd /D "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command "[scriptblock]::Create((Get-Content -LiteralPath '%~f0' -Raw)).Invoke()"
exit /b %ERRORLEVEL%
: end batch / begin powershell #>

$backupPath = Join-Path $env:SystemRoot "TextInputHost.exe.bak"				
$systemAppPath = Get-ChildItem "$env:SystemRoot\SystemApps" -Directory -Filter "MicrosoftWindows.Client.CBS_*" | Select-Object -First 1 -ExpandProperty FullName				
if ($systemAppPath -and (Test-Path $backupPath)) {				
	$originalPath = Join-Path $systemAppPath "TextInputHost.exe"    			
	takeown /f $originalPath /a > $null 2>&1    			
	icacls $originalPath /reset > $null 2>&1    			
	if (Test-Path $originalPath) { Remove-Item $originalPath -Force }    			
	Move-Item -Path $backupPath -Destination $originalPath -Force    			
	icacls $originalPath /reset > $null 2>&1    			
	Start-Process $originalPath    			
	Start-Process taskmgr    			
}				