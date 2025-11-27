<# : batch portion
@echo off
fltmc >nul || (powershell "Start -Verb RunAs '%~f0'" & exit) & cd /D "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "[scriptblock]::Create((Get-Content -LiteralPath '%~f0' -Raw -Encoding UTF8)).Invoke(@(&{$args}%*))"
: end batch / begin powershell #>

netsh interface tcp set global autotuninglevel=normal								
bcdedit /deletevalue disabledynamictick				
bcdedit /deletevalue useplatformtick				
bcdedit /set nx OptIn				
bcdedit /deletevalue integrityservices				
bcdedit /set hypervisorlaunchtype Auto				
bcdedit /deletevalue vsmlaunchtype				
bcdedit /deletevalue vm				
bcdedit /deletevalue isolatedcontext				
bcdedit /deletevalue useplatformclock				
bcdedit /set tscsyncpolicy Legacy							
bcdedit /set bootmenupolicy Standard				
bcdedit /deletevalue quietboot				
bcdedit /deletevalue bootux				
bcdedit /deletevalue bootlog				
bcdedit /timeout 30				
bcdedit /event on								
bcdedit /set bootdebug off				
bcdedit /set debug off				
bcdedit /set ems off				
bcdedit /set bootems off				
bcdedit /set sos off				