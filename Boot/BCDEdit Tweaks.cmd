<# : batch portion
@echo off
fltmc >nul || (powershell "Start -Verb RunAs '%~f0'" & exit) & cd /D "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "[scriptblock]::Create((Get-Content -LiteralPath '%~f0' -Raw -Encoding UTF8)).Invoke(@(&{$args}%*))"
: end batch / begin powershell #>

netsh interface tcp set global autotuninglevel=disabled				
bcdedit /set disabledynamictick Yes | Out-Null				
bcdedit /set useplatformtick Yes | Out-Null				
bcdedit /set nx AlwaysOff | Out-Null        					
bcdedit /set integrityservices disable | Out-Null					
bcdedit /set hypervisorlaunchtype off | Out-Null 					
bcdedit /set vsmlaunchtype Off | Out-Null     					
bcdedit /set vm No | Out-Null           					
bcdedit /set isolatedcontext No | Out-Null					
bcdedit /set useplatformclock no | Out-Null      					
bcdedit /set tscsyncpolicy Enhanced | Out-Null				
# forces Windows to use logical destination mode for interrupts				
# bcdedit /set usephysicaldestination no | Out-Null 					
bcdedit /set bootmenupolicy Legacy | Out-Null     					
bcdedit /set quietboot yes | Out-Null             					
bcdedit /set bootux disabled | Out-Null           					
bcdedit /set bootlog no | Out-Null                					
bcdedit /timeout 3 | Out-Null     					
bcdedit /event off | Out-Null                 					
bcdedit /bootdebug off | Out-Null				
bcdedit /set debug no | Out-Null         					
bcdedit /set ems no | Out-Null              					
bcdedit /set bootems no | Out-Null				
# disable legacy APIC				
# bcdedit /set uselegacyapicmode no | Out-Null					
bcdedit /set sos no | Out-Null				