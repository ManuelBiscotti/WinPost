<# : batch portion
@echo off
setlocal DisableDelayedExpansion
:: Capture ALL arguments
set "ALL_ARGS=%*"
echo "%ALL_ARGS%"|find /i "-el">nul && set _elev=1
set "_PSarg="""%~f0""" %*"
setlocal EnableDelayedExpansion
:: Admin check
>nul 2>&1 fltmc || >nul 2>&1 net session || (
    if not defined _elev (
        powershell -NoProfile -Command "Start-Process cmd.exe -ArgumentList '/c', '!_PSarg!' -Verb RunAs" && exit /b 0
        echo ERROR: Admin elevation failed
        exit /b 1
    )
)
:: PowerShell execution
where pwsh.exe >nul 2>&1 && set "ps1=pwsh" || set "ps1=powershell"
%ps1% -NoProfile -ExecutionPolicy Bypass -Command "Get-Content '%~f0' -Raw | iex"
if errorlevel 1 (
    echo ERROR: PowerShell execution failed - Errorlevel: %errorlevel%
    exit /b %errorlevel%
)
goto :eof
: end batch / begin powershell #>




# PowerShell portion
param(
    [string[]]$ScriptArgs
)

# Convert batch arguments to PowerShell
if ($env:ALL_ARGS) {
    $ScriptArgs = $env:ALL_ARGS -split ' '
}

Write-Host "Arguments received: $($ScriptArgs -join ', ')" -ForegroundColor Green



Write-Host "Admin:" ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator") -ForegroundColor Green

function Invoke-RemoveUWPApps {
	Write-Host "Uninstalling: UWP Apps. Please wait . . ."
	# uninstall all uwp apps keep nvidia & cbs
	# cbs needed for w11 explorer
	Get-AppXPackage -AllUsers | Where-Object { $_.Name -notlike '*Winget*' -and $_.Name -notlike '*AppInstaller*' -and $_.Name -notlike '*NVIDIA*' -and $_.Name -notlike '*CBS*' } | Remove-AppxPackage -ErrorAction SilentlyContinue
}

function Invoke-UninstallOneDrive { 
	# Uninstall OneDrive
	# github.com/asheroto/UninstallOneDrive
	Invoke-RestMethod 'https://github.com/asheroto/UninstallOneDrive/raw/refs/heads/master/UninstallOneDrive.ps1' | Invoke-Expression 
}


function Invoke-NETFramework35 {
	# .NET 3.5 Feature Installer for Windows 10/11 x86/x64
	# Standalone Offline Installer to enable (install .NET Framework 3.5 feature for Windows 10
	# https://github.com/ionuttbara/dotNet2035onW1X
	
	$feature = Get-WindowsOptionalFeature -Online -FeatureName NetFx3
	if ($feature.State -eq 'Enabled') {
		$null # do nothing
	} else {
		# Get Windows build number from registry
		$build = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuild
 
        # <16299 → W10P1
        if ($build -lt 16299) {
            Write-Host "Installing .NET for Windows 10 P1 Build: $build..." -ForegroundColor Yellow
        	curl.exe -L "https://github.com/ionuttbara/dotNet2035onW1X/releases/download/release_tag/dotNet2035_W10P1.exe" -o "$env:TEMP\dotNet2035_W10P1.exe"
            Start-Process -Wait -FilePath "$env:TEMP\dotNet2035_W10P1.exe" -ArgumentList "/ai"
        }
        # >=16299 AND <19041 → W10P2
        elseif ($build -ge 16299 -and $build -lt 19041) {
            Write-Host "Installing .NET for Windows 10 Build: $build..." -ForegroundColor Yellow
        	curl.exe -L "https://github.com/ionuttbara/dotNet2035onW1X/releases/download/release_tag/dotNet2035_W10P2.exe" -o "$env:TEMP\dotNet2035_W10P2.exe"
            Start-Process -Wait -FilePath "$env:TEMP\dotNet2035_W10P2.exe" -ArgumentList "/ai"
        }
        # >=22000 → Windows 11
        elseif ($build -ge 22000) {
            Write-Host "Installing .NET for Windows 11 Build: $build..." -ForegroundColor Yellow
        	curl.exe -L "https://github.com/ionuttbara/dotNet2035onW1X/releases/download/release_tag/dotNet2035_W11.exe" -o "$env:TEMP\dotNet2035_W11.exe"
            Start-Process -Wait -FilePath "$env:TEMP\dotNet2035_W11.exe" -ArgumentList "/ai"
        	$feature = Get-WindowsOptionalFeature -Online -FeatureName NetFx3
			if ($feature.State -eq 'Enabled') {
				$null # do nothing
			} else {
				# Error code: 0x800F0950
				# Windows 11 .NET Framework 3.5 Offline Installer
				# https://github.com/akbarhabiby/Windows11_dotNET-3.5
				Write-Host "Installing .NET for Windows 11 Build: $build..." -ForegroundColor Yellow
				curl.exe -L "https://github.com/akbarhabiby/Windows11_dotNET-3.5/archive/refs/tags/v1.1.zip" -o "$env:TEMP\v1.1.zip"
				Expand-Archive "$env:TEMP\v1.1.zip" $env:TEMP -Force
				(Get-Content "$env:TEMP\Windows11_dotNET-3.5-1.1\app\start.bat") | Where-Object {$_ -notmatch '^\s*pause\s*$'} | Set-Content "$env:TEMP\Windows11_dotNET-3.5-1.1\app\start.bat"
				Start-Process -Wait -FilePath "$env:TEMP\Windows11_dotNET-3.5-1.1\app\start.bat"
			}
		}
        else {
            Write-Host "Installing .NET for Windows 10 P1 Build: $build..." -ForegroundColor Yellow
			dism.exe /Online /Enable-Feature /FeatureName:NetFx3 /All /NoRestart      
		}
	}
}


# Your argument handling here
if ($ScriptArgs -contains "-onedrive") {
    Write-Host "Removing OneDrive..." -ForegroundColor Yellow
	Invoke-UninstallOneDrive
}

if ($ScriptArgs -contains "-edge") {
    Write-Host "Removing Edge..." -ForegroundColor Yellow
}

if ($ScriptArgs -contains "-both") {
    Write-Host "Running Both..." -ForegroundColor Yellow
	Invoke-RemoveUWPApps
	Invoke-UninstallOneDrive
	Invoke-NETFramework35
}

Write-Host "Script completed!" -ForegroundColor Cyan
pause

#Requires -RunAsAdministrator

$Host.UI.RawUI.WindowTitle = 'Windows X Post Install'
Clear-Host

$ProgressPreference = 'SilentlyContinue'  
$ErrorActionPreference = 'SilentlyContinue'

function RunAsTI ($cmd,$arg) { $id='RunAsTI'; $key="Registry::HKU\$(((whoami /user)-split' ')[-1])\Volatile Environment"; $code=@'
 $I=[int32]; $M=$I.module.gettype("System.Runtime.Interop`Services.Mar`shal"); $P=$I.module.gettype("System.Int`Ptr"); $S=[string]
 $D=@(); $T=@(); $DM=[AppDomain]::CurrentDomain."DefineDynami`cAssembly"(1,1)."DefineDynami`cModule"(1); $Z=[uintptr]::size
 0..5|% {$D += $DM."Defin`eType"("AveYo_$_",1179913,[ValueType])}; $D += [uintptr]; 4..6|% {$D += $D[$_]."MakeByR`efType"()}
 $F='kernel','advapi','advapi', ($S,$S,$I,$I,$I,$I,$I,$S,$D[7],$D[8]), ([uintptr],$S,$I,$I,$D[9]),([uintptr],$S,$I,$I,[byte[]],$I)
 0..2|% {$9=$D[0]."DefinePInvok`eMethod"(('CreateProcess','RegOpenKeyEx','RegSetValueEx')[$_],$F[$_]+'32',8214,1,$S,$F[$_+3],1,4)}
 $DF=($P,$I,$P),($I,$I,$I,$I,$P,$D[1]),($I,$S,$S,$S,$I,$I,$I,$I,$I,$I,$I,$I,[int16],[int16],$P,$P,$P,$P),($D[3],$P),($P,$P,$I,$I)
 1..5|% {$k=$_; $n=1; $DF[$_-1]|% {$9=$D[$k]."Defin`eField"('f' + $n++, $_, 6)}}; 0..5|% {$T += $D[$_]."Creat`eType"()}
 0..5|% {nv "A$_" ([Activator]::CreateInstance($T[$_])) -fo}; function F ($1,$2) {$T[0]."G`etMethod"($1).invoke(0,$2)}
 $TI=(whoami /groups)-like'*1-16-16384*'; $As=0; if(!$cmd) {$cmd='control';$arg='admintools'}; if ($cmd-eq'This PC'){$cmd='file:'}
 if (!$TI) {'TrustedInstaller','lsass','winlogon'|% {if (!$As) {$9=sc.exe start $_; $As=@(get-process -name $_ -ea 0|% {$_})[0]}}
 function M ($1,$2,$3) {$M."G`etMethod"($1,[type[]]$2).invoke(0,$3)}; $H=@(); $Z,(4*$Z+16)|% {$H += M "AllocHG`lobal" $I $_}
 M "WriteInt`Ptr" ($P,$P) ($H[0],$As.Handle); $A1.f1=131072; $A1.f2=$Z; $A1.f3=$H[0]; $A2.f1=1; $A2.f2=1; $A2.f3=1; $A2.f4=1
 $A2.f6=$A1; $A3.f1=10*$Z+32; $A4.f1=$A3; $A4.f2=$H[1]; M "StructureTo`Ptr" ($D[2],$P,[boolean]) (($A2 -as $D[2]),$A4.f2,$false)
 $Run=@($null, "powershell -win 1 -nop -c iex `$env:R; # $id", 0, 0, 0, 0x0E080600, 0, $null, ($A4 -as $T[4]), ($A5 -as $T[5]))
 F 'CreateProcess' $Run; return}; $env:R=''; rp $key $id -force; $priv=[diagnostics.process]."GetM`ember"('SetPrivilege',42)[0]
 'SeSecurityPrivilege','SeTakeOwnershipPrivilege','SeBackupPrivilege','SeRestorePrivilege' |% {$priv.Invoke($null, @("$_",2))}
 $HKU=[uintptr][uint32]2147483651; $NT='S-1-5-18'; $reg=($HKU,$NT,8,2,($HKU -as $D[9])); F 'RegOpenKeyEx' $reg; $LNK=$reg[4]
 function L ($1,$2,$3) {sp 'HKLM:\Software\Classes\AppID\{CDCBCFCA-3CDC-436f-A4E2-0E02075250C2}' 'RunAs' $3 -force -ea 0
  $b=[Text.Encoding]::Unicode.GetBytes("\Registry\User\$1"); F 'RegSetValueEx' @($2,'SymbolicLinkValue',0,6,[byte[]]$b,$b.Length)}
 function Q {[int](gwmi win32_process -filter 'name="explorer.exe"'|?{$_.getownersid().sid-eq$NT}|select -last 1).ProcessId}
 $11bug=($((gwmi Win32_OperatingSystem).BuildNumber)-eq'22000')-AND(($cmd-eq'file:')-OR(test-path -lit $cmd -PathType Container))
 if ($11bug) {'System.Windows.Forms','Microsoft.VisualBasic' |% {[Reflection.Assembly]::LoadWithPartialName("'$_")}}
 if ($11bug) {$path='^(l)'+$($cmd -replace '([\+\^\%\~\(\)\[\]])','{$1}')+'{ENTER}'; $cmd='control.exe'; $arg='admintools'}
 L ($key-split'\\')[1] $LNK ''; $R=[diagnostics.process]::start($cmd,$arg); if ($R) {$R.PriorityClass='High'; $R.WaitForExit()}
 if ($11bug) {$w=0; do {if($w-gt40){break}; sleep -mi 250;$w++} until (Q); [Microsoft.VisualBasic.Interaction]::AppActivate($(Q))}
 if ($11bug) {[Windows.Forms.SendKeys]::SendWait($path)}; do {sleep 7} while(Q); L '.Default' $LNK 'Interactive User'
'@; $V='';'cmd','arg','id','key'|%{$V+="`n`$$_='$($(gv $_ -val)-replace"'","''")';"}; sp $key $id $($V,$code) -type 7 -force -ea 0
 start powershell -args "-win 1 -nop -c `n$V `$env:R=(gi `$key -ea 0).getvalue(`$id)-join''; iex `$env:R" -verb runas
}  # lean & mean snippet by AveYo, 2022.01.28


















































Clear-Host
Write-Host "Restart to apply . . ."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")