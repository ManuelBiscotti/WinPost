<# : batch portion
@echo off
setlocal DisableDelayedExpansion
echo "%*"|find /i "-el">nul && set _elev=1
set _PSarg="""%~f0""" -el
setlocal EnableDelayedExpansion
>nul 2>&1 fltmc || >nul 2>&1 net session || (
    if not defined _elev (
        powershell -NoProfile -Command "Start-Process cmd.exe -ArgumentList '/c', '!_PSarg!' -Verb RunAs" && exit /b 0
        exit /b 1
    )
)
where pwsh.exe>nul 2>&1 && set "PS1=pwsh" || set "PS1=powershell"
%PS1% -nop -c "Get-Content '%~f0' -Raw | iex"
Color 0F
goto :eof
: end batch / begin powershell #>

$Host.UI.RawUI.WindowTitle = "enable updates"
$Host.UI.RawUI.BackgroundColor = "Black"
$Host.PrivateData.ProgressBackgroundColor = "Black"
$Host.PrivateData.ProgressForegroundColor = "White"
Clear-Host
Write-Host "Restoring Windows Update..."

$ProgressPreference = 'SilentlyContinue'
function Get-FileFromWeb {
	param([string]$URL, [string]$File)
 	try{if(Get-Command curl.exe -ErrorAction SilentlyContinue){curl.exe -L $URL -o $File -s}
 	elseif((Get-Service BITS -ErrorAction SilentlyContinue).Status -eq 'Running'){
 	Start-BitsTransfer -Source $URL -Destination $File -ErrorAction Stop
 	}else{Invoke-WebRequest -Uri $URL -OutFile $File -UseBasicParsing -ErrorAction Stop}
	}catch{throw $_}
}

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

try {
	
	# Enable Windows Update
	$zip = Join-Path $env:TEMP "windows-update-disabler-main.zip"			
	$batch = Join-Path $env:TEMP "windows-update-disabler-main\enable updates.bat"		
	
	Get-FileFromWeb "https://github.com/tsgrgo/windows-update-disabler/releases/latest/download/windows-update-disabler-main.zip" "$zip" -ErrorAction Stop	
	Expand-Archive -Path $zip -DestinationPath "$env:TEMP" -Force -ErrorAction Stop
	
	(Get-Content $batch) | Where-Object {				
		$_ -notmatch 'if not "%1"=="admin"' -and
		$_ -notmatch 'if not "%2"=="system"' -and			
		$_ -notmatch '^\s*pause\s*$'				
	} | Set-Content -Path $batch -Encoding ASCII				
	
	RunAsTI $batch "" -ErrorAction Stop
	
	# Wait for process completion				
	do {
		Start-Sleep -Seconds 2				
		$running = Get-WmiObject Win32_Process -Filter "Name='cmd.exe'" 2>$null |				
	    	Where-Object { $_.CommandLine -like "*enable updates.bat*" }				
	} while ($running)
	
	# Show Windows Update settings
	Remove-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "SettingsPageVisibility" -ErrorAction SilentlyContinue
	Get-Process -Name "SystemSettings","Settings" -ErrorAction SilentlyContinue | ForEach-Object { $_ | Stop-Process -Force -ErrorAction SilentlyContinue }	
	
} catch {
	
    <#
		
    .SYNOPSIS
        Resets Windows Update settings to default
		
    #>
	
    try {
		
        Get-FileFromWeb "https://raw.githubusercontent.com/ChrisTitusTech/winutil/main/functions/public/Invoke-WPFUpdatesdefault.ps1" "$env:TEMP\Invoke-WPFUpdatesdefault.ps1"
        . "$env:TEMP\Invoke-WPFUpdatesdefault.ps1" -ErrorAction Stop
		
        # call the function
        Invoke-WPFUpdatesdefault -ErrorAction Stop
		
        # Show Windows Update settings
        Remove-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "SettingsPageVisibility" -ErrorAction SilentlyContinue
        Get-Process -Name "SystemSettings","Settings" -ErrorAction SilentlyContinue | ForEach-Object { $_ | Stop-Process -Force -ErrorAction SilentlyContinue }
		
    } catch {
        Write-Host "$($_.Exception.Message)" -ForegroundColor Red
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        exit 1
    }
	
}