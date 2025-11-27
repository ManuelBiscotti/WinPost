@Echo Off & Set "_F0=%~f0" & Title

PowerShell.exe -NoProfile -Command "Set-Content -LiteralPath $Env:Temp\_.ps1 -Value ([RegEx]::Matches([System.IO.File]::ReadAllText($Env:_F0), '(?smi)^(Pause|Exit)(.*)$').Groups[2].Value) -Encoding Unicode -Force"
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%Temp%\_.ps1"
exit

function Del-PS1 {Remove-Item -LiteralPath $Env:Temp\_.ps1 -Force}

if ((Get-Item -LiteralPath 'Registry::HKU\S-1-5-19' -ErrorAction SilentlyContinue)) {Del-PS1} Else {
    try {Start-Process -FilePath PowerShell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$Env:Temp\_.ps1`"" -Verb RunAs} Catch {Del-PS1}
    exit
}

$Host.UI.RawUI.BackgroundColor = "Black"
$Host.UI.RawUI.ForegroundColor = "White"
Clear-Host

$u="https://download.sysinternals.com/files/ProcessExplorer.zip";$p="$env:TEMP\ProcessExplorer.zip";$d="$env:ProgramFiles\ProcessExplorer";$e="$d\procexp64.exe";iwr $u -OutFile $p -UseBasicParsing; if(!(Test-Path $d)){New-Item $d -ItemType Directory -Force|Out-Null}; Expand-Archive $p $d -Force; Remove-Item $p -Force

New-Item "HKCU:\SOFTWARE\Sysinternals\Process Explorer","HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe" -Force|Out-Null; Set-ItemProperty "HKCU:\SOFTWARE\Sysinternals\Process Explorer" OneInstance 1; Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe" Debugger "`"$e`" /e"

$MultilineComment = @"				
Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\Sysinternals\Process Explorer]
"ShowDllView"=dword:00000000
"HandleSortColumn"=dword:00000000
"HandleSortDirection"=dword:00000001
"DllSortColumn"=dword:00000000
"DllSortDirection"=dword:00000001
"ProcessSortColumn"=dword:ffffffff
"ProcessSortDirection"=dword:00000001
"HighlightServices"=dword:00000001
"HighlightOwnProcesses"=dword:00000001
"HighlightRelocatedDlls"=dword:00000000
"HighlightJobs"=dword:00000000
"HighlightNewProc"=dword:00000001
"HighlightDelProc"=dword:00000001
"HighlightImmersive"=dword:00000001
"HighlightProtected"=dword:00000000
"HighlightPacked"=dword:00000001
"HighlightNetProcess"=dword:00000000
"HighlightSuspend"=dword:00000001
"HighlightDuration"=dword:000003e8
"ShowCpuFractions"=dword:00000001
"FindWindowplacement"=hex(3):2C,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
00,00,00,00,00,00,00,00,00,00,00,00,00,96,00,00,00,96,00,00,00,00,00,00,00,\
00,00,00,00
"ShowAllUsers"=dword:00000001
"ShowProcessTree"=dword:00000001
"SymbolWarningShown"=dword:00000000
"HideWhenMinimized"=dword:00000000
"AlwaysOntop"=dword:00000000
"OneInstance"=dword:00000001
"NumColumnSets"=dword:00000000
"Windowplacement"=hex(3):2C,00,00,00,02,00,00,00,03,00,00,00,00,00,00,00,00,\
00,00,00,FF,FF,FF,FF,FF,FF,FF,FF,37,02,00,00,8C,01,00,00,57,05,00,00,E4,03,\
00,00
"RefreshRate"=dword:000003e8
"PrcessColumnCount"=dword:0000000d
"DllColumnCount"=dword:00000004
"HandleColumnCount"=dword:00000002
"DefaultProcPropPage"=dword:00000000
"DefaultSysInfoPage"=dword:00000000
"DefaultDllPropPage"=dword:00000000
"ProcessImageColumnWidth"=dword:000000c8
"SymbolPath"=""
"ColorPacked"=dword:00ff0080
"ColorImmersive"=dword:00eaea00
"ColorOwn"=dword:00ffd0d0
"ColorServices"=dword:00d0d0ff
"ColorRelocatedDlls"=dword:00a0ffff
"ColorGraphBk"=dword:00f0f0f0
"ColorJobs"=dword:00006cd0
"ColorDelProc"=dword:004646ff
"ColorNewProc"=dword:0046ff46
"ColorNet"=dword:00a0ffff
"ColorProtected"=dword:008000ff
"ShowHeatmaps"=dword:00000001
"ColorSuspend"=dword:00808080
"StatusBarColumns"=dword:00002015
"ShowAllCpus"=dword:00000000
"ShowAllGpus"=dword:00000000
"Opacity"=dword:00000064
"GpuNodeUsageMask"=dword:00000001
"GpuNodeUsageMask1"=dword:00000000
"VerifySignatures"=dword:00000000
"VirusTotalCheck"=dword:00000000
"VirusTotalSubmitUnknown"=dword:00000000
"ToolbarBands"=hex(3):06,01,00,00,00,00,00,00,00,00,00,00,4B,00,00,00,01,00,\
00,00,00,00,00,00,4B,00,00,00,02,00,00,00,00,00,00,00,4B,00,00,00,03,00,00,\
00,00,00,00,00,4B,00,00,00,04,00,00,00,00,00,00,00,4B,00,00,00,05,00,00,00,\
00,00,00,00,4B,00,00,00,06,00,00,00,00,00,00,00,4B,00,00,00,07,00,00,00,00,\
00,00,00,00,00,00,00,08,00,00,00,00,00,00,00
"UseGoogle"=dword:00000000
"ShowNewProcesses"=dword:00000000
"TrayCPUHistory"=dword:00000000
"ShowIoTray"=dword:00000000
"ShowNetTray"=dword:00000000
"ShowDiskTray"=dword:00000000
"ShowPhysTray"=dword:00000000
"ShowCommitTray"=dword:00000000
"ShowGpuTray"=dword:00000000
"FormatIoBytes"=dword:00000001
"StackWindowPlacement"=hex(3):00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
00,00,00,00
"ETWstandardUserWarning"=dword:00000000
"ShowUnnamedHandles"=dword:00000000
"SavedDivider"=hex(3):00,00,00,00,00,00,E0,3F
"UnicodeFont"=hex(3):08,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,90,01,\
00,00,00,00,00,00,00,00,00,00,4D,00,53,00,20,00,53,00,68,00,65,00,6C,00,6C,\
00,20,00,44,00,6C,00,67,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00
"Divider"=hex(3):00,00,00,00,00,00,F0,3F
"DllPropWindowplacement"=hex(3):2C,00,00,00,00,00,00,00,00,00,00,00,00,00,\
00,00,00,00,00,00,00,00,00,00,00,00,00,00,28,00,00,00,28,00,00,00,00,00,00,\
00,00,00,00,00
"PropWindowplacement"=hex(3):2C,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
00,00,00,00,00,00,00,00,00,00,00,00,00,28,00,00,00,28,00,00,00,00,00,00,00,\
00,00,00,00
"DbgHelpPath"="C:\\Windows\\SYSTEM32\\dbghelp.dll"
"SysinfoWindowplacement"=hex(3):2C,00,00,00,00,00,00,00,00,00,00,00,00,00,\
00,00,00,00,00,00,00,00,00,00,00,00,00,00,28,00,00,00,28,00,00,00,00,00,00,\
00,00,00,00,00
"ConfirmKill"=dword:00000001
"ShowLowerpane"=dword:00000000

[HKEY_CURRENT_USER\Software\Sysinternals\Process Explorer\DllColumnMap]
"3"=dword:00000457
"2"=dword:00000409
"0"=dword:0000001a
"1"=dword:0000002a

[HKEY_CURRENT_USER\Software\Sysinternals\Process Explorer\DllColumns]
"2"=dword:0000008c
"0"=dword:0000006e
"1"=dword:000000b4
"3"=dword:0000012c

[HKEY_CURRENT_USER\Software\Sysinternals\Process Explorer\HandleColumnMap]
"1"=dword:00000016
"0"=dword:00000015

[HKEY_CURRENT_USER\Software\Sysinternals\Process Explorer\HandleColumns]
"0"=dword:00000064
"1"=dword:000001c2

[HKEY_CURRENT_USER\Software\Sysinternals\Process Explorer\ProcessColumnMap]
"10"=dword:0000049b
"8"=dword:00000005
"12"=dword:00000409
"13"=dword:00000672
"7"=dword:00000004
"5"=dword:00000427
"11"=dword:00000026
"9"=dword:0000053c
"0"=dword:00000003
"1"=dword:0000041f
"2"=dword:00000672
"6"=dword:00000429
"3"=dword:000004b0
"4"=dword:00000424

[HKEY_CURRENT_USER\Software\Sysinternals\Process Explorer\ProcessColumns]
"9"=dword:0000002a
"10"=dword:00000035
"11"=dword:00000096
"12"=dword:0000008c
"8"=dword:0000002b
"7"=dword:00000028
"5"=dword:00000050
"4"=dword:00000050
"3"=dword:00000056
"2"=dword:00000022
"1"=dword:00000028
"6"=dword:00000022
"0"=dword:000000c8   
"@
Set-Content -Path "$env:TEMP\ProcessExplorerSettings.reg" -Value $MultilineComment -Force				
# edit reg file				
$path = "$env:TEMP\ProcessExplorerSettings.reg"				
(Get-Content $path) -replace "\?","$" | Out-File $path				
# import reg file				
Regedit.exe /S "$env:TEMP\ProcessExplorerSettings.reg"	

rm @("$env:TEMP\*","$env:SystemRoot\Temp\*") -Recurse -Force -ea 0

clear-host; write-host "Press any key to continue . . ."; $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown'); exit
