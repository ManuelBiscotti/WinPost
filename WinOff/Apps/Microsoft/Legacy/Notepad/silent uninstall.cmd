<# : batch portion
@echo off
fltmc >nul || (powershell "Start -Verb RunAs '%~f0'" & exit) & cd /D "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "[scriptblock]::Create((Get-Content -LiteralPath '%~f0' -Raw -Encoding UTF8)).Invoke(@(&{$args}%*))" 2>nul
exit /b
: end batch / begin powershell #>

function Invoke-CleanNotepadClassic {

	# remove start menu shortcuts
	Remove-Item "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Notepad (Classic).lnk" -Force -ErrorAction SilentlyContinue
	Remove-Item "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Notepad.lnk" -Force -ErrorAction SilentlyContinue
	
	# delete edit with notepad
	Regedit.exe /S ".\context menu item\edit with notepad\remove.reg"
    # remove new text document context menu item
    Regedit.exe /S ".\context menu item\new text document\remove.reg"
	
	# uninstall notepad
	Start-Process "${env:ProgramFiles}\notepad\unins000.exe" -ArgumentList "/SILENT" -Wait
	Stop-Process -Name OpenWith -Force -ErrorAction SilentlyContinue
	
}

# Windows 11
if ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild -ge 22000) {

    if (Test-Path "$env:SystemRoot\System32\notepad.exe") {

        # remove notepad start menu shortcut
        Remove-Item "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Notepad.lnk" -Force -ErrorAction SilentlyContinue
<#
        # remove new text document context menu item
        Regedit.exe /S ".\context menu item\new text document\remove.reg"
#>
    } else {
        Invoke-CleanNotepadClassic
    }

}

# Windows 10 (and older 11 builds)
elseif ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild -le 19045) {

    if (Test-Path "$env:SystemRoot\System32\notepad.exe") {

        # remove notepad
        $ProgressPreference = 'SilentlyContinue'
        Remove-WindowsCapability -Online -Name "Microsoft.Windows.Notepad.System~~~~0.0.1.0" -ErrorAction SilentlyContinue | Out-Null
        Remove-WindowsCapability -Online -Name "Microsoft.Windows.Notepad~~~~0.0.1.0" -ErrorAction SilentlyContinue | Out-Null

        # remove notepad start menu shortcut
        Remove-Item "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Notepad.lnk" -Force -ErrorAction SilentlyContinue

        # remove new text document context menu item
        Regedit.exe /S ".\context menu item\new text document\remove.reg"

    } else {
        Invoke-CleanNotepadClassic
    }

}



