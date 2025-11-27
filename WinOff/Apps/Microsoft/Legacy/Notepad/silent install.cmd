<# : batch portion
@echo off
fltmc >nul || (powershell "Start -Verb RunAs '%~f0'" & exit) & cd /D "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "[scriptblock]::Create((Get-Content -LiteralPath '%~f0' -Raw -Encoding UTF8)).Invoke(@(&{$args}%*))" 2>nul
exit /b
: end batch / begin powershell #>

function Invoke-NotepadClassic {
	
	# install notepad	
	Start-Process ".\setup\notepad-setup.exe" -ArgumentList "/S" -Wait	
	Start-Sleep -Seconds 5
	
	# delete notepad desktop shortcut
	Remove-Item "$env:Public\Desktop\Notepad (Classic).lnk" -Force -ErrorAction SilentlyContinue
	# move and rename notepad start menu shortcut
	Move-Item "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Notepad (Classic).lnk" "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Notepad.lnk" -Force -ErrorAction SilentlyContinue
	
	# delete edit with notepad context menu	item
	reg.exe delete "HKCR\*\shell\ClassicNotepad" /f | Out-Null 2>&1	
	
	# restore new text document context menu item	
	Regedit.exe /S ".\context menu item\new text document\restore2.reg"
	
}	

# Windows 11
if ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild -ge 22000) {

    if (Test-Path "$env:SystemRoot\System32\notepad.exe") {
	
        # restore new text document context menu item
        Regedit.exe /S ".\context menu item\new text document\restore.reg"

        # create notepad start menu shortcut
        $shell = New-Object -ComObject WScript.Shell
        $lnk  = 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Notepad.lnk'
        $shortcut = $shell.CreateShortcut($lnk)
        $shortcut.TargetPath = "$env:SystemRoot\System32\notepad.exe"
        $shortcut.Save()

    } else {
        Invoke-NotepadClassic
    }
}

# Windows 10 (and older 11 builds)
elseif ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild -le 19045) {
    
	if (Test-Path "$env:SystemRoot\System32\notepad.exe") {
		$ProgressPreference = 'SilentlyContinue'
		Add-WindowsCapability -Online -Name "Microsoft.Windows.Notepad.System~~~~0.0.1.0" -ErrorAction SilentlyContinue | Out-Null
		Add-WindowsCapability -Online -Name "Microsoft.Windows.Notepad~~~~0.0.1.0" -ErrorAction SilentlyContinue | Out-Null
    
	} else {
        Invoke-NotepadClassic
    }
	
} else {
    # other OS builds: no-op
}

pause