<# : batch portion
@echo off
fltmc >nul || (powershell "Start -Verb RunAs '%~f0'" & exit) & cd /D "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command "[scriptblock]::Create((Get-Content -LiteralPath '%~f0' -Raw)).Invoke()"
exit /b %ERRORLEVEL%
: end batch / begin powershell #>

# install 7zip
Start-Process ".\setup\7z-x64.exe" -ArgumentList "/S" -Wait
# register file extensions
'7z','xz','bzip2','gzip','tar','zip','wim','apfs','ar','arj','cab','chm','cpio','cramfs','dmg','ext','fat','gpt','hfs','ihex','iso','lzh','lzma','mbr','nsis','ntfs','qcow2','rar','rpm','squashfs','udf','uefi','vdi','vhd','vhdx','vmdk','xar','z' | % { cmd /c "assoc .$_=7zFM.exe" >$null 2>&1 }
cmd /c "ftype 7zFM.exe=""$env:ProgramFiles\7-Zip\7zFM.exe"" ""%1"" ""%*""" >$null 2>&1
# move and rename 7zip start menu shortcut
Move-Item "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\7-Zip\7-Zip File Manager.lnk" "$env:ProgramData\Microsoft\Windows\Start Menu\Programs" -Force -ErrorAction SilentlyContinue
Rename-Item "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\7-Zip File Manager.lnk" "7-Zip.lnk" -Force
# remove 7zip folder
Remove-Item "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\7-Zip" -Recurse -Force -ErrorAction SilentlyContinue
