@echo off
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit" /v LastKey /t REG_SZ /d "Computer\HKEY_CLASSES_ROOT\DesktopBackground\Shell" /f >nul
start regedit.exe
