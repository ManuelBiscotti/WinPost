for /f "tokens=2 delims=:()" %A in ('powercfg -getactivescheme') do powercfg /export "%USERPROFILE%\Desktop\ActivePowerPlan.pow" %A
