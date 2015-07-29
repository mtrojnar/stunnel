@echo off
::call "C:\Program Files\Microsoft eMbedded Tools\EVC\WCE300\BIN\WCEARM.BAT"
call "C:\Progra~1\MSEVC4\EVC\WCE420\BIN\WCEARMV4.BAT"
nmake /NOLOGO -f evc.mak %1 %2 %3 %4 %5 %6 %7 %8 %9
