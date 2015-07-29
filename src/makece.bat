@echo off
call "C:\Program Files\Microsoft eMbedded Tools\EVC\WCE300\BIN\WCEARM.BAT"
nmake /NOLOGO -f evc.mak %1 %2 %3 %4 %5 %6 %7 %8 %9
