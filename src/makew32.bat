@echo off
TITLE W32 STUNNEL 
::pdelaage 20101026: for use with MS VCexpress 2008 (v9)
::some trick to avoid re-pollution of env vars as much as possible

:: In multitarget compilation environment, it is better to open a new cmd.exe window
:: to avoid pollution of PATH from, eg, some previous WCE compilation attempts.

set NEWTGTCPU=W32

rem Adjust MS VC env vars
rem ---------------------

rem Check MSenv vars against our ref values

set isenvok=0
if NOT DEFINED TARGETCPU set TARGETCPU=XXXXX
if "%NEWTGTCPU%"=="%TARGETCPU%"  set /A "isenvok+=1"

if %isenvok%==1 echo W32 ENVIRONMENT OK
if %isenvok%==1 goto envisok

:: useless since separated tgt folders
::echo W32 TARGET CPU changed, destroying every obj files
::del .\*.obj

:: if env is NOT ok, adjust MS VC env vars to be used by MS VC
:: (this is to avoid repetitive pollution of PATH)

echo W32 ENVIRONMENT ADJUSTED

:: reset of INCLUDE needed because of accumulation of includes in vcvars32

set INCLUDE=

call "C:\Program Files\Microsoft Visual Studio 9.0\VC\bin\vcvars32.bat"

set TARGETCPU=%NEWTGTCPU%

:envisok

rem make everything
rem ---------------

nmake.exe -f vc.mak %1 %2 %3 %4 %5 %6 %7 %8 %9
