@echo off
:: created by pdelaage on 20100928
:: usage : makece ARMV4|X86|... other cpus: see bat scripts in evc/bin
::     eg  makece X86, makece X86 clean
::     makece <=> makece ARMV4 all
:: NEVER DO makece clean ! but makece TARGETCPU clean !
:: Note : adapt EVC/bin/WCE<target>.bat scripts
Title WCE STUNNEL

:: !!!!!!!!!!!!!!
:: CUSTOMIZE THIS according to your EVC INSTALLED ENVIRONMENT
:: !!!!!!!!!!!!!!

set OSVERSION=WCE420
set PLATFORM=STANDARDSDK
set WCEROOT=C:\Program Files\MSEVC4
set SDKROOT=C:\Program Files\Microsoft SDKs

:: !!!!!!!!!!!!!!!!!!
:: END CUSTOMIZATION
:: !!!!!!!!!!!!!!!!!!

:: Define TARGET CPU 
:: -----------------

:: define "new" target (useful if one wants to compile for various WCE target CPUs)
if "%1"=="" echo "USAGE : makece TARGETCPU other_make_options..."
if "%1"=="" echo "TARGETCPU=(ARMV4|ARMV4I|ARMV4T|MIPS16|MIPSII|MIPSII_FP|MIPSIV|MIPSIV_FP|SH3|SH4|X86), other cpu: see bat scripts in evc/bin"
if "%1"=="" echo "!!! do not hesitate to adapt evc.mak for CPU and/or better compilation flags !!!"
if "%1"=="" exit /B

:: old code to default to ARMV4, but it is better that users are WARNED that the script now need an explicit target!
::if "%1"=="" set NEWTGTCPU=ARMV4

if NOT DEFINED TARGETCPU set TARGETCPU=XXXXX
if NOT "%1"=="" set NEWTGTCPU=%1
if NOT "%1"=="" shift

echo WCE TARGET CPU is %NEWTGTCPU%

rem Adjust MS EVC env vars
rem ----------------------

rem Check MSenv vars against our ref values

set isenvok=0
if "%NEWTGTCPU%"=="%TARGETCPU%"  set /A "isenvok+=1"

if %isenvok%==1 echo WCE ENVIRONMENT OK
if %isenvok%==1 goto envisok

:: useless since separated tgt folders
::echo WCE TARGET CPU changed, destroying every obj files
::del .\*.obj

:: if env is NOT ok, adjust MS EVC env vars to be used by MS WCE<CPU>.BAT
:: (this is to avoid repetitive pollution of PATH)

echo WCE ENVIRONMENT ADJUSTED

:: call "%WCEROOT%\EVC\WCE420\BIN\WCE%NEWTGTCPU%.BAT"
call "%WCEROOT%\EVC\%OSVERSION%\bin\WCE%NEWTGTCPU%.BAT"

set TARGETCPU=%NEWTGTCPU%

:envisok

::exit /B

rem make everything
rem ---------------

nmake /NOLOGO -f evc.mak %1 %2 %3 %4 %5 %6 %7 %8 %9
