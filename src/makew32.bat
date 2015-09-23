@echo off
TITLE W32 STUNNEL 
:: In a multi-target compilation environment, it is better to open
:: a new cmd.exe window in order to avoid PATH pollution
:: (for example with some previous WCE compilation attempts)

set NEWTGTCPU=W32

rem Adjust the MS VC environment variables
rem ---------------------

rem Detect the latest Visual Studio
rem Visual Studio 2008
if DEFINED VS90COMNTOOLS if exist "%VS90COMNTOOLS%..\..\vc\vcvarsall.bat" set vsTools=%VS90COMNTOOLS%
rem Visual Studio 2010
if DEFINED VS100COMNTOOLS if exist "%VS100COMNTOOLS%..\..\vc\vcvarsall.bat" set vsTools=%VS100COMNTOOLS%
rem Visual Studio 2012
if DEFINED VS110COMNTOOLS if exist "%VS110COMNTOOLS%..\..\vc\vcvarsall.bat" set vsTools=%VS110COMNTOOLS%
rem Visual Studio 2013
if DEFINED VS120COMNTOOLS if exist "%VS120COMNTOOLS%..\..\vc\vcvarsall.bat" set vsTools=%VS120COMNTOOLS%
rem Visual Studio 2015
if DEFINED VS140COMNTOOLS if exist "%VS140COMNTOOLS%..\..\vc\vcvarsall.bat" set vsTools=%VS140COMNTOOLS%

::rem Initialize the Visual Studio tools
::call "%vsTools%..\..\vc\vcvarsall.bat"

rem Check the MSenv variables against our reference values
set isenvok=0
if NOT DEFINED TARGETCPU set TARGETCPU=XXXXX
if "%NEWTGTCPU%"=="%TARGETCPU%"  set /A "isenvok+=1"

if %isenvok%==1 echo W32 ENVIRONMENT OK
if %isenvok%==1 goto envisok

:: Useless with separated target folders
::echo W32 TARGET CPU changed, destroying every obj files
::del .\*.obj

:: if env is NOT ok, adjust the MS VC environment variables
:: (this is to avoid repetitive pollution of PATH)

echo W32 ENVIRONMENT ADJUSTED

:: Reset of INCLUDE is needed because of accumulation of includes in vcvars32

set INCLUDE=

call "%vsTools%..\..\vc\bin\vcvars32.bat"

set TARGETCPU=%NEWTGTCPU%

:envisok

rem Make everything
rem ---------------

nmake.exe -f vc.mak %1 %2 %3 %4 %5 %6 %7 %8 %9
