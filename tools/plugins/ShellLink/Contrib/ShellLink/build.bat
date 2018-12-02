@ECHO OFF
Set VCDIR=D:\Program Files\Microsoft Visual C++ Toolkit 2003

Set PATH=%VCDIR%\bin;%PATH%
Set INCLUDE=%VCDIR%\include;%INCLUDE%
Set LIB=%VCDIR%\lib;%LIB%

cl /O1 ShellLink.cpp /LD /link kernel32.lib user32.lib uuid.lib ole32.lib /OPT:NOWIN98 /NODEFAULTLIB /ENTRY:DllMain
@PAUSE