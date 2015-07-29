!MESSAGE !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!MESSAGE
!MESSAGE REMEMBER TO EDIT PATH_2_SSL_INCLUDE !!!
!MESSAGE
!MESSAGE !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!MESSAGE

!IF "$(CFG)" == ""
CFG=stunnel - Win32 rel
!MESSAGE No configuration specified. Defaulting to stunnel - Win32 rel.
!ENDIF 

!IF "$(CFG)" != "stunnel - Win32 rel"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "stunnel.mak" CFG="stunnel - Win32 rel"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "stunnel - Win32 rel" (based on "Win32 (x86) Console Application")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "stunnel - Win32 rel"
#PATH_2_SSL_INCLUDE=D:\ssl\ssl
PATH_2_SSL_INCLUDE=c:/tpsrc/openssl-0.9.6g/inc32/openssl
OUTDIR=.\stunnel_Win32
INTDIR=.\stunnel_Win32
# Begin Custom Macros
OutDir=.\stunnel_Win32
# End Custom Macros

ALL : "$(OUTDIR)\stunnel.exe"


CLEAN :
	-@erase "$(INTDIR)\log.obj"
	-@erase "$(INTDIR)\sthreads.obj"
	-@erase "$(INTDIR)\stunnel.obj"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(OUTDIR)\stunnel.exe"
	-@erase "$(OUTDIR)\stunnel.ilk"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MT /W3 /Od /I "$(PATH_2_SSL_INCLUDE)" /I "$(PATH_2_SSL_INCLUDE)/.." /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /D "USE_WIN32" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /GZ /c 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\stunnel.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=wsock32.lib ssleay32.lib libeay32.lib /nologo /subsystem:console /incremental:yes /pdb:"$(OUTDIR)\stunnel.pdb" /machine:I386 /out:"$(OUTDIR)\stunnel.exe" /pdbtype:sept /libpath:"c:/tpsrc/openssl-0.9.6g/out32dll"
LINK32_OBJS= \
	"$(INTDIR)\log.obj" \
	"$(INTDIR)\sthreads.obj" \
	"$(INTDIR)\client.obj" 
	"$(INTDIR)\options.obj" 
	"$(INTDIR)\protocol.obj" 
	"$(INTDIR)\ssl.obj" 
	"$(INTDIR)\stunnel.obj"

"$(OUTDIR)\stunnel.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 

.c{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.c{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

!IF "$(CFG)" == "stunnel - Win32 Release" || "$(CFG)" == "stunnel - Win32 Debug" || "$(CFG)" == "stunnel - Win32 Debug2" || "$(CFG)" == "stunnel - Win32 rel"
SOURCE=.\log.c

"$(INTDIR)\log.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\sthreads.c

"$(INTDIR)\sthreads.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\stunnel.c

"$(INTDIR)\stunnel.obj" : $(SOURCE) "$(INTDIR)"



!ENDIF 

