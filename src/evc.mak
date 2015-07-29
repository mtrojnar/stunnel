# wce.mak for stunnel.exe by Michal Trojnara 2006-2011
#
# 20101016 pdelaage : support for MULTI-TARGETS, very useful to avoid total 
# recompilation when validating for various target environments.
# + : support for version management, including "windows explorer property sheet" and "info balloon".
# + winsock2 instead of winsock1
# + DEFAULTLIB management : only 2 are necessary and defaultlibS as given for CLxxx in the MS doc ARE WRONG.

# !!!!!!!!!!!!!! 
# CUSTOMIZE THIS according to your wcecompat and openssl directories
# !!!!!!!!!!!!!!

# Modify this to point to your actual openssl compile directory
# (You did already compile openssl, didn't you???)

SSLDIR=C:\Users\standard\Documents\Dvts\Contrib\openssl\v1.0.0a\patched3

# Note that we currently use a multi-target customized version of legacy Essemer/wcecompat lib
COMPATDIR=C:\Users\standard\Documents\Dvts\Contrib\wcecompat\v12\patchedX86

WCEVER=420

# pdelaage 20101024 : VERSION is now managed in version.h and version.rc
#VERSION=4.35


# !!!!!!!!!!!!!!!!!!
# END CUSTOMIZATION
# !!!!!!!!!!!!!!!!!!

!IF "$(TARGETCPU)"=="X86" 
# the following flag is required by (eg) winnt.h, and is different from targetcpu

WCETARGETCPU=_X86_
# many errors with WCETARGETCPU=X86 or x86

# pdelaage : WCE msdocs says X86 for LDtgt, IX86 is for win32 PC platforms ! but many people use IX86 even in WCE context...
#LDTARGETCPU=IX86
LDTARGETCPU=X86
# following is a useless flag dealing with default libs : on WCE the default libs MUST BE FORCED to coredll and corelibc !
# the MS DOC of the clXXX commands are just wrong 
#MORECFLAGS=/ML
MORECFLAGS=/MT

# TODO : continue list for other targets : see wcecompat/wcedefs.mak for a good ref.
# see also openssl/util/pl/vc-32.pl, also link /?
# for LDTARGETCPU:    /MACHINE:{AM33|ARM|IA64|M32R|MIPS|MIPS16|MIPSFPU|MIPSFPU16|MIPSR41XX|SH3|SH3DSP|SH4|SH5|THUMB|X86}
# see wce/include/winnt.h for other "target architecture" flag

!ELSEIF "$(TARGETCPU)"=="emulator"
WCETARGETCPU=_X86_
LDTARGETCPU=X86
MORECFLAGS=/MT

!ELSEIF "$(TARGETCPU)"=="MIPS16" || "$(TARGETCPU)"=="MIPSII" || "$(TARGETCPU)"=="MIPSII_FP" || "$(TARGETCPU)"=="MIPSIV" || "$(TARGETCPU)"=="MIPSIV_FP"
#pdelaage : TO BE IMPROVED vs subtype of mips
WCETARGETCPU=_MIPS_
LDTARGETCPU=MIPS
MORECFLAGS=/DMIPS /MC

!ELSEIF "$(TARGETCPU)"=="SH3" || "$(TARGETCPU)"=="SH4"

WCETARGETCPU=SHx
LDTARGETCPU=$(TARGETCPU)
MORECFLAGS=/MC

!ELSE  
# default is ARM !
# !IF "$(TARGETCPU)"=="ARMV4" || "$(TARGETCPU)"=="ARMV4I" || "$(TARGETCPU)"=="ARMV4T"
# the following flag is required by (eg) winnt.h, and is different from targetcpu (armV4)

WCETARGETCPU=ARM
LDTARGETCPU=ARM
MORECFLAGS=/MC
!ENDIF
  
# ceutilsdir probably useless (nb : were tools from essemer; but ms delivers a cecopy anyway, see ms dld site)
CEUTILSDIR=..\..\ceutils
# "ce:" is not a correct location , but we never "make install"
DSTDIR=ce:\stunnel

# use MS env vars, as in wcecompat and openssl makefiles 
SDKDIR=$(SDKROOT)\$(OSVERSION)\$(PLATFORM)

INCLUDES=-I$(SSLDIR)\inc32 -I$(COMPATDIR)\include -I"$(SDKDIR)\include\$(TARGETCPU)"

# pdelaage ERROR ! ws2 is required, ie winsock2, instead of winsock, ie winsock1!
# pdelaage :   for X86 and other it appears that /MC or /ML flags are absurd, we always have to override runtime lib list to coredll and corelibc
#LIBS=libeay32.lib ssleay32.lib wcecompatex.lib winsock.lib
LIBS=/NODEFAULTLIB COREDLL.LIB CORELIBC.LIB ws2.lib wcecompatex.lib libeay32.lib ssleay32.lib  

# not correct because for armv4 cc is just clarm.exe. Moreover cc is already set in the ms wce$TARGETCPU.bat script, so it is not necessary to set it up here
#  CC=CL$(TARGETCPU)

# pdelaage 20101024 DEFINES=/DVERSION_MAJOR=$(VERSION_MAJOR) /DVERSION_MINOR=$(VERSION_MINOR) /DVERSION=\"$(VERSION)\"
# good but mingw does not accept dbl quotes DEFINES=/DHOST=\"$(TARGETCPU)-WCE-eVC-$(WCEVER)\"
DEFINES=/DHOST=\"$(TARGETCPU)-WCE-eVC-$(WCEVER)\"
# pdelaage /O1 /Oi more correct vs MS doc
CFLAGS=/nologo $(MORECFLAGS) /O1 /Oi /W3 /WX /GF /Gy $(DEFINES)  /D$(WCETARGETCPU) /D$(TARGETCPU) /DUNDER_CE=$(WCEVER) /D_WIN32_WCE=$(WCEVER) /DUNICODE -D_UNICODE $(INCLUDES)
#pdelaage 20101024 RFLAGS=/DVERSION=\"$(VERSION)\" $(INCLUDES)  
RFLAGS=$(DEFINES) $(INCLUDES)  
# LDFLAGS: since openssl >> 098a  (eg 098h) out32dll is out32dll_targetCPU for WCE
# pdelaage added $(TARGETCPU) in legacy Essemer/wcecompat libpath to ease multitarget compilation without recompiling everything
# this customized version is available here : http://delaage.pierre.free.fr/contrib/wcecompat/wcecompat12_patched.zip

LDFLAGS=/nologo /subsystem:windowsce,3.00 /machine:$(LDTARGETCPU) /libpath:"$(SDKDIR)\lib\$(TARGETCPU)" /libpath:"$(COMPATDIR)\lib\$(TARGETCPU)" /libpath:"$(SSLDIR)\out32dll_$(TARGETCPU)"

# Multi-target support for stunnel

SRC=..\src
OBJROOT=..\obj
OBJ=$(OBJROOT)\$(TARGETCPU)
BINROOT=..\bin
BIN=$(BINROOT)\$(TARGETCPU)

OBJS=$(OBJ)\stunnel.obj $(OBJ)\ssl.obj $(OBJ)\ctx.obj $(OBJ)\verify.obj \
  $(OBJ)\file.obj $(OBJ)\client.obj $(OBJ)\protocol.obj $(OBJ)\sthreads.obj \
  $(OBJ)\log.obj $(OBJ)\options.obj $(OBJ)\network.obj \
  $(OBJ)\resolver.obj \
  $(OBJ)\version.res

GUIOBJS=$(OBJ)\gui.obj $(OBJ)\resources.res
NOGUIOBJS=$(OBJ)\nogui.obj

{$(SRC)\}.c{$(OBJ)\}.obj:
	$(CC) $(CFLAGS) -Fo$@ -c $<

{$(SRC)\}.cpp{$(OBJ)\}.obj:
	$(CC) $(CFLAGS) -Fo$@ -c $<
	
{$(SRC)\}.rc{$(OBJ)\}.res:
	$(RC) $(RFLAGS) -fo$@ -r $<

all: makedirs $(BIN)\stunnel.exe $(BIN)\tstunnel.exe

makedirs: 
  -@ IF NOT EXIST $(OBJROOT) mkdir $(OBJROOT) >NUL 2>&1
  -@ IF NOT EXIST $(OBJ) mkdir $(OBJ) >NUL 2>&1
  -@ IF NOT EXIST $(BINROOT) mkdir $(BINROOT) >NUL 2>&1
  -@ IF NOT EXIST $(BIN) mkdir $(BIN) >NUL 2>&1

$(BIN)\stunnel.exe:$(OBJS) $(GUIOBJS)
	link $(LDFLAGS)  /out:$(BIN)\stunnel.exe $(LIBS) commctrl.lib $**

$(BIN)\tstunnel.exe:$(OBJS) $(NOGUIOBJS)
	link $(LDFLAGS)  /out:$(BIN)\tstunnel.exe $(LIBS) $**

# pdelaage added this to rebuild some things on version.h change
$(OBJ)\resources.res: $(SRC)\resources.rc $(SRC)\resources.h $(SRC)\version.h
$(OBJ)\version.res: $(SRC)\version.rc $(SRC)\version.h
$(OBJ)\gui.obj: $(SRC)\gui.c $(SRC)\version.h
$(OBJ)\stunnel.obj: $(SRC)\stunnel.c $(SRC)\version.h


#  20100926: pdelaage, changed location for openssl dll subdir, compliant with last openssl conventions,
#  Nota: now list of openssl dll has also much more files...but we do not use "make  install" for stunnel
# TODO 20100926: update all this ceutils stuff, or suppress it. ceutils come from essemer/wcecompat website.
# some tools can be found at MS website.

install: stunnel.exe tstunnel.exe
	$(CEUTILSDIR)\cemkdir $(DSTDIR) || echo Directory exists?
	$(CEUTILSDIR)\cecopy stunnel.exe $(DSTDIR)
	$(CEUTILSDIR)\cecopy tstunnel.exe $(DSTDIR)
	$(CEUTILSDIR)\cecopy $(SSLDIR)\out32dll_$(TARGETCPU)\libeay32.dll $(DSTDIR)
	$(CEUTILSDIR)\cecopy $(SSLDIR)\out32dll_$(TARGETCPU)\ssleay32.dll $(DSTDIR)

clean:
	-@ IF NOT "$(TARGETCPU)"=="" del $(OBJS) $(GUIOBJS) $(NOGUIOBJS) $(BIN)\stunnel.exe $(BIN)\tstunnel.exe   >NUL 2>&1
	-@ IF NOT "$(TARGETCPU)"=="" rmdir $(OBJ)   >NUL 2>&1
  -@ IF NOT "$(TARGETCPU)"=="" rmdir $(BIN)   >NUL 2>&1
