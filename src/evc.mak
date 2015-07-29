# wce.mak for stunnel.exe by Michal Trojnara 2006-2012
# with help of Pierre Delaage <delaage.pierre@free.fr>
# pdelaage 20140610 : added UNICODE optional FLAG, always ACTIVE on WCE because of poor ANSI support
# pdelaage 20140610 : added _WIN32_WCE flag for RC compilation, to preprocess out "HELP" unsupported menu flag on WCE
# pdelaage 20140610 : ws2 lib is required to get WSAGetLastError routine (absent from winsock lib)
# pdelaage 20140610 : /Dx86 flag required for X86/Emulator targets, to get proper definition for InterlockedExchange
# pdelaage 20140610 : /MT flag is NON-SENSE for X86-WCE platforms, it is only meaningful for X86-W32-Desktop.
#                     for X86-WCE targets, although compiler "cl.exe" is REALLY the same as desktop W32 VS6 C++ compiler,
#                     the MT flags relating to LIBCMT is useless BECAUSE LIBCMT does NOT exist on WCE. No msvcrt on WCE either...

# pdelaage 20140610 :  Note on /MC flag 
# For other targets than X86/Emulator, /MC flag is redundant with "/nodefaultlib coredll.lib corelibc.lib" LD lib list.
# For << X86 / Emulator >> target, as the cl.exe compiler IS the SAME as the standard VS6.0 C++ compiler for Desktop Pentium processor, 
# /MC flag is in fact NOT existing, thus requiring an explicit linking with core libs by using : 
# /NODEFAULTLIB coredll.lib corelibc.lib,
# something that is correct for any WCE target, X86 and other, and leading /MC flag to be useless ALSO for other target than X86.


#
# DEFAULTLIB management: only 2 are necessary
# defaultlibS, as given for CLxxx in the MS doc, ARE WRONG

# !!!!!!!!!!!!!!
# CUSTOMIZE THIS according to your wcecompat and openssl directories
# !!!!!!!!!!!!!!

# Modify this to point to your actual openssl compile directory
# (You did already compile openssl, didn't you???)
SSLDIR=C:\Users\pdelaage\Dvts\Contrib\openssl

# Note that we currently use a multi-target customized version of legacy Essemer/wcecompat lib
COMPATDIR=C:\Users\pdelaage\Dvts\Contrib\wcecompat\v12\patched3emu

WCEVER=420

# !!!!!!!!!!!!!!!!!!
# END CUSTOMIZATION
# !!!!!!!!!!!!!!!!!!

!IF "$(TARGETCPU)"=="X86"
WCETARGETCPU=_X86_
LDTARGETCPU=X86
#pdelaage 20140621 /Dx86 for inline defs of InterlockedExchange inline in winbase.h; no more /MT
MORECFLAGS=/Dx86

# TODO: continue list for other targets : see wcecompat/wcedefs.mak for a good ref.
# see also openssl/util/pl/vc-32.pl, also link /?
# for LDTARGETCPU: /MACHINE:{AM33|ARM|IA64|M32R|MIPS|MIPS16|MIPSFPU|MIPSFPU16|MIPSR41XX|SH3|SH3DSP|SH4|SH5|THUMB|X86}
# see wce/include/winnt.h for other "target architecture" flag

!ELSEIF "$(TARGETCPU)"=="emulator"
WCETARGETCPU=_X86_
LDTARGETCPU=X86
#pdelaage 20140621 /Dx86 for inline defs of InterlockedExchange inline in winbase.h; no more /MT
MORECFLAGS=/Dx86

!ELSEIF "$(TARGETCPU)"=="MIPS16" || "$(TARGETCPU)"=="MIPSII" || "$(TARGETCPU)"=="MIPSII_FP" || "$(TARGETCPU)"=="MIPSIV" || "$(TARGETCPU)"=="MIPSIV_FP"
WCETARGETCPU=_MIPS_
LDTARGETCPU=MIPS
#pdelaage 20140621  no more /MC required
MORECFLAGS=/DMIPS

!ELSEIF "$(TARGETCPU)"=="SH3" || "$(TARGETCPU)"=="SH4"
WCETARGETCPU=SHx
LDTARGETCPU=$(TARGETCPU)
#pdelaage 20140621  no more /MC required
MORECFLAGS=

!ELSE
# default is ARM !
# !IF "$(TARGETCPU)"=="ARMV4" || "$(TARGETCPU)"=="ARMV4I" || "$(TARGETCPU)"=="ARMV4T"
# the following flag is required by (eg) winnt.h, and is different from targetcpu (armV4)
WCETARGETCPU=ARM
LDTARGETCPU=ARM
#pdelaage 20140621  no more /MC required
MORECFLAGS=
!ENDIF

# ceutilsdir probably useless (nb : were tools from essemer; but ms delivers a cecopy anyway, see ms dld site)
CEUTILSDIR=..\..\ceutils
# "ce:" is not a correct location , but we never "make install"
DSTDIR=ce:\stunnel
# use MS env vars, as in wcecompat and openssl makefiles
SDKDIR=$(SDKROOT)\$(OSVERSION)\$(PLATFORM)
INCLUDES=-I$(SSLDIR)\inc32 -I$(COMPATDIR)\include -I"$(SDKDIR)\include\$(TARGETCPU)"
# for X86 and other it appears that /MC or /ML flags are absurd,
# we always have to override runtime lib list to coredll and corelibc
#LIBS=/NODEFAULTLIB winsock.lib wcecompatex.lib libeay32.lib ssleay32.lib coredll.lib corelibc.lib
LIBS=/NODEFAULTLIB ws2.lib      wcecompatex.lib libeay32.lib ssleay32.lib coredll.lib corelibc.lib

DEFINES=/DHOST=\"$(TARGETCPU)-WCE-eVC-$(WCEVER)\"
# pdelaage 20140610 added unicode flag : ALWAYS ACTIVE on WCE, because of poor ANSI support by the MS SDK
UNICODEFLAGS=/DUNICODE -D_UNICODE
# /O1 /Oi more correct vs MS doc
CFLAGS=/nologo $(MORECFLAGS) /O1 /Oi /W3 /WX /GF /Gy $(DEFINES) /D$(WCETARGETCPU) /D$(TARGETCPU) /DUNDER_CE=$(WCEVER) /D_WIN32_WCE=$(WCEVER) $(UNICODEFLAGS) $(INCLUDES)
# pdelaage 20140610 : RC compilation requires D_WIN32_WCE flag to comment out unsupported "HELP" flag in menu definition, in resources.rc file
RFLAGS=$(DEFINES) /D_WIN32_WCE=$(WCEVER) $(INCLUDES)

# LDFLAGS: since openssl >> 098a (eg 098h) out32dll is out32dll_targetCPU for WCE
# delaage added $(TARGETCPU) in legacy Essemer/wcecompat libpath
# to ease multitarget compilation without recompiling everything
# this customized version is available on:
# http://delaage.pierre.free.fr/contrib/wcecompat/wcecompat12_patched.zip

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
	$(OBJ)\resolver.obj $(OBJ)\str.obj $(OBJ)\tls.obj $(OBJ)\fd.obj

GUIOBJS=$(OBJ)\ui_win_gui.obj $(OBJ)\resources.res
CLIOBJS=$(OBJ)\ui_win_cli.obj

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

$(BIN)\tstunnel.exe:$(OBJS) $(CLIOBJS)
	link $(LDFLAGS)  /out:$(BIN)\tstunnel.exe $(LIBS) $**

$(OBJ)\resources.res: $(SRC)\resources.rc $(SRC)\resources.h $(SRC)\version.h
$(OBJ)\ui_win_gui.obj: $(SRC)\ui_win_gui.c $(SRC)\version.h
$(OBJ)\stunnel.obj: $(SRC)\stunnel.c $(SRC)\version.h

# now list of openssl dll has more files,
# but we do not use "make install" for stunnel
# ceutils come from essemer/wcecompat website
# some tools can be found at MS website
# TODO: update all this ceutils stuff, or suppress it

install: stunnel.exe tstunnel.exe
	$(CEUTILSDIR)\cemkdir $(DSTDIR) || echo Directory exists?
	$(CEUTILSDIR)\cecopy stunnel.exe $(DSTDIR)
	$(CEUTILSDIR)\cecopy tstunnel.exe $(DSTDIR)
	$(CEUTILSDIR)\cecopy $(SSLDIR)\out32dll_$(TARGETCPU)\libeay32.dll $(DSTDIR)
	$(CEUTILSDIR)\cecopy $(SSLDIR)\out32dll_$(TARGETCPU)\ssleay32.dll $(DSTDIR)

clean:
	-@ IF NOT "$(TARGETCPU)"=="" del $(OBJS) $(GUIOBJS) $(CLIOBJS) $(BIN)\stunnel.exe $(BIN)\tstunnel.exe >NUL 2>&1
	-@ IF NOT "$(TARGETCPU)"=="" rmdir $(OBJ) >NUL 2>&1
	-@ IF NOT "$(TARGETCPU)"=="" rmdir $(BIN) >NUL 2>&1
