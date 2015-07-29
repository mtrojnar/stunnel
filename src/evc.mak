# wce.mak for stunnel.exe by Michal Trojnara 2006-2012
# with help of Pierre Delaage <delaage.pierre@free.fr>
#
# DEFAULTLIB management: only 2 are necessary
# defaultlibS as given for CLxxx in the MS doc ARE WRONG

# !!!!!!!!!!!!!!
# CUSTOMIZE THIS according to your wcecompat and openssl directories
# !!!!!!!!!!!!!!

# Modify this to point to your actual openssl compile directory
# (You did already compile openssl, didn't you???)
SSLDIR=C:\Users\standard\Documents\Dvts\Contrib\openssl\v1.0.0a\patched3

# Note that we currently use a multi-target customized version of legacy Essemer/wcecompat lib
COMPATDIR=C:\Users\standard\Documents\Dvts\Contrib\wcecompat\v12\patchedX86

WCEVER=420

# !!!!!!!!!!!!!!!!!!
# END CUSTOMIZATION
# !!!!!!!!!!!!!!!!!!

!IF "$(TARGETCPU)"=="X86"
WCETARGETCPU=_X86_
LDTARGETCPU=X86
MORECFLAGS=/MT

# TODO: continue list for other targets : see wcecompat/wcedefs.mak for a good ref.
# see also openssl/util/pl/vc-32.pl, also link /?
# for LDTARGETCPU: /MACHINE:{AM33|ARM|IA64|M32R|MIPS|MIPS16|MIPSFPU|MIPSFPU16|MIPSR41XX|SH3|SH3DSP|SH4|SH5|THUMB|X86}
# see wce/include/winnt.h for other "target architecture" flag

!ELSEIF "$(TARGETCPU)"=="emulator"
WCETARGETCPU=_X86_
LDTARGETCPU=X86
MORECFLAGS=/MT

!ELSEIF "$(TARGETCPU)"=="MIPS16" || "$(TARGETCPU)"=="MIPSII" || "$(TARGETCPU)"=="MIPSII_FP" || "$(TARGETCPU)"=="MIPSIV" || "$(TARGETCPU)"=="MIPSIV_FP"
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
# for X86 and other it appears that /MC or /ML flags are absurd,
# we always have to override runtime lib list to coredll and corelibc
LIBS=/NODEFAULTLIB winsock.lib wcecompatex.lib libeay32.lib ssleay32.lib coredll.lib corelibc.lib

DEFINES=/DHOST=\"$(TARGETCPU)-WCE-eVC-$(WCEVER)\"
# /O1 /Oi more correct vs MS doc
CFLAGS=/nologo $(MORECFLAGS) /O1 /Oi /W3 /WX /GF /Gy $(DEFINES) /D$(WCETARGETCPU) /D$(TARGETCPU) /DUNDER_CE=$(WCEVER) /D_WIN32_WCE=$(WCEVER) /DUNICODE -D_UNICODE $(INCLUDES)
RFLAGS=$(DEFINES) $(INCLUDES)
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
	$(OBJ)\resolver.obj $(OBJ)\str.obj $(OBJ)\fd.obj

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

$(OBJ)\resources.res: $(SRC)\resources.rc $(SRC)\resources.h $(SRC)\version.h
$(OBJ)\gui.obj: $(SRC)\gui.c $(SRC)\version.h
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
	-@ IF NOT "$(TARGETCPU)"=="" del $(OBJS) $(GUIOBJS) $(NOGUIOBJS) $(BIN)\stunnel.exe $(BIN)\tstunnel.exe >NUL 2>&1
	-@ IF NOT "$(TARGETCPU)"=="" rmdir $(OBJ) >NUL 2>&1
	-@ IF NOT "$(TARGETCPU)"=="" rmdir $(BIN) >NUL 2>&1
