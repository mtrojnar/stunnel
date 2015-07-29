# wce.mak for stunnel.exe by Michal Trojnara 2006-2009
#

WCEVER=420
# the following flag is required by (eg) winnt.h, and is different from targetcpu (armV4)
WCETARGETCPU=ARM

# Modify this to point to your actual openssl compile directory
# (You did already compile openssl, didn't you???)
SSLDIR=C:\Users\standard\Documents\Dvts\Contrib\openssl\openssl-0.9.8-stable-SNAP-20090102\openssl-0.9.8-stable-SNAP-20090102
COMPATDIR=C:\Users\standard\Documents\Dvts\openssl\build\wcecompat
# ceutilsdir probably useless
CEUTILSDIR=..\..\ceutils
# "ce:" is not a correct location , but we never "make install"
DSTDIR=ce:\stunnel

SDKDIR="C:\Progra~1\Micros~2\wce$(WCEVER)\standardsdk"

# eroneous path for sdkdir INCLUDES=-I$(SSLDIR)/inc32 -I$(COMPATDIR)\include -I"$(SDKDIR)\include"
INCLUDES=-I$(SSLDIR)\inc32 -I$(COMPATDIR)\include -I"$(SDKDIR)\include\$(TARGETCPU)"
LIBS=libeay32.lib ssleay32.lib wcecompatex.lib winsock.lib

# not correct because for armv4 cc is just clarm.exe. Moreover cc is already set in the ms wce$TARGETCPU.bat script, so it is not necessary to set it up here
#  CC=CL$(TARGETCPU)

VERSION=4.29
DEFINES=/DVERSION=\"$(VERSION)\"
CFLAGS=/nologo /MC /O1i /W3 /WX /GF /Gy $(DEFINES) /DHOST=\"$(TARGETCPU)-WCE-eVC-$(WCEVER)\" /D$(WCETARGETCPU) /D$(TARGETCPU) /DUNDER_CE=$(WCEVER) /D_WIN32_WCE=$(WCEVER) /DUNICODE -D_UNICODE $(INCLUDES)
RFLAGS=/DVERSION=\"$(VERSION)\" $(INCLUDES)  
# LDFLAGS: since openssl >> 098a  (eg 098h) out32dll is out32dll_targetCPU
LDFLAGS=/nologo /subsystem:windowsce,3.00 /machine:ARM /libpath:"$(SDKDIR)\lib\$(TARGETCPU)" /libpath:"$(COMPATDIR)\lib" /libpath:"$(SSLDIR)\out32dll_$(TARGETCPU)"

OBJS=stunnel.obj ssl.obj ctx.obj verify.obj file.obj client.obj protocol.obj sthreads.obj log.obj options.obj network.obj resolver.obj
GUIOBJS=gui.obj resources.res
NOGUIOBJS=nogui.obj

all: stunnel.exe tstunnel.exe

stunnel.exe: $(OBJS) $(GUIOBJS)
	link $(LDFLAGS) /out:stunnel.exe $(LIBS) commctrl.lib $(OBJS) $(GUIOBJS)

tstunnel.exe: $(OBJS) $(NOGUIOBJS)
	link $(LDFLAGS) /out:tstunnel.exe $(LIBS) $(OBJS) $(NOGUIOBJS)

resources.res: resources.rc resources.h

install: stunnel.exe tstunnel.exe
	$(CEUTILSDIR)\cemkdir $(DSTDIR) || echo Directory exists?
	$(CEUTILSDIR)\cecopy stunnel.exe $(DSTDIR)
	$(CEUTILSDIR)\cecopy tstunnel.exe $(DSTDIR)
	$(CEUTILSDIR)\cecopy $(SSLDIR)\out32dll\libeay32.dll $(DSTDIR)
	$(CEUTILSDIR)\cecopy $(SSLDIR)\out32dll\ssleay32.dll $(DSTDIR)

clean:
	del $(OBJS) $(GUIOBJS) $(NOGUIOBJS) stunnel.exe tstunnel.exe

