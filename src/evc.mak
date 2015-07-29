# wce.mak for stunnel.exe by Michal Trojnara 2006
#

WCEVER=300

# Modify this to point to your actual openssl compile directory
# (You did already compile openssl, didn't you???)
SSLDIR=..\..\build\openssl-0.9.8a
COMPATDIR=..\..\build\wcecompat
CEUTILSDIR=..\..\ceutils
DSTDIR=ce:\stunnel
SDKDIR=C:\Windows CE Tools\wce$(WCEVER)\Pocket PC 2002

INCLUDES=-I$(SSLDIR)/inc32 -I$(COMPATDIR)\include -I"$(SDKDIR)\include"
LIBS=libeay32.lib ssleay32.lib wcecompatex.lib winsock.lib

CC=CL$(TARGETCPU)
CFLAGS=/nologo /MC /O1i /W3 /WX /GF /Gy /DHOST=\"$(TARGETCPU)-WCE-eVC-$(WCEVER)\" /D$(TARGETCPU) /DUNDER_CE=$(WCEVER) /D_WIN32_WCE=$(WCEVER) /DUNICODE -D_UNICODE $(INCLUDES)
RFLAGS=$(INCLUDES)
LDFLAGS=/nologo /subsystem:windowsce,3.00 /machine:ARM /libpath:"$(SDKDIR)\lib\$(TARGETCPU)" /libpath:"$(COMPATDIR)\lib" /libpath:"$(SSLDIR)\out32dll"

OBJS=stunnel.obj ssl.obj ctx.obj file.obj client.obj protocol.obj sthreads.obj log.obj options.obj network.obj resolver.obj
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

