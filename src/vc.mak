# vc.mak by Michal Trojnara 1998-2009
# with help of David Gillingham <dgillingham@gmail.com>

# Modify this to point to your actual openssl compile directory
# (You did already compile openssl, didn't you?)
SSLDIR=..\..\openssl-0.9.8l
VERSION=4.29

OBJS=stunnel.obj ssl.obj ctx.obj verify.obj file.obj client.obj \
	protocol.obj sthreads.obj log.obj options.obj network.obj \
	resolver.obj gui.obj
	
CC=cl
CFLAGS=/MD /W3 /Ox /O2 /Ob2 /Gs0 /GF /Gy /GL /nologo \
	/I"$(SSLDIR)\inc32" $(DEFINES)
DEFINES=/DUSE_WIN32 /D_CRT_SECURE_NO_DEPRECATE \
	/D_CRT_NONSTDC_NO_DEPRECATE /D_MBCS /DVERSION=\"$(VERSION)\"

LINK=link
LDFLAGS=/INCREMENTAL:NO /NOLOGO /SUBSYSTEM:WINDOWS /OPT:REF \
	/OPT:ICF /LTCG /MACHINE:X86 /ERRORREPORT:PROMPT
LIBS=/LIBPATH:"$(SSLDIR)\out32dll" wsock32.lib ssleay32.lib \
	libeay32.lib user32.lib gdi32.lib shell32.lib comdlg32.lib \
	advapi32.lib

all: stunnel.exe

clean:
	del $(OBJS) resources.res
	del *.manifest
	del stunnel.exe

stunnel.exe: $(OBJS) resources.res
	$(LINK) $(LDFLAGS) $(LIBS) /OUT:$@ $**
	IF EXIST $@.manifest \
		mt -nologo -manifest $@.manifest -outputresource:$@;1

resources.res: resources.rc resources.h version.h stunnel.ico
	rc /dVERSION=\"$(VERSION)\" /fo $@ resources.rc

$(OBJS): *.h vc.mak

# end of vc.mak
