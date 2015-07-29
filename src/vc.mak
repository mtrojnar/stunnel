# Simple Makefile.w32 for stunnel.exe by Michal Trojnara 1998-2006
#
# Modified by David Gillingham (dgillingham@gmail.com) for Visual
# Studio

# Modify this to point to your actual openssl compile directory
# (You did already compile openssl, didn't you???)
SSLDIR=..\openssl-0.9.7j

OBJS=stunnel.obj ssl.obj ctx.obj file.obj client.obj protocol.obj \
	sthreads.obj log.obj options.obj network.obj resolver.obj \
	gui.obj
	
CC=cl
CFLAGS=-MD -W3 -Ox -O2 -Ob2 -Gs0 -GF -Gy -GL -nologo \
	-I"$(SSLDIR)\inc32" $(DEFINES)
DEFINES=-DUSE_WIN32 -D_CRT_SECURE_NO_DEPRECATE \
	-D_CRT_NONSTDC_NO_DEPRECATE -DHAVE_GETADDRINFO \
	-DHAVE_GETNAMEINFO -D_MBCS

LINK=link
LDFLAGS=-INCREMENTAL:NO -NOLOGO -SUBSYSTEM:WINDOWS -OPT:REF \
	-OPT:ICF -LTCG -MACHINE:X86 -ERRORREPORT:PROMPT
LIBS=-LIBPATH:"$(SSLDIR)\out32dll" wsock32.lib ssleay32.lib \
	libeay32.lib user32.lib gdi32.lib shell32.lib comdlg32.lib \
	advapi32.lib

all: stunnel.exe

clean:
	del $(OBJS) resources.res
	del *.manifest
	del stunnel.exe

stunnel.exe: $(OBJS) resources.res
	$(LINK) $(LDFLAGS) $(LIBS) -OUT:$@ $**
	IF EXIST $@.manifest mt -nologo -manifest $@.manifest -outputresource:$@;1

resources.res: resources.rc resources.h stunnel.ico
	rc -fo $@ resources.rc

$(OBJS): *.h vc.mak
