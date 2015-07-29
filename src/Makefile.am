## Process this file with automake to produce Makefile.in

# File lists
common_headers = common.h prototypes.h version.h
common_sources = str.c file.c client.c log.c options.c protocol.c network.c
common_sources += resolver.c ssl.c ctx.c verify.c sthreads.c fd.c stunnel.c
unix_sources = pty.c libwrap.c
shared_sources = env.c
win32_sources = gui.c resources.h resources.rc stunnel.ico

# Unix executables
bin_PROGRAMS = stunnel
stunnel_SOURCES = $(common_headers) $(common_sources) $(unix_sources)
bin_SCRIPTS = stunnel3

# Unix shared library
pkglib_LTLIBRARIES = libstunnel.la
libstunnel_la_SOURCES = $(shared_sources)
libstunnel_la_LDFLAGS = -avoid-version

# Red Hat "by design" bug #82369
stunnel_CPPFLAGS = -I/usr/kerberos/include

# Additional preprocesor definitions
stunnel_CPPFLAGS += -I$(SSLDIR)/include
stunnel_CPPFLAGS += -DLIBDIR='"$(pkglibdir)"'
stunnel_CPPFLAGS += -DCONFDIR='"$(sysconfdir)/stunnel"'
stunnel_CPPFLAGS += -DPIDFILE='"$(localstatedir)/run/stunnel/stunnel.pid"'

# SSL library
stunnel_LDFLAGS = -L$(SSLDIR)/lib64 -L$(SSLDIR)/lib -lssl -lcrypto

# Win32 executable
EXTRA_DIST = make.bat makece.bat makew32.bat
EXTRA_DIST += mingw.mak evc.mak vc.mak os2.mak
EXTRA_PROGRAMS = stunnel.exe tstunnel.exe
stunnel_exe_SOURCES = $(common_headers) $(common_sources) $(win32_sources)
tstunnel_exe_SOURCES = $(common_headers) $(common_sources) nogui.c

# OPENSSLDIR = /usr/src/openssl-0.9.8u-fips
# WINCPPFLAGS = -I$(OPENSSLDIR)/inc32
OPENSSLDIR = /usr/src/openssl-1.0.2a-i686
WINCPPFLAGS = -I$(OPENSSLDIR)/include
WINCFLAGS = -mthreads -fstack-protector -O2 -Wall -Wextra -Wno-long-long -pedantic
WINLDFLAGS = -mthreads -fstack-protector -s
WINLIBS = -L$(OPENSSLDIR) -lcrypto -lssl -lpsapi -lws2_32 -lgdi32
# WINLIBS = -L$(OPENSSLDIR) -lzdll -lcrypto.dll -lssl.dll -lpsapi -lws2_32 -lgdi32
# WINLIBS = -L$(OPENSSLDIR) -lzdll -lcrypto -lssl -lpsapi -lws2_32 -lgdi32
WINOBJ = str.obj file.obj client.obj log.obj options.obj protocol.obj
WINOBJ += network.obj resolver.obj ssl.obj ctx.obj verify.obj sthreads.obj
WINOBJ += fd.obj stunnel.obj
WINGUIOBJ = $(WINOBJ) gui.obj resources.obj
WINNOGUIOBJ = $(WINOBJ) nogui.obj
WINPREFIX = i686-w64-mingw32-
WINGCC = $(WINPREFIX)gcc
WINDRES = $(WINPREFIX)windres

dist-hook: stunnel.exe tstunnel.exe

distclean-local:
	rm -f stunnel.exe tstunnel.exe

# SUFFIXES = .c .rc .obj

stunnel.exe: $(WINGUIOBJ)
	$(WINGCC) -mwindows $(WINLDFLAGS) -o stunnel.exe $(WINGUIOBJ) $(WINLIBS)

tstunnel.exe: $(WINNOGUIOBJ)
	$(WINGCC) $(WINLDFLAGS) -o tstunnel.exe $(WINNOGUIOBJ) $(WINLIBS)

%.obj: %.c $(common_headers)
	$(WINGCC) -c $(WINCPPFLAGS) $(WINCFLAGS) -o $@ $<

resources.obj: resources.rc resources.h version.h
	$(WINDRES) --include-dir $(srcdir) $< $@

mostlyclean-local:
	-rm -f *.obj

