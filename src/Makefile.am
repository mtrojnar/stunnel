## Process this file with automake to produce Makefile.in

# File lists

common_headers = common.h prototypes.h
common_sources = file.c client.c log.c options.c protocol.c network.c resolver.c ssl.c ctx.c verify.c sthreads.c stunnel.c
unix_sources = pty.c libwrap.c
shared_sources = env.c
win32_sources = gui.c resources.h resources.rc stunnel.ico

# Unix executable

bin_PROGRAMS = stunnel
stunnel_SOURCES = $(common_headers) $(common_sources) $(unix_sources)

bin_SCRIPTS = stunnel3

# Unix shared library

pkglib_LTLIBRARIES = libstunnel.la
libstunnel_la_SOURCES = $(shared_sources)
libstunnel_la_LDFLAGS = -avoid-version

# Red Hat "by design" bug #82369

INCLUDES = -I/usr/kerberos/include

# Additional compiler flags

AM_CPPFLAGS = -DLIBDIR='"$(pkglibdir)"' -DCONFDIR='"$(sysconfdir)/stunnel"' -DPIDFILE='"$(localstatedir)/run/stunnel/stunnel.pid"'

# Win32 executable

EXTRA_DIST = stunnel.exe make.bat mingw.mak makece.bat evc.mak vc.mak nogui.c os2.mak
EXTRA_PROGRAMS = stunnel.exe
stunnel_exe_SOURCES =  $(common_headers) $(common_sources) $(win32_sources)

OPENSSLDIR=/usr/src/openssl-0.9.8l
WINCFLAGS=-O2 -Wall -I$(OPENSSLDIR)/include -DUSE_WIN32=1 -DVERSION=\"@VERSION@\"
WINLIBS=-L$(OPENSSLDIR) -lzdll -leay32 -lssl32 -lws2_32 -lgdi32 -mwindows

# OPENSSLDIR=/usr/src/openssl-0.9.7m-fips
# WINCFLAGS=-O2 -Wall -I$(OPENSSLDIR)/include -DUSE_WIN32=1 -DVERSION=\"@VERSION@\"
# WINLIBS=-L$(OPENSSLDIR) -lzdll -lcrypto -lssl -lws2_32 -lgdi32 -mwindows

# WINCFLAGS=-O2 -Wall -I/usr/src/openssl-0.9.7m/include -DUSE_WIN32=1 -DVERSION=\"@VERSION@\"
# WINLIBS=-L../../FIPS -leay32 -lssl32 -lws2_32 -lgdi32 -mwindows

WINOBJ=file.obj client.obj log.obj options.obj protocol.obj network.obj resolver.obj ssl.obj ctx.obj verify.obj sthreads.obj stunnel.obj gui.obj resources.obj
WINPREFIX=i586-mingw32msvc-
WINGCC=$(WINPREFIX)gcc
WINDRES=$(WINPREFIX)windres

SUFFIXES = .c .rc .obj

stunnel.exe: $(WINOBJ)
	$(WINGCC) -s -o stunnel.exe $(WINOBJ) $(WINLIBS)

%.obj: %.c $(common_headers)
	$(WINGCC) -c $(WINCFLAGS) -o $@ $<

resources.obj: resources.rc resources.h
	$(WINDRES) --define VERSION=\\\"@VERSION@\\\" --include-dir $(srcdir) $< $@

mostlyclean-local:
	-rm -f *.obj

