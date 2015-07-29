## Process this file with automake to produce Makefile.in

# File lists

common_headers = common.h prototypes.h
common_sources = file.c client.c log.c options.c protocol.c \
    network.c resolver.c ssl.c ctx.c sthreads.c stunnel.c
unix_sources = pty.c
shared_sources = env.c
win32_sources = gui.c resources.h resources.rc stunnel.ico

# Unix executable

sbin_PROGRAMS = stunnel
stunnel_SOURCES = $(common_headers) $(common_sources) $(unix_sources)

sbin_SCRIPTS = stunnel3

# Unix shared library

lib_LTLIBRARIES = libstunnel.la
libstunnel_la_SOURCES = $(shared_sources)
libstunnel_la_LDFLAGS = -avoid-version

# Red Hat "by design" bug #82369

INCLUDES = -I/usr/kerberos/include

# Additional compiler flags

AM_CPPFLAGS = -DLIBDIR='"$(libdir)"' -DCONFDIR='"$(sysconfdir)/stunnel"' -DPIDFILE='"$(prefix)/var/run/stunnel/stunnel.pid"'

# Win32 executable

EXTRA_DIST = stunnel.exe make.bat mingw.mak makece.bat evc.mak vc.mak nogui.c
EXTRA_PROGRAMS = stunnel.exe
stunnel_exe_SOURCES =  $(common_headers) $(common_sources) $(win32_sources)
# dist-hook: stunnel.exe
# 	cp -p stunnel.exe $(distdir)/../

OPENSSLDIR=/usr/src/openssl-0.9.7i
WINCFLAGS=-O2 -Wall -I$(OPENSSLDIR)/outinc \
	-DUSE_WIN32=1 -DVERSION=\"@VERSION@\"
WINLIBS=-L$(OPENSSLDIR)/out -lzdll -leay32 -lssl32 -lws2_32 -lgdi32 -mwindows
WINOBJ=file.obj client.obj log.obj options.obj protocol.obj network.obj \
	resolver.obj ssl.obj ctx.obj sthreads.obj stunnel.obj gui.obj resources.obj
WINGCC=i586-mingw32msvc-gcc
WINDRES=i586-mingw32msvc-windres

SUFFIXES = .c .rc .obj

stunnel.exe: $(WINOBJ)
	$(WINGCC) -s -o stunnel.exe $(WINOBJ) $(WINLIBS)

.c.obj: $(common_headers)
	$(WINGCC) $(WINCFLAGS) -c $< -o $@

.rc.obj:
	$(WINDRES) --define VERSION=\"@VERSION@\" --include-dir $(srcdir) $< $@

mostlyclean-local:
	-rm -f *.obj

