# File lists

common_headers = client.h common.h prototypes.h
common_sources = client.c log.c options.c protocol.c ssl.c sthreads.c stunnel.c
unix_sources = pty.c
shared_sources = env.c
win32_sources = gui.c resources.h resources.rc stunnel.ico

# Unix executable

sbin_PROGRAMS = stunnel
stunnel_SOURCES = $(common_headers) $(common_sources) $(unix_sources)

# Unix shared library

lib_LTLIBRARIES = libstunnel.la
libstunnel_la_SOURCES = $(shared_sources)
libstunnel_la_LDFLAGS = -version-info 0:0:0

# Win32 executable

EXTRA_DIST = stunnel.exe make.bat Makefile.w32
EXTRA_PROGRAMS = stunnel.exe
stunnel_exe_SOURCES =  $(common_headers) $(common_sources) $(win32_sources)

OPENSSLDIR=/usr/src/openssl-0.9.6g
WINCFLAGS=-O2 -Wall -I$(OPENSSLDIR)/outinc \
	-DUSE_WIN32=1 -DHAVE_OPENSSL=1 -DVERSION=\"@VERSION@\"
WINLIBS=-L$(OPENSSLDIR)/out -leay32 -lssl32 -lwsock32 -lgdi32 -mwindows
WINOBJ=client.obj log.obj options.obj protocol.obj ssl.obj sthreads.obj \
	stunnel.obj gui.obj resources.obj
WINGCC=i586-mingw32msvc-gcc
WINDRES=i586-mingw32msvc-windres

SUFFIXES = .c .rc .obj

stunnel.exe: $(WINOBJ)
	$(WINGCC) -s -o stunnel.exe $(WINOBJ) $(WINLIBS)

.c.obj: $(common_headers)
	$(WINGCC) $(WINCFLAGS) -c $< -o $@

.rc.obj:
	$(WINDRES) --include-dir $(srcdir) $< $@

mostlyclean-local:
	-rm -f *.obj

