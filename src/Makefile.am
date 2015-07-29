## Process this file with automake to produce Makefile.in

# File lists
common_headers = common.h prototypes.h version.h
common_sources = tls.c str.c file.c client.c log.c options.c protocol.c
common_sources += network.c resolver.c ssl.c ctx.c verify.c sthreads.c
common_sources += fd.c dhparam.c cron.c stunnel.c
unix_sources = pty.c libwrap.c ui_unix.c
shared_sources = env.c
win32_gui_sources = ui_win_gui.c resources.h resources.rc
win32_gui_sources += stunnel.ico active.ico error.ico idle.ico
win32_cli_sources = ui_win_cli.c

# Unix executables
bin_PROGRAMS = stunnel
stunnel_SOURCES = $(common_headers) $(common_sources) $(unix_sources)
bin_SCRIPTS = stunnel3

EXTRA_DIST = stunnel3.in
CLEANFILES = stunnel3

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

# Generate a new set of DH parameters for each version
dhparam.c: version.h
	echo '#include "common.h"' >dhparam.c
	echo '#ifndef OPENSSL_NO_DH' >>dhparam.c
	echo '#define DN_new DH_new' >>dhparam.c
	openssl dhparam -noout -C 2048 >>dhparam.c
	echo '#endif /* OPENSSL_NO_DH */' >>dhparam.c

# SSL library
stunnel_LDFLAGS = -L$(SSLDIR)/lib64 -L$(SSLDIR)/lib -lssl -lcrypto

# Win32 executables

# Just check if the programs can be built, don't perform any actual tests
check_PROGRAMS = stunnel.exe tstunnel.exe
stunnel_exe_SOURCES = $(common_headers) $(common_sources) $(win32_gui_sources)
tstunnel_exe_SOURCES = $(common_headers) $(common_sources) $(win32_cli_sources)

# Remaining files to be included
# EXTRA_PROGRAMS = stunnel.exe tstunnel.exe
# EXTRA_DIST += $(win32_gui_sources) $(win32_cli_sources)
EXTRA_DIST += make.bat makece.bat makew32.bat
EXTRA_DIST += mingw.mak evc.mak vc.mak os2.mak

# win32_ssl_dir = /usr/src/openssl-0.9.8u-fips
# win32_cppflags = -I$(win32_ssl_dir)/inc32
win32_ssl_dir = /usr/src/openssl-1.0.2d-i686
win32_cppflags = -I$(win32_ssl_dir)/include
win32_cflags = -mthreads -fstack-protector -O2
win32_cflags += -Wall -Wextra -Wpedantic -Wformat=2 -Wconversion -Wno-long-long
win32_cflags += -D_FORTIFY_SOURCE=2 -DUNICODE -D_UNICODE
win32_ldflags = -mthreads -fstack-protector -s

win32_common_libs = -lws2_32
win32_ssl_libs = -L$(win32_ssl_dir) -lcrypto -lssl
win32_gui_libs = $(win32_common_libs) -lgdi32 -lpsapi $(win32_ssl_libs)
win32_cli_libs = $(win32_common_libs) $(win32_ssl_libs)

win32_common_objs = tls.obj str.obj file.obj client.obj log.obj options.obj
win32_common_objs += protocol.obj network.obj resolver.obj ssl.obj ctx.obj
win32_common_objs += verify.obj sthreads.obj fd.obj dhparam.obj cron.obj
win32_common_objs += stunnel.obj
win32_gui_objs = ui_win_gui.obj resources.obj
win32_cli_objs = ui_win_cli.obj

win32_prefix = i686-w64-mingw32-
win32_cc = $(win32_prefix)gcc
win32_windres = $(win32_prefix)windres

MOSTLYCLEANFILES = $(win32_common_objs) $(win32_gui_objs) $(win32_cli_objs)
CLEANFILES += stunnel.exe tstunnel.exe

# dist-hook: stunnel.exe tstunnel.exe

# SUFFIXES = .c .rc .obj

stunnel.exe: $(win32_common_objs) $(win32_gui_objs)
	$(win32_cc) -mwindows $(win32_ldflags) -o stunnel.exe $(win32_common_objs) $(win32_gui_objs) $(win32_gui_libs)

tstunnel.exe: $(win32_common_objs) $(win32_cli_objs)
	$(win32_cc) $(win32_ldflags) -o tstunnel.exe $(win32_common_objs) $(win32_cli_objs) $(win32_cli_libs)

%.obj: %.c $(common_headers)
	$(win32_cc) -c $(win32_cppflags) $(win32_cflags) -o $@ $<

resources.obj: resources.rc resources.h version.h
	$(win32_windres) --include-dir $(srcdir) $< $@

edit = sed \
	-e 's|@bindir[@]|$(bindir)|g'

stunnel3: Makefile
	$(edit) '$(srcdir)/$@.in' >$@

stunnel3: $(srcdir)/stunnel3.in
