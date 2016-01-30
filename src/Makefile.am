## Process this file with automake to produce Makefile.in
# by Michal Trojnara 2015-2016

###############################################################################
# File lists                                                                  #
###############################################################################

common_headers = common.h prototypes.h version.h
common_sources = tls.c str.c file.c client.c log.c options.c protocol.c
common_sources += network.c resolver.c ssl.c ctx.c verify.c sthreads.c
common_sources += fd.c dhparam.c cron.c stunnel.c
unix_sources = pty.c libwrap.c ui_unix.c
shared_sources = env.c
win32_gui_sources = ui_win_gui.c resources.h resources.rc
win32_gui_sources += stunnel.ico active.ico error.ico idle.ico
win32_cli_sources = ui_win_cli.c

###############################################################################
# Generate a new set of DH parameters for each version                        #
###############################################################################

dhparam.c: version.h
	echo '#include "common.h"' >dhparam.c
	echo '#ifndef OPENSSL_NO_DH' >>dhparam.c
	echo '#define DN_new DH_new' >>dhparam.c
	openssl dhparam -noout -C 2048 >>dhparam.c
	echo '#endif /* OPENSSL_NO_DH */' >>dhparam.c

###############################################################################
# Unix executables and shared library                                         #
###############################################################################

bin_PROGRAMS = stunnel
stunnel_SOURCES = $(common_headers) $(common_sources) $(unix_sources)
bin_SCRIPTS = stunnel3

EXTRA_DIST = stunnel3.in
CLEANFILES = stunnel3

# Red Hat "by design" bug #82369
stunnel_CPPFLAGS = -I/usr/kerberos/include

# Additional preprocesor definitions
stunnel_CPPFLAGS += -I$(SSLDIR)/include
stunnel_CPPFLAGS += -DLIBDIR='"$(pkglibdir)"'
stunnel_CPPFLAGS += -DCONFDIR='"$(sysconfdir)/stunnel"'

# SSL library
stunnel_LDFLAGS = -L$(SSLDIR)/lib64 -L$(SSLDIR)/lib -lssl -lcrypto

# stunnel3 script
edit = sed \
	-e 's|@bindir[@]|$(bindir)|g'
stunnel3: Makefile
	$(edit) '$(srcdir)/$@.in' >$@
stunnel3: $(srcdir)/stunnel3.in

# Unix shared library
pkglib_LTLIBRARIES = libstunnel.la
libstunnel_la_SOURCES = $(shared_sources)
libstunnel_la_LDFLAGS = -avoid-version

###############################################################################
# Win32 executables                                                           #
###############################################################################

if AUTHOR_TESTS
# Just check if the programs can be built, don't perform any actual tests
check-local: mingw mingw64
endif

mingw:
	$(MAKE) -f $(srcdir)/mingw.mk srcdir=$(srcdir) win32_targetcpu=i686 win32_mingw=mingw
mingw64:
	$(MAKE) -f $(srcdir)/mingw.mk srcdir=$(srcdir) win32_targetcpu=x86_64 win32_mingw=mingw64
.PHONY: mingw mingw64

clean-local:
	rm -rf ../obj ../bin

# Remaining files to be included
EXTRA_DIST += $(win32_gui_sources) $(win32_cli_sources)
EXTRA_DIST += make.bat makece.bat makew32.bat
EXTRA_DIST += mingw.mk mingw.mak evc.mak vc.mak os2.mak
