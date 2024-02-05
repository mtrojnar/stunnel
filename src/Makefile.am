## Process this file with automake to produce Makefile.in
# by Michal Trojnara 1998-2024

###############################################################################
# File lists                                                                  #
###############################################################################

common_headers = common.h prototypes.h version.h
common_sources = tls.c str.c file.c client.c log.c options.c protocol.c
common_sources += network.c resolver.c ssl.c ctx.c verify.c sthreads.c
common_sources += ocsp.c fd.c dhparam.c cron.c stunnel.c
unix_sources = pty.c libwrap.c ui_unix.c
shared_sources = env.c
win32_gui_sources = ui_win_gui.c resources.h resources.rc
win32_gui_sources += stunnel.ico active.ico error.ico idle.ico
win32_cli_sources = ui_win_cli.c

###############################################################################
# Unix executables and shared library                                         #
###############################################################################

bin_PROGRAMS = stunnel
stunnel_SOURCES = $(common_headers) $(common_sources) $(unix_sources)
bin_SCRIPTS = stunnel3

EXTRA_DIST = stunnel3.in
CLEANFILES = stunnel3

# Red Hat "by design" bug #82369
stunnel_CPPFLAGS = -I$(SYSROOT)/usr/kerberos/include

# Additional preprocessor definitions
stunnel_CPPFLAGS += -I$(SSLDIR)/include
stunnel_CPPFLAGS += -DLIBDIR='"$(pkglibdir)"'
stunnel_CPPFLAGS += -DCONFDIR='"$(sysconfdir)/stunnel"'

# TLS library
stunnel_LDFLAGS = -L$(SSLDIR)/lib64 -L$(SSLDIR)/lib -lssl -lcrypto

# Apply substitutions
edit = sed \
	-e 's|@bindir[@]|$(bindir)|g' \
	-e 's|@PACKAGE_VERSION[@]|$(PACKAGE_VERSION)|g'
stunnel3 os2.mak: Makefile
	$(edit) '$(srcdir)/$@.in' >$@
stunnel3: $(srcdir)/stunnel3.in
os2.mak: $(srcdir)/os2.mak.in

# Unix shared library
pkglib_LTLIBRARIES = libstunnel.la
libstunnel_la_SOURCES = $(shared_sources)
libstunnel_la_LDFLAGS = -avoid-version

###############################################################################
# Win32 executables                                                           #
###############################################################################

mingw:
	$(MAKE) -f $(srcdir)/mingw.mk srcdir=$(srcdir) win32_arch=win32 win32_targetcpu=i686 win32_mingw=mingw

mingw64:
	$(MAKE) -f $(srcdir)/mingw.mk srcdir=$(srcdir) win32_arch=win64 win32_targetcpu=x86_64 win32_mingw=mingw64

.PHONY: mingw mingw64

clean-local:
	rm -rf ../obj ../bin

###############################################################################
# Remaining files to be included                                              #
###############################################################################

dist_noinst_DATA = os2.mak
EXTRA_DIST += os2.mak.in
CLEANFILES += os2.mak

EXTRA_DIST += $(win32_gui_sources) $(win32_cli_sources)
EXTRA_DIST += make.bat makece.bat makew32.bat
EXTRA_DIST += mingw.mk mingw.mak evc.mak vc.mak
