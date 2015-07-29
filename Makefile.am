## Process this file with automake to produce Makefile.in

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = src doc tools

LIBTOOL_DEPS = @LIBTOOL_DEPS@
libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status libtool

EXTRA_DIST = PORTS BUGS COPYRIGHT.GPL CREDITS
EXTRA_DIST += INSTALL.W32 INSTALL.WCE INSTALL.FIPS
EXTRA_DIST += build-android.sh

docdir = $(datadir)/doc/stunnel
doc_DATA = INSTALL README TODO COPYING AUTHORS ChangeLog
doc_DATA += PORTS BUGS COPYRIGHT.GPL CREDITS
doc_DATA += INSTALL.W32 INSTALL.WCE INSTALL.FIPS

distcleancheck_listfiles = find -type f -exec sh -c 'test -f $(srcdir)/{} || echo {}' ';'

distclean-local:
	rm -rf autom4te.cache
	rm -f $(distdir)-installer.exe

#dist-hook:
#	makensis -NOCD -DVERSION=${VERSION} -DSRCDIR=$(srcdir) \
#		-DOPENSSL=/usr/src/openssl-0.9.8u-fips/out32dll \
#		-DZLIB=/usr/src/zlib-1.2.6-i586 \
#		$(srcdir)/tools/stunnel.nsi

#	cp -f $(distdir)-installer.exe ../dist
#	gpg --yes --armor --detach-sign --force-v3-sigs ../dist/$(distdir)-installer.exe

sign: dist
	cp -f $(distdir).tar.gz ../dist
	gpg --yes --armor --detach-sign --force-v3-sigs ../dist/$(distdir).tar.gz
	sha256sum $(distdir).tar.gz | tee ../dist/$(distdir).tar.gz.sha256

