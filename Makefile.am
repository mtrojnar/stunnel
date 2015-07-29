## Process this file with automake to produce Makefile.in

SUBDIRS = src doc tools

EXTRA_DIST = PORTS BUGS COPYRIGHT.GPL CREDITS INSTALL.W32 INSTALL.WCE INSTALL.FIPS

docdir = $(datadir)/doc/stunnel
doc_DATA = INSTALL README COPYING AUTHORS ChangeLog \
	INSTALL.W32 INSTALL.WCE INSTALL.FIPS \
	BUGS PORTS COPYRIGHT.GPL CREDITS TODO

distcleancheck_listfiles = \
	find -type f -exec sh -c 'test -f $(srcdir)/{} || echo {}' ';'

distclean-local:
	rm -rf autom4te.cache
	rm -f $(distdir)-installer.exe

cert:
	(cd tools; rm -f stunnel.pem; $(MAKE) stunnel.pem)

dist-hook:
	makensis -NOCD -DSRCDIR=$(srcdir)/ $(srcdir)/tools/stunnel.nsi

sign: dist
	cp -f $(distdir).tar.gz ../dist
	cp -f $(distdir)-installer.exe ../dist
	gpg --yes --armor --detach-sign --force-v3-sigs \
		../dist/$(distdir).tar.gz
	gpg --yes --armor --detach-sign --force-v3-sigs \
		../dist/$(distdir)-installer.exe
	sha1sum $(distdir).tar.gz | tee ../dist/$(distdir).tar.gz.sha1

