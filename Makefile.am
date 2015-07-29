## Process this file with automake to produce Makefile.in

SUBDIRS = src doc tools

# extra_src = src/gui.c src/resources.rc src/stunnel.ico src/stunnel.exe
# extra_doc = doc/stunnel.pod doc/stunnel.8 doc/stunnel.html doc/en doc/pl
# extra_tools = tools/ca.html tools/ca.pl tools/importCA.html tools/importCA.sh \
# 	tools/stunnel.spec tools/make.bat tools/stunnel.mak tools/stunnel.cnf
# EXTRA_DIST = auto PORTS $(extra_src) $(extra_doc) $(extra_tools)

EXTRA_DIST = PORTS BUGS COPYRIGHT.GPL CREDITS INSTALL.W32

docdir = $(datadir)/doc/stunnel
doc_DATA = AUTHORS BUGS ChangeLog COPYING COPYRIGHT.GPL CREDITS \
	INSTALL INSTALL.W32 NEWS PORTS README TODO

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

