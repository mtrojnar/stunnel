SUBDIRS = src doc tools

# extra_src = src/gui.c src/resources.rc src/stunnel.ico src/stunnel.exe
# extra_doc = doc/stunnel.pod doc/stunnel.8 doc/stunnel.html doc/en doc/pl
# extra_tools = tools/ca.html tools/ca.pl tools/importCA.html tools/importCA.sh \
# 	tools/stunnel.spec tools/make.bat tools/stunnel.mak tools/stunnel.cnf
# EXTRA_DIST = auto PORTS $(extra_src) $(extra_doc) $(extra_tools)

EXTRA_DIST = auto PORTS BUGS COPYRIGHT.GPL CREDITS FAQ INSTALL.W32

docdir = $(datadir)/doc/stunnel
doc_DATA = AUTHORS BUGS ChangeLog COPYING COPYRIGHT.GPL CREDITS FAQ \
	INSTALL INSTALL.W32 NEWS PORTS README TODO

distclean-local:
	rm -rf autom4te.cache

sign: dist
	mv -f $(distdir).tar.gz ../dist
	cp -f src/stunnel.exe ../dist/$(distdir).exe
	gpg --yes --armor --detach-sign --force-v3-sigs ../dist/$(distdir).tar.gz
	gpg --yes --armor --detach-sign --force-v3-sigs ../dist/$(distdir).exe

