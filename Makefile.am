## Process this file with automake to produce Makefile.in
# by Michal Trojnara 1998-2021

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = src doc tools tests

LIBTOOL_DEPS = @LIBTOOL_DEPS@
libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status libtool

docdir = $(datadir)/doc/stunnel
doc_DATA = README.md TODO.md COPYING.md AUTHORS.md NEWS.md
doc_DATA += PORTS.md BUGS.md COPYRIGHT.md CREDITS.md
doc_DATA += INSTALL.W32.md INSTALL.WCE.md INSTALL.FIPS.md

EXTRA_DIST = .travis.yml $(doc_DATA)

distcleancheck_listfiles = find -type f -exec sh -c 'test -f $(srcdir)/{} || echo {}' ';'

distclean-local:
	rm -rf autom4te.cache

sign:
	cp -f $(distdir).tar.gz $(distdir)-win64-installer.exe $(distdir)-android.zip ../dist
	-gpg-agent --daemon
	/bin/sh -c "cd ../dist; gpg --yes --armor --detach-sign --force-v3-sigs $(distdir).tar.gz; gpg --yes --armor --detach-sign --force-v3-sigs $(distdir)-win64-installer.exe; gpg --yes --armor --detach-sign --force-v3-sigs $(distdir)-android.zip"
	sha256sum $(distdir).tar.gz >../dist/$(distdir).tar.gz.sha256
	sha256sum $(distdir)-win64-installer.exe >../dist/$(distdir)-win64-installer.exe.sha256
	sha256sum $(distdir)-android.zip >../dist/$(distdir)-android.zip.sha256
	cat ../dist/$(distdir)*.sha256 | tac

cert:
	$(MAKE) -C tools cert

mingw:
	$(MAKE) -C src mingw

mingw64:
	$(MAKE) -C src mingw64

test: check

install-data-hook:
	@echo "*********************************************************"
	@echo "* Type 'make cert' to also install a sample certificate *"
	@echo "*********************************************************"

.PHONY: sign cert mingw mingw64 test
