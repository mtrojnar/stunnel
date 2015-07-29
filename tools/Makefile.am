## Process this file with automake to produce Makefile.in

DISTCLEANFILES = stunnel.pem
EXTRA_DIST = ca.html ca.pl importCA.html importCA.sh script.sh \
	stunnel.spec stunnel.mak stunnel.cnf

confdir = $(sysconfdir)/stunnel
conf_DATA = stunnel.conf-sample stunnel.pem

docdir = $(datadir)/doc/stunnel
examplesdir = $(docdir)/examples
examples_DATA = ca.html ca.pl importCA.html importCA.sh script.sh \
	stunnel.spec stunnel.init

install-data-local:
	mkdir -p $(localstatedir)/stunnel
	-chmod a=rwx,+t $(localstatedir)/stunnel
	-uname | grep SunOS && \
		mkdir -p $(localstatedir)/stunnel/dev && \
		chmod u=rwx,go=rx $(localstatedir)/stunnel/dev && \
		mknod $(localstatedir)/stunnel/dev/zero c 13 12 && \
		chmod a=rw $(localstatedir)/stunnel/dev/zero

openssl=$(ssldir)/bin/openssl
stunnel.pem: stunnel.cnf
	if test -r "$(RANDOM_FILE)"; \
		then dd if="$(RANDOM_FILE)" of=stunnel.rnd bs=256 count=1; \
			RND="-rand stunnel.rnd"; \
		else RND=""; fi; \
	$(openssl) req -new -x509 -days 365 -nodes $$RND \
		-config $(srcdir)/stunnel.cnf -out stunnel.pem -keyout stunnel.pem; \
	test $(USE_DH) -eq 0 || $(openssl) gendh $$RND 512 >> stunnel.pem
	$(openssl) x509 -subject -dates -fingerprint -noout \
		-in stunnel.pem

install-data-hook:
	chmod 0600 $(DESTDIR)$(confdir)/stunnel.pem

clean-local:
	-rm -f stunnel.rnd

