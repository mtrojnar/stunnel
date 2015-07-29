## Process this file with automake to produce Makefile.in

EXTRA_DIST = ca.html ca.pl importCA.html importCA.sh script.sh \
	stunnel.spec stunnel.cnf stunnel.nsi stunnel.license stunnel.conf

confdir = $(sysconfdir)/stunnel
conf_DATA = stunnel.conf-sample

docdir = $(datadir)/doc/stunnel
examplesdir = $(docdir)/examples
examples_DATA = ca.html ca.pl importCA.html importCA.sh script.sh \
	stunnel.spec stunnel.init stunnel.service

install-data-local:
	${INSTALL} -d -m 1770 $(DESTDIR)$(localstatedir)/lib/stunnel
	-chgrp $(DEFAULT_GROUP) $(DESTDIR)$(localstatedir)/lib/stunnel

OPENSSL=$(SSLDIR)/bin/openssl

cert:
	@if test -r $(DESTDIR)$(confdir)/stunnel.pem; \
	then \
		echo "$(DESTDIR)$(confdir)/stunnel.pem already exists"; \
	else \
		if test -r "$(RANDOM_FILE)"; then \
			dd if="$(RANDOM_FILE)" of=stunnel.rnd bs=256 count=1; \
			RND="-rand stunnel.rnd"; \
		else \
			RND=""; \
		fi; \
		$(OPENSSL) req -new -x509 -days 365 $$RND \
			-config $(srcdir)/stunnel.cnf \
			-out stunnel.pem -keyout stunnel.pem; \
		$(OPENSSL) gendh $$RND 1024 >> stunnel.pem; \
		$(OPENSSL) x509 -subject -dates -fingerprint -noout -in stunnel.pem; \
		${INSTALL} -m 600 stunnel.pem $(DESTDIR)$(confdir)/stunnel.pem; \
		rm stunnel.pem; \
		rm -f stunnel.rnd; \
	fi

