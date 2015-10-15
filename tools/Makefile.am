## Process this file with automake to produce Makefile.in
# by Michal Trojnara 2015

EXTRA_DIST = ca.html ca.pl importCA.html importCA.sh script.sh \
	stunnel.spec openssl.cnf stunnel.nsi stunnel.license stunnel.conf \
	stunnel.conf-sample.in stunnel.init.in stunnel.service.in

confdir = $(sysconfdir)/stunnel
conf_DATA = stunnel.conf-sample

docdir = $(datadir)/doc/stunnel
examplesdir = $(docdir)/examples
examples_DATA = stunnel.spec stunnel.init stunnel.service
examples_DATA += ca.html ca.pl importCA.html importCA.sh script.sh

CLEANFILES = stunnel.conf-sample stunnel.init stunnel.service

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
			-config $(srcdir)/openssl.cnf \
			-out stunnel.pem -keyout stunnel.pem; \
		$(OPENSSL) x509 -subject -dates -fingerprint -noout -in stunnel.pem; \
		${INSTALL} -m 600 stunnel.pem $(DESTDIR)$(confdir)/stunnel.pem; \
		rm stunnel.pem; \
		rm -f stunnel.rnd; \
	fi

edit = sed \
	-e 's|@prefix[@]|$(prefix)|g' \
	-e 's|@bindir[@]|$(bindir)|g' \
	-e 's|@localstatedir[@]|$(localstatedir)|g' \
	-e 's|@sysconfdir[@]|$(sysconfdir)|g' \
	-e 's|@DEFAULT_GROUP[@]|$(DEFAULT_GROUP)|g'

stunnel.conf-sample stunnel.init stunnel.service: Makefile
	$(edit) '$(srcdir)/$@.in' >$@

stunnel.conf-sample: $(srcdir)/stunnel.conf-sample.in
stunnel.init: $(srcdir)/stunnel.init.in
stunnel.service: $(srcdir)/stunnel.service.in
