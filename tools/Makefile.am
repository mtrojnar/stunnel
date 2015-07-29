## Process this file with automake to produce Makefile.in

EXTRA_DIST = ca.html ca.pl importCA.html importCA.sh script.sh \
	stunnel.spec stunnel.cnf stunnel.nsi stunnel.conf

confdir = $(sysconfdir)/stunnel
conf_DATA = stunnel.conf-sample

docdir = $(datadir)/doc/stunnel
examplesdir = $(docdir)/examples
examples_DATA = ca.html ca.pl importCA.html importCA.sh script.sh \
	stunnel.spec stunnel.init stunnel.service

openssl=$(ssldir)/bin/openssl
install-data-local:
	if test ! -r $(DESTDIR)$(confdir)/stunnel.pem; then \
		if test -r "$(RANDOM_FILE)"; then \
			dd if="$(RANDOM_FILE)" of=stunnel.rnd bs=256 count=1; \
			RND="-rand stunnel.rnd"; \
		else \
			RND=""; \
		fi; \
		$(openssl) req -new -x509 -days 365 -nodes $$RND \
			-config $(srcdir)/stunnel.cnf \
			-out stunnel.pem -keyout stunnel.pem; \
		$(openssl) gendh $$RND 512 >> stunnel.pem; \
		$(openssl) x509 -subject -dates -fingerprint -noout -in stunnel.pem; \
		${INSTALL} -m 600 stunnel.pem $(DESTDIR)$(confdir)/stunnel.pem; \
		rm stunnel.pem; \
	fi
	${INSTALL} -d -m 1770 $(DESTDIR)$(localstatedir)/lib/stunnel
	-chgrp $(DEFAULT_GROUP) $(DESTDIR)$(localstatedir)/lib/stunnel
	if uname | grep SunOS; then \
		${INSTALL} -d -m 755 $(DESTDIR)$(localstatedir)/lib/stunnel/dev; \
		mknod $(DESTDIR)$(localstatedir)/lib/stunnel/dev/zero c 13 12; \
		chmod 666 $(DESTDIR)$(localstatedir)/lib/stunnel/dev/zero; \
	fi

clean-local:
	-rm -f stunnel.rnd

