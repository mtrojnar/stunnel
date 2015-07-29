DISTCLEANFILES = stunnel.pem
EXTRA_DIST = ca.html ca.pl importCA.html importCA.sh \
	stunnel.spec stunnel.mak stunnel.cnf

confdir = $(sysconfdir)/stunnel
conf_DATA = stunnel.conf-sample stunnel.pem

docdir = $(datadir)/doc/stunnel
examplesdir = $(docdir)/examples
examples_DATA = ca.html ca.pl importCA.html importCA.sh \
	stunnel.spec stunnel.init

openssl=$(ssldir)/bin/openssl
stunnel.pem: stunnel.cnf
	$(openssl) req -new -x509 -days 365 -nodes \
		-config $(srcdir)/stunnel.cnf -out stunnel.pem -keyout stunnel.pem
	test $(USE_DH) -eq 0 || test ! -r $(RANDOM_FILE) || \
		$(openssl) gendh -rand $(RANDOM_FILE) 512 >> stunnel.pem
	test $(USE_DH) -eq 0 || test -r $(RANDOM_FILE) || \
		$(openssl) gendh 512 >> stunnel.pem
	$(openssl) x509 -subject -dates -fingerprint -noout \
		-in stunnel.pem

install-data-hook:
	chmod 0600 $(confdir)/stunnel.pem

