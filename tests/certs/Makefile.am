## Process this file with automake to produce Makefile.in
# by Michal Trojnara 1998-2021

EXTRA_DIST = maketestcert.sh openssltest.cnf
EXTRA_DIST += CACertCRL.pem CACert.pem
EXTRA_DIST += server_cert.pem server_cert.p12 client_cert.pem
EXTRA_DIST += revoked_cert.pem stunnel.pem PeerCerts.pem
EXTRA_DIST += psk1.txt psk2.txt secrets.txt

check-local:
	$(srcdir)/maketestcert.sh

dist-local:
	$(srcdir)/maketestcert.sh
