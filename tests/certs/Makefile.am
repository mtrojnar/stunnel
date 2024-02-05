## Process this file with automake to produce Makefile.in
# by Michal Trojnara 1998-2024

EXTRA_DIST = maketestcert.sh openssl_root.cnf openssl_intermediate.cnf

CLEANFILES = makecerts.log

check-local:
	$(srcdir)/maketestcert.sh

dist-local:
	$(srcdir)/maketestcert.sh
