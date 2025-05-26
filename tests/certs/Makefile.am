## Process this file with automake to produce Makefile.in
# by Michal Trojnara 1998-2025

EXTRA_DIST = maketestcert.sh openssl_root.cnf openssl_intermediate.cnf

CLEANFILES = makecerts.log

check-local:
	OPENSSL_PATH=@SSLDIR@ $(srcdir)/maketestcert.sh

dist-local:
	OPENSSL_PATH=@SSLDIR@ $(srcdir)/maketestcert.sh
