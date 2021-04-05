## Process this file with automake to produce Makefile.in
# by Michal Trojnara 1998-2021

SUBDIRS = certs

EXTRA_DIST = make_test test_library recipes execute execute_read execute_write http_request server.py

check-local:
	$(srcdir)/make_test

distclean-local:
	rm -f logs/*.log
