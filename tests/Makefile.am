## Process this file with automake to produce Makefile.in
# by Michal Trojnara 1998-2019

SUBDIRS = certs

EXTRA_DIST = make_test test_library recipes execute execute_read execute_write

check-local:
	$(srcdir)/make_test

distclean-local:
	rm -f logs/*.log
