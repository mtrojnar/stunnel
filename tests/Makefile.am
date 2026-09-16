## Process this file with automake to produce Makefile.in
# by Michal Trojnara 1998-2026

SUBDIRS = certs

EXTRA_DIST = maketest.py plugin_collection.py reader.py error.py plugins

# Helpers run by the regression-test plugin, including a select-only variant.
check_PROGRAMS = fd_limits_test fd_limits_select_test
fd_limits_test_SOURCES = fd_limits.c
fd_limits_test_CPPFLAGS = -I$(top_builddir)/src -I$(top_srcdir)/src -I$(SSLDIR)/include
fd_limits_select_test_SOURCES = fd_limits.c
fd_limits_select_test_CPPFLAGS = $(fd_limits_test_CPPFLAGS) -DTEST_SELECT

# try to find a supported python version (>= 3.7) that works
check-local: $(check_PROGRAMS)
	for v in $$(seq 20 -1 7); do command -v python3.$$v && break; done || ( echo "Python 3.7 or later not found" && false )
	for v in $$(seq 20 -1 7); do command -v python3.$$v && python3.$$v $(srcdir)/maketest.py --debug=10 --libs=$(SSLDIR)/lib64:$(SSLDIR)/lib && break; done

dist-hook:
	rm -rf $(distdir)/__pycache__ $(distdir)/plugins/__pycache__

distclean-local:
	rm -f logs/*.log
	rm -f certs/*.pem
	rm -f certs/*.p12
	rm -f certs/*.txt
