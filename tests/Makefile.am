## Process this file with automake to produce Makefile.in
# by Michal Trojnara 1998-2022

SUBDIRS = certs

EXTRA_DIST = maketest.py plugin_collection.py reader.py error.py plugins

# try to find a supported python version (>= 3.7) that works
check-local:
	for v in $$(seq 20 -1 7); do command -v python3.$$v && break; done || ( echo "Python 3.7 or later not found" && false )
	for v in $$(seq 20 -1 7); do command -v python3.$$v && python3.$$v $(srcdir)/maketest.py --debug=10 --libs=$(SSLDIR)/lib64:$(SSLDIR)/lib && break; done

dist-hook:
	rm -rf $(distdir)/__pycache__ $(distdir)/plugins/__pycache__

distclean-local:
	rm -f logs/*.log
	rm -f certs/*.pem
	rm -f certs/*.p12
	rm -f certs/*.txt
