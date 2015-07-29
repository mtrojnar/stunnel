## Process this file with automake to produce Makefile.in

EXTRA_DIST = stunnel.pod.in stunnel.pod stunnel.8 stunnel.html en
EXTRA_DIST += stunnel.pl.pod.in stunnel.pl.pod stunnel.pl.8 stunnel.pl.html pl

man_MANS = stunnel.8 stunnel.pl.8

docdir = $(datadir)/doc/stunnel
doc_DATA = stunnel.html stunnel.pl.html

SUFFIXES = .pod .8 .html

.pod.8:
	pod2man -u --section=8 --release=$(VERSION) --center=stunnel \
		--date=`date +%Y.%m.%d` $< $@

.pod.html:
	pod2html --noindex --title stunnel.8 --infile=$< --outfile=$@
	rm -f pod2htmd.tmp pod2htmi.tmp

edit = sed \
	-e 's|@bindir[@]|$(bindir)|g' \
	-e 's|@sysconfdir[@]|$(sysconfdir)|g'

stunnel.pod stunnel.pl.pod: Makefile
	$(edit) '$(srcdir)/$@.in' >$@

stunnel.pod: $(srcdir)/stunnel.pod.in
stunnel.pl.pod: $(srcdir)/stunnel.pl.pod.in
