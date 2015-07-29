## Process this file with automake to produce Makefile.in

EXTRA_DIST = stunnel.pod.in stunnel.8.in stunnel.html.in en
EXTRA_DIST += stunnel.pl.pod.in stunnel.pl.8.in stunnel.pl.html.in pl

man_MANS = stunnel.8 stunnel.pl.8

docdir = $(datadir)/doc/stunnel
doc_DATA = stunnel.html stunnel.pl.html

CLEANFILES = $(man_MANS) $(doc_DATA)

SUFFIXES = .pod.in .8.in .html.in

.pod.in.8.in:
	pod2man -u --section=8 --release=$(VERSION) --center=stunnel \
		--date=`date +%Y.%m.%d` $< $@

.pod.in.html.in:
	pod2html --noindex --title stunnel.8 --infile=$< --outfile=$@
	rm -f pod2htmd.tmp pod2htmi.tmp

edit = sed \
	-e 's|@bindir[@]|$(bindir)|g' \
	-e 's|@sysconfdir[@]|$(sysconfdir)|g'

$(man_MANS) $(doc_DATA): Makefile
	$(edit) '$(srcdir)/$@.in' >$@

stunnel.8: $(srcdir)/stunnel.8.in
stunnel.html: $(srcdir)/stunnel.html.in
stunnel.pl.8: $(srcdir)/stunnel.pl.8.in
stunnel.pl.html: $(srcdir)/stunnel.pl.html.in
