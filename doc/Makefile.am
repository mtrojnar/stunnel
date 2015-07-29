## Process this file with automake to produce Makefile.in

EXTRA_DIST = stunnel.pod stunnel.pl.pod stunnel.fr.pod \
    stunnel.8 stunnel.pl.8 stunnel.fr.8 \
	stunnel.html stunnel.pl.html stunnel.fr.html en pl

man_MANS = stunnel.8 stunnel.pl.8 stunnel.fr.8

docdir = $(datadir)/doc/stunnel
doc_DATA = stunnel.html stunnel.pl.html stunnel.fr.html

SUFFIXES = .pod .8 .html

.pod.8:
	pod2man -u --section=8 --release=$(VERSION) --center=stunnel \
		--date=`date +%Y.%m.%d` $< $@

.pod.html:
	pod2html --noindex --title stunnel.8 --infile=$< --outfile=$@
	rm -f pod2htmd.tmp pod2htmi.tmp

