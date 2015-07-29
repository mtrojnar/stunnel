## Process this file with automake to produce Makefile.in

EXTRA_DIST = stunnel.pod stunnel.pl.pod stunnel.fr.pod \
    stunnel.8 stunnel.pl.8 stunnel.fr.8 \
	stunnel.html stunnel.pl.html stunnel.fr.html en pl

man_MANS = stunnel.8 stunnel.pl.8 stunnel.fr.8

docdir = $(datadir)/doc/stunnel
doc_DATA = stunnel.html stunnel.pl.html stunnel.fr.html

SUFFIXES = .pod .8 .html

.pod.8:
	pod2man --section=8 --release=4.35 --center=stunnel \
		--date=`date +%Y.%m.%d` -u $< $@

stunnel.html: stunnel.pod
	pod2html --infile=$< --outfile $@ --title stunnel.8
	rm -f pod2htmd.tmp pod2htmi.tmp

stunnel.fr.html: stunnel.fr.pod
	pod2html --infile=$< --title stunnel.8 | \
		sed 's/<head>/<head>\n<meta http-equiv=content-type content="text\/html; charset=ISO-8859-1">/' > $@
	rm -f pod2htmd.tmp pod2htmi.tmp

stunnel.pl.html: stunnel.pl.pod
	pod2html --infile=$< --title stunnel.8 | \
		sed 's/<head>/<head>\n<meta http-equiv=content-type content="text\/html; charset=ISO-8859-2">/' > $@
	rm -f pod2htmd.tmp pod2htmi.tmp

