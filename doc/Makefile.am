EXTRA_DIST = stunnel.pod stunnel.pl.pod stunnel.fr.pod \
    stunnel.8 stunnel.pl.8 stunnel.fr.8 \
	stunnel.html stunnel.pl.html stunnel.fr.html en pl

man_MANS = stunnel.8 stunnel.pl.8 stunnel.fr.8

docdir = $(datadir)/doc/stunnel
doc_DATA = stunnel.html stunnel.pl.html stunnel.fr.html

SUFFIXES = .pod .8 .html

.pod.8:
	pod2man --section=8 --release=4.05 --center=stunnel --date=`date +%Y.%m.%d` \
	$< $@

.pod.html:
	pod2html --infile=$< --outfile=$@ --title stunnel.8
	rm -f pod2htmd.x~~ pod2htmi.x~~

