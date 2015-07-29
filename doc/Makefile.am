EXTRA_DIST = stunnel.pod stunnel.8 stunnel.html en pl

man_MANS = stunnel.8

docdir = $(datadir)/doc/stunnel
doc_DATA = stunnel.html

stunnel.8: stunnel.pod
	pod2man --section=8 --release=4.0 --center=stunnel --date=`date +%Y.%m.%d` \
	stunnel.pod stunnel.8

stunnel.html: stunnel.pod
	pod2html --infile=stunnel.pod --outfile=stunnel.html --title stunnel.8
	rm -f pod2htmd.x~~ pod2htmi.x~~

