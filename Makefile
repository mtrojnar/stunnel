################################################
# Makefile for stunnel by Michal Trojnara 1998 #
################################################

VERSION=1.3
INSTALL=./install-sh -c
BINDIR=/usr/sbin
MANDIR=/usr/man/man8

CC=gcc
CFLAGS=-O2 -Wall -I/usr/local/ssl/include
LIBS=-L/usr/local/ssl/lib -lssl -lcrypto

stunnel: stunnel.o
	$(CC) -o stunnel stunnel.o $(LIBS)
	strip stunnel
	cp stunnel bin/stunnel.`uname -s`-`uname -m`

stunnel.o: stunnel.c
	$(CC) -c $(CFLAGS) stunnel.c

$(BINDIR)/stunnel: stunnel
	$(INSTALL) -m 711 stunnel $(BINDIR)

$(MANDIR)/stunnel.8: stunnel.8
	$(INSTALL) -m 644 stunnel.8 $(MANDIR)

install: $(BINDIR)/stunnel $(MANDIR)/stunnel.8

clean:
	rm -f stunnel stunnel.o core

distrib: clean
	tar -cf - -C .. stunnel | gzip > ../stunnel-$(VERSION).tar.gz

