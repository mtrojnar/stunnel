################################################
# Makefile for stunnel by Michal Trojnara 1998 #
################################################

CC=gcc
CFLAGS=-O2 -Wall -I/usr/local/ssl/include
LIBS=-L/usr/local/ssl/lib -lssl -lcrypto
TARGET=stunnel
DEST=/usr/sbin/$(TARGET)

$(TARGET): $(TARGET).o
	$(CC) -o $(TARGET) $(TARGET).o $(LIBS)
	strip $(TARGET)
	cp $(TARGET) bin/$(TARGET).`uname -s`-`uname -m`

$(TARGET).o: $(TARGET).c
	$(CC) -c $(CFLAGS) $(TARGET).c

$(DEST): $(TARGET)
	cp $(TARGET) $(DEST)
	chmod 711 $(DEST)

install: $(DEST)

clean:
	rm -f $(TARGET) $(TARGET).o core

distrib: clean
	tar -cf - -C .. $(TARGET) | gzip > ../$(TARGET).tar.gz

