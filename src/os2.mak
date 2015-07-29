prefix=.
DEFS = -DPACKAGE_NAME=\"stunnel\" \
	-DPACKAGE_TARNAME=\"stunnel\" \
	-DPACKAGE_VERSION=\"5.00\" \
	-DPACKAGE_STRING=\"stunnel\ 5.00\" \
	-DPACKAGE_BUGREPORT=\"\" \
	-DPACKAGE=\"stunnel\" \
	-DVERSION=\"5.00\" \
	-DSTDC_HEADERS=1 \
	-DHAVE_SYS_TYPES_H=1 \
	-DHAVE_SYS_STAT_H=1 \
	-DHAVE_STDLIB_H=1 \
	-DHAVE_STRING_H=1 \
	-DHAVE_MEMORY_H=1 \
	-DHAVE_STRINGS_H=1 \
	-DHAVE_UNISTD_H=1 \
	-DHAVE_OSSL_ENGINE_H=1 \
	-DSSLDIR=\"/usr\" \
	-DHOST=\"i386-pc-os2-emx\" \
	-DHAVE_LIBSOCKET=1 \
	-DHAVE_GRP_H=1 \
	-DHAVE_UNISTD_H=1 \
	-DHAVE_SYS_SELECT_H=1 \
	-DHAVE_SYS_IOCTL_H=1 \
	-DHAVE_SYS_RESOURCE_H=1 \
	-DHAVE_SNPRINTF=1 \
	-DHAVE_VSNPRINTF=1 \
	-DHAVE_WAITPID=1 \
	-DHAVE_SYSCONF=1 \
	-DHAVE_ENDHOSTENT=1 \
        -DUSE_OS2=1 \
	-DSIZEOF_UNSIGNED_CHAR=1 \
	-DSIZEOF_UNSIGNED_SHORT=2 \
	-DSIZEOF_UNSIGNED_INT=4 \
	-DSIZEOF_UNSIGNED_LONG=4 \
      	-DLIBDIR=\"$(prefix)/lib\" \
        -DCONFDIR=\"$(prefix)/etc\"

CC = gcc
.SUFFIXES = .c .o
OPENSSLDIR = u:/extras
#SYSLOGDIR = /unixos2/workdir/syslog
INCLUDES = -I$(OPENSSLDIR)/outinc
LIBS = -lsocket -L$(OPENSSLDIR)/out -lssl -lcrypto -lz -lsyslog
OBJS = file.o client.o log.o options.o protocol.o network.o ssl.o ctx.o verify.o sthreads.o stunnel.o pty.o resolver.o str.o fd.o
LIBDIR = .
CFLAGS = -O2 -Wall -Wshadow -Wcast-align -Wpointer-arith

all: stunnel.exe

stunnel.exe: $(OBJS)
	$(CC) -Zmap $(CFLAGS) -o $@ $(OBJS) $(LIBS)

.c.o:
	$(CC) $(CFLAGS) $(DEFS) $(INCLUDES) -o $@ -c $<

client.o: client.c common.h prototypes.h
#env.o: env.c common.h prototypes.h
#gui.o: gui.c common.h prototypes.h
file.o: file.c common.h prototypes.h
network.o: network.c common.h prototypes.h
options.o: options.c common.h prototypes.h
protocol.o: protocol.c common.h prototypes.h
pty.o: pty.c common.h prototypes.h
ssl.o: ssl.c common.h prototypes.h
ctx.o: ctx.c common.h prototypes.h
verify.o: verify.c common.h prototypes.h
sthreads.o: sthreads.c common.h prototypes.h
stunnel.o: stunnel.c common.h prototypes.h
resolver.o: resolver.c common.h prototypes.h
str.o: str.c common.h prototypes.h
fd.o: fd.c common.h prototypes.h

clean:
	rm -f *.o *.exe
