/*
 *   stunnel       Universal SSL tunnel
 *   Copyright (c) 1998-2001 Michal Trojnara <Michal.Trojnara@mirt.net>
 *                 All Rights Reserved
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define OPT_CLIENT      0x01
#define OPT_CERT        0x02
#define OPT_DAEMON      0x04
#define OPT_FOREGROUND  0x08
#define OPT_PROGRAM     0x10
#define OPT_REMOTE      0x20
#define OPT_TRANSPARENT 0x40
#define OPT_PTY         0x80

/* Certificate defaults */

/* let's not use openssl defaults unless told to at compile time. */
#ifndef SSLLIB_CS
#define SSLLIB_CS	0
#endif

#define SSL_CERT_DEFAULTS	1
#define STUNNEL_CERT_DEFAULTS	2

#define CERT_DEFAULTS ( SSLLIB_CS | STUNNEL_CERT_DEFAULTS )


/* Set some defaults if not set in makefiles */
#ifndef CERT_DIR
#define CERT_DIR	""
#endif
#ifndef CERT_FILE
#define CERT_FILE	""
#endif
#ifndef PEM_DIR
#define PEM_DIR	""
#endif


#ifdef USE_WIN32

#define VERSION "3.14"
#ifdef __MINGW32__
#define HOST "x86-pc-mingw32-gnu"
#else
#define HOST "x86-pc-unknown"
#endif

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned long u32;
typedef unsigned long long u64;

#define HAVE_VSNPRINTF
#define vsnprintf _vsnprintf
/*  Already defined for mingw, perhaps others
int _vsnprintf(char *, int, char *, ...);
*/

#define get_last_socket_error() WSAGetLastError()
#define get_last_error()        GetLastError()
#define readsocket(s,b,n)       recv((s),(b),(n),0)
#define writesocket(s,b,n)      send((s),(b),(n),0)

#define LOG_EMERG       0
#define LOG_ALERT       1
#define LOG_CRIT        2
#define LOG_ERR         3
#define LOG_WARNING     4
#define LOG_NOTICE      5
#define LOG_INFO        6
#define LOG_DEBUG       7

#else /* USE_WIN32 */

#if SIZEOF_UNSIGNED_CHAR == 1
typedef unsigned char u8;
#endif

#if SIZEOF_UNSIGNED_SHORT == 2
typedef unsigned short u16;
#else
typedef unsigned int u16;
#endif

#if SIZEOF_UNSIGNED_INT == 4
typedef unsigned int u32;
#else
typedef unsigned long u32;
#endif

#if SIZEOF_UNSIGNED_LONG == 8
typedef unsigned long u64;
#else
typedef unsigned long long u64;
#endif

#define get_last_socket_error() errno
#define get_last_error()        errno
#define readsocket(s,b,n)       read((s),(b),(n))
#define writesocket(s,b,n)      write((s),(b),(n))
#define closesocket(s)          close(s)
#define ioctlsocket(a,b,c)      ioctl((a),(b),(c))

/* POSIX threads */
#if HAVE_PTHREAD_H && HAVE_LIBPTHREAD
#define USE_PTHREAD
#define THREADS
#define _REENTRANT
#define _THREAD_SAFE
#else
#define USE_FORK
#endif

/* TCP wrapper */
#if HAVE_TCPD_H && HAVE_LIBWRAP
#define USE_LIBWRAP
#endif

#include <syslog.h>
#include <sys/types.h>

#endif /* USE_WIN32 */

#if defined(sun) && !defined(__svr4__)  /* ie. SunOS 4 */
#define atexit(a) on_exit((a), NULL)
extern int sys_nerr;
extern char *sys_errlist[];
#define strerror(num) ((num)==0 ? "No error" : \
    ((num)>=sys_nerr ? "Unknown error" : sys_errlist[num]))
#endif /* SunOS 4 */

#ifdef USE_PTHREAD
#define STUNNEL_TMP "stunnel " VERSION " on " HOST " PTHREAD"
#endif
#ifdef USE_WIN32
#define STUNNEL_TMP "stunnel " VERSION " on " HOST " WIN32"
#endif
#ifdef USE_FORK
#define STUNNEL_TMP "stunnel " VERSION " on " HOST " FORK"
#endif
#ifdef USE_LIBWRAP
#define STUNNEL_INFO STUNNEL_TMP "+LIBWRAP"
#else
#define STUNNEL_INFO STUNNEL_TMP
#endif

/* Length of strings (including the terminating '\0' character) */
#define STRLEN         1024

/* How many bytes of random input to read from files for PRNG */
/* OpenSSL likes at least 128 bits, so 64 bytes seems plenty. */
#define RANDOM_BYTES		64

/* Safe copy for strings declarated as char[STRLEN] */
#define safecopy(dst, src) \
    (dst[STRLEN-1]='\0', strncpy((dst), (src), STRLEN-1))
#define safeconcat(dst, src) \
    (dst[STRLEN-1]='\0', strncat((dst), (src), STRLEN-strlen(dst)-1))

typedef struct {
    char pem[STRLEN];  		/* pem (priv key/cert) filename */
    char cert_dir[STRLEN];	/* directory for hashed certs */
    char cert_file[STRLEN];	/* file containing bunches of certs */
    char pidfile[STRLEN];
    unsigned long dpid;
    int clients;
    int option;
    int foreground;         /* force messages to stderr */
    unsigned short localport, remoteport;
    u32 *localnames, *remotenames;
    char *execname, **execargs; /* program name and arguments for local mode */
    char servname[STRLEN];  /* service name for loggin & permission checking */
    int verify_level;
    int verify_use_only_my;
    int debug_level;		/* debug level for syslog */
    int facility;		/* debug facility for syslog */
    long session_timeout;
    char *cipher_list;
    char *username;
    char *protocol;
    char *setuid_user;
    char *setgid_group;
    char *egd_sock;	/* entropy gathering daemon socket */
    char *rand_file;	/* file with random data */
    int rand_write;	/* overwrite rand_file with new rand data when PRNG seeded */
    int random_bytes;	/* how many random bytes to read */
    char *pid_dir;
    int cert_defaults;
} server_options;

/* Prototypes for stunnel.c */

void sockerror(char *);
int connect_local(u32);
int connect_remote(u32);

/* Prototypes for ssl.c */

void context_init();
void context_free();
void client(int);

/* Prototypes for protocol.c */

int negotiate(char *, int, int, int);

/* Prototypes for log.c */

void log_open();
void log_close();
void log(int, char *, ...);
int  parse_debug_level(char *);

/* Prototypes for sthreads.c */

void enter_critical_section(int);
void leave_critical_section(int);
void sthreads_init(void);
unsigned long process_id(void);
unsigned long thread_id(void);
int create_client(int, int, void (*)(int));

/* Prototypes for pty.c */
/* Based on Public Domain code by Tatu Ylonen <ylo@cs.hut.fi> */

int pty_allocate(int *ptyfd, int *ttyfd, char *ttyname, int ttynamelen);
void pty_release(char *ttyname);
void pty_make_controlling_tty(int *ttyfd, char *ttyname);

/* define for windows, although ignored */
#ifndef PIDDIR
#define PIDDIR ""
#endif

#define STRINGIFY_H(x) #x
#define STRINGIFY(x) STRINGIFY_H(x)


/* End of common.h */

