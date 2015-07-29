/*
 *   stunnel       Universal SSL tunnel
 *   Copyright (c) 1998-1999 Michal Trojnara <Michal.Trojnara@centertel.pl>
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

#ifdef USE_WIN32

#define VERSION "3.5"
#define HOST "i586-pc-mingw32-gnu"

#define HAVE_VSNPRINTF
#define vsnprintf _vsnprintf
int _vsnprintf(char *, int, char *, ...);

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

#include "config.h"

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
#else
#define USE_FORK
#endif

/* Pseudoterminals */
#if HAVE_PTY_H && HAVE_LIBUTIL
#define USE_PTY
#endif

/* TCP wrapper */
#if HAVE_TCPD_H && HAVE_LIBWRAP
#define USE_LIBWRAP
#endif

#include <syslog.h>

#endif /* USE_WIN32 */

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

typedef struct {
    char certfile[STRLEN];  /* name of the certificate */
    char clientdir[STRLEN];
    char pidfile[STRLEN];
    unsigned long dpid;
    int clients;
    int option;
    int foreground;         /* force messages to stderr */
    unsigned short localport, remoteport;
    unsigned long *localnames, *remotenames;
    char *execname, **execargs; /* program name and arguments for local mode */
    char servname[STRLEN];  /* service name for loggin & permission checking */
    int verify_level;
    int verify_use_only_my;
    int debug_level;
    long session_timeout;
    char *cipher_list;
    char *username;
    char *protocol;
} server_options;

/* Prototypes for stunnel.c */

void sockerror(char *);
int connect_local(unsigned long);
int connect_remote(unsigned long);

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

/* Prototypes for sthreads.c */

void sthreads_init(void);
unsigned long process_id(void);
unsigned long thread_id(void);
int create_client(int, int, void (*)(int));

/* End of common.h */

