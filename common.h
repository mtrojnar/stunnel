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

#ifndef COMMON_H
#define COMMON_H

/* Certificate defaults */

/* let's not use openssl defaults unless told to at compile time. */
#ifndef SSLLIB_CS
#define SSLLIB_CS 0
#endif

#define SSL_CERT_DEFAULTS     1
#define STUNNEL_CERT_DEFAULTS 2

#define CERT_DEFAULTS ( SSLLIB_CS | STUNNEL_CERT_DEFAULTS )

/* Set some defaults if not set in makefiles */
#ifndef CERT_DIR
#define CERT_DIR  ""
#endif
#ifndef CERT_FILE
#define CERT_FILE ""
#endif
#ifndef PEM_DIR
#define PEM_DIR   ""
#endif

/* define for windows, although ignored */
#ifndef PIDDIR
#define PIDDIR ""
#endif

/* For FormatGuard */
#define __NO_FORMATGUARD_

#ifndef USE_WIN32

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

#endif /* USE_WIN32 */

/* Must be included before sys/stat.h for Ultrix */
#include <sys/types.h>   /* u_short, u_long */

/* General headers */
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>      /* va_ */
#include <string.h>
#include <ctype.h>       /* isalnum */
#include <time.h>
#include <sys/stat.h>    /* stat */

#ifdef USE_WIN32

#ifndef VERSION
#define VERSION "3.22"
#endif

#ifdef __MINGW32__
#define HOST "x86-pc-mingw32-gnu"
#else
#define HOST "x86-pc-unknown"
#endif

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned long u32;
typedef unsigned __int64 u64;

#define HAVE_VSNPRINTF
#define vsnprintf _vsnprintf
/*  Already defined for mingw, perhaps others
int _vsnprintf(char *, int, char *, ...);
*/
#define strcasecmp _stricmp

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

#define Win32_Winsock
#include <windows.h>
#define ECONNRESET WSAECONNRESET
#define ENOTSOCK WSAENOTSOCK
#define ENOPROTOOPT WSAENOPROTOOPT
#define EINPROGRESS WSAEINPROGRESS

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

    /* Unix-specific headers */
#include <syslog.h>
#include <signal.h>      /* signal */
#include <sys/wait.h>    /* wait */
#ifdef HAVE_GETOPT_H
#include <getopt.h>      /* getopt */
/* Assume that we have getopt() function */
#define HAVE_GETOPT      1
#endif
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h> /* getrlimit */
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>      /* getpid, fork, execvp, exit */
#endif
#ifdef HAVE_STROPTS_H
#include <stropts.h>
#endif
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>  /* for aix */
#endif
#ifdef HAVE_SYS_FILIO_H
#include <sys/filio.h>   /* for FIONBIO */
#endif
#include <pwd.h>
#include <grp.h>
#include <fcntl.h>

    /* Networking headers */
#include <netinet/in.h>  /* struct sockaddr_in */
#include <sys/socket.h>  /* getpeername */
#include <arpa/inet.h>   /* inet_ntoa */
#include <sys/time.h>    /* select */
#include <sys/ioctl.h>   /* ioctl */
#include <netinet/tcp.h>
#include <netdb.h>
#ifndef INADDR_ANY
#define INADDR_ANY       (u32)0x00000000
#endif
#ifndef INADDR_LOOPBACK
#define INADDR_LOOPBACK  (u32)0x7F000001
#endif

#if defined(HAVE_WAITPID)
/* For SYSV systems */
#define wait_for_pid(a, b, c) waitpid((a), (b), (c))
#define HAVE_WAIT_FOR_PID 1
#elif defined(HAVE_WAIT4)
/* For BSD systems */
#define wait_for_pid(a, b, c) wait4((a), (b), (c), NULL)
#define HAVE_WAIT_FOR_PID 1
#endif

#if defined(sun) && !defined(__svr4__)  /* ie. SunOS 4 */
#define atexit(a) on_exit((a), NULL)
extern int sys_nerr;
extern char *sys_errlist[];
#define strerror(num) ((num)==0 ? "No error" : \
    ((num)>=sys_nerr ? "Unknown error" : sys_errlist[num]))
#endif /* SunOS 4 */

#endif /* USE_WIN32 */

/* Length of strings (including the terminating '\0' character) */
#define STRLEN       1024

/* How many bytes of random input to read from files for PRNG */
/* OpenSSL likes at least 128 bits, so 64 bytes seems plenty. */
#define RANDOM_BYTES 64

/* STDIN/STDOUT used instead of a single file desriptor */
#define STDIO_FILENO (-2)

/* Safe copy for strings declarated as char[STRLEN] */
#define safecopy(dst, src) \
    (dst[STRLEN-1]='\0', strncpy((dst), (src), STRLEN-1))
#define safeconcat(dst, src) \
    (dst[STRLEN-1]='\0', strncat((dst), (src), STRLEN-strlen(dst)-1))
/* change all non-printable characters to '.' */
#define safestring(s) \
    do {char *p; for(p=(s); *p; p++) if(!isprint((int)*p)) *p='.';} while(0)
/* change all unsafe characters to '.' */
#define safename(s) \
    do {char *p; for(p=(s); *p; p++) if(!isalnum((int)*p)) *p='.';} while(0)

#endif /* defined COMMON_H */

/* End of common.h */
