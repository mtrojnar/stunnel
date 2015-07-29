/*
 *   stunnel       Universal SSL tunnel
 *   Copyright (C) 1998-2013 Michal Trojnara <Michal.Trojnara@mirt.net>
 *
 *   This program is free software; you can redistribute it and/or modify it
 *   under the terms of the GNU General Public License as published by the
 *   Free Software Foundation; either version 2 of the License, or (at your
 *   option) any later version.
 * 
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *   See the GNU General Public License for more details.
 * 
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, see <http://www.gnu.org/licenses>.
 * 
 *   Linking stunnel statically or dynamically with other modules is making
 *   a combined work based on stunnel. Thus, the terms and conditions of
 *   the GNU General Public License cover the whole combination.
 * 
 *   In addition, as a special exception, the copyright holder of stunnel
 *   gives you permission to combine stunnel with free software programs or
 *   libraries that are released under the GNU LGPL and with code included
 *   in the standard release of OpenSSL under the OpenSSL License (or
 *   modified versions of such code, with unchanged license). You may copy
 *   and distribute such a system following the terms of the GNU GPL for
 *   stunnel and the licenses of the other code concerned.
 * 
 *   Note that people who make modified versions of stunnel are not obligated
 *   to grant this special exception for their modified versions; it is their
 *   choice whether to do so. The GNU General Public License gives permission
 *   to release a modified version without this exception; this exception
 *   also makes it possible to release a modified version which carries
 *   forward this exception.
 */

#ifndef COMMON_H
#define COMMON_H

#include "version.h"


/**************************************** common constants */

#define LIBWRAP_CLIENTS 5

/* CPU stack size */
#define DEFAULT_STACK_SIZE 65536
/* #define DEBUG_STACK_SIZE */

/* I/O buffer size - 18432 is the maximum size of SSL record payload */
#define BUFFSIZE 18432

/* how many bytes of random input to read from files for PRNG */
/* OpenSSL likes at least 128 bits, so 64 bytes seems plenty. */
#define RANDOM_BYTES 64

/* for FormatGuard */
/* #define __NO_FORMATGUARD_ */

/* additional diagnostic messages */
/* #define DEBUG_FD_ALLOC */

/**************************************** platform */

#ifdef _WIN32
#define USE_WIN32
#endif

#ifdef _WIN32_WCE
#define USE_WIN32
typedef int socklen_t;
#endif

#ifdef USE_WIN32
#define USE_IPv6
#define _CRT_SECURE_NO_DEPRECATE
#define _CRT_NONSTDC_NO_DEPRECATE
#define HAVE_OSSL_ENGINE_H
#define HAVE_OSSL_OCSP_H
/* prevent including wincrypt.h, as it defines it's own OCSP_RESPONSE */
#define __WINCRYPT_H__
#endif

#ifdef USE_WIN32
#define S_EADDRINUSE  WSAEADDRINUSE
/* winsock does not define WSAEAGAIN */
/* in most (but not all!) BSD implementations EAGAIN==EWOULDBLOCK */
#define S_EAGAIN        WSAEWOULDBLOCK
#define S_ECONNRESET    WSAECONNRESET
#define S_EINPROGRESS   WSAEINPROGRESS
#define S_EINTR         WSAEINTR
#define S_EINVAL        WSAEINVAL
#define S_EISCONN       WSAEISCONN
#define S_EMFILE        WSAEMFILE
/* winsock does not define WSAENFILE */
#define S_ENOBUFS       WSAENOBUFS
/* winsock does not define WSAENOMEM */
#define S_ENOPROTOOPT   WSAENOPROTOOPT
#define S_ENOTSOCK      WSAENOTSOCK
#define S_EOPNOTSUPP    WSAEOPNOTSUPP
#define S_EWOULDBLOCK   WSAEWOULDBLOCK
#define S_ECONNABORTED  WSAECONNABORTED
#else /* USE_WIN32 */
#define S_EADDRINUSE    EADDRINUSE
#define S_EAGAIN        EAGAIN
#define S_ECONNRESET    ECONNRESET
#define S_EINPROGRESS   EINPROGRESS
#define S_EINTR         EINTR
#define S_EINVAL        EINVAL
#define S_EISCONN       EISCONN
#define S_EMFILE        EMFILE
#ifdef ENFILE
#define S_ENFILE        ENFILE
#endif
#ifdef ENOBUFS
#define S_ENOBUFS       ENOBUFS
#endif
#ifdef ENOMEM
#define S_ENOMEM        ENOMEM
#endif
#define S_ENOPROTOOPT   ENOPROTOOPT
#define S_ENOTSOCK      ENOTSOCK
#define S_EOPNOTSUPP    EOPNOTSUPP
#define S_EWOULDBLOCK   EWOULDBLOCK
#define S_ECONNABORTED  ECONNABORTED
#endif /* USE_WIN32 */

/**************************************** generic headers */

#ifdef __vms
#include <starlet.h>
#endif /* __vms */

/* for nsr-tandem-nsk architecture */
#ifdef __TANDEM
#include <floss.h>
#endif

/* threads model */
#ifdef USE_UCONTEXT
#define __MAKECONTEXT_V2_SOURCE
#include <ucontext.h>
#endif

#ifdef USE_PTHREAD
#ifndef THREADS
#define THREADS
#endif
#ifndef _REENTRANT
/* _REENTRANT is required for thread-safe errno on Solaris */
#define _REENTRANT
#endif
#ifndef _THREAD_SAFE
#define _THREAD_SAFE
#endif
#include <pthread.h>
#endif

/* TCP wrapper */
#if defined HAVE_TCPD_H && defined HAVE_LIBWRAP
#define USE_LIBWRAP 1
#endif

/* must be included before sys/stat.h for Ultrix */
/* must be included before sys/socket.h for OpenBSD */
#include <sys/types.h>   /* u_short, u_long */
/* general headers */
#include <stdio.h>
/* must be included before sys/stat.h for Ultrix */
#ifndef _WIN32_WCE
#include <errno.h>
#endif
#include <stdlib.h>
#include <stdarg.h>      /* va_ */
#include <string.h>
#include <ctype.h>       /* isalnum */
#include <time.h>
#include <sys/stat.h>    /* stat */
#include <setjmp.h>
#include <fcntl.h>

/**************************************** WIN32 headers */

#ifdef USE_WIN32

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned long u32;

#define HAVE_STRUCT_ADDRINFO
#define HAVE_SNPRINTF
#define snprintf                    _snprintf
#define HAVE_VSNPRINTF
#define vsnprintf                   _vsnprintf
#define strcasecmp                  _stricmp
#define strncasecmp                 _strnicmp
#define sleep(c)                    Sleep(1000*(c))

#define get_last_socket_error()     WSAGetLastError()
#define set_last_socket_error(e)    WSASetLastError(e)
#define get_last_error()            GetLastError()
#define set_last_error(e)           SetLastError(e)
#define readsocket(s,b,n)           recv((s),(b),(n),0)
#define writesocket(s,b,n)          send((s),(b),(n),0)

/* #define FD_SETSIZE 4096 */
/* #define Win32_Winsock */
#define __USE_W32_SOCKETS

/* Winsock2 header for IPv6 definitions */
#include <winsock2.h>
#include <ws2tcpip.h>

#include <windows.h>

#include <process.h>     /* _beginthread */
#include <tchar.h>

#include "resources.h"

/**************************************** non-WIN32 headers */

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

#ifdef __INNOTEK_LIBC__
#define socklen_t                   __socklen_t
#define strcasecmp                  stricmp
#define strncasecmp                 strnicmp
#define NI_NUMERICHOST              1
#define NI_NUMERICSERV              2
#define get_last_socket_error()     sock_errno()
#define set_last_socket_error(e)    ()
#define get_last_error()            errno
#define set_last_error(e)           (errno=(e))
#define readsocket(s,b,n)           recv((s),(b),(n),0)
#define writesocket(s,b,n)          send((s),(b),(n),0)
#define closesocket(s)              close(s)
#define ioctlsocket(a,b,c)          so_ioctl((a),(b),(c))
#else
#define get_last_socket_error()     errno
#define set_last_socket_error(e)    (errno=(e))
#define get_last_error()            errno
#define set_last_error(e)           (errno=(e))
#define readsocket(s,b,n)           read((s),(b),(n))
#define writesocket(s,b,n)          write((s),(b),(n))
#define closesocket(s)              close(s)
#define ioctlsocket(a,b,c)          ioctl((a),(b),(c))
#endif

    /* OpenVMS compatibility */
#ifdef __vms
#define LIBDIR "__NA__"
#define PIDFILE "SYS$LOGIN:STUNNEL.PID"
#ifdef __alpha
#define HOST "alpha-openvms"
#else
#define HOST "vax-openvms"
#endif
#include <inet.h>
#include <unistd.h>
#else   /* __vms */
#include <syslog.h>
#endif  /* __vms */

    /* Unix-specific headers */
#include <signal.h>         /* signal */
#include <sys/wait.h>       /* wait */
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>   /* getrlimit */
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>         /* getpid, fork, execvp, exit */
#endif
#ifdef HAVE_STROPTS_H
#include <stropts.h>
#endif
#ifdef HAVE_MALLOC_H
#include <malloc.h>         /* mallopt */
#endif
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>     /* for aix */
#endif

#if defined(HAVE_POLL) && !defined(BROKEN_POLL)
#ifdef HAVE_POLL_H
#include <poll.h>
#define USE_POLL
#else /* HAVE_POLL_H */
#ifdef HAVE_SYS_POLL_H
#include <sys/poll.h>
#define USE_POLL
#endif /* HAVE_SYS_POLL_H */
#endif /* HAVE_POLL_H */
#endif /* HAVE_POLL && !BROKEN_POLL */

#ifdef HAVE_SYS_FILIO_H
#include <sys/filio.h>   /* for FIONBIO */
#endif
#include <pwd.h>
#ifdef HAVE_GRP_H
#include <grp.h>
#endif
#ifdef __BEOS__
#include <posix/grp.h>
#endif

#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>    /* struct iovec */
#endif /* HAVE_SYS_UIO_H */

#include <netinet/in.h>  /* struct sockaddr_in */
#include <sys/socket.h>  /* getpeername */
#include <arpa/inet.h>   /* inet_ntoa */
#include <sys/time.h>    /* select */
#include <sys/ioctl.h>   /* ioctl */
#ifdef HAVE_SYS_UN_H
#include <sys/un.h>
#endif
#include <netinet/tcp.h>
#include <netdb.h>
#ifndef INADDR_ANY
#define INADDR_ANY       (u32)0x00000000
#endif
#ifndef INADDR_LOOPBACK
#define INADDR_LOOPBACK  (u32)0x7F000001
#endif

#if defined(HAVE_WAITPID)
/* for SYSV systems */
#define wait_for_pid(a, b, c) waitpid((a), (b), (c))
#define HAVE_WAIT_FOR_PID 1
#elif defined(HAVE_WAIT4)
/* for BSD systems */
#define wait_for_pid(a, b, c) wait4((a), (b), (c), NULL)
#define HAVE_WAIT_FOR_PID 1
#endif

/* SunOS 4 */
#if defined(sun) && !defined(__svr4__) && !defined(__SVR4)
#define atexit(a) on_exit((a), NULL)
extern int sys_nerr;
extern char *sys_errlist[];
#define strerror(num) ((num)==0 ? "No error" : \
    ((num)>=sys_nerr ? "Unknown error" : sys_errlist[num]))
#endif /* SunOS 4 */

/* AIX does not have SOL_TCP defined */
#ifndef SOL_TCP
#define SOL_TCP SOL_SOCKET
#endif /* SOL_TCP */

/* Linux */
#ifdef __linux__
#ifndef IP_FREEBIND
/* kernel headers without IP_FREEBIND definition */
#define IP_FREEBIND 15
#endif /* IP_FREEBIND */
#ifndef IP_TRANSPARENT
/* kernel headers without IP_TRANSPARENT definition */
#define IP_TRANSPARENT 19
#endif /* IP_TRANSPARENT */
#ifdef HAVE_LINUX_NETFILTER_IPV4_H
#include <limits.h>
#include <linux/types.h>
#include <linux/netfilter_ipv4.h>
#endif /* HAVE_LINUX_NETFILTER_IPV4_H */
#endif /* __linux__ */

#endif /* USE_WIN32 */

/**************************************** OpenSSL headers */

#define OPENSSL_THREAD_DEFINES
#include <openssl/opensslconf.h>
#if defined(USE_PTHREAD) && !(defined(OPENSSL_THREADS) || \
    (OPENSSL_VERSION_NUMBER<0x0090700fL && defined(THREADS)))
#error OpenSSL library compiled without thread support
#endif /* !OPENSSL_THREADS && USE_PTHREAD */

#if defined (USE_WIN32) && defined(OPENSSL_FIPS)
#define USE_FIPS
#endif

/* OpenSSL 0.9.6 comp.h needs ZLIB macro to declare COMP_zlib() */
#define ZLIB

#include <openssl/lhash.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h> /* for CRYPTO_* and SSLeay_version */
#include <openssl/rand.h>
#ifndef OPENSSL_NO_MD4
#include <openssl/md4.h>
#endif
#include <openssl/des.h>

#ifdef HAVE_OSSL_ENGINE_H
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#else
#undef HAVE_OSSL_ENGINE_H
#endif
#endif /* HAVE_OSSL_ENGINE_H */

/* non-blocking OCSP API is not available before OpenSSL 0.9.8h */
#if OPENSSL_VERSION_NUMBER<0x00908080L
#ifdef HAVE_OSSL_OCSP_H
#undef HAVE_OSSL_OCSP_H
#endif /* HAVE_OSSL_OCSP_H */
#endif /* OpenSSL older than 0.9.8h */

#ifdef HAVE_OSSL_OCSP_H
#include <openssl/ocsp.h>
#endif /* HAVE_OSSL_OCSP_H */

#ifdef HAVE_OSSL_FIPS_H
#include <openssl/fips.h>
#include <openssl/fips_rand.h>
#endif /* HAVE_OSSL_FIPS_H */

#if OPENSSL_VERSION_NUMBER<0x0090800fL
#define OPENSSL_NO_ECDH
#endif /* OpenSSL version < 0.8.0 */

#if OPENSSL_VERSION_NUMBER<0x10000000L
#define OPENSSL_NO_TLSEXT
#endif /* OpenSSL version < 1.0.0 */

#ifndef OPENSSL_NO_COMP
/* not defined in public headers before OpenSSL 0.9.8 */
STACK_OF(SSL_COMP) *SSL_COMP_get_compression_methods(void);
#endif /* OPENSSL_NO_COMP */

/**************************************** other defines */

/* change all non-printable characters to '.' */
#define safestring(s) \
    do {unsigned char *p; for(p=(unsigned char *)(s); *p; p++) \
        if(!isprint((int)*p)) *p='.';} while(0)
/* change all unsafe characters to '.' */
#define safename(s) \
    do {unsigned char *p; for(p=(s); *p; p++) \
        if(!isalnum((int)*p)) *p='.';} while(0)

/* always use IPv4 defaults! */
#define DEFAULT_LOOPBACK "127.0.0.1"
#define DEFAULT_ANY "0.0.0.0"
#if 0
#define DEFAULT_LOOPBACK "::1"
#define DEFAULT_ANY "::"
#endif

#if defined (USE_WIN32) || defined (__vms)
#define LOG_EMERG       0
#define LOG_ALERT       1
#define LOG_CRIT        2
#define LOG_ERR         3
#define LOG_WARNING     4
#define LOG_NOTICE      5
#define LOG_INFO        6
#define LOG_DEBUG       7
#endif /* defined (USE_WIN32) || defined (__vms) */

#ifndef offsetof
#define offsetof(T, F) ((unsigned int)((char *)&((T *)0L)->F - (char *)0L))
#endif

#endif /* defined COMMON_H */

/* end of common.h */
