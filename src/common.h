/*
 *   stunnel       TLS offloading and load-balancing proxy
 *   Copyright (C) 1998-2016 Michal Trojnara <Michal.Trojnara@mirt.net>
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

/* I/O buffer size: 18432 (0x4800) is the maximum size of SSL record payload */
#define BUFFSIZE 18432

/* how many bytes of random input to read from files for PRNG */
/* OpenSSL likes at least 128 bits, so 64 bytes seems plenty. */
#define RANDOM_BYTES 64

/* for FormatGuard */
/* #define __NO_FORMATGUARD_ */

/* additional diagnostic messages */
/* #define DEBUG_FD_ALLOC */

#ifdef DEBUG_INFO
#define NOEXPORT
#else
#define NOEXPORT static
#endif

/**************************************** platform */

#ifdef _WIN32
#define USE_WIN32
#endif

#ifdef _WIN32_WCE
#define USE_WIN32
typedef int                 socklen_t;
#endif

#ifdef USE_WIN32
typedef signed   char       int8_t;
typedef signed   short      int16_t;
typedef signed   int        int32_t;
typedef signed   long long  int64_t;
typedef unsigned char       uint8_t;
typedef unsigned short      uint16_t;
typedef unsigned int        uint32_t;
typedef unsigned long long  uint64_t;
#ifndef __MINGW32__
#ifdef  _WIN64
typedef __int64             ssize_t;
#else /* _WIN64 */
typedef int                 ssize_t;
#endif /* _WIN64 */
#endif /* !__MINGW32__ */
#define PATH_MAX MAX_PATH
#define USE_IPv6
#define _CRT_SECURE_NO_DEPRECATE
#define _CRT_NONSTDC_NO_DEPRECATE
#define _CRT_NON_CONFORMING_SWPRINTFS
/* prevent including wincrypt.h, as it defines its own OCSP_RESPONSE */
#define __WINCRYPT_H__
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

/* systemd */
#ifdef USE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
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
#define readsocket(s,b,n)           recv((s),(b),(int)(n),0)
#define writesocket(s,b,n)          send((s),(b),(int)(n),0)

/* #define Win32_Winsock */
#define __USE_W32_SOCKETS

/* Winsock2 header for IPv6 definitions */
#include <winsock2.h>
#include <ws2tcpip.h>

#include <windows.h>

#include <process.h>     /* _beginthread */
#include <shlobj.h>      /* SHGetFolderPath */
#include <tchar.h>

#include "resources.h"

/**************************************** non-WIN32 headers */

#else /* USE_WIN32 */

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

typedef int SOCKET;
#define INVALID_SOCKET (-1)

    /* OpenVMS compatibility */
#ifdef __vms
#define LIBDIR "__NA__"
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
#ifdef HAVE_LIMITS_H
#include <limits.h>         /* INT_MAX */
#endif
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
#include <dirent.h>

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

/* BSD sockets */
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
#ifdef HAVE_SYS_SYSCALL_H
#include <sys/syscall.h> /* SYS_gettid */
#endif
#ifdef HAVE_LINUX_SCHED_H
#include <linux/sched.h> /* SCHED_BATCH */
#endif

#endif /* USE_WIN32 */

#ifndef S_ISREG
#define S_ISREG(m) (((m)&S_IFMT)==S_IFREG)
#endif

/**************************************** OpenSSL headers */

#define OPENSSL_THREAD_DEFINES
#include <openssl/opensslconf.h>
/* opensslv.h requires prior opensslconf.h to include -fips in version string */
#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER<0x0090700fL
#error OpenSSL 0.9.7 or later is required
#endif /* OpenSSL older than 0.9.7 */

#if defined(USE_PTHREAD) && !defined(OPENSSL_THREADS)
#error OpenSSL library compiled without thread support
#endif /* !OPENSSL_THREADS && USE_PTHREAD */

#if OPENSSL_VERSION_NUMBER<0x0090800fL
#define OPENSSL_NO_ECDH
#define OPENSSL_NO_COMP
#endif /* OpenSSL older than 0.9.8 */

/* non-blocking OCSP API is not available before OpenSSL 0.9.8h */
#if OPENSSL_VERSION_NUMBER<0x00908080L
#ifndef OPENSSL_NO_OCSP
#define OPENSSL_NO_OCSP
#endif /* !defined(OPENSSL_NO_OCSP) */
#endif /* OpenSSL older than 0.9.8h */

#if OPENSSL_VERSION_NUMBER<0x10000000L
#define OPENSSL_NO_TLSEXT
#define OPENSSL_NO_PSK
#endif /* OpenSSL older than 1.0.0 */

#if OPENSSL_VERSION_NUMBER<0x10001000L || defined(OPENSSL_NO_TLS1)
#define OPENSSL_NO_TLS1_1
#define OPENSSL_NO_TLS1_2
#endif /* OpenSSL older than 1.0.1 || defined(OPENSSL_NO_TLS1) */

#if OPENSSL_VERSION_NUMBER>=0x10100000L
#ifndef OPENSSL_NO_SSL2
#define OPENSSL_NO_SSL2
#endif /* !defined(OPENSSL_NO_SSL2) */
#endif /* OpenSSL 1.1.0 or newer */

#if defined(USE_WIN32) && defined(OPENSSL_FIPS)
#define USE_FIPS
#endif

#include <openssl/lhash.h>
#include <openssl/ssl.h>
#include <openssl/ssl23.h>
#include <openssl/ui.h>
#include <openssl/err.h>
#include <openssl/crypto.h> /* for CRYPTO_* and SSLeay_version */
#include <openssl/rand.h>
#include <openssl/bn.h>
#ifndef OPENSSL_NO_MD4
#include <openssl/md4.h>
#endif /* !defined(OPENSSL_NO_MD4) */
#include <openssl/des.h>
#ifndef OPENSSL_NO_DH
#include <openssl/dh.h>
#endif /* !defined(OPENSSL_NO_DH) */
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif /* !defined(OPENSSL_NO_ENGINE) */
#ifndef OPENSSL_NO_OCSP
#include <openssl/ocsp.h>
#endif /* !defined(OPENSSL_NO_OCSP) */
#ifndef OPENSSL_NO_COMP
/* not defined in public headers before OpenSSL 0.9.8 */
STACK_OF(SSL_COMP) *SSL_COMP_get_compression_methods(void);
#endif /* !defined(OPENSSL_NO_COMP) */

#ifndef OPENSSL_VERSION
#define OPENSSL_VERSION SSLEAY_VERSION
#define OpenSSL_version_num() SSLeay()
#define OpenSSL_version(x) SSLeay_version(x)
#endif

/**************************************** other defines */

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
#define offsetof(T, F) ((unsigned)((char *)&((T *)0L)->F - (char *)0L))
#endif

#endif /* defined COMMON_H */

/* end of common.h */
