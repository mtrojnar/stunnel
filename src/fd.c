/*
 *   stunnel       TLS offloading and load-balancing proxy
 *   Copyright (C) 1998-2025 Michal Trojnara <Michal.Trojnara@stunnel.org>
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

#include "prototypes.h"

#if defined HAVE_PIPE2 && defined HAVE_ACCEPT4
#define USE_NEW_LINUX_API 1
#endif

/* try to use non-POSIX O_NDELAY on obsolete BSD systems */
#if !defined O_NONBLOCK && defined O_NDELAY
#define O_NONBLOCK O_NDELAY
#endif

/**************************************** prototypes */

NOEXPORT SOCKET setup_fd(SOCKET, int, const char *);

/**************************************** internal limit of file descriptors */

#ifndef USE_FORK

static SOCKET max_fds;

void get_limits(void) { /* set max_fds and max_clients */
    /* start with current ulimit */
#if defined(HAVE_SYSCONF)
    errno=0;
    max_fds=(SOCKET)sysconf(_SC_OPEN_MAX);
    if(errno)
        ioerror("sysconf");
    if(max_fds<0)
        max_fds=0; /* unlimited */
#elif defined(HAVE_GETRLIMIT)
    struct rlimit rlim;

    if(getrlimit(RLIMIT_NOFILE, &rlim)<0) {
        ioerror("getrlimit");
        max_fds=0; /* unlimited */
    } else
        max_fds=rlim.rlim_cur!=RLIM_INFINITY ? rlim.rlim_cur : 0;
#else
    max_fds=0; /* unlimited */
#endif /* HAVE_SYSCONF || HAVE_GETRLIMIT */

#if !defined(USE_WIN32) && !defined(USE_POLL) && !defined(__INNOTEK_LIBC__)
    /* apply FD_SETSIZE if select() is used on Unix */
    if(!max_fds || max_fds>FD_SETSIZE)
        max_fds=FD_SETSIZE; /* start with select() limit */
#endif /* select() on Unix */

    /* stunnel needs at least 16 file descriptors */
    if(max_fds && max_fds<16)
        max_fds=16;

    if(max_fds) {
        max_clients=(int)(max_fds>=256 ? max_fds*125/256 : (max_fds-6)/2);
        s_log(LOG_DEBUG, "Clients allowed=%d", max_clients);
    } else {
        max_clients=0;
        s_log(LOG_DEBUG, "No limit detected for the number of clients");
    }
}

#endif

/**************************************** file descriptor validation */

SOCKET s_socket(int domain, int type, int protocol, int nonblock, const char *msg) {
    SOCKET fd;

#ifdef USE_NEW_LINUX_API
    if(nonblock)
        type|=SOCK_NONBLOCK;
    type|=SOCK_CLOEXEC;
#endif
#ifdef USE_WIN32
    /* http://stackoverflow.com/questions/4993119 */
    /* CreateProcess() needs a non-overlapped handle */
    fd=WSASocket(domain, type, protocol, NULL, 0, 0);
#else /* USE_WIN32 */
    fd=socket(domain, type, protocol);
#endif /* USE_WIN32 */
    return setup_fd(fd, nonblock, msg);
}

SOCKET s_accept(SOCKET sockfd, struct sockaddr *addr, socklen_t *addrlen,
        int nonblock, const char *msg) {
    SOCKET fd;

#ifdef USE_NEW_LINUX_API
    if(nonblock)
        fd=accept4(sockfd, addr, addrlen, SOCK_NONBLOCK|SOCK_CLOEXEC);
    else
        fd=accept4(sockfd, addr, addrlen, SOCK_CLOEXEC);
#else
    fd=accept(sockfd, addr, addrlen);
#endif
    return setup_fd(fd, nonblock, msg);
}

#ifndef USE_WIN32

int s_socketpair(int domain, int type, int protocol, SOCKET sv[2],
        int nonblock, const char *msg) {
#ifdef USE_NEW_LINUX_API
    if(nonblock)
        type|=SOCK_NONBLOCK;
    type|=SOCK_CLOEXEC;
#endif
    if(socketpair(domain, type, protocol, sv)<0) {
        ioerror(msg);
        return -1;
    }
    if(setup_fd(sv[0], nonblock, msg)<0) {
        closesocket(sv[1]);
        return -1;
    }
    if(setup_fd(sv[1], nonblock, msg)<0) {
        closesocket(sv[0]);
        return -1;
    }
    return 0;
}

int s_pipe(int pipefd[2], int nonblock, const char *msg) {
    int retval;

#ifdef USE_NEW_LINUX_API
    if(nonblock)
        retval=pipe2(pipefd, O_NONBLOCK|O_CLOEXEC);
    else
        retval=pipe2(pipefd, O_CLOEXEC);
#else
    retval=pipe(pipefd);
#endif
    if(retval<0) {
        ioerror(msg);
        return -1;
    }
    if(setup_fd(pipefd[0], nonblock, msg)<0) {
        close(pipefd[1]);
        return -1;
    }
    if(setup_fd(pipefd[1], nonblock, msg)<0) {
        close(pipefd[0]);
        return -1;
    }
    return 0;
}

#endif /* USE_WIN32 */

NOEXPORT SOCKET setup_fd(SOCKET fd, int nonblock, const char *msg) {
#if !defined USE_NEW_LINUX_API && defined FD_CLOEXEC
    int err;
#endif

    if(fd==INVALID_SOCKET) {
        sockerror(msg);
        return INVALID_SOCKET;
    }
#ifndef USE_FORK
    if(max_fds && fd>=max_fds) {
        s_log(LOG_ERR, "%s: FD=%ld out of range (max %d)",
            msg, (long)fd, (int)max_fds);
        closesocket(fd);
        return INVALID_SOCKET;
    }
#endif

#ifdef USE_NEW_LINUX_API
    (void)nonblock; /* squash the unused parameter warning */
#else /* set O_NONBLOCK and F_SETFD */
    set_nonblock(fd, (unsigned long)nonblock);
#ifdef FD_CLOEXEC
    do {
        err=fcntl(fd, F_SETFD, FD_CLOEXEC);
    } while(err<0 && get_last_socket_error()==S_EINTR);
    if(err<0)
        sockerror("fcntl SETFD"); /* non-critical */
#endif /* FD_CLOEXEC */
#endif /* USE_NEW_LINUX_API */

#ifdef DEBUG_FD_ALLOC
    s_log(LOG_DEBUG, "%s: FD=%ld allocated (%sblocking mode)",
        msg, (long)fd, nonblock?"non-":"");
#endif /* DEBUG_FD_ALLOC */

    return fd;
}

void set_nonblock(SOCKET fd, unsigned long nonblock) {
#if defined F_GETFL && defined F_SETFL && defined O_NONBLOCK && !defined __INNOTEK_LIBC__
    int err, flags;

    do {
        flags=fcntl(fd, F_GETFL, 0);
    } while(flags<0 && get_last_socket_error()==S_EINTR);
    if(flags<0) {
        sockerror("fcntl GETFL"); /* non-critical */
        return;
    }
    if(nonblock)
        flags|=O_NONBLOCK;
    else
        flags&=~O_NONBLOCK;
    do {
        err=fcntl(fd, F_SETFL, flags);
    } while(err<0 && get_last_socket_error()==S_EINTR);
    if(err<0)
        sockerror("fcntl SETFL"); /* non-critical */
#else /* WIN32 or similar */
    if(ioctlsocket(fd, (long)FIONBIO, &nonblock)<0)
        sockerror("ioctlsocket"); /* non-critical */
#if 0
    else
        s_log(LOG_DEBUG, "Socket %d set to %s mode",
            fd, nonblock ? "non-blocking" : "blocking");
#endif
#endif
}

/* end of fd.c */
