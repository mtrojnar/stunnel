/*
 *   stunnel       TLS offloading and load-balancing proxy
 *   Copyright (C) 1998-2021 Michal Trojnara <Michal.Trojnara@stunnel.org>
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

#include "common.h"
#include "prototypes.h"

#ifdef USE_LIBWRAP

#include <tcpd.h>

#if defined(USE_PTHREAD) && !defined(__CYGWIN__)
/* http://wiki.osdev.org/Cygwin_Issues#Passing_file_descriptors */
#define USE_LIBWRAP_POOL
#endif /* USE_PTHREAD && !__CYGWIN__ */

NOEXPORT uint8_t check(char *, int);

int allow_severity=LOG_NOTICE, deny_severity=LOG_WARNING;

#ifdef USE_LIBWRAP_POOL
#define SERVNAME_LEN 256

NOEXPORT ssize_t read_fd(int, void *, size_t, int *);
NOEXPORT ssize_t write_fd(int, void *, size_t, int);

unsigned num_processes=0;
static int *ipc_socket, *busy;
#endif /* USE_LIBWRAP_POOL */

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
#endif /* __GNUC__ */
int libwrap_init() {
#ifdef USE_LIBWRAP_POOL
    unsigned i, j;
    int rfd;
    uint8_t result;
    char servname[SERVNAME_LEN];
    static int initialized=0;
    SERVICE_OPTIONS *opt;

    if(initialized) /* during startup or previous configuration file reload */
        return 0;
    for(opt=service_options.next; opt; opt=opt->next)
        if(opt->option.libwrap) /* libwrap is enabled for this service */
            break;
    if(!opt) /* disabled for all sections or inetd mode (no sections) */
        return 0;

    num_processes=LIBWRAP_CLIENTS;
    ipc_socket=str_alloc(2*num_processes*sizeof(int));
    busy=str_alloc(num_processes*sizeof(int));
    for(i=0; i<num_processes; ++i) { /* spawn a child */
        if(s_socketpair(AF_UNIX, SOCK_STREAM, 0, ipc_socket+2*i, 0, "libwrap_init"))
            return 1;
        switch(fork()) {
        case -1:    /* error */
            ioerror("fork");
            return 1;
        case  0:    /* child */
            tls_alloc(NULL, ui_tls, "libwrap");
            drop_privileges(0); /* libwrap processes are not chrooted */
            close(0); /* stdin */
            close(1); /* stdout */
            if(!global_options.option.log_stderr) /* for logging in read_fd */
                close(2); /* stderr */
            for(j=0; j<=i; ++j) /* close parent-side sockets created so far */
                close(ipc_socket[2*j]);
            while(1) { /* main libwrap child loop */
                if(read_fd(ipc_socket[2*i+1], servname, SERVNAME_LEN, &rfd)<=0)
                    _exit(0);
                result=check(servname, rfd);
                write(ipc_socket[2*i+1], &result, sizeof result);
                if(rfd>=0)
                    close(rfd);
            }
        default:    /* parent */
            close(ipc_socket[2*i+1]); /* child-side socket */
        }
    }
    initialized=1;
#endif /* USE_LIBWRAP_POOL */
    return 0;
}
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif /* __GNUC__ */

void libwrap_auth(CLI *c) {
    uint8_t result=0; /* deny by default */
#ifdef USE_LIBWRAP_POOL
    jmp_buf exception_buffer, *exception_backup;
    static volatile unsigned num_busy=0, roundrobin=0;
    unsigned my_process;
    int retval;
    static pthread_mutex_t mutex=PTHREAD_MUTEX_INITIALIZER;
    static pthread_cond_t cond=PTHREAD_COND_INITIALIZER;
#endif /* USE_LIBWRAP_POOL */

    if(!c->opt->option.libwrap) /* libwrap is disabled for this service */
        return; /* allow connection */
#ifdef HAVE_STRUCT_SOCKADDR_UN
    if(c->peer_addr.sa.sa_family==AF_UNIX) {
        s_log(LOG_INFO, "Libwrap is not supported on Unix sockets");
        return;
    }
#endif
#ifdef USE_LIBWRAP_POOL
    if(num_processes) {
        s_log(LOG_DEBUG, "Waiting for a libwrap process");

        retval=pthread_mutex_lock(&mutex);
        if(retval) {
            errno=retval;
            ioerror("pthread_mutex_lock");
        }
        while(num_busy==num_processes) { /* all child processes are busy */
            retval=pthread_cond_wait(&cond, &mutex);
            if(retval) {
                errno=retval;
                ioerror("pthread_cond_wait");
            }
        }
        while(busy[roundrobin]) /* find a free child process */
            roundrobin=(roundrobin+1)%num_processes;
        my_process=roundrobin; /* the process allocated by this thread */
        ++num_busy; /* the child process has been allocated */
        busy[my_process]=1; /* mark the child process as busy */
        retval=pthread_mutex_unlock(&mutex);
        if(retval) {
            errno=retval;
            ioerror("pthread_mutex_unlock");
        }

        s_log(LOG_DEBUG, "Acquired libwrap process #%d", my_process);
        exception_backup=c->exception_pointer;
        c->exception_pointer=&exception_buffer;
        if(!setjmp(exception_buffer)) {
            write_fd(ipc_socket[2*my_process], c->opt->servname,
                strlen(c->opt->servname)+1, c->local_rfd.fd);
            s_read(c, ipc_socket[2*my_process], &result, sizeof result);
        }
        c->exception_pointer=exception_backup;
        s_log(LOG_DEBUG, "Releasing libwrap process #%d", my_process);

        retval=pthread_mutex_lock(&mutex);
        if(retval) {
            errno=retval;
            ioerror("pthread_mutex_lock");
        }
        busy[my_process]=0; /* mark the child process as free */
        --num_busy; /* the child process has been released */
        retval=pthread_cond_signal(&cond); /* signal a waiting thread */
        if(retval) {
            errno=retval;
            ioerror("pthread_cond_signal");
        }
        retval=pthread_mutex_unlock(&mutex);
        if(retval) {
            errno=retval;
            ioerror("pthread_mutex_unlock");
        }

        s_log(LOG_DEBUG, "Released libwrap process #%d", my_process);
    } else
#endif /* USE_LIBWRAP_POOL */
    { /* use original, synchronous libwrap calls */
        CRYPTO_THREAD_write_lock(stunnel_locks[LOCK_LIBWRAP]);
        result=check(c->opt->servname, c->local_rfd.fd);
        CRYPTO_THREAD_unlock(stunnel_locks[LOCK_LIBWRAP]);
    }
    if(!result) {
        s_log(LOG_WARNING, "Service [%s] REFUSED by libwrap from %s",
            c->opt->servname, c->accepted_address);
        s_log(LOG_DEBUG, "See hosts_access(5) manual for details");
        throw_exception(c, 1);
    }
    s_log(LOG_DEBUG, "Service [%s] permitted by libwrap from %s",
        c->opt->servname, c->accepted_address);
}

NOEXPORT uint8_t check(char *name, int fd) {
    struct request_info request;

    request_init(&request, RQ_DAEMON, name, RQ_FILE, fd, 0);
    fromhost(&request);
    return hosts_access(&request)!=0;
}

#ifdef USE_LIBWRAP_POOL

NOEXPORT ssize_t read_fd(SOCKET fd, void *ptr, size_t nbytes, SOCKET *recvfd) {
    struct msghdr msg;
    struct iovec iov[1];
    ssize_t n;

#ifdef HAVE_MSGHDR_MSG_CONTROL
    union {
        struct cmsghdr cm;
        char control[CMSG_SPACE(sizeof(int))];
    } control_un;
    struct cmsghdr *cmptr;

    msg.msg_control=control_un.control;
    msg.msg_controllen=sizeof control_un.control;
#else
    int newfd;

    msg.msg_accrights=(caddr_t)&newfd;
    msg.msg_accrightslen=sizeof(int);
#endif

    msg.msg_name=NULL;
    msg.msg_namelen=0;

    iov[0].iov_base=ptr;
    iov[0].iov_len=nbytes;
    msg.msg_iov=iov;
    msg.msg_iovlen=1;

    *recvfd=INVALID_SOCKET; /* descriptor was not passed */
    n=recvmsg(fd, &msg, 0);
    if(n<=0)
        return n;

#ifdef HAVE_MSGHDR_MSG_CONTROL
    cmptr=CMSG_FIRSTHDR(&msg);
    if(!cmptr || cmptr->cmsg_len!=CMSG_LEN(sizeof(int)))
        return n;
    if(cmptr->cmsg_level!=SOL_SOCKET) {
        s_log(LOG_ERR, "control level != SOL_SOCKET");
        return -1;
    }
    if(cmptr->cmsg_type!=SCM_RIGHTS) {
        s_log(LOG_ERR, "control type != SCM_RIGHTS");
        return -1;
    }
    memcpy(recvfd, CMSG_DATA(cmptr), sizeof(int));
#else
    if(msg.msg_accrightslen==sizeof(int))
        *recvfd=newfd;
#endif

    return n;
}

NOEXPORT ssize_t write_fd(int fd, void *ptr, size_t nbytes, int sendfd) {
    struct msghdr msg;
    struct iovec iov[1];

#ifdef HAVE_MSGHDR_MSG_CONTROL
    union {
        struct cmsghdr cm;
        char control[CMSG_SPACE(sizeof(int))];
    } control_un;
    struct cmsghdr *cmptr;

    msg.msg_control=control_un.control;
    msg.msg_controllen=sizeof control_un.control;

    cmptr=CMSG_FIRSTHDR(&msg);
    cmptr->cmsg_len=CMSG_LEN(sizeof(int));
    cmptr->cmsg_level=SOL_SOCKET;
    cmptr->cmsg_type=SCM_RIGHTS;
    memcpy(CMSG_DATA(cmptr), &sendfd, sizeof(int));
#else
    msg.msg_accrights=(caddr_t)&sendfd;
    msg.msg_accrightslen=sizeof(int);
#endif

    msg.msg_name=NULL;
    msg.msg_namelen=0;

    iov[0].iov_base=ptr;
    iov[0].iov_len=nbytes;
    msg.msg_iov=iov;
    msg.msg_iovlen=1;

    return sendmsg(fd, &msg, 0);
}

#endif /* USE_LIBWRAP_POOL */

#endif /* USE_LIBWRAP */

/* end of libwrap.c */
