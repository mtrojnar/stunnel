/*
 *   stunnel       TLS offloading and load-balancing proxy
 *   Copyright (C) 1998-2026 Michal Trojnara <Michal.Trojnara@stunnel.org>
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

#ifdef USE_LIBWRAP

#include <tcpd.h>

#if defined(USE_PTHREAD) && !defined(__CYGWIN__)
/* http://wiki.osdev.org/Cygwin_Issues#Passing_file_descriptors */
#define USE_LIBWRAP_POOL
#endif /* USE_PTHREAD && !__CYGWIN__ */

NOEXPORT uint8_t check(char *name, int fd);

int allow_severity=LOG_NOTICE, deny_severity=LOG_WARNING;

#ifdef USE_LIBWRAP_POOL
#define SERVNAME_LEN 256

NOEXPORT ssize_t read_fd(int fd, void *ptr, size_t nbytes, int *recvfd);
NOEXPORT ssize_t write_fd(int fd, void *ptr, size_t nbytes, int sendfd);

NOEXPORT unsigned num_processes=0;
NOEXPORT int *ipc_socket, *busy;
#endif /* USE_LIBWRAP_POOL */

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
#endif /* __GNUC__ */
int libwrap_init(void) {
#ifdef USE_LIBWRAP_POOL
    unsigned i, j, children=0;
    int rfd;
    uint8_t result;
    char servname[SERVNAME_LEN];
    pid_t child_pid[LIBWRAP_CLIENTS], pid;
    static int initialized=0;
    const SERVICE_OPTIONS *opt;

    if(initialized!=0) { /* startup or a previous configuration file reload */
        return 0;
    }
    for(opt=service_options.next; opt; opt=opt->next) {
        if(opt->option.libwrap) { /* libwrap is enabled for this service */
            break;
        }
    }
    if(!opt) { /* disabled for all sections or inetd mode (no sections) */
        return 0;
    }

    num_processes=LIBWRAP_CLIENTS;
    ipc_socket=str_alloc(2U*(size_t)num_processes*sizeof(int));
    busy=str_alloc((size_t)num_processes*sizeof(int));
    for(i=0; i<2U*num_processes; ++i)
        ipc_socket[i]=INVALID_SOCKET;
    for(i=0; i<num_processes; ++i) { /* spawn a child */
        if(s_socketpair(AF_UNIX, SOCK_STREAM, 0, &ipc_socket[2U*i],
                0, "libwrap_init")!=0) {
            /* s_socketpair() closes both descriptors on setup failure */
            ipc_socket[2U*i]=INVALID_SOCKET;
            ipc_socket[(2U*i)+1U]=INVALID_SOCKET;
            goto fail;
        }
        pid=fork();
        switch(pid) {
        case -1:    /* error */
            ioerror("fork");
            goto fail;
        case  0:    /* child */
            (void)tls_alloc(NULL, ui_tls, "libwrap");
            (void)drop_privileges(0); /* libwrap processes are not chrooted */
            (void)close(0); /* stdin */
            (void)close(1); /* stdout */
            if(!global_options.option.log_stderr) { /* logging in read_fd */
                (void)close(2); /* stderr */
            }
            for(j=0; j<=i; ++j) { /* close parent sockets created so far */
                (void)close(ipc_socket[2U*j]);
            }
            while(1) { /* main libwrap child loop */
                if(read_fd(ipc_socket[(2U*i)+1U], servname,
                        SERVNAME_LEN, &rfd)<=0) {
                    _exit(0);
                }
                result=check(servname, rfd);
                (void)write(ipc_socket[(2U*i)+1U], &result, sizeof result);
                if(rfd>=0) {
                    (void)close(rfd);
                }
            }
            break; /* unreached */
        default:    /* parent */
            child_pid[children++]=pid;
            (void)close(ipc_socket[(2U*i)+1U]); /* child-side socket */
            ipc_socket[(2U*i)+1U]=INVALID_SOCKET;
            break;
        }
    }
    initialized=1;
    return 0;

fail:
    /* Closing the parent endpoints makes initialized children exit on EOF. */
    for(i=0; i<2U*num_processes; ++i) {
        if(ipc_socket[i]!=INVALID_SOCKET)
            (void)close(ipc_socket[i]);
    }
    for(i=0; i<children; ++i) {
        do {
            pid=waitpid(child_pid[i], NULL, 0);
        } while(pid<0 && errno==EINTR);
        if(pid<0)
            ioerror("waitpid");
    }
    str_free(ipc_socket);
    str_free(busy);
    num_processes=0;
    return 1;
#endif /* USE_LIBWRAP_POOL */
    return 0;
}
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif /* __GNUC__ */

void libwrap_auth(CLI *c) {
    CRYPTO_RWLOCK *lock;
    uint8_t result=0; /* deny by default */
#ifdef USE_LIBWRAP_POOL
    jmp_buf exception_buffer, *exception_backup;
    static volatile unsigned num_busy=0, roundrobin=0;
    unsigned my_process;
    int retval;
    static pthread_mutex_t mutex=PTHREAD_MUTEX_INITIALIZER;
    static pthread_cond_t cond=PTHREAD_COND_INITIALIZER;
#endif /* USE_LIBWRAP_POOL */

    if(!c->opt->option.libwrap) { /* libwrap is disabled for this service */
        return; /* allow connection */
    }
#ifdef HAVE_STRUCT_SOCKADDR_UN
    /* AF_UNIX and sa_family_t are defined by the platform socket API. */
    /* cppcheck-suppress misra-c2012-10.4 */
    if(c->peer_addr.sa.sa_family==AF_UNIX) {
        s_log(LOG_INFO, "Libwrap is not supported on Unix sockets");
        return;
    }
#endif
#ifdef USE_LIBWRAP_POOL
    if(num_processes!=0U) {
        s_log(LOG_DEBUG, "Waiting for a libwrap process");

        retval=pthread_mutex_lock(&mutex);
        if(retval!=0) {
            errno=retval;
            ioerror("pthread_mutex_lock");
        }
        while(num_busy==num_processes) { /* all child processes are busy */
            retval=pthread_cond_wait(&cond, &mutex);
            if(retval!=0) {
                errno=retval;
                ioerror("pthread_cond_wait");
            }
        }
        while(busy[roundrobin]!=0) { /* find a free child process */
            roundrobin=(roundrobin+1U)%num_processes;
        }
        my_process=roundrobin; /* the process allocated by this thread */
        ++num_busy; /* the child process has been allocated */
        busy[my_process]=1; /* mark the child process as busy */
        retval=pthread_mutex_unlock(&mutex);
        if(retval!=0) {
            errno=retval;
            ioerror("pthread_mutex_unlock");
        }

        s_log(LOG_DEBUG, "Acquired libwrap process #%d", my_process);
        exception_backup=c->exception_pointer;
        c->exception_pointer=&exception_buffer;
        if(setjmp(exception_buffer)==0) {
            (void)write_fd(ipc_socket[2U*my_process], c->opt->servname,
                strlen(c->opt->servname)+1U, c->local_rfd.fd);
            s_read(c, ipc_socket[2U*my_process], &result, sizeof result);
        }
        c->exception_pointer=exception_backup;
        s_log(LOG_DEBUG, "Releasing libwrap process #%d", my_process);

        retval=pthread_mutex_lock(&mutex);
        if(retval!=0) {
            errno=retval;
            ioerror("pthread_mutex_lock");
        }
        busy[my_process]=0; /* mark the child process as free */
        --num_busy; /* the child process has been released */
        retval=pthread_cond_signal(&cond); /* signal a waiting thread */
        if(retval!=0) {
            errno=retval;
            ioerror("pthread_cond_signal");
        }
        retval=pthread_mutex_unlock(&mutex);
        if(retval!=0) {
            errno=retval;
            ioerror("pthread_mutex_unlock");
        }

        s_log(LOG_DEBUG, "Released libwrap process #%d", my_process);
    } else
#endif /* USE_LIBWRAP_POOL */
    { /* use original, synchronous libwrap calls */
        lock=s_write_lock(LOCK_LIBWRAP);
        result=check(c->opt->servname, c->local_rfd.fd);
        s_unlock(lock);
    }
    if(result==0U) {
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

    (void)request_init(&request, RQ_DAEMON, name, RQ_FILE, fd, 0);
    fromhost(&request);
    /* hosts_access() uses the integer result defined by libwrap. */
    /* cppcheck-suppress misra-c2012-10.4 */
    return hosts_access(&request)!=0;
}

#ifdef USE_LIBWRAP_POOL

NOEXPORT ssize_t read_fd(SOCKET fd, void *ptr, size_t nbytes, SOCKET *recvfd) {
    struct msghdr msg;
    struct iovec iov[1];
    ssize_t n;

#ifdef HAVE_MSGHDR_MSG_CONTROL
    union {
        /* This unread member provides the alignment required by CMSG_FIRSTHDR. */
        /* cppcheck-suppress unusedStructMember */
        struct cmsghdr align;
        /* CMSG_SPACE is a platform macro with analyzer-unknown size and type. */
        /* cppcheck-suppress [misra-config, misra-c2012-10.4] */
        char control[CMSG_SPACE(sizeof(int))];
    } control_un;
    const struct cmsghdr *cmptr;

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
    if(n<=0) {
        return n;
    }

#ifdef HAVE_MSGHDR_MSG_CONTROL
    cmptr=CMSG_FIRSTHDR(&msg);
    /* CMSG_LEN returns the implementation-defined ancillary-data type. */
    /* cppcheck-suppress misra-c2012-10.4 */
    if(!cmptr || (cmptr->cmsg_len!=CMSG_LEN(sizeof(int)))) {
        return n;
    }
    if(cmptr->cmsg_level!=SOL_SOCKET) {
        s_log(LOG_ERR, "control level != SOL_SOCKET");
        return -1;
    }
    if(cmptr->cmsg_type!=SCM_RIGHTS) {
        s_log(LOG_ERR, "control type != SCM_RIGHTS");
        return -1;
    }
    /* POSIX defines CMSG_DATA as an untyped, suitably aligned byte buffer. */
    /* cppcheck-suppress misra-c2012-21.15 */
    (void)memcpy(recvfd, CMSG_DATA(cmptr), sizeof(int));
#else
    if(msg.msg_accrightslen==sizeof(int)) {
        *recvfd=newfd;
    }
#endif

    return n;
}

NOEXPORT ssize_t write_fd(int fd, void *ptr, size_t nbytes, int sendfd) {
    struct msghdr msg;
    struct iovec iov[1];

#ifdef HAVE_MSGHDR_MSG_CONTROL
    union {
        /* This unread member provides the alignment required by CMSG_FIRSTHDR. */
        /* cppcheck-suppress unusedStructMember */
        struct cmsghdr align;
        /* CMSG_SPACE is a platform macro with analyzer-unknown size and type. */
        /* cppcheck-suppress [misra-config, misra-c2012-10.4] */
        char control[CMSG_SPACE(sizeof(int))];
    } control_un;
    struct cmsghdr *cmptr;

    msg.msg_control=control_un.control;
    msg.msg_controllen=sizeof control_un.control;

    cmptr=CMSG_FIRSTHDR(&msg);
    /* CMSG_LEN returns the implementation-defined ancillary-data type. */
    /* cppcheck-suppress misra-c2012-10.4 */
    cmptr->cmsg_len=CMSG_LEN(sizeof(int));
    cmptr->cmsg_level=SOL_SOCKET;
    cmptr->cmsg_type=SCM_RIGHTS;
    /* POSIX defines CMSG_DATA as an untyped, suitably aligned byte buffer. */
    /* cppcheck-suppress misra-c2012-21.15 */
    (void)memcpy(CMSG_DATA(cmptr), &sendfd, sizeof(int));
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
