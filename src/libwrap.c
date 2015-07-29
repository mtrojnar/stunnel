/*
 *   stunnel       Universal SSL tunnel
 *   Copyright (c) 1998-2007 Michal Trojnara <Michal.Trojnara@mirt.net>
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
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 *   In addition, as a special exception, Michal Trojnara gives
 *   permission to link the code of this program with the OpenSSL
 *   library (or with modified versions of OpenSSL that use the same
 *   license as OpenSSL), and distribute linked combinations including
 *   the two.  You must obey the GNU General Public License in all
 *   respects for all of the code used other than OpenSSL.  If you modify
 *   this file, you may extend this exception to your version of the
 *   file, but you are not obligated to do so.  If you do not wish to
 *   do so, delete this exception statement from your version.
 */


#include "common.h"
#include "prototypes.h"

#ifdef USE_LIBWRAP

#include <tcpd.h>

static int check_libwrap(char *, int);

int allow_severity=LOG_NOTICE, deny_severity=LOG_WARNING;

#ifdef USE_PTHREAD
static ssize_t read_fd(int, void *, size_t, int *);
static ssize_t write_fd(int, void *, size_t, int);

int nproc=0;
static int *ipc_socket, *busy;
#endif /* USE_PTHREAD */

#define HAVE_MSGHDR_MSG_CONTROL 1

void libwrap_init(int num) {
#ifdef USE_PTHREAD
    int i, rfd, result;
    char servname[STRLEN];

    nproc=num;
    if(!nproc) /* no extra processes to spawn */
        return;
    ipc_socket=calloc(2*nproc, sizeof(int));
    busy=calloc(nproc, sizeof(int));
    if(!ipc_socket || !busy) {
        s_log(LOG_ERR, "Memory allocation failed");
        exit(1);
    }
    for(i=0; i<nproc; ++i) { /* spawn a child */
        if(socketpair(AF_UNIX, SOCK_STREAM, 0, ipc_socket+2*i)) {
            sockerror("socketpair");
            exit(1);
        }
        switch(fork()) {
        case -1:    /* error */
            ioerror("fork");
            exit(1);
        case  0:    /* child */
            close(ipc_socket[2*i]); /* server side */
            while(1) { /* main libwrap client loop */
                read_fd(ipc_socket[2*i+1], servname, STRLEN, &rfd);
                result=check_libwrap(servname, rfd);
                write(ipc_socket[2*i+1], (u8 *)&result, sizeof(result));
                if(rfd>=0)
                    close(rfd);
            }
        default:    /* parent */
#ifdef FD_CLOEXEC
            fcntl(ipc_socket[2*i], F_SETFD, FD_CLOEXEC); /* server side */
#endif
            close(ipc_socket[2*i+1]); /* client side */
        }
    }
#endif /* USE_PTHREAD */
}

void auth_libwrap(CLI *c) {
    int result=0; /* deny by default */
#ifdef USE_PTHREAD
    static int num_busy=0, rr=0;
    static pthread_mutex_t mutex=PTHREAD_MUTEX_INITIALIZER;
    static pthread_cond_t cond=PTHREAD_COND_INITIALIZER;

    if(nproc) {
        s_log(LOG_DEBUG, "Waiting for a libwrap process");

        pthread_mutex_lock(&mutex);
        while(num_busy>=nproc) /* all child processes are busy */
            pthread_cond_wait(&cond, &mutex);
        while(busy[rr]) /* find a free child process */
            rr=(rr+1)%nproc;
        ++num_busy; /* the child process has been allocated */
        busy[rr]=1; /* mark the child process as busy */
        pthread_mutex_unlock(&mutex);

        s_log(LOG_DEBUG, "Acquired libwrap process #%d", rr);
        write_fd(ipc_socket[2*rr], c->opt->servname,
            strlen(c->opt->servname)+1, c->local_rfd.fd);
        read_blocking(c, ipc_socket[2*rr], (u8 *)&result, sizeof(result));
        s_log(LOG_DEBUG, "Releasing libwrap process #%d", rr);

        pthread_mutex_lock(&mutex);
        busy[rr]=0; /* mark the child process as free */
        --num_busy; /* the child process has been released */
        pthread_cond_signal(&cond); /* signal other waiting threads */
        pthread_mutex_unlock(&mutex);

        s_log(LOG_DEBUG, "Released libwrap process #%d", rr);
    } else
#endif /* USE_PTHREAD */
    { /* use original, synchronous libwrap calls */
        enter_critical_section(CRIT_LIBWRAP);
        result=check_libwrap(c->opt->servname, c->local_rfd.fd);
        leave_critical_section(CRIT_LIBWRAP);
    }
    if(!result) {
        s_log(LOG_WARNING, "%s REFUSED by libwrap from %s",
            c->opt->servname, c->accepted_address);
        s_log(LOG_DEBUG, "See hosts_access(5) manual for details");
        longjmp(c->err, 1);
    }
    s_log(LOG_DEBUG, "%s permitted by libwrap from %s",
        c->opt->servname, c->accepted_address);
}

static int check_libwrap(char *name, int fd) {
    struct request_info request;

    request_init(&request, RQ_DAEMON, name, RQ_FILE, fd, 0);
    fromhost(&request);
    return hosts_access(&request);
}

#ifdef USE_PTHREAD

static ssize_t read_fd(int fd, void *ptr, size_t nbytes, int *recvfd) {
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
    msg.msg_controllen=sizeof(control_un.control);
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

    *recvfd=-1; /* descriptor was not passed */
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
    *recvfd=*((int *)CMSG_DATA(cmptr));
#else
    if(msg.msg_accrightslen==sizeof(int))
        *recvfd=newfd;
#endif

    return n;
}

static ssize_t write_fd(int fd, void *ptr, size_t nbytes, int sendfd) {
    struct msghdr msg;
    struct iovec iov[1];

#ifdef HAVE_MSGHDR_MSG_CONTROL
    union {
        struct cmsghdr cm;
        char control[CMSG_SPACE(sizeof(int))];
    } control_un;
    struct cmsghdr *cmptr;

    msg.msg_control=control_un.control;
    msg.msg_controllen=sizeof(control_un.control);

    cmptr=CMSG_FIRSTHDR(&msg);
    cmptr->cmsg_len=CMSG_LEN(sizeof(int));
    cmptr->cmsg_level=SOL_SOCKET;
    cmptr->cmsg_type=SCM_RIGHTS;
    *((int *)CMSG_DATA(cmptr))=sendfd;
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

#endif /* USE_PTHREAD */

#endif /* USE_LIBWRAP */

/* End of libwrap.c */
