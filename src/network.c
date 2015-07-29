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

#include "common.h"
#include "prototypes.h"

/* #define DEBUG_UCONTEXT */

static int get_socket_error(const int);

/**************************************** s_poll functions */

#ifdef USE_POLL

s_poll_set *s_poll_alloc() {
    /* it needs to be filled with zeros */
    return str_alloc(sizeof(s_poll_set));
}

void s_poll_free(s_poll_set *fds) {
    if(fds) {
        if(fds->ufds)
            str_free(fds->ufds);
        str_free(fds);
    }
}

void s_poll_init(s_poll_set *fds) {
    fds->nfds=0;
    fds->allocated=4; /* prealloc 4 file desciptors */
    fds->ufds=str_realloc(fds->ufds, fds->allocated*sizeof(struct pollfd));
}

void s_poll_add(s_poll_set *fds, int fd, int rd, int wr) {
    unsigned int i;

    for(i=0; i<fds->nfds && fds->ufds[i].fd!=fd; i++)
        ;
    if(i==fds->nfds) {
        if(i==fds->allocated) {
            fds->allocated=i+1;
            fds->ufds=str_realloc(fds->ufds, fds->allocated*sizeof(struct pollfd));
        }
        fds->ufds[i].fd=fd;
        fds->ufds[i].events=0;
        fds->nfds++;
    }
    if(rd)
        fds->ufds[i].events|=POLLIN;
    if(wr)
        fds->ufds[i].events|=POLLOUT;
}

int s_poll_canread(s_poll_set *fds, int fd) {
    unsigned int i;

    for(i=0; i<fds->nfds; i++)
        if(fds->ufds[i].fd==fd)
            return fds->ufds[i].revents&POLLIN;
    return 0; /* not listed in fds */
}

int s_poll_canwrite(s_poll_set *fds, int fd) {
    unsigned int i;

    for(i=0; i<fds->nfds; i++)
        if(fds->ufds[i].fd==fd)
            return fds->ufds[i].revents&POLLOUT;
    return 0; /* not listed in fds */
}

int s_poll_hup(s_poll_set *fds, int fd) {
    unsigned int i;

    for(i=0; i<fds->nfds; i++)
        if(fds->ufds[i].fd==fd)
            return fds->ufds[i].revents&POLLHUP;
    return 0; /* not listed in fds */
}

int s_poll_error(s_poll_set *fds, int fd) {
    unsigned int i;

    for(i=0; i<fds->nfds; i++)
        if(fds->ufds[i].fd==fd)
            return fds->ufds[i].revents&(POLLERR|POLLNVAL) ?
                get_socket_error(fd) : 0;
    return 0; /* not listed in fds */
}

#ifdef USE_UCONTEXT

/* move ready contexts from waiting queue to ready queue */
static void scan_waiting_queue(void) {
    int retval;
    CONTEXT *context, *prev;
    int min_timeout;
    unsigned int nfds, i;
    time_t now;
    static unsigned int max_nfds=0;
    static struct pollfd *ufds=NULL;

    time(&now);
    /* count file descriptors */
    min_timeout=-1;
    nfds=0;
    for(context=waiting_head; context; context=context->next) {
        nfds+=context->fds->nfds;
        if(context->finish>=0) /* finite time */
            if(min_timeout<0 || min_timeout>context->finish-now)
                min_timeout=context->finish-now<0 ? 0 : context->finish-now;
    }
    /* setup ufds structure */
    if(nfds>max_nfds) { /* need to allocate more memory */
        ufds=str_realloc(ufds, nfds*sizeof(struct pollfd));
        max_nfds=nfds;
    }
    nfds=0;
    for(context=waiting_head; context; context=context->next)
        for(i=0; i<context->fds->nfds; i++) {
            ufds[nfds].fd=context->fds->ufds[i].fd;
            ufds[nfds].events=context->fds->ufds[i].events;
            nfds++;
        }

#ifdef DEBUG_UCONTEXT
    s_log(LOG_DEBUG, "Waiting %d second(s) for %d file descriptor(s)",
        min_timeout, nfds);
#endif
    do { /* skip "Interrupted system call" errors */
        retval=poll(ufds, nfds, min_timeout<0 ? -1 : 1000*min_timeout);
    } while(retval<0 && get_last_socket_error()==S_EINTR);
    time(&now);
    /* process the returned data */
    nfds=0;
    prev=NULL; /* previous element of the waiting queue */
    context=waiting_head;
    while(context) {
        context->ready=0;
        /* count ready file descriptors in each context */
        for(i=0; i<context->fds->nfds; i++) {
            context->fds->ufds[i].revents=ufds[nfds].revents;
#ifdef DEBUG_UCONTEXT
            s_log(LOG_DEBUG, "CONTEXT %ld, FD=%d,%s%s ->%s%s%s%s%s",
                context->id, ufds[nfds].fd,
                ufds[nfds].events & POLLIN ? " IN" : "",
                ufds[nfds].events & POLLOUT ? " OUT" : "",
                ufds[nfds].revents & POLLIN ? " IN" : "",
                ufds[nfds].revents & POLLOUT ? " OUT" : "",
                ufds[nfds].revents & POLLERR ? " ERR" : "",
                ufds[nfds].revents & POLLHUP ? " HUP" : "",
                ufds[nfds].revents & POLLNVAL ? " NVAL" : "");
#endif
            if(ufds[nfds].revents)
                context->ready++;
            nfds++;
        }
        if(context->ready || (context->finish>=0 && context->finish<=now)) {
            /* remove context from the waiting queue */
            if(prev)
                prev->next=context->next;
            else
                waiting_head=context->next;
            if(!context->next) /* same as context==waiting_tail */
                waiting_tail=prev;

            /* append context context to the ready queue */
            context->next=NULL;
            if(ready_tail)
                ready_tail->next=context;
            ready_tail=context;
            if(!ready_head)
                ready_head=context;
        } else { /* leave the context context in the waiting queue */
            prev=context;
        }
        context=prev ? prev->next : waiting_head;
    }
}

int s_poll_wait(s_poll_set *fds, int sec, int msec) {
    CONTEXT *context; /* current context */
    static CONTEXT *to_free=NULL; /* delayed memory deallocation */

    /* FIXME: msec parameter is currently ignored with UCONTEXT threads */
    (void)msec; /* skip warning about unused parameter */

    /* remove the current context from ready queue */
    context=ready_head;
    ready_head=ready_head->next;
    if(!ready_head) /* the queue is empty */
        ready_tail=NULL;
    /* it it safe to s_log() after new ready_head is set */

    /* it's illegal to deallocate the stack of the current context */
    if(to_free) { /* a delayed deallocation is scheduled */
#ifdef DEBUG_UCONTEXT
        s_log(LOG_DEBUG, "Releasing context %ld", to_free->id);
#endif
        str_free(to_free->stack);
        str_free(to_free);
        to_free=NULL;
    }

    /* manage the current thread */
    if(fds) { /* something to wait for -> swap the context */
        context->fds=fds; /* set file descriptors to wait for */
        context->finish=sec<0 ? -1 : time(NULL)+sec;

        /* append the current context to the waiting queue */
        context->next=NULL;
        if(waiting_tail)
            waiting_tail->next=context;
        waiting_tail=context;
        if(!waiting_head)
            waiting_head=context;
    } else { /* nothing to wait for -> drop the context */
        to_free=context; /* schedule for delayed deallocation */
    }

    while(!ready_head) /* wait until there is a thread to switch to */
        scan_waiting_queue();

    /* switch threads */
    if(fds) { /* swap the current context */
        if(context->id!=ready_head->id) {
#ifdef DEBUG_UCONTEXT
            s_log(LOG_DEBUG, "Context swap: %ld -> %ld",
                context->id, ready_head->id);
#endif
            swapcontext(&context->context, &ready_head->context);
#ifdef DEBUG_UCONTEXT
            s_log(LOG_DEBUG, "Current context: %ld", ready_head->id);
#endif
        }
        return ready_head->ready;
    } else { /* drop the current context */
#ifdef DEBUG_UCONTEXT
        s_log(LOG_DEBUG, "Context set: %ld (dropped) -> %ld",
            context->id, ready_head->id);
#endif
        setcontext(&ready_head->context);
        ioerror("setcontext"); /* should not ever happen */
        return 0;
    }
}

#else /* USE_UCONTEXT */

int s_poll_wait(s_poll_set *fds, int sec, int msec) {
    int retval;

    do { /* skip "Interrupted system call" errors */
        retval=poll(fds->ufds, fds->nfds, sec<0 ? -1 : 1000*sec+msec);
    } while(retval<0 && get_last_socket_error()==S_EINTR);
    return retval;
}

#endif /* USE_UCONTEXT */

#else /* select */

s_poll_set *s_poll_alloc() {
    /* it needs to be filled with zeros */
    return str_alloc(sizeof(s_poll_set));
}

void s_poll_free(s_poll_set *fds) {
    if(fds)
        str_free(fds);
}

void s_poll_init(s_poll_set *fds) {
    FD_ZERO(&fds->irfds);
    FD_ZERO(&fds->iwfds);
    FD_ZERO(&fds->ixfds);
    fds->max=0; /* no file descriptors */
}

void s_poll_add(s_poll_set *fds, int fd, int rd, int wr) {
    if(rd)
        FD_SET((unsigned int)fd, &fds->irfds);
    if(wr)
        FD_SET((unsigned int)fd, &fds->iwfds);
    /* always expect errors (and the Spanish Inquisition) */
    FD_SET((unsigned int)fd, &fds->ixfds);
    if(fd>fds->max)
        fds->max=fd;
}

int s_poll_canread(s_poll_set *fds, int fd) {
    return FD_ISSET(fd, &fds->orfds);
}

int s_poll_canwrite(s_poll_set *fds, int fd) {
    return FD_ISSET(fd, &fds->owfds);
}

int s_poll_hup(s_poll_set *fds, int fd) {
    (void)fds; /* skip warning about unused parameter */
    (void)fd; /* skip warning about unused parameter */
    return 0; /* FIXME: how to detect HUP condition with select()? */
}

int s_poll_error(s_poll_set *fds, int fd) {
    /* error conditions are signaled as read, but apparently *not* in Winsock:
     * http://msdn.microsoft.com/en-us/library/windows/desktop/ms737625%28v=vs.85%29.aspx */
    if(!FD_ISSET(fd, &fds->orfds) && !FD_ISSET(fd, &fds->oxfds))
        return 0;
    return get_socket_error(fd); /* check if it's really an error */
}

int s_poll_wait(s_poll_set *fds, int sec, int msec) {
    int retval;
    struct timeval tv, *tv_ptr;

    do { /* skip "Interrupted system call" errors */
        memcpy(&fds->orfds, &fds->irfds, sizeof(fd_set));
        memcpy(&fds->owfds, &fds->iwfds, sizeof(fd_set));
        memcpy(&fds->oxfds, &fds->ixfds, sizeof(fd_set));
        if(sec<0) { /* infinite timeout */
            tv_ptr=NULL;
        } else {
            tv.tv_sec=sec;
            tv.tv_usec=1000*msec;
            tv_ptr=&tv;
        }
        retval=select(fds->max+1, &fds->orfds, &fds->owfds, &fds->oxfds, tv_ptr);
    } while(retval<0 && get_last_socket_error()==S_EINTR);
    return retval;
}

#endif /* USE_POLL */

/**************************************** fd management */

int set_socket_options(int s, int type) {
    SOCK_OPT *ptr;
    extern SOCK_OPT sock_opts[];
    static char *type_str[3]={"accept", "local", "remote"};
    int opt_size;
    int retval=0; /* no error found */

    for(ptr=sock_opts; ptr->opt_str; ptr++) {
        if(!ptr->opt_val[type])
            continue; /* default */
        switch(ptr->opt_type) {
        case TYPE_LINGER:
            opt_size=sizeof(struct linger);
            break;
        case TYPE_TIMEVAL:
            opt_size=sizeof(struct timeval);
            break;
        case TYPE_STRING:
            opt_size=strlen(ptr->opt_val[type]->c_val)+1;
            break;
        default:
            opt_size=sizeof(int);
        }
        if(setsockopt(s, ptr->opt_level, ptr->opt_name,
                (void *)ptr->opt_val[type], opt_size)) {
            if(get_last_socket_error()==S_EOPNOTSUPP) {
                /* most likely stdin/stdout or AF_UNIX socket */
                s_log(LOG_DEBUG,
                    "Option %s not supported on %s socket",
                    ptr->opt_str, type_str[type]);
            } else {
                sockerror(ptr->opt_str);
                retval=-1; /* failed to set this option */
            }
        }
#ifdef DEBUG_FD_ALLOC
        else {
            s_log(LOG_DEBUG, "Option %s set on %s socket",
                ptr->opt_str, type_str[type]);
        }
#endif /* DEBUG_FD_ALLOC */
    }
    return retval; /* returns 0 when all options succeeded */
}

static int get_socket_error(const int fd) {
    int err;
    socklen_t optlen=sizeof err;

    if(getsockopt(fd, SOL_SOCKET, SO_ERROR, (void *)&err, &optlen))
        err=get_last_socket_error(); /* failed -> ask why */
    return err==S_ENOTSOCK ? 0 : err;
}

/**************************************** simulate blocking I/O */

int connect_blocking(CLI *c, SOCKADDR_UNION *addr, socklen_t addrlen) {
    int error;
    char *dst;

    dst=s_ntop(addr, addrlen);
    s_log(LOG_INFO, "connect_blocking: connecting %s", dst);

    if(!connect(c->fd, &addr->sa, addrlen)) {
        s_log(LOG_NOTICE, "connect_blocking: connected %s", dst);
        str_free(dst);
        return 0; /* no error -> success (on some OSes over the loopback) */
    }
    error=get_last_socket_error();
    if(error!=S_EINPROGRESS && error!=S_EWOULDBLOCK) {
        s_log(LOG_ERR, "connect_blocking: connect %s: %s (%d)",
            dst, s_strerror(error), error);
        str_free(dst);
        return -1;
    }

    s_log(LOG_DEBUG, "connect_blocking: s_poll_wait %s: waiting %d seconds",
        dst, c->opt->timeout_connect);
    s_poll_init(c->fds);
    s_poll_add(c->fds, c->fd, 1, 1);
    switch(s_poll_wait(c->fds, c->opt->timeout_connect, 0)) {
    case -1:
        error=get_last_socket_error();
        s_log(LOG_ERR, "connect_blocking: s_poll_wait %s: %s (%d)",
            dst, s_strerror(error), error);
        str_free(dst);
        return -1;
    case 0:
        s_log(LOG_ERR, "connect_blocking: s_poll_wait %s:"
            " TIMEOUTconnect exceeded", dst);
        str_free(dst);
        return -1;
    default:
        error=get_socket_error(c->fd);
        if(error) {
            s_log(LOG_ERR, "connect_blocking: connect %s: %s (%d)",
               dst, s_strerror(error), error);
            str_free(dst);
            return -1;
        }
        if(s_poll_canwrite(c->fds, c->fd)) {
            s_log(LOG_NOTICE, "connect_blocking: connected %s", dst);
            str_free(dst);
            return 0; /* success */
        }
        s_log(LOG_ERR, "connect_blocking: s_poll_wait %s: internal error",
            dst);
        str_free(dst);
        return -1;
    }
    return -1; /* should not be possible */
}

void write_blocking(CLI *c, int fd, void *ptr, int len) {
        /* simulate a blocking write */
    int num;

    while(len>0) {
        s_poll_init(c->fds);
        s_poll_add(c->fds, fd, 0, 1); /* write */
        switch(s_poll_wait(c->fds, c->opt->timeout_busy, 0)) {
        case -1:
            sockerror("write_blocking: s_poll_wait");
            longjmp(c->err, 1); /* error */
        case 0:
            s_log(LOG_INFO, "write_blocking: s_poll_wait:"
                " TIMEOUTbusy exceeded: sending reset");
            longjmp(c->err, 1); /* timeout */
        case 1:
            break; /* OK */
        default:
            s_log(LOG_ERR, "write_blocking: s_poll_wait: unknown result");
            longjmp(c->err, 1); /* error */
        }
        num=writesocket(fd, ptr, len);
        switch(num) {
        case -1: /* error */
            sockerror("writesocket (write_blocking)");
            longjmp(c->err, 1);
        }
        ptr=(u8 *)ptr+num;
        len-=num;
    }
}

void read_blocking(CLI *c, int fd, void *ptr, int len) {
        /* simulate a blocking read */
    int num;

    while(len>0) {
        s_poll_init(c->fds);
        s_poll_add(c->fds, fd, 1, 0); /* read */
        switch(s_poll_wait(c->fds, c->opt->timeout_busy, 0)) {
        case -1:
            sockerror("read_blocking: s_poll_wait");
            longjmp(c->err, 1); /* error */
        case 0:
            s_log(LOG_INFO, "read_blocking: s_poll_wait:"
                " TIMEOUTbusy exceeded: sending reset");
            longjmp(c->err, 1); /* timeout */
        case 1:
            break; /* OK */
        default:
            s_log(LOG_ERR, "read_blocking: s_poll_wait: unknown result");
            longjmp(c->err, 1); /* error */
        }
        num=readsocket(fd, ptr, len);
        switch(num) {
        case -1: /* error */
            sockerror("readsocket (read_blocking)");
            longjmp(c->err, 1);
        case 0: /* EOF */
            s_log(LOG_ERR, "Unexpected socket close (read_blocking)");
            longjmp(c->err, 1);
        }
        ptr=(u8 *)ptr+num;
        len-=num;
    }
}

void fd_putline(CLI *c, int fd, const char *line) {
    char *tmpline;
    const char crlf[]="\r\n";
    int len;

    tmpline=str_printf("%s%s", line, crlf);
    len=strlen(tmpline);
    write_blocking(c, fd, tmpline, len);
    tmpline[len-2]='\0'; /* remove CRLF */
    safestring(tmpline);
    s_log(LOG_DEBUG, " -> %s", tmpline);
    str_free(tmpline);
}

char *fd_getline(CLI *c, int fd) {
    char *line, *tmpline;
    int ptr=0, allocated=32;

    line=str_alloc(allocated);
    for(;;) {
        s_poll_init(c->fds);
        s_poll_add(c->fds, fd, 1, 0); /* read */
        switch(s_poll_wait(c->fds, c->opt->timeout_busy, 0)) {
        case -1:
            sockerror("fd_getline: s_poll_wait");
            str_free(line);
            longjmp(c->err, 1); /* error */
        case 0:
            s_log(LOG_INFO, "fd_getline: s_poll_wait:"
                " TIMEOUTbusy exceeded: sending reset");
            str_free(line);
            longjmp(c->err, 1); /* timeout */
        case 1:
            break; /* OK */
        default:
            s_log(LOG_ERR, "fd_getline: s_poll_wait: Unknown result");
            str_free(line);
            longjmp(c->err, 1); /* error */
        }
        if(allocated<ptr+1) {
            allocated*=2;
            line=str_realloc(line, allocated);
        }
        switch(readsocket(fd, line+ptr, 1)) {
        case -1: /* error */
            sockerror("fd_getline: readsocket");
            str_free(line);
            longjmp(c->err, 1);
        case 0: /* EOF */
            s_log(LOG_ERR, "fd_getline: Unexpected socket close");
            str_free(line);
            longjmp(c->err, 1);
        }
        if(line[ptr]=='\r')
            continue;
        if(line[ptr]=='\n')
            break;
        if(line[ptr]=='\0')
            break;
        if(++ptr>65536) { /* >64KB --> DoS protection */
            s_log(LOG_ERR, "fd_getline: Line too long");
            str_free(line);
            longjmp(c->err, 1);
        }
    }
    line[ptr]='\0';
    tmpline=str_dup(line);
    safestring(tmpline);
    s_log(LOG_DEBUG, " <- %s", tmpline);
    str_free(tmpline);
    return line;
}

void fd_printf(CLI *c, int fd, const char *format, ...) {
    va_list ap;
    char *line;

    va_start(ap, format);
    line=str_vprintf(format, ap);
    va_end(ap);
    if(!line) {
        s_log(LOG_ERR, "fd_printf: str_vprintf failed");
        longjmp(c->err, 1);
    }
    fd_putline(c, fd, line);
    str_free(line);
}

#define INET_SOCKET_PAIR

int make_sockets(int fd[2]) { /* make a pair of connected ipv4 sockets */
#ifdef INET_SOCKET_PAIR
    struct sockaddr_in addr;
    socklen_t addrlen;
    int s; /* temporary socket awaiting for connection */

    /* create two *blocking* sockets first */
    s=s_socket(AF_INET, SOCK_STREAM, 0, 0, "make_sockets: s_socket#1");
    if(s<0) {
        return 1;
    }
    fd[1]=s_socket(AF_INET, SOCK_STREAM, 0, 0, "make_sockets: s_socket#2");
    if(fd[1]<0) {
        closesocket(s);
        return 1;
    }

    addrlen=sizeof addr;
    memset(&addr, 0, addrlen);
    addr.sin_family=AF_INET;
    addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    addr.sin_port=htons(0); /* dynamic port allocation */
    if(bind(s, (struct sockaddr *)&addr, addrlen))
        log_error(LOG_DEBUG, get_last_socket_error(), "make_sockets: bind#1");
    if(bind(fd[1], (struct sockaddr *)&addr, addrlen))
        log_error(LOG_DEBUG, get_last_socket_error(), "make_sockets: bind#2");

    if(listen(s, 1)) {
        sockerror("make_sockets: listen");
        closesocket(s);
        closesocket(fd[1]);
        return 1;
    }
    if(getsockname(s, (struct sockaddr *)&addr, &addrlen)) {
        sockerror("make_sockets: getsockname");
        closesocket(s);
        closesocket(fd[1]);
        return 1;
    }
    if(connect(fd[1], (struct sockaddr *)&addr, addrlen)) {
        sockerror("make_sockets: connect");
        closesocket(s);
        closesocket(fd[1]);
        return 1;
    }
    fd[0]=s_accept(s, (struct sockaddr *)&addr, &addrlen, 1,
        "make_sockets: s_accept");
    if(fd[0]<0) {
        closesocket(s);
        closesocket(fd[1]);
        return 1;
    }
    closesocket(s); /* don't care about the result */
    set_nonblock(fd[0], 1);
    set_nonblock(fd[1], 1);
#else
    if(s_socketpair(AF_UNIX, SOCK_STREAM, 0, fd, 1, "make_sockets: socketpair"))
        return 1;
#endif
    return 0;
}

/* end of network.c */
