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

#if defined(_WIN32) || defined(_WIN32_WCE)
/* bypass automatic index bound checks in the FD_SET() macro */
#define FD_SETSIZE 1000000
#endif

#include "common.h"
#include "prototypes.h"

/* #define DEBUG_UCONTEXT */

NOEXPORT void s_poll_realloc(s_poll_set *);
#ifndef USE_UCONTEXT
NOEXPORT void check_terminate(s_poll_set *);
#endif

/**************************************** s_poll functions */

#ifdef USE_POLL

s_poll_set *s_poll_alloc() {
    /* it needs to be filled with zeros */
    return str_alloc(sizeof(s_poll_set));
}

void s_poll_free(s_poll_set *fds) {
    if(fds) {
        str_free(fds->ufds);
        str_free(fds);
    }
}

void s_poll_init(s_poll_set *fds, int main_thread) {
    fds->nfds=0;
    fds->allocated=4; /* prealloc 4 file descriptors */
    s_poll_realloc(fds);
    fds->main_thread=main_thread;
    s_poll_add(fds, main_thread ? signal_pipe[0] : terminate_pipe[0], 1, 0);
}

void s_poll_add(s_poll_set *fds, SOCKET fd, int rd, int wr) {
    unsigned i;

    for(i=0; i<fds->nfds && fds->ufds[i].fd!=fd; i++)
        ;
    if(i==fds->nfds) { /* not found */
        if(i==fds->allocated) {
            fds->allocated=i+1;
            s_poll_realloc(fds);
        }
        fds->ufds[i].fd=fd;
        fds->ufds[i].events=0;
        fds->nfds++;
    }
    if(rd) {
        fds->ufds[i].events|=POLLIN;
#ifdef POLLRDHUP
        fds->ufds[i].events|=POLLRDHUP;
#endif
    }
    if(wr)
        fds->ufds[i].events|=POLLOUT;
}

void s_poll_remove(s_poll_set *fds, SOCKET fd) {
    unsigned i;

    for(i=0; i<fds->nfds && fds->ufds[i].fd!=fd; i++)
        ;
    if(i<fds->nfds) { /* found */
        memmove(fds->ufds+i, fds->ufds+i+1,
            (fds->nfds-i-1)*sizeof(struct pollfd));
        fds->nfds--;
    }
}

int s_poll_canread(s_poll_set *fds, SOCKET fd) {
    unsigned i;

    for(i=0; i<fds->nfds; i++)
        if(fds->ufds[i].fd==fd)
            return fds->ufds[i].revents&(POLLIN|POLLERR);
    return 0; /* not listed in fds */
}

int s_poll_canwrite(s_poll_set *fds, SOCKET fd) {
    unsigned i;

    for(i=0; i<fds->nfds; i++)
        if(fds->ufds[i].fd==fd)
            return fds->ufds[i].revents&(POLLOUT|POLLERR);
    return 0; /* not listed in fds */
}

/* best doc: http://lxr.free-electrons.com/source/net/ipv4/tcp.c#L456 */

int s_poll_hup(s_poll_set *fds, SOCKET fd) {
    unsigned i;

    for(i=0; i<fds->nfds; i++)
        if(fds->ufds[i].fd==fd)
            return fds->ufds[i].revents&POLLHUP; /* read and write closed */
    return 0; /* not listed in fds */
}

int s_poll_rdhup(s_poll_set *fds, SOCKET fd) {
    unsigned i;

    for(i=0; i<fds->nfds; i++)
        if(fds->ufds[i].fd==fd)
#ifdef POLLRDHUP
            return fds->ufds[i].revents&POLLRDHUP; /* read closed */
#else
            return fds->ufds[i].revents&POLLHUP; /* read and write closed */
#endif
    return 0; /* not listed in fds */
}

int s_poll_err(s_poll_set *fds, SOCKET fd) {
    unsigned i;

    for(i=0; i<fds->nfds; i++)
        if(fds->ufds[i].fd==fd)
            return fds->ufds[i].revents&POLLERR;
    return 0; /* not listed in fds */
}

NOEXPORT void s_poll_realloc(s_poll_set *fds) {
    fds->ufds=str_realloc(fds->ufds, fds->allocated*sizeof(struct pollfd));
}

void s_poll_dump(s_poll_set *fds, int level) {
    unsigned i;

    for(i=0; i<fds->nfds; i++)
        s_log(level, "FD=%ld events=0x%X revents=0x%X",
            (long)fds->ufds[i].fd, fds->ufds[i].events, fds->ufds[i].revents);
}

#ifdef USE_UCONTEXT

/* move ready contexts from waiting queue to ready queue */
NOEXPORT void scan_waiting_queue(void) {
    int retval;
    CONTEXT *context, *prev;
    int min_timeout;
    unsigned nfds, i;
    time_t now;
    static unsigned max_nfds=0;
    static struct pollfd *ufds=NULL;

    time(&now);
    /* count file descriptors */
    min_timeout=-1; /* infinity */
    nfds=0;
    for(context=waiting_head; context; context=context->next) {
        nfds+=context->fds->nfds;
        if(context->finish>=0) /* finite time */
            if(min_timeout<0 || min_timeout>context->finish-now)
                min_timeout=
                    (int)(context->finish-now<0 ? 0 : context->finish-now);
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
            s_log(LOG_DEBUG, "CONTEXT %ld, FD=%ld,%s%s ->%s%s%s%s%s",
                context->id, (long)ufds[nfds].fd,
                (ufds[nfds].events & POLLIN) ? " IN" : "",
                (ufds[nfds].events & POLLOUT) ? " OUT" : "",
                (ufds[nfds].revents & POLLIN) ? " IN" : "",
                (ufds[nfds].revents & POLLOUT) ? " OUT" : "",
                (ufds[nfds].revents & POLLERR) ? " ERR" : "",
                (ufds[nfds].revents & POLLHUP) ? " HUP" : "",
                (ufds[nfds].revents & POLLNVAL) ? " NVAL" : "");
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
    (void)msec; /* squash the unused parameter warning */

    /* remove the current context from ready queue */
    context=ready_head;
    ready_head=ready_head->next;
    if(!ready_head) /* the queue is empty */
        ready_tail=NULL;
    /* it is safe to s_log() after new ready_head is set */

    /* it is illegal to deallocate the stack of the current context */
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
    if(retval>0)
        check_terminate(fds);
    return retval;
}

#endif /* USE_UCONTEXT */

#else /* select */

s_poll_set *s_poll_alloc() {
    /* it needs to be filled with zeros */
    return str_alloc(sizeof(s_poll_set));
}

void s_poll_free(s_poll_set *fds) {
    if(fds) {
        str_free(fds->irfds);
        str_free(fds->iwfds);
        str_free(fds->ixfds);
        str_free(fds->orfds);
        str_free(fds->owfds);
        str_free(fds->oxfds);
        str_free(fds);
    }
}

void s_poll_init(s_poll_set *fds, int main_thread) {
#ifdef USE_WIN32
    fds->allocated=4; /* prealloc 4 file descriptors */
#endif
    s_poll_realloc(fds);
    FD_ZERO(fds->irfds);
    FD_ZERO(fds->iwfds);
    FD_ZERO(fds->ixfds);
    fds->max=0; /* no file descriptors */
    fds->main_thread=main_thread;
#ifdef USE_WIN32
    /* there seems to be a deadlock in the Windows select() function when
     * waiting for the same terminate_pipe socket in multiple threads */
    if(main_thread)
        s_poll_add(fds, signal_pipe[0], 1, 0);
#else
    s_poll_add(fds, main_thread ? signal_pipe[0] : terminate_pipe[0], 1, 0);
#endif
}

void s_poll_add(s_poll_set *fds, SOCKET fd, int rd, int wr) {
#ifdef USE_WIN32
    /* fds->ixfds contains union of fds->irfds and fds->iwfds */
    if(fds->ixfds->fd_count>=fds->allocated) {
        fds->allocated=fds->ixfds->fd_count+1;
        s_poll_realloc(fds);
    }
#endif
    if(rd)
        FD_SET(fd, fds->irfds);
    if(wr)
        FD_SET(fd, fds->iwfds);
    /* always expect errors (and the Spanish Inquisition) */
    FD_SET(fd, fds->ixfds);
    if(fd>fds->max)
        fds->max=fd;
}

void s_poll_remove(s_poll_set *fds, SOCKET fd) {
    FD_CLR(fd, fds->irfds);
    FD_CLR(fd, fds->iwfds);
    FD_CLR(fd, fds->ixfds);
}

int s_poll_canread(s_poll_set *fds, SOCKET fd) {
    /* ignore exception if there is no error (WinCE 6.0 anomaly) */
    return FD_ISSET(fd, fds->orfds) ||
        (FD_ISSET(fd, fds->oxfds) && get_socket_error(fd));
}

int s_poll_canwrite(s_poll_set *fds, SOCKET fd) {
    /* ignore exception if there is no error (WinCE 6.0 anomaly) */
    return FD_ISSET(fd, fds->owfds) ||
        (FD_ISSET(fd, fds->oxfds) && get_socket_error(fd));
}

int s_poll_hup(s_poll_set *fds, SOCKET fd) {
    (void)fds; /* squash the unused parameter warning */
    (void)fd; /* squash the unused parameter warning */
    return 0; /* FIXME: how to detect the HUP condition with select()? */
}

int s_poll_rdhup(s_poll_set *fds, SOCKET fd) {
    (void)fds; /* squash the unused parameter warning */
    (void)fd; /* squash the unused parameter warning */
    return 0; /* FIXME: how to detect the RDHUP condition with select()? */
}

int s_poll_err(s_poll_set *fds, SOCKET fd) {
    return FD_ISSET(fd, fds->oxfds);
}

#ifdef USE_WIN32
#define FD_SIZE(fds) (8+(fds)->allocated*sizeof(SOCKET))
#else
#define FD_SIZE(fds) (sizeof(fd_set))
#endif

int s_poll_wait(s_poll_set *fds, int sec, int msec) {
    int retval;
    struct timeval tv, *tv_ptr;

    do { /* skip "Interrupted system call" errors */
        memcpy(fds->orfds, fds->irfds, FD_SIZE(fds));
        memcpy(fds->owfds, fds->iwfds, FD_SIZE(fds));
#ifndef _WIN32_WCE
        memcpy(fds->oxfds, fds->ixfds, FD_SIZE(fds));
#else /* WinCE reports unexpected permanent exceptions */
        FD_ZERO(fds->oxfds);
#endif
        if(sec<0) { /* infinite timeout */
            tv_ptr=NULL;
        } else {
            tv.tv_sec=sec;
            tv.tv_usec=1000*msec;
            tv_ptr=&tv;
        }
        retval=select((int)fds->max+1,
            fds->orfds, fds->owfds, fds->oxfds, tv_ptr);
    } while(retval<0 && get_last_socket_error()==S_EINTR);
    if(retval>0)
        check_terminate(fds);
    return retval;
}

NOEXPORT void s_poll_realloc(s_poll_set *fds) {
    fds->irfds=str_realloc(fds->irfds, FD_SIZE(fds));
    fds->iwfds=str_realloc(fds->iwfds, FD_SIZE(fds));
    fds->ixfds=str_realloc(fds->ixfds, FD_SIZE(fds));
    fds->orfds=str_realloc(fds->orfds, FD_SIZE(fds));
    fds->owfds=str_realloc(fds->owfds, FD_SIZE(fds));
    fds->oxfds=str_realloc(fds->oxfds, FD_SIZE(fds));
}

void s_poll_dump(s_poll_set *fds, int level) {
    SOCKET fd;
    int ir, iw, ix, or, ow, ox;

    for(fd=0; fd<fds->max+1; fd++) {
        ir=FD_ISSET(fd, fds->irfds);
        iw=FD_ISSET(fd, fds->iwfds);
        ix=FD_ISSET(fd, fds->ixfds);
        or=FD_ISSET(fd, fds->orfds);
        ow=FD_ISSET(fd, fds->owfds);
        ox=FD_ISSET(fd, fds->oxfds);
        if(ir || iw || ix || or || ow || ox)
            s_log(level, "FD=%ld ifds=%c%c%c ofds=%c%c%c", (long)fd,
                ir?'r':'-', iw?'w':'-', ix?'x':'-',
                or?'r':'-', ow?'w':'-', ox?'x':'-');
    }
}

#endif /* USE_POLL */

void s_poll_sleep(int sec, int msec) {
#ifdef USE_WIN32
    Sleep(1000*(DWORD)sec+(DWORD)msec);
#else
    s_poll_set *fds=s_poll_alloc();
    s_poll_init(fds, 0);
    s_poll_wait(fds, sec, msec);
    s_poll_free(fds);
#endif
}

#ifndef USE_UCONTEXT
NOEXPORT void check_terminate(s_poll_set *fds) {
    if(!fds->main_thread && s_poll_canread(fds, terminate_pipe[0])) {
#ifdef USE_PTHREAD
        pthread_exit(NULL);
#endif /* USE_PTHREAD */
#if defined(USE_WIN32) || defined(USE_OS2)
#if defined(_WIN32_WCE)
        /* FIXME */
#else /* !_WIN32_WCE */
        _endthreadex(0);
#endif /* _WIN32_WCE */
#endif /* USE_WIN32 || USE_OS2 */
#ifdef USE_UCONTEXT
        /* currently unused */
        s_poll_wait(NULL, 0, 0); /* wait on poll() */
#endif /* USE_UCONTEXT */
#ifdef USE_FORK
        exit(0);
#endif /* USE_FORK */
    }
}
#endif

/**************************************** fd management */

int socket_options_set(SERVICE_OPTIONS *service, SOCKET s, int type) {
    SOCK_OPT *ptr;
    static char *type_str[3]={"accept", "local", "remote"};
    socklen_t opt_size;
    int retval=0; /* no error found */

    s_log(LOG_DEBUG, "Setting %s socket options (FD=%ld)",
        type_str[type], (long)s);
    for(ptr=service->sock_opts; ptr->opt_str; ptr++) {
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
            opt_size=(socklen_t)strlen(ptr->opt_val[type]->c_val)+1;
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
        else {
            s_log(LOG_DEBUG, "Option %s set on %s socket",
                ptr->opt_str, type_str[type]);
        }
    }
    return retval; /* returns 0 when all options succeeded */
}

int get_socket_error(const SOCKET fd) {
    int err;
    socklen_t optlen=sizeof err;

    if(getsockopt(fd, SOL_SOCKET, SO_ERROR, (void *)&err, &optlen))
        err=get_last_socket_error(); /* failed -> ask why */
    return err==S_ENOTSOCK ? 0 : err;
}

/**************************************** simulate blocking I/O */

int s_connect(CLI *c, SOCKADDR_UNION *addr, socklen_t addrlen) {
    int error;
    char *dst;

    dst=s_ntop(addr, addrlen);
    s_log(LOG_INFO, "s_connect: connecting %s", dst);

    if(!connect(c->fd, &addr->sa, addrlen)) {
        s_log(LOG_INFO, "s_connect: connected %s", dst);
        str_free(dst);
        return 0; /* no error -> success (on some OSes over the loopback) */
    }
    error=get_last_socket_error();
    if(error!=S_EINPROGRESS && error!=S_EWOULDBLOCK) {
        s_log(LOG_ERR, "s_connect: connect %s: %s (%d)",
            dst, s_strerror(error), error);
        str_free(dst);
        return -1;
    }

    s_log(LOG_DEBUG, "s_connect: s_poll_wait %s: waiting %d seconds",
        dst, c->opt->timeout_connect);
    s_poll_init(c->fds, 0);
    s_poll_add(c->fds, c->fd, 1, 1);
    s_poll_dump(c->fds, LOG_DEBUG);
    switch(s_poll_wait(c->fds, c->opt->timeout_connect, 0)) {
    case -1:
        error=get_last_socket_error();
        s_log(LOG_ERR, "s_connect: s_poll_wait %s: %s (%d)",
            dst, s_strerror(error), error);
        str_free(dst);
        return -1;
    case 0:
        s_log(LOG_ERR, "s_connect: s_poll_wait %s:"
            " TIMEOUTconnect exceeded", dst);
        str_free(dst);
        return -1;
    default:
        error=get_socket_error(c->fd);
        if(error) {
            s_log(LOG_ERR, "s_connect: connect %s: %s (%d)",
               dst, s_strerror(error), error);
            str_free(dst);
            return -1;
        }
        if(s_poll_canwrite(c->fds, c->fd)) {
            s_log(LOG_NOTICE, "s_connect: connected %s", dst);
            str_free(dst);
            return 0; /* success */
        }
        s_log(LOG_ERR, "s_connect: s_poll_wait %s: internal error",
            dst);
        str_free(dst);
        return -1;
    }
    return -1; /* should not be possible */
}

void s_write(CLI *c, SOCKET fd, const void *buf, size_t len) {
        /* simulate a blocking write */
    uint8_t *ptr=(uint8_t *)buf;
    ssize_t num;

    while(len>0) {
        s_poll_init(c->fds, 0);
        s_poll_add(c->fds, fd, 0, 1); /* write */
        switch(s_poll_wait(c->fds, c->opt->timeout_busy, 0)) {
        case -1:
            sockerror("s_write: s_poll_wait");
            throw_exception(c, 1); /* error */
        case 0:
            s_log(LOG_INFO, "s_write: s_poll_wait:"
                " TIMEOUTbusy exceeded: sending reset");
            throw_exception(c, 1); /* timeout */
        case 1:
            break; /* OK */
        default:
            s_log(LOG_ERR, "s_write: s_poll_wait: unknown result");
            throw_exception(c, 1); /* error */
        }
        num=writesocket(fd, (void *)ptr, len);
        if(num==-1) { /* error */
            sockerror("writesocket (s_write)");
            throw_exception(c, 1);
        }
        ptr+=(size_t)num;
        len-=(size_t)num;
    }
}

void s_read(CLI *c, SOCKET fd, void *ptr, size_t len) {
        /* simulate a blocking read */
    ssize_t num;

    while(len>0) {
        s_poll_init(c->fds, 0);
        s_poll_add(c->fds, fd, 1, 0); /* read */
        switch(s_poll_wait(c->fds, c->opt->timeout_busy, 0)) {
        case -1:
            sockerror("s_read: s_poll_wait");
            throw_exception(c, 1); /* error */
        case 0:
            s_log(LOG_INFO, "s_read: s_poll_wait:"
                " TIMEOUTbusy exceeded: sending reset");
            throw_exception(c, 1); /* timeout */
        case 1:
            break; /* OK */
        default:
            s_log(LOG_ERR, "s_read: s_poll_wait: unknown result");
            throw_exception(c, 1); /* error */
        }
        num=readsocket(fd, ptr, len);
        switch(num) {
        case -1: /* error */
            sockerror("readsocket (s_read)");
            throw_exception(c, 1);
        case 0: /* EOF */
            s_log(LOG_ERR, "Unexpected socket close (s_read)");
            throw_exception(c, 1);
        }
        ptr=(uint8_t *)ptr+num;
        len-=(size_t)num;
    }
}

void fd_putline(CLI *c, SOCKET fd, const char *line) {
    char *tmpline;
    const char crlf[]="\r\n";
    size_t len;

    tmpline=str_printf("%s%s", line, crlf);
    len=strlen(tmpline);
    s_write(c, fd, tmpline, len);
    str_free(tmpline);
    s_log(LOG_DEBUG, " -> %s", line);
}

char *fd_getline(CLI *c, SOCKET fd) {
    char *line;
    size_t ptr=0, allocated=32;

    line=str_alloc(allocated);
    for(;;) {
        if(ptr>65536) { /* >64KB --> DoS protection */
            s_log(LOG_ERR, "fd_getline: Line too long");
            str_free(line);
            throw_exception(c, 1);
        }
        if(allocated<ptr+1) {
            allocated*=2;
            line=str_realloc(line, allocated);
        }
        s_read(c, fd, line+ptr, 1);
        if(line[ptr]=='\r')
            continue;
        if(line[ptr]=='\n')
            break;
        if(line[ptr]=='\0')
            break;
        ++ptr;
    }
    line[ptr]='\0';
    s_log(LOG_DEBUG, " <- %s", line);
    return line;
}

void fd_printf(CLI *c, SOCKET fd, const char *format, ...) {
    va_list ap;
    char *line;

    va_start(ap, format);
    line=str_vprintf(format, ap);
    va_end(ap);
    if(!line) {
        s_log(LOG_ERR, "fd_printf: str_vprintf failed");
        throw_exception(c, 1);
    }
    fd_putline(c, fd, line);
    str_free(line);
}

void s_ssl_write(CLI *c, const void *buf, int len) {
        /* simulate a blocking SSL_write */
    uint8_t *ptr=(uint8_t *)buf;
    int num;

    while(len>0) {
        s_poll_init(c->fds, 0);
        s_poll_add(c->fds, c->ssl_wfd->fd, 0, 1); /* write */
        switch(s_poll_wait(c->fds, c->opt->timeout_busy, 0)) {
        case -1:
            sockerror("s_write: s_poll_wait");
            throw_exception(c, 1); /* error */
        case 0:
            s_log(LOG_INFO, "s_write: s_poll_wait:"
                " TIMEOUTbusy exceeded: sending reset");
            throw_exception(c, 1); /* timeout */
        case 1:
            break; /* OK */
        default:
            s_log(LOG_ERR, "s_write: s_poll_wait: unknown result");
            throw_exception(c, 1); /* error */
        }
        num=SSL_write(c->ssl, (void *)ptr, len);
        if(num==-1) { /* error */
            sockerror("SSL_write (s_ssl_write)");
            throw_exception(c, 1);
        }
        ptr+=num;
        len-=num;
    }
}

void s_ssl_read(CLI *c, void *ptr, int len) {
        /* simulate a blocking SSL_read */
    int num;

    while(len>0) {
        if(!SSL_pending(c->ssl)) {
            s_poll_init(c->fds, 0);
            s_poll_add(c->fds, c->ssl_rfd->fd, 1, 0); /* read */
            switch(s_poll_wait(c->fds, c->opt->timeout_busy, 0)) {
            case -1:
                sockerror("s_read: s_poll_wait");
                throw_exception(c, 1); /* error */
            case 0:
                s_log(LOG_INFO, "s_read: s_poll_wait:"
                    " TIMEOUTbusy exceeded: sending reset");
                throw_exception(c, 1); /* timeout */
            case 1:
                break; /* OK */
            default:
                s_log(LOG_ERR, "s_read: s_poll_wait: unknown result");
                throw_exception(c, 1); /* error */
            }
        }
        num=SSL_read(c->ssl, ptr, len);
        switch(num) {
        case -1: /* error */
            sockerror("SSL_read (s_ssl_read)");
            throw_exception(c, 1);
        case 0: /* EOF */
            s_log(LOG_ERR, "Unexpected socket close (s_ssl_read)");
            throw_exception(c, 1);
        }
        ptr=(uint8_t *)ptr+num;
        len-=num;
    }
}

char *ssl_getstring(CLI *c) { /* get null-terminated string */
    char *line;
    size_t ptr=0, allocated=32;

    line=str_alloc(allocated);
    for(;;) {
        if(ptr>65536) { /* >64KB --> DoS protection */
            s_log(LOG_ERR, "ssl_getstring: Line too long");
            str_free(line);
            throw_exception(c, 1);
        }
        if(allocated<ptr+1) {
            allocated*=2;
            line=str_realloc(line, allocated);
        }
        s_ssl_read(c, line+ptr, 1);
        if(line[ptr]=='\0')
            break;
        ++ptr;
    }
    return line;
}

char *ssl_getline(CLI *c) { /* get newline-terminated string */
    char *line;
    size_t ptr=0, allocated=32;

    line=str_alloc(allocated);
    for(;;) {
        if(ptr>65536) { /* >64KB --> DoS protection */
            s_log(LOG_ERR, "ssl_getline: Line too long");
            str_free(line);
            throw_exception(c, 1);
        }
        if(allocated<ptr+1) {
            allocated*=2;
            line=str_realloc(line, allocated);
        }
        s_ssl_read(c, line+ptr, 1);
        if(line[ptr]=='\r')
            continue;
        if(line[ptr]=='\n')
            break;
        if(line[ptr]=='\0')
            break;
        ++ptr;
    }
    line[ptr]='\0';
    s_log(LOG_DEBUG, " <- %s", line);
    return line;
}

void ssl_putline(CLI *c, const char *line) { /* put newline-terminated string */
    char *tmpline;
    const char crlf[]="\r\n";
    size_t len;

    tmpline=str_printf("%s%s", line, crlf);
    len=strlen(tmpline);
    if(len>INT_MAX) { /* paranoia */
        s_log(LOG_ERR, "ssl_putline: Line too long");
        str_free(tmpline);
        throw_exception(c, 1);
    }
    s_ssl_write(c, tmpline, (int)len);
    str_free(tmpline);
    s_log(LOG_DEBUG, " -> %s", line);
}

void ssl_printf(CLI *c, const char *format, ...) {
    va_list ap;
    char *line;

    va_start(ap, format);
    line=str_vprintf(format, ap);
    va_end(ap);
    if(!line) {
        s_log(LOG_ERR, "ssl_printf: str_vprintf failed");
        throw_exception(c, 1);
    }
    ssl_putline(c, line);
    str_free(line);
}

/**************************************** network helpers */

#define INET_SOCKET_PAIR

int make_sockets(SOCKET fd[2]) { /* make a pair of connected ipv4 sockets */
#ifdef INET_SOCKET_PAIR
    struct sockaddr_in addr;
    socklen_t addrlen;
    SOCKET s; /* temporary socket awaiting for connection */

    /* create two *blocking* sockets first */
    s=s_socket(AF_INET, SOCK_STREAM, 0, 0, "make_sockets: s_socket#1");
    if(s==INVALID_SOCKET)
        return 1;
    fd[1]=s_socket(AF_INET, SOCK_STREAM, 0, 0, "make_sockets: s_socket#2");
    if(fd[1]==INVALID_SOCKET) {
        closesocket(s);
        return 1;
    }

    addrlen=sizeof addr;
    memset(&addr, 0, sizeof addr);
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
    if(fd[0]==INVALID_SOCKET) {
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

/* returns 0 on success, and -1 on error */
int original_dst(const SOCKET fd, SOCKADDR_UNION *addr) {
    socklen_t addrlen;

    memset(addr, 0, sizeof(SOCKADDR_UNION));
    addrlen=sizeof(SOCKADDR_UNION);
#ifdef SO_ORIGINAL_DST
#ifdef USE_IPv6
    if(!getsockopt(fd, SOL_IPV6, SO_ORIGINAL_DST, &addr->sa, &addrlen))
        return 0; /* succeeded */
#endif /* USE_IPv6 */
    if(!getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, &addr->sa, &addrlen))
        return 0; /* succeeded */
    sockerror("getsockopt SO_ORIGINAL_DST");
#else /* SO_ORIGINAL_DST */
    if(!getsockname(fd, &addr->sa, &addrlen))
        return 0; /* succeeded */
    sockerror("getsockname");
#endif /* SO_ORIGINAL_DST */
    return -1; /* failed */
}

/* end of network.c */
