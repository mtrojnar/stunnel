/*
 *   stunnel       Universal SSL tunnel
 *   Copyright (C) 1998-2011 Michal Trojnara <Michal.Trojnara@mirt.net>
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

#ifndef USE_WIN32
static int signal_pipe[2]={-1, -1};
#ifdef __INNOTEK_LIBC__
struct sockaddr_un {
    u_char  sun_len;             /* sockaddr len including null */
    u_char  sun_family;          /* AF_OS2 or AF_UNIX */
    char    sun_path[108];       /* path name */
};
#endif
static void signal_pipe_empty(void);
#ifdef USE_FORK
static void client_status(void); /* dead children detected */
#endif
#endif /* !defined(USE_WIN32) */

/**************************************** s_poll functions */

#ifdef USE_POLL

void s_poll_init(s_poll_set *fds) {
    fds->nfds=0;
}

void s_poll_add(s_poll_set *fds, int fd, int rd, int wr) {
    unsigned int i;

    for(i=0; i<fds->nfds && fds->ufds[i].fd!=fd; i++)
        ;
    if(i>=MAX_FD) {
        s_log(LOG_ERR,
            "s_poll_add failed for FD=%d: too many file descriptors", fd);
        return;
    }
    if(i==fds->nfds) {
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
            return fds->ufds[i].revents&(POLLIN|POLLHUP); /* read or closed */
    return 0;
}

int s_poll_canwrite(s_poll_set *fds, int fd) {
    unsigned int i;

    for(i=0; i<fds->nfds; i++)
        if(fds->ufds[i].fd==fd)
            return fds->ufds[i].revents&POLLOUT; /* it is possible to write */
    return 0;
}

int s_poll_error(s_poll_set *fds, int fd) {
    unsigned int i;

    for(i=0; i<fds->nfds; i++)
        if(fds->ufds[i].fd==fd)
            return fds->ufds[i].revents&(POLLERR|POLLNVAL) ?
                get_socket_error(fd) : 0;
    return 0;
}

#ifdef USE_UCONTEXT

/* move ready contexts from waiting queue to ready queue */
static void scan_waiting_queue(void) {
    int retval, retry;
    CONTEXT *context, *prev;
    int min_timeout;
    unsigned int nfds, i;
    time_t now;
    short *signal_revents;
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
        if(!ufds) {
            s_log(LOG_CRIT, "Memory allocation failed");
            die(1);
        }
        max_nfds=nfds;
    }
    nfds=0;
    signal_revents=NULL;
    for(context=waiting_head; context; context=context->next)
        for(i=0; i<context->fds->nfds; i++) {
            ufds[nfds].fd=context->fds->ufds[i].fd;
            ufds[nfds].events=context->fds->ufds[i].events;
            if(ufds[nfds].fd==signal_pipe[0])
                signal_revents=&ufds[nfds].revents;
            nfds++;
        }

#ifdef DEBUG_UCONTEXT
    s_log(LOG_DEBUG, "Waiting %d second(s) for %d file descriptor(s)",
        min_timeout, nfds);
#endif
    do { /* skip "Interrupted system call" errors */
        retry=0;
        retval=poll(ufds, nfds, min_timeout<0 ? -1 : 1000*min_timeout);
        if(retval>0 && signal_revents && (*signal_revents & POLLIN)) {
            signal_pipe_empty(); /* no timeout -> main loop */
            retry=1;
        }
    } while(retry || (retval<0 && get_last_socket_error()==EINTR));
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
        s_log(LOG_DEBUG, "Releasing context %ld", to_free->id);
        free(to_free->stack);
        free(to_free);
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
            s_log(LOG_DEBUG, "Context swap: %ld -> %ld",
                context->id, ready_head->id);
            swapcontext(&context->context, &ready_head->context);
            s_log(LOG_DEBUG, "Current context: %ld", ready_head->id);
        }
        return ready_head->ready;
    } else { /* drop the current context */
        s_log(LOG_DEBUG, "Context set: %ld (dropped) -> %ld",
            context->id, ready_head->id);
        setcontext(&ready_head->context);
        ioerror("setcontext"); /* should not ever happen */
        return 0;
    }
}

#else /* USE_UCONTEXT */

int s_poll_wait(s_poll_set *fds, int sec, int msec) {
    int retval, retry;

    do { /* skip "Interrupted system call" errors */
        retry=0;
        retval=poll(fds->ufds, fds->nfds, sec<0 ? -1 : 1000*sec+msec);
        if(sec<0 && retval>0 && s_poll_canread(fds, signal_pipe[0])) {
            signal_pipe_empty(); /* no timeout -> main loop */
            retry=1;
        }
    } while(retry || (retval<0 && get_last_socket_error()==EINTR));
    return retval;
}

#endif /* USE_UCONTEXT */

#else /* select */

void s_poll_init(s_poll_set *fds) {
    FD_ZERO(&fds->irfds);
    FD_ZERO(&fds->iwfds);
    fds->max=0; /* no file descriptors */
}

void s_poll_add(s_poll_set *fds, int fd, int rd, int wr) {
    if(rd)
        FD_SET((unsigned int)fd, &fds->irfds);
    if(wr)
        FD_SET((unsigned int)fd, &fds->iwfds);
    if(fd>fds->max)
        fds->max=fd;
}

int s_poll_canread(s_poll_set *fds, int fd) {
    return FD_ISSET(fd, &fds->orfds);
}

int s_poll_canwrite(s_poll_set *fds, int fd) {
    return FD_ISSET(fd, &fds->owfds);
}

int s_poll_error(s_poll_set *fds, int fd) {
    if(!FD_ISSET(fd, &fds->orfds)) /* error conditions are signaled as read */
        return 0;
    return get_socket_error(fd); /* check if it's really an error */
}

int s_poll_wait(s_poll_set *fds, int sec, int msec) {
    int retval, retry;
    struct timeval tv, *tv_ptr;

    do { /* skip "Interrupted system call" errors */
        retry=0;
        memcpy(&fds->orfds, &fds->irfds, sizeof(fd_set));
        memcpy(&fds->owfds, &fds->iwfds, sizeof(fd_set));
        if(sec<0) { /* infinite timeout */
            tv_ptr=NULL;
        } else {
            tv.tv_sec=sec;
            tv.tv_usec=1000*msec;
            tv_ptr=&tv;
        }
        retval=select(fds->max+1, &fds->orfds, &fds->owfds, NULL, tv_ptr);
#if !defined(USE_WIN32) && !defined(USE_OS2)
        if(sec<0 && retval>0 && s_poll_canread(fds, signal_pipe[0])) {
            signal_pipe_empty(); /* no timeout -> main loop */
            retry=1;
        }
#endif
    } while(retry || (retval<0 && get_last_socket_error()==EINTR));
    return retval;
}

#endif /* USE_POLL */

/**************************************** signal pipe handling */

#if !defined(USE_WIN32) && !defined(USE_OS2)

void signal_handler(int sig) {
    int saved_errno;

    saved_errno=errno;
    writesocket(signal_pipe[1], &sig, sizeof sig);
    signal(sig, signal_handler);
    errno=saved_errno;
}

int signal_pipe_init(void) {
#if defined(__INNOTEK_LIBC__)
    /* Innotek port of GCC can not use select on a pipe
     * use local socket instead */
    struct sockaddr_un un;
    fd_set set_pipe;
    int pipe_in;

    FD_ZERO(&set_pipe);
    signal_pipe[0]=s_socket(PF_OS2, SOCK_STREAM, 0, 0, "socket#1");
    signal_pipe[1]=s_socket(PF_OS2, SOCK_STREAM, 0, 0, "socket#2");

    /* connect the two endpoints */
    memset(&un, 0, sizeof un);
    un.sun_len=sizeof un;
    un.sun_family=AF_OS2;
    sprintf(un.sun_path, "\\socket\\stunnel-%u", getpid());
    /* make the first endpoint listen */
    bind(signal_pipe[0], (struct sockaddr *)&un, sizeof un);
    listen(signal_pipe[0], 1);
    connect(signal_pipe[1], (struct sockaddr *)&un, sizeof un);
    FD_SET(signal_pipe[0], &set_pipe);
    if(select(signal_pipe[0]+1, &set_pipe, NULL, NULL, NULL)>0) {
        pipe_in=signal_pipe[0];
        signal_pipe[0]=s_accept(signal_pipe[0], NULL, 0, 0, "accept");
        closesocket(pipe_in);
    } else {
        sockerror("select");
        die(1);
    }
#else /* __INNOTEK_LIBC__ */
    if(s_pipe(signal_pipe, 0, "signal_pipe"))
        die(1);
#endif /* __INNOTEK_LIBC__ */

    signal(SIGCHLD, signal_handler); /* a child has died */
    signal(SIGHUP, signal_handler); /* configuration reload */
    signal(SIGUSR1, signal_handler); /* log reopen */
    signal(SIGPIPE, SIG_IGN); /* ignore "broken pipe" */
    if(signal(SIGTERM, SIG_IGN)!=SIG_IGN)
        signal(SIGTERM, signal_handler); /* fatal */
    if(signal(SIGQUIT, SIG_IGN)!=SIG_IGN)
        signal(SIGQUIT, signal_handler); /* fatal */
    if(signal(SIGINT, SIG_IGN)!=SIG_IGN)
        signal(SIGINT, signal_handler); /* fatal */
    /* signal(SIGSEGV, signal_handler); */
    return signal_pipe[0];
}

static void signal_pipe_empty(void) {
    int sig;

    s_log(LOG_DEBUG, "Dispatching signals from the signal pipe");
    while(readsocket(signal_pipe[0], &sig, sizeof sig)==sizeof sig) {
        switch(sig) {
        case SIGCHLD:
#ifdef USE_FORK
            client_status(); /* report status of client process */
#else /* USE_UCONTEXT || USE_PTHREAD */
            child_status();  /* report status of libwrap or 'exec' process */
#endif /* defined USE_FORK */
            break;
        case SIGHUP:
            log_close();
            parse_conf(NULL, CONF_RELOAD);
            log_open();
            bind_ports();
            break;
        case SIGUSR1:
            log_close();
            log_open();
            break;
        default:
            s_log(sig==SIGTERM ? LOG_NOTICE : LOG_ERR,
                "Received signal %d; terminating", sig);
            str_stats();
            die(3);
        }
    }
    s_log(LOG_DEBUG, "Signal pipe is empty");
}

#ifdef USE_FORK
static void client_status(void) { /* dead children detected */
    int pid, status;

#ifdef HAVE_WAIT_FOR_PID
    while((pid=wait_for_pid(-1, &status, WNOHANG))>0) {
        --num_clients; /* one client less */
#else
    if((pid=wait(&status))>0) {
        --num_clients; /* one client less */
#endif
#ifdef WIFSIGNALED
        if(WIFSIGNALED(status)) {
            s_log(LOG_DEBUG, "Process %d terminated on signal %d (%d left)",
                pid, WTERMSIG(status), num_clients);
        } else {
            s_log(LOG_DEBUG, "Process %d finished with code %d (%d left)",
                pid, WEXITSTATUS(status), num_clients);
        }
    }
#else
        s_log(LOG_DEBUG, "Process %d finished with code %d (%d left)",
            pid, status, num_clients);
    }
#endif
}
#endif /* defined USE_FORK */

void child_status(void) { /* dead libwrap or 'exec' process detected */
    int pid, status;

#ifdef HAVE_WAIT_FOR_PID
    while((pid=wait_for_pid(-1, &status, WNOHANG))>0) {
#else
    if((pid=wait(&status))>0) {
#endif
#ifdef WIFSIGNALED
        if(WIFSIGNALED(status)) {
            s_log(LOG_INFO, "Child process %d terminated on signal %d",
                pid, WTERMSIG(status));
        } else {
            s_log(LOG_INFO, "Child process %d finished with code %d",
                pid, WEXITSTATUS(status));
        }
#else
        s_log(LOG_INFO, "Child process %d finished with status %d",
            pid, status);
#endif
    }
}

#endif /* !defined(USE_WIN32) && !defined(USE_OS2) */

/**************************************** fd management */

int set_socket_options(int s, int type) {
    SOCK_OPT *ptr;
    extern SOCK_OPT sock_opts[];
    static char *type_str[3]={"accept", "local", "remote"};
    int opt_size;

    for(ptr=sock_opts;ptr->opt_str;ptr++) {
        if(!ptr->opt_val[type])
            continue; /* default */
        switch(ptr->opt_type) {
        case TYPE_LINGER:
            opt_size=sizeof(struct linger); break;
        case TYPE_TIMEVAL:
            opt_size=sizeof(struct timeval); break;
        case TYPE_STRING:
            opt_size=strlen(ptr->opt_val[type]->c_val)+1; break;
        default:
            opt_size=sizeof(int); break;
        }
        if(setsockopt(s, ptr->opt_level, ptr->opt_name,
                (void *)ptr->opt_val[type], opt_size)) {
            sockerror(ptr->opt_str);
            return -1; /* FAILED */
        } else {
            s_log(LOG_DEBUG, "Option %s set on %s socket",
                ptr->opt_str, type_str[type]);
        }
    }
    return 0; /* OK */
}

int get_socket_error(const int fd) {
    int err;
    socklen_t optlen=sizeof err;

    if(getsockopt(fd, SOL_SOCKET, SO_ERROR, (void *)&err, &optlen))
        return get_last_socket_error(); /* failed -> ask why */
    return err;
}

/**************************************** simulate blocking I/O */

int connect_blocking(CLI *c, SOCKADDR_UNION *addr, socklen_t addrlen) {
    int error;
    char dst[IPLEN];

    s_ntop(dst, addr);
    s_log(LOG_INFO, "connect_blocking: connecting %s", dst);

    if(!connect(c->fd, &addr->sa, addrlen)) {
        s_log(LOG_NOTICE, "connect_blocking: connected %s", dst);
        return 0; /* no error -> success (on some OSes over the loopback) */
    }
    error=get_last_socket_error();
    if(error!=EINPROGRESS && error!=EWOULDBLOCK) {
        s_log(LOG_ERR, "connect_blocking: connect %s: %s (%d)",
            dst, s_strerror(error), error);
        return -1;
    }

    s_log(LOG_DEBUG, "connect_blocking: s_poll_wait %s: waiting %d seconds",
        dst, c->opt->timeout_connect);
    s_poll_init(&c->fds);
    s_poll_add(&c->fds, c->fd, 1, 1);
    switch(s_poll_wait(&c->fds, c->opt->timeout_connect, 0)) {
    case -1:
        error=get_last_socket_error();
        s_log(LOG_ERR, "connect_blocking: s_poll_wait %s: %s (%d)",
            dst, s_strerror(error), error);
        return -1;
    case 0:
        s_log(LOG_ERR, "connect_blocking: s_poll_wait %s:"
            " TIMEOUTconnect exceeded", dst);
        return -1;
    default:
        if(s_poll_canread(&c->fds, c->fd) || s_poll_error(&c->fds, c->fd)) {
            /* newly connected socket should not be ready for read */
            /* get the resulting error code, now */
            error=get_socket_error(c->fd);
            if(error) { /* really an error? */
                s_log(LOG_ERR, "connect_blocking: getsockopt %s: %s (%d)",
                    dst, s_strerror(error), error);
                return -1;
            }
        }
        if(s_poll_canwrite(&c->fds, c->fd)) {
            s_log(LOG_NOTICE, "connect_blocking: connected %s", dst);
            return 0; /* success */
        }
        s_log(LOG_ERR, "connect_blocking: s_poll_wait %s: internal error",
            dst);
        return -1;
    }
    return -1; /* should not be possible */
}

void write_blocking(CLI *c, int fd, void *ptr, int len) {
        /* simulate a blocking write */
    s_poll_set fds;
    int num;

    while(len>0) {
        s_poll_init(&fds);
        s_poll_add(&fds, fd, 0, 1); /* write */
        switch(s_poll_wait(&fds, c->opt->timeout_busy, 0)) {
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
    s_poll_set fds;
    int num;

    while(len>0) {
        s_poll_init(&fds);
        s_poll_add(&fds, fd, 1, 0); /* read */
        switch(s_poll_wait(&fds, c->opt->timeout_busy, 0)) {
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

void fdputline(CLI *c, int fd, const char *line) {
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

char *fdgetline(CLI *c, int fd) {
    char *line=NULL, *tmpline;
    s_poll_set fds;
    int ptr=0;

    for(;;) {
        s_poll_init(&fds);
        s_poll_add(&fds, fd, 1, 0); /* read */
        switch(s_poll_wait(&fds, c->opt->timeout_busy, 0)) {
        case -1:
            sockerror("fdgetline: s_poll_wait");
            str_free(line);
            longjmp(c->err, 1); /* error */
        case 0:
            s_log(LOG_INFO, "fdgetline: s_poll_wait:"
                " TIMEOUTbusy exceeded: sending reset");
            str_free(line);
            longjmp(c->err, 1); /* timeout */
        case 1:
            break; /* OK */
        default:
            s_log(LOG_ERR, "fdgetline: s_poll_wait: unknown result");
            str_free(line);
            longjmp(c->err, 1); /* error */
        }
        line=str_realloc(line, ptr+1);
        if(!line) {
            s_log(LOG_CRIT, "Memory allocation failed");
            longjmp(c->err, 1); /* error */
        }
        switch(readsocket(fd, line+ptr, 1)) {
        case -1: /* error */
            sockerror("readsocket (fdgetline)");
            str_free(line);
            longjmp(c->err, 1);
        case 0: /* EOF */
            s_log(LOG_ERR, "Unexpected socket close (fdgetline)");
            str_free(line);
            longjmp(c->err, 1);
        }
        if(line[ptr]=='\r')
            continue;
        if(line[ptr]=='\n')
            break;
        if(!line[ptr])
            break;
        ++ptr;
    }
    line[ptr]='\0';
    tmpline=str_dup(line);
    safestring(tmpline);
    s_log(LOG_DEBUG, " <- %s", tmpline);
    str_free(tmpline);
    return line;
}

int fdprintf(CLI *c, int fd, const char *format, ...) {
    va_list ap;
    char *line;

    va_start(ap, format);
    line=str_vprintf(format, ap);
    va_end(ap);
    if(!line) {
        s_log(LOG_ERR, "fdprintf: str_vprintf failed");
        longjmp(c->err, 1);
    }
    fdputline(c, fd, line);
    str_free(line);
    return strlen(line)+2;
}

/* end of network.c */
