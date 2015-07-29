/*
 *   stunnel       Universal SSL tunnel
 *   Copyright (C) 1998-2009 Michal Trojnara <Michal.Trojnara@mirt.net>
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
static char signal_buffer[16];
static void sigchld_handler(int);
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
    int i;

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
    int i;

    for(i=0; i<fds->nfds; i++)
        if(fds->ufds[i].fd==fd)
            return fds->ufds[i].revents&~POLLOUT; /* read or error */
    return 0;
}

int s_poll_canwrite(s_poll_set *fds, int fd) {
    int i;

    for(i=0; i<fds->nfds; i++)
        if(fds->ufds[i].fd==fd)
            return fds->ufds[i].revents&POLLOUT; /* write */
    return 0;
}

#ifdef USE_UCONTEXT

/* move ready contexts from waiting queue to ready queue */
static void scan_waiting_queue(void) {
    int retval, retry;
    CONTEXT *ctx, *prev;
    int min_timeout;
    int nfds, i;
    time_t now;
    short *signal_revents;
    static int max_nfds=0;
    static struct pollfd *ufds=NULL;

    time(&now);
    /* count file descriptors */
    min_timeout=-1;
    nfds=0;
    for(ctx=waiting_head; ctx; ctx=ctx->next) {
        nfds+=ctx->fds->nfds;
        if(ctx->finish>=0) /* finite time */
            if(min_timeout<0 || min_timeout>ctx->finish-now)
                min_timeout=ctx->finish-now<0 ? 0 : ctx->finish-now;
    }
    /* setup ufds structure */
    if(nfds>max_nfds) { /* need to allocate more memory */
        ufds=realloc(ufds, nfds*sizeof(struct pollfd));
        if(!ufds) {
            s_log(LOG_CRIT, "Memory allocation failed");
            die(1);
        }
        max_nfds=nfds;
    }
    nfds=0;
    signal_revents=NULL;
    for(ctx=waiting_head; ctx; ctx=ctx->next)
        for(i=0; i<ctx->fds->nfds; i++) {
            ufds[nfds].fd=ctx->fds->ufds[i].fd;
            ufds[nfds].events=ctx->fds->ufds[i].events;
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
    ctx=waiting_head;
    while(ctx) {
        ctx->ready=0;
        /* count ready file descriptors in each context */
        for(i=0; i<ctx->fds->nfds; i++) {
            ctx->fds->ufds[i].revents=ufds[nfds].revents;
#ifdef DEBUG_UCONTEXT
            s_log(LOG_DEBUG, "CONTEXT %ld, FD=%d, (%s%s)->(%s%s%s%s%s)",
                ctx->id, ufds[nfds].fd,
                ufds[nfds].events & POLLIN ? "IN" : "",
                ufds[nfds].events & POLLOUT ? "OUT" : "",
                ufds[nfds].revents & POLLIN ? "IN" : "",
                ufds[nfds].revents & POLLOUT ? "OUT" : "",
                ufds[nfds].revents & POLLERR ? "ERR" : "",
                ufds[nfds].revents & POLLHUP ? "HUP" : "",
                ufds[nfds].revents & POLLNVAL ? "NVAL" : "");
#endif
            if(ufds[nfds].revents)
                ctx->ready++;
            nfds++;
        }
        if(ctx->ready || (ctx->finish>=0 && ctx->finish<=now)) {
            /* remove context ctx from the waiting queue */
            if(prev)
                prev->next=ctx->next;
            else
                waiting_head=ctx->next;
            if(!ctx->next) /* same as ctx==waiting_tail */
                waiting_tail=prev;

            /* append context ctx to the ready queue */
            ctx->next=NULL;
            if(ready_tail)
                ready_tail->next=ctx;
            ready_tail=ctx;
            if(!ready_head)
                ready_head=ctx;
        } else { /* leave the context ctx in the waiting queue */
            prev=ctx;
        }
        ctx=prev ? prev->next : waiting_head;
    }
}

int s_poll_wait(s_poll_set *fds, int sec, int msec) {
    /* FIXME: msec parameter is currently ignored with UCONTEXT threads */
    CONTEXT *ctx; /* current context */
    static CONTEXT *to_free=NULL; /* delayed memory deallocation */

    /* remove the current context from ready queue */
    ctx=ready_head;
    ready_head=ready_head->next;
    if(!ready_head) /* the queue is empty */
        ready_tail=NULL;

    if(fds) { /* something to wait for -> swap the context */
        ctx->fds=fds; /* set file descriptors to wait for */
        ctx->finish=sec<0 ? -1 : time(NULL)+sec;
        /* move (append) the current context to the waiting queue */
        ctx->next=NULL;
        if(waiting_tail)
            waiting_tail->next=ctx;
        waiting_tail=ctx;
        if(!waiting_head)
            waiting_head=ctx;
        while(!ready_head) /* no context ready */
            scan_waiting_queue();
        if(ctx->id!=ready_head->id) {
            s_log(LOG_DEBUG, "Context swap: %ld -> %ld",
                ctx->id, ready_head->id);
            swapcontext(&ctx->ctx, &ready_head->ctx);
            s_log(LOG_DEBUG, "Current context: %ld", ready_head->id);
            if(to_free) {
                s_log(LOG_DEBUG, "Releasing context %ld", to_free->id);
                free(to_free->stack);
                free(to_free);
                to_free=NULL;
            }
        }
        return ready_head->ready;
    } else { /* nothing to wait for -> drop the context */
        /* it's illegal to deallocate the stack of the current context */
        if(to_free) {
            s_log(LOG_DEBUG, "Releasing context %ld", to_free->id);
            free(to_free->stack);
            free(to_free);
        }
        to_free=ctx;
        while(!ready_head) /* no context ready */
            scan_waiting_queue();
        s_log(LOG_DEBUG, "Context set: %ld (dropped) -> %ld",
            ctx->id, ready_head->id);
        setcontext(&ready_head->ctx);
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
    fds->max = 0; /* no file descriptors */
}

void s_poll_add(s_poll_set *fds, int fd, int rd, int wr) {
    if(rd)
        FD_SET(fd, &fds->irfds);
    if(wr)
        FD_SET(fd, &fds->iwfds);
    if(fd > fds->max)
        fds->max = fd;
}

int s_poll_canread(s_poll_set *fds, int fd) {
    return FD_ISSET(fd, &fds->orfds);
}

int s_poll_canwrite(s_poll_set *fds, int fd) {
    return FD_ISSET(fd, &fds->owfds);
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

#ifndef USE_WIN32

static void sigchld_handler(int sig) { /* SIGCHLD detected */
    int save_errno;
#ifdef __sgi
    int status;
#endif

    save_errno=errno;
#ifdef __sgi
    while(wait_for_pid(-1, &status, WNOHANG)>0) {
        /* no logging is possible in a signal handler */
#ifdef USE_FORK
        --num_clients; /* one client less */
#endif /* USE_FORK */
    }
#else /* __sgi */
#ifdef __INNOTEK_LIBC__
    writesocket(signal_pipe[1], signal_buffer, 1);
#else
    write(signal_pipe[1], signal_buffer, 1);
#endif /* __INNOTEK_LIBC__ */
#endif /* __sgi */
    signal(SIGCHLD, sigchld_handler);
    errno=save_errno;
}

/**************************************** signal pipe */

int signal_pipe_init(void) {
#if defined(__INNOTEK_LIBC__)
    /* Innotek port of GCC can not use select on a pipe, use local socket instead */
    struct sockaddr_un un;
    fd_set set_pipe;
    int pipe_in;

    FD_ZERO(&set_pipe);
    signal_pipe[0]=socket(PF_OS2, SOCK_STREAM, 0);
    pipe_in=signal_pipe[0];
    signal_pipe[1]=socket(PF_OS2, SOCK_STREAM, 0);

    alloc_fd(signal_pipe[0]);
    alloc_fd(signal_pipe[1]);

    /* Connect the two endpoints */
    memset(&un, 0, sizeof un);

    un.sun_len=sizeof un;
    un.sun_family=AF_OS2;
    sprintf(un.sun_path, "\\socket\\stunnel-%u", getpid());
    /* Make the first endpoint listen */
    bind(signal_pipe[0], (struct sockaddr *)&un, sizeof un);
    listen(signal_pipe[0], 5);
    connect(signal_pipe[1], (struct sockaddr *)&un, sizeof un);
    FD_SET(signal_pipe[0], &set_pipe);
    if (select(signal_pipe[0]+1, &set_pipe, NULL, NULL, NULL)>0) {
        signal_pipe[0]=accept(signal_pipe[0], NULL, 0);
        closesocket(pipe_in);
    } else {
        sockerror("select");
        die(1);
    }
#else /* __INNOTEK_LIBC__ */
    if(pipe(signal_pipe)) {
        ioerror("pipe");
        die(1);
    }
    alloc_fd(signal_pipe[0]);
    alloc_fd(signal_pipe[1]);
#ifdef FD_CLOEXEC
    /* close the pipe in child execvp */
    fcntl(signal_pipe[0], F_SETFD, FD_CLOEXEC);
    fcntl(signal_pipe[1], F_SETFD, FD_CLOEXEC);
#endif /* FD_CLOEXEC */
#endif /* __INNOTEK_LIBC__ */
    signal(SIGCHLD, sigchld_handler);
    return signal_pipe[0];
}

static void signal_pipe_empty(void) {
    s_log(LOG_DEBUG, "Cleaning up the signal pipe");
#ifdef __INNOTEK_LIBC__
    readsocket(signal_pipe[0], signal_buffer, sizeof signal_buffer);
#else
    read(signal_pipe[0], signal_buffer, sizeof signal_buffer);
#endif
#ifdef USE_FORK
    client_status(); /* report status of client process */
#else /* USE_UCONTEXT || USE_PTHREAD */
    child_status();  /* report status of libwrap or 'exec' process */
#endif /* defined USE_FORK */
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

#endif /* !defined USE_WIN32 */

/**************************************** fd management */

int alloc_fd(int sock) {
#ifndef USE_WIN32
    if(!max_fds || sock>=max_fds) {
        s_log(LOG_ERR,
            "File descriptor out of range (%d>=%d)", sock, max_fds);
        closesocket(sock);
        return -1;
    }
#endif
    setnonblock(sock, 1);
    return 0;
}

/* Try to use non-POSIX O_NDELAY on obsolete BSD systems */
#if !defined O_NONBLOCK && defined O_NDELAY
#define O_NONBLOCK O_NDELAY
#endif

void setnonblock(int sock, unsigned long l) {
#if defined F_GETFL && defined F_SETFL && defined O_NONBLOCK && !defined __INNOTEK_LIBC__
    int retval, flags;
    do {
        flags=fcntl(sock, F_GETFL, 0);
    }while(flags<0 && get_last_socket_error()==EINTR);
    flags=l ? flags|O_NONBLOCK : flags&~O_NONBLOCK;
    do {
        retval=fcntl(sock, F_SETFL, flags);
    }while(retval<0 && get_last_socket_error()==EINTR);
    if(retval<0)
#else
    if(ioctlsocket(sock, FIONBIO, &l)<0)
#endif
        sockerror("nonblocking"); /* non-critical */
    else
        s_log(LOG_DEBUG, "FD %d in %sblocking mode", sock,
            l ? "non-" : "");
}

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
            s_log(LOG_DEBUG, "%s option set on %s socket",
                ptr->opt_str, type_str[type]);
        }
    }
    return 0; /* OK */
}

/**************************************** simulate blocking I/O */

int connect_blocking(CLI *c, SOCKADDR_UNION *addr, socklen_t addrlen) {
    int error;
    socklen_t optlen;
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
            dst, my_strerror(error), error);
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
            dst, my_strerror(error), error);
        return -1;
    case 0:
        s_log(LOG_ERR, "connect_blocking: s_poll_wait %s: timeout", dst);
        return -1;
    default:
        if(s_poll_canread(&c->fds, c->fd)) {
            /* newly connected socket should not be ready for read */
            /* get the resulting error code, now */
            optlen=sizeof error;
            if(getsockopt(c->fd, SOL_SOCKET, SO_ERROR,
                    (void *)&error, &optlen))
                error=get_last_socket_error(); /* failed -> ask why */
            if(error) { /* really an error? */
                s_log(LOG_ERR, "connect_blocking: getsockopt %s: %s (%d)",
                    dst, my_strerror(error), error);
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
            s_log(LOG_INFO, "write_blocking: s_poll_wait timeout");
            longjmp(c->err, 1); /* timeout */
        case 1:
            break; /* OK */
        default:
            s_log(LOG_ERR, "write_blocking: s_poll_wait unknown result");
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
            s_log(LOG_INFO, "read_blocking: s_poll_wait timeout");
            longjmp(c->err, 1); /* timeout */
        case 1:
            break; /* OK */
        default:
            s_log(LOG_ERR, "read_blocking: s_poll_wait unknown result");
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
    char tmpline[STRLEN];
    const char crlf[]="\r\n";
    int len;

    safecopy(tmpline, line);
    safeconcat(tmpline, crlf);
    len=strlen(tmpline);
    write_blocking(c, fd, tmpline, len);
    tmpline[len-2]='\0'; /* remove CRLF */
    safestring(tmpline);
    s_log(LOG_DEBUG, " -> %s", tmpline);
}

void fdgetline(CLI *c, int fd, char *line) {
    char tmpline[STRLEN];
    s_poll_set fds;
    int ptr;

    for(ptr=0;;) {
        s_poll_init(&fds);
        s_poll_add(&fds, fd, 1, 0); /* read */
        switch(s_poll_wait(&fds, c->opt->timeout_busy, 0)) {
        case -1:
            sockerror("fdgetline: s_poll_wait");
            longjmp(c->err, 1); /* error */
        case 0:
            s_log(LOG_INFO, "fdgetline: s_poll_wait timeout");
            longjmp(c->err, 1); /* timeout */
        case 1:
            break; /* OK */
        default:
            s_log(LOG_ERR, "fdgetline: s_poll_wait unknown result");
            longjmp(c->err, 1); /* error */
        }
        switch(readsocket(fd, line+ptr, 1)) {
        case -1: /* error */
            sockerror("readsocket (fdgetline)");
            longjmp(c->err, 1);
        case 0: /* EOF */
            s_log(LOG_ERR, "Unexpected socket close (fdgetline)");
            longjmp(c->err, 1);
        }
        if(line[ptr]=='\r')
            continue;
        if(line[ptr]=='\n')
            break;
        if(!line[ptr])
            break;
        if(++ptr==STRLEN) {
            s_log(LOG_ERR, "Input line too long");
            longjmp(c->err, 1);
        }
    }
    line[ptr]='\0';
    safecopy(tmpline, line);
    safestring(tmpline);
    s_log(LOG_DEBUG, " <- %s", tmpline);
}

int fdprintf(CLI *c, int fd, const char *format, ...) {
    va_list arglist;
    char line[STRLEN];
    int len;

    va_start(arglist, format);
#ifdef HAVE_VSNPRINTF
    len=vsnprintf(line, STRLEN-2, format, arglist);
#else
    len=vsprintf(line, format, arglist);
#endif
    va_end(arglist);
    if(len<0) {
        s_log(LOG_ERR, "fdprintf: vs(n)printf failed");
        longjmp(c->err, 1);
    }
    fdputline(c, fd, line);
    return len+2;
}

int fdscanf(CLI *c, int fd, const char *format, char *buffer) {
    char line[STRLEN], lformat[STRLEN];
    int ptr, retval;

    fdgetline(c, fd, line);

    retval=sscanf(line, format, buffer);
    if(retval>=0)
        return retval;

    s_log(LOG_DEBUG, "fdscanf falling back to lowercase");
    safecopy(lformat, format);
    for(ptr=0; lformat[ptr]; ptr++)
        lformat[ptr]=tolower(lformat[ptr]);
    for(ptr=0; line[ptr]; ptr++)
        line[ptr]=tolower(line[ptr]);
    return sscanf(line, lformat, buffer);
}

/* End of network.c */
