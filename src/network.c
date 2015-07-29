/*
 *   stunnel       Universal SSL tunnel
 *   Copyright (c) 1998-2004 Michal Trojnara <Michal.Trojnara@mirt.net>
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
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
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

#ifdef USE_FORK
static void client_status(void); /* dead children detected */
#endif
 
#ifndef USE_WIN32

static int signal_pipe[2];
static char signal_buffer[16];

static void sigchld_handler(int sig) { /* SIGCHLD detected */
    int save_errno=errno;

    write(signal_pipe[1], signal_buffer, 1);
    signal(SIGCHLD, sigchld_handler);
    errno=save_errno;
}

int signal_pipe_init(void) {
    if(pipe(signal_pipe)) {
        ioerror("pipe");
        exit(1);
    }
    alloc_fd(signal_pipe[0]);
    alloc_fd(signal_pipe[1]);
#ifdef FD_CLOEXEC
    /* close the pipe in child execvp */
    fcntl(signal_pipe[0], F_SETFD, FD_CLOEXEC);
    fcntl(signal_pipe[1], F_SETFD, FD_CLOEXEC);
#endif
    signal(SIGCHLD, sigchld_handler);
    return signal_pipe[0];
}

static void signal_pipe_empty(void) {
    read(signal_pipe[0], signal_buffer, sizeof(signal_buffer));
#ifdef USE_PTHREAD
    exec_status(); /* report status of 'exec' process */
#endif /* USE_PTHREAD */
#ifdef USE_FORK
    client_status(); /* report status of client process */
#endif /* USE_FORK */
}

#endif /* !defined(USE_WIN32) */

#ifdef HAVE_POLL

void s_poll_zero(s_poll_set *fds) {
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
            return fds->ufds[i].revents&POLLIN;
    return 0;
}

int s_poll_canwrite(s_poll_set *fds, int fd) {
    int i;

    for(i=0; i<fds->nfds; i++)
        if(fds->ufds[i].fd==fd)
            return fds->ufds[i].revents&POLLOUT;
    return 0;
}

int s_poll_wait(s_poll_set *fds, int timeout) {
    int retval;

    do { /* skip "Interrupted system call" errors */
        retval=poll(fds->ufds, fds->nfds, 1000*timeout);
            /* no timeout -> main loop */
        if(timeout<0 && retval>0 && s_poll_canread(fds, signal_pipe[0]))
            signal_pipe_empty();
    } while(retval<0 && get_last_socket_error()==EINTR);
    return retval;
}

#else /* HAVE_POLL */

void s_poll_zero(s_poll_set *fds) {
    FD_ZERO(&fds->irfds);
    FD_ZERO(&fds->iwfds);
    fds->max = 0; /* No file descriptors */
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

int s_poll_wait(s_poll_set *fds, int timeout) {
    int retval;
    struct timeval tv;

    do { /* skip "Interrupted system call" errors */
        memcpy(&fds->orfds, &fds->irfds, sizeof(fd_set));
        memcpy(&fds->owfds, &fds->iwfds, sizeof(fd_set));
        if(timeout<0) { /* no timeout -> main loop */
            retval=select(fds->max+1, &fds->orfds, &fds->owfds, NULL, NULL);
#ifndef USE_WIN32
            if(retval>0 && s_poll_canread(fds, signal_pipe[0]))
                signal_pipe_empty();
#endif
        } else {
            tv.tv_sec=timeout;
            tv.tv_usec=0;
            retval=select(fds->max+1, &fds->orfds, &fds->owfds, NULL, &tv);
        }
    } while(retval<0 && get_last_socket_error()==EINTR);
    return retval;
}

#endif /* HAVE_POLL */

#ifdef USE_FORK
static void client_status(void) { /* dead children detected */
    int pid, status;

#ifdef HAVE_WAIT_FOR_PID
    while((pid=wait_for_pid(-1, &status, WNOHANG))>0) {
        num_clients--; /* one client less */
#else
    if((pid=wait(&status))>0) {
        num_clients--; /* one client less */
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
#endif

#ifndef USE_WIN32
void exec_status(void) { /* dead local ('exec') process detected */
    int pid, status;

#ifdef HAVE_WAIT_FOR_PID
    while((pid=wait_for_pid(-1, &status, WNOHANG))>0) {
#else
    if((pid=wait(&status))>0) {
#endif
#ifdef WIFSIGNALED
        if(WIFSIGNALED(status)) {
            s_log(LOG_INFO, "Local process %d terminated on signal %d",
                pid, WTERMSIG(status));
        } else {
            s_log(LOG_INFO, "Local process %d finished with code %d",
                pid, WEXITSTATUS(status));
        }
#else
        s_log(LOG_INFO, "Local process %d finished with status %d",
            pid, status);
#endif
    }
}
#endif /* !defined USE_WIN32 */

int write_blocking(CLI *c, int fd, u8 *ptr, int len) {
        /* simulate a blocking write */
        /* returns 0 on success, -1 on failure */
    s_poll_set fds;
    int num;

    while(len>0) {
        s_poll_zero(&fds);
        s_poll_add(&fds, fd, 0, 1); /* write */
        switch(s_poll_wait(&fds, c->opt->timeout_busy)) {
        case -1:
            sockerror("write_blocking: s_poll_wait");
            return -1; /* error */
        case 0:
            s_log(LOG_INFO, "write_blocking: s_poll_wait timeout");
            return -1; /* timeout */
        case 1:
            break; /* OK */
        default:
            s_log(LOG_ERR, "write_blocking: s_poll_wait unknown result");
            return -1; /* error */
        }
        num=writesocket(fd, ptr, len);
        switch(num) {
        case -1: /* error */
            sockerror("writesocket (write_blocking)");
            return -1;
        }
        ptr+=num;
        len-=num;
    }
    return 0; /* OK */
}

int read_blocking(CLI *c, int fd, u8 *ptr, int len) {
        /* simulate a blocking read */
        /* returns 0 on success, -1 on failure */
    s_poll_set fds;
    int num;

    while(len>0) {
        s_poll_zero(&fds);
        s_poll_add(&fds, fd, 1, 0); /* read */
        switch(s_poll_wait(&fds, c->opt->timeout_busy)) {
        case -1:
            sockerror("read_blocking: s_poll_wait");
            return -1; /* error */
        case 0:
            s_log(LOG_INFO, "read_blocking: s_poll_wait timeout");
            return -1; /* timeout */
        case 1:
            break; /* OK */
        default:
            s_log(LOG_ERR, "read_blocking: s_poll_wait unknown result");
            return -1; /* error */
        }
        num=readsocket(fd, ptr, len);
        switch(num) {
        case -1: /* error */
            sockerror("readsocket (read_blocking)");
            return -1;
        case 0: /* EOF */
            s_log(LOG_ERR, "Unexpected socket close (read_blocking)");
            return -1;
        }
        ptr+=num;
        len-=num;
    }
    return 0; /* OK */
}

int fdprintf(CLI *c, int fd, const char *format, ...) {
    va_list arglist;
    char line[STRLEN], logline[STRLEN];
    char crlf[]="\r\n";
    int len;

    va_start(arglist, format);
#ifdef HAVE_VSNPRINTF
    len=vsnprintf(line, STRLEN, format, arglist);
#else
    len=vsprintf(line, format, arglist);
#endif
    va_end(arglist);
    len+=2;
    if(len>=STRLEN) {
        s_log(LOG_ERR, "Line too long in fdprintf");
        return -1;
    }
    safecopy(logline, line); /* The line without crlf */
    safeconcat(line, crlf);
    if(write_blocking(c, fd, line, len)<0)
        return -1;
    safestring(logline);
    s_log(LOG_DEBUG, " -> %s", logline);
    return len;
}

int fdscanf(CLI *c, int fd, const char *format, char *buffer) {
    char line[STRLEN], logline[STRLEN], lformat[STRLEN];
    s_poll_set fds;
    int ptr, retval;

    for(ptr=0; ptr<STRLEN-1; ptr++) {
        s_poll_zero(&fds);
        s_poll_add(&fds, fd, 1, 0); /* read */
        switch(s_poll_wait(&fds, c->opt->timeout_busy)) {
        case -1:
            sockerror("fdscanf: s_poll_wait");
            return -1; /* error */
        case 0:
            s_log(LOG_INFO, "fdscanf: s_poll_wait timeout");
            return -1; /* timeout */
        case 1:
            break; /* OK */
        default:
            s_log(LOG_ERR, "fdscanf: s_poll_wait unknown result");
            return -1; /* error */
        }
        switch(readsocket(fd, line+ptr, 1)) {
        case -1: /* error */
            sockerror("readsocket (fdscanf)");
            return -1;
        case 0: /* EOF */
            s_log(LOG_ERR, "Unexpected socket close (fdscanf)");
            return -1;
        }
        if(line[ptr]=='\r')
            continue;
        if(line[ptr]=='\n')
            break;
    }
    line[ptr]='\0';
    safecopy(logline, line);
    safestring(logline);
    s_log(LOG_DEBUG, " <- %s", logline);
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

/**************************************** Resolver functions */

int name2addrlist(SOCKADDR_LIST *addr_list, char *name, char *default_host) {
    char tmp[STRLEN], *hostname, *portname;

    /* set hostname and portname */
    safecopy(tmp, name);
    portname=strrchr(tmp, ':');
    if(portname) {
        hostname=tmp;
        *portname++='\0';
    } else { /* no ':' - use default host IP */
        hostname=default_host;
        portname=tmp;
    }

    /* fill addr_list structure */
    return hostport2addrlist(addr_list, hostname, portname);
}

#ifdef HAVE_GETADDRINFO

/* Due to a problem with Mingw32 I decided to define my own gai_strerror() */
static const char *s_gai_strerror(int err) {
    switch(err) {
        case EAI_BADFLAGS:
            return "Invalid value for ai_flags (EAI_BADFLAGS)";
        case EAI_NONAME:
            return "Neither nodename nor servname known (EAI_NONAME)";
        case EAI_AGAIN:
            return "Temporary failure in name resolution (EAI_AGAIN)";
        case EAI_FAIL:
            return "Non-recoverable failure in name resolution (EAI_FAIL)";
        case EAI_NODATA:
            return "No address associated with nodename (EAI_NODATA)";
        case EAI_FAMILY:
            return "ai_family not supported (EAI_FAMILY)";
        case EAI_SOCKTYPE:
            return "ai_socktype not supported (EAI_SOCKTYPE)";
        case EAI_SERVICE:
            return "servname is not supported for ai_socktype (EAI_SERVICE)";
#ifdef EAI_ADDRFAMILY
        case EAI_ADDRFAMILY:
            return "Address family for nodename not supported (EAI_ADDRFAMILY)";
#endif
        case EAI_MEMORY:
            return "Memory allocation failure (EAI_MEMORY)";
#ifdef EAI_SYSTEM
        case EAI_SYSTEM:
            return "System error returned in errno (EAI_SYSTEM)";
#endif
        default:
            return "Unknown error";
    }
}

/* getaddrinfo() version */
int hostport2addrlist(SOCKADDR_LIST *addr_list,
        char *hostname, char *portname) {
    struct addrinfo hints, *res=NULL, *cur;
    int err;

    addr_list->cur=0; /* initialize round-robin counter */

    memset(&hints, 0, sizeof(hints));
#if defined(USE_IPv6) || defined(USE_WIN32)
    hints.ai_family=PF_UNSPEC;
#else
    hints.ai_family=PF_INET;
#endif
    hints.ai_socktype=SOCK_STREAM;
    hints.ai_protocol=IPPROTO_TCP;

    err=getaddrinfo(hostname, portname, &hints, &res);
    if(err) {
        s_log(LOG_ERR, "Error resolving '%s': %s",
            hostname, s_gai_strerror(err));
        if(res)
            freeaddrinfo(res);
        return 0; /* Error */
    }
    /* copy the list of addresses */
    cur=res;
    while(cur && addr_list->num<MAX_HOSTS) {
        if(cur->ai_addrlen>sizeof(SOCKADDR_UNION)) {
            s_log(LOG_ERR, "INTERNAL ERROR: ai_addrlen value too big");
            freeaddrinfo(res);
            return 0; /* no results */
        }
        memcpy(&addr_list->addr[addr_list->num],
            cur->ai_addr, cur->ai_addrlen);
        cur=cur->ai_next;
        addr_list->num++;
    }
    freeaddrinfo(res);
    return addr_list->num; /* ok - return the number of addresses */
}

#else /* defined(HAVE_GETADDRINFO) */

/* traditional BSD version */
int hostport2addrlist(SOCKADDR_LIST *addr_list,
        char *hostname, char *portname) {
    struct hostent *h;
    struct servent *p;
    u_short port;

    addr_list->cur=0; /* initialize round-robin counter */
    if(addr_list->num>=MAX_HOSTS) {
        s_log(LOG_ERR, "Too many IP addresses");
        return 0;
    }

    /* set addr_list->port */
    port=htons((u_short)atoi(portname));
    if(!port) { /* zero is an illegal value for port number */
        p=getservbyname(portname, "tcp");
        if(!p) {
            s_log(LOG_ERR, "Invalid port: %s", portname);
            return 0;
        }
        port=p->s_port;
    }

#if defined(USE_IPv6) && !defined(USE_WIN32)
    addr_list->addr[addr_list->num].in6.sin6_family=AF_INET6;
    if(inet_pton(AF_INET6, hostname,
            &addr_list->addr[addr_list->num].in6.sin6_addr)>0) {
#else
    addr_list->addr[addr_list->num].in.sin_family=AF_INET;
    addr_list->addr[addr_list->num].in.sin_addr.s_addr=inet_addr(hostname);
    if(addr_list->addr[addr_list->num].in.sin_addr.s_addr+1) {
            /* (signed)addr_list->addr[addr_list->num].s_addr!=-1 */
#endif
        addr_list->addr[addr_list->num++].in.sin_port=port;
        return addr_list->num; /* single result */
    }

    /* not dotted decimal - we have to call resolver */
    enter_critical_section(CRIT_INET);
#if defined(USE_IPv6) && !defined(USE_WIN32)
    h=gethostbyname2(hostname, AF_INET); /* AF_INET6? */ /* get list of addresses */
#else
    h=gethostbyname(hostname); /* get list of addresses */
#endif
    if(!h) { /* resolver failed */
        leave_critical_section(CRIT_INET);
        s_log(LOG_ERR, "Failed to resolve hostname '%s'", hostname);
        return 0; /* no results */
    }
    /* copy addresses */
    for(; addr_list->num<MAX_HOSTS && h->h_addr_list[addr_list->num];
            addr_list->num++) {
        addr_list->addr[addr_list->num].sa.sa_family=h->h_addrtype;
#if defined(USE_IPv6) || defined(USE_WIN32)
        if(h->h_addrtype==AF_INET6)
            memcpy(&addr_list->addr[addr_list->num].in6.sin6_addr,
                h->h_addr_list[addr_list->num], h->h_length);
        else
#endif
            memcpy(&addr_list->addr[addr_list->num].in.sin_addr,
                h->h_addr_list[addr_list->num], h->h_length);
        /* offsets of sin_port and sin6_port should be the same */
        addr_list->addr[addr_list->num].in.sin_port=port;
    }
#ifdef HAVE_ENDHOSTENT
    endhostent();
#endif
    leave_critical_section(CRIT_INET);
    return addr_list->num;
}

#endif /* defined(HAVE_GETADDRINFO) */

#ifdef HAVE_GETNAMEINFO

/* getnameinfo() version */
char *s_ntop(char *text, SOCKADDR_UNION *addr) {
    char host[20], port[6];

    if(getnameinfo(&addr->sa, addr_len(*addr),
            host, 20, port, 6, NI_NUMERICHOST|NI_NUMERICSERV)) {
        sockerror("getnameinfo");
        strcpy(text, "unresolvable IP");
        return text;
    }
    strcpy(text, host);
    strcat(text, ":");
    strcat(text, port);
    return text;
}

#else /* defined(HAVE_GETNAMEINFO) */

/* traditional BSD version */
char *s_ntop(char *text, SOCKADDR_UNION *addr) {
    char port[6]; /* max length for unsigned short integer + 1 */
#ifdef USE_IPv6
    if(addr->sa.sa_family==AF_INET6)
        inet_ntop(AF_INET6, &addr->in6.sin6_addr, text, IPLEN-6);
    else
        inet_ntop(AF_INET, &addr->in.sin_addr, text, IPLEN-6);
#else /* USE_IPv6 */
    enter_critical_section(CRIT_INET); /* inet_ntoa is not mt-safe */
    strncpy(text, inet_ntoa(addr->in.sin_addr), IPLEN-7);
    leave_critical_section(CRIT_INET);
#endif /* USE_IPv6 */
    text[IPLEN-7]='\0';
    strcat(text, ":");
    sprintf(port, "%u", ntohs(addr->in.sin_port));
    strcat(text, port);
    return text;
}

#endif /* defined(HAVE_GETNAMEINFO) */

void debug_sockaddr_union(char *text, SOCKADDR_UNION *addr) {
    int i;
    char t[3*sizeof(SOCKADDR_UNION)];
    const char hex[16]="0123456789abcdef";
    
    for(i=0; i<sizeof(SOCKADDR_UNION); i++) {
        t[3*i]=hex[((u8 *)addr)[i]/16];
        t[3*i+1]=hex[((u8 *)addr)[i]%16];
        t[3*i+2]=' ';
    }
    t[3*sizeof(SOCKADDR_UNION)-1]='\0';
    s_log(LOG_DEBUG, "%s\n", t);
}

/* End of network.c */
