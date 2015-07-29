/*
 *   stunnel       Universal SSL tunnel
 *   Copyright (c) 1998-2000 Michal Trojnara <Michal.Trojnara@centertel.pl>
 *                 All Rights Reserved
 *
 *   Version:      3.6              (stunnel.c)
 *   Date:         2000.02.03
 *   Author:       Michal Trojnara  <Michal.Trojnara@centertel.pl>
 *   SSL support:  Adam Hernik      <adas@infocentrum.com>
 *                 Pawel Krawczyk   <kravietz@ceti.com.pl>
 *   PTY support:  Dirk O. Siebnich <dok@vossnet.de>
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
 */

/* Undefine if you have problems with make_sockets() */
#define INET_SOCKET_PAIR

/* Max number of children */
#define MAX_CLIENTS    100

#ifdef USE_WIN32

/* default certificate */
#define DEFAULT_CERT "stunnel.pem"

/* additional directory (hashed!) with trusted CA client certs */
#define CA_DIR "trusted"

#else /* USE_WIN32 */

/* directory for certificate */
#define CERT_DIR sslcnf "/certs"

/* default certificate */
#define DEFAULT_CERT CERT_DIR "/stunnel.pem"

/* additional directory (hashed!) with trusted CA client certs */
#define CA_DIR CERT_DIR "/trusted"

#endif /* USE_WIN32 */

#include "common.h"

    /* General headers */
#include <stdio.h>
#include <errno.h>       /* errno */
#include <stdlib.h>
#include <string.h>      /* strerror */
#include <sys/stat.h>    /* stat */
#include <ctype.h>       /* isalnum */

#ifdef USE_WIN32

#define Win32_Winsock
#include <windows.h>

static struct WSAData wsa_state;

#else /* defined USE_WIN32 */

    /* Unix-specific headers */
#include <signal.h>      /* signal */
#include <sys/wait.h>    /* wait */
#include <netdb.h>
#ifdef HAVE_GETOPT_H
#include <getopt.h>      /* getopt */
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>      /* getpid, fork, execvp, exit */
#endif
#ifdef HAVE_PTY_H
#include <pty.h>
#endif
#include <fcntl.h>

    /* Networking headers */
#include <sys/types.h>   /* u_short, u_long */
#include <netinet/in.h>  /* struct sockaddr_in */
#include <sys/socket.h>  /* getpeername */
#include <arpa/inet.h>   /* inet_ntoa */
#include <sys/time.h>    /* select */
#include <sys/ioctl.h>   /* ioctl */
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>  /* for aix */
#endif
#ifndef INADDR_ANY
#define INADDR_ANY       (u_long)0x00000000
#endif
#ifndef INADDR_LOOPBACK
#define INADDR_LOOPBACK  (u_long)0x7F000001
#endif

#endif /* defined USE_WIN32 */

    /* Prototypes */
static void get_options(int, char *[]);
static void daemon_loop();
#ifndef USE_WIN32
static void daemonize();
static void create_pid();
static void delete_pid();
#endif

    /* Socket functions */
static int listen_local();
#ifndef USE_WIN32
static int make_sockets(int [2]);
#endif
static void name2nums(char *, u_long **, u_short *);
static u_short port2num(char *);
static void host2num(u_long **, char *);

    /* Error/exceptions handling functions */
static void ioerror(char *);
void sockerror(char *);
#ifdef USE_FORK
static void sigchld_handler(int);
#endif
#ifndef USE_WIN32
static void signal_handler(int);
#endif
#ifndef HAVE_GETOPT
static int getopt(int, char **, char *);
#endif
static void safestring(char *);
static void alloc(u_long **, int);
static void print_help();

server_options options;

    /* Macros */
/* Safe copy for strings declarated as char[STRLEN] */
#define safecopy(dst, src) \
    (dst[STRLEN-1]='\0', strncpy((dst), (src), STRLEN-1))
#define safeconcat(dst, src) \
    (dst[STRLEN-1]='\0', strncat((dst), (src), STRLEN-strlen(dst)-1))

    /* Functions */
int main(int argc, char* argv[])
{ /* execution begins here 8-) */
    struct stat st; /* buffer for stat */

#ifdef USE_WIN32
    if(WSAStartup(0x0101, &wsa_state)!=0) {
        sockerror("WSAStartup");
        exit(1);
    }
#else
    signal(SIGPIPE, SIG_IGN); /* avoid 'broken pipe' signal */
    signal(SIGTERM, signal_handler);
    signal(SIGQUIT, signal_handler);
    /* signal(SIGSEGV, signal_handler); */
#endif

    /* process options */
    options.foreground=1;
    safecopy(options.certfile, DEFAULT_CERT);
    safecopy(options.clientdir, CA_DIR);
    get_options(argc, argv);
    if(!(options.option&OPT_FOREGROUND)) {
        options.foreground=0;
        log_open();
    }

    /* check if certificate exists */
    if(options.option&OPT_CERT) {
        if(stat(options.certfile, &st)) {
            ioerror(options.certfile);
            exit(1);
        }
#ifndef USE_WIN32
        if(st.st_mode & 7)
            log(LOG_WARNING, "Wrong permissions on %s", options.certfile);
#endif /* defined USE_WIN32 */
    }

    /* check if started from inetd */
    context_init(); /* initialize global SSL context */
    sthreads_init(); /* initialize threads */
    log(LOG_NOTICE, STUNNEL_INFO);
    if (options.option & OPT_DAEMON) {
        /* client or server, daemon mode */
#ifndef USE_WIN32
        if (!(options.option & OPT_FOREGROUND))
            daemonize();
        create_pid();
#endif
        daemon_loop();
    } else if ((options.option & OPT_CLIENT) &&
        (options.option & OPT_PROGRAM)) {
        /* client, program mode */
        int local;
        u_long ip = 0; /* local program or stdin/stdout */
        if ((local = connect_local(ip)) >= 0) {
            options.clients = 1;
            client(local);
        }
    } else {
        /* client or server, inetd mode */
        options.clients = 1;
        client(0); /* connection from fd 0 - stdin */
    }
    /* close SSL */
    context_free(); /* free global SSL context */
    log_close();
    return 0; /* success */
}

static void get_options(int argc, char *argv[]) {
    /* get options and set global variables */
    int c;
    extern char *optarg;
    extern int optind, opterr, optopt;
    char *tmpstr;
    static char *default_args[2];

    options.option=0;
    options.verify_level=0x00; /* SSL_VERIFY_NONE */
    options.verify_use_only_my=0;
    options.debug_level=5;
    options.session_timeout=0;
    options.cipher_list=NULL;
    options.username=NULL;
    options.protocol=NULL;
    opterr=0;
    while ((c = getopt(argc, argv, "a:cp:v:d:fTl:L:r:t:u:n:hC:D:V")) != EOF)
        switch (c) {
            case 'a':
                safecopy(options.clientdir, optarg);
                break;
            case 'c':
                options.option|=OPT_CLIENT;
                break;
            case 'p':
                options.option|=OPT_CERT;
                safecopy(options.certfile, optarg);
                break;
            case 'v':
                switch(atoi(optarg)) {
                case 3:
                    options.verify_use_only_my=1;
                case 2:
                    options.verify_level |= 0x02;
                        /* SSL_VERIFY_FAIL_IF_NO_PEER_CERT */
                case 1:
                    options.verify_level |= 0x01;
                        /* SSL_VERIFY_PEER */
                    break;
                default:
                    log(LOG_ERR, "Bad verify level");
                    print_help();
                }
                break;
             case 'd':
                if(options.option&OPT_DAEMON) {
                    log(LOG_ERR, "Multiple daemons not allowed");
                    print_help();
                }
                options.option|=OPT_DAEMON;
                options.localnames=NULL;
                name2nums(optarg, &options.localnames, &options.localport);
                if(!options.localnames) {
                    alloc(&options.localnames, 1);
                    options.localnames[0]=htonl(INADDR_ANY);
                }
                break;
            case 'f':
                options.option|=OPT_FOREGROUND;
                break;
            case 'T':
                options.option|=OPT_TRANSPARENT;
                break;
#ifdef USE_PTY
            case 'L':
                options.option |= OPT_PTY;
#endif
            case 'l':
                options.option |= OPT_PROGRAM;
                options.execname = optarg;
                /* Default servname is options.execname w/o path */
                tmpstr = strrchr(options.execname, '/');
                if (tmpstr)
                    safecopy(options.servname, tmpstr+1);
                else
                    safecopy(options.servname, options.execname);
                break;
            case 'r':
                options.option |= OPT_REMOTE;
                if (!(options.option & OPT_PROGRAM)) {
                    /* Default servname is optarg with '.' instead of ':' */
                    safecopy(options.servname, optarg);
                    safestring(options.servname);
                }
                options.remotenames=NULL;
                name2nums(optarg, &options.remotenames, &options.remoteport);
                if (!options.remotenames) {
                    alloc(&options.remotenames, 1);
                    options.remotenames[0] = htonl(INADDR_LOOPBACK);
                }
                break;
            case 't':
                if(!(options.session_timeout=atoi(optarg))) {
                    log(LOG_ERR, "Illegal session timeout: %s", optarg);
                    print_help();
                }
                break;
            case 'u':
                options.username=optarg;
                break;
            case 'n':
                options.protocol=optarg;
                break;
            case 'C':
                options.cipher_list=optarg;
                break;
            case 'D':
                if(optarg[0]<'0' || optarg[0]>'7' || optarg[1]!='\0') {
                    log(LOG_ERR, "Illegal debug level: %s", optarg);
                    print_help();
                }
                options.debug_level=optarg[0]-'0';
                break;
            case 'V':
                fprintf(stderr, "\n" STUNNEL_INFO "\n\n");
                exit(0);
            case '?':
                log(LOG_ERR, "Illegal option '%c'", optopt);
            case 'h':
                print_help();
            default:
                log(LOG_ERR, "Internal error in get_options");
                print_help();
        }
    if (options.option & OPT_CLIENT) {
        if (!(options.option & OPT_REMOTE)) {
            log(LOG_ERR, "Remote service must be specified");
            print_help();
        }
        if (options.option & OPT_TRANSPARENT) {
            log(LOG_ERR,
                "Client mode not available in transparent proxy mode");
            print_help();
        }
        if ((options.option & OPT_PROGRAM) &&
            (options.option & OPT_DAEMON)) {
            log(LOG_ERR,
                "Only one of program or daemon mode can be specified");
            print_help();
        }
    } else {
        options.option |= OPT_CERT; /* Server always needs a certificate */
        if (!(options.option & (OPT_PROGRAM | OPT_REMOTE))) {
            log(LOG_ERR, "Either program or remote service must be specified");
            print_help();
        }
        if ((options.option & OPT_PROGRAM) && (options.option & OPT_REMOTE)) {
            log(LOG_ERR, "Only one of program or remote service can be specified");
            print_help();
        }
    }
    if (optind == argc) { /* No arguments - use servname as execargs */
        default_args[0] = options.servname;
        default_args[1] = 0;
        options.execargs = default_args;
    } else { /* There are some arguments - use execargs[0] as servname */
        options.execargs = argv + optind;
        safecopy(options.servname, options.execargs[0]);
    }
    log(LOG_DEBUG, "Service name to be used: %s", options.servname);
}

static void daemon_loop()
{
    int ls, s;
    struct sockaddr_in addr;
    int addrlen;

    ls=listen_local();
    options.clients=0;
#ifndef USE_WIN32
#ifdef USE_FORK
    signal(SIGCHLD, sigchld_handler);
#else /* defined USE_FORK */
    signal(SIGCHLD, SIG_IGN);
#endif /* defined USE_FORK */
#endif /* ndefined USE_WIN32 */
    while(1) {
        addrlen=sizeof(addr);
        do s=accept(ls, (struct sockaddr *)&addr, &addrlen);
        while(s<0 && errno==EINTR);
        if(s<0) {
            sockerror("accept");
            continue;
        }
        if(options.clients<MAX_CLIENTS) {
            if(create_client(ls, s, client))
                log(LOG_WARNING,
                    "%s fork failed - connection from %s:%d REJECTED",
                    options.servname,
                    inet_ntoa(addr.sin_addr),
                    ntohs(addr.sin_port));
            else
                options.clients++;
        } else {
            log(LOG_WARNING,
                "%s has too many clients - connection from %s:%d REJECTED",
                options.servname, inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
            closesocket(s);
        }
    }
}

#ifndef USE_WIN32
static void daemonize() /* go to background */
{
    switch (fork()) {
    case -1:    /* fork failed */
        ioerror("fork");
        exit(1);
    case 0:     /* child */
        break;
    default:    /* parent */
        exit(0);
    }
    if (setsid() == -1) {
        ioerror("setsid");
        exit(1);
    }
    chdir("/");
    close(0);
    close(1);
    close(2);
}

static void create_pid()
{
    FILE *pf;

    options.dpid=(unsigned long)getpid();
#ifdef HAVE_SNPRINTF
    snprintf(options.pidfile, STRLEN,
#else
    sprintf(options.pidfile,
#endif
        "/var/run/stunnel.%s.pid", options.servname);
    umask(022);
    pf=fopen(options.pidfile, "w");
    if(!pf) {
        ioerror(options.pidfile);
        return; /* not critical */
    }
    fprintf(pf, "%lu", options.dpid);
    fclose(pf);
    atexit(delete_pid);
}

static void delete_pid()
{
    if((unsigned long)getpid()!=options.dpid)
        return; /* Current process is not main deamon process */
    if(unlink(options.pidfile)<0)
        ioerror(options.pidfile); /* not critical */
}
#endif /* defined USE_WIN32 */

static int listen_local() /* bind and listen on local interface */
{
    struct sockaddr_in addr;
    int ls, on=1;

    if((ls=socket(AF_INET, SOCK_STREAM, 0))<0) {
        sockerror("socket");
        exit(1);
    }
    if(setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, (void *)&on, sizeof(on))<0) {
        sockerror("setsockopt (SO_REUSEADDR)");
        /* Ignore the error if any */
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family=AF_INET;
    addr.sin_addr.s_addr=*options.localnames;
    addr.sin_port=options.localport;
    if(bind(ls, (struct sockaddr *)&addr, sizeof(addr))) {
        sockerror("bind");
        exit(1);
    }
    log(LOG_DEBUG, "%s bound to %s:%d", options.servname,
        inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
    if(listen(ls, 5)) {
        sockerror("listen");
        exit(1);
    }
    return ls;
}

int connect_local(u_long ip) /* connect to local host */
{
#ifdef USE_WIN32
    log(LOG_ERR, "LOCAL MODE NOT SUPPORTED ON WIN32 PLATFORM");
    return -1;
#else
    {
        struct in_addr addr;
        char text[STRLEN];
        int fd[2];

#ifdef USE_PTY
        char tty[STRLEN];

        if (options.option & OPT_PTY) {
            if(openpty(fd, fd+1, tty, NULL, NULL)<0) {
                ioerror("openpty");
                return -1;
            }
            log(LOG_DEBUG, "%s allocated", tty);
        } else
#endif /* USE_PTY */
        {
            if(make_sockets(fd))
                return -1;
        }
        switch (fork()) {
        case -1:    /* error */
            closesocket(fd[0]);
            closesocket(fd[1]);
            ioerror("fork");
            return -1;
        case  0:    /* child */
            closesocket(fd[0]);
            dup2(fd[1], 0);
            dup2(fd[1], 1);
            if (!options.foreground)
                dup2(fd[1], 2);
            closesocket(fd[1]);
            if (ip) {
                putenv("LD_PRELOAD=" libdir "/stunnel.so");
                addr.s_addr = ip;
                safecopy(text, "REMOTE_HOST=");
                safeconcat(text, inet_ntoa(addr));
                putenv(text);
            }
            execvp(options.execname, options.execargs);
            ioerror("execvp"); /* execv failed */
            exit(1);
        }
        /* parent */
        closesocket(fd[1]);
        return fd[0];
    }
#endif /* USE_WIN32 */
}

int connect_remote(u_long ip) /* connect to remote host */
{
    struct sockaddr_in addr;
    int s; /* destination socket */
    u_long *list; /* destination addresses list */

    if((s=socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        sockerror("remote socket");
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family=AF_INET;

    if(ip) { /* transparent proxy */
        addr.sin_addr.s_addr=ip;
        addr.sin_port=htons(0);
        if(bind(s, (struct sockaddr *)&addr, sizeof(addr))<0) {
            sockerror("bind transparent");
            return -1;
        }
    }

    addr.sin_port=options.remoteport;

    /* connect each host from the list*/
    for(list=options.remotenames; *list!=-1; list++) {
        addr.sin_addr.s_addr=*list;
        log(LOG_DEBUG, "%s connecting %s:%d", options.servname,
            inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        if(!connect(s, (struct sockaddr *) &addr, sizeof(addr)))
            return s; /* success */
    }
    sockerror("remote connect");
    return -1;
}

int auth_user(struct sockaddr_in *addr)
{
    struct servent *s_ent;    /* structure for getservbyname */
    struct sockaddr_in ident; /* IDENT socket name */
    int s;                    /* IDENT socket descriptor */
    char buff[STRLEN], name[STRLEN];
    int ptr, len;

    if(!options.username)
        return 0; /* -u option not specified */
    if((s=socket(AF_INET, SOCK_STREAM, 0))<0) {
        sockerror("socket (ident)");
        return -1;
    }
    memcpy(&ident, addr, sizeof(ident));
    s_ent=getservbyname("auth", "tcp");
    if(!s_ent) {
        log(LOG_WARNING, "Unknown service 'auth' - using default 113");
        ident.sin_port=htons(113);
    } else {
        ident.sin_port=s_ent->s_port;
    }
    if(connect(s, (struct sockaddr *)&ident, sizeof(ident))<0) {
        sockerror("connect (ident)");
        closesocket(s);
        return -1;
    }
#ifdef HAVE_SNPRINTF
    len=snprintf(buff, STRLEN,
#else
    len=sprintf(buff,
#endif
        "%u , %u\r\n", ntohs(addr->sin_port), ntohs(options.localport));
    len=writesocket(s, buff, len);
    if(len<0) {
        sockerror("writesocket (ident)");
        closesocket(s);
        return -1;
    }
    ptr=0;
    do {
        len=readsocket(s, buff+ptr, STRLEN-ptr-1);
        if(len<0) {
            sockerror("readsocket (ident)");
            closesocket(s);
            return -1;
        }
        ptr+=len;
    } while(len && ptr<STRLEN-1);
    closesocket(s);
    buff[ptr]='\0';
    if(sscanf(buff, "%*[^:]: USERID :%*[^:]:%s", name)!=1) {
        log(LOG_ERR, "Incorrect data from inetd server");
        return -1;
    }
    log(LOG_INFO, "IDENT resolved remote user to %s", name);
    if(strcmp(name, options.username))
        return -1;
    return 0;
}

#ifndef USE_WIN32
static int make_sockets(int fd[2]) /* make pair of connected sockets */
{
#ifdef INET_SOCKET_PAIR
    struct sockaddr_in addr;
    int addrlen;
    int s; /* temporary socket awaiting for connection */

    if((s=socket(AF_INET, SOCK_STREAM, 0))<0) {
        sockerror("socket#1");
        return -1;
    }
    if((fd[1]=socket(AF_INET, SOCK_STREAM, 0))<0) {
        sockerror("socket#2");
        return -1;
    }
    addrlen=sizeof(addr);
    memset(&addr, 0, addrlen);
    addr.sin_family=AF_INET;
    addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    addr.sin_port=0; /* dynamic port allocation */
    if(bind(s, (struct sockaddr *)&addr, addrlen))
        log(LOG_DEBUG, "bind#1: %s (%d)", strerror(errno), errno);
    if(bind(fd[1], (struct sockaddr *)&addr, addrlen))
        log(LOG_DEBUG, "bind#2: %s (%d)", strerror(errno), errno);
    if(listen(s, 5)) {
        sockerror("listen");
        return -1;
    }
    if(getsockname(s, (struct sockaddr *)&addr, &addrlen)) {
        sockerror("getsockname");
        return -1;
    }
    if(connect(fd[1], (struct sockaddr *)&addr, addrlen)) {
        sockerror("connect");
        return -1;
    }
    if((fd[0]=accept(s, (struct sockaddr *)&addr, &addrlen))<0) {
        sockerror("accept");
        return -1;
    }
    closesocket(s); /* don't care about the result */
#else
    if(socketpair(AF_UNIX, SOCK_STREAM, 0, fd)) {
        sockerror("socketpair");
        return -1;
    }
#endif
    return 0;
}
#endif

static void name2nums(char *name, u_long **names, u_short *port)
{
    char hostname[STRLEN], *portname;

    safecopy(hostname, name);
    if((portname=strrchr(hostname, ':'))) {
        *portname++='\0';
        host2num(names, hostname);
        *port=port2num(portname);
    } else {
        *port=port2num(hostname); /* no ':' - use default host IP */
    }
}

static u_short port2num(char *portname) /* get port number */
{
    struct servent *p;
    u_short port;

    if((p=getservbyname(portname, "tcp")))
        port=p->s_port;
    else
        port=htons(atoi(portname));
    if(!port) {
        log(LOG_ERR, "Invalid port: %s", portname);
        exit(2);
    }
    return port;
}

static void host2num(u_long **hostlist, char *hostname)
{ /* get list of host addresses */
    struct hostent *h;
    u_long ip;
    int i;
    char **tab;

    ip=inet_addr(hostname);
    if(ip!=-1) { /* dotted decimal */
        alloc(hostlist, 1);
        (*hostlist)[0]=ip;
        return;
    }
    /* not dotted decimal - we have to call resolver */
    if(!(h=gethostbyname(hostname))) { /* get list of addresses */
        sockerror("gethostbyname");
        exit(1);
    }
    i=0;
    tab=h->h_addr_list;
    while(*tab++) /* count the addresses */
        i++;
    alloc(hostlist, i); /* allocate memory */
    while(--i>=0)
        (*hostlist)[i]=*(u_long *)(h->h_addr_list[i]);
}

static void ioerror(char *txt) /* Input/Output error handler */
{
    int error;

    error=get_last_error();
    log(LOG_ERR, "%s: %s (%d)", txt, strerror(error), error);
}

void sockerror(char *txt) /* Socket error handler */
{
    int error;

    error=get_last_socket_error();
    log(LOG_ERR, "%s: %s (%d)", txt, strerror(error), error);
}

#ifdef USE_FORK
static void sigchld_handler(int sig) /* Our child is dead */
{
    int pid, status;

    options.clients--; /* One client less */
    pid=wait(&status);
    log(LOG_DEBUG, "%s[%d] finished with code %d (%d left)",
        options.servname, pid, status, options.clients);
    signal(SIGCHLD, sigchld_handler);
}
#endif

#ifndef USE_WIN32
static void signal_handler(int sig) /* Signal handler */
{
    log(LOG_ERR, "Received signal %d; terminating.", sig);
    exit(3);
}
#endif /* !defined USE_WIN32 */

#ifndef HAVE_GETOPT
char *optarg;
int optind=1, opterr=0, optopt;

static int getopt(int argc, char **argv, char *options)
{ /* simplified version for Win32 */
    char *option;

    if(optind==argc || argv[optind][0]!='-')
        return EOF;
    optopt=argv[optind][1];
    option=strrchr(options, optopt);
    if(!option)
        return '?';
    if(option[1]==':') {
        if(optind+1==argc)
            return '?'; /* Argument not found */
        else
            optarg=argv[++optind];
    }
    ++optind;
    return optopt;
}
#endif /* !defined HAVE_GETOPT */

static void safestring(char *string)
{ /* change all unsafe characters to '.' */
    for(; *string; string++)
        if(!isalnum((unsigned char)*string))
		*string='.';
}

static void alloc(u_long **ptr, int len)
{ /* Allocate len+1 words terminated with -1 */
    if (*ptr) /* Deallocate if not null */
        free(*ptr);
    *ptr=malloc((len+1)*sizeof(u_long));
    if (!*ptr) {
        log(LOG_ERR, "Fatal memory allocation error");
        exit(2);
    }
    (*ptr)[len]=-1;
}

static void print_help()
{
    fprintf(stderr,
        "\nstunnel [-T] [-p pemfile] [-v level] [-a directory]"
        "\n\t[-t timeout] [-u username] [-n protocol]"
#ifndef USE_WIN32
        "\n\t[-d [ip:]port [-f]]"
        "\n\t[ -l program | -r [ip:]port | -L program [-- args] ]"
#else
        "\n\t-d [ip:]port -r [ip:]port"
#endif
        "\nstunnel {-c} [-p pemfile] [-v level] [-a directory]"
        "\n\t[-t timeout] [-u username] [-n protocol]"
#ifndef USE_WIN32
        "\n\t-r [ip:]port"
        "\n\t[ -d [ip:]port [-f] | -l program | -L program [-- args] ]"
#else
        "\n\t-r [ip:]port -d [ip:]port"
#endif
        "\n\n  -c\t\tclient mode (remote service uses SSL)"
        "\n\t\tdefault: server mode"
        "\n  -T\t\ttransparent proxy mode (on hosts that support it)"
        "\n  -p pemfile\tcertificate (*.pem) file name"
        "\n\t\tdefault: " DEFAULT_CERT " for server mode,"
        "\n\t\t\t none for client mode"
        "\n  -v level\tverify peer certificate"
        "\n\t\tlevel 1 - verify peer certificate if present"
        "\n\t\tlevel 2 - verify peer certificate"
        "\n\t\tlevel 3 - verify peer with locally installed certificate"
        "\n\t\tdefault: no verify"
        "\n  -a directory\tclient certificate directory for -v 3 option"
        "\n\t\tdefault: " CA_DIR
        "\n  -t timeout\tsession cache timeout"
        "\n\t\tdefault: 300 s."
        "\n  -u user\tUse IDENT (RFC 1413) username checking"
        "\n  -n proto\tNegotiate SSL with specified protocol"
        "\n\t\tcurrenty supported: smtp"
        "\n  -d [ip:]port\tdaemon mode (ip defaults to INADDR_ANY)"
#ifndef USE_WIN32
        "\n\t\tdefault: inetd mode"
        "\n  -f\t\tforeground mode (don't fork, log to stderr)"
        "\n\t\tdefault: background in daemon mode"
        "\n  -l program\texecute local inetd-type program"
        "\n  -L program\topen local pty and execute program"
#endif
        "\n  -r [ip:]port\tconnect to remote service"
        " (ip defaults to INADDR_LOOPBACK)"
        "\n  -h\t\tprint this help screen"
        "\n  -C list\tset permitted SSL ciphers"
        "\n  -D level\tdebug level (0-7)  default: 5"
        "\n  -V\t\tprint stunnel version\n");
    exit(1);
}

/* End of stunnel.c */

