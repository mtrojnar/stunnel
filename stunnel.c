/*
 *   stunnel       Universal SSL tunnel
 *   Copyright (c) 1998-2001 Michal Trojnara <Michal.Trojnara@mirt.net>
 *                 All Rights Reserved
 *
 *   Version:      3.14                  (stunnel.c)
 *   Date:         2001.02.21
 *   
 *   Author:   		Michal Trojnara  <Michal.Trojnara@mirt.net>
 *   SSL support:  	Adam Hernik      <adas@infocentrum.com>
 *                 	Pawel Krawczyk   <kravietz@ceti.com.pl>
 *   PTY support:  	Dirk O. Siebnich <dok@vossnet.de>
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

#include "common.h"

    /* Must be included before sys/stat.h for Ultrix */
#include <sys/types.h>   /* u_short, u_long */

/* Needed so we know which version of OpenSSL we're using */
#ifdef HAVE_OPENSSL
#include <openssl/crypto.h>
#else
#include <crypto.h>
#endif

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
#ifdef HAVE_STROPTS_H
#include <stropts.h>
#endif

#include <pwd.h>
#include <grp.h>

#include <fcntl.h>

    /* Networking headers */
#include <netinet/in.h>  /* struct sockaddr_in */
#include <sys/socket.h>  /* getpeername */
#include <arpa/inet.h>   /* inet_ntoa */
#include <sys/time.h>    /* select */
#include <sys/ioctl.h>   /* ioctl */
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>  /* for aix */
#endif
#ifndef INADDR_ANY
#define INADDR_ANY       (u32)0x00000000
#endif
#ifndef INADDR_LOOPBACK
#define INADDR_LOOPBACK  (u32)0x7F000001
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
static void name2nums(char *, u32 **, u_short *);
static u_short port2num(char *);
static void host2num(u32 **, char *);

    /* Error/exceptions handling functions */
static void ioerror(char *);
void sockerror(char *);
#ifdef USE_FORK
static void sigchld_handler(int);
#endif
#ifndef USE_WIN32
static void local_handler(int);
static void signal_handler(int);
#endif
#ifndef HAVE_GETOPT
static int getopt(int, char **, char *);
#endif
static void safestring(char *);
static void alloc(u32 **, int);
static void print_help();
static void print_version();

server_options options;

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
    signal(SIGINT, signal_handler);
    signal(SIGHUP, signal_handler);
    /* signal(SIGSEGV, signal_handler); */
#endif

    /* process options */
    options.foreground=1;
    options.cert_defaults = CERT_DEFAULTS;
    
    safecopy(options.pem, PEM_DIR);
    if ( options.pem[0] ) { safeconcat(options.pem, "/"); }
    safeconcat(options.pem, "stunnel.pem");

    get_options(argc, argv);
    if(!(options.option&OPT_FOREGROUND)) {
        options.foreground=0;
        log_open();
    }
    log(LOG_NOTICE, "Using '%s' as tcpwrapper service name", options.servname);

    /* check if certificate exists */
    if(options.option&OPT_CERT) {
        if(stat(options.pem, &st)) {
            ioerror(options.pem);
            exit(1);
        }
#ifndef USE_WIN32
        if(st.st_mode & 7)
            log(LOG_WARNING, "Wrong permissions on %s", options.pem);
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
        u32 ip = 0; /* local program or stdin/stdout */
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
    char *servname_selected=NULL;

    options.option=0;
    options.verify_level=0x00; /* SSL_VERIFY_NONE */
    options.verify_use_only_my=0;
    options.debug_level=5;
#ifndef USE_WIN32
    options.facility=LOG_DAEMON;
#endif
    options.session_timeout=300;
    options.cipher_list=NULL;
    options.username=NULL;
    options.protocol=NULL;
    options.setuid_user=NULL;
    options.setgid_group=NULL;
    options.pid_dir=PIDDIR;
    options.egd_sock=NULL;
    options.rand_file=NULL;
    options.rand_write=1;
    options.random_bytes=RANDOM_BYTES;
    opterr=0;
    while ((c = getopt(argc, argv, "A:a:cp:v:d:fTl:L:r:s:g:t:u:n:N:hC:D:E:R:WB:VP:S:")) != EOF)
        switch (c) {
	    case 'A':
	    	safecopy(options.cert_file,optarg);
		break;
            case 'a':
                safecopy(options.cert_dir, optarg);
                break;
	    case 'S':
		options.cert_defaults = atoi(optarg);
		if ( options.cert_defaults < 0 ||
		     options.cert_defaults > 3 ) {
		     log(LOG_ERR, "Bad -S value '%d'", options.cert_defaults);
		     print_help();
		}
		break;
            case 'c':
                options.option|=OPT_CLIENT;
                break;
            case 'p':
                options.option|=OPT_CERT;
                safecopy(options.pem, optarg);
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
	    case 'R':
	    	options.rand_file=optarg;
		break;
	    case 'W':
	        options.rand_write=0;
		break;
	    case 'B':
	    	options.random_bytes=atoi(optarg);
		break;
	    case 'E':
#if SSLEAY_VERSION_NUMBER >= 0x0090581fL
	    	options.egd_sock=optarg;
#else
		log(LOG_ERR, "-E is only supported when compiled with OpenSSL 0.9.5a or later");
		/* exit(1) ??? */
#endif
		break;
            case 'L':
                options.option |= OPT_PTY;
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
            case 's':
                options.setuid_user=optarg;
                break;
            case 'g':
                options.setgid_group=optarg;
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
	    case 'N':
	    	servname_selected=optarg;
		break;
            case 'C':
                options.cipher_list=optarg;
                break;
            case 'D':
	    	if ( ! parse_debug_level(optarg) ) {
                    log(LOG_ERR, "Illegal debug argument: %s", optarg);
                    fprintf(stderr, "Illegal debug argument: %s\n", optarg);
                    print_help();
                }
                break;
            case 'V':
                print_version();
                exit(0);
	    case 'P':
	    	options.pid_dir=optarg;
		break;
            case '?':
                log(LOG_ERR, "Illegal option: '%c'", optopt);
            case 'h':
                print_help();
            default:
                log(LOG_ERR, "INTERNAL ERROR: Illegal option: '%c'", c);
                print_help();
        }
#ifdef USE_WIN32
    if (! (options.option & OPT_DAEMON) ) {
    	log(LOG_ERR, "You must use daemon mode (-d) in Windows.");
	print_help();
    }
#endif
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
    if ( servname_selected ) {
    	safecopy(options.servname, servname_selected);
    }
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
    /* Main process will receive signals about dead children */
    signal(SIGCHLD, sigchld_handler);
#else /* defined USE_FORK */
    /* Main process will receive signals about dead children of it's threads */
    signal(SIGCHLD, local_handler);
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
            if(create_client(ls, s, client)) {
                log(LOG_WARNING,
                    "%s create_client failed - connection from %s:%d REJECTED",
                    options.servname,
                    inet_ntoa(addr.sin_addr),
                    ntohs(addr.sin_port));
            } else {
                enter_critical_section(2); /* for multi-cpu machines */
                options.clients++;
                leave_critical_section(2);
            }
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
#ifdef HAVE_DAEMON
    if ( daemon(0,0) == -1 ) {
	ioerror("daemon");
        exit(1);
    }
#else
    chdir("/");
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
    close(0);
    close(1);
    close(2);
#endif
}

static void create_pid()
{
    int pf;
    char pid[STRLEN];
    struct stat sb;
    int force_dir;
    char tmpdir[STRLEN];

    safecopy(tmpdir, options.pid_dir);

    if(strcmp(tmpdir, "none") == 0) {
        log(LOG_DEBUG, "No pid file being created.");
        options.pidfile[0]='\0';
        return;
    }
    if(!strchr(tmpdir, '/')) {
        log(LOG_ERR, "Argument to -P (%s) must be full path name.",
            tmpdir);
        /* Why?  Because we don't want to confuse by
           allowing '.', which would be '/' after
           daemonizing) */
        exit(1);
    }
    options.dpid=(unsigned long)getpid();

    /* determine if they specified a pid dir or pid file,
       and set our options.pidfile appropriately */
    if(tmpdir[strlen(tmpdir)-1] == '/' ) {
        force_dir=1; /* user requested -P argument to be a directory */
        tmpdir[strlen(tmpdir)-1] = '\0';
    } else {
        force_dir=0; /* this can be either a file or a directory */
    }
    if(!stat(tmpdir, &sb) && S_ISDIR(sb.st_mode)) { /* directory */
#ifdef HAVE_SNPRINTF 
        snprintf(options.pidfile, STRLEN,
            "%s/stunnel.%s.pid", tmpdir, options.servname);
#else
        safecopy(options.pidfile, tmpdir);
        safeconcat(options.pidfile, "/stunnel.");
        safeconcat(options.pidfile, options.servname);
        safeconcat(options.pidfile, ".pid");
#endif
    } else { /* file */
        if(force_dir) {
            log(LOG_ERR, "Argument to -P (%s/) is not valid a directory name.",
                tmpdir);
            exit(1);
        }
        safecopy(options.pidfile, tmpdir);
    }

    /* silently remove old pid file */
    unlink(options.pidfile);
    if (-1==(pf=open(options.pidfile, O_WRONLY|O_CREAT|O_TRUNC|O_EXCL,0644))) {
        log(LOG_ERR, "Cannot create pid file %s", options.pidfile);
        ioerror("create");
        exit(1);
    }
    sprintf(pid, "%lu", options.dpid);
    write( pf, pid, strlen(pid) );
    close(pf);
    log(LOG_DEBUG, "Created pid file %s", options.pidfile);
    atexit(delete_pid);
}

static void delete_pid()
{
    log(LOG_DEBUG, "removing pid file %s", options.pidfile);
    if((unsigned long)getpid()!=options.dpid)
        return; /* Current process is not main daemon process */
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

#ifndef USE_WIN32
    if(options.setgid_group) {
        struct group *gr;
        gid_t gr_list[1];

        gr=getgrnam(options.setgid_group);
        if(!gr) {
            log(LOG_ERR, "Failed to get GID for group %s",
                options.setgid_group);
            exit(1);
        }
        if(setgid(gr->gr_gid)) {
            sockerror("setgid");
            exit(1);
        }
        gr_list[0]=gr->gr_gid;
        if(setgroups(1, gr_list)) {
            sockerror("setgroups");
            exit(1);
        }
    }

    if(options.setuid_user) {
        struct passwd *pw;

        pw=getpwnam(options.setuid_user);
        if(!pw) {
            log(LOG_ERR, "Failed to get UID for user %s",
                options.setuid_user);
            exit(1);
        }
#ifndef USE_WIN32
        /* gotta chown that pid file, or we can't remove it. */
        if ( options.pidfile[0] && chown( options.pidfile, pw->pw_uid, -1) ) {
            log(LOG_ERR, "Failed to chown pidfile %s", options.pidfile);
        }
#endif
        if(setuid(pw->pw_uid)) {
            sockerror("setuid");
            exit(1);
        }
    }
#endif /* USE_WIN32 */

    return ls;
}

int connect_local(u32 ip) /* spawn local process */
{
#ifdef USE_WIN32
    log(LOG_ERR, "LOCAL MODE NOT SUPPORTED ON WIN32 PLATFORM");
    return -1;
#else
    struct in_addr addr;
    char text[STRLEN];
    int fd[2];

    if (options.option & OPT_PTY) {
        char tty[STRLEN];

        if(pty_allocate(fd, fd+1, tty, STRLEN)) {
            return -1;
        }
        log(LOG_DEBUG, "%s allocated", tty);
    } else {
        if(make_sockets(fd))
            return -1;
    }
#ifdef USE_FORK
    /* Each child has to take care of its own dead children */
    signal(SIGCHLD, local_handler);
#endif /* defined USE_FORK */
    /* With USE_PTHREAD main thread does the work */
    /* and SIGCHLD is blocked in other theads */
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
        _exit(1);
    }
    /* parent */
    closesocket(fd[1]);
    return fd[0];
#endif /* USE_WIN32 */
}

int connect_remote(u32 ip) /* connect to remote host */
{
    struct sockaddr_in addr;
    int s; /* destination socket */
    u32 *list; /* destination addresses list */

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

static void name2nums(char *name, u32 **names, u_short *port)
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

static void host2num(u32 **hostlist, char *hostname)
{ /* get list of host addresses */
    struct hostent *h;
    u32 ip;
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
        (*hostlist)[i]=*(u32 *)(h->h_addr_list[i]);
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
static void sigchld_handler(int sig) /* Dead children detected */
{
    int pid, status;

#if defined(HAVE_WAITPID)
    while((pid=waitpid(-1, &status, WNOHANG))>0) {
        options.clients--; /* One client less */
        if(WIFSIGNALED(status)) {
            log(LOG_DEBUG, "%s[%d] terminated on signal %d (%d left)",
                options.servname, pid, WTERMSIG(status), options.clients);
        } else {
            log(LOG_DEBUG, "%s[%d] finished with code %d (%d left)",
                options.servname, pid, WEXITSTATUS(status), options.clients);
        }
    }
#else
    pid=wait(&status);
    options.clients--; /* One client less */
    log(LOG_DEBUG, "%s[%d] finished with code %d (%d left)",
        options.servname, pid, status, options.clients);
#endif
    signal(SIGCHLD, sigchld_handler);
}
#endif

#ifndef USE_WIN32

static void local_handler(int sig) { /* sigchld handler for -l processes */
    int pid, status;

    pid=wait(&status);
    log(LOG_DEBUG, "Local process %s[%d] finished with code %d)",
        options.servname, pid, status);
    signal(SIGCHLD, local_handler);
}

static void signal_handler(int sig) { /* Signal handler */
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

static void alloc(u32 **ptr, int len)
{ /* Allocate len+1 words terminated with -1 */
    if (*ptr) /* Deallocate if not null */
        free(*ptr);
    *ptr=malloc((len+1)*sizeof(u32));
    if (!*ptr) {
        log(LOG_ERR, "Fatal memory allocation error");
        exit(2);
    }
    (*ptr)[len]=-1;
}

static void print_version()
{
    fprintf(stderr, "\n" STUNNEL_INFO "\n\n");
    fprintf(stderr, "Default behaviour:\n"
#ifdef USE_WIN32
        "\trun in daemon mode\n"
        "\trun in foreground\n"
#else
        "\trun in inetd mode (unless -d used)\n"
        "\trun in background (unless -f used)\n"
#endif
        "\trun in ssl server mode (unless -c used)\n"
        "\n");

    fprintf(stderr, "Compile time defaults:\n");
    fprintf(stderr, "\t-v level\tno verify\n");
    fprintf(stderr, "\t-a directory\t%s\n",
        strcmp("",CERT_DIR)? CERT_DIR : "(none)");
    fprintf(stderr, "\t-A file\t\t%s\n",
        strcmp("",CERT_FILE)? CERT_FILE : "(none)");
    fprintf(stderr, "\t-S sources\t%d\n", CERT_DEFAULTS);
    fprintf(stderr, "\t-t timeout\t%ld seconds\n", options.session_timeout);
    fprintf(stderr, "\t-B bytes\t%d\n", RANDOM_BYTES);
    fprintf(stderr, "\t-D level\t%d\n", options.debug_level);
#ifndef USE_WIN32
    fprintf(stderr, "\t-P pid dir\t%s\n", options.pid_dir);
#endif
    fprintf(stderr, "\t-p pemfile\t"
        "in server mode: %s\n"
        "\t\t\tin client mode: none\n", options.pem);
        fprintf(stderr, "\n\n");
}

static void print_help()
{
    fprintf(stderr,
/* Server execution */
	"\nstunnel\t"
	"[-h] "
	"[-V] "
	"[-c | -T] "
	"[-D level] "
	"[-C cipherlist] "
	"[-p pemfile] "
	"\n\t"
	"[-v level] "
	"[-A certfile] "
	"[-a directory] "
	"[-S sources] "
	"[-t timeout] "
	"\n\t"
	"[-u ident_username] "
	"[-s setuid_user] "
	"[-g setgid_group] "
	"[-n protocol]"
	"\n\t"
	"[-R randfile] "
#if SSLEAY_VERSION_NUMBER >= 0x0090581fL
	"[-E egdsock] "
#endif
	"[-B bytes] "

#ifndef USE_WIN32
	"[-P { dir/ | filename | none } ] "
	"\n\t[-d [host:]port [-f] ] "
	"\n\t[-r [host:]port | { -l | -L }  program [-- args] ] "
#else
	"\n\t-d [host:]port -r [host:]port"
#endif


	/* Argument notes */

	"\n\n  -h\t\tprint this help screen"
        "\n  -V\t\tprint stunnel version and compile-time defaults"
	"\n"
        "\n  -d [host:]port   daemon mode (host defaults to INADDR_ANY)"
        "\n  -r [host:]port   connect to remote service (host defaults to INADDR_LOOPBACK)"
#ifndef USE_WIN32
        "\n  -l program\t   execute local inetd-type program"
        "\n  -L program\t   open local pty and execute program"
#endif
	"\n"
        "\n  -c\t\tclient mode (remote service uses SSL)"
#ifndef USE_WIN32
        "\n  -f\t\tforeground mode (don't fork, log to stderr)"
#endif
        "\n  -T\t\ttransparent proxy mode on hosts that support it."
        "\n  -p pemfile\tprivate key/certificate PEM filename"
        "\n  -v level\tverify peer certificate"
        "\n\t\t   level 1 - verify peer certificate if present"
        "\n\t\t   level 2 - require valid peer certificate always"
        "\n\t\t   level 3 - verify peer with locally installed certificate"
        "\n  -a directory\tclient certificate directory for -v options"
	"\n  -A certfile\tCA certificate for -v options"
	"\n  -S sources\twhich certificate source defaults to use"
	"\n\t\t   0 = ignore all defaults sources"
	"\n\t\t   1 = use ssl library defaults"
	"\n\t\t   2 = use stunnel defaults"
	"\n\t\t   3 = use both ssl library and stunnel defaults"
        "\n  -t timeout\tsession cache timeout"
        "\n  -u user\tUse IDENT (RFC 1413) username checking"
        "\n  -n proto\tNegotiate SSL with specified protocol"
        "\n\t\tcurrenty supported: smtp"
	"\n  -N name\tService name to use for tcp wrapper checking"
#ifndef USE_WIN32
        "\n  -s username\tsetuid() to username in daemon mode"
        "\n  -g groupname\tsetgid() to groupname in daemon mode"
        "\n  -P arg\tSpecify pid file.    { dir/ | filename | none }"
#endif
        "\n  -C list\tset permitted SSL ciphers"
#if SSLEAY_VERSION_NUMBER >= 0x0090581fL
        "\n  -E socket\tpath to Entropy Gathering Daemon socket"
#ifdef EGD_SOCKET
	"\n\t\t" EGD_SOCKET " is used when this option is not specified."
#endif
        "\n  -B bytes\thow many bytes to read from random seed files"
#else
        "\n  -B bytes\tnum bytes of random data considered 'sufficient' for PRNG"
	"\n\t\tand maximum number of bytes to read from random seed files."
#endif
        "\n  -R file\tpath to file with random seed data"
#ifdef RANDOM_FILE
	"\n\t\t" RANDOM_FILE " is used when this option is not specified."
#endif
	"\n  -W\t\tDo not overwrite random seed datafiles with new random data"
        "\n  -D [fac.]lev\tdebug level (e.g. daemon.info)"
	"\n"
	"\nSee stunnel -V output for default values\n"
	"\n");
    exit(1);
}

/* End of stunnel.c */

