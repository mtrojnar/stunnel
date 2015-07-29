/*
 *   stunnel       Universal SSL tunnel
 *   Copyright (c) 1998-2001 Michal Trojnara <Michal.Trojnara@mirt.net>
 *                 All Rights Reserved
 *
 *   Version:      3.19                  (stunnel.c)
 *   Date:         2001.08.10
 *   
 *   Author:       Michal Trojnara  <Michal.Trojnara@mirt.net>
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

/* Max number of children is limited by FD_SETSIZE */
#ifdef FD_SETSIZE
#define MAX_CLIENTS    ((FD_SETSIZE-24)/2)
#else
#define MAX_CLIENTS    500
#endif

#include "common.h"

#ifdef USE_WIN32
static struct WSAData wsa_state;
#endif

    /* Prototypes */
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

server_options options;

    /* Functions */
int main(int argc, char* argv[]) { /* execution begins here 8-) */
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

    parse_options(argc, argv);
    if(!(options.option&OPT_FOREGROUND))
        options.foreground=0;
    log_open();
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
        client(STDIO_FILENO); /* rd fd=0, wr fd=1 */
    }
    /* close SSL */
    context_free(); /* free global SSL context */
    log_close();
    return 0; /* success */
}

static void daemon_loop() {
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
        do {
            s=accept(ls, (struct sockaddr *)&addr, &addrlen);
        } while(s<0 && get_last_socket_error()==EINTR);
        if(s<0) {
            sockerror("accept");
            continue;
        }
        if(options.clients<MAX_CLIENTS) {
            if(create_client(ls, s, client)) {
                enter_critical_section(4); /* inet_ntoa is not mt-safe */
                log(LOG_WARNING,
                    "%s create_client failed - connection from %s:%d REJECTED",
                    options.servname,
                    inet_ntoa(addr.sin_addr),
                    ntohs(addr.sin_port));
                leave_critical_section(4);
            } else {
                enter_critical_section(2); /* for multi-cpu machines */
                options.clients++;
                leave_critical_section(2);
            }
        } else {
            enter_critical_section(4); /* inet_ntoa is not mt-safe */
            log(LOG_WARNING,
                "%s has too many clients - connection from %s:%d REJECTED",
                options.servname, inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
            leave_critical_section(4);
            closesocket(s);
        }
    }
}

#ifndef USE_WIN32
static void daemonize() { /* go to background */
#ifdef HAVE_DAEMON
    if(daemon(0,0)==-1){
        ioerror("daemon");
        exit(1);
    }
#else
    chdir("/");
    switch(fork()) {
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

static void create_pid() {
    int pf;
    char pid[STRLEN];
    struct stat sb;
    int force_dir;
    char tmpdir[STRLEN];

    safecopy(tmpdir, options.pid_dir);

    if(strcmp(tmpdir, "none") == 0) {
        log(LOG_DEBUG, "No pid file being created");
        options.pidfile[0]='\0';
        return;
    }
    if(!strchr(tmpdir, '/')) {
        log(LOG_ERR, "Argument to -P (%s) must be full path name",
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
            log(LOG_ERR, "Argument to -P (%s/) is not valid a directory name",
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

static void delete_pid() {
    log(LOG_DEBUG, "removing pid file %s", options.pidfile);
    if((unsigned long)getpid()!=options.dpid)
        return; /* Current process is not main daemon process */
    if(unlink(options.pidfile)<0)
        ioerror(options.pidfile); /* not critical */
}
#endif /* defined USE_WIN32 */

static int listen_local() { /* bind and listen on local interface */
    struct sockaddr_in addr;
    int ls;

    if((ls=socket(AF_INET, SOCK_STREAM, 0))<0) {
        sockerror("local socket");
        exit(1);
    }
    if(set_socket_options(ls, 0)<0)
        exit(1);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family=AF_INET;
    addr.sin_addr.s_addr=*options.localnames;
    addr.sin_port=options.localport;
    if(bind(ls, (struct sockaddr *)&addr, sizeof(addr))) {
        sockerror("bind");
        exit(1);
    }
    enter_critical_section(4); /* inet_ntoa is not mt-safe */
    log(LOG_DEBUG, "%s bound to %s:%d", options.servname,
        inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
    leave_critical_section(4);
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

int connect_local(u32 ip) { /* spawn local process */
#ifdef USE_WIN32
    log(LOG_ERR, "LOCAL MODE NOT SUPPORTED ON WIN32 PLATFORM");
    return -1;
#else
    struct in_addr addr;
    char text[STRLEN];
    int fd[2];
    unsigned long pid;
   
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
    pid=(unsigned long)fork();
    switch(pid) {
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
            /* For Tru64 _RLD_LIST is used instead */
            putenv("_RLD_LIST=" libdir "/stunnel.so:DEFAULT");
            addr.s_addr = ip;
            safecopy(text, "REMOTE_HOST=");
            enter_critical_section(4); /* inet_ntoa is not mt-safe */
            safeconcat(text, inet_ntoa(addr));
            leave_critical_section(4);
            putenv(text);
        }
        execvp(options.execname, options.execargs);
        ioerror("execvp"); /* execv failed */
        _exit(1);
    }
    /* parent */
    log(LOG_INFO, "Local mode child started (PID=%lu)", pid);
    closesocket(fd[1]);
    return fd[0];
#endif /* USE_WIN32 */
}

int connect_remote(u32 ip) { /* connect to remote host */
    struct sockaddr_in addr;
    int s; /* destination socket */
    u32 *list; /* destination addresses list */

    if((s=socket(AF_INET, SOCK_STREAM, 0))<0) {
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
        enter_critical_section(4); /* inet_ntoa is not mt-safe */
        log(LOG_DEBUG, "%s connecting %s:%d", options.servname,
            inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        leave_critical_section(4);
        if(!connect(s, (struct sockaddr *) &addr, sizeof(addr)))
            return s; /* success */
    }
    sockerror("remote connect");
    return -1;
}

int auth_user(struct sockaddr_in *addr) {
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
static int make_sockets(int fd[2]) { /* make pair of connected sockets */
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
        log(LOG_DEBUG, "bind#1: %s (%d)",
            strerror(get_last_socket_error()), get_last_socket_error());
    if(bind(fd[1], (struct sockaddr *)&addr, addrlen))
        log(LOG_DEBUG, "bind#2: %s (%d)",
            strerror(get_last_socket_error()), get_last_socket_error());
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

int set_socket_options(int s, int type) {
    sock_opt *ptr;
    extern sock_opt sock_opts[];
    static char *type_str[3]={"accept", "local", "remote"};

    for(ptr=sock_opts;ptr->opt_str;ptr++) {
        if(!ptr->opt_val[type])
            continue; /* default */
        if(setsockopt(s, ptr->opt_level, ptr->opt_name,
                (void *)ptr->opt_val[type], sizeof(opt_union))) {
            sockerror("setsockopt");
            return -1; /* FAILED */
        } else {
            log(LOG_DEBUG, "%s option set on %s socket",
                ptr->opt_str, type_str[type]);
        }
    }
    return 0; /* OK */
}

static void ioerror(char *txt) { /* Input/Output error handler */
    int error;

    error=get_last_error();
    log(LOG_ERR, "%s: %s (%d)", txt, strerror(error), error);
}

void sockerror(char *txt) { /* Socket error handler */
    int error;

    error=get_last_socket_error();
    log(LOG_ERR, "%s: %s (%d)", txt, strerror(error), error);
}

#ifdef USE_FORK
static void sigchld_handler(int sig) { /* Dead children detected */
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
    log(LOG_ERR, "Received signal %d; terminating", sig);
    exit(3);
}

#endif /* !defined USE_WIN32 */

/* End of stunnel.c */
