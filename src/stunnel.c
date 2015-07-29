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

/**************************************** prototypes */

#ifdef __INNOTEK_LIBC__
struct sockaddr_un {
    u_char  sun_len;             /* sockaddr len including null */
    u_char  sun_family;          /* AF_OS2 or AF_UNIX */
    char    sun_path[108];       /* path name */
};
#endif

static void accept_connection(SERVICE_OPTIONS *);
static void get_limits(void); /* setup global max_clients and max_fds */
#ifdef HAVE_CHROOT
static void change_root(void);
#endif
#if !defined(USE_WIN32) && !defined(__vms)
static void daemonize(void);
static void create_pid(void);
static void delete_pid(void);
#endif
static int setup_fd(int, int, char *);
#if !defined(USE_WIN32) && !defined(USE_OS2)
static void signal_handler(int);
#endif
static void signal_pipe_init(void);
static void signal_pipe_empty(void);
#ifdef USE_FORK
static void client_status(void); /* dead children detected */
#endif

/**************************************** global variables */

static int max_fds;
static int max_clients=0;
static int signal_pipe[2]={-1, -1};

volatile int num_clients=0; /* current number of clients */
s_poll_set *fds; /* file descriptors of listening sockets */

/**************************************** startup */

#ifndef USE_WIN32
int main(int argc, char* argv[]) { /* execution begins here 8-) */
    str_init(); /* initialize per-thread string management */
    main_initialize(argc>1 ? argv[1] : NULL, argc>2 ? argv[2] : NULL);
    if(service_options.next) { /* there are service sections -> daemon mode */
#if !defined(__vms) && !defined(USE_OS2)
        if(!(global_options.option.foreground))
            daemonize();
        /* create_pid() must be called after drop_privileges()
         * or it won't be possible to remove the file on exit */
        /* create_pid() must be called after daemonize()
         * since the final pid is not known beforehand */
        create_pid();
#endif /* standard Unix */
        num_clients=0;
        daemon_loop();
    } else { /* inetd mode */
        num_clients=1;
        client(alloc_client_session(&service_options, 0, 1));
        log_close();
    }
    return 0; /* success */
}
#endif

void main_initialize(char *arg1, char *arg2) {
    ssl_init(); /* initialize SSL library */
    sthreads_init(); /* initialize critical sections & SSL callbacks */
    get_limits(); /* required by setup_fd() */

    fds=s_poll_alloc();
    signal_pipe_init();
    s_poll_init(fds);
    s_poll_add(fds, signal_pipe[0], 1, 0);
    /* the most essential initialization is performed here,
     * so gui.c can execute a thread with daemon_loop() */

    stunnel_info(LOG_NOTICE);
    parse_commandline(arg1, arg2);
    str_canary(); /* needs prng initialization from parse_commandline */
#if !defined(USE_WIN32) && !defined(__vms)
    /* syslog_open() must be called before change_root()
     * to be able to access /dev/log socket */
    syslog_open();
#endif /* !defined(USE_WIN32) && !defined(__vms) */
    if(bind_ports())
        die(1);

#ifdef HAVE_CHROOT
    /* change_root() must be called before drop_privileges()
     * since chroot() needs root privileges */
    change_root();
#endif /* HAVE_CHROOT */

#if !defined(USE_WIN32) && !defined(__vms) && !defined(USE_OS2)
    drop_privileges(1);
#endif /* standard Unix */

    /* log_open() must be be called after drop_privileges()
     * or logfile rotation won't be possible */
    /* log_open() must be be called before daemonize()
     * since daemonize() invalidates stderr */
    log_open();
}

/**************************************** main loop */

void daemon_loop(void) {
    SERVICE_OPTIONS *opt;

    while(1) {
        if(s_poll_wait(fds, -1, -1)>=0) { /* non-critical error */
            if(s_poll_canread(fds, signal_pipe[0]))
                signal_pipe_empty();
            for(opt=service_options.next; opt; opt=opt->next)
                if(s_poll_canread(fds, opt->fd))
                    accept_connection(opt);
        } else {
            log_error(LOG_INFO, get_last_socket_error(),
                "daemon_loop: s_poll_wait");
            sleep(1); /* to avoid log trashing */
        }
    }
}

static void accept_connection(SERVICE_OPTIONS *opt) {
    SOCKADDR_UNION addr;
    char *from_address;
    int s;
    socklen_t addrlen;

    addrlen=sizeof addr;
    for(;;) {
        s=s_accept(opt->fd, &addr.sa, &addrlen, 1, "local socket");
        if(s>=0) /* success! */
            break;
        switch(get_last_socket_error()) {
            case S_EINTR:
                break; /* retry */
            case S_EMFILE:
#ifdef S_ENFILE
            case S_ENFILE:
#endif
#ifdef S_ENOBUFS
            case S_ENOBUFS:
#endif
#ifdef S_ENOMEM
            case S_ENOMEM:
#endif
                sleep(1); /* temporarily out of resources - short delay */
            default:
                sockerror("accept");
                return; /* error */
        }
    }
    from_address=s_ntop(&addr, addrlen);
    s_log(LOG_DEBUG, "Service %s accepted FD=%d from %s",
        opt->servname, s, from_address);
    str_free(from_address);
    if(max_clients && num_clients>=max_clients) {
        s_log(LOG_WARNING, "Connection rejected: too many clients (>=%d)",
            max_clients);
        closesocket(s);
        return;
    }
    enter_critical_section(CRIT_CLIENTS); /* for multi-cpu machines */
    /* increment before create_client() to prevent race condition
     * resulting in logging "Service xxx finished (-1 left)" */
    ++num_clients;
    leave_critical_section(CRIT_CLIENTS);
    if(create_client(opt->fd, s, alloc_client_session(opt, s, s), client)) {
        s_log(LOG_ERR, "Connection rejected: create_client failed");
        enter_critical_section(CRIT_CLIENTS); /* for multi-cpu machines */
        --num_clients;
        leave_critical_section(CRIT_CLIENTS);
        closesocket(s);
        return;
    }
}

/**************************************** initialization helpers */

/* clear fds, close old ports */
void unbind_ports(void) {
    SERVICE_OPTIONS *opt;
#ifdef HAVE_STRUCT_SOCKADDR_UN
    struct stat st; /* buffer for stat */
#endif

    s_poll_init(fds);
    s_poll_add(fds, signal_pipe[0], 1, 0);
    for(opt=service_options.next; opt; opt=opt->next)
        if(opt->option.accept && opt->fd>=0) {
            closesocket(opt->fd);
#ifdef HAVE_STRUCT_SOCKADDR_UN
            if(opt->local_addr.sa.sa_family==AF_UNIX) {
                if(lstat(opt->local_addr.un.sun_path, &st))
                    sockerror(opt->local_addr.un.sun_path);
                else if(!S_ISSOCK(st.st_mode))
                    s_log(LOG_ERR, "Not a socket: %s",
                        opt->local_addr.un.sun_path);
                else if(unlink(opt->local_addr.un.sun_path))
                    sockerror(opt->local_addr.un.sun_path);
                else
                    s_log(LOG_DEBUG, "Socket removed: %s",
                        opt->local_addr.un.sun_path);
            }
#endif
            s_log(LOG_DEBUG, "Service %s closed FD=%d",
                opt->servname, opt->fd);
            opt->fd=-1;
        }
}

/* open new ports, update fds */
int bind_ports(void) {
    SERVICE_OPTIONS *opt;
    char *local_address;

#ifdef USE_LIBWRAP
    /* execute after parse_commandline() to know service_options.next,
     * but as early as possible to avoid leaking file descriptors */
    /* retry on each bind_ports() in case stunnel.conf was reloaded
       without "libwrap = no" */
    libwrap_init();
#endif /* USE_LIBWRAP */

    s_poll_init(fds);
    s_poll_add(fds, signal_pipe[0], 1, 0);
    for(opt=service_options.next; opt; opt=opt->next) {
        if(opt->option.accept) {
            opt->fd=s_socket(opt->local_addr.sa.sa_family,
                SOCK_STREAM, 0, 1, "accept socket");
            if(opt->fd<0)
                return 1;
            if(set_socket_options(opt->fd, 0)<0) {
                closesocket(opt->fd);
                return 1;
            }
            /* local socket can't be unnamed */
            local_address=s_ntop(&opt->local_addr, addr_len(&opt->local_addr));
            if(bind(opt->fd, &opt->local_addr.sa, addr_len(&opt->local_addr))) {
                s_log(LOG_ERR, "Error binding %s to %s",
                    opt->servname, local_address);
                sockerror("bind");
                closesocket(opt->fd);
                str_free(local_address);
                return 1;
            }
            s_log(LOG_DEBUG, "Service %s bound to %s",
                opt->servname, local_address);
            str_free(local_address);
            if(listen(opt->fd, SOMAXCONN)) {
                sockerror("listen");
                closesocket(opt->fd);
                return 1;
            }
            s_poll_add(fds, opt->fd, 1, 0);
            s_log(LOG_DEBUG, "Service %s opened FD=%d",
                opt->servname, opt->fd);
        } else if(opt->option.program && opt->option.remote) {
            /* create exec+connect services */
            enter_critical_section(CRIT_CLIENTS);
            ++num_clients;
            leave_critical_section(CRIT_CLIENTS);
            create_client(-1, -1, alloc_client_session(opt, -1, -1), client);
        }
    }
    return 0; /* OK */
}

static void get_limits(void) {
    /* start with current ulimit */
#if defined(HAVE_SYSCONF)
    errno=0;
    max_fds=sysconf(_SC_OPEN_MAX);
    if(errno)
        ioerror("sysconf");
    if(max_fds<0)
        max_fds=0; /* unlimited */
#elif defined(HAVE_GETRLIMIT)
    struct rlimit rlim;

    if(getrlimit(RLIMIT_NOFILE, &rlim)<0) {
        ioerror("getrlimit");
        max_fds=0; /* unlimited */
    } else
        max_fds=rlim.rlim_cur!=RLIM_INFINITY ? rlim.rlim_cur : 0;
#else
    max_fds=0; /* unlimited */
#endif /* HAVE_SYSCONF || HAVE_GETRLIMIT */

#if !defined(USE_WIN32) && !defined(USE_POLL) && !defined(__INNOTEK_LIBC__)
    /* apply FD_SETSIZE if select() is used on Unix */
    if(!max_fds || max_fds>FD_SETSIZE)
        max_fds=FD_SETSIZE; /* start with select() limit */
#endif /* select() on Unix */

    /* stunnel needs at least 16 file desriptors */
    if(max_fds && max_fds<16)
        max_fds=16;

    if(max_fds) {
        max_clients=max_fds>=256 ? max_fds*125/256 : (max_fds-6)/2;
        s_log(LOG_DEBUG, "Clients allowed=%d", max_clients);
    } else {
        max_clients=0;
        s_log(LOG_DEBUG, "No limit detected for the number of clients");
    }
}

#ifdef HAVE_CHROOT
static void change_root(void) {
    if(global_options.chroot_dir) {
        if(chroot(global_options.chroot_dir)) {
            sockerror("chroot");
            die(1);
        }
        if(chdir("/")) {
            sockerror("chdir");
            die(1);
        }
    }
}
#endif /* HAVE_CHROOT */

#if !defined(USE_WIN32) && !defined(__vms) && !defined(USE_OS2)

void drop_privileges(int critical) {
#ifdef HAVE_SETGROUPS
    gid_t gr_list[1];
#endif

    /* set uid and gid */
    if(global_options.gid) {
        if(setgid(global_options.gid) && critical) {
            sockerror("setgid");
            die(1);
        }
#ifdef HAVE_SETGROUPS
        gr_list[0]=global_options.gid;
        if(setgroups(1, gr_list) && critical) {
            sockerror("setgroups");
            die(1);
        }
#endif
    }
    if(global_options.uid) {
        if(setuid(global_options.uid) && critical) {
            sockerror("setuid");
            die(1);
        }
    }
}

static void daemonize(void) { /* go to background */
    close(0);
    close(1);
    close(2);
#if defined(HAVE_DAEMON) && !defined(__BEOS__)
    /* set noclose option when calling daemon() function,
     * so it does not require /dev/null device in the chrooted directory */
    if(daemon(0, 1)==-1) {
        ioerror("daemon");
        die(1);
    }
#else
    chdir("/");
    switch(fork()) {
    case -1:    /* fork failed */
        ioerror("fork");
        die(1);
    case 0:     /* child */
        break;
    default:    /* parent */
        die(0);
    }
#endif
#ifdef HAVE_SETSID
    setsid(); /* ignore the error */
#endif
}

static void create_pid(void) {
    int pf;
    char *pid;

    if(!global_options.pidfile) {
        s_log(LOG_DEBUG, "No pid file being created");
        return;
    }
    if(global_options.pidfile[0]!='/') {
        /* to prevent creating pid file relative to '/' after daemonize() */
        s_log(LOG_ERR, "Pid file (%s) must be full path name", global_options.pidfile);
        die(1);
    }
    global_options.dpid=(unsigned long)getpid();

    /* silently remove old pid file */
    unlink(global_options.pidfile);
    pf=open(global_options.pidfile, O_WRONLY|O_CREAT|O_TRUNC|O_EXCL, 0644);
    if(pf==-1) {
        s_log(LOG_ERR, "Cannot create pid file %s", global_options.pidfile);
        ioerror("create");
        die(1);
    }
    pid=str_printf("%lu\n", global_options.dpid);
    write(pf, pid, strlen(pid));
    str_free(pid);
    close(pf);
    s_log(LOG_DEBUG, "Created pid file %s", global_options.pidfile);
    atexit(delete_pid);
}

static void delete_pid(void) {
    if((unsigned long)getpid()!=global_options.dpid)
        return; /* current process is not main daemon process */
    s_log(LOG_DEBUG, "removing pid file %s", global_options.pidfile);
    if(unlink(global_options.pidfile)<0)
        ioerror(global_options.pidfile); /* not critical */
}

#endif /* standard Unix */

/**************************************** signal pipe handling */

static void signal_pipe_init(void) {
#ifdef USE_WIN32
    if(make_sockets(signal_pipe))
        die(1);
#else
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
    if(s_pipe(signal_pipe, 1, "signal_pipe"))
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
#endif /* USE_WIN32 */
}

void signal_post(int sig) {
    writesocket(signal_pipe[1], (char *)&sig, sizeof sig);
}

static void signal_pipe_empty(void) {
    int sig, err;

    s_log(LOG_DEBUG, "Dispatching signals from the signal pipe");
    while(readsocket(signal_pipe[0], (char *)&sig, sizeof sig)==sizeof sig) {
        switch(sig) {
#ifndef USE_WIN32
        case SIGCHLD:
            s_log(LOG_DEBUG, "Processing SIGCHLD");
#ifdef USE_FORK
            client_status(); /* report status of client process */
#else /* USE_UCONTEXT || USE_PTHREAD */
            child_status();  /* report status of libwrap or 'exec' process */
#endif /* defined USE_FORK */
            break;
#endif /* !defind USE_WIN32 */
        case SIGNAL_RELOAD_CONFIG:
            s_log(LOG_DEBUG, "Processing SIGNAL_RELOAD_CONFIG");
            err=parse_conf(NULL, CONF_RELOAD);
            if(err) {
                s_log(LOG_ERR, "Failed to reload the configuration file");
            } else {
                unbind_ports();
                log_close();
                apply_conf();
                log_open();
                if(bind_ports()) {
                    /* FIXME: handle the error */
                }
            }
#ifdef USE_WIN32
            win_newconfig();
#endif
            break;
        case SIGNAL_REOPEN_LOG:
            s_log(LOG_DEBUG, "Processing SIGNAL_REOPEN_LOG");
            log_close();
            log_open();
            s_log(LOG_NOTICE, "Log file reopened");
            break;
        case SIGNAL_TERMINATE:
            s_log(LOG_DEBUG, "Processing SIGNAL_TERMINATE");
            s_log(LOG_NOTICE, "Terminated");
            die(2);
        default:
            s_log(LOG_ERR, "Received signal %d; terminating", sig);
            die(1);
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

#if !defined(USE_WIN32) && !defined(USE_OS2)

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

static void signal_handler(int sig) {
    int saved_errno;

    saved_errno=errno;
    signal_post(sig);
    signal(sig, signal_handler);
    errno=saved_errno;
}

#endif /* !defined(USE_WIN32) && !defined(USE_OS2) */

/**************************************** file descriptor validation */

#if defined USE_NEW_LINUX_API && defined HAVE_SOCKET4
#define USE_NEW_LINUX_API 1
#endif

int s_socket(int domain, int type, int protocol, int nonblock, char *msg) {
#ifdef USE_NEW_LINUX_API
    if(nonblock)
        type|=SOCK_NONBLOCK|SOCK_CLOEXEC;
    else
        type|=SOCK_CLOEXEC;
#endif
    return setup_fd(socket(domain, type, protocol), nonblock, msg);
}

int s_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen,
        int nonblock, char *msg) {
    int fd;

#ifdef USE_NEW_LINUX_API
    if(nonblock)
        fd=accept4(sockfd, addr, addrlen, SOCK_NONBLOCK|SOCK_CLOEXEC);
    else
        fd=accept4(sockfd, addr, addrlen, SOCK_CLOEXEC);
#else
    fd=accept(sockfd, addr, addrlen);
#endif
    return setup_fd(fd, nonblock, msg);
}

#ifndef USE_WIN32

int s_socketpair(int domain, int type, int protocol, int sv[2],
        int nonblock, char *msg) {
#ifdef USE_NEW_LINUX_API
    if(nonblock)
        type|=SOCK_NONBLOCK|SOCK_CLOEXEC;
    else
        type|=SOCK_CLOEXEC;
#endif
    if(socketpair(domain, type, protocol, sv)<0) {
        ioerror(msg);
        return -1;
    }
    if(setup_fd(sv[0], nonblock, msg)<0) {
        closesocket(sv[1]);
        return -1;
    }
    if(setup_fd(sv[1], nonblock, msg)<0) {
        closesocket(sv[0]);
        return -1;
    }
    return 0;
}

int s_pipe(int pipefd[2], int nonblock, char *msg) {
    int retval;

#ifdef USE_NEW_LINUX_API
    if(nonblock)
        retval=pipe2(pipefd, O_NONBLOCK|O_CLOEXEC);
    else
        retval=pipe2(pipefd, O_CLOEXEC);
#else
    retval=pipe(pipefd);
#endif
    if(retval<0) {
        ioerror(msg);
        return -1;
    }
    if(setup_fd(pipefd[0], nonblock, msg)<0) {
        close(pipefd[1]);
        return -1;
    }
    if(setup_fd(pipefd[1], nonblock, msg)<0) {
        close(pipefd[0]);
        return -1;
    }
    return 0;
}

#endif /* USE_WIN32 */

/* try to use non-POSIX O_NDELAY on obsolete BSD systems */
#if !defined O_NONBLOCK && defined O_NDELAY
#define O_NONBLOCK O_NDELAY
#endif

static int setup_fd(int fd, int nonblock, char *msg) {
#ifdef FD_CLOEXEC
    int err;
#endif /* FD_CLOEXEC */

    if(fd<0) {
        sockerror(msg);
        return -1;
    }
    if(max_fds && fd>=max_fds) {
        s_log(LOG_ERR,
            "%s: FD=%d out of range (max %d)", msg, fd, max_fds);
        closesocket(fd);
        return -1;
    }
#ifndef USE_NEW_LINUX_API
    set_nonblock(fd, nonblock);
#ifdef FD_CLOEXEC
    do {
        err=fcntl(fd, F_SETFD, FD_CLOEXEC);
    } while(err<0 && get_last_socket_error()==S_EINTR);
    if(err<0)
        sockerror("fcntl SETFD"); /* non-critical */
#endif /* FD_CLOEXEC */
#endif /* USE_NEW_LINUX_API */
    s_log(LOG_DEBUG, "%s: FD=%d allocated (%sblocking mode)",
        msg, fd, nonblock?"non-":"");
    return fd;
}

void set_nonblock(int fd, unsigned long nonblock) {
#if defined F_GETFL && defined F_SETFL && defined O_NONBLOCK && !defined __INNOTEK_LIBC__
    int err, flags;

    do {
        flags=fcntl(fd, F_GETFL, 0);
    } while(flags<0 && get_last_socket_error()==S_EINTR);
    if(flags<0) {
        sockerror("fcntl GETFL"); /* non-critical */
        return;
    }
    if(nonblock)
        flags|=O_NONBLOCK;
    else
        flags&=~O_NONBLOCK;
    do {
        err=fcntl(fd, F_SETFL, flags);
    } while(err<0 && get_last_socket_error()==S_EINTR);
    if(err<0)
        sockerror("fcntl SETFL"); /* non-critical */
#else /* use fcntl() */
    if(ioctlsocket(fd, FIONBIO, &nonblock)<0)
        sockerror("ioctlsocket"); /* non-critical */
#endif /* use fcntl() */
}

/**************************************** log messages to identify  build */

void stunnel_info(int level) {
    s_log(level, "stunnel " STUNNEL_VERSION " on " HOST " platform");
    if(SSLeay()==SSLEAY_VERSION_NUMBER) {
        s_log(level, "Compiled/running with " OPENSSL_VERSION_TEXT);
    } else {
        s_log(level, "Compiled with " OPENSSL_VERSION_TEXT);
        s_log(level, "Running  with %s", SSLeay_version(SSLEAY_VERSION));
        s_log(level, "Update OpenSSL shared libraries or rebuild stunnel");
    }
    s_log(level,
        "Threading:"
#ifdef USE_UCONTEXT
        "UCONTEXT"
#endif
#ifdef USE_PTHREAD
        "PTHREAD"
#endif
#ifdef USE_WIN32
        "WIN32"
#endif
#ifdef USE_FORK
        "FORK"
#endif

        " SSL:"
#ifdef HAVE_OSSL_ENGINE_H
        "ENGINE"
#else /* defined(HAVE_OSSL_ENGINE_H) */
        "NOENGINE"
#endif /* defined(HAVE_OSSL_ENGINE_H) */
#ifdef USE_FIPS
        ",FIPS"
#endif /* USE_FIPS */

        " Auth:"
#ifdef USE_LIBWRAP
        "LIBWRAP"
#else
        "none"
#endif

        " Sockets:"
#ifdef USE_POLL
        "POLL"
#else /* defined(USE_POLL) */
        "SELECT"
#endif /* defined(USE_POLL) */
        ",IPv%c",
#if defined(USE_WIN32) && !defined(_WIN32_WCE)
        s_getaddrinfo ? '6' : '4'
#else /* defined(USE_WIN32) */
#if defined(USE_IPv6)
        '6'
#else /* defined(USE_IPv6) */
        '4'
#endif /* defined(USE_IPv6) */
#endif /* defined(USE_WIN32) */
        );
}

/**************************************** fatal error */

void die(int status) { /* some cleanup and exit */
    unbind_ports();
    s_poll_free(fds);
    str_stats();
    log_flush(LOG_MODE_ERROR);
#ifdef USE_WIN32
    win_exit(status);
#else
    exit(status);
#endif
}

/* end of stunnel.c */
