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

static void daemon_loop(void);
static void accept_connection(SERVICE_OPTIONS *);
static void get_limits(void); /* setup global max_clients and max_fds */
#if !defined(USE_WIN32) && !defined(__vms)
static void change_root(void);
static void daemonize(void);
static void create_pid(void);
static void delete_pid(void);
#endif
static int setup_fd(int, int, char *);

/**************************************** global variables */

static int max_fds;
static int max_clients=0;

int volatile num_clients=0; /* current number of clients */
s_poll_set fds; /* file descriptors of listening sockets */
#if !defined(USE_WIN32) && !defined(USE_OS2)
int signal_fd;
#endif

/**************************************** startup */

#ifndef USE_WIN32
int main(int argc, char* argv[]) { /* execution begins here 8-) */

    main_initialize(argc>1 ? argv[1] : NULL, argc>2 ? argv[2] : NULL);

    main_execute();

    return 0; /* success */
}
#endif

void main_initialize(char *arg1, char *arg2) {
    ssl_init(); /* initialize SSL library */
    sthreads_init(); /* initialize critical sections & SSL callbacks */
    parse_commandline(arg1, arg2);

    max_fds=FD_SETSIZE; /* start with select() limit */
    get_limits();
#ifdef USE_LIBWRAP
    /* spawn LIBWRAP_CLIENTS processes unless inetd mode is configured
     * execute after parse_commandline() to know service_options.next,
     * but as early as possible to avoid leaking file descriptors */
    libwrap_init(service_options.next ? LIBWRAP_CLIENTS : 0);
#endif /* USE_LIBWRAP */
#if !defined(USE_WIN32) && !defined(__vms)
    /* syslog_open() must be called before change_root()
     * to be able to access /dev/log socket */
    syslog_open();
#endif /* !defined(USE_WIN32) && !defined(__vms) */
#if !defined(USE_WIN32) && !defined(USE_OS2)
    signal_fd=signal_pipe_init();
#endif
    if(!bind_ports())
        die(1);

#ifdef HAVE_CHROOT
    /* change_root() must be called before drop_privileges()
     * since chroot() needs root privileges */
    change_root();
#endif /* HAVE_CHROOT */

#if !defined(USE_WIN32) && !defined(__vms) && !defined(USE_OS2)
    drop_privileges();
#endif /* standard Unix */

    /* log_open() must be be called after drop_privileges()
     * or logfile rotation won't be possible */
    /* log_open() must be be called before daemonize()
     * since daemonize() invalidates stderr */
    log_open();

#if !defined(USE_WIN32) && !defined(__vms) && !defined(USE_OS2)
    if(service_options.next) { /* there are service sections -> daemon mode */
        if(!(global_options.option.foreground))
            daemonize();
        /* create_pid() must be called after drop_privileges()
         * or it won't be possible to remove the file on exit */
        /* create_pid() must be called after daemonize()
         * since the final pid is not known beforehand */
        create_pid();
    }
#endif /* standard Unix */

    stunnel_info(LOG_NOTICE);
}

void main_execute(void) {
    if(service_options.next) { /* there are service sections -> daemon mode */
        num_clients=0;
        while(1)
            daemon_loop();
    } else { /* inetd mode */
        num_clients=1;
        client(alloc_client_session(&service_options, 0, 1));
        log_close();
    }
}

/**************************************** main loop */

static void daemon_loop(void) {
    SERVICE_OPTIONS *opt;

    if(s_poll_wait(&fds, -1, -1)>=0) { /* non-critical error */
        for(opt=service_options.next; opt; opt=opt->next)
            if(s_poll_canread(&fds, opt->fd))
                accept_connection(opt);
    } else {
        log_error(LOG_INFO, get_last_socket_error(),
            "daemon_loop: s_poll_wait");
        sleep(1); /* to avoid log trashing */
    }
}

static void accept_connection(SERVICE_OPTIONS *opt) {
    SOCKADDR_UNION addr;
    char from_address[IPLEN];
    int s;
    socklen_t addrlen;

    addrlen=sizeof addr;
    for(;;) {
        s=s_accept(opt->fd, &addr.sa, &addrlen, 1, "local socket");
        if(s>=0) /* success! */
            break;
        switch(get_last_socket_error()) {
            case EINTR:
                break; /* retry */
            case EMFILE:
#ifdef ENFILE
            case ENFILE:
#endif
#ifdef ENOBUFS
            case ENOBUFS:
#endif
            case ENOMEM:
                sleep(1); /* temporarily out of resources - short delay */
            default:
                sockerror("accept");
                return; /* error */
        }
    }
    s_ntop(from_address, &addr);
    s_log(LOG_DEBUG, "Service %s accepted FD=%d from %s",
        opt->servname, s, from_address);
    if(max_clients && num_clients>=max_clients) {
        s_log(LOG_WARNING, "Connection rejected: too many clients (>=%d)",
            max_clients);
        closesocket(s);
        return;
    }
    if(create_client(opt->fd, s, alloc_client_session(opt, s, s), client)) {
        s_log(LOG_ERR, "Connection rejected: create_client failed");
        closesocket(s);
        return;
    }
    enter_critical_section(CRIT_CLIENTS); /* for multi-cpu machines */
    ++num_clients;
    leave_critical_section(CRIT_CLIENTS);
}

/**************************************** initialization helpers */

/* close old ports, open new ports, update fds */
int bind_ports(void) {
    SERVICE_OPTIONS *opt;
    static SERVICE_OPTIONS *prev_opt=NULL;
    SOCKADDR_UNION addr;

    s_poll_init(&fds);
#if !defined(USE_WIN32) && !defined(USE_OS2)
    s_poll_add(&fds, signal_fd, 1, 0);
#endif

    for(opt=prev_opt; opt; opt=opt->next)
        if(opt->option.accept) {
            closesocket(opt->fd);
            s_log(LOG_DEBUG, "Service %s closed FD=%d",
                opt->servname, opt->fd);
        }
    prev_opt=service_options.next;

    for(opt=prev_opt; opt; opt=opt->next) {
        if(opt->option.accept) {
            memcpy(&addr, &opt->local_addr.addr[0], sizeof addr);
            opt->fd=s_socket(addr.sa.sa_family, SOCK_STREAM, 0, 1, "accept socket");
            if(opt->fd<0)
                return 0;
            if(set_socket_options(opt->fd, 0)<0)
                return 0;
            s_ntop(opt->local_address, &addr);
            if(bind(opt->fd, &addr.sa, addr_len(addr))) {
                s_log(LOG_ERR, "Error binding %s to %s",
                    opt->servname, opt->local_address);
                sockerror("bind");
                return 0;
            }
            s_log(LOG_DEBUG, "Service %s bound to %s",
                opt->servname, opt->local_address);
            if(listen(opt->fd, 5)) {
                sockerror("listen");
                return 0;
            }
            s_poll_add(&fds, opt->fd, 1, 0);
            s_log(LOG_DEBUG, "Service %s opened FD=%d",
                opt->servname, opt->fd);
        } else { /* create exec+connect services */
            enter_critical_section(CRIT_CLIENTS);
            ++num_clients;
            leave_critical_section(CRIT_CLIENTS);
            create_client(-1, -1, alloc_client_session(opt, -1, -1), client);
        }
    }
    return 1; /* OK */
}

static void get_limits(void) {
#if defined(USE_WIN32) || defined(USE_POLL)
    max_fds=0; /* unlimited */
#elif defined(USE_OS2) && defined(__INNOTEK_LIBC__)
    /* OS/2 with the Innotek LIBC does not share the same
       handles between files and socket connections */
#else /* Unix */
#if defined(HAVE_SYSCONF)
    int open_max;

    open_max=sysconf(_SC_OPEN_MAX);
    if(open_max<0)
        ioerror("sysconf");
    if(open_max<max_fds)
        max_fds=open_max;
#elif defined(HAVE_GETRLIMIT)
    struct rlimit rlim;

    if(getrlimit(RLIMIT_NOFILE, &rlim)<0)
        ioerror("getrlimit");
    if(rlim.rlim_cur!=RLIM_INFINITY && rlim.rlim_cur<max_fds)
        max_fds=rlim.rlim_cur;
#endif /* HAVE_SYSCONF || HAVE_GETRLIMIT */
#endif /* Unix */
    if(max_fds && max_fds<16) /* stunnel needs at least 16 file desriptors */
        max_fds=16;

    if(max_fds) {
        max_clients=max_fds>=256 ? max_fds*125/256 : (max_fds-6)/2;
        s_log(LOG_NOTICE, "Clients allowed=%d", max_clients);
    } else {
        max_clients=0;
        s_log(LOG_NOTICE, "No limit detected for the number of clients");
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

void drop_privileges(void) {
#ifdef HAVE_SETGROUPS
    gid_t gr_list[1];
#endif

    /* set uid and gid */
    if(global_options.gid) {
        if(setgid(global_options.gid)) {
            sockerror("setgid");
            die(1);
        }
#ifdef HAVE_SETGROUPS
        gr_list[0]=global_options.gid;
        if(setgroups(1, gr_list)) {
            sockerror("setgroups");
            die(1);
        }
#endif
    }
    if(global_options.uid) {
        if(setuid(global_options.uid)) {
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
    char pid[STRLEN];

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
    if((pf=open(global_options.pidfile, O_WRONLY|O_CREAT|O_TRUNC|O_EXCL,0644))==-1) {
        s_log(LOG_ERR, "Cannot create pid file %s", global_options.pidfile);
        ioerror("create");
        die(1);
    }
    sprintf(pid, "%lu\n", global_options.dpid);
    write(pf, pid, strlen(pid));
    close(pf);
    s_log(LOG_DEBUG, "Created pid file %s", global_options.pidfile);
    atexit(delete_pid);
}

static void delete_pid(void) {
    s_log(LOG_DEBUG, "removing pid file %s", global_options.pidfile);
    if((unsigned long)getpid()!=global_options.dpid)
        return; /* current process is not main daemon process */
    if(unlink(global_options.pidfile)<0)
        ioerror(global_options.pidfile); /* not critical */
}

#endif /* standard Unix */

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
#ifdef USE_WIN32
    unsigned long l;
#else /* USE_WIN32 */
    int err, flags;
#endif /* USE_WIN32 */

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
#if defined F_GETFL && defined F_SETFL && defined O_NONBLOCK && !defined __INNOTEK_LIBC__
    do {
        flags=fcntl(fd, F_GETFL, 0);
    } while(flags<0 && get_last_socket_error()==EINTR);
    if(nonblock)
        flags|=O_NONBLOCK;
    else
        flags&=~O_NONBLOCK;
#ifdef FD_CLOEXEC
    flags|=FD_CLOEXEC;
#endif /* FD_CLOEXEC */
    do {
        err=fcntl(fd, F_SETFL, flags);
    } while(err<0 && get_last_socket_error()==EINTR);
    if(err<0)
        sockerror("fcntl"); /* non-critical */
#else /* use fcntl() */
    if(ioctlsocket(fd, FIONBIO, &l)<0)
        sockerror("ioctlsocket"); /* non-critical */
#endif /* use fcntl() */
#endif /* USE_NEW_LINUX_API */
    s_log(LOG_DEBUG, "%s: FD=%d allocated (%sblocking mode)",
        msg, fd, nonblock?"non-":"");
    return fd;
}

/**************************************** log messages to identify  build */

void stunnel_info(int level) {
    char line[STRLEN];

    s_log(level, "stunnel " STUNNEL_VERSION " on " HOST " with %s",
        SSLeay_version(SSLEAY_VERSION));

    safecopy(line, "Threading:");
#ifdef USE_UCONTEXT
    safeconcat(line, "UCONTEXT");
#endif
#ifdef USE_PTHREAD
    safeconcat(line, "PTHREAD");
#endif
#ifdef USE_WIN32
    safeconcat(line, "WIN32");
#endif
#ifdef USE_FORK
    safeconcat(line, "FORK");
#endif

    safeconcat(line, " SSL:");
#ifdef HAVE_OSSL_ENGINE_H
    safeconcat(line, "ENGINE");
#else /* defined(HAVE_OSSL_ENGINE_H) */
    safeconcat(line, "NOENGINE");
#endif /* defined(HAVE_OSSL_ENGINE_H) */
#ifdef USE_FIPS
    safeconcat(line, ",FIPS");
#endif /* USE_FIPS */

    safeconcat(line, " Sockets:");
#ifdef USE_POLL
    safeconcat(line, "POLL");
#else /* defined(USE_POLL) */
    safeconcat(line, "SELECT");
#endif /* defined(USE_POLL) */
#if defined(USE_WIN32) && !defined(_WIN32_WCE)
    if(s_getaddrinfo)
        safeconcat(line, ",IPv6");
    else
        safeconcat(line, ",IPv4");
#else /* defined(USE_WIN32) */
#if defined(USE_IPv6)
    safeconcat(line, ",IPv6");
#else /* defined(USE_IPv6) */
    safeconcat(line, ",IPv4");
#endif /* defined(USE_IPv6) */
#endif /* defined(USE_WIN32) */

#ifdef USE_LIBWRAP
    safeconcat(line, " Auth:LIBWRAP");
#endif

    s_log(level, "%s", line);
}

/**************************************** fatal error */

void die(int status) { /* some cleanup and exit */
    log_flush(LOG_MODE_ERROR);
#ifdef USE_WIN32
    exit_win32(status);
#else
    exit(status);
#endif
}

/* end of stunnel.c */
