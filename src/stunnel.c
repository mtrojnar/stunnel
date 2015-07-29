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

    /* Prototypes */
static void daemon_loop(void);
static void accept_connection(LOCAL_OPTIONS *);
static void get_limits(void); /* setup global max_clients and max_fds */
#if !defined (USE_WIN32) && !defined (__vms)
static void change_root(void);
static void daemonize(void);
static void create_pid(void);
static void delete_pid(void);
#endif

    /* Error/exceptions handling functions */
#ifndef USE_WIN32
static void signal_handler(int);
#endif

int volatile num_clients=0; /* Current number of clients */

    /* Functions */

#ifndef USE_WIN32
int main(int argc, char* argv[]) { /* execution begins here 8-) */

    main_initialize(argc>1 ? argv[1] : NULL, argc>2 ? argv[2] : NULL);

    signal(SIGPIPE, SIG_IGN); /* avoid 'broken pipe' signal */
    if(signal(SIGTERM, SIG_IGN)!=SIG_IGN)
        signal(SIGTERM, signal_handler);
    if(signal(SIGQUIT, SIG_IGN)!=SIG_IGN)
        signal(SIGQUIT, signal_handler);
    if(signal(SIGINT, SIG_IGN)!=SIG_IGN)
        signal(SIGINT, signal_handler);
    if(signal(SIGHUP, SIG_IGN)!=SIG_IGN)
        signal(SIGHUP, signal_handler);
    /* signal(SIGSEGV, signal_handler); */

    main_execute();

    return 0; /* success */
}
#endif

void main_initialize(char *arg1, char *arg2) {
    ssl_init(); /* initialize SSL library */
    sthreads_init(); /* initialize critical sections & SSL callbacks */
    parse_config(arg1, arg2);

#ifdef USE_FIPS
    if(options.option.fips) {
        if(!FIPS_mode_set(1)) {
            ERR_load_crypto_strings();
            sslerror("FIPS_mode_set");
            die(1);
        } else
            s_log(LOG_NOTICE, "stunnel is in FIPS mode");
    } else
        s_log(LOG_DEBUG, "FIPS mode disabled");
#endif /* USE_FIPS */

#ifdef USE_LIBWRAP
    /* spawn LIBWRAP_CLIENTS processes unless inetd mode is configured */
    /* execute after parse_config() to know local_options.next, */
    /* but as early as possible to avoid leaking file descriptors */
    libwrap_init(local_options.next ? LIBWRAP_CLIENTS : 0);
#endif /* USE_LIBWRAP */
    log_open();
    log_flush();
    stunnel_info(0);
}

void main_execute(void) {
    /* check if started from inetd */
    if(local_options.next) { /* there are service sections -> daemon mode */
        daemon_loop();
    } else { /* inetd mode */
#if !defined (USE_WIN32) && !defined (__vms)
        max_fds=FD_SETSIZE; /* just in case */
#ifdef HAVE_CHROOT
        change_root();
#endif /* HAVE_CHROOT */
        drop_privileges();
#endif /* standard Unix */
        num_clients=1;
        client(alloc_client_session(&local_options, 0, 1));
    }
    log_close();
}

static void daemon_loop(void) {
    SOCKADDR_UNION addr;
    s_poll_set fds;
    LOCAL_OPTIONS *opt;
    get_limits();
    s_poll_init(&fds);
#if !defined(USE_WIN32) && !defined(USE_OS2)
    s_poll_add(&fds, signal_pipe_init(), 1, 0);
#endif
    if(!local_options.next) {
        s_log(LOG_ERR, "No connections defined in config file");
        die(1);
    }
    num_clients=0;

    /* bind local ports */
    for(opt=local_options.next; opt; opt=opt->next) {
        if(!opt->option.accept) /* no need to bind this service */
            continue;
        memcpy(&addr, &opt->local_addr.addr[0], sizeof addr);
        if((opt->fd=socket(addr.sa.sa_family, SOCK_STREAM, 0))<0) {
            sockerror("local socket");
            die(1);
        }
        if(alloc_fd(opt->fd))
            die(1);
        if(set_socket_options(opt->fd, 0)<0)
            die(1);
        s_ntop(opt->local_address, &addr);
        if(bind(opt->fd, &addr.sa, addr_len(addr))) {
            s_log(LOG_ERR, "Error binding %s to %s",
                opt->servname, opt->local_address);
            sockerror("bind");
            die(1);
        }
        s_log(LOG_DEBUG, "%s bound to %s", opt->servname, opt->local_address);
        if(listen(opt->fd, 5)) {
            sockerror("listen");
            die(1);
        }
#ifdef FD_CLOEXEC
        fcntl(opt->fd, F_SETFD, FD_CLOEXEC); /* close socket in child execvp */
#endif
        s_poll_add(&fds, opt->fd, 1, 0);
    }

#if !defined (USE_WIN32) && !defined (__vms) && !defined(USE_OS2)
    if(!(options.option.foreground))
        daemonize();
#ifdef HAVE_CHROOT
    change_root();
#endif /* HAVE_CHROOT */
    drop_privileges();
    create_pid();
#endif /* standard Unix */
    /* create exec+connect services */
    for(opt=local_options.next; opt; opt=opt->next) {
        if(opt->option.accept) /* skip ordinary (accepting) services */
            continue;
        enter_critical_section(CRIT_CLIENTS); /* for multi-cpu machines */
        ++num_clients;
        leave_critical_section(CRIT_CLIENTS);
        create_client(-1, -1, alloc_client_session(opt, -1, -1), client);
    }
    while(1) {
        if(s_poll_wait(&fds, -1, -1)<0) { /* non-critical error */
            log_error(LOG_INFO, get_last_socket_error(),
                "daemon_loop: s_poll_wait");
            sleep(1); /* to avoid log trashing */
        } else {
            for(opt=local_options.next; opt; opt=opt->next)
                if(s_poll_canread(&fds, opt->fd))
                    accept_connection(opt);

        }
    }
    s_log(LOG_ERR, "INTERNAL ERROR: End of infinite loop 8-)");
}

static void accept_connection(LOCAL_OPTIONS *opt) {
    SOCKADDR_UNION addr;
    char from_address[IPLEN];
    int s;
    socklen_t addrlen;

    addrlen=sizeof addr;
    while((s=accept(opt->fd, &addr.sa, &addrlen))<0) {
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
    s_log(LOG_DEBUG, "%s accepted FD=%d from %s",
        opt->servname, s, from_address);
    if(max_clients && num_clients>=max_clients) {
        s_log(LOG_WARNING, "Connection rejected: too many clients (>=%d)",
            max_clients);
        closesocket(s);
        return;
    }
#ifdef FD_CLOEXEC
    fcntl(s, F_SETFD, FD_CLOEXEC); /* close socket in child execvp */
#endif
    if(create_client(opt->fd, s, alloc_client_session(opt, s, s), client)) {
        s_log(LOG_ERR, "Connection rejected: create_client failed");
        closesocket(s);
        return;
    }
    enter_critical_section(CRIT_CLIENTS); /* for multi-cpu machines */
    ++num_clients;
    leave_critical_section(CRIT_CLIENTS);
}

static void get_limits(void) {
#ifdef USE_WIN32
    max_clients=0;
    s_log(LOG_NOTICE, "No limit detected for the number of clients");
#else
#if defined(USE_OS2) && defined(__INNOTEK_LIBC__)
    /* OS/2 with the Innotek LIBC does not share the same handles between files
     and socket connections.
     */
    max_clients=(FD_SETSIZE-6)/2;
    max_fds=FD_SETSIZE;
#else
    max_fds=0; /* unlimited */

#if defined HAVE_SYSCONF
    max_fds=sysconf(_SC_OPEN_MAX);
    if(max_fds<0)
        ioerror("sysconf");
#elif defined HAVE_GETRLIMIT
    struct rlimit rlim;
    if(getrlimit(RLIMIT_NOFILE, &rlim)<0)
        ioerror("getrlimit");
    else
        max_fds=rlim.rlim_cur;
    if(max_fds==RLIM_INFINITY)
        max_fds=0; /* RLIM_INFINITY should be equal to zero, anyway */
#endif
    s_log(LOG_INFO, "file ulimit = %d%s (can be changed with 'ulimit -n')",
        max_fds, max_fds ? "" : " (unlimited)");
#ifdef USE_POLL
    s_log(LOG_INFO, "poll() used - no FD_SETSIZE limit for file descriptors");
#else
    s_log(LOG_INFO,
        "FD_SETSIZE = %d (some systems allow to increase this value)",
        FD_SETSIZE);
    if(!max_fds || max_fds>FD_SETSIZE)
        max_fds=FD_SETSIZE;
#endif
    if(max_fds && max_fds<16) /* stunnel needs at least 16 file desriptors */
        max_fds=16;
    if(max_fds) {
        max_clients=max_fds>=256 ? max_fds*125/256 : (max_fds-6)/2;
        s_log(LOG_NOTICE, "%d clients allowed", max_clients);
    } else {
        max_clients=0;
        s_log(LOG_NOTICE, "No limit detected for the number of clients");
    }
#endif
#endif
}

#if !defined (USE_WIN32) && !defined (__vms) && !defined(USE_OS2)

#ifdef HAVE_CHROOT
static void change_root(void) {
    if(options.chroot_dir) {
        if(chroot(options.chroot_dir)) {
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

void drop_privileges(void) {
#ifdef HAVE_SETGROUPS
    gid_t gr_list[1];
#endif

    /* Set uid and gid */
    if(options.gid) {
        if(setgid(options.gid)) {
            sockerror("setgid");
            die(1);
        }
#ifdef HAVE_SETGROUPS
        gr_list[0]=options.gid;
        if(setgroups(1, gr_list)) {
            sockerror("setgroups");
            die(1);
        }
#endif
    }
    if(options.uid) {
        if(setuid(options.uid)) {
            sockerror("setuid");
            die(1);
        }
    }
}

static void daemonize(void) { /* go to background */
#if defined(HAVE_DAEMON) && !defined(__BEOS__)
    if(daemon(0, 0)==-1) {
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
    close(0);
    close(1);
    close(2);
#endif
#ifdef HAVE_SETSID
    setsid(); /* Ignore the error */
#endif
}

static void create_pid(void) {
    int pf;
    char pid[STRLEN];

    if(!options.pidfile) {
        s_log(LOG_DEBUG, "No pid file being created");
        return;
    }
    if(options.pidfile[0]!='/') {
        s_log(LOG_ERR, "Pid file (%s) must be full path name", options.pidfile);
        /* Why?  Because we don't want to confuse by
           allowing '.', which would be '/' after
           daemonizing) */
        die(1);
    }
    options.dpid=(unsigned long)getpid();

    /* silently remove old pid file */
    unlink(options.pidfile);
    if((pf=open(options.pidfile, O_WRONLY|O_CREAT|O_TRUNC|O_EXCL,0644))==-1) {
        s_log(LOG_ERR, "Cannot create pid file %s", options.pidfile);
        ioerror("create");
        die(1);
    }
    sprintf(pid, "%lu\n", options.dpid);
    write(pf, pid, strlen(pid));
    close(pf);
    s_log(LOG_DEBUG, "Created pid file %s", options.pidfile);
    atexit(delete_pid);
}

static void delete_pid(void) {
    s_log(LOG_DEBUG, "removing pid file %s", options.pidfile);
    if((unsigned long)getpid()!=options.dpid)
        return; /* current process is not main daemon process */
    if(unlink(options.pidfile)<0)
        ioerror(options.pidfile); /* not critical */
}

static void signal_handler(int sig) { /* signal handler */
    s_log(sig==SIGTERM ? LOG_NOTICE : LOG_ERR,
        "Received signal %d; terminating", sig);
    die(3);
}

#endif /* standard Unix */

void stunnel_info(int raw) {
    char line[STRLEN];

    sprintf(line, "stunnel " VERSION " on " HOST " with %s",
        SSLeay_version(SSLEAY_VERSION));
    s_log(raw ? LOG_RAW : LOG_NOTICE, "%s", line);

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

    s_log(raw ? LOG_RAW : LOG_NOTICE, "%s", line);
}

void die(int status) { /* some cleanup and exit */
    log_flush();
#ifdef USE_WIN32
    exit_win32(status);
#else
    exit(status);
#endif
}

/* End of stunnel.c */
