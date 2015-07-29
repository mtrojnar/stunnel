/*
 *   stunnel       Universal SSL tunnel
 *   Copyright (C) 1998-2013 Michal Trojnara <Michal.Trojnara@mirt.net>
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

/* http://www.openssl.org/support/faq.html#PROG2 */
#ifdef USE_WIN32
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-pedantic"
#endif /* __GNUC__ */
#ifdef __GNUC__
#include <../ms/applink.c>
#else /* __GNUC__ */
#include <openssl/applink.c>
#endif /* __GNUC__ */
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif /* __GNUC__ */
#endif /* USE_WIN32 */

/**************************************** prototypes */

#ifdef __INNOTEK_LIBC__
struct sockaddr_un {
    u_char  sun_len;             /* sockaddr len including null */
    u_char  sun_family;          /* AF_OS2 or AF_UNIX */
    char    sun_path[108];       /* path name */
};
#endif

#ifndef USE_WIN32
static int main_unix(int, char*[]);
#endif
static int accept_connection(SERVICE_OPTIONS *);
#ifdef HAVE_CHROOT
static int change_root(void);
#endif
#if !defined(USE_WIN32) && !defined(__vms)
static int daemonize(int);
static int create_pid(void);
static void delete_pid(void);
#endif
#if !defined(USE_WIN32) && !defined(USE_OS2)
static void signal_handler(int);
#endif
static int signal_pipe_init(void);
static int signal_pipe_dispatch(void);
#ifdef USE_FORK
static void client_status(void); /* dead children detected */
#endif

/**************************************** global variables */

static int signal_pipe[2]={-1, -1};

#ifndef USE_FORK
int max_clients=0;
volatile int num_clients=0; /* current number of clients */
#endif
s_poll_set *fds; /* file descriptors of listening sockets */

/**************************************** startup */

#ifndef USE_WIN32
int main(int argc, char* argv[]) { /* execution begins here 8-) */
    int retval;

#ifdef M_MMAP_THRESHOLD
    mallopt(M_MMAP_THRESHOLD, 4096);
#endif
    str_init(); /* initialize per-thread string management */
    retval=main_unix(argc, argv);
    unbind_ports();
    s_poll_free(fds);
    fds=NULL;
    str_stats();
    log_flush(LOG_MODE_ERROR);
    return retval;
}

static int main_unix(int argc, char* argv[]) {
#if !defined(__vms) && !defined(USE_OS2)
    int fd;

    fd=open("/dev/null", O_RDWR); /* open /dev/null before chroot */
    if(fd<0)
        fatal("Could not open /dev/null");
#endif /* standard Unix */
    main_initialize();
    if(main_configure(argc>1 ? argv[1] : NULL, argc>2 ? argv[2] : NULL)) {
        close(fd);
        return 1;
    }
    if(service_options.next) { /* there are service sections -> daemon mode */
#if !defined(__vms) && !defined(USE_OS2)
        if(daemonize(fd)) {
            close(fd);
            return 1;
        }
        close(fd);
        /* create_pid() must be called after drop_privileges()
         * or it won't be possible to remove the file on exit */
        /* create_pid() must be called after daemonize()
         * since the final pid is not known beforehand */
        if(create_pid())
            return 1;
#endif /* standard Unix */
        signal(SIGCHLD, signal_handler); /* handle dead children */
        signal(SIGHUP, signal_handler); /* configuration reload */
        signal(SIGUSR1, signal_handler); /* log reopen */
        signal(SIGPIPE, SIG_IGN); /* ignore broken pipe */
        if(signal(SIGTERM, SIG_IGN)!=SIG_IGN)
            signal(SIGTERM, signal_handler); /* fatal */
        if(signal(SIGQUIT, SIG_IGN)!=SIG_IGN)
            signal(SIGQUIT, signal_handler); /* fatal */
        if(signal(SIGINT, SIG_IGN)!=SIG_IGN)
            signal(SIGINT, signal_handler); /* fatal */
        daemon_loop();
    } else { /* inetd mode */
#if !defined(__vms) && !defined(USE_OS2)
        close(fd);
#endif /* standard Unix */
        signal(SIGCHLD, SIG_IGN); /* ignore dead children */
        signal(SIGPIPE, SIG_IGN); /* ignore broken pipe */
        client_main(alloc_client_session(&service_options, 0, 1));
    }
    return 0;
}
#endif

void main_initialize() { /* one-time initialization */
    /* basic initialization contains essential functions required for logging
     * subsystem to function properly, thus all errors here are fatal */
    if(ssl_init()) /* initialize SSL library */
        fatal("SSL initialization failed");
    if(sthreads_init()) /* initialize critical sections & SSL callbacks */
        fatal("Threads initialization failed");
#ifndef USE_FORK
    get_limits(); /* required by setup_fd() */
#endif
    fds=s_poll_alloc();
    if(signal_pipe_init())
        fatal("Signal pipe initialization failed: "
            "check your personal firewall");
    stunnel_info(LOG_NOTICE);
}

    /* configuration-dependent initialization */
int main_configure(char *arg1, char *arg2) {
    if(parse_commandline(arg1, arg2))
        return 1;
    str_canary_init(); /* needs prng initialization from parse_commandline */
#if !defined(USE_WIN32) && !defined(__vms)
    /* syslog_open() must be called before change_root()
     * to be able to access /dev/log socket */
    syslog_open();
#endif /* !defined(USE_WIN32) && !defined(__vms) */
    if(bind_ports())
        return 1;

#ifdef HAVE_CHROOT
    /* change_root() must be called before drop_privileges()
     * since chroot() needs root privileges */
    if(change_root())
        return 1;
#endif /* HAVE_CHROOT */

#if !defined(USE_WIN32) && !defined(__vms) && !defined(USE_OS2)
    if(drop_privileges(1))
        return 1;
#endif /* standard Unix */

    /* log_open() must be be called after drop_privileges()
     * or logfile rotation won't be possible */
    /* log_open() must be be called before daemonize()
     * since daemonize() invalidates stderr */
    if(log_open())
        return 1;
    return 0;
}

/**************************************** main loop accepting connections */

void daemon_loop(void) {
    SERVICE_OPTIONS *opt;
    int temporary_lack_of_resources;

    while(1) {
        temporary_lack_of_resources=0;
        if(s_poll_wait(fds, -1, -1)>=0) {
            if(s_poll_canread(fds, signal_pipe[0]))
                if(signal_pipe_dispatch()) /* received SIGNAL_TERMINATE */
                    break; /* terminate daemon_loop */
            for(opt=service_options.next; opt; opt=opt->next)
                if(opt->option.accept && s_poll_canread(fds, opt->fd))
                    if(accept_connection(opt))
                        temporary_lack_of_resources=1;
        } else {
            log_error(LOG_NOTICE, get_last_socket_error(),
                "daemon_loop: s_poll_wait");
            temporary_lack_of_resources=1;
        }
        if(temporary_lack_of_resources) {
            s_log(LOG_NOTICE,
                "Accepting new connections suspended for 1 second");
            sleep(1); /* to avoid log trashing */
        }
    }
}

    /* return 1 when a short delay is needed before another try */
static int accept_connection(SERVICE_OPTIONS *opt) {
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
            case S_EINTR: /* interrupted by a signal */
                break; /* retry now */
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
                return 1; /* temporary lack of resources */
            default:
                return 0; /* any other error */
        }
    }
    from_address=s_ntop(&addr, addrlen);
    s_log(LOG_DEBUG, "Service [%s] accepted (FD=%d) from %s",
        opt->servname, s, from_address);
    str_free(from_address);
#ifdef USE_FORK
    RAND_add("", 1, 0.0); /* each child needs a unique entropy pool */
#else
    if(max_clients && num_clients>=max_clients) {
        s_log(LOG_WARNING, "Connection rejected: too many clients (>=%d)",
            max_clients);
        closesocket(s);
        return 0;
    }
#endif
    if(create_client(opt->fd, s,
            alloc_client_session(opt, s, s), client_thread)) {
        s_log(LOG_ERR, "Connection rejected: create_client failed");
        closesocket(s);
        return 0;
    }
    return 0;
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

    for(opt=service_options.next; opt; opt=opt->next) {
        s_log(LOG_DEBUG, "Closing service [%s]", opt->servname);
        if(opt->option.accept && opt->fd>=0) {
            closesocket(opt->fd);
            s_log(LOG_DEBUG, "Service [%s] closed (FD=%d)",
                opt->servname, opt->fd);
            opt->fd=-1;
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
        } else if(opt->option.program && opt->option.remote) {
            /* create exec+connect services */
            /* FIXME: this is just a crude workaround */
            /*        is it better to kill the service? */
            opt->option.retry=0;
        }
        if(opt->ctx) {
            s_log(LOG_DEBUG, "Sessions cached before flush: %ld",
                SSL_CTX_sess_number(opt->ctx));
            SSL_CTX_flush_sessions(opt->ctx,
                (long)time(NULL)+opt->session_timeout+1);
            s_log(LOG_DEBUG, "Sessions cached after flush: %ld",
                SSL_CTX_sess_number(opt->ctx));
        }
        s_log(LOG_DEBUG, "Service [%s] closed", opt->servname);
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

    /* allow clean unbind_ports() even though
       bind_ports() was not fully performed */
    for(opt=service_options.next; opt; opt=opt->next)
        if(opt->option.accept)
            opt->fd=-1;

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
                s_log(LOG_ERR, "Error binding service [%s] to %s",
                    opt->servname, local_address);
                sockerror("bind");
                closesocket(opt->fd);
                str_free(local_address);
                return 1;
            }
            if(listen(opt->fd, SOMAXCONN)) {
                sockerror("listen");
                closesocket(opt->fd);
                str_free(local_address);
                return 1;
            }
            s_poll_add(fds, opt->fd, 1, 0);
            s_log(LOG_DEBUG, "Service [%s] (FD=%d) bound to %s",
                opt->servname, opt->fd, local_address);
            str_free(local_address);
        } else if(opt->option.program && opt->option.remote) {
            /* create exec+connect services */
            /* FIXME: needs to be delayed on reload with opt->option.retry set */
            create_client(-1, -1,
                alloc_client_session(opt, -1, -1), client_thread);
        }
    }
    return 0; /* OK */
}

#ifdef HAVE_CHROOT
static int change_root(void) {
    if(!global_options.chroot_dir)
        return 0;
    if(chroot(global_options.chroot_dir)) {
        sockerror("chroot");
        return 1;
    }
    if(chdir("/")) {
        sockerror("chdir");
        return 1;
    }
    return 0;
}
#endif /* HAVE_CHROOT */

#if !defined(USE_WIN32) && !defined(__vms) && !defined(USE_OS2)

int drop_privileges(int critical) {
#ifdef HAVE_SETGROUPS
    gid_t gr_list[1];
#endif

    /* set uid and gid */
    if(global_options.gid) {
        if(setgid(global_options.gid) && critical) {
            sockerror("setgid");
            return 1;
        }
#ifdef HAVE_SETGROUPS
        gr_list[0]=global_options.gid;
        if(setgroups(1, gr_list) && critical) {
            sockerror("setgroups");
            return 1;
        }
#endif
    }
    if(global_options.uid) {
        if(setuid(global_options.uid) && critical) {
            sockerror("setuid");
            return 1;
        }
    }
    return 0;
}

static int daemonize(int fd) { /* go to background */
    if(global_options.option.foreground)
        return 0;
    dup2(fd, 0);
    dup2(fd, 1);
    dup2(fd, 2);
#if defined(HAVE_DAEMON) && !defined(__BEOS__)
    /* set noclose option when calling daemon() function,
     * so it does not require /dev/null device in the chrooted directory */
    if(daemon(0, 1)==-1) {
        ioerror("daemon");
        return 1;
    }
#else
    chdir("/");
    switch(fork()) {
    case -1:    /* fork failed */
        ioerror("fork");
        return 1;
    case 0:     /* child */
        break;
    default:    /* parent */
        exit(0);
    }
#endif
#ifdef HAVE_SETSID
    setsid(); /* ignore the error */
#endif
    return 0;
}

static int create_pid(void) {
    int pf;
    char *pid;

    if(!global_options.pidfile) {
        s_log(LOG_DEBUG, "No pid file being created");
        return 0;
    }
    if(global_options.pidfile[0]!='/') {
        /* to prevent creating pid file relative to '/' after daemonize() */
        s_log(LOG_ERR, "Pid file (%s) must be full path name", global_options.pidfile);
        return 1;
    }
    global_options.dpid=(unsigned long)getpid();

    /* silently remove old pid file */
    unlink(global_options.pidfile);
    pf=open(global_options.pidfile, O_WRONLY|O_CREAT|O_TRUNC|O_EXCL, 0644);
    if(pf==-1) {
        s_log(LOG_ERR, "Cannot create pid file %s", global_options.pidfile);
        ioerror("create");
        return 1;
    }
    pid=str_printf("%lu\n", global_options.dpid);
    write(pf, pid, strlen(pid));
    str_free(pid);
    close(pf);
    s_log(LOG_DEBUG, "Created pid file %s", global_options.pidfile);
    atexit(delete_pid);
    return 0;
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

static int signal_pipe_init(void) {
#ifdef USE_WIN32
    if(make_sockets(signal_pipe))
        return 1;
#elif defined(__INNOTEK_LIBC__)
    /* Innotek port of GCC can not use select on a pipe:
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
        return 1;
    }
#else /* Unix */
    if(s_pipe(signal_pipe, 1, "signal_pipe"))
        return 1;
#endif /* USE_WIN32 */
    return 0;
}

void signal_post(int sig) {
    writesocket(signal_pipe[1], (char *)&sig, sizeof sig);
}

static int signal_pipe_dispatch(void) {
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
            return 2;
        default:
            s_log(LOG_ERR, "Received signal %d; terminating", sig);
            return 1;
        }
    }
    s_log(LOG_DEBUG, "Signal pipe is empty");
    return 0;
}

#ifdef USE_FORK
static void client_status(void) { /* dead children detected */
    int pid, status;

#ifdef HAVE_WAIT_FOR_PID
    while((pid=wait_for_pid(-1, &status, WNOHANG))>0) {
#else
    if((pid=wait(&status))>0) {
#endif
#ifdef WIFSIGNALED
        if(WIFSIGNALED(status)) {
            s_log(LOG_DEBUG, "Process %d terminated on signal %d",
                pid, WTERMSIG(status));
        } else {
            s_log(LOG_DEBUG, "Process %d finished with code %d",
                pid, WEXITSTATUS(status));
        }
    }
#else
        s_log(LOG_DEBUG, "Process %d finished with code %d",
            pid, status);
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

/**************************************** log build details */

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

        " Sockets:"
#ifdef USE_POLL
        "POLL"
#else /* defined(USE_POLL) */
        "SELECT"
#endif /* defined(USE_POLL) */
        ",IPv%c"

#if defined HAVE_OSSL_ENGINE_H || defined HAVE_OSSL_OCSP_H || defined USE_FIPS
        " SSL:"
#define ITEM_SEPARATOR ""
#ifdef HAVE_OSSL_ENGINE_H
        "ENGINE"
#undef ITEM_SEPARATOR
#define ITEM_SEPARATOR ","
#endif /* defined(HAVE_OSSL_ENGINE_H) */
#ifdef HAVE_OSSL_OCSP_H
        ITEM_SEPARATOR "OCSP"
#undef ITEM_SEPARATOR
#define ITEM_SEPARATOR ","
#endif /* HAVE_OSSL_OCSP_H */
#ifdef USE_FIPS
        ITEM_SEPARATOR "FIPS"
#endif /* USE_FIPS */
#endif /* an SSL optional feature enabled */

#ifdef USE_LIBWRAP
        " Auth:LIBWRAP"
#endif

        , /* supported IP version parameter */
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

/* end of stunnel.c */
