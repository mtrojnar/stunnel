/*
 *   stunnel       TLS offloading and load-balancing proxy
 *   Copyright (C) 1998-2016 Michal Trojnara <Michal.Trojnara@mirt.net>
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

#include <openssl/applink.c>

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

NOEXPORT int accept_connection(SERVICE_OPTIONS *);
#ifdef HAVE_CHROOT
NOEXPORT int change_root(void);
#endif
NOEXPORT int signal_pipe_init(void);
NOEXPORT int signal_pipe_dispatch(void);
#ifdef USE_FORK
NOEXPORT void client_status(void); /* dead children detected */
#endif
NOEXPORT char *signal_name(int);

/**************************************** global variables */

static SOCKET signal_pipe[2]={INVALID_SOCKET, INVALID_SOCKET};

#ifndef USE_FORK
long max_clients=0;
/* -1 before a valid config is loaded, then the current number of clients */
volatile long num_clients=-1;
#endif
s_poll_set *fds; /* file descriptors of listening sockets */
int systemd_fds; /* number of file descriptors passed by systemd */
int listen_fds_start; /* base for systemd-provided file descriptors */

/**************************************** startup */

void main_init() { /* one-time initialization */
#ifdef USE_SYSTEMD
    int i;

    systemd_fds=sd_listen_fds(1);
    if(systemd_fds<0)
        fatal("systemd initialization failed");
    listen_fds_start=SD_LISTEN_FDS_START;
    /* set non-blocking mode on systemd file descriptors */
    for(i=0; i<systemd_fds; ++i)
        set_nonblock(listen_fds_start+i, 1);
#else
    systemd_fds=0; /* no descriptors received */
    listen_fds_start=3; /* the value is not really important */
#endif
    /* basic initialization contains essential functions required for logging
     * subsystem to function properly, thus all errors here are fatal */
    if(ssl_init()) /* initialize SSL library */
        fatal("SSL initialization failed");
    if(sthreads_init()) /* initialize critical sections & SSL callbacks */
        fatal("Threads initialization failed");
    if(cron_init()) /* initialize periodic events */
        fatal("Cron initialization failed");
    options_defaults();
    options_apply();
#ifndef USE_FORK
    get_limits(); /* required by setup_fd() */
#endif
    fds=s_poll_alloc();
    if(signal_pipe_init())
        fatal("Signal pipe initialization failed: "
            "check your personal firewall");
    stunnel_info(LOG_NOTICE);
}

/* return values:
   0 - configuration accepted
   1 - error
   2 - information printed
*/

    /* configuration-dependent initialization */
int main_configure(char *arg1, char *arg2) {
    int cmdline_status;

    cmdline_status=options_cmdline(arg1, arg2);
    if(cmdline_status) /* cannot proceed */
        return cmdline_status;
    options_apply();
    str_canary_init(); /* needs prng initialization from options_cmdline */
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

    if(drop_privileges(1))
        return 1;

    /* log_open() must be be called after drop_privileges()
     * or logfile rotation won't be possible */
    /* log_open() must be be called before daemonize()
     * since daemonize() invalidates stderr */
    if(log_open())
        return 1;
#ifndef USE_FORK
    num_clients=0; /* the first valid config */
#endif
    return 0;
}

int drop_privileges(int critical) {
#if defined(USE_WIN32) || defined(__vms) || defined(USE_OS2)
    (void)critical; /* squash the unused parameter warning */
#else
#ifdef HAVE_SETGROUPS
    gid_t gr_list[1];
#endif

    /* set uid and gid */
    if(service_options.gid) {
        if(setgid(service_options.gid) && critical) {
            sockerror("setgid");
            return 1;
        }
#ifdef HAVE_SETGROUPS
        gr_list[0]=service_options.gid;
        if(setgroups(1, gr_list) && critical) {
            sockerror("setgroups");
            return 1;
        }
#endif
    }
    if(service_options.uid) {
        if(setuid(service_options.uid) && critical) {
            sockerror("setuid");
            return 1;
        }
    }
#endif /* standard Unix */
    return 0;
}

void main_cleanup() {
    unbind_ports();
    s_poll_free(fds);
    fds=NULL;
#if 0
    str_stats(); /* main thread allocation tracking */
#endif
    log_flush(LOG_MODE_ERROR);
}

/**************************************** Unix-specific initialization */

#ifndef USE_WIN32

#ifdef USE_FORK
NOEXPORT void client_status(void) { /* dead children detected */
    int pid, status;
    char *sig_name;

#ifdef HAVE_WAIT_FOR_PID
    while((pid=wait_for_pid(-1, &status, WNOHANG))>0) {
#else
    if((pid=wait(&status))>0) {
#endif
#ifdef WIFSIGNALED
        if(WIFSIGNALED(status)) {
            sig_name=signal_name(WTERMSIG(status));
            s_log(LOG_DEBUG, "Process %d terminated on %s",
                pid, sig_name);
            str_free(sig_name);
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

#ifndef USE_OS2

void child_status(void) { /* dead libwrap or 'exec' process detected */
    int pid, status;
    char *sig_name;

#ifdef HAVE_WAIT_FOR_PID
    while((pid=wait_for_pid(-1, &status, WNOHANG))>0) {
#else
    if((pid=wait(&status))>0) {
#endif
#ifdef WIFSIGNALED
        if(WIFSIGNALED(status)) {
            sig_name=signal_name(WTERMSIG(status));
            s_log(LOG_INFO, "Child process %d terminated on %s",
                pid, sig_name);
            str_free(sig_name);
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

#endif /* !defined(USE_OS2) */

#endif /* !defined(USE_WIN32) */

/**************************************** main loop accepting connections */

void daemon_loop(void) {
    while(1) {
        int temporary_lack_of_resources=0;
        int num=s_poll_wait(fds, -1, -1);
        if(num>=0) {
            SERVICE_OPTIONS *opt;
            s_log(LOG_DEBUG, "Found %d ready file descriptor(s)", num);
            if(service_options.log_level>=LOG_DEBUG) /* performance optimization */
                s_poll_dump(fds, LOG_DEBUG);
            if(s_poll_canread(fds, signal_pipe[0]))
                if(signal_pipe_dispatch()) /* SIGNAL_TERMINATE or error */
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
NOEXPORT int accept_connection(SERVICE_OPTIONS *opt) {
    SOCKADDR_UNION addr;
    char *from_address;
    SOCKET s;
    socklen_t addrlen;

    addrlen=sizeof addr;
    for(;;) {
        s=s_accept(opt->fd, &addr.sa, &addrlen, 1, "local socket");
        if(s!=INVALID_SOCKET) /* success! */
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
    s_log(LOG_DEBUG, "Service [%s] accepted (FD=%ld) from %s",
        opt->servname, (long)s, from_address);
    str_free(from_address);
#ifdef USE_FORK
    RAND_add("", 1, 0.0); /* each child needs a unique entropy pool */
#else
    if(max_clients && num_clients>=max_clients) {
        s_log(LOG_WARNING, "Connection rejected: too many clients (>=%ld)",
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
    struct stat sb; /* buffer for lstat() */
#endif

    s_poll_init(fds);
    s_poll_add(fds, signal_pipe[0], 1, 0);

    for(opt=service_options.next; opt; opt=opt->next) {
        s_log(LOG_DEBUG, "Closing service [%s]", opt->servname);
        if(opt->option.accept && opt->fd!=INVALID_SOCKET) {
            if(opt->fd<(SOCKET)listen_fds_start ||
                    opt->fd>=(SOCKET)(listen_fds_start+systemd_fds))
                closesocket(opt->fd);
            s_log(LOG_DEBUG, "Service [%s] closed (FD=%ld)",
                opt->servname, (long)opt->fd);
            opt->fd=INVALID_SOCKET;
#ifdef HAVE_STRUCT_SOCKADDR_UN
            if(opt->local_addr.sa.sa_family==AF_UNIX) {
                if(lstat(opt->local_addr.un.sun_path, &sb))
                    sockerror(opt->local_addr.un.sun_path);
                else if(!S_ISSOCK(sb.st_mode))
                    s_log(LOG_ERR, "Not a socket: %s",
                        opt->local_addr.un.sun_path);
                else if(unlink(opt->local_addr.un.sun_path))
                    sockerror(opt->local_addr.un.sun_path);
                else
                    s_log(LOG_DEBUG, "Socket removed: %s",
                        opt->local_addr.un.sun_path);
            }
#endif
        } else if(opt->exec_name && opt->connect_addr.names) {
            /* create exec+connect services             */
            /* FIXME: this is just a crude workaround   */
            /*        is it better to kill the service? */
            opt->option.retry=0;
        }
        /* purge session cache of the old SSL_CTX object */
        /* this workaround won't be needed anymore after */
        /* delayed deallocation calls SSL_CTX_free()     */
        if(opt->ctx)
            SSL_CTX_flush_sessions(opt->ctx,
                (long)time(NULL)+opt->session_timeout+1);
        s_log(LOG_DEBUG, "Service [%s] closed", opt->servname);
    }
}

/* open new ports, update fds */
int bind_ports(void) {
    SERVICE_OPTIONS *opt;
    char *local_address;
    int listening_section;
#ifdef HAVE_STRUCT_SOCKADDR_UN
    struct stat sb; /* buffer for lstat() */
#endif

#ifdef USE_LIBWRAP
    /* execute after options_cmdline() to know service_options.next,
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
            opt->fd=INVALID_SOCKET;

    listening_section=0;
    for(opt=service_options.next; opt; opt=opt->next) {
        if(opt->option.accept) {
            if(listening_section<systemd_fds) {
                opt->fd=(SOCKET)(listen_fds_start+listening_section);
                s_log(LOG_DEBUG,
                    "Listening file descriptor received from systemd (FD=%ld)",
                    (long)opt->fd);
            } else {
                opt->fd=s_socket(opt->local_addr.sa.sa_family,
                    SOCK_STREAM, 0, 1, "accept socket");
                if(opt->fd==INVALID_SOCKET)
                    return 1;
                s_log(LOG_DEBUG, "Listening file descriptor created (FD=%ld)",
                    (long)opt->fd);
            }
            if(set_socket_options(opt->fd, 0)<0) {
                closesocket(opt->fd);
                opt->fd=INVALID_SOCKET;
                return 1;
            }
            /* local socket can't be unnamed */
            local_address=s_ntop(&opt->local_addr, addr_len(&opt->local_addr));
            /* we don't bind or listen on a socket inherited from systemd */
            if(listening_section>=systemd_fds) {
                if(bind(opt->fd, &opt->local_addr.sa, addr_len(&opt->local_addr))) {
                    sockerror("bind");
                    s_log(LOG_ERR, "Error binding service [%s] to %s",
                        opt->servname, local_address);
                    closesocket(opt->fd);
                    opt->fd=INVALID_SOCKET;
                    str_free(local_address);
                    return 1;
                }
                if(listen(opt->fd, SOMAXCONN)) {
                    sockerror("listen");
                    closesocket(opt->fd);
                    opt->fd=INVALID_SOCKET;
                    str_free(local_address);
                    return 1;
                }
            }
#ifdef HAVE_STRUCT_SOCKADDR_UN
            /* chown the UNIX socket, errors are ignored */
            if(opt->local_addr.sa.sa_family==AF_UNIX &&
                    (opt->uid || opt->gid)) {
                /* fchown() does *not* work on UNIX sockets */
                if(!lchown(opt->local_addr.un.sun_path, opt->uid, opt->gid))
                    s_log(LOG_DEBUG,
                        "Socket chown succeeded: %s, UID=%u, GID=%u",
                        opt->local_addr.un.sun_path,
                        (unsigned)opt->uid, (unsigned)opt->gid);
                else if(lstat(opt->local_addr.un.sun_path, &sb))
                    sockerror(opt->local_addr.un.sun_path);
                else if(sb.st_uid==opt->uid && sb.st_gid==opt->gid)
                    s_log(LOG_DEBUG,
                        "Socket chown unneeded: %s, UID=%u, GID=%u",
                        opt->local_addr.un.sun_path,
                        (unsigned)opt->uid, (unsigned)opt->gid);
                else
                    s_log(LOG_ERR, "Socket chown failed: %s, UID=%u, GID=%u",
                        opt->local_addr.un.sun_path,
                        (unsigned)opt->uid, (unsigned)opt->gid);
            }
#endif
            s_poll_add(fds, opt->fd, 1, 0);
            s_log(LOG_DEBUG, "Service [%s] (FD=%ld) bound to %s",
                opt->servname, (long)opt->fd, local_address);
            str_free(local_address);
            ++listening_section;
        } else if(opt->exec_name && opt->connect_addr.names) {
            /* create exec+connect services */
            /* FIXME: needs to be delayed on reload with opt->option.retry set */
            create_client(INVALID_SOCKET, INVALID_SOCKET,
                alloc_client_session(opt, INVALID_SOCKET, INVALID_SOCKET),
                client_thread);
        }
    }
    if(listening_section<systemd_fds) {
        s_log(LOG_ERR,
            "Too many listening file descriptors received from systemd, got %d",
            systemd_fds);
        return 1;
    }
    return 0; /* OK */
}

#ifdef HAVE_CHROOT
NOEXPORT int change_root(void) {
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

/**************************************** signal pipe handling */

NOEXPORT int signal_pipe_init(void) {
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

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
#endif /* __GNUC__ */
void signal_post(int sig) {
    /* no meaningful way here to handle the result */
    writesocket(signal_pipe[1], (char *)&sig, sizeof sig);
}
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif /* __GNUC__ */

NOEXPORT int signal_pipe_dispatch(void) {
    static int sig;
    static size_t ptr=0;
    ssize_t num;
    char *sig_name;

    s_log(LOG_DEBUG, "Dispatching signals from the signal pipe");
    for(;;) {
        num=readsocket(signal_pipe[0], (char *)&sig+ptr, sizeof sig-ptr);
        if(num==-1 && get_last_socket_error()==S_EWOULDBLOCK) {
            s_log(LOG_DEBUG, "Signal pipe is empty");
            return 0;
        }
        if(num==-1 || num==0) {
            if(num)
                sockerror("signal pipe read");
            else
                s_log(LOG_ERR, "Signal pipe closed");
            s_poll_remove(fds, signal_pipe[0]);
            closesocket(signal_pipe[0]);
            closesocket(signal_pipe[1]);
            if(signal_pipe_init()) {
                s_log(LOG_ERR,
                    "Signal pipe reinitialization failed; terminating");
                return 1;
            }
            s_poll_add(fds, signal_pipe[0], 1, 0);
            s_log(LOG_ERR, "Signal pipe reinitialized");
            return 0;
        }
        ptr+=(size_t)num;
        if(ptr<sizeof sig) {
            s_log(LOG_DEBUG, "Incomplete signal pipe read (ptr=%ld)",
                (long)ptr);
            return 0;
        }
        ptr=0;
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
            if(options_parse(CONF_RELOAD)) {
                s_log(LOG_ERR, "Failed to reload the configuration file");
            } else {
                unbind_ports();
                log_close();
                options_apply();
                log_open();
                ui_config_reloaded();
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
            return 1;
        default:
            sig_name=signal_name(sig);
            s_log(LOG_ERR, "Received %s; terminating", sig_name);
            str_free(sig_name);
            return 1;
        }
    }
}

/**************************************** signal name decoding */

#define check_signal(s) if(signum==s) return str_dup(#s);

NOEXPORT char *signal_name(int signum) {
#ifdef SIGHUP
    check_signal(SIGHUP)
#endif
#ifdef SIGINT
    check_signal(SIGINT)
#endif
#ifdef SIGQUIT
    check_signal(SIGQUIT)
#endif
#ifdef SIGILL
    check_signal(SIGILL)
#endif
#ifdef SIGTRAP
    check_signal(SIGTRAP)
#endif
#ifdef SIGABRT
    check_signal(SIGABRT)
#endif
#ifdef SIGIOT
    check_signal(SIGIOT)
#endif
#ifdef SIGBUS
    check_signal(SIGBUS)
#endif
#ifdef SIGFPE
    check_signal(SIGFPE)
#endif
#ifdef SIGKILL
    check_signal(SIGKILL)
#endif
#ifdef SIGUSR1
    check_signal(SIGUSR1)
#endif
#ifdef SIGSEGV
    check_signal(SIGSEGV)
#endif
#ifdef SIGUSR2
    check_signal(SIGUSR2)
#endif
#ifdef SIGPIPE
    check_signal(SIGPIPE)
#endif
#ifdef SIGALRM
    check_signal(SIGALRM)
#endif
#ifdef SIGTERM
    check_signal(SIGTERM)
#endif
#ifdef SIGSTKFLT
    check_signal(SIGSTKFLT)
#endif
#ifdef SIGCHLD
    check_signal(SIGCHLD)
#endif
#ifdef SIGCONT
    check_signal(SIGCONT)
#endif
#ifdef SIGSTOP
    check_signal(SIGSTOP)
#endif
#ifdef SIGTSTP
    check_signal(SIGTSTP)
#endif
#ifdef SIGTTIN
    check_signal(SIGTTIN)
#endif
#ifdef SIGTTOU
    check_signal(SIGTTOU)
#endif
#ifdef SIGURG
    check_signal(SIGURG)
#endif
#ifdef SIGXCPU
    check_signal(SIGXCPU)
#endif
#ifdef SIGXFSZ
    check_signal(SIGXFSZ)
#endif
#ifdef SIGVTALRM
    check_signal(SIGVTALRM)
#endif
#ifdef SIGPROF
    check_signal(SIGPROF)
#endif
#ifdef SIGWINCH
    check_signal(SIGWINCH)
#endif
#ifdef SIGIO
    check_signal(SIGIO)
#endif
#ifdef SIGPOLL
    check_signal(SIGPOLL)
#endif
#ifdef SIGLOST
    check_signal(SIGLOST)
#endif
#ifdef SIGPWR
    check_signal(SIGPWR)
#endif
#ifdef SIGSYS
    check_signal(SIGSYS)
#endif
#ifdef SIGUNUSED
    check_signal(SIGUNUSED)
#endif
    return str_printf("signal %d", signum);
}

/**************************************** log build details */

void stunnel_info(int level) {
    s_log(level, "stunnel " STUNNEL_VERSION " on " HOST " platform");
    if(strcmp(OPENSSL_VERSION_TEXT, OpenSSL_version(OPENSSL_VERSION))) {
        s_log(level, "Compiled with " OPENSSL_VERSION_TEXT);
        s_log(level, "Running  with %s", OpenSSL_version(OPENSSL_VERSION));
        s_log(level, "Update OpenSSL shared libraries or rebuild stunnel");
    } else {
        s_log(level, "Compiled/running with " OPENSSL_VERSION_TEXT);
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
#ifdef USE_SYSTEMD
        ",SYSTEMD"
#endif /* defined(USE_SYSTEMD) */

        " TLS:"
#ifndef OPENSSL_NO_ENGINE
#define TLS_FEATURE_FOUND
        "ENGINE"
#endif /* !defined(OPENSSL_NO_ENGINE) */
#ifdef USE_FIPS
#ifdef TLS_FEATURE_FOUND
        ","
#else
#define TLS_FEATURE_FOUND
#endif
        "FIPS"
#endif /* defined(USE_FIPS) */
#ifndef OPENSSL_NO_OCSP
#ifdef TLS_FEATURE_FOUND
        ","
#else
#define TLS_FEATURE_FOUND
#endif
        "OCSP"
#endif /* !defined(OPENSSL_NO_OCSP) */
#ifndef OPENSSL_NO_PSK
#ifdef TLS_FEATURE_FOUND
        ","
#else
#define TLS_FEATURE_FOUND
#endif
        "PSK"
#endif /* !defined(OPENSSL_NO_PSK) */
#ifndef OPENSSL_NO_TLSEXT
#ifdef TLS_FEATURE_FOUND
        ","
#else
#define TLS_FEATURE_FOUND
#endif
        "SNI"
#endif /* !defined(OPENSSL_NO_TLSEXT) */
#ifndef TLS_FEATURE_FOUND
        "NONE"
#endif /* !defined(TLS_FEATURE_FOUND) */

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
#ifdef errno
#define xstr(a) str(a)
#define str(a) #a
    s_log(LOG_DEBUG, "errno: " xstr(errno));
#endif /* errno */
}

/* end of stunnel.c */
