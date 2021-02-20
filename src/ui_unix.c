/*
 *   stunnel       TLS offloading and load-balancing proxy
 *   Copyright (C) 1998-2021 Michal Trojnara <Michal.Trojnara@stunnel.org>
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

NOEXPORT int main_unix(int, char*[]);
#if !defined(__vms) && !defined(USE_OS2)
NOEXPORT int daemonize(int);
NOEXPORT int create_pid(void);
NOEXPORT void delete_pid(void);
#endif
#ifndef USE_OS2
NOEXPORT void signal_handler(int);
#endif

int main(int argc, char* argv[]) { /* execution begins here 8-) */
    int retval;

#ifdef M_MMAP_THRESHOLD
    mallopt(M_MMAP_THRESHOLD, 4096);
#endif
    tls_init(); /* initialize thread-local storage */
    retval=main_unix(argc, argv);
    main_cleanup();
    return retval;
}

NOEXPORT int main_unix(int argc, char* argv[]) {
    int configure_status;

#if !defined(__vms) && !defined(USE_OS2)
    int fd;

    fd=open("/dev/null", O_RDWR); /* open /dev/null before chroot */
    if(fd==INVALID_SOCKET)
        fatal("Could not open /dev/null");
#endif
    main_init();
    configure_status=main_configure(argc>1 ? argv[1] : NULL,
        argc>2 ? argv[2] : NULL);
    switch(configure_status) {
    case 1: /* error -> exit with 1 to indicate error */
        close(fd);
        return 1;
    case 2: /* information printed -> exit with 0 to indicate success */
        close(fd);
        return 0;
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
#endif
#ifndef USE_OS2
        signal(SIGCHLD, signal_handler); /* handle dead children */
        signal(SIGHUP, signal_handler); /* configuration reload */
        signal(SIGUSR1, signal_handler); /* log reopen */
        signal(SIGUSR2, signal_handler); /* connections */
        signal(SIGPIPE, SIG_IGN); /* ignore broken pipe */
        if(signal(SIGTERM, SIG_IGN)!=SIG_IGN)
            signal(SIGTERM, signal_handler); /* fatal */
        if(signal(SIGQUIT, SIG_IGN)!=SIG_IGN)
            signal(SIGQUIT, signal_handler); /* fatal */
        if(signal(SIGINT, SIG_IGN)!=SIG_IGN)
            signal(SIGINT, signal_handler); /* fatal */
#endif
#ifdef USE_FORK
        setpgid(0, 0); /* create a new process group if needed */
#endif
        daemon_loop();
#ifdef USE_FORK
        s_log(LOG_NOTICE, "Terminating service processes");
        signal(SIGCHLD, SIG_IGN);
        signal(SIGTERM, SIG_IGN);
        kill(0, SIGTERM); /* kill the whole process group */
        while(wait(NULL)!=-1)
            ;
        s_log(LOG_NOTICE, "Service processes terminated");
#endif
#if !defined(__vms) && !defined(USE_OS2)
        delete_pid();
#endif /* standard Unix */
    } else { /* inetd mode */
        CLI *c;
#if !defined(__vms) && !defined(USE_OS2)
        close(fd);
#endif /* standard Unix */
#ifndef USE_OS2
        signal(SIGCHLD, SIG_IGN); /* ignore dead children */
        signal(SIGPIPE, SIG_IGN); /* ignore broken pipe */
#endif
        set_nonblock(0, 1); /* stdin */
        set_nonblock(1, 1); /* stdout */
        c=alloc_client_session(&service_options, 0, 1);
        tls_alloc(c, ui_tls, NULL);
        service_up_ref(&service_options);
        client_main(c);
        client_free(c);
    }
    return 0;
}

#ifndef USE_OS2
NOEXPORT void signal_handler(int sig) {
    int saved_errno;

    saved_errno=errno;
    signal_post((uint8_t)sig);
    signal(sig, signal_handler);
    errno=saved_errno;
}
#endif

#if !defined(__vms) && !defined(USE_OS2)

NOEXPORT int daemonize(int fd) { /* go to background */
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
    tls_alloc(NULL, ui_tls, "main"); /* reuse thread-local storage */
#ifdef HAVE_SETSID
    setsid(); /* ignore the error */
#endif
    return 0;
}

NOEXPORT int create_pid(void) {
    int pf;
    char *pid;

    if(!global_options.pidfile) {
        s_log(LOG_DEBUG, "No pid file being created");
        return 0;
    }

    /* silently remove the old pid file */
    unlink(global_options.pidfile);

    /* create a new pid file */
    pf=open(global_options.pidfile, O_WRONLY|O_CREAT|O_TRUNC|O_EXCL, 0644);
    if(pf==-1) {
        s_log(LOG_ERR, "Cannot create pid file %s", global_options.pidfile);
        ioerror("create");
        return 1;
    }
    pid=str_printf("%lu\n", (unsigned long)getpid());
    if(write(pf, pid, strlen(pid))<(int)strlen(pid)) {
        s_log(LOG_ERR, "Cannot write pid file %s", global_options.pidfile);
        ioerror("write");
        return 1;
    }
    str_free(pid);
    close(pf);
    s_log(LOG_DEBUG, "Created pid file %s", global_options.pidfile);
    return 0;
}

NOEXPORT void delete_pid(void) {
    if(global_options.pidfile) {
        if(unlink(global_options.pidfile)<0)
            ioerror(global_options.pidfile); /* not critical */
        else
            s_log(LOG_DEBUG, "Removed pid file %s", global_options.pidfile);
    } else {
        s_log(LOG_DEBUG, "No pid file to remove");
    }
}

#endif /* standard Unix */

/**************************************** options callbacks */

void ui_config_reloaded(void) {
    /* no action */
}

#ifdef ICON_IMAGE

ICON_IMAGE load_icon_default(ICON_TYPE icon) {
    (void)icon; /* squash the unused parameter warning */
    return (ICON_IMAGE)0;
}

ICON_IMAGE load_icon_file(const char *file) {
    (void)file; /* squash the unused parameter warning */
    return (ICON_IMAGE)0;
}

#endif

/**************************************** client callbacks */

void ui_new_chain(const unsigned section_number) {
    (void)section_number; /* squash the unused parameter warning */
}

void ui_clients(const long num) {
    (void)num; /* squash the unused parameter warning */
}

/**************************************** s_log callbacks */

void ui_new_log(const char *line) {
    fprintf(stderr, "%s\n", line);
}

/**************************************** ctx callbacks */

int ui_passwd_cb(char *buf, int size, int rwflag, void *userdata) {
    return PEM_def_callback(buf, size, rwflag, userdata);
}

#ifndef OPENSSL_NO_ENGINE

int (*ui_get_opener()) (UI *) {
    return UI_method_get_opener(UI_OpenSSL());
}

int (*ui_get_writer()) (UI *, UI_STRING *) {
    return UI_method_get_writer(UI_OpenSSL());
}

int (*ui_get_reader()) (UI *, UI_STRING *) {
    return UI_method_get_reader(UI_OpenSSL());
}

int (*ui_get_closer()) (UI *) {
    return UI_method_get_closer(UI_OpenSSL());
}

#endif

/* end of ui_unix.c */
