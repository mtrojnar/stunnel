/*
 *   stunnel       Universal SSL tunnel
 *   Copyright (C) 1998-2015 Michal Trojnara <Michal.Trojnara@mirt.net>
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
#if !defined(__vms) && !defined(USE_OS2)
    int fd;

    fd=open("/dev/null", O_RDWR); /* open /dev/null before chroot */
    if(fd<0)
        fatal("Could not open /dev/null");
#endif
    main_init();
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
#endif
#ifndef USE_OS2
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
#endif
        daemon_loop();
    } else { /* inetd mode */
#if !defined(__vms) && !defined(USE_OS2)
        close(fd);
#endif /* standard Unix */
#ifndef USE_OS2
        signal(SIGCHLD, SIG_IGN); /* ignore dead children */
        signal(SIGPIPE, SIG_IGN); /* ignore broken pipe */
#endif
        set_nonblock(0, 1); /* stdin */
        set_nonblock(1, 1); /* stdout */
        client_main(alloc_client_session(&service_options, 0, 1));
    }
    return 0;
}

#ifndef USE_OS2
NOEXPORT void signal_handler(int sig) {
    int saved_errno;

    saved_errno=errno;
    signal_post(sig);
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
    if(write(pf, pid, strlen(pid))<(int)strlen(pid)) {
        s_log(LOG_ERR, "Cannot write pid file %s", global_options.pidfile);
        ioerror("write");
        return 1;
    }
    str_free(pid);
    close(pf);
    s_log(LOG_DEBUG, "Created pid file %s", global_options.pidfile);
    atexit(delete_pid);
    return 0;
}

NOEXPORT void delete_pid(void) {
    if((unsigned long)getpid()!=global_options.dpid)
        return; /* current process is not main daemon process */
    s_log(LOG_DEBUG, "removing pid file %s", global_options.pidfile);
    if(unlink(global_options.pidfile)<0)
        ioerror(global_options.pidfile); /* not critical */
}

#endif /* standard Unix */

/**************************************** options callbacks */

void ui_config_reloaded(void) {
    /* no action */
}

#ifdef ICON_IMAGE

ICON_IMAGE load_icon_default(ICON_TYPE icon) {
    (void)icon; /* skip warning about unused parameter */
    return (ICON_IMAGE)0;
}

ICON_IMAGE load_icon_file(const char *file) {
    (void)file; /* skip warning about unused parameter */
    return (ICON_IMAGE)0;
}

#endif

/**************************************** client callbacks */

void ui_new_chain(const int section_number) {
    (void)section_number; /* skip warning about unused parameter */
}

void ui_clients(const long num) {
    (void)num; /* skip warning about unused parameter */
}

/**************************************** s_log callbacks */

void ui_new_log(const char *line) {
    fprintf(stderr, "%s\n", line);
}

/**************************************** ctx callbacks */

int passwd_cb(char *buf, int size, int rwflag, void *userdata) {
    (void)buf; /* skip warning about unused parameter */
    (void)size; /* skip warning about unused parameter */
    (void)rwflag; /* skip warning about unused parameter */
    (void)userdata; /* skip warning about unused parameter */
    return 0; /* not implemented */
}

#ifndef OPENSSL_NO_ENGINE
int pin_cb(UI *ui, UI_STRING *uis) {
    (void)ui; /* skip warning about unused parameter */
    (void)uis; /* skip warning about unused parameter */
    return 0; /* not implemented */
}
#endif

/* end of ui_unix.c */
