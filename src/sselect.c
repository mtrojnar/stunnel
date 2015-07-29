/*
 *   stunnel       Universal SSL tunnel
 *   Copyright (c) 1998-2004 Michal Trojnara <Michal.Trojnara@mirt.net>
 *                 All Rights Reserved
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
 *
 *   In addition, as a special exception, Michal Trojnara gives
 *   permission to link the code of this program with the OpenSSL
 *   library (or with modified versions of OpenSSL that use the same
 *   license as OpenSSL), and distribute linked combinations including
 *   the two.  You must obey the GNU General Public License in all
 *   respects for all of the code used other than OpenSSL.  If you modify
 *   this file, you may extend this exception to your version of the
 *   file, but you are not obligated to do so.  If you do not wish to
 *   do so, delete this exception statement from your version.
 */

#include "common.h"
#include "prototypes.h"

#ifdef USE_FORK
static void client_status(void); /* dead children detected */
#endif
 
#ifndef USE_WIN32

static int signal_pipe[2];
static char signal_buffer[16];

#ifndef USE_WIN32

static void sigchld_handler(int sig) { /* SIGCHLD detected */
    int save_errno=errno;

    write(signal_pipe[1], signal_buffer, 1);
    signal(SIGCHLD, sigchld_handler);
    errno=save_errno;
}

#endif

void sselect_init(fd_set *set, int *n) {
    if(pipe(signal_pipe)) {
        ioerror("pipe");
        exit(1);
    }
    alloc_fd(signal_pipe[0]);
    alloc_fd(signal_pipe[1]);
#ifdef FD_CLOEXEC
    /* close the pipe in child execvp */
    fcntl(signal_pipe[0], F_SETFD, FD_CLOEXEC);
    fcntl(signal_pipe[1], F_SETFD, FD_CLOEXEC);
#endif
    FD_SET(signal_pipe[0], set);
    if(signal_pipe[0]>*n)
        *n=signal_pipe[0];
    signal(SIGCHLD, sigchld_handler);
}

#endif /* USE_WIN32 */

int sselect(int n, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
        struct timeval *timeout) {
    int retval;
    struct timeval tv;

    do { /* Skip "Interrupted system call" errors */
        if(timeout) {
            memcpy(&tv, timeout, sizeof(struct timeval));
            retval=select(n, readfds, writefds, exceptfds, &tv);
        } else { /* No timeout - main loop */
            retval=select(n, readfds, writefds, exceptfds, NULL);
#ifndef USE_WIN32
            if(retval>0 && FD_ISSET(signal_pipe[0], readfds)) {
                /* Empty the pipe */
                read(signal_pipe[0], signal_buffer, sizeof(signal_buffer));
#ifdef USE_PTHREAD
                exec_status(); /* Report status of 'exec' process */
#endif /* USE_PTHREAD */
#ifdef USE_FORK
                client_status(); /* Report status of client process */
#endif /* USE_FORK */
            }
#endif /* USE_WIN32 */
        }
    } while(retval<0 && get_last_socket_error()==EINTR);
    return retval;
}

int waitforsocket(int fd, int dir, int timeout) {
    /* dir: 0 for read, 1 for write */
    struct timeval tv;
    fd_set set;
    int ready;

    log(LOG_DEBUG, "waitforsocket: FD=%d, DIR=%s", fd, dir ? "write" : "read");
    FD_ZERO(&set);
    FD_SET(fd, &set);
    tv.tv_sec=timeout;
    tv.tv_usec=0;
    ready=sselect(fd+1, dir ? NULL : &set, dir ? &set : NULL, NULL, &tv);
    switch(ready) {
    case -1:
        sockerror("waitforsocket");
        break;
    case 0:
        log(LOG_DEBUG, "waitforsocket: timeout");
        break;
    case 1:
        log(LOG_DEBUG, "waitforsocket: ok");
        break;
    default:
        log(LOG_INFO, "waitforsocket: unexpected result");
    }
    return ready;
}

#ifdef USE_FORK
static void client_status(void) { /* dead children detected */
    int pid, status;

#ifdef HAVE_WAIT_FOR_PID
    while((pid=wait_for_pid(-1, &status, WNOHANG))>0) {
        num_clients--; /* one client less */
#else
    if((pid=wait(&status))>0) {
        num_clients--; /* one client less */
#endif
#ifdef WIFSIGNALED
        if(WIFSIGNALED(status)) {
            log(LOG_DEBUG, "Process %d terminated on signal %d (%d left)",
                pid, WTERMSIG(status), num_clients);
        } else {
            log(LOG_DEBUG, "Process %d finished with code %d (%d left)",
                pid, WEXITSTATUS(status), num_clients);
        }
    }
#else
        log(LOG_DEBUG, "Process %d finished with code %d (%d left)",
            pid, status, num_clients);
    }
#endif
}
#endif

#ifndef USE_WIN32
void exec_status(void) { /* dead local ('exec') process detected */
    int pid, status;

#ifdef HAVE_WAIT_FOR_PID
    while((pid=wait_for_pid(-1, &status, WNOHANG))>0) {
#else
    if((pid=wait(&status))>0) {
#endif
#ifdef WIFSIGNALED
        if(WIFSIGNALED(status)) {
            log(LOG_INFO, "Local process %d terminated on signal %d",
                pid, WTERMSIG(status));
        } else {
            log(LOG_INFO, "Local process %d finished with code %d",
                pid, WEXITSTATUS(status));
        }
#else
        log(LOG_INFO, "Local process %d finished with status %d",
            pid, status);
#endif
    }
}
#endif /* !defined USE_WIN32 */

int write_blocking(CLI *c, int fd, u8 *ptr, int len) {
        /* simulate a blocking write */
        /* returns 0 on success, -1 on failure */
    int num;

    while(len>0) {
        if(waitforsocket(fd, 1 /* write */, c->opt->timeout_busy)<1)
            return -1;
        num=writesocket(fd, ptr, len);
        switch(num) {
        case -1: /* error */
            sockerror("writesocket (write_blocking)");
            return -1;
        }
        ptr+=num;
        len-=num;
    }
    return 0; /* OK */
}

int read_blocking(CLI *c, int fd, u8 *ptr, int len) {
        /* simulate a blocking read */
        /* returns 0 on success, -1 on failure */
    int num;

    while(len>0) {
        if(waitforsocket(fd, 0 /* read */, c->opt->timeout_busy)<1)
            return -1;
        num=readsocket(fd, ptr, len);
        switch(num) {
        case -1: /* error */
            sockerror("readsocket (read_blocking)");
            return -1;
        case 0: /* EOF */
            log(LOG_ERR, "Unexpected socket close (read_blocking)");
            return -1;
        }
        ptr+=num;
        len-=num;
    }
    return 0; /* OK */
}

int fdprintf(CLI *c, int fd, const char *format, ...) {
    va_list arglist;
    char line[STRLEN], logline[STRLEN];
    char crlf[]="\r\n";
    int len;

    va_start(arglist, format);
#ifdef HAVE_VSNPRINTF
    len=vsnprintf(line, STRLEN, format, arglist);
#else
    len=vsprintf(line, format, arglist);
#endif
    va_end(arglist);
    len+=2;
    if(len>=STRLEN) {
        log(LOG_ERR, "Line too long in fdprintf");
        return -1;
    }
    safecopy(logline, line); /* The line without crlf */
    safeconcat(line, crlf);
    if(write_blocking(c, fd, line, len)<0)
        return -1;
    safestring(logline);
    log(LOG_DEBUG, " -> %s", logline);
    return len;
}

int fdscanf(CLI *c, int fd, const char *format, char *buffer) {
    char line[STRLEN], logline[STRLEN], lformat[STRLEN];
    int ptr, retval;

    for(ptr=0; ptr<STRLEN-1; ptr++) {
        if(waitforsocket(fd, 0 /* read */, c->opt->timeout_busy)<1)
            return -1;
        switch(readsocket(fd, line+ptr, 1)) {
        case -1: /* error */
            sockerror("readsocket (fdscanf)");
            return -1;
        case 0: /* EOF */
            log(LOG_ERR, "Unexpected socket close (fdscanf)");
            return -1;
        }
        if(line[ptr]=='\r')
            continue;
        if(line[ptr]=='\n')
            break;
    }
    line[ptr]='\0';
    safecopy(logline, line);
    safestring(logline);
    log(LOG_DEBUG, " <- %s", logline);
    retval=sscanf(line, format, buffer);
    if(retval>=0)
        return retval;
    log(LOG_DEBUG, "fdscanf falling back to lowercase");
    safecopy(lformat, format);
    for(ptr=0; lformat[ptr]; ptr++)
        lformat[ptr]=tolower(lformat[ptr]);
    for(ptr=0; line[ptr]; ptr++)
        line[ptr]=tolower(line[ptr]);
    return sscanf(line, lformat, buffer);
}

/* End of select.c */
