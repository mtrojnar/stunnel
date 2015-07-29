/*
 *   stunnel       Universal SSL tunnel
 *   Copyright (c) 1998-2005 Michal Trojnara <Michal.Trojnara@mirt.net>
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

static FILE *outfile=NULL; /* Logging to file disabled by default */

#if defined (USE_WIN32) || defined (__vms)

/* HANDLE evt=NULL; */

void log_open(void) { /* Win32 version */
#if 0
    AllocConsole();
    /* reopen stdin handle as console window input */
    freopen("CONIN$", "rb", stdin);
    /* reopen stout handle as console window output */
    freopen("CONOUT$", "wb", stdout);
    /* reopen stderr handle as console window output */
    freopen("CONOUT$", "wb", stderr);
    printf("Close this window to exit stunnel\n\n");
#endif
    if(options.output_file)
        outfile=fopen(options.output_file, "a");
    if(outfile)
        return; /* It was possible to open a log file */
    /* TODO: Register NT EventLog source here */
    /* evt=RegisterEventSource(NULL, "stunnel"); */
    if(options.output_file)
        s_log(LOG_ERR, "Unable to open output file: %s", options.output_file);
}

void log_close(void) {
    if(outfile)
        fclose(outfile);
#if 0
    else
        FreeConsole();
#endif
}

#else /* USE_WIN32, __vms */

void log_open(void) { /* Unix version */
    int fd;

    if(options.output_file) { /* 'output' option specified */
        fd=open(options.output_file, O_CREAT|O_WRONLY|O_APPEND, 0640);
        if(fd>=0) { /* file opened or created */
            fcntl(fd, F_SETFD, FD_CLOEXEC);
            outfile=fdopen(fd, "a");
            if(outfile)
                return; /* no need to setup syslog */
        }
    }
    if(options.option.syslog) {
#ifdef __ultrix__
        openlog("stunnel", LOG_PID);
#else
        openlog("stunnel", LOG_CONS | LOG_NDELAY | LOG_PID, options.facility);
#endif /* __ultrix__ */
    }
    if(options.output_file)
        s_log(LOG_ERR, "Unable to open output file: %s", options.output_file);
}

void log_close(void) {
    if(outfile) {
        fclose(outfile);
        return;
    }
    if(options.option.syslog)
        closelog();
}

#endif /* USE_WIN32, __vms */

void s_log(int level, const char *format, ...) {
    va_list arglist;
    char text[STRLEN], timestamped[STRLEN];
    FILE *out;
    time_t gmt;
    struct tm *timeptr;
#if defined(HAVE_LOCALTIME_R) && defined(_REENTRANT)
    struct tm timestruct;
#endif

    if(level>options.debug_level)
        return;
    va_start(arglist, format);
#ifdef HAVE_VSNPRINTF
    vsnprintf(text, STRLEN, format, arglist);
#else
    vsprintf(text, format, arglist);
#endif
    va_end(arglist);
#if !defined (USE_WIN32) && !defined (__vms)
    if(!outfile && options.option.syslog) {
        syslog(level, "%s", text);
        return;
    }
#endif /* USE_WIN32, __vms */
    out=outfile?outfile:stderr;
    time(&gmt);
#if defined(HAVE_LOCALTIME_R) && defined(_REENTRANT)
    timeptr=localtime_r(&gmt, &timestruct);
#else
    timeptr=localtime(&gmt);
#endif
#ifdef HAVE_SNPRINTF
    snprintf(timestamped, STRLEN,
#else
    sprintf(timestamped,
#endif
        "%04d.%02d.%02d %02d:%02d:%02d LOG%d[%lu:%lu]: %s",
        timeptr->tm_year+1900, timeptr->tm_mon+1, timeptr->tm_mday,
        timeptr->tm_hour, timeptr->tm_min, timeptr->tm_sec,
        level, stunnel_process_id(), stunnel_thread_id(), text);
#ifdef USE_WIN32
    win_log(timestamped); /* Always log to the GUI window */
    if(outfile) /* to the file - only if it exists */
#endif
    {
        fprintf(out, "%s\n", timestamped);
        fflush(out);
    }
}

void log_raw(const char *format, ...) {
    va_list arglist;
    char text[STRLEN];
    FILE *out;

    va_start(arglist, format);
#ifdef HAVE_VSNPRINTF
    vsnprintf(text, STRLEN, format, arglist);
#else
    vsprintf(text, format, arglist);
#endif
    va_end(arglist);
    out=outfile?outfile:stderr;
#ifdef USE_WIN32
    win_log(text);
#else
    fprintf(out, "%s\n", text);
    fflush(out);
#endif
}

void ioerror(const char *txt) { /* input/output error handler */
    log_error(LOG_ERR, get_last_error(), txt);
}

void sockerror(const char *txt) { /* socket error handler */
    log_error(LOG_ERR, get_last_socket_error(), txt);
}

void log_error(int level, int error, const char *txt) { /* generic error logger */
    s_log(level, "%s: %s (%d)", txt, my_strerror(error), error);
}

char *my_strerror(int errnum) {
    switch(errnum) {
#ifdef USE_WIN32
    case 10004:
        return "Interrupted system call (WSAEINTR)";
    case 10009:
        return "Bad file number (WSAEBADF)";
    case 10013:
        return "Permission denied (WSAEACCES)";
    case 10014:
        return "Bad address (WSAEFAULT)";
    case 10022:
        return "Invalid argument (WSAEINVAL)";
    case 10024:
        return "Too many open files (WSAEMFILE)";
    case 10035:
        return "Operation would block (WSAEWOULDBLOCK)";
    case 10036:
        return "Operation now in progress (WSAEINPROGRESS)";
    case 10037:
        return "Operation already in progress (WSAEALREADY)";
    case 10038:
        return "Socket operation on non-socket (WSAENOTSOCK)";
    case 10039:
        return "Destination address required (WSAEDESTADDRREQ)";
    case 10040:
        return "Message too long (WSAEMSGSIZE)";
    case 10041:
        return "Protocol wrong type for socket (WSAEPROTOTYPE)";
    case 10042:
        return "Bad protocol option (WSAENOPROTOOPT)";
    case 10043:
        return "Protocol not supported (WSAEPROTONOSUPPORT)";
    case 10044:
        return "Socket type not supported (WSAESOCKTNOSUPPORT)";
    case 10045:
        return "Operation not supported on socket (WSAEOPNOTSUPP)";
    case 10046:
        return "Protocol family not supported (WSAEPFNOSUPPORT)";
    case 10047:
        return "Address family not supported by protocol family (WSAEAFNOSUPPORT)";
    case 10048:
        return "Address already in use (WSAEADDRINUSE)";
    case 10049:
        return "Can't assign requested address (WSAEADDRNOTAVAIL)";
    case 10050:
        return "Network is down (WSAENETDOWN)";
    case 10051:
        return "Network is unreachable (WSAENETUNREACH)";
    case 10052:
        return "Net dropped connection or reset (WSAENETRESET)";
    case 10053:
        return "Software caused connection abort (WSAECONNABORTED)";
    case 10054:
        return "Connection reset by peer (WSAECONNRESET)";
    case 10055:
        return "No buffer space available (WSAENOBUFS)";
    case 10056:
        return "Socket is already connected (WSAEISCONN)";
    case 10057:
        return "Socket is not connected (WSAENOTCONN)";
    case 10058:
        return "Can't send after socket shutdown (WSAESHUTDOWN)";
    case 10059:
        return "Too many references, can't splice (WSAETOOMANYREFS)";
    case 10060:
        return "Connection timed out (WSAETIMEDOUT)";
    case 10061:
        return "Connection refused (WSAECONNREFUSED)";
    case 10062:
        return "Too many levels of symbolic links (WSAELOOP)";
    case 10063:
        return "File name too long (WSAENAMETOOLONG)";
    case 10064:
        return "Host is down (WSAEHOSTDOWN)";
    case 10065:
        return "No Route to Host (WSAEHOSTUNREACH)";
    case 10066:
        return "Directory not empty (WSAENOTEMPTY)";
    case 10067:
        return "Too many processes (WSAEPROCLIM)";
    case 10068:
        return "Too many users (WSAEUSERS)";
    case 10069:
        return "Disc Quota Exceeded (WSAEDQUOT)";
    case 10070:
        return "Stale NFS file handle (WSAESTALE)";
    case 10091:
        return "Network SubSystem is unavailable (WSASYSNOTREADY)";
    case 10092:
        return "WINSOCK DLL Version out of range (WSAVERNOTSUPPORTED)";
    case 10093:
        return "Successful WSASTARTUP not yet performed (WSANOTINITIALISED)";
    case 10071:
        return "Too many levels of remote in path (WSAEREMOTE)";
    case 11001:
        return "Host not found (WSAHOST_NOT_FOUND)";
    case 11002:
        return "Non-Authoritative Host not found (WSATRY_AGAIN)";
    case 11003:
        return "Non-Recoverable errors: FORMERR, REFUSED, NOTIMP (WSANO_RECOVERY)";
    case 11004:
        return "Valid name, no data record of requested type (WSANO_DATA)";
#if 0
    case 11004: /* typically, only WSANO_DATA is reported */
        return "No address, look for MX record (WSANO_ADDRESS)";
#endif
#endif /* defined USE_WIN32 */
    default:
        return strerror(errnum);
    }
}

/* End of log.c */
