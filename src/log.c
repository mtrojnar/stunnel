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

NOEXPORT void log_raw(const SERVICE_OPTIONS *, const int,
    const char *, const char *, const char *);
NOEXPORT void safestring(char *);

static DISK_FILE *outfile=NULL;
static struct LIST { /* single-linked list of log lines */
    struct LIST *next;
    SERVICE_OPTIONS *opt;
    int level;
    char *stamp, *id, *text;
} *head=NULL, *tail=NULL;
static LOG_MODE mode=LOG_MODE_NONE;

#if !defined(USE_WIN32) && !defined(__vms)

static int syslog_opened=0;

void syslog_open(void) {
    syslog_close();
    if(global_options.option.log_syslog)
#ifdef __ultrix__
        openlog(service_options.servname, 0);
#else
        openlog(service_options.servname,
            LOG_CONS|LOG_NDELAY, global_options.log_facility);
#endif /* __ultrix__ */
    syslog_opened=1;
}

void syslog_close(void) {
    if(syslog_opened) {
        if(global_options.option.log_syslog)
            closelog();
        syslog_opened=0;
    }
}

#endif /* !defined(USE_WIN32) && !defined(__vms) */

int log_open(void) {
    if(global_options.output_file) { /* 'output' option specified */
        outfile=file_open(global_options.output_file,
            global_options.log_file_mode);
#if defined(USE_WIN32) && !defined(_WIN32_WCE)
        if(!outfile) {
            char appdata[MAX_PATH], *path;
            if(SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA|CSIDL_FLAG_CREATE,
                    NULL, 0, appdata)==S_OK) {
                path=str_printf("%s\\%s", appdata, global_options.output_file);
                outfile=file_open(path, global_options.log_file_mode);
                if(outfile)
                    s_log(LOG_NOTICE, "Logging to %s", path);
                str_free(path);
            }
        }
#endif
        if(!outfile) {
            s_log(LOG_ERR, "Cannot open log file: %s",
                global_options.output_file);
            return 1;
        }
    }
    log_flush(LOG_MODE_CONFIGURED);
    return 0;
}

void log_close(void) {
    mode=LOG_MODE_NONE;
    if(outfile) {
        file_close(outfile);
        outfile=NULL;
    }
}

void log_flush(LOG_MODE new_mode) {
    struct LIST *tmp;

    /* prevent changing LOG_MODE_CONFIGURED to LOG_MODE_ERROR
     * once stderr file descriptor is closed */
    if(mode!=LOG_MODE_CONFIGURED)
        mode=new_mode;

    CRYPTO_w_lock(stunnel_locks[LOCK_LOG]);
    while(head) {
        log_raw(head->opt, head->level, head->stamp, head->id, head->text);
        str_free(head->stamp);
        str_free(head->id);
        str_free(head->text);
        tmp=head;
        head=head->next;
        str_free(tmp);
    }
    CRYPTO_w_unlock(stunnel_locks[LOCK_LOG]);
    head=tail=NULL;
}

void s_log(int level, const char *format, ...) {
    va_list ap;
    char *text, *stamp, *id;
    struct LIST *tmp;
#ifdef USE_WIN32
    DWORD libc_error;
#else
    int libc_error;
#endif
    int socket_error;
    time_t gmt;
    struct tm *timeptr;
#if defined(HAVE_LOCALTIME_R) && defined(_REENTRANT)
    struct tm timestruct;
#endif
    TLS_DATA *tls_data;

    tls_data=tls_get();
    if(!tls_data) {
        tls_data=tls_alloc(NULL, NULL, "log");
        s_log(LOG_ERR, "INTERNAL ERROR: Uninitialized TLS at %s, line %d",
            __FILE__, __LINE__);
    }

    /* performance optimization: skip the trivial case early */
    if(mode==LOG_MODE_CONFIGURED && level>tls_data->opt->log_level)
        return;

    libc_error=get_last_error();
    socket_error=get_last_socket_error();

    /* format the id to be logged */
    time(&gmt);
#if defined(HAVE_LOCALTIME_R) && defined(_REENTRANT)
    timeptr=localtime_r(&gmt, &timestruct);
#else
    timeptr=localtime(&gmt);
#endif
    stamp=str_printf("%04d.%02d.%02d %02d:%02d:%02d",
        timeptr->tm_year+1900, timeptr->tm_mon+1, timeptr->tm_mday,
        timeptr->tm_hour, timeptr->tm_min, timeptr->tm_sec);
    id=str_printf("LOG%d[%s]", level, tls_data->id);

    /* format the text to be logged */
    va_start(ap, format);
    text=str_vprintf(format, ap);
    va_end(ap);
    safestring(text);

    if(mode==LOG_MODE_NONE) { /* save the text to log it later */
        CRYPTO_w_lock(stunnel_locks[LOCK_LOG]);
        tmp=str_alloc_detached(sizeof(struct LIST));
        tmp->next=NULL;
        tmp->opt=tls_data->opt;
        tmp->level=level;
        tmp->stamp=stamp;
        str_detach(tmp->stamp);
        tmp->id=id;
        str_detach(tmp->id);
        tmp->text=text;
        str_detach(tmp->text);
        if(tail)
            tail->next=tmp;
        else
            head=tmp;
        tail=tmp;
        CRYPTO_w_unlock(stunnel_locks[LOCK_LOG]);
    } else { /* ready log the text directly */
        log_raw(tls_data->opt, level, stamp, id, text);
        str_free(stamp);
        str_free(id);
        str_free(text);
    }

    set_last_error(libc_error);
    set_last_socket_error(socket_error);
}

NOEXPORT void log_raw(const SERVICE_OPTIONS *opt,
        const int level, const char *stamp,
        const char *id, const char *text) {
    char *line;

    /* build the line and log it to syslog/file */
    if(mode==LOG_MODE_CONFIGURED) { /* configured */
        line=str_printf("%s %s: %s", stamp, id, text);
        if(level<=opt->log_level) {
#if !defined(USE_WIN32) && !defined(__vms)
            if(global_options.option.log_syslog)
                syslog(level, "%s: %s", id, text);
#endif /* USE_WIN32, __vms */
            if(outfile)
                file_putline(outfile, line); /* send log to file */
        }
    } else if(mode==LOG_MODE_ERROR) {
        if(level>=0 && level<=7) /* just in case */
            line=str_printf("[%c] %s", "***!:.  "[level], text);
        else
            line=str_printf("[?] %s", text);
    } else /* LOG_MODE_INFO */
        line=str_dup(text); /* don't log the time stamp in error mode */

    /* log the line to the UI (GUI, stderr, etc.) */
    if(mode==LOG_MODE_ERROR ||
            (mode==LOG_MODE_INFO && level<LOG_DEBUG) ||
#if defined(USE_WIN32) || defined(USE_JNI)
            level<=opt->log_level
#else
            (level<=opt->log_level &&
            global_options.option.log_stderr)
#endif
            )
        ui_new_log(line);

    str_free(line);
}

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-extra-args"
#endif /* __GNUC__ */
char *log_id(CLI *c) {
    const char table[62]=
        "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    unsigned char rnd[22];
    char *uniq;
    size_t i;
    unsigned long tid;

    switch(c->opt->log_id) {
    case LOG_ID_SEQUENTIAL:
        return str_printf("%llu", c->seq);
    case LOG_ID_UNIQUE:
        if(RAND_bytes(rnd, sizeof rnd)<=0) /* log2(62^22)=130.99 */
            return str_dup("error");
        for(i=0; i<sizeof rnd; ++i) {
            rnd[i]&=63;
            while(rnd[i]>=62) {
                if(RAND_bytes(rnd+i, 1)<=0)
                    return str_dup("error");
                rnd[i]&=63;
            }
        }
        uniq=str_alloc(sizeof rnd+1);
        for(i=0; i<sizeof rnd; ++i)
            uniq[i]=table[rnd[i]];
        uniq[sizeof rnd]='\0';
        return uniq;
    case LOG_ID_THREAD:
        tid=stunnel_thread_id();
        if(!tid) /* currently USE_FORK */
            tid=stunnel_process_id();
        return str_printf("%lu", tid);
    }
    return str_dup("error");
}
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif /* __GNUC__ */

/* critical problem handling */
/* str.c functions are not safe to use here */
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
#endif /* __GNUC__ */
void fatal_debug(char *txt, const char *file, int line) {
    char msg[80];
#ifdef USE_WIN32
    DWORD num;
#ifdef UNICODE
    TCHAR tmsg[80];
#endif
#endif /* USE_WIN32 */

    snprintf(msg, sizeof msg, /* with newline */
        "INTERNAL ERROR: %s at %s, line %d\n", txt, file, line);

    if(outfile) {
#ifdef USE_WIN32
        WriteFile(outfile->fh, msg, (DWORD)strlen(msg), &num, NULL);
#else /* USE_WIN32 */
        /* no file -> write to stderr */
        /* no meaningful way here to handle the result */
        write(outfile ? outfile->fd : 2, msg, strlen(msg));
#endif /* USE_WIN32 */
    }

#ifndef USE_WIN32
    if(mode!=LOG_MODE_CONFIGURED || global_options.option.log_stderr) {
        fputs(msg, stderr);
        fflush(stderr);
    }
#endif /* !USE_WIN32 */

    snprintf(msg, sizeof msg, /* without newline */
        "INTERNAL ERROR: %s at %s, line %d", txt, file, line);

#if !defined(USE_WIN32) && !defined(__vms)
    if(global_options.option.log_syslog)
        syslog(LOG_CRIT, "%s", msg);
#endif /* USE_WIN32, __vms */

#ifdef USE_WIN32
#ifdef UNICODE
    if(MultiByteToWideChar(CP_UTF8, 0, msg, -1, tmsg, 80))
        message_box(tmsg, MB_ICONERROR);
#else
    message_box(msg, MB_ICONERROR);
#endif
#endif /* USE_WIN32 */

    abort();
}
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif /* __GNUC__ */

void ioerror(const char *txt) { /* input/output error */
    log_error(LOG_ERR, (int)get_last_error(), txt);
}

void sockerror(const char *txt) { /* socket error */
    log_error(LOG_ERR, get_last_socket_error(), txt);
}

void log_error(int level, int error, const char *txt) { /* generic error */
    s_log(level, "%s: %s (%d)", txt, s_strerror(error), error);
}

char *s_strerror(int errnum) {
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

/* replace non-UTF-8 and non-printable control characters with '.' */
NOEXPORT void safestring(char *c) {
    for(; *c; ++c)
        if(!(*c&0x80 || isprint((int)*c)))
            *c='.';
}

/* end of log.c */
