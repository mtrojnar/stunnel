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

NOEXPORT void log_queue(SERVICE_OPTIONS *, int, char *, char *, char *);
NOEXPORT void log_raw(SERVICE_OPTIONS *, int, char *, char *, char *);
NOEXPORT void safestring(char *);

static DISK_FILE *outfile=NULL;
static struct LIST { /* single-linked list of log lines */
    struct LIST *next;
    SERVICE_OPTIONS *opt;
    int level;
    char *stamp, *id, *text;
} *head=NULL, *tail=NULL;
static LOG_MODE log_mode=LOG_MODE_BUFFER;

#if !defined(USE_WIN32) && !defined(__vms)

static int syslog_opened=0;

NOEXPORT void syslog_open(void) {
    if(global_options.option.log_syslog) {
        static char *servname=NULL;
        char *servname_old;

        /* openlog(3) requires a persistent copy of the "ident" parameter */
        servname_old=servname;
        servname=str_dup(service_options.servname);
#ifdef __ultrix__
        openlog(servname, 0);
#else
        openlog(servname, LOG_CONS|LOG_NDELAY, global_options.log_facility);
#endif /* __ultrix__ */
        str_free(servname_old);
    }
    syslog_opened=1;
}

NOEXPORT void syslog_close(void) {
    if(syslog_opened) {
        if(global_options.option.log_syslog)
            closelog();
        syslog_opened=0;
    }
}

#endif /* !defined(USE_WIN32) && !defined(__vms) */

NOEXPORT int outfile_open(void) {
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
    return 0;
}

NOEXPORT void outfile_close(void) {
    if(outfile) {
        file_close(outfile);
        outfile=NULL;
    }
}

int log_open(int sink) {
#if !defined(USE_WIN32) && !defined(__vms)
    if(sink&SINK_SYSLOG)
        syslog_open();
#endif
    if(sink&SINK_OUTFILE && outfile_open())
        return 1;
    return 0;
}

void log_close(int sink) {
    /* prevent changing the mode while logging */
    CRYPTO_THREAD_write_lock(stunnel_locks[LOCK_LOG_MODE]);
#if !defined(USE_WIN32) && !defined(__vms)
    if(sink&SINK_SYSLOG)
        syslog_close();
#endif
    if(sink&SINK_OUTFILE)
        outfile_close();
    CRYPTO_THREAD_unlock(stunnel_locks[LOCK_LOG_MODE]);
}

void s_log(int level, const char *format, ...) {
    va_list ap;
    char *text, *stamp, *id;
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

    libc_error=get_last_error();
    socket_error=get_last_socket_error();

    tls_data=tls_get();
    if(!tls_data) {
        tls_data=tls_alloc(NULL, NULL, "log");
        s_log(LOG_ERR, "INTERNAL ERROR: Uninitialized TLS at %s, line %d",
            __FILE__, __LINE__);
    }

    /* performance optimization: skip the trivial case early */
    if(log_mode!=LOG_MODE_CONFIGURED || level<=tls_data->opt->log_level) {
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

        /* either log or queue for logging */
        CRYPTO_THREAD_read_lock(stunnel_locks[LOCK_LOG_MODE]);
        if(log_mode==LOG_MODE_BUFFER)
            log_queue(tls_data->opt, level, stamp, id, text);
        else
            log_raw(tls_data->opt, level, stamp, id, text);
        CRYPTO_THREAD_unlock(stunnel_locks[LOCK_LOG_MODE]);
    }

    set_last_error(libc_error);
    set_last_socket_error(socket_error);
}

NOEXPORT void log_queue(SERVICE_OPTIONS *opt,
        int level, char *stamp, char *id, char *text) {
    struct LIST *tmp;

    /* make a new element */
    tmp=str_alloc_detached(sizeof(struct LIST));
    tmp->next=NULL;
    tmp->opt=opt;
    tmp->level=level;
    tmp->stamp=stamp;
    str_detach(tmp->stamp);
    tmp->id=id;
    str_detach(tmp->id);
    tmp->text=text;
    str_detach(tmp->text);

    /* append the new element to the list */
    CRYPTO_THREAD_write_lock(stunnel_locks[LOCK_LOG_BUFFER]);
    if(tail)
        tail->next=tmp;
    else
        head=tmp;
    tail=tmp;
    if(stunnel_locks[LOCK_LOG_BUFFER])
    CRYPTO_THREAD_unlock(stunnel_locks[LOCK_LOG_BUFFER]);
}

void log_flush(LOG_MODE new_mode) {
    CRYPTO_THREAD_write_lock(stunnel_locks[LOCK_LOG_MODE]);

    log_mode=new_mode;

    /* emit the buffered logs (unless we just started buffering) */
    if(new_mode!=LOG_MODE_BUFFER) {
        /* log_raw() will use the new value of log_mode */
        CRYPTO_THREAD_write_lock(stunnel_locks[LOCK_LOG_BUFFER]);
        while(head) {
            struct LIST *tmp=head;
            head=head->next;
            log_raw(tmp->opt, tmp->level, tmp->stamp, tmp->id, tmp->text);
            str_free(tmp);
        }
        head=tail=NULL;
        CRYPTO_THREAD_unlock(stunnel_locks[LOCK_LOG_BUFFER]);
    }

    CRYPTO_THREAD_unlock(stunnel_locks[LOCK_LOG_MODE]);
}

NOEXPORT void log_raw(SERVICE_OPTIONS *opt,
        int level, char *stamp, char *id, char *text) {
    char *line;

    /* NOTE: opt->log_level may have changed since s_log().
     * It is important to use the new value and not the old one. */

    /* build the line and log it to syslog/file if configured */
    switch(log_mode) {
    case LOG_MODE_CONFIGURED:
        line=str_printf("%s %s: %s", stamp, id, text);
        if(level<=opt->log_level) {
#if !defined(USE_WIN32) && !defined(__vms)
            if(global_options.option.log_syslog)
                syslog(level, "%s: %s", id, text);
#endif /* USE_WIN32, __vms */
            if(outfile)
                file_putline(outfile, line);
        }
        break;
    case LOG_MODE_ERROR:
        /* don't log the id or the time stamp */
        if(level>=0 && level<=7) /* just in case */
            line=str_printf("[%c] %s", "***!:.  "[level], text);
        else
            line=str_printf("[?] %s", text);
        break;
    default: /* LOG_MODE_INFO */
        /* don't log the level, the id or the time stamp */
        line=str_dup(text);
    }

    /* free the memory */
    str_free(stamp);
    str_free(id);
    str_free(text);

    /* log the line to the UI (GUI, stderr, etc.) */
    if(log_mode==LOG_MODE_ERROR ||
            (log_mode==LOG_MODE_INFO && level<LOG_DEBUG) ||
#if defined(USE_WIN32) || defined(USE_JNI)
            level<=opt->log_level
#else
            (level<=opt->log_level &&
            opt->option.log_stderr)
#endif
            )
        ui_new_log(line);

    str_free(line);
}

#ifdef __GNUC__
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6)
#pragma GCC diagnostic push
#endif /* __GNUC__>=4.6 */
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
        memset(rnd, 0, sizeof rnd);
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
    case LOG_ID_PROCESS:
        return str_printf("%lu", stunnel_process_id());
    }
    return str_dup("error");
}
#ifdef __GNUC__
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6)
#pragma GCC diagnostic pop
#endif /* __GNUC__>=4.6 */
#endif /* __GNUC__ */

/* critical problem handling */
/* str.c functions are not safe to use here */
#ifdef __GNUC__
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
#endif /* __GNUC__>=4.6 */
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
    if(log_mode!=LOG_MODE_CONFIGURED || global_options.option.log_stderr) {
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
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6)
#pragma GCC diagnostic pop
#endif /* __GNUC__>=4.6 */
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

/* provide hex string corresponding to the input string
 * will be NULL terminated */
void bin2hexstring(const unsigned char *in_data, size_t in_size, char *out_data, size_t out_size) {
    const char hex[16]="0123456789ABCDEF";
    size_t i;

    for(i=0; i<in_size && 2*i+2<out_size; ++i) {
        out_data[2*i]=hex[in_data[i]>>4];
        out_data[2*i+1]=hex[in_data[i]&0x0f];
    }
    out_data[2*i]='\0';
}

/* end of log.c */
