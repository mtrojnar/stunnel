/*
 *   stunnel       TLS offloading and load-balancing proxy
 *   Copyright (C) 1998-2026 Michal Trojnara <Michal.Trojnara@stunnel.org>
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

#include "prototypes.h"

#define LOG_FIELD_SIZE 72
#define LOG_MAX_TEXT_LENGTH 1024
#define LOG_MAX_LINE_LENGTH \
    (LOG_MAX_TEXT_LENGTH+2*(LOG_FIELD_SIZE-1)+3)

NOEXPORT void log_emit(TLS_DATA *tls_data, int level, char *text);
NOEXPORT void log_queue(SERVICE_OPTIONS *opt, int level,
    char *stamp, char *id, char *text);
NOEXPORT void log_raw(SERVICE_OPTIONS *opt, int level,
    char *stamp, char *id, char *text);
NOEXPORT void safestring(char *c);

DISK_FILE *outfile=NULL;

NOEXPORT struct LIST { /* single-linked list of log lines */
    struct LIST *next;
    SERVICE_OPTIONS *opt;
    int level;
    char *stamp, *id, *text;
} *head=NULL, *tail=NULL;
NOEXPORT LOG_MODE log_mode=LOG_MODE_BUFFER;

#if !defined(USE_WIN32) && !defined(__vms)

NOEXPORT int syslog_opened=0;

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
    CRYPTO_RWLOCK *lock;

    /* prevent changing the mode while logging */
    lock=s_write_lock(LOCK_LOG_MODE);
#if !defined(USE_WIN32) && !defined(__vms)
    if(sink&SINK_SYSLOG)
        syslog_close();
#endif
    if(sink&SINK_OUTFILE)
        outfile_close();
    s_unlock(lock);
}

void s_log(int level, const char *format, ...) {
    va_list ap;

    va_start(ap, format);
    s_vlog(level, format, ap);
    va_end(ap);
}

NOEXPORT void log_emit(TLS_DATA *tls_data, int level, char *text) {
    time_t gmt;
    struct tm ts;
    char stamp[LOG_FIELD_SIZE], id[LOG_FIELD_SIZE];
    size_t len;
    CRYPTO_RWLOCK *lock;

    /* format the id to be logged */
    (void)time(&gmt);
    safe_localtime(&ts, gmt);
    (void)snprintf(stamp, sizeof stamp, "%04d.%02d.%02d %02d:%02d:%02d",
        ts.tm_year+1900, ts.tm_mon+1, ts.tm_mday,
        ts.tm_hour, ts.tm_min, ts.tm_sec);
    (void)snprintf(id, sizeof id, "LOG%d[%s]", level, tls_data->id);

    /* sanitize the text to be logged */
    len=strlen(text);
    while(len>0U && text[len-1U]=='\n')
        text[--len]='\0'; /* strip trailing newlines */
    safestring(text);

    /* either log or queue for logging */
    lock=s_read_lock(LOCK_LOG_MODE);
    if(log_mode==LOG_MODE_BUFFER)
        log_queue(tls_data->opt, level, stamp, id, text);
    else
        log_raw(tls_data->opt, level, stamp, id, text);
    s_unlock(lock);
}

#ifdef __GNUC__
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6)
#pragma GCC diagnostic push
#endif /* __GNUC__>=4.6 */
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#endif /* __GNUC__ */
void s_vlog(int level, const char *format, va_list ap) {
#ifdef USE_WIN32
    DWORD libc_error;
#else
    int libc_error;
#endif
    int socket_error;
    TLS_DATA *tls_data;

    libc_error=get_last_error();
    socket_error=get_last_socket_error();

    tls_data=tls_get();
    if(!tls_data) {
        tls_data=tls_alloc(NULL, NULL, "log");
        if(log_mode!=LOG_MODE_CONFIGURED ||
                LOG_ERR<=tls_data->opt->log_level) {
            char text[LOG_MAX_TEXT_LENGTH+1]={0};

            (void)snprintf(text, sizeof text,
                "INTERNAL ERROR: Uninitialized TLS at %s, line %d",
                __FILE__, __LINE__);
            log_emit(tls_data, LOG_ERR, text);
        }
    }

    /* performance optimization: skip the trivial case early */
    if(log_mode!=LOG_MODE_CONFIGURED || level<=tls_data->opt->log_level) {
        char text[LOG_MAX_TEXT_LENGTH+1]={0};

        (void)vsnprintf(text, sizeof text, format, ap);
        text[sizeof text-1U]='\0';
        log_emit(tls_data, level, text);
    }

    set_last_error(libc_error);
    set_last_socket_error(socket_error);
}
#ifdef __GNUC__
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6)
#pragma GCC diagnostic pop
#endif /* __GNUC__>=4.6 */
#endif /* __GNUC__ */

NOEXPORT void log_queue(SERVICE_OPTIONS *opt,
        int level, char *stamp, char *id, char *text) {
    struct LIST *tmp;
    CRYPTO_RWLOCK *lock;

    /* make a new element */
    tmp=str_alloc_detached(sizeof(struct LIST));
    tmp->next=NULL;
    tmp->opt=opt;
    tmp->level=level;
    tmp->stamp=str_dup_detached(stamp);
    tmp->id=str_dup_detached(id);
    tmp->text=str_dup_detached(text);

    /* append the new element to the list */
    lock=s_write_lock(LOCK_LOG_BUFFER);
    if(tail)
        tail->next=tmp;
    else
        head=tmp;
    tail=tmp;
    s_unlock(lock);
}

void log_flush(LOG_MODE new_mode) {
    CRYPTO_RWLOCK *mode_lock, *buffer_lock;

    mode_lock=s_write_lock(LOCK_LOG_MODE);

    log_mode=new_mode;

    /* emit the buffered logs (unless we just started buffering) */
    if(new_mode!=LOG_MODE_BUFFER) {
        /* log_raw() will use the new value of log_mode */
        buffer_lock=s_write_lock(LOCK_LOG_BUFFER);
        while(head) {
            struct LIST *tmp=head;
            head=head->next;
            log_raw(tmp->opt, tmp->level, tmp->stamp, tmp->id, tmp->text);
            str_free(tmp->stamp);
            str_free(tmp->id);
            str_free(tmp->text);
            str_free(tmp);
        }
        head=tail=NULL;
        s_unlock(buffer_lock);
    }

    s_unlock(mode_lock);
}

NOEXPORT void log_raw(SERVICE_OPTIONS *opt,
        int level, char *stamp, char *id, char *text) {
    char line_buffer[LOG_MAX_LINE_LENGTH+1], *line;

    /* NOTE: opt->log_level may have changed since s_log().
     * It is important to use the new value and not the old one. */

    /* build the line and log it to syslog/file if configured */
    switch(log_mode) {
    case LOG_MODE_CONFIGURED:
        line=line_buffer;
        (void)snprintf(line, sizeof line_buffer, "%s %s: %s", stamp, id, text);
        if(level<=opt->log_level) {
#if !defined(USE_WIN32) && !defined(__vms)
            if(global_options.option.log_syslog)
                syslog(level, "%s: %s", id, text);
#endif /* USE_WIN32, __vms */
            if(outfile) {
                (void)file_putline_newline(outfile, line);
#ifndef USE_OS_THREADS
                file_flush(outfile);
#endif /* !USE_OS_THREADS */
            }
        }
        break;
    case LOG_MODE_ERROR:
        if(level>=LOG_INFO && level<=LOG_DEBUG)
            return;
        /* don't log the id or the time stamp */
        line=line_buffer;
        if(level>=LOG_EMERG && level<=LOG_NOTICE)
            (void)snprintf(line, sizeof line_buffer,
                "[%c] %s", "***!:."[level], text);
        else /* invalid level */
            (void)snprintf(line, sizeof line_buffer, "[?] %s", text);
        break;
    default: /* LOG_MODE_INFO */
        /* don't log the level, the id or the time stamp */
        line=text;
    }

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
}

#ifdef __GNUC__
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6)
#pragma GCC diagnostic push
#endif /* __GNUC__>=4.6 */
#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-extra-args"
#endif /* __GNUC__ */
char *log_id_alloc(CLI *c) {
    const char table[62]=
        {'0', '1', '2', '3', '4', '5', '6', '7',
         '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
         'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
         'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
         'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D',
         'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L',
         'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
         'U', 'V', 'W', 'X', 'Y', 'Z'};
    unsigned char rnd[22];
    char *uniq;
    size_t i;
    unsigned long tid;

    switch(c->opt->log_id) {
    case LOG_ID_SEQUENTIAL:
        return str_printf("%llu", c->seq);
    case LOG_ID_UNIQUE:
        (void)memset(rnd, 0, sizeof rnd);
        if(RAND_bytes(rnd, sizeof rnd)<=0) /* log2(62^22)=130.99 */
            return str_dup("error");
        for(i=0; i<sizeof rnd; ++i) {
            rnd[i]&=63U;
            while(rnd[i]>=62U) {
                if(RAND_bytes(rnd+i, 1)<=0)
                    return str_dup("error");
                rnd[i]&=63U;
            }
        }
        uniq=str_alloc(sizeof rnd+1U);
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
void fatal_debug(const char *txt, const char *file, int line) {
    char msg[80];
#ifdef USE_WIN32
#ifdef UNICODE
    TCHAR tmsg[80];
#endif
#endif /* USE_WIN32 */

    (void)snprintf(msg, sizeof msg, /* with newline */
        "INTERNAL ERROR: %s at %s, line %d\n", txt, file, line);

    if(outfile) {
        (void)file_putline_nonewline(outfile, msg);
        (void)file_flush(outfile);
    }

#ifndef USE_WIN32
    if(log_mode!=LOG_MODE_CONFIGURED || global_options.option.log_stderr) {
        (void)fputs(msg, stderr);
        (void)fflush(stderr);
    }
#endif /* !USE_WIN32 */

    (void)snprintf(msg, sizeof msg, /* without newline */
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

    /* fatal() cannot safely return to its caller. */
    /* cppcheck-suppress misra-c2012-21.8 */
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
    while(*c) {
        if(!(*c&0x80 || isprint((int)*c)))
            *c='.';
        ++c;
    }
}

/* provide hex string corresponding to the input string
 * will be NULL terminated */
void bin2hexstring(const unsigned char *in_data, size_t in_size, char *out_data, size_t out_size) {
    const char hex[16]=
        {'0', '1', '2', '3', '4', '5', '6', '7',
         '8', '9' ,'A', 'B', 'C', 'D', 'E', 'F'};
    size_t i, input_limit;

    if(!out_size)
        return;
    input_limit=(out_size-1U)/2U;
    if(input_limit>in_size)
        input_limit=in_size;
    for(i=0; i<input_limit; ++i) {
        out_data[2U*i]=hex[in_data[i]>>4U];
        out_data[2U*i+1U]=hex[in_data[i]&0x0fU];
    }
    out_data[2U*i]='\0';
}

void safe_localtime(struct tm *ts, time_t unix_time) {
#if defined(HAVE_LOCALTIME_R) && defined(_REENTRANT)
    if(!localtime_r(&unix_time, ts))
        (void)memset(ts, 0, sizeof *ts);
#else
    CRYPTO_RWLOCK *lock;

    lock=s_write_lock(LOCK_LOCALTIME);
    {
        struct tm *tp=localtime(&unix_time);

        if(tp)
            (void)memcpy(ts, tp, sizeof *ts);
        else
            (void)memset(ts, 0, sizeof *ts);
    }
    s_unlock(lock);
#endif
}
/* end of log.c */
