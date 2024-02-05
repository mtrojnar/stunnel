/*
 *   stunnel       TLS offloading and load-balancing proxy
 *   Copyright (C) 1998-2024 Michal Trojnara <Michal.Trojnara@stunnel.org>
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

DISK_FILE *file_fdopen(int fd, FILE_MODE file_mode) {
    DISK_FILE *df;
    FILE *f;
    char *mode;

    switch(fd) {
    case 0:
        f=stdin;
        break;
    case 1:
        f=stdout;
        break;
    case 2:
        f=stderr;
        break;
    default:
        switch(file_mode) {
        case FILE_MODE_READ:
            mode="r";
            break;
        case FILE_MODE_APPEND:
            mode="a";
            break;
        case FILE_MODE_OVERWRITE:
            mode="w";
            break;
        default: /* invalid file_mode */
            return NULL;
        }
        f=fdopen(fd, mode);
    }
    if(!f)
        return NULL;
    df=str_alloc(sizeof(DISK_FILE));
    df->f=f;
    return df;
}

DISK_FILE *file_open(char *name, FILE_MODE file_mode) {
    int fd, flags;

    /* open file */
    switch(file_mode) {
    case FILE_MODE_READ:
        flags=O_RDONLY;
        break;
    case FILE_MODE_APPEND:
        flags=O_CREAT|O_WRONLY|O_APPEND;
        break;
    case FILE_MODE_OVERWRITE:
        flags=O_CREAT|O_WRONLY|O_TRUNC;
        break;
    default: /* invalid file_mode */
        return NULL;
    }
#ifdef O_CLOEXEC
    flags|=O_CLOEXEC;
#endif /* O_CLOEXEC */
    /* don't fopen() directly to prevent O_CLOEXEC race condition */
#ifdef USE_WIN32
    fd=_open(name, flags, _S_IREAD|_S_IWRITE);
#else /* USE_WIN32 */
    fd=open(name, flags, 0640);
#endif /* USE_WIN32 */
    if(fd<0)
        return NULL;
    return file_fdopen(fd, file_mode);
}

void file_close(DISK_FILE *df) {
    if(!df) /* nothing to do */
        return;
    if(fileno(df->f)>2) /* never close stdin/stdout/stder */
        fclose(df->f);
    str_free(df);
}

ssize_t file_getline(DISK_FILE *df, char *line, int len) {
    ssize_t i;
    int c;

    if(!df) /* not opened */
        return -1;

    for(i=0; i<len-1; i++) {
        c=getc(df->f);
        if(c==EOF) {
            if(!i) /* no previously retrieved data */
                return -1;
            break; /* MSDOS-style last file line */
        }
        line[i]=(char)c;
        if(line[i]=='\n') /* LF */
            break;
        if(line[i]=='\r') /* CR */
            --i; /* ignore - it must be the last check */
    }
    line[i]='\0';
    return i;
}

ssize_t file_putline_nonewline(DISK_FILE *df, char *line) {
    /* used for fatal_debug() -> no str.c functions are allowed */
    FILE *f;
    int num;

    f=df ? df->f : stderr; /* no file -> write to stderr */
    num=fputs(line, f); /* automatically converts LF->CRLF on Windows */
    return (ssize_t)num;
}

ssize_t file_putline_newline(DISK_FILE *df, char *line) {
    char *buff;
    size_t len;
    ssize_t num;

    len=strlen(line);
    buff=str_alloc(len+3); /* +2 for LF+NUL */
    strcpy(buff, line);
    buff[len++]='\n'; /* LF */
    buff[len]='\0'; /* NUL */
    num=file_putline_nonewline(df, buff);
    str_free(buff);
    return num;
}

int file_flush(DISK_FILE *df) {
    return fflush(df ? df->f : stderr); /* no file -> flush stderr */
}

int file_permissions(const char *file_name) {
#if !defined(USE_WIN32) && !defined(USE_OS2)
    struct stat sb; /* buffer for stat */

    /* check permissions of the private key file */
    if(stat(file_name, &sb)) {
        ioerror(file_name);
        return 1; /* FAILED */
    }
    if(sb.st_mode & 7)
        s_log(LOG_WARNING,
            "Insecure file permissions on %s", file_name);
#else
    (void)file_name; /* squash the unused parameter warning */
    /* not (yet) implemented */
#endif
    return 0;
}

#ifdef USE_WIN32

LPTSTR str2tstr(LPCSTR in) {
    LPTSTR out;
#ifdef UNICODE
    int len;

    len=MultiByteToWideChar(CP_UTF8, 0, in, -1, NULL, 0);
    if(!len)
        return str_tprintf(TEXT("MultiByteToWideChar() failed"));
    out=str_alloc(((size_t)len+1)*sizeof(WCHAR));
    len=MultiByteToWideChar(CP_UTF8, 0, in, -1, out, len);
    if(!len) {
        str_free(out);
        return str_tprintf(TEXT("MultiByteToWideChar() failed"));
    }
#else
    /* FIXME: convert UTF-8 to native codepage */
    out=str_dup(in);
#endif
    return out;
}

LPSTR tstr2str(LPCTSTR in) {
    LPSTR out;
#ifdef UNICODE
    int len;

    len=WideCharToMultiByte(CP_UTF8, 0, in, -1, NULL, 0, NULL, NULL);
    if(!len)
        return str_printf("WideCharToMultiByte() failed");
    out=str_alloc((size_t)len+1);
    len=WideCharToMultiByte(CP_UTF8, 0, in, -1, out, len, NULL, NULL);
    if(!len) {
        str_free(out);
        return str_printf("WideCharToMultiByte() failed");
    }
#else
    /* FIXME: convert native codepage to UTF-8 */
    out=str_dup(in);
#endif
    return out;
}

#endif /* USE_WIN32 */

/* end of file.c */
