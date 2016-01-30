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

#ifdef USE_WIN32

DISK_FILE *file_open(char *name, FILE_MODE mode) {
    DISK_FILE *df;
    LPTSTR tname;
    HANDLE fh;
    DWORD desired_access, creation_disposition;

    /* open file */
    switch(mode) {
    case FILE_MODE_READ:
        desired_access=GENERIC_READ;
        creation_disposition=OPEN_EXISTING;
        break;
    case FILE_MODE_APPEND:
            /* reportedly more compatible than FILE_APPEND_DATA */
        desired_access=GENERIC_WRITE;
        creation_disposition=OPEN_ALWAYS; /* keep the data */
        break;
    case FILE_MODE_OVERWRITE:
        desired_access=GENERIC_WRITE;
        creation_disposition=CREATE_ALWAYS; /* remove the data */
        break;
    default: /* invalid mode */
        return NULL;
    }
    tname=str2tstr(name);
    fh=CreateFile(tname, desired_access, FILE_SHARE_READ, NULL,
        creation_disposition, FILE_ATTRIBUTE_NORMAL, (HANDLE)NULL);
    str_free(tname); /* str_free() overwrites GetLastError() value */
    if(fh==INVALID_HANDLE_VALUE)
        return NULL;
    if(mode==FILE_MODE_APPEND) /* workaround for FILE_APPEND_DATA */
        SetFilePointer(fh, 0, NULL, FILE_END);

    /* setup df structure */
    df=str_alloc(sizeof df);
    df->fh=fh;
    return df;
}

#else /* USE_WIN32 */

DISK_FILE *file_fdopen(int fd) {
    DISK_FILE *df;

    df=str_alloc(sizeof(DISK_FILE));
    df->fd=fd;
    return df;
}

DISK_FILE *file_open(char *name, FILE_MODE mode) {
    DISK_FILE *df;
    int fd, flags;

    /* open file */
    switch(mode) {
    case FILE_MODE_READ:
        flags=O_RDONLY;
        break;
    case FILE_MODE_APPEND:
        flags=O_CREAT|O_WRONLY|O_APPEND;
        break;
    case FILE_MODE_OVERWRITE:
        flags=O_CREAT|O_WRONLY|O_TRUNC;
        break;
    default: /* invalid mode */
        return NULL;
    }
#ifdef O_NONBLOCK
    flags|=O_NONBLOCK;
#elif defined O_NDELAY
    flags|=O_NDELAY;
#endif
#ifdef O_CLOEXEC
    flags|=O_CLOEXEC;
#endif /* O_CLOEXEC */
    fd=open(name, flags, 0640);
    if(fd==INVALID_SOCKET)
        return NULL;

    /* setup df structure */
    df=str_alloc(sizeof df);
    df->fd=fd;
    return df;
}

#endif /* USE_WIN32 */

void file_close(DISK_FILE *df) {
    if(!df) /* nothing to do */
        return;
#ifdef USE_WIN32
    CloseHandle(df->fh);
#else /* USE_WIN32 */
    if(df->fd>2) /* never close stdin/stdout/stder */
        close(df->fd);
#endif /* USE_WIN32 */
    str_free(df);
}

ssize_t file_getline(DISK_FILE *df, char *line, int len) {
    /* this version is really slow, but performance is not important here */
    /* (no buffering is implemented) */
    ssize_t i;
#ifdef USE_WIN32
    DWORD num;
#else /* USE_WIN32 */
    ssize_t num;
#endif /* USE_WIN32 */

    if(!df) /* not opened */
        return -1;

    for(i=0; i<len-1; i++) {
#ifdef USE_WIN32
        ReadFile(df->fh, line+i, 1, &num, NULL);
#else /* USE_WIN32 */
        num=read(df->fd, line+i, 1);
#endif /* USE_WIN32 */
        if(num!=1) { /* EOF */
            if(i) /* any previously retrieved data */
                break;
            else
                return -1;
        }
        if(line[i]=='\n') /* LF */
            break;
        if(line[i]=='\r') /* CR */
            --i; /* ignore - it must be the last check */
    }
    line[i]='\0';
    return i;
}

ssize_t file_putline(DISK_FILE *df, char *line) {
    char *buff;
    size_t len;
#ifdef USE_WIN32
    DWORD num;
#else /* USE_WIN32 */
    ssize_t num;
#endif /* USE_WIN32 */

    len=strlen(line);
    buff=str_alloc(len+2); /* +2 for CR+LF */
    strcpy(buff, line);
#ifdef USE_WIN32
    buff[len++]='\r'; /* CR */
#endif /* USE_WIN32 */
    buff[len++]='\n'; /* LF */
#ifdef USE_WIN32
    WriteFile(df->fh, buff, (DWORD)len, &num, NULL);
#else /* USE_WIN32 */
    /* no file -> write to stderr */
    num=write(df ? df->fd : 2, buff, len);
#endif /* USE_WIN32 */
    str_free(buff);
    return (ssize_t)num;
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
