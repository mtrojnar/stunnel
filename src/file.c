/*
 *   stunnel       Universal SSL tunnel
 *   Copyright (C) 1998-2009 Michal Trojnara <Michal.Trojnara@mirt.net>
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

#ifndef USE_WIN32
DISK_FILE *file_fdopen(int fd) {
    DISK_FILE *df;

    df=calloc(1, sizeof(DISK_FILE));
    if(!df)
        return NULL;
    df->fd=fd;
    return df;
}
#endif /* USE_WIN32 */

DISK_FILE *file_open(char *name, int wr) {
    DISK_FILE *df;
#ifdef USE_WIN32
    LPTSTR tstr;
#endif /* USE_WIN32 */

    df=calloc(1, sizeof(DISK_FILE));
    if(!df)
        return NULL;
#ifdef USE_WIN32
    tstr=str2tstr(name);
    df->fh=CreateFile(tstr, wr ? GENERIC_WRITE : GENERIC_READ,
        FILE_SHARE_READ, NULL, wr ? OPEN_ALWAYS : OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, (HANDLE)NULL);
    free(tstr);
    if(df->fh!=INVALID_HANDLE_VALUE) { /* OK! */
        if(wr) /* append */
            SetFilePointer(df->fh, 0, NULL, FILE_END);
        return df;
    }
#else /* USE_WIN32 */
    df->fd=open(name, wr ? O_CREAT|O_WRONLY|O_APPEND : O_RDONLY, 0640);
    if(df->fd>=0) { /* OK! */
#ifndef __vms
        fcntl(df->fd, F_SETFD, FD_CLOEXEC);
#endif /* ! __vms */
        return df;
    }
#endif /* USE_WIN32 */
    /* failed to open the file */
    free(df);
    ioerror(name);
    return NULL;
}

void file_close(DISK_FILE *df) {
    if(!df) /* nothing to do */
        return;
#ifdef USE_WIN32
    CloseHandle(df->fh);
#else /* USE_WIN32 */
    close(df->fd);
#endif /* USE_WIN32 */
    free(df);
}

int file_getline(DISK_FILE *df, char *line, int len) {
    /* this version is really slow, but performance is not important here */
    /* (no buffering is implemented) */
    int i;
#ifdef USE_WIN32
    DWORD num;
#else /* USE_WIN32 */
    int num;
#endif /* USE_WIN32 */

    if(!df) /* not opened */
        return 0;

    for(i=0; i<len-1; i++) {
        if(i>0 && line[i-1]=='\n')
            break;
#ifdef USE_WIN32
        ReadFile(df->fh, line+i, 1, &num, NULL);
#else /* USE_WIN32 */
        num=read(df->fd, line+i, 1);
#endif /* USE_WIN32 */
        if(num!=1)
            break;
    }
    line[i]='\0';
    return i;
}

int file_putline(DISK_FILE *df, char *line) {
    int len;
    char *buff;
#ifdef USE_WIN32
    DWORD num;
#else /* USE_WIN32 */
    int num;
#endif /* USE_WIN32 */

    len=strlen(line);
    buff=calloc(len+2, 1); /* +2 for \r\n */
    if(!buff)
        return 0;
    strcpy(buff, line);
#ifdef USE_WIN32
    buff[len++]='\r';
#endif /* USE_WIN32 */
    buff[len++]='\n';
#ifdef USE_WIN32
    WriteFile(df->fh, buff, len, &num, NULL);
#else /* USE_WIN32 */
    /* no file -> write to stderr */
    num=write(df ? df->fd : 2, buff, len);
#endif /* USE_WIN32 */
    free(buff);
    return num;
}

#ifdef USE_WIN32

LPTSTR str2tstr(const LPSTR in) {
    LPTSTR out;
    int len;

#ifdef UNICODE
    len=MultiByteToWideChar(CP_ACP, 0, in, -1, NULL, 0);
    if(!len)
        return NULL;
    out=malloc((len+1)*sizeof(WCHAR));
    if(!out)
        return NULL;
    len=MultiByteToWideChar(CP_ACP, 0, in, -1, out, len);
    if(!len)
        return NULL;
#else
    len=strlen(in);
    out=malloc(len+1);
    if(!out)
        return NULL;
    strcpy(out, in);
#endif
    return out;
}

LPSTR tstr2str(const LPTSTR in) {
    LPSTR out;
    int len;

#ifdef UNICODE
    len=WideCharToMultiByte(CP_ACP, 0, in, -1, NULL, 0, NULL, NULL);
    if(!len)
        return NULL;
    out=malloc(len+1);
    if(!out)
        return NULL;
    len=WideCharToMultiByte(CP_ACP, 0, in, -1, out, len, NULL, NULL);
    if(!len)
        return NULL;
#else
    len=strlen(in);
    out=malloc(len+1);
    if(!out)
        return NULL;
    strcpy(out, in);
#endif
    return out;
}

#endif /* USE_WIN32 */

/* End of file.c */
