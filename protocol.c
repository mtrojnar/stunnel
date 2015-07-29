/*
 *   stunnel       Universal SSL tunnel
 *   Copyright (c) 1998-2001 Michal Trojnara <Michal.Trojnara@mirt.net>
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
 */

#include "common.h"

#ifdef USE_WIN32
#define Win32_Winsock
#include <windows.h>
#endif

#include <stdio.h>
#include <stdarg.h>    /* for va_* */
#include <unistd.h>    /* for read(), write() */
#include <string.h>
#include <sys/time.h>  /* for select() */
#include <sys/types.h> /* Ultrix needs it for fd_set */

/* protocol-specific function prototypes */
static int smb_client(int, int);
static int smb_server(int, int);
static int smtp_client(int, int);
static int smtp_server(int, int);
static int telnet_client(int, int);
static int telnet_server(int, int);
static int RFC2487(int);

/* descriptor versions of fprintf/fscanf */
static int fdprintf(int, char *, ...);
static int fdscanf(int, char *, char *);

int negotiate(char *protocol, int client, int local, int remote)
{
    if(!protocol)
        return 0; /* No protocol negotiations */
    log(LOG_DEBUG, "Negotiations for %s(%s side) started", protocol,
        client ? "client" : "server");
    if(!strcmp(protocol, "smb")) {
        if(client)
            return smb_client(local, remote);
        else
            return smb_server(local, remote);
    }
    if(!strcmp(protocol, "smtp")) {
        if(client)
            return smtp_client(local, remote);
        else
            return smtp_server(local, remote);
    }
    if(!strcmp(protocol, "telnet")) {
        if(client)
            return telnet_client(local, remote);
        else
            return telnet_server(local, remote);
    }
    log(LOG_ERR, "Protocol %s not supported in %s mode",
        protocol, client ? "client" : "server");
    return -1;
}

static int smb_client(int local, int remote)
{
    log(LOG_ERR, "Protocol not supported");
    return -1;
}

static int smb_server(int local, int remote)
{
    log(LOG_ERR, "Protocol not supported");
    return -1;
}

static int smtp_client(int local, int remote)
{
    log(LOG_ERR, "Protocol not supported");
    return -1;
}

static int smtp_server(int local, int remote)
{
    char line[STRLEN];

    if(RFC2487(local)==0)
        return 0; /* Return if RFC 2487 is not used */

    if(fdscanf(remote, "220%[^\n]", line)!=1) {
        log(LOG_ERR, "Unknown server welcome");
        return -1;
    }
    if(fdprintf(local, "220%s + stunnel", line)<0)
        return -1;
    if(fdscanf(local, "EHLO %[^\n]", line)!=1) {
        log(LOG_ERR, "Unknown client EHLO");
        return -1;
    }
    if(fdprintf(local, "250-%s Welcome", line)<0)
        return -1;
    if(fdprintf(local, "250 STARTTLS")<0)
        return -1;
    if(fdscanf(local, "STARTTLS", line)<0) {
        log(LOG_ERR, "STARTTLS expected");
        return -1;
    }
    if(fdprintf(local, "220 Go ahead", line)<0)
        return -1;
    return 0;
}

static int telnet_client(int local, int remote)
{
    log(LOG_ERR, "Protocol not supported");
    return -1;
}

static int telnet_server(int local, int remote)
{
    log(LOG_ERR, "Protocol not supported");
    return -1;
}

static int fdprintf(int fd, char *format, ...)
{
    va_list arglist;
    char line[STRLEN], *crlf="\r\n";
    int len;

    va_start(arglist, format);
#ifdef HAVE_VSNPRINTF
    len=vsnprintf(line, STRLEN, format, arglist);
#else
    len=vsprintf(line, format, arglist);
#endif
    va_end(arglist);
    if(writesocket(fd, line, len)<0) {
        sockerror("writesocket (fdprintf)");
        return -1;
    }
    if(writesocket(fd, crlf, 2)<0) {
        sockerror("writesocket (fdprintf)");
        return -1;
    }
    log(LOG_DEBUG, " -> %s", line);
    return len;
}

static int fdscanf(int fd, char *format, char *buffer)
{
    char line[STRLEN];
    int ptr;

    ptr=0;
    for(;;) {
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
        if(++ptr==STRLEN-1)
            break;
    }
    line[ptr]='\0';
    log(LOG_DEBUG, " <- %s", line);
    return sscanf(line, format, buffer);
}

/* 
*
* stunnel can recognize a TLS-RFC2487 connection 
* Use checkConnectionTyp routine from sendmail-tls.c
* If response is true return 1
*
* Pascual Perez       pps@posta.unizar.es 
* Borja Perez         borja@posta.unizar.es 
*
*/

static int RFC2487(int fd)
{
    fd_set         fdsRead;
    struct timeval timeout;

    FD_ZERO(&fdsRead);
    FD_SET(fd, &fdsRead);
    memset(&timeout, 0, sizeof(timeout)); /* don't wait */

    switch(select(fd+1, &fdsRead, NULL, NULL, &timeout)) {
    case 0: /* fd not ready to read */
        log(LOG_DEBUG, "RFC 2487 detected");
        return 1;
    case 1: /* fd ready to read */
        log(LOG_DEBUG, "RFC 2487 not detected");
        return 0;
    }
    sockerror("RFC2487 (select)");
    return -1;
}

