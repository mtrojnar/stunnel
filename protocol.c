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

/* protocol-specific function prototypes */
static int smb_client(int, int, int);
static int smb_server(int, int, int);
static int smtp_client(int, int, int);
static int smtp_server(int, int, int);
static int pop3_client(int, int, int);
static int pop3_server(int, int, int);
static int nntp_client(int, int, int);
static int nntp_server(int, int, int);
static int telnet_client(int, int, int);
static int telnet_server(int, int, int);
static int RFC2487(int);

/* descriptor versions of fprintf/fscanf */
static int fdprintf(int, char *, ...);
static int fdscanf(int, char *, char *);

int negotiate(char *protocol, int client, int local_rd, int local_wr, int remote) {
    if(!protocol)
        return 0; /* No protocol negotiations */
    log(LOG_DEBUG, "Negotiations for %s(%s side) started", protocol,
        client ? "client" : "server");
    if(!strcmp(protocol, "smb")) {
        if(client)
            return smb_client(local_rd, local_wr, remote);
        else
            return smb_server(local_rd, local_wr, remote);
    }
    if(!strcmp(protocol, "smtp")) {
        if(client)
            return smtp_client(local_rd, local_wr, remote);
        else
            return smtp_server(local_rd, local_wr, remote);
    }
    if(!strcmp(protocol, "pop3")) {
        if(client)
            return pop3_client(local_rd, local_wr, remote);
        else
            return pop3_server(local_rd, local_wr, remote);
    }
    if(!strcmp(protocol, "nntp")) {
        if(client)
            return nntp_client(local_rd, local_wr, remote);
        else
            return nntp_server(local_rd, local_wr, remote);
    }
    if(!strcmp(protocol, "telnet")) {
        if(client)
            return telnet_client(local_rd, local_wr, remote);
        else
            return telnet_server(local_rd, local_wr, remote);
    }
    log(LOG_ERR, "Protocol %s not supported in %s mode",
        protocol, client ? "client" : "server");
    return -1;
}

static int smb_client(int local_rd, int local_wr, int remote) {
    log(LOG_ERR, "Protocol not supported");
    return -1;
}

static int smb_server(int local_rd, int local_wr, int remote) {
    log(LOG_ERR, "Protocol not supported");
    return -1;
}

static int smtp_client(int local_rd, int local_wr, int remote) {
    char line[STRLEN];
    
    do { /* Copy multiline greeting */
        if(fdscanf(remote, "%[^\n]", line)<0)
            return -1;
        if(fdprintf(local_wr, line)<0)
            return -1;
    } while(strncmp(line,"220-",4)==0);

    if(fdprintf(remote, "EHLO localhost")<0) /* Send an EHLO command */
        return -1;
    do { /* Skip multiline reply */
        if(fdscanf(remote, "%[^\n]", line)<0)
            return -1;
    } while(strncmp(line,"250-",4)==0);
    if(strncmp(line,"250 ",4)!=0) { /* Error */
        log(LOG_ERR, "Remote server is not RFC 1425 compliant");
        return -1;
    }

    if(fdprintf(remote, "STARTTLS")<0) /* Send STARTTLS command */
        return -1;
    do { /* Skip multiline reply */
        if(fdscanf(remote, "%[^\n]", line)<0)
            return -1;
    } while(strncmp(line,"220-",4)==0);
    if(strncmp(line,"220 ",4)!=0) { /* Error */
        log(LOG_ERR, "Remote server is not RFC 2487 compliant");
        return -1;
    }
    return 0;
}

static int smtp_server(int local_rd, int local_wr, int remote) {
    char line[STRLEN];

    if(RFC2487(local_rd)==0)
        return 0; /* Return if RFC 2487 is not used */

    if(fdscanf(remote, "220%[^\n]", line)!=1) {
        log(LOG_ERR, "Unknown server welcome");
        return -1;
    }
    if(fdprintf(local_wr, "220%s + stunnel", line)<0)
        return -1;
    if(fdscanf(local_rd, "EHLO %[^\n]", line)!=1) {
        log(LOG_ERR, "Unknown client EHLO");
        return -1;
    }
    if(fdprintf(local_wr, "250-%s Welcome", line)<0)
        return -1;
    if(fdprintf(local_wr, "250 STARTTLS")<0)
        return -1;
    if(fdscanf(local_rd, "STARTTLS", line)<0) {
        log(LOG_ERR, "STARTTLS expected");
        return -1;
    }
    if(fdprintf(local_wr, "220 Go ahead", line)<0)
        return -1;
    return 0;
}

static int pop3_client(int local_rd, int local_wr, int remote) {
    char line[STRLEN];

    fdscanf(remote, "%[^\n]", line);
    if(strncmp(line,"+OK ",4)) {
        log(LOG_ERR, "Unknown server welcome");
        return -1;
    }
    if(fdprintf(local_wr, line)<0)
        return -1;
    if(fdprintf(remote, "STLS")<0)
        return -1;
    fdscanf(remote, "%[^\n]", line);
    if(strncmp(line,"+OK ",4)) {
        log(LOG_ERR, "Server does not support TLS");
        return -1;
    }
    return 0;
}

static int pop3_server(int local_rd, int local_wr, int remote) {
    log(LOG_ERR, "Protocol not supported in server mode");
    return -1;
}

static int nntp_client(int local_rd, int local_wr, int remote) {
    char line[STRLEN];

    fdscanf(remote, "%[^\n]", line);
    if(strncmp(line,"200 ",4) && strncmp(line,"201 ",4)) {
        log(LOG_ERR, "Unknown server welcome");
        return -1;
    }
    if(fdprintf(local_wr, line)<0)
        return -1;
    if(fdprintf(remote, "STARTTLS")<0)
        return -1;
    fdscanf(remote, "%[^\n]", line);
    if(strncmp(line,"382 ",4)) {
        log(LOG_ERR, "Server does not support TLS");
        return -1;
    }
    return 0;
}

static int nntp_server(int local_rd, int local_wr, int remote) {
    log(LOG_ERR, "Protocol not supported in server mode");
    return -1;
}

static int telnet_client(int local_rd, int local_wr, int remote) {
    log(LOG_ERR, "Protocol not supported");
    return -1;
}

static int telnet_server(int local_rd, int local_wr, int remote) {
    log(LOG_ERR, "Protocol not supported");
    return -1;
}

static int fdprintf(int fd, char *format, ...) {
    va_list arglist;
    char line[STRLEN], logline[STRLEN];
    char *crlf="\r\n";
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
    safecopy(logline, line);
    safestring(logline);
    log(LOG_DEBUG, " -> %s", line);
    return len;
}

static int fdscanf(int fd, char *format, char *buffer) {
    char line[STRLEN], logline[STRLEN];
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
    safecopy(logline, line);
    safestring(logline);
    log(LOG_DEBUG, " <- %s", logline);
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

static int RFC2487(int fd) {
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

/* End of protocol.c */
