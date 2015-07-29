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
#include "client.h"

/* protocol-specific function prototypes */
static int smb_client(CLI *);
static int smb_server(CLI *);
static int smtp_client(CLI *);
static int smtp_server(CLI *);
static int pop3_client(CLI *);
static int pop3_server(CLI *);
static int nntp_client(CLI *);
static int nntp_server(CLI *);
static int telnet_client(CLI *);
static int telnet_server(CLI *);
static int RFC2487(int);

int negotiate(char *protocol, int client, CLI *c) {
    if(!protocol)
        return 0; /* No protocol negotiations */
    if(!c)
        return 0; /* No client present */
    log(LOG_DEBUG, "Negotiations for %s(%s side) started", protocol,
        client ? "client" : "server");
    if(!strcmp(protocol, "smb")) {
        if(client)
            return smb_client(c);
        else
            return smb_server(c);
    }
    if(!strcmp(protocol, "smtp")) {
        if(client)
            return smtp_client(c);
        else
            return smtp_server(c);
    }
    if(!strcmp(protocol, "pop3")) {
        if(client)
            return pop3_client(c);
        else
            return pop3_server(c);
    }
    if(!strcmp(protocol, "nntp")) {
        if(client)
            return nntp_client(c);
        else
            return nntp_server(c);
    }
    if(!strcmp(protocol, "telnet")) {
        if(client)
            return telnet_client(c);
        else
            return telnet_server(c);
    }
    log(LOG_ERR, "Protocol %s not supported in %s mode",
        protocol, client ? "client" : "server");
    return -1;
}

static int smb_client(CLI *c) {
    log(LOG_ERR, "Protocol not supported");
    return -1;
}

static int smb_server(CLI *c) {
    log(LOG_ERR, "Protocol not supported");
    return -1;
}

static int smtp_client(CLI *c) {
    char line[STRLEN];
    
    do { /* Copy multiline greeting */
        if(fdscanf(c->remote_fd, "%[^\n]", line)<0)
            return -1;
        if(fdprintf(c->local_wfd, "%s", line)<0)
            return -1;
    } while(strncmp(line,"220-",4)==0);

    if(fdprintf(c->remote_fd, "EHLO localhost")<0) /* Send an EHLO command */
        return -1;
    do { /* Skip multiline reply */
        if(fdscanf(c->remote_fd, "%[^\n]", line)<0)
            return -1;
    } while(strncmp(line,"250-",4)==0);
    if(strncmp(line,"250 ",4)!=0) { /* Error */
        log(LOG_ERR, "Remote server is not RFC 1425 compliant");
        return -1;
    }

    if(fdprintf(c->remote_fd, "STARTTLS")<0) /* Send STARTTLS command */
        return -1;
    do { /* Skip multiline reply */
        if(fdscanf(c->remote_fd, "%[^\n]", line)<0)
            return -1;
    } while(strncmp(line,"220-",4)==0);
    if(strncmp(line,"220 ",4)!=0) { /* Error */
        log(LOG_ERR, "Remote server is not RFC 2487 compliant");
        return -1;
    }
    return 0;
}

static int smtp_server(CLI *c) {
    char line[STRLEN];

    if(RFC2487(c->local_rfd)==0)
        return 0; /* Return if RFC 2487 is not used */

    if(fdscanf(c->remote_fd, "220%[^\n]", line)!=1) {
        log(LOG_ERR, "Unknown server welcome");
        return -1;
    }
    if(fdprintf(c->local_wfd, "220%s + stunnel", line)<0)
        return -1;
    if(fdscanf(c->local_rfd, "EHLO %[^\n]", line)!=1) {
        log(LOG_ERR, "Unknown client EHLO");
        return -1;
    }
    if(fdprintf(c->local_wfd, "250-%s Welcome", line)<0)
        return -1;
    if(fdprintf(c->local_wfd, "250 STARTTLS")<0)
        return -1;
    if(fdscanf(c->local_rfd, "STARTTLS", line)<0) {
        log(LOG_ERR, "STARTTLS expected");
        return -1;
    }
    if(fdprintf(c->local_wfd, "220 Go ahead", line)<0)
        return -1;
    return 0;
}

static int pop3_client(CLI *c) {
    char line[STRLEN];

    if(fdscanf(c->remote_fd, "%[^\n]", line)<0)
        return -1;
    if(strncmp(line,"+OK ",4)) {
        log(LOG_ERR, "Unknown server welcome");
        return -1;
    }
    if(fdprintf(c->local_wfd, "%s", line)<0)
        return -1;
    if(fdprintf(c->remote_fd, "STLS")<0)
        return -1;
    if(fdscanf(c->remote_fd, "%[^\n]", line)<0)
        return -1;
    if(strncmp(line,"+OK ",4)) {
        log(LOG_ERR, "Server does not support TLS");
        return -1;
    }
    return 0;
}

static int pop3_server(CLI *c) {
    char line[STRLEN];

    if(fdscanf(c->remote_fd, "%[^\n]", line)<0)
        return -1;
    if(fdprintf(c->local_wfd, "%s + stunnel", line)<0)
        return -1;
    if(fdscanf(c->local_rfd, "%[^\n]", line)<0)
        return -1;
    if(!strncmp(line, "CAPA", 4)) { /* Client wants RFC 2449 extensions */
        if(fdprintf(c->local_wfd, "-ERR Stunnel does not support capabilities")<0)
            return -1;
        if(fdscanf(c->local_rfd, "%[^\n]", line)<0)
            return -1;
    }
    if(strncmp(line, "STLS", 4)) {
        log(LOG_ERR, "Client does not want TLS");
        return -1;
    }
    if(fdprintf(c->local_wfd, "+OK Stunnel starts TLS negotiation")<0)
        return -1;

    return 0;
}

static int nntp_client(CLI *c) {
    char line[STRLEN];

    if(fdscanf(c->remote_fd, "%[^\n]", line)<0)
        return -1;
    if(strncmp(line,"200 ",4) && strncmp(line,"201 ",4)) {
        log(LOG_ERR, "Unknown server welcome");
        return -1;
    }
    if(fdprintf(c->local_wfd, "%s", line)<0)
        return -1;
    if(fdprintf(c->remote_fd, "STARTTLS")<0)
        return -1;
    if(fdscanf(c->remote_fd, "%[^\n]", line)<0)
        return -1;
    if(strncmp(line,"382 ",4)) {
        log(LOG_ERR, "Server does not support TLS");
        return -1;
    }
    return 0;
}

static int nntp_server(CLI *c) {
    log(LOG_ERR, "Protocol not supported in server mode");
    return -1;
}

static int telnet_client(CLI *c) {
    log(LOG_ERR, "Protocol not supported");
    return -1;
}

static int telnet_server(CLI *c) {
    log(LOG_ERR, "Protocol not supported");
    return -1;
}

static int RFC2487(int fd) {
    fd_set         fdsRead;
    struct timeval timeout;

    FD_ZERO(&fdsRead);
    FD_SET(fd, &fdsRead);
    timeout.tv_sec=timeout.tv_usec=0; /* don't wait */

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
