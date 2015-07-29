/*
 *   stunnel       Universal SSL tunnel
 *   Copyright (c) 1998-2004 Michal Trojnara <Michal.Trojnara@mirt.net>
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

/* protocol-specific function prototypes */
static int cifs_client(CLI *);
static int cifs_server(CLI *);
static int smtp_client(CLI *);
static int smtp_server(CLI *);
static int pop3_client(CLI *);
static int pop3_server(CLI *);
static int nntp_client(CLI *);
static int nntp_server(CLI *);
static int RFC2487(int);

int negotiate(CLI *c) {
    int retval=-1; /* 0 = OK, -1 = ERROR */

    if(!c->opt->protocol)
        return 0; /* No protocol negotiations */
    log(LOG_NOTICE, "Negotiations for %s (%s side) started", c->opt->protocol,
        options.option.client ? "client" : "server");

    if(!strcmp(c->opt->protocol, "cifs"))
        retval = options.option.client ? cifs_client(c) : cifs_server(c);
    else if(!strcmp(c->opt->protocol, "smtp"))
        retval = options.option.client ? smtp_client(c) : smtp_server(c);
    else if(!strcmp(c->opt->protocol, "pop3"))
        retval = options.option.client ? pop3_client(c) : pop3_server(c);
    else if(!strcmp(c->opt->protocol, "nntp"))
        retval = options.option.client ? nntp_client(c) : nntp_server(c);
    else {
        log(LOG_ERR, "Protocol %s not supported in %s mode",
            c->opt->protocol, options.option.client ? "client" : "server");
        return -1;
    }

    if(retval)
        log(LOG_NOTICE, "Protocol negotiation failed");
    else
        log(LOG_NOTICE, "Protocol negotiation succeded");
    return retval;
}

static int cifs_client(CLI *c) {
    u8 buffer[5];
    u8 request_dummy[4] = {0x81, 0, 0, 0}; /* a zero-length request */

    if(write_blocking(c, c->remote_fd.fd, request_dummy, 4)<0)
        return -1;
    if(read_blocking(c, c->remote_fd.fd, buffer, 5)<0) {
        log(LOG_ERR, "Failed to read NetBIOS response");
        return -1;
    }
    if(buffer[0]!=0x83) { /* NB_SSN_NEGRESP */
        log(LOG_ERR, "Negative response expected");
        return -1;
    }
    if(buffer[2]!=0 || buffer[3]!=1) { /* length != 1 */
        log(LOG_ERR, "Unexpected NetBIOS response size");
        return -1;
    }
    if(buffer[4]!=0x8e) { /* use SSL */
        log(LOG_ERR, "Remote server does not require SSL");
        return -1;
    }
    return 0; /* OK */
}

static int cifs_server(CLI *c) {
    u8 buffer[128];
    u8 response_access_denied[5] = {0x83, 0, 0, 1, 0x81};
    u8 response_use_ssl[5] = {0x83, 0, 0, 1, 0x8e};
    u16 len;

    if(read_blocking(c, c->local_rfd.fd, buffer, 4)<0) /* NetBIOS header */
        return -1;
    len=buffer[3];
    len|=(u16)(buffer[2]) << 8;
    if(len>sizeof(buffer)-4) {
        log(LOG_ERR, "Received block too long");
        return -1;
    }
    if(read_blocking(c, c->local_rfd.fd, buffer+4, len)<0)
        return -1;
    if(buffer[0]!=0x81){ /* NB_SSN_REQUEST */
        log(LOG_ERR, "Client did not send session setup");
        write_blocking(c, c->local_wfd.fd, response_access_denied, 5);
        return -1;
    }
    if(write_blocking(c, c->local_wfd.fd, response_use_ssl, 5)<0)
        return -1;
    return 0; /* OK */
}

static int smtp_client(CLI *c) {
    char line[STRLEN];
    
    do { /* Copy multiline greeting */
        if(fdscanf(c, c->remote_fd.fd, "%[^\n]", line)<0)
            return -1;
        if(fdprintf(c, c->local_wfd.fd, "%s", line)<0)
            return -1;
    } while(strncasecmp(line,"220-",4)==0);

    if(fdprintf(c, c->remote_fd.fd, "EHLO localhost")<0) /* Send an EHLO command */
        return -1;
    do { /* Skip multiline reply */
        if(fdscanf(c, c->remote_fd.fd, "%[^\n]", line)<0)
            return -1;
    } while(strncasecmp(line,"250-",4)==0);
    if(strncasecmp(line,"250 ",4)!=0) { /* Error */
        log(LOG_ERR, "Remote server is not RFC 1425 compliant");
        return -1;
    }

    if(fdprintf(c, c->remote_fd.fd, "STARTTLS")<0) /* Send STARTTLS command */
        return -1;
    do { /* Skip multiline reply */
        if(fdscanf(c, c->remote_fd.fd, "%[^\n]", line)<0)
            return -1;
    } while(strncasecmp(line,"220-",4)==0);
    if(strncasecmp(line,"220 ",4)!=0) { /* Error */
        log(LOG_ERR, "Remote server is not RFC 2487 compliant");
        return -1;
    }
    return 0;
}

static int smtp_server(CLI *c) {
    char line[STRLEN];

    if(RFC2487(c->local_rfd.fd)==0)
        return 0; /* Return if RFC 2487 is not used */

    if(fdscanf(c, c->remote_fd.fd, "220%[^\n]", line)!=1) {
        log(LOG_ERR, "Unknown server welcome");
        return -1;
    }
    if(fdprintf(c, c->local_wfd.fd, "220%s + stunnel", line)<0)
        return -1;
    if(fdscanf(c, c->local_rfd.fd, "EHLO %[^\n]", line)!=1) {
        log(LOG_ERR, "Unknown client EHLO");
        return -1;
    }
    if(fdprintf(c, c->local_wfd.fd, "250-%s Welcome", line)<0)
        return -1;
    if(fdprintf(c, c->local_wfd.fd, "250 STARTTLS")<0)
        return -1;
    if(fdscanf(c, c->local_rfd.fd, "STARTTLS", line)<0) {
        log(LOG_ERR, "STARTTLS expected");
        return -1;
    }
    if(fdprintf(c, c->local_wfd.fd, "220 Go ahead")<0)
        return -1;
    return 0;
}

static int pop3_client(CLI *c) {
    char line[STRLEN];

    if(fdscanf(c, c->remote_fd.fd, "%[^\n]", line)<0)
        return -1;
    if(strncasecmp(line,"+OK ",4)) {
        log(LOG_ERR, "Unknown server welcome");
        return -1;
    }
    if(fdprintf(c, c->local_wfd.fd, "%s", line)<0)
        return -1;
    if(fdprintf(c, c->remote_fd.fd, "STLS")<0)
        return -1;
    if(fdscanf(c, c->remote_fd.fd, "%[^\n]", line)<0)
        return -1;
    if(strncasecmp(line,"+OK ",4)) {
        log(LOG_ERR, "Server does not support TLS");
        return -1;
    }
    return 0;
}

static int pop3_server(CLI *c) {
    char line[STRLEN];

    if(fdscanf(c, c->remote_fd.fd, "%[^\n]", line)<0)
        return -1;
    if(fdprintf(c, c->local_wfd.fd, "%s + stunnel", line)<0)
        return -1;
    if(fdscanf(c, c->local_rfd.fd, "%[^\n]", line)<0)
        return -1;
    if(!strncasecmp(line, "CAPA", 4)) { /* Client wants RFC 2449 extensions */
        if(fdprintf(c, c->local_wfd.fd, "-ERR Stunnel does not support capabilities")<0)
            return -1;
        if(fdscanf(c, c->local_rfd.fd, "%[^\n]", line)<0)
            return -1;
    }
    if(strncasecmp(line, "STLS", 4)) {
        log(LOG_ERR, "Client does not want TLS");
        return -1;
    }
    if(fdprintf(c, c->local_wfd.fd, "+OK Stunnel starts TLS negotiation")<0)
        return -1;

    return 0;
}

static int nntp_client(CLI *c) {
    char line[STRLEN];

    if(fdscanf(c, c->remote_fd.fd, "%[^\n]", line)<0)
        return -1;
    if(strncasecmp(line,"200 ",4) && strncasecmp(line,"201 ",4)) {
        log(LOG_ERR, "Unknown server welcome");
        return -1;
    }
    if(fdprintf(c, c->local_wfd.fd, "%s", line)<0)
        return -1;
    if(fdprintf(c, c->remote_fd.fd, "STARTTLS")<0)
        return -1;
    if(fdscanf(c, c->remote_fd.fd, "%[^\n]", line)<0)
        return -1;
    if(strncasecmp(line,"382 ",4)) {
        log(LOG_ERR, "Server does not support TLS");
        return -1;
    }
    return 0;
}

static int nntp_server(CLI *c) {
    log(LOG_ERR, "Protocol not supported in server mode");
    return -1;
}

static int RFC2487(int fd) {
    fd_set         fdsRead;
    struct timeval timeout;

    FD_ZERO(&fdsRead);
    FD_SET(fd, &fdsRead);
    timeout.tv_sec=timeout.tv_usec=0; /* don't wait */

    switch(sselect(fd+1, &fdsRead, NULL, NULL, &timeout)) {
    case 0: /* fd not ready to read */
        log(LOG_DEBUG, "RFC 2487 detected");
        return 1;
    case 1: /* fd ready to read */
        log(LOG_DEBUG, "RFC 2487 not detected");
        return 0;
    default: /* -1 */
        sockerror("RFC2487 (select)");
        return -1;
    }
}

/* End of protocol.c */
