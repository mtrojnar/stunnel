/*
 *   stunnel       Universal SSL tunnel
 *   Copyright (c) 1998-2006 Michal Trojnara <Michal.Trojnara@mirt.net>
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

/* \n is not a character expected in the string */
#define LINE "%[^\n]"

#define isprefix(a, b) (strncasecmp((a), (b), strlen(b))==0)

/* protocol-specific function prototypes */
static void cifs_client(CLI *);
static void cifs_server(CLI *);
static void smtp_client(CLI *);
static void smtp_server(CLI *);
static void pop3_client(CLI *);
static void pop3_server(CLI *);
static void imap_client(CLI *);
static void nntp_client(CLI *);
static void connect_client(CLI *);

void negotiate(CLI *c) {
    if(!c->opt->protocol)
        return; /* No protocol negotiations */

    s_log(LOG_NOTICE, "Negotiations for %s (%s side) started", c->opt->protocol,
        c->opt->option.client ? "client" : "server");

    if(c->opt->option.client) {
        if(!strcmp(c->opt->protocol, "cifs"))
            cifs_client(c);
        else if(!strcmp(c->opt->protocol, "smtp"))
            smtp_client(c);
        else if(!strcmp(c->opt->protocol, "pop3"))
            pop3_client(c);
        else if(!strcmp(c->opt->protocol, "imap"))
            imap_client(c);
        else if(!strcmp(c->opt->protocol, "nntp"))
            nntp_client(c);
        else if(!strcmp(c->opt->protocol, "connect"))
            connect_client(c);
        else {
            s_log(LOG_ERR, "Protocol %s not supported in client mode",
                c->opt->protocol);
            longjmp(c->err, 1);
        }
    } else {
        if(!strcmp(c->opt->protocol, "cifs"))
            cifs_server(c);
        else if(!strcmp(c->opt->protocol, "smtp"))
            smtp_server(c);
        else if(!strcmp(c->opt->protocol, "pop3"))
            pop3_server(c);
        else {
            s_log(LOG_ERR, "Protocol %s not supported in server mode",
                c->opt->protocol);
            longjmp(c->err, 1);
        }
    }
    s_log(LOG_NOTICE, "Protocol negotiations succeded");
}

static void cifs_client(CLI *c) {
    u8 buffer[5];
    u8 request_dummy[4] = {0x81, 0, 0, 0}; /* a zero-length request */

    write_blocking(c, c->remote_fd.fd, request_dummy, 4);
    read_blocking(c, c->remote_fd.fd, buffer, 5);
    if(buffer[0]!=0x83) { /* NB_SSN_NEGRESP */
        s_log(LOG_ERR, "Negative response expected");
        longjmp(c->err, 1);
    }
    if(buffer[2]!=0 || buffer[3]!=1) { /* length != 1 */
        s_log(LOG_ERR, "Unexpected NetBIOS response size");
        longjmp(c->err, 1);
    }
    if(buffer[4]!=0x8e) { /* use SSL */
        s_log(LOG_ERR, "Remote server does not require SSL");
        longjmp(c->err, 1);
    }
}

static void cifs_server(CLI *c) {
    u8 buffer[128];
    u8 response_access_denied[5] = {0x83, 0, 0, 1, 0x81};
    u8 response_use_ssl[5] = {0x83, 0, 0, 1, 0x8e};
    u16 len;

    read_blocking(c, c->local_rfd.fd, buffer, 4) ;/* NetBIOS header */
    len=buffer[3];
    len|=(u16)(buffer[2]) << 8;
    if(len>sizeof(buffer)-4) {
        s_log(LOG_ERR, "Received block too long");
        longjmp(c->err, 1);
    }
    read_blocking(c, c->local_rfd.fd, buffer+4, len);
    if(buffer[0]!=0x81){ /* NB_SSN_REQUEST */
        s_log(LOG_ERR, "Client did not send session setup");
        write_blocking(c, c->local_wfd.fd, response_access_denied, 5);
        longjmp(c->err, 1);
    }
    write_blocking(c, c->local_wfd.fd, response_use_ssl, 5);
}

static void smtp_client(CLI *c) {
    char line[STRLEN];
    
    do { /* Copy multiline greeting */
        fdgetline(c, c->remote_fd.fd, line);
        fdputline(c, c->local_wfd.fd, line);
    } while(isprefix(line, "220-"));

    fdputline(c, c->remote_fd.fd, "EHLO localhost");
    do { /* Skip multiline reply */
        fdgetline(c, c->remote_fd.fd, line);
    } while(isprefix(line, "250-"));
    if(!isprefix(line, "250 ")) { /* Error */
        s_log(LOG_ERR, "Remote server is not RFC 1425 compliant");
        longjmp(c->err, 1);
    }

    fdputline(c, c->remote_fd.fd, "STARTTLS");
    do { /* Skip multiline reply */
        fdgetline(c, c->remote_fd.fd, line);
    } while(isprefix(line, "220-"));
    if(!isprefix(line, "220 ")) { /* Error */
        s_log(LOG_ERR, "Remote server is not RFC 2487 compliant");
        longjmp(c->err, 1);
    }
}

static void smtp_server(CLI *c) {
    char line[STRLEN];

    s_poll_zero(&c->fds);
    s_poll_add(&c->fds, c->local_rfd.fd, 1, 0);
    switch(s_poll_wait(&c->fds, 0, 100)) {
    case 0: /* fd not ready to read */
        s_log(LOG_DEBUG, "RFC 2487 detected");
        break;
    case 1: /* fd ready to read */
        s_log(LOG_DEBUG, "RFC 2487 not detected");
        return; /* Return if RFC 2487 is not used */
    default: /* -1 */
        sockerror("RFC2487 (s_poll_wait)");
        longjmp(c->err, 1);
    }

    fdgetline(c, c->remote_fd.fd, line);
    if(!isprefix(line, "220")) {
        s_log(LOG_ERR, "Unknown server welcome");
        longjmp(c->err, 1);
    }
    fdprintf(c, c->local_wfd.fd, "220%s + stunnel", line);
    fdgetline(c, c->local_rfd.fd, line);
    if(!isprefix(line, "EHLO ")) {
        s_log(LOG_ERR, "Unknown client EHLO");
        longjmp(c->err, 1);
    }
    fdprintf(c, c->local_wfd.fd, "250-%s Welcome", line);
    fdputline(c, c->local_wfd.fd, "250 STARTTLS");
    fdgetline(c, c->local_rfd.fd, line);
    if(!isprefix(line, "STARTTLS")) {
        s_log(LOG_ERR, "STARTTLS expected");
        longjmp(c->err, 1);
    }
    fdputline(c, c->local_wfd.fd, "220 Go ahead");
}

static void pop3_client(CLI *c) {
    char line[STRLEN];

    fdgetline(c, c->remote_fd.fd, line);
    if(!isprefix(line, "+OK ")) {
        s_log(LOG_ERR, "Unknown server welcome");
        longjmp(c->err, 1);
    }
    fdputline(c, c->local_wfd.fd, line);
    fdputline(c, c->remote_fd.fd, "STLS");
    fdgetline(c, c->remote_fd.fd, line);
    if(!isprefix(line, "+OK ")) {
        s_log(LOG_ERR, "Server does not support TLS");
        longjmp(c->err, 1);
    }
}

static void pop3_server(CLI *c) {
    char line[STRLEN];

    fdgetline(c, c->remote_fd.fd, line);
    fdprintf(c, c->local_wfd.fd, "%s + stunnel", line);
    fdgetline(c, c->local_rfd.fd, line);
    if(isprefix(line, "CAPA")) { /* Client wants RFC 2449 extensions */
        fdputline(c, c->local_wfd.fd, "-ERR Stunnel does not support capabilities");
        fdgetline(c, c->local_rfd.fd, line);
    }
    if(!isprefix(line, "STLS")) {
        s_log(LOG_ERR, "Client does not want TLS");
        longjmp(c->err, 1);
    }
    fdputline(c, c->local_wfd.fd, "+OK Stunnel starts TLS negotiation");
}

static void imap_client(CLI *c) {
    char line[STRLEN];

    fdgetline(c, c->remote_fd.fd, line);
    if(!isprefix(line, "* OK")) {
        s_log(LOG_ERR, "Unknown server welcome");
        longjmp(c->err, 1);
    }
    fdputline(c, c->local_wfd.fd, line);
    fdputline(c, c->remote_fd.fd, "stunnel STARTTLS");
    fdgetline(c, c->remote_fd.fd, line);
    if(!isprefix(line, "stunnel OK")) {
        s_log(LOG_ERR, "Server does not support TLS");
        longjmp(c->err, 1);
    }
}

static void nntp_client(CLI *c) {
    char line[STRLEN];

    fdgetline(c, c->remote_fd.fd, line);
    if(!isprefix(line, "200 ") && !isprefix(line, "201 ")) {
        s_log(LOG_ERR, "Unknown server welcome");
        longjmp(c->err, 1);
    }
    fdputline(c, c->local_wfd.fd, line);
    fdputline(c, c->remote_fd.fd, "STARTTLS");
    fdgetline(c, c->remote_fd.fd, line);
    if(!isprefix(line, "382 ")) {
        s_log(LOG_ERR, "Server does not support TLS");
        longjmp(c->err, 1);
    }
}

static void connect_client(CLI *c) {
    char line[STRLEN];

    if(!c->opt->protocol_host) {
        s_log(LOG_ERR, "protocolHost not specified");
        longjmp(c->err, 1);
    }
    fdprintf(c, c->remote_fd.fd, "CONNECT %s HTTP/1.1",
        c->opt->protocol_host);
    fdprintf(c, c->remote_fd.fd, "Host: %s", c->opt->protocol_host);
    if(c->opt->protocol_credentials)
        fdprintf(c, c->remote_fd.fd, "Proxy-Authorization: basic %s",
            c->opt->protocol_credentials);
    fdputline(c, c->remote_fd.fd, ""); /* empty line */
    fdgetline(c, c->remote_fd.fd, line);
    if(line[9]!='2') { /* "HTTP/1.0 200 Connection established" */
        s_log(LOG_ERR, "CONNECT request rejected");
        do {
            fdgetline(c, c->remote_fd.fd, line); /* read all headers */
        } while(line[0]);
        longjmp(c->err, 1);
    }
    s_log(LOG_INFO, "CONNECT request accepted");
    do {
        fdgetline(c, c->remote_fd.fd, line); /* read all headers */
    } while(line[0]);
}

/* End of protocol.c */
