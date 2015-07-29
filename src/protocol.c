/*
 *   stunnel       Universal SSL tunnel
 *   Copyright (C) 1998-2011 Michal Trojnara <Michal.Trojnara@mirt.net>
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

/* \n is not a character expected in the string */
#define LINE "%[^\n]"
#define isprefix(a, b) (strncasecmp((a), (b), strlen(b))==0)

/* protocol-specific function prototypes */
static void cifs_client(CLI *);
static void cifs_server(CLI *);
static void pgsql_client(CLI *);
static void pgsql_server(CLI *);
static void smtp_client(CLI *);
static void smtp_server(CLI *);
static void pop3_client(CLI *);
static void pop3_server(CLI *);
static void imap_client(CLI *);
static void imap_server(CLI *);
static void nntp_client(CLI *);
static void connect_client(CLI *);
static void ntlm(CLI *);
#ifndef OPENSSL_NO_MD4
static char *ntlm1();
static char *ntlm3(char *, char *, char *);
static void crypt_DES(DES_cblock, DES_cblock, DES_cblock);
#endif
static char *base64(int, char *, int);

void negotiate(CLI *c) {
    if(!c->opt->protocol)
        return; /* no protocol negotiations */

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
        else if(!strcmp(c->opt->protocol, "pgsql"))
            pgsql_client(c);
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
        else if(!strcmp(c->opt->protocol, "imap"))
            imap_server(c);
        else if(!strcmp(c->opt->protocol, "pgsql"))
            pgsql_server(c);
        else {
            s_log(LOG_ERR, "Protocol %s not supported in server mode",
                c->opt->protocol);
            longjmp(c->err, 1);
        }
    }
    s_log(LOG_NOTICE, "Protocol negotiations succeeded");
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
    if(len>sizeof buffer-4) {
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

/* http://www.postgresql.org/docs/8.3/static/protocol-flow.html#AEN73013 */
u8 ssl_request[8]={0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f};

static void pgsql_client(CLI *c) {
    u8 buffer[1];

    write_blocking(c, c->remote_fd.fd, ssl_request, sizeof ssl_request);
    read_blocking(c, c->remote_fd.fd, buffer, 1);
    /* S - accepted, N - rejected, non-SSL preferred */
    if(buffer[0]!='S') {
        s_log(LOG_ERR, "PostgreSQL server rejected SSL");
        longjmp(c->err, 1);
    }
}

static void pgsql_server(CLI *c) {
    u8 buffer[8], ssl_ok[1]={'S'};

    memset(buffer, 0, sizeof buffer);
    read_blocking(c, c->local_rfd.fd, buffer, sizeof buffer);
    if(memcmp(buffer, ssl_request, sizeof ssl_request)) {
        s_log(LOG_ERR, "PostgreSQL client did not request SSL, rejecting");
        /* no way to send error on startup, so just drop the client */
        longjmp(c->err, 1);
    }
    write_blocking(c, c->local_wfd.fd, ssl_ok, sizeof ssl_ok);
}

static void smtp_client(CLI *c) {
    char line[STRLEN];

    do { /* copy multiline greeting */
        fdgetline(c, c->remote_fd.fd, line);
        fdputline(c, c->local_wfd.fd, line);
    } while(isprefix(line, "220-"));

    fdputline(c, c->remote_fd.fd, "EHLO localhost");
    do { /* skip multiline reply */
        fdgetline(c, c->remote_fd.fd, line);
    } while(isprefix(line, "250-"));
    if(!isprefix(line, "250 ")) { /* error */
        s_log(LOG_ERR, "Remote server is not RFC 1425 compliant");
        longjmp(c->err, 1);
    }

    fdputline(c, c->remote_fd.fd, "STARTTLS");
    do { /* skip multiline reply */
        fdgetline(c, c->remote_fd.fd, line);
    } while(isprefix(line, "220-"));
    if(!isprefix(line, "220 ")) { /* error */
        s_log(LOG_ERR, "Remote server is not RFC 2487 compliant");
        longjmp(c->err, 1);
    }
}

static void smtp_server(CLI *c) {
    char line[STRLEN];

    s_poll_init(&c->fds);
    s_poll_add(&c->fds, c->local_rfd.fd, 1, 0);
    switch(s_poll_wait(&c->fds, 0, 200)) { /* wait up to 200ms */
    case 0: /* fd not ready to read */
        s_log(LOG_DEBUG, "RFC 2487 detected");
        break;
    case 1: /* fd ready to read */
        s_log(LOG_DEBUG, "RFC 2487 not detected");
        return; /* return if RFC 2487 is not used */
    default: /* -1 */
        sockerror("RFC2487 (s_poll_wait)");
        longjmp(c->err, 1);
    }

    fdgetline(c, c->remote_fd.fd, line);
    if(!isprefix(line, "220")) {
        s_log(LOG_ERR, "Unknown server welcome");
        longjmp(c->err, 1);
    }
    fdprintf(c, c->local_wfd.fd, "%s + stunnel", line);
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
    if(isprefix(line, "CAPA")) { /* client wants RFC 2449 extensions */
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
        fdputline(c, c->local_wfd.fd,
            "* BYE stunnel: Server does not support TLS");
        s_log(LOG_ERR, "Server does not support TLS");
        longjmp(c->err, 2); /* don't reset */
    }
}

static void imap_server(CLI *c) {
    char line[STRLEN], id[STRLEN], *tail, *capa;
 
    s_poll_init(&c->fds);
    s_poll_add(&c->fds, c->local_rfd.fd, 1, 0);
    switch(s_poll_wait(&c->fds, 0, 200)) {
    case 0: /* fd not ready to read */
        s_log(LOG_DEBUG, "RFC 2595 detected");
        break;
    case 1: /* fd ready to read */
        s_log(LOG_DEBUG, "RFC 2595 not detected");
        return; /* return if RFC 2595 is not used */
    default: /* -1 */
        sockerror("RFC2595 (s_poll_wait)");
        longjmp(c->err, 1);
    }

    /* process server welcome and send it to client */
    fdgetline(c, c->remote_fd.fd, line);
    if(!isprefix(line, "* OK")) {
        s_log(LOG_ERR, "Unknown server welcome");
        longjmp(c->err, 1);
    }
    capa=strstr(line, "CAPABILITY");
    if(!capa)
        capa=strstr(line, "capability");
    if(capa)
        *capa='K'; /* disable CAPABILITY within greeting */
    fdprintf(c, c->local_wfd.fd, "%s (stunnel)", line);

    while(1) { /* process client commands */
        fdgetline(c, c->local_rfd.fd, line);
        /* split line into id and tail */
        safecopy(id, line);
        tail=strchr(id, ' ');
        if(!tail)
            break;
        *tail++='\0';

        if(isprefix(tail, "STARTTLS")) {
            fdprintf(c, c->local_wfd.fd,
                "%s OK Begin TLS negotiation now", id);
            return; /* success */
        } else if(isprefix(tail, "CAPABILITY")) {
            fdputline(c, c->remote_fd.fd, line); /* send it to server */
            fdgetline(c, c->remote_fd.fd, line); /* get the capabilites */
            if(*line=='*') {
                /* 
                 * append STARTTLS
                 * should also add LOGINDISABLED, but can't because
                 * of Mozilla bug #324138/#312009
                 * LOGIN would fail as "unexpected command", anyway
                 */
                fdprintf(c, c->local_wfd.fd, "%s STARTTLS", line);
                fdgetline(c, c->remote_fd.fd, line); /* next line */
            }
            fdputline(c, c->local_wfd.fd, line); /* forward to the client */
            tail=strchr(line, ' ');
            if(!tail || !isprefix(tail+1, "OK")) { /* not OK? */
                fdputline(c, c->local_wfd.fd,
                    "* BYE unexpected server response");
                s_log(LOG_ERR, "Unexpected server response: %s", line);
                break;
            }
        } else if(isprefix(tail, "LOGOUT")) {
            fdputline(c, c->local_wfd.fd, "* BYE server terminating");
            fdprintf(c, c->local_wfd.fd, "%s OK LOGOUT completed", id);
            break;
        } else {
            fdputline(c, c->local_wfd.fd, "* BYE stunnel: unexpected command");
            fdprintf(c, c->local_wfd.fd, "%s BAD %s unexpected", id, tail);
            s_log(LOG_ERR, "Unexpected client command %s", tail);
            break;
        }
    }    
    /* clean server shutdown */
    fdputline(c, c->remote_fd.fd, "stunnel LOGOUT");
    fdgetline(c, c->remote_fd.fd, line);
    if(*line=='*')
        fdgetline(c, c->remote_fd.fd, line);
    longjmp(c->err, 2); /* don't reset */
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
    char line[STRLEN], *encoded;

    if(!c->opt->protocol_host) {
        s_log(LOG_ERR, "protocolHost not specified");
        longjmp(c->err, 1);
    }
    fdprintf(c, c->remote_fd.fd, "CONNECT %s HTTP/1.1",
        c->opt->protocol_host);
    fdprintf(c, c->remote_fd.fd, "Host: %s", c->opt->protocol_host);
    if(c->opt->protocol_username && c->opt->protocol_password) {
        if(!strcasecmp(c->opt->protocol_authentication, "NTLM")) {
            ntlm(c);
        } else { /* basic authentication */
            safecopy(line, c->opt->protocol_username);
            safeconcat(line, ":");
            safeconcat(line, c->opt->protocol_password);
            encoded=base64(1, line, strlen(line));
            safecopy(line, encoded);
            free(encoded);
            fdprintf(c, c->remote_fd.fd, "Proxy-Authorization: basic %s",
                line);
        }
    }
    fdputline(c, c->remote_fd.fd, ""); /* empty line */
    fdgetline(c, c->remote_fd.fd, line);
    if(line[9]!='2') { /* "HTTP/1.0 200 Connection established" */
        s_log(LOG_ERR, "CONNECT request rejected");
        do { /* read all headers */
            fdgetline(c, c->remote_fd.fd, line);
        } while(*line);
        longjmp(c->err, 1);
    }
    s_log(LOG_INFO, "CONNECT request accepted");
    do {
        fdgetline(c, c->remote_fd.fd, line); /* read all headers */
    } while(*line);
}

/* 
 * NTLM code is based on the following documentation:
 * http://davenport.sourceforge.net/ntlm.html
 * http://www.innovation.ch/personal/ronald/ntlm.html
 */

#define s_min(a, b) ((a)>(b)?(b):(a))

static void ntlm(CLI *c) {
#ifndef OPENSSL_NO_MD4
    char line[STRLEN], *encoded;
    char buf[BUFSIZ], ntlm2[STRLEN];
    long content_length;

    /* send Proxy-Authorization (phase 1) */
    fdprintf(c, c->remote_fd.fd, "Proxy-Connection: keep-alive");
    fdprintf(c, c->remote_fd.fd, "Proxy-Authorization: NTLM %s", ntlm1());
    fdputline(c, c->remote_fd.fd, ""); /* empty line */
    fdgetline(c, c->remote_fd.fd, line);

    /* receive Proxy-Authenticate (phase 2) */
    if(line[9]!='4' || line[10]!='0' || line[11]!='7') { /* code 407 */
        s_log(LOG_ERR, "NTLM authorization request rejected");
        do { /* read all headers */
            fdgetline(c, c->remote_fd.fd, line);
        } while(*line);
        longjmp(c->err, 1);
    }
    *ntlm2='\0';
    content_length=0; /* no HTTP content */
    do { /* read all headers */
        fdgetline(c, c->remote_fd.fd, line);
        if(isprefix(line, "Proxy-Authenticate: NTLM "))
            safecopy(ntlm2, line+25);
        else if(isprefix(line, "Content-Length: "))
            content_length=atol(line+16);
    } while(*line);

    /* read and ignore HTTP content (if any) */
    while(content_length) {
        read_blocking(c, c->remote_fd.fd, buf, s_min(content_length, BUFSIZ));
        content_length-=s_min(content_length, BUFSIZ);
    }

    /* send Proxy-Authorization (phase 3) */
    fdprintf(c, c->remote_fd.fd, "CONNECT %s HTTP/1.1", c->opt->protocol_host);
    fdprintf(c, c->remote_fd.fd, "Host: %s", c->opt->protocol_host);
    encoded=ntlm3(c->opt->protocol_username, c->opt->protocol_password, ntlm2);
    safecopy(line, encoded);
    free(encoded);
    fdprintf(c, c->remote_fd.fd, "Proxy-Authorization: NTLM %s", line);
#else
    s_log(LOG_ERR, "NTLM authentication is not available");
    longjmp(c->err, 1);
#endif
}

#ifndef OPENSSL_NO_MD4

static char *ntlm1() {
    char phase1[16];

    memset(phase1, 0, sizeof phase1);
    strcpy(phase1, "NTLMSSP");
    phase1[8]=1; /* type: 1 */
    phase1[12]=2; /* flag: negotiate OEM */
    phase1[13]=2; /* flag: negotiate NTLM */
    return base64(1, phase1, sizeof phase1); /* encode */
}

static char *ntlm3(char *username, char *password, char *phase2) {
    MD4_CTX md4;
    char *decoded; /* decoded reply from proxy */
    char phase3[146];
    unsigned char md4_hash[21];
    unsigned int userlen=strlen(username);
    unsigned int phase3len=s_min(88+userlen, sizeof phase3);

    /* setup phase3 structure */
    memset(phase3, 0, sizeof phase3);
    strcpy(phase3, "NTLMSSP");
    phase3[8]=3;            /* type: 3 */
    phase3[16]=phase3len;   /* LM-resp off */
    phase3[20]=24;          /* NT-resp len */
    phase3[22]=24;          /* NT-Resp len */
    phase3[24]=64;          /* NT-resp off */
    phase3[32]=phase3len;   /* domain offset */
    phase3[36]=userlen;     /* user length */
    phase3[38]=userlen;     /* user length */
    phase3[40]=88;          /* user offset */
    phase3[48]=phase3len;   /* host offset */
    phase3[56]=phase3len;   /* message len */
    phase3[60]=2;           /* flag: negotiate OEM */
    phase3[61]=2;           /* flag: negotiate NTLM */

    /* calculate MD4 of UTF-16 encoded password */
    MD4_Init(&md4);
    while(*password) {
        MD4_Update(&md4, password++, 1);
        MD4_Update(&md4, "", 1); /* UTF-16 */
    }
    MD4_Final(md4_hash, &md4);
    memset(md4_hash+16, 0, 5); /* pad to 21 bytes */

    /* decode challenge and calculate response */
    decoded=base64(0, phase2, strlen(phase2)); /* decode */
    crypt_DES((unsigned char *)phase3+64,
        (unsigned char *)decoded+24, md4_hash);
    crypt_DES((unsigned char *)phase3+72,
        (unsigned char *)decoded+24, md4_hash+7);
    crypt_DES((unsigned char *)phase3+80,
        (unsigned char *)decoded+24, md4_hash+14);
    free(decoded);

    strncpy(phase3+88, username, sizeof phase3-88);

    return base64(1, phase3, phase3len); /* encode */
}

static void crypt_DES(DES_cblock dst, const_DES_cblock src, DES_cblock hash) {
    DES_cblock key;
    DES_key_schedule sched;

    /* convert key from 56 to 64 bits */
    key[0]=hash[0];
    key[1]=((hash[0]&1)<<7)|(hash[1]>>1);
    key[2]=((hash[1]&3)<<6)|(hash[2]>>2);
    key[3]=((hash[2]&7)<<5)|(hash[3]>>3);
    key[4]=((hash[3]&15)<<4)|(hash[4]>>4);
    key[5]=((hash[4]&31)<<3)|(hash[5]>>5);
    key[6]=((hash[5]&63)<<2)|(hash[6]>>6);
    key[7]=((hash[6]&127)<<1);
    DES_set_odd_parity(&key);

    /* encrypt */
    DES_set_key_unchecked(&key, &sched);
    DES_ecb_encrypt((const_DES_cblock *)src,
        (DES_cblock *)dst, &sched, DES_ENCRYPT);
}

#endif

static char *base64(int encode, char *in, int len) {
    BIO *bio, *b64;
    char *out;

    b64=BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio=BIO_new(BIO_s_mem());
    if(encode)
        bio=BIO_push(b64, bio);
    BIO_write(bio, in, len);
    (void)BIO_flush(bio); /* ignore the error if any */
    if(encode) {
        bio=BIO_pop(bio);
        BIO_free(b64);
    } else {
        bio=BIO_push(b64, bio);
    }
    len=BIO_pending(bio);
    /* 32 bytes as a safety precaution for passing decoded data to crypt_DES */
    /* len+1 to get null-terminated string on encode */
    out=calloc(len<32?32:len+1, 1);
    if(!out) {
        s_log(LOG_ERR, "Fatal memory allocation error");
        die(2);
    }
    BIO_read(bio, out, len);
    BIO_free_all(bio);
    return out;
}

/* end of protocol.c */
