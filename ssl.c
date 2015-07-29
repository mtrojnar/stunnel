/*
 *   stunnel       Universal SSL tunnel
 *   Copyright (c) 1998-1999 Michal Trojnara <Michal.Trojnara@centertel.pl>
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

/* For US citizens having problems with patents, undefined by default */
/* #define NO_RSA */

/* DH is an experimental code, so feel free to uncomment the next line */
/* #define NO_DH */

/* Length of temporary RSA key */
#ifndef NO_RSA
#define KEYLENGTH      512
#endif /* NO_RSA */

/* Undefine if you have problems with make_sockets() */
#define INET_SOCKET_PAIR

/* Max number of children */
#define MAX_CLIENTS    100

/* I/O buffer size */
#define BUFFSIZE       8192

#ifdef USE_WIN32

/* default certificate */
#define DEFAULT_CERT "stunnel.pem"

/* additional directory (hashed!) with trusted CA client certs */
#define CA_DIR "mytrusted"

/* certificate used for sign our client certs */
#define CLIENT_CA "cacert.pem"

#else /* USE_WIN32 */

/* directory for certificate */
#define CERT_DIR ssldir "/certs"

/* default certificate */
#define DEFAULT_CERT CERT_DIR "/stunnel.pem"

/* additional directory (hashed!) with trusted CA client certs */
#define CA_DIR CERT_DIR "/mytrusted"

/* certificate used for sign our client certs */
#define CLIENT_CA ssldir "/bin/demoCA/cacert.pem"

#endif /* USE_WIN32 */

#include "common.h"

#include <stdio.h>

#ifdef HAVE_OPENSSL
#include <openssl/lhash.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#else
#include <lhash.h>
#include <ssl.h>
#include <err.h>
#endif

#ifdef USE_WIN32

#define Win32_Winsock
#include <windows.h>
#include <io.h>
#include <stdlib.h>
#include <process.h>
#include <malloc.h>
#include <string.h>
#include <sys/stat.h>
#define ECONNRESET WSAECONNRESET
#define ENOTSOCK WSAENOTSOCK

#else /* defined USE_WIN32 */

/* General headers */
#include <errno.h>       /* errno */
#include <sys/stat.h>    /* stat */
#include <signal.h>      /* signal */
#include <sys/wait.h>    /* wait */
#include <string.h>      /* strerror */
#include <ctype.h>
#include <stdlib.h>
#include <netdb.h>
#ifdef HAVE_GETOPT_H
#include <getopt.h>      /* getopt */
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>      /* getpid, fork, execvp, exit */
#endif

/* Networking headers */
#include <sys/types.h>   /* u_short, u_long */
#include <netinet/in.h>  /* struct sockaddr_in */
#include <sys/socket.h>  /* getpeername */
#include <arpa/inet.h>   /* inet_ntoa */
#include <sys/time.h>    /* select */
#include <sys/ioctl.h>   /* ioctl */
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>  /* for aix */
#endif

    /* TCP wrapper */
#ifdef USE_LIBWRAP
#include <tcpd.h>
int allow_severity=LOG_NOTICE;
int deny_severity=LOG_WARNING;
#endif

#endif /* defined USE_WIN32 */

extern server_options options;

int auth_user(struct sockaddr_in *);

    /* SSL functions */
void context_init();
void context_free();
void client(int);
static int transfer(SSL *, int);
#ifndef NO_RSA
static RSA *tmp_rsa_cb(SSL *, int, int);
#endif /* NO_RSA */
static int verify_callback (int, X509_STORE_CTX *);
static void info_callback(SSL *, int, int);
static void print_stats();
static void print_cipher(SSL *);
static void sslerror(char *);

/* Correct callback definitions overriding ssl.h */
#ifndef NO_RSA
#ifdef SSL_CTX_set_tmp_rsa_callback
    #undef SSL_CTX_set_tmp_rsa_callback
#endif
#define SSL_CTX_set_tmp_rsa_callback(ctx,cb) \
    SSL_CTX_ctrl(ctx,SSL_CTRL_SET_TMP_RSA_CB,0,(char *)cb)
#endif /* NO_RSA */

SSL_CTX *ctx;           /* global SSL context */
#ifndef NO_RSA
RSA *rsa_tmp;           /* temporary RSA key */
#endif /* NO_RSA */
#if SSLEAY_VERSION_NUMBER >= 0x0922
static unsigned char *sid_ctx=(unsigned char *)"stunnel SID";
    /* const allowed here */
#endif

void context_init() /* init SSL */
{
#ifndef NO_DH
    static DH *dh=NULL;
    BIO *bio=NULL;
#endif /* NO_DH */

    SSLeay_add_ssl_algorithms();
    SSL_load_error_strings();
    if(options.option&OPT_CLIENT) {
        ctx=SSL_CTX_new(TLSv1_client_method());
    } else { /* Server mode */
        ctx=SSL_CTX_new(TLSv1_server_method());
#ifndef NO_RSA
        log(LOG_DEBUG, "Generating %d bit temporary RSA key...", KEYLENGTH);
#if SSLEAY_VERSION_NUMBER <= 0x0800
        rsa_tmp=RSA_generate_key(KEYLENGTH, RSA_F4, NULL);
#else
        rsa_tmp=RSA_generate_key(KEYLENGTH, RSA_F4, NULL, NULL);
#endif
        if(!rsa_tmp) {
            sslerror("tmp_rsa_cb");
            exit(1);
        }
        log(LOG_DEBUG, "Temporary RSA key generated");
        if(!SSL_CTX_set_tmp_rsa_callback(ctx, tmp_rsa_cb)) {
            sslerror("SSL_CTX_set_tmp_rsa_callback");
            exit(1);
        }
#endif /* NO_RSA */
#ifndef NO_DH
        if(!(bio=BIO_new_file(options.certfile, "r"))) {
            log(LOG_ERR, "DH: Could not read %s: %s", options.certfile,
                strerror(errno));
            goto dh_failed;
        }
        if(!(dh=PEM_read_bio_DHparams(bio, NULL, NULL))) {
            log(LOG_ERR, "Could not load DH parameters from %s",
                options.certfile);
            goto dh_failed;
        }
        SSL_CTX_set_tmp_dh(ctx, dh);
        log(LOG_DEBUG, "Diffie-Hellman initialized with %d bit key",
            8*DH_size(dh));
        goto dh_done;
dh_failed:
        log(LOG_WARNING, "Diffie-Hellman initialization failed");
dh_done:
        if(bio)
            BIO_free(bio);
        if(dh)
            DH_free(dh);
#endif /* NO_DH */
    }
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_BOTH);
    SSL_CTX_set_timeout(ctx, options.session_timeout);
    if(options.option&OPT_CERT) {
        log(LOG_DEBUG, "Certificate: %s", options.certfile);
        if(!SSL_CTX_use_certificate_file(ctx, options.certfile,
                SSL_FILETYPE_PEM)) {
            sslerror("SSL_CTX_use_certificate_file");
            exit(1);
        }
#ifdef NO_RSA
        if(!SSL_CTX_use_PrivateKey_file(ctx, options.certfile,
                SSL_FILETYPE_PEM)) {
            sslerror("SSL_CTX_use_PrivateKey_file");
            exit(1);
        }
#else /* NO_RSA */
        if(!SSL_CTX_use_RSAPrivateKey_file(ctx, options.certfile,
                SSL_FILETYPE_PEM)) {
            sslerror("SSL_CTX_use_RSAPrivateKey_file");
            exit(1);
        }
#endif /* NO_RSA */
    }
    if(options.verify_level!=SSL_VERIFY_NONE) {
        if ((!SSL_CTX_set_default_verify_paths(ctx))
                || (!SSL_CTX_load_verify_locations(ctx, CLIENT_CA,
                options.clientdir))){
            sslerror("X509_load_verify_locations");
            exit(1);
        }
        SSL_CTX_set_verify(ctx, options.verify_level, verify_callback);
        SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(CLIENT_CA));
        if (options.verify_use_only_my)
            log(LOG_NOTICE, "Peer certificate location %s", options.clientdir);
    }
    if(!SSL_CTX_set_info_callback(ctx, info_callback)) {
        sslerror("SSL_CTX_set_info_callback");
        exit(1);
    }
    if(options.cipher_list) {
        if (!SSL_CTX_set_cipher_list(ctx, options.cipher_list)) {
            sslerror("SSL_CTX_set_cipher_list");
            exit(1);
        }
    }
}

void context_free() /* free SSL */
{
    SSL_CTX_free(ctx);
}

void client(int local)
{
    struct sockaddr_in addr;
    int addrlen;
    SSL *ssl;
    int remote;
    struct linger l;
    u_long ip;
#ifdef USE_LIBWRAP
    struct request_info request;
#endif

    log(LOG_DEBUG, "%s started", options.servname);
    l.l_onoff=1;
    l.l_linger=0;
    addrlen=sizeof(addr);
    if(getpeername(local, (struct sockaddr *)&addr, &addrlen)<0) {
        if(options.option&OPT_TRANSPARENT || errno!=ENOTSOCK) {
            sockerror("getpeerbyname");
            goto cleanup_local;
        }
        /* Ignore ENOTSOCK error so 'local' doesn't have to be a socket */
    } else {
#ifdef USE_LIBWRAP
        request_init(&request, RQ_DAEMON, options.servname, RQ_FILE, local, 0);
        fromhost(&request);
        if (!hosts_access(&request)) {
            log(LOG_WARNING, "Connection from %s:%d REFUSED by LIBWRAP",
                inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
            goto cleanup_local;
        }
#endif
        if(auth_user(&addr)<0) {
            log(LOG_WARNING, "Connection from %s:%d REFUSED by IDENT",
                inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
            goto cleanup_local;
        }
        log(LOG_NOTICE, "%s connected from %s:%d", options.servname,
            inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
    }

    /* create connection to host/service */
    ip=options.option&OPT_TRANSPARENT ? addr.sin_addr.s_addr : 0;
    if(options.option&OPT_REMOTE) { /* remote host */
        if((remote=connect_remote(ip))<0)
            goto cleanup_local; /* Failed to connect remote server */
        log(LOG_DEBUG, "Remote host connected");
    } else { /* local service */
        if((remote=connect_local(ip))<0)
            goto cleanup_local; /* Failed to spawn local service */
        log(LOG_DEBUG, "Local service connected");
    }

    /* negotiate protocol */
    if(negotiate(options.protocol, options.option&OPT_CLIENT,
            local, remote) <0) {
        log(LOG_ERR, "Protocol negotiations failed");
        goto cleanup_remote;
    }

    /* do the job */
    if(!(ssl=SSL_new(ctx))) {
        sslerror("SSL_new");
        goto cleanup_remote;
    }
#if SSLEAY_VERSION_NUMBER >= 0x0922
    SSL_set_session_id_context(ssl, sid_ctx, strlen(sid_ctx));
#endif
    if(options.option&OPT_CLIENT) {
        SSL_set_fd(ssl, remote);
        SSL_set_connect_state(ssl);
        if(SSL_connect(ssl)<=0) {
            sslerror("SSL_connect");
            goto cleanup_ssl;
        }
        print_cipher(ssl);
        if(transfer(ssl, local)<0)
            goto cleanup_ssl;
    } else {
        SSL_set_fd(ssl, local);
        SSL_set_accept_state(ssl);
        if(SSL_accept(ssl)<=0) {
            sslerror("SSL_accept");
            goto cleanup_ssl;
        }
        print_cipher(ssl);
        if(transfer(ssl, remote)<0)
            goto cleanup_ssl;
    }
    /* No error - normal shutdown */
    SSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
    SSL_free(ssl);
    ERR_remove_state(0);
    closesocket(remote);
    closesocket(local);
    goto done;
cleanup_ssl: /* close SSL and reset sockets */
    SSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
    SSL_free(ssl);
    ERR_remove_state(0);
cleanup_remote: /* reset remote and local socket */
    setsockopt(remote, SOL_SOCKET, SO_LINGER, (char *)&l, sizeof(l));
    /* Ignore the error */
    closesocket(remote);
cleanup_local: /* reset local socket */
    setsockopt(local, SOL_SOCKET, SO_LINGER, (char *)&l, sizeof(l));
    /* Ignore the error */
    closesocket(local);
done:
#ifndef USE_FORK
    log(LOG_DEBUG, "%s finished (%d left)", options.servname,
        --options.clients);
#endif
    ; /* ANSI C compiler needs it */
}

static int transfer(SSL *ssl, int sock_fd) /* transfer data */
{
    fd_set rd_set, wr_set;
    int num, fdno, ssl_fd, ssl_bytes, sock_bytes, retval;
    char sock_buff[BUFFSIZE], ssl_buff[BUFFSIZE];
    int sock_ptr, ssl_ptr, sock_open, ssl_open;
#ifdef FIONBIO
    unsigned long l;
#endif

    ssl_fd=SSL_get_fd(ssl);
    fdno=(ssl_fd>sock_fd ? ssl_fd : sock_fd)+1;
    sock_ptr=0;
    ssl_ptr=0;
    sock_open=1;
    ssl_open=1;
    sock_bytes=0;
    ssl_bytes=0;

#ifdef FIONBIO
    l=1; /* ON */
    if(ioctlsocket(sock_fd, FIONBIO, &l)<0)
        sockerror("ioctlsocket (sock)"); /* non-critical */
    if(ioctlsocket(ssl_fd, FIONBIO, &l)<0)
        sockerror("ioctlsocket (ssl)"); /* non-critical */
    log(LOG_DEBUG, "Sockets set to non-blocking mode");
#endif

    while((sock_open||sock_ptr) && (ssl_open||ssl_ptr)) {
        FD_ZERO(&rd_set);
        if(sock_open && sock_ptr<BUFFSIZE) /* can read from socket */
            FD_SET(sock_fd, &rd_set);
        if(ssl_open && ssl_ptr<BUFFSIZE) /* can read from SSL */
            FD_SET(ssl_fd, &rd_set);
        FD_ZERO(&wr_set);
        if(sock_open && ssl_ptr) /* can write to socket */
            FD_SET(sock_fd, &wr_set);
        if(ssl_open && sock_ptr) /* can write to SSL */
            FD_SET(ssl_fd, &wr_set);
        if(select(fdno, &rd_set, &wr_set, NULL, NULL)<0) {
            sockerror("select");
            goto error;
        }
        if(sock_open && FD_ISSET(sock_fd, &rd_set)) {
            num=readsocket(sock_fd, sock_buff+sock_ptr, BUFFSIZE-sock_ptr);
            if(num<0 && errno==ECONNRESET) {
                log(LOG_NOTICE, "IPC reset (child died)");
                break; /* close connection */
            }
            if(num<0) {
                sockerror("read");
                goto error;
            }
            if(num) {
                sock_ptr+=num;
            } else { /* close */
                log(LOG_DEBUG, "Socket closed on read");
                sock_open=0;
            }
        }
        if(ssl_open && FD_ISSET(ssl_fd, &rd_set)) {
            num=SSL_read(ssl, ssl_buff+ssl_ptr, BUFFSIZE-ssl_ptr);
            switch(SSL_get_error(ssl, num)) {
            case SSL_ERROR_NONE:
                ssl_ptr+=num;
                break;
            case SSL_ERROR_WANT_WRITE:
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_X509_LOOKUP:
                log(LOG_DEBUG, "SSL_read returned WANT_ - retry");
                break;
            case SSL_ERROR_SYSCALL:
                if(num) { /* not EOF */
                    sockerror("SSL_read (socket)");
                    goto error;
                }
            case SSL_ERROR_ZERO_RETURN:
                log(LOG_DEBUG, "SSL closed on read");
                ssl_open=0;
                break;
            case SSL_ERROR_SSL:
                sslerror("SSL_read");
                goto error;
            }
        }
        if(sock_open && FD_ISSET(sock_fd, &wr_set)) {
            num=writesocket(sock_fd, ssl_buff, ssl_ptr);
            if(num<0) {
                sockerror("write");
                goto error;
            }
            if(num) {
                memcpy(ssl_buff, ssl_buff+num, ssl_ptr-num);
                ssl_ptr-=num;
                sock_bytes+=num;
            } else { /* close */
                log(LOG_DEBUG, "Socket closed on write");
                sock_open=0;
            }
        }
        if(ssl_open && FD_ISSET(ssl_fd, &wr_set)) {
            num=SSL_write(ssl, sock_buff, sock_ptr);
            switch(SSL_get_error(ssl, num)) {
            case SSL_ERROR_NONE:
                memcpy(sock_buff, sock_buff+num, sock_ptr-num);
                sock_ptr-=num;
                ssl_bytes+=num;
                break;
            case SSL_ERROR_WANT_WRITE:
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_X509_LOOKUP:
                log(LOG_DEBUG, "SSL_write returned WANT_ - retry");
                break;
            case SSL_ERROR_SYSCALL:
                if(num) { /* not EOF */
                    sockerror("SSL_write (socket)");
                    goto error;
                }
            case SSL_ERROR_ZERO_RETURN:
                log(LOG_DEBUG, "SSL closed on write");
                ssl_open=0;
                break;
            case SSL_ERROR_SSL:
                sslerror("SSL_write");
                goto error;
            }
        }
    }
    retval=0;
    goto done;
error:
    retval=-1;
done:

#ifdef FIONBIO
    l=0; /* OFF */
    if(ioctlsocket(sock_fd, FIONBIO, &l)<0)
        sockerror("ioctlsocket (sock)"); /* non-critical */
    if(ioctlsocket(ssl_fd, FIONBIO, &l)<0)
        sockerror("ioctlsocket (ssl)"); /* non-critical */
#endif

    log(LOG_NOTICE,
        "Connection %s: %d bytes sent to SSL, %d bytes sent to socket",
        retval<0 ? "reset" : "closed", ssl_bytes, sock_bytes);
    return retval;
}

#ifndef NO_RSA
static RSA *tmp_rsa_cb(SSL *s, int export, int keylength)
{ /* temporary RSA key callback */
    return rsa_tmp;
}
#endif /* NO_RSA */

static int verify_callback(int state, X509_STORE_CTX *ctx)
{ /* our verify callback function */
    char txt[256];
    X509_OBJECT ret;

    X509_NAME_oneline(X509_get_subject_name(ctx->current_cert),
        txt, sizeof(txt));
    if(!state) {
        /* Remote site specified a certificate, but it's not correct */
        log(LOG_WARNING, "VERIFY ERROR: depth=%d error=%s: %s",
            ctx->error_depth,
            X509_verify_cert_error_string (ctx->error), txt);
        return 0; /* Reject connection */
    }
    if(options.verify_use_only_my && ctx->error_depth==0 &&
            X509_STORE_get_by_subject(ctx, X509_LU_X509,
                X509_get_subject_name(ctx->current_cert), &ret)!=1) {
        log (LOG_WARNING, "VERIFY ERROR ONLY MY: no cert for: %s", txt);
        return 0; /* Reject connection */
    }
    log(LOG_NOTICE, "VERIFY OK: depth=%d: %s", ctx->error_depth, txt);
    return 1; /* Accept connection */
}

static void info_callback(SSL *s, int where, int ret)
{
    log(LOG_DEBUG, "%s", SSL_state_string_long(s));
    if(where==SSL_CB_HANDSHAKE_DONE)
        print_stats();
}

static void print_stats() /* print statistics */
{
    log(LOG_DEBUG, "%4ld items in the session cache",
        SSL_CTX_sess_number(ctx));
    log(LOG_DEBUG, "%4d client connects (SSL_connect())",
        SSL_CTX_sess_connect(ctx));
    log(LOG_DEBUG, "%4d client connects that finished",
        SSL_CTX_sess_connect_good(ctx));
#if SSLEAY_VERSION_NUMBER >= 0x0922
    log(LOG_DEBUG, "%4d client renegotiatations requested",
        SSL_CTX_sess_connect_renegotiate(ctx));
#endif
    log(LOG_DEBUG, "%4d server connects (SSL_accept())",
        SSL_CTX_sess_accept(ctx));
    log(LOG_DEBUG, "%4d server connects that finished",
        SSL_CTX_sess_accept_good(ctx));
#if SSLEAY_VERSION_NUMBER >= 0x0922
    log(LOG_DEBUG, "%4d server renegotiatiations requested",
        SSL_CTX_sess_accept_renegotiate(ctx));
#endif
    log(LOG_DEBUG, "%4d session cache hits", SSL_CTX_sess_hits(ctx));
    log(LOG_DEBUG, "%4d session cache misses", SSL_CTX_sess_misses(ctx));
    log(LOG_DEBUG, "%4d session cache timeouts", SSL_CTX_sess_timeouts(ctx));
}

static void print_cipher(SSL *ssl) /* print negotiated cipher */
{
#if SSLEAY_VERSION_NUMBER > 0x0800
    SSL_CIPHER *c;
    char *ver;
    int bits;
#endif

#if SSLEAY_VERSION_NUMBER <= 0x0800
    log(LOG_INFO, "%s opened with SSLv%d, cipher %s",
        options.servname, ssl->session->ssl_version, SSL_get_cipher(ssl));
#else
    switch(ssl->session->ssl_version) {
    case SSL2_VERSION:
        ver="SSLv2"; break;
    case SSL3_VERSION:
        ver="SSLv3"; break;
    case TLS1_VERSION:
        ver="TLSv1"; break;
    default:
        ver="UNKNOWN";
    }
    c=SSL_get_current_cipher(ssl);
    SSL_CIPHER_get_bits(c, &bits);
    log(LOG_INFO, "%s opened with %s, cipher %s (%u bits)",
        options.servname, ver, SSL_CIPHER_get_name(c), bits);
#endif
}

static void sslerror(char *txt) /* SSL Error handler */
{
    char string[120];

    ERR_error_string(ERR_get_error(), string);
    log(LOG_ERR, "%s: %s", txt, string);
}

/* End of stunnel.c */

