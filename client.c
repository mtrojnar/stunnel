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

/* I/O buffer size */
#define BUFFSIZE       8192

#include "common.h"

#ifndef SHUT_RD
#define SHUT_RD 0
#endif
#ifndef SHUT_WR
#define SHUT_WR 1
#endif
#ifndef SHUT_RDWR
#define SHUT_RDWR 2
#endif

#ifdef HAVE_OPENSSL
#include <openssl/lhash.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#else
#include <lhash.h>
#include <ssl.h>
#include <err.h>
#endif

/* TCP wrapper */
#ifdef USE_LIBWRAP
#include <tcpd.h>
int allow_severity=LOG_NOTICE;
int deny_severity=LOG_WARNING;
#endif

#if SSLEAY_VERSION_NUMBER >= 0x0922
static unsigned char *sid_ctx=(unsigned char *)"stunnel SID";
    /* const allowed here */
#endif

extern SSL_CTX *ctx; /* global SSL context defined in ssl.c */
extern server_options options;

    /* SSL functions */
static int transfer(int, int, SSL *, int, int);
static void print_cipher(SSL *);

void client(int local) {
    int local_rd, local_wr;
    struct sockaddr_in addr;
    int addrlen;
    SSL *ssl;
    int remote;
    struct linger l;
    u32 ip;
#ifdef USE_LIBWRAP
    struct request_info request;
    int result;
#endif

    log(LOG_DEBUG, "%s started", options.servname);
    l.l_onoff=1;
    l.l_linger=0;
    addrlen=sizeof(addr);

    if(local==STDIO_FILENO) { /* Read from STDIN, write to STDOUT */
        local_rd=0;
        local_wr=1;
    } else
        local_rd=local_wr=local;

    if(getpeername(local_rd, (struct sockaddr *)&addr, &addrlen)<0) {
        if(options.option&OPT_TRANSPARENT || get_last_socket_error()!=ENOTSOCK) {
            sockerror("getpeerbyname");
            goto cleanup_local;
        }
        /* Ignore ENOTSOCK error so 'local' doesn't have to be a socket */
    } else {
        /* It's a socket - lets setup options */
        if(set_socket_options(local_rd, 1)<0)
            goto cleanup_local;

#ifdef USE_LIBWRAP
        enter_critical_section(CRIT_LIBWRAP); /* libwrap is not mt-safe */
        request_init(&request, RQ_DAEMON, options.servname, RQ_FILE, local_rd, 0);
        fromhost(&request);
        result=hosts_access(&request);
        leave_critical_section(CRIT_LIBWRAP);
        if (!result) {
            enter_critical_section(CRIT_NTOA); /* inet_ntoa is not mt-safe */
            log(LOG_WARNING, "Connection from %s:%d REFUSED by libwrap",
                inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
            leave_critical_section(CRIT_NTOA);
            log(LOG_DEBUG, "See hosts_access(5) for details");
            goto cleanup_local;
        }
#endif
        if(auth_user(&addr)<0) {
            enter_critical_section(CRIT_NTOA); /* inet_ntoa is not mt-safe */
            log(LOG_WARNING, "Connection from %s:%d REFUSED by IDENT",
                inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
            leave_critical_section(CRIT_NTOA);
            goto cleanup_local;
        }
        enter_critical_section(CRIT_NTOA); /* inet_ntoa is not mt-safe */
        log(LOG_NOTICE, "%s connected from %s:%d", options.servname,
            inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        leave_critical_section(CRIT_NTOA);
    }

    /* create connection to host/service */
    if(options.local_ip)
        ip=*options.local_ip;
    else if(options.option&OPT_TRANSPARENT)
        ip=addr.sin_addr.s_addr;
    else
        ip=0;
    if(options.option&OPT_REMOTE) { /* remote host */
        if((remote=connect_remote(ip))<0)
            goto cleanup_local; /* Failed to connect remote server */
        log(LOG_DEBUG, "Remote host connected");
        if(set_socket_options(remote, 2)<0)
            goto cleanup_remote;

    } else { /* local service */
        if((remote=connect_local(ip))<0)
            goto cleanup_local; /* Failed to spawn local service */
        log(LOG_DEBUG, "Local service connected");
    }

    /* negotiate protocol */
    if(negotiate(options.protocol, options.option&OPT_CLIENT,
            local_rd, local_wr, remote) <0) {
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
        /* Attempt to use the most recent id in the session cache */
        if ( ctx->session_cache_head )
            if ( ! SSL_set_session(ssl, ctx->session_cache_head) )
                log(LOG_WARNING, "Cannot set SSL session id to most recent used");
        SSL_set_fd(ssl, remote);
        SSL_set_connect_state(ssl);
        if(SSL_connect(ssl)<=0) {
            sslerror("SSL_connect");
            goto cleanup_ssl;
        }
        print_cipher(ssl);
        if(transfer(local_rd, local_wr, ssl, remote, remote)<0)
            goto cleanup_ssl;
    } else {
        if(local==STDIO_FILENO) {
           /* Does it make sence to have SSL on STDIN/STDOUT? */
           SSL_set_rfd(ssl, 0);
           SSL_set_wfd(ssl, 1);
        } else
            SSL_set_fd(ssl, local);
        SSL_set_accept_state(ssl);
        if(SSL_accept(ssl)<=0) {
            sslerror("SSL_accept");
            goto cleanup_ssl;
        }
        print_cipher(ssl);
        if(transfer(remote, remote, ssl, local_rd, local_wr)<0)
            goto cleanup_ssl;
    }
    /* No error - normal shutdown */
    SSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
    SSL_free(ssl);
    ERR_remove_state(0);
    closesocket(remote);
    if(local!=STDIO_FILENO)
        closesocket(local);
    goto done;
cleanup_ssl: /* close SSL and reset sockets */
    SSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
    SSL_free(ssl);
    ERR_remove_state(0);
cleanup_remote: /* reset remote and local socket */
    if(options.option&OPT_REMOTE)
        if(setsockopt(remote, SOL_SOCKET, SO_LINGER,
                (void *)&l, sizeof(l)) &&
                get_last_socket_error()!=ENOTSOCK)
            sockerror("linger (remote)");
    closesocket(remote);
cleanup_local: /* reset local socket */
    if(local==STDIO_FILENO) {
        if(setsockopt(local_rd, SOL_SOCKET, SO_LINGER,
                (void *)&l, sizeof(l)) &&
                get_last_socket_error()!=ENOTSOCK)
            sockerror("linger (local_rd)");
        if(setsockopt(local_wr, SOL_SOCKET, SO_LINGER,
                (void *)&l, sizeof(l)) &&
                get_last_socket_error()!=ENOTSOCK)
            sockerror("linger (local_wr)");
    } else {
        if(setsockopt(local, SOL_SOCKET, SO_LINGER,
                (void *)&l, sizeof(l)) &&
                get_last_socket_error()!=ENOTSOCK)
            sockerror("linger (local)");
        closesocket(local);
    }
done:
#ifndef USE_FORK
    enter_critical_section(CRIT_CLIENTS); /* for multi-cpu machines */
    log(LOG_DEBUG, "%s finished (%d left)", options.servname,
        --options.clients);
    leave_critical_section(CRIT_CLIENTS);
#endif
    ; /* ANSI C compiler needs it */
}

static int transfer(int sock_rfd, int sock_wfd,
    SSL *ssl, int ssl_rfd, int ssl_wfd) { /* transfer data */

    fd_set rd_set, wr_set;
    int num, fdno, ssl_bytes, sock_bytes, retval;
    char sock_buff[BUFFSIZE], ssl_buff[BUFFSIZE];
    int sock_ptr, ssl_ptr, sock_rd, sock_wr, ssl_rd, ssl_wr;
    int check_SSL_pending;
    int ready;
    struct timeval tv;
#if defined FIONBIO && defined USE_NBIO
    unsigned long l;
#endif

    fdno=sock_rfd;
    if(sock_wfd>fdno) fdno=sock_wfd;
    if(ssl_rfd>fdno) fdno=ssl_rfd;
    if(ssl_wfd>fdno) fdno=ssl_wfd;
    fdno+=1;

    sock_ptr=ssl_ptr=0;
    sock_rd=sock_wr=ssl_rd=ssl_wr=1;
    sock_bytes=ssl_bytes=0;

#if defined FIONBIO && defined USE_NBIO
    log(LOG_DEBUG, "Seting sockets to non-blocking mode");
    l=1; /* ON */
    if(ioctlsocket(sock_rfd, FIONBIO, &l)<0)
        sockerror("ioctlsocket (sock_rfd)"); /* non-critical */
    if(sock_wfd!=sock_rfd && ioctlsocket(sock_wfd, FIONBIO, &l)<0)
        sockerror("ioctlsocket (sock_wfd)"); /* non-critical */
    if(ioctlsocket(ssl_rfd, FIONBIO, &l)<0)
        sockerror("ioctlsocket (ssl_rfd)"); /* non-critical */
    if(ssl_wfd!=ssl_rfd && ioctlsocket(ssl_wfd, FIONBIO, &l)<0)
        sockerror("ioctlsocket (ssl_wfd)"); /* non-critical */
    log(LOG_DEBUG, "Sockets set to non-blocking mode");
#endif

    while(((sock_rd||sock_ptr)&&ssl_wr)||((ssl_rd||ssl_ptr)&&sock_wr)) {

        FD_ZERO(&rd_set); /* Setup rd_set */
        if(sock_rd && sock_ptr<BUFFSIZE) /* socket input buffer not full*/
            FD_SET(sock_rfd, &rd_set);
        if(ssl_rd && (ssl_ptr<BUFFSIZE || /* SSL input buffer not full */
                (sock_ptr && SSL_want_read(ssl))
                /* I want to SSL_write but read from the underlying */
                /* socket needed for the SSL protocol */
                )) {
            FD_SET(ssl_rfd, &rd_set);
        }

        FD_ZERO(&wr_set); /* Setup wr_set */
        if(sock_wr && ssl_ptr) /* SSL input buffer not empty */
            FD_SET(sock_wfd, &wr_set);
        if (ssl_wr && (sock_ptr || /* socket input buffer not empty */
                (ssl_ptr<BUFFSIZE && SSL_want_write(ssl))
                /* I want to SSL_read but write to the underlying */
                /* socket needed for the SSL protocol */
                )) {
            FD_SET(ssl_wfd, &wr_set);
        }

        /* socket open for read -> set timeout to 1 hour */
        /* socket closed for read -> set timeout to 10 seconds */
        tv.tv_sec=sock_rd ? 3600 : 10;
        tv.tv_usec=0;

        do { /* Skip "Interrupted system call" errors */
            ready=select(fdno, &rd_set, &wr_set, NULL, &tv);
        } while(ready<0 && get_last_socket_error()==EINTR);
        if(ready<0) { /* Break the connection for others */
            sockerror("select");
            goto error;
        }
        if(!ready) { /* Timeout */
            if(sock_rd) { /* No traffic for a long time */
                log(LOG_DEBUG, "select timeout - connection reset");
                goto error;
            } else { /* Timeout waiting for SSL close_notify */
                log(LOG_DEBUG, "select timeout waiting for SSL close_notify");
                break; /* Leave the while() loop */
            }
        }

        /* Set flag to try and read any buffered SSL data if we made */
        /* room in the buffer by writing to the socket */
        check_SSL_pending = 0;

        if(sock_wr && FD_ISSET(sock_wfd, &wr_set)) {
            num=writesocket(sock_wfd, ssl_buff, ssl_ptr);
            if(num<0) {
                sockerror("write");
                goto error;
            }
            if(num) {
                memcpy(ssl_buff, ssl_buff+num, ssl_ptr-num);
                if(ssl_ptr==BUFFSIZE)
                    check_SSL_pending=1;
                ssl_ptr-=num;
                sock_bytes+=num;
                if(!ssl_rd && !ssl_ptr) {
                    shutdown(sock_wfd, SHUT_WR);
                    log(LOG_DEBUG,
                        "Socket write shutdown (no more data to send)");
                    sock_wr=0;
                }
            }
        }

        if(ssl_wr && ( /* SSL sockets are still open */
                (sock_ptr && FD_ISSET(ssl_wfd, &wr_set)) ||
                /* See if application data can be written */
                (SSL_want_read(ssl) && FD_ISSET(ssl_rfd, &rd_set))
                /* I want to SSL_write but read from the underlying */
                /* socket needed for the SSL protocol */
                )) {
            num=SSL_write(ssl, sock_buff, sock_ptr);

            switch(SSL_get_error(ssl, num)) {
            case SSL_ERROR_NONE:
                memcpy(sock_buff, sock_buff+num, sock_ptr-num);
                sock_ptr-=num;
                ssl_bytes+=num;
                if(!sock_rd && !sock_ptr && ssl_wr) {
                    SSL_shutdown(ssl); /* Send close_notify */
                    log(LOG_DEBUG,
                        "SSL write shutdown (no more data to send)");
                    ssl_wr=0;
                }
                break;
            case SSL_ERROR_WANT_WRITE:
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_X509_LOOKUP:
                log(LOG_DEBUG, "SSL_write returned WANT_ - retry");
                break;
            case SSL_ERROR_SYSCALL:
                if(num<0) { /* not EOF */
                    sockerror("SSL_write (ERROR_SYSCALL)");
                    goto error;
                }
                log(LOG_DEBUG, "SSL socket closed on SSL_write");
                ssl_rd=ssl_wr=0;
                break;
            case SSL_ERROR_ZERO_RETURN: /* close_notify received */
                log(LOG_DEBUG, "SSL closed on SSL_write");
                ssl_rd=ssl_wr=0;
                break;
            case SSL_ERROR_SSL:
                sslerror("SSL_write");
                goto error;
            }
        }

        if(sock_rd && FD_ISSET(sock_rfd, &rd_set)) {
            num=readsocket(sock_rfd, sock_buff+sock_ptr, BUFFSIZE-sock_ptr);

            if(num<0 && get_last_socket_error()==ECONNRESET) {
                log(LOG_NOTICE, "IPC reset (child died)");
                break; /* close connection */
            }
            if (num<0 && get_last_socket_error()!=EIO) {
                sockerror("read");
                goto error;
            } else if (num>0) {
                sock_ptr += num;
            } else { /* close */
                log(LOG_DEBUG, "Socket closed on read");
                sock_rd=0;
                if(!sock_ptr && ssl_wr) {
                    SSL_shutdown(ssl); /* Send close_notify */
                    log(LOG_DEBUG,
                        "SSL write shutdown (output buffer empty)");
                    ssl_wr=0;
                }
            }
        }

        if(ssl_rd && ( /* SSL sockets are still open */
                (ssl_ptr<BUFFSIZE && FD_ISSET(ssl_rfd, &rd_set)) ||
                /* See if there's any application data coming in */
                (SSL_want_write(ssl) && FD_ISSET(ssl_wfd, &wr_set)) ||
                /* I want to SSL_read but write to the underlying */
                /* socket needed for the SSL protocol */
                (check_SSL_pending && SSL_pending(ssl))
                /* Write made space from full buffer */
                )) {
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
                if(num<0) { /* not EOF */
                    sockerror("SSL_read (SSL_ERROR_SYSCALL)");
                    goto error;
                }
                log(LOG_DEBUG, "SSL socket closed on SSL_read");
                ssl_rd=ssl_wr=0;
                break;
            case SSL_ERROR_ZERO_RETURN: /* close_notify received */
                log(LOG_DEBUG, "SSL closed on SSL_read");
                ssl_rd=0;
                if(!sock_ptr && ssl_wr) {
                    SSL_shutdown(ssl); /* Send close_notify back */
                    log(LOG_DEBUG,
                        "SSL write shutdown (output buffer empty)");
                    ssl_wr=0;
                }
                if(!ssl_ptr && sock_wr) {
                    shutdown(sock_wfd, SHUT_WR);
                    log(LOG_DEBUG,
                        "Socket write shutdown (output buffer empty)");
                    sock_wr=0;
                }
                break;
            case SSL_ERROR_SSL:
                sslerror("SSL_read");
                goto error;
            }
        }
    }
    retval=0;
    goto done;
error:
    retval=-1;
done:

#if defined FIONBIO && defined USE_NBIO
    log(LOG_DEBUG, "Seting sockets to blocking mode");
    l=0; /* OFF */
    if(sock_rd && ioctlsocket(sock_rfd, FIONBIO, &l)<0)
        sockerror("ioctlsocket (sock_rfd)"); /* non-critical */
    if(sock_wr && sock_wfd!=sock_rfd && ioctlsocket(sock_wfd, FIONBIO, &l)<0)
        sockerror("ioctlsocket (sock_wfd)"); /* non-critical */
    if(ssl_rd && ioctlsocket(ssl_rfd, FIONBIO, &l)<0)
        sockerror("ioctlsocket (ssl_rfd)"); /* non-critical */
    if(ssl_wr && ssl_wfd!=ssl_rfd && ioctlsocket(ssl_wfd, FIONBIO, &l)<0)
        sockerror("ioctlsocket (ssl_wfd)"); /* non-critical */
    log(LOG_DEBUG, "Sockets back in blocking mode");
#endif

    log(LOG_NOTICE,
        "Connection %s: %d bytes sent to SSL, %d bytes sent to socket",
        retval<0 ? "reset" : "closed", ssl_bytes, sock_bytes);
    return retval;
}

static void print_cipher(SSL *ssl) { /* print negotiated cipher */
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

/* End of client.c */
