/*
 *   stunnel       TLS offloading and load-balancing proxy
 *   Copyright (C) 1998-2015 Michal Trojnara <Michal.Trojnara@mirt.net>
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

#ifndef SHUT_RD
#define SHUT_RD 0
#endif
#ifndef SHUT_WR
#define SHUT_WR 1
#endif
#ifndef SHUT_RDWR
#define SHUT_RDWR 2
#endif

NOEXPORT void client_try(CLI *);
NOEXPORT void client_run(CLI *);
NOEXPORT void local_start(CLI *);
NOEXPORT void remote_start(CLI *);
NOEXPORT void ssl_start(CLI *);
NOEXPORT void new_chain(CLI *);
NOEXPORT void transfer(CLI *);
NOEXPORT int parse_socket_error(CLI *, const char *);

NOEXPORT void print_cipher(CLI *);
NOEXPORT void auth_user(CLI *, char *);
NOEXPORT SOCKET connect_local(CLI *);
NOEXPORT SOCKET connect_remote(CLI *);
NOEXPORT void connect_cache(SSL_SESSION *, SOCKADDR_UNION *);
NOEXPORT unsigned connect_index(CLI *);
NOEXPORT void setup_connect_addr(CLI *);
NOEXPORT void local_bind(CLI *c);
NOEXPORT void print_bound_address(CLI *);
NOEXPORT void reset(SOCKET, char *);

/* allocate local data structure for the new thread */
CLI *alloc_client_session(SERVICE_OPTIONS *opt, SOCKET rfd, SOCKET wfd) {
    CLI *c;

    c=str_alloc_detached(sizeof(CLI));
    c->opt=opt;
    c->local_rfd.fd=rfd;
    c->local_wfd.fd=wfd;
    c->redirect=REDIRECT_OFF;
    return c;
}

void *client_thread(void *arg) {
    CLI *c=arg;

    c->tls=NULL; /* do not reuse */
    tls_alloc(c, NULL, NULL);
#ifdef DEBUG_STACK_SIZE
    stack_info(1); /* initialize */
#endif
    client_main(c);
#ifdef DEBUG_STACK_SIZE
    stack_info(0); /* display computed value */
#endif
    str_stats(); /* client thread allocation tracking */
    tls_cleanup();
    /* s_log() is not allowed after tls_cleanup() */
#if defined(USE_WIN32) && !defined(_WIN32_WCE)
    _endthread();
#endif
#ifdef USE_UCONTEXT
    s_poll_wait(NULL, 0, 0); /* wait on poll() */
#endif
    return NULL;
}

void client_main(CLI *c) {
    s_log(LOG_DEBUG, "Service [%s] started", c->opt->servname);
    if(c->opt->exec_name && c->opt->connect_addr.names) {
            /* exec and connect options specified together
             * -> spawn a local program instead of stdio */
        for(;;) {
            SERVICE_OPTIONS *opt=c->opt;
            memset(c, 0, sizeof(CLI)); /* connect_local needs clean c */
            c->opt=opt;
            if(!setjmp(c->err))
                c->local_rfd.fd=c->local_wfd.fd=connect_local(c);
            else
                break;
            client_run(c);
            if(!c->opt->option.retry)
                break;
            sleep(1); /* FIXME: not a good idea in ucontext threading */
            s_poll_free(c->fds);
            c->fds=NULL;
            str_stats(); /* client thread allocation tracking */
            /* c allocation is detached, so it is safe to call str_stats() */
            if(service_options.next) /* no tls_cleanup() in inetd mode */
                tls_cleanup();
        }
    } else
        client_run(c);
    str_free(c);
}

NOEXPORT void client_run(CLI *c) {
    int err, rst;
#ifndef USE_FORK
    long num_clients_copy;
#endif

#ifndef USE_FORK
    enter_critical_section(CRIT_CLIENTS);
    ui_clients(++num_clients);
    leave_critical_section(CRIT_CLIENTS);
#endif

        /* initialize the client context */
    c->remote_fd.fd=INVALID_SOCKET;
    c->fd=INVALID_SOCKET;
    c->ssl=NULL;
    c->sock_bytes=c->ssl_bytes=0;
    if(c->opt->option.client) {
        c->sock_rfd=&(c->local_rfd);
        c->sock_wfd=&(c->local_wfd);
        c->ssl_rfd=c->ssl_wfd=&(c->remote_fd);
    } else {
        c->sock_rfd=c->sock_wfd=&(c->remote_fd);
        c->ssl_rfd=&(c->local_rfd);
        c->ssl_wfd=&(c->local_wfd);
    }
    c->fds=s_poll_alloc();
    addrlist_clear(&c->connect_addr);

        /* try to process the request */
    err=setjmp(c->err);
    if(!err)
        client_try(c);
    rst=err==1 && c->opt->option.reset;
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-extra-args"
#endif /* __GNUC__ */
    s_log(LOG_NOTICE,
        "Connection %s: %llu byte(s) sent to SSL, %llu byte(s) sent to socket",
        rst ? "reset" : "closed",
        (unsigned long long)c->ssl_bytes, (unsigned long long)c->sock_bytes);
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif /* __GNUC__ */

        /* cleanup temporary (e.g. IDENT) socket */
    if(c->fd!=INVALID_SOCKET)
        closesocket(c->fd);
    c->fd=INVALID_SOCKET;

        /* cleanup the SSL context */
    if(c->ssl) { /* SSL initialized */
        SSL_set_shutdown(c->ssl, SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
        SSL_free(c->ssl);
        c->ssl=NULL;
#if OPENSSL_VERSION_NUMBER>=0x10000000L
        ERR_remove_thread_state(NULL);
#else /* OpenSSL version < 1.0.0 */
        ERR_remove_state(0);
#endif /* OpenSSL version >= 1.0.0 */
    }

        /* cleanup the remote socket */
    if(c->remote_fd.fd!=INVALID_SOCKET) { /* remote socket initialized */
        if(rst && c->remote_fd.is_socket) /* reset */
            reset(c->remote_fd.fd, "linger (remote)");
        closesocket(c->remote_fd.fd);
        s_log(LOG_DEBUG, "Remote socket (FD=%d) closed", c->remote_fd.fd);
        c->remote_fd.fd=INVALID_SOCKET;
    }

        /* cleanup the local socket */
    if(c->local_rfd.fd!=INVALID_SOCKET) { /* local socket initialized */
        if(c->local_rfd.fd==c->local_wfd.fd) {
            if(rst && c->local_rfd.is_socket)
                reset(c->local_rfd.fd, "linger (local)");
            closesocket(c->local_rfd.fd);
            s_log(LOG_DEBUG, "Local socket (FD=%d) closed", c->local_rfd.fd);
        } else { /* stdin/stdout */
            if(rst && c->local_rfd.is_socket)
                reset(c->local_rfd.fd, "linger (local_rfd)");
            if(rst && c->local_wfd.is_socket)
                reset(c->local_wfd.fd, "linger (local_wfd)");
        }
        c->local_rfd.fd=c->local_wfd.fd=INVALID_SOCKET;
    }

#ifdef USE_FORK
    /* display child return code if it managed to arrive on time */
    /* otherwise it will be retrieved by the init process and ignored */
    if(c->opt->exec_name) /* 'exec' specified */
        child_status(); /* null SIGCHLD handler was used */
    s_log(LOG_DEBUG, "Service [%s] finished", c->opt->servname);
#else
    enter_critical_section(CRIT_CLIENTS);
    ui_clients(--num_clients);
    num_clients_copy=num_clients; /* to move s_log() away from CRIT_CLIENTS */
    leave_critical_section(CRIT_CLIENTS);
    s_log(LOG_DEBUG, "Service [%s] finished (%ld left)",
        c->opt->servname, num_clients_copy);
#endif

        /* free the client context */
    str_free(c->connect_addr.addr);
    s_poll_free(c->fds);
    c->fds=NULL;
}

NOEXPORT void client_try(CLI *c) {
    local_start(c);
    protocol(c, c->opt, PROTOCOL_EARLY);
    if(c->opt->option.connect_before_ssl) {
        remote_start(c);
        protocol(c, c->opt, PROTOCOL_MIDDLE);
        ssl_start(c);
    } else {
        ssl_start(c);
        protocol(c, c->opt, PROTOCOL_MIDDLE);
        remote_start(c);
    }
    protocol(c, c->opt, PROTOCOL_LATE);
    transfer(c);
}

NOEXPORT void local_start(CLI *c) {
    SOCKADDR_UNION addr;
    socklen_t addr_len;
    char *accepted_address;

    /* check if local_rfd is a socket and get peer address */
    addr_len=sizeof(SOCKADDR_UNION);
    c->local_rfd.is_socket=!getpeername(c->local_rfd.fd, &addr.sa, &addr_len);
    if(c->local_rfd.is_socket) {
        memcpy(&c->peer_addr.sa, &addr.sa, (size_t)addr_len);
        c->peer_addr_len=addr_len;
        if(set_socket_options(c->local_rfd.fd, 1))
            s_log(LOG_WARNING, "Failed to set local socket options");
    } else {
        if(get_last_socket_error()!=S_ENOTSOCK) {
            sockerror("getpeerbyname (local_rfd)");
            longjmp(c->err, 1);
        }
    }

    /* check if local_wfd is a socket and get peer address */
    if(c->local_rfd.fd==c->local_wfd.fd) {
        c->local_wfd.is_socket=c->local_rfd.is_socket;
    } else {
        addr_len=sizeof(SOCKADDR_UNION);
        c->local_wfd.is_socket=!getpeername(c->local_wfd.fd, &addr.sa, &addr_len);
        if(c->local_wfd.is_socket) {
            if(!c->local_rfd.is_socket) { /* already retrieved */
                memcpy(&c->peer_addr.sa, &addr.sa, (size_t)addr_len);
                c->peer_addr_len=addr_len;
            }
            if(set_socket_options(c->local_wfd.fd, 1))
                s_log(LOG_WARNING, "Failed to set local socket options");
        } else {
            if(get_last_socket_error()!=S_ENOTSOCK) {
                sockerror("getpeerbyname (local_wfd)");
                longjmp(c->err, 1);
            }
        }
    }

    /* neither of local descriptors is a socket */
    if(!c->local_rfd.is_socket && !c->local_wfd.is_socket) {
#ifndef USE_WIN32
        if(c->opt->option.transparent_src) {
            s_log(LOG_ERR, "Transparent source needs a socket");
            longjmp(c->err, 1);
        }
#endif
        s_log(LOG_NOTICE, "Service [%s] accepted connection", c->opt->servname);
        return;
    }

    /* authenticate based on retrieved IP address of the client */
    accepted_address=s_ntop(&c->peer_addr, c->peer_addr_len);
#ifdef USE_LIBWRAP
    libwrap_auth(c, accepted_address);
#endif /* USE_LIBWRAP */
    auth_user(c, accepted_address);
    s_log(LOG_NOTICE, "Service [%s] accepted connection from %s",
        c->opt->servname, accepted_address);
    str_free(accepted_address);
}

NOEXPORT void remote_start(CLI *c) {
    /* where to bind connecting socket */
    if(c->opt->option.local) /* outgoing interface */
        c->bind_addr=&c->opt->source_addr;
#ifndef USE_WIN32
    else if(c->opt->option.transparent_src)
        c->bind_addr=&c->peer_addr;
#endif
    else
        c->bind_addr=NULL; /* don't bind */

    /* setup c->remote_fd, now */
    if(c->opt->connect_addr.names
#ifndef USE_WIN32
                || c->opt->option.transparent_dst
#endif
            ) {
        /* try remote first for exec+connect targets */
        c->remote_fd.fd=connect_remote(c);
    } else if(c->opt->exec_name) { /* exec+connect uses local fd */
        c->remote_fd.fd=connect_local(c);
    } else {
        s_log(LOG_ERR, "INTERNAL ERROR: No target for remote socket");
        longjmp(c->err, 1);
    }

    c->remote_fd.is_socket=1; /* always! */
    s_log(LOG_DEBUG, "Remote socket (FD=%d) initialized", c->remote_fd.fd);
    if(set_socket_options(c->remote_fd.fd, 2))
        s_log(LOG_WARNING, "Failed to set remote socket options");
}

NOEXPORT void ssl_start(CLI *c) {
    int i, err;
    SSL_SESSION *old_session;
    int unsafe_openssl;
    X509 *peer_cert;

    c->ssl=SSL_new(c->opt->ctx);
    if(!c->ssl) {
        sslerror("SSL_new");
        longjmp(c->err, 1);
    }
    SSL_set_ex_data(c->ssl, index_cli, c); /* for callbacks */
    if(c->opt->option.client) {
#ifndef OPENSSL_NO_TLSEXT
        if(c->opt->sni) {
            s_log(LOG_INFO, "SNI: sending servername: %s", c->opt->sni);
            if(!SSL_set_tlsext_host_name(c->ssl, c->opt->sni)) {
                sslerror("SSL_set_tlsext_host_name");
                longjmp(c->err, 1);
            }
        }
#endif
        if(c->opt->session) {
            enter_critical_section(CRIT_SESSION);
            SSL_set_session(c->ssl, c->opt->session);
            leave_critical_section(CRIT_SESSION);
        }
        SSL_set_fd(c->ssl, (int)c->remote_fd.fd);
        SSL_set_connect_state(c->ssl);
    } else { /* SSL server */
        if(c->local_rfd.fd==c->local_wfd.fd)
            SSL_set_fd(c->ssl, (int)c->local_rfd.fd);
        else {
           /* does it make sense to have SSL on STDIN/STDOUT? */
            SSL_set_rfd(c->ssl, (int)c->local_rfd.fd);
            SSL_set_wfd(c->ssl, (int)c->local_wfd.fd);
        }
        SSL_set_accept_state(c->ssl);
    }

    unsafe_openssl=SSLeay()<0x0090810fL ||
        (SSLeay()>=0x10000000L && SSLeay()<0x1000002fL);
    while(1) {
        /* critical section for OpenSSL version < 0.9.8p or 1.x.x < 1.0.0b *
         * this critical section is a crude workaround for CVE-2010-3864   *
         * see http://www.securityfocus.com/bid/44884 for details          *
         * alternative solution is to disable internal session caching     *
         * NOTE: this critical section also covers callbacks (e.g. OCSP)   */
        if(unsafe_openssl)
            enter_critical_section(CRIT_SSL);

        if(c->opt->option.client)
            i=SSL_connect(c->ssl);
        else
            i=SSL_accept(c->ssl);

        if(unsafe_openssl)
            leave_critical_section(CRIT_SSL);

        err=SSL_get_error(c->ssl, i);
        if(err==SSL_ERROR_NONE)
            break; /* ok -> done */
        if(err==SSL_ERROR_WANT_READ || err==SSL_ERROR_WANT_WRITE) {
            s_poll_init(c->fds);
            s_poll_add(c->fds, c->ssl_rfd->fd,
                err==SSL_ERROR_WANT_READ,
                err==SSL_ERROR_WANT_WRITE);
            switch(s_poll_wait(c->fds, c->opt->timeout_busy, 0)) {
            case -1:
                sockerror("ssl_start: s_poll_wait");
                longjmp(c->err, 1);
            case 0:
                s_log(LOG_INFO, "ssl_start: s_poll_wait:"
                    " TIMEOUTbusy exceeded: sending reset");
                longjmp(c->err, 1);
            case 1:
                break; /* OK */
            default:
                s_log(LOG_ERR, "ssl_start: s_poll_wait: unknown result");
                longjmp(c->err, 1);
            }
            continue; /* ok -> retry */
        }
        if(err==SSL_ERROR_SYSCALL) {
            switch(get_last_socket_error()) {
            case S_EINTR:
            case S_EWOULDBLOCK:
#if S_EAGAIN!=S_EWOULDBLOCK
            case S_EAGAIN:
#endif
                continue;
            }
        }
        if(c->opt->option.client)
            sslerror("SSL_connect");
        else
            sslerror("SSL_accept");
        longjmp(c->err, 1);
    }
    s_log(LOG_INFO, "SSL %s: %s",
        c->opt->option.client ? "connected" : "accepted",
        SSL_session_reused(c->ssl) ?
            "previous session reused" : "new session negotiated");
    if(SSL_session_reused(c->ssl)) {
        c->redirect=(uintptr_t)SSL_SESSION_get_ex_data(SSL_get_session(c->ssl),
            index_redirect);
        if(c->opt->redirect_addr.names && !c->redirect) {
            s_log(LOG_ERR, "No application data found in the reused session");
            longjmp(c->err, 1);
        }
    } else { /* a new session was negotiated */
        new_chain(c);
        peer_cert=SSL_get_peer_certificate(c->ssl);
        if(peer_cert) /* c->redirect was set by the callback */
            X509_free(peer_cert);
        else if(c->opt->redirect_addr.names)
            c->redirect=REDIRECT_ON;
        SSL_SESSION_set_ex_data(SSL_get_session(c->ssl),
            index_redirect, (void *)c->redirect);
        if(c->opt->option.client) {
            enter_critical_section(CRIT_SESSION);
            old_session=c->opt->session;
            c->opt->session=SSL_get1_session(c->ssl); /* store it */
            leave_critical_section(CRIT_SESSION);
            if(old_session)
                SSL_SESSION_free(old_session); /* release the old one */
        } else { /* SSL server */
            SSL_CTX_add_session(c->opt->ctx, SSL_get_session(c->ssl));
        }
        print_cipher(c);
    }
}

NOEXPORT void new_chain(CLI *c) {
    BIO *bio;
    int i, len;
    X509 *peer_cert;
    STACK_OF(X509) *sk;
    char *chain;

    if(c->opt->chain) /* already cached */
        return; /* this race condition is safe to ignore */
    bio=BIO_new(BIO_s_mem());
    if(!bio)
        return;
    sk=SSL_get_peer_cert_chain(c->ssl);
    for(i=0; sk && i<sk_X509_num(sk); i++) {
        peer_cert=sk_X509_value(sk, i);
        PEM_write_bio_X509(bio, peer_cert);
    }
    if(!sk || !c->opt->option.client) {
        peer_cert=SSL_get_peer_certificate(c->ssl);
        if(peer_cert) {
            PEM_write_bio_X509(bio, peer_cert);
            X509_free(peer_cert);
        }
    }
    len=BIO_pending(bio);
    if(len<=0) {
        s_log(LOG_INFO, "No peer certificate received");
        BIO_free(bio);
        return;
    }
    /* prevent automatic deallocation of the cached value */
    chain=str_alloc_detached((size_t)len+1);
    len=BIO_read(bio, chain, len);
    if(len<0) {
        s_log(LOG_ERR, "BIO_read failed");
        BIO_free(bio);
        str_free(chain);
        return;
    }
    chain[len]='\0';
    BIO_free(bio);
    c->opt->chain=chain; /* this race condition is safe to ignore */
    ui_new_chain(c->opt->section_number);
    s_log(LOG_DEBUG, "Peer certificate was cached (%d bytes)", len);
}

/****************************** transfer data */
NOEXPORT void transfer(CLI *c) {
    int watchdog=0; /* a counter to detect an infinite loop */
    ssize_t num;
    int err;
    /* logical channels (not file descriptors!) open for read or write */
    int sock_open_rd=1, sock_open_wr=1;
    /* awaited conditions on SSL file descriptors */
    int shutdown_wants_read=0, shutdown_wants_write=0;
    int read_wants_read=0, read_wants_write=0;
    int write_wants_read=0, write_wants_write=0;
    /* actual conditions on file descriptors */
    int sock_can_rd, sock_can_wr, ssl_can_rd, ssl_can_wr;
#ifdef USE_WIN32
    unsigned long bytes;
#else
    int bytes;
#endif

    c->sock_ptr=c->ssl_ptr=0;

    do { /* main loop of client data transfer */
        /****************************** initialize *_wants_* */
        read_wants_read|=!(SSL_get_shutdown(c->ssl)&SSL_RECEIVED_SHUTDOWN)
            && c->ssl_ptr<BUFFSIZE && !read_wants_write;
        write_wants_write|=!(SSL_get_shutdown(c->ssl)&SSL_SENT_SHUTDOWN)
            && c->sock_ptr && !write_wants_read;

        /****************************** setup c->fds structure */
        s_poll_init(c->fds); /* initialize the structure */
        /* for plain socket open data strem = open file descriptor */
        /* make sure to add each open socket to receive exceptions! */
        if(sock_open_rd) /* only poll if the read file descriptor is open */
            s_poll_add(c->fds, c->sock_rfd->fd, c->sock_ptr<BUFFSIZE, 0);
        if(sock_open_wr) /* only poll if the write file descriptor is open */
            s_poll_add(c->fds, c->sock_wfd->fd, 0, c->ssl_ptr>0);
        /* poll SSL file descriptors unless SSL shutdown was completed */
        if(SSL_get_shutdown(c->ssl)!=
                (SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN)) {
            s_poll_add(c->fds, c->ssl_rfd->fd,
                read_wants_read || write_wants_read || shutdown_wants_read, 0);
            s_poll_add(c->fds, c->ssl_wfd->fd, 0,
                read_wants_write || write_wants_write || shutdown_wants_write);
        }

        /****************************** wait for an event */
        err=s_poll_wait(c->fds,
            (sock_open_rd && /* both peers open */
                !(SSL_get_shutdown(c->ssl)&SSL_RECEIVED_SHUTDOWN)) ||
            c->ssl_ptr /* data buffered to write to socket */ ||
            c->sock_ptr /* data buffered to write to SSL */ ?
            c->opt->timeout_idle : c->opt->timeout_close, 0);
        switch(err) {
        case -1:
            sockerror("transfer: s_poll_wait");
            longjmp(c->err, 1);
        case 0: /* timeout */
            if((sock_open_rd &&
                    !(SSL_get_shutdown(c->ssl)&SSL_RECEIVED_SHUTDOWN)) ||
                    c->ssl_ptr || c->sock_ptr) {
                s_log(LOG_INFO, "transfer: s_poll_wait:"
                    " TIMEOUTidle exceeded: sending reset");
                longjmp(c->err, 1);
            } else { /* already closing connection */
                s_log(LOG_ERR, "transfer: s_poll_wait:"
                    " TIMEOUTclose exceeded: closing");
                return; /* OK */
            }
        }

        /****************************** retrieve results from c->fds */
        sock_can_rd=s_poll_canread(c->fds, c->sock_rfd->fd);
        sock_can_wr=s_poll_canwrite(c->fds, c->sock_wfd->fd);
        ssl_can_rd=s_poll_canread(c->fds, c->ssl_rfd->fd);
        ssl_can_wr=s_poll_canwrite(c->fds, c->ssl_wfd->fd);

        /****************************** checks for internal failures */
        /* please report any internal errors to stunnel-users mailing list */
        if(!(sock_can_rd || sock_can_wr || ssl_can_rd || ssl_can_wr)) {
            s_log(LOG_ERR, "INTERNAL ERROR: "
                "s_poll_wait returned %d, but no descriptor is ready", err);
            longjmp(c->err, 1);
        }

        if(c->reneg_state==RENEG_DETECTED && !c->opt->option.renegotiation) {
            s_log(LOG_ERR, "Aborting due to renegotiation request");
            longjmp(c->err, 1);
        }

        /****************************** send SSL close_notify alert */
        if(shutdown_wants_read || shutdown_wants_write) {
            num=SSL_shutdown(c->ssl); /* send close_notify alert */
            if(num<0) /* -1 - not completed */
                err=SSL_get_error(c->ssl, (int)num);
            else /* 0 or 1 - success */
                err=SSL_ERROR_NONE;
            switch(err) {
            case SSL_ERROR_NONE: /* the shutdown was successfully completed */
                s_log(LOG_INFO, "SSL_shutdown successfully sent close_notify alert");
                shutdown_wants_read=shutdown_wants_write=0;
                break;
            case SSL_ERROR_SYSCALL: /* socket error */
                if(parse_socket_error(c, "SSL_shutdown"))
                    break; /* a non-critical error: retry */
                SSL_set_shutdown(c->ssl, SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
                shutdown_wants_read=shutdown_wants_write=0;
                break;
            case SSL_ERROR_WANT_WRITE:
                s_log(LOG_DEBUG, "SSL_shutdown returned WANT_WRITE: retrying");
                shutdown_wants_read=0;
                shutdown_wants_write=1;
                break;
            case SSL_ERROR_WANT_READ:
                s_log(LOG_DEBUG, "SSL_shutdown returned WANT_READ: retrying");
                shutdown_wants_read=1;
                shutdown_wants_write=0;
                break;
            case SSL_ERROR_SSL: /* SSL error */
                sslerror("SSL_shutdown");
                longjmp(c->err, 1);
            default:
                s_log(LOG_ERR, "SSL_shutdown/SSL_get_error returned %d", err);
                longjmp(c->err, 1);
            }
        }

        /****************************** write to socket */
        if(sock_open_wr && sock_can_wr) {
            num=writesocket(c->sock_wfd->fd, c->ssl_buff, c->ssl_ptr);
            switch(num) {
            case -1: /* error */
                if(parse_socket_error(c, "writesocket"))
                    break; /* a non-critical error: retry */
                sock_open_rd=sock_open_wr=0;
                break;
            default:
                memmove(c->ssl_buff, c->ssl_buff+num, c->ssl_ptr-(size_t)num);
                c->ssl_ptr-=(size_t)num;
                memset(c->ssl_buff+c->ssl_ptr, 0, (size_t)num); /* paranoia */
                c->sock_bytes+=(size_t)num;
                watchdog=0; /* reset watchdog */
            }
        }

        /****************************** read from socket */
        if(sock_open_rd && sock_can_rd) {
            num=readsocket(c->sock_rfd->fd,
                c->sock_buff+c->sock_ptr, BUFFSIZE-c->sock_ptr);
            switch(num) {
            case -1:
                if(parse_socket_error(c, "readsocket"))
                    break; /* a non-critical error: retry */
                sock_open_rd=sock_open_wr=0;
                break;
            case 0: /* close */
                s_log(LOG_INFO, "Read socket closed (readsocket)");
                sock_open_rd=0;
                break;
            default:
                c->sock_ptr+=(size_t)num;
                watchdog=0; /* reset watchdog */
            }
        }

        /****************************** update *_wants_* based on new *_ptr */
        /* this update is also required for SSL_pending() to be used */
        read_wants_read|=!(SSL_get_shutdown(c->ssl)&SSL_RECEIVED_SHUTDOWN)
            && c->ssl_ptr<BUFFSIZE && !read_wants_write;
        write_wants_write|=!(SSL_get_shutdown(c->ssl)&SSL_SENT_SHUTDOWN)
            && c->sock_ptr && !write_wants_read;

        /****************************** write to SSL */
        if((write_wants_read && ssl_can_rd) ||
                (write_wants_write && ssl_can_wr)) {
            write_wants_read=0;
            write_wants_write=0;
            num=SSL_write(c->ssl, c->sock_buff, (int)(c->sock_ptr));
            switch(err=SSL_get_error(c->ssl, (int)num)) {
            case SSL_ERROR_NONE:
                if(num==0)
                    s_log(LOG_DEBUG, "SSL_write returned 0");
                memmove(c->sock_buff, c->sock_buff+num,
                    c->sock_ptr-(size_t)num);
                c->sock_ptr-=(size_t)num;
                memset(c->sock_buff+c->sock_ptr, 0, (size_t)num); /* paranoia */
                c->ssl_bytes+=(size_t)num;
                watchdog=0; /* reset watchdog */
                break;
            case SSL_ERROR_WANT_WRITE: /* buffered data? */
                s_log(LOG_DEBUG, "SSL_write returned WANT_WRITE: retrying");
                write_wants_write=1;
                break;
            case SSL_ERROR_WANT_READ:
                s_log(LOG_DEBUG, "SSL_write returned WANT_READ: retrying");
                write_wants_read=1;
                break;
            case SSL_ERROR_WANT_X509_LOOKUP:
                s_log(LOG_DEBUG,
                    "SSL_write returned WANT_X509_LOOKUP: retrying");
                break;
            case SSL_ERROR_SYSCALL: /* socket error */
                if(num && parse_socket_error(c, "SSL_write"))
                    break; /* a non-critical error: retry */
                /* EOF -> buggy (e.g. Microsoft) peer:
                 * SSL socket closed without close_notify alert */
                if(c->sock_ptr) { /* TODO: what about buffered data? */
                    s_log(LOG_ERR,
                        "SSL socket closed (SSL_write) with %ld unsent byte(s)",
                        c->sock_ptr);
                    longjmp(c->err, 1); /* reset the socket */
                }
                s_log(LOG_INFO, "SSL socket closed (SSL_write)");
                SSL_set_shutdown(c->ssl, SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
                break;
            case SSL_ERROR_ZERO_RETURN: /* close_notify alert received */
                s_log(LOG_INFO, "SSL closed (SSL_write)");
                if(SSL_version(c->ssl)==SSL2_VERSION)
                    SSL_set_shutdown(c->ssl, SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
                break;
            case SSL_ERROR_SSL:
                sslerror("SSL_write");
                longjmp(c->err, 1);
            default:
                s_log(LOG_ERR, "SSL_write/SSL_get_error returned %d", err);
                longjmp(c->err, 1);
            }
        }

        /****************************** read from SSL */
        if((read_wants_read && (ssl_can_rd || SSL_pending(c->ssl))) ||
                /* it may be possible to read some pending data after
                 * writesocket() above made some room in c->ssl_buff */
                (read_wants_write && ssl_can_wr)) {
            read_wants_read=0;
            read_wants_write=0;
            num=SSL_read(c->ssl, c->ssl_buff+c->ssl_ptr, (int)(BUFFSIZE-c->ssl_ptr));
            switch(err=SSL_get_error(c->ssl, (int)num)) {
            case SSL_ERROR_NONE:
                if(num==0)
                    s_log(LOG_DEBUG, "SSL_read returned 0");
                c->ssl_ptr+=(size_t)num;
                watchdog=0; /* reset watchdog */
                break;
            case SSL_ERROR_WANT_WRITE:
                s_log(LOG_DEBUG, "SSL_read returned WANT_WRITE: retrying");
                read_wants_write=1;
                break;
            case SSL_ERROR_WANT_READ: /* is it possible? */
                s_log(LOG_DEBUG, "SSL_read returned WANT_READ: retrying");
                read_wants_read=1;
                break;
            case SSL_ERROR_WANT_X509_LOOKUP:
                s_log(LOG_DEBUG,
                    "SSL_read returned WANT_X509_LOOKUP: retrying");
                break;
            case SSL_ERROR_SYSCALL:
                if(num && parse_socket_error(c, "SSL_read"))
                    break; /* a non-critical error: retry */
                /* EOF -> buggy (e.g. Microsoft) peer:
                 * SSL socket closed without close_notify alert */
                if(c->sock_ptr || write_wants_write) {
                    s_log(LOG_ERR,
                        "SSL socket closed (SSL_read) with %ld unsent byte(s)",
                        c->sock_ptr);
                    longjmp(c->err, 1); /* reset the socket */
                }
                s_log(LOG_INFO, "SSL socket closed (SSL_read)");
                SSL_set_shutdown(c->ssl,
                    SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
                break;
            case SSL_ERROR_ZERO_RETURN: /* close_notify alert received */
                s_log(LOG_INFO, "SSL closed (SSL_read)");
                if(SSL_version(c->ssl)==SSL2_VERSION)
                    SSL_set_shutdown(c->ssl,
                        SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
                break;
            case SSL_ERROR_SSL:
                sslerror("SSL_read");
                longjmp(c->err, 1);
            default:
                s_log(LOG_ERR, "SSL_read/SSL_get_error returned %d", err);
                longjmp(c->err, 1);
            }
        }

        /****************************** check for hangup conditions */
        /* http://marc.info/?l=linux-man&m=128002066306087 */
        /* readsocket() must be the last sock_rfd operation before FIONREAD */
        if(sock_open_rd && s_poll_rdhup(c->fds, c->sock_rfd->fd) &&
                (ioctlsocket(c->sock_rfd->fd, FIONREAD, &bytes) || !bytes)) {
            s_log(LOG_INFO, "Read socket closed (read hangup)");
            sock_open_rd=0;
        }
        if(sock_open_wr && s_poll_hup(c->fds, c->sock_wfd->fd)) {
            if(c->ssl_ptr) {
                s_log(LOG_ERR,
                    "Write socket closed (write hangup) with %ld unsent byte(s)",
                    c->ssl_ptr);
                longjmp(c->err, 1); /* reset the socket */
            }
            s_log(LOG_INFO, "Write socket closed (write hangup)");
            sock_open_wr=0;
        }
        /* SSL_read() must be the last ssl_rfd operation before FIONREAD */
        if(!(SSL_get_shutdown(c->ssl)&SSL_RECEIVED_SHUTDOWN) &&
                s_poll_rdhup(c->fds, c->ssl_rfd->fd) &&
                (ioctlsocket(c->ssl_rfd->fd, FIONREAD, &bytes) || !bytes)) {
            /* hangup -> buggy (e.g. Microsoft) peer:
             * SSL socket closed without close_notify alert */
            s_log(LOG_INFO, "SSL socket closed (read hangup)");
            SSL_set_shutdown(c->ssl,
                SSL_get_shutdown(c->ssl)|SSL_RECEIVED_SHUTDOWN);
        }
        if(!(SSL_get_shutdown(c->ssl)&SSL_SENT_SHUTDOWN) &&
                s_poll_hup(c->fds, c->ssl_wfd->fd)) {
            if(c->sock_ptr || write_wants_write) {
                s_log(LOG_ERR,
                    "SSL socket closed (write hangup) with %ld unsent byte(s)",
                    c->sock_ptr);
                longjmp(c->err, 1); /* reset the socket */
            }
            s_log(LOG_INFO, "SSL socket closed (write hangup)");
            SSL_set_shutdown(c->ssl,
                SSL_get_shutdown(c->ssl)|SSL_SENT_SHUTDOWN);
        }

        /****************************** check write shutdown conditions */
        if(sock_open_wr && SSL_get_shutdown(c->ssl)&SSL_RECEIVED_SHUTDOWN &&
                !c->ssl_ptr) {
            sock_open_wr=0; /* no further write allowed */
            if(!c->sock_wfd->is_socket) {
                s_log(LOG_DEBUG, "Closing the file descriptor");
                sock_open_rd=0; /* file descriptor is ready to be closed */
            } else if(!shutdown(c->sock_wfd->fd, SHUT_WR)) { /* send TCP FIN */
                s_log(LOG_DEBUG, "Sent socket write shutdown");
            } else {
                s_log(LOG_DEBUG, "Failed to send socket write shutdown");
                sock_open_rd=0; /* file descriptor is ready to be closed */
            }
        }
        if(!(SSL_get_shutdown(c->ssl)&SSL_SENT_SHUTDOWN) && !sock_open_rd &&
                !c->sock_ptr && !write_wants_write) {
            if(SSL_version(c->ssl)!=SSL2_VERSION) {
                s_log(LOG_DEBUG, "Sending close_notify alert");
                shutdown_wants_write=1;
            } else { /* no alerts in SSLv2, including the close_notify alert */
                s_log(LOG_DEBUG, "Closing SSLv2 socket");
                if(c->ssl_rfd->is_socket)
                    shutdown(c->ssl_rfd->fd, SHUT_RD); /* notify the kernel */
                if(c->ssl_wfd->is_socket)
                    shutdown(c->ssl_wfd->fd, SHUT_WR); /* send TCP FIN */
                /* notify the OpenSSL library */
                SSL_set_shutdown(c->ssl, SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
            }
        }

        /****************************** check watchdog */
        if(++watchdog>100) { /* loop executes without transferring any data */
            s_log(LOG_ERR,
                "transfer() loop executes not transferring any data");
            s_log(LOG_ERR,
                "please report the problem to Michal.Trojnara@mirt.net");
            stunnel_info(LOG_ERR);
            s_log(LOG_ERR, "protocol=%s, SSL_pending=%d",
                SSL_get_version(c->ssl), SSL_pending(c->ssl));
            s_log(LOG_ERR, "sock_open_rd=%s, sock_open_wr=%s",
                sock_open_rd ? "Y" : "n", sock_open_wr ? "Y" : "n");
            s_log(LOG_ERR, "SSL_RECEIVED_SHUTDOWN=%s, SSL_SENT_SHUTDOWN=%s",
                SSL_get_shutdown(c->ssl)&SSL_RECEIVED_SHUTDOWN ? "Y" : "n",
                SSL_get_shutdown(c->ssl)&SSL_SENT_SHUTDOWN ? "Y" : "n");
            s_log(LOG_ERR, "sock_can_rd=%s, sock_can_wr=%s",
                sock_can_rd ? "Y" : "n", sock_can_wr ? "Y" : "n");
            s_log(LOG_ERR, "ssl_can_rd=%s, ssl_can_wr=%s",
                ssl_can_rd ? "Y" : "n", ssl_can_wr ? "Y" : "n");
            s_log(LOG_ERR, "read_wants_read=%s, read_wants_write=%s",
                read_wants_read ? "Y" : "n", read_wants_write ? "Y" : "n");
            s_log(LOG_ERR, "write_wants_read=%s, write_wants_write=%s",
                write_wants_read ? "Y" : "n", write_wants_write ? "Y" : "n");
            s_log(LOG_ERR, "shutdown_wants_read=%s, shutdown_wants_write=%s",
                shutdown_wants_read ? "Y" : "n",
                shutdown_wants_write ? "Y" : "n");
            s_log(LOG_ERR, "socket input buffer: %ld byte(s), "
                "ssl input buffer: %ld byte(s)", c->sock_ptr, c->ssl_ptr);
            longjmp(c->err, 1);
        }

    } while(sock_open_wr || !(SSL_get_shutdown(c->ssl)&SSL_SENT_SHUTDOWN) ||
        shutdown_wants_read || shutdown_wants_write);
}

    /* returns 0 on close and 1 on non-critical errors */
NOEXPORT int parse_socket_error(CLI *c, const char *text) {
    switch(get_last_socket_error()) {
        /* http://tangentsoft.net/wskfaq/articles/bsd-compatibility.html */
    case 0: /* close on read, or close on write on WIN32 */
#ifndef USE_WIN32
    case EPIPE: /* close on write on Unix */
#endif
    case S_ECONNABORTED:
        s_log(LOG_INFO, "%s: Socket is closed", text);
        return 0;
    case S_EINTR:
        s_log(LOG_DEBUG, "%s: Interrupted by a signal: retrying", text);
        return 1;
    case S_EWOULDBLOCK:
        s_log(LOG_NOTICE, "%s: Would block: retrying", text);
        sleep(1); /* Microsoft bug KB177346 */
        return 1;
#if S_EAGAIN!=S_EWOULDBLOCK
    case S_EAGAIN:
        s_log(LOG_DEBUG,
            "%s: Temporary lack of resources: retrying", text);
        return 1;
#endif
#ifdef USE_WIN32
    case S_ECONNRESET:
        /* dying "exec" processes on Win32 cause reset instead of close */
        if(c->opt->exec_name) {
            s_log(LOG_INFO, "%s: Socket is closed (exec)", text);
            return 0;
        }
#endif
    default:
        sockerror(text);
        longjmp(c->err, 1);
        return -1; /* some C compilers require a return value */
    }
}

NOEXPORT void print_cipher(CLI *c) { /* print negotiated cipher */
    SSL_CIPHER *cipher;
#ifndef OPENSSL_NO_COMP
    const COMP_METHOD *compression, *expansion;
#endif

    if(c->opt->log_level<LOG_INFO) /* performance optimization */
        return;
    cipher=(SSL_CIPHER *)SSL_get_current_cipher(c->ssl);
    s_log(LOG_INFO, "Negotiated %s ciphersuite %s (%d-bit encryption)",
        SSL_get_version(c->ssl), SSL_CIPHER_get_name(cipher),
        SSL_CIPHER_get_bits(cipher, NULL));

#ifndef OPENSSL_NO_COMP
    compression=SSL_get_current_compression(c->ssl);
    expansion=SSL_get_current_expansion(c->ssl);
    s_log(compression||expansion ? LOG_INFO : LOG_DEBUG,
        "Compression: %s, expansion: %s",
        compression ? SSL_COMP_get_name(compression) : "null",
        expansion ? SSL_COMP_get_name(expansion) : "null");
#endif
}

NOEXPORT void auth_user(CLI *c, char *accepted_address) {
#ifndef _WIN32_WCE
    struct servent *s_ent;    /* structure for getservbyname */
#endif
    SOCKADDR_UNION ident;     /* IDENT socket name */
    char *line, *type, *system, *user;

    if(!c->opt->username)
        return; /* -u option not specified */
#ifdef HAVE_STRUCT_SOCKADDR_UN
    if(c->peer_addr.sa.sa_family==AF_UNIX) {
        s_log(LOG_INFO, "IDENT not supported on Unix sockets");
        return;
    }
#endif
    c->fd=s_socket(c->peer_addr.sa.sa_family, SOCK_STREAM,
        0, 1, "socket (auth_user)");
    if(c->fd==INVALID_SOCKET)
        longjmp(c->err, 1);
    memcpy(&ident, &c->peer_addr, (size_t)c->peer_addr_len);
#ifndef _WIN32_WCE
    s_ent=getservbyname("auth", "tcp");
    if(s_ent) {
        ident.in.sin_port=(u_short)s_ent->s_port;
    } else
#endif
    {
        s_log(LOG_WARNING, "Unknown service 'auth': using default 113");
        ident.in.sin_port=htons(113);
    }
    if(s_connect(c, &ident, addr_len(&ident)))
        longjmp(c->err, 1);
    s_log(LOG_DEBUG, "IDENT server connected");
    fd_printf(c, c->fd, "%u , %u",
        ntohs(c->peer_addr.in.sin_port),
        ntohs(c->opt->local_addr.in.sin_port));
    line=fd_getline(c, c->fd);
    closesocket(c->fd);
    c->fd=INVALID_SOCKET; /* avoid double close on cleanup */
    type=strchr(line, ':');
    if(!type) {
        s_log(LOG_ERR, "Malformed IDENT response");
        str_free(line);
        longjmp(c->err, 1);
    }
    *type++='\0';
    system=strchr(type, ':');
    if(!system) {
        s_log(LOG_ERR, "Malformed IDENT response");
        str_free(line);
        longjmp(c->err, 1);
    }
    *system++='\0';
    if(strcmp(type, " USERID ")) {
        s_log(LOG_ERR, "Incorrect INETD response type");
        str_free(line);
        longjmp(c->err, 1);
    }
    user=strchr(system, ':');
    if(!user) {
        s_log(LOG_ERR, "Malformed IDENT response");
        str_free(line);
        longjmp(c->err, 1);
    }
    *user++='\0';
    while(*user==' ') /* skip leading spaces */
        ++user;
    if(strcmp(user, c->opt->username)) {
        s_log(LOG_WARNING, "Connection from %s REFUSED by IDENT (user \"%s\")",
            accepted_address, user);
        str_free(line);
        longjmp(c->err, 1);
    }
    s_log(LOG_INFO, "IDENT authentication passed");
    str_free(line);
}

#if defined(_WIN32_WCE) || defined(__vms)

NOEXPORT int connect_local(CLI *c) { /* spawn local process */
    s_log(LOG_ERR, "Local mode is not supported on this platform");
    longjmp(c->err, 1);
    return -1; /* some C compilers require a return value */
}

#elif defined(USE_WIN32)

NOEXPORT SOCKET connect_local(CLI *c) { /* spawn local process */
    SOCKET fd[2];
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    LPTSTR name, args;

    if(make_sockets(fd))
        longjmp(c->err, 1);
    memset(&si, 0, sizeof si);
    si.cb=sizeof si;
    si.dwFlags=STARTF_USESHOWWINDOW|STARTF_USESTDHANDLES;
    si.wShowWindow=SW_HIDE;
    si.hStdInput=si.hStdOutput=si.hStdError=(HANDLE)fd[1];
    memset(&pi, 0, sizeof pi);

    name=str2tstr(c->opt->exec_name);
    args=str2tstr(c->opt->exec_args);
    CreateProcess(name, args, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
    str_free(name);
    str_free(args);

    closesocket(fd[1]);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return fd[0];
}

#else /* standard Unix version */

NOEXPORT SOCKET connect_local(CLI *c) { /* spawn local process */
    char *name, host[40], port[6];
    int fd[2], pid;
    X509 *peer_cert;
#ifdef HAVE_PTHREAD_SIGMASK
    sigset_t newmask;
#endif

    if(c->opt->option.pty) {
        char tty[64];

        if(pty_allocate(fd, fd+1, tty))
            longjmp(c->err, 1);
        s_log(LOG_DEBUG, "TTY=%s allocated", tty);
    } else
        if(make_sockets(fd))
            longjmp(c->err, 1);

    pid=fork();
    c->pid=(unsigned long)pid;
    switch(pid) {
    case -1:    /* error */
        closesocket(fd[0]);
        closesocket(fd[1]);
        ioerror("fork");
        longjmp(c->err, 1);
    case  0:    /* child */
        tls_alloc(NULL, c->tls, NULL); /* reuse thread-local storage */
        closesocket(fd[0]);
        set_nonblock(fd[1], 0); /* switch back to blocking mode */
        /* dup2() does not copy FD_CLOEXEC flag */
        dup2(fd[1], 0);
        dup2(fd[1], 1);
        if(!global_options.option.foreground)
            dup2(fd[1], 2);
        closesocket(fd[1]); /* not really needed due to FD_CLOEXEC */

        if(!getnameinfo(&c->peer_addr.sa, c->peer_addr_len,
                host, 40, port, 6, NI_NUMERICHOST|NI_NUMERICSERV)) {
            /* just don't set these variables if getnameinfo() fails */
            putenv(str_printf("REMOTE_HOST=%s", host));
            putenv(str_printf("REMOTE_PORT=%s", port));
            if(c->opt->option.transparent_src) {
#ifndef LIBDIR
#define LIBDIR "."
#endif
#ifdef MACH64
                putenv("LD_PRELOAD_32=" LIBDIR "/libstunnel.so");
                putenv("LD_PRELOAD_64=" LIBDIR "/" MACH64 "/libstunnel.so");
#elif __osf /* for Tru64 _RLD_LIST is used instead */
                putenv("_RLD_LIST=" LIBDIR "/libstunnel.so:DEFAULT");
#else
                putenv("LD_PRELOAD=" LIBDIR "/libstunnel.so");
#endif
            }
        }

        if(c->ssl) {
            peer_cert=SSL_get_peer_certificate(c->ssl);
            if(peer_cert) {
                name=X509_NAME2text(X509_get_subject_name(peer_cert));
                putenv(str_printf("SSL_CLIENT_DN=%s", name));
                name=X509_NAME2text(X509_get_issuer_name(peer_cert));
                putenv(str_printf("SSL_CLIENT_I_DN=%s", name));
                X509_free(peer_cert);
            }
        }
#ifdef HAVE_PTHREAD_SIGMASK
        sigemptyset(&newmask);
        sigprocmask(SIG_SETMASK, &newmask, NULL);
#endif
        signal(SIGCHLD, SIG_DFL);
        signal(SIGHUP, SIG_DFL);
        signal(SIGUSR1, SIG_DFL);
        signal(SIGPIPE, SIG_DFL);
        signal(SIGTERM, SIG_DFL);
        signal(SIGQUIT, SIG_DFL);
        signal(SIGINT, SIG_DFL);
        execvp(c->opt->exec_name, c->opt->exec_args);
        ioerror(c->opt->exec_name); /* execvp failed */
        _exit(1);
    default: /* parent */
        s_log(LOG_INFO, "Local mode child started (PID=%lu)", c->pid);
        closesocket(fd[1]);
        return fd[0];
    }
}

#endif /* not USE_WIN32 or __vms */

/* connect remote host */
NOEXPORT SOCKET connect_remote(CLI *c) {
    SOCKET fd;
    unsigned ind_start, ind_try, ind_cur;

    setup_connect_addr(c);
    if(!c->connect_addr.num) {
        s_log(LOG_ERR, "No host resolved");
        longjmp(c->err, 1);
    }
    ind_start=connect_index(c);

    /* try to connect each host from the list */
    for(ind_try=0; ind_try<c->connect_addr.num; ind_try++) {
        ind_cur=(ind_start+ind_try)%c->connect_addr.num;
        c->fd=s_socket(c->connect_addr.addr[ind_cur].sa.sa_family,
            SOCK_STREAM, 0, 1, "remote socket");
        if(c->fd==INVALID_SOCKET)
            longjmp(c->err, 1);

        local_bind(c); /* explicit local bind or transparent proxy */

        if(s_connect(c, &c->connect_addr.addr[ind_cur],
                addr_len(&c->connect_addr.addr[ind_cur]))) {
            closesocket(c->fd);
            c->fd=INVALID_SOCKET;
            continue; /* next IP */
        }
        if(c->ssl)
            connect_cache(SSL_get_session(c->ssl),
                &c->connect_addr.addr[ind_cur]);
        print_bound_address(c);
        fd=c->fd;
        c->fd=INVALID_SOCKET;
        return fd; /* success! */
    }
    longjmp(c->err, 1);
    return INVALID_SOCKET; /* some C compilers require a return value */
}

NOEXPORT void connect_cache(SSL_SESSION *sess, SOCKADDR_UNION *cur_addr) {
    SOCKADDR_UNION *old_addr, *new_addr;
    socklen_t len;

    /* make a copy of the address, so it may work with delayed resolver */
    len=addr_len(cur_addr);
    new_addr=str_alloc_detached((size_t)len);
    memcpy(new_addr, cur_addr, (size_t)len);

    enter_critical_section(CRIT_ADDR);
    old_addr=SSL_SESSION_get_ex_data(sess, index_addr);
    SSL_SESSION_set_ex_data(sess, index_addr, new_addr);
    leave_critical_section(CRIT_ADDR);
    str_free(old_addr); /* NULL pointers are ignored */
}

NOEXPORT unsigned connect_index(CLI *c) {
    unsigned i;
    SOCKADDR_UNION addr, *ptr;
    socklen_t len;

    if(c->ssl && SSL_session_reused(c->ssl)) {
        enter_critical_section(CRIT_ADDR);
        ptr=SSL_SESSION_get_ex_data(SSL_get_session(c->ssl), index_addr);
        len=addr_len(ptr);
        memcpy(&addr, ptr, (size_t)len);
        leave_critical_section(CRIT_ADDR);
        if(ptr) { /* address was copied, ptr itself is no longer valid */
            for(i=0; i<c->connect_addr.num; ++i) {
                if(addr_len(&c->connect_addr.addr[i])==len &&
                        !memcmp(&c->connect_addr.addr[i],
                            &addr, (size_t)len)) {
                    s_log(LOG_INFO, "Cached address reused");
                    return i;
                }
            }
            s_log(LOG_ERR, "Cached address not configured");
        } else {
            s_log(LOG_NOTICE, "No cached address found");
        }
    }
    i=*c->connect_addr.rr_ptr;
    /* the race condition here can be safely ignored */
    if(c->opt->failover==FAILOVER_RR) {
        *c->connect_addr.rr_ptr=(i+1)%c->connect_addr.num;
        s_log(LOG_INFO, "Failover strategy: round-robin");
    } else {
        s_log(LOG_INFO, "Failover strategy: priority");
    }
    return i;
}

NOEXPORT void setup_connect_addr(CLI *c) {
#ifdef SO_ORIGINAL_DST
    socklen_t addrlen=sizeof(SOCKADDR_UNION);
#endif /* SO_ORIGINAL_DST */

    /* process "redirect" first */
    if(c->redirect==REDIRECT_ON) {
        s_log(LOG_NOTICE, "Redirecting connection");
        /* c->connect_addr.addr may be allocated in protocol negotiations */
        str_free(c->connect_addr.addr);
        addrlist_dup(&c->connect_addr, &c->opt->redirect_addr);
        return;
    }

    /* check if the address was already set in protocol negotiations */
    /* used by the following protocols: CONNECT, SOCKS */
    if(c->connect_addr.num)
        return;

    /* transparent destination */
#ifdef SO_ORIGINAL_DST
    if(c->opt->option.transparent_dst) {
        c->connect_addr.num=1;
        c->connect_addr.addr=str_alloc(sizeof(SOCKADDR_UNION));
        if(getsockopt(c->local_rfd.fd, SOL_IP, SO_ORIGINAL_DST,
                c->connect_addr.addr, &addrlen)) {
            sockerror("setsockopt SO_ORIGINAL_DST");
            longjmp(c->err, 1);
        }
        return;
    }
#endif /* SO_ORIGINAL_DST */

    /* default "connect" target */
    addrlist_dup(&c->connect_addr, &c->opt->connect_addr);
}

NOEXPORT void local_bind(CLI *c) {
#ifndef USE_WIN32
    int on;

    on=1;
#endif
    if(!c->bind_addr)
        return;
#if defined(USE_WIN32)
    /* do nothing */
#elif defined(__linux__)
    /* non-local bind on Linux */
    if(c->opt->option.transparent_src) {
        if(setsockopt(c->fd, SOL_IP, IP_TRANSPARENT, &on, sizeof on)) {
            sockerror("setsockopt IP_TRANSPARENT");
            if(setsockopt(c->fd, SOL_IP, IP_FREEBIND, &on, sizeof on))
                sockerror("setsockopt IP_FREEBIND");
            else
                s_log(LOG_INFO, "IP_FREEBIND socket option set");
        } else
            s_log(LOG_INFO, "IP_TRANSPARENT socket option set");
        /* ignore the error to retain Linux 2.2 compatibility */
        /* the error will be handled by bind(), anyway */
    }
#elif defined(IP_BINDANY) && defined(IPV6_BINDANY)
    /* non-local bind on FreeBSD */
    if(c->opt->option.transparent_src) {
        if(c->bind_addr->sa.sa_family==AF_INET) { /* IPv4 */
            if(setsockopt(c->fd, IPPROTO_IP, IP_BINDANY, &on, sizeof on)) {
                sockerror("setsockopt IP_BINDANY");
                longjmp(c->err, 1);
            }
        } else { /* IPv6 */
            if(setsockopt(c->fd, IPPROTO_IPV6, IPV6_BINDANY, &on, sizeof on)) {
                sockerror("setsockopt IPV6_BINDANY");
                longjmp(c->err, 1);
            }
        }
    }
#else
    /* unsupported platform */
    if(c->opt->option.transparent_src) {
        s_log(LOG_ERR, "Transparent proxy in remote mode is not supported"
            " on this platform");
        longjmp(c->err, 1);
    }
#endif

    if(ntohs(c->bind_addr->in.sin_port)>=1024) { /* security check */
        /* this is currently only possible with transparent_src */
        if(!bind(c->fd, &c->bind_addr->sa, addr_len(c->bind_addr))) {
            s_log(LOG_INFO, "local_bind succeeded on the original port");
            return; /* success */
        }
        if(get_last_socket_error()!=S_EADDRINUSE) {
            sockerror("local_bind (original port)");
            longjmp(c->err, 1);
        }
    }

    c->bind_addr->in.sin_port=htons(0); /* retry with ephemeral port */
    if(!bind(c->fd, &c->bind_addr->sa, addr_len(c->bind_addr))) {
        s_log(LOG_INFO, "local_bind succeeded on an ephemeral port");
        return; /* success */
    }
    sockerror("local_bind (ephemeral port)");
    longjmp(c->err, 1);
}

NOEXPORT void print_bound_address(CLI *c) {
    char *txt;
    SOCKADDR_UNION addr;
    socklen_t addrlen=sizeof addr;

    if(c->opt->log_level<LOG_NOTICE) /* performance optimization */
        return;
    memset(&addr, 0, (size_t)addrlen);
    if(getsockname(c->fd, (struct sockaddr *)&addr, &addrlen)) {
        sockerror("getsockname");
        return;
    }
    txt=s_ntop(&addr, addrlen);
    s_log(LOG_NOTICE,"Service [%s] connected remote server from %s",
        c->opt->servname, txt);
    str_free(txt);
}

NOEXPORT void reset(SOCKET fd, char *txt) { /* set lingering on a socket */
    struct linger l;

    l.l_onoff=1;
    l.l_linger=0;
    if(setsockopt(fd, SOL_SOCKET, SO_LINGER, (void *)&l, sizeof l))
        log_error(LOG_DEBUG, get_last_socket_error(), txt);
}

/* end of client.c */
