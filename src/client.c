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

#ifndef SHUT_RD
#define SHUT_RD 0
#endif
#ifndef SHUT_WR
#define SHUT_WR 1
#endif
#ifndef SHUT_RDWR
#define SHUT_RDWR 2
#endif

static char *sid_ctx="stunnel SID";
    /* const allowed here */

static void do_client(CLI *);
static void run_client(CLI *);
static void init_local(CLI *);
static void init_remote(CLI *);
static void init_ssl(CLI *);
static void transfer(CLI *);
static void parse_socket_error(CLI *, const char *);

static void print_cipher(CLI *);
static void auth_user(CLI *, char *);
static int connect_local(CLI *);
static int connect_remote(CLI *, SOCKADDR_UNION *);
#ifdef SO_ORIGINAL_DST
static int connect_transparent(CLI *, SOCKADDR_UNION *);
#endif /* SO_ORIGINAL_DST */
static void local_bind(CLI *c, SOCKADDR_UNION *);
static void print_bound_address(CLI *);
static void reset(int, char *);

/* allocate local data structure for the new thread */
CLI *alloc_client_session(SERVICE_OPTIONS *opt, int rfd, int wfd) {
    CLI *c;

    c=str_alloc(sizeof(CLI));
    str_detach(c);
    c->opt=opt;
    c->local_rfd.fd=rfd;
    c->local_wfd.fd=wfd;
    return c;
}

void *client(void *arg) {
    CLI *c=arg;

#ifdef DEBUG_STACK_SIZE
    stack_info(1); /* initialize */
#endif
    s_log(LOG_DEBUG, "Service %s started", c->opt->servname);
    c->fds=s_poll_alloc();
    if(c->opt->option.remote && c->opt->option.program) {
            /* connect and exec options specified together */
            /* -> spawn a local program instead of stdio */
        while((c->local_rfd.fd=c->local_wfd.fd=connect_local(c))>=0) {
            run_client(c);
            if(!c->opt->option.retry)
                break;
            sleep(1); /* FIXME: not a good idea in ucontext threading */
            str_stats();
            str_cleanup();
        }
    } else
        run_client(c);
    s_poll_free(c->fds);
    str_free(c);
#ifdef DEBUG_STACK_SIZE
    stack_info(0); /* display computed value */
#endif
#ifdef USE_UCONTEXT
    s_log(LOG_DEBUG, "Context %ld closed", ready_head->id);
#endif
    str_stats();
    str_cleanup();
    /* s_log() is not allowed after str_cleanup() */
#if defined(USE_WIN32) && !defined(_WIN32_WCE)
    _endthread();
#endif
#ifdef USE_UCONTEXT
    s_poll_wait(NULL, 0, 0); /* wait on poll() */
#endif
    return NULL;
}

static void run_client(CLI *c) {
    int error;

    c->remote_fd.fd=-1;
    c->fd=-1;
    c->ssl=NULL;
    c->sock_bytes=c->ssl_bytes=0;

    error=setjmp(c->err);
    if(!error)
        do_client(c);

    s_log(LOG_NOTICE,
        "Connection %s: %d bytes sent to SSL, %d bytes sent to socket",
         error==1 ? "reset" : "closed", c->ssl_bytes, c->sock_bytes);

        /* cleanup temporary (e.g. IDENT) socket */
    if(c->fd>=0)
        closesocket(c->fd);

        /* cleanup SSL */
    if(c->ssl) { /* SSL initialized */
        SSL_set_shutdown(c->ssl, SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
        SSL_free(c->ssl);
        ERR_remove_state(0);
    }

        /* cleanup remote socket */
    if(c->remote_fd.fd>=0) { /* remote socket initialized */
        if(error==1 && c->remote_fd.is_socket)
            reset(c->remote_fd.fd, "linger (remote)");
        closesocket(c->remote_fd.fd);
    }

        /* cleanup local socket */
    if(c->local_rfd.fd>=0) { /* local socket initialized */
        if(c->local_rfd.fd==c->local_wfd.fd) {
            if(error==1 && c->local_rfd.is_socket)
                reset(c->local_rfd.fd, "linger (local)");
            closesocket(c->local_rfd.fd);
        } else { /* STDIO */
            if(error==1 && c->local_rfd.is_socket)
                reset(c->local_rfd.fd, "linger (local_rfd)");
            if(error==1 && c->local_wfd.is_socket)
                reset(c->local_wfd.fd, "linger (local_wfd)");
       }
    }
#ifdef USE_FORK
    if(!c->opt->option.remote) /* 'exec' specified */
        child_status(); /* null SIGCHLD handler was used */
#else
    enter_critical_section(CRIT_CLIENTS); /* for multi-cpu machines */
    s_log(LOG_DEBUG, "Service %s finished (%d left)", c->opt->servname,
        --num_clients);
    leave_critical_section(CRIT_CLIENTS);
#endif
}

static void do_client(CLI *c) {
    init_local(c);
    if(!c->opt->option.client && c->opt->protocol<0) {
        /* server mode and no protocol negotiation needed */
        init_ssl(c);
        init_remote(c);
    } else {
        init_remote(c);
        protocol(c, 0); /* pre-SSL protocol negotiations */
        init_ssl(c);
    }
    protocol(c, 1); /* post-SSL protocol negotiations */
    transfer(c);
}

static void init_local(CLI *c) {
    char *accepted_address;

    c->peer_addr_len=sizeof(SOCKADDR_UNION);
    if(getpeername(c->local_rfd.fd, &c->peer_addr.sa, &c->peer_addr_len)<0) {
        c->local_rfd.is_socket=0;
        c->local_wfd.is_socket=0; /* TODO: It's not always true */
#ifdef USE_WIN32
        if(get_last_socket_error()!=S_ENOTSOCK) {
#else
        if(c->opt->option.transparent_src || get_last_socket_error()!=S_ENOTSOCK) {
#endif
            sockerror("getpeerbyname");
            longjmp(c->err, 1);
        }
        /* ignore S_ENOTSOCK error so 'local' doesn't have to be a socket */
        s_log(LOG_NOTICE, "Service %s accepted connection", c->opt->servname);
        return;
    }
    accepted_address=s_ntop(&c->peer_addr, c->peer_addr_len);
    c->local_rfd.is_socket=1;
    c->local_wfd.is_socket=1; /* TODO: It's not always true */
    /* it's a socket: lets setup options */
    if(set_socket_options(c->local_rfd.fd, 1)<0)
        longjmp(c->err, 1);
#ifdef USE_LIBWRAP
    libwrap_auth(c, accepted_address);
#endif /* USE_LIBWRAP */
    auth_user(c, accepted_address);
    s_log(LOG_NOTICE, "Service %s accepted connection from %s",
        c->opt->servname, accepted_address);
    str_free(accepted_address);
}

static void init_remote(CLI *c) {
    SOCKADDR_UNION *bind_addr;

    /* where to bind connecting socket */
    if(c->opt->option.local) /* outgoing interface */
        bind_addr=&c->opt->source_addr;
#ifndef USE_WIN32
    else if(c->opt->option.transparent_src)
        bind_addr=&c->peer_addr;
#endif
    else
        bind_addr=NULL; /* don't bind */

    /* setup c->remote_fd, now */
    if(c->opt->option.remote)
        c->remote_fd.fd=connect_remote(c, bind_addr);
#ifdef SO_ORIGINAL_DST
    else if(c->opt->option.transparent_dst)
        c->remote_fd.fd=connect_transparent(c, bind_addr);
#endif /* SO_ORIGINAL_DST */
    else /* NOT in remote mode */
        c->remote_fd.fd=connect_local(c);
    c->remote_fd.is_socket=1; /* always! */
    s_log(LOG_DEBUG, "Remote FD=%d initialized", c->remote_fd.fd);
    if(set_socket_options(c->remote_fd.fd, 2)<0)
        longjmp(c->err, 1);
}

static void init_ssl(CLI *c) {
    int i, err;
    SSL_SESSION *old_session;

    if(!(c->ssl=SSL_new(c->opt->ctx))) {
        sslerror("SSL_new");
        longjmp(c->err, 1);
    }
    SSL_set_ex_data(c->ssl, cli_index, c); /* for callbacks */
    SSL_set_session_id_context(c->ssl, (unsigned char *)sid_ctx,
        strlen(sid_ctx) );
    if(c->opt->option.client) {
#ifndef OPENSSL_NO_TLSEXT
        if(c->opt->host_name) {
            s_log(LOG_DEBUG, "SNI: host name: %s", c->opt->host_name);
            if(!SSL_set_tlsext_host_name(c->ssl, c->opt->host_name)) {
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
        SSL_set_fd(c->ssl, c->remote_fd.fd);
        SSL_set_connect_state(c->ssl);
    } else {
        if(c->local_rfd.fd==c->local_wfd.fd)
            SSL_set_fd(c->ssl, c->local_rfd.fd);
        else {
           /* does it make sence to have SSL on STDIN/STDOUT? */
            SSL_set_rfd(c->ssl, c->local_rfd.fd);
            SSL_set_wfd(c->ssl, c->local_wfd.fd);
        }
        SSL_set_accept_state(c->ssl);
    }

    /* setup some values for transfer() function */
    if(c->opt->option.client) {
        c->sock_rfd=&(c->local_rfd);
        c->sock_wfd=&(c->local_wfd);
        c->ssl_rfd=c->ssl_wfd=&(c->remote_fd);
    } else {
        c->sock_rfd=c->sock_wfd=&(c->remote_fd);
        c->ssl_rfd=&(c->local_rfd);
        c->ssl_wfd=&(c->local_wfd);
    }

    while(1) {
#if OPENSSL_VERSION_NUMBER<0x1000002fL
        /* this critical section is a crude workaround for CVE-2010-3864 *
         * see http://www.securityfocus.com/bid/44884 for details        *
         * NOTE: this critical section also covers callbacks (e.g. OCSP) */
        enter_critical_section(CRIT_SSL);
#endif /* OpenSSL version < 1.0.0b */
        if(c->opt->option.client)
            i=SSL_connect(c->ssl);
        else
            i=SSL_accept(c->ssl);
#if OPENSSL_VERSION_NUMBER<0x1000002fL
        leave_critical_section(CRIT_SSL);
#endif /* OpenSSL version < 1.0.0b */
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
                sockerror("init_ssl: s_poll_wait");
                longjmp(c->err, 1);
            case 0:
                s_log(LOG_INFO, "init_ssl: s_poll_wait:"
                    " TIMEOUTbusy exceeded: sending reset");
                longjmp(c->err, 1);
            case 1:
                break; /* OK */
            default:
                s_log(LOG_ERR, "init_ssl: s_poll_wait: unknown result");
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
    if(SSL_session_reused(c->ssl)) {
        s_log(LOG_INFO, "SSL %s: previous session reused",
            c->opt->option.client ? "connected" : "accepted");
    } else { /* a new session was negotiated */
#ifdef USE_WIN32
        win_newcert(c->ssl, c->opt);
#endif
        if(c->opt->option.client) {
            s_log(LOG_INFO, "SSL connected: new session negotiated");
            enter_critical_section(CRIT_SESSION);
            old_session=c->opt->session;
            c->opt->session=SSL_get1_session(c->ssl); /* store it */
            if(old_session)
                SSL_SESSION_free(old_session); /* release the old one */
            leave_critical_section(CRIT_SESSION);
        } else
            s_log(LOG_INFO, "SSL accepted: new session negotiated");
        print_cipher(c);
    }
}

/****************************** transfer data */
static void transfer(CLI *c) {
    int watchdog=0; /* a counter to detect an infinite loop */
    int num, err;
    /* logical channels (not file descriptors!) open for read or write */
    int sock_open_rd=1, sock_open_wr=1, ssl_open_rd=1, ssl_open_wr=1;
    /* awaited conditions on SSL file descriptors */
    int shutdown_wants_read=0, shutdown_wants_write=0;
    int read_wants_read, read_wants_write=0;
    int write_wants_read=0, write_wants_write;
    /* actual conditions on file descriptors */
    int sock_can_rd, sock_can_wr, ssl_can_rd, ssl_can_wr;

    c->sock_ptr=c->ssl_ptr=0;

    do { /* main loop of client data transfer */
        /****************************** initialize *_wants_* */
        read_wants_read=
            ssl_open_rd && c->ssl_ptr<BUFFSIZE && !read_wants_write;
        write_wants_write=
            ssl_open_wr && c->sock_ptr && !write_wants_read;

        /****************************** setup c->fds structure */
        s_poll_init(c->fds); /* initialize the structure */
        /* for plain socket open data strem = open file descriptor */
        /* make sure to add each open socket to receive exceptions! */
        if(sock_open_rd)
            s_poll_add(c->fds, c->sock_rfd->fd, c->sock_ptr<BUFFSIZE, 0);
        if(sock_open_wr)
            s_poll_add(c->fds, c->sock_wfd->fd, 0, c->ssl_ptr);
        /* for SSL assume that sockets are open if there any pending requests */
        if(read_wants_read || write_wants_read || shutdown_wants_read)
            s_poll_add(c->fds, c->ssl_rfd->fd, 1, 0);
        if(read_wants_write || write_wants_write || shutdown_wants_write)
            s_poll_add(c->fds, c->ssl_wfd->fd, 0, 1);

        /****************************** wait for an event */
        err=s_poll_wait(c->fds,
            (sock_open_rd && ssl_open_rd) /* both peers open */ ||
            c->ssl_ptr /* data buffered to write to socket */ ||
            c->sock_ptr /* data buffered to write to SSL */ ?
            c->opt->timeout_idle : c->opt->timeout_close, 0);
        switch(err) {
        case -1:
            sockerror("transfer: s_poll_wait");
            longjmp(c->err, 1);
        case 0: /* timeout */
            if((sock_open_rd && ssl_open_rd) || c->ssl_ptr || c->sock_ptr) {
                s_log(LOG_INFO, "transfer: s_poll_wait:"
                    " TIMEOUTidle exceeded: sending reset");
                longjmp(c->err, 1);
            } else { /* already closing connection */
                s_log(LOG_ERR, "transfer: s_poll_wait:"
                    " TIMEOUTclose exceeded: closing");
                return; /* OK */
            }
        }

        /****************************** check for errors on sockets */
        err=s_poll_error(c->fds, c->sock_rfd->fd);
        if(err) {
            s_log(LOG_NOTICE,
                "Error detected on socket (read) file descriptor: %s (%d)",
                s_strerror(err), err);
            longjmp(c->err, 1);
        }
        if(c->sock_wfd->fd != c->sock_rfd->fd) { /* performance optimization */
            err=s_poll_error(c->fds, c->sock_wfd->fd);
            if(err) {
                s_log(LOG_NOTICE,
                    "Error detected on socket write file descriptor: %s (%d)",
                    s_strerror(err), err);
                longjmp(c->err, 1);
            }
        }
        err=s_poll_error(c->fds, c->ssl_rfd->fd);
        if(err) {
            s_log(LOG_NOTICE,
                "Error detected on SSL (read) file descriptor: %s (%d)",
                s_strerror(err), err);
            longjmp(c->err, 1);
        }
        if(c->ssl_wfd->fd != c->ssl_rfd->fd) { /* performance optimization */
            err=s_poll_error(c->fds, c->ssl_wfd->fd);
            if(err) {
                s_log(LOG_NOTICE,
                    "Error detected on SSL write file descriptor: %s (%d)",
                    s_strerror(err), err);
                longjmp(c->err, 1);
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
        /* these checks should no longer be needed */
        /* I'm going to remove them soon */
        if(!sock_open_rd && sock_can_rd) {
            err=get_socket_error(c->sock_rfd->fd);
            if(err) { /* really an error? */
                s_log(LOG_ERR, "INTERNAL ERROR: "
                    "Closed socket ready to read: %s (%d)",
                    s_strerror(err), err);
                longjmp(c->err, 1);
            }
            if(c->ssl_ptr) { /* anything left to write */
                s_log(LOG_ERR, "INTERNAL ERROR: "
                    "Closed socket ready to read: sending reset");
                longjmp(c->err, 1);
            }
            s_log(LOG_ERR, "INTERNAL ERROR: "
                "Closed socket ready to read: write close");
            sock_open_wr=0; /* no further write allowed */
            shutdown(c->sock_wfd->fd, SHUT_WR); /* send TCP FIN */
        }

        /****************************** send SSL close_notify message */
        if(shutdown_wants_read || shutdown_wants_write) {
            shutdown_wants_read=shutdown_wants_write=0;
            num=SSL_shutdown(c->ssl); /* send close_notify */
            if(num<0) /* -1 - not completed */
                err=SSL_get_error(c->ssl, num);
            else /* 0 or 1 - success */
                err=SSL_ERROR_NONE;
            switch(err) {
            case SSL_ERROR_NONE: /* the shutdown was successfully completed */
                s_log(LOG_INFO, "SSL_shutdown successfully sent close_notify");
                break;
            case SSL_ERROR_WANT_WRITE:
                s_log(LOG_DEBUG, "SSL_shutdown returned WANT_WRITE: retrying");
                shutdown_wants_write=1;
                break;
            case SSL_ERROR_WANT_READ:
                s_log(LOG_DEBUG, "SSL_shutdown returned WANT_READ: retrying");
                shutdown_wants_read=1;
                break;
            case SSL_ERROR_SYSCALL: /* socket error */
                parse_socket_error(c, "SSL_shutdown");
                break;
            case SSL_ERROR_SSL: /* SSL error */
                sslerror("SSL_shutdown");
                longjmp(c->err, 1);
            default:
                s_log(LOG_ERR, "SSL_shutdown/SSL_get_error returned %d", err);
                longjmp(c->err, 1);
            }
        }

        /****************************** read from socket */
        if(sock_open_rd && sock_can_rd) {
            num=readsocket(c->sock_rfd->fd,
                c->sock_buff+c->sock_ptr, BUFFSIZE-c->sock_ptr);
            switch(num) {
            case -1:
                parse_socket_error(c, "readsocket");
                break;
            case 0: /* close */
                s_log(LOG_DEBUG, "Socket closed on read");
                sock_open_rd=0;
                break;
            default:
                c->sock_ptr+=num;
                watchdog=0; /* reset watchdog */
            }
        }

        /****************************** write to socket */
        if(sock_open_wr && sock_can_wr) {
            num=writesocket(c->sock_wfd->fd, c->ssl_buff, c->ssl_ptr);
            switch(num) {
            case -1: /* error */
                parse_socket_error(c, "writesocket");
                break;
            case 0:
                s_log(LOG_DEBUG, "No data written to the socket: retrying");
                break;
            default:
                memmove(c->ssl_buff, c->ssl_buff+num, c->ssl_ptr-num);
                c->ssl_ptr-=num;
                c->sock_bytes+=num;
                watchdog=0; /* reset watchdog */
            }
        }

        /****************************** update *_wants_* based on new *_ptr */
        /* this update is also required for SSL_pending() to be used */
        read_wants_read=
            ssl_open_rd && c->ssl_ptr<BUFFSIZE && !read_wants_write;
        write_wants_write=
            ssl_open_wr && c->sock_ptr && !write_wants_read;

        /****************************** read from SSL */
        if((read_wants_read && (ssl_can_rd || SSL_pending(c->ssl))) ||
                /* it may be possible to read some pending data after
                 * writesocket() above made some room in c->ssl_buff */
                (read_wants_write && ssl_can_wr)) {
            read_wants_write=0;
            num=SSL_read(c->ssl, c->ssl_buff+c->ssl_ptr, BUFFSIZE-c->ssl_ptr);
            switch(err=SSL_get_error(c->ssl, num)) {
            case SSL_ERROR_NONE:
                c->ssl_ptr+=num;
                watchdog=0; /* reset watchdog */
                break;
            case SSL_ERROR_WANT_WRITE:
                s_log(LOG_DEBUG, "SSL_read returned WANT_WRITE: retrying");
                read_wants_write=1;
                break;
            case SSL_ERROR_WANT_READ: /* nothing unexpected */
                break;
            case SSL_ERROR_WANT_X509_LOOKUP:
                s_log(LOG_DEBUG,
                    "SSL_read returned WANT_X509_LOOKUP: retrying");
                break;
            case SSL_ERROR_SYSCALL:
                if(!num) { /* EOF */
                    if(c->sock_ptr) {
                        s_log(LOG_ERR,
                            "SSL socket closed on SSL_read "
                                "with %d byte(s) in buffer",
                            c->sock_ptr);
                        longjmp(c->err, 1); /* reset the socket */
                    }
                    s_log(LOG_DEBUG, "SSL socket closed on SSL_read");
                    ssl_open_rd=ssl_open_wr=0; /* buggy peer: no close_notify */
                } else
                    parse_socket_error(c, "SSL_read");
                break;
            case SSL_ERROR_ZERO_RETURN: /* close_notify received */
                s_log(LOG_DEBUG, "SSL closed on SSL_read");
                ssl_open_rd=0;
                if(!strcmp(SSL_get_version(c->ssl), "SSLv2"))
                    ssl_open_wr=0;
                break;
            case SSL_ERROR_SSL:
                sslerror("SSL_read");
                longjmp(c->err, 1);
            default:
                s_log(LOG_ERR, "SSL_read/SSL_get_error returned %d", err);
                longjmp(c->err, 1);
            }
        }

        /****************************** write to SSL */
        if((write_wants_read && ssl_can_rd) ||
                (write_wants_write && ssl_can_wr)) {
            write_wants_read=0;
            num=SSL_write(c->ssl, c->sock_buff, c->sock_ptr);
            switch(err=SSL_get_error(c->ssl, num)) {
            case SSL_ERROR_NONE:
                memmove(c->sock_buff, c->sock_buff+num, c->sock_ptr-num);
                c->sock_ptr-=num;
                c->ssl_bytes+=num;
                watchdog=0; /* reset watchdog */
                break;
            case SSL_ERROR_WANT_WRITE: /* nothing unexpected */
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
                if(!num) { /* EOF */
                    if(c->sock_ptr) {
                        s_log(LOG_ERR,
                            "SSL socket closed on SSL_write "
                                "with %d byte(s) in buffer",
                            c->sock_ptr);
                        longjmp(c->err, 1); /* reset the socket */
                    }
                    s_log(LOG_DEBUG, "SSL socket closed on SSL_write");
                    ssl_open_rd=ssl_open_wr=0; /* buggy peer: no close_notify */
                } else
                    parse_socket_error(c, "SSL_write");
                break;
            case SSL_ERROR_ZERO_RETURN: /* close_notify received */
                s_log(LOG_DEBUG, "SSL closed on SSL_write");
                ssl_open_rd=0;
                if(!strcmp(SSL_get_version(c->ssl), "SSLv2"))
                    ssl_open_wr=0;
                break;
            case SSL_ERROR_SSL:
                sslerror("SSL_write");
                longjmp(c->err, 1);
            default:
                s_log(LOG_ERR, "SSL_write/SSL_get_error returned %d", err);
                longjmp(c->err, 1);
            }
        }

        /****************************** check write shutdown conditions */
        if(sock_open_wr && !ssl_open_rd && !c->ssl_ptr) {
            s_log(LOG_DEBUG, "Sending socket write shutdown");
            sock_open_wr=0; /* no further write allowed */
            shutdown(c->sock_wfd->fd, SHUT_WR); /* send TCP FIN */
        }
        if(ssl_open_wr && !sock_open_rd && !c->sock_ptr) {
            s_log(LOG_DEBUG, "Sending SSL write shutdown");
            ssl_open_wr=0; /* no further write allowed */
            if(strcmp(SSL_get_version(c->ssl), "SSLv2")) { /* SSLv3, TLSv1 */
                shutdown_wants_write=1; /* initiate close_notify */
            } else { /* no alerts in SSLv2 including close_notify alert */
                shutdown(c->sock_rfd->fd, SHUT_RD); /* notify the kernel */
                shutdown(c->sock_wfd->fd, SHUT_WR); /* send TCP FIN */
                SSL_set_shutdown(c->ssl, /* notify the OpenSSL library */
                    SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
                ssl_open_rd=0; /* no further read allowed */
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
            s_log(LOG_ERR, "sock_open_rd=%s, sock_open_wr=%s, "
                "ssl_open_rd=%s, ssl_open_wr=%s",
                sock_open_rd ? "Y" : "n", sock_open_wr ? "Y" : "n",
                ssl_open_rd ? "Y" : "n", ssl_open_wr ? "Y" : "n");
            s_log(LOG_ERR, "sock_can_rd=%s,  sock_can_wr=%s,  "
                "ssl_can_rd=%s,  ssl_can_wr=%s",
                sock_can_rd ? "Y" : "n", sock_can_wr ? "Y" : "n",
                ssl_can_rd ? "Y" : "n", ssl_can_wr ? "Y" : "n");
            s_log(LOG_ERR, "read_wants_read=%s,     read_wants_write=%s",
                read_wants_read ? "Y" : "n",
                read_wants_write ? "Y" : "n");
            s_log(LOG_ERR, "write_wants_read=%s,    write_wants_write=%s",
                write_wants_read ? "Y" : "n",
                write_wants_write ? "Y" : "n");
            s_log(LOG_ERR, "shutdown_wants_read=%s, shutdown_wants_write=%s",
                shutdown_wants_read ? "Y" : "n",
                shutdown_wants_write ? "Y" : "n");
            s_log(LOG_ERR, "socket input buffer: %d byte(s), "
                "ssl input buffer: %d byte(s)", c->sock_ptr, c->ssl_ptr);
            longjmp(c->err, 1);
        }

    } while(sock_open_wr || ssl_open_wr ||
        shutdown_wants_read || shutdown_wants_write);
}

static void parse_socket_error(CLI *c, const char *text) {
    switch(get_last_socket_error()) {
    case S_EINTR:
        s_log(LOG_DEBUG,
            "Function %s interrupted by a signal: retrying", text);
        return;
    case S_EWOULDBLOCK:
        s_log(LOG_NOTICE, "Function %s would block: retrying", text);
        sleep(1); /* Microsoft bug KB177346 */
        return;
#if S_EAGAIN!=S_EWOULDBLOCK
    case S_EAGAIN:
        s_log(LOG_DEBUG,
            "Function %s temporary lack of resources: retrying", text);
        return;
#endif
    default:
        sockerror(text);
        longjmp(c->err, 1);
    }
}

static void print_cipher(CLI *c) { /* print negotiated cipher */
    SSL_CIPHER *cipher;
    char *buf, *i, *j;

    if(global_options.debug_level<LOG_INFO) /* performance optimization */
        return;
    cipher=(SSL_CIPHER *)SSL_get_current_cipher(c->ssl);
    buf=SSL_CIPHER_description(cipher, NULL, 0);
    i=j=buf;
    do {
        switch(*i) {
        case ' ':
            *j++=' ';
            while(i[1]==' ')
                ++i;
            break;
        case '\n':
            break;
        default:
            *j++=*i;
        }
    } while(*i++);
    s_log(LOG_INFO, "Negotiated ciphers: %s", buf);
    OPENSSL_free(buf);
}

static void auth_user(CLI *c, char *accepted_address) {
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
    if(c->fd<0)
        longjmp(c->err, 1);
    memcpy(&ident, &c->peer_addr, c->peer_addr_len);
#ifndef _WIN32_WCE
    s_ent=getservbyname("auth", "tcp");
    if(s_ent) {
        ident.in.sin_port=s_ent->s_port;
    } else
#endif
    {
        s_log(LOG_WARNING, "Unknown service 'auth': using default 113");
        ident.in.sin_port=htons(113);
    }
    if(connect_blocking(c, &ident, addr_len(&ident)))
        longjmp(c->err, 1);
    s_log(LOG_DEBUG, "IDENT server connected");
    fdprintf(c, c->fd, "%u , %u",
        ntohs(c->peer_addr.in.sin_port),
        ntohs(c->opt->local_addr.in.sin_port));
    line=fdgetline(c, c->fd);
    closesocket(c->fd);
    c->fd=-1; /* avoid double close on cleanup */
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
        safestring(user);
        s_log(LOG_WARNING, "Connection from %s REFUSED by IDENT (user %s)",
            accepted_address, user);
        str_free(line);
        longjmp(c->err, 1);
    }
    s_log(LOG_INFO, "IDENT authentication passed");
    str_free(line);
}

#if defined(_WIN32_WCE) || defined(__vms)

static int connect_local(CLI *c) { /* spawn local process */
    s_log(LOG_ERR, "Local mode is not supported on this platform");
    longjmp(c->err, 1);
    return -1; /* some C compilers require a return value */
}

#elif defined(USE_WIN32)

static int connect_local(CLI *c) { /* spawn local process */
    int fd[2];
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    LPTSTR execname_l, execargs_l;

    if(make_sockets(fd))
        longjmp(c->err, 1);
    memset(&si, 0, sizeof si);
    si.cb=sizeof si;
    si.wShowWindow=SW_HIDE;
    si.dwFlags=STARTF_USESHOWWINDOW|STARTF_USESTDHANDLES;
    si.hStdInput=si.hStdOutput=si.hStdError=(HANDLE)fd[1];
    memset(&pi, 0, sizeof pi);

    execname_l=str2tstr(c->opt->execname);
    execargs_l=str2tstr(c->opt->execargs);
    CreateProcess(execname_l, execargs_l, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
    str_free(execname_l);
    str_free(execargs_l);

    closesocket(fd[1]);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return fd[0];
}

#else /* standard Unix version */

static int connect_local(CLI *c) { /* spawn local process */
    char *name, host[40];
    int fd[2], pid;
    X509 *peer;
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
        closesocket(fd[0]);
        set_nonblock(fd[1], 0); /* switch back to blocking mode */
        /* dup2() does not copy FD_CLOEXEC flag */
        dup2(fd[1], 0);
        dup2(fd[1], 1);
        if(!global_options.option.foreground)
            dup2(fd[1], 2);
        closesocket(fd[1]); /* not really needed due to FD_CLOEXEC */

        if(!getnameinfo(&c->peer_addr.sa, c->peer_addr_len,
                host, 40, NULL, 0, NI_NUMERICHOST)) {
            /* just don't set these variables if getnameinfo() fails */
            putenv(str_printf("REMOTE_HOST=%s", host));
            if(c->opt->option.transparent_src) {
                putenv("LD_PRELOAD=" LIBDIR "/libstunnel.so");
                /* for Tru64 _RLD_LIST is used instead */
                putenv("_RLD_LIST=" LIBDIR "/libstunnel.so:DEFAULT");
            }
        }

        if(c->ssl) {
            peer=SSL_get_peer_certificate(c->ssl);
            if(peer) {
                name=X509_NAME_oneline(X509_get_subject_name(peer), NULL, 0);
                safestring(name);
                putenv(str_printf("SSL_CLIENT_DN=%s", name));
                name=X509_NAME_oneline(X509_get_issuer_name(peer), NULL, 0);
                safestring(name);
                putenv(str_printf("SSL_CLIENT_I_DN=%s", name));
                X509_free(peer);
            }
        }
#ifdef HAVE_PTHREAD_SIGMASK
        sigemptyset(&newmask);
        sigprocmask(SIG_SETMASK, &newmask, NULL);
#endif
        execvp(c->opt->execname, c->opt->execargs);
        ioerror(c->opt->execname); /* execv failed */
        _exit(1);
    default: /* parent */
        s_log(LOG_INFO, "Local mode child started (PID=%lu)", c->pid);
        closesocket(fd[1]);
        return fd[0];
    }
}

#endif /* not USE_WIN32 or __vms */

/* connect remote host */
static int connect_remote(CLI *c, SOCKADDR_UNION *bind_addr) {
    SOCKADDR_LIST resolved_list, *address_list;
    int fd, ind_try, ind_cur;

    /* setup address_list */
    resolved_list.num=0;
    resolved_list.addr=NULL;
    if(c->opt->option.delayed_lookup) {
        if(!name2addrlist(&resolved_list,
                c->opt->remote_address, DEFAULT_LOOPBACK)) {
            s_log(LOG_ERR, "No host resolved");
            longjmp(c->err, 1);
        }
        address_list=&resolved_list;
    } else /* use pre-resolved addresses */
        address_list=&c->opt->remote_addr;

    /* try to connect each host from the list */
    for(ind_try=0; ind_try<address_list->num; ind_try++) {
        if(c->opt->failover==FAILOVER_RR) {
            ind_cur=address_list->cur;
            /* the race condition here can be safely ignored */
            address_list->cur=(ind_cur+1)%address_list->num;
        } else { /* FAILOVER_PRIO */
            ind_cur=ind_try; /* ignore address_list->cur */
        }

        c->fd=s_socket(address_list->addr[ind_cur].sa.sa_family,
            SOCK_STREAM, 0, 1, "remote socket");
        if(c->fd<0) {
            if(resolved_list.addr)
                str_free(resolved_list.addr);
            longjmp(c->err, 1);
        }

        local_bind(c, bind_addr); /* explicit local bind or transparent proxy */

        if(connect_blocking(c, &address_list->addr[ind_cur],
                addr_len(&address_list->addr[ind_cur]))) {
            closesocket(c->fd);
            c->fd=-1;
            continue; /* next IP */
        }
        print_bound_address(c);
        fd=c->fd;
        c->fd=-1;
        if(resolved_list.addr)
            str_free(resolved_list.addr);
        return fd; /* success! */
    }
    if(resolved_list.addr)
        str_free(resolved_list.addr);
    longjmp(c->err, 1);
    return -1; /* some C compilers require a return value */
}

#ifdef SO_ORIGINAL_DST
/* connect the original dst */
static int connect_transparent(CLI *c, SOCKADDR_UNION *bind_addr) {
    SOCKADDR_UNION addr;
    socklen_t addrlen=sizeof addr;
    int retval;

    if(getsockopt(c->local_rfd.fd, SOL_IP, SO_ORIGINAL_DST,
            &addr, &addrlen)) {
        sockerror("setsockopt SO_ORIGINAL_DST");
        longjmp(c->err, 1);
    }
    c->fd=s_socket(addr.sa.sa_family, SOCK_STREAM, 0, 1, "remote socket");
    if(c->fd<0)
        longjmp(c->err, 1);
    local_bind(c, bind_addr); /* explicit local bind or transparent proxy */
    if(connect_blocking(c, &addr, addr_len(&addr)))
        longjmp(c->err, 1); /* socket closed on cleanup */
    print_bound_address(c);
    retval=c->fd;
    c->fd=-1;
    return retval; /* success! */
}
#endif /* SO_ORIGINAL_DST */

static void local_bind(CLI *c, SOCKADDR_UNION *bind_addr) {
    int on;

    on=1;
    if(!bind_addr)
        return;
#if defined(USE_WIN32)
    /* do nothing */
#elif defined(IP_TRANSPARENT)
    /* non-local bind on Linux */
    if(c->opt->option.transparent_src) {
        if(setsockopt(c->fd, SOL_IP, IP_TRANSPARENT, &on, sizeof on))
            sockerror("setsockopt IP_TRANSPARENT");
        /* ignore the error to retain Linux 2.2 compatibility */
        /* the error will be handled by bind(), anyway */
    }
#elif defined(IP_BINDANY) && defined(IPV6_BINDANY)
    /* non-local bind on FreeBSD */
    if(c->opt->option.transparent_src) {
        if(bind_addr->sa.sa_family==AF_INET) { /* IPv4 */
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

    if(ntohs(bind_addr->in.sin_port)>=1024) { /* security check */
        if(!bind(c->fd, &bind_addr->sa, addr_len(bind_addr))) {
            s_log(LOG_INFO, "local_bind succeeded on the original port");
            return; /* success */
        }
        if(get_last_socket_error()!=S_EADDRINUSE
#ifndef USE_WIN32
                || !c->opt->option.transparent_src
#endif /* USE_WIN32 */
                ) {
            sockerror("local_bind (original port)");
            longjmp(c->err, 1);
        }
    }

    bind_addr->in.sin_port=htons(0); /* retry with ephemeral port */
    if(!bind(c->fd, &bind_addr->sa, addr_len(bind_addr))) {
        s_log(LOG_INFO, "local_bind succeeded on an ephemeral port");
        return; /* success */
    }
    sockerror("local_bind (ephemeral port)");
    longjmp(c->err, 1);
}

static void print_bound_address(CLI *c) {
    char *txt;
    SOCKADDR_UNION addr;
    socklen_t addrlen=sizeof addr;

    if(global_options.debug_level<LOG_NOTICE) /* performance optimization */
        return;
    memset(&addr, 0, addrlen);
    if(getsockname(c->fd, (struct sockaddr *)&addr, &addrlen)) {
        sockerror("getsockname");
        return;
    }
    txt=s_ntop(&addr, addrlen);
    s_log(LOG_NOTICE,"Service %s connected remote server from %s",
        c->opt->servname, txt);
    str_free(txt);
}

static void reset(int fd, char *txt) {
    /* set lingering on a socket if needed*/
    struct linger l;

    l.l_onoff=1;
    l.l_linger=0;
    if(setsockopt(fd, SOL_SOCKET, SO_LINGER, (void *)&l, sizeof l))
        log_error(LOG_DEBUG, get_last_socket_error(), txt);
}

/* end of client.c */
