/*
 *   stunnel       Universal SSL tunnel
 *   Copyright (c) 1998-1999 Michal Trojnara <Michal.Trojnara@centertel.pl>
 *                 All Rights Reserved
 *
 *   Version:      3.0              (stunnel.c)
 *   Date:         1999.04.16
 *   Author:       Michal Trojnara  <Michal.Trojnara@centertel.pl>
 *   SSL support:  Adam Hernik      <adas@infocentrum.com>
 *                 Pawel Krawczyk   <kravietz@ceti.com.pl>
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

/* Undefine if you have problems with make_sockets() */
#define INET_SOCKET_PAIR

/* DH is an experimental code, so it's undefined by default */
/* #define USE_DH */

#ifdef USE_WIN32

/* default certificate */
#define DEFAULT_CERT "stunnel.pem"

/* additional directory (hashed!) with trusted CA client certs */
#define CA_DIR "mytrusted"

/* certificate used for sign our client certs */
#define CLIENT_CA "cacert.pem"

#else /* USE_WIN32 */

/* directory for certificate */
#define CERT_DIR SSLDIR "/certs"

/* default certificate */
#define DEFAULT_CERT CERT_DIR "/stunnel.pem"

/* additional directory (hashed!) with trusted CA client certs */
#define CA_DIR CERT_DIR "/mytrusted"

/* certificate used for sign our client certs */
#define CLIENT_CA SSLDIR "/bin/demoCA/cacert.pem"

#endif /* USE_WIN32 */

#define MAX_CLIENTS 100  /* Max number of children */
#define BUFFSIZE 8192    /* I/O buffer size */
#define HOSTNAME_SIZE 256

#if defined __CYGWIN__ || defined __CYGWIN32__
#define WIN32
#endif

#include "common.h"

#ifdef USE_WIN32

#define Win32_Winsock
#include <windows.h>
#include <io.h>
#include <stdlib.h>
#include <process.h>
#include <malloc.h>
#include <string.h>
#include <sys/stat.h>
#define LOG_EMERG       0
#define LOG_ALERT       1
#define LOG_CRIT        2
#define LOG_ERR         3
#define LOG_WARNING     4
#define LOG_NOTICE      5
#define LOG_INFO        6
#define LOG_DEBUG       7
#define ECONNRESET WSAECONNRESET

static struct WSAData wsa_state;

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
#include <syslog.h>
#ifdef HAVE_GETOPT_H
#include <getopt.h>      /* getopt */
#endif
#ifdef HAVE_STRINGS_H
#include <strings.h>     /* rindex */
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>      /* fork, execvp, exit */
#endif

/* Networking headers */
#include <sys/types.h>   /* u_short, u_long */
#include <netinet/in.h>  /* struct sockaddr_in */
#include <sys/socket.h>  /* getpeername */
#include <arpa/inet.h>   /* inet_ntoa */
#include <sys/time.h>    /* select */
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>  /* for aix */
#endif
#ifndef INADDR_ANY
#define INADDR_ANY       (u_long)0x00000000
#endif
#ifndef INADDR_LOOPBACK
#define INADDR_LOOPBACK  (u_long)0x7F000001
#endif

/* TCP wrapper */
#ifdef USE_LIBWRAP
#include <tcpd.h>
int allow_severity=LOG_NOTICE;
int deny_severity=LOG_WARNING;
#endif

#endif /* defined USE_WIN32 */

/* Correct callback definitions overriding ssl.h */
#ifdef SSL_CTX_set_tmp_rsa_callback
    #undef SSL_CTX_set_tmp_rsa_callback
#endif
#define SSL_CTX_set_tmp_rsa_callback(ctx,cb) \
    SSL_CTX_ctrl(ctx,SSL_CTRL_SET_TMP_RSA_CB,0,(char *)cb)
#ifdef SSL_CTX_set_tmp_dh_callback
    #undef SSL_CTX_set_tmp_dh_callback
#endif
#define SSL_CTX_set_tmp_dh_callback(ctx,dh) \
    SSL_CTX_ctrl(ctx,SSL_CTRL_SET_TMP_DH_CB,0,(char *)dh)

/* Prototypes */
static void get_options(int, char *[]);
static void context_init();
static void daemon_loop();
#ifndef USE_WIN32
static void daemonize();
#endif
    /* Socket functions */
static void client(int);
static void transfer(SSL *, int);
static int listen_local();
static int connect_local();
static int connect_remote();
static void name2nums(char *, u_long **, u_short *);
static u_short port2num(char *);
static void host2num(u_long **, char *);
#ifndef USE_WIN32
static int make_sockets(int [2]);
#endif
    /* SSL functions */
static RSA *tmp_rsa_cb(SSL *, int, int);
#ifdef USE_DH
static DH *tmp_dh_cb(SSL *, int);
#endif
static int verify_callback (int, X509_STORE_CTX *);
static void info_callback(SSL *, int, int);
static void print_stats();
    /* Error/exceptions handling functions */
static void ioerror(char *);
static void sockerror(char *);
static void sslerror(char *);
#ifdef USE_FORK
static void sigchld_handler(int);
#endif
#ifndef USE_WIN32
static void signal_handler(int);
#else
static char *rindex(char *, int);
static int getopt(int, char **, char*);
#endif
static void alloc(u_long **, int);
static void print_help();

#define OPT_CLIENT     0x01
#define OPT_CERT       0x02
#define OPT_DAEMON     0x04
#define OPT_FOREGROUND 0x08
#define OPT_LOCAL      0x10
#define OPT_REMOTE     0x20

    /* Global variables */
SSL_CTX *ctx;           /* global SSL context */
RSA *rsa_tmp;           /* temporary RSA key */
char certfile[256];     /* name of the certificate */
char clientdir[256];
char signCAfile[256];
#if SSLEAY_VERSION_NUMBER >= 0x0922
static unsigned char *sid_ctx="stunnel SID"; /* const allowed here */
#endif
int clients;
int option=0;
int foreground;         /* force messages to stderr */
u_short localport, remoteport;
u_long *localnames=NULL, *remotenames=NULL;
char *execname=NULL, **execargs;
int verify_level=SSL_VERIFY_NONE;
int verify_use_only_my=0;
int debug_level=5;
long session_timeout=0;

int main(int argc, char* argv[]) /* execution begins here 8-) */
{
    struct stat st; /* buffer for stat */

#ifdef USE_WIN32
    if(WSAStartup(0x0101, &wsa_state)!=0) {
        sockerror("WSAStartup");
        exit(1);
    }
#else
    signal(SIGPIPE, SIG_IGN); /* avoid 'broken pipe' signal */
    signal(SIGTERM, signal_handler);
    signal(SIGQUIT, signal_handler);
    /* signal(SIGSEGV, signal_handler); */
#endif

    /* process options */
    foreground=1;
    strcpy(certfile, DEFAULT_CERT);
    strcpy(clientdir, CA_DIR);
    get_options(argc, argv);
    if(!(option&OPT_FOREGROUND)) {
        foreground=0;
#ifndef USE_WIN32
        openlog("stunnel", LOG_CONS | LOG_NDELAY | LOG_PID, LOG_DAEMON);
#endif /* defined USE_WIN32 */
    }

    /* check if certificate exists */
    if(option&OPT_CERT) {
        if(stat(certfile, &st)) {
            ioerror(certfile);
            exit(1);
        }
#ifndef WIN32
        if(st.st_mode & 7)
            log(LOG_WARNING, "Wrong permissions on %s", certfile);
#endif /* defined WIN32 */
    }

    /* check if started from inetd */
    context_init(); /* initialize global SSL context */
    sthreads_init(); /* initialize threads */
    log(LOG_NOTICE, STUNNEL_INFO);
    if(option&OPT_DAEMON) {
#ifndef USE_WIN32
        if(!(option&OPT_FOREGROUND))
            daemonize();
#endif
        daemon_loop(ctx);
    } else { /* inetd mode */
        clients=1; /* single client */
        client(0); /* connection from fd 0 - stdin */
    }
    /* close SSL */
    SSL_CTX_free(ctx);
    return 0; /* success */
}

static void get_options(int argc, char *argv[])
{   /* get options and set global variables */
    int c;
    extern char *optarg;
    extern int optind, opterr, optopt;

    opterr=0;
    while ((c = getopt(argc, argv, "a:cp:v:d:fl:r:t:hD:V")) != EOF)
        switch (c) {
            case 'a':
                strcpy(clientdir,optarg);
                break;
            case 'c':
                option|=OPT_CLIENT;
                break;
            case 'p':
                option|=OPT_CERT;
                strcpy(certfile, optarg);
                break;
            case 'v':
                switch(atoi(optarg)) {
                case 3:
                    verify_use_only_my=1;
                case 2:
                    verify_level |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
                case 1:
                    verify_level |= SSL_VERIFY_PEER;
                    break;
                default:
                    log(LOG_ERR, "Bad verify level");
                    print_help();
                }
                break;
             case 'd':
                if(option&OPT_DAEMON) {
                    log(LOG_ERR, "Multiple daemons not allowed");
                    print_help();
                }
                option|=OPT_DAEMON;
                name2nums(optarg, &localnames, &localport);
                if(!localnames) {
                    alloc(&localnames, 1);
                    localnames[0]=htonl(INADDR_ANY);
                }
                break;
            case 'f':
                option|=OPT_FOREGROUND;
                break;
            case 'l':
                if(option&(OPT_LOCAL|OPT_REMOTE)) {
                    log(LOG_ERR, "Multiple local/remote mode not allowed");
                    print_help();
                }
                option|=OPT_LOCAL;
                execname=optarg;
                break;
            case 'r':
                if(option&(OPT_LOCAL|OPT_REMOTE)) {
                    log(LOG_ERR, "Multiple local/remote mode not allowed");
                    print_help();
                }
                option|=OPT_REMOTE;
                execname=optarg;
                name2nums(optarg, &remotenames, &remoteport);
                if(!remotenames) {
                    alloc(&remotenames, 1);
                    remotenames[0]=htonl(INADDR_LOOPBACK);
                }
                break;
            case 't':
                session_timeout=atoi(optarg);
                break;
            case 'D':
                debug_level=atoi(optarg);
                break;
            case 'V':
                fprintf(stderr, "\n" STUNNEL_INFO "\n\n");
                exit(0);
            case '?':
                log(LOG_ERR, "Illegal option '%c'", optopt);
            case 'h':
                print_help();
            default:
                log(LOG_ERR, "Internal error in get_options");
                print_help();
        }
        if(!(option&(OPT_LOCAL|OPT_REMOTE))) {
            log(LOG_ERR, "Either local or remote mode must be specified");
            print_help();
    }
    if(!(option&OPT_CLIENT))
        option|=OPT_CERT; /* Server always needs a certificate */
    execargs=argv+optind-1;
}

static void context_init() /* init SSL */
{
    SSLeay_add_ssl_algorithms();
    SSL_load_error_strings();
    if(option&OPT_CLIENT) {
        ctx=SSL_CTX_new(SSLv3_client_method());
    } else {
        ctx=SSL_CTX_new(SSLv23_server_method());
    }
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_BOTH);
    SSL_CTX_set_timeout(ctx, session_timeout);
    if(option&OPT_CERT) {
        log(LOG_DEBUG, "Certificate: %s", certfile);
        if(!SSL_CTX_use_certificate_file(ctx, certfile, SSL_FILETYPE_PEM)) {
            sslerror("SSL_CTX_use_certificate_file");
            exit(1);
        }
        if(!SSL_CTX_use_RSAPrivateKey_file(ctx, certfile, SSL_FILETYPE_PEM)) {
            sslerror("SSL_CTX_use_RSAPrivateKey_file");
            exit(1);
        }
    }
    if(verify_level!=SSL_VERIFY_NONE) {
        if ((!SSL_CTX_set_default_verify_paths(ctx))
                || (!SSL_CTX_load_verify_locations(ctx, CLIENT_CA, clientdir))){
            sslerror("X509_load_verify_locations");
            exit(1);
        }
        SSL_CTX_set_verify(ctx, verify_level, verify_callback);
        SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(CLIENT_CA));
        if (verify_use_only_my)
            log(LOG_NOTICE, "Peer certificate location %s", clientdir);
    }
    log(LOG_DEBUG, "Generating 512 bit RSA key...");
#if SSLEAY_VERSION_NUMBER <= 0x0800
    rsa_tmp=RSA_generate_key(512, RSA_F4, NULL);
#else
    rsa_tmp=RSA_generate_key(512, RSA_F4, NULL, NULL);
#endif
    if(!rsa_tmp) {
        sslerror("tmp_rsa_cb");
        exit(1);
    }
    if(!SSL_CTX_set_tmp_rsa_callback(ctx, tmp_rsa_cb)) {
        sslerror("SSL_CTX_set_tmp_rsa_callback");
        exit(1);
    }
    if(!SSL_CTX_set_info_callback(ctx, info_callback)) {
        sslerror("SSL_CTX_set_info_callback");
        exit(1);
    }
#ifdef USE_DH
    if(!SSL_CTX_set_tmp_dh_callback(ctx, tmp_dh_cb)) {
        sslerror("SSL_CTX_set_tmp_dh_callback");
        exit(1);
    }
#endif
}

static void daemon_loop()
{
    int ls, s;
    struct sockaddr_in addr;
    int addrlen;

    ls=listen_local();
    clients=0;
#ifdef USE_FORK
    signal(SIGCHLD, sigchld_handler);
#endif
    while(1) {
        addrlen=sizeof(addr);
        do s=accept(ls, (struct sockaddr *)&addr, &addrlen);
        while(s<0 && errno==EINTR);
        if(s<0) {
            sockerror("accept");
            exit(1);
        }
        if(clients<MAX_CLIENTS) {
            if(create_client(ls, s, client))
                log(LOG_WARNING,
                    "%s fork failed - connection from %s:%d REJECTED",
                    execname, inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
            else
                clients++;
        } else {
            log(LOG_WARNING,
                "%s has too many clients - connection from %s:%d REJECTED",
                execname, inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
            closesocket(s);
        }
    }
}

#ifndef USE_WIN32
static void daemonize() /* go to background */
{
    switch (fork()) {
    case -1:    /* fork failed */
        ioerror("fork");
        exit(1);
    case 0:     /* child */
        break;
    default:    /* parent */
        exit(0);
    }
    if (setsid() == -1) {
        ioerror("setsid");
        exit(1);
    }
    chdir("/");
    close(0);
    close(1);
    close(2);
}
#endif /* defined USE_WIN32 */

static void client(int s)
{
    struct sockaddr_in addr;
    int addrlen;
    SSL *ssl;
    int remote;
#if SSLEAY_VERSION_NUMBER > 0x0800
    SSL_CIPHER *c;
    char *ver;
    int bits;
#endif
#ifdef USE_LIBWRAP
    struct request_info request;
#endif

    log(LOG_DEBUG, "%s started", execname);
    addrlen=sizeof(addr);
    if(!getpeername(s, (struct sockaddr *)&addr, &addrlen)) {
#ifdef USE_LIBWRAP
        request_init(&request, RQ_DAEMON, execname, RQ_FILE, s, 0);
        fromhost(&request);
        if (!hosts_access(&request)) {
            log(LOG_WARNING, "%s connection from %s:%d REFUSED", execname,
                inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
            goto cleanup_local;
        }
#endif
        log(LOG_NOTICE, "%s connected from %s:%d", execname,
            inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
    }

    /* create connection to host/service */
    if(option&OPT_REMOTE) { /* remote host */
        if((remote=connect_remote())<0)
            goto cleanup_local; /* Failed to connect remote server */
        log(LOG_DEBUG, "Remote host connected");
    } else { /* local service */
        if((remote=connect_local())<0)
            goto cleanup_local; /* Failed to spawn local service */
        log(LOG_DEBUG, "Local service connected");
    }

    /* do the job */
    if(!(ssl=SSL_new(ctx))) {
        sslerror("SSL_new");
        goto cleanup_remote;
    }

#if SSLEAY_VERSION_NUMBER >= 0x0922
    SSL_set_session_id_context(ssl, sid_ctx, strlen(sid_ctx));
#endif

    if(option&OPT_CLIENT) {
        SSL_set_fd(ssl, remote);
        SSL_set_connect_state(ssl);
        if(SSL_connect(ssl)<=0) {
            sslerror("SSL_connect");
            goto cleanup_ssl;
        }
    } else {
        SSL_set_fd(ssl, s);
        SSL_set_accept_state(ssl);
        if(SSL_accept(ssl)<=0) {
            sslerror("SSL_accept");
            goto cleanup_ssl;
        }
    }

#if SSLEAY_VERSION_NUMBER <= 0x0800
    log(LOG_INFO, "%s opened with SSLv%d, cipher %s",
        execname, ssl->session->ssl_version, SSL_get_cipher(ssl));
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
        execname, ver, SSL_CIPHER_get_name(c), bits);
#endif
    if(option&OPT_CLIENT)
        transfer(ssl, s);
    else
        transfer(ssl, remote);
cleanup_ssl:
    SSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
    SSL_free(ssl);
cleanup_remote:
    closesocket(remote);
cleanup_local:
    closesocket(s);
#ifndef USE_FORK
    log(LOG_DEBUG, "%s finished (%d left)", execname, --clients);
#endif
}

static void transfer(SSL *ssl, int fd_sock) /* transfer data */
{
    fd_set rd_set, wr_set;
    int num, fdno, fd_ssl, bytes_in, bytes_out;
    char sock_buff[BUFFSIZE], ssl_buff[BUFFSIZE];
    int sock_ptr, ssl_ptr, sock_open, ssl_open;

    fd_ssl=SSL_get_fd(ssl);
    fdno=(fd_ssl>fd_sock ? fd_ssl : fd_sock)+1;
    sock_ptr=0;
    ssl_ptr=0;
    sock_open=1;
    ssl_open=1;
    bytes_in=0;
    bytes_out=0;

    while((sock_open||sock_ptr) && (ssl_open||ssl_ptr)) {
        FD_ZERO(&rd_set);
        if(sock_open && sock_ptr<BUFFSIZE) /* can read from socket */
            FD_SET(fd_sock, &rd_set);
        if(ssl_open && ssl_ptr<BUFFSIZE) /* can read from SSL */
            FD_SET(fd_ssl, &rd_set);
        FD_ZERO(&wr_set);
        if(sock_open && ssl_ptr) /* can write to socket */
            FD_SET(fd_sock, &wr_set);
        if(ssl_open && sock_ptr) /* can write to SSL */
            FD_SET(fd_ssl, &wr_set);
        if(select(fdno, &rd_set, &wr_set, NULL, NULL)<0) {
            sockerror("select");
            return;
        }
        if(sock_open && FD_ISSET(fd_sock, &rd_set)) {
            num=readsocket(fd_sock, sock_buff+sock_ptr, BUFFSIZE-sock_ptr);
            if(num<0 && errno==ECONNRESET) {
                log(LOG_NOTICE, "IPC reset (child died)");
                break; /* close connection */
            }
            if(num<0) {
                sockerror("read");
                return;
            }
            if(num) {
                sock_ptr+=num;
            } else { /* close */
                log(LOG_DEBUG, "Socket closed on read");
                sock_open=0;
            }
        }
        if(ssl_open && FD_ISSET(fd_ssl, &rd_set)) {
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
                    return;
                }
            case SSL_ERROR_ZERO_RETURN:
                log(LOG_DEBUG, "SSL closed on read");
                ssl_open=0;
                break;
            case SSL_ERROR_SSL:
                sslerror("SSL_read");
                return;
            }
        }
        if(sock_open && FD_ISSET(fd_sock, &wr_set)) {
            num=writesocket(fd_sock, ssl_buff, ssl_ptr);
            if(num<0) {
                sockerror("write");
                return;
            }
            if(num) {
                memcpy(ssl_buff, ssl_buff+num, ssl_ptr-num);
                ssl_ptr-=num;
                bytes_in+=num;
            } else { /* close */
                log(LOG_DEBUG, "Socket closed on write");
                sock_open=0;
            }
        }
        if(ssl_open && FD_ISSET(fd_ssl, &wr_set)) {
            num=SSL_write(ssl, sock_buff, sock_ptr);
            switch(SSL_get_error(ssl, num)) {
            case SSL_ERROR_NONE:
                memcpy(sock_buff, sock_buff+num, sock_ptr-num);
                sock_ptr-=num;
                bytes_out+=num;
                break;
            case SSL_ERROR_WANT_WRITE:
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_X509_LOOKUP:
                log(LOG_DEBUG, "SSL_write returned WANT_ - retry");
                break;
            case SSL_ERROR_SYSCALL:
                if(num) { /* not EOF */
                    sockerror("SSL_write (socket)");
                    return;
                }
            case SSL_ERROR_ZERO_RETURN:
                log(LOG_DEBUG, "SSL closed on write");
                ssl_open=0;
                break;
            case SSL_ERROR_SSL:
                sslerror("SSL_write");
                return;
            }
        }
    }
    log(LOG_NOTICE, "Connection closed: %d bytes in, %d bytes out",
        bytes_in, bytes_out);
}

static int listen_local() /* bind and listen on local interface */
{
    struct sockaddr_in addr;
    int ls;

    if((ls=socket(AF_INET, SOCK_STREAM, 0))<0) {
        sockerror("socket");
        exit(1);
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family=AF_INET;
    addr.sin_addr.s_addr=*localnames;
    addr.sin_port=localport;
    if(bind(ls, (struct sockaddr *)&addr, sizeof(addr))) {
        sockerror("bind");
        exit(1);
    }
    log(LOG_DEBUG, "%s bound to %s:%d", execname,
        inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
    if(listen(ls, 5)) {
        sockerror("listen");
        exit(1);
    }
    return ls;
}

static int connect_remote() /* connect to remote host */
{
    struct sockaddr_in addr;
    int s; /* destination socket */
    u_long *list; /* destination addresses list */

    if((s=socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        sockerror("remote socket");
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family=AF_INET;
    addr.sin_port=remoteport;

    /* connect each host from the list*/
    for(list=remotenames; *list!=-1; list++) {
        addr.sin_addr.s_addr=*list;
        log(LOG_DEBUG, "%s connecting %s:%d", execname,
            inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        if(!connect(s, (struct sockaddr *) &addr, sizeof(addr)))
            return s; /* success */
    }
    sockerror("remote connect");
    return -1;
}

static int connect_local() /* connect to local host */
{
#ifdef USE_WIN32
    log(LOG_ERR, "LOCAL MODE NOT SUPPORTED ON WIN32 PLATFORM");
    return -1;
#else
    int fd[2];

    if(make_sockets(fd))
        return -1;
    switch(fork()) {
    case -1:    /* error */
        closesocket(fd[0]);
        closesocket(fd[1]);
        ioerror("fork");
        return -1;
    case  0:    /* child */
        log(LOG_DEBUG, "Child created");
        closesocket(fd[0]);
        dup2(fd[1], 0);
        dup2(fd[1], 1);
        if(!foreground)
            dup2(fd[1], 2);
        closesocket(fd[1]);
        execvp(execname, execargs);
        ioerror("execvp"); /* execvp failed */
        exit(1);
    }
    /* parent */
    closesocket(fd[1]);
    return fd[0];
#endif
}

static void name2nums(char *name, u_long **names, u_short *port)
{
    char hostname[HOSTNAME_SIZE], *portname;

    strncpy(hostname, name, HOSTNAME_SIZE-1);
    hostname[HOSTNAME_SIZE-1]='\0';
    if((portname=rindex(hostname, ':'))) {
        *portname++='\0';
        host2num(names, hostname);
        *port=port2num(portname);
    } else {
        *port=port2num(hostname); /* no ':' - use default host IP */
    }
}

static u_short port2num(char *portname) /* get port number */
{
    struct servent *p;
    u_short port;

    if((p=getservbyname(portname, "tcp")))
        port=p->s_port;
    else
        port=htons(atoi(portname));
    if(!port) {
        log(LOG_ERR, "Invalid port: %s", portname);
        exit(2);
    }
    return port;
}

static void host2num(u_long **hostlist, char *hostname)
{ /* get list of host addresses */
    struct hostent *h;
    u_long ip;
    int i;
    char **tab;

    ip=inet_addr(hostname);
    if(ip!=-1) { /* dotted decimal */
        alloc(hostlist, 1);
        (*hostlist)[0]=ip;
        return;
    }
    /* not dotted decimal - we have to call resolver */
    if(!(h=gethostbyname(hostname))) /* get list of addresses */
        sockerror("gethostbyname");
    i=0;
    tab=h->h_addr_list;
    while(*tab++) /* count the addresses */
        i++;
    alloc(hostlist, i); /* allocate memory */
    while(--i>=0)
        (*hostlist)[i]=*(u_long *)(h->h_addr_list[i]);
}

#ifndef USE_WIN32
static int make_sockets(int fd[2]) /* make pair of connected sockets */
{
#ifdef INET_SOCKET_PAIR
    struct sockaddr_in addr;
    int addrlen;
    int s; /* temporary socket awaiting for connection */

    if((s=socket(AF_INET, SOCK_STREAM, 0))<0) {
        sockerror("socket#1");
        return -1;
    }
    if((fd[1]=socket(AF_INET, SOCK_STREAM, 0))<0) {
        sockerror("socket#2");
        return -1;
    }
    addrlen=sizeof(addr);
    memset(&addr, 0, addrlen);
    addr.sin_family=AF_INET;
    addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    addr.sin_port=0; /* dynamic port allocation */
    if(bind(s, (struct sockaddr *)&addr, addrlen))
        log(LOG_DEBUG, "bind#1: %s (%d)", strerror(errno), errno);
    if(bind(fd[1], (struct sockaddr *)&addr, addrlen))
        log(LOG_DEBUG, "bind#2: %s (%d)", strerror(errno), errno);
    if(listen(s, 5)) {
        sockerror("listen");
        return -1;
    }
    if(getsockname(s, (struct sockaddr *)&addr, &addrlen)) {
        sockerror("getsockname");
        return -1;
    }
    if(connect(fd[1], (struct sockaddr *)&addr, addrlen)) {
        sockerror("connect");
        return -1;
    }
    if((fd[0]=accept(s, (struct sockaddr *)&addr, &addrlen))<0) {
        sockerror("accept");
        return -1;
    }
    closesocket(s); /* don't care about the result */
#else
    if(socketpair(AF_UNIX, SOCK_STREAM, 0, fd)) {
        sockerror("socketpair");
        return -1;
    }
#endif
    return 0;
}
#endif

static RSA *tmp_rsa_cb(SSL *s, int export, int keylength)
{ /* temporary RSA key callback */
    return rsa_tmp;
}

#ifdef USE_DH
static DH *tmp_dh_cb(SSL *s, int export)
{ /* temporary DH key callback */
    static DH *dh_tmp = NULL;
    BIO *in=NULL;

    if(dh_tmp)
        return(dh_tmp);
    log(LOG_DEBUG, "Generating Diffie-Hellman key...");
    in=BIO_new_file(certfile, "r");
    if(in == NULL) {
        log(LOG_ERR, "DH: could not read %s: %s", certfile, strerror(errno));
        return(NULL);
    }
    dh_tmp=PEM_read_bio_DHparams(in,NULL,NULL);
    if(dh_tmp==NULL) {
        log(LOG_ERR, "could not load DH parameters");
        return(NULL);
    }
    if(!DH_generate_key(dh_tmp)) {
        log(LOG_ERR, "could not generate DH keys");
        return(NULL);
    }
    log(LOG_DEBUG, "Diffie-Hellman length: %d", DH_size(dh_tmp));
    if(in != NULL) BIO_free(in);
    return(dh_tmp);
}
#endif

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
    if(verify_use_only_my && ctx->error_depth==0 &&
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
    if(where==SSL_CB_HANDSHAKE_DONE)
        print_stats();
}

static void print_stats()
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

static void ioerror(char *txt) /* Input/Output error handler */
{
    int error;

    error=get_last_error();
    log(LOG_ERR, "%s: %s (%d)", txt, strerror(error), error);
}

static void sockerror(char *txt) /* Socket error handler */
{
    int error;

    error=get_last_socket_error();
    log(LOG_ERR, "%s: %s (%d)", txt, strerror(error), error);
}

static void sslerror(char *txt) /* SSL Error handler */
{
    char string[120];

    ERR_error_string(ERR_get_error(), string);
    log(LOG_ERR, "%s: %s", txt, string);
}

#ifdef USE_FORK

static void sigchld_handler(int sig) /* Our child is dead */
{
    int pid, status;

    clients--; /* One client less */
    pid=wait(&status);
    log(LOG_DEBUG, "%s[%d] finished with code %d (%d left)",
        execname, pid, status, clients);
    signal(SIGCHLD, sigchld_handler);
}
#endif

#ifndef USE_WIN32

static void signal_handler(int sig) /* Signal handler */
{
    log(LOG_ERR, "Received signal %d; terminating.", sig);
    exit(3);
}

#else /* !defined USE_WIN32 */

static char *rindex(char *txt, int c)
{ /* Find last 'c' in "txt" */
    char *retval;

    for(retval=NULL; *txt; txt++)
        if(*txt==c)
            retval=txt;
    return retval;
}

char *optarg;
int optind=1, opterr=0, optopt=0;

static int getopt(int argc, char **argv, char *options)
{ /* simplified version for Win32 */
    char *current, *option;

    current=argv[optind++];
    if(optind>argc || current[0]!='-')
        return EOF;
    option=rindex(options, current[1]);
    if(!option)
        return '?';
    if(option[1]==':')
        optarg=argv[optind++];
    return current[1];
}

#endif /* !defined USE_WIN32 */

static void alloc(u_long **ptr, int len)
{ /* Allocate len+1 words terminated with -1 */
    if (*ptr) /* Deallocate if not null */
        free(*ptr);
    *ptr=malloc((len+1)*sizeof(u_long));
    if (!*ptr) {
        log(LOG_ERR, "Fatal memory allocation error");
        exit(2);
    }
    (*ptr)[len]=-1;
}

static void print_help()
{
    fprintf(stderr,
        "\nstunnel [-c] [-p pemfile] [-v level] [-a directory] [-t timeout]"
#ifndef USE_WIN32
        "\n\t\t[-d [ip:]port [-f]] -l program | -r [ip:]port"
#else
        "\n\t\t[-d [ip:]port] -r [ip:]port"
#endif
        "\n\n  -c\t\tclient mode (remote service uses SSL)"
        "\n\t\tdefault: server mode"
        "\n  -p pemfile\tcertificate (*.pem) file name"
        "\n\t\tdefault: " DEFAULT_CERT " for server mode,"
        "\n\t\t\t none for client mode"
        "\n  -v level\tverify peer certificate"
        "\n\t\tlevel 1 - verify peer certificate if present"
        "\n\t\tlevel 2 - verify peer certificate"
        "\n\t\tlevel 3 - verify peer with localy installed certificate"
        "\n\t\tdefault: no verify"
        "\n  -a directory\tclient certificate directory for -v 3 option"
        "\n\t\tdefault: " CA_DIR
        "\n  -t timeout\tsession cache timeout"
        "\n\t\tdefault: 300 s."
        "\n  -d [ip:]port\tdaemon mode (ip defaults to INADDR_ANY)"
        "\n\t\tdefault: inetd mode"
#ifndef USE_WIN32
        "\n  -f\t\tforeground mode (don't fork, log to stderr)"
        "\n\t\tdefault: background in daemon mode"
        "\n  -l program\texecute local inetd-type program"
#endif
        "\n  -r [ip:]port\tconnect to remote daemon"
        " (ip defaults to INADDR_LOOPBACK)"
        "\n  -h\t\tprint this help screen"
        "\n  -D\t\tdebug level (0-7)  default: 5"
        "\n  -V\t\tprint stunnel version\n");
    exit(1);
}

/* End of stunnel.c */

