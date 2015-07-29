/*
 *   stunnel       Universal SSL tunnel for standard network daemons
 *   Copyright (c) 1998 Michal Trojnara <mtrojnar@ddc.daewoo.com.pl>
 *                 All Rights Reserved
 *
 *   Version:      2.0a             (stunnel.c)
 *   Date:         1998.05.26
 *   Author:       Michal Trojnara  <mtrojnar@ddc.daewoo.com.pl>
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

/* Change to 0 if you have problems with make_sockets() */
#define INET_SOCKET_PAIR 1

#define BUFFSIZE 8192    /* I/O buffer size */
#define HOSTNAME_SIZE 256

#include "config.h"

/* General headers */
#include <stdio.h>
#include <errno.h>       /* errno */
#include <sys/stat.h>    /* stat */
#include <signal.h>      /* signal */
#include <syslog.h>      /* openlog, syslog */
#include <string.h>      /* strerror */
#include <ctype.h>
#include <stdlib.h>
#include <netdb.h>
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

/* SSL headers */
#include <ssl.h>
#include <err.h>
#include <bio.h>
#include <pem.h>

/* libwrap header */
#if HAVE_TCPD_H && HAVE_LIBWRAP
#include <tcpd.h>
#define USE_LIBWRAP 1
#endif

/* DH requires some more hacking ;) -pk */
#undef USE_DH

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
void daemon_loop(char **, SSL_CTX *);
void client(struct sockaddr_in *, char **, int, SSL_CTX *);
void transfer(SSL *, int);
int listen_local(char *);
int connect_remote(char *);
u_short port2num(char *);
char **host2num(char *);
void make_sockets(int [2]);
void daemonize();
static RSA *tmp_rsa_cb(SSL *, int);
#ifdef USE_DH
static DH *tmp_dh_cb(SSL *, int);
#endif
void ioerror(char *);
void sslerror(char *);
void signal_handler(int);

/* certfile needs to be global - tmp_dh_cb() uses it */
char certfile[128]; /* server certificate */

int main(int argc, char* argv[]) /* execution begins here 8-) */
{
    char *name; /* name of service */
    struct stat st; /* buffer for stat */
    struct sockaddr_in addr;
    int addrlen;
    SSL_CTX *ctx;
    int inetd_mode;
    char **parameters;

    openlog("stunnel", LOG_CONS | LOG_NDELAY | LOG_PID, LOG_DAEMON);
    signal(SIGPIPE, SIG_IGN); /* avoid 'broken pipe' signal */
    signal(SIGTERM, signal_handler);
    signal(SIGQUIT, signal_handler);
    signal(SIGSEGV, signal_handler);

    /* check if started from inetd */
    addrlen=sizeof(addr);
    memset(&addr, 0, addrlen);
    if(getpeername(0, (struct sockaddr *)&addr, &addrlen)) {
        if(argc<3) {
            fprintf(stderr, "ERROR: Not enough parameters for daemon mode\n");
            exit(2);
        }
        syslog(LOG_NOTICE, "Daemon started for %s", argv[1]);
        parameters=argv+2;
        inetd_mode=0;
    } else { /* started from inetd */
        parameters=argv;
        inetd_mode=1;
    }

    /* find server certificate filename */
    if(*parameters[0]=='@') {
        name=parameters[0]+1;
    } else {
        if((name=rindex(parameters[0], '/')))
            name++; /* first character after '/' */
        else
            name=parameters[0]; /* relative name - no '/' */
    }
    sprintf(certfile, "%s/%s.pem", X509_get_default_cert_dir(), name);
    if(stat(certfile, &st))
        ioerror(certfile);
    if(st.st_mode & 7)
        syslog(LOG_WARNING, "WARNING: Wrong permissions on %s", certfile);

    /* init SSL */
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();
    ctx=SSL_CTX_new(SSLv23_server_method());
    if(!SSL_CTX_use_RSAPrivateKey_file(ctx, certfile, SSL_FILETYPE_PEM))
        sslerror("SSL_CTX_use_RSAPrivateKey_file");
    if(!SSL_CTX_use_certificate_file(ctx, certfile, SSL_FILETYPE_PEM))
        sslerror("SSL_CTX_use_certificate_file");
    if(!SSL_CTX_set_tmp_rsa_callback(ctx, tmp_rsa_cb))
        sslerror("SSL_CTX_set_tmp_rsa_callback");
#ifdef USE_DH
    if(!SSL_CTX_set_tmp_dh_callback(ctx, tmp_dh_cb))
    sslerror("SSL_CTX_set_tmp_dh_callback");
#endif

    /* accept client(s) */
    if(inetd_mode) {
        client(&addr, argv, 0, ctx);
    } else {
        daemonize();
        daemon_loop(argv+1, ctx);
    }

    /* close SSL */
    SSL_CTX_free(ctx);
    return 0; /* success */
}

void daemon_loop(char **parameters, SSL_CTX *ctx)
{
    int ls, s;
    struct sockaddr_in addr;
    int addrlen;

    ls=listen_local(parameters[0]);
    while(1) {
        addrlen=sizeof(addr);
        if((s=accept(ls, (struct sockaddr *)&addr, &addrlen))<0)
            ioerror("accept");
        switch(fork()) {
        case -1:    /* error */
            ioerror("fork");
        case  0:    /* child */
            close(ls);
            client(&addr, parameters+1, s, ctx);
            _exit(0);
        default:    /* parent */
            close(s);
        }
    }
}

void client(struct sockaddr_in *addr, char **parameters, int s, SSL_CTX *ctx)
{
    SSL *ssl;
    int fd[2], remote; /* sockets */
#if SSLEAY_VERSION_NUMBER > 0x0800
    SSL_CIPHER *c;
    char *ver;
    int bits;
#endif

#ifdef USE_LIBWRAP
    struct request_info request;

    request_init(&request, RQ_DAEMON, parameters[0], RQ_FILE, s, 0);
    fromhost(&request);
    if (!hosts_access(&request)) {
        syslog(LOG_ERR, "%s connection refused from %s:%d", parameters[0],
            inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
	exit(2);
    }
#endif

    syslog(LOG_NOTICE, "%s connected from %s:%d", parameters[0],
        inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));

/* create connection to remote host/service */
    if(*parameters[0]=='@') {
        remote=connect_remote(parameters[0]+1);
    } else {
        make_sockets(fd);
        switch(fork()) {
        case -1:    /* error */
            ioerror("fork");
        case  0:    /* child */
            close(fd[0]);
            dup2(fd[1], 0);
            dup2(fd[1], 1);
            dup2(fd[1], 2);
            close(fd[1]);
            execvp(parameters[0], parameters);
            ioerror("execvp"); /* execvp failed */
        }
        close(fd[1]);
        remote=fd[0];
    }

    /* do the job */
    ssl=SSL_new(ctx);
    SSL_set_fd(ssl, s);
    if(SSL_accept(ssl)<=0)
        sslerror("SSL_accept");
#if SSLEAY_VERSION_NUMBER <= 0x0800
    syslog(LOG_INFO, "SSLv%d opened for %s, cipher %s",
        ssl->session->ssl_version,
        parameters[0],
        SSL_get_cipher(ssl));
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
    syslog(LOG_INFO, "%s opened for %s, cipher %s (%u bits)",
        ver, parameters[0], SSL_CIPHER_get_name(c), bits);
#endif
    transfer(ssl, remote);
    SSL_free(ssl);
}

void transfer(SSL *ssl, int tunnel) /* transfer data */
{
    fd_set rin, rout;
    int num, fdno, fd_ssl, bytes_in=0, bytes_out=0;
    char buffer[BUFFSIZE];

    fd_ssl=SSL_get_fd(ssl);
    FD_ZERO(&rin);
    FD_SET(fd_ssl, &rin);
    FD_SET(tunnel, &rin);
    fdno=(fd_ssl>tunnel ? fd_ssl : tunnel)+1;
    while(1)
    {
        rout=rin;
        if(select(fdno, &rout, NULL, NULL, NULL)<0)
            ioerror("select");
        if(FD_ISSET(tunnel, &rout))
        {
            num=read(tunnel, buffer, BUFFSIZE);
            if(num<0 && errno==ECONNRESET)
            {
                syslog(LOG_INFO, "IPC reset (child died)");
                break; /* close connection */
            }
            if(num<0)
                ioerror("read");
            if(num==0)
                break; /* close */
            if(SSL_write(ssl, buffer, num)!=num)
                sslerror("SSL_write");
            bytes_out+=num;
        }
        if(FD_ISSET(fd_ssl, &rout))
        {
            num=SSL_read(ssl, buffer, BUFFSIZE);
            if(num<0)
                sslerror("SSL_read");
            if(num==0)
                break; /* close */
            if(write(tunnel, buffer, num)!=num)
                ioerror("write");
            bytes_in+=num;
        }
    }
    syslog(LOG_INFO, "Connection closed: %d bytes in, %d bytes out",
        bytes_in, bytes_out);
}

int listen_local(char *name) /* bind and listen on local interface */
{
    char hostname[HOSTNAME_SIZE], *portname;
    struct sockaddr_in addr;
    int ls;

    if((ls=socket(AF_INET, SOCK_STREAM, 0))<0)
        ioerror("socket");
    memset(&addr, 0, sizeof(addr));
    addr.sin_family=AF_INET;
    strncpy(hostname, name, HOSTNAME_SIZE-1);
    hostname[HOSTNAME_SIZE-1]='\0';
    if((portname=rindex(hostname, ':'))) {
        *portname++='\0';
        memcpy((char *)&addr.sin_addr, *host2num(hostname),
            sizeof(struct in_addr));
        addr.sin_port=port2num(portname);
    } else {
        addr.sin_addr.s_addr=htonl(INADDR_ANY);
        addr.sin_port=port2num(hostname);
    }
    if(bind(ls, (struct sockaddr *)&addr, sizeof(addr)))
        ioerror("bind");
    if(listen(ls, 5))
        ioerror("listen");
    return ls;
}

int connect_remote(char *name) /* connect to remote host */
{
    char hostname[HOSTNAME_SIZE], *portname;
    struct sockaddr_in addr;
    int s; /* destination socket */
    char **list; /* destination addresses list */

    if((s=socket(AF_INET, SOCK_STREAM, 0)) < 0)
        ioerror("remote socket");
    memset(&addr, 0, sizeof(addr));
    addr.sin_family=AF_INET;
    strncpy(hostname, name, HOSTNAME_SIZE-1);
    hostname[HOSTNAME_SIZE-1]='\0';
    if(!(portname=rindex(hostname, ':'))) {
        syslog(LOG_ERR, "no port specified: \"%s\"", hostname);
        exit(2);
    }
    *portname++='\0';
    addr.sin_port=port2num(portname);

    /* connect each host from the list*/
    for(list=host2num(hostname); *list; list++) {
        memcpy((char *)&addr.sin_addr, *list, sizeof(struct in_addr));
        if(!connect(s, (struct sockaddr *) &addr, sizeof(addr))) {
            return s; /* success */
        }
    }
    ioerror("remote connect");
    return 0; /* to satisfy compiler */
}

u_short port2num(char *portname) /* get port number */
{
    struct servent *p;
    u_short port;

    if((p=getservbyname(portname, "tcp")))
        port=p->s_port;
    else
        port=htons(atoi(portname));
    if(!port) {
        syslog(LOG_ERR, "invalid port: %s", portname);
        exit(2);
    }
    return port;
}

char **host2num(char *hostname) /* get list of host addresses */
{
    struct hostent *h;
    static struct in_addr ip;
    static char *table[]={(char *)&ip, NULL};

    if((ip.s_addr=inet_addr(hostname))!=-1) /* dotted decimal */
        return table;
    /* not dotted decimal - we have to call resolver */
    if(!(h=gethostbyname(hostname))) /* get list of addresses */
        ioerror("gethostbyname");
    return h->h_addr_list;
}

void make_sockets(int fd[2]) /* make pair of connected sockets */
{
#if INET_SOCKET_PAIR
    struct sockaddr_in addr;
    int addrlen;
    int s; /* temporary socket awaiting for connection */

    if((s=socket(AF_INET, SOCK_STREAM, 0))<0)
        ioerror("socket#1");
    if((fd[1]=socket(AF_INET, SOCK_STREAM, 0))<0)
        ioerror("socket#2");
    addrlen=sizeof(addr);
    memset(&addr, 0, addrlen);
    addr.sin_family=AF_INET;
    addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    addr.sin_port=0; /* dynamic port allocation */
    if(bind(s, (struct sockaddr *)&addr, addrlen))
        syslog(LOG_DEBUG, "bind#1: %s (%d)", strerror(errno), errno);
    if(bind(fd[1], (struct sockaddr *)&addr, addrlen))
        syslog(LOG_DEBUG, "bind#2: %s (%d)", strerror(errno), errno);
    if(listen(s, 5))
        ioerror("listen");
    if(getsockname(s, (struct sockaddr *)&addr, &addrlen))
        ioerror("getsockname");
    if(connect(fd[1], (struct sockaddr *)&addr, addrlen))
        ioerror("connect");
    if((fd[0]=accept(s, (struct sockaddr *)&addr, &addrlen))<0)
        ioerror("accept");
    close(s); /* don't care about the result */
#else
    if(socketpair(AF_UNIX, SOCK_STREAM, 0, fd))
        ioerror("socketpair");
#endif
}

void daemonize() /* go to background */
{
    switch (fork()) {
    case -1:
        ioerror("fork");
    case 0:
        break;
    default:
        _exit(0);
    }
    if (setsid() == -1)
        ioerror("setsid");
    chdir("/");
    close(0);
    close(1);
    close(2);
}

static RSA *tmp_rsa_cb(SSL *s, int export) /* temporary RSA key callback */
{
    static RSA *rsa_tmp = NULL;

    if(rsa_tmp)
        return(rsa_tmp);
    syslog(LOG_DEBUG, "Generating 512 bit RSA key...");
#if SSLEAY_VERSION_NUMBER <= 0x0800
    rsa_tmp=RSA_generate_key(512, RSA_F4, NULL);
#else
    rsa_tmp=RSA_generate_key(512, RSA_F4, NULL, NULL);
#endif
    if(rsa_tmp == NULL)
        sslerror("tmp_rsa_cb");
    return(rsa_tmp);
}

#ifdef USE_DH
static DH *tmp_dh_cb(SSL *s, int export) /* temporary DH key callback */
{
    static DH *dh_tmp = NULL;
    BIO *in=NULL;

    if(dh_tmp)
        return(dh_tmp);
    syslog(LOG_DEBUG, "Generating Diffie-Hellman key...");
    in=BIO_new_file(certfile, "r");
    if(in == NULL) {
        syslog(LOG_ERR, "DH: could not read %s: %s", certfile, strerror(errno));
        return(NULL);
    }
    dh_tmp=PEM_read_bio_DHparams(in,NULL,NULL);
    if(dh_tmp==NULL) {
        syslog(LOG_ERR, "could not load DH parameters");
        return(NULL);
    }
    if(!DH_generate_key(dh_tmp)) {
        syslog(LOG_ERR, "could not generate DH keys");
        return(NULL);
    }
    syslog(LOG_DEBUG, "Diffie-Hellman length: %d", DH_size(dh_tmp));
    if(in != NULL) BIO_free(in);
    return(dh_tmp);
}
#endif

void ioerror(char *fun) /* Input/Output Error handler */
{
    syslog(LOG_ERR, "%s: %s (%d)", fun, strerror(errno), errno);
    exit(1);
}

void sslerror(char *fun) /* SSL Error handler */
{
    char string[120];

    ERR_error_string(ERR_get_error(), string);
    syslog(LOG_ERR, "%s: %s", fun, string);
    exit(2);
}

void signal_handler(int sig) /* Signal handler */
{
    syslog(LOG_ERR, "Received signal %d; terminating.", sig);
    exit(3);
}

/* End of stunnel.c */

