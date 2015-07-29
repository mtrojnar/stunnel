/*
 *   stunnel       Universal SSL tunnel for daemons invoked by inetd
 *   Copyright (c) 1998 Michal Trojnara <mtrojnar@ddc.daewoo.com.pl>
 *                 All Rights Reserved
 *
 *   Version:      1.4              (stunnel.c)
 *   Date:         1998.02.14
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

#define BUFFSIZE 8192	/* I/O buffer size */

#include "config.h"

/* General headers */
#include <stdio.h>
#include <errno.h>	/* errno */
#include <sys/stat.h>	/* stat */
#include <signal.h>	/* signal */
#include <syslog.h>	/* openlog, syslog */
#include <string.h>	/* strerror */
#ifdef HAVE_STRINGS_H
#include <strings.h>	/* rindex */
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>	/* fork, execvp, exit */

/* Networking headers */
#include <sys/types.h>  /* u_short, u_long */
#include <netinet/in.h>	/* struct sockaddr_in */
#include <sys/socket.h> /* getpeername */
#include <arpa/inet.h>	/* inet_ntoa */
#include <sys/time.h>	/* select */
#endif
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>	/* for aix */
#endif

/* SSL headers */
#include <ssl.h>
#include <err.h>

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
void transfer(SSL *, int);
void make_sockets(int [2]);
static RSA *tmp_rsa_cb(SSL *, int);
static DH *tmp_dh_cb(SSL *, int);
void ioerror(char *);
void sslerror(char *);
void signal_handler(int);

int main(int argc, char* argv[])
{
    int fd[2];
    SSL *ssl;
    SSL_CTX *ctx;
    char *name; /* name of service */
    char certfile[128]; /* server certificate */
    struct stat st; /* buffer for stat */
    struct sockaddr_in addr;
    int addrlen;

    openlog("stunnel", LOG_CONS | LOG_NDELAY | LOG_PID, LOG_DAEMON);
    signal(SIGPIPE, SIG_IGN); /* avoid 'broken pipe' signal */
    signal(SIGTERM, signal_handler);
    signal(SIGQUIT, signal_handler);
    signal(SIGSEGV, signal_handler);

    if((name=rindex(argv[0], '/')))
        name++; /* first character after '/' */
    else
        name=argv[0]; /* relative name - no '/' */
    addrlen=sizeof(addr);
    memset(&addr, 0, addrlen);
    if(getpeername(0, (struct sockaddr *)&addr, &addrlen))
        ioerror("getpeername");
    syslog(LOG_INFO, "%s connected from %s:%u", name,
        inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
    sprintf(certfile, "%s/%s.pem", X509_get_default_cert_dir(), name);
    if(stat(certfile, &st))
        ioerror(certfile);
    if(st.st_mode & 7)
        syslog(LOG_WARNING, "WARNING: Wrong permissions on %s", certfile);

    make_sockets(fd);
    switch(fork()) {
    case -1:	/* error */
        ioerror("fork");
    case  0:	/* child */
        close(fd[0]);
        dup2(fd[1], 0);
        dup2(fd[1], 1);
        dup2(fd[1], 2);
        close(fd[1]);
        execvp(argv[0], argv);
        ioerror("execvp"); /* execvp failed */
    default:	/* parent */
        close(fd[1]);
        SSL_load_error_strings();
        SSLeay_add_ssl_algorithms();
        ctx=SSL_CTX_new(SSLv23_server_method());
        if(!SSL_CTX_use_RSAPrivateKey_file(ctx, certfile, SSL_FILETYPE_PEM))
            sslerror("SSL_CTX_use_RSAPrivateKey_file");
        if(!SSL_CTX_use_certificate_file(ctx, certfile, SSL_FILETYPE_PEM))
            sslerror("SSL_CTX_use_certificate_file");
        if(!SSL_CTX_set_tmp_rsa_callback(ctx, tmp_rsa_cb))
            sslerror("SSL_CTX_set_tmp_rsa_callback");
        if(!SSL_CTX_set_tmp_dh_callback(ctx, tmp_dh_cb))
            sslerror("SSL_CTX_set_tmp_dh_callback");
        ssl=SSL_new(ctx);
        SSL_set_fd(ssl, 0);
        if(!SSL_accept(ssl))
            sslerror("SSL_accept");
        syslog(LOG_NOTICE, "SSLv%d opened for %s, cipher %s",
            ssl->session->ssl_version, name, SSL_get_cipher(ssl));
        transfer(ssl, fd[0]);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
    }
    return 0; /* success */
}

void transfer(SSL *ssl, int tunnel) /* main loop */
{
    fd_set rin, rout;
    int num, fdno, fd_ssl;
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
        if(FD_ISSET(fd_ssl, &rout))
        {
            num=SSL_read(ssl, buffer, BUFFSIZE);
            if(num<0)
                sslerror("SSL_read");
            if(num==0)
                return; /* close */
            if(write(tunnel, buffer, num)!=num)
                ioerror("write");
        }
        if(FD_ISSET(tunnel, &rout))
        {
            num=read(tunnel, buffer, BUFFSIZE);
            if(num<0)
                ioerror("read");
            if(num==0)
                return; /* close */
            if(SSL_write(ssl, buffer, num)!=num)
                sslerror("SSL_write");
        }
    }
}

/* Should be done with AF_INET instead of AF_UNIX */
void make_sockets(int fd[2]) /* make pair of connected sockets */
{
    if(socketpair(AF_UNIX, SOCK_STREAM, 0, fd))
        ioerror("socketpair");
}

static RSA *tmp_rsa_cb(SSL *s, int export) /* temporary RSA key callback */
{
    static RSA *rsa_tmp = NULL;
 
    if(rsa_tmp == NULL)
    {
        syslog(LOG_DEBUG, "Generating 512 bit RSA key...");
        rsa_tmp=RSA_generate_key(512, RSA_F4, NULL);
        if(rsa_tmp == NULL)
            sslerror("tmp_rsa_cb");
    }
    return(rsa_tmp);
}

static DH *tmp_dh_cb(SSL *s, int export) /* temporary DH key callback */
{
    static DH *dh_tmp = NULL;

    if(dh_tmp == NULL)
    {
        syslog(LOG_DEBUG, "Generating Diffie-Hellman key...");
        if((dh_tmp = DH_new()) == NULL)
            sslerror("DH_new");
        if(!DH_generate_key(dh_tmp))
            sslerror("DH_generate_key");
        syslog(LOG_DEBUG, "Diffie-Hellman length: %u", DH_size(dh_tmp));
    }
    return(dh_tmp);
}

void ioerror(char *fun) /* Input/Output Error handler */
{
    syslog(LOG_ERR, "%s: %s (%u)", fun, strerror(errno), errno);
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

