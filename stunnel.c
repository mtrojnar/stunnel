/*****************************************************/
/* stunnel.c          version 1.00          97.02.11 */
/* by Michal Trojnara   <mtrojnar@ddc.daewoo.com.pl> */
/* special thx to Adam Hernik <adas@infocentrum.com> */
/*****************************************************/

#define MYCERT "/etc/server.pem"
#define BUFFSIZE 8192	/* I/O buffer size */

#include <stdio.h>
#include <unistd.h>	/* for fork, execvp, exit */
#include <errno.h>	/* for errno */
#include <string.h>	/* for strerror */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>	/* for select */
#include <signal.h>	/* for signal */
#include <syslog.h>	/* for openlog, syslog */
#include <ssl.h>
#include <err.h>

void make_sockets(int [2]);
void transfer(SSL *, int);
void signal_handler(int sig);
void ioerror(char*);
void sslerror(char*);
void generror(char*);

int main(int argc, char* argv[])
{
    int fd[2];
    SSL *ssl;
    SSL_CTX *ctx;

    signal(SIGPIPE, SIG_IGN); /* avoid 'broken pipe' signal */
    signal(SIGTERM, signal_handler);
    signal(SIGQUIT, signal_handler);
    signal(SIGSEGV, signal_handler);
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
        SSLeay_add_ssl_algorithms();
        ctx=SSL_CTX_new(SSLv23_server_method());
        if(!SSL_CTX_use_RSAPrivateKey_file(ctx, MYCERT, SSL_FILETYPE_PEM))
            sslerror("SSL_CTX_use_RSAPrivateKey_file");
        if(!SSL_CTX_use_certificate_file(ctx, MYCERT, SSL_FILETYPE_PEM))
            sslerror("SSL_CTX_use_certificate_file");
        ssl=SSL_new(ctx);
        SSL_set_fd(ssl, 0);
        if(!SSL_accept(ssl))
            sslerror("SSL_accept");
        transfer(ssl, fd[0]);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
    }
    return 0; /* success */
}

/* Should be done with AF_INET instead of AF_UNIX */
void make_sockets(int fd[2])
{
    if(socketpair(AF_UNIX, SOCK_STREAM, 0, fd))
        ioerror("socketpair");
}

void transfer(SSL *ssl, int tunnel)
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
            /* replace next line with ssl function */
            if(SSL_write(ssl, buffer, num)!=num)
                ioerror("SSL_write");
        }
    }
}

void signal_handler(int sig) /* Signal handler */
{
    char buffer[256];

    sprintf(buffer, "received signal %d; terminating.", sig);
    generror(buffer);
}

void ioerror(char *fun) /* Input/Output Error handler */
{
    char buffer[256];

    sprintf(buffer, "%s: %s (%d)", fun, strerror(errno), errno);
    generror(buffer);
}

void sslerror(char *fun) /* SSL Error handler */
{
    char buffer[256], string[120];

    SSL_load_error_strings();
    ERR_error_string(ERR_get_error(), string);
    sprintf(buffer, "%s: %s", fun, string);
    generror(buffer);
}

void generror(char *text) /* Generic Error handler */
{
    openlog("stunnel", LOG_CONS | LOG_NDELAY | LOG_PID, LOG_DAEMON);
    syslog(LOG_ERR, text);
    closelog();
    exit(1);
}

