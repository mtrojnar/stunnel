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

#ifndef CLIENT_H
#define CLIENT_H

#include "common.h"

/* I/O buffer size */
#define BUFFSIZE 16384

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

typedef struct {
    int error; /* Reset connections */
    struct sockaddr_in addr; /* Local address */
    int local_rfd, local_wfd; /* Read and write local descriptors */
    int remote_fd; /* Remote descriptor */
    int negotiation_level; /* fdscanf() or fdprintf() number in negotiate() */
    SSL *ssl; /* SSL Connection */
    int ip; /* for connect_local() and connect_remote() */
    unsigned long pid; /* PID of local process */
    char sock_buff[BUFFSIZE]; /* Socket read buffer */
    char ssl_buff[BUFFSIZE]; /* SSL read buffer */
    int sock_ptr, ssl_ptr; /* Index of first unused byte in buffer */
    int sock_rfd, sock_wfd; /* Read and write socket descriptors */
    int ssl_rfd, ssl_wfd; /* Read and write SSL descriptors */
    int sock_bytes, ssl_bytes; /* Bytes written to socket and ssl */
} CLI;

typedef enum {
    STATE_NONE,         /* Not used */
    STATE_ACCEPT,       /* On accept() */
    STATE_CONNECT,      /* On connect() */
    STATE_NEGOTIATE,    /* On negotiate() */
    STATE_SSL_INIT,     /* On SSL_accept() or SSL_connect() */
    STATE_SSL_SHUTDOWN, /* On SSL_shutdown() */
    STATE_SSL,          /* On SSL_read or SSL_write */
    STATE_PLAIN,        /* On readsocket() or writesocket() */
    STATE_USER          /* On auth_user */
} STATE;

typedef struct {
    STATE state;
    int rd; /* Open for read */
    int wr; /* Open for write */
    int is_socket; /* File descriptor is a socket */
    CLI *cli; /* Client structure if state>STATE_ACCEPT */
} FD;

extern int max_fds;
extern FD *d;

#define sock_rd (d[c->sock_rfd].rd)
#define sock_wr (d[c->sock_wfd].wr)
#define ssl_rd (d[c->ssl_rfd].rd)
#define ssl_wr (d[c->ssl_wfd].wr)

/* Prototype for protocol.c */
int negotiate(char *, int, CLI *c);

#endif /* defined CLIENT_H */

/* End of client.h */
