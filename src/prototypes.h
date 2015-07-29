/*
 *   stunnel       Universal SSL tunnel
 *   Copyright (c) 1998-2004 Michal Trojnara <Michal.Trojnara@mirt.net>
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

#ifndef PROTOTYPES_H
#define PROTOTYPES_H

#include "common.h"

/**************************************** Prototypes for stunnel.c */

extern int num_clients;

void main_initialize(char *, char *);
void main_execute(void);
void ioerror(char *);
void sockerror(char *);
void log_error(int, int, char *);
char *my_strerror(int);
int set_socket_options(int, int);
char *stunnel_info(void);
int alloc_fd(int);
char *safe_ntoa(char *, struct in_addr);

/**************************************** Prototypes for ssl.c */

void context_init(void);
void context_free(void);
void sslerror(char *);

/**************************************** Prototypes for log.c */

void log_open(void);
void log_close(void);
#if defined (USE_WIN32) || defined (__vms)
/* This conflicts with the "double log (double __x)" routine from math.h */
#define log stunnel_log
#endif
void log(int, const char *, ...)
#ifdef __GNUC__
    __attribute__ ((format (printf, 2, 3)));
#else
    ;
#endif
void log_raw(const char *, ...)
#ifdef __GNUC__
    __attribute__ ((format (printf, 1, 2)));
#else
    ;
#endif
    
/**************************************** Prototypes for sthreads.c */

typedef enum {
    CRIT_KEYGEN, CRIT_NTOA, CRIT_CLIENTS, CRIT_WIN_LOG, CRIT_SECTIONS
} section_code;

void enter_critical_section(section_code);
void leave_critical_section(section_code);
void sthreads_init(void);
unsigned long stunnel_process_id(void);
unsigned long stunnel_thread_id(void);
int create_client(int, int, void *, void *(*)(void *));
#ifdef DEBUG_STACK_SIZE
void stack_info(int);
#endif

/**************************************** Prototypes for pty.c */
/* Based on Public Domain code by Tatu Ylonen <ylo@cs.hut.fi>  */

int pty_allocate(int *, int *, char *, int);
#if 0
void pty_release(char *);
void pty_make_controlling_tty(int *, char *);
#endif

/**************************************** Prototypes for options.c */

typedef struct {
        /* some data for SSL initialization in ssl.c */
    char *ca_dir;                              /* directory for hashed certs */
    char *ca_file;                       /* file containing bunches of certs */
    char *crl_dir;                              /* directory for hashed CRLs */
    char *crl_file;                       /* file containing bunches of CRLs */
    char *cipher_list;
    char *cert;                                             /* cert filename */
    char *egd_sock;                       /* entropy gathering daemon socket */
    char *key;                               /* pem (priv key/cert) filename */
    char *rand_file;                                /* file with random data */
    int random_bytes;                       /* how many random bytes to read */
    long session_timeout;
    int verify_level;
    int verify_use_only_my;
    long ssl_options;

        /* some global data for stunnel.c */
#ifndef USE_WIN32
#ifdef HAVE_CHROOT
    char *chroot_dir;
#endif
    unsigned long dpid;
    char *pidfile;
    char *setuid_user;
    char *setgid_group;
#endif

        /* Win32 specific data for gui.c */
#ifdef USE_WIN32
    char *win32_service;
    char *win32_name;
#endif

        /* logging-support data for log.c */
    int debug_level;                               /* debug level for syslog */
#ifndef USE_WIN32
    int facility;                               /* debug facility for syslog */
#endif
    char *output_file;

        /* on/off switches */
    struct {
        unsigned int cert:1;
        unsigned int client:1;
        unsigned int foreground:1;
        unsigned int syslog:1;                              /* log to syslog */
        unsigned int rand_write:1;                    /* overwrite rand_file */
#ifdef USE_WIN32
        unsigned int taskbar:1;                   /* enable the taskbar icon */
#endif
    } option;
} GLOBAL_OPTIONS;

extern GLOBAL_OPTIONS options;

typedef struct local_options {
    struct local_options *next;            /* next node in the services list */

    char local_address[16]; /* Dotted-decimal address to bind */

        /* name of service */
    char *servname;         /* service name for loggin & permission checking */

        /* service-specific data for client.c */
    int fd;        /* file descriptor accepting connections for this service */
    unsigned short localport, remoteport;
    char *execname, **execargs; /* program name and arguments for local mode */
    u32 *localnames, *remotenames;
    u32 *local_ip;
    char *username;
    char *remote_address;
    int timeout_busy; /* Maximum waiting for data time */
    int timeout_idle; /* Maximum idle connection time */
    int timeout_close; /* Maximum close_notify time */

        /* protocol name for protocol.c */
    char *protocol;

        /* on/off switches */
    struct {
        unsigned int delayed_lookup:1;
        unsigned int accept:1;
        unsigned int remote:1;
#ifndef USE_WIN32
        unsigned int program:1;
        unsigned int pty:1;
        unsigned int transparent:1;
#endif
    } option;
} LOCAL_OPTIONS;

extern LOCAL_OPTIONS local_options;

typedef enum {
    TYPE_NONE, TYPE_FLAG, TYPE_INT, TYPE_LINGER, TYPE_TIMEVAL, TYPE_STRING
} VAL_TYPE;

typedef union {
    int            i_val;
    long           l_val;
    char           c_val[16];
    struct linger  linger_val;
    struct timeval timeval_val;
} OPT_UNION;

typedef struct {
    char *opt_str;
    int  opt_level;
    int  opt_name;
    VAL_TYPE opt_type;
    OPT_UNION *opt_val[3];
} SOCK_OPT;

void parse_config(char *, char *);
int name2nums(char *, char *, u32 **, u_short *);

/**************************************** Prototypes for client.c */

typedef struct {
    int fd; /* File descriptor */
    int rd; /* Open for read */
    int wr; /* Open for write */
    int is_socket; /* File descriptor is a socket */
} FD;

typedef struct {
    LOCAL_OPTIONS *opt;
    char accepting_address[16], connecting_address[16]; /* Dotted-decimal */
    struct sockaddr_in addr; /* Local address */
    FD local_rfd, local_wfd; /* Read and write local descriptors */
    FD remote_fd; /* Remote descriptor */
    SSL *ssl; /* SSL Connection */
    int bind_ip; /* IP for explicit local bind or transparent proxy */
    unsigned long pid; /* PID of local process */
    u32 *resolved_addresses; /* List of IP addresses for delayed lookup */

    char sock_buff[BUFFSIZE]; /* Socket read buffer */
    char ssl_buff[BUFFSIZE]; /* SSL read buffer */
    int sock_ptr, ssl_ptr; /* Index of first unused byte in buffer */
    FD *sock_rfd, *sock_wfd; /* Read and write socket descriptors */
    FD *ssl_rfd, *ssl_wfd; /* Read and write SSL descriptors */
    int sock_bytes, ssl_bytes; /* Bytes written to socket and ssl */
} CLI;

extern int max_clients;
#ifndef USE_WIN32
extern int max_fds;
#endif

#define sock_rd (c->sock_rfd->rd)
#define sock_wr (c->sock_wfd->wr)
#define ssl_rd (c->ssl_rfd->rd)
#define ssl_wr (c->ssl_wfd->wr)

void *alloc_client_session(LOCAL_OPTIONS *, int, int);
void *client(void *);

/**************************************** Prototype for protocol.c */

int negotiate(CLI *c);

/**************************************** Prototypes for select.c */

int sselect(int, fd_set *, fd_set *, fd_set *, struct timeval *);
int waitforsocket(int, int, int);
#ifndef USE_WIN32
void sselect_init(fd_set *, int *);
void exec_status(void);
#endif
int write_blocking(CLI *, int fd, u8 *, int);
int read_blocking(CLI *, int fd, u8 *, int);
/* descriptor versions of fprintf/fscanf */
int fdprintf(CLI *, int, const char *, ...)
#ifdef __GNUC__
       __attribute__ ((format (printf, 3, 4)));
#else
       ;
#endif
int fdscanf(CLI *, int, const char *, char *)
#ifdef __GNUC__
       __attribute__ ((format (scanf, 3, 0)));
#else
       ;
#endif

/**************************************** Prototypes for gui.c */

#ifdef USE_WIN32
void win_log(char *);
void exit_stunnel(int);
int pem_passwd_cb(char *, int, int, void *);
#endif

#endif /* defined PROTOTYPES_H */

/* End of prototypes.h */
