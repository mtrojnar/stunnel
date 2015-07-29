/*
 *   stunnel       Universal SSL tunnel
 *   Copyright (c) 1998-2002 Michal Trojnara <Michal.Trojnara@mirt.net>
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

/* Prototypes for stunnel.c */

void main_initialize(char *);
void main_execute(void);
void ioerror(char *);
void sockerror(char *);
void log_error(int, int, char *);
void log_error_addr(int, int, struct sockaddr_in *, char *);
int set_socket_options(int, int);
#ifndef USE_WIN32
void local_handler(int);
#endif
char *stunnel_info(void);
int alloc_fd(int);
void setnonblock(int, unsigned long);

/* Prototypes for ssl.c */

void context_init(void);
void context_free(void);
void sslerror(char *);

/* Prototypes for log.c */

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
    
/* Prototypes for sthreads.c */

typedef enum {
    CRIT_KEYGEN, CRIT_LIBWRAP, CRIT_NTOA, CRIT_CLIENTS, CRIT_WIN_LOG,
    CRIT_SECTIONS
} section_code;

void enter_critical_section(section_code);
void leave_critical_section(section_code);
void sthreads_init(void);
unsigned long process_id(void);
unsigned long thread_id(void);
int create_client(int, int, void *, void *(*)(void *));

/* Prototypes for pty.c */
/* Based on Public Domain code by Tatu Ylonen <ylo@cs.hut.fi> */

int pty_allocate(int *ptyfd, int *ttyfd, char *ttyname, int ttynamelen);
void pty_release(char *ttyname);
void pty_make_controlling_tty(int *ttyfd, char *ttyname);

/* Prototypes for options.c */

typedef struct {
        /* some data for SSL initialization in ssl.c */
    char *ca_dir;                              /* directory for hashed certs */
    char *ca_file;                       /* file containing bunches of certs */
    char *cipher_list;
    char *cert;                                             /* cert filename */
    char *egd_sock;                       /* entropy gathering daemon socket */
    char *key;                               /* pem (priv key/cert) filename */
    char *rand_file;                                /* file with random data */
    int random_bytes;                       /* how many random bytes to read */
    long session_timeout;
    int verify_level;
    int verify_use_only_my;

        /* some global data for stunnel.c */
#ifndef USE_WIN32
    char *chroot_dir;
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
        unsigned int rand_write;                      /* overwrite rand_file */
    } option;
} GLOBAL_OPTIONS;

extern GLOBAL_OPTIONS options;

typedef struct local_options {
    struct local_options *next;            /* next node in the services list */

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

void parse_config(char *);
int name2nums(char *, char *, u32 **, u_short *);

/* Prototypes for client.c */
void *alloc_client_session(LOCAL_OPTIONS *, int, int);
void *client(void *);

/* Prototypes for gui.c */
#ifdef USE_WIN32
void win_log(char *);
void exit_stunnel(int);
#endif

#endif /* defined PROTOTYPES_H */

/* End of prototypes.h */
