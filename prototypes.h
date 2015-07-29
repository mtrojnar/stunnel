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

#ifndef PROTOTYPES_H
#define PROTOTYPES_H

#include "common.h"

/* Prototypes for stunnel.c */

void ioerror(char *);
void sockerror(char *);
void log_error(int, int, char *);
int set_socket_options(int, int);
void local_handler(int);
char *stunnel_info();

/* Prototypes for ssl.c */

void context_init();
void context_free();
void sslerror(char *);

/* Prototypes for client.c */
void *client(void *);
/* descriptor versions of fprintf/fscanf */
int fdprintf(int, char *, ...);
int fdscanf(int, char *, char *);

/* Prototypes for log.c */

void log_open();
void log_close();
void log(int, char *, ...);

/* Prototypes for sthreads.c */

typedef enum {
    CRIT_KEYGEN, CRIT_LIBWRAP, CRIT_NTOA, CRIT_CLIENTS, CRIT_SECTIONS
} section_code;

void enter_critical_section(section_code);
void leave_critical_section(section_code);
void sthreads_init(void);
unsigned long process_id(void);
unsigned long thread_id(void);
int create_client(int, int, void *(*)(void *));

/* Prototypes for pty.c */
/* Based on Public Domain code by Tatu Ylonen <ylo@cs.hut.fi> */

int pty_allocate(int *ptyfd, int *ttyfd, char *ttyname, int ttynamelen);
void pty_release(char *ttyname);
void pty_make_controlling_tty(int *ttyfd, char *ttyname);

/* Prototypes for options.c */
#define OPT_CLIENT      0x01
#define OPT_CERT        0x02
#define OPT_DAEMON      0x04
#define OPT_FOREGROUND  0x08
#define OPT_PROGRAM     0x10
#define OPT_REMOTE      0x20
#define OPT_TRANSPARENT 0x40
#define OPT_PTY         0x80

typedef struct {
    char pem[STRLEN];                        /* pem (priv key/cert) filename */
    char cert_dir[STRLEN];                     /* directory for hashed certs */
    char cert_file[STRLEN];              /* file containing bunches of certs */
    char pidfile[STRLEN];
    unsigned long dpid;
    int clients;
    int option;
    int foreground;                              /* force messages to stderr */
    unsigned short localport, remoteport;
    u32 *localnames, *remotenames;
    char *execname, **execargs; /* program name and arguments for local mode */
    char servname[STRLEN];  /* service name for loggin & permission checking */
    int verify_level;
    int verify_use_only_my;
    int debug_level;                               /* debug level for syslog */
    int facility;                               /* debug facility for syslog */
    long session_timeout;
    char *cipher_list;
    char *username;
    char *protocol;
    char *setuid_user;
    char *setgid_group;
    char *egd_sock;                       /* entropy gathering daemon socket */
    char *rand_file;                                /* file with random data */
    int rand_write; /* overwrite rand_file with new rand data when PRNG seeded */
    int random_bytes;                       /* how many random bytes to read */
    char *pid_dir;
    int cert_defaults;
    char *output_file;
    u32 *local_ip;
} server_options;

typedef enum {
    TYPE_NONE, TYPE_FLAG, TYPE_INT, TYPE_LINGER, TYPE_TIMEVAL, TYPE_STRING
} val_type;

typedef union {
    int            i_val;
    long           l_val;
    char           c_val[16];
    struct linger  linger_val;
    struct timeval timeval_val;
} opt_union;

typedef struct {
    char *opt_str;
    int  opt_level;
    int  opt_name;
    val_type opt_type;
    opt_union *opt_val[3];
} sock_opt;

void parse_options(int argc, char *argv[]);

#endif /* defined PROTOTYPES_H */

/* End of prototypes.h */
