/*
 *   stunnel       Universal SSL tunnel
 *   Copyright (C) 1998-2009 Michal Trojnara <Michal.Trojnara@mirt.net>
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

#ifndef PROTOTYPES_H
#define PROTOTYPES_H

#include "common.h"

/**************************************** Network data structure */

#define MAX_HOSTS 16

typedef union sockaddr_union {
    struct sockaddr sa;
    struct sockaddr_in in;
#if defined(USE_IPv6)
    struct sockaddr_in6 in6;
#endif
} SOCKADDR_UNION;

typedef struct sockaddr_list {      /* list of addresses */
    SOCKADDR_UNION addr[MAX_HOSTS]; /* the list of addresses */
    u16 cur;                        /* current address for round-robin */
    u16 num;                        /* how many addresses are used */
} SOCKADDR_LIST;

#ifdef __INNOTEK_LIBC__
#define socklen_t    __socklen_t
#define strcasecmp   stricmp
#define strncasecmp  strnicmp
#define NI_NUMERICHOST 1
#define NI_NUMERICSERV 2
#endif


/**************************************** Prototypes for stunnel.c */

extern volatile int num_clients;

void main_initialize(char *, char *);
void main_execute(void);
#if !defined (USE_WIN32) && !defined (__vms) && !defined(USE_OS2)
void drop_privileges(void);
#endif
void stunnel_info(int);
void die(int);

/**************************************** Prototypes for log.c */

void log_open(void);
void log_close(void);
void log_flush(void);
void s_log(int, const char *, ...)
#ifdef __GNUC__
    __attribute__ ((format (printf, 2, 3)));
#else
    ;
#endif
void ioerror(const char *);
void sockerror(const char *);
void log_error(int, int, const char *);
char *my_strerror(int);

/**************************************** Prototypes for pty.c */
/* Based on Public Domain code by Tatu Ylonen <ylo@cs.hut.fi>  */

int pty_allocate(int *, int *, char *, int);
#if 0
void pty_release(char *);
void pty_make_controlling_tty(int *, char *);
#endif

/**************************************** Prototypes for ssl.c */

typedef enum {
    COMP_NONE, COMP_ZLIB, COMP_RLE
} COMP_TYPE;

extern int cli_index, opt_index;;

void ssl_init(void);
void ssl_configure(void);
#ifdef HAVE_OSSL_ENGINE_H
void open_engine(const char *);
void ctrl_engine(const char *, const char *);
void close_engine(void);
ENGINE *get_engine(int);
#endif

/**************************************** Prototypes for options.c */

typedef struct {
        /* some data for SSL initialization in ssl.c */
    COMP_TYPE compression;                               /* compression type */
    char *egd_sock;                       /* entropy gathering daemon socket */
    char *rand_file;                                /* file with random data */
    int random_bytes;                       /* how many random bytes to read */

        /* some global data for stunnel.c */
#ifndef USE_WIN32
#ifdef HAVE_CHROOT
    char *chroot_dir;
#endif
    unsigned long dpid;
    char *pidfile;
    int uid, gid;
#endif

        /* Win32 specific data for gui.c */
#if defined(USE_WIN32) && !defined(_WIN32_WCE)
    char *win32_service;
#endif

        /* logging-support data for log.c */
    int debug_level;                              /* debug level for logging */
#ifndef USE_WIN32
    int facility;                               /* debug facility for syslog */
#endif
    char *output_file;

        /* on/off switches */
    struct {
        unsigned int rand_write:1;                    /* overwrite rand_file */
#ifdef USE_WIN32
        unsigned int taskbar:1;                   /* enable the taskbar icon */
#else /* !USE_WIN32 */
        unsigned int foreground:1;
        unsigned int syslog:1;
#endif
#ifdef USE_FIPS
        unsigned int fips:1;                       /* enable FIPS 140-2 mode */
#endif
    } option;
} GLOBAL_OPTIONS;

extern GLOBAL_OPTIONS options;

typedef struct local_options {
    SSL_CTX *ctx;                                            /*  SSL context */
    X509_STORE *revocation_store;             /* cert store for CRL checking */
#ifdef HAVE_OSSL_ENGINE_H
    ENGINE *engine;                        /* engine to read the private key */
#endif
    struct local_options *next;            /* next node in the services list */
    char *servname;        /* service name for logging & permission checking */
    SSL_SESSION *session;                           /* jecently used session */
    char local_address[IPLEN];             /* dotted-decimal address to bind */
#ifndef USE_FORK
    int stack_size;                            /* stack size for this thread */
#endif

        /* service-specific data for ctx.c */
    char *ca_dir;                              /* directory for hashed certs */
    char *ca_file;                       /* file containing bunches of certs */
    char *crl_dir;                              /* directory for hashed CRLs */
    char *crl_file;                       /* file containing bunches of CRLs */
    char *cipher_list;
    char *cert;                                             /* cert filename */
    char *key;                               /* pem (priv key/cert) filename */
    long session_timeout;
    int verify_level;
    int verify_use_only_my;
    long ssl_options;
#if SSLEAY_VERSION_NUMBER >= 0x00907000L
    SOCKADDR_LIST ocsp_addr;
    char *ocsp_path;
    unsigned long ocsp_flags;
#endif /* OpenSSL-0.9.7 */
    SSL_METHOD *client_method, *server_method;
    SOCKADDR_LIST sessiond_addr;

        /* service-specific data for client.c */
    int fd;        /* file descriptor accepting connections for this service */
    char *execname, **execargs; /* program name and arguments for local mode */
    SOCKADDR_LIST local_addr, remote_addr, source_addr;
    char *username;
    char *remote_address;
    int timeout_busy; /* maximum waiting for data time */
    int timeout_close; /* maximum close_notify time */
    int timeout_connect; /* maximum connect() time */
    int timeout_idle; /* maximum idle connection time */
    enum {FAILOVER_RR, FAILOVER_PRIO} failover; /* failover strategy */

        /* protocol name for protocol.c */
    char *protocol;
    char *protocol_host;
    char *protocol_username;
    char *protocol_password;
    char *protocol_authentication;

        /* on/off switches */
    struct {
        unsigned int cert:1;
        unsigned int client:1;
        unsigned int delayed_lookup:1;
        unsigned int accept:1;
        unsigned int remote:1;
        unsigned int retry:1; /* loop remote+program */
        unsigned int sessiond:1;
#ifndef USE_WIN32
        unsigned int program:1;
        unsigned int pty:1;
        unsigned int transparent:1;
#endif
#if SSLEAY_VERSION_NUMBER >= 0x00907000L
        unsigned int ocsp:1;
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

/**************************************** Prototypes for ctx.c */

void context_init(LOCAL_OPTIONS *);
void sslerror(char *);

/**************************************** Prototypes for verify.c */

void verify_init(LOCAL_OPTIONS *);

/**************************************** Prototypes for network.c */

#ifdef USE_POLL
#define MAX_FD 256
#endif

typedef struct {
#ifdef USE_POLL
    struct pollfd ufds[MAX_FD];
    unsigned int nfds;
#else
    fd_set irfds, iwfds, orfds, owfds;
    int max;
#endif
} s_poll_set;

void s_poll_init(s_poll_set *);
void s_poll_add(s_poll_set *, int, int, int);
int s_poll_canread(s_poll_set *, int);
int s_poll_canwrite(s_poll_set *, int);
int s_poll_wait(s_poll_set *, int, int);

#ifndef USE_WIN32
int signal_pipe_init(void);
void child_status(void);  /* dead libwrap or 'exec' process detected */
#endif
int set_socket_options(int, int);
int alloc_fd(int);
void setnonblock(int, unsigned long);

/**************************************** Prototypes for client.c */

typedef struct {
    int fd; /* File descriptor */
    int rd; /* Open for read */
    int wr; /* Open for write */
    int is_socket; /* File descriptor is a socket */
} FD;

typedef struct {
    LOCAL_OPTIONS *opt;
    char accepted_address[IPLEN]; /* text */
    SOCKADDR_LIST peer_addr; /* Peer address */
    FD local_rfd, local_wfd; /* Read and write local descriptors */
    FD remote_fd; /* Remote file descriptor */
    SSL *ssl; /* SSL Connection */
    SOCKADDR_LIST bind_addr;
        /* IP for explicit local bind or transparent proxy */
    unsigned long pid; /* PID of local process */
    int fd; /* Temporary file descriptor */
    jmp_buf err;

    char sock_buff[BUFFSIZE]; /* Socket read buffer */
    char ssl_buff[BUFFSIZE]; /* SSL read buffer */
    int sock_ptr, ssl_ptr; /* Index of first unused byte in buffer */
    FD *sock_rfd, *sock_wfd; /* Read and write socket descriptors */
    FD *ssl_rfd, *ssl_wfd; /* Read and write SSL descriptors */
    int sock_bytes, ssl_bytes; /* Bytes written to socket and ssl */
    s_poll_set fds; /* File descriptors */
} CLI;

extern int max_clients;
#ifndef USE_WIN32
extern int max_fds;
#endif

CLI *alloc_client_session(LOCAL_OPTIONS *, int, int);
void *client(void *);

/**************************************** Prototypes for network.c */

int connect_blocking(CLI *, SOCKADDR_UNION *, socklen_t);
void write_blocking(CLI *, int fd, void *, int);
void read_blocking(CLI *, int fd, void *, int);
void fdputline(CLI *, int, const char *);
void fdgetline(CLI *, int, char *);
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

/**************************************** Prototype for protocol.c */

void negotiate(CLI *c);

/**************************************** Prototypes for resolver.c */

int name2addrlist(SOCKADDR_LIST *, char *, char *);
int hostport2addrlist(SOCKADDR_LIST *, char *, char *);
char *s_ntop(char *, SOCKADDR_UNION *);

/**************************************** Prototypes for sthreads.c */

typedef enum {
    CRIT_KEYGEN, CRIT_INET, CRIT_CLIENTS, CRIT_WIN_LOG, CRIT_SESSION,
    CRIT_LIBWRAP, CRIT_SSL, CRIT_SECTIONS
} SECTION_CODE;

void enter_critical_section(SECTION_CODE);
void leave_critical_section(SECTION_CODE);
void sthreads_init(void);
unsigned long stunnel_process_id(void);
unsigned long stunnel_thread_id(void);
int create_client(int, int, CLI *, void *(*)(void *));
#ifdef USE_UCONTEXT
typedef struct CONTEXT_STRUCTURE {
    char *stack; /* CPU stack for this thread */
    unsigned long id;
    ucontext_t ctx;
    s_poll_set *fds;
    int ready; /* number of ready file descriptors */
    time_t finish; /* when to finish poll() for this context */
    struct CONTEXT_STRUCTURE *next; /* next context on a list */
} CONTEXT;
extern CONTEXT *ready_head, *ready_tail;
extern CONTEXT *waiting_head, *waiting_tail;
#endif
#ifdef _WIN32_WCE
int _beginthread(void (*)(void *), int, void *);
void _endthread(void);
#endif
#ifdef DEBUG_STACK_SIZE
void stack_info(int);
#endif

/**************************************** Prototypes for gui.c */

typedef struct {
    LOCAL_OPTIONS *section;
    char pass[PEM_BUFSIZE];
} UI_DATA;

#ifdef USE_WIN32
void win_log(char *);
void exit_win32(int);
int passwd_cb(char *, int, int, void *);
#ifdef HAVE_OSSL_ENGINE_H
int pin_cb(UI *, UI_STRING *);
#endif

#ifndef _WIN32_WCE
typedef int (CALLBACK * GETADDRINFO) (const char *,
    const char *, const struct addrinfo *, struct addrinfo **);
typedef void (CALLBACK * FREEADDRINFO) (struct addrinfo FAR *);
typedef int (CALLBACK * GETNAMEINFO) (const struct sockaddr *, socklen_t,
    char *, size_t, char *, size_t, int);
extern GETADDRINFO s_getaddrinfo;
extern FREEADDRINFO s_freeaddrinfo;
extern GETNAMEINFO s_getnameinfo;
#endif /* ! _WIN32_WCE */
#endif /* USE_WIN32 */

/**************************************** Prototypes for file.c */

typedef struct disk_file {
#ifdef USE_WIN32
    HANDLE fh;
#else
    int fd;
#endif
    /* the inteface is prepared to easily implement buffering if needed */
} DISK_FILE;

#ifndef USE_WIN32
DISK_FILE *file_fdopen(int);
#endif
DISK_FILE *file_open(char *, int);
void file_close(DISK_FILE *);
int file_getline(DISK_FILE *, char *, int);
int file_putline(DISK_FILE *, char *);

#ifdef USE_WIN32
LPTSTR str2tstr(const LPSTR);
LPSTR tstr2str(const LPTSTR);
#endif

/**************************************** Prototypes for libwrap.c */

void libwrap_init(int);
void auth_libwrap(CLI *);

#endif /* defined PROTOTYPES_H */

/* End of prototypes.h */
