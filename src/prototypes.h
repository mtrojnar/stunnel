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

#ifndef PROTOTYPES_H
#define PROTOTYPES_H

#include "common.h"

/**************************************** data structures */

#define MAX_HOSTS 16

typedef enum {LOG_MODE_NONE, LOG_MODE_ERROR, LOG_MODE_FULL} LOG_MODE;

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

typedef enum {
    COMP_NONE, COMP_ZLIB, COMP_RLE
} COMP_TYPE;

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

extern GLOBAL_OPTIONS global_options;

typedef struct servername_list_struct SERVERNAME_LIST; /* forward declaration */

typedef struct service_options_struct {
    SSL_CTX *ctx;                                            /*  SSL context */
    X509_STORE *revocation_store;             /* cert store for CRL checking */
#ifdef HAVE_OSSL_ENGINE_H
    ENGINE *engine;                        /* engine to read the private key */
#endif
    struct service_options_struct *next;   /* next node in the services list */
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
    int curve;
    long ssl_options;
    SOCKADDR_LIST ocsp_addr;
    char *ocsp_path;
    unsigned long ocsp_flags;
    SSL_METHOD *client_method, *server_method;
    SOCKADDR_LIST sessiond_addr;
    SERVERNAME_LIST *servername_list_head, *servername_list_tail;

        /* service-specific data for client.c */
    int fd;        /* file descriptor accepting connections for this service */
    char *execname; /* program name for local mode */
#ifdef USE_WIN32
    char *execargs; /* program arguments for local mode */
#else
    char **execargs; /* program arguments for local mode */
#endif
    SOCKADDR_LIST local_addr, remote_addr, source_addr;
    char *username;
    char *remote_address;
    char *host_name;
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
        unsigned int accept:1;          /* endpoint: accept */
        unsigned int client:1;
        unsigned int delayed_lookup:1;
#ifdef USE_LIBWRAP
        unsigned int libwrap:1;
#endif
        unsigned int remote:1;          /* endpoint: connect */
        unsigned int retry:1;           /* loop remote+program */
        unsigned int sessiond:1;
        unsigned int program:1;         /* endpoint: exec */
        unsigned int sni:1;             /* endpoint: sni */
#ifndef USE_WIN32
        unsigned int pty:1;
        unsigned int transparent_src:1;
        unsigned int transparent_dst:1; /* endpoint: transparent destination */
#endif
        unsigned int ocsp:1;
    } option;
} SERVICE_OPTIONS;

extern SERVICE_OPTIONS service_options;

struct servername_list_struct {
    char *servername;
    SERVICE_OPTIONS *opt;
    struct servername_list_struct *next;
};

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

typedef enum {
    CONF_RELOAD, CONF_FILE, CONF_FD
} CONF_TYPE;

        /* s_poll_set definition for network.c */

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

typedef struct disk_file {
#ifdef USE_WIN32
    HANDLE fh;
#else
    int fd;
#endif
    /* the inteface is prepared to easily implement buffering if needed */
} DISK_FILE;

/**************************************** prototypes for stunnel.c */

extern volatile int num_clients;

void main_initialize(char *, char *);
void daemon_loop(void);
void unbind_ports(void);
int bind_ports(void);
#if !defined (USE_WIN32) && !defined (__vms) && !defined(USE_OS2)
void drop_privileges(void);
#endif
int s_socket(int, int, int, int, char *);
int s_pipe(int [2], int, char *);
int s_socketpair(int, int, int, int [2], int, char *);
int s_accept(int, struct sockaddr *, socklen_t *, int, char *);
void stunnel_info(int);
void die(int);
void set_nonblock(int, unsigned long);

/**************************************** prototypes for log.c */

#if !defined(USE_WIN32) && !defined(__vms)
void syslog_open(void);
void syslog_close(void);
#endif
void log_open(void);
void log_close(void);
void log_flush(LOG_MODE);
void s_log(int, const char *, ...)
#ifdef __GNUC__
    __attribute__ ((format (printf, 2, 3)));
#else
    ;
#endif
void ioerror(const char *);
void sockerror(const char *);
void log_error(int, int, const char *);
char *s_strerror(int);

/**************************************** prototypes for pty.c */

int pty_allocate(int *, int *, char *);

/**************************************** prototypes for ssl.c */

extern int cli_index, opt_index;

void ssl_init(void);
int ssl_configure(void);
#ifdef HAVE_OSSL_ENGINE_H
char *open_engine(const char *);
char *ctrl_engine(const char *, const char *);
void close_engine(void);
ENGINE *get_engine(int);
#endif

/**************************************** prototypes for options.c */

void parse_commandline(char *, char *);
int parse_conf(char *, CONF_TYPE);

/**************************************** prototypes for ctx.c */

int context_init(SERVICE_OPTIONS *);
void sslerror(char *);

/**************************************** prototypes for verify.c */

int verify_init(SERVICE_OPTIONS *);

/**************************************** prototypes for network.c */

void s_poll_init(s_poll_set *);
void s_poll_add(s_poll_set *, int, int, int);
int s_poll_canread(s_poll_set *, int);
int s_poll_canwrite(s_poll_set *, int);
int s_poll_error(s_poll_set *, int);
int s_poll_wait(s_poll_set *, int, int);

#ifdef USE_WIN32
#define SIGNAL_RELOAD_CONFIG    1
#define SIGNAL_REOPEN_LOG       2
#define SIGNAL_TERMINATE        3
#else
#define SIGNAL_RELOAD_CONFIG    SIGHUP
#define SIGNAL_REOPEN_LOG       SIGUSR1
#define SIGNAL_TERMINATE        SIGTERM
#endif
void signal_handler(int);
int signal_pipe_init(void);
void signal_post(int);
#if !defined(USE_WIN32) && !defined(USE_OS2)
void child_status(void);  /* dead libwrap or 'exec' process detected */
#endif

int set_socket_options(int, int);
int get_socket_error(const int);
int make_sockets(int [2]);

/**************************************** prototypes for client.c */

typedef struct {
    int fd; /* file descriptor */
    int is_socket; /* file descriptor is a socket */
} FD;

typedef struct {
    SSL *ssl; /* SSL connnection */
    SERVICE_OPTIONS *opt;
    jmp_buf err; /* exception handler */

    char accepted_address[IPLEN]; /* IP address as text for logging */
    SOCKADDR_LIST peer_addr; /* peer address */
    FD local_rfd, local_wfd; /* read and write local descriptors */
    FD remote_fd; /* remote file descriptor */
    SOCKADDR_LIST bind_addr;
        /* IP for explicit local bind or transparent proxy */
    unsigned long pid; /* PID of the local process */
    int fd; /* temporary file descriptor */

    /* data for transfer() function */
    char sock_buff[BUFFSIZE]; /* socket read buffer */
    char ssl_buff[BUFFSIZE]; /* SSL read buffer */
    int sock_ptr, ssl_ptr; /* index of first unused byte in buffer */
    FD *sock_rfd, *sock_wfd; /* read and write socket descriptors */
    FD *ssl_rfd, *ssl_wfd; /* read and write SSL descriptors */
    int sock_bytes, ssl_bytes; /* bytes written to socket and SSL */
    s_poll_set fds; /* file descriptors */
} CLI;

CLI *alloc_client_session(SERVICE_OPTIONS *, int, int);
void *client(void *);

/**************************************** prototypes for network.c */

int connect_blocking(CLI *, SOCKADDR_UNION *, socklen_t);
void write_blocking(CLI *, int fd, void *, int);
void read_blocking(CLI *, int fd, void *, int);
void fdputline(CLI *, int, const char *);
char *fdgetline(CLI *, int);
/* descriptor versions of fprintf/fscanf */
int fdprintf(CLI *, int, const char *, ...)
#ifdef __GNUC__
       __attribute__ ((format (printf, 3, 4)));
#else
       ;
#endif

/**************************************** prototype for protocol.c */

void negotiate(CLI *c);

/**************************************** prototypes for resolver.c */

int name2addrlist(SOCKADDR_LIST *, char *, char *);
int hostport2addrlist(SOCKADDR_LIST *, char *, char *);
char *s_ntop(char *, SOCKADDR_UNION *);

/**************************************** prototypes for sthreads.c */

typedef enum {
    CRIT_KEYGEN, CRIT_INET, CRIT_CLIENTS,
    CRIT_WIN_LOG, CRIT_SESSION, CRIT_LIBWRAP,
#if OPENSSL_VERSION_NUMBER<0x1000002f
    CRIT_SSL,
#endif /* OpenSSL version < 1.0.0b */
    CRIT_SECTIONS
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
    ucontext_t context;
    s_poll_set *fds;
    int ready; /* number of ready file descriptors */
    time_t finish; /* when to finish poll() for this context */
    struct CONTEXT_STRUCTURE *next; /* next context on a list */
    void *tls; /* thread local storage for str.c */
} CONTEXT;
extern CONTEXT *ready_head, *ready_tail;
extern CONTEXT *waiting_head, *waiting_tail;
#endif
#ifdef _WIN32_WCE
long _beginthread(void (*)(void *), int, void *);
void _endthread(void);
#endif
#ifdef DEBUG_STACK_SIZE
void stack_info(int);
#endif

/**************************************** prototypes for gui.c */

typedef struct {
    SERVICE_OPTIONS *opt;
    char pass[PEM_BUFSIZE];
} UI_DATA;

#ifdef USE_WIN32
void win_log(char *);
void win_exit(int);
void win_newconfig(int);
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

/**************************************** prototypes for file.c */

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

/**************************************** prototypes for libwrap.c */

void libwrap_init(int);
void libwrap_auth(CLI *);

/**************************************** prototypes for str.c */

void str_init();
void str_cleanup();
void str_stats();
void *str_alloc(size_t);
void *str_realloc(void *, size_t);
void str_free(void *);
char *str_dup(const char *);
char *str_vprintf(const char *, va_list);
char *str_printf(const char *, ...)
#ifdef __GNUC__
    __attribute__ ((format (printf, 1, 2)));
#else
    ;
#endif

#endif /* defined PROTOTYPES_H */

/* end of prototypes.h */
