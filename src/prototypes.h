/*
 *   stunnel       Universal SSL tunnel
 *   Copyright (C) 1998-2013 Michal Trojnara <Michal.Trojnara@mirt.net>
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

typedef enum {
    LOG_MODE_NONE,
    LOG_MODE_ERROR,
    LOG_MODE_INFO,
    LOG_MODE_CONFIGURED
} LOG_MODE;

typedef union sockaddr_union {
    struct sockaddr sa;
    struct sockaddr_in in;
#ifdef USE_IPv6
    struct sockaddr_in6 in6;
#endif
#ifdef HAVE_STRUCT_SOCKADDR_UN
    struct sockaddr_un un;
#endif
} SOCKADDR_UNION;

typedef struct name_list_struct {
    char *name;
    struct name_list_struct *next;
} NAME_LIST;

typedef struct sockaddr_list {                          /* list of addresses */
    SOCKADDR_UNION *addr;                           /* the list of addresses */
    u16 cur;                              /* current address for round-robin */
    u16 num;                                  /* how many addresses are used */
} SOCKADDR_LIST;

#ifndef OPENSSL_NO_COMP
typedef enum {
    COMP_NONE, COMP_DEFLATE, COMP_ZLIB, COMP_RLE
} COMP_TYPE;
#endif /* OPENSSL_NO_COMP */

typedef struct {
        /* some data for SSL initialization in ssl.c */
#ifndef OPENSSL_NO_COMP
    COMP_TYPE compression;                               /* compression type */
#endif /* OPENSSL_NO_COMP */
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

#ifndef OPENSSL_NO_TLSEXT
typedef struct servername_list_struct SERVERNAME_LIST;/* forward declaration */
#endif

typedef struct service_options_struct {
    struct service_options_struct *next;   /* next node in the services list */
    SSL_CTX *ctx;                                            /*  SSL context */
    char *servname;        /* service name for logging & permission checking */

        /* service-specific data for sthreads.c */
#ifndef USE_FORK
    int stack_size;                            /* stack size for this thread */
#endif

        /* service-specific data for verify.c */
    char *ca_dir;                              /* directory for hashed certs */
    char *ca_file;                       /* file containing bunches of certs */
    char *crl_dir;                              /* directory for hashed CRLs */
    char *crl_file;                       /* file containing bunches of CRLs */
    int verify_level;
    X509_STORE *revocation_store;             /* cert store for CRL checking */
#ifdef HAVE_OSSL_OCSP_H
    SOCKADDR_UNION ocsp_addr;
    char *ocsp_path;
    unsigned long ocsp_flags;
#endif

        /* service-specific data for ctx.c */
    char *cipher_list;
    char *cert;                                             /* cert filename */
    char *key;                               /* pem (priv key/cert) filename */
    long session_size, session_timeout;
    long ssl_options;
    SSL_METHOD *client_method, *server_method;
    SOCKADDR_UNION sessiond_addr;
#ifndef OPENSSL_NO_TLSEXT
    char *sni;
    SERVERNAME_LIST *servername_list_head, *servername_list_tail;
#endif
#ifndef OPENSSL_NO_ECDH
    int curve;
#endif
#ifdef HAVE_OSSL_ENGINE_H
    ENGINE *engine;                        /* engine to read the private key */
#endif

        /* service-specific data for client.c */
    int fd;        /* file descriptor accepting connections for this service */
    SSL_SESSION *session;                           /* recently used session */
    char *execname;                           /* program name for local mode */
#ifdef USE_WIN32
    char *execargs;                      /* program arguments for local mode */
#else
    char **execargs;                     /* program arguments for local mode */
#endif
    SOCKADDR_UNION local_addr, source_addr;
    SOCKADDR_LIST connect_addr;
    char *username;
    NAME_LIST *connect_list;
    int timeout_busy;                       /* maximum waiting for data time */
    int timeout_close;                          /* maximum close_notify time */
    int timeout_connect;                           /* maximum connect() time */
    int timeout_idle;                        /* maximum idle connection time */
    enum {FAILOVER_RR, FAILOVER_PRIO} failover;         /* failover strategy */

        /* service-specific data for protocol.c */
    int protocol;
    char *protocol_host;
    char *protocol_username;
    char *protocol_password;
    char *protocol_authentication;

        /* service-specific data for gui.c */
#ifdef USE_WIN32
    int section_number;
    LPTSTR file;
    char *help, *chain;
#endif

        /* on/off switches */
    struct {
        unsigned int accept:1;          /* endpoint: accept */
        unsigned int client:1;
        unsigned int delayed_lookup:1;
#ifdef USE_LIBWRAP
        unsigned int libwrap:1;
#endif
        unsigned int local:1;           /* outgoing interface specified */
        unsigned int remote:1;          /* endpoint: connect */
        unsigned int retry:1;           /* loop remote+program */
        unsigned int sessiond:1;
        unsigned int program:1;         /* endpoint: exec */
#ifndef OPENSSL_NO_TLSEXT
        unsigned int sni:1;             /* endpoint: sni */
#endif
#ifndef USE_WIN32
        unsigned int pty:1;
        unsigned int transparent_src:1;
        unsigned int transparent_dst:1; /* endpoint: transparent destination */
#endif
#ifdef HAVE_OSSL_OCSP_H
        unsigned int ocsp:1;
#endif
        unsigned int reset:1;           /* reset sockets on error */
        unsigned int renegotiation:1;
    } option;
} SERVICE_OPTIONS;

extern SERVICE_OPTIONS service_options;

#ifndef OPENSSL_NO_TLSEXT
struct servername_list_struct {
    char *servername;
    SERVICE_OPTIONS *opt;
    struct servername_list_struct *next;
};
#endif

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

typedef struct {
#ifdef USE_POLL
    struct pollfd *ufds;
    unsigned int nfds;
    unsigned int allocated;
#else /* select */
    fd_set irfds, iwfds, ixfds, orfds, owfds, oxfds;
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

    /* FD definition for client.c */

typedef struct {
    int fd; /* file descriptor */
    int is_socket; /* file descriptor is a socket */
} FD;

/**************************************** prototypes for stunnel.c */

#ifndef USE_FORK
extern int max_clients;
extern volatile int num_clients;
#endif

void main_initialize(void);
int main_configure(char *, char *);
void daemon_loop(void);
void unbind_ports(void);
int bind_ports(void);
#if !defined (USE_WIN32) && !defined (__vms) && !defined(USE_OS2)
int drop_privileges(int);
#endif
void signal_post(int);
#if !defined(USE_WIN32) && !defined(USE_OS2)
void child_status(void);  /* dead libwrap or 'exec' process detected */
#endif
void stunnel_info(int);

/**************************************** prototypes for fd.c */

#ifndef USE_FORK
void get_limits(void); /* setup global max_clients and max_fds */
#endif
int s_socket(int, int, int, int, char *);
int s_pipe(int [2], int, char *);
int s_socketpair(int, int, int, int [2], int, char *);
int s_accept(int, struct sockaddr *, socklen_t *, int, char *);
void set_nonblock(int, unsigned long);

/**************************************** prototypes for log.c */

#if !defined(USE_WIN32) && !defined(__vms)
void syslog_open(void);
void syslog_close(void);
#endif
int log_open(void);
void log_close(void);
void log_flush(LOG_MODE);
void s_log(int, const char *, ...)
#ifdef __GNUC__
    __attribute__((format(printf, 2, 3)));
#else
    ;
#endif
void fatal_debug(char *, char *, int);
#define fatal(a) fatal_debug((a), __FILE__, __LINE__)
void ioerror(const char *);
void sockerror(const char *);
void log_error(int, int, const char *);
char *s_strerror(int);

/**************************************** prototypes for pty.c */

int pty_allocate(int *, int *, char *);

/**************************************** prototypes for ssl.c */

extern int cli_index, opt_index;

int ssl_init(void);
int ssl_configure(GLOBAL_OPTIONS *);

/**************************************** prototypes for options.c */

int parse_commandline(char *, char *);
int parse_conf(char *, CONF_TYPE);
void apply_conf(void);

/**************************************** prototypes for ctx.c */

typedef struct {
    SERVICE_OPTIONS *section;
    char pass[PEM_BUFSIZE];
} UI_DATA;

int context_init(SERVICE_OPTIONS *);
void sslerror(char *);

/**************************************** prototypes for verify.c */

int verify_init(SERVICE_OPTIONS *);

/**************************************** prototypes for network.c */

s_poll_set *s_poll_alloc(void);
void s_poll_free(s_poll_set *);
void s_poll_init(s_poll_set *);
void s_poll_add(s_poll_set *, int, int, int);
int s_poll_canread(s_poll_set *, int);
int s_poll_canwrite(s_poll_set *, int);
int s_poll_hup(s_poll_set *, int);
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

int set_socket_options(int, int);
int make_sockets(int [2]);

/**************************************** prototypes for client.c */

typedef enum {
    RENEG_INIT, /* initial state */
    RENEG_ESTABLISHED, /* initial handshake completed */
    RENEG_DETECTED /* renegotiation detected */
} RENEG_STATE;

typedef struct {
    jmp_buf err; /* exception handler needs to be 16-byte aligned on Itanium */
    SSL *ssl; /* SSL connnection */
    SERVICE_OPTIONS *opt;

    SOCKADDR_UNION peer_addr; /* peer address */
    socklen_t peer_addr_len;
    SOCKADDR_UNION *bind_addr; /* address to bind() the socket */
    SOCKADDR_LIST connect_addr; /* for dynamically assigned addresses */
    FD local_rfd, local_wfd; /* read and write local descriptors */
    FD remote_fd; /* remote file descriptor */
        /* IP for explicit local bind or transparent proxy */
    unsigned long pid; /* PID of the local process */
    int fd; /* temporary file descriptor */
    RENEG_STATE reneg_state; /* used to track renegotiation attempts */

    /* data for transfer() function */
    char sock_buff[BUFFSIZE]; /* socket read buffer */
    char ssl_buff[BUFFSIZE]; /* SSL read buffer */
    int sock_ptr, ssl_ptr; /* index of first unused byte in buffer */
    FD *sock_rfd, *sock_wfd; /* read and write socket descriptors */
    FD *ssl_rfd, *ssl_wfd; /* read and write SSL descriptors */
    int sock_bytes, ssl_bytes; /* bytes written to socket and SSL */
    s_poll_set *fds; /* file descriptors */
} CLI;

CLI *alloc_client_session(SERVICE_OPTIONS *, int, int);
void *client_thread(void *);
void client_main(CLI *);

/**************************************** prototypes for network.c */

int connect_blocking(CLI *, SOCKADDR_UNION *, socklen_t);
void write_blocking(CLI *, int fd, void *, int);
void read_blocking(CLI *, int fd, void *, int);
void fd_putline(CLI *, int, const char *);
char *fd_getline(CLI *, int);
/* descriptor versions of fprintf/fscanf */
void fd_printf(CLI *, int, const char *, ...)
#ifdef __GNUC__
    __attribute__((format(printf, 3, 4)));
#else
    ;
#endif

/**************************************** prototype for protocol.c */

typedef enum {
    PROTOCOL_NONE,
    PROTOCOL_PRE_CONNECT,
    PROTOCOL_PRE_SSL,
    PROTOCOL_POST_SSL
} PROTOCOL_PHASE;

int find_protocol_id(const char *);
void protocol(CLI *, const PROTOCOL_PHASE);

/**************************************** prototypes for resolver.c */

void resolver_init();
int name2addr(SOCKADDR_UNION *, char *, char *);
int hostport2addr(SOCKADDR_UNION *, char *, char *);
int namelist2addrlist(SOCKADDR_LIST *, NAME_LIST *, char *);
char *s_ntop(SOCKADDR_UNION *, socklen_t);
socklen_t addr_len(const SOCKADDR_UNION *);
const char *s_gai_strerror(int);

#ifndef HAVE_GETNAMEINFO

#ifndef NI_NUMERICHOST
#define NI_NUMERICHOST  2
#endif
#ifndef NI_NUMERICSERV
#define NI_NUMERICSERV  8
#endif

#ifdef USE_WIN32

/* rename some locally shadowed declarations */
#define getnameinfo     local_getnameinfo

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

int getnameinfo(const struct sockaddr *, int, char *, int, char *, int, int);

#endif /* !defined HAVE_GETNAMEINFO */

/**************************************** prototypes for sthreads.c */

typedef enum {
    CRIT_CLIENTS, CRIT_SESSION, CRIT_SSL,   /* client.c */
    CRIT_INET,                              /* resolver.c */
#ifndef USE_WIN32
    CRIT_LIBWRAP,                           /* libwrap.c */
#endif
    CRIT_LOG,                               /* log.c */
    CRIT_SECTIONS                           /* number of critical sections */
} SECTION_CODE;

void enter_critical_section(SECTION_CODE);
void leave_critical_section(SECTION_CODE);
int sthreads_init(void);
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

#ifdef USE_WIN32
void message_box(const LPSTR, const UINT);
void win_new_chain(int);
void win_new_log(char *);
void win_new_config(void);
int passwd_cb(char *, int, int, void *);
#ifdef HAVE_OSSL_ENGINE_H
int pin_cb(UI *, UI_STRING *);
#endif
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

int libwrap_init();
void libwrap_auth(CLI *, char *);

/**************************************** prototypes for str.c */

void str_init();
void str_canary_init();
void str_cleanup();
void str_stats();
void *str_alloc_debug(size_t, char *, int);
#define str_alloc(a) str_alloc_debug((a), __FILE__, __LINE__)
void *str_realloc_debug(void *, size_t, char *, int);
#define str_realloc(a, b) str_realloc_debug((a), (b), __FILE__, __LINE__)
void str_detach_debug(void *, char *, int);
#define str_detach(a) str_detach_debug((a), __FILE__, __LINE__)
void str_free_debug(void *, char *, int);
#define str_free(a) str_free_debug((a), __FILE__, __LINE__), (a)=NULL
char *str_dup(const char *);
char *str_vprintf(const char *, va_list);
char *str_printf(const char *, ...)
#ifdef __GNUC__
    __attribute__((format(printf, 1, 2)));
#else
    ;
#endif

#endif /* defined PROTOTYPES_H */

/* end of prototypes.h */
