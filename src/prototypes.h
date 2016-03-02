/*
 *   stunnel       TLS offloading and load-balancing proxy
 *   Copyright (C) 1998-2016 Michal Trojnara <Michal.Trojnara@mirt.net>
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

/**************************************** forward declarations */

typedef struct tls_data_struct TLS_DATA;

/**************************************** data structures */

/* non-zero constants for the "redirect" option */
#define REDIRECT_ON         1
#define REDIRECT_OFF        2

#if defined (USE_WIN32)
#define ICON_IMAGE HICON
#elif defined(__APPLE__)
#define ICON_IMAGE void *
#endif

typedef enum {
    ICON_ERROR,
    ICON_IDLE,
    ICON_ACTIVE,
    ICON_NONE /* it has to be the last one */
} ICON_TYPE;

typedef enum {
    LOG_MODE_NONE,
    LOG_MODE_ERROR,
    LOG_MODE_INFO,
    LOG_MODE_CONFIGURED
} LOG_MODE;

typedef enum {
    LOG_ID_SEQUENTIAL,
    LOG_ID_UNIQUE,
    LOG_ID_THREAD
} LOG_ID;

typedef enum {
    FILE_MODE_READ,
    FILE_MODE_APPEND,
    FILE_MODE_OVERWRITE
} FILE_MODE;

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
    unsigned *rr_ptr, rr_val;             /* current address for round-robin */
    unsigned num;                             /* how many addresses are used */
    int passive;                                         /* listening socket */
    NAME_LIST *names;                          /* a list of unresolved names */
} SOCKADDR_LIST;

#ifndef OPENSSL_NO_COMP
typedef enum {
    COMP_NONE, COMP_DEFLATE, COMP_ZLIB
} COMP_TYPE;
#endif /* !defined(OPENSSL_NO_COMP) */

typedef struct {
        /* some data for SSL initialization in ssl.c */
#ifndef OPENSSL_NO_COMP
    COMP_TYPE compression;                               /* compression type */
#endif /* !defined(OPENSSL_NO_COMP) */
    char *egd_sock;                       /* entropy gathering daemon socket */
    char *rand_file;                                /* file with random data */
    long random_bytes;                      /* how many random bytes to read */

        /* some global data for stunnel.c */
#ifndef USE_WIN32
#ifdef HAVE_CHROOT
    char *chroot_dir;
#endif
    unsigned long dpid;
    char *pidfile;
#endif

        /* logging-support data for log.c */
#ifndef USE_WIN32
    int log_facility;                           /* debug facility for syslog */
#endif
    char *output_file;
    FILE_MODE log_file_mode;

        /* user interface configuraion */
#ifdef ICON_IMAGE
    ICON_IMAGE icon[ICON_NONE];                  /* user-specified GUI icons */
#endif

        /* on/off switches */
    struct {
        unsigned rand_write:1;                        /* overwrite rand_file */
#ifdef USE_WIN32
        unsigned taskbar:1;                       /* enable the taskbar icon */
#else /* !USE_WIN32 */
        unsigned foreground:1;
        unsigned log_stderr:1;
        unsigned log_syslog:1;
#endif
#ifdef USE_FIPS
        unsigned fips:1;                           /* enable FIPS 140-2 mode */
#endif
    } option;
} GLOBAL_OPTIONS;

extern GLOBAL_OPTIONS global_options;

#ifndef OPENSSL_NO_TLSEXT
typedef struct servername_list_struct SERVERNAME_LIST;/* forward declaration */
#endif /* !defined(OPENSSL_NO_TLSEXT) */

#ifndef OPENSSL_NO_PSK
typedef struct psk_keys_struct {
    char *identity;
    unsigned char *key_val;
    size_t key_len;
    struct psk_keys_struct *next;
} PSK_KEYS;
typedef struct psk_table_struct {
    PSK_KEYS **val;
    size_t num;
} PSK_TABLE;
#endif /* !defined(OPENSSL_NO_PSK) */

typedef struct service_options_struct {
    struct service_options_struct *next;   /* next node in the services list */
    SSL_CTX *ctx;                                            /*  SSL context */
    char *servname;        /* service name for logging & permission checking */

        /* service-specific data for stunnel.c */
#ifndef USE_WIN32
    uid_t uid;
    gid_t gid;
#endif

        /* service-specific data for log.c */
    int log_level;                                /* debug level for logging */
    LOG_ID log_id;                                /* logging session id type */

        /* service-specific data for sthreads.c */
#ifndef USE_FORK
    size_t stack_size;                         /* stack size for this thread */
#endif

        /* service-specific data for verify.c */
    char *ca_dir;                              /* directory for hashed certs */
    char *ca_file;                       /* file containing bunches of certs */
    char *crl_dir;                              /* directory for hashed CRLs */
    char *crl_file;                       /* file containing bunches of CRLs */
    int verify_level;
#ifndef OPENSSL_NO_OCSP
    char *ocsp_url;
    unsigned long ocsp_flags;
#endif /* !defined(OPENSSL_NO_OCSP) */
#if OPENSSL_VERSION_NUMBER>=0x10002000L
    NAME_LIST *check_host, *check_email, *check_ip;   /* cert subject checks */
    NAME_LIST *config;                               /* OpenSSL CONF options */
#endif /* OPENSSL_VERSION_NUMBER>=0x10002000L */

        /* service-specific data for ctx.c */
    char *cipher_list;
    char *cert;                                             /* cert filename */
    char *key;                               /* pem (priv key/cert) filename */
    long session_size, session_timeout;
    long unsigned ssl_options_set;
#if OPENSSL_VERSION_NUMBER>=0x009080dfL
    long unsigned ssl_options_clear;
#endif /* OpenSSL 0.9.8m or later */
    SSL_METHOD *client_method, *server_method;
    SOCKADDR_UNION sessiond_addr;
#ifndef OPENSSL_NO_TLSEXT
    char *sni;
    SERVERNAME_LIST *servername_list_head, *servername_list_tail;
#endif /* !defined(OPENSSL_NO_TLSEXT) */
#ifndef OPENSSL_NO_PSK
    char *psk_identity;
    PSK_KEYS *psk_keys, *psk_selected;
    PSK_TABLE psk_sorted;
#endif /* !defined(OPENSSL_NO_PSK) */
#ifndef OPENSSL_NO_ECDH
    int curve;
#endif /* !defined(OPENSSL_NO_ECDH) */
#ifndef OPENSSL_NO_ENGINE
    ENGINE *engine;                        /* engine to read the private key */
#endif /* !defined(OPENSSL_NO_ENGINE) */

        /* service-specific data for client.c */
    SOCKET fd;     /* file descriptor accepting connections for this service */
    SSL_SESSION *session;                           /* recently used session */
    char *exec_name;                          /* program name for local mode */
#ifdef USE_WIN32
    char *exec_args;                     /* program arguments for local mode */
#else
    char **exec_args;                    /* program arguments for local mode */
#endif
    SOCKADDR_UNION local_addr, source_addr;
    SOCKADDR_LIST connect_addr, redirect_addr;
    int timeout_busy;                       /* maximum waiting for data time */
    int timeout_close;                          /* maximum close_notify time */
    int timeout_connect;                           /* maximum connect() time */
    int timeout_idle;                        /* maximum idle connection time */
    enum {FAILOVER_RR, FAILOVER_PRIO} failover;         /* failover strategy */
    char *username;

        /* service-specific data for protocol.c */
    char * protocol;
    char *protocol_host;
    char *protocol_domain;
    char *protocol_username;
    char *protocol_password;
    char *protocol_authentication;

        /* service-specific data for ui_*.c */
#ifdef USE_WIN32
    LPTSTR file, help;
#endif
    unsigned section_number;
    char *chain;

        /* on/off switches */
    struct {
        unsigned accept:1;              /* endpoint: accept */
        unsigned client:1;
        unsigned delayed_lookup:1;
#ifdef USE_LIBWRAP
        unsigned libwrap:1;
#endif
        unsigned local:1;               /* outgoing interface specified */
        unsigned retry:1;               /* loop remote+program */
        unsigned sessiond:1;
#ifndef OPENSSL_NO_TLSEXT
        unsigned sni:1;                 /* endpoint: sni */
#endif /* !defined(OPENSSL_NO_TLSEXT) */
#ifndef USE_WIN32
        unsigned pty:1;
        unsigned transparent_src:1;
#endif
        unsigned transparent_dst:1;     /* endpoint: transparent destination */
        unsigned protocol_endpoint:1;   /* dynamic target from the protocol */
        unsigned reset:1;               /* reset sockets on error */
        unsigned renegotiation:1;
        unsigned connect_before_ssl:1;
#ifndef OPENSSL_NO_OCSP
        unsigned aia:1;                 /* Authority Information Access */
        unsigned nonce:1;               /* send and verify OCSP nonce */
#endif /* !defined(OPENSSL_NO_OCSP) */
#ifndef OPENSSL_NO_DH
        unsigned dh_needed:1;
#endif /* OPENSSL_NO_DH */
    } option;
} SERVICE_OPTIONS;

extern SERVICE_OPTIONS service_options;

#ifndef OPENSSL_NO_TLSEXT
struct servername_list_struct {
    char *servername;
    SERVICE_OPTIONS *opt;
    struct servername_list_struct *next;
};
#endif /* !defined(OPENSSL_NO_TLSEXT) */

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
    unsigned nfds;
    unsigned allocated;
#else /* select */
    fd_set *irfds, *iwfds, *ixfds, *orfds, *owfds, *oxfds;
    SOCKET max;
#ifdef USE_WIN32
    unsigned allocated;
#endif
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

    /* definitions for client.c */

typedef struct {
    SOCKET fd; /* file descriptor */
    int is_socket; /* file descriptor is a socket */
} FD;

typedef enum {
    RENEG_INIT, /* initial state */
    RENEG_ESTABLISHED, /* initial handshake completed */
    RENEG_DETECTED /* renegotiation detected */
} RENEG_STATE;

typedef struct {
    jmp_buf err; /* exception handler needs to be 16-byte aligned on Itanium */
    SSL *ssl; /* SSL connnection */
    SERVICE_OPTIONS *opt;
    TLS_DATA *tls;

    SOCKADDR_UNION peer_addr; /* peer address */
    socklen_t peer_addr_len;
    SOCKADDR_UNION *bind_addr; /* address to bind() the socket */
    SOCKADDR_LIST connect_addr; /* either copied or resolved dynamically */
    FD local_rfd, local_wfd; /* read and write local descriptors */
    FD remote_fd; /* remote file descriptor */
        /* IP for explicit local bind or transparent proxy */
    unsigned long pid; /* PID of the local process */
    SOCKET fd; /* temporary file descriptor */
    RENEG_STATE reneg_state; /* used to track renegotiation attempts */
    unsigned long long seq; /* sequential thread number for logging */

    /* data for transfer() function */
    char sock_buff[BUFFSIZE]; /* socket read buffer */
    char ssl_buff[BUFFSIZE]; /* SSL read buffer */
    size_t sock_ptr, ssl_ptr; /* index of the first unused byte */
    FD *sock_rfd, *sock_wfd; /* read and write socket descriptors */
    FD *ssl_rfd, *ssl_wfd; /* read and write SSL descriptors */
    uint64_t sock_bytes, ssl_bytes; /* bytes written to socket and SSL */
    s_poll_set *fds; /* file descriptors */
    uintptr_t redirect; /* redirect to another destination after failed auth */
} CLI;

/**************************************** prototypes for stunnel.c */

#ifndef USE_FORK
extern long max_clients;
extern volatile long num_clients;
#endif

void main_init(void);
int main_configure(char *, char *);
void main_cleanup(void);
int drop_privileges(int);
void daemon_loop(void);
void unbind_ports(void);
int bind_ports(void);
void signal_post(int);
#if !defined(USE_WIN32) && !defined(USE_OS2)
void child_status(void);  /* dead libwrap or 'exec' process detected */
#endif
void stunnel_info(int);

/**************************************** prototypes for options.c */

extern char configuration_file[PATH_MAX];

int options_cmdline(char *, char *);
int options_parse(CONF_TYPE);
void options_defaults(void);
void options_apply(void);

/**************************************** prototypes for fd.c */

#ifndef USE_FORK
void get_limits(void); /* setup global max_clients and max_fds */
#endif
SOCKET s_socket(int, int, int, int, char *);
int s_pipe(int[2], int, char *);
int s_socketpair(int, int, int, SOCKET[2], int, char *);
SOCKET s_accept(SOCKET, struct sockaddr *, socklen_t *, int, char *);
void set_nonblock(SOCKET, unsigned long);

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
char *log_id(CLI *);
void fatal_debug(char *, const char *, int);
#define fatal(a) fatal_debug((a), __FILE__, __LINE__)
void ioerror(const char *);
void sockerror(const char *);
void log_error(int, int, const char *);
char *s_strerror(int);

/**************************************** prototypes for pty.c */

int pty_allocate(int *, int *, char *);

/**************************************** prototypes for dhparam.c */

DH *get_dh2048(void);

/**************************************** prototypes for cron.c */

int cron_init(void);

/**************************************** prototypes for ssl.c */

extern int index_cli, index_opt, index_redirect, index_addr;

int ssl_init(void);
int ssl_configure(GLOBAL_OPTIONS *);

/**************************************** prototypes for ctx.c */

typedef struct {
    SERVICE_OPTIONS *section;
    char pass[PEM_BUFSIZE];
} UI_DATA;

#ifndef OPENSSL_NO_DH
extern DH *dh_params;
extern int dh_needed;
#endif /* OPENSSL_NO_DH */

int context_init(SERVICE_OPTIONS *);
#ifndef OPENSSL_NO_PSK
void psk_sort(PSK_TABLE *, PSK_KEYS *);
PSK_KEYS *psk_find(const PSK_TABLE *, const char *);
#endif /* !defined(OPENSSL_NO_PSK) */
void sslerror(char *);

/**************************************** prototypes for verify.c */

int verify_init(SERVICE_OPTIONS *);
void print_client_CA_list(const STACK_OF(X509_NAME) *);
char *X509_NAME2text(X509_NAME *);

/**************************************** prototypes for network.c */

s_poll_set *s_poll_alloc(void);
void s_poll_free(s_poll_set *);
void s_poll_init(s_poll_set *);
void s_poll_add(s_poll_set *, SOCKET, int, int);
void s_poll_remove(s_poll_set *, SOCKET);
int s_poll_canread(s_poll_set *, SOCKET);
int s_poll_canwrite(s_poll_set *, SOCKET);
int s_poll_hup(s_poll_set *, SOCKET);
int s_poll_rdhup(s_poll_set *, SOCKET);
int s_poll_err(s_poll_set *, SOCKET);
int s_poll_wait(s_poll_set *, int, int);
void s_poll_dump(s_poll_set *, int);

#ifdef USE_WIN32
#define SIGNAL_RELOAD_CONFIG    1
#define SIGNAL_REOPEN_LOG       2
#define SIGNAL_TERMINATE        3
#else
#define SIGNAL_RELOAD_CONFIG    SIGHUP
#define SIGNAL_REOPEN_LOG       SIGUSR1
#define SIGNAL_TERMINATE        SIGTERM
#endif

int set_socket_options(SOCKET, int);
int make_sockets(SOCKET[2]);
int original_dst(const SOCKET, SOCKADDR_UNION *);

/**************************************** prototypes for client.c */

CLI *alloc_client_session(SERVICE_OPTIONS *, SOCKET, SOCKET);
void *client_thread(void *);
void client_main(CLI *);

/**************************************** prototypes for network.c */

int get_socket_error(const SOCKET);
int s_connect(CLI *, SOCKADDR_UNION *, socklen_t);
void s_write(CLI *, SOCKET fd, const void *, size_t);
void s_read(CLI *, SOCKET fd, void *, size_t);
void fd_putline(CLI *, SOCKET, const char *);
char *fd_getline(CLI *, SOCKET);
/* descriptor versions of fprintf/fscanf */
void fd_printf(CLI *, SOCKET, const char *, ...)
#ifdef __GNUC__
    __attribute__((format(printf, 3, 4)));
#else
    ;
#endif
void s_ssl_write(CLI *, const void *, int);
void s_ssl_read(CLI *, void *, int);
char *ssl_getstring(CLI *c);
char *ssl_getline(CLI *c);
void ssl_putline(CLI *c, const char *);

/**************************************** prototype for protocol.c */

typedef enum {
    PROTOCOL_CHECK,
    PROTOCOL_EARLY,
    PROTOCOL_MIDDLE,
    PROTOCOL_LATE
} PHASE;

char *protocol(CLI *, SERVICE_OPTIONS *opt, const PHASE);

/**************************************** prototypes for resolver.c */

void resolver_init();

unsigned name2addr(SOCKADDR_UNION *, char *, int);
unsigned hostport2addr(SOCKADDR_UNION *, char *, char *, int);

unsigned name2addrlist(SOCKADDR_LIST *, char *);
unsigned hostport2addrlist(SOCKADDR_LIST *, char *, char *);

void addrlist_clear(SOCKADDR_LIST *, int);
unsigned addrlist_dup(SOCKADDR_LIST *, const SOCKADDR_LIST *);
unsigned addrlist_resolve(SOCKADDR_LIST *);

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

int getnameinfo(const struct sockaddr *, socklen_t,
    char *, size_t, char *, size_t, int);

#endif /* !defined HAVE_GETNAMEINFO */

/**************************************** prototypes for sthreads.c */

typedef enum {
    LOCK_SESSION, LOCK_ADDR,
    LOCK_CLIENTS, LOCK_SSL,                 /* client.c */
    LOCK_INET,                              /* resolver.c */
#ifndef USE_WIN32
    LOCK_LIBWRAP,                           /* libwrap.c */
#endif
    LOCK_LOG, LOCK_LEAK,                    /* log.c */
#ifndef OPENSSL_NO_DH
    LOCK_DH,                                /* ctx.c */
#endif /* OPENSSL_NO_DH */
    STUNNEL_LOCKS                           /* number of locks */
} LOCK_TYPE;
extern int stunnel_locks[STUNNEL_LOCKS];

int sthreads_init(void);
unsigned long stunnel_process_id(void);
unsigned long stunnel_thread_id(void);
int create_client(SOCKET, SOCKET, CLI *, void *(*)(void *));
#ifdef USE_UCONTEXT
typedef struct CONTEXT_STRUCTURE {
    char *stack; /* CPU stack for this thread */
    unsigned long id;
    ucontext_t context;
    s_poll_set *fds;
    int ready; /* number of ready file descriptors */
    time_t finish; /* when to finish poll() for this context */
    struct CONTEXT_STRUCTURE *next; /* next context on a list */
    void *tls; /* thread local storage for tls.c */
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

/**************************************** prototypes for file.c */

#ifndef USE_WIN32
DISK_FILE *file_fdopen(int);
#endif
DISK_FILE *file_open(char *, FILE_MODE mode);
void file_close(DISK_FILE *);
ssize_t file_getline(DISK_FILE *, char *, int);
ssize_t file_putline(DISK_FILE *, char *);
int file_permissions(const char *);

#ifdef USE_WIN32
LPTSTR str2tstr(LPCSTR);
LPSTR tstr2str(LPCTSTR);
#endif

/**************************************** prototypes for libwrap.c */

int libwrap_init();
void libwrap_auth(CLI *, char *);

/**************************************** prototypes for tls.c */

extern volatile int tls_initialized;

void tls_init();
TLS_DATA *tls_alloc(CLI *, TLS_DATA *, char *);
void tls_cleanup();
void tls_set(TLS_DATA *);
TLS_DATA *tls_get();

/**************************************** prototypes for str.c */

extern TLS_DATA *ui_tls;
typedef struct alloc_list_struct ALLOC_LIST;

struct tls_data_struct {
    ALLOC_LIST *alloc_head;
    size_t alloc_bytes, alloc_blocks;
    CLI *c;
    SERVICE_OPTIONS *opt;
    char *id;
};

void str_init(TLS_DATA *);
void str_cleanup(TLS_DATA *);
char *str_dup_debug(const char *, const char *, int);
#define str_dup(a) str_dup_debug((a), __FILE__, __LINE__)
char *str_vprintf(const char *, va_list);
char *str_printf(const char *, ...)
#ifdef __GNUC__
    __attribute__((format(printf, 1, 2)));
#else
    ;
#endif
#ifdef USE_WIN32
LPTSTR str_tprintf(LPCTSTR, ...);
#endif

void str_canary_init();
void str_stats();
void *str_alloc_debug(size_t, const char *, int);
#define str_alloc(a) str_alloc_debug((a), __FILE__, __LINE__)
void *str_alloc_detached_debug(size_t, const char *, int);
#define str_alloc_detached(a) str_alloc_detached_debug((a), __FILE__, __LINE__)
void *str_realloc_debug(void *, size_t, const char *, int);
#define str_realloc(a, b) str_realloc_debug((a), (b), __FILE__, __LINE__)
void str_detach_debug(void *, const char *, int);
#define str_detach(a) str_detach_debug((a), __FILE__, __LINE__)
void str_free_debug(void *, const char *, int);
#define str_free(a) str_free_debug((a), __FILE__, __LINE__), (a)=NULL
#define str_free_expression(a) str_free_debug((a), __FILE__, __LINE__)

int safe_memcmp(const void *, const void *, size_t);

/**************************************** prototypes for ui_*.c */

void ui_config_reloaded(void);
void ui_new_chain(const unsigned);
void ui_clients(const long);

void ui_new_log(const char *);
#ifdef USE_WIN32
void message_box(LPCTSTR, const UINT);
#endif /* USE_WIN32 */

int passwd_cb(char *, int, int, void *);
#ifndef OPENSSL_NO_ENGINE
int pin_cb(UI *, UI_STRING *);
#endif /* !defined(OPENSSL_NO_ENGINE) */

#ifdef ICON_IMAGE
ICON_IMAGE load_icon_default(ICON_TYPE);
ICON_IMAGE load_icon_file(const char *);
#endif

#endif /* defined PROTOTYPES_H */

/* end of prototypes.h */
