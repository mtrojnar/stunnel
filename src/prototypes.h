/*
 *   stunnel       TLS offloading and load-balancing proxy
 *   Copyright (C) 1998-2021 Michal Trojnara <Michal.Trojnara@stunnel.org>
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

#if defined(USE_PTHREAD) || defined(USE_WIN32)
#define USE_OS_THREADS
#endif

/**************************************** forward declarations */

typedef struct tls_data_struct TLS_DATA;
typedef struct sock_opt_struct SOCK_OPT;

/**************************************** data structures */

#ifdef USE_PTHREAD
    typedef pthread_t THREAD_ID;
#endif
#ifdef USE_WIN32
    typedef HANDLE THREAD_ID;
#endif

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
    LOG_MODE_BUFFER,
    LOG_MODE_ERROR,
    LOG_MODE_INFO,
    LOG_MODE_CONFIGURED
} LOG_MODE;

typedef enum {
    LOG_ID_SEQUENTIAL,
    LOG_ID_UNIQUE,
    LOG_ID_THREAD,
    LOG_ID_PROCESS
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
    struct sockaddr_list *parent;   /* used by copies to locate their parent */
    SOCKADDR_UNION *addr;                     /* array of resolved addresses */
    unsigned start;              /* initial address for round-robin failover */
    unsigned num;                             /* how many addresses are used */
    int passive;                                         /* listening socket */
    NAME_LIST *names;                          /* a list of unresolved names */
} SOCKADDR_LIST;

#ifndef OPENSSL_NO_COMP
typedef enum {
    COMP_NONE,                           /* empty compression algorithms set */
    COMP_DEFLATE,            /* default OpenSSL's compression algorithms set */
    COMP_ZLIB,          /* additional historic ZLIB compression algorithm id */
    STUNNEL_COMPS                   /* number of compression algorithms sets */
} COMP_TYPE;
#endif /* !defined(OPENSSL_NO_COMP) */

typedef struct {
        /* some data for TLS initialization in ssl.c */
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
    char *pidfile;
#endif

        /* logging-support data for log.c */
#ifndef USE_WIN32
    int log_facility;                           /* debug facility for syslog */
#endif
    char *output_file;
    FILE_MODE log_file_mode;

        /* user interface configuration */
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
    unsigned key_len;
    struct psk_keys_struct *next;
} PSK_KEYS;
typedef struct psk_table_struct {
    PSK_KEYS **val;
    size_t num;
} PSK_TABLE;
#endif /* !defined(OPENSSL_NO_PSK) */

#if OPENSSL_VERSION_NUMBER>=0x10000000L
typedef struct ticket_key_struct {
    unsigned char *key_val;
    int key_len;
} TICKET_KEY;
#endif /* OpenSSL 1.0.0 or later */

typedef struct service_options_struct {
    struct service_options_struct *next;   /* next node in the services list */
    SSL_CTX *ctx;                                            /*  TLS context */
    char *servname;        /* service name for logging & permission checking */
    int ref;                   /* reference counter for delayed deallocation */

        /* service-specific data for stunnel.c */
#ifndef USE_WIN32
    uid_t uid;
    gid_t gid;
#endif
    int bound_ports;                /* number of ports bound to this service */

        /* service-specific data for log.c */
    int log_level;                                /* debug level for logging */
    LOG_ID log_id;                                /* logging session id type */

        /* service-specific data for sthreads.c */
#ifndef USE_FORK
    size_t stack_size;                         /* stack size for this thread */
#endif

        /* some global data for network.c */
    SOCK_OPT *sock_opts;

        /* service-specific data for verify.c */
    char *ca_dir;                              /* directory for hashed certs */
    char *ca_file;                       /* file containing bunches of certs */
    char *crl_dir;                              /* directory for hashed CRLs */
    char *crl_file;                       /* file containing bunches of CRLs */
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
#ifndef OPENSSL_NO_TLS1_3
    char *ciphersuites;
#endif /* TLS 1.3 */
    char *cert;                                             /* cert filename */
    char *key;                               /* pem (priv key/cert) filename */
    long session_size, session_timeout;
#if OPENSSL_VERSION_NUMBER>=0x10100000L
    int security_level;
#endif /* OpenSSL 1.1.0 or later */
    long unsigned ssl_options_set;
#if OPENSSL_VERSION_NUMBER>=0x009080dfL
    long unsigned ssl_options_clear;
#endif /* OpenSSL 0.9.8m or later */
#if OPENSSL_VERSION_NUMBER>=0x10100000L
    int min_proto_version, max_proto_version;
#else /* OPENSSL_VERSION_NUMBER<0x10100000L */
    SSL_METHOD *client_method, *server_method;
#endif /* OPENSSL_VERSION_NUMBER<0x10100000L */
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
    char *curves;
#endif /* !defined(OPENSSL_NO_ECDH) */
#ifndef OPENSSL_NO_ENGINE
    ENGINE *engine;                        /* engine to read the private key */
#endif /* !defined(OPENSSL_NO_ENGINE) */
#if OPENSSL_VERSION_NUMBER>=0x10000000L
    TICKET_KEY *ticket_key;              /* key for handling session tickets */
    TICKET_KEY *ticket_mac;            /* key for protecting session tickets */
#endif /* OpenSSL 1.0.0 or later */

        /* service-specific data for client.c */
    char *exec_name;                          /* program name for local mode */
#ifdef USE_WIN32
    char *exec_args;                     /* program arguments for local mode */
#else
    char **exec_args;                    /* program arguments for local mode */
#endif
    SOCKADDR_UNION source_addr;
    SOCKADDR_LIST local_addr, connect_addr, redirect_addr;
    SOCKET *local_fd;                 /* array of accepting file descriptors */
    SSL_SESSION **connect_session;   /* per-destination client session cache */
    SSL_SESSION *session;    /* previous client session for delayed resolver */
    int timeout_busy;                       /* maximum waiting for data time */
    int timeout_close;                          /* maximum close_notify time */
    int timeout_connect;                           /* maximum connect() time */
    int timeout_idle;                        /* maximum idle connection time */
    enum {FAILOVER_RR, FAILOVER_PRIO} failover;         /* failover strategy */
    unsigned rr;   /* per-service sequential number for round-robin failover */
    char *username;

        /* service-specific data for protocol.c */
    char *protocol;
    NAME_LIST *protocol_header;
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
        unsigned request_cert:1;        /* request a peer certificate */
        unsigned require_cert:1;        /* require a client certificate */
        unsigned verify_chain:1;        /* verify certificate chain */
        unsigned verify_peer:1;         /* verify peer certificate */
        unsigned accept:1;              /* endpoint: accept */
        unsigned client:1;
        unsigned delayed_lookup:1;
#ifdef USE_LIBWRAP
        unsigned libwrap:1;
#endif
        unsigned local:1;               /* outgoing interface specified */
        unsigned retry:1;               /* loop remote+program */
        unsigned sessiond:1;
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
        unsigned dh_temp_params:1;
#endif /* OPENSSL_NO_DH */
#ifndef USE_WIN32
        unsigned log_stderr:1;          /* a copy of the global switch */
#endif /* USE_WIN32 */
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

struct sock_opt_struct {
    char *opt_str;
    int  opt_level;
    int  opt_name;
    VAL_TYPE opt_type;
    OPT_UNION *opt_val[3];
};

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
    int main_thread;
} s_poll_set;

typedef struct disk_file {
#ifdef USE_WIN32
    HANDLE fh;
#else
    int fd;
#endif
    /* the interface is prepared to easily implement buffering if needed */
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

typedef struct client_data_struct {
    jmp_buf *exception_pointer;

    SSL *ssl;                                              /* TLS connection */
    SERVICE_OPTIONS *opt;
    TLS_DATA *tls;

#ifdef USE_OS_THREADS
    THREAD_ID thread_id;
#endif
#ifndef USE_FORK
    struct client_data_struct *thread_prev, *thread_next;
#endif

    SOCKADDR_UNION peer_addr;                                /* peer address */
    socklen_t peer_addr_len;
    char *accepted_address;    /* textual representation of the peer address */
    SOCKADDR_UNION *bind_addr;               /* address to bind() the socket */
    SOCKADDR_LIST connect_addr;     /* either copied or resolved dynamically */
    unsigned idx;              /* actually connected address in connect_addr */
    FD local_rfd, local_wfd;             /* read and write local descriptors */
    FD remote_fd;                                  /* remote file descriptor */
    unsigned long pid;                           /* PID of the local process */
    SOCKET fd;                                  /* temporary file descriptor */
    RENEG_STATE reneg_state;         /* used to track renegotiation attempts */
    unsigned long long seq;          /* sequential thread number for logging */
    unsigned rr;    /* per-client sequential number for round-robin failover */

    /* data for transfer() function */
    char sock_buff[BUFFSIZE];                          /* socket read buffer */
    char ssl_buff[BUFFSIZE];                              /* TLS read buffer */
    size_t sock_ptr, ssl_ptr;              /* index of the first unused byte */
    FD *sock_rfd, *sock_wfd;            /* read and write socket descriptors */
    FD *ssl_rfd, *ssl_wfd;                 /* read and write TLS descriptors */
    uint64_t sock_bytes, ssl_bytes;       /* bytes written to socket and TLS */
    s_poll_set *fds;                                     /* file descriptors */
    struct {
        unsigned psk:1;                            /* PSK identity was found */
    } flag;
} CLI;

/**************************************** prototypes for stunnel.c */

#ifndef USE_FORK
extern int max_clients;
extern int num_clients;
#endif
extern SOCKET signal_pipe[2];
extern SOCKET terminate_pipe[2];

void main_init(void);
int main_configure(char *, char *);
void main_cleanup(void);
int drop_privileges(int);
void daemon_loop(void);
void signal_post(uint8_t);
#if !defined(USE_WIN32) && !defined(USE_OS2)
void pid_status_hang(const char *);
#endif
void stunnel_info(int);

/**************************************** prototypes for options.c */

extern char *configuration_file;
extern unsigned number_of_sections;

int options_cmdline(char *, char *);
int options_parse(CONF_TYPE);
void options_defaults(void);
void options_apply(void);
void options_free(int);

void service_up_ref(SERVICE_OPTIONS *);
void service_free(SERVICE_OPTIONS *);

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

#define SINK_SYSLOG 1
#define SINK_OUTFILE 2

int log_open(int);
void log_close(int);
void log_flush(LOG_MODE);
void s_log(int, const char *, ...)
#ifdef __GNUC__
    __attribute__((format(printf, 2, 3)));
#else
    ;
#endif
char *log_id(CLI *);
void fatal_debug(char *, const char *, int) NORETURN;
#define fatal(a) fatal_debug((a), __FILE__, __LINE__)
void ioerror(const char *);
void sockerror(const char *);
void log_error(int, int, const char *);
char *s_strerror(int);
void bin2hexstring(const unsigned char *, size_t, char *, size_t);

/**************************************** prototypes for pty.c */

int pty_allocate(int *, int *, char *);

/**************************************** prototypes for dhparam.c */

DH *get_dh2048(void);

/**************************************** prototypes for cron.c */

#ifdef USE_OS_THREADS
extern THREAD_ID cron_thread_id;
#endif

int cron_init(void);

/**************************************** prototypes for ssl.c */

extern int index_ssl_cli, index_ssl_ctx_opt;
extern int index_session_authenticated, index_session_connect_address;

int fips_available();
int ssl_init(void);
int ssl_configure(GLOBAL_OPTIONS *);

/**************************************** prototypes for ctx.c */

extern SERVICE_OPTIONS *current_section;

#ifndef OPENSSL_NO_DH
extern DH *dh_params;
extern int dh_temp_params;
#endif /* OPENSSL_NO_DH */

int context_init(SERVICE_OPTIONS *);
#ifndef OPENSSL_NO_PSK
void psk_sort(PSK_TABLE *, PSK_KEYS *);
PSK_KEYS *psk_find(const PSK_TABLE *, const char *);
#endif /* !defined(OPENSSL_NO_PSK) */
#ifndef OPENSSL_NO_ENGINE
UI_METHOD *ui_stunnel(void);
#endif /* !defined(OPENSSL_NO_ENGINE) */
void print_session_id(SSL_SESSION *);
void sslerror(char *);

/**************************************** prototypes for verify.c */

int verify_init(SERVICE_OPTIONS *);
void print_client_CA_list(const STACK_OF(X509_NAME) *);
char *X509_NAME2text(X509_NAME *);

/**************************************** prototypes for network.c */

s_poll_set *s_poll_alloc(void);
void s_poll_free(s_poll_set *);
void s_poll_init(s_poll_set *, int);
void s_poll_add(s_poll_set *, SOCKET, int, int);
void s_poll_remove(s_poll_set *, SOCKET);
int s_poll_canread(s_poll_set *, SOCKET);
int s_poll_canwrite(s_poll_set *, SOCKET);
int s_poll_hup(s_poll_set *, SOCKET);
int s_poll_rdhup(s_poll_set *, SOCKET);
int s_poll_err(s_poll_set *, SOCKET);
int s_poll_wait(s_poll_set *, int, int);
void s_poll_dump(s_poll_set *, int);
void s_poll_sleep(int, int);

#ifdef USE_WIN32
#define SIGNAL_TERMINATE        1
#define SIGNAL_RELOAD_CONFIG    2
#define SIGNAL_REOPEN_LOG       3
#define SIGNAL_CONNECTIONS      4
#else
#define SIGNAL_TERMINATE        SIGTERM
#define SIGNAL_RELOAD_CONFIG    SIGHUP
#define SIGNAL_REOPEN_LOG       SIGUSR1
#define SIGNAL_CONNECTIONS      SIGUSR2
#endif

int socket_options_set(SERVICE_OPTIONS *, SOCKET, int);
int make_sockets(SOCKET[2]);
int original_dst(const SOCKET, SOCKADDR_UNION *);

/**************************************** prototypes for client.c */

CLI *alloc_client_session(SERVICE_OPTIONS *, SOCKET, SOCKET);
#if defined(USE_WIN32) || defined(USE_OS2)
unsigned __stdcall
#else
void *
#endif
    client_thread(void *);
void client_main(CLI *);
void client_free(CLI *);
void throw_exception(CLI *, int) NORETURN;

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
void ssl_printf(CLI *, const char *, ...)
#ifdef __GNUC__
    __attribute__((format(printf, 2, 3)));
#else
    ;
#endif

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
typedef void (CALLBACK * FREEADDRINFO) (struct addrinfo *);
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

#ifndef USE_FORK
extern CLI *thread_head;
#endif

#if OPENSSL_VERSION_NUMBER<0x10100004L

#ifdef USE_OS_THREADS

struct CRYPTO_dynlock_value {
#ifdef USE_PTHREAD
    pthread_rwlock_t rwlock;
#endif
#ifdef USE_WIN32
    CRITICAL_SECTION critical_section;
#endif
#ifdef DEBUG_LOCKS
    const char *init_file, *read_lock_file, *write_lock_file,
        *unlock_file, *destroy_file;
    int init_line, read_lock_line, write_lock_line, unlock_line, destroy_line;
#endif
};

typedef struct CRYPTO_dynlock_value CRYPTO_RWLOCK;

#else /* USE_OS_THREADS */

typedef void CRYPTO_RWLOCK;

#endif /* USE_OS_THREADS */

#endif /* OPENSSL_VERSION_NUMBER<0x10100004L */

typedef enum {
    LOCK_THREAD_LIST,                       /* sthreads.c */
    LOCK_SESSION, LOCK_ADDR,
    LOCK_CLIENTS, LOCK_SSL,                 /* client.c */
    LOCK_REF,                               /* options.c */
    LOCK_INET,                              /* resolver.c */
#ifndef USE_WIN32
    LOCK_LIBWRAP,                           /* libwrap.c */
#endif
    LOCK_LOG_BUFFER, LOCK_LOG_MODE,         /* log.c */
    LOCK_LEAK_HASH, LOCK_LEAK_RESULTS,      /* str.c */
#ifndef OPENSSL_NO_DH
    LOCK_DH,                                /* ctx.c */
#endif /* OPENSSL_NO_DH */
#ifdef USE_WIN32
    LOCK_WIN_LOG,                           /* ui_win_gui.c */
#endif
    LOCK_SECTIONS,                          /* traversing section list */
    STUNNEL_LOCKS                           /* number of locks */
} LOCK_TYPE;

extern CRYPTO_RWLOCK *stunnel_locks[STUNNEL_LOCKS];

#if OPENSSL_VERSION_NUMBER<0x10100004L
/* Emulate the OpenSSL 1.1 locking API for older OpenSSL versions */
CRYPTO_RWLOCK *CRYPTO_THREAD_lock_new(void);
int CRYPTO_THREAD_read_lock(CRYPTO_RWLOCK *);
int CRYPTO_THREAD_write_lock(CRYPTO_RWLOCK *);
int CRYPTO_THREAD_unlock(CRYPTO_RWLOCK *);
void CRYPTO_THREAD_lock_free(CRYPTO_RWLOCK *);
int CRYPTO_atomic_add(int *, int, int *, CRYPTO_RWLOCK *);
#endif

int sthreads_init(void);
unsigned long stunnel_process_id(void);
unsigned long stunnel_thread_id(void);
int create_client(SOCKET, SOCKET, CLI *);

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
void stack_info(size_t, int);
void ignore_value(void *);
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
void libwrap_auth(CLI *);

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
char *str_dup_detached_debug(const char *, const char *, int);
#define str_dup_detached(a) str_dup_detached_debug((a), __FILE__, __LINE__)
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
void *str_realloc_detached_debug(void *, size_t, const char *, int);
#define str_realloc_detached(a, b) str_realloc_detached_debug((a), (b), __FILE__, __LINE__)
void str_detach_debug(void *, const char *, int);
#define str_detach(a) str_detach_debug((a), __FILE__, __LINE__)
void str_free_debug(void *, const char *, int);
#define str_free(a) str_free_debug((a), __FILE__, __LINE__), (a)=NULL
#define str_free_expression(a) str_free_debug((a), __FILE__, __LINE__)

void leak_table_utilization(void);

int safe_memcmp(const void *, const void *, size_t);

/**************************************** prototypes for ui_*.c */

void ui_config_reloaded(void);
void ui_new_chain(const unsigned);
void ui_clients(const long);

void ui_new_log(const char *);
#ifdef USE_WIN32
void message_box(LPCTSTR, const UINT);
#endif /* USE_WIN32 */

int ui_passwd_cb(char *, int, int, void *);
#ifndef OPENSSL_NO_ENGINE
int (*ui_get_opener(void)) (UI *);
int (*ui_get_writer(void)) (UI *, UI_STRING *);
int (*ui_get_reader(void)) (UI *, UI_STRING *);
int (*ui_get_closer(void)) (UI *);
#endif /* !defined(OPENSSL_NO_ENGINE) */

#ifdef ICON_IMAGE
ICON_IMAGE load_icon_default(ICON_TYPE);
ICON_IMAGE load_icon_file(const char *);
#endif

#endif /* defined PROTOTYPES_H */

/* end of prototypes.h */
