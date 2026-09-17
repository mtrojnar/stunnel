/*
 *   stunnel       TLS offloading and load-balancing proxy
 *   Copyright (C) 1998-2026 Michal Trojnara <Michal.Trojnara@stunnel.org>
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

#ifdef USE_OS_THREADS
#ifndef USE_WIN32
    /* FIXME: waiting for a single terminate_pipe socket
     * from multiple threads causes a deadlock on WIN32 */
#define USE_TERMINATE_PIPE
#endif /* USE_WIN32 */
#endif /* USE_OS_THREADS */

/**************************************** forward declarations */

typedef struct tls_data_struct TLS_DATA;
typedef struct sock_opt_struct SOCK_OPT;
typedef struct client_data_struct CLI;
typedef struct global_options_struct GLOBAL_OPTIONS;
typedef struct service_options_struct SERVICE_OPTIONS;
#ifndef OPENSSL_NO_TLSEXT
typedef struct servername_list_struct SERVERNAME_LIST;
#endif /* !defined(OPENSSL_NO_TLSEXT) */

/**************************************** data structures */

#ifdef USE_PTHREAD
    typedef pthread_t THREAD_ID;
#endif
#ifdef USE_WIN32
    typedef HANDLE THREAD_ID;
#endif

#if OPENSSL_VERSION_NUMBER<0x10100004L || defined(LIBRESSL_VERSION_NUMBER)

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
#ifndef OPENSSL_NO_OCSP
    LOCK_OCSP_RESPONSE,                     /* ocsp.c */
#endif /* OPENSSL_NO_OCSP */
    LOCK_LEAK_HASH, LOCK_LEAK_RESULTS,      /* str.c */
#ifndef OPENSSL_NO_DH
    LOCK_DH,                                /* ctx.c */
#endif /* OPENSSL_NO_DH */
#ifdef USE_WIN32
    LOCK_WIN_LOG,                           /* ui_win_gui.c */
#endif
    LOCK_SECTIONS,                          /* traversing section list */
#if !defined(HAVE_LOCALTIME_R) || !defined(_REENTRANT)
    LOCK_LOCALTIME,                         /* unsafe localtime() */
#endif
    STUNNEL_LOCKS                           /* number of locks */
} LOCK_TYPE;

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
#ifdef USE_IPV6
    struct sockaddr_in6 in6;
#endif
#ifdef HAVE_STRUCT_SOCKADDR_UN
    struct sockaddr_un un;
#endif
    struct sockaddr_storage ss; /* generic storage, large enough for any AF */
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

extern GLOBAL_OPTIONS global_options;
#ifndef OPENSSL_NO_COMP
typedef enum {
    COMP_NONE,                           /* empty compression algorithms set */
    COMP_DEFLATE,            /* default OpenSSL's compression algorithms set */
    COMP_ZLIB,          /* additional historic ZLIB compression algorithm id */
#if OPENSSL_VERSION_NUMBER>=0x30200000L
    COMP_ZSTD,                 /* non-standard ZSTD compression algorithm id */
    COMP_BROTLI,             /* non-standard BROTLI compression algorithm id */
#endif
} COMP_TYPE;
#endif /* !defined(OPENSSL_NO_COMP) */

struct global_options_struct {
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
        unsigned fips:1;                           /* enable FIPS 140-3 mode */
#endif
    } option;
};

#ifndef OPENSSL_NO_PSK
typedef struct psk_keys_struct {
    const char *identity;                  /* the OpenSSL API requires const */
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

struct service_options_struct {
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
#ifndef OPENSSL_NO_ENGINE
    NAME_LIST *ca_engine;  /* engine-specific CA certificate identifier list */
#endif
    char *ca_dir;                    /* directory containing hashed CA certs */
    char *ca_file;                  /* file containing concatenated CA certs */
#if OPENSSL_VERSION_NUMBER>=0x30000000L
    char *ca_store;                                     /* store of CA certs */
#endif
    char *crl_dir;                       /* directory containing hashed CRLs */
    char *crl_file;                     /* file containing concatenated CRLs */
#ifndef OPENSSL_NO_OCSP
    char *ocsp_url;
    unsigned long ocsp_flags;
    unsigned char *ocsp_response_der;                  /* OCSP response data */
    int ocsp_response_len;                           /* OCSP response length */
    unsigned stapling_cb_flag:1;          /* OCSP stapling callback executed */
    unsigned verify_cb_flag:1;        /* verify callback executed at depth 0 */
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
    NAME_LIST *cert;    /* list of certificate identifiers (URI or filename) */
    char *key;                               /* pem (priv key/cert) filename */
    long session_size, session_timeout;
#if OPENSSL_VERSION_NUMBER>=0x10100000L
    int security_level;
#endif /* OpenSSL 1.1.0 or later */
    uint64_t ssl_options_set;
#if OPENSSL_VERSION_NUMBER>=0x009080dfL
    uint64_t ssl_options_clear;
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
#ifdef USE_DTLS
    /* DTLS cookie callbacks - required for DTLSv1_listen()
     * Use HMAC-SHA256 with random per-section secret bound to the client
     * IP address (not port) so cookies survive ephemeral port changes. */
    unsigned char dtls_cookie_secret[32];
#endif /* USE_DTLS */

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
    int timeout_connect;                         /* maximum s_connect() time */
    int timeout_idle;                        /* maximum idle connection time */
#ifndef OPENSSL_NO_OCSP
    int timeout_ocsp;                   /* maximum s_connect() time for OCSP */
#endif /* !OPENSSL_NO_OCSP */
    enum {FAILOVER_RR, FAILOVER_PRIO} failover;         /* failover strategy */
    unsigned rr;   /* per-service sequential number for round-robin failover */
    char *username;                                 /* ident client username */
    long retry;     /* retry delay for remote+program loop or -1 if disabled */

        /* service-specific data for protocol.c */
    char *protocol;
    void (*protocol_early)(CLI *c);
    void (*protocol_middle)(CLI *c);
    void (*protocol_late)(CLI *c);
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
    int sock_type;                      /* SOCK_STREAM (default) or SOCK_DGRAM */
    struct {
        unsigned request_cert:1;        /* request a peer certificate */
        unsigned require_cert:1;        /* require a client certificate */
        unsigned verify_chain:1;        /* verify certificate chain */
        unsigned crl_check_chain:1;     /* check CRLs for the full chain */
        unsigned verify_peer:1;         /* verify peer certificate */
        unsigned accept_set:1;          /* endpoint: accept */
        unsigned client:1;
        unsigned delayed_lookup:1;
#ifdef USE_LIBWRAP
        unsigned libwrap:1;
#endif
        unsigned local:1;               /* outgoing interface specified */
        unsigned session_resume:1;      /* enable session resumption */
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
        unsigned ocsp_require:1;        /* require a conclusive OCSP response */
#endif /* !defined(OPENSSL_NO_OCSP) */
#ifndef OPENSSL_NO_DH
        unsigned dh_temp_params_set:1;
#endif /* OPENSSL_NO_DH */
#ifndef USE_WIN32
        unsigned log_stderr:1;          /* a copy of the global switch */
#endif /* USE_WIN32 */
        unsigned default_local_addr:1;
        unsigned default_ca_engine:1;
        unsigned default_cert:1;
        unsigned default_check_email:1;
        unsigned default_check_host:1;
        unsigned default_check_ip:1;
        unsigned default_config:1;
        unsigned default_connect_addr:1;
        unsigned default_protocol_header:1;
        unsigned default_redirect_addr:1;
    } option;
};

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
    const char *opt_str;
    int  opt_level;
    int  opt_name;
    VAL_TYPE opt_type;
    OPT_UNION *opt_val_tcp[3];
    OPT_UNION *opt_val_udp[3];
};

typedef enum {
    CONF_RELOAD, CONF_FILE, CONF_FD
} CONF_TYPE;

        /* s_poll_set definition for network.c */

typedef struct {
#if defined(USE_POLL) || defined(USE_WIN32)
    unsigned capacity;
#endif
#ifdef USE_POLL
    struct pollfd *ufds;
    unsigned nfds;
#else /* select */
    fd_set *irfds, *orfds, *iwfds, *owfds;
#ifndef USE_WIN32
    fd_set *ixfds, *oxfds;
#endif
    SOCKET max_fd;
#endif
    int main_thread;
} s_poll_set;

typedef struct {
    /* stdio is currently used, but alternative implementations can be added */
    FILE *f;
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

struct client_data_struct {
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
    int fatal_alert;                               /* received a fatal alert */
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
        unsigned redirect:1;                     /* redirect the destination */
#ifndef OPENSSL_NO_PSK
        unsigned psk_found:1;                      /* PSK identity was found */
#endif /* !defined(OPENSSL_NO_PSK) */
    } flag;

#ifdef USE_DTLS
    BIO *udp_preload_bio;  /* drain_udp_datagrams() (server + client); see
                             * set_preload_bio() / transfer_udp() */
#endif /* USE_DTLS */
};

/**************************************** prototypes for stunnel.c */

#ifndef USE_FORK
extern int max_clients;
extern int num_clients;
#endif
extern SOCKET signal_pipe[2];
extern SOCKET terminate_pipe[2];

int stunnel_init(void);
void main_init(void);
int main_configure(char *arg1, char *arg2);
void main_cleanup(void);
int drop_privileges(int critical);
void daemon_loop(void);
void signal_post(uint8_t sig);
#if !defined(USE_WIN32) && !defined(USE_OS2)
void pid_status_hang(const char *info);
#endif
void stunnel_info(int level);

/**************************************** prototypes for options.c */

extern unsigned number_of_sections;

int options_cmdline(char *arg1, char *arg2);
int options_parse(CONF_TYPE type);
void options_defaults(void);
void options_apply(void);
void options_free(int current);

SERVICE_OPTIONS *service_up_ref(SERVICE_OPTIONS *section);
void service_free(SERVICE_OPTIONS *section);

/**************************************** prototypes for fd.c */

#ifndef USE_FORK
void get_limits(void); /* setup global max_clients and max_fds */
#endif
SOCKET s_socket(int domain, int type, int protocol, int nonblock, const char *msg);
int s_pipe(int pipefd[2], int nonblock, const char *msg);
int s_socketpair(int domain, int type, int protocol, SOCKET *sv,
    int nonblock, const char *msg);
SOCKET s_accept(SOCKET sockfd, struct sockaddr *addr, socklen_t *addrlen, int nonblock, const char *msg);
void set_nonblock(SOCKET fd, unsigned long nonblock);

/**************************************** prototypes for log.c */

#define SINK_SYSLOG 1
#define SINK_OUTFILE 2

extern DISK_FILE *outfile;

int log_open(int sink);
void log_close(int sink);
void log_flush(LOG_MODE new_mode);
void s_log(int level, const char *format, ...)
#ifdef __GNUC__
    __attribute__((format(printf, 2, 3)));
#else
    ;
#endif
void s_vlog(int level, const char *format, va_list ap);
char *log_id_alloc(CLI *c);
void fatal_debug(const char *txt, const char *file, int line) NORETURN;
#define fatal(a) fatal_debug((a), __FILE__, __LINE__)
void ioerror(const char *txt);
void sockerror(const char *txt);
void log_error(int level, int error, const char *txt);
char *s_strerror(int errnum);
void bin2hexstring(const unsigned char *in_data, size_t in_size, char *out_data, size_t out_size);
void safe_localtime(struct tm *ts, time_t unix_time);

/**************************************** prototypes for pty.c */

int pty_allocate(int *ptyfd, int *ttyfd, char *namebuf);

/**************************************** prototypes for dhparam.c */

DH *get_dh2048(void);

/**************************************** prototypes for cron.c */

#ifdef USE_OS_THREADS
extern THREAD_ID per_second_thread_id;
extern THREAD_ID per_minute_thread_id;
extern THREAD_ID per_day_thread_id;
#endif

int cron_init(void);

/**************************************** prototypes for ssl.c */

extern int index_ssl_cli, index_ssl_ctx_opt;
extern int index_session_authenticated, index_session_connect_address;
#if OPENSSL_VERSION_NUMBER<0x10100000L
extern int unsafe_openssl;
#endif /* OpenSSL version < 1.1.0 */

#ifdef USE_FIPS
int fips_default(void);
int fips_available(void);
#endif
int crypto_init(void);
void crypto_cleanup(void);
int ssl_init(void);
void ssl_cleanup(void);
int ssl_configure(GLOBAL_OPTIONS *global);

/**************************************** prototypes for ctx.c */

#ifndef OPENSSL_NO_DH
extern DH *dh_params;
extern int dh_temp_params;
#endif /* OPENSSL_NO_DH */

#if !defined(OPENSSL_NO_ENGINE) || OPENSSL_VERSION_NUMBER>=0x10101000L
extern UI_METHOD *ui_stunnel;
#endif /* !defined(OPENSSL_NO_ENGINE) || OPENSSL_VERSION_NUMBER>=0x10101000L*/

extern SERVICE_OPTIONS *current_section;

int ctx_init(void);
void ctx_cleanup(void);
int context_init(SERVICE_OPTIONS *section);
void context_cleanup(SERVICE_OPTIONS *section);
#if !defined(OPENSSL_NO_DH) && OPENSSL_VERSION_NUMBER<0x10100000L
int DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g);
#endif /* !defined(OPENSSL_NO_DH) && OPENSSL_VERSION_NUMBER<0x10100000L */
#ifndef OPENSSL_NO_PSK
void psk_sort(PSK_TABLE *table, PSK_KEYS *head);
PSK_KEYS *psk_find(const PSK_TABLE *table, const char *identity);
#endif /* !defined(OPENSSL_NO_PSK) */
void print_session_id(const char *txt, SSL_SESSION *sess);
void ssl_error(CLI *c, const char *txt);

/**************************************** prototypes for verify.c */

int verify_section_init(SERVICE_OPTIONS *section);
#ifndef OPENSSL_NO_ENGINE
X509 *engine_get_cert(ENGINE *engine, const char *id);
#endif
void print_CA_list(const char *type, const STACK_OF (X509_NAME) *ca_dn);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
char *X509_NAME2text(const X509_NAME *name);
#else /* OpenSSL 1.1.0 or newer */
char *X509_NAME2text(X509_NAME *name);
#endif /* OpenSSL 1.1.0 or newer */

/**************************************** prototypes for ocsp.c */

#ifndef OPENSSL_NO_OCSP
int ocsp_check(CLI *c, X509_STORE_CTX *callback_ctx);      /* OCSP client-driven checking */
int ocsp_init(SERVICE_OPTIONS *section);            /* OCSP stapling initialization */
#if OPENSSL_VERSION_NUMBER>=0x10002000L
void ocsp_cleanup(SERVICE_OPTIONS *section);
int ocsp_stapling(SERVICE_OPTIONS *opt);
#endif /* OPENSSL_VERSION_NUMBER>=0x10002000L */
#endif /* !defined(OPENSSL_NO_OCSP) */

/**************************************** prototypes for network.c */

s_poll_set *s_poll_alloc(void);
void s_poll_free(s_poll_set *fds);
void s_poll_init(s_poll_set *fds, int main_thread);
void s_poll_add(s_poll_set *fds, SOCKET fd, int rd, int wr);
void s_poll_remove(s_poll_set *fds, SOCKET fd);
int s_poll_canread(s_poll_set *fds, SOCKET fd);
int s_poll_canwrite(s_poll_set *fds, SOCKET fd);
int s_poll_hup(s_poll_set *fds, SOCKET fd);
int s_poll_rdhup(s_poll_set *fds, SOCKET fd);
int s_poll_err(s_poll_set *fds, SOCKET fd);
int s_poll_wait(s_poll_set *fds, int sec, int msec);
void s_poll_dump(s_poll_set *fds, int level);
void s_poll_sleep(int sec, int msec);

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

int socket_options_set(SERVICE_OPTIONS *service, SOCKET s, int type);
int socket_type_is_stream(int socket_type);
int socket_type_is_datagram(int socket_type);
int make_sockets(SOCKET *fd, int sock_type);
int original_dst(const SOCKET fd, SOCKADDR_UNION *addr);
int socket_needs_retry(CLI *c, const char *text);

#ifdef USE_DTLS
#if OPENSSL_VERSION_NUMBER>=0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
int bio_addr_to_sockaddr(const BIO_ADDR *src, SOCKADDR_UNION *dst);
#endif
int dtls_listen(CLI *c, SOCKET fd);
void dtls_accept(CLI *c);
int drain_udp_datagrams(CLI *c, SOCKET fd);
#endif /* USE_DTLS */

/**************************************** prototypes for client.c */

CLI *alloc_client(SERVICE_OPTIONS *opt);
void free_client(CLI *c);
#if defined(USE_WIN32) || defined(USE_OS2)
unsigned __stdcall
#else
void *
#endif
    client_thread(void *arg);
void client_main(CLI *c);
void throw_exception(CLI *c, int v) NORETURN;

/**************************************** prototypes for network.c */

int get_socket_error(const SOCKET fd);
int s_connect(CLI *c, SOCKADDR_UNION *addr, socklen_t addrlen, int timeout);
void s_write(CLI *c, SOCKET fd, const void *buf, size_t len);
size_t s_read_eof(CLI *c, SOCKET fd, void *ptr, size_t len);
void s_read(CLI *c, SOCKET fd, void *ptr, size_t len);
void fd_putline(CLI *c, SOCKET fd, const char *line);
char *fd_getline(CLI *c, SOCKET fd);
/* descriptor versions of fprintf/fscanf */
void fd_printf(CLI *c, SOCKET fd, const char *format, ...)
#ifdef __GNUC__
    __attribute__((format(printf, 3, 4)));
#else
    ;
#endif
void s_ssl_write(CLI *c, const void *buf, int len);
void s_ssl_read(CLI *c, void *ptr, int len);
char *ssl_getstring(CLI *c);
char *ssl_getline(CLI *c);
void ssl_putline(CLI *c, const char *line);
void ssl_printf(CLI *c, const char *format, ...)
#ifdef __GNUC__
    __attribute__((format(printf, 2, 3)));
#else
    ;
#endif

/**************************************** prototype for protocol.c */

#ifdef USE_WIN32
extern HWND capwin_hwnd;
extern LONG capwin_connectivity;
#endif

const char *protocol_init(SERVICE_OPTIONS *opt);

/**************************************** prototypes for resolver.c */

void resolver_init(void);
int use_ipv6(void);

unsigned name2addr(SOCKADDR_UNION *addr, char *name, int passive);
unsigned hostport2addr(SOCKADDR_UNION *addr, char *host_name, const char *port_name, int passive);

unsigned name2addrlist(SOCKADDR_LIST *addr_list, char *name);
unsigned hostport2addrlist(SOCKADDR_LIST *addr_list, char *host_name, const char *port_name);

void addrlist_clear(SOCKADDR_LIST *addr_list, int passive);
unsigned addrlist_dup(SOCKADDR_LIST *dst, const SOCKADDR_LIST *src);
unsigned addrlist_resolve(SOCKADDR_LIST *addr_list);

char *s_ntop(SOCKADDR_UNION *addr, socklen_t addrlen);
int addr_cmp(const SOCKADDR_UNION *addr1, socklen_t addrlen1,
    const SOCKADDR_UNION *addr2, socklen_t addrlen2);
int addr_family_is(const SOCKADDR_UNION *addr, int family);
socklen_t sockaddr_len(const SOCKADDR_UNION *addr);
const char *s_gai_strerror(int err);

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
#endif /* USE_WIN32 */

int getnameinfo(const struct sockaddr *sa, socklen_t salen,
    char *host, size_t hostlen, char *serv, size_t servlen, int flags);

#endif /* !defined HAVE_GETNAMEINFO */

/**************************************** prototypes for sthreads.c */

#ifndef USE_FORK
extern CLI *thread_head;
#endif

int s_atomic_add_debug(int *val, int amount, int type,
    const char *file, int line);
#define s_atomic_add(a, b, c) \
    s_atomic_add_debug((a), (b), (c), __FILE__, __LINE__)
CRYPTO_RWLOCK *s_read_lock_debug(int type, const char *file, int line);
#define s_read_lock(a) s_read_lock_debug((a), __FILE__, __LINE__)
CRYPTO_RWLOCK *s_write_lock_debug(int type, const char *file, int line);
#define s_write_lock(a) s_write_lock_debug((a), __FILE__, __LINE__)
void s_unlock_debug(CRYPTO_RWLOCK *lock, const char *file, int line);
#define s_unlock(a) s_unlock_debug((a), __FILE__, __LINE__)

int sthreads_init(void);
int sthreads_stack_size_validate(size_t stack_size);
unsigned long stunnel_process_id(void);
unsigned long stunnel_thread_id(void);
int create_client(SOCKET ls, CLI *arg);

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
long _beginthread(void (*start_address)(void *arglist),
    int stack_size, void *arglist);
void _endthread(void);
#endif

#ifdef DEBUG_STACK_SIZE
void stack_info(size_t stack_size, int init);
void ignore_value(void *ptr);
#endif

/**************************************** prototypes for file.c */

#ifndef USE_WIN32
DISK_FILE *file_fdopen(int fd, FILE_MODE file_mode);
#endif
DISK_FILE *file_open(char *name, FILE_MODE file_mode);
void file_close(DISK_FILE *df);
ssize_t file_getline(DISK_FILE *df, char *line, int len);
ssize_t file_putline_nonewline(DISK_FILE *df, char *line);
ssize_t file_putline_newline(DISK_FILE *df, char *line);
int file_flush(DISK_FILE *df);
int file_permissions(const char *file_name);

#ifdef USE_WIN32
LPTSTR str2tstr(LPCSTR in);
LPSTR tstr2str(LPCTSTR in);
#endif

/**************************************** prototypes for libwrap.c */

int libwrap_init(void);
void libwrap_auth(CLI *c);

/**************************************** prototypes for tls.c */

extern volatile int tls_initialized;

void tls_init(void);
TLS_DATA *tls_alloc(CLI *c, TLS_DATA *inherited, const char *txt);
void tls_cleanup(void);
TLS_DATA *tls_get(void);

/**************************************** prototypes for str.c */

extern TLS_DATA *ui_tls;
typedef struct alloc_list_struct ALLOC_LIST;

struct tls_data_struct {
    ALLOC_LIST *alloc_head;
    size_t alloc_bytes, alloc_blocks;
    CLI *c;
    SERVICE_OPTIONS *opt;
    const char *id;
};

void str_init(void);
void str_thread_init(TLS_DATA *tls_data);
void str_thread_cleanup(TLS_DATA *tls_data);
char *str_dup_debug(const char *source, const char *file, int line);
#define str_dup(a) str_dup_debug((a), __FILE__, __LINE__)
char *str_dup_detached_debug(const char *source, const char *file, int line);
#define str_dup_detached(a) str_dup_detached_debug((a), __FILE__, __LINE__)
long str_to_long(char *source, char **end);
char *str_vprintf(const char *format, va_list ap);
char *str_printf(const char *format, ...)
#ifdef __GNUC__
    __attribute__((format(printf, 1, 2)));
#else
    ;
#endif
#ifdef USE_WIN32
LPTSTR str_tprintf(LPCTSTR format, ...);
#endif

void str_canary_init(void);
void str_stats(void);

void *str_alloc_debug(size_t size, const char *file, int line);
#define str_alloc(a) str_alloc_debug((a), __FILE__, __LINE__)
void *str_alloc_detached_debug(size_t size, const char *file, int line);
#define str_alloc_detached(a) str_alloc_detached_debug((a), __FILE__, __LINE__)

void *str_realloc_debug(void *ptr, size_t size, const char *file, int line);
#define str_realloc(a, b) str_realloc_debug((a), (b), __FILE__, __LINE__)
void *str_realloc_detached_debug(void *ptr, size_t size, const char *file, int line);
#define str_realloc_detached(a, b) str_realloc_detached_debug((a), (b), __FILE__, __LINE__)

void str_detach_debug(void *ptr, const char *file, int line);
#define str_detach(a) str_detach_debug((a), __FILE__, __LINE__)
void str_detach_const_debug(const void *ptr, const char *file, int line);
#define str_detach_const(a) str_detach_const_debug((a), __FILE__, __LINE__)

void str_free_debug(void *ptr, const char *file, int line);
#define str_free(a) str_free_debug((a), __FILE__, __LINE__), (a)=NULL
#define str_free_expression(a) str_free_debug((a), __FILE__, __LINE__)
void str_free_const_debug(const void *ptr, const char *file, int line);
#define str_free_const(a) str_free_const_debug((a), __FILE__, __LINE__), (a)=NULL

void leak_table_utilization(void);

int safe_memcmp(const void *s1, const void *s2, size_t n);

/**************************************** prototypes for ui_*.c */

void ui_config_reloaded(void);
void ui_new_chain(const unsigned section_number);
void ui_clients(const long client_count);

void ui_new_log(const char *line);
#ifdef USE_WIN32
void message_box(LPCTSTR text, const UINT type);
#endif /* USE_WIN32 */

int ui_passwd_cb(char *buf, int size, int rwflag, void *userdata);
#if !defined(OPENSSL_NO_ENGINE) || OPENSSL_VERSION_NUMBER>=0x10101000L
int (*ui_get_opener(void)) (UI *ui);
int (*ui_get_writer(void)) (UI *ui, UI_STRING *uis);
int (*ui_get_reader(void)) (UI *ui, UI_STRING *uis);
int (*ui_get_closer(void)) (UI *ui);
#endif /* !defined(OPENSSL_NO_ENGINE) || OPENSSL_VERSION_NUMBER>=0x10101000L */

#ifdef ICON_IMAGE
ICON_IMAGE load_icon_default(ICON_TYPE type);
ICON_IMAGE load_icon_file(const char *file_name);
#endif

#endif /* defined PROTOTYPES_H */

/* end of prototypes.h */
