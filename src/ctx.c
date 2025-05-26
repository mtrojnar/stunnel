/*
 *   stunnel       TLS offloading and load-balancing proxy
 *   Copyright (C) 1998-2025 Michal Trojnara <Michal.Trojnara@stunnel.org>
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

#include "prototypes.h"

#define MAX_ERRORS 10
#define MAX_ERROR_LEN 256

#if defined(__GNUC__) && defined(USE_WIN32)
#pragma GCC diagnostic ignored "-Wformat"
#endif /* defined(__GNUC__) && defined(USE_WIN32) */

SERVICE_OPTIONS *current_section=NULL;

#if OPENSSL_VERSION_NUMBER<0x10101000L
/* try an empty passphrase first */
static char cached_passwd[PEM_BUFSIZE]="";
static int cached_len=0;
#endif /* OpenSSL older than 1.1.1 */
typedef struct {
    const char *password;
    const char *prompt_info;
} PW_CB_DATA;

#ifndef OPENSSL_NO_DH
DH *dh_params=NULL;
int dh_temp_params=0;
#endif /* OPENSSL_NO_DH */

/**************************************** prototypes */

/* SNI */
#ifndef OPENSSL_NO_TLSEXT
NOEXPORT int servername_cb(SSL *, int *, void *);
NOEXPORT int matches_wildcard(const char *, const char *);
#endif

/* DH/ECDH */
#ifndef OPENSSL_NO_DH
NOEXPORT int dh_init(SERVICE_OPTIONS *);
NOEXPORT DH *dh_read(char *);
#endif /* OPENSSL_NO_DH */
#ifndef OPENSSL_NO_ECDH
NOEXPORT int ecdh_init(SERVICE_OPTIONS *);
#endif /* USE_ECDH */

/* configuration commands */
NOEXPORT int conf_init(SERVICE_OPTIONS *section);

/* authentication */
NOEXPORT int auth_init(SERVICE_OPTIONS *);
#ifndef OPENSSL_NO_PSK
NOEXPORT unsigned psk_client_callback(SSL *, const char *,
    char *, unsigned, unsigned char *, unsigned);
NOEXPORT unsigned psk_server_callback(SSL *, const char *,
    unsigned char *, unsigned);
#endif /* !defined(OPENSSL_NO_PSK) */

#if OPENSSL_VERSION_NUMBER>=0x10101000L
NOEXPORT int load_objects(SERVICE_OPTIONS *, int, int);
NOEXPORT int load_objects_from_store(SSL_CTX *, const char *, int, int);
#else /* OpenSSL 1.1.1 or later */
NOEXPORT int load_cert_file(SERVICE_OPTIONS *);
NOEXPORT int load_key_file(SERVICE_OPTIONS *);
NOEXPORT int pkcs12_extension(const char *);
NOEXPORT int load_pkcs12_file(SERVICE_OPTIONS *);
NOEXPORT int cache_passwd_get_cb(char *, int, int, void *);
NOEXPORT int cache_passwd_set_cb(char *, int, int, void *);
NOEXPORT void set_prompt(const char *);
#endif /* OpenSSL 1.1.1 or later */

#ifndef OPENSSL_NO_ENGINE
NOEXPORT int load_cert_engine(SERVICE_OPTIONS *);
NOEXPORT int load_key_engine(SERVICE_OPTIONS *);
#endif

NOEXPORT int ui_retry(void);

/* session tickets */
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
NOEXPORT int generate_session_ticket_cb(SSL *, void *);
NOEXPORT int decrypt_session_ticket_cb(SSL *, SSL_SESSION *,
    const unsigned char *, size_t, SSL_TICKET_STATUS, void *);
#endif /* OpenSSL 1.1.1 or later */

#if OPENSSL_VERSION_NUMBER>=0x10000000L
NOEXPORT int ssl_tlsext_ticket_key_cb(SSL *, unsigned char *,
    unsigned char *, EVP_CIPHER_CTX *, HMAC_CTX *, int);
#endif /* OpenSSL 1.0.0 or later */

/* session callbacks */
NOEXPORT int sess_new_cb(SSL *, SSL_SESSION *);
NOEXPORT void new_chain(CLI *);
NOEXPORT void session_cache_save(CLI *, SSL_SESSION *);
#if OPENSSL_VERSION_NUMBER<0x10101000L
NOEXPORT SSL_SESSION *SSL_SESSION_dup(SSL_SESSION *);
#endif
NOEXPORT SSL_SESSION *sess_get_cb(SSL *,
#if OPENSSL_VERSION_NUMBER>=0x10100000L
    const
#endif
    unsigned char *, int, int *);
NOEXPORT void sess_remove_cb(SSL_CTX *, SSL_SESSION *);

/* sessiond interface */
NOEXPORT void cache_new(SSL *, SSL_SESSION *);
NOEXPORT SSL_SESSION *cache_get(SSL *, const unsigned char *, int);
NOEXPORT void cache_remove(SSL_CTX *, SSL_SESSION *);
NOEXPORT void cache_transfer(SSL_CTX *, const u_char, const long,
    const u_char *, const size_t,
    const u_char *, const size_t,
    unsigned char **, size_t *);

/* info callbacks */
NOEXPORT void info_callback(const SSL *, int, int);

#ifndef OPENSSL_NO_TLS1_3
NOEXPORT char *compare_cipher_lists(STACK_OF(SSL_CIPHER) *, STACK_OF(SSL_CIPHER) *);
NOEXPORT char *get_tls13_cipher_list(STACK_OF(SSL_CIPHER) *);
#endif /* TLS 1.3 */

/**************************************** initialize section->ctx */

#if OPENSSL_VERSION_NUMBER>=0x10100000L
typedef long unsigned SSL_OPTIONS_TYPE;
#else
typedef long SSL_OPTIONS_TYPE;
#endif

int context_init(SERVICE_OPTIONS *section) { /* init TLS context */
    s_log(LOG_DEBUG, "Initializing context [%s]", section->servname);

    /* create a new TLS context */
#if OPENSSL_VERSION_NUMBER>=0x30000000L
    section->ctx=SSL_CTX_new_ex(NULL,
        EVP_default_properties_is_fips_enabled(NULL) ?
            "fips=yes" : "provider!=fips",
        section->option.client ?
            TLS_client_method() : TLS_server_method());
#elif OPENSSL_VERSION_NUMBER>=0x10100000L
    section->ctx=SSL_CTX_new(section->option.client ?
        TLS_client_method() : TLS_server_method());
#else /* OPENSSL_VERSION_NUMBER<0x10100000L */
    section->ctx=SSL_CTX_new(section->option.client ?
        section->client_method : section->server_method);
#endif
    if(!section->ctx) {
        sslerror("SSL_CTX_new");
        return 1; /* FAILED */
    }

    /* set supported protocol versions */
#if OPENSSL_VERSION_NUMBER>=0x10100000L
    if(section->min_proto_version &&
            !SSL_CTX_set_min_proto_version(section->ctx,
            section->min_proto_version)) {
        s_log(LOG_ERR, "Failed to set the minimum protocol version 0x%X",
            section->min_proto_version);
        return 1; /* FAILED */
    }
    if(section->max_proto_version &&
            !SSL_CTX_set_max_proto_version(section->ctx,
            section->max_proto_version)) {
        s_log(LOG_ERR, "Failed to set the maximum protocol version 0x%X",
            section->max_proto_version);
        return 1; /* FAILED */
    }
#endif /* OPENSSL_VERSION_NUMBER>=0x10100000L */

    /* allow callbacks to access their SERVICE_OPTIONS structure */
    if(!SSL_CTX_set_ex_data(section->ctx, index_ssl_ctx_opt, section)) {
        sslerror("SSL_CTX_set_ex_data");
        return 1; /* FAILED */
    }
    current_section=section; /* setup current section for callbacks */

#if OPENSSL_VERSION_NUMBER>=0x10100000L
    /* set the security level */
    if(section->security_level>=0) {
        /* set the user-specified value */
        SSL_CTX_set_security_level(section->ctx, section->security_level);
        s_log(LOG_INFO, "User-specified security level set: %d",
            section->security_level);
    } else if(SSL_CTX_get_security_level(section->ctx)<DEFAULT_SECURITY_LEVEL) {
        /* set our default, as it is more secure than the OpenSSL default */
        SSL_CTX_set_security_level(section->ctx, DEFAULT_SECURITY_LEVEL);
        s_log(LOG_INFO, "stunnel default security level set: %d",
            DEFAULT_SECURITY_LEVEL);
    } else { /* our default is not more secure than the OpenSSL default */
        s_log(LOG_INFO, "OpenSSL security level is used: %d",
            SSL_CTX_get_security_level(section->ctx));
    }
#endif /* OpenSSL 1.1.0 or later */

    /* ciphers */
    if(section->cipher_list) {
        s_log(LOG_DEBUG, "Ciphers: %s", section->cipher_list);
        if(!SSL_CTX_set_cipher_list(section->ctx, section->cipher_list)) {
            sslerror("SSL_CTX_set_cipher_list");
            return 1; /* FAILED */
        }
    }

#ifndef OPENSSL_NO_TLS1_3
    /* ciphersuites */
    if(section->ciphersuites) {
        STACK_OF(SSL_CIPHER) *cipher_list, *tmp_cipher_list;
        char *tls12_cipher_list, *tls13_cipher_list;

        tmp_cipher_list=sk_SSL_CIPHER_dup(SSL_CTX_get_ciphers(section->ctx));
        if(!SSL_CTX_set_ciphersuites(section->ctx, section->ciphersuites)) {
            sslerror("SSL_CTX_set_ciphersuites");
            return 1; /* FAILED */
        }
        cipher_list=SSL_CTX_get_ciphers(section->ctx);
        tls12_cipher_list=compare_cipher_lists(tmp_cipher_list, cipher_list);
        sk_SSL_CIPHER_free(tmp_cipher_list);
        if(tls12_cipher_list) {
            s_log(LOG_DEBUG, "TLSv1.2 and below ciphers: %s", tls12_cipher_list);
        }
        tls13_cipher_list=get_tls13_cipher_list(cipher_list);
        if(tls13_cipher_list) {
            s_log(LOG_DEBUG, "TLSv1.3 ciphersuites: %s", tls13_cipher_list);
        }
    }
#endif /* TLS 1.3 */

    /* TLS options: configure the stunnel defaults first */
    SSL_CTX_set_options(section->ctx, SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3);
    /* no session ticket gets sent to the client at all in TLSv1.2
       and below, but a stateful ticket will be sent in TLSv1.3 */
#ifdef SSL_OP_NO_TICKET
    if(!section->option.client && !section->option.session_resume) {
        SSL_CTX_set_options(section->ctx, SSL_OP_NO_TICKET);
    }
#endif
#ifdef SSL_OP_NO_COMPRESSION
    /* we implemented a better way to disable compression if needed */
    SSL_CTX_clear_options(section->ctx, SSL_OP_NO_COMPRESSION);
#endif /* SSL_OP_NO_COMPRESSION */

    /* TLS options: configure the user-specified values */
    SSL_CTX_set_options(section->ctx,
        (SSL_OPTIONS_TYPE)(section->ssl_options_set));
#if OPENSSL_VERSION_NUMBER>=0x009080dfL
    SSL_CTX_clear_options(section->ctx,
        (SSL_OPTIONS_TYPE)(section->ssl_options_clear));
#endif /* OpenSSL 0.9.8m or later */

    /* TLS options: log the configured values */
#if OPENSSL_VERSION_NUMBER>=0x009080dfL
    s_log(LOG_DEBUG,
        "TLS options: 0x%" PRIX64 " (+0x%" PRIX64 ", -0x%" PRIX64 ")",
        SSL_CTX_get_options(section->ctx),
        section->ssl_options_set, section->ssl_options_clear);
#else /* OpenSSL older than 0.9.8m */
    s_log(LOG_DEBUG, "TLS options: 0x%" PRIX64 " (+0x%" PRIX64 ")",
        SSL_CTX_get_options(section->ctx), section->ssl_options_set);
#endif /* OpenSSL 0.9.8m or later */

    /* initialize OpenSSL CONF options */
    if(conf_init(section))
        return 1; /* FAILED */

    /* setup mode of operation for the TLS state machine */
#ifdef SSL_MODE_RELEASE_BUFFERS
    SSL_CTX_set_mode(section->ctx,
        SSL_MODE_ENABLE_PARTIAL_WRITE |
        SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
        SSL_MODE_RELEASE_BUFFERS);
#else
    SSL_CTX_set_mode(section->ctx,
        SSL_MODE_ENABLE_PARTIAL_WRITE |
        SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
#endif

    /* setup session tickets */
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
    SSL_CTX_set_session_ticket_cb(section->ctx, generate_session_ticket_cb,
        decrypt_session_ticket_cb, NULL);
#endif /* OpenSSL 1.1.1 or later */

#if OPENSSL_VERSION_NUMBER>=0x10000000L
    if((section->ticket_key)&&(section->ticket_mac))
        SSL_CTX_set_tlsext_ticket_key_cb(section->ctx, ssl_tlsext_ticket_key_cb);
#endif /* OpenSSL 1.0.0 or later */

    /* setup session cache */
    if(!section->option.client) {
        unsigned servname_len=(unsigned)strlen(section->servname);
        if(servname_len>SSL_MAX_SSL_SESSION_ID_LENGTH)
            servname_len=SSL_MAX_SSL_SESSION_ID_LENGTH;
#ifndef OPENSSL_NO_TLS1_3
        /* suppress all tickets (stateful and stateless) in TLSv1.3 */
        if(!section->option.session_resume && !SSL_CTX_set_num_tickets(section->ctx, 0)) {
            sslerror("SSL_CTX_set_num_tickets");
            return 1; /* FAILED */
        }
#endif /* TLS 1.3 */
        if(!SSL_CTX_set_session_id_context(section->ctx,
                (unsigned char *)section->servname, servname_len)) {
            sslerror("SSL_CTX_set_session_id_context");
            return 1; /* FAILED */
        }
    }
    if(section->option.session_resume) {
        SSL_CTX_set_session_cache_mode(section->ctx,
            SSL_SESS_CACHE_BOTH | SSL_SESS_CACHE_NO_INTERNAL_STORE);
    } else {
        SSL_CTX_set_session_cache_mode(section->ctx, SSL_SESS_CACHE_OFF);
    }
    s_log(LOG_INFO, "Session resumption %s", section->option.session_resume
        ? "enabled" : "disabled");
    SSL_CTX_sess_set_cache_size(section->ctx, section->session_size);
    SSL_CTX_set_timeout(section->ctx, section->session_timeout);
    SSL_CTX_sess_set_new_cb(section->ctx, sess_new_cb);
    SSL_CTX_sess_set_get_cb(section->ctx, sess_get_cb);
    SSL_CTX_sess_set_remove_cb(section->ctx, sess_remove_cb);

    /* set info callback */
    SSL_CTX_set_info_callback(section->ctx, info_callback);

    /* load certificate and private key to be verified by the peer server */
    if(auth_init(section))
        return 1; /* FAILED */

    /* initialize verification of the peer server certificate */
    if(verify_init(section))
        return 1; /* FAILED */

    /* OCSP stapling */
#ifndef OPENSSL_NO_OCSP
    if(ocsp_init(section))
        return 1; /* FAILED */
#endif /* OPENSSL_NO_OCSP */

    /* initialize the DH/ECDH key agreement */
#ifndef OPENSSL_NO_TLSEXT
    if(!section->option.client)
        SSL_CTX_set_tlsext_servername_callback(section->ctx, servername_cb);
#endif /* OPENSSL_NO_TLSEXT */
#ifndef OPENSSL_NO_DH
    dh_init(section); /* ignore the result (errors are not critical) */
#endif /* OPENSSL_NO_DH */
#ifndef OPENSSL_NO_ECDH
    if(ecdh_init(section))
        return 1; /* FAILED */
#endif /* OPENSSL_NO_ECDH */

    return 0; /* OK */
}

/**************************************** cleanup TLS context */

/*
 * free anything allocate from context_init() and callbacks
 * also free any cached data allocated in client.c
 */
void context_cleanup(SERVICE_OPTIONS *section) {
    s_log(LOG_DEBUG, "Cleaning up context [%s]", section->servname);

#ifndef OPENSSL_NO_OCSP
    ocsp_cleanup(section);
#endif /* !defined(OPENSSL_NO_OCSP) */
    str_free(section->chain);
    if(section->session)
        SSL_SESSION_free(section->session);
    if(section->ctx)
        SSL_CTX_free(section->ctx);
}

/**************************************** SNI callback */

#ifndef OPENSSL_NO_TLSEXT

NOEXPORT int servername_cb(SSL *ssl, int *ad, void *arg) {
    const char *servername=SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    CLI *c=SSL_get_ex_data(ssl, index_ssl_cli);
    SERVERNAME_LIST *list;

    /* leave the alert type at SSL_AD_UNRECOGNIZED_NAME */
    (void)ad; /* squash the unused parameter warning */
    (void)arg; /* squash the unused parameter warning */

    /* handle trivial cases first */
    if(!c->opt->servername_list_head) {
        s_log(LOG_DEBUG, "SNI: no virtual services defined");
        return SSL_TLSEXT_ERR_OK;
    }
    if(!servername) {
        s_log(LOG_NOTICE, "SNI: no servername received");
        return SSL_TLSEXT_ERR_NOACK;
    }

    /* find a matching section */
    s_log(LOG_INFO, "SNI: requested servername: %s", servername);
    for(list=c->opt->servername_list_head; list; list=list->next)
        if(matches_wildcard(servername, list->servername))
            break;
    if(!list) {
        s_log(LOG_ERR, "SNI: no pattern matched servername: %s", servername);
        return SSL_TLSEXT_ERR_OK;
    }
    s_log(LOG_DEBUG, "SNI: matched pattern: %s", list->servername);

    /* switch to the new section */
#ifndef USE_FORK
    service_up_ref(list->opt);
    service_free(c->opt);
#endif
    c->opt=list->opt;
    SSL_set_SSL_CTX(ssl, c->opt->ctx);
    SSL_set_verify(ssl, SSL_CTX_get_verify_mode(c->opt->ctx),
        SSL_CTX_get_verify_callback(c->opt->ctx));
    s_log(LOG_NOTICE, "SNI: switched to service [%s]", c->opt->servname);
#ifdef USE_LIBWRAP
    libwrap_auth(c); /* retry on a service switch */
#endif /* USE_LIBWRAP */
    return SSL_TLSEXT_ERR_OK;
}
/* TLSEXT callback return codes:
 *  - SSL_TLSEXT_ERR_OK
 *  - SSL_TLSEXT_ERR_ALERT_WARNING
 *  - SSL_TLSEXT_ERR_ALERT_FATAL
 *  - SSL_TLSEXT_ERR_NOACK */

NOEXPORT int matches_wildcard(const char *servername, const char *pattern) {
    if(!servername || !pattern)
        return 0;
    if(*pattern=='*') { /* wildcard comparison */
        ssize_t diff=(ssize_t)strlen(servername)-((ssize_t)strlen(pattern)-1);
        if(diff<0) /* pattern longer than servername */
            return 0;
        return !strcasecmp(servername+diff, pattern+1);
    } else { /* string comparison */
        return !strcasecmp(servername, pattern);
    }
}

#endif /* OPENSSL_NO_TLSEXT */

/**************************************** DH initialization */

#ifndef OPENSSL_NO_DH

#if OPENSSL_VERSION_NUMBER<0x10100000L
NOEXPORT STACK_OF(SSL_CIPHER) *SSL_CTX_get_ciphers(const SSL_CTX *ctx) {
    return ctx->cipher_list;
}
#endif

NOEXPORT int dh_init(SERVICE_OPTIONS *section) {
    DH *dh=NULL;
    int i, n;
    char description[128];
    STACK_OF(SSL_CIPHER) *ciphers;

    section->option.dh_temp_params=0; /* disable by default */

    /* check if DH is needed for this section */
    if(section->option.client) {
        s_log(LOG_INFO, "DH initialization skipped: client section");
        return 0; /* OK */
    }
    ciphers=SSL_CTX_get_ciphers(section->ctx);
    if(!ciphers)
        return 1; /* ERROR (unlikely) */
    n=sk_SSL_CIPHER_num(ciphers);
    for(i=0; i<n; ++i) {
        *description='\0';
        SSL_CIPHER_description(sk_SSL_CIPHER_value(ciphers, i),
            description, sizeof description);
        /* s_log(LOG_INFO, "Ciphersuite: %s", description); */
        if(strstr(description, " Kx=DH")) {
            s_log(LOG_INFO, "DH initialization needed for %s",
                SSL_CIPHER_get_name(sk_SSL_CIPHER_value(ciphers, i)));
            break;
        }
    }
    if(i==n) { /* no DH ciphers found */
        s_log(LOG_INFO, "DH initialization skipped: no DH ciphersuites");
        return 0; /* OK */
    }

    s_log(LOG_DEBUG, "DH initialization");
#ifndef OPENSSL_NO_ENGINE
    if(!section->engine) /* cert is a file and not an identifier */
#endif
        dh=dh_read(section->cert);
    if(dh) {
        SSL_CTX_set_tmp_dh(section->ctx, dh);
        s_log(LOG_INFO, "%d-bit DH parameters loaded", 8*DH_size(dh));
        DH_free(dh);
        return 0; /* OK */
    }
    CRYPTO_THREAD_read_lock(stunnel_locks[LOCK_DH]);
    SSL_CTX_set_tmp_dh(section->ctx, dh_params);
    CRYPTO_THREAD_unlock(stunnel_locks[LOCK_DH]);
    dh_temp_params=1; /* generate temporary DH parameters in cron */
    section->option.dh_temp_params=1; /* update this section in cron */
    s_log(LOG_INFO, "Using dynamic DH parameters");
    return 0; /* OK */
}

NOEXPORT DH *dh_read(char *cert) {
    DH *dh;
    BIO *bio;

    if(!cert) {
        s_log(LOG_DEBUG, "No certificate available to load DH parameters");
        return NULL; /* FAILED */
    }
    bio=BIO_new_file(cert, "r");
    if(!bio) {
        sslerror("BIO_new_file");
        return NULL; /* FAILED */
    }
    dh=PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if(!dh) {
        while(ERR_get_error())
            ; /* OpenSSL error queue cleanup */
        s_log(LOG_DEBUG, "Could not load DH parameters from %s", cert);
        return NULL; /* FAILED */
    }
    s_log(LOG_DEBUG, "Using DH parameters from %s", cert);
    return dh;
}

#endif /* OPENSSL_NO_DH */

/**************************************** ECDH initialization */

#ifndef OPENSSL_NO_ECDH

#if OPENSSL_VERSION_NUMBER < 0x10101000L
/* simplified version that only supports a single curve */
NOEXPORT int SSL_CTX_set1_groups_list(SSL_CTX *ctx, char *list) {
    int nid;
    EC_KEY *ecdh;

    nid=OBJ_txt2nid(list);
    if(nid==NID_undef) {
        s_log(LOG_ERR, "Unsupported curve: %s", list);
        return 0; /* FAILED */
    }
    ecdh=EC_KEY_new_by_curve_name(nid);
    if(!ecdh) {
        sslerror("EC_KEY_new_by_curve_name");
        return 0; /* FAILED */
    }
    if(!SSL_CTX_set_tmp_ecdh(ctx, ecdh)) {
        sslerror("SSL_CTX_set_tmp_ecdhSSL_CTX_set_tmp_ecdh");
        EC_KEY_free(ecdh);
        return 0; /* FAILED */
    }
    EC_KEY_free(ecdh);
    return 1; /* OK */
}
#endif /* OpenSSL version < 1.1.1 */

NOEXPORT int ecdh_init(SERVICE_OPTIONS *section) {
    s_log(LOG_DEBUG, "ECDH initialization");
    if(!SSL_CTX_set1_groups_list(section->ctx, section->curves)) {
        s_log(LOG_ERR, "Invalid groups list in 'curves'");
        return 1; /* FAILED */
    }
    s_log(LOG_DEBUG, "ECDH initialized with curves %s", section->curves);
    return 0; /* OK */
}

#endif /* OPENSSL_NO_ECDH */

/**************************************** initialize OpenSSL CONF */

NOEXPORT int conf_init(SERVICE_OPTIONS *section) {
#if OPENSSL_VERSION_NUMBER>=0x10002000L
    SSL_CONF_CTX *cctx;
    NAME_LIST *curr;
    char *cmd, *param;

    if(!section->config)
        return 0; /* OK */
    cctx=SSL_CONF_CTX_new();
    if(!cctx) {
        sslerror("SSL_CONF_CTX_new");
        return 1; /* FAILED */
    }
    SSL_CONF_CTX_set_ssl_ctx(cctx, section->ctx);
    SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_FILE);
    SSL_CONF_CTX_set_flags(cctx, section->option.client ?
        SSL_CONF_FLAG_CLIENT : SSL_CONF_FLAG_SERVER);
    SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_CERTIFICATE);

    for(curr=section->config; curr; curr=curr->next) {
        cmd=str_dup(curr->name);
        param=strchr(cmd, ':');
        if(param)
            *param++='\0';
        switch(SSL_CONF_cmd(cctx, cmd, param)) {
        case 2:
            s_log(LOG_DEBUG, "OpenSSL config \"%s\" set to \"%s\"", cmd, param);
            break;
        case 1:
            s_log(LOG_DEBUG, "OpenSSL config command \"%s\" executed", cmd);
            break;
        case -2:
            s_log(LOG_ERR,
                "OpenSSL config command \"%s\" was not recognised", cmd);
            str_free(cmd);
            SSL_CONF_CTX_free(cctx);
            return 1; /* FAILED */
        case -3:
            s_log(LOG_ERR,
                "OpenSSL config command \"%s\" requires a parameter", cmd);
            str_free(cmd);
            SSL_CONF_CTX_free(cctx);
            return 1; /* FAILED */
        default:
            sslerror("SSL_CONF_cmd");
            str_free(cmd);
            SSL_CONF_CTX_free(cctx);
            return 1; /* FAILED */
        }
        str_free(cmd);
    }

    if(!SSL_CONF_CTX_finish(cctx)) {
        sslerror("SSL_CONF_CTX_finish");
        SSL_CONF_CTX_free(cctx);
        return 1; /* FAILED */
    }
    SSL_CONF_CTX_free(cctx);
#else /* OpenSSL earlier than 1.0.2 */
    (void)section; /* squash the unused parameter warning */
#endif /* OpenSSL 1.0.2 or later */
    return 0; /* OK */
}

/**************************************** initialize authentication */

NOEXPORT int auth_init(SERVICE_OPTIONS *section) {
    int cert_needed=1, key_needed=1;

    /* initialize PSK */
#ifndef OPENSSL_NO_PSK
    if(section->psk_keys) {
        if(section->option.client)
            SSL_CTX_set_psk_client_callback(section->ctx, psk_client_callback);
        else
            SSL_CTX_set_psk_server_callback(section->ctx, psk_server_callback);
    }
#endif /* !defined(OPENSSL_NO_PSK) */

    /* initialize the client cert engine */
#if !defined(OPENSSL_NO_ENGINE) && OPENSSL_VERSION_NUMBER>=0x0090809fL
    /* SSL_CTX_set_client_cert_engine() was introduced in OpenSSL 0.9.8i */
    if(section->option.client && section->engine) {
        if(SSL_CTX_set_client_cert_engine(section->ctx, section->engine)) {
            s_log(LOG_INFO, "Client certificate engine (%s) enabled",
                ENGINE_get_id(section->engine));
        } else { /* no client certificate functionality in this engine */
            while(ERR_get_error())
                ; /* OpenSSL error queue cleanup */
            s_log(LOG_INFO, "Client certificate engine (%s) not supported",
                ENGINE_get_id(section->engine));
        }
    }
#endif

    /* load the certificate and private key */
    if(!section->cert || !section->key) {
        s_log(LOG_DEBUG, "No certificate or private key specified");
        return 0; /* OK */
    }
#ifndef OPENSSL_NO_ENGINE
    if(section->engine) { /* try to use the engine first */
        cert_needed=load_cert_engine(section);
        key_needed=load_key_engine(section);
    }
#endif
#if OPENSSL_VERSION_NUMBER>=0x10101000L
    if(load_objects(section, cert_needed, key_needed))
        return 1; /* FAILED */
#else /* OpenSSL 1.1.1 or later */
    if(cert_needed && pkcs12_extension(section->cert)) {
        if(load_pkcs12_file(section)) {
            return 1; /* FAILED */
        }
        cert_needed=key_needed=0; /* don't load any PEM files */
    }
    if(cert_needed && load_cert_file(section))
        return 1; /* FAILED */
    if(key_needed && load_key_file(section))
        return 1; /* FAILED */
#endif /* OpenSSL 1.1.1 or later */

    /* validate the private key against the certificate */
    if(!SSL_CTX_check_private_key(section->ctx)) {
        sslerror("Private key does not match the certificate");
        return 1; /* FAILED */
    }
    s_log(LOG_DEBUG, "Private key check succeeded");
    return 0; /* OK */
}

#ifndef OPENSSL_NO_PSK

NOEXPORT unsigned psk_client_callback(SSL *ssl, const char *hint,
    char *identity, unsigned max_identity_len,
    unsigned char *psk, unsigned max_psk_len) {
    CLI *c;
    size_t identity_len;

    (void)hint; /* squash the unused parameter warning */
    c=SSL_get_ex_data(ssl, index_ssl_cli);
    if(!c->opt->psk_selected) {
        s_log(LOG_ERR, "INTERNAL ERROR: No PSK identity selected");
        return 0;
    }
    /* the source seems to have its buffer large enough for
     * the trailing null character, but the manual page says
     * nothing about it -- lets play safe */
    identity_len=strlen(c->opt->psk_selected->identity)+1;
    if(identity_len>max_identity_len) {
        s_log(LOG_ERR, "PSK identity too long (%lu>%d bytes)",
            (long unsigned)identity_len, max_psk_len);
        return 0;
    }
    if(c->opt->psk_selected->key_len>max_psk_len) {
        s_log(LOG_ERR, "PSK too long (%lu>%d bytes)",
            (long unsigned)c->opt->psk_selected->key_len, max_psk_len);
        return 0;
    }
    strcpy(identity, c->opt->psk_selected->identity);
    memcpy(psk, c->opt->psk_selected->key_val, c->opt->psk_selected->key_len);
    s_log(LOG_INFO, "PSK client configured for identity \"%s\"", identity);
    return (unsigned)(c->opt->psk_selected->key_len);
}

NOEXPORT unsigned psk_server_callback(SSL *ssl, const char *identity,
    unsigned char *psk, unsigned max_psk_len) {
    CLI *c;
    PSK_KEYS *found;

    c=SSL_get_ex_data(ssl, index_ssl_cli);
    found=psk_find(&c->opt->psk_sorted, identity);
    if(!found) {
        const char *c=identity;
        while(*c && isprint((unsigned char)*c))
            c++;
        if(*c)
            s_log(LOG_INFO, "PSK identity not found (session resumption?)");
        else
            s_log(LOG_INFO, "PSK identity not found: %s", identity);
        return 0;
    }
    if(found->key_len>max_psk_len) {
        s_log(LOG_ERR, "PSK too long (%u>%u)", found->key_len, max_psk_len);
        return 0;
    }
    memcpy(psk, found->key_val, found->key_len);
    s_log(LOG_NOTICE, "Key configured for PSK identity \"%s\"", identity);
    c->flag.psk_found=1;
    return found->key_len;
}

NOEXPORT int psk_compar(const void *a, const void *b) {
    const PSK_KEYS *x=*(PSK_KEYS *const*)a, *y=*(PSK_KEYS *const*)b;

#if 0
    s_log(LOG_DEBUG, "PSK cmp: %s %s", x->identity, y->identity);
#endif
    return strcmp(x->identity, y->identity);
}

void psk_sort(PSK_TABLE *table, PSK_KEYS *head) {
    PSK_KEYS *curr;
    size_t i;

    table->num=0;
    for(curr=head; curr; curr=curr->next)
        ++table->num;
    s_log(LOG_INFO, "PSK identities: %lu retrieved",
        (long unsigned)table->num);
    table->val=str_alloc_detached(table->num*sizeof(PSK_KEYS *));
    for(curr=head, i=0; i<table->num; ++i) {
        table->val[i]=curr;
        curr=curr->next;
    }
    qsort(table->val, table->num, sizeof(PSK_KEYS *), psk_compar);
#if 0
    for(i=0; i<table->num; ++i)
        s_log(LOG_DEBUG, "PSK table: %s", table->val[i]->identity);
#endif
}

PSK_KEYS *psk_find(const PSK_TABLE *table, const char *identity) {
    PSK_KEYS key, *ptr=&key, **ret;

    key.identity=identity;
    ret=bsearch(&ptr,
        table->val, table->num, sizeof(PSK_KEYS *), psk_compar);
    return ret ? *ret : NULL;
}

#endif /* !defined(OPENSSL_NO_PSK) */

#if OPENSSL_VERSION_NUMBER<0x10101000L

NOEXPORT int pkcs12_extension(const char *filename) {
    const char *ext=strrchr(filename, '.');
    return ext && (!strcasecmp(ext, ".p12") || !strcasecmp(ext, ".pfx"));
}

NOEXPORT int load_pkcs12_file(SERVICE_OPTIONS *section) {
    size_t len;
    int i, success;
    BIO *bio=NULL;
    PKCS12 *p12=NULL;
    X509 *cert=NULL;
    STACK_OF(X509) *ca=NULL;
    EVP_PKEY *pkey=NULL;
    char pass[PEM_BUFSIZE];

    s_log(LOG_INFO, "Loading certificate and private key from file: %s",
        section->cert);
    if(file_permissions(section->cert))
        return 1; /* FAILED */

    bio=BIO_new_file(section->cert, "rb");
    if(!bio) {
        sslerror("BIO_new_file");
        return 1; /* FAILED */
    }
    p12=d2i_PKCS12_bio(bio, NULL);
    if(!p12) {
        sslerror("d2i_PKCS12_bio");
        BIO_free(bio);
        return 1; /* FAILED */
    }
    BIO_free(bio);

    /* try the cached value first */
    set_prompt(section->cert);
    len=(size_t)cache_passwd_get_cb(pass, sizeof pass, 0, NULL);
    if(len>=sizeof pass)
        len=sizeof pass-1;
    pass[len]='\0'; /* null-terminate */
    success=PKCS12_parse(p12, pass, &pkey, &cert, &ca);

    /* invoke the UI */
    for(i=0; !success && i<3; i++) {
        if(!ui_retry())
            break;
        if(i>0)
            s_log(LOG_ERR, "Wrong passphrase: retrying");

        /* invoke the UI on subsequent calls */
        len=(size_t)cache_passwd_set_cb(pass, sizeof pass, 0, NULL);
        if(len>=sizeof pass)
            len=sizeof pass-1;
        pass[len]='\0'; /* null-terminate */
        success=PKCS12_parse(p12, pass, &pkey, &cert, &ca);
    }
    if(!success) {
        sslerror("PKCS12_parse");
        PKCS12_free(p12);
        return 1; /* FAILED */
    }

    PKCS12_free(p12);

    if(!SSL_CTX_use_certificate(section->ctx, cert)) {
        sslerror("SSL_CTX_use_certificate");
        return 1; /* FAILED */
    }
    if(!SSL_CTX_use_PrivateKey(section->ctx, pkey)) {
        sslerror("SSL_CTX_use_PrivateKey");
        return 1; /* FAILED */
    }
#if OPENSSL_VERSION_NUMBER>=0x10002000L
    if(!SSL_CTX_set0_chain(section->ctx, ca)) {
        sslerror("SSL_CTX_set0_chain");
        return 1; /* FAILED */
    }
#else /* OPENSSL_VERSION_NUMBER>=0x10002000L */
    /* FIXME: implement for OpenSSL older than 1.0.2 */
#if 0
    /* struct cert_st is private, so the following code won't build */
    if(section->ctx->cert->key->chain)
        sk_X509_pop_free(section->ctx->cert->key->chain, X509_free);
    section->ctx->cert->key->chain=ca;
#endif
    sk_X509_pop_free(ca, X509_free); /* just free the memory */
#endif /* OPENSSL_VERSION_NUMBER>=0x10002000L */
    s_log(LOG_INFO, "Certificate and private key loaded from file: %s",
        section->cert);
    return 0; /* OK */
}

NOEXPORT int load_cert_file(SERVICE_OPTIONS *section) {
    s_log(LOG_INFO, "Loading certificate from file: %s", section->cert);
    if(!SSL_CTX_use_certificate_chain_file(section->ctx, section->cert)) {
        sslerror("SSL_CTX_use_certificate_chain_file");
        return 1; /* FAILED */
    }
    s_log(LOG_INFO, "Certificate loaded from file: %s", section->cert);
    return 0; /* OK */
}

NOEXPORT int load_key_file(SERVICE_OPTIONS *section) {
    int i, success;

    s_log(LOG_INFO, "Loading private key from file: %s", section->key);
    if(file_permissions(section->key))
        return 1; /* FAILED */

    /* try the cached value first */
    set_prompt(section->key);
    SSL_CTX_set_default_passwd_cb(section->ctx, cache_passwd_get_cb);
    success=SSL_CTX_use_PrivateKey_file(section->ctx, section->key,
        SSL_FILETYPE_PEM);
    /* invoke the UI on subsequent calls */
    SSL_CTX_set_default_passwd_cb(section->ctx, cache_passwd_set_cb);

    /* invoke the UI */
    for(i=0; !success && i<3; i++) {
        if(!ui_retry())
            break;
        if(i>0)
            s_log(LOG_ERR, "Wrong passphrase: retrying");

        success=SSL_CTX_use_PrivateKey_file(section->ctx, section->key,
            SSL_FILETYPE_PEM);
    }
    if(!success) {
        sslerror("SSL_CTX_use_PrivateKey_file");
        return 1; /* FAILED */
    }
    s_log(LOG_INFO, "Private key loaded from file: %s", section->key);
    return 0; /* OK */
}

#endif /* OpenSSL older than 1.1.1 */

#ifndef OPENSSL_NO_ENGINE

NOEXPORT int load_cert_engine(SERVICE_OPTIONS *section) {
    X509 *cert;

    s_log(LOG_INFO, "Loading certificate from engine ID: %s", section->cert);
    cert=engine_get_cert(section->engine, section->cert);
    if(!cert)
        return 1; /* FAILED */
    if(!SSL_CTX_use_certificate(section->ctx, cert)) {
        sslerror("SSL_CTX_use_certificate");
        X509_free(cert);
        return 1; /* FAILED */
    }
    s_log(LOG_INFO, "Certificate loaded from engine ID: %s", section->cert);
    X509_free(cert);
    return 0; /* OK */
}

#endif /* !defined(OPENSSL_NO_ENGINE) */

#if !defined(OPENSSL_NO_ENGINE) || OPENSSL_VERSION_NUMBER>=0x10101000L

NOEXPORT void clear_cached_password(PW_CB_DATA *cb_data) {
    char *previous=(char *)cb_data->password;

    cb_data->password=NULL;
    if(previous) {
        OPENSSL_cleanse(previous, strlen(previous));
        str_free(previous);
    }
}

#if OPENSSL_VERSION_NUMBER>=0x10000000L
NOEXPORT char *ui_prompt_constructor(UI *ui,
        const char *phrase_desc, const char *object_name) {
    PW_CB_DATA *cb_data=UI_get0_user_data(ui);

    if(!phrase_desc) {
        if(cb_data->prompt_info && is_prefix(cb_data->prompt_info, "pkcs11:"))
            phrase_desc="PIN";
        else
            phrase_desc="passphrase";
    }
    if(!object_name && cb_data)
        object_name=cb_data->prompt_info;
    return UI_construct_prompt(NULL, phrase_desc, object_name);
}
#endif /* OPENSSL_VERSION_NUMBER>=0x10000000L */

NOEXPORT int ui_caching_reader(UI *ui, UI_STRING *uis) {
    PW_CB_DATA *cb_data=UI_get0_user_data(ui);
    int (*reader)(UI *, UI_STRING *);

    /* return the cached password if available */
    if(cb_data && cb_data->password) {
        /* Set user_data password */
        if(UI_set_result(ui, uis, cb_data->password) < 0)
            s_log(LOG_DEBUG, "Failed to set the cached password");
        else
            return 1; /* OK */
    }

    /* invoke the UI if available */
    reader=ui_get_reader();
    if(reader) {
        const char *result;

        if(!reader(ui, uis))
            return 0; /* FAILED */
        result=UI_get0_result_string(uis);
        if(result && *result) {
            clear_cached_password(cb_data);
            cb_data->password=str_dup(result);
            s_log(LOG_DEBUG, "Password cached");
        }
        return 1; /* OK */
    }

    /* default to the empty password if we've got nothing better */
    s_log(LOG_DEBUG, "No reader available, using empty password");
    if(UI_set_result(ui, uis, "") < 0) {
        s_log(LOG_DEBUG, "Failed to set empty password");
        return 0; /* FAILED */
    }
    return 1; /* OK */
}

UI_METHOD *ui_stunnel(void) {
    static UI_METHOD *ui_method=NULL;

    if(ui_method) /* already initialized */
        return ui_method;
    ui_method=UI_create_method("stunnel UI");
    if(!ui_method) {
        sslerror("UI_create_method");
        return NULL;
    }
#if OPENSSL_VERSION_NUMBER>=0x10000000L
    UI_method_set_prompt_constructor(ui_method, ui_prompt_constructor);
#endif /* OPENSSL_VERSION_NUMBER>=0x10000000L */
    UI_method_set_opener(ui_method, ui_get_opener());
    UI_method_set_writer(ui_method, ui_get_writer());
    UI_method_set_reader(ui_method, ui_caching_reader);
    UI_method_set_closer(ui_method, ui_get_closer());
    return ui_method;
}

#endif /* !defined(OPENSSL_NO_ENGINE) || OPENSSL_VERSION_NUMBER>=0x10101000L */

#ifndef OPENSSL_NO_ENGINE

NOEXPORT int load_key_engine(SERVICE_OPTIONS *section) {
    int i;
    EVP_PKEY *pkey;

    s_log(LOG_INFO, "Initializing private key on engine ID: %s", section->key);

    /* do not use caching for engine PINs to prevent device lockout */
    SSL_CTX_set_default_passwd_cb(section->ctx, ui_passwd_cb);

    for(i=0; i<3; i++) {
        pkey=ENGINE_load_private_key(section->engine, section->key,
            ui_stunnel(), NULL);
        if(!pkey) {
            if(i<2 && ui_retry()) { /* wrong PIN */
                s_log(LOG_ERR, "Wrong PIN: retrying");
                continue;
            }
            sslerror("ENGINE_load_private_key");
            return 1; /* FAILED */
        }
        if(SSL_CTX_use_PrivateKey(section->ctx, pkey))
            break; /* success */
        sslerror("SSL_CTX_use_PrivateKey");
        return 1; /* FAILED */
    }
    s_log(LOG_INFO, "Private key initialized on engine ID: %s", section->key);
    return 0; /* OK */
}

#endif /* !defined(OPENSSL_NO_ENGINE) */

#if OPENSSL_VERSION_NUMBER>=0x10101000L

NOEXPORT int load_objects(SERVICE_OPTIONS *section, int cert_needed, int key_needed) {

    if(!strcmp(section->cert, section->key)) {
        /* Try to open store from section->cert resource and get all objects */
        if(!load_objects_from_store(section->ctx, section->cert, cert_needed, key_needed))
            return 1; /* FAILED */
    } else {
        /* Try to open store from section->key resource and get the private key */
        if(key_needed && !load_objects_from_store(section->ctx, section->key, 0, key_needed))
            return 1; /* FAILED */
        /* Try to open store from section->cert resource and get certificates */
        if(cert_needed && !load_objects_from_store(section->ctx, section->cert, cert_needed, 0))
            return 1; /* FAILED */
    }
    return 0; /* OK */
}

NOEXPORT int load_objects_from_store(SSL_CTX *ctx, const char *uri,
        int cert_needed, int key_needed) {
    static PW_CB_DATA cb_data={NULL, NULL};
    int i=0;

    cb_data.prompt_info=uri;
    ERR_clear_error(); /* PROV_R_MISSING_CONFIG_DATA OpenSSL 3.5.0 */
    for(;;) {
        OSSL_STORE_CTX *store_ctx;

        store_ctx=OSSL_STORE_open(uri, ui_stunnel(), &cb_data, NULL, NULL);
        if(store_ctx) {
            while(!OSSL_STORE_eof(store_ctx)) {
                OSSL_STORE_INFO *object=OSSL_STORE_load(store_ctx);
                int store_type;

                if(!object)
                    continue;
                store_type=OSSL_STORE_INFO_get_type(object);
                switch(store_type) {
                case OSSL_STORE_INFO_PKEY:
                    if(key_needed) { /* found the first private key */
                        if(!SSL_CTX_use_PrivateKey(ctx,
                                OSSL_STORE_INFO_get0_PKEY(object))) {
                            sslerror("SSL_CTX_use_PrivateKey");
                            OSSL_STORE_INFO_free(object);
                            OSSL_STORE_close(store_ctx);
                            return 0; /* FAILED */
                        }
                        s_log(LOG_INFO, "Private key loaded from: %s", uri);
                        key_needed=0;
                    }
                    /* skip any private keys after the first one was loaded */
                    break;
                case OSSL_STORE_INFO_CERT:
                    if(cert_needed) { /* found the first certificate */
                        if(!SSL_CTX_use_certificate(ctx,
                                OSSL_STORE_INFO_get0_CERT(object))) {
                            sslerror("SSL_CTX_use_certificate");
                            OSSL_STORE_INFO_free(object);
                            OSSL_STORE_close(store_ctx);
                            return 0; /* FAILED */
                        }
                        s_log(LOG_INFO, "Certificate loaded from: %s", uri);
                        cert_needed=0;
                    } else { /* found a subsequent certificate */
                        /* add it to the certificate chain */
                        if(!SSL_CTX_add1_chain_cert(ctx,
                                OSSL_STORE_INFO_get0_CERT(object))) {
                            sslerror("SSL_CTX_add1_chain_cert");
                            OSSL_STORE_INFO_free(object);
                            OSSL_STORE_close(store_ctx);
                            return 0; /* FAILED */
                        }
                    }
                    break;
                default:
                    break; /* skip any other type */
                }
                OSSL_STORE_INFO_free(object);
            }
            OSSL_STORE_close(store_ctx);
        }

        if(!cert_needed && !key_needed) { /* all done */
            ERR_clear_error();
            return 1; /* OK */
        }

        /* this attempt has failed, so the cached password
         * should not be used for the next attempt */
        clear_cached_password(&cb_data);
        s_log(LOG_DEBUG, "Cached password cleared");

        if(!ui_retry()) { /* process the error queue first */
            s_log(LOG_ERR, "Unrecoverable error: giving up");
            break;
        }

        if(++i>=3) { /* allow up to 3 attempts */
            s_log(LOG_ERR, "Wrong password or PIN: giving up");
            break;
        }

        s_log(LOG_WARNING, "Wrong password or PIN: retrying");
    }
    if(cert_needed)
        s_log(LOG_ERR, "Failed to load certificate from: %s", uri);
    if(key_needed)
        s_log(LOG_ERR, "Failed to load private key from: %s", uri);
    return 0; /* FAILED */
}

#else /* OpenSSL 1.1.1 or later */

/* additional caching layer on top of ui_passwd_cb() */

/* retrieve the cached passwd */
NOEXPORT int cache_passwd_get_cb(char *buf, int size,
        int rwflag, void *userdata) {
    int len=cached_len;

    (void)rwflag; /* squash the unused parameter warning */
    (void)userdata; /* squash the unused parameter warning */
    if(len<0 || size<0) /* the API uses signed integers */
        return 0;
    if(len>size) /* truncate the returned data if needed */
        len=size;
    memcpy(buf, cached_passwd, (size_t)len);
    return len;
}

/* cache the passwd retrieved from UI */
NOEXPORT int cache_passwd_set_cb(char *buf, int size,
        int rwflag, void *userdata) {
    memset(cached_passwd, 0, sizeof cached_passwd);
    cached_len=ui_passwd_cb(cached_passwd, sizeof cached_passwd,
        rwflag, userdata);
    return cache_passwd_get_cb(buf, size, rwflag, userdata);
}

NOEXPORT void set_prompt(const char *name) {
    char *prompt;

    prompt=str_printf("Enter %s passphrase:", name);
    EVP_set_pw_prompt(prompt);
    str_free(prompt);
}

#endif /* OpenSSL 1.1.1 or later */

NOEXPORT int ui_retry(void) {
    typedef struct {
        int lib;
        int reason;
    } retriable;
    const retriable retriables[]={
        {ERR_LIB_EVP /* 6 */, EVP_R_BAD_DECRYPT},
        {ERR_LIB_PEM /* 9 */, PEM_R_BAD_PASSWORD_READ},
        {ERR_LIB_PEM /* 9 */, PEM_R_BAD_DECRYPT},
        {ERR_LIB_ASN1 /* 13 */, -1},
        {ERR_LIB_PKCS12 /* 35 */, PKCS12_R_MAC_VERIFY_FAILURE},
#ifdef ERR_LIB_DSO
        {ERR_LIB_DSO /* 37 */, -1},
#endif
        {ERR_LIB_UI /* 40 */, UI_R_RESULT_TOO_LARGE},
        {ERR_LIB_UI /* 40 */, UI_R_RESULT_TOO_SMALL},
#ifdef UI_R_PROCESSING_ERROR
        {ERR_LIB_UI /* 40 */, UI_R_PROCESSING_ERROR},
#endif
#ifdef ERR_LIB_OSSL_STORE /* OpenSSL 1.1.1 */
        {ERR_LIB_OSSL_STORE /* 44 */, OSSL_STORE_R_BAD_PASSWORD_READ},
        {ERR_LIB_OSSL_STORE /* 44 */, OSSL_STORE_R_ERROR_VERIFYING_PKCS12_MAC},
#endif
#ifdef ERR_LIB_PROV /* OpenSSL 3.0 */
        {ERR_LIB_PROV /* 57 */, PROV_R_BAD_DECRYPT},
#endif
        /* libp11 hacks */
        {-1 /* libp11 */, 7 /* CKR_ARGUMENTS_BAD */},
        {-1 /* libp11 */, 0xa0 /* CKR_PIN_INCORRECT */},
        {0, 0}
    }, *r;
    char *errors[MAX_ERRORS];
    char *error_string;
    int i, retry=0;

    error_string=str_alloc(MAX_ERROR_LEN);
    for(i=0; i<MAX_ERRORS; i++) {
        unsigned long err=0;
        int line=0, flags=0, lib, reason;
        const char *file=NULL, *func=NULL, *data=NULL;

        /* pop an error from the error stack */
#if OPENSSL_VERSION_NUMBER>=0x30000000L
        err=ERR_get_error_all(&file, &line, &func, &data, &flags);
#else
        err=ERR_get_error_line(&file, &line);
#endif
        if(!err)
            break;

        /* save the error message for logging */
        ERR_error_string_n(err, error_string, MAX_ERROR_LEN);
        errors[i]=str_printf("ui_retry: %s%s%s:%d: %s%s%s",
            func && *func ? func : "",
            func && *func ? "@" : "",
            file, line, error_string,
            flags&ERR_TXT_STRING && data && *data ? ": " : "",
            flags&ERR_TXT_STRING && data && *data ? data : "");

        /* check whether this error should be retried */
        if(retry)
            continue; /* just save the remaining error messages */
        lib=ERR_GET_LIB(err);
        reason=ERR_GET_REASON(err);
        for(r=retriables; r->lib && r->reason; r++) {
            if(reason!=r->reason && r->reason!=-1)
                continue;
            if(lib==r->lib) {
                s_log(LOG_DEBUG, "ui_retry: retrying on lib=%d reason=%d",
                    lib, reason);
                retry=1;
                break;
            }
            if(r->lib==-1 && lib>=ERR_LIB_USER &&
                    !strcmp(ERR_lib_error_string(err), "PKCS#11 module")) {
                s_log(LOG_DEBUG, "ui_retry: retrying on lib=PKCS#11 reason=%d",
                    reason);
                retry=1;
                break;
            }
        }
        if(retry) /* we just decided to retry */
            continue;
        s_log(LOG_DEBUG, "ui_retry: giving up on lib=%d reason=%d",
            lib, reason);
    }
    str_free(error_string);
    ERR_clear_error(); /* in case more than MAX_ERRORS errors were collected */

    if(i==0) { /* there was no error in the queue */
        s_log(LOG_ERR, "ui_retry: giving up: No error");
    } else { /* log and free the collected error messages */
        while(i-->0) {
            s_log(LOG_ERR, "%s", errors[i]);
            str_free(errors[i]);
        }
    }

    return retry;
}

/**************************************** session tickets */

#if OPENSSL_VERSION_NUMBER >= 0x10101000L

typedef struct {
    void *session_authenticated;
#if 0
    SOCKADDR_UNION addr;
#endif
} TICKET_DATA;

NOEXPORT int generate_session_ticket_cb(SSL *ssl, void *arg) {
    SSL_SESSION *sess;
    TICKET_DATA ticket_data;
#if 0
    SOCKADDR_UNION *addr;
#endif
    int retval;

    (void)arg; /* squash the unused parameter warning */

    s_log(LOG_DEBUG, "Generate session ticket callback");

    sess=SSL_get1_session(ssl);
    if(!sess)
        return 0;
    memset(&ticket_data, 0, sizeof(TICKET_DATA));

    ticket_data.session_authenticated=
        SSL_SESSION_get_ex_data(sess, index_session_authenticated);

#if 0
    /* TODO: add remote_start() invocation here */
    CRYPTO_THREAD_read_lock(stunnel_locks[LOCK_ADDR]);
    addr=SSL_SESSION_get_ex_data(sess, index_session_connect_address);
    if(addr)
        memcpy(&ticket_data.addr, addr, (size_t)addr_len(addr));
    CRYPTO_THREAD_unlock(stunnel_locks[LOCK_ADDR]);
#endif

    retval=SSL_SESSION_set1_ticket_appdata(sess,
        &ticket_data, sizeof(TICKET_DATA));
    SSL_SESSION_free(sess);
    return retval;
}

NOEXPORT int decrypt_session_ticket_cb(SSL *ssl, SSL_SESSION *sess,
        const unsigned char *keyname, size_t keyname_len,
        SSL_TICKET_STATUS status, void *arg) {
    TICKET_DATA *ticket_data;
    size_t ticket_len;

    (void)ssl; /* squash the unused parameter warning */
    (void)keyname; /* squash the unused parameter warning */
    (void)keyname_len; /* squash the unused parameter warning */
    (void)arg; /* squash the unused parameter warning */

    s_log(LOG_DEBUG, "Decrypt session ticket callback");

    switch(status) {
    case SSL_TICKET_EMPTY:
    case SSL_TICKET_NO_DECRYPT:
        return SSL_TICKET_RETURN_IGNORE_RENEW;
    case SSL_TICKET_SUCCESS:
    case SSL_TICKET_SUCCESS_RENEW:
        break;
    default:
        return SSL_TICKET_RETURN_ABORT;
    }

    if(!SSL_SESSION_get0_ticket_appdata(sess,
            (void **)&ticket_data, &ticket_len)) {
        s_log(LOG_WARNING, "Failed to get ticket application data");
        return SSL_TICKET_RETURN_IGNORE_RENEW;
    }
    if(!ticket_data) {
        s_log(LOG_WARNING, "Invalid ticket application data value");
        return SSL_TICKET_RETURN_IGNORE_RENEW;
    }
    if(ticket_len != sizeof(TICKET_DATA)) {
        s_log(LOG_WARNING, "Invalid ticket application data length");
        return SSL_TICKET_RETURN_IGNORE_RENEW;
    }

    s_log(LOG_INFO, "Decrypted ticket for an authenticated session: %s",
        ticket_data->session_authenticated ? "yes" : "no");
    SSL_SESSION_set_ex_data(sess, index_session_authenticated,
        ticket_data->session_authenticated);

#if 0
    if(ticket_data->addr.sa.sa_family) {
        char *addr_txt;
        SOCKADDR_UNION *old_addr;

        addr_txt=s_ntop(&ticket_data->addr, addr_len(&ticket_data->addr));
        s_log(LOG_INFO, "Decrypted ticket persistence address: %s", addr_txt);
        str_free(addr_txt);
        CRYPTO_THREAD_write_lock(stunnel_locks[LOCK_ADDR]);
        old_addr=SSL_SESSION_get_ex_data(sess, index_session_connect_address);
        if(SSL_SESSION_set_ex_data(sess, index_session_connect_address, &ticket_data->addr)) {
            CRYPTO_THREAD_unlock(stunnel_locks[LOCK_ADDR]);
            str_free(old_addr); /* NULL pointers are ignored */
        } else { /* failed to store ticket_data->addr */
            CRYPTO_THREAD_unlock(stunnel_locks[LOCK_ADDR]);
            sslerror("SSL_SESSION_set_ex_data");
        }
    } else {
        s_log(LOG_INFO, "Decrypted ticket did not include a persistence address");
    }
#endif

    switch(status) {
    case SSL_TICKET_SUCCESS:
        return SSL_TICKET_RETURN_USE;
    case SSL_TICKET_SUCCESS_RENEW:
        return SSL_TICKET_RETURN_USE_RENEW;
    }
    return SSL_TICKET_RETURN_ABORT; /* it should never get executed */
}
#endif

#if OPENSSL_VERSION_NUMBER>=0x10000000L
NOEXPORT int ssl_tlsext_ticket_key_cb(SSL *ssl, unsigned char *key_name,
        unsigned char *iv, EVP_CIPHER_CTX *ctx, HMAC_CTX *hctx, int enc) {
    CLI *c;
    const EVP_CIPHER *cipher;
    int iv_len;

    (void)key_name; /* squash the unused parameter warning */
    s_log(LOG_DEBUG, "Session ticket processing callback");

    c=SSL_get_ex_data(ssl, index_ssl_cli);
    if(!HMAC_Init_ex(hctx, (const unsigned char *)(c->opt->ticket_mac->key_val),
        c->opt->ticket_mac->key_len, EVP_sha256(), NULL)) {
        s_log(LOG_ERR, "HMAC_Init_ex failed");
        return -1;
    }
    if(c->opt->ticket_key->key_len == 16)
        cipher=EVP_aes_128_cbc();
    else /* c->opt->ticket_key->key_len == 32 */
        cipher=EVP_aes_256_cbc();
    if(enc) { /* create new session */
        /* EVP_CIPHER_iv_length() returns 16 for either cipher EVP_aes_128_cbc() or EVP_aes_256_cbc() */
        iv_len=EVP_CIPHER_iv_length(cipher);
        if(RAND_bytes(iv, iv_len) <= 0) { /* RAND_bytes error */
            s_log(LOG_ERR, "RAND_bytes failed");
            return -1;
        }
        if(!EVP_EncryptInit_ex(ctx, cipher, NULL,
            (const unsigned char *)(c->opt->ticket_key->key_val), iv)) {
            s_log(LOG_ERR, "EVP_EncryptInit_ex failed");
            return -1;
        }
    } else /* retrieve session */
        if(!EVP_DecryptInit_ex(ctx, cipher, NULL,
            (const unsigned char *)(c->opt->ticket_key->key_val), iv)) {
            s_log(LOG_ERR, "EVP_DecryptInit_ex failed");
            return -1;
        }
    /* By default, in TLSv1.2 and below, a new session ticket */
    /* is not issued on a successful resumption. */
    /* In TLSv1.3 the default behaviour is to always issue a new ticket on resumption. */
    /* This behaviour can NOT be changed if this ticket key callback is in use! */
    if(strcmp(SSL_get_version(c->ssl), "TLSv1.3"))
        return 1; /* new session ticket is not issued */
    else
        return 2; /* session ticket should be replaced */
}
#endif /* OpenSSL 1.0.0 or later */

/**************************************** session callbacks */

NOEXPORT int sess_new_cb(SSL *ssl, SSL_SESSION *sess) {
    CLI *c;

    s_log(LOG_DEBUG, "New session callback");
    c=SSL_get_ex_data(ssl, index_ssl_cli);

    new_chain(c); /* new session -> we may have a new peer certificate chain */

    session_cache_save(c, sess);

    if(c->opt->option.sessiond)
        cache_new(ssl, sess);

    print_session_id("Session id", sess);

    return 0; /* the OpenSSL's manual is really bad -> use the source here */
}

#if OPENSSL_VERSION_NUMBER<0x0090800fL
NOEXPORT const unsigned char *SSL_SESSION_get_id(const SSL_SESSION *s,
        unsigned int *len) {
    if(len)
        *len=s->session_id_length;
    return (const unsigned char *)s->session_id;
}
#endif

void print_session_id(const char *txt, SSL_SESSION *sess) {
    const unsigned char *session_id;
    unsigned int session_id_length;
    char session_id_txt[2*SSL_MAX_SSL_SESSION_ID_LENGTH+1];

    session_id=SSL_SESSION_get_id(sess, &session_id_length);
    bin2hexstring(session_id, session_id_length,
        session_id_txt, sizeof session_id_txt);
    s_log(LOG_INFO, "%s: %s", txt, session_id_txt);
}

NOEXPORT void new_chain(CLI *c) {
    BIO *bio;
    int i, len;
    X509 *peer_cert;
    STACK_OF(X509) *sk;
    char *chain;

    if(c->opt->chain) /* already cached */
        return; /* this race condition is safe to ignore */
    bio=BIO_new(BIO_s_mem());
    if(!bio)
        return;
    sk=SSL_get_peer_cert_chain(c->ssl);
    for(i=0; sk && i<sk_X509_num(sk); i++) {
        peer_cert=sk_X509_value(sk, i);
        PEM_write_bio_X509(bio, peer_cert);
    }
    if(!sk || !c->opt->option.client) {
        peer_cert=SSL_get_peer_certificate(c->ssl);
        if(peer_cert) {
            PEM_write_bio_X509(bio, peer_cert);
            X509_free(peer_cert);
        }
    }
    len=BIO_pending(bio);
    if(len<=0) {
        s_log(LOG_INFO, "No peer certificate received");
        BIO_free(bio);
        return;
    }
    /* prevent automatic deallocation of the cached value */
    chain=str_alloc_detached((size_t)len+1);
    len=BIO_read(bio, chain, len);
    if(len<0) {
        s_log(LOG_ERR, "BIO_read failed");
        BIO_free(bio);
        str_free(chain);
        return;
    }
    chain[len]='\0';
    BIO_free(bio);
    c->opt->chain=chain; /* this race condition is safe to ignore */
    ui_new_chain(c->opt->section_number);
    s_log(LOG_DEBUG, "Peer certificate was cached (%d bytes)", len);
}

/* cache client sessions */
NOEXPORT void session_cache_save(CLI *c, SSL_SESSION *sess) {
    if(!c->opt->option.client || !sess)
        return;

#if OPENSSL_VERSION_NUMBER>=0x10101000L
    if(!SSL_SESSION_is_resumable(sess))
        return;
#endif

    CRYPTO_THREAD_write_lock(stunnel_locks[LOCK_SESSION]);

    /* save per-destination client session */
    if(c->opt->connect_session) {
        if(c->opt->connect_session[c->idx])
            SSL_SESSION_free(c->opt->connect_session[c->idx]);
        c->opt->connect_session[c->idx]=SSL_SESSION_dup(sess);
    }

    /* save fallback client session */
    if(c->opt->session)
        SSL_SESSION_free(c->opt->session);
    c->opt->session=SSL_SESSION_dup(sess);

    CRYPTO_THREAD_unlock(stunnel_locks[LOCK_SESSION]);
}

#if OPENSSL_VERSION_NUMBER<0x10101000L
NOEXPORT SSL_SESSION *SSL_SESSION_dup(SSL_SESSION *src) {
    int der_len;
    unsigned char *der_data;
    unsigned char *tmp;
    const unsigned char *const_tmp;
    SSL_SESSION *dst;

    der_len=i2d_SSL_SESSION(src, NULL);
    if(der_len<=0)
        return NULL;
    der_data=str_alloc((size_t)der_len);
    tmp=der_data;
    der_len=i2d_SSL_SESSION(src, &tmp);
    if(der_len<=0) {
        str_free(der_data);
        return NULL;
    }
    const_tmp=der_data;
    dst=d2i_SSL_SESSION(NULL, &const_tmp, der_len);
    str_free(der_data);
    return dst;
}
#endif

NOEXPORT SSL_SESSION *sess_get_cb(SSL *ssl,
#if OPENSSL_VERSION_NUMBER>=0x10100000L
        const
#endif
        unsigned char *key, int key_len, int *do_copy) {
    CLI *c;

    s_log(LOG_DEBUG, "Get session callback");
    *do_copy=0; /* allow the session to be freed automatically */
    c=SSL_get_ex_data(ssl, index_ssl_cli);
    if(c->opt->option.sessiond)
        return cache_get(ssl, key, key_len);
    return NULL; /* no session to resume */
}

NOEXPORT void sess_remove_cb(SSL_CTX *ctx, SSL_SESSION *sess) {
    SERVICE_OPTIONS *opt;

    s_log(LOG_DEBUG, "Remove session callback");
    opt=SSL_CTX_get_ex_data(ctx, index_ssl_ctx_opt);
    if(opt->option.sessiond)
        cache_remove(ctx, sess);
}

/**************************************** sessiond functionality */

#define CACHE_CMD_NEW     0x00
#define CACHE_CMD_GET     0x01
#define CACHE_CMD_REMOVE  0x02
#define CACHE_RESP_ERR    0x80
#define CACHE_RESP_OK     0x81

NOEXPORT void cache_new(SSL *ssl, SSL_SESSION *sess) {
    unsigned char *val, *val_tmp;
    ssize_t val_len;
    const unsigned char *session_id;
    unsigned int session_id_length;

    val_len=i2d_SSL_SESSION(sess, NULL);
    val_tmp=val=str_alloc((size_t)val_len);
    i2d_SSL_SESSION(sess, &val_tmp);

    session_id=SSL_SESSION_get_id(sess, &session_id_length);
    cache_transfer(SSL_get_SSL_CTX(ssl), CACHE_CMD_NEW,
        SSL_SESSION_get_timeout(sess),
        session_id, session_id_length, val, (size_t)val_len, NULL, NULL);
    str_free(val);
}

NOEXPORT SSL_SESSION *cache_get(SSL *ssl,
        const unsigned char *key, int key_len) {
    unsigned char *val=NULL;
    const unsigned char *val_tmp=NULL;
    ssize_t val_len=0;
    SSL_SESSION *sess;

    cache_transfer(SSL_get_SSL_CTX(ssl), CACHE_CMD_GET, 0,
        key, (size_t)key_len, NULL, 0, &val, (size_t *)&val_len);
    if(!val)
        return NULL;
    val_tmp=val;
    sess=d2i_SSL_SESSION(NULL, &val_tmp, (long)val_len);
    str_free(val);
    return sess;
}

NOEXPORT void cache_remove(SSL_CTX *ctx, SSL_SESSION *sess) {
    const unsigned char *session_id;
    unsigned int session_id_length;

    session_id=SSL_SESSION_get_id(sess, &session_id_length);
    cache_transfer(ctx, CACHE_CMD_REMOVE, 0,
        session_id, session_id_length, NULL, 0, NULL, NULL);
}

#define MAX_VAL_LEN 512
typedef struct {
    u_char version, type;
    u_short timeout;
    u_char key[SSL_MAX_SSL_SESSION_ID_LENGTH];
    u_char val[MAX_VAL_LEN];
} CACHE_PACKET;

NOEXPORT void cache_transfer(SSL_CTX *ctx, const u_char type,
        const long timeout,
        const u_char *key, const size_t key_len,
        const u_char *val, const size_t val_len,
        unsigned char **ret, size_t *ret_len) {
    char session_id_txt[2*SSL_MAX_SSL_SESSION_ID_LENGTH+1];
    const char *type_description[]={"new", "get", "remove"};
    SOCKET s;
    ssize_t len;
    struct timeval t;
    CACHE_PACKET *packet;
    SERVICE_OPTIONS *section;

    if(ret) /* set error as the default result if required */
        *ret=NULL;

    /* log the request information */
    bin2hexstring(key, key_len, session_id_txt, sizeof session_id_txt);
    s_log(LOG_INFO,
        "cache_transfer: request=%s, timeout=%ld, id=%s, length=%lu",
        type_description[type], timeout, session_id_txt, (long unsigned)val_len);

    /* allocate UDP packet buffer */
    if(key_len>SSL_MAX_SSL_SESSION_ID_LENGTH) {
        s_log(LOG_ERR, "cache_transfer: session id too big (%lu bytes)",
            (unsigned long)key_len);
        return;
    }
    if(val_len>MAX_VAL_LEN) {
        s_log(LOG_ERR, "cache_transfer: encoded session too big (%lu bytes)",
            (unsigned long)key_len);
        return;
    }
    packet=str_alloc(sizeof(CACHE_PACKET));

    /* setup packet */
    packet->version=1;
    packet->type=type;
    packet->timeout=htons((u_short)(timeout<64800?timeout:64800));/* 18 hours */
    memcpy(packet->key, key, key_len);
    if(val && val_len) /* only check it to make code analysis tools happy */
        memcpy(packet->val, val, val_len);

    /* create the socket */
    s=s_socket(AF_INET, SOCK_DGRAM, 0, 0, "cache_transfer: socket");
    if(s==INVALID_SOCKET) {
        str_free(packet);
        return;
    }

    /* retrieve pointer to the section structure of this ctx */
    section=SSL_CTX_get_ex_data(ctx, index_ssl_ctx_opt);
    if(sendto(s, (void *)packet,
#ifdef USE_WIN32
            (int)
#endif
            (sizeof(CACHE_PACKET)-MAX_VAL_LEN+val_len),
            0, &section->sessiond_addr.sa,
            addr_len(&section->sessiond_addr))<0) {
        sockerror("cache_transfer: sendto");
        closesocket(s);
        str_free(packet);
        return;
    }

    if(!ret || !ret_len) { /* no response is required */
        closesocket(s);
        str_free(packet);
        return;
    }

    /* set recvfrom timeout to 200ms */
    t.tv_sec=0;
    t.tv_usec=200;
    if(setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (void *)&t, sizeof t)<0) {
        sockerror("cache_transfer: setsockopt SO_RCVTIMEO");
        closesocket(s);
        str_free(packet);
        return;
    }

    /* retrieve response */
    len=recv(s, (void *)packet, sizeof(CACHE_PACKET), 0);
    closesocket(s);
    if(len<0) {
        int err=get_last_socket_error();

        if(err==S_EWOULDBLOCK || (S_EWOULDBLOCK!=S_EAGAIN && err==S_EAGAIN))
            s_log(LOG_INFO, "cache_transfer: recv timeout");
        else
            sockerror("cache_transfer: recv");
        str_free(packet);
        return;
    }

    /* parse results */
    if(len<(int)sizeof(CACHE_PACKET)-MAX_VAL_LEN || /* too short */
            packet->version!=1 || /* wrong version */
            safe_memcmp(packet->key, key, key_len)) { /* wrong session id */
        s_log(LOG_DEBUG, "cache_transfer: malformed packet received");
        str_free(packet);
        return;
    }
    if(packet->type!=CACHE_RESP_OK) {
        s_log(LOG_INFO, "cache_transfer: session not found");
        str_free(packet);
        return;
    }
    *ret_len=(size_t)len-(sizeof(CACHE_PACKET)-MAX_VAL_LEN);
    *ret=str_alloc(*ret_len);
    s_log(LOG_INFO, "cache_transfer: session found");
    memcpy(*ret, packet->val, *ret_len);
    str_free(packet);
}

/**************************************** informational callback */

NOEXPORT void info_callback(const SSL *ssl, int where, int ret) {
    CLI *c;
    SSL_CTX *ctx;
    const char *state_string;
#if OPENSSL_VERSION_NUMBER>=0x10100000L
    OSSL_HANDSHAKE_STATE state=SSL_get_state(ssl);
#else
    int state=SSL_get_state((SSL *)ssl);
#endif

    c=SSL_get_ex_data(ssl, index_ssl_cli);
    if(!c) {
        s_log(LOG_ERR,
            "INTERNAL ERROR: info_callback() called without CLI, state = %x",
            state);
        return;
    }
#if 0
    s_log(LOG_DEBUG, "state = %x", state);
#endif

        /* do not reset the TLS socket after a fatal alert */
    if(where & SSL_CB_ALERT && !strcmp(SSL_alert_type_string(ret), "F"))
        c->fatal_alert=1;

        /* log the client certificate request (if received) */
#ifndef SSL3_ST_CR_CERT_REQ_A
    if(state==TLS_ST_CR_CERT_REQ)
#else
    if(state==SSL3_ST_CR_CERT_REQ_A)
#endif
        print_CA_list("Received trusted client CA",
            SSL_get_client_CA_list(ssl));
#ifndef SSL3_ST_CR_SRVR_DONE_A
    if(state==TLS_ST_CR_SRVR_DONE)
#else
    if(state==SSL3_ST_CR_SRVR_DONE_A)
#endif
        if(!SSL_get_client_CA_list(ssl))
            s_log(LOG_INFO, "Client certificate not requested");

    /* prevent renegotiation DoS attack */
    if((where&SSL_CB_HANDSHAKE_DONE)
            && c->reneg_state==RENEG_INIT) {
        /* first (initial) handshake was completed, remember this,
         * so that further renegotiation attempts can be detected */
        c->reneg_state=RENEG_ESTABLISHED;
    } else if((where&SSL_CB_ACCEPT_LOOP)
            && c->reneg_state==RENEG_ESTABLISHED) {
#ifndef SSL3_ST_SR_CLNT_HELLO_A
        if(state==TLS_ST_SR_CLNT_HELLO) {
#else
        if(state==SSL3_ST_SR_CLNT_HELLO_A
                || state==SSL23_ST_SR_CLNT_HELLO_A) {
#endif
            /* client hello received after initial handshake,
             * this means renegotiation -> mark it */
            c->reneg_state=RENEG_DETECTED;
        }
    }

    if(c->opt->log_level<LOG_DEBUG)
        return; /* performance optimization: skip logging debug info */

    if(where & SSL_CB_LOOP) {
        state_string=SSL_state_string_long(ssl);
        if(strcmp(state_string, "unknown state"))
            s_log(LOG_DEBUG, "TLS state (%s): %s",
                (where & SSL_ST_CONNECT) ? "connect" :
                (where & SSL_ST_ACCEPT) ? "accept" :
                "undefined", state_string);
    } else if(where & SSL_CB_ALERT) {
        s_log(LOG_DEBUG, "TLS alert (%s): %s: %s",
            (where & SSL_CB_READ) ? "read" : "write",
            SSL_alert_type_string_long(ret),
            SSL_alert_desc_string_long(ret));
    } else if(where==SSL_CB_HANDSHAKE_DONE) {
        ctx=SSL_get_SSL_CTX(ssl);
        if(c->opt->option.client) {
            s_log(LOG_DEBUG, "%6ld client connect(s) requested",
                SSL_CTX_sess_connect(ctx));
            s_log(LOG_DEBUG, "%6ld client connect(s) succeeded",
                SSL_CTX_sess_connect_good(ctx));
            s_log(LOG_DEBUG, "%6ld client renegotiation(s) requested",
                SSL_CTX_sess_connect_renegotiate(ctx));
        } else {
            s_log(LOG_DEBUG, "%6ld server accept(s) requested",
                SSL_CTX_sess_accept(ctx));
            s_log(LOG_DEBUG, "%6ld server accept(s) succeeded",
                SSL_CTX_sess_accept_good(ctx));
            s_log(LOG_DEBUG, "%6ld server renegotiation(s) requested",
                SSL_CTX_sess_accept_renegotiate(ctx));
        }
        /* according to the source it not only includes internal
           and external session caches, but also session tickets */
        s_log(LOG_DEBUG, "%6ld session reuse(s)",
            SSL_CTX_sess_hits(ctx));
        if(!c->opt->option.client) { /* server session cache stats */
            s_log(LOG_DEBUG, "%6ld internal session cache item(s)",
                SSL_CTX_sess_number(ctx));
            s_log(LOG_DEBUG, "%6ld internal session cache fill-up(s)",
                SSL_CTX_sess_cache_full(ctx));
            s_log(LOG_DEBUG, "%6ld internal session cache miss(es)",
                SSL_CTX_sess_misses(ctx));
            s_log(LOG_DEBUG, "%6ld external session cache hit(s)",
                SSL_CTX_sess_cb_hits(ctx));
            s_log(LOG_DEBUG, "%6ld expired session(s) retrieved",
                SSL_CTX_sess_timeouts(ctx));
        }
    }
}

/**************************************** TLS error reporting */

void sslerror(const char *txt) { /* OpenSSL error handler */
    char *errors[MAX_ERRORS];
    char *error_string;
    int i;

    error_string=str_alloc(MAX_ERROR_LEN);
    for(i=0; i<MAX_ERRORS; i++) {
        unsigned long err=0;
        const char *file=NULL, *func=NULL, *data=NULL;
        int line=0, flags=0;

#if OPENSSL_VERSION_NUMBER>=0x30000000L
        err=ERR_get_error_all(&file, &line, &func, &data, &flags);
#else
        err=ERR_get_error_line(&file, &line);
#endif
        if(!err) {
            if(txt && i==0)
                errors[i++]=str_printf("%s: Peer suddenly disconnected", txt);
            break;
        }

        ERR_error_string_n(err, error_string, MAX_ERROR_LEN);
        errors[i]=str_printf("%s: %s%s%s:%d: %s%s%s",
            txt && i==0 ? txt : "error queue",
            func && *func ? func : "",
            func && *func ? "@" : "",
            file, line, error_string,
            flags&ERR_TXT_STRING && data && *data ? ": " : "",
            flags&ERR_TXT_STRING && data && *data ? data : "");
    }
    str_free(error_string);
    ERR_clear_error();

    while(i-->0) {
        s_log(LOG_ERR, "%s", errors[i]);
        str_free(errors[i]);
    }
}

/**************************************** ciphersuites */
#ifndef OPENSSL_NO_TLS1_3
NOEXPORT char *compare_cipher_lists(STACK_OF(SSL_CIPHER) *list1, STACK_OF(SSL_CIPHER) *list2) {
    char *result=NULL;
    size_t result_len=0;
    int i;

    for(i=0; i<sk_SSL_CIPHER_num(list2); i++) {
        const SSL_CIPHER *cipher2=sk_SSL_CIPHER_value(list2, i);
        const char *cipher2_name=SSL_CIPHER_get_name(cipher2);
        int found=0;

        for(int j=0; j<sk_SSL_CIPHER_num(list1); j++) {
            const SSL_CIPHER *cipher1=sk_SSL_CIPHER_value(list1, j);
            const char *cipher1_name=SSL_CIPHER_get_name(cipher1);

            if(!strcmp(cipher2_name, cipher1_name)) {
                found=1;
                break;
            }
        }
        if(!found) {
            size_t name_len=strlen(cipher2_name);

            result=realloc(result, result_len + name_len + 2); /* +2 for ':' and '\0' */
            if(result_len == 0) {
                strcpy(result, cipher2_name);
            } else {
                strcat(result, ":");
                strcat(result, cipher2_name);
            }
            result_len+=name_len + 1; /* +1 for ':' */
        }
    }
    return result;
}

NOEXPORT char *get_tls13_cipher_list(STACK_OF(SSL_CIPHER) *list) {
    char *result=NULL;
    size_t result_len=0;
    int i;

    for(i=0; i<sk_SSL_CIPHER_num(list); i++) {
        const SSL_CIPHER *cipher=sk_SSL_CIPHER_value(list, i);

        if(!strcmp(SSL_CIPHER_get_version(cipher), "TLSv1.3")) {
            const char *cipher_name=SSL_CIPHER_get_name(cipher);
            size_t name_len=strlen(cipher_name);

            result=realloc(result, result_len + name_len + 2); /* +2 for ':' and '\0' */
            if(result_len == 0) {
                strcpy(result, cipher_name);
            } else {
                strcat(result, ":");
                strcat(result, cipher_name);
            }
            result_len+=name_len + 1; /* +1 for ':' */
        }
    }
    return result;
}
#endif /* TLS 1.3 */
/* end of ctx.c */
