/*
 *   stunnel       Universal SSL tunnel
 *   Copyright (c) 1998-2006 Michal Trojnara <Michal.Trojnara@mirt.net>
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
 *
 *   In addition, as a special exception, Michal Trojnara gives
 *   permission to link the code of this program with the OpenSSL
 *   library (or with modified versions of OpenSSL that use the same
 *   license as OpenSSL), and distribute linked combinations including
 *   the two.  You must obey the GNU General Public License in all
 *   respects for all of the code used other than OpenSSL.  If you modify
 *   this file, you may extend this exception to your version of the
 *   file, but you are not obligated to do so.  If you do not wish to
 *   do so, delete this exception statement from your version.
 */

#ifndef NO_RSA

/* Cache temporary keys up to 2048 bits */
#define KEY_CACHE_LENGTH 2049

/* Cache temporary keys up to 1 hour */
#define KEY_CACHE_TIME 3600

#endif /* NO_RSA */

#include "common.h"
#include "prototypes.h"

/**************************************** prototypes */

static void sslerror_stack(void);

#if SSLEAY_VERSION_NUMBER >= 0x00907000L
static void info_callback(const SSL *, int, int);
#else /* OpenSSL-0.9.7 */
static void info_callback(SSL *, int, int);
#endif /* OpenSSL-0.9.7 */
static void print_stats(SSL_CTX *);

#ifdef USE_DH
static int init_dh(SSL_CTX *, LOCAL_OPTIONS *);
#endif /* USE_DH */
#ifndef NO_RSA
static RSA *tmp_rsa_cb(SSL *, int, int);
static RSA *make_temp_key(int);
#endif /* NO_RSA */

static void load_certificate(LOCAL_OPTIONS *);
static void verify_init(LOCAL_OPTIONS *);
static int verify_callback(int, X509_STORE_CTX *);
static int cert_check(CLI *c, X509_STORE_CTX *, char *, int);
static int crl_check(CLI *c, X509_STORE_CTX *, char *);
static int ocsp_check(CLI *c, X509_STORE_CTX *, char *);

/**************************************** initialize section->ctx and */
/*                                        section->revocation_store */

void context_init(LOCAL_OPTIONS *section) { /* init SSL context */
    struct stat st; /* buffer for stat */

    /* check if certificate exists */
    if(!section->key) /* key file not specified */
        section->key=section->cert;
#ifdef HAVE_OSSL_ENGINE_H
    if(!section->engine)
#endif
    if(section->option.cert) {
        if(stat(section->key, &st)) {
            ioerror(section->key);
            exit(1);
        }
#if !defined(USE_WIN32) && !defined(USE_OS2)
        if(st.st_mode & 7)
            s_log(LOG_WARNING, "Wrong permissions on %s", section->key);
#endif /* defined USE_WIN32 */
    }
    /* create SSL context */
    if(section->option.client) {
        section->ctx=SSL_CTX_new(section->client_method());
    } else { /* Server mode */
        section->ctx=SSL_CTX_new(section->server_method());
#ifndef NO_RSA
        SSL_CTX_set_tmp_rsa_callback(section->ctx, tmp_rsa_cb);
#endif /* NO_RSA */
#ifdef USE_DH
        if(init_dh(section->ctx, section))
            s_log(LOG_WARNING, "Diffie-Hellman initialization failed");
#endif /* USE_DH */
    }
    if(section->ssl_options) {
        s_log(LOG_DEBUG, "Configuration SSL options: 0x%08lX",
            section->ssl_options);
        s_log(LOG_DEBUG, "SSL options set: 0x%08lX",
            SSL_CTX_set_options(section->ctx, section->ssl_options));
    }
    if(section->cipher_list) {
        if (!SSL_CTX_set_cipher_list(section->ctx, section->cipher_list)) {
            sslerror("SSL_CTX_set_cipher_list");
            exit(1);
        }
    }
#if SSLEAY_VERSION_NUMBER >= 0x00906000L
    SSL_CTX_set_mode(section->ctx,
        SSL_MODE_ENABLE_PARTIAL_WRITE|SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
#endif /* OpenSSL-0.9.6 */

    SSL_CTX_set_session_cache_mode(section->ctx, SSL_SESS_CACHE_BOTH);
    SSL_CTX_set_timeout(section->ctx, section->session_timeout);

    section->revocation_store=X509_STORE_new();
    if(!section->revocation_store) {
        sslerror("X509_STORE_new");
        exit(1);
    }

    if(section->option.cert)
        load_certificate(section);
    verify_init(section); /* initialize certificate verification */

    SSL_CTX_set_info_callback(section->ctx, info_callback);
    s_log(LOG_DEBUG, "SSL context initialized for service %s",
        section->servname);
}

/**************************************** SSL error reporting */

void sslerror(char *txt) { /* SSL Error handler */
    unsigned long err;
    char string[120];

    err=ERR_get_error();
    if(!err) {
        s_log(LOG_ERR, "%s: Peer suddenly disconnected", txt);
        return;
    }
    sslerror_stack();
    ERR_error_string(err, string);
    s_log(LOG_ERR, "%s: %lX: %s", txt, err, string);
}

static void sslerror_stack(void) { /* recursive dump of the error stack */
    unsigned long err;
    char string[120];

    err=ERR_get_error();
    if(!err)
        return;
    sslerror_stack();
    ERR_error_string(err, string);
    s_log(LOG_ERR, "error stack: %lX : %s", err, string);
}

/**************************************** informational callback */

#if SSLEAY_VERSION_NUMBER >= 0x00907000L
static void info_callback(const SSL *s, int where, int ret) {
#else /* OpenSSL-0.9.7 */
static void info_callback(SSL *s, int where, int ret) {
#endif /* OpenSSL-0.9.7 */
    if(where & SSL_CB_LOOP)
        s_log(LOG_DEBUG, "SSL state (%s): %s",
        where & SSL_ST_CONNECT ? "connect" :
        where & SSL_ST_ACCEPT ? "accept" :
        "undefined", SSL_state_string_long(s));
    else if(where & SSL_CB_ALERT)
        s_log(LOG_DEBUG, "SSL alert (%s): %s: %s",
            where & SSL_CB_READ ? "read" : "write",
            SSL_alert_type_string_long(ret),
            SSL_alert_desc_string_long(ret));
    else if(where==SSL_CB_HANDSHAKE_DONE)
        print_stats(s->ctx);
}

static void print_stats(SSL_CTX *ctx) { /* print statistics */
    s_log(LOG_DEBUG, "%4ld items in the session cache",
        SSL_CTX_sess_number(ctx));
    s_log(LOG_DEBUG, "%4ld client connects (SSL_connect())",
        SSL_CTX_sess_connect(ctx));
    s_log(LOG_DEBUG, "%4ld client connects that finished",
        SSL_CTX_sess_connect_good(ctx));
#if SSLEAY_VERSION_NUMBER >= 0x0922
    s_log(LOG_DEBUG, "%4ld client renegotiations requested",
        SSL_CTX_sess_connect_renegotiate(ctx));
#endif
    s_log(LOG_DEBUG, "%4ld server connects (SSL_accept())",
        SSL_CTX_sess_accept(ctx));
    s_log(LOG_DEBUG, "%4ld server connects that finished",
        SSL_CTX_sess_accept_good(ctx));
#if SSLEAY_VERSION_NUMBER >= 0x0922
    s_log(LOG_DEBUG, "%4ld server renegotiations requested",
        SSL_CTX_sess_accept_renegotiate(ctx));
#endif
    s_log(LOG_DEBUG, "%4ld session cache hits", SSL_CTX_sess_hits(ctx));
    s_log(LOG_DEBUG, "%4ld session cache misses", SSL_CTX_sess_misses(ctx));
    s_log(LOG_DEBUG, "%4ld session cache timeouts", SSL_CTX_sess_timeouts(ctx));
}

/**************************************** DH initialization */

#ifdef USE_DH
static int init_dh(SSL_CTX *ctx, LOCAL_OPTIONS *section) {
    FILE *fp;
    DH *dh;
    BIO *bio;

    fp=fopen(section->cert, "r");
    if(!fp) {
#ifdef USE_WIN32
        /* fopen() does not return the error via GetLastError() on Win32 */
        s_log(LOG_ERR, "Failed to open %s", section->cert);
#else
        ioerror(section->cert);
#endif
        return -1; /* FAILED */
    }
    bio=BIO_new_fp(fp, BIO_CLOSE|BIO_FP_TEXT);
    if(!bio) {
        s_log(LOG_ERR, "BIO_new_fp failed");
        return -1; /* FAILED */
    }
    if((dh=PEM_read_bio_DHparams(bio, NULL, NULL
#if SSLEAY_VERSION_NUMBER >= 0x00904000L
            , NULL
#endif
            ))) {
        BIO_free(bio);
        s_log(LOG_DEBUG, "Using Diffie-Hellman parameters from %s",
            section->cert);
    } else { /* Failed to load DH parameters from file */
        BIO_free(bio);
        s_log(LOG_NOTICE, "Could not load DH parameters from %s", section->cert);
        return -1; /* FAILED */
    }
    SSL_CTX_set_tmp_dh(ctx, dh);
    s_log(LOG_INFO, "Diffie-Hellman initialized with %d bit key",
        8*DH_size(dh));
    DH_free(dh);
    return 0; /* OK */
}
#endif /* USE_DH */

/**************************************** temporary RSA keys generation */

#ifndef NO_RSA

static RSA *tmp_rsa_cb(SSL *s, int export, int keylen) {
    static int initialized=0;
    static struct keytabstruct {
        RSA *key;
        time_t timeout;
    } keytable[KEY_CACHE_LENGTH];
    static RSA *longkey=NULL;
    static int longlen=0;
    static time_t longtime=0;
    RSA *oldkey, *retval;
    time_t now;
    int i;

    enter_critical_section(CRIT_KEYGEN);
        /* Only one make_temp_key() at a time */
    if(!initialized) {
        for(i=0; i<KEY_CACHE_LENGTH; i++) {
            keytable[i].key=NULL;
            keytable[i].timeout=0;
        }
        initialized=1;
    }
    time(&now);
    if(keylen<KEY_CACHE_LENGTH) {
        if(keytable[keylen].timeout<now) {
            oldkey=keytable[keylen].key;
            keytable[keylen].key=make_temp_key(keylen);
            keytable[keylen].timeout=now+KEY_CACHE_TIME;
            if(oldkey)
                RSA_free(oldkey);
        }
        retval=keytable[keylen].key;
    } else { /* Temp key > 2048 bits.  Is it possible? */
        if(longtime<now || longlen!=keylen) {
            oldkey=longkey;
            longkey=make_temp_key(keylen);
            longtime=now+KEY_CACHE_TIME;
            longlen=keylen;
            if(oldkey)
                RSA_free(oldkey);
        }
        retval=longkey;
    }
    leave_critical_section(CRIT_KEYGEN);
    return retval;
}

static RSA *make_temp_key(int keylen) {
    RSA *result;

    s_log(LOG_DEBUG, "Generating %d bit temporary RSA key...", keylen);
#if SSLEAY_VERSION_NUMBER >= 0x0900
    result=RSA_generate_key(keylen, RSA_F4, NULL, NULL);
#else
    result=RSA_generate_key(keylen, RSA_F4, NULL);
#endif
    s_log(LOG_DEBUG, "Temporary RSA key created");
    return result;
}

#endif /* NO_RSA */

/**************************************** certificates */

static void load_certificate(LOCAL_OPTIONS *section) {
    int i, reason;
    UI_DATA ui_data;
#ifdef HAVE_OSSL_ENGINE_H
    EVP_PKEY *pkey;
    UI_METHOD *uim;
#endif

    ui_data.section=section; /* setup current section for callbacks */

    s_log(LOG_DEBUG, "Certificate: %s", section->cert);
    if(!SSL_CTX_use_certificate_chain_file(section->ctx, section->cert)) {
        s_log(LOG_ERR, "Error reading certificate file: %s", section->cert);
        sslerror("SSL_CTX_use_certificate_chain_file");
        exit(1);
    }
    s_log(LOG_DEBUG, "Certificate loaded");

    s_log(LOG_DEBUG, "Key file: %s", section->key);
#ifdef USE_WIN32
    SSL_CTX_set_default_passwd_cb(section->ctx, passwd_cb);
    SSL_CTX_set_default_passwd_cb_userdata(section->ctx, &ui_data);
#endif
#ifdef HAVE_OSSL_ENGINE_H
#ifdef USE_WIN32
    uim=UI_create_method("stunnel WIN32 UI");
    UI_method_set_reader(uim, pin_cb);
#else
    uim=NULL;
#endif
#endif
#ifdef HAVE_OSSL_ENGINE_H
    if(section->engine)
        for(i=0; i<3; i++) {
            pkey=ENGINE_load_private_key(section->engine, section->key,
                uim, &ui_data);
            if(!pkey) {
                reason=ERR_GET_REASON(ERR_peek_error());
                if(i<2 && (reason==7 || reason==160)) { /* wrong PIN */
                    sslerror_stack(); /* dump the error stack */
                    s_log(LOG_ERR, "Wrong PIN: retrying");
                    continue;
                }
                sslerror("ENGINE_load_private_key");
                exit(1);
            }
            if(SSL_CTX_use_PrivateKey(section->ctx, pkey))
                break; /* success */
            sslerror("SSL_CTX_use_PrivateKey");
            exit(1);
        }
    else
#endif
        for(i=0; i<3; i++) {
#ifdef NO_RSA
            if(SSL_CTX_use_PrivateKey_file(section->ctx, section->key,
                    SSL_FILETYPE_PEM))
#else /* NO_RSA */
            if(SSL_CTX_use_RSAPrivateKey_file(section->ctx, section->key,
                    SSL_FILETYPE_PEM))
#endif /* NO_RSA */
                break;
            reason=ERR_GET_REASON(ERR_peek_error());
            if(i<2 && reason==EVP_R_BAD_DECRYPT) {
                sslerror_stack(); /* dump the error stack */
                s_log(LOG_ERR, "Wrong pass phrase: retrying");
                continue;
            }
#ifdef NO_RSA
            sslerror("SSL_CTX_use_PrivateKey_file");
#else /* NO_RSA */
            sslerror("SSL_CTX_use_RSAPrivateKey_file");
#endif /* NO_RSA */
            exit(1);
        }
    if(!SSL_CTX_check_private_key(section->ctx)) {
        sslerror("Private key does not match the certificate");
        exit(1);
    }
    s_log(LOG_DEBUG, "Private key loaded");
}

static void verify_init(LOCAL_OPTIONS *section) {
    X509_LOOKUP *lookup;

    if(section->verify_level<0)
        return; /* No certificate verification */

    if(section->verify_level>1 && !section->ca_file && !section->ca_dir) {
        s_log(LOG_ERR, "Either CApath or CAfile "
            "has to be used for authentication");
        exit(1);
    }

    if(section->ca_file) {
        if(!SSL_CTX_load_verify_locations(section->ctx,
                section->ca_file, NULL)) {
            s_log(LOG_ERR, "Error loading verify certificates from %s",
                section->ca_file);
            sslerror("SSL_CTX_load_verify_locations");
            exit(1);
        }
#if 0
        SSL_CTX_set_client_CA_list(section->ctx,
            SSL_load_client_CA_file(section->ca_file));
#endif
        s_log(LOG_DEBUG, "Loaded verify certificates from %s",
            section->ca_file);
    }

    if(section->ca_dir) {
        if(!SSL_CTX_load_verify_locations(section->ctx,
                NULL, section->ca_dir)) {
            s_log(LOG_ERR, "Error setting verify directory to %s",
                section->ca_dir);
            sslerror("SSL_CTX_load_verify_locations");
            exit(1);
        }
        s_log(LOG_DEBUG, "Verify directory set to %s", section->ca_dir);
    }

    if(section->crl_file) {
        lookup=X509_STORE_add_lookup(section->revocation_store,
            X509_LOOKUP_file());
        if(!lookup) {
            sslerror("X509_STORE_add_lookup");
            exit(1);
        }
        if(!X509_LOOKUP_load_file(lookup, section->crl_file,
                X509_FILETYPE_PEM)) {
            s_log(LOG_ERR, "Error loading CRLs from %s",
                section->crl_file);
            sslerror("X509_LOOKUP_load_file");
            exit(1);
        }
        s_log(LOG_DEBUG, "Loaded CRLs from %s", section->crl_file);
    }

    if(section->crl_dir) {
        section->revocation_store->cache=0; /* don't cache CRLs */
        lookup=X509_STORE_add_lookup(section->revocation_store,
            X509_LOOKUP_hash_dir());
        if(!lookup) {
            sslerror("X509_STORE_add_lookup");
            exit(1);
        }
        if(!X509_LOOKUP_add_dir(lookup, section->crl_dir,
                X509_FILETYPE_PEM)) {
            s_log(LOG_ERR, "Error setting CRL directory to %s",
                section->crl_dir);
            sslerror("X509_LOOKUP_add_dir");
            exit(1);
        }
        s_log(LOG_DEBUG, "CRL directory set to %s", section->crl_dir);
    }

    SSL_CTX_set_verify(section->ctx, section->verify_level==SSL_VERIFY_NONE ?
        SSL_VERIFY_PEER : section->verify_level, verify_callback);

    if(section->ca_dir && section->verify_use_only_my)
        s_log(LOG_NOTICE, "Peer certificate location %s", section->ca_dir);
}

static int verify_callback(int preverify_ok, X509_STORE_CTX *callback_ctx) {
        /* our verify callback function */
    SSL *ssl;
    CLI *c;
    char subject_name[STRLEN];

    X509_NAME_oneline(X509_get_subject_name(callback_ctx->current_cert),
        subject_name, STRLEN);
    safestring(subject_name);

    /* Retrieve the pointer to the SSL of the connection currently treated
     * and the application specific data stored into the SSL object. */
    ssl=X509_STORE_CTX_get_ex_data(callback_ctx,
        SSL_get_ex_data_X509_STORE_CTX_idx());
    c=SSL_get_ex_data(ssl, cli_index);

    if(!cert_check(c, callback_ctx, subject_name, preverify_ok))
        return 0; /* reject connection */
    if(c->opt->revocation_store && !crl_check(c, callback_ctx, subject_name))
        return 0; /* reject connection */
#if SSLEAY_VERSION_NUMBER >= 0x00907000L
    if(!ocsp_check(c, callback_ctx, subject_name))
        return 0; /* reject connection */
#endif /* OpenSSL-0.9.7 */

    /* errnum=X509_STORE_CTX_get_error(ctx); */
    s_log(LOG_NOTICE, "VERIFY OK: depth=%d, %s",
        callback_ctx->error_depth, subject_name);
    return 1; /* accept connection */
}

static int cert_check(CLI *c, X509_STORE_CTX *callback_ctx,
        char *subject_name, int preverify_ok) {
    X509_OBJECT ret;

    if(c->opt->verify_level==SSL_VERIFY_NONE) {
        s_log(LOG_NOTICE, "VERIFY IGNORE: depth=%d, %s",
            callback_ctx->error_depth, subject_name);
        return 1; /* accept connection */
    }
    if(!preverify_ok) {
        /* Remote site specified a certificate, but it's not correct */
        s_log(LOG_WARNING, "VERIFY ERROR: depth=%d, error=%s: %s",
            callback_ctx->error_depth,
            X509_verify_cert_error_string (callback_ctx->error),
                subject_name);
        return 0; /* reject connection */
    }
    if(c->opt->verify_use_only_my && callback_ctx->error_depth==0 &&
            X509_STORE_get_by_subject(callback_ctx, X509_LU_X509,
                X509_get_subject_name(callback_ctx->current_cert), &ret)!=1) {
        s_log(LOG_WARNING, "VERIFY ERROR ONLY MY: no cert for %s",
            subject_name);
        return 0; /* reject connection */
    }
    return 1; /* accept connection */
}

/* Based on BSD-style licensed code of mod_ssl */
static int crl_check(CLI *c, X509_STORE_CTX *callback_ctx,
        char *subject_name) {
    X509_STORE_CTX store_ctx;
    X509_OBJECT obj;
    X509_NAME *subject;
    X509_NAME *issuer;
    X509 *cert;
    X509_CRL *crl;
    X509_REVOKED *revoked;
    EVP_PKEY *pubkey;
    long serial;
    BIO *bio;
    int i, n, rc;
    char *cp;
    char *cp2;
    ASN1_TIME *t;

    /* Determine certificate ingredients in advance */
    cert=X509_STORE_CTX_get_current_cert(callback_ctx);
    subject=X509_get_subject_name(cert);
    issuer=X509_get_issuer_name(cert);

    /* Try to retrieve a CRL corresponding to the _subject_ of
     * the current certificate in order to verify it's integrity. */
    memset((char *)&obj, 0, sizeof(obj));
    X509_STORE_CTX_init(&store_ctx, c->opt->revocation_store, NULL, NULL);
    rc=X509_STORE_get_by_subject(&store_ctx, X509_LU_CRL, subject, &obj);
    X509_STORE_CTX_cleanup(&store_ctx);
    crl=obj.data.crl;
    if(rc>0 && crl) {
        /* Log information about CRL
         * (A little bit complicated because of ASN.1 and BIOs...) */
        bio=BIO_new(BIO_s_mem());
        BIO_printf(bio, "lastUpdate: ");
        ASN1_UTCTIME_print(bio, X509_CRL_get_lastUpdate(crl));
        BIO_printf(bio, ", nextUpdate: ");
        ASN1_UTCTIME_print(bio, X509_CRL_get_nextUpdate(crl));
        n=BIO_pending(bio);
        cp=malloc(n+1);
        n=BIO_read(bio, cp, n);
        cp[n]='\0';
        BIO_free(bio);
        cp2=X509_NAME_oneline(subject, NULL, 0);
        s_log(LOG_NOTICE, "CA CRL: Issuer: %s, %s", cp2, cp);
        OPENSSL_free(cp2);
        free(cp);

        /* Verify the signature on this CRL */
        pubkey=X509_get_pubkey(cert);
        if(X509_CRL_verify(crl, pubkey)<=0) {
            s_log(LOG_WARNING, "Invalid signature on CRL");
            X509_STORE_CTX_set_error(callback_ctx,
                X509_V_ERR_CRL_SIGNATURE_FAILURE);
            X509_OBJECT_free_contents(&obj);
            if(pubkey)
                EVP_PKEY_free(pubkey);
            return 0; /* reject connection */
        }
        if(pubkey)
            EVP_PKEY_free(pubkey);

        /* Check date of CRL to make sure it's not expired */
        t=X509_CRL_get_nextUpdate(crl);
        if(!t) {
            s_log(LOG_WARNING, "Found CRL has invalid nextUpdate field");
            X509_STORE_CTX_set_error(callback_ctx,
                X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD);
            X509_OBJECT_free_contents(&obj);
            return 0; /* reject connection */
        }
        if(X509_cmp_current_time(t)<0) {
            s_log(LOG_WARNING, "Found CRL is expired - "
                "revoking all certificates until you get updated CRL");
            X509_STORE_CTX_set_error(callback_ctx, X509_V_ERR_CRL_HAS_EXPIRED);
            X509_OBJECT_free_contents(&obj);
            return 0; /* reject connection */
        }
        X509_OBJECT_free_contents(&obj);
    }

    /* Try to retrieve a CRL corresponding to the _issuer_ of
     * the current certificate in order to check for revocation. */
    memset((char *)&obj, 0, sizeof(obj));
    X509_STORE_CTX_init(&store_ctx, c->opt->revocation_store, NULL, NULL);
    rc=X509_STORE_get_by_subject(&store_ctx, X509_LU_CRL, issuer, &obj);
    X509_STORE_CTX_cleanup(&store_ctx);
    crl=obj.data.crl;
    if(rc>0 && crl) {
        /* Check if the current certificate is revoked by this CRL */
#if SSLEAY_VERSION_NUMBER >= 0x00904000
        n=sk_X509_REVOKED_num(X509_CRL_get_REVOKED(crl));
#else
        n=sk_num(X509_CRL_get_REVOKED(crl));
#endif
        for(i=0; i<n; i++) {
#if SSLEAY_VERSION_NUMBER >= 0x00904000
            revoked=sk_X509_REVOKED_value(X509_CRL_get_REVOKED(crl), i);
#else
            revoked=(X509_REVOKED *)sk_value(X509_CRL_get_REVOKED(crl), i);
#endif
            if(ASN1_INTEGER_cmp(revoked->serialNumber,
                    X509_get_serialNumber(cert)) == 0) {
                serial=ASN1_INTEGER_get(revoked->serialNumber);
                cp=X509_NAME_oneline(issuer, NULL, 0);
                s_log(LOG_NOTICE, "Certificate with serial %ld (0x%lX) "
                    "revoked per CRL from issuer %s", serial, serial, cp);
                OPENSSL_free(cp);
                X509_STORE_CTX_set_error(callback_ctx, X509_V_ERR_CERT_REVOKED);
                X509_OBJECT_free_contents(&obj);
                return 0; /* reject connection */
            }
        }
        X509_OBJECT_free_contents(&obj);
    }
    return 1; /* accept connection */
}

#if SSLEAY_VERSION_NUMBER >= 0x00907000L
static int ocsp_check(CLI *c, X509_STORE_CTX *callback_ctx,
        char *subject_name) {
    int error, retval=0;
    SOCKADDR_UNION addr;
    X509 *cert;
    X509 *issuer=NULL;
    OCSP_CERTID *certID;
    BIO *bio=NULL;
    OCSP_REQUEST *request=NULL;
    OCSP_RESPONSE *response=NULL;
    OCSP_BASICRESP *basicResponse=NULL;
    ASN1_GENERALIZEDTIME *produced_at, *this_update, *next_update;
    int status, reason;

    s_log(LOG_INFO, "*** starting OCSP verification ***");
    /* TODO: check OCSP server specified in the certificate */

    if(!c->opt->option.ocsp) /* OCSP server (responder) not specified */
        return 1; /* accept connection */

    /* connect specified OCSP server (responder) */
    if((c->fd=
        socket(c->opt->ocsp_addr.addr[0].sa.sa_family, SOCK_STREAM, 0))<0) {
        sockerror("socket (auth_user)");
        return 0; /* reject connection */
    }
    if(alloc_fd(c->fd))
        goto cleanup;
    memcpy(&addr, &c->opt->ocsp_addr.addr[0], sizeof(SOCKADDR_UNION));
    if(connect(c->fd, &addr.sa, addr_len(addr))) {
        error=get_last_socket_error();
        if(error!=EINPROGRESS && error!=EWOULDBLOCK) {
            sockerror("OCSP server connect");
            goto cleanup;
        }
        if(connect_wait(c))
            goto cleanup;
    }
    s_log(LOG_DEBUG, "OCSP server connected");

    /* get current certificate ID */
    cert=X509_STORE_CTX_get_current_cert(callback_ctx); /* get current cert */
    if(X509_STORE_CTX_get1_issuer(&issuer, callback_ctx, cert)!=1) {
        sslerror("X509_STORE_CTX_get1_issuer");
        goto cleanup;
    }
    certID=OCSP_cert_to_id(0, cert, issuer);
    if(!certID) {
        sslerror("OCSP_cert_to_id");
        goto cleanup;
    }

    /* build request */
    request=OCSP_REQUEST_new();
    if(!request) {
        sslerror("OCSP_REQUEST_new");
        goto cleanup;
    }
    if(!OCSP_request_add0_id(request, certID)) {
        sslerror("OCSP_request_add0_id");
        goto cleanup;
    }
    OCSP_request_add1_nonce(request, 0, -1);

    /* send the request and get a response */
    /* FIXME: this code won't work with ucontext threading */
    /* (blocking sockets are used) */
    bio=BIO_new_fd(c->fd, BIO_NOCLOSE);
    setnonblock(c->fd, 0);
    response=OCSP_sendreq_bio(bio, c->opt->ocsp_path, request);
    setnonblock(c->fd, 1);
    if(!response) {
        sslerror("OCSP_sendreq_bio");
        goto cleanup;
    }
    error=OCSP_response_status(response);
    if(error!=OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        s_log(LOG_ERR, "Responder Error: %s (%d)",
            OCSP_response_status_str(error), error);
        goto cleanup;
    }
    s_log(LOG_INFO, "OCSP response received");

    /* verify the response */
    basicResponse=OCSP_response_get1_basic(response);
    if(!basicResponse) {
        sslerror("OCSP_response_get1_basic");
        goto cleanup;
    }
    if(OCSP_check_nonce(request, basicResponse)<=0) {
        sslerror("OCSP_check_nonce");
        goto cleanup;
    }
    if(OCSP_basic_verify(basicResponse, NULL, c->opt->revocation_store,
            -1 /* FIXME: be 0 */)<=0) {
        sslerror("OCSP_basic_verify");
        goto cleanup;
    }
    if(OCSP_resp_find_status(basicResponse, certID, &status, &reason,
            &produced_at, &this_update, &next_update)==0) {
        sslerror("OCSP_resp_find_status");
        goto cleanup;
    }

    /* success */
    s_log(LOG_INFO, "OCSP verification passed: status=%d, reason=%d",
        status, reason);
    retval=1; /* accept connection */
cleanup:
    if(bio)
        BIO_free_all(bio);
    if(issuer)
        X509_free(issuer);
    if(request)
        OCSP_REQUEST_free(request);
    if(response)
        OCSP_RESPONSE_free(response);
    if(basicResponse)
        OCSP_BASICRESP_free(basicResponse);
    closesocket(c->fd);
    c->fd=-1; /* avoid double close on cleanup */
    return retval;
}
#endif /* OpenSSL-0.9.7 */

/* End of ctx.c */
