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

#include "common.h"
#include "prototypes.h"

#ifndef NO_RSA

/* Cache temporary keys up to 2048 bits */
#define KEY_CACHE_LENGTH 2049

/* Cache temporary keys up to 1 hour */
#define KEY_CACHE_TIME 3600

#endif /* NO_RSA */

/**************************************** prototypes */

/* RSA/DH initialization */
#ifndef NO_RSA
static RSA *tmp_rsa_cb(SSL *, int, int);
static RSA *make_temp_key(int);
#endif /* NO_RSA */
#ifdef USE_DH
static int init_dh(SSL_CTX *, LOCAL_OPTIONS *);
#endif /* USE_DH */

/* loading certificate */
static void load_certificate(LOCAL_OPTIONS *);
static int cache_cb(char *, int, int, void *);

#if SSLEAY_VERSION_NUMBER >= 0x00907000L
static void info_callback(const SSL *, int, int);
#else /* OpenSSL-0.9.7 */
static void info_callback(SSL *, int, int);
#endif /* OpenSSL-0.9.7 */
static void print_stats(SSL_CTX *);

static void sslerror_stack(void);

/**************************************** initialize section->ctx */

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

    if(section->option.cert)
        load_certificate(section);

    verify_init(section); /* initialize certificate verification */

    SSL_CTX_set_info_callback(section->ctx, info_callback);
    s_log(LOG_DEBUG, "SSL context initialized for service %s",
        section->servname);
}

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
        /* only one make_temp_key() at a time */
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
    } else { /* temp key > 2048 bits.  Is it possible? */
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
    } else { /* failed to load DH parameters from file */
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

/**************************************** loading certificate */

static int cache_initialized=0;

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
    SSL_CTX_set_default_passwd_cb(section->ctx, cache_cb);
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
        for(i=1; i<=3; i++) {
            pkey=ENGINE_load_private_key(section->engine, section->key,
                uim, &ui_data);
            if(!pkey) {
                reason=ERR_GET_REASON(ERR_peek_error());
                if(i<=2 && (reason==7 || reason==160)) { /* wrong PIN */
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
        for(i=0; i<=3; i++) {
            if(!i && !cache_initialized)
                continue; /* there is no cached value */
            SSL_CTX_set_default_passwd_cb_userdata(section->ctx,
                i ? &ui_data : NULL); /* try the cached password first */
#ifdef NO_RSA
            if(SSL_CTX_use_PrivateKey_file(section->ctx, section->key,
                    SSL_FILETYPE_PEM))
#else /* NO_RSA */
            if(SSL_CTX_use_RSAPrivateKey_file(section->ctx, section->key,
                    SSL_FILETYPE_PEM))
#endif /* NO_RSA */
                break;
            reason=ERR_GET_REASON(ERR_peek_error());
            if(i<=2 && reason==EVP_R_BAD_DECRYPT) {
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

static int cache_cb(char *buf, int size, int rwflag, void *userdata) {
    static char cache[PEM_BUFSIZE];
    int len;

    if(size>PEM_BUFSIZE)
        size=PEM_BUFSIZE;

    if(userdata) { /* prompt the user */
#ifdef USE_WIN32
        len=passwd_cb(buf, size, rwflag, userdata);
#else
        len=PEM_def_callback(buf, size, rwflag, NULL);
#endif
        memcpy(cache, buf, size); /* save in cache */
        cache_initialized=1;
    } else { /* try the cached value */
        strncpy(buf, cache, size);
        buf[size-1]='\0';
        len=strlen(buf);
    }
    return len;
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

/* End of ctx.c */
