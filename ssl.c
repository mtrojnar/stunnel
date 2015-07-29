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

#ifdef HAVE_OPENSSL
#include <openssl/lhash.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#else
#include <lhash.h>
#include <ssl.h>
#include <err.h>
#endif

extern server_options options;

    /* SSL functions */
static int init_dh();
static int init_prng();
static int prng_seeded(int);
static int add_rand_file(char *);
#ifndef NO_RSA
static RSA *tmp_rsa_cb(SSL *, int, int);
static RSA *make_temp_key(int);
#endif /* NO_RSA */
static void verify_init();
static int verify_callback(int, X509_STORE_CTX *);
static void info_callback(SSL *, int, int);
static void print_stats();

SSL_CTX *ctx; /* global SSL context */

void context_init() { /* init SSL */

    if(!init_prng())
        log(LOG_INFO, "PRNG seeded successfully");
    SSLeay_add_ssl_algorithms();
    SSL_load_error_strings();
    if(options.option&OPT_CLIENT) {
        ctx=SSL_CTX_new(SSLv3_client_method());
    } else { /* Server mode */
        ctx=SSL_CTX_new(SSLv23_server_method());
#ifndef NO_RSA
        SSL_CTX_set_tmp_rsa_callback(ctx, tmp_rsa_cb);
#endif /* NO_RSA */
        if(init_dh())
            log(LOG_WARNING, "Diffie-Hellman initialization failed");
    }

#if SSLEAY_VERSION_NUMBER >= 0x00906000L
    SSL_CTX_set_mode(ctx,
        SSL_MODE_ENABLE_PARTIAL_WRITE|SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
#endif /* OpenSSL-0.9.6 */

    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_BOTH);
    SSL_CTX_set_timeout(ctx, options.session_timeout);
    if(options.option&OPT_CERT) {
        if(!SSL_CTX_use_certificate_chain_file(ctx, options.pem)) {
            log(LOG_ERR, "Error reading certificate file: %s", options.pem);
            sslerror("SSL_CTX_use_certificate_chain_file");
            exit(1);
        }
        log(LOG_DEBUG, "Certificate: %s", options.pem);
#ifdef NO_RSA
        if(!SSL_CTX_use_PrivateKey_file(ctx, options.pem,
                SSL_FILETYPE_PEM)) {
            sslerror("SSL_CTX_use_PrivateKey_file");
            exit(1);
        }
#else /* NO_RSA */
        if(!SSL_CTX_use_RSAPrivateKey_file(ctx, options.pem,
                SSL_FILETYPE_PEM)) {
            sslerror("SSL_CTX_use_RSAPrivateKey_file");
            exit(1);
        }
#endif /* NO_RSA */
        if(!SSL_CTX_check_private_key(ctx)) {
            sslerror("Private key does not match the certificate");
            exit(1);
        }
    }

    verify_init(); /* Initialize certificate verification */

    SSL_CTX_set_info_callback(ctx, info_callback);

    if(options.cipher_list) {
        if (!SSL_CTX_set_cipher_list(ctx, options.cipher_list)) {
            sslerror("SSL_CTX_set_cipher_list");
            exit(1);
        }
    }
}

void context_free() { /* free SSL */
    SSL_CTX_free(ctx);
}

static int init_prng() {
    int totbytes=0;
    char filename[STRLEN];
    int bytes;
    bytes=0; /* avoid warning if #ifdef'd out for windows */

    filename[0]='\0';

    /* If they specify a rand file on the command line we
       assume that they really do want it, so try it first */
    if(options.rand_file) {
        totbytes+=add_rand_file(options.rand_file);
        if(prng_seeded(totbytes))
            return 0;
    }

    /* try the $RANDFILE or $HOME/.rnd files */
    RAND_file_name(filename, STRLEN);
    if(filename[0]) {
        filename[STRLEN-1]='\0';        /* just in case */
        totbytes+=add_rand_file(filename);
        if(prng_seeded(totbytes))
            return 0;
    }

#ifdef RANDOM_FILE
    totbytes += add_rand_file( RANDOM_FILE );
    if(prng_seeded(totbytes))
        return 0;
#endif

#ifdef USE_WIN32
    RAND_screen();
    if(prng_seeded(totbytes)) {
        log(LOG_DEBUG, "Seeded PRNG with RAND_screen");
        return 0;
    }
    log(LOG_DEBUG, "RAND_screen failed to sufficiently seed PRNG");
#else

#if SSLEAY_VERSION_NUMBER >= 0x0090581fL
    if(options.egd_sock) {
        if((bytes=RAND_egd(options.egd_sock))==-1) {
            log(LOG_WARNING, "EGD Socket %s failed", options.egd_sock);
            bytes=0;
        } else {
            totbytes += bytes;
            log(LOG_DEBUG, "Snagged %d random bytes from EGD Socket %s",
                bytes, options.egd_sock);
            return 0; /* OpenSSL always gets what it needs or fails,
                         so no need to check if seeded sufficiently */
        }
    }
#ifdef EGD_SOCKET
    if ( (bytes=RAND_egd( EGD_SOCKET )) == -1 ) {
        log(LOG_WARNING, "EGD Socket %s failed", EGD_SOCKET);
    } else {
        totbytes += bytes;
        log(LOG_DEBUG, "Snagged %d random bytes from EGD Socket %s",
                bytes, EGD_SOCKET);
        return 0;
    }
#endif /* EGD_SOCKET */

#endif /* OpenSSL-0.9.5a */
#endif /* USE_WIN32 */

    /* Try the good-old default /dev/urandom, if available  */
    totbytes+=add_rand_file( "/dev/urandom" );
    if(prng_seeded(totbytes))
        return 0;

    /* Random file specified during configure */

    log(LOG_INFO, "PRNG seeded with %d bytes total", totbytes);
    log(LOG_WARNING, "PRNG may not have been seeded with enough random bytes");
    return -1; /* FAILED */
}

static int init_dh() {
#ifndef NO_DH
    DH *dh;
    BIO *bio;

    if(!(bio=BIO_new_file(options.pem, "r"))) {
        ioerror(options.pem);
        return -1; /* FAILED */
    }
    if((dh=PEM_read_bio_DHparams(bio, NULL, NULL
#if SSLEAY_VERSION_NUMBER >= 0x00904000L
            , NULL
#endif
            ))) {
        BIO_free(bio);
        log(LOG_DEBUG, "Using Diffie-Hellman parameters from %s",
            options.pem);
    } else { /* Failed to load DH parameters from file */
        BIO_free(bio);
        log(LOG_NOTICE, "Could not load DH parameters from %s", options.pem);
        return -1; /* FAILED */
    }
    SSL_CTX_set_tmp_dh(ctx, dh);
    log(LOG_INFO, "Diffie-Hellman initialized with %d bit key",
        8*DH_size(dh));
    DH_free(dh);
#endif /* NO_DH */
    return 0; /* OK */
}

/* shortcut to determine if sufficient entropy for PRNG is present */
static int prng_seeded(int bytes) {
#if SSLEAY_VERSION_NUMBER >= 0x0090581fL
    if(RAND_status()){
        log(LOG_DEBUG, "RAND_status claims sufficient entropy for the PRNG");
        return 1;
    }
#else
    if(bytes>=options.random_bytes) {
        log(LOG_INFO, "Sufficient entropy in PRNG assumed (>= %d)", options.random_bytes);
        return 1;
    }
#endif
    return 0;        /* assume we don't have enough */
}

static int add_rand_file(char *filename) {
    int readbytes;
    int writebytes;
    struct stat sb;

    if(stat(filename, &sb))
        return 0;
    if((readbytes=RAND_load_file(filename, options.random_bytes)))
        log(LOG_DEBUG, "Snagged %d random bytes from %s", readbytes, filename);
    else
        log(LOG_INFO, "Unable to retrieve any random data from %s", filename);
    /* Write new random data for future seeding if it's a regular file */
    if(options.rand_write && (sb.st_mode & S_IFREG)){
        writebytes = RAND_write_file(filename);
        if(writebytes==-1)
            log(LOG_WARNING, "Failed to write strong random data to %s - "
                "may be a permissions or seeding problem", filename);
        else
            log(LOG_DEBUG, "Wrote %d new random bytes to %s", writebytes, filename);
    }
    return readbytes;
}

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

    enter_critical_section(CRIT_KEYGEN); /* Only one make_temp_key() at a time */
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

    log(LOG_DEBUG, "Generating %d bit temporary RSA key...", keylen);
#if SSLEAY_VERSION_NUMBER >= 0x0900
    result=RSA_generate_key(keylen, RSA_F4, NULL, NULL);
#else
    result=RSA_generate_key(keylen, RSA_F4, NULL);
#endif
    log(LOG_DEBUG, "Temporary RSA key created");
    return result;
}

#endif /* NO_RSA */

static void verify_init() {
    if(options.verify_level<0)
        return; /* No certificate verification */
    log(LOG_DEBUG, "cert_defaults is %d", options.cert_defaults);
    log(LOG_DEBUG, "cert_dir is %s", options.cert_dir);
    log(LOG_DEBUG, "cert_file is %s", options.cert_file);
    if (options.cert_defaults & SSL_CERT_DEFAULTS) {
        log(LOG_DEBUG, "Initializing SSL library verify paths");
        if(!SSL_CTX_set_default_verify_paths(ctx)) {
            sslerror("X509_set_default_verify_paths");
            exit(1);
        }
    }

    /* put in defaults (if not set on cmd line) if -S says to */
    if (options.cert_defaults & STUNNEL_CERT_DEFAULTS) {
        log(LOG_DEBUG, "installing defaults where not set");
        if(!options.cert_file[0])
            safecopy(options.cert_file, CERT_FILE);
        if(!options.cert_dir[0])
            safecopy(options.cert_dir, CERT_DIR);
    }
    if(options.cert_file[0]) {
        if(!SSL_CTX_load_verify_locations(ctx, options.cert_file, NULL)) {
            log(LOG_ERR, "Error loading verify certificates from %s",
                options.cert_file);
            sslerror("SSL_CTX_load_verify_locations");
            exit(1);
        }
        SSL_CTX_set_client_CA_list(ctx,
            SSL_load_client_CA_file(options.cert_file));
        log(LOG_DEBUG, "Loaded verify certificates from %s",
            options.cert_file);
    }
    if(options.cert_dir[0]) {
        if (!SSL_CTX_load_verify_locations(ctx, NULL ,options.cert_dir)) {
            log(LOG_ERR, "Error setting verify directory to %s",
                options.cert_dir);
            sslerror("SSL_CTX_load_verify_locations");
            exit(1);
        }
        log(LOG_DEBUG, "Set verify directory to %s", options.cert_dir);
    }

    SSL_CTX_set_verify(ctx, options.verify_level==SSL_VERIFY_NONE ?
        SSL_VERIFY_PEER : options.verify_level, verify_callback);

    if (options.verify_use_only_my)
        log(LOG_NOTICE, "Peer certificate location %s", options.cert_dir);
}

#if 0
static void verify_info() {
    STACK_OF(X509_NAME) *stack;
    X509_STORE *store;

    stack=SSL_CTX_get_client_CA_list(ctx);
    log(LOG_DEBUG, "there are %d CA_list things", sk_X509_NAME_num(stack));

    store=SSL_CTX_get_cert_store(ctx);
    log(LOG_DEBUG, "it's a %p", store);
}
#endif

static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx) {
        /* our verify callback function */
    char txt[STRLEN];
    X509_OBJECT ret;

    X509_NAME_oneline(X509_get_subject_name(ctx->current_cert),
        txt, STRLEN);
    safestring(txt);
    if(options.verify_level==SSL_VERIFY_NONE) {
        log(LOG_NOTICE, "VERIFY IGNORE: depth=%d, %s", ctx->error_depth, txt);
        return 1; /* Accept connection */
    }
    if(!preverify_ok) {
        /* Remote site specified a certificate, but it's not correct */
        log(LOG_WARNING, "VERIFY ERROR: depth=%d, error=%s: %s",
            ctx->error_depth,
            X509_verify_cert_error_string (ctx->error), txt);
        return 0; /* Reject connection */
    }
    if(options.verify_use_only_my && ctx->error_depth==0 &&
            X509_STORE_get_by_subject(ctx, X509_LU_X509,
                X509_get_subject_name(ctx->current_cert), &ret)!=1) {
        log(LOG_WARNING, "VERIFY ERROR ONLY MY: no cert for %s", txt);
        return 0; /* Reject connection */
    }
    log(LOG_NOTICE, "VERIFY OK: depth=%d, %s", ctx->error_depth, txt);
    return 1; /* Accept connection */
}

static void info_callback(SSL *s, int where, int ret) {
    if(where & SSL_CB_LOOP)
        log(LOG_DEBUG, "SSL state (%s): %s",
        where & SSL_ST_CONNECT ? "connect" :
        where & SSL_ST_ACCEPT ? "accept" :
        "undefined", SSL_state_string_long(s));
    else if(where & SSL_CB_ALERT)
        log(LOG_DEBUG, "SSL alert (%s): %s: %s",
            where & SSL_CB_READ ? "read" : "write",
            SSL_alert_type_string_long(ret),
            SSL_alert_desc_string_long(ret));
    else if(where==SSL_CB_HANDSHAKE_DONE)
        print_stats();
}

static void print_stats() { /* print statistics */
    log(LOG_DEBUG, "%4ld items in the session cache",
        SSL_CTX_sess_number(ctx));
    log(LOG_DEBUG, "%4d client connects (SSL_connect())",
        SSL_CTX_sess_connect(ctx));
    log(LOG_DEBUG, "%4d client connects that finished",
        SSL_CTX_sess_connect_good(ctx));
#if SSLEAY_VERSION_NUMBER >= 0x0922
    log(LOG_DEBUG, "%4d client renegotiatations requested",
        SSL_CTX_sess_connect_renegotiate(ctx));
#endif
    log(LOG_DEBUG, "%4d server connects (SSL_accept())",
        SSL_CTX_sess_accept(ctx));
    log(LOG_DEBUG, "%4d server connects that finished",
        SSL_CTX_sess_accept_good(ctx));
#if SSLEAY_VERSION_NUMBER >= 0x0922
    log(LOG_DEBUG, "%4d server renegotiatiations requested",
        SSL_CTX_sess_accept_renegotiate(ctx));
#endif
    log(LOG_DEBUG, "%4d session cache hits", SSL_CTX_sess_hits(ctx));
    log(LOG_DEBUG, "%4d session cache misses", SSL_CTX_sess_misses(ctx));
    log(LOG_DEBUG, "%4d session cache timeouts", SSL_CTX_sess_timeouts(ctx));
}

void sslerror(char *txt) { /* SSL Error handler */
    unsigned long err;
    char string[120];

    err=ERR_get_error();
    if(err) {
        ERR_error_string(err, string);
        log(LOG_ERR, "%s: %s", txt, string);
    } else
        log(LOG_ERR, "%s: Peer suddenly disconnected", txt);
}

/* End of ssl.c */
