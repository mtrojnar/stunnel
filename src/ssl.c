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

#include "common.h"
#include "prototypes.h"

    /* global OpenSSL initialization: compression, engine, entropy */
NOEXPORT void cb_new_auth(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
        int idx, long argl, void *argp);
#if OPENSSL_VERSION_NUMBER>=0x30000000L
NOEXPORT int cb_dup_addr(CRYPTO_EX_DATA *to, const CRYPTO_EX_DATA *from,
    void **from_d, int idx, long argl, void *argp);
#elif OPENSSL_VERSION_NUMBER>=0x10100000L
NOEXPORT int cb_dup_addr(CRYPTO_EX_DATA *to, const CRYPTO_EX_DATA *from,
    void *from_d, int idx, long argl, void *argp);
#else
NOEXPORT int cb_dup_addr(CRYPTO_EX_DATA *to, CRYPTO_EX_DATA *from,
    void *from_d, int idx, long argl, void *argp);
#endif
NOEXPORT void cb_free_addr(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
    int idx, long argl, void *argp);
#ifndef OPENSSL_NO_COMP
NOEXPORT void compression_init();
NOEXPORT int compression_configure(GLOBAL_OPTIONS *);
#endif
NOEXPORT int prng_init(GLOBAL_OPTIONS *);
NOEXPORT int add_rand_file(GLOBAL_OPTIONS *, const char *);
NOEXPORT void update_rand_file(const char *);

int index_ssl_cli, index_ssl_ctx_opt;
int index_session_authenticated, index_session_connect_address;
#ifndef OPENSSL_NO_COMP
NOEXPORT STACK_OF(SSL_COMP) *comp_methods[STUNNEL_COMPS];
#endif

int fips_available() { /* either FIPS provider or container is available */
#ifdef USE_FIPS
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    return OSSL_PROVIDER_available(NULL, "fips");
#else /* OPENSSL_VERSION_NUMBER >= 0x30000000L */
    /* checking for OPENSSL_FIPS would be less precise, because it only
     * depends on the compiled, and not on the running OpenSSL version */
    return strstr(OpenSSL_version(OPENSSL_VERSION), "-fips") != NULL ||
        strstr(OpenSSL_version(OPENSSL_VERSION), "FIPS") != NULL; /* RHEL */
#endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L */
#else /* USE_FIPS */
    return 0;
#endif /* USE_FIPS */
}

int ssl_init(void) { /* init TLS before parsing configuration file */
#if OPENSSL_VERSION_NUMBER>=0x10100000L
    OPENSSL_INIT_SETTINGS *conf=OPENSSL_INIT_new();
#ifdef USE_WIN32
    OPENSSL_INIT_set_config_filename(conf, "..\\config\\openssl.cnf");
#endif /* USE_WIN32 */
    OPENSSL_init_crypto(
        OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_LOAD_CONFIG, conf);
    OPENSSL_INIT_free(conf);
#else
    OPENSSL_config(NULL);
    SSL_load_error_strings();
    SSL_library_init();
#endif
    index_ssl_cli=SSL_get_ex_new_index(0,
        "CLI pointer", NULL, NULL, NULL);
    index_ssl_ctx_opt=SSL_CTX_get_ex_new_index(0,
        "SERVICE_OPTIONS pointer", NULL, NULL, NULL);
    index_session_authenticated=SSL_SESSION_get_ex_new_index(0,
        "session authenticated", cb_new_auth, NULL, NULL);
    index_session_connect_address=SSL_SESSION_get_ex_new_index(0,
        "session connect address", NULL, cb_dup_addr, cb_free_addr);
    if(index_ssl_cli<0 || index_ssl_ctx_opt<0 ||
            index_session_authenticated<0 ||
            index_session_connect_address<0) {
        s_log(LOG_ERR, "Application specific data initialization failed");
        return 1;
    }
#ifndef OPENSSL_NO_DH
    dh_params=get_dh2048();
    if(!dh_params) {
        s_log(LOG_ERR, "Failed to get default DH parameters");
        return 1;
    }
#endif /* OPENSSL_NO_DH */
#ifndef OPENSSL_NO_COMP
    compression_init();
#endif /* OPENSSL_NO_COMP */
    return 0;
}

#ifndef OPENSSL_NO_DH
#if OPENSSL_VERSION_NUMBER<0x10100000L
/* this is needed for dhparam.c generated with OpenSSL >= 1.1.0
 * to be linked against the older versions */
int DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g) {
    if(!p || !g) /* q is optional */
        return 0;
    BN_free(dh->p);
    BN_free(dh->q);
    BN_free(dh->g);
    dh->p=p;
    dh->q=q;
    dh->g=g;
    if(q)
        dh->length=BN_num_bits(q);
    return 1;
}
#endif
#endif

NOEXPORT void cb_new_auth(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
        int idx, long argl, void *argp) {
    (void)parent; /* squash the unused parameter warning */
    (void)ptr; /* squash the unused parameter warning */
    (void)argl; /* squash the unused parameter warning */
    s_log(LOG_DEBUG, "Initializing application specific data for %s",
        (char *)argp);
    if(!CRYPTO_set_ex_data(ad, idx, (void *)(-1)))
        sslerror("CRYPTO_set_ex_data");
}

#if OPENSSL_VERSION_NUMBER>=0x30000000L
NOEXPORT int cb_dup_addr(CRYPTO_EX_DATA *to, const CRYPTO_EX_DATA *from,
        void **from_d, int idx, long argl, void *argp) {
#elif OPENSSL_VERSION_NUMBER>=0x10100000L
NOEXPORT int cb_dup_addr(CRYPTO_EX_DATA *to, const CRYPTO_EX_DATA *from,
        void *from_d, int idx, long argl, void *argp) {
#else
NOEXPORT int cb_dup_addr(CRYPTO_EX_DATA *to, CRYPTO_EX_DATA *from,
        void *from_d, int idx, long argl, void *argp) {
#endif
    SOCKADDR_UNION *src, *dst;
    socklen_t len;

    (void)to; /* squash the unused parameter warning */
    (void)from; /* squash the unused parameter warning */
    (void)idx; /* squash the unused parameter warning */
    (void)argl; /* squash the unused parameter warning */
    s_log(LOG_DEBUG, "Duplicating application specific data for %s",
        (char *)argp);
    src=*(void **)from_d;
    len=addr_len(src);
    dst=str_alloc_detached((size_t)len);
    memcpy(dst, src, (size_t)len);
    *(void **)from_d=dst;
    return 1;
}

NOEXPORT void cb_free_addr(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
        int idx, long argl, void *argp) {
    (void)parent; /* squash the unused parameter warning */
    (void)ad; /* squash the unused parameter warning */
    (void)idx; /* squash the unused parameter warning */
    (void)argl; /* squash the unused parameter warning */
    s_log(LOG_DEBUG, "Deallocating application specific data for %s",
        (char *)argp);
    str_free(ptr);
}

int ssl_configure(GLOBAL_OPTIONS *global) { /* configure global TLS settings */
#ifdef USE_FIPS
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    static OSSL_PROVIDER *prov=NULL;

    if(global->option.fips) {
        if(!prov) { /* need to load */
            if(!fips_available()) {
                s_log(LOG_ERR, "FIPS provider not available");
                return 1;
            }
            prov=OSSL_PROVIDER_load(NULL, "fips");
            if(!prov) {
                sslerror("OSSL_PROVIDER_load");
                return 1;
            }
        }
    } else {
        if(prov) { /* need to unload */
            OSSL_PROVIDER_unload(prov);
            prov=NULL;
        }
    }
#else /* OPENSSL_VERSION_NUMBER >= 0x30000000L */
    if(FIPS_mode()!=global->option.fips) {
        RAND_set_rand_method(NULL); /* reset RAND methods */
        if(!FIPS_mode_set(global->option.fips)) {
#if OPENSSL_VERSION_NUMBER>=0x10100000L
            OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
#else
            ERR_load_crypto_strings();
#endif
            sslerror("FIPS_mode_set");
            return 1;
        }
    }
#endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L */
    s_log(LOG_NOTICE, "FIPS mode %s",
        global->option.fips ? "enabled" : "disabled");
#endif /* USE_FIPS */

#ifndef OPENSSL_NO_COMP
    if(compression_configure(global))
        return 1;
#endif /* OPENSSL_NO_COMP */
    if(prng_init(global))
        return 1;

#ifndef OPENSSL_NO_ENGINE
    ENGINE_load_builtin_engines();
#endif

    /* cryptographic algoritms can only be configured once,
     * after all the engines are initialized */
#if OPENSSL_VERSION_NUMBER>=0x10100000L
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL);
#else
    OpenSSL_add_all_algorithms();
#endif
    return 0; /* SUCCESS */
}

#ifndef OPENSSL_NO_COMP

#if OPENSSL_VERSION_NUMBER<0x10100000L

NOEXPORT int COMP_get_type(const COMP_METHOD *meth) {
    return meth->type;
}

NOEXPORT const char *SSL_COMP_get0_name(const SSL_COMP *comp) {
    return comp->name;
}

NOEXPORT int SSL_COMP_get_id(const SSL_COMP *comp) {
    return comp->id;
}

#endif /* OPENSSL_VERSION_NUMBER<0x10100000L */

#if OPENSSL_VERSION_NUMBER<0x10002000L

NOEXPORT void SSL_COMP_set0_compression_methods(STACK_OF(SSL_COMP) *new_meths) {
    STACK_OF(SSL_COMP) *old_meths;
    int num, i;

    old_meths=SSL_COMP_get_compression_methods();
    sk_SSL_COMP_zero(old_meths);

    num=sk_SSL_COMP_num(new_meths);
    for(i=0; i<num; ++i)
        sk_SSL_COMP_push(old_meths, sk_SSL_COMP_value(new_meths, i));
}

#endif /* OPENSSL_VERSION_NUMBER>=0x10002000L */

NOEXPORT void compression_init() {
    STACK_OF(SSL_COMP) *methods;
    COMP_METHOD *zlib;

    memset(comp_methods, 0, sizeof comp_methods);

    /* setup COMP_NONE */
    comp_methods[COMP_NONE]=sk_SSL_COMP_new_null();

    /* setup COMP_DEFLATE (RFC 1951) */
    methods=SSL_COMP_get_compression_methods();
    if(!methods || !sk_SSL_COMP_num(methods))
        return;
    comp_methods[COMP_DEFLATE]=sk_SSL_COMP_dup(methods);

    /* setup COMP_ZLIB (DEFLATE + obsolete private id 0xe0) */
    zlib=COMP_zlib();
    if(!zlib || COMP_get_type(zlib)==NID_undef)
        return;
    if(SSL_COMP_add_compression_method(0xe0, zlib))
        return;
    comp_methods[COMP_ZLIB]=methods; /* reuse the memory */
}

NOEXPORT int compression_configure(GLOBAL_OPTIONS *global) {
    STACK_OF(SSL_COMP) *methods;
    int num_methods, i;

    if(!comp_methods[global->compression]) {
        s_log(LOG_ERR, "Configured compression is unsupported by OpenSSL");
        return 1;
    }
    SSL_COMP_set0_compression_methods(comp_methods[global->compression]);

    methods=SSL_COMP_get_compression_methods();
    num_methods=sk_SSL_COMP_num(methods);
    s_log(LOG_INFO, "Compression enabled: %d method%s",
        num_methods, num_methods==1 ? "" : "s");
    for(i=0; i<num_methods; ++i) {
        SSL_COMP *comp=sk_SSL_COMP_value(methods, i);
        if(comp) {
            const char *name=SSL_COMP_get0_name(comp);
            /* see OpenSSL commit 847406923534dd791f73d0cda15d3f17f513f2a5 */
            if(!name)
                name="unknown";
            s_log(LOG_INFO, "Compression id 0x%02x: %s",
                SSL_COMP_get_id(comp), name);
        }
    }
    return 0; /* success */
}
#endif /* OPENSSL_NO_COMP */

NOEXPORT int prng_init(GLOBAL_OPTIONS *global) {
    int totbytes=0;
    char filename[256];
    const RAND_METHOD *meth=RAND_get_rand_method();

    /* skip PRNG initialization when no seeding methods are available */
    if(meth->status==NULL || meth->add==NULL) {
        s_log(LOG_DEBUG, "No PRNG seeding methods");
        return 0; /* success */
    }

    if(RAND_status()) {
        s_log(LOG_DEBUG, "No PRNG seeding was required");
        return 0; /* success */
    }

    /* if they specify a rand file on the command line we
       assume that they really do want it, so try it first */
    if(global->rand_file) {
        totbytes+=add_rand_file(global, global->rand_file);
        if(RAND_status())
            return 0; /* success */
    }

    /* try the $RANDFILE or $HOME/.rnd files */
    filename[0]='\0';
    RAND_file_name(filename, sizeof filename);
    if(filename[0]) {
        totbytes+=add_rand_file(global, filename);
        if(RAND_status())
            return 0; /* success */
    }

#ifdef USE_WIN32

#if OPENSSL_VERSION_NUMBER<0x10100000L
    RAND_screen();
    if(RAND_status()) {
        s_log(LOG_DEBUG, "Seeded PRNG with RAND_screen");
        return 0; /* success */
    }
    s_log(LOG_DEBUG, "RAND_screen failed to sufficiently seed PRNG");
#endif

#else /* USE_WIN32 */

#ifndef OPENSSL_NO_EGD
    if(global->egd_sock) {
        int bytes=RAND_egd(global->egd_sock);
        if(bytes>=0) {
            s_log(LOG_DEBUG, "Snagged %d random bytes from EGD Socket %s",
                bytes, global->egd_sock);
            return 0; /* OpenSSL always gets what it needs or fails,
                         so no need to check if seeded sufficiently */
        }
        s_log(LOG_WARNING, "EGD Socket %s failed", global->egd_sock);
    }
#endif

#ifndef RANDOM_FILE
    /* try the good-old default /dev/urandom, if no RANDOM_FILE is defined */
    totbytes+=add_rand_file(global, "/dev/urandom");
    if(RAND_status())
        return 0; /* success */
#endif

#endif /* USE_WIN32 */

    /* random file specified during configure */
    s_log(LOG_ERR, "PRNG seeded with %d bytes total", totbytes);
    s_log(LOG_ERR, "PRNG was not seeded with enough random bytes");
    return 1; /* FAILED */
}

NOEXPORT int add_rand_file(GLOBAL_OPTIONS *global, const char *filename) {
    int readbytes;
    struct stat sb;

    if(stat(filename, &sb))
        return 0; /* could not stat() file --> return 0 bytes */

    readbytes=RAND_load_file(filename, global->random_bytes);
    if(readbytes<0) {
        sslerror("RAND_load_file");
        s_log(LOG_INFO, "Cannot retrieve any random data from %s",
            filename);
        return 0;
    }
    s_log(LOG_DEBUG, "Snagged %d random bytes from %s", readbytes, filename);

    /* write new random data for future seeding if it's a regular file */
    if(global->option.rand_write && S_ISREG(sb.st_mode))
        update_rand_file(filename);

    return readbytes;
}

NOEXPORT void update_rand_file(const char *filename) {
    int writebytes;

    writebytes=RAND_write_file(filename);
    if(writebytes<0) {
        sslerror("RAND_write_file");
        s_log(LOG_WARNING, "Failed to write strong random data to %s - "
            "may be a permissions or seeding problem", filename);
        return;
    }
    s_log(LOG_DEBUG, "Wrote %d new random bytes to %s",
        writebytes, filename);
}

/* end of ssl.c */
