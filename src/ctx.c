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

#include "common.h"
#include "prototypes.h"

#ifndef OPENSSL_NO_RSA
/* cache temporary keys up to 4096 bits */
#define KEY_CACHE_LENGTH 4097
/* cache temporary keys up to 1 hour */
#define KEY_CACHE_TIME 3600
static struct keytabstruct {
    RSA *key;
    time_t timeout;
} key_table[KEY_CACHE_LENGTH];
static BIGNUM *e_value;
#endif /* OPENSSL_NO_RSA */

/**************************************** prototypes */

/* RSA/DH initialization */
#ifndef OPENSSL_NO_RSA
static RSA *tmp_rsa_cb(SSL *, int, int);
static RSA *make_temp_key(int);
#endif /* OPENSSL_NO_RSA */
#ifndef OPENSSL_NO_DH
static int init_dh(SSL_CTX *, SERVICE_OPTIONS *);
#endif /* OPENSSL_NO_DH */
#ifndef OPENSSL_NO_ECDH
static int init_ecdh(SSL_CTX *, SERVICE_OPTIONS *);
#endif /* USE_ECDH */

/* loading certificate */
static int load_pem_cert(SERVICE_OPTIONS *);
static int password_cb(char *, int, int, void *);

/* session cache callbacks */
static int sess_new_cb(SSL *, SSL_SESSION *);
static SSL_SESSION *sess_get_cb(SSL *, unsigned char *, int, int *);
static void sess_remove_cb(SSL_CTX *, SSL_SESSION *);
static void cache_transfer(SSL_CTX *, const unsigned int, const unsigned,
    const unsigned char *, const unsigned int,
    const unsigned char *, const unsigned int,
    unsigned char **, unsigned int *);

/* info callbacks */
static void info_callback(const SSL *, int, int);
static void print_stats(SSL_CTX *);

static void sslerror_queue(void);

/**************************************** initialize section->ctx */

int context_init(SERVICE_OPTIONS *section) { /* init SSL context */
    struct stat st; /* buffer for stat */
#ifndef OPENSSL_NO_RSA
    int i;
#endif /* OPENSSL_NO_RSA */

    /* check if certificate exists */
    if(!section->key) /* key file not specified */
        section->key=section->cert;
#ifdef HAVE_OSSL_ENGINE_H
    if(!section->engine)
#endif
    if(section->key) {
        if(stat(section->key, &st)) {
            ioerror(section->key);
            return 0;
        }
#if !defined(USE_WIN32) && !defined(USE_OS2)
        if(st.st_mode & 7)
            s_log(LOG_WARNING, "Wrong permissions on %s", section->key);
#endif /* defined USE_WIN32 */
    }

    /* create SSL context */
    if(section->option.client)
        section->ctx=SSL_CTX_new(section->client_method);
    else /* server mode */
        section->ctx=SSL_CTX_new(section->server_method);
    SSL_CTX_set_ex_data(section->ctx, opt_index, section); /* for callbacks */
    if(!section->option.client) { /* RSA/DH/ECDH server mode initialization */
#ifndef OPENSSL_NO_RSA
        for(i=0; i<KEY_CACHE_LENGTH; ++i) {
            key_table[i].key=NULL;
            key_table[i].timeout=0;
        }
        e_value=BN_new();
        if(!e_value) {
            sslerror("BN_new");
            return 0;
        }
        if(!BN_set_word(e_value, RSA_F4)) {
            sslerror("BN_set_word");
            return 0;
        }
        SSL_CTX_set_tmp_rsa_callback(section->ctx, tmp_rsa_cb);
#endif /* OPENSSL_NO_RSA */
#ifndef OPENSSL_NO_DH
        init_dh(section->ctx, section); /* ignore the result */
#endif /* OPENSSL_NO_DH */
#ifndef OPENSSL_NO_ECDH
        init_ecdh(section->ctx, section); /* ignore the result */
#endif /* OPENSSL_NO_ECDH */
    }
    if(section->ssl_options) {
        s_log(LOG_DEBUG, "Configuration SSL options: 0x%08lX",
            section->ssl_options);
        s_log(LOG_DEBUG, "SSL options set: 0x%08lX",
            SSL_CTX_set_options(section->ctx, section->ssl_options));
    }
    if(section->cipher_list) {
        if(!SSL_CTX_set_cipher_list(section->ctx, section->cipher_list)) {
            sslerror("SSL_CTX_set_cipher_list");
            return 0;
        }
    }
    SSL_CTX_set_mode(section->ctx,
        SSL_MODE_ENABLE_PARTIAL_WRITE|SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

    /* session cache */
    SSL_CTX_set_session_cache_mode(section->ctx, SSL_SESS_CACHE_BOTH);
    SSL_CTX_set_timeout(section->ctx, section->session_timeout);
    if(section->option.sessiond) {
        SSL_CTX_sess_set_new_cb(section->ctx, sess_new_cb);
        SSL_CTX_sess_set_get_cb(section->ctx, sess_get_cb);
        SSL_CTX_sess_set_remove_cb(section->ctx, sess_remove_cb);
    }

    /* info callback */
    SSL_CTX_set_info_callback(section->ctx, info_callback);

    /* initialize certificate verification */
    if(!load_pem_cert(section))
        return 0;
    if(!verify_init(section))
        return 0;

    s_log(LOG_DEBUG, "SSL context initialized for service %s",
        section->servname);
    return 1; /* OK */
}

/**************************************** temporary RSA keys generation */

#ifndef OPENSSL_NO_RSA

static RSA *tmp_rsa_cb(SSL *s, int export, int keylen) {
    RSA *rsa;
    time_t now;
    int idx, key_is_long;
    static int long_keylen=0;

    (void)s; /* skip warning about unused parameter */
    (void)export; /* skip warning about unused parameter */
    key_is_long=keylen>=KEY_CACHE_LENGTH;
    idx=key_is_long ? 0 : keylen;
    time(&now);
    enter_critical_section(CRIT_KEYGEN);
    if(key_table[idx].timeout<now || (key_is_long && keylen!=long_keylen)) {
        rsa=key_table[idx].key;
        key_table[idx].key=make_temp_key(keylen);
        if(rsa)
            RSA_free(rsa);
        key_table[idx].timeout=now+KEY_CACHE_TIME;
        if(key_is_long)
            long_keylen=keylen;
    }
    rsa=key_table[idx].key;
    leave_critical_section(CRIT_KEYGEN);
    return rsa;
}

static RSA *make_temp_key(int keylen) {
    RSA *rsa;

    s_log(LOG_DEBUG, "Generating %d bit temporary RSA key...", keylen);
    rsa=RSA_new();
    if(!rsa) {
        sslerror("RSA_new");
        return NULL;
    }
    if(RSA_generate_key_ex(rsa, keylen, e_value, NULL)) {
        sslerror("RSA_generate_key_ex");
        return NULL;
    }
    s_log(LOG_DEBUG, "Temporary RSA key created");
    return rsa;
}

#endif /* OPENSSL_NO_RSA */

/**************************************** DH initialization */

#ifndef OPENSSL_NO_DH
static int init_dh(SSL_CTX *ctx, SERVICE_OPTIONS *section) {
    DH *dh;
    BIO *bio;

    if(!section->cert) {
        s_log(LOG_INFO, "No certificate available to load DH parameters");
        return 0; /* FAILED */
    }
    bio=BIO_new_file(section->cert, "r");
    if(!bio) {
        sslerror("BIO_new_file");
        return 0; /* FAILED */
    }
    dh=PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if(!dh) {
        while(ERR_get_error())
            ; /* OpenSSL error queue cleanup */
        s_log(LOG_INFO, "Could not load DH parameters from %s",
            section->cert);
        return 0; /* FAILED */
    }
    s_log(LOG_DEBUG, "Using DH parameters from %s", section->cert);
    SSL_CTX_set_tmp_dh(ctx, dh);
    s_log(LOG_INFO, "DH initialized with %d bit key", 8*DH_size(dh));
    DH_free(dh);
    return 1; /* OK */
}
#endif /* OPENSSL_NO_DH */

/**************************************** ECDH initialization */

#ifndef OPENSSL_NO_ECDH
static int init_ecdh(SSL_CTX *ctx, SERVICE_OPTIONS *section) {
    EC_KEY *ecdh;

    ecdh=EC_KEY_new_by_curve_name(section->curve);
    if(!ecdh) {
        s_log(LOG_ERR, "Unable to create curve for NID=%d", section->curve);
        return 0; /* FAILED */
    }
    SSL_CTX_set_tmp_ecdh(ctx, ecdh);
    SSL_CTX_set_options(ctx, SSL_OP_SINGLE_ECDH_USE);
    EC_KEY_free(ecdh);
    s_log(LOG_DEBUG, "ECDH initialized");
    return 1; /* OK */
}
#endif /* OPENSSL_NO_ECDH */

/**************************************** loading certificate */

static int cache_initialized=0;

static int load_pem_cert(SERVICE_OPTIONS *section) {
    int i, reason;
    UI_DATA ui_data;
#ifdef HAVE_OSSL_ENGINE_H
    EVP_PKEY *pkey;
    UI_METHOD *ui_method;
#endif

    if(!section->cert) /* no certificate specified */
        return 1; /* OK */

    ui_data.section=section; /* setup current section for callbacks */

    s_log(LOG_DEBUG, "Certificate: %s", section->cert);
    if(!SSL_CTX_use_certificate_chain_file(section->ctx, section->cert)) {
        s_log(LOG_ERR, "Error reading certificate file: %s", section->cert);
        sslerror("SSL_CTX_use_certificate_chain_file");
        return 0;
    }
    s_log(LOG_DEBUG, "Certificate loaded");

    s_log(LOG_DEBUG, "Key file: %s", section->key);
    SSL_CTX_set_default_passwd_cb(section->ctx, password_cb);
#ifdef HAVE_OSSL_ENGINE_H
#ifdef USE_WIN32
    ui_method=UI_create_method("stunnel WIN32 UI");
    UI_method_set_reader(ui_method, pin_cb);
#else /* USE_WIN32 */
    ui_method=UI_OpenSSL();
#endif /* USE_WIN32 */
    if(section->engine)
        for(i=1; i<=3; i++) {
            pkey=ENGINE_load_private_key(section->engine, section->key,
                ui_method, &ui_data);
            if(!pkey) {
                reason=ERR_GET_REASON(ERR_peek_error());
                if(i<=2 && (reason==7 || reason==160)) { /* wrong PIN */
                    sslerror_queue(); /* dump the error queue */
                    s_log(LOG_ERR, "Wrong PIN: retrying");
                    continue;
                }
                sslerror("ENGINE_load_private_key");
                return 0;
            }
            if(SSL_CTX_use_PrivateKey(section->ctx, pkey))
                break; /* success */
            sslerror("SSL_CTX_use_PrivateKey");
            return 0;
        }
    else
#endif /* HAVE_OSSL_ENGINE_H */
        for(i=0; i<=3; i++) {
            if(!i && !cache_initialized)
                continue; /* there is no cached value */
            SSL_CTX_set_default_passwd_cb_userdata(section->ctx,
                i ? &ui_data : NULL); /* try the cached password first */
            if(SSL_CTX_use_PrivateKey_file(section->ctx, section->key,
                    SSL_FILETYPE_PEM))
                break;
            reason=ERR_GET_REASON(ERR_peek_error());
            if(i<=2 && reason==EVP_R_BAD_DECRYPT) {
                sslerror_queue(); /* dump the error queue */
                s_log(LOG_ERR, "Wrong pass phrase: retrying");
                continue;
            }
            sslerror("SSL_CTX_use_PrivateKey_file");
            return 0;
        }
    if(!SSL_CTX_check_private_key(section->ctx)) {
        sslerror("Private key does not match the certificate");
        return 0;
    }
    s_log(LOG_DEBUG, "Private key loaded");
    return 1; /* OK */
}

static int password_cb(char *buf, int size, int rwflag, void *userdata) {
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

/**************************************** session cache callbacks */

#define CACHE_CMD_NEW     0x00
#define CACHE_CMD_GET     0x01
#define CACHE_CMD_REMOVE  0x02
#define CACHE_RESP_ERR    0x80
#define CACHE_RESP_OK     0x81

static int sess_new_cb(SSL *ssl, SSL_SESSION *sess) {
    unsigned char *val, *val_tmp;
    int val_len;

    val_len=i2d_SSL_SESSION(sess, NULL);
    val_tmp=val=str_alloc(val_len);
    if(!val)
        return 1;
    i2d_SSL_SESSION(sess, &val_tmp);

    cache_transfer(ssl->ctx, CACHE_CMD_NEW, SSL_SESSION_get_timeout(sess),
        sess->session_id, sess->session_id_length, val, val_len, NULL, NULL);
    str_free(val);
    return 1; /* leave the session in local cache for reuse */
}

static SSL_SESSION *sess_get_cb(SSL *ssl,
        unsigned char *key, int key_len, int *do_copy) {
    unsigned char *val, *val_tmp=NULL;
    unsigned int val_len=0;
    SSL_SESSION *sess;

    *do_copy = 0; /* allow the session to be freed autmatically */
    cache_transfer(ssl->ctx, CACHE_CMD_GET, 0,
        key, key_len, NULL, 0, &val, &val_len);
    if(!val)
        return NULL;
    val_tmp=val;
    sess=d2i_SSL_SESSION(NULL, (const unsigned char **)&val_tmp, val_len);
    str_free(val);
    return sess;
}

static void sess_remove_cb(SSL_CTX *ctx, SSL_SESSION *sess) {
    cache_transfer(ctx, CACHE_CMD_REMOVE, 0,
        sess->session_id, sess->session_id_length, NULL, 0, NULL, NULL);
}

#define MAX_VAL_LEN 512
typedef struct {
    u_char version, type;
    u_short timeout;
    u_char key[SSL_MAX_SSL_SESSION_ID_LENGTH];
    u_char val[MAX_VAL_LEN];
} CACHE_PACKET;

static void cache_transfer(SSL_CTX *ctx, const unsigned int type,
        const unsigned int timeout,
        const unsigned char *key, const unsigned int key_len,
        const unsigned char *val, const unsigned int val_len,
        unsigned char **ret, unsigned int *ret_len) {
    char session_id_txt[2*SSL_MAX_SSL_SESSION_ID_LENGTH+1];
    const char hex[16]="0123456789ABCDEF";
    const char *type_description[]={"new", "get", "remove"};
    unsigned int i;
    int s, len;
    SOCKADDR_UNION addr;
    struct timeval t;
    CACHE_PACKET *packet;
    SERVICE_OPTIONS *opt;

    if(ret) /* set error as the default result if required */
        *ret=NULL;

    /* log the request information */
    for(i=0; i<key_len && i<SSL_MAX_SSL_SESSION_ID_LENGTH; ++i) {
        session_id_txt[2*i]=hex[key[i]>>4];
        session_id_txt[2*i+1]=hex[key[i]&0x0f];
    }
    session_id_txt[2*i]='\0';
    s_log(LOG_INFO,
        "cache_transfer: request=%s, timeout=%u, id=%s, length=%d",
        type_description[type], timeout, session_id_txt, val_len);

    /* allocate UDP packet buffer */
    if(key_len>SSL_MAX_SSL_SESSION_ID_LENGTH) {
        s_log(LOG_ERR, "cache_transfer: session id too big (%d bytes)",
            key_len);
        return;
    }
    if(val_len>MAX_VAL_LEN) {
        s_log(LOG_ERR, "cache_transfer: encoded session too big (%d bytes)",
            key_len);
        return;
    }
    packet=str_alloc(sizeof(CACHE_PACKET));
    if(!packet) {
        s_log(LOG_ERR, "cache_transfer: packet buffer allocation failed");
        return;
    }

    /* setup packet */
    packet->version=1;
    packet->type=type;
    packet->timeout=htons((u_short)(timeout<64800?timeout:64800));/* 18 hours */
    memcpy(packet->key, key, key_len);
    memcpy(packet->val, val, val_len);

    /* create the socket */
    s=s_socket(AF_INET, SOCK_DGRAM, 0, 0, "cache_transfer: socket");
    if(s<0) {
        str_free(packet);
        return;
    }

    /* retrieve pointer to the section structure of this ctx */
    opt=SSL_CTX_get_ex_data(ctx, opt_index);
    memcpy(&addr, &opt->sessiond_addr.addr[0], sizeof addr);
    if(sendto(s, (void *)packet, sizeof(CACHE_PACKET)-MAX_VAL_LEN+val_len, 0,
            &addr.sa, addr_len(addr))<0) {
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
        if(get_last_socket_error()==EAGAIN)
            s_log(LOG_INFO, "cache_transfer: recv timeout");
        else
            sockerror("cache_transfer: recv");
        str_free(packet);
        return;
    }

    /* parse results */
    if(len<(int)sizeof(CACHE_PACKET)-MAX_VAL_LEN || /* too short */
            packet->version!=1 || /* wrong version */
            memcmp(packet->key, key, key_len)) { /* wrong session id */
        s_log(LOG_DEBUG, "cache_transfer: malformed packet received");
        str_free(packet);
        return;
    }
    if(packet->type!=CACHE_RESP_OK) {
        s_log(LOG_INFO, "cache_transfer: session not found");
        str_free(packet);
        return;
    }
    *ret_len=len-(sizeof(CACHE_PACKET)-MAX_VAL_LEN);
    *ret=str_alloc(*ret_len);
    if(!*ret) {
        s_log(LOG_ERR, "cache_transfer: return value allocation failed");
        str_free(packet);
        return;
    }
    s_log(LOG_INFO, "cache_transfer: session found");
    memcpy(*ret, packet->val, *ret_len);
    str_free(packet);
}

/**************************************** informational callback */

static void info_callback(const SSL *ssl, int where, int ret) {
    if(where & SSL_CB_LOOP)
        s_log(LOG_DEBUG, "SSL state (%s): %s",
        where & SSL_ST_CONNECT ? "connect" :
        where & SSL_ST_ACCEPT ? "accept" :
        "undefined", SSL_state_string_long(ssl));
    else if(where & SSL_CB_ALERT)
        s_log(LOG_DEBUG, "SSL alert (%s): %s: %s",
            where & SSL_CB_READ ? "read" : "write",
            SSL_alert_type_string_long(ret),
            SSL_alert_desc_string_long(ret));
    else if(where==SSL_CB_HANDSHAKE_DONE)
        print_stats(ssl->ctx);
}

static void print_stats(SSL_CTX *ctx) { /* print statistics */
    s_log(LOG_DEBUG, "%4ld items in the session cache",
        SSL_CTX_sess_number(ctx));
    s_log(LOG_DEBUG, "%4ld client connects (SSL_connect())",
        SSL_CTX_sess_connect(ctx));
    s_log(LOG_DEBUG, "%4ld client connects that finished",
        SSL_CTX_sess_connect_good(ctx));
    s_log(LOG_DEBUG, "%4ld client renegotiations requested",
        SSL_CTX_sess_connect_renegotiate(ctx));
    s_log(LOG_DEBUG, "%4ld server connects (SSL_accept())",
        SSL_CTX_sess_accept(ctx));
    s_log(LOG_DEBUG, "%4ld server connects that finished",
        SSL_CTX_sess_accept_good(ctx));
    s_log(LOG_DEBUG, "%4ld server renegotiations requested",
        SSL_CTX_sess_accept_renegotiate(ctx));
    s_log(LOG_DEBUG, "%4ld session cache hits",
        SSL_CTX_sess_hits(ctx));
    s_log(LOG_DEBUG, "%4ld external session cache hits",
        SSL_CTX_sess_cb_hits(ctx));
    s_log(LOG_DEBUG, "%4ld session cache misses",
        SSL_CTX_sess_misses(ctx));
    s_log(LOG_DEBUG, "%4ld session cache timeouts",
        SSL_CTX_sess_timeouts(ctx));
}

/**************************************** SSL error reporting */

void sslerror(char *txt) { /* OpenSSL error handler */
    unsigned long err;
    char string[120];

    err=ERR_get_error();
    if(!err) {
        s_log(LOG_ERR, "%s: Peer suddenly disconnected", txt);
        return;
    }
    sslerror_queue();
    ERR_error_string(err, string);
    s_log(LOG_ERR, "%s: %lX: %s", txt, err, string);
}

static void sslerror_queue(void) { /* recursive dump of the error queue */
    unsigned long err;
    char string[120];

    err=ERR_get_error();
    if(!err)
        return;
    sslerror_queue();
    ERR_error_string(err, string);
    s_log(LOG_ERR, "error queue: %lX : %s", err, string);
}

/* end of ctx.c */
