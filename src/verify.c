/*
 *   stunnel       TLS offloading and load-balancing proxy
 *   Copyright (C) 1998-2023 Michal Trojnara <Michal.Trojnara@stunnel.org>
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

/**************************************** prototypes */

/* verify initialization */
NOEXPORT int init_ca(SERVICE_OPTIONS *section);
NOEXPORT int init_crl(SERVICE_OPTIONS *section);
NOEXPORT int load_file_lookup(X509_STORE *, char *);
NOEXPORT int add_dir_lookup(X509_STORE *, char *);
NOEXPORT void auth_warnings(SERVICE_OPTIONS *);

/* verify callback */
NOEXPORT int verify_callback(int, X509_STORE_CTX *);
NOEXPORT int verify_checks(CLI *, int, X509_STORE_CTX *);
NOEXPORT int cert_check(CLI *, X509_STORE_CTX *, int);
#if OPENSSL_VERSION_NUMBER>=0x10002000L
NOEXPORT int cert_check_subject(CLI *, X509_STORE_CTX *);
#endif /* OPENSSL_VERSION_NUMBER>=0x10002000L */
NOEXPORT int cert_check_local(X509_STORE_CTX *);
NOEXPORT int compare_pubkeys(X509 *, X509 *);

/**************************************** verify initialization */

int verify_init(SERVICE_OPTIONS *section) {
    int verify_mode=0;

    if(init_ca(section)) {
        if(section->option.verify_chain || section->option.verify_peer) {
            s_log(LOG_ERR, "No trusted certificates found");
            return 1; /* FAILED */
        }
        s_log(LOG_INFO, "No trusted certificates found");
    }
    if(init_crl(section))
        return 1; /* FAILED */

    /* verify callback setup */
    if(section->option.request_cert) {
        verify_mode|=SSL_VERIFY_PEER;
        if(section->option.require_cert && !section->redirect_addr.names)
            verify_mode|=SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    }
    SSL_CTX_set_verify(section->ctx, verify_mode, verify_callback);

    auth_warnings(section);

    return 0; /* OK */
}

NOEXPORT int init_ca(SERVICE_OPTIONS *section) {
    STACK_OF(X509_NAME) *ca_dn=NULL;
#ifndef OPENSSL_NO_ENGINE
    NAME_LIST *ptr;
#endif

    /* CA initialization with the file and/or directory */
    if(section->ca_file || section->ca_dir) {
        if(!SSL_CTX_load_verify_locations(section->ctx,
                section->ca_file, section->ca_dir)) {
            sslerror("SSL_CTX_load_verify_locations");
        }
    }

    ca_dn=sk_X509_NAME_new_null();

#ifndef OPENSSL_NO_ENGINE
    /* CA and client CA list initialization with the engine */
    for(ptr=section->ca_engine; ptr; ptr=ptr->next) {
        X509 *cert=engine_get_cert(section->engine, ptr->name);
        if(cert) {
            X509_STORE_add_cert(SSL_CTX_get_cert_store(section->ctx), cert);
            sk_X509_NAME_push(ca_dn,
                X509_NAME_dup(X509_get_subject_name(cert)));
            X509_free(cert);
        } else {
            s_log(LOG_ERR, "CAengine failed to retrieve \"%s\"", ptr->name);
        }
    }
#endif

    /* client CA list initialization with the file and/or directory */
    if(section->ca_file)
        SSL_add_file_cert_subjects_to_stack(ca_dn, section->ca_file);
    if(section->ca_dir)
        SSL_add_dir_cert_subjects_to_stack(ca_dn, section->ca_dir);

    if(!sk_X509_NAME_num(ca_dn)) {
        sk_X509_NAME_pop_free(ca_dn, X509_NAME_free);
        return 1; /* FAILED */
    }

    if(section->option.client) {
        print_CA_list("Configured trusted server CA", ca_dn);
        sk_X509_NAME_pop_free(ca_dn, X509_NAME_free);
    } else { /* only set the client CA list on the server */
        print_CA_list("Configured trusted client CA", ca_dn);
        SSL_CTX_set_client_CA_list(section->ctx, ca_dn);
    }

    return 0; /* OK */
}

NOEXPORT int init_crl(SERVICE_OPTIONS *section) {
    X509_STORE *store;

    if(!section->crl_file && !section->crl_dir)
        return 0; /* OK (nothing to initialize) */

    store=SSL_CTX_get_cert_store(section->ctx);
    if(section->crl_file) {
        if(load_file_lookup(store, section->crl_file))
            return 1; /* FAILED */
    }
    if(section->crl_dir) {
#if OPENSSL_VERSION_NUMBER<0x10100000L
        /* do not cache CRLs (only required with OpenSSL version < 1.0.0) */
        store->cache=0;
#endif
        if(add_dir_lookup(store, section->crl_dir))
            return 1; /* FAILED */
    }
    X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
    return 0; /* OK */
}

NOEXPORT int load_file_lookup(X509_STORE *store, char *name) {
    X509_LOOKUP *lookup;

    lookup=X509_STORE_add_lookup(store, X509_LOOKUP_file());
    if(!lookup) {
        sslerror("X509_STORE_add_lookup(X509_LOOKUP_file)");
        return 1; /* FAILED */
    }
    if(!X509_load_crl_file(lookup, name, X509_FILETYPE_PEM)) {
        s_log(LOG_ERR, "Failed to load %s revocation lookup file", name);
        sslerror("X509_load_crl_file");
        return 1; /* FAILED */
    }
    s_log(LOG_DEBUG, "Loaded %s revocation lookup file", name);
    return 0; /* OK */
}

NOEXPORT int add_dir_lookup(X509_STORE *store, char *name) {
    X509_LOOKUP *lookup;

    lookup=X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir());
    if(!lookup) {
        sslerror("X509_STORE_add_lookup(X509_LOOKUP_hash_dir)");
        return 1; /* FAILED */
    }
    if(!X509_LOOKUP_add_dir(lookup, name, X509_FILETYPE_PEM)) {
        s_log(LOG_ERR, "Failed to add %s revocation lookup directory", name);
        sslerror("X509_LOOKUP_add_dir");
        return 1; /* FAILED */
    }
    s_log(LOG_DEBUG, "Added %s revocation lookup directory", name);
    return 0; /* OK */
}

/* issue warnings on insecure/missing authentication */
NOEXPORT void auth_warnings(SERVICE_OPTIONS *section) {
#ifndef OPENSSL_NO_PSK
    if(section->psk_keys)
        return;
#endif /* !defined(OPENSSL_NO_PSK) */
    /* for servers it is usually okay to accept all client
       certificates signed by a specified certificate authority */
    if(!section->option.client)
        return;
    if(section->option.verify_peer) /* verify_peer does not depend on PKI */
        return;
    if(section->option.verify_chain) {
#if OPENSSL_VERSION_NUMBER>=0x10002000L
        if(section->check_email || section->check_host || section->check_ip)
            return;
#endif /* OPENSSL_VERSION_NUMBER>=0x10002000L */
        s_log(LOG_WARNING,
            "Service [%s] uses \"verifyChain\" without subject checks",
            section->servname);
#if OPENSSL_VERSION_NUMBER<0x10002000L
        s_log(LOG_WARNING,
            "Rebuild your stunnel against OpenSSL version 1.0.2 or higher");
#endif /* OPENSSL_VERSION_NUMBER<0x10002000L */
        s_log(LOG_WARNING,
            "Use \"checkHost\" or \"checkIP\" to restrict trusted certificates");
        return;
    }
    s_log(LOG_WARNING,
        "Service [%s] needs authentication to prevent MITM attacks",
        section->servname);
}

/**************************************** verify callback */

NOEXPORT int verify_callback(int preverify_ok, X509_STORE_CTX *callback_ctx) {
        /* our verify callback function */
    SSL *ssl;
    CLI *c;

    /* retrieve application specific data */
    ssl=X509_STORE_CTX_get_ex_data(callback_ctx,
        SSL_get_ex_data_X509_STORE_CTX_idx());
    c=SSL_get_ex_data(ssl, index_ssl_cli);

    if(!c->opt->option.verify_chain && !c->opt->option.verify_peer) {
        s_log(LOG_INFO, "CERT: Certificate verification disabled");
        return 1; /* accept */
    }
    if(verify_checks(c, preverify_ok, callback_ctx))
        return 1; /* accept */
    if(c->opt->option.connect_before_ssl)
        return 0; /* reject */
    if(c->opt->redirect_addr.names) {
        SSL_SESSION *sess=SSL_get1_session(c->ssl);
        if(!sess)
            return 0; /* reject */
        if(!SSL_SESSION_set_ex_data(sess,
                index_session_authenticated, NULL)) {
            sslerror("SSL_SESSION_set_ex_data");
            SSL_SESSION_free(sess);
            return 0; /* reject */
        }
        SSL_SESSION_free(sess);
        return 1; /* accept */
    }
    return 0; /* reject */
}

NOEXPORT int verify_checks(CLI *c,
        int preverify_ok, X509_STORE_CTX *callback_ctx) {
    X509 *cert;
    int depth;
    char *subject;

    cert=X509_STORE_CTX_get_current_cert(callback_ctx);
    depth=X509_STORE_CTX_get_error_depth(callback_ctx);
    subject=X509_NAME2text(X509_get_subject_name(cert));

    s_log(LOG_DEBUG, "Verification started at depth=%d: %s", depth, subject);

    if(!cert_check(c, callback_ctx, preverify_ok)) {
        s_log(LOG_WARNING, "Rejected by CERT at depth=%d: %s", depth, subject);
        str_free(subject);
        return 0; /* reject */
    }
#ifndef OPENSSL_NO_OCSP
    if(!ocsp_check(c, callback_ctx)) {
        s_log(LOG_WARNING, "Rejected by OCSP at depth=%d: %s", depth, subject);
        str_free(subject);
        return 0; /* reject */
    }
#endif /* !defined(OPENSSL_NO_OCSP) */

    s_log(depth ? LOG_INFO : LOG_NOTICE,
        "Certificate accepted at depth=%d: %s", depth, subject);
    str_free(subject);
    return 1; /* accept */
}

/**************************************** certificate checking */

NOEXPORT int cert_check(CLI *c, X509_STORE_CTX *callback_ctx,
        int preverify_ok) {
    int err=X509_STORE_CTX_get_error(callback_ctx);
    int depth=X509_STORE_CTX_get_error_depth(callback_ctx);

    if(preverify_ok) {
        s_log(LOG_DEBUG, "CERT: Pre-verification succeeded");
    } else { /* remote site sent an invalid certificate */
        if(c->opt->option.verify_chain || (depth==0 &&
                err!=X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY &&
                err!=X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE &&
                err!=X509_V_ERR_CERT_UNTRUSTED)) {
            s_log(LOG_WARNING, "CERT: Pre-verification error: %s",
                X509_verify_cert_error_string(err));
            /* retain the STORE_CTX error produced by pre-verification */
            return 0; /* reject */
        }
        s_log(LOG_INFO, "CERT: Pre-verification error ignored: %s",
            X509_verify_cert_error_string(err));
    }

    if(depth==0) { /* additional peer certificate checks */
#if OPENSSL_VERSION_NUMBER>=0x10002000L
        if(!cert_check_subject(c, callback_ctx))
            return 0; /* reject */
#endif /* OPENSSL_VERSION_NUMBER>=0x10002000L */
        if(c->opt->option.verify_peer && !cert_check_local(callback_ctx))
            return 0; /* reject */
    }

    return 1; /* accept */
}

#if OPENSSL_VERSION_NUMBER>=0x10002000L
NOEXPORT int cert_check_subject(CLI *c, X509_STORE_CTX *callback_ctx) {
    X509 *cert=X509_STORE_CTX_get_current_cert(callback_ctx);
    NAME_LIST *ptr;
    char *peername=NULL;

    if(!c->opt->check_host && !c->opt->check_email && !c->opt->check_ip) {
        s_log(LOG_INFO, "CERT: No subject checks configured");
        return 1; /* accept */
    }

    for(ptr=c->opt->check_host; ptr; ptr=ptr->next)
        if(X509_check_host(cert, ptr->name, 0, 0, &peername)>0) {
            s_log(LOG_INFO, "CERT: Host name \"%s\" matched with \"%s\"",
                ptr->name, peername);
            OPENSSL_free(peername);
            return 1; /* accept */
        }

    for(ptr=c->opt->check_email; ptr; ptr=ptr->next)
        if(X509_check_email(cert, ptr->name, 0, 0)>0) {
            s_log(LOG_INFO, "CERT: Email address \"%s\" matched",
                ptr->name);
            return 1; /* accept */
        }

    for(ptr=c->opt->check_ip; ptr; ptr=ptr->next)
        if(X509_check_ip_asc(cert, ptr->name, 0)>0) {
            s_log(LOG_INFO, "CERT: IP address \"%s\" matched",
                ptr->name);
            return 1; /* accept */
        }

    s_log(LOG_WARNING, "CERT: Subject checks failed");
    return 0; /* reject */
}
#endif /* OPENSSL_VERSION_NUMBER>=0x10002000L */

#if OPENSSL_VERSION_NUMBER>=0x10000000L
/* modern implementation for OpenSSL version >= 1.0.0 */

NOEXPORT int cert_check_local(X509_STORE_CTX *callback_ctx) {
    X509 *cert;
    X509_NAME *subject;
    STACK_OF(X509) *sk;
    int i;

    cert=X509_STORE_CTX_get_current_cert(callback_ctx);
    subject=X509_get_subject_name(cert);

#if OPENSSL_VERSION_NUMBER<0x10100006L
#define X509_STORE_CTX_get1_certs X509_STORE_get1_certs
#endif
    /* modern API allows retrieving multiple matching certificates */
    sk=X509_STORE_CTX_get1_certs(callback_ctx, subject);
    if(sk) {
        for(i=0; i<sk_X509_num(sk); i++)
            if(compare_pubkeys(cert, sk_X509_value(sk, i))) {
                sk_X509_pop_free(sk, X509_free);
                return 1; /* accept */
            }
        sk_X509_pop_free(sk, X509_free);
    }

    s_log(LOG_WARNING, "CERT: Certificate not found in local repository");
    X509_STORE_CTX_set_error(callback_ctx, X509_V_ERR_CERT_REJECTED);
    return 0; /* reject */
}

#else /* OPENSSL_VERSION_NUMBER<0x10000000L */
/* legacy implementation for OpenSSL version < 1.0.0 */

NOEXPORT int cert_check_local(X509_STORE_CTX *callback_ctx) {
    X509 *cert;
    X509_NAME *subject;
    X509_OBJECT obj;
    int success;

    cert=X509_STORE_CTX_get_current_cert(callback_ctx);
    subject=X509_get_subject_name(cert);

    /* pre-1.0.0 API only returns a single matching certificate */
    memset((char *)&obj, 0, sizeof obj);
    if(X509_STORE_get_by_subject(callback_ctx, X509_LU_X509,
            subject, &obj)<=0) {
        s_log(LOG_WARNING, "CERT: Certificate not found in local repository");
        X509_STORE_CTX_set_error(callback_ctx, X509_V_ERR_CERT_REJECTED);
        return 0; /* reject */
    }
    success=compare_pubkeys(cert, obj.data.x509);
    X509_OBJECT_free_contents(&obj);
    if(success)
        return 1; /* accept */

    s_log(LOG_WARNING, "CERT: Public keys do not match");
    X509_STORE_CTX_set_error(callback_ctx, X509_V_ERR_CERT_REJECTED);
    return 0; /* reject */
}

#endif /* OPENSSL_VERSION_NUMBER>=0x10000000L */

NOEXPORT int compare_pubkeys(X509 *c1, X509 *c2) {
    ASN1_BIT_STRING *k1=X509_get0_pubkey_bitstr(c1);
    ASN1_BIT_STRING *k2=X509_get0_pubkey_bitstr(c2);
    if(!k1 || !k2 || k1->length!=k2->length || k1->length<0 ||
            safe_memcmp(k1->data, k2->data, (size_t)k1->length))
        return 0; /* reject */
    s_log(LOG_INFO, "CERT: Locally installed certificate matched");
    return 1; /* accept */
}

#ifndef OPENSSL_NO_ENGINE

X509 *engine_get_cert(ENGINE *engine, const char *id) {
    struct {
        const char *id;
        X509 *cert;
    } parms;

    parms.id=id;
    parms.cert=NULL;
    ENGINE_ctrl_cmd(engine, "LOAD_CERT_CTRL", 0, &parms, NULL, 1);
    if(!parms.cert)
        sslerror("ENGINE_ctrl_cmd");
    return parms.cert;
}

#endif

void print_CA_list(const char *type, const STACK_OF(X509_NAME) *ca_dn) {
    char *ca_name;
    int n, i;

    if(!ca_dn) {
        s_log(LOG_INFO, "%s list not found", type);
        return;
    }
    n=sk_X509_NAME_num(ca_dn);
    if(n==0) {
        s_log(LOG_INFO, "%s list is empty", type);
        return;
    }
    for(i=0; i<n; ++i) {
        ca_name=X509_NAME2text(sk_X509_NAME_value(ca_dn, i));
        s_log(LOG_INFO, "%s: %s", type, ca_name);
        str_free(ca_name);
    }
}

char *X509_NAME2text(X509_NAME *name) {
    char *text;
    BIO *bio;
    int n;

    bio=BIO_new(BIO_s_mem());
    if(!bio)
        return str_dup("BIO_new() failed");
    X509_NAME_print_ex(bio, name, 0,
        XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB & ~XN_FLAG_SPC_EQ);
    n=BIO_pending(bio);
    text=str_alloc((size_t)n+1);
    n=BIO_read(bio, text, n);
    if(n<0) {
        BIO_free(bio);
        str_free(text);
        return str_dup("BIO_read() failed");
    }
    text[n]='\0';
    BIO_free(bio);
    return text;
}

/* end of verify.c */
