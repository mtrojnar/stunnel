/*
 *   stunnel       Universal SSL tunnel
 *   Copyright (c) 1998-2007 Michal Trojnara <Michal.Trojnara@mirt.net>
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
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
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

/**************************************** prototypes */

/* verify initialization */
static void load_file_lookup(X509_STORE *, char *);
static void add_dir_lookup(X509_STORE *, char *);

/* verify callback */
static int verify_callback(int, X509_STORE_CTX *);
static int cert_check(CLI *c, X509_STORE_CTX *, char *, int);
static int crl_check(CLI *c, X509_STORE_CTX *, char *);
static int ocsp_check(CLI *c, X509_STORE_CTX *, char *);

/**************************************** verify initialization */

void verify_init(LOCAL_OPTIONS *section) {
    if(section->verify_level<0)
        return; /* No certificate verification */

    if(section->verify_level>1 && !section->ca_file && !section->ca_dir) {
        s_log(LOG_ERR, "Either CApath or CAfile "
            "has to be used for authentication");
        exit(1);
    }

    section->revocation_store=X509_STORE_new();
    if(!section->revocation_store) {
        sslerror("X509_STORE_new");
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
        /* list of trusted CAs for the client to choose the right cert */
        SSL_CTX_set_client_CA_list(section->ctx,
            SSL_load_client_CA_file(section->ca_file));
        s_log(LOG_DEBUG, "Loaded verify certificates from %s",
            section->ca_file);
        load_file_lookup(section->revocation_store, section->ca_file);
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
        add_dir_lookup(section->revocation_store, section->ca_dir);
    }

    if(section->crl_file)
        load_file_lookup(section->revocation_store, section->crl_file);

    if(section->crl_dir) {
        section->revocation_store->cache=0; /* don't cache CRLs */
        add_dir_lookup(section->revocation_store, section->crl_dir);
    }

    SSL_CTX_set_verify(section->ctx, section->verify_level==SSL_VERIFY_NONE ?
        SSL_VERIFY_PEER : section->verify_level, verify_callback);

    if(section->ca_dir && section->verify_use_only_my)
        s_log(LOG_NOTICE, "Peer certificate location %s", section->ca_dir);
}

static void load_file_lookup(X509_STORE *store, char *name) {
    X509_LOOKUP *lookup;

    lookup=X509_STORE_add_lookup(store, X509_LOOKUP_file());
    if(!lookup) {
        sslerror("X509_STORE_add_lookup");
        exit(1);
    }
    if(!X509_LOOKUP_load_file(lookup, name, X509_FILETYPE_PEM)) {
        s_log(LOG_ERR, "Failed to load %s revocation lookup file", name);
        sslerror("X509_LOOKUP_load_file");
        exit(1);
    }
    s_log(LOG_DEBUG, "Loaded %s revocation lookup file", name);
}

static void add_dir_lookup(X509_STORE *store, char *name) {
    X509_LOOKUP *lookup;

    lookup=X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir());
    if(!lookup) {
        sslerror("X509_STORE_add_lookup");
        exit(1);
    }
    if(!X509_LOOKUP_add_dir(lookup, name, X509_FILETYPE_PEM)) {
        s_log(LOG_ERR, "Failed to add %s revocation lookup directory", name);
        sslerror("X509_LOOKUP_add_dir");
        exit(1);
    }
    s_log(LOG_DEBUG, "Added %s revocation lookup directory", name);
}

/**************************************** verify callback */

static int verify_callback(int preverify_ok, X509_STORE_CTX *callback_ctx) {
        /* our verify callback function */
    SSL *ssl;
    CLI *c;
    char subject_name[STRLEN];

    X509_NAME_oneline(X509_get_subject_name(callback_ctx->current_cert),
        subject_name, STRLEN);
    safestring(subject_name);

    /* retrieve the pointer to the SSL of the connection currently treated
     * and the application specific data stored into the SSL object */
    ssl=X509_STORE_CTX_get_ex_data(callback_ctx,
        SSL_get_ex_data_X509_STORE_CTX_idx());
    c=SSL_get_ex_data(ssl, cli_index);

    if(!cert_check(c, callback_ctx, subject_name, preverify_ok))
        return 0; /* reject connection */
    if(!crl_check(c, callback_ctx, subject_name))
        return 0; /* reject connection */
#if SSLEAY_VERSION_NUMBER >= 0x00907000L
    if(c->opt->option.ocsp && !ocsp_check(c, callback_ctx, subject_name))
        return 0; /* reject connection */
#endif /* OpenSSL-0.9.7 */

    /* errnum=X509_STORE_CTX_get_error(ctx); */
    s_log(LOG_NOTICE, "VERIFY OK: depth=%d, %s",
        callback_ctx->error_depth, subject_name);
    return 1; /* accept connection */
}

/**************************************** certificate checking */

static int cert_check(CLI *c, X509_STORE_CTX *callback_ctx,
        char *subject_name, int preverify_ok) {
    X509_OBJECT ret;

    if(c->opt->verify_level==SSL_VERIFY_NONE) {
        s_log(LOG_NOTICE, "VERIFY IGNORE: depth=%d, %s",
            callback_ctx->error_depth, subject_name);
        return 1; /* accept connection */
    }
    if(!preverify_ok) {
        /* remote site specified a certificate, but it's not correct */
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

/**************************************** CRL checking */

/* based on BSD-style licensed code of mod_ssl */
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

    /* determine certificate ingredients in advance */
    cert=X509_STORE_CTX_get_current_cert(callback_ctx);
    subject=X509_get_subject_name(cert);
    issuer=X509_get_issuer_name(cert);

    /* try to retrieve a CRL corresponding to the _subject_ of
     * the current certificate in order to verify it's integrity */
    memset((char *)&obj, 0, sizeof(obj));
    X509_STORE_CTX_init(&store_ctx, c->opt->revocation_store, NULL, NULL);
    rc=X509_STORE_get_by_subject(&store_ctx, X509_LU_CRL, subject, &obj);
    X509_STORE_CTX_cleanup(&store_ctx);
    crl=obj.data.crl;
    if(rc>0 && crl) {
        /* log information about CRL
         * (a little bit complicated because of ASN.1 and BIOs...) */
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

        /* verify the signature on this CRL */
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

        /* check date of CRL to make sure it's not expired */
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

    /* try to retrieve a CRL corresponding to the _issuer_ of
     * the current certificate in order to check for revocation */
    memset((char *)&obj, 0, sizeof(obj));
    X509_STORE_CTX_init(&store_ctx, c->opt->revocation_store, NULL, NULL);
    rc=X509_STORE_get_by_subject(&store_ctx, X509_LU_CRL, issuer, &obj);
    X509_STORE_CTX_cleanup(&store_ctx);
    crl=obj.data.crl;
    if(rc>0 && crl) {
        /* check if the current certificate is revoked by this CRL */
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

/**************************************** OCSP checking */

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

    /* TODO: check OCSP server specified in the certificate */
    s_log(LOG_DEBUG, "Starting OCSP verification");

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
    if(OCSP_basic_verify(basicResponse, NULL,
            c->opt->revocation_store, c->opt->ocsp_flags)<=0) {
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

/* End of verify.c */
