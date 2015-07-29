/*
 *   stunnel       Universal SSL tunnel
 *   Copyright (C) 1998-2014 Michal Trojnara <Michal.Trojnara@mirt.net>
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

/**************************************** prototypes */

/* verify initialization */
NOEXPORT int load_file_lookup(X509_STORE *, char *);
NOEXPORT int add_dir_lookup(X509_STORE *, char *);

/* verify callback */
NOEXPORT int verify_callback(int, X509_STORE_CTX *);
NOEXPORT int verify_checks(int, X509_STORE_CTX *);
NOEXPORT int cert_check(X509_STORE_CTX *, int);
NOEXPORT int crl_check(X509_STORE_CTX *);
#ifdef HAVE_OSSL_OCSP_H
NOEXPORT int ocsp_check(X509_STORE_CTX *);
NOEXPORT OCSP_RESPONSE *ocsp_get_response(CLI *, OCSP_REQUEST *);
#endif

/* utility functions */
NOEXPORT void log_time(const int, const char *, ASN1_TIME *);

/**************************************** verify initialization */

int verify_init(SERVICE_OPTIONS *section) {
    STACK_OF(X509_NAME) *ca_dn;
    char *ca_name;
    int i;

    if(section->verify_level<0)
        return 0; /* OK - no certificate verification */

    if(section->verify_level>=2 && !section->ca_file && !section->ca_dir) {
        s_log(LOG_ERR,
            "Either CApath or CAfile has to be used for authentication");
        return 1; /* FAILED */
    }

    section->revocation_store=X509_STORE_new();
    if(!section->revocation_store) {
        sslerror("X509_STORE_new");
        return 1; /* FAILED */
    }

    if(section->ca_file) {
        if(!SSL_CTX_load_verify_locations(section->ctx,
                section->ca_file, NULL)) {
            s_log(LOG_ERR, "Error loading verify certificates from %s",
                section->ca_file);
            sslerror("SSL_CTX_load_verify_locations");
            return 1; /* FAILED */
        }
        /* revocation store needs CA certificates for CRL validation */
        if(load_file_lookup(section->revocation_store, section->ca_file))
            return 1; /* FAILED */
        /* trusted CA names sent to clients for client cert selection */
        if(!section->option.client) { /* only performed on server */
            s_log(LOG_DEBUG, "Client CA list: %s",
                section->ca_file);
            ca_dn=SSL_load_client_CA_file(section->ca_file);
            for (i=0; i<sk_X509_NAME_num(ca_dn); ++i) {
                ca_name=X509_NAME_oneline(sk_X509_NAME_value(ca_dn, i),
                    NULL, 0);
                s_log(LOG_INFO, "Client CA: %s", ca_name);
                OPENSSL_free(ca_name);
            }
            SSL_CTX_set_client_CA_list(section->ctx, ca_dn);
        }
    }

    if(section->ca_dir) {
        if(!SSL_CTX_load_verify_locations(section->ctx,
                NULL, section->ca_dir)) {
            s_log(LOG_ERR, "Error setting verify directory to %s",
                section->ca_dir);
            sslerror("SSL_CTX_load_verify_locations");
            return 1; /* FAILED */
        }
        s_log(LOG_DEBUG, "Verify directory set to %s", section->ca_dir);
        add_dir_lookup(section->revocation_store, section->ca_dir);
    }

    if(section->crl_file)
        if(load_file_lookup(section->revocation_store, section->crl_file))
            return 1; /* FAILED */

    if(section->crl_dir) {
        section->revocation_store->cache=0; /* don't cache CRLs */
        add_dir_lookup(section->revocation_store, section->crl_dir);
    }

    SSL_CTX_set_verify(section->ctx, SSL_VERIFY_PEER |
        (section->verify_level>=2 ? SSL_VERIFY_FAIL_IF_NO_PEER_CERT : 0),
        verify_callback);

    if(section->ca_dir && section->verify_level>=3)
        s_log(LOG_INFO, "Peer certificate location %s", section->ca_dir);
    return 0; /* OK */
}

NOEXPORT int load_file_lookup(X509_STORE *store, char *name) {
    X509_LOOKUP *lookup;

    lookup=X509_STORE_add_lookup(store, X509_LOOKUP_file());
    if(!lookup) {
        sslerror("X509_STORE_add_lookup");
        return 1; /* FAILED */
    }
    if(!X509_LOOKUP_load_file(lookup, name, X509_FILETYPE_PEM)) {
        s_log(LOG_ERR, "Failed to load %s revocation lookup file", name);
        sslerror("X509_LOOKUP_load_file");
        return 1; /* FAILED */
    }
    s_log(LOG_DEBUG, "Loaded %s revocation lookup file", name);
    return 0; /* OK */
}

NOEXPORT int add_dir_lookup(X509_STORE *store, char *name) {
    X509_LOOKUP *lookup;

    lookup=X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir());
    if(!lookup) {
        sslerror("X509_STORE_add_lookup");
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

/**************************************** verify callback */

NOEXPORT int verify_callback(int preverify_ok, X509_STORE_CTX *callback_ctx) {
        /* our verify callback function */
    SSL *ssl;
    CLI *c;

    /* retrieve application specific data */
    ssl=X509_STORE_CTX_get_ex_data(callback_ctx,
        SSL_get_ex_data_X509_STORE_CTX_idx());
    c=SSL_get_ex_data(ssl, cli_index);
    if(c->opt->verify_level<1) {
        s_log(LOG_INFO, "Certificate verification disabled");
        return 1; /* accept */
    }
    if(verify_checks(preverify_ok, callback_ctx))
        return 1; /* accept */
    if(c->opt->option.client || c->opt->protocol>=0)
        return 0; /* reject */
    if(c->opt->redirect_addr.num) { /* pre-resolved addresses */
        addrlist_dup(&c->connect_addr, &c->opt->redirect_addr);
        s_log(LOG_INFO, "Redirecting connection");
        return 1; /* accept */
    }
    /* delayed lookup */
    if(namelist2addrlist(&c->connect_addr,
            c->opt->redirect_list, DEFAULT_LOOPBACK)) {
        s_log(LOG_INFO, "Redirecting connection");
        return 1; /* accept */
    }
    return 0; /* reject */
}

NOEXPORT int verify_checks(int preverify_ok, X509_STORE_CTX *callback_ctx) {
    X509 *cert;
    int depth;
    char *subject;

    cert=X509_STORE_CTX_get_current_cert(callback_ctx);
    depth=X509_STORE_CTX_get_error_depth(callback_ctx);
    subject=X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);

    s_log(LOG_DEBUG, "Starting certificate verification: depth=%d, subject=%s",
        depth, subject);

    if(!cert_check(callback_ctx, preverify_ok)) {
        s_log(LOG_WARNING, "Certificate check failed: depth=%d, subject=%s",
            depth, subject);
        OPENSSL_free(subject);
        return 0; /* fail */
    }
    if(!crl_check(callback_ctx)) {
        s_log(LOG_WARNING, "CRL check failed: depth=%d, subject=%s",
            depth, subject);
        OPENSSL_free(subject);
        return 0; /* fail */
    }
#ifdef HAVE_OSSL_OCSP_H
    if(!ocsp_check(callback_ctx)) {
        s_log(LOG_WARNING, "OCSP check failed: depth=%d, subject=%s",
            depth, subject);
        OPENSSL_free(subject);
        return 0; /* fail */
    }
#endif /* HAVE_OSSL_OCSP_H */

    s_log(depth ? LOG_INFO : LOG_NOTICE,
        "Certificate accepted: depth=%d, subject=%s", depth, subject);
    OPENSSL_free(subject);
    return 1; /* success */
}

/**************************************** certificate checking */

NOEXPORT int cert_check(X509_STORE_CTX *callback_ctx, int preverify_ok) {
    SSL *ssl;
    CLI *c;
    X509_OBJECT obj;
#if OPENSSL_VERSION_NUMBER>=0x0090700fL
    ASN1_BIT_STRING *local_key, *peer_key;
#endif
    X509 *cert;
    int depth;

    ssl=X509_STORE_CTX_get_ex_data(callback_ctx,
        SSL_get_ex_data_X509_STORE_CTX_idx());
    c=SSL_get_ex_data(ssl, cli_index);
    cert=X509_STORE_CTX_get_current_cert(callback_ctx);
    depth=X509_STORE_CTX_get_error_depth(callback_ctx);

    if(!preverify_ok) {
        /* remote site specified a certificate, but it's not correct */
        if(c->opt->verify_level>=4 && depth>0) {
            s_log(LOG_INFO, "CERT: Invalid CA certificate ignored");
            return 1; /* success */
        } else {
            s_log(LOG_WARNING, "CERT: Verification error: %s",
                X509_verify_cert_error_string(
                    X509_STORE_CTX_get_error(callback_ctx)));
            return 0; /* fail */
        }
    }
    if(c->opt->verify_level>=3 && depth==0) {
        if(X509_STORE_get_by_subject(callback_ctx, X509_LU_X509,
                X509_get_subject_name(cert), &obj)!=1) {
            s_log(LOG_WARNING,
                "CERT: Certificate not found in local repository");
            return 0; /* fail */
        }
#if OPENSSL_VERSION_NUMBER>=0x0090700fL
        peer_key=X509_get0_pubkey_bitstr(cert);
        local_key=X509_get0_pubkey_bitstr(obj.data.x509);
        if(!peer_key || !local_key || peer_key->length!=local_key->length ||
                memcmp(peer_key->data, local_key->data, local_key->length)) {
            s_log(LOG_WARNING, "CERT: Public keys do not match");
            return 0; /* fail */
        }
#endif
        s_log(LOG_INFO, "CERT: Locally installed certificate matched");
    }
    return 1; /* success */
}

/**************************************** CRL checking */

/* based on BSD-style licensed code of mod_ssl */
NOEXPORT int crl_check(X509_STORE_CTX *callback_ctx) {
    SSL *ssl;
    CLI *c;
    X509_STORE_CTX store_ctx;
    X509_OBJECT obj;
    X509_NAME *subject;
    X509_NAME *issuer;
    X509 *cert;
    X509_CRL *crl;
    X509_REVOKED *revoked;
    EVP_PKEY *pubkey;
    long serial;
    int i, n, rc;
    char *cp;
    ASN1_TIME *last_update=NULL, *next_update=NULL;

    ssl=X509_STORE_CTX_get_ex_data(callback_ctx,
        SSL_get_ex_data_X509_STORE_CTX_idx());
    c=SSL_get_ex_data(ssl, cli_index);
    cert=X509_STORE_CTX_get_current_cert(callback_ctx);
    subject=X509_get_subject_name(cert);
    issuer=X509_get_issuer_name(cert);

    /* try to retrieve a CRL corresponding to the _subject_ of
     * the current certificate in order to verify it's integrity */
    memset((char *)&obj, 0, sizeof obj);
    X509_STORE_CTX_init(&store_ctx, c->opt->revocation_store, NULL, NULL);
    rc=X509_STORE_get_by_subject(&store_ctx, X509_LU_CRL, subject, &obj);
    X509_STORE_CTX_cleanup(&store_ctx);
    crl=obj.data.crl;
    if(rc>0 && crl) {
        cp=X509_NAME_oneline(subject, NULL, 0);
        s_log(LOG_INFO, "CRL: issuer: %s", cp);
        OPENSSL_free(cp);
        last_update=X509_CRL_get_lastUpdate(crl);
        next_update=X509_CRL_get_nextUpdate(crl);
        log_time(LOG_INFO, "CRL: last update", last_update);
        log_time(LOG_INFO, "CRL: next update", next_update);

        /* verify the signature on this CRL */
        pubkey=X509_get_pubkey(cert);
        if(X509_CRL_verify(crl, pubkey)<=0) {
            s_log(LOG_WARNING, "CRL: Invalid signature");
            X509_STORE_CTX_set_error(callback_ctx,
                X509_V_ERR_CRL_SIGNATURE_FAILURE);
            X509_OBJECT_free_contents(&obj);
            if(pubkey)
                EVP_PKEY_free(pubkey);
            return 0; /* fail */
        }
        if(pubkey)
            EVP_PKEY_free(pubkey);

        /* check date of CRL to make sure it's not expired */
        if(!next_update) {
            s_log(LOG_WARNING, "CRL: Invalid nextUpdate field");
            X509_STORE_CTX_set_error(callback_ctx,
                X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD);
            X509_OBJECT_free_contents(&obj);
            return 0; /* fail */
        }
        if(X509_cmp_current_time(next_update)<0) {
            s_log(LOG_WARNING, "CRL: CRL Expired - revoking all certificates");
            X509_STORE_CTX_set_error(callback_ctx, X509_V_ERR_CRL_HAS_EXPIRED);
            X509_OBJECT_free_contents(&obj);
            return 0; /* fail */
        }
        X509_OBJECT_free_contents(&obj);
    }

    /* try to retrieve a CRL corresponding to the _issuer_ of
     * the current certificate in order to check for revocation */
    memset((char *)&obj, 0, sizeof obj);
    X509_STORE_CTX_init(&store_ctx, c->opt->revocation_store, NULL, NULL);
    rc=X509_STORE_get_by_subject(&store_ctx, X509_LU_CRL, issuer, &obj);
    X509_STORE_CTX_cleanup(&store_ctx);
    crl=obj.data.crl;
    if(rc>0 && crl) {
        /* check if the current certificate is revoked by this CRL */
        n=sk_X509_REVOKED_num(X509_CRL_get_REVOKED(crl));
        for(i=0; i<n; i++) {
            revoked=sk_X509_REVOKED_value(X509_CRL_get_REVOKED(crl), i);
            if(ASN1_INTEGER_cmp(revoked->serialNumber,
                    X509_get_serialNumber(cert)) == 0) {
                serial=ASN1_INTEGER_get(revoked->serialNumber);
                cp=X509_NAME_oneline(issuer, NULL, 0);
                s_log(LOG_WARNING, "CRL: Certificate with serial %ld (0x%lX) "
                    "revoked per CRL from issuer %s", serial, serial, cp);
                OPENSSL_free(cp);
                X509_STORE_CTX_set_error(callback_ctx, X509_V_ERR_CERT_REVOKED);
                X509_OBJECT_free_contents(&obj);
                return 0; /* fail */
            }
        }
        X509_OBJECT_free_contents(&obj);
    }
    return 1; /* success */
}

#ifdef HAVE_OSSL_OCSP_H

/**************************************** OCSP checking */
/* TODO: check OCSP server specified in the certificate */

NOEXPORT int ocsp_check(X509_STORE_CTX *callback_ctx) {
    SSL *ssl;
    CLI *c;
    int error, retval=0;
    X509 *cert;
    X509 *issuer=NULL;
    OCSP_CERTID *certID;
    OCSP_REQUEST *request=NULL;
    OCSP_RESPONSE *response=NULL;
    OCSP_BASICRESP *basicResponse=NULL;
    ASN1_GENERALIZEDTIME *revoked_at=NULL,
        *this_update=NULL, *next_update=NULL;
    int status, reason;

    ssl=X509_STORE_CTX_get_ex_data(callback_ctx,
        SSL_get_ex_data_X509_STORE_CTX_idx());
    c=SSL_get_ex_data(ssl, cli_index);

    if(!c->opt->option.ocsp)
        return 1; /* success */

    /* get current certificate ID */
    cert=X509_STORE_CTX_get_current_cert(callback_ctx);
    if(X509_STORE_CTX_get1_issuer(&issuer, callback_ctx, cert)!=1) {
        sslerror("OCSP: X509_STORE_CTX_get1_issuer");
        goto cleanup;
    }
    certID=OCSP_cert_to_id(0, cert, issuer);
    if(!certID) {
        sslerror("OCSP: OCSP_cert_to_id");
        goto cleanup;
    }

    /* build request */
    request=OCSP_REQUEST_new();
    if(!request) {
        sslerror("OCSP: OCSP_REQUEST_new");
        goto cleanup;
    }
    if(!OCSP_request_add0_id(request, certID)) {
        sslerror("OCSP: OCSP_request_add0_id");
        goto cleanup;
    }
    OCSP_request_add1_nonce(request, 0, -1);

    /* send the request and get a response */
    response=ocsp_get_response(c, request);
    if(!response)
        goto cleanup;
    error=OCSP_response_status(response);
    if(error!=OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        s_log(LOG_WARNING, "OCSP: Responder error: %d: %s",
            error, OCSP_response_status_str(error));
        goto cleanup;
    }
    s_log(LOG_DEBUG, "OCSP: Response received");

    /* verify the response */
    basicResponse=OCSP_response_get1_basic(response);
    if(!basicResponse) {
        sslerror("OCSP: OCSP_response_get1_basic");
        goto cleanup;
    }
    if(OCSP_check_nonce(request, basicResponse)<=0) {
        sslerror("OCSP: OCSP_check_nonce");
        goto cleanup;
    }
    if(OCSP_basic_verify(basicResponse, NULL,
            c->opt->revocation_store, c->opt->ocsp_flags)<=0) {
        sslerror("OCSP: OCSP_basic_verify");
        goto cleanup;
    }
    if(!OCSP_resp_find_status(basicResponse, certID, &status, &reason,
            &revoked_at, &this_update, &next_update)) {
        sslerror("OCSP: OCSP_resp_find_status");
        goto cleanup;
    }
    s_log(LOG_NOTICE, "OCSP: Status: %d: %s",
        status, OCSP_cert_status_str(status));
    log_time(LOG_INFO, "OCSP: This update", this_update);
    log_time(LOG_INFO, "OCSP: Next update", next_update);
    /* check if the response is valid for at least one minute */
    if(!OCSP_check_validity(this_update, next_update, 60, -1)) {
        sslerror("OCSP: OCSP_check_validity");
        goto cleanup;
    }
    if(status==V_OCSP_CERTSTATUS_REVOKED) {
        if(reason==-1)
            s_log(LOG_WARNING, "OCSP: Certificate revoked");
        else
            s_log(LOG_WARNING, "OCSP: Certificate revoked: %d: %s",
                reason, OCSP_crl_reason_str(reason));
        log_time(LOG_NOTICE, "OCSP: Revoked at", revoked_at);
        goto cleanup;
    }
    retval=1; /* success */
cleanup:
    if(issuer)
        X509_free(issuer);
    if(request)
        OCSP_REQUEST_free(request);
    if(response)
        OCSP_RESPONSE_free(response);
    if(basicResponse)
        OCSP_BASICRESP_free(basicResponse);
    return retval;
}

NOEXPORT OCSP_RESPONSE *ocsp_get_response(CLI *c, OCSP_REQUEST *req) {
    BIO *bio=NULL;
    OCSP_REQ_CTX *req_ctx=NULL;
    OCSP_RESPONSE *resp=NULL;
    int err;

    /* connect specified OCSP server (responder) */
    c->fd=s_socket(c->opt->ocsp_addr.sa.sa_family, SOCK_STREAM, 0,
        1, "OCSP: socket (auth_user)");
    if(c->fd<0)
        goto cleanup;
    if(s_connect(c, &c->opt->ocsp_addr, addr_len(&c->opt->ocsp_addr)))
        goto cleanup;
    bio=BIO_new_fd(c->fd, BIO_NOCLOSE);
    if(!bio)
        goto cleanup;
    s_log(LOG_DEBUG, "OCSP: server connected");

    /* OCSP protocol communication loop */
    req_ctx=OCSP_sendreq_new(bio, c->opt->ocsp_path, req, -1);
    if(!req_ctx) {
        sslerror("OCSP: OCSP_sendreq_new");
        goto cleanup;
    }
    while(OCSP_sendreq_nbio(&resp, req_ctx)==-1) {
        s_poll_init(c->fds);
        s_poll_add(c->fds, c->fd, BIO_should_read(bio), BIO_should_write(bio));
        err=s_poll_wait(c->fds, c->opt->timeout_busy, 0);
        if(err==-1)
            sockerror("OCSP: s_poll_wait");
        if(err==0)
            s_log(LOG_INFO, "OCSP: s_poll_wait: TIMEOUTbusy exceeded");
        if(err<=0)
            goto cleanup;
    }
    /* s_log(LOG_DEBUG, "OCSP: context state: 0x%x", *(int *)req_ctx); */
    /* http://www.mail-archive.com/openssl-users@openssl.org/msg61691.html */
    if(!resp) {
        if(ERR_peek_error())
            sslerror("OCSP: OCSP_sendreq_nbio");
        else /* OpenSSL error: OCSP_sendreq_nbio does not use OCSPerr */
            s_log(LOG_ERR, "OCSP: OCSP_sendreq_nbio: OpenSSL internal error");
    }

cleanup:
    if(req_ctx)
        OCSP_REQ_CTX_free(req_ctx);
    if(bio)
        BIO_free_all(bio);
    if(c->fd>=0) {
        closesocket(c->fd);
        c->fd=-1; /* avoid double close on cleanup */
    }
    return resp;
}

#endif /* HAVE_OSSL_OCSP_H */

NOEXPORT void log_time(const int level, const char *txt, ASN1_TIME *t) {
    char *cp;
    BIO *bio;
    int n;

    if(!t)
        return;
    bio=BIO_new(BIO_s_mem());
    if(!bio)
        return;
    ASN1_TIME_print(bio, t);
    n=BIO_pending(bio);
    cp=str_alloc(n+1);
    n=BIO_read(bio, cp, n);
    if(n<0) {
        BIO_free(bio);
        str_free(cp);
        return;
    }
    cp[n]='\0';
    BIO_free(bio);
    s_log(level, "%s: %s", txt, cp);
    str_free(cp);
}

/* end of verify.c */
