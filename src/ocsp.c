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

#ifndef OPENSSL_NO_OCSP

#define INVALID_TIME ((time_t)-1)
#ifdef DEFINE_STACK_OF
/* defined in openssl/safestack.h:
 * DEFINE_SPECIAL_STACK_OF(OPENSSL_STRING, char) */
#else /* DEFINE_STACK_OF */
#ifndef sk_OPENSSL_STRING_num
#define sk_OPENSSL_STRING_num(st) sk_num(st)
#endif /* sk_OPENSSL_STRING_num */
#ifndef sk_OPENSSL_STRING_value
#define sk_OPENSSL_STRING_value(st, i) sk_value((st),(i))
#endif /* sk_OPENSSL_STRING_value */
#endif /* DEFINE_STACK_OF */

typedef struct {
    /* OCSP request and validation parameters */
    int depth;
    int nonce;
    int aia;
    long leeway;
    unsigned long flags;
    char *url;
    STACK_OF(X509) *chain_to_verify;
    X509 *root_ca;
    OCSP_CERTID *cert_id;

    /* OCSP validation results */
    int requested;
    int callback_ctx_error;

    /* OCSP single request and result */
    OCSP_REQUEST *request;
    OCSP_RESPONSE *response;
    ASN1_GENERALIZEDTIME *revoked_at, *this_update, *next_update;
} OCSP_PARAMS;

/**************************************** OCSP stapling callbacks */

NOEXPORT int ocsp_client_cb(SSL *, void *);
#if OPENSSL_VERSION_NUMBER>=0x10002000L
NOEXPORT int ocsp_server_cb(SSL *, void *);
#endif /* OpenSSL version 1.0.2 or later */

/**************************************** OCSP utility functions */

NOEXPORT void ocsp_params_free(OCSP_PARAMS *);
NOEXPORT void ocsp_params_cleanup(OCSP_PARAMS *);
NOEXPORT int ocsp_verify(CLI *, OCSP_PARAMS *);
NOEXPORT int check_aia(CLI *, OCSP_PARAMS *);
NOEXPORT int ocsp_request(CLI *, OCSP_PARAMS *);
NOEXPORT int ocsp_get_response(CLI *, OCSP_PARAMS *);
NOEXPORT int ocsp_response_validate(CLI *, OCSP_PARAMS *);
NOEXPORT void ocsp_params_setup_cert_id(OCSP_PARAMS *);
NOEXPORT int ocsp_params_append_root_ca(CLI *, OCSP_PARAMS *);
NOEXPORT void log_time(const int, const char *, ASN1_GENERALIZEDTIME *);
#if OPENSSL_VERSION_NUMBER>=0x10101000L
NOEXPORT time_t time_t_get_asn1_time(const ASN1_TIME *);
#endif /* OpenSSL version 1.1.1 or later */

/**************************************** OCSP initialization */

int ocsp_init(SERVICE_OPTIONS *section) {
    section->ocsp_response_lock=CRYPTO_THREAD_lock_new();
    if(section->option.client) {
        if(!SSL_CTX_set_tlsext_status_cb(section->ctx, ocsp_client_cb)) {
            sslerror("OCSP: SSL_CTX_set_tlsext_status_cb");
            return 1; /* FAILED */
        }
        s_log(LOG_DEBUG, "OCSP: Client OCSP stapling enabled");
    } else {
#if OPENSSL_VERSION_NUMBER>=0x10002000L
        if(!section->psk_keys) {
            if(SSL_CTX_set_tlsext_status_cb(section->ctx, ocsp_server_cb)==TLSEXT_STATUSTYPE_ocsp)
                s_log(LOG_DEBUG, "OCSP: Server OCSP stapling enabled");
        } else {
            s_log(LOG_NOTICE, "OCSP: Server OCSP stapling is incompatible with PSK");
        }
#else /* OpenSSL version 1.0.2 or later */
        s_log(LOG_NOTICE, "OCSP: Server OCSP stapling not supported");
#endif /* OpenSSL version 1.0.2 or later */
    }

    return 0; /* OK */
}

/* free all of the OCSP_PARAMS values */
NOEXPORT void ocsp_params_free(OCSP_PARAMS *params) {
    ocsp_params_cleanup(params);
    if(params->chain_to_verify) {
        sk_X509_free(params->chain_to_verify);
        params->chain_to_verify=NULL;
    }
    if(params->root_ca) {
        X509_free(params->root_ca);
        params->root_ca=NULL;
    }
    if(params->cert_id) {
        OCSP_CERTID_free(params->cert_id);
        params->cert_id=NULL;
    }
}

/* free the OCSP_PARAMS values required to reuse it for a next request */
NOEXPORT void ocsp_params_cleanup(OCSP_PARAMS *params) {
    if(params->response) {
        OCSP_RESPONSE_free(params->response);
        params->response=NULL;
    }
    if(params->request) {
        OCSP_REQUEST_free(params->request);
        params->request=NULL;
    }
    params->revoked_at=NULL;
    params->this_update=NULL;
    params->next_update=NULL;
}

/**************************************** OCSP cleanup */

void ocsp_cleanup(SERVICE_OPTIONS *section) {
    if(section->ocsp_response_len) {
        OPENSSL_free(section->ocsp_response_der);
        section->ocsp_response_len=0;
    }
    if(section->ocsp_response_lock)
        CRYPTO_THREAD_lock_free(section->ocsp_response_lock);
}

/**************************************** OCSP verify.c callback */

int ocsp_check(CLI *c, X509_STORE_CTX *callback_ctx) {
    OCSP_PARAMS params;
    int ret=0; /* failed */

    /* initial checks */
    if(!c->opt->option.verify_chain) {
        s_log(LOG_INFO, "OCSP: Certificate chain verification disabled");
        return 1; /* accept */
    }
    if(c->opt->option.client &&
            !X509_STORE_CTX_get_error_depth(callback_ctx) &&
            !c->opt->stapling_cb_flag) {
        /* for client peer certificate verification,
         * tlsext_status_ocsp_resp is needed for oscp_verify_ssl() */
        c->opt->verify_cb_flag=1;
        /* ocsp_verify() will be invoked from ocsp_client_cb() */
        s_log(LOG_DEBUG, "OCSP: Waiting for OCSP stapling response");
        return 1; /* accept */
    }

    /* initialize the OCSP_PARAMS structure */
    memset(&params, 0, sizeof(OCSP_PARAMS));
    params.depth=X509_STORE_CTX_get_error_depth(callback_ctx);
    params.nonce=c->opt->option.nonce;
    params.aia=c->opt->option.aia;
    params.leeway=60; /* allow for one minute leeway */
    params.flags=c->opt->ocsp_flags;
    params.url=c->opt->ocsp_url;
    params.callback_ctx_error=X509_V_ERR_APPLICATION_VERIFICATION;

    /* get the client certificate chain */
    params.chain_to_verify=sk_X509_dup(X509_STORE_CTX_get0_chain(callback_ctx));
    if(!params.chain_to_verify) {
        s_log(LOG_ERR, "OCSP: sk_X509_dup");
        goto cleanup;
    }
    ocsp_params_append_root_ca(c, &params); /* ignore failures */

    ret=ocsp_verify(c, &params);

cleanup:
    if(!ret)
        X509_STORE_CTX_set_error(callback_ctx, params.callback_ctx_error);
    ocsp_params_free(&params);
    return ret;
}

/**************************************** OCSP stapling client callback */

/*
 * Returns 0 if the response is not acceptable (the handshake will fail)
 * or 1 if it is acceptable.
 */
NOEXPORT int ocsp_client_cb(SSL *ssl, void *arg) {
    CLI *c;
    OCSP_PARAMS params;
    int ret=0; /* failed */

    (void)arg; /* squash the unused parameter warning */
    s_log(LOG_DEBUG, "OCSP stapling: Client callback called");

    c=SSL_get_ex_data(ssl, index_ssl_cli);

    /* initial checks */
    if(!c->opt->option.verify_chain) {
        s_log(LOG_INFO, "OCSP: Certificate chain verification disabled");
        return 1; /* accept */
    }
    if(SSL_session_reused(ssl)) {
        s_log(LOG_DEBUG, "OCSP: Skipped OCSP stapling (previous session reused)");
        return 1; /* accept: there is nothing we can do at session resumption */
    }
    if(!c->opt->option.client) { /* just in case */
        s_log(LOG_DEBUG, "OCSP: Client callback ignored on a server");
        return 1; /* accept */
    }
    if(!c->opt->verify_cb_flag) {
        /* for client peer certificate verification,
         * peer certificates are needed for oscp_verify_ssl() */
        c->opt->stapling_cb_flag=1;
        /* ocsp_verify() will be invoked from ocsp_check() */
        s_log(LOG_DEBUG, "OCSP: Waiting for OCSP peer certificates");
        return 1; /* accept */
    }

    /* initialize the OCSP_PARAMS structure */
    memset(&params, 0, sizeof(OCSP_PARAMS));
    params.depth=0; /* peer (leaf) certificate */
    params.nonce=c->opt->option.nonce;
    params.aia=c->opt->option.aia;
    params.leeway=60; /* allow for one minute leeway */
    params.flags=c->opt->ocsp_flags;
    params.url=c->opt->ocsp_url;

    /* get the client certificate chain */
    params.chain_to_verify=sk_X509_dup(SSL_get_peer_cert_chain(ssl));
    if(!params.chain_to_verify) {
        s_log(LOG_ERR, "OCSP: sk_X509_dup");
        goto cleanup;
    }
    ocsp_params_append_root_ca(c, &params); /* ignore failures */

    ret=ocsp_verify(c, &params);

cleanup:
    ocsp_params_free(&params);
    return ret;
}

/**************************************** OCSP stapling server callback */

#if OPENSSL_VERSION_NUMBER>=0x10002000L
/*
 * This is called when a client includes a certificate status request extension.
 * The response is either obtained from a cache, or from an OCSP responder.
 * Returns one of:
 * SSL_TLSEXT_ERR_OK - the OCSP response that has been set should be returned
 * SSL_TLSEXT_ERR_NOACK - the OCSP response should not be returned
 * SSL_TLSEXT_ERR_ALERT_FATAL - a fatal error has occurred
 */
NOEXPORT int ocsp_server_cb(SSL *ssl, void *arg) {
    CLI *c;
    OCSP_PARAMS params;
    X509 *cert;
    STACK_OF(X509) *chain=NULL;
    unsigned char *response_der=NULL;
    const unsigned char *response_tmp;
    int response_len=0, ret=SSL_TLSEXT_ERR_ALERT_FATAL;
    int ocsp_status=V_OCSP_CERTSTATUS_UNKNOWN;

    (void)arg; /* squash the unused parameter warning */
    s_log(LOG_DEBUG, "OCSP stapling: Server callback called");

    c=SSL_get_ex_data(ssl, index_ssl_cli);

    /* initialize the OCSP_PARAMS structure */
    memset(&params, 0, sizeof(OCSP_PARAMS));
    params.depth=0; /* peer (leaf) certificate */
    params.nonce=0; /* disable nonce */
    params.aia=1; /* enable AIA */
    params.leeway=30; /* allow for 30 second leeway */
    /* OCSP_basic_verify() returns success if the signer certificate
     * was found in a set of untrusted intermediate certificates */
    params.flags=OCSP_TRUSTOTHER;
    params.url=NULL; /* to be set in check_aia() */

    /* get the server certificate chain */
    cert=SSL_get_certificate(ssl);
    if(!cert) {
        s_log(LOG_ERR, "OCSP: SSL_get_certificate");
        goto cleanup;
    }
    if(!SSL_CTX_get0_chain_certs(c->opt->ctx, &chain)) {
        s_log(LOG_ERR, "OCSP: SSL_CTX_get0_chain_certs");
        goto cleanup;
    }
    if(chain) {
        params.chain_to_verify=sk_X509_dup(chain);
        if(!params.chain_to_verify) {
            s_log(LOG_ERR, "OCSP: sk_X509_dup");
            goto cleanup;
        }
    } else {
        params.chain_to_verify=sk_X509_new_null();
        if(!params.chain_to_verify) {
            s_log(LOG_ERR, "OCSP: sk_X509_new_null");
            goto cleanup;
        }
    }
    /* insert the server certificate into the chain */
    if (!sk_X509_unshift(params.chain_to_verify, cert)) {
        s_log(LOG_ERR, "OCSP: sk_X509_unshift");
        goto cleanup;
    }
    ocsp_params_append_root_ca(c, &params); /* ignore failures */

    /* retrieve the cached response */
    CRYPTO_THREAD_read_lock(c->opt->ocsp_response_lock);
    if(c->opt->ocsp_response_len) {
        response_len=c->opt->ocsp_response_len;
        response_der=OPENSSL_malloc((size_t)response_len);
        memcpy(response_der, c->opt->ocsp_response_der, (size_t)response_len);
    }
    CRYPTO_THREAD_unlock(c->opt->ocsp_response_lock);

    if(response_len) { /* found a cached response */
        /* decode */
        response_tmp=response_der;
        params.response=d2i_OCSP_RESPONSE(NULL, &response_tmp, response_len);

        /* validate */
        ocsp_status=ocsp_response_validate(c, &params);
        if(ocsp_status!=V_OCSP_CERTSTATUS_UNKNOWN) {
            s_log(LOG_DEBUG, "OCSP: Use the cached OCSP response");
            goto success;
        }

        /* cleanup */
        ERR_clear_error(); /* silence any cached errors */
        if(response_der) {
            OPENSSL_free(response_der);
            response_der=NULL;
        }
        response_len=0;
    }

    /* try fetching response from the OCSP responder */
    ocsp_status=check_aia(c, &params);
    if(ocsp_status==V_OCSP_CERTSTATUS_UNKNOWN) { /* no useful response */
        s_log(LOG_INFO, "OCSP: No OCSP stapling response to send");
        ret=SSL_TLSEXT_ERR_NOACK;
        goto cleanup;
    }

    /* encode */
    response_len=i2d_OCSP_RESPONSE(params.response, &response_der);

    if(params.next_update) {
        /* cache the newly fetched OCSP response */
        CRYPTO_THREAD_write_lock(c->opt->ocsp_response_lock);
        if(c->opt->ocsp_response_len)
            OPENSSL_free(c->opt->ocsp_response_der);
        c->opt->ocsp_response_len=response_len;
        c->opt->ocsp_response_der=OPENSSL_malloc((size_t)response_len);
        memcpy(c->opt->ocsp_response_der, response_der, (size_t)response_len);
        CRYPTO_THREAD_unlock(c->opt->ocsp_response_lock);
        s_log(LOG_DEBUG, "OCSP: Response cached");
    }

success:
    SSL_set_tlsext_status_ocsp_resp(ssl, response_der, response_len);
    s_log(LOG_DEBUG, "OCSP stapling: OCSP response sent back");
    ret=SSL_TLSEXT_ERR_OK;

cleanup:
    ocsp_params_free(&params);
    return ret;
}
#endif /* OpenSSL version 1.0.2 or later */

/**************************************** OCSP utility functions */

/*
 * Issue an OCSP client-driven request and the validate reponse.
 * Returns the error code of X509_STORE_CTX.
 * Returns 0 if the response is not acceptable (the handshake will fail)
 * or 1 if it is acceptable.
 */
NOEXPORT int ocsp_verify(CLI *c, OCSP_PARAMS *params) {
    int ocsp_status=V_OCSP_CERTSTATUS_UNKNOWN;

    /* ignoring the root certificate */
    if(params->depth==sk_X509_num(params->chain_to_verify)-1) {
        s_log(LOG_DEBUG, "OCSP: Ignoring the root certificate");
        return 1; /* accept */
    }

    if(!params->depth) { /* peer (leaf) certificate */
        const unsigned char *resp_der;
        long resp_der_len;

        if(c->opt->option.client) { /* no stapling on the server */
            /* process the stapling response if available */
            resp_der_len=SSL_get_tlsext_status_ocsp_resp(c->ssl, &resp_der);
            if(resp_der_len>0 && resp_der) {
                s_log(LOG_INFO, "OCSP: OCSP stapling response received");
                params->response=d2i_OCSP_RESPONSE(NULL, &resp_der, resp_der_len);

                /* validate */
                ocsp_status=ocsp_response_validate(c, params);
                if(ocsp_status!=V_OCSP_CERTSTATUS_UNKNOWN) {
                    params->requested=1;
                    goto cleanup;
                }
            } else {
                s_log(LOG_ERR, "OCSP: No OCSP stapling response received");
            }
        }

        if(params->url) { /* a responder URL was configured */
            s_log(LOG_NOTICE, "OCSP: Connecting the configured responder \"%s\"",
                params->url);
            ocsp_status=ocsp_request(c, params);
            if(ocsp_status!=V_OCSP_CERTSTATUS_UNKNOWN)
                goto cleanup;
        }
    }

    /* client-driven checks (configured url, aia) */
    ocsp_status=check_aia(c, params);

cleanup:
    if(!params->requested) /* neither url or aia verification was needed */
        return 1; /* accept */
    switch(ocsp_status) {
    case V_OCSP_CERTSTATUS_GOOD:
        s_log(LOG_NOTICE, "OCSP: Accepted (good)");
        return 1; /* accept */
    case V_OCSP_CERTSTATUS_REVOKED:
        s_log(LOG_ERR, "OCSP: Rejected (revoked)");
        return 0; /* reject */
    default: /* V_OCSP_CERTSTATUS_UNKNOWN */
        if(c->opt->option.ocsp_require) {
            s_log(LOG_ERR, "OCSP: Rejected (OCSPrequire = yes)");
            return 0; /* reject */
        } else {
            s_log(LOG_NOTICE, "OCSP: Accepted (OCSPrequire = no)");
            return 1; /* accept */
        }
    }
}

/*
 * OCSP AIA checks
 * Returns one of:
 *  - V_OCSP_CERTSTATUS_GOOD
 *  - V_OCSP_CERTSTATUS_REVOKED
 *  - V_OCSP_CERTSTATUS_UNKNOWN
 */
NOEXPORT int check_aia(CLI *c, OCSP_PARAMS *params) {
    int ocsp_status=V_OCSP_CERTSTATUS_UNKNOWN;
    STACK_OF(OPENSSL_STRING) *aia;
    int i, num;

    if(!params->aia)
        goto cleanup;
    aia=X509_get1_ocsp(sk_X509_value(params->chain_to_verify, params->depth));
    if(!aia) {
        s_log(LOG_INFO, "OCSP: No AIA responder URL");
        goto cleanup;
    }
    num=sk_OPENSSL_STRING_num(aia);
    if(!num) {
        s_log(LOG_INFO, "OCSP: Empty AIA responder URL list");
        goto cleanup;
    }
    for(i=0; i<num; i++) {
        params->url=sk_OPENSSL_STRING_value(aia, i);
        s_log(LOG_NOTICE, "OCSP: Connecting the AIA responder \"%s\"", params->url);
        ocsp_status=ocsp_request(c, params);
        if(ocsp_status!=V_OCSP_CERTSTATUS_UNKNOWN)
            break; /* we received a definitive response */
    }
    X509_email_free(aia);

cleanup:
    return ocsp_status;
}

/*
 * OCSP request handling.
 * Returns one of:
 *  - V_OCSP_CERTSTATUS_GOOD
 *  - V_OCSP_CERTSTATUS_REVOKED
 *  - V_OCSP_CERTSTATUS_UNKNOWN
 */
NOEXPORT int ocsp_request(CLI *c, OCSP_PARAMS *params) {
    int ocsp_status=V_OCSP_CERTSTATUS_UNKNOWN;

    /* prepare params for reuse */
    ocsp_params_cleanup(params);

    /* build request */
    params->requested=1;
    params->request=OCSP_REQUEST_new();
    if(!params->request) {
        sslerror("OCSP: OCSP_REQUEST_new");
        goto cleanup;
    }
    ocsp_params_setup_cert_id(params);
    if(!params->cert_id)
        goto cleanup;
    if(!OCSP_request_add0_id(params->request,
            OCSP_CERTID_dup(params->cert_id))) {
        sslerror("OCSP: OCSP_request_add0_id");
        goto cleanup;
    }
    if(params->nonce) {
        OCSP_request_add1_nonce(params->request, NULL, -1);
    }

    /* send the request and get a response */
    if(!ocsp_get_response(c, params)) {
        goto cleanup;
    }

    /* validate */
    ocsp_status=ocsp_response_validate(c, params);
    if(ocsp_status==V_OCSP_CERTSTATUS_REVOKED)
        params->callback_ctx_error=X509_V_ERR_CERT_REVOKED;

cleanup:
    return ocsp_status;
}

/*
 * Sends the OCSP request to the specified URL and retrieves the OCSP response.
 * Returns 0 on error or 1 if response received.
 */
NOEXPORT int ocsp_get_response(CLI *c, OCSP_PARAMS *params) {
    BIO *bio=NULL;
    OCSP_REQ_CTX *req_ctx=NULL;
    char *host=NULL, *port=NULL, *path=NULL;
    SOCKADDR_UNION addr;
    int ssl, ret=0;

    /* parse the OCSP URL */
    if(!OCSP_parse_url(params->url, &host, &port, &path, &ssl)) {
        s_log(LOG_ERR, "OCSP: Failed to parse the OCSP URL");
        goto cleanup;
    }
    if(ssl) {
        s_log(LOG_ERR, "OCSP: TLS not supported for OCSP"
            " - an additional stunnel service needs to be defined");
        goto cleanup;
    }
    if(!hostport2addr(&addr, host, port, 0)) {
        s_log(LOG_ERR, "OCSP: Failed to resolve the OCSP responder address");
        goto cleanup;
    }

    /* connect specified OCSP responder */
    c->fd=s_socket(addr.sa.sa_family, SOCK_STREAM, 0, 1, "OCSP: socket");
    if(c->fd==INVALID_SOCKET)
        goto cleanup;
    if(s_connect(c, &addr, addr_len(&addr), c->opt->timeout_ocsp))
        goto cleanup;
    bio=BIO_new_socket((int)c->fd, BIO_NOCLOSE);
    if(!bio) {
        sslerror("OCSP: BIO_new_socket");
        goto cleanup;
    }
    s_log(LOG_DEBUG, "OCSP: Connected %s:%s", host, port);

    /* initialize an HTTP request with the POST method */
#if OPENSSL_VERSION_NUMBER>=0x10000000L
    req_ctx=OCSP_sendreq_new(bio, path, NULL, -1);
#else /* OpenSSL version >= 1.0.0 */
    /* there is no way to send the Host header with older OpenSSL versions */
    req_ctx=OCSP_sendreq_new(bio, path, params->request, -1);
#endif /* OpenSSL version 1.0.0 or later */
    if(!req_ctx) {
        sslerror("OCSP: OCSP_sendreq_new");
        goto cleanup;
    }
#if OPENSSL_VERSION_NUMBER>=0x10000000L
    /* add the HTTP headers */
    if(!OCSP_REQ_CTX_add1_header(req_ctx, "Host", host)) {
        sslerror("OCSP: OCSP_REQ_CTX_add1_header");
        goto cleanup;
    }
    if(!OCSP_REQ_CTX_add1_header(req_ctx, "User-Agent", "stunnel")) {
        sslerror("OCSP: OCSP_REQ_CTX_add1_header");
        goto cleanup;
    }
    /* add the remaining HTTP headers and the OCSP request body */
    if(!OCSP_REQ_CTX_set1_req(req_ctx, params->request)) {
        sslerror("OCSP: OCSP_REQ_CTX_set1_req");
        goto cleanup;
    }
#endif /* OpenSSL version 1.0.0 or later */

    /* OCSP protocol communication loop */
    while(OCSP_sendreq_nbio(&params->response, req_ctx)==-1) {
        s_poll_init(c->fds, 0);
        s_poll_add(c->fds, c->fd, BIO_should_read(bio), BIO_should_write(bio));
        switch(s_poll_wait(c->fds, c->opt->timeout_busy, 0)) {
        case -1:
            sockerror("OCSP: s_poll_wait");
            goto cleanup;
        case 0:
            s_log(LOG_INFO, "OCSP: s_poll_wait: TIMEOUTbusy exceeded");
            goto cleanup;
        }
    }
#if 0
    s_log(LOG_DEBUG, "OCSP: context state: 0x%x", *(int *)req_ctx);
#endif
    /* http://www.mail-archive.com/openssl-users@openssl.org/msg61691.html */
    if(params->response) {
        s_log(LOG_DEBUG, "OCSP: Response received");
        ret=1;
    } else {
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
    if(c->fd!=INVALID_SOCKET) {
        closesocket(c->fd);
        c->fd=INVALID_SOCKET; /* avoid double close on cleanup */
    }
    if(host)
        OPENSSL_free(host);
    if(port)
        OPENSSL_free(port);
    if(path)
        OPENSSL_free(path);
    return ret;
}

/*
 * Validates the cached or fetched OCSP response.
 * Returns one of:
 *  - V_OCSP_CERTSTATUS_GOOD
 *  - V_OCSP_CERTSTATUS_REVOKED
 *  - V_OCSP_CERTSTATUS_UNKNOWN
 */
NOEXPORT int ocsp_response_validate(CLI *c, OCSP_PARAMS *params) {
    int response_status, reason;
    OCSP_BASICRESP *basic_response=NULL;
    int ocsp_status=V_OCSP_CERTSTATUS_UNKNOWN;

    s_log(LOG_DEBUG, "OCSP: Validate the OCSP response");
    if(!params->response) {
        s_log(LOG_ERR, "OCSP: No OCSP response");
        goto cleanup;
    }
    response_status=OCSP_response_status(params->response);
    if(response_status!=OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        s_log(LOG_ERR, "OCSP: OCSP responder error: %d: %s",
            response_status, OCSP_response_status_str(response_status));
        goto cleanup;
    }
    basic_response=OCSP_response_get1_basic(params->response);
    if(!basic_response) {
        s_log(LOG_WARNING, "OCSP: OCSP_response_get1_basic");
        goto cleanup;
    }
    if(params->request && params->nonce &&
        OCSP_check_nonce(params->request, basic_response)<=0) {
        s_log(LOG_ERR, "OCSP: Invalid or unsupported nonce");
        goto cleanup;
    }
    if(OCSP_basic_verify(basic_response, params->chain_to_verify,
        SSL_CTX_get_cert_store(c->opt->ctx), params->flags)<=0) {
        sslerror("OCSP: OCSP_basic_verify");
        goto cleanup;
    }
    ocsp_params_setup_cert_id(params);
    if(!params->cert_id)
        goto cleanup;
    if(!OCSP_resp_find_status(basic_response, params->cert_id, &ocsp_status, &reason,
        &params->revoked_at, &params->this_update, &params->next_update)) {
        s_log(LOG_WARNING, "OCSP: OCSP_resp_find_status");
        goto cleanup;
    }
    s_log(LOG_INFO, "OCSP: Status: %s", OCSP_cert_status_str(ocsp_status));
    log_time(LOG_INFO, "OCSP: This update", params->this_update);
    if(params->next_update)
        log_time(LOG_INFO, "OCSP: Next update", params->next_update);
    if(!OCSP_check_validity(params->this_update, params->next_update, params->leeway, -1)) {
        sslerror("OCSP: OCSP_check_validity");
        ocsp_status=V_OCSP_CERTSTATUS_UNKNOWN; /* override an invalid response */
    }
    switch(ocsp_status) {
    case V_OCSP_CERTSTATUS_GOOD:
        s_log(LOG_NOTICE, "OCSP: Certificate accepted");
        break;
    case V_OCSP_CERTSTATUS_REVOKED:
        if(reason==-1)
            s_log(LOG_ERR, "OCSP: Certificate revoked");
        else
            s_log(LOG_ERR, "OCSP: Certificate revoked: %d: %s",
                reason, OCSP_crl_reason_str(reason));
        log_time(LOG_NOTICE, "OCSP: Revoked at", params->revoked_at);
        break;
    case V_OCSP_CERTSTATUS_UNKNOWN:
        s_log(LOG_WARNING, "OCSP: Unknown verification status");
    }

cleanup:
    if(basic_response)
        OCSP_BASICRESP_free(basic_response);
    return ocsp_status;
}

/*
 * Create an OCSP_CERTID object from params->chain_to_verify at params->depth.
 */
NOEXPORT void ocsp_params_setup_cert_id(OCSP_PARAMS *params) {
    X509 *subject, *issuer=NULL;
    int chain_len;

    if(params->cert_id) /* already set */
        return; /* nothing to do */
    chain_len=sk_X509_num(params->chain_to_verify);
    if(params->depth<0 || params->depth>chain_len-1) { /* sanity check */
        s_log(LOG_ERR, "OCSP: INTERNAL ERROR: Invalid verification depth");
        return;
    }
    subject=sk_X509_value(params->chain_to_verify, params->depth);
    issuer=params->depth==chain_len-1 ? subject /* root CA certificate */ :
        sk_X509_value(params->chain_to_verify, params->depth+1);
    /* if dgst is NULL then SHA1 is used */
    params->cert_id=OCSP_cert_to_id(NULL, subject, issuer);
    if(!params->cert_id)
        s_log(LOG_ERR, "OCSP: Can't create an OCSP_CERTID object");
}

#if OPENSSL_VERSION_NUMBER<0x10100000L
#define X509_OBJECT_new() str_alloc(sizeof(X509_OBJECT))
#define X509_OBJECT_free(x) X509_OBJECT_free_contents(x); str_free(x)
#define X509_OBJECT_get0_X509(x) ((x)->data.x509)
#endif /* OpenSSL older than 1.1.0 */

NOEXPORT int ocsp_params_append_root_ca(CLI *c, OCSP_PARAMS *params) {
    int chain_len;
    X509 *cert;
    X509_STORE_CTX *store_ctx=NULL;
    X509_OBJECT *obj=NULL;
    int ret=0; /* failure */

    chain_len=sk_X509_num(params->chain_to_verify);
    if(!chain_len) { /* empty chain */
        s_log(LOG_ERR, "OCSP: Empty verification chain");
        goto cleanup;
    }
    cert=sk_X509_value(params->chain_to_verify, chain_len-1);
    store_ctx=X509_STORE_CTX_new();
    if(!store_ctx) {
        s_log(LOG_ERR, "OCSP: X509_STORE_CTX_new");
        goto cleanup;
    }
    if(!X509_STORE_CTX_init(store_ctx,
            SSL_CTX_get_cert_store(c->opt->ctx), NULL, NULL)) {
        s_log(LOG_ERR, "OCSP: X509_STORE_CTX_init");
        goto cleanup;
    }
    obj=X509_OBJECT_new();
    if(X509_STORE_get_by_subject(store_ctx,
            X509_LU_X509, X509_get_subject_name(cert), obj)>0) {
        goto success; /* the certificate is already trusted */
    }
    if(X509_STORE_get_by_subject(store_ctx,
            X509_LU_X509, X509_get_issuer_name(cert), obj)<=0) {
        s_log(LOG_INFO, "OCSP: The root CA certificate was not found");
        goto cleanup;
    }
    /* append the root CA certificate into the verified chain */
    params->root_ca=X509_dup(X509_OBJECT_get0_X509(obj));
    if(!params->root_ca) {
        s_log(LOG_ERR, "OCSP: X509_dup");
        goto cleanup;
    }
    if(!sk_X509_push(params->chain_to_verify, params->root_ca)) {
        s_log(LOG_ERR, "OCSP: sk_X509_push");
        goto cleanup;
    }

success:
    ret=1; /* success: a trusted root CA certificate appended to the chain */

cleanup:
    if(obj)
        X509_OBJECT_free(obj);
    if(store_ctx)
        X509_STORE_CTX_free(store_ctx);
    return ret;
}

/* Logs the time structure in a human-readable format */
NOEXPORT void log_time(const int level, const char *txt, ASN1_GENERALIZEDTIME *t) {
    char *cp;
    BIO *bio;
    int n;
#if OPENSSL_VERSION_NUMBER>=0x10101000L
    time_t posix_time;
    struct tm *timeptr;
#if defined(HAVE_LOCALTIME_R) && defined(_REENTRANT)
    struct tm timestruct;
#endif /* defined(HAVE_LOCALTIME_R) && defined(_REENTRANT) */
#endif /* OpenSSL version 1.1.1 or later */

    if(!t)
        return;
    bio=BIO_new(BIO_s_mem());
    if(!bio)
        return;
#if OPENSSL_VERSION_NUMBER>=0x10101000L
    posix_time = time_t_get_asn1_time(t);
    if(posix_time==INVALID_TIME) {
        BIO_free(bio);
        return;
    }
#if defined(HAVE_LOCALTIME_R) && defined(_REENTRANT)
    timeptr=localtime_r(&posix_time, &timestruct);
#else /* defined(HAVE_LOCALTIME_R) && defined(_REENTRANT) */
    timeptr=localtime(&posix_time);
#endif /* defined(HAVE_LOCALTIME_R) && defined(_REENTRANT) */
    BIO_printf(bio, "%04d.%02d.%02d %02d:%02d:%02d",
        timeptr->tm_year + 1900, timeptr->tm_mon + 1, timeptr->tm_mday,
        timeptr->tm_hour, timeptr->tm_min, timeptr->tm_sec);
#else /* OpenSSL version 1.1.1 or later */
    ASN1_TIME_print(bio, t);
#endif /* OpenSSL version 1.1.1 or later */

    n=BIO_pending(bio);
    cp=str_alloc((size_t)n+1);
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

#if OPENSSL_VERSION_NUMBER>=0x10101000L
/* Converts ASN1_TIME structure to time_t */
NOEXPORT time_t time_t_get_asn1_time(const ASN1_TIME *s) {
    struct tm tm;

    if ((!s) || (!ASN1_TIME_check(s))) {
        return INVALID_TIME;
    }
    /* The ASN1_TIME_to_tm() function was added in OpenSSL 1.1.1 */
    if (ASN1_TIME_to_tm(s, &tm)) {
#ifdef _WIN32
        return _mkgmtime(&tm);
#else /* defined _WIN32 */
        return timegm(&tm);
#endif /* defined _WIN32 */
    } else {
        return INVALID_TIME;
    }
}
#endif /* OpenSSL version 1.1.0 or later */

#endif /* !defined(OPENSSL_NO_OCSP) */
