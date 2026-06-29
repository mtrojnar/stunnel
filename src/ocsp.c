/*
 *   stunnel       TLS offloading and load-balancing proxy
 *   Copyright (C) 1998-2026 Michal Trojnara <Michal.Trojnara@stunnel.org>
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
    int use_nonce; /* include nonce in OCSP requests */
    int use_aia;   /* use AuthorityInfoAccess to fetch the responder URL */
    long leeway;
    unsigned long flags;
    char *url;
    STACK_OF(X509) *chain_to_verify;
    X509 *root_ca;
    OCSP_CERTID *cert_id;

    /* OCSP validation results */
    int source_found; /* found either a conclusive stapling or a responder */
    int callback_ctx_error;

    /* OCSP single request and result */
    OCSP_REQUEST *request;
    OCSP_RESPONSE *response;
    ASN1_GENERALIZEDTIME *revoked_at, *this_update, *next_update;
} OCSP_CTX;

/**************************************** OCSP stapling callbacks */

NOEXPORT int ocsp_client_cb(SSL *, void *);
#if OPENSSL_VERSION_NUMBER>=0x10002000L
NOEXPORT int ocsp_server_cb(SSL *, void *);
NOEXPORT int ocsp_set_stapling_response(CLI *);
#endif /* OpenSSL version 1.0.2 or later */

/**************************************** OCSP utility functions */

NOEXPORT void ocsp_ctx_free(OCSP_CTX *);
NOEXPORT void ocsp_ctx_cleanup(OCSP_CTX *);
NOEXPORT int ocsp_verify(CLI *, OCSP_CTX *);
NOEXPORT int check_aia(CLI *, SERVICE_OPTIONS *, OCSP_CTX *);
NOEXPORT int ocsp_request(CLI *c, SERVICE_OPTIONS *, OCSP_CTX *);
NOEXPORT int ocsp_get_response(SERVICE_OPTIONS *, OCSP_CTX *);
NOEXPORT int ocsp_response_validate(CLI *, SERVICE_OPTIONS *, OCSP_CTX *);
NOEXPORT void ocsp_ctx_setup_cert_id(OCSP_CTX *);
NOEXPORT int ocsp_ctx_append_root_ca(SERVICE_OPTIONS *, OCSP_CTX *);
NOEXPORT void log_time(const int, const char *, ASN1_GENERALIZEDTIME *);
#if OPENSSL_VERSION_NUMBER>=0x10101000L
NOEXPORT time_t time_t_get_asn1_time(const ASN1_TIME *);
#endif /* OpenSSL version 1.1.1 or later */

/**************************************** OCSP initialization */

int ocsp_init(SERVICE_OPTIONS *section) {
    section->ocsp_response_lock=CRYPTO_THREAD_lock_new();
    if(section->option.client) {
        if(!SSL_CTX_set_tlsext_status_cb(section->ctx, ocsp_client_cb)) {
            ssl_error(NULL, "OCSP: SSL_CTX_set_tlsext_status_cb");
            return 1; /* FAILED */
        }
        s_log(LOG_DEBUG, "OCSP: Client OCSP stapling enabled");
    } else {
#if OPENSSL_VERSION_NUMBER>=0x10002000L
#ifndef OPENSSL_NO_PSK
        if(!section->psk_keys) {
#endif /* !defined(OPENSSL_NO_PSK) */
            if(SSL_CTX_set_tlsext_status_cb(section->ctx, ocsp_server_cb)) {
                ocsp_stapling(section);
                s_log(LOG_DEBUG, "OCSP: Server OCSP stapling enabled");
            } else {
                s_log(LOG_NOTICE, "OCSP: Server OCSP stapling not supported");
            }
#ifndef OPENSSL_NO_PSK
        } else {
            s_log(LOG_NOTICE, "OCSP: Server OCSP stapling is incompatible with PSK");
        }
#endif /* !defined(OPENSSL_NO_PSK) */
#else /* OpenSSL version 1.0.2 or later */
        s_log(LOG_NOTICE, "OCSP: Server OCSP stapling not supported");
#endif /* OpenSSL version 1.0.2 or later */
    }

    return 0; /* OK */
}

/* free all of the OCSP_CTX values */
NOEXPORT void ocsp_ctx_free(OCSP_CTX *ocsp) {
    ocsp_ctx_cleanup(ocsp);
    if(ocsp->chain_to_verify) {
        sk_X509_free(ocsp->chain_to_verify);
        ocsp->chain_to_verify=NULL;
    }
    if(ocsp->root_ca) {
        X509_free(ocsp->root_ca);
        ocsp->root_ca=NULL;
    }
    if(ocsp->cert_id) {
        OCSP_CERTID_free(ocsp->cert_id);
        ocsp->cert_id=NULL;
    }
}

/* free the OCSP_CTX values required to reuse it for a next request */
NOEXPORT void ocsp_ctx_cleanup(OCSP_CTX *ocsp) {
    if(ocsp->response) {
        OCSP_RESPONSE_free(ocsp->response);
        ocsp->response=NULL;
    }
    if(ocsp->request) {
        OCSP_REQUEST_free(ocsp->request);
        ocsp->request=NULL;
    }
    ocsp->revoked_at=NULL;
    ocsp->this_update=NULL;
    ocsp->next_update=NULL;
}

/**************************************** OCSP cleanup */

void ocsp_cleanup(SERVICE_OPTIONS *section) {
    if(section->ocsp_response_len) {
        str_free(section->ocsp_response_der);
        section->ocsp_response_len=0;
    }
    if(section->ocsp_response_lock)
        CRYPTO_THREAD_lock_free(section->ocsp_response_lock);
}

/**************************************** OCSP verify.c callback */

int ocsp_check(CLI *c, X509_STORE_CTX *callback_ctx) {
    OCSP_CTX ocsp;
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

    /* initialize the OCSP_CTX structure */
    memset(&ocsp, 0, sizeof(OCSP_CTX));
    ocsp.depth=X509_STORE_CTX_get_error_depth(callback_ctx);
    ocsp.use_nonce=c->opt->option.nonce;
    ocsp.use_aia=c->opt->option.aia;
    ocsp.leeway=60; /* allow for one minute leeway */
    ocsp.flags=c->opt->ocsp_flags;
    ocsp.url=c->opt->ocsp_url;
    ocsp.source_found=0;
    ocsp.callback_ctx_error=X509_V_ERR_APPLICATION_VERIFICATION;

    /* get the client certificate chain */
    ocsp.chain_to_verify=sk_X509_dup(X509_STORE_CTX_get0_chain(callback_ctx));
    if(!ocsp.chain_to_verify) {
        s_log(LOG_ERR, "OCSP: sk_X509_dup");
        goto cleanup;
    }
    ocsp_ctx_append_root_ca(c->opt, &ocsp); /* ignore failures */

    ret=ocsp_verify(c, &ocsp);

cleanup:
    if(!ret)
        X509_STORE_CTX_set_error(callback_ctx, ocsp.callback_ctx_error);
    ocsp_ctx_free(&ocsp);
    return ret;
}

/**************************************** OCSP stapling client callback */

/*
 * Returns 0 if the response is not acceptable (the handshake will fail)
 * or 1 if it is acceptable.
 */
NOEXPORT int ocsp_client_cb(SSL *ssl, void *arg) {
    CLI *c;
    OCSP_CTX ocsp;
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

    /* initialize the OCSP_CTX structure */
    memset(&ocsp, 0, sizeof(OCSP_CTX));
    ocsp.depth=0; /* peer (leaf) certificate */
    ocsp.use_nonce=c->opt->option.nonce;
    ocsp.use_aia=c->opt->option.aia;
    ocsp.leeway=60; /* allow for one minute leeway */
    ocsp.flags=c->opt->ocsp_flags;
    ocsp.url=c->opt->ocsp_url;
    ocsp.source_found=0;
    ocsp.callback_ctx_error=0;

    /* get the client certificate chain */
    ocsp.chain_to_verify=sk_X509_dup(SSL_get_peer_cert_chain(ssl));
    if(!ocsp.chain_to_verify) {
        s_log(LOG_ERR, "OCSP: sk_X509_dup");
        goto cleanup;
    }
    ocsp_ctx_append_root_ca(c->opt, &ocsp); /* ignore failures */
    ret=ocsp_verify(c, &ocsp);

cleanup:
    ocsp_ctx_free(&ocsp);
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
    int ret;

    (void)arg; /* squash the unused parameter warning */
    s_log(LOG_DEBUG, "OCSP stapling: Server callback called");

    c=SSL_get_ex_data(ssl, index_ssl_cli);
#ifdef USE_OS_THREADS /* use the stapling cached by a cron thread */
    ret=ocsp_set_stapling_response(c);
#else /* attempt to fetch a stapling each time */
    ret=ocsp_stapling(c->opt);
    if(ret==SSL_TLSEXT_ERR_OK)
        ret=ocsp_set_stapling_response(c);
#endif /* USE_OS_THREADS */
    return ret;
}

/*
 * Validate the stapling cache and update it if needed.
 * Returns one of:
 * SSL_TLSEXT_ERR_OK - the OCSP response that has been set should be returned
 * SSL_TLSEXT_ERR_NOACK - the OCSP response should not be returned
 * SSL_TLSEXT_ERR_ALERT_FATAL - a fatal error has occurred
 */
int ocsp_stapling(SERVICE_OPTIONS *opt) {
    OCSP_CTX ocsp;
    X509 *cert;
    STACK_OF(X509) *chain=NULL;
    unsigned char *response_der=NULL;
    const unsigned char *response_tmp;
    int response_len=0, ret=SSL_TLSEXT_ERR_ALERT_FATAL;
    int ocsp_status=V_OCSP_CERTSTATUS_UNKNOWN;

    /* initialize the OCSP_CTX structure */
    memset(&ocsp, 0, sizeof(OCSP_CTX));
    ocsp.depth=0; /* peer (leaf) certificate */
    ocsp.use_nonce=0; /* disable nonce */
    ocsp.use_aia=1; /* enable AIA */
    ocsp.leeway=30; /* allow for 30 second leeway */
    /* OCSP_basic_verify() returns success if the signer certificate
     * was found in a set of untrusted intermediate certificates */
    ocsp.flags=OCSP_TRUSTOTHER;
    ocsp.url=NULL; /* to be set in check_aia() */
    ocsp.source_found=0;
    ocsp.callback_ctx_error=0;

    /* get the server certificate chain */
    cert=SSL_CTX_get0_certificate(opt->ctx);
    if(!cert) {
        s_log(LOG_ERR, "OCSP: SSL_get_certificate");
        goto cleanup;
    }
    if(!SSL_CTX_get0_chain_certs(opt->ctx, &chain)) {
        s_log(LOG_ERR, "OCSP: SSL_CTX_get0_chain_certs");
        goto cleanup;
    }
    if(chain) {
        ocsp.chain_to_verify=sk_X509_dup(chain);
        if(!ocsp.chain_to_verify) {
            s_log(LOG_ERR, "OCSP: sk_X509_dup");
            goto cleanup;
        }
    } else {
        ocsp.chain_to_verify=sk_X509_new_null();
        if(!ocsp.chain_to_verify) {
            s_log(LOG_ERR, "OCSP: sk_X509_new_null");
            goto cleanup;
        }
    }
    /* insert the server certificate into the chain */
    if (!sk_X509_unshift(ocsp.chain_to_verify, cert)) {
        s_log(LOG_ERR, "OCSP: sk_X509_unshift");
        goto cleanup;
    }
    ocsp_ctx_append_root_ca(opt, &ocsp); /* ignore failures */

    /* retrieve the cached response */
    CRYPTO_THREAD_read_lock(opt->ocsp_response_lock);
    if(opt->ocsp_response_len) {
        response_len=opt->ocsp_response_len;
        response_der=str_alloc((size_t)response_len);
        memcpy(response_der, opt->ocsp_response_der, (size_t)response_len);
    }
    CRYPTO_THREAD_unlock(opt->ocsp_response_lock);

    if(response_len) { /* found a cached response */
        /* decode */
        response_tmp=response_der;
        ocsp.response=d2i_OCSP_RESPONSE(NULL, &response_tmp, response_len);

        /* validate */
        ocsp_status=ocsp_response_validate(NULL, opt, &ocsp);

        /* cleanup */
        ERR_clear_error(); /* silence any cached errors */
        if(response_der) {
            str_free(response_der);
            response_der=NULL;
        }
        response_len=0;

        /* skip fetching if we have a conclusive status */
        if(ocsp_status!=V_OCSP_CERTSTATUS_UNKNOWN) {
            s_log(LOG_DEBUG, "OCSP: Use the cached OCSP response");
            ret=SSL_TLSEXT_ERR_OK;
            goto cleanup;
        }
    }

    /* invalidate the cache */
    CRYPTO_THREAD_write_lock(opt->ocsp_response_lock);
    if(opt->ocsp_response_len) {
        opt->ocsp_response_len=0;
        str_free(opt->ocsp_response_der);
        opt->ocsp_response_der=NULL;
    }
    CRYPTO_THREAD_unlock(opt->ocsp_response_lock);

    /* try fetching response from the OCSP responder */
    ocsp_status=check_aia(NULL, opt, &ocsp);
    if(ocsp_status==V_OCSP_CERTSTATUS_UNKNOWN) { /* no useful response */
        s_log(LOG_INFO, "OCSP: No OCSP stapling response to send");
        ret=SSL_TLSEXT_ERR_NOACK;
        goto cleanup;
    }

    /* encode */
    response_len=i2d_OCSP_RESPONSE(ocsp.response, &response_der);

    /* update the cache */
    if(ocsp.next_update) {
        /* cache the newly fetched OCSP response */
        CRYPTO_THREAD_write_lock(opt->ocsp_response_lock);
        opt->ocsp_response_len=response_len;
        opt->ocsp_response_der=str_alloc_detached((size_t)response_len);
        memcpy(opt->ocsp_response_der, response_der, (size_t)response_len);
        CRYPTO_THREAD_unlock(opt->ocsp_response_lock);
        s_log(LOG_DEBUG, "OCSP: Response cached");
    }

    OPENSSL_free(response_der);
    ret=SSL_TLSEXT_ERR_OK;

cleanup:
    ocsp_ctx_free(&ocsp);
    return ret;
}

/* Set the stapling response based on our cache.
 * Returns one of:
 * SSL_TLSEXT_ERR_OK - the OCSP response that has been set should be returned
 * SSL_TLSEXT_ERR_NOACK - the OCSP response should not be returned
 * SSL_TLSEXT_ERR_ALERT_FATAL - a fatal error has occurred
 */
NOEXPORT int ocsp_set_stapling_response(CLI *c) {
    int ret=SSL_TLSEXT_ERR_NOACK;

    if(!c->opt->ocsp_response_len) /* performance optimization */
        return ret; /* return without locking */

    CRYPTO_THREAD_read_lock(c->opt->ocsp_response_lock);
    if(c->opt->ocsp_response_len) {
        unsigned char *response_der=
            OPENSSL_malloc((size_t)c->opt->ocsp_response_len);

        memcpy(response_der, c->opt->ocsp_response_der,
            (size_t)c->opt->ocsp_response_len);
        /* SSL_set_tlsext_status_ocsp_resp requires *us* to allocate the
         * response with OPENSSL_malloc(), but it will free it for us */
        SSL_set_tlsext_status_ocsp_resp(c->ssl,
            response_der, c->opt->ocsp_response_len);
        ret=SSL_TLSEXT_ERR_OK;
    }
    CRYPTO_THREAD_unlock(c->opt->ocsp_response_lock);
    if(ret==SSL_TLSEXT_ERR_OK)
        s_log(LOG_DEBUG, "OCSP stapling: OCSP response sent back");
    return ret;
}

#endif /* OpenSSL version 1.0.2 or later */

/**************************************** OCSP utility functions */

/*
 * Issue an OCSP client-driven request and the validate response.
 * Returns the error code of X509_STORE_CTX.
 * Returns 0 if the response is not acceptable (the handshake will fail)
 * or 1 if it is acceptable.
 */
NOEXPORT int ocsp_verify(CLI *c, OCSP_CTX *ocsp) {
    int ocsp_status=V_OCSP_CERTSTATUS_UNKNOWN;

    /* ignoring the root certificate */
    if(ocsp->depth==sk_X509_num(ocsp->chain_to_verify)-1) {
        s_log(LOG_DEBUG, "OCSP: Ignoring the root certificate");
        return 1; /* accept */
    }

    if(!ocsp->depth) { /* peer (leaf) certificate */
        const unsigned char *resp_der;
        long resp_der_len;

        if(c->opt->option.client) { /* no stapling on the server */
            /* process the stapling response if available */
            resp_der_len=SSL_get_tlsext_status_ocsp_resp(c->ssl, &resp_der);
            if(resp_der_len>0 && resp_der) {
                s_log(LOG_INFO, "OCSP: OCSP stapling response received");
                ocsp->response=d2i_OCSP_RESPONSE(NULL, &resp_der, resp_der_len);
                /* validate */
                ocsp_status=ocsp_response_validate(c, c->opt, ocsp);
                if(ocsp_status!=V_OCSP_CERTSTATUS_UNKNOWN)
                    ocsp->source_found=1; /* conclusive stapling found */
            } else {
                s_log(LOG_INFO, "OCSP: No OCSP stapling response received");
            }
        }

        if(ocsp_status==V_OCSP_CERTSTATUS_UNKNOWN && ocsp->url) {
            /* ocsp_request() from a statically configured responder URL */
            s_log(LOG_NOTICE, "OCSP: Connecting the configured responder \"%s\"",
                ocsp->url);
            ocsp_status=ocsp_request(c, c->opt, ocsp);
        }
    }

    if(ocsp_status==V_OCSP_CERTSTATUS_UNKNOWN)
        /* ocsp_request() from AIA responders defined in the certificate */
        ocsp_status=check_aia(c, c->opt, ocsp);

    if(!ocsp->source_found) /* to conclusive stapling or ocsp_request() */
        return 1; /* accept */
    if(ocsp_status==V_OCSP_CERTSTATUS_GOOD) {
        s_log(LOG_NOTICE, "OCSP: Accepted (good)");
        return 1; /* accept */
    }
    if(ocsp_status==V_OCSP_CERTSTATUS_REVOKED) {
        s_log(LOG_ERR, "OCSP: Rejected (revoked)");
        return 0; /* reject */
    }
    if(c->opt->option.ocsp_require) {
        s_log(LOG_ERR, "OCSP: Rejected (OCSPrequire = yes)");
        return 0; /* reject */
    }
    s_log(LOG_NOTICE, "OCSP: Accepted (OCSPrequire = no)");
    return 1; /* accept */
}

/*
 * OCSP AIA checks
 * Returns one of:
 *  - V_OCSP_CERTSTATUS_GOOD
 *  - V_OCSP_CERTSTATUS_REVOKED
 *  - V_OCSP_CERTSTATUS_UNKNOWN
 */
NOEXPORT int check_aia(CLI *c, SERVICE_OPTIONS *opt, OCSP_CTX *ocsp) {
    int ocsp_status=V_OCSP_CERTSTATUS_UNKNOWN;
    STACK_OF(OPENSSL_STRING) *aia;
    int i, num;

    if(!ocsp->use_aia)
        goto cleanup;
    aia=X509_get1_ocsp(sk_X509_value(ocsp->chain_to_verify, ocsp->depth));
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
        ocsp->url=sk_OPENSSL_STRING_value(aia, i);
        s_log(LOG_NOTICE, "OCSP: Connecting the AIA responder \"%s\"", ocsp->url);
        ocsp_status=ocsp_request(c, opt, ocsp);
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
NOEXPORT int ocsp_request(CLI *c, SERVICE_OPTIONS *opt, OCSP_CTX *ocsp) {
    int ocsp_status=V_OCSP_CERTSTATUS_UNKNOWN;

    /* prepare params for reuse */
    ocsp_ctx_cleanup(ocsp);

    /* build request */
    ocsp->source_found=1; /* either AIA or a configured responder */
    ocsp->request=OCSP_REQUEST_new();
    if(!ocsp->request) {
        ssl_error(c, "OCSP: OCSP_REQUEST_new");
        goto cleanup;
    }
    ocsp_ctx_setup_cert_id(ocsp);
    if(!ocsp->cert_id)
        goto cleanup;
    if(!OCSP_request_add0_id(ocsp->request,
            OCSP_CERTID_dup(ocsp->cert_id))) {
        ssl_error(c, "OCSP: OCSP_request_add0_id");
        goto cleanup;
    }
    if(ocsp->use_nonce) {
        OCSP_request_add1_nonce(ocsp->request, NULL, -1);
    }

    /* send the request and get a response */
    if(!ocsp_get_response(opt, ocsp)) {
        goto cleanup;
    }

    /* validate */
    ocsp_status=ocsp_response_validate(NULL, opt, ocsp);
    if(ocsp_status==V_OCSP_CERTSTATUS_REVOKED)
        ocsp->callback_ctx_error=X509_V_ERR_CERT_REVOKED;

cleanup:
    return ocsp_status;
}

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wclobbered"
#endif
/*
 * Send the OCSP request over HTTP and read the responder's reply.
 * A lightweight CLI structure is created only for socket handling.
 */
NOEXPORT int ocsp_get_response(SERVICE_OPTIONS *opt, OCSP_CTX *ocsp) {
    BIO *bio=NULL;
    OCSP_REQ_CTX *req_ctx=NULL;
    char *host=NULL, *port=NULL, *path=NULL;
    SOCKADDR_UNION addr;
    int ssl, ret=0;
    CLI *c; /* TODO */
    jmp_buf exception_buffer; /* TODO */

    /* fake a CLI structure only for the socket API */
    /* TODO: rewrite the network.c API:
     * - move c->fd, c->fds, and c->exception_pointer into a separate structure
     * - put this new structure inside CLI and here
     * - rewrite the network.c interface to use this structure */
    c=str_alloc(sizeof(CLI));
    c->fds=s_poll_alloc();
    c->fd=INVALID_SOCKET;
    c->exception_pointer=&exception_buffer;
    if(setjmp(exception_buffer)) {
        s_poll_free(c->fds);
        str_free(c);
        return 0;
    }

    /* parse the OCSP URL */
    if(!OCSP_parse_url(ocsp->url, &host, &port, &path, &ssl)) {
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
    if(s_connect(c, &addr, addr_len(&addr), opt->timeout_ocsp))
        goto cleanup;
    bio=BIO_new_socket((int)c->fd, BIO_NOCLOSE);
    if(!bio) {
        ssl_error(c, "OCSP: BIO_new_socket");
        goto cleanup;
    }
    s_log(LOG_DEBUG, "OCSP: Connected %s:%s", host, port);

    /* initialize an HTTP request with the POST method */
#if OPENSSL_VERSION_NUMBER>=0x10000000L
    req_ctx=OCSP_sendreq_new(bio, path, NULL, -1);
#else /* OpenSSL version >= 1.0.0 */
    /* there is no way to send the Host header with older OpenSSL versions */
    req_ctx=OCSP_sendreq_new(bio, path, ocsp->request, -1);
#endif /* OpenSSL version 1.0.0 or later */
    if(!req_ctx) {
        ssl_error(c, "OCSP: OCSP_sendreq_new");
        goto cleanup;
    }
#if OPENSSL_VERSION_NUMBER>=0x10000000L
    /* add the HTTP headers */
    if(!OCSP_REQ_CTX_add1_header(req_ctx, "Host", host)) {
        ssl_error(c, "OCSP: OCSP_REQ_CTX_add1_header");
        goto cleanup;
    }
    if(!OCSP_REQ_CTX_add1_header(req_ctx, "User-Agent", "stunnel")) {
        ssl_error(c, "OCSP: OCSP_REQ_CTX_add1_header");
        goto cleanup;
    }
    /* add the remaining HTTP headers and the OCSP request body */
    if(!OCSP_REQ_CTX_set1_req(req_ctx, ocsp->request)) {
        ssl_error(c, "OCSP: OCSP_REQ_CTX_set1_req");
        goto cleanup;
    }
#endif /* OpenSSL version 1.0.0 or later */

    /* OCSP protocol communication loop */
    while(OCSP_sendreq_nbio(&ocsp->response, req_ctx)==-1) {
        s_poll_init(c->fds, 0);
        s_poll_add(c->fds, c->fd, BIO_should_read(bio), BIO_should_write(bio));
        switch(s_poll_wait(c->fds, opt->timeout_busy, 0)) {
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
    if(ocsp->response) {
        s_log(LOG_DEBUG, "OCSP: Response received");
        ret=1;
    } else {
        if(ERR_peek_error())
            ssl_error(c, "OCSP: OCSP_sendreq_nbio");
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
    s_poll_free(c->fds); /* TODO */
    str_free(c); /* TODO */
    return ret;
}
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

/*
 * Validates the cached or fetched OCSP response.
 * Returns one of:
 *  - V_OCSP_CERTSTATUS_GOOD
 *  - V_OCSP_CERTSTATUS_REVOKED
 *  - V_OCSP_CERTSTATUS_UNKNOWN
 */
NOEXPORT int ocsp_response_validate(CLI *c, SERVICE_OPTIONS *opt, OCSP_CTX *ocsp) {
    int response_status, reason;
    OCSP_BASICRESP *basic_response=NULL;
    int ocsp_status=V_OCSP_CERTSTATUS_UNKNOWN;

    s_log(LOG_DEBUG, "OCSP: Validate the OCSP response");
    if(!ocsp->response) {
        s_log(LOG_ERR, "OCSP: No OCSP response");
        goto cleanup;
    }
    response_status=OCSP_response_status(ocsp->response);
    if(response_status!=OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        s_log(LOG_ERR, "OCSP: OCSP responder error: %d: %s",
            response_status, OCSP_response_status_str(response_status));
        goto cleanup;
    }
    basic_response=OCSP_response_get1_basic(ocsp->response);
    if(!basic_response) {
        s_log(LOG_WARNING, "OCSP: OCSP_response_get1_basic");
        goto cleanup;
    }
    if(ocsp->request && ocsp->use_nonce &&
        OCSP_check_nonce(ocsp->request, basic_response)<=0) {
        s_log(LOG_ERR, "OCSP: Invalid or unsupported nonce");
        goto cleanup;
    }
    if(OCSP_basic_verify(basic_response, ocsp->chain_to_verify,
        SSL_CTX_get_cert_store(opt->ctx), ocsp->flags)<=0) {
        ssl_error(c, "OCSP: OCSP_basic_verify");
        goto cleanup;
    }
    ocsp_ctx_setup_cert_id(ocsp);
    if(!ocsp->cert_id)
        goto cleanup;
    if(!OCSP_resp_find_status(basic_response, ocsp->cert_id, &ocsp_status, &reason,
        &ocsp->revoked_at, &ocsp->this_update, &ocsp->next_update)) {
        s_log(LOG_WARNING, "OCSP: OCSP_resp_find_status");
        goto cleanup;
    }
    s_log(LOG_INFO, "OCSP: Status: %s", OCSP_cert_status_str(ocsp_status));
    log_time(LOG_INFO, "OCSP: This update", ocsp->this_update);
    if(ocsp->next_update)
        log_time(LOG_INFO, "OCSP: Next update", ocsp->next_update);
    if(!OCSP_check_validity(ocsp->this_update, ocsp->next_update, ocsp->leeway, -1)) {
        ssl_error(c, "OCSP: OCSP_check_validity");
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
        log_time(LOG_NOTICE, "OCSP: Revoked at", ocsp->revoked_at);
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
 * Create an OCSP_CERTID object from ocsp->chain_to_verify at ocsp->depth.
*/
NOEXPORT void ocsp_ctx_setup_cert_id(OCSP_CTX *ocsp) {
    X509 *subject, *issuer=NULL;
    int chain_len;

    if(ocsp->cert_id) /* already set */
        return; /* nothing to do */
    chain_len=sk_X509_num(ocsp->chain_to_verify);
    if(ocsp->depth<0 || ocsp->depth>chain_len-1) { /* sanity check */
        s_log(LOG_ERR, "OCSP: INTERNAL ERROR: Invalid verification depth");
        return;
    }
    subject=sk_X509_value(ocsp->chain_to_verify, ocsp->depth);
    issuer=ocsp->depth==chain_len-1 ? subject /* root CA certificate */ :
        sk_X509_value(ocsp->chain_to_verify, ocsp->depth+1);
    /* if dgst is NULL then SHA1 is used */
    ocsp->cert_id=OCSP_cert_to_id(NULL, subject, issuer);
    if(!ocsp->cert_id)
        s_log(LOG_ERR, "OCSP: Can't create an OCSP_CERTID object");
}

#if OPENSSL_VERSION_NUMBER<0x10100000L
#define X509_OBJECT_new() str_alloc(sizeof(X509_OBJECT))
#define X509_OBJECT_free(x) X509_OBJECT_free_contents(x); str_free(x)
#define X509_OBJECT_get0_X509(x) ((x)->data.x509)
#endif /* OpenSSL older than 1.1.0 */

NOEXPORT int ocsp_ctx_append_root_ca(SERVICE_OPTIONS *opt,
        OCSP_CTX *ocsp) {
    int chain_len;
    X509 *cert;
    X509_STORE_CTX *store_ctx=NULL;
    X509_OBJECT *obj=NULL;
    int ret=0; /* failure */

    chain_len=sk_X509_num(ocsp->chain_to_verify);
    if(!chain_len) { /* empty chain */
        s_log(LOG_ERR, "OCSP: Empty verification chain");
        goto cleanup;
    }
    cert=sk_X509_value(ocsp->chain_to_verify, chain_len-1);
    store_ctx=X509_STORE_CTX_new();
    if(!store_ctx) {
        s_log(LOG_ERR, "OCSP: X509_STORE_CTX_new");
        goto cleanup;
    }
    if(!X509_STORE_CTX_init(store_ctx,
            SSL_CTX_get_cert_store(opt->ctx), NULL, NULL)) {
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
    ocsp->root_ca=X509_dup(X509_OBJECT_get0_X509(obj));
    if(!ocsp->root_ca) {
        s_log(LOG_ERR, "OCSP: X509_dup");
        goto cleanup;
    }
    if(!sk_X509_push(ocsp->chain_to_verify, ocsp->root_ca)) {
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
    struct tm ts;
#endif /* OpenSSL version 1.1.1 or later */

    if(!t)
        return;
    bio=BIO_new(BIO_s_mem());
    if(!bio)
        return;
#if OPENSSL_VERSION_NUMBER>=0x10101000L
    posix_time=time_t_get_asn1_time(t);
    if(posix_time==INVALID_TIME) {
        BIO_free(bio);
        return;
    }
    safe_localtime(&ts, posix_time);
    BIO_printf(bio, "%04d.%02d.%02d %02d:%02d:%02d",
        ts.tm_year + 1900, ts.tm_mon + 1, ts.tm_mday,
        ts.tm_hour, ts.tm_min, ts.tm_sec);
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

#if !defined(HAVE_TIMEGM)
/* Alternate, portable, O(1), and re-entrant timegm(3) implementation.
 * See: https://blog.reverberate.org/2020/05/12/optimizing-date-algorithms.html
 * This code uses a calendar algorithm attributed to Howard Hinnant. The key
 * idea is to shift the calendar year so that it begins on March 1. By making
 * February the last month of the year, all leap-day complexities are pushed to
 * the very end, eliminating the need for messy "if (is_leap_year)" checks.
 * This avoids loops that count years or months, array lookups for the number
 * of days in each month, and calls to standard library functions with side
 * effects (for example, setenv, getenv, and mktime). */
NOEXPORT time_t timegm_alt(const struct tm *tm) {
    int64_t year=(int64_t)tm->tm_year+1900;
    int64_t month=tm->tm_mon;
    int64_t days;
    int64_t secs;

    /* 0. Normalize month to 0..11 */
    year+=month/12;
    month%=12;
    if(month < 0) {
        month+=12;
        --year;
    }

    /* 1. Shift calendar to start on March 1st.
     * This puts the leap day (Feb 29) at the very end of the shifted year. */
    if(month < 2) {
        --year;
        month+=10; /* Jan (0) -> 10, Feb (1) -> 11 */
    } else {
        month-=2; /* Mar (2) -> 0, Apr (3) -> 1, ..., Dec (11) -> 9 */
    }

    /* 2. Calculate days since the computational epoch 0000-03-01.
     * This leap-year arithmetic is intended for AD dates only. */
    days=year*365 + year/4 - year/100 + year/400;

    /* 3. Add days passed in the current shifted year.
     * The magic formula (153 * month + 2) / 5 perfectly distributes
     * the 30- and 31-day months in the shifted calendar. */
    days+=(153*month + 2)/5;

    /* 4. Add the zero-based day offset within the month. */
    days+=tm->tm_mday - 1;

    /* 5. Subtract the number of days between 0000-03-01 and the
     * Unix Epoch (1970-01-01), which is exactly 719468 days. */
    days-=719468;

    /* 6. Convert total days to seconds and add hours, minutes, and seconds */
    secs=days*86400;
    secs+=(int64_t)tm->tm_hour*3600;
    secs+=(int64_t)tm->tm_min*60;
    secs+=tm->tm_sec;

    return (time_t)secs;
}
#endif

#if OPENSSL_VERSION_NUMBER>=0x10101000L
/* Converts ASN1_TIME structure to time_t */
NOEXPORT time_t time_t_get_asn1_time(const ASN1_TIME *s) {
    struct tm tm;

    if ((!s) || (!ASN1_TIME_check(s))) {
        return INVALID_TIME;
    }
    /* The ASN1_TIME_to_tm() function was added in OpenSSL 1.1.1 */
    if (ASN1_TIME_to_tm(s, &tm)) {
#if defined(HAVE_TIMEGM)
        return timegm(&tm);
#else /* defined HAVE_TIMEGM */
        return timegm_alt(&tm);
#endif /* defined HAVE_TIMEGM */
    } else {
        return INVALID_TIME;
    }
}
#endif /* OpenSSL version 1.1.0 or later */

#endif /* !defined(OPENSSL_NO_OCSP) */
