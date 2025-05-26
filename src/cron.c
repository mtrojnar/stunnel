/*
 *   stunnel       TLS offloading and load-balancing proxy
 *   Copyright (C) 1998-2025 Michal Trojnara <Michal.Trojnara@stunnel.org>
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

/* run the per-day job every 24 hours */
#define PER_DAY_PERIOD (24*60*60)

#ifdef USE_OS_THREADS
THREAD_ID per_second_thread_id=(THREAD_ID)0;
THREAD_ID per_minute_thread_id=(THREAD_ID)0;
THREAD_ID per_day_thread_id=(THREAD_ID)0;
#endif

#ifdef USE_PTHREAD
NOEXPORT void *per_second_thread(void *arg);
NOEXPORT void *per_minute_thread(void *arg);
NOEXPORT void *per_day_thread(void *arg);
#endif

#ifdef USE_WIN32
NOEXPORT unsigned __stdcall per_second_thread(void *arg);
NOEXPORT unsigned __stdcall per_minute_thread(void *arg);
NOEXPORT unsigned __stdcall per_day_thread(void *arg);
#endif

#ifdef USE_OS_THREADS
NOEXPORT void per_second_worker(void);
NOEXPORT void per_minute_worker(void);
NOEXPORT void per_minute_stapling_update(void);
NOEXPORT void per_day_worker(void);
#ifndef OPENSSL_NO_DH
#if OPENSSL_VERSION_NUMBER>=0x0090800fL
NOEXPORT void per_day_dh_param(BN_GENCB *);
NOEXPORT BN_GENCB *per_day_bn_gencb(void);
NOEXPORT int bn_callback(int, int, BN_GENCB *);
#else /* OpenSSL older than 0.9.8 */
NOEXPORT void per_day_dh_param(void);
NOEXPORT void dh_callback(int, int, void *);
#endif /* OpenSSL 0.9.8 or later */
#endif /* OPENSSL_NO_DH */
#endif /* USE_OS_THREADS */

#if defined(USE_PTHREAD)

int cron_init(void) {
#if defined(HAVE_PTHREAD_SIGMASK) && !defined(__APPLE__)
    sigset_t new_set, old_set;
#endif /* HAVE_PTHREAD_SIGMASK && !__APPLE__*/

#if defined(HAVE_PTHREAD_SIGMASK) && !defined(__APPLE__)
    sigfillset(&new_set);
    pthread_sigmask(SIG_SETMASK, &new_set, &old_set); /* block signals */
#endif /* HAVE_PTHREAD_SIGMASK && !__APPLE__*/
    CRYPTO_THREAD_write_lock(stunnel_locks[LOCK_THREAD_LIST]);
    if(pthread_create(&per_second_thread_id, NULL, per_second_thread, NULL))
        ioerror("pthread_create");
    if(pthread_create(&per_minute_thread_id, NULL, per_minute_thread, NULL))
        ioerror("pthread_create");
    if(pthread_create(&per_day_thread_id, NULL, per_day_thread, NULL))
        ioerror("pthread_create");
    CRYPTO_THREAD_unlock(stunnel_locks[LOCK_THREAD_LIST]);
#if defined(HAVE_PTHREAD_SIGMASK) && !defined(__APPLE__)
    pthread_sigmask(SIG_SETMASK, &old_set, NULL); /* unblock signals */
#endif /* HAVE_PTHREAD_SIGMASK && !__APPLE__*/
    return 0;
}

NOEXPORT void *per_second_thread(void *arg) {
    (void)arg; /* squash the unused parameter warning */
    tls_alloc(NULL, NULL, "per-second");
    per_second_worker();
    return NULL; /* it should never be executed */
}

NOEXPORT void *per_minute_thread(void *arg) {
    (void)arg; /* squash the unused parameter warning */
    tls_alloc(NULL, NULL, "per-minute");
    per_minute_worker();
    return NULL; /* it should never be executed */
}

NOEXPORT void *per_day_thread(void *arg) {
#ifdef SCHED_BATCH
    struct sched_param param;
#endif

    (void)arg; /* squash the unused parameter warning */
    tls_alloc(NULL, NULL, "per-day");
#ifdef SCHED_BATCH
    param.sched_priority=0;
    if(pthread_setschedparam(pthread_self(), SCHED_BATCH, &param))
        ioerror("pthread_getschedparam");
#endif
    per_day_worker();
    return NULL; /* it should never be executed */
}

#elif defined(USE_WIN32)

int cron_init(void) {
    CRYPTO_THREAD_write_lock(stunnel_locks[LOCK_THREAD_LIST]);
    per_second_thread_id=(HANDLE)_beginthreadex(NULL, 0, per_second_thread, NULL, 0, NULL);
    per_minute_thread_id=(HANDLE)_beginthreadex(NULL, 0, per_minute_thread, NULL, 0, NULL);
    per_day_thread_id=(HANDLE)_beginthreadex(NULL, 0, per_day_thread, NULL, 0, NULL);
    CRYPTO_THREAD_unlock(stunnel_locks[LOCK_THREAD_LIST]);
    if(!per_day_thread_id || !per_day_thread_id) {
        ioerror("_beginthreadex");
        return 1;
    }
    return 0;
}

NOEXPORT unsigned __stdcall per_second_thread(void *arg) {
    (void)arg; /* squash the unused parameter warning */

    tls_alloc(NULL, NULL, "per-second");
    per_second_worker();
    _endthreadex(0); /* it should never be executed */
    return 0;
}

NOEXPORT unsigned __stdcall per_minute_thread(void *arg) {
    (void)arg; /* squash the unused parameter warning */

    tls_alloc(NULL, NULL, "per-minute");
    per_minute_worker();
    _endthreadex(0); /* it should never be executed */
    return 0;
}

NOEXPORT unsigned __stdcall per_day_thread(void *arg) {
    (void)arg; /* squash the unused parameter warning */

    tls_alloc(NULL, NULL, "per-day");
    if(!SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_LOWEST))
        ioerror("SetThreadPriority");
    per_day_worker();
    _endthreadex(0); /* it should never be executed */
    return 0;
}

#else /* USE_OS_THREADS */

int cron_init(void) {
    /* not implemented for now */
    return 0;
}

#endif

#ifdef USE_OS_THREADS

NOEXPORT void per_second_worker(void) {
    s_log(LOG_DEBUG, "Per-second thread initialized");
    for(;;) {
        s_poll_sleep(1, 0); /* 1 second */

        CRYPTO_THREAD_read_lock(stunnel_locks[LOCK_LOG_MODE]);
        file_flush(outfile);
        CRYPTO_THREAD_unlock(stunnel_locks[LOCK_LOG_MODE]);
    }
}

NOEXPORT void per_minute_worker(void) {
    s_log(LOG_DEBUG, "Per-minute thread initialized");
    for(;;) {
        s_poll_sleep(60, 0); /* 1 minute */

        per_minute_stapling_update();
    }
}

NOEXPORT void per_minute_stapling_update(void) {
#if !defined(OPENSSL_NO_OCSP) && OPENSSL_VERSION_NUMBER>=0x10002000L
    SERVICE_OPTIONS **srv, *opt;
    int num=0;

    /* acquire references of server sections */
    CRYPTO_THREAD_read_lock(stunnel_locks[LOCK_SECTIONS]);
    srv=str_alloc(number_of_sections*sizeof(SERVICE_OPTIONS *));
    for(opt=service_options.next; opt; opt=opt->next)
        if(!opt->option.client)
            srv[num++]=service_up_ref(opt);
    CRYPTO_THREAD_unlock(stunnel_locks[LOCK_SECTIONS]);

    /* update stapling caches and release the references */
    while(num--) {
        ocsp_stapling(srv[num]);
        service_free(srv[num]);
    }
    str_free(srv);
#endif /* !OPENSSL_NO_OCSP && OPENSSL_VERSION_NUMBER>=0x10002000L */
}

NOEXPORT void per_day_worker(void) {
    time_t now, then;
    int delay;
#if !defined(OPENSSL_NO_DH) && OPENSSL_VERSION_NUMBER>=0x0090800fL
    BN_GENCB *bn_gencb;
#endif

    s_log(LOG_DEBUG, "Per-day thread initialized");
#if !defined(OPENSSL_NO_DH) && OPENSSL_VERSION_NUMBER>=0x0090800fL
    bn_gencb=per_day_bn_gencb();
#endif
    time(&then);
    for(;;) {
        s_log(LOG_INFO, "Executing per-day jobs");
#ifndef OPENSSL_NO_DH
#if OPENSSL_VERSION_NUMBER>=0x0090800fL
        per_day_dh_param(bn_gencb);
#else /* OpenSSL older than 0.9.8 */
        per_day_dh_param();
#endif /* OpenSSL 0.9.8 or later */
#endif /* OPENSSL_NO_DH */
        time(&now);
        s_log(LOG_INFO, "Per-day jobs completed in %d seconds", (int)(now-then));
        then+=PER_DAY_PERIOD;
        if(then>now) {
            delay=(int)(then-now);
        } else {
            s_log(LOG_NOTICE, "Per-day backlog cleared (possible hibernation)");
            delay=PER_DAY_PERIOD-(int)(now-then)%PER_DAY_PERIOD;
            then=now+delay;
        }
        s_log(LOG_DEBUG, "Waiting %d seconds", delay);
        do { /* retry s_poll_sleep() if it was interrupted by a signal */
            s_poll_sleep(delay, 0);
            time(&now);
            delay=(int)(then-now);
        } while(delay>0);
        s_log(LOG_INFO, "Reopening log file");
        signal_post(SIGNAL_REOPEN_LOG);
    }
}

#ifndef OPENSSL_NO_DH

#if OPENSSL_VERSION_NUMBER>=0x0090800fL
NOEXPORT void per_day_dh_param(BN_GENCB *bn_gencb) {
#else /* OpenSSL older than 0.9.8 */
NOEXPORT void per_day_dh_param(void) {
#endif /* OpenSSL 0.9.8 or later */
    SERVICE_OPTIONS *opt;
    DH *dh;

    if(!dh_temp_params || !service_options.next)
        return;

    s_log(LOG_NOTICE, "Updating DH parameters");
#if OPENSSL_VERSION_NUMBER>=0x0090800fL
    /* generate 2048-bit DH parameters */
    dh=DH_new();
    if(!dh) {
        sslerror("DH_new");
        return;
    }
    if(!DH_generate_parameters_ex(dh, 2048, 2, bn_gencb)) {
        DH_free(dh);
        sslerror("DH_generate_parameters_ex");
        return;
    }
#else /* OpenSSL older than 0.9.8 */
    dh=DH_generate_parameters(2048, 2, dh_callback, NULL);
    if(!dh) {
        sslerror("DH_generate_parameters");
        return;
    }
#endif /* OpenSSL 0.9.8 or later */

    /* update global dh_params for future configuration reloads */
    CRYPTO_THREAD_write_lock(stunnel_locks[LOCK_DH]);
    DH_free(dh_params);
    dh_params=dh;
    CRYPTO_THREAD_unlock(stunnel_locks[LOCK_DH]);

    /* set for all sections that require it */
    CRYPTO_THREAD_read_lock(stunnel_locks[LOCK_SECTIONS]);
    for(opt=service_options.next; opt; opt=opt->next)
        if(opt->option.dh_temp_params)
            SSL_CTX_set_tmp_dh(opt->ctx, dh);
    CRYPTO_THREAD_unlock(stunnel_locks[LOCK_SECTIONS]);
    s_log(LOG_NOTICE, "DH parameters updated");
}

#if OPENSSL_VERSION_NUMBER>=0x0090800fL

NOEXPORT BN_GENCB *per_day_bn_gencb(void) {
#if OPENSSL_VERSION_NUMBER>=0x10100000L
    BN_GENCB *bn_gencb;

    bn_gencb=BN_GENCB_new();
    if(!bn_gencb) {
        sslerror("BN_GENCB_new");
        return NULL;
    }
    BN_GENCB_set(bn_gencb, bn_callback, NULL);
    return bn_gencb;
#else
    static BN_GENCB bn_gencb;

    BN_GENCB_set(&bn_gencb, bn_callback, NULL);
    return &bn_gencb;
#endif
}

NOEXPORT int bn_callback(int p, int n, BN_GENCB *cb) {
    (void)p; /* squash the unused parameter warning */
    (void)n; /* squash the unused parameter warning */
    (void)cb; /* squash the unused parameter warning */
    s_poll_sleep(0, 100); /* 100ms */
    return 1; /* return nonzero for success */
}

#else /* OpenSSL older than 0.9.8 */

NOEXPORT void dh_callback(int p, int n, void *arg) {
    (void)p; /* squash the unused parameter warning */
    (void)n; /* squash the unused parameter warning */
    (void)arg; /* squash the unused parameter warning */
    s_poll_sleep(0, 100); /* 100ms */
}

#endif /* OpenSSL 0.9.8 or later */

#endif /* OPENSSL_NO_DH */

#endif /* USE_OS_THREADS */

/* end of cron.c */
