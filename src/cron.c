/*
 *   stunnel       TLS offloading and load-balancing proxy
 *   Copyright (C) 1998-2016 Michal Trojnara <Michal.Trojnara@mirt.net>
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

#ifdef USE_PTHREAD
NOEXPORT void *cron_thread(void *arg);
#endif
#ifdef USE_WIN32
NOEXPORT void cron_thread(void *arg);
#endif
#if defined(USE_PTHREAD) || defined(USE_WIN32)
NOEXPORT void cron_worker(void);
NOEXPORT void cron_dh_param(void);
#endif

#if defined(USE_PTHREAD)

int cron_init() {
    pthread_t thread;
    pthread_attr_t pth_attr;
#if defined(HAVE_PTHREAD_SIGMASK) && !defined(__APPLE__)
    sigset_t new_set, old_set;
#endif /* HAVE_PTHREAD_SIGMASK && !__APPLE__*/

#if defined(HAVE_PTHREAD_SIGMASK) && !defined(__APPLE__)
    sigfillset(&new_set);
    pthread_sigmask(SIG_SETMASK, &new_set, &old_set); /* block signals */
#endif /* HAVE_PTHREAD_SIGMASK && !__APPLE__*/
    pthread_attr_init(&pth_attr);
    pthread_attr_setdetachstate(&pth_attr, PTHREAD_CREATE_DETACHED);
    if(pthread_create(&thread, &pth_attr, cron_thread, NULL))
        ioerror("pthread_create");
    pthread_attr_destroy(&pth_attr);
#if defined(HAVE_PTHREAD_SIGMASK) && !defined(__APPLE__)
    pthread_sigmask(SIG_SETMASK, &old_set, NULL); /* unblock signals */
#endif /* HAVE_PTHREAD_SIGMASK && !__APPLE__*/
    return 0;
}

NOEXPORT void *cron_thread(void *arg) {
#ifdef SCHED_BATCH
    struct sched_param param;
#endif

    (void)arg; /* squash the unused parameter warning */
    tls_alloc(NULL, NULL, "cron");
#ifdef SCHED_BATCH
    param.sched_priority=0;
    if(pthread_setschedparam(pthread_self(), SCHED_BATCH, &param))
        ioerror("pthread_getschedparam");
#endif
    cron_worker();
    return NULL; /* it should never be executed */
}

#elif defined(USE_WIN32)

int cron_init() {
    if((long)_beginthread(cron_thread, 0, NULL)==-1)
        ioerror("_beginthread");
    return 0;
}

NOEXPORT void cron_thread(void *arg) {
    (void)arg; /* squash the unused parameter warning */
    tls_alloc(NULL, NULL, "cron");
    if(!SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_LOWEST))
        ioerror("SetThreadPriority");
    cron_worker();
    _endthread(); /* it should never be executed */
}

#else /* !defined(USE_PTHREAD) && !defined(USE_WIN32) */

int cron_init() {
    /* not implemented for now */
    return 0;
}

#endif

/* run the cron job every 24 hours */
#define CRON_PERIOD (24*60*60)

#if defined(USE_PTHREAD) || defined(USE_WIN32)

NOEXPORT void cron_worker(void) {
    time_t now, then;
    int delay;

    s_log(LOG_DEBUG, "Cron thread initialized");
    sleep(60); /* allow the other services to start with idle CPU */
    time(&then);
    for(;;) {
        s_log(LOG_INFO, "Executing cron jobs");
#ifndef OPENSSL_NO_DH
        cron_dh_param();
#endif /* OPENSSL_NO_DH */
        time(&now);
        s_log(LOG_INFO, "Cron jobs completed in %d seconds", (int)(now-then));
        then+=CRON_PERIOD;
        if(then>now) {
            delay=(int)(then-now);
        } else {
            s_log(LOG_NOTICE, "Cron backlog cleared (possible hibernation)");
            delay=CRON_PERIOD-(int)(now-then)%CRON_PERIOD;
            then=now+delay;
        }
        s_log(LOG_DEBUG, "Waiting %d seconds", delay);
        do { /* retry sleep() if it was interrupted by a signal */
            sleep((unsigned)delay);
            time(&now);
            delay=(int)(then-now);
        } while(delay>0);
        s_log(LOG_INFO, "Reopening log file");
        signal_post(SIGNAL_REOPEN_LOG);
    }
}

#ifndef OPENSSL_NO_DH
NOEXPORT void cron_dh_param(void) {
    SERVICE_OPTIONS *opt;
    DH *dh;

    if(!dh_needed)
        return;

    s_log(LOG_NOTICE, "Updating DH parameters");
#if OPENSSL_VERSION_NUMBER>=0x0090800fL
    /* generate 2048-bit DH parameters */
    dh=DH_new();
    if(!dh) {
        sslerror("DH_new");
        return;
    }
    if(!DH_generate_parameters_ex(dh, 2048, 2, NULL)) {
        DH_free(dh);
        sslerror("DH_generate_parameters_ex");
        return;
    }
#else /* OpenSSL older than 0.9.8 */
    dh=DH_generate_parameters(2048, 2, NULL, NULL);
    if(!dh) {
        sslerror("DH_generate_parameters");
        return;
    }
#endif

    /* update global dh_params for future configuration reloads */
    CRYPTO_w_lock(stunnel_locks[LOCK_DH]);
    DH_free(dh_params);
    dh_params=dh;
    CRYPTO_w_unlock(stunnel_locks[LOCK_DH]);

    /* set for all sections that require it */
    for(opt=service_options.next; opt; opt=opt->next)
        if(opt->option.dh_needed)
            SSL_CTX_set_tmp_dh(opt->ctx, dh);
    s_log(LOG_NOTICE, "DH parameters updated");
}
#endif /* OPENSSL_NO_DH */

#endif /* USE_PTHREAD || USE_WIN32 */

/* end of cron.c */
