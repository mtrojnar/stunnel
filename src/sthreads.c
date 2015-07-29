/*
 *   stunnel       Universal SSL tunnel
 *   Copyright (c) 1998-2002 Michal Trojnara <Michal.Trojnara@mirt.net>
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

#include "common.h"
#include "prototypes.h"

#ifdef HAVE_OPENSSL
#include <openssl/crypto.h> /* for CRYPTO_* */
#else
#include <crypto.h> /* for CRYPTO_* */
#endif


#ifdef USE_PTHREAD

#include <pthread.h>

pthread_mutex_t stunnel_cs[CRIT_SECTIONS];

pthread_mutex_t lock_cs[CRYPTO_NUM_LOCKS];
pthread_attr_t pth_attr;

void enter_critical_section(section_code i) {
    pthread_mutex_lock(stunnel_cs+i);
}

void leave_critical_section(section_code i) {
    pthread_mutex_unlock(stunnel_cs+i);
}

static void locking_callback(int mode, int type,
#ifdef HAVE_OPENSSL
    const /* Callback definition has been changed in openssl 0.9.3 */
#endif
    char *file, int line) {
    if(mode&CRYPTO_LOCK)
        pthread_mutex_lock(lock_cs+type);
    else
        pthread_mutex_unlock(lock_cs+type);
}

void sthreads_init() {
    int i;

    /* Initialize stunnel critical sections */
    for(i=0; i<CRIT_SECTIONS; i++)
        pthread_mutex_init(stunnel_cs+i, NULL);

    /* Initialize OpenSSL locking callback */
    for(i=0; i<CRYPTO_NUM_LOCKS; i++)
        pthread_mutex_init(lock_cs+i, NULL);
    CRYPTO_set_id_callback(thread_id);
    CRYPTO_set_locking_callback(locking_callback);

    pthread_attr_init(&pth_attr);
    pthread_attr_setdetachstate(&pth_attr, PTHREAD_CREATE_DETACHED);
}

unsigned long process_id() {
    return (unsigned long)getpid();
}

unsigned long thread_id() {
    return (unsigned long)pthread_self();
}

int create_client(int ls, int s, void *arg, void *(*cli)(void *)) {
    pthread_t thread;
#ifdef HAVE_PTHREAD_SIGMASK
    sigset_t newmask, oldmask;

    /* The idea is that only the main thread handles all the signals with
     * posix threads.  Signals are blocked for any other thread. */
    sigemptyset(&newmask);
    sigaddset(&newmask, SIGCHLD);
    sigaddset(&newmask, SIGTERM);
    sigaddset(&newmask, SIGQUIT);
    sigaddset(&newmask, SIGINT);
    sigaddset(&newmask, SIGHUP);
    pthread_sigmask(SIG_BLOCK, &newmask, &oldmask); /* block signals */
#endif /* HAVE_PTHREAD_SIGMASK */
    if(pthread_create(&thread, &pth_attr, cli, arg)) {
#ifdef HAVE_PTHREAD_SIGMASK
        pthread_sigmask(SIG_SETMASK, &oldmask, NULL); /* restore the mask */
#endif /* HAVE_PTHREAD_SIGMASK */
        closesocket(s);
        return -1;
    }
#ifdef HAVE_PTHREAD_SIGMASK
    pthread_sigmask(SIG_SETMASK, &oldmask, NULL); /* restore the mask */
#endif /* HAVE_PTHREAD_SIGMASK */
    return 0;
}

#endif

#ifdef USE_WIN32

CRITICAL_SECTION stunnel_cs[CRIT_SECTIONS];

void enter_critical_section(section_code i) {
    EnterCriticalSection(stunnel_cs+i);
}

void leave_critical_section(section_code i) {
    LeaveCriticalSection(stunnel_cs+i);
}

void sthreads_init() {
    int i;

    /* Initialize stunnel critical sections */
    for(i=0; i<CRIT_SECTIONS; i++)
        InitializeCriticalSection(stunnel_cs+i);
}

unsigned long process_id() {
    return GetCurrentProcessId() & 0x00ffffff;
}

unsigned long thread_id() {
    return GetCurrentThreadId() & 0x00ffffff;
}

int create_client(int ls, int s, void *arg, void *(*cli)(void *)) {
    DWORD iID;

    CloseHandle(CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)cli,
        arg, 0, &iID));
    return 0;
}

#endif

#ifdef USE_FORK

void enter_critical_section(section_code i) {
    /* empty */
}

void leave_critical_section(section_code i) {
    /* empty */
}

void sthreads_init() {
    /* empty */
}

unsigned long process_id() {
    return (unsigned long)getpid();
}

unsigned long thread_id() {
    return 0L;
}

int create_client(int ls, int s, void *arg, void *(*cli)(void *)) {
    switch(fork()) {
    case -1:    /* error */
        closesocket(s);
        return -1;
    case  0:    /* child */
        closesocket(ls);
        signal(SIGCHLD, local_handler);
        cli(arg);
        exit(0);
    default:    /* parent */
        closesocket(s);
    }
    return 0;
}

#endif

/* End of sthreads.c */
