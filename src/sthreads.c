/*
 *   stunnel       Universal SSL tunnel
 *   Copyright (c) 1998-2005 Michal Trojnara <Michal.Trojnara@mirt.net>
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

#if defined(USE_UCONTEXT) || defined(USE_FORK)
/* no need for critical sections */

void enter_critical_section(SECTION_CODE i) {
    /* empty */
}

void leave_critical_section(SECTION_CODE i) {
    /* empty */
}

#endif /* USE_UCONTEXT || USE_FORK */

#ifdef USE_UCONTEXT

CONTEXT *ready_head, *ready_tail;       /* ready to execute */
/* first context on the ready list is the active context */
CONTEXT *waiting_head, *waiting_tail;   /* waiting on poll() */
ucontext_t ctx_cleanup;                             /* cleanup context */
char cleanup_stack[8192];
int next_id;

unsigned long stunnel_process_id(void) {
    return (unsigned long)getpid();
}

unsigned long stunnel_thread_id(void) {
    return ready_head ? ready_head->id : 0;
}

static void ctx_cleanup_func(void) { /* cleanup the active thread */
    s_log(LOG_DEBUG, "Context %ld closed", ready_head->id);
    s_poll_wait(NULL, 0); /* wait on poll() */
}

static CONTEXT *new_context(void) {
    CONTEXT *ctx;

    /* allocate and fill the CONTEXT structure */
    ctx=malloc(sizeof(CONTEXT));
    if(!ctx) {
        s_log(LOG_ERR, "Unable to allocate CONTEXT structure");
        return NULL;
    }
    ctx->id=next_id++;
    ctx->fds=NULL;
    ctx->ready=0;
    /* some manuals claim that initialization of ctx structure is required */
    if(getcontext(&ctx->ctx)<0) {
        free(ctx);
        ioerror("getcontext");
        return NULL;
    }
    ctx->ctx.uc_link=&ctx_cleanup;
    ctx->ctx.uc_stack.ss_sp=ctx->stack;
    ctx->ctx.uc_stack.ss_size=STACK_SIZE;

    /* attach to the tail of the ready queue */
    ctx->next=NULL;
    if(ready_tail)
        ready_tail->next=ctx;
    ready_tail=ctx;
    if(!ready_head)
        ready_head=ctx;
    return ctx;
}

void sthreads_init(void) {
    next_id=1;
    ready_head=ready_tail=NULL;
    waiting_head=waiting_tail=NULL;

    /* alocate cleanup context */
    if(getcontext(&ctx_cleanup)<0) {
        ioerror("getcontext");
        exit(1);
    }
    ctx_cleanup.uc_link=NULL; /* it should never happen */
    ctx_cleanup.uc_stack.ss_sp=cleanup_stack;
    ctx_cleanup.uc_stack.ss_size=sizeof(cleanup_stack);
    makecontext(&ctx_cleanup, ctx_cleanup_func, 0);

    /* create the first (listening) context and put it in the running queue */
    if(!new_context()) {
        s_log(LOG_ERR, "Unable create the listening context");
        exit(1);
    }
}

int create_client(int ls, int s, void *arg, void *(*cli)(void *)) {
    CONTEXT *ctx;

    s_log(LOG_DEBUG, "Creating a new context");
    ctx=new_context();
    if(!ctx)
        return -1;
    s_log(LOG_DEBUG, "Context %ld created", ctx->id);
    makecontext(&ctx->ctx, (void(*)(void))cli, 1, arg);
    return 0;
}

#endif /* USE_UCONTEXT */

#ifdef USE_FORK

void sthreads_init(void) {
    /* empty */
}

unsigned long stunnel_process_id(void) {
    return (unsigned long)getpid();
}

unsigned long stunnel_thread_id(void) {
    return 0L;
}

static void null_handler(int sig) {
    signal(SIGCHLD, null_handler);
}

int create_client(int ls, int s, void *arg, void *(*cli)(void *)) {
    switch(fork()) {
    case -1:    /* error */
        if(arg)
            free(arg);
        if(s>=0)
            closesocket(s);
        return -1;
    case  0:    /* child */
        if(ls>=0)
            closesocket(ls);
        signal(SIGCHLD, null_handler);
        cli(arg);
        exit(0);
    default:    /* parent */
        if(arg)
            free(arg);
        if(s>=0)
            closesocket(s);
    }
    return 0;
}

#endif /* USE_FORK */

#ifdef USE_PTHREAD

static pthread_mutex_t stunnel_cs[CRIT_SECTIONS];
static pthread_mutex_t lock_cs[CRYPTO_NUM_LOCKS];
static pthread_attr_t pth_attr;

void enter_critical_section(SECTION_CODE i) {
    pthread_mutex_lock(stunnel_cs+i);
}

void leave_critical_section(SECTION_CODE i) {
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

void sthreads_init(void) {
    int i;

    /* Initialize stunnel critical sections */
    for(i=0; i<CRIT_SECTIONS; i++)
        pthread_mutex_init(stunnel_cs+i, NULL);

    /* Initialize OpenSSL locking callback */
    for(i=0; i<CRYPTO_NUM_LOCKS; i++)
        pthread_mutex_init(lock_cs+i, NULL);
    CRYPTO_set_id_callback(stunnel_thread_id);
    CRYPTO_set_locking_callback(locking_callback);

    pthread_attr_init(&pth_attr);
    pthread_attr_setdetachstate(&pth_attr, PTHREAD_CREATE_DETACHED);
    pthread_attr_setstacksize(&pth_attr, STACK_SIZE);
}

unsigned long stunnel_process_id(void) {
    return (unsigned long)getpid();
}

unsigned long stunnel_thread_id(void) {
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
        if(s>=0)
            closesocket(s);
        return -1;
    }
#ifdef HAVE_PTHREAD_SIGMASK
    pthread_sigmask(SIG_SETMASK, &oldmask, NULL); /* restore the mask */
#endif /* HAVE_PTHREAD_SIGMASK */
    return 0;
}

#endif /* USE_PTHREAD */

#ifdef USE_WIN32

static CRITICAL_SECTION stunnel_cs[CRIT_SECTIONS];
static CRITICAL_SECTION lock_cs[CRYPTO_NUM_LOCKS];

void enter_critical_section(SECTION_CODE i) {
    EnterCriticalSection(stunnel_cs+i);
}

void leave_critical_section(SECTION_CODE i) {
    LeaveCriticalSection(stunnel_cs+i);
}

static void locking_callback(int mode, int type,
#ifdef HAVE_OPENSSL
    const /* Callback definition has been changed in openssl 0.9.3 */
#endif
    char *file, int line) {
    if(mode&CRYPTO_LOCK)
        EnterCriticalSection(lock_cs+type);
    else
        LeaveCriticalSection(lock_cs+type);
}

void sthreads_init(void) {
    int i;

    /* Initialize stunnel critical sections */
    for(i=0; i<CRIT_SECTIONS; i++)
        InitializeCriticalSection(stunnel_cs+i);

    /* Initialize OpenSSL locking callback */
    for(i=0; i<CRYPTO_NUM_LOCKS; i++)
        InitializeCriticalSection(lock_cs+i);
    CRYPTO_set_locking_callback(locking_callback);
}

unsigned long stunnel_process_id(void) {
    return GetCurrentProcessId() & 0x00ffffff;
}

unsigned long stunnel_thread_id(void) {
    return GetCurrentThreadId() & 0x00ffffff;
}

int create_client(int ls, int s, void *arg, void *(*cli)(void *)) {
    s_log(LOG_DEBUG, "Creating a new thread");
    if(_beginthread((void(*)(void *))cli, STACK_SIZE, arg)==-1) {
        ioerror("_beginthread");
        return -1;
    }
    s_log(LOG_DEBUG, "New thread created");
    return 0;
}

#endif /* USE_WIN32 */

#ifdef DEBUG_STACK_SIZE

#define STACK_RESERVE (STACK_SIZE/2)
#define TEST_VALUE 44

/* Some heuristic to determine the usage of client stack size.  It can
 * fail on some platforms and/or OSes, so it'is not enabled by default. */

void stack_info(int init) { /* 1-initialize, 0-display */
    char table[STACK_SIZE-STACK_RESERVE];
    int i;

    if(init) {
        memset(table, TEST_VALUE, STACK_SIZE-STACK_RESERVE);
    } else {
        i=0;
        while(i<STACK_SIZE-STACK_RESERVE && table[i]==TEST_VALUE)
            i++;
        if(i<64)
            s_log(LOG_ERR, "STACK_RESERVE is to high");
        else
            s_log(LOG_NOTICE, "stack_info: %d of %d bytes used (%d%%)",
                STACK_SIZE-STACK_RESERVE-i, STACK_SIZE,
                (STACK_SIZE-STACK_RESERVE-i)*100/STACK_SIZE);
    }
}

#endif /* DEBUG_STACK_SIZE */

/* End of sthreads.c */
