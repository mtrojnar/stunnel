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

#ifdef USE_OS2
#define INCL_DOSPROCESS
#include <os2.h>
#endif

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

#if defined(CPU_SPARC) && ( \
        defined(OS_SOLARIS2_0) || \
        defined(OS_SOLARIS2_1) || \
        defined(OS_SOLARIS2_2) || \
        defined(OS_SOLARIS2_3) || \
        defined(OS_SOLARIS2_4) || \
        defined(OS_SOLARIS2_5) || \
        defined(OS_SOLARIS2_6) || \
        defined(OS_SOLARIS2_7) || \
        defined(OS_SOLARIS2_8))
#define ARGC 2
#else
#define ARGC 1
#endif

/* first context on the ready list is the active context */
CONTEXT *ready_head=NULL, *ready_tail=NULL;         /* ready to execute */
CONTEXT *waiting_head=NULL, *waiting_tail=NULL;     /* waiting on poll() */
int next_id=1;

unsigned long stunnel_process_id(void) {
    return (unsigned long)getpid();
}

unsigned long stunnel_thread_id(void) {
    return ready_head ? ready_head->id : 0;
}

static CONTEXT *new_context(int stack_size) {
    CONTEXT *context;

    /* allocate and fill the CONTEXT structure */
    context=malloc(sizeof(CONTEXT));
    if(!context) {
        s_log(LOG_ERR, "Unable to allocate CONTEXT structure");
        return NULL;
    }
    context->stack=malloc(stack_size);
    if(!context->stack) {
        s_log(LOG_ERR, "Unable to allocate CONTEXT stack");
        return NULL;
    }
    context->id=next_id++;
    context->fds=NULL;
    context->ready=0;
    /* some manuals claim that initialization of context structure is required */
    if(getcontext(&context->context)<0) {
        free(context->stack);
        free(context);
        ioerror("getcontext");
        return NULL;
    }
    context->context.uc_link=NULL; /* it should never happen */
#if defined(__sgi) || ARGC==2 /* obsolete ss_sp semantics */
    context->context.uc_stack.ss_sp=context->stack+stack_size-8;
#else
    context->context.uc_stack.ss_sp=context->stack;
#endif
    context->context.uc_stack.ss_size=stack_size;
    context->context.uc_stack.ss_flags=0;

    /* attach to the tail of the ready queue */
    context->next=NULL;
    if(ready_tail)
        ready_tail->next=context;
    ready_tail=context;
    if(!ready_head)
        ready_head=context;
    return context;
}

void sthreads_init(void) {
    /* create the first (listening) context and put it in the running queue */
    if(!new_context(DEFAULT_STACK_SIZE)) {
        s_log(LOG_ERR, "Unable create the listening context");
        die(1);
    }
}

int create_client(int ls, int s, CLI *arg, void *(*cli)(void *)) {
    CONTEXT *context;

    (void)ls; /* this parameter is only used with USE_FORK */
    s_log(LOG_DEBUG, "Creating a new context");
    context=new_context(arg->opt->stack_size);
    if(!context) {
        if(arg)
            free(arg);
        if(s>=0)
            closesocket(s);
        return -1;
    }
    s_log(LOG_DEBUG, "Context %ld created", context->id);
    makecontext(&context->context, (void(*)(void))cli, ARGC, arg);
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

int create_client(int ls, int s, CLI *arg, void *(*cli)(void *)) {
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
        _exit(0);
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

void enter_critical_section(SECTION_CODE i) {
    pthread_mutex_lock(stunnel_cs+i);
}

void leave_critical_section(SECTION_CODE i) {
    pthread_mutex_unlock(stunnel_cs+i);
}

static void locking_callback(int mode, int type,
#ifdef HAVE_OPENSSL
    const /* callback definition has been changed in openssl 0.9.3 */
#endif
    char *file, int line) {
    (void)file; /* skip warning about unused parameter */
    (void)line; /* skip warning about unused parameter */
    if(mode&CRYPTO_LOCK)
        pthread_mutex_lock(lock_cs+type);
    else
        pthread_mutex_unlock(lock_cs+type);
}

struct CRYPTO_dynlock_value {
    pthread_mutex_t mutex;
};

static struct CRYPTO_dynlock_value *dyn_create_function(const char *file,
        int line) {
    struct CRYPTO_dynlock_value *value;

    (void)file; /* skip warning about unused parameter */
    (void)line; /* skip warning about unused parameter */
    value=malloc(sizeof(struct CRYPTO_dynlock_value));
    if(!value)
        return NULL;
    pthread_mutex_init(&value->mutex, NULL);
    return value;
}

static void dyn_lock_function(int mode, struct CRYPTO_dynlock_value *value,
        const char *file, int line) {
    (void)file; /* skip warning about unused parameter */
    (void)line; /* skip warning about unused parameter */
    if(mode&CRYPTO_LOCK)
        pthread_mutex_lock(&value->mutex);
    else
        pthread_mutex_unlock(&value->mutex);
}

static void dyn_destroy_function(struct CRYPTO_dynlock_value *value,
        const char *file, int line) {
    (void)file; /* skip warning about unused parameter */
    (void)line; /* skip warning about unused parameter */
    pthread_mutex_destroy(&value->mutex);
    free(value);
}

unsigned long stunnel_process_id(void) {
    return (unsigned long)getpid();
}

unsigned long stunnel_thread_id(void) {
    return (unsigned long)pthread_self();
}

void sthreads_init(void) {
    int i;

    /* initialize stunnel critical sections */
    for(i=0; i<CRIT_SECTIONS; i++)
        pthread_mutex_init(stunnel_cs+i, NULL);

    /* initialize OpenSSL locking callback */
    for(i=0; i<CRYPTO_NUM_LOCKS; i++)
        pthread_mutex_init(lock_cs+i, NULL);
    CRYPTO_set_id_callback(stunnel_thread_id);
    CRYPTO_set_locking_callback(locking_callback);

    /* initialize OpenSSL dynamic locks callbacks */
    CRYPTO_set_dynlock_create_callback(dyn_create_function);
    CRYPTO_set_dynlock_lock_callback(dyn_lock_function);
    CRYPTO_set_dynlock_destroy_callback(dyn_destroy_function);
}

int create_client(int ls, int s, CLI *arg, void *(*cli)(void *)) {
    pthread_attr_t pth_attr;
    pthread_t thread;
#ifdef HAVE_PTHREAD_SIGMASK
    sigset_t newmask, oldmask;

    (void)ls; /* this parameter is only used with USE_FORK */
    /* initialize attributes for creating new threads */
    pthread_attr_init(&pth_attr);
    pthread_attr_setdetachstate(&pth_attr, PTHREAD_CREATE_DETACHED);
    pthread_attr_setstacksize(&pth_attr, arg->opt->stack_size);

    /* the idea is that only the main thread handles all the signals with
     * posix threads;  signals are blocked for any other thread */
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
        if(arg)
            free(arg);
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
    const /* callback definition has been changed in openssl 0.9.3 */
#endif
    char *file, int line) {
    (void)file; /* skip warning about unused parameter */
    (void)line; /* skip warning about unused parameter */
    if(mode&CRYPTO_LOCK)
        EnterCriticalSection(lock_cs+type);
    else
        LeaveCriticalSection(lock_cs+type);
}

struct CRYPTO_dynlock_value {
    CRITICAL_SECTION mutex;
};

static struct CRYPTO_dynlock_value *dyn_create_function(const char *file,
        int line) {
    struct CRYPTO_dynlock_value *value;

    (void)file; /* skip warning about unused parameter */
    (void)line; /* skip warning about unused parameter */
    value=malloc(sizeof(struct CRYPTO_dynlock_value));
    if(!value)
        return NULL;
    InitializeCriticalSection(&value->mutex);
    return value;
}

static void dyn_lock_function(int mode, struct CRYPTO_dynlock_value *value,
        const char *file, int line) {
    (void)file; /* skip warning about unused parameter */
    (void)line; /* skip warning about unused parameter */
    if(mode&CRYPTO_LOCK)
        EnterCriticalSection(&value->mutex);
    else
        LeaveCriticalSection(&value->mutex);
}

static void dyn_destroy_function(struct CRYPTO_dynlock_value *value,
        const char *file, int line) {
    (void)file; /* skip warning about unused parameter */
    (void)line; /* skip warning about unused parameter */
    DeleteCriticalSection(&value->mutex);
    free(value);
}

unsigned long stunnel_process_id(void) {
    return GetCurrentProcessId() & 0x00ffffff;
}

unsigned long stunnel_thread_id(void) {
    return GetCurrentThreadId() & 0x00ffffff;
}

void sthreads_init(void) {
    int i;

    /* initialize stunnel critical sections */
    for(i=0; i<CRIT_SECTIONS; i++)
        InitializeCriticalSection(stunnel_cs+i);

    /* initialize OpenSSL locking callback */
    for(i=0; i<CRYPTO_NUM_LOCKS; i++)
        InitializeCriticalSection(lock_cs+i);
    CRYPTO_set_locking_callback(locking_callback);

    /* initialize OpenSSL dynamic locks callbacks */
    CRYPTO_set_dynlock_create_callback(dyn_create_function);
    CRYPTO_set_dynlock_lock_callback(dyn_lock_function);
    CRYPTO_set_dynlock_destroy_callback(dyn_destroy_function);
}

int create_client(int ls, int s, CLI *arg, void *(*cli)(void *)) {
    (void)ls; /* this parameter is only used with USE_FORK */
    s_log(LOG_DEBUG, "Creating a new thread");
    if((long)_beginthread((void(*)(void *))cli, arg->opt->stack_size, arg)==-1) {
        ioerror("_beginthread");
        if(arg)
            free(arg);
        if(s>=0)
            closesocket(s);
        return -1;
    }
    s_log(LOG_DEBUG, "New thread created");
    return 0;
}

#endif /* USE_WIN32 */

#ifdef USE_OS2

void enter_critical_section(SECTION_CODE i) {
    DosEnterCritSec();
}

void leave_critical_section(SECTION_CODE i) {
    DosExitCritSec();
}

void sthreads_init(void) {
}

unsigned long stunnel_process_id(void) {
    PTIB ptib=NULL;
    DosGetInfoBlocks(&ptib, NULL);
    return (unsigned long)ptib->tib_ordinal;
}

unsigned long stunnel_thread_id(void) {
    PPIB ppib=NULL;
    DosGetInfoBlocks(NULL, &ppib);
    return (unsigned long)ppib->pib_ulpid;
}

int create_client(int ls, int s, CLI *arg, void *(*cli)(void *)) {
    (void)ls; /* this parameter is only used with USE_FORK */
    s_log(LOG_DEBUG, "Creating a new thread");
    if((long)_beginthread((void(*)(void *))cli, NULL, arg->opt->stack_size, arg)==-1L) {
        ioerror("_beginthread");
        if(arg)
            free(arg);
        if(s>=0)
            closesocket(s);
        return -1;
    }
    s_log(LOG_DEBUG, "New thread created");
    return 0;
}

#endif /* USE_OS2 */

#ifdef _WIN32_WCE

long _beginthread(void (*start_address)(void *),
        int stack_size, void *arglist) {
    DWORD thread_id;
    HANDLE handle;

    handle=CreateThread(NULL, stack_size,
        (LPTHREAD_START_ROUTINE)start_address, arglist,
        STACK_SIZE_PARAM_IS_A_RESERVATION, &thread_id);
    if(!handle)
        return -1L;
    CloseHandle(handle);
    return 0;
}

void _endthread(void) {
    ExitThread(0);
}

#endif /* _WIN32_WCE */

#ifdef DEBUG_STACK_SIZE

#define STACK_RESERVE (STACK_SIZE/8)
#define VERIFY_AREA ((STACK_SIZE-STACK_RESERVE)/sizeof(u32))
#define TEST_VALUE 0xdeadbeef

/* some heuristic to determine the usage of client stack size */
void stack_info(int init) { /* 1-initialize, 0-display */
    u32 table[VERIFY_AREA];
    int i, num;
    static int min_num=VERIFY_AREA;

    if(init) {
        for(i=0; i<VERIFY_AREA; i++)
            table[i]=TEST_VALUE;
    } else {
        /* the stack is growing down */
        for(i=0; i<VERIFY_AREA; i++)
            if(table[i]!=TEST_VALUE)
                break;
        num=i;
        /* the stack is growing up */
        for(i=0; i<VERIFY_AREA; i++)
            if(table[VERIFY_AREA-i-1]!=TEST_VALUE)
                break;
        if(i>num) /* use the higher value */
            num=i;
        if(num<64) {
            s_log(LOG_NOTICE, "STACK_RESERVE is too high");
            return;
        }
        if(num<min_num)
            min_num=num;
        s_log(LOG_NOTICE,
            "stack_info: size=%d, current=%d (%d%%), maximum=%d (%d%%)",
            STACK_SIZE,
            (int)((VERIFY_AREA-num)*sizeof(u32)),
            (int)((VERIFY_AREA-num)*sizeof(u32)*100/STACK_SIZE),
            (int)((VERIFY_AREA-min_num)*sizeof(u32)),
            (int)((VERIFY_AREA-min_num)*sizeof(u32)*100/STACK_SIZE));
    }
}

#endif /* DEBUG_STACK_SIZE */

/* end of sthreads.c */
