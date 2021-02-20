/*
 *   stunnel       TLS offloading and load-balancing proxy
 *   Copyright (C) 1998-2021 Michal Trojnara <Michal.Trojnara@stunnel.org>
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

#ifndef USE_FORK
CLI *thread_head=NULL;
NOEXPORT void thread_list_add(CLI *);
#endif

/**************************************** thread ID callbacks */

#ifdef USE_UCONTEXT

unsigned long stunnel_process_id(void) {
    return (unsigned long)getpid();
}

unsigned long stunnel_thread_id(void) {
    return ready_head ? ready_head->id : 0;
}

#endif /* USE_UCONTEXT */

#ifdef USE_FORK

unsigned long stunnel_process_id(void) {
    return (unsigned long)getpid();
}

unsigned long stunnel_thread_id(void) {
    return 0L;
}

#endif /* USE_FORK */

#ifdef USE_PTHREAD

unsigned long stunnel_process_id(void) {
    return (unsigned long)getpid();
}

unsigned long stunnel_thread_id(void) {
#if defined(SYS_gettid) && defined(__linux__)
    return (unsigned long)syscall(SYS_gettid);
#else
    return (unsigned long)pthread_self();
#endif
}

#endif /* USE_PTHREAD */

#ifdef USE_WIN32

unsigned long stunnel_process_id(void) {
    return GetCurrentProcessId() & 0x00ffffff;
}

unsigned long stunnel_thread_id(void) {
    return GetCurrentThreadId() & 0x00ffffff;
}

#endif /* USE_WIN32 */

#if OPENSSL_VERSION_NUMBER>=0x10000000L && OPENSSL_VERSION_NUMBER<0x10100004L
NOEXPORT void threadid_func(CRYPTO_THREADID *tid) {
    CRYPTO_THREADID_set_numeric(tid, stunnel_thread_id());
}
#endif

void thread_id_init(void) {
#if OPENSSL_VERSION_NUMBER>=0x10000000L && OPENSSL_VERSION_NUMBER<0x10100000L
    CRYPTO_THREADID_set_callback(threadid_func);
#endif
#if OPENSSL_VERSION_NUMBER<0x10000000L || !defined(OPENSSL_NO_DEPRECATED)
    CRYPTO_set_id_callback(stunnel_thread_id);
#endif
}

/**************************************** locking */

/* we only need to initialize locking with OpenSSL older than 1.1.0 */
#if OPENSSL_VERSION_NUMBER<0x10100004L

#ifdef USE_PTHREAD

NOEXPORT void s_lock_init_debug(struct CRYPTO_dynlock_value *lock,
        const char *file, int line) {
    pthread_rwlock_init(&lock->rwlock, NULL);
#ifdef DEBUG_LOCKS
    lock->init_file=file;
    lock->init_line=line;
#else
    (void)file; /* squash the unused parameter warning */
    (void)line; /* squash the unused parameter warning */
#endif
}

NOEXPORT void s_read_lock_debug(struct CRYPTO_dynlock_value *lock,
        const char *file, int line) {
    pthread_rwlock_rdlock(&lock->rwlock);
#ifdef DEBUG_LOCKS
    lock->read_lock_file=file;
    lock->read_lock_line=line;
#else
    (void)file; /* squash the unused parameter warning */
    (void)line; /* squash the unused parameter warning */
#endif
}

NOEXPORT void s_write_lock_debug(struct CRYPTO_dynlock_value *lock,
        const char *file, int line) {
    pthread_rwlock_wrlock(&lock->rwlock);
#ifdef DEBUG_LOCKS
    lock->write_lock_file=file;
    lock->write_lock_line=line;
#else
    (void)file; /* squash the unused parameter warning */
    (void)line; /* squash the unused parameter warning */
#endif
}

NOEXPORT void s_unlock_debug(struct CRYPTO_dynlock_value *lock,
        const char *file, int line) {
    pthread_rwlock_unlock(&lock->rwlock);
#ifdef DEBUG_LOCKS
    lock->unlock_file=file;
    lock->unlock_line=line;
#else
    (void)file; /* squash the unused parameter warning */
    (void)line; /* squash the unused parameter warning */
#endif
}

NOEXPORT void s_lock_destroy_debug(struct CRYPTO_dynlock_value *lock,
        const char *file, int line) {
    pthread_rwlock_destroy(&lock->rwlock);
#ifdef DEBUG_LOCKS
    lock->destroy_file=file;
    lock->destroy_line=line;
#else
    (void)file; /* squash the unused parameter warning */
    (void)line; /* squash the unused parameter warning */
#endif
    str_free(lock);
}

#endif /* USE_PTHREAD */

#ifdef USE_WIN32

/* Slim Reader/Writer (SRW) Lock would be better than CRITICAL_SECTION,
 * but it is unsupported on Windows XP (and earlier versions of Windows):
 * https://msdn.microsoft.com/en-us/library/windows/desktop/aa904937%28v=vs.85%29.aspx */

NOEXPORT void s_lock_init_debug(struct CRYPTO_dynlock_value *lock,
        const char *file, int line) {
    InitializeCriticalSection(&lock->critical_section);
#ifdef DEBUG_LOCKS
    lock->init_file=file;
    lock->init_line=line;
#else
    (void)file; /* squash the unused parameter warning */
    (void)line; /* squash the unused parameter warning */
#endif
}

NOEXPORT void s_read_lock_debug(struct CRYPTO_dynlock_value *lock,
        const char *file, int line) {
    EnterCriticalSection(&lock->critical_section);
#ifdef DEBUG_LOCKS
    lock->read_lock_file=file;
    lock->read_lock_line=line;
#else
    (void)file; /* squash the unused parameter warning */
    (void)line; /* squash the unused parameter warning */
#endif
}

NOEXPORT void s_write_lock_debug(struct CRYPTO_dynlock_value *lock,
        const char *file, int line) {
    EnterCriticalSection(&lock->critical_section);
#ifdef DEBUG_LOCKS
    lock->write_lock_file=file;
    lock->write_lock_line=line;
#else
    (void)file; /* squash the unused parameter warning */
    (void)line; /* squash the unused parameter warning */
#endif
}

NOEXPORT void s_unlock_debug(struct CRYPTO_dynlock_value *lock,
        const char *file, int line) {
    LeaveCriticalSection(&lock->critical_section);
#ifdef DEBUG_LOCKS
    lock->unlock_file=file;
    lock->unlock_line=line;
#else
    (void)file; /* squash the unused parameter warning */
    (void)line; /* squash the unused parameter warning */
#endif
}

NOEXPORT void s_lock_destroy_debug(struct CRYPTO_dynlock_value *lock,
        const char *file, int line) {
    DeleteCriticalSection(&lock->critical_section);
#ifdef DEBUG_LOCKS
    lock->destroy_file=file;
    lock->destroy_line=line;
#else
    (void)file; /* squash the unused parameter warning */
    (void)line; /* squash the unused parameter warning */
#endif
    str_free(lock);
}

#endif /* USE_WIN32 */

NOEXPORT int s_atomic_add(int *val, int amount, CRYPTO_RWLOCK *lock) {
    int ret;

    (void)lock; /* squash the unused parameter warning */
#if !defined(USE_OS_THREADS)
    /* no synchronization is needed */
    return *val+=amount;
#elif defined(__GNUC__) && defined(__ATOMIC_ACQ_REL)
    if(__atomic_is_lock_free(sizeof *val, val))
        return __atomic_add_fetch(val, amount, __ATOMIC_ACQ_REL);
#elif defined(_MSC_VER)
    return InterlockedExchangeAdd(val, amount)+amount;
#endif
    CRYPTO_THREAD_write_lock(lock);
    ret=(*val+=amount);
    CRYPTO_THREAD_unlock(lock);
    return ret;
}

#endif /* OPENSSL_VERSION_NUMBER<0x10100004L */

CRYPTO_RWLOCK *stunnel_locks[STUNNEL_LOCKS];

#if OPENSSL_VERSION_NUMBER<0x10100004L

#ifdef USE_OS_THREADS

static struct CRYPTO_dynlock_value *lock_cs;

NOEXPORT struct CRYPTO_dynlock_value *s_dynlock_create_cb(const char *file,
        int line) {
    struct CRYPTO_dynlock_value *lock;

    lock=str_alloc_detached(sizeof(struct CRYPTO_dynlock_value));
    s_lock_init_debug(lock, file, line);
    return lock;
}

NOEXPORT void s_dynlock_lock_cb(int mode, struct CRYPTO_dynlock_value *lock,
        const char *file, int line) {
    if(mode&CRYPTO_LOCK) {
        /* either CRYPTO_READ or CRYPTO_WRITE (but not both) are needed */
        if(!(mode&CRYPTO_READ)==!(mode&CRYPTO_WRITE))
            fatal("Invalid locking mode");
        if(mode&CRYPTO_WRITE)
            s_write_lock_debug(lock, file, line);
        else
            s_read_lock_debug(lock, file, line);
    } else
        s_unlock_debug(lock, file, line);
}

NOEXPORT void s_dynlock_destroy_cb(struct CRYPTO_dynlock_value *lock,
        const char *file, int line) {
    s_lock_destroy_debug(lock, file, line);
}

NOEXPORT void s_locking_cb(int mode, int type, const char *file, int line) {
    s_dynlock_lock_cb(mode, lock_cs+type, file, line);
}

NOEXPORT int s_add_lock_cb(int *num, int amount, int type,
        const char *file, int line) {
    (void)file; /* squash the unused parameter warning */
    (void)line; /* squash the unused parameter warning */
    return s_atomic_add(num, amount, lock_cs+type);
}

CRYPTO_RWLOCK *CRYPTO_THREAD_lock_new(void) {
    struct CRYPTO_dynlock_value *lock;

    lock=str_alloc_detached(sizeof(CRYPTO_RWLOCK));
    s_lock_init_debug(lock, __FILE__, __LINE__);
    return lock;
}

int CRYPTO_THREAD_read_lock(CRYPTO_RWLOCK *lock) {
    s_read_lock_debug(lock, __FILE__, __LINE__);
    return 1;
}

int CRYPTO_THREAD_write_lock(CRYPTO_RWLOCK *lock) {
    s_write_lock_debug(lock, __FILE__, __LINE__);
    return 1;
}

int CRYPTO_THREAD_unlock(CRYPTO_RWLOCK *lock) {
    s_unlock_debug(lock, __FILE__, __LINE__);
    return 1;
}

void CRYPTO_THREAD_lock_free(CRYPTO_RWLOCK *lock) {
    s_lock_destroy_debug(lock, __FILE__, __LINE__);
}

#else /* USE_OS_THREADS */

CRYPTO_RWLOCK *CRYPTO_THREAD_lock_new(void) {
    return NULL;
}

int CRYPTO_THREAD_read_lock(CRYPTO_RWLOCK *lock) {
    (void)lock; /* squash the unused parameter warning */
    return 1;
}

int CRYPTO_THREAD_write_lock(CRYPTO_RWLOCK *lock) {
    (void)lock; /* squash the unused parameter warning */
    return 1;
}

int CRYPTO_THREAD_unlock(CRYPTO_RWLOCK *lock) {
    (void)lock; /* squash the unused parameter warning */
    return 1;
}

void CRYPTO_THREAD_lock_free(CRYPTO_RWLOCK *lock) {
    (void)lock; /* squash the unused parameter warning */
}

#endif /* USE_OS_THREADS */

int CRYPTO_atomic_add(int *val, int amount, int *ret, CRYPTO_RWLOCK *lock) {
    *ret=s_atomic_add(val, amount, lock);
    return 1;
}

#endif /* OPENSSL_VERSION_NUMBER<0x10100004L */

void locking_init(void) {
    size_t i;
#if defined(USE_OS_THREADS) && OPENSSL_VERSION_NUMBER<0x10100004L
    size_t num;

    /* initialize the OpenSSL static locking */
    num=(size_t)CRYPTO_num_locks();
    lock_cs=str_alloc_detached(num*sizeof(struct CRYPTO_dynlock_value));
    for(i=0; i<num; i++)
        s_lock_init_debug(lock_cs+i, __FILE__, __LINE__);

    /* initialize the OpenSSL static locking callbacks */
    CRYPTO_set_locking_callback(s_locking_cb);
    CRYPTO_set_add_lock_callback(s_add_lock_cb);

    /* initialize the OpenSSL dynamic locking callbacks */
    CRYPTO_set_dynlock_create_callback(s_dynlock_create_cb);
    CRYPTO_set_dynlock_lock_callback(s_dynlock_lock_cb);
    CRYPTO_set_dynlock_destroy_callback(s_dynlock_destroy_cb);
#endif /* defined(USE_OS_THREADS) && OPENSSL_VERSION_NUMBER<0x10100004L */

    /* initialize stunnel critical sections */
    for(i=0; i<STUNNEL_LOCKS; i++) /* all the mutexes */
        stunnel_locks[i]=CRYPTO_THREAD_lock_new();
}

/**************************************** creating a client */

#if defined(USE_UCONTEXT) || defined(USE_FORK)
/* no need for critical sections */

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

NOEXPORT CONTEXT *new_context(void) {
    static unsigned long next_id=1;
    CONTEXT *context;

    /* allocate and fill the CONTEXT structure */
    context=str_alloc_detached(sizeof(CONTEXT));
    context->id=next_id++;
    context->fds=NULL;
    context->ready=0;

    /* append to the tail of the ready queue */
    context->next=NULL;
    if(ready_tail)
        ready_tail->next=context;
    ready_tail=context;
    if(!ready_head)
        ready_head=context;

    return context;
}

int sthreads_init(void) {
    thread_id_init();
    locking_init();
    /* create the first (listening) context and put it in the running queue */
    if(!new_context()) {
        s_log(LOG_ERR, "Cannot create the listening context");
        return 1;
    }
    /* update tls for newly allocated ready_head */
    ui_tls=tls_alloc(NULL, ui_tls, "ui");
    /* no need to initialize ucontext_t structure here
       it will be initialied with swapcontext() call */
    return 0;
}

int create_client(SOCKET ls, SOCKET s, CLI *arg) {
    CONTEXT *context;

    (void)ls; /* this parameter is only used with USE_FORK */

    s_log(LOG_DEBUG, "Creating a new context");
    context=new_context();
    if(!context) {
        str_free(arg);
        if(s>=0)
            closesocket(s);
        return -1;
    }

    /* initialize context_t structure */
    if(getcontext(&context->context)<0) {
        str_free(context);
        str_free(arg);
        if(s>=0)
            closesocket(s);
        ioerror("getcontext");
        return -1;
    }
    context->context.uc_link=NULL; /* stunnel does not use uc_link */

    /* create stack */
    context->stack=str_alloc_detached(arg->opt->stack_size);
#if defined(__sgi) || ARGC==2 /* obsolete ss_sp semantics */
    context->context.uc_stack.ss_sp=context->stack+arg->opt->stack_size-8;
#else
    context->context.uc_stack.ss_sp=context->stack;
#endif
    context->context.uc_stack.ss_size=arg->opt->stack_size;
    context->context.uc_stack.ss_flags=0;

    makecontext(&context->context, (void(*)(void))client_thread, ARGC, arg);
    thread_list_add(arg);
    s_log(LOG_DEBUG, "New context created");
    return 0;
}

#endif /* USE_UCONTEXT */

#ifdef USE_FORK

int sthreads_init(void) {
    thread_id_init();
    locking_init();
    return 0;
}

NOEXPORT void null_handler(int sig) {
    (void)sig; /* squash the unused parameter warning */
    signal(SIGCHLD, null_handler);
}

int create_client(SOCKET ls, SOCKET s, CLI *arg) {
    switch(fork()) {
    case -1:    /* error */
        str_free(arg);
        if(s>=0)
            closesocket(s);
        return -1;
    case  0:    /* child */
        if(ls>=0)
            closesocket(ls);
        signal(SIGCHLD, null_handler);
        client_thread(arg);
        _exit(0);
    default:    /* parent */
        str_free(arg);
        if(s>=0)
            closesocket(s);
    }
    return 0;
}

#endif /* USE_FORK */

#ifdef USE_PTHREAD

NOEXPORT void *dummy_thread(void *arg) {
    pthread_exit(arg);
    return arg;
}

int sthreads_init(void) {
    pthread_t thread_id;

    /* this is a workaround for NPTL threads failing to invoke
     * pthread_exit() or pthread_cancel() from a chroot jail */
    if(!pthread_create(&thread_id, NULL, dummy_thread, NULL))
        pthread_join(thread_id, NULL);

    thread_id_init();
    locking_init();
    return 0;
}

int create_client(SOCKET ls, SOCKET s, CLI *arg) {
    pthread_attr_t pth_attr;
    int error;
#if defined(HAVE_PTHREAD_SIGMASK) && !defined(__APPLE__)
    /* disabled on OS X due to strange problems on Mac OS X 10.5
       it seems to restore signal mask somewhere (I couldn't find where)
       effectively blocking signals after first accepted connection */
    sigset_t new_set, old_set;
#endif /* HAVE_PTHREAD_SIGMASK && !__APPLE__*/

    (void)ls; /* this parameter is only used with USE_FORK */

#if defined(HAVE_PTHREAD_SIGMASK) && !defined(__APPLE__)
    /* the idea is that only the main thread handles all the signals with
     * posix threads;  signals are blocked for any other thread */
    sigfillset(&new_set);
    pthread_sigmask(SIG_SETMASK, &new_set, &old_set); /* block signals */
#endif /* HAVE_PTHREAD_SIGMASK && !__APPLE__*/
    pthread_attr_init(&pth_attr);
    pthread_attr_setstacksize(&pth_attr, arg->opt->stack_size);

    CRYPTO_THREAD_write_lock(stunnel_locks[LOCK_THREAD_LIST]);
    error=pthread_create(&arg->thread_id, &pth_attr, client_thread, arg);
    pthread_attr_destroy(&pth_attr);
#if defined(HAVE_PTHREAD_SIGMASK) && !defined(__APPLE__)
    pthread_sigmask(SIG_SETMASK, &old_set, NULL); /* unblock signals */
#endif /* HAVE_PTHREAD_SIGMASK && !__APPLE__*/
    if(error) {
        errno=error;
        ioerror("pthread_create");
        CRYPTO_THREAD_unlock(stunnel_locks[LOCK_THREAD_LIST]);
        str_free(arg);
        if(s>=0)
            closesocket(s);
        return -1;
    }
    thread_list_add(arg);
    CRYPTO_THREAD_unlock(stunnel_locks[LOCK_THREAD_LIST]);
    return 0;
}

#endif /* USE_PTHREAD */

#ifdef USE_WIN32

#if !defined(_MT)
#error _beginthreadex requires a multithreaded C run-time library
#endif

int sthreads_init(void) {
    thread_id_init();
    locking_init();
    return 0;
}

int create_client(SOCKET ls, SOCKET s, CLI *arg) {
    (void)ls; /* this parameter is only used with USE_FORK */
    s_log(LOG_DEBUG, "Creating a new thread");
    CRYPTO_THREAD_write_lock(stunnel_locks[LOCK_THREAD_LIST]);
    arg->thread_id=(HANDLE)_beginthreadex(NULL,
        (unsigned)arg->opt->stack_size, client_thread, arg,
        STACK_SIZE_PARAM_IS_A_RESERVATION, NULL);
    if(!arg->thread_id) {
        ioerror("_beginthreadex");
        CRYPTO_THREAD_unlock(stunnel_locks[LOCK_THREAD_LIST]);
        str_free(arg);
        if(s!=INVALID_SOCKET)
            closesocket(s);
        return -1;
    }
    thread_list_add(arg);
    CRYPTO_THREAD_unlock(stunnel_locks[LOCK_THREAD_LIST]);
    s_log(LOG_DEBUG, "New thread created");
    return 0;
}

#endif /* USE_WIN32 */

#ifdef USE_OS2

int sthreads_init(void) {
    return 0;
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

int create_client(SOCKET ls, SOCKET s, CLI *arg) {
    (void)ls; /* this parameter is only used with USE_FORK */
    s_log(LOG_DEBUG, "Creating a new thread");
    if((long)_beginthread(client_thread, NULL, arg->opt->stack_size, arg)==-1L) {
        ioerror("_beginthread");
        str_free(arg);
        if(s>=0)
            closesocket(s);
        return -1;
    }
    s_log(LOG_DEBUG, "New thread created");
    return 0;
}

#endif /* USE_OS2 */

#ifdef _WIN32_WCE

uintptr_t _beginthreadex(void *security, unsigned stack_size,
        unsigned ( __stdcall *start_address)(void *),
        void *arglist, unsigned initflag, unsigned *thrdaddr) {
    return CreateThread(NULL, stack_size,
        (LPTHREAD_START_ROUTINE)start_address, arglist,
        (DWORD)initflag, (LPDWORD)thrdaddr);
}

void _endthreadex(unsigned retval) {
    ExitThread(retval);
}

#endif /* _WIN32_WCE */

#ifdef DEBUG_STACK_SIZE

#define STACK_RESERVE 16384

/* some heuristic to determine the usage of client stack size */
NOEXPORT size_t stack_num(size_t stack_size, int init) {
#ifdef _WIN64
    typedef unsigned long long TL;
#else
    typedef unsigned long TL;
#endif
    size_t verify_area, verify_num, i;
    TL test_value, *table;

    if(stack_size<STACK_RESERVE)
        return 0;
    verify_area=(stack_size-STACK_RESERVE)&~(sizeof(TL)-1);
    verify_num=verify_area/sizeof(TL);
    test_value=(TL)0x1337deadbeef1337;
    table=alloca(verify_area);

    if(init) {
        for(i=0; i<verify_num; i++)
            table[i]=test_value;
        ignore_value(table); /* prevent code optimization */
        return 0;
    } else {
        /* the stack grows down */
        for(i=0; i<verify_num; i++)
            if(table[i]!=test_value)
                break;
        if(i>=16)
            return stack_size-i*sizeof(TL);
        /* the stack grows up */
        for(i=0; i<verify_num; i++)
            if(table[verify_num-i-1]!=test_value)
                break;
        if(i>=16)
            return stack_size-(i*sizeof(TL)+STACK_RESERVE);
        return 0; /* not enough samples for meaningful results */
    }
}

#ifdef __GNUC__
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6)
#pragma GCC diagnostic push
#endif /* __GNUC__>=4.6 */
#pragma GCC diagnostic ignored "-Wformat"
#endif /* __GNUC__ */
void stack_info(size_t stack_size, int init) { /* 1-initialize, 0-display */
    static size_t max_num=0;
    size_t num;

#ifdef USE_WIN32
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    stack_size&=~((size_t)si.dwPageSize-1);
#elif defined(_SC_PAGESIZE)
    stack_size&=~((size_t)sysconf(_SC_PAGESIZE)-1);
#elif defined(_SC_PAGE_SIZE)
    stack_size&=~((size_t)sysconf(_SC_PAGE_SIZE)-1);
#else
    stack_size&=~(4096-1); /* just a guess */
#endif
    num=stack_num(stack_size, init);
    if(init)
        return;
    if(!num) {
        s_log(LOG_NOTICE, "STACK_RESERVE is too high");
        return;
    }
    if(num>max_num)
        max_num=num;
    s_log(LOG_NOTICE,
#ifdef USE_WIN32
        "stack_info: size=%Iu, current=%Iu (%Iu%%), maximum=%Iu (%Iu%%)",
#else
        "stack_info: size=%zu, current=%zu (%zu%%), maximum=%zu (%zu%%)",
#endif
        stack_size,
        num, num*100/stack_size,
        max_num, max_num*100/stack_size);
}
#ifdef __GNUC__
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6)
#pragma GCC diagnostic pop
#endif /* __GNUC__>=4.6 */
#endif /* __GNUC__ */

#endif /* DEBUG_STACK_SIZE */

#ifndef USE_FORK
NOEXPORT void thread_list_add(CLI *c) {
    c->thread_next=thread_head;
    c->thread_prev=NULL;
    if(thread_head)
        thread_head->thread_prev=c;
    thread_head=c;
}
#endif /* !USE_FORK */

/* end of sthreads.c */
