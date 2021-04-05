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

#include "common.h"
#include "prototypes.h"

/* Uncomment to see allocation sources in core dumps */
/* #define DEBUG_PADDING 64 */

/* reportedly, malloc does not always return 16-byte aligned addresses
 * for 64-bit targets as specified by
 * https://msdn.microsoft.com/en-us/library/6ewkz86d.aspx */
#ifdef USE_WIN32
#define system_malloc(n) _aligned_malloc((n),16)
#define system_realloc(p,n) _aligned_realloc((p),(n),16)
#define system_free(p) _aligned_free(p)
#else
#define system_malloc(n) malloc(n)
#define system_realloc(p,n) realloc((p),(n))
#define system_free(p) free(p)
#endif

#define CANARY_INITIALIZED  0x0000c0ded0000000LL
#define CANARY_UNINTIALIZED 0x0000abadbabe0000LL
#define MAGIC_ALLOCATED     0x0000a110c8ed0000LL
#define MAGIC_DEALLOCATED   0x0000defec8ed0000LL

/* most platforms require allocations to be aligned */
#ifdef _MSC_VER
__declspec(align(16))
#endif
struct alloc_list_struct {
    ALLOC_LIST *prev, *next;
    TLS_DATA *tls;
    size_t size;
    const char *alloc_file, *free_file;
    int alloc_line, free_line;
#ifdef DEBUG_PADDING
    char debug[DEBUG_PADDING];
#endif
    uint64_t valid_canary, magic;
#ifdef __GNUC__
} __attribute__((aligned(16)));
#else
#ifndef MSC_VER
    uint64_t :0; /* align the structure */
#endif
};
#endif

#define LEAK_TABLE_SIZE 997
typedef struct {
    const char *alloc_file;
    int alloc_line;
    int num, max;
} LEAK_ENTRY;
NOEXPORT LEAK_ENTRY leak_hash_table[LEAK_TABLE_SIZE],
    *leak_results[LEAK_TABLE_SIZE];
NOEXPORT int leak_result_num=0;

#ifdef USE_WIN32
NOEXPORT LPTSTR str_vtprintf(LPCTSTR, va_list);
#endif /* USE_WIN32 */

NOEXPORT void *str_realloc_internal_debug(void *, size_t, const char *, int);

NOEXPORT ALLOC_LIST *get_alloc_list_ptr(void *, const char *, int);
NOEXPORT void str_leak_debug(const ALLOC_LIST *, int);

NOEXPORT LEAK_ENTRY *leak_search(const ALLOC_LIST *);
NOEXPORT void leak_report();
NOEXPORT long leak_threshold();

TLS_DATA *ui_tls;
NOEXPORT uint8_t canary[10]; /* 80-bit canary value */
NOEXPORT volatile uint64_t canary_initialized=CANARY_UNINTIALIZED;

/**************************************** string manipulation functions */

#ifndef va_copy
#ifdef __va_copy
#define va_copy(dst, src) __va_copy((dst), (src))
#else /* __va_copy */
#define va_copy(dst, src) memcpy(&(dst), &(src), sizeof(va_list))
#endif /* __va_copy */
#endif /* va_copy */

char *str_dup_debug(const char *str, const char *file, int line) {
    char *retval;

    if(!str)
        return NULL;
    retval=str_alloc_debug(strlen(str)+1, file, line);
    strcpy(retval, str);
    return retval;
}

char *str_dup_detached_debug(const char *str, const char *file, int line) {
    char *retval;

    if(!str)
        return NULL;
    retval=str_alloc_detached_debug(strlen(str)+1, file, line);
    strcpy(retval, str);
    return retval;
}

char *str_printf(const char *format, ...) {
    char *txt;
    va_list arglist;

    va_start(arglist, format);
    txt=str_vprintf(format, arglist);
    va_end(arglist);
    return txt;
}

#ifdef __GNUC__
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6)
#pragma GCC diagnostic push
#endif /* __GNUC__>=4.6 */
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#endif /* __GNUC__ */
char *str_vprintf(const char *format, va_list start_ap) {
    int n;
    size_t size=32;
    char *p;
    va_list ap;

    p=str_alloc(size);
    for(;;) {
        va_copy(ap, start_ap);
        n=vsnprintf(p, size, format, ap);
        if(n>-1 && n<(int)size)
            return p;
        if(n>-1)                /* glibc 2.1 */
            size=(size_t)n+1;   /* precisely what is needed */
        else                    /* glibc 2.0, WIN32, etc. */
            size*=2;            /* twice the old size */
        p=str_realloc(p, size);
    }
}
#ifdef __GNUC__
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6)
#pragma GCC diagnostic pop
#endif /* __GNUC__>=4.6 */
#endif /* __GNUC__ */

#ifdef USE_WIN32

LPTSTR str_tprintf(LPCTSTR format, ...) {
    LPTSTR txt;
    va_list arglist;

    va_start(arglist, format);
    txt=str_vtprintf(format, arglist);
    va_end(arglist);
    return txt;
}

NOEXPORT LPTSTR str_vtprintf(LPCTSTR format, va_list start_ap) {
    int n;
    size_t size=32;
    LPTSTR p;
    va_list ap;

    p=str_alloc(size*sizeof(TCHAR));
    for(;;) {
        va_copy(ap, start_ap);
        n=_vsntprintf(p, size, format, ap);
        if(n>-1 && n<(int)size)
            return p;
        size*=2;
        p=str_realloc(p, size*sizeof(TCHAR));
    }
}

#endif

/**************************************** memory allocation wrappers */

void str_init(TLS_DATA *tls_data) {
    tls_data->alloc_head=NULL;
    tls_data->alloc_bytes=tls_data->alloc_blocks=0;
}

void str_cleanup(TLS_DATA *tls_data) {
    /* free all attached allocations */
    while(tls_data->alloc_head) /* str_free macro requires an lvalue */
        str_free_expression(tls_data->alloc_head+1);
}

void str_canary_init() {
    if(canary_initialized!=CANARY_UNINTIALIZED)
        return; /* prevent double initialization on config reload */
    RAND_bytes(canary, (int)sizeof canary);
    /* an error would reduce the effectiveness of canaries */
    /* this is nothing critical, so the return value is ignored here */
    canary_initialized=CANARY_INITIALIZED; /* after RAND_bytes */
}

void str_stats() {
    TLS_DATA *tls_data;
    ALLOC_LIST *alloc_list;
    int i=0;

    if(!tls_initialized)
        fatal("str not initialized");
    leak_report();
    tls_data=tls_get();
    if(!tls_data || (!tls_data->alloc_blocks && !tls_data->alloc_bytes))
        return; /* skip if no data is allocated */
    s_log(LOG_DEBUG, "str_stats: %lu block(s), "
            "%lu data byte(s), %lu control byte(s)",
        (unsigned long)tls_data->alloc_blocks,
        (unsigned long)tls_data->alloc_bytes,
        (unsigned long)(tls_data->alloc_blocks*
            (sizeof(ALLOC_LIST)+sizeof canary)));
    for(alloc_list=tls_data->alloc_head; alloc_list; alloc_list=alloc_list->next) {
        if(++i>10) /* limit the number of results */
            break;
        s_log(LOG_DEBUG, "str_stats: %lu byte(s) at %s:%d",
            (unsigned long)alloc_list->size,
            alloc_list->alloc_file, alloc_list->alloc_line);
    }
}

void *str_alloc_debug(size_t size, const char *file, int line) {
    TLS_DATA *tls_data;
    ALLOC_LIST *alloc_list;

    if(!tls_initialized)
        fatal_debug("str not initialized", file, line);
    tls_data=tls_get();
    if(!tls_data) {
        tls_data=tls_alloc(NULL, NULL, "alloc");
        s_log(LOG_CRIT, "INTERNAL ERROR: Uninitialized TLS at %s, line %d",
            file, line);
    }

    alloc_list=(ALLOC_LIST *)str_alloc_detached_debug(size, file, line)-1;
    alloc_list->prev=NULL;
    alloc_list->next=tls_data->alloc_head;
    alloc_list->tls=tls_data;
    if(tls_data->alloc_head)
        tls_data->alloc_head->prev=alloc_list;
    tls_data->alloc_head=alloc_list;
    tls_data->alloc_bytes+=size;
    tls_data->alloc_blocks++;

    return alloc_list+1;
}

void *str_alloc_detached_debug(size_t size, const char *file, int line) {
    ALLOC_LIST *alloc_list;

#if 0
    printf("allocating %lu bytes at %s:%d\n", (unsigned long)size, file, line);
#endif
    alloc_list=system_malloc(sizeof(ALLOC_LIST)+size+sizeof canary);
    if(!alloc_list)
        fatal_debug("Out of memory", file, line);
    memset(alloc_list, 0, sizeof(ALLOC_LIST)+size+sizeof canary);
    alloc_list->prev=NULL; /* for debugging */
    alloc_list->next=NULL; /* for debugging */
    alloc_list->tls=NULL;
    alloc_list->size=size;
    alloc_list->alloc_file=file;
    alloc_list->alloc_line=line;
    alloc_list->free_file="none";
    alloc_list->free_line=0;
#ifdef DEBUG_PADDING
    snprintf(alloc_list->debug+1, DEBUG_PADDING-1, "ALLOC_%lu@%s:%d",
        (unsigned long)size, file, line);
#endif
    alloc_list->valid_canary=canary_initialized; /* before memcpy */
    memcpy((uint8_t *)(alloc_list+1)+size, canary, sizeof canary);
    alloc_list->magic=MAGIC_ALLOCATED;
    str_leak_debug(alloc_list, 1);

    return alloc_list+1;
}

void *str_realloc_debug(void *ptr, size_t size, const char *file, int line) {
    if(ptr)
        return str_realloc_internal_debug(ptr, size, file, line);
    else
        return str_alloc_debug(size, file, line);
}

void *str_realloc_detached_debug(void *ptr, size_t size, const char *file, int line) {
    if(ptr)
        return str_realloc_internal_debug(ptr, size, file, line);
    else
        return str_alloc_detached_debug(size, file, line);
}

NOEXPORT void *str_realloc_internal_debug(void *ptr, size_t size, const char *file, int line) {
    ALLOC_LIST *prev_alloc_list, *alloc_list;

    prev_alloc_list=get_alloc_list_ptr(ptr, file, line);
    str_leak_debug(prev_alloc_list, -1);
    if(prev_alloc_list->size>size) /* shrinking the allocation */
        memset((uint8_t *)ptr+size, 0, prev_alloc_list->size-size); /* paranoia */
    alloc_list=system_realloc(prev_alloc_list, sizeof(ALLOC_LIST)+size+sizeof canary);
    if(!alloc_list)
        fatal_debug("Out of memory", file, line);
    ptr=alloc_list+1;
    if(size>alloc_list->size) /* growing the allocation */
        memset((uint8_t *)ptr+alloc_list->size, 0, size-alloc_list->size);
    if(alloc_list->tls) { /* not detached */
        /* refresh possibly invalidated linked list pointers */
        if(alloc_list->tls->alloc_head==prev_alloc_list)
            alloc_list->tls->alloc_head=alloc_list;
        if(alloc_list->next)
            alloc_list->next->prev=alloc_list;
        if(alloc_list->prev)
            alloc_list->prev->next=alloc_list;
        /* update statistics while the old size is still available */
        alloc_list->tls->alloc_bytes+=size-alloc_list->size;
    }
    alloc_list->size=size;
    alloc_list->alloc_file=file;
    alloc_list->alloc_line=line;
    alloc_list->free_file="none";
    alloc_list->free_line=0;
#ifdef DEBUG_PADDING
    snprintf(alloc_list->debug+1, DEBUG_PADDING-1, "ALLOC_%lu@%s:%d",
        (unsigned long)size, file, line);
#endif
    alloc_list->valid_canary=canary_initialized; /* before memcpy */
    memcpy((uint8_t *)ptr+size, canary, sizeof canary);
    str_leak_debug(alloc_list, 1);
    return ptr;
}

/* detach from thread automatic deallocation list */
/* it has no effect if the allocation is already detached */
void str_detach_debug(void *ptr, const char *file, int line) {
    ALLOC_LIST *alloc_list;

    if(!ptr) /* do not attempt to free null pointers */
        return;
    alloc_list=get_alloc_list_ptr(ptr, file, line);
    if(alloc_list->tls) { /* not detached */
        /* remove from linked list */
        if(alloc_list->tls->alloc_head==alloc_list)
            alloc_list->tls->alloc_head=alloc_list->next;
        if(alloc_list->next)
            alloc_list->next->prev=alloc_list->prev;
        if(alloc_list->prev)
            alloc_list->prev->next=alloc_list->next;
        /* update statistics */
        alloc_list->tls->alloc_bytes-=alloc_list->size;
        alloc_list->tls->alloc_blocks--;
        /* clear pointers */
        alloc_list->next=NULL;
        alloc_list->prev=NULL;
        alloc_list->tls=NULL;
    }
}

void str_free_debug(void *ptr, const char *file, int line) {
    ALLOC_LIST *alloc_list;

    if(!ptr) /* do not attempt to free null pointers */
        return;
    alloc_list=(ALLOC_LIST *)ptr-1;
    if(alloc_list->magic==MAGIC_DEALLOCATED) { /* double free */
        /* this may (unlikely) log garbage instead of file names */
        s_log(LOG_CRIT, "INTERNAL ERROR: Double free attempt: "
                "ptr=%p alloc=%s:%d free#1=%s:%d free#2=%s:%d",
            ptr,
            alloc_list->alloc_file, alloc_list->alloc_line,
            alloc_list->free_file, alloc_list->free_line,
            file, line);
        return;
    }
    str_detach_debug(ptr, file, line);
    str_leak_debug(alloc_list, -1);
    alloc_list->free_file=file;
    alloc_list->free_line=line;
    alloc_list->magic=MAGIC_DEALLOCATED; /* detect double free attempts */
    memset(ptr, 0, alloc_list->size+sizeof canary); /* paranoia */
    system_free(alloc_list);
}

NOEXPORT ALLOC_LIST *get_alloc_list_ptr(void *ptr, const char *file, int line) {
    ALLOC_LIST *alloc_list;

    if(!tls_initialized)
        fatal_debug("str not initialized", file, line);
    alloc_list=(ALLOC_LIST *)ptr-1;
    if(alloc_list->magic!=MAGIC_ALLOCATED) /* not allocated by str_alloc() */
        fatal_debug("Bad magic", file, line); /* LOL */
    if(alloc_list->tls /* not detached */ && alloc_list->tls!=tls_get())
        fatal_debug("Memory allocated in a different thread", file, line);
    if(alloc_list->valid_canary!=CANARY_UNINTIALIZED &&
            safe_memcmp((uint8_t *)ptr+alloc_list->size, canary, sizeof canary))
        fatal_debug("Dead canary", file, line); /* LOL */
    return alloc_list;
}

/**************************************** memory leak detection */

NOEXPORT void str_leak_debug(const ALLOC_LIST *alloc_list, int change) {
    static size_t entries=0;
    LEAK_ENTRY *entry;
    int new_entry;
    int allocations;

    if(service_options.log_level<LOG_DEBUG) /* performance optimization */
        return;
#ifdef USE_OS_THREADS
    if(!stunnel_locks[STUNNEL_LOCKS-1]) /* threads not initialized */
        return;
#endif /* USE_OS_THREADS */
    if(!number_of_sections) /* configuration file not initialized */
        return;

    entry=leak_search(alloc_list);
    /* the race condition may lead to false positives, which is handled later */
    new_entry=entry->alloc_line!=alloc_list->alloc_line ||
        entry->alloc_file!=alloc_list->alloc_file;

    if(new_entry) { /* the file:line pair was encountered for the first time */
        CRYPTO_THREAD_write_lock(stunnel_locks[LOCK_LEAK_HASH]);
        entry=leak_search(alloc_list); /* the list may have changed */
        if(entry->alloc_line==0) {
            if(entries>LEAK_TABLE_SIZE-100) { /* this should never happen */
                CRYPTO_THREAD_unlock(stunnel_locks[LOCK_LEAK_HASH]);
                return;
            }
            entries++;
            entry->alloc_line=alloc_list->alloc_line;
            entry->alloc_file=alloc_list->alloc_file;
        }
        CRYPTO_THREAD_unlock(stunnel_locks[LOCK_LEAK_HASH]);
    }

    /* for performance we try to avoid calling CRYPTO_atomic_add() here */
#ifdef USE_OS_THREADS
#if defined(__GNUC__) && defined(__ATOMIC_ACQ_REL)
    if(__atomic_is_lock_free(sizeof entry->num, &entry->num))
        allocations=__atomic_add_fetch(&entry->num, change, __ATOMIC_ACQ_REL);
    else
        CRYPTO_atomic_add(&entry->num, change, &allocations,
            stunnel_locks[LOCK_LEAK_HASH]);
#elif defined(_MSC_VER)
    allocations=InterlockedExchangeAdd(&entry->num, change)+change;
#else /* atomic add not directly supported by the compiler */
    CRYPTO_atomic_add(&entry->num, change, &allocations,
        stunnel_locks[LOCK_LEAK_HASH]);
#endif
#else /* USE_OS_THREADS */
    allocations=(entry->num+=change);
#endif /* USE_OS_THREADS */

    if(allocations<=leak_threshold()) /* leak not detected */
        return;
    if(allocations<=entry->max) /* not the biggest leak for this entry */
        return;
    if(entry->max) { /* not the first time we found a leak for this entry */
        entry->max=allocations; /* just update the value */
        return;
    }
    /* we *may* need to allocate a new leak_results entry */
    /* locking is slow, so we try to avoid it if possible */
    CRYPTO_THREAD_write_lock(stunnel_locks[LOCK_LEAK_RESULTS]);
    if(entry->max==0) /* the table may have changed */
        leak_results[leak_result_num++]=entry;
    entry->max=allocations;
    CRYPTO_THREAD_unlock(stunnel_locks[LOCK_LEAK_RESULTS]);
}

/* O(1) hash table lookup */
NOEXPORT LEAK_ENTRY *leak_search(const ALLOC_LIST *alloc_list) {
    /* a trivial hash based on source file name *address* and line number */
    unsigned i=((unsigned)(uintptr_t)alloc_list->alloc_file+
        (unsigned)alloc_list->alloc_line)%LEAK_TABLE_SIZE;

    while(!(leak_hash_table[i].alloc_line==0 ||
            (leak_hash_table[i].alloc_line==alloc_list->alloc_line &&
            leak_hash_table[i].alloc_file==alloc_list->alloc_file)))
        i=(i+1)%LEAK_TABLE_SIZE;
    return leak_hash_table+i;
}

void leak_table_utilization() {
    int i, utilization=0;

    for(i=0; i<LEAK_TABLE_SIZE; ++i) {
        if(leak_hash_table[i].alloc_line) {
            ++utilization;
#if 0
            s_log(LOG_DEBUG, "Leak hash entry %d: %s:%d", i,
                leak_hash_table[i].alloc_file, leak_hash_table[i].alloc_line);
#endif
        }
    }
    s_log(LOG_DEBUG, "Leak detection table utilization: %d/%d, %02.2f%%",
        utilization, LEAK_TABLE_SIZE, 100.0*utilization/LEAK_TABLE_SIZE);
}

/* report identified leaks */
NOEXPORT void leak_report() {
    int i;
    long limit;

    limit=leak_threshold();

    CRYPTO_THREAD_read_lock(stunnel_locks[LOCK_LEAK_RESULTS]);
    for(i=0; i<leak_result_num; ++i)
        if(leak_results[i] /* an officious compiler could reorder code */ &&
                leak_results[i]->max>limit /* the limit could have changed */)
            s_log(LOG_WARNING, "Possible memory leak at %s:%d: %d allocations",
                leak_results[i]->alloc_file, leak_results[i]->alloc_line,
                leak_results[i]->max);
    CRYPTO_THREAD_unlock(stunnel_locks[LOCK_LEAK_RESULTS]);
}

NOEXPORT long leak_threshold() {
    long limit;

    limit=10000*((int)number_of_sections+1);
#ifndef USE_FORK
    limit+=100*num_clients;
#endif
    return limit;
}

/**************************************** memcmp() replacement */

/* a version of memcmp() with execution time not dependent on data values */
/* it does *not* allow testing whether s1 is greater or lesser than s2  */
int safe_memcmp(const void *s1, const void *s2, size_t n) {
#ifdef _WIN64
    typedef unsigned long long TL;
#else
    typedef unsigned long TL;
#endif
    typedef unsigned char TS;
    TL r=0, *pl1, *pl2;
    TS *ps1, *ps2;
    int n1=(int)((uintptr_t)s1&(sizeof(TL)-1)); /* unaligned bytes in s1 */
    int n2=(int)((uintptr_t)s2&(sizeof(TL)-1)); /* unaligned bytes in s2 */

    if(n1 || n2) { /* either pointer unaligned */
        ps1=(TS *)s1;
        ps2=(TS *)s2;
    } else { /* both pointers aligned -> compare full words */
        pl1=(TL *)s1;
        pl2=(TL *)s2;
        while(n>=sizeof(TL)) {
            n-=sizeof(TL);
            r|=(*pl1++)^(*pl2++);
        }
        ps1=(TS *)pl1;
        ps2=(TS *)pl2;
    }
    while(n--)
        r|=(*ps1++)^(*ps2++);
    return r!=0;
}

/* end of str.c */
