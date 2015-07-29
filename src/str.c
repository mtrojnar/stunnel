/*
 *   stunnel       TLS offloading and load-balancing proxy
 *   Copyright (C) 1998-2015 Michal Trojnara <Michal.Trojnara@mirt.net>
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

struct alloc_list_struct {
    ALLOC_LIST *prev, *next;
    TLS_DATA *tls;
    size_t size;
    const char *file;
    int line;
    int valid_canary;
    unsigned magic;
        /* at least on IA64 allocations need to be aligned */
#ifdef __GNUC__
} __attribute__((aligned(16)));
#else
    uint64_t :0; /* align the structure */
};
#endif

#ifdef USE_WIN32
NOEXPORT LPTSTR str_vtprintf(LPCTSTR, va_list);
#endif /* USE_WIN32 */

NOEXPORT ALLOC_LIST *get_alloc_list_ptr(void *, const char *, int);
NOEXPORT void str_leak_debug(ALLOC_LIST *, int);

TLS_DATA *ui_tls;
static uint8_t canary[10]; /* 80-bit canary value */
static volatile int canary_initialized=0;

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

    retval=str_alloc_debug(strlen(str)+1, file, line);
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
    if(canary_initialized) /* prevent double initialization on config reload */
        return;
    RAND_bytes(canary, sizeof canary);
    /* an error would reduce the effectiveness of canaries */
    /* this is nothing critical, so the return value is ignored here */
    canary_initialized=1; /* after RAND_bytes */
}

void str_stats() {
    TLS_DATA *tls_data;
    ALLOC_LIST *alloc_list;
    int i=0;

    if(!tls_initialized)
        fatal("str not initialized");
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
            alloc_list->file, alloc_list->line);
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
        s_log(LOG_ERR, "INTERNAL ERROR: Uninitialized TLS at %s, line %d",
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
    alloc_list=calloc(1, sizeof(ALLOC_LIST)+size+sizeof canary);
    if(!alloc_list)
        fatal_debug("Out of memory", file, line);
    alloc_list->prev=NULL; /* for debugging */
    alloc_list->next=NULL; /* for debugging */
    alloc_list->tls=NULL;
    alloc_list->size=size;
    alloc_list->file=file;
    alloc_list->line=line;
    alloc_list->valid_canary=canary_initialized; /* before memcpy */
    memcpy((uint8_t *)(alloc_list+1)+size, canary, sizeof canary);
    alloc_list->magic=0xdeadbeef;
    str_leak_debug(alloc_list, 1);

    return alloc_list+1;
}

void *str_realloc_debug(void *ptr, size_t size, const char *file, int line) {
    ALLOC_LIST *prev_alloc_list, *alloc_list;

    if(!ptr)
        return str_alloc_debug(size, file, line);
    prev_alloc_list=get_alloc_list_ptr(ptr, file, line);
    str_leak_debug(prev_alloc_list, -1);
    if(prev_alloc_list->size>size) /* shrinking the allocation */
        memset((uint8_t *)ptr+size, 0, prev_alloc_list->size-size); /* paranoia */
    alloc_list=realloc(prev_alloc_list,
        sizeof(ALLOC_LIST)+size+sizeof canary);
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
    alloc_list->file=file;
    alloc_list->line=line;
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
    str_detach_debug(ptr, file, line);
    alloc_list=(ALLOC_LIST *)ptr-1;
    str_leak_debug(alloc_list, -1);
    alloc_list->magic=0xdefec8ed; /* to detect double free attempts */
    memset(ptr, 0, alloc_list->size); /* paranoia */
    free(alloc_list);
}

NOEXPORT ALLOC_LIST *get_alloc_list_ptr(void *ptr, const char *file, int line) {
    ALLOC_LIST *alloc_list;

    if(!tls_initialized)
        fatal_debug("str not initialized", file, line);
    alloc_list=(ALLOC_LIST *)ptr-1;
    if(alloc_list->magic!=0xdeadbeef) { /* not allocated by str_alloc() */
        if(alloc_list->magic==0xdefec8ed)
            fatal_debug("Double free attempt", file, line);
        else
            fatal_debug("Bad magic", file, line); /* LOL */
    }
    if(alloc_list->tls /* not detached */ && alloc_list->tls!=tls_get())
        fatal_debug("Memory allocated in a different thread", file, line);
    if(alloc_list->valid_canary &&
            safe_memcmp((uint8_t *)ptr+alloc_list->size, canary, sizeof canary))
        fatal_debug("Dead canary", file, line); /* LOL */
    return alloc_list;
}

/* #define STR_LEAK_DEBUG */
/* the implementation is slow, but it's not going to be used in production */
NOEXPORT void str_leak_debug(ALLOC_LIST *alloc_list, int change) {
#ifndef STR_LEAK_DEBUG
    (void)alloc_list; /* skip warning about unused parameter */
    (void)change; /* skip warning about unused parameter */
#else
#define ALLOC_TABLE_SIZE 1000
#define MAX_ALLOCS 200
    static struct {
        const char *file;
        int line;
        int num;
    } alloc_table[ALLOC_TABLE_SIZE];
    static size_t alloc_num=0;
    size_t i;

    enter_critical_section(CRIT_LEAK);
    for(i=0; i<alloc_num; ++i)
        if(alloc_table[i].file==alloc_list->file &&
                alloc_table[i].line==alloc_list->line)
            break;
    if(i==alloc_num) {
        if(alloc_num==ALLOC_TABLE_SIZE) {
            leave_critical_section(CRIT_LEAK);
            return;
        }
        alloc_table[i].file=alloc_list->file;
        alloc_table[i].line=alloc_list->line;
        alloc_table[i].num=0;
        ++alloc_num;
    }
    alloc_table[i].num+=change;
    leave_critical_section(CRIT_LEAK);
    if(alloc_table[i].num>MAX_ALLOCS && strcmp(alloc_table[i].file, "lhash.c"))
        fprintf(stderr, "%d allocations detected at %s:%d\n",
            alloc_table[i].num, alloc_table[i].file, alloc_table[i].line);
#endif
}

/**************************************** memcmp() replacement */

/* a version of memcmp() with execution time not dependent on data values */
/* it does *not* allow to test wheter s1 is greater or lesser than s2  */
int safe_memcmp(const void *s1, const void *s2, size_t n) {
    uint8_t *p1=(uint8_t *)s1, *p2=(uint8_t *)s2;
    int r=0;
    while(n--)
        r|=*p1++^*p2++;
    return r;
}

/* end of str.c */
