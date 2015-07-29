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

#include "common.h"
#include "prototypes.h"

#ifndef va_copy
#ifdef __va_copy
#define va_copy(dst, src) __va_copy((dst), (src))
#else /* __va_copy */
#define va_copy(dst, src) memcpy(&(dst), &(src), sizeof(va_list))
#endif /* __va_copy */
#endif /* va_copy */

typedef struct alloc_list {
    struct alloc_list *prev, *next;
    size_t size;
    unsigned int magic;
} ALLOC_LIST;

static void set_alloc_head(ALLOC_LIST *);
static ALLOC_LIST *get_alloc_head();

char *str_dup(const char *str) {
    char *retval;

    retval=str_alloc(strlen(str)+1);
    if(retval)
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
    int n, size=64;
    char *p, *np;
    va_list ap;

    p=str_alloc(size);
    if(!p)
        return NULL;
    for(;;) {
        va_copy(ap, start_ap);
        n=vsnprintf(p, size, format, ap);
        if(n>-1 && n<size)
            return p;
        if(n>-1)      /* glibc 2.1 */
            size=n+1; /* precisely what is needed */
        else          /* glibc 2.0, WIN32, etc. */
            size*=2;  /* twice the old size */
        np=str_realloc(p, size);
        if(!np) {
            str_free(p);
            return NULL;
        }
        p=np; /* LOL */
    }
}

#ifdef USE_UCONTEXT

static ALLOC_LIST *alloc_tls=NULL;

void str_init() {
}

static void set_alloc_head(ALLOC_LIST *alloc_head) {
    if(ready_head)
        ready_head->tls=alloc_head;
    else /* ucontext threads not initialized */
        alloc_tls=alloc_head;
}

static ALLOC_LIST *get_alloc_head() {
    if(ready_head)
        return ready_head->tls;
    else /* ucontext threads not initialized */
        return alloc_tls;
}

#endif /* USE_UCONTEXT */

#ifdef USE_FORK

static ALLOC_LIST *alloc_tls=NULL;

void str_init() {
}

static void set_alloc_head(ALLOC_LIST *alloc_head) {
    alloc_tls=alloc_head;
}

static ALLOC_LIST *get_alloc_head() {
    return alloc_tls;
}

#endif /* USE_FORK */

#ifdef USE_PTHREAD

static pthread_key_t pthread_key;

void str_init() {
    pthread_key_create(&pthread_key, NULL);
}

static void set_alloc_head(ALLOC_LIST *alloc_head) {
    pthread_setspecific(pthread_key, alloc_head);
}

static ALLOC_LIST *get_alloc_head() {
    return pthread_getspecific(pthread_key);
}

#endif /* USE_PTHREAD */

#ifdef USE_WIN32

static DWORD tls_index; 

void str_init() {
    tls_index=TlsAlloc();
    if(tls_index==TLS_OUT_OF_INDEXES) {
        s_log(LOG_ERR, "TlsAlloc failed");
        die(1);
    }
}

static void set_alloc_head(ALLOC_LIST *alloc_head) {
    if(!TlsSetValue(tls_index, alloc_head)) {
        s_log(LOG_ERR, "TlsSetValue failed");
        die(1);
    }
}

static ALLOC_LIST *get_alloc_head() {
    ALLOC_LIST *alloc_head;

    alloc_head=TlsGetValue(tls_index);
    if(!alloc_head && GetLastError()!=ERROR_SUCCESS) {
        s_log(LOG_ERR, "TlsGetValue failed");
        die(1);
    }
    return alloc_head;
}

#endif /* USE_WIN32 */

void str_cleanup() {
    ALLOC_LIST *alloc_head, *tmp;

    alloc_head=get_alloc_head();
    while(alloc_head) {
        tmp=alloc_head;
        alloc_head=tmp->next;
        free(tmp);
    }
    set_alloc_head(NULL);
}

void str_stats() {
    ALLOC_LIST *tmp;
    int blocks=0, bytes=0;

    for(tmp=get_alloc_head(); tmp; tmp=tmp->next) {
        ++blocks;
        bytes+=tmp->size;
    }
    s_log(LOG_DEBUG, "str_stats: %d block(s), %d byte(s)", blocks, bytes);
}

void *str_alloc(size_t size) {
    ALLOC_LIST *alloc_head, *tmp;

    if(size>=1024*1024) /* huge allocations are not allowed */
        return NULL;
    tmp=calloc(1, sizeof(ALLOC_LIST)+size);
    if(!tmp)
        return NULL;
    alloc_head=get_alloc_head();
    tmp->prev=NULL;
    tmp->next=alloc_head;
    tmp->size=size;
    tmp->magic=0xdeadbeef;
    if(alloc_head)
        alloc_head->prev=tmp;
    set_alloc_head(tmp);
    return tmp+1;
}

void *str_realloc(void *ptr, size_t size) {
    ALLOC_LIST *old_tmp, *tmp;

    if(!ptr)
        return str_alloc(size);
    old_tmp=(ALLOC_LIST *)ptr-1;
    if(old_tmp->magic!=0xdeadbeef) { /* not allocated by str_alloc() */
        s_log(LOG_CRIT, "INTERNAL ERROR: str_realloc: Bad magic");
        die(1);
    }
    if(size>=1024*1024) /* huge allocations are not allowed */
        return NULL;
    tmp=realloc(old_tmp, sizeof(ALLOC_LIST)+size);
    if(!tmp)
        return NULL;
    /* refresh all possibly invalidated pointers */
    if(tmp->next)
        tmp->next->prev=tmp;
    if(tmp->prev)
        tmp->prev->next=tmp;
    tmp->size=size;
    if(get_alloc_head()==old_tmp)
        set_alloc_head(tmp);
    return tmp+1;
}

void str_free(void *ptr) {
    ALLOC_LIST *tmp;

    if(!ptr) /* do not attempt to free null pointers */
        return;
    tmp=(ALLOC_LIST *)ptr-1;
    if(tmp->magic!=0xdeadbeef) { /* not allocated by str_alloc() */
        s_log(LOG_CRIT, "INTERNAL ERROR: str_free: Bad magic");
        die(1);
    }
    tmp->magic=0xdefec8ed; /* to detect double free */
    if(tmp->next)
        tmp->next->prev=tmp->prev;
    if(tmp->prev)
        tmp->prev->next=tmp->next;
    if(get_alloc_head()==tmp)
        set_alloc_head(tmp->next);
    free(tmp);
}

/* end of str.c */
