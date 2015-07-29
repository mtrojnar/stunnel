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

typedef struct str_struct {
    struct str_struct *prev, *next;
    size_t size;
    unsigned int magic;
} STR;
static void str_set(STR *);
static STR *str_get();

#ifdef USE_WIN32

/* __thread does not work in mingw32 due to a bug in GCC */
static DWORD tls_index; 

void str_init() {
    tls_index=TlsAlloc();
    if(tls_index==TLS_OUT_OF_INDEXES) {
        s_log(LOG_ERR, "TlsAlloc failed");
        die(1);
    }
}

static void str_set(STR *str) {
    if(!TlsSetValue(tls_index, str)) {
        s_log(LOG_ERR, "TlsSetValue failed");
        die(1);
    }
}

static STR *str_get() {
    STR *str;

    str=TlsGetValue(tls_index);
    if(!str && GetLastError()!=ERROR_SUCCESS) {
        s_log(LOG_ERR, "TlsGetValue failed");
        die(1);
    }
    return str;
}

#else

/* gcc Thread-Local Storage */
static __thread STR *root_str=NULL;

void str_init() {
    if(root_str)
        s_log(LOG_WARNING, "str_init: Non-empty allocation list");
}

static void str_set(STR *str) {
    root_str=str;
}

static STR *str_get() {
    return root_str;
}

#endif

void str_cleanup() {
    STR *str, *tmp;

    str=str_get();
    while(str) {
        tmp=str;
        str=tmp->next;
        free(tmp);
    }
    str_set(NULL);
}

void str_stats() {
    STR *tmp;
    int blocks=0, bytes=0;

    for(tmp=str_get(); tmp; tmp=tmp->next) {
        ++blocks;
        bytes+=tmp->size;
    }
    s_log(LOG_DEBUG, "str_stats: %d blocks, %d bytes", blocks, bytes);
}

void *str_alloc(size_t size) {
    STR *str, *tmp;

    if(size>=1024*1024) /* huge allocations are not allowed */
        return NULL;
    tmp=calloc(1, sizeof(STR)+size);
    if(!tmp)
        return NULL;
    str=str_get();
    tmp->prev=NULL;
    tmp->next=str;
    tmp->size=size;
    tmp->magic=0xdeadbeef;
    if(str)
        str->prev=tmp;
    str_set(tmp);
    return tmp+1;
}

void *str_realloc(void *ptr, size_t size) {
    STR *oldtmp, *tmp;

    if(!ptr)
        return str_alloc(size);
    oldtmp=(STR *)ptr-1;
    if(oldtmp->magic!=0xdeadbeef) { /* not allocated by str_alloc() */
        s_log(LOG_CRIT, "INTERNAL ERROR: str_realloc: Bad magic");
        die(1);
    }
    tmp=realloc(oldtmp, sizeof(STR)+size);
    if(!tmp)
        return NULL;
    /* refresh all possibly invalidated pointers */
    if(tmp->next)
        tmp->next->prev=tmp;
    if(tmp->prev)
        tmp->prev->next=tmp;
    tmp->size=size;
    if(str_get()==oldtmp)
        str_set(tmp);
    return tmp+1;
}

void str_free(void *ptr) {
    STR *tmp;

    if(!ptr) /* do not attempt to free null pointers */
        return;
    tmp=(STR *)ptr-1;
    if(tmp->magic!=0xdeadbeef) { /* not allocated by str_alloc() */
        s_log(LOG_CRIT, "INTERNAL ERROR: str_free: Bad magic");
        die(1);
    }
    tmp->magic=0xdefec8ed; /* to detect double free */
    if(tmp->next)
        tmp->next->prev=tmp->prev;
    if(tmp->prev)
        tmp->prev->next=tmp->next;
    if(str_get()==tmp)
        str_set(tmp->next);
    free(tmp);
}

char *str_dup(const char *str) {
    char *retval;

    retval=str_alloc(strlen(str)+1);
    if(retval)
        strcpy(retval, str);
    return retval;
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
        else          /* glibc 2.0 */
            size*=2;  /* twice the old size */
        np=str_realloc(p, size);
        if(!np) {
            str_free(p);
            return NULL;
        }
        p=np; /* LOL */
    }
}

char *str_printf(const char *format, ...) {
    char *txt;
    va_list arglist;

    va_start(arglist, format);
    txt=str_vprintf(format, arglist);
    va_end(arglist);
    return txt;
}

/* end of str.c */
