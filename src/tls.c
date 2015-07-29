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

volatile int tls_initialized=0;

NOEXPORT void tls_platform_init();
NOEXPORT void free_function(void *);

/**************************************** thread local storage */

/* this has to be the first function called from ui_*.c */
void tls_init() {
    tls_platform_init();
    tls_initialized=1;
    ui_tls=tls_alloc(NULL, NULL, "ui");
    CRYPTO_set_mem_ex_functions(str_alloc_detached_debug,
        str_realloc_debug, free_function);
}

/* this has to be the first function called by a new thread */
TLS_DATA *tls_alloc(CLI *c, TLS_DATA *inherited, char *txt) {
    TLS_DATA *tls_data;

    if(inherited) { /* reuse the thread-local storage after fork() */
        tls_data=inherited;
        str_free(tls_data->id);
    } else {
        tls_data=calloc(1, sizeof(TLS_DATA));
        if(!tls_data)
            fatal("Out of memory");
        if(c)
            c->tls=tls_data;
        str_init(tls_data);
        tls_data->c=c;
        tls_data->opt=c?c->opt:&service_options;
    }
    tls_data->id="unconfigured";
    tls_set(tls_data);

    /* str.c functions can be used below this point */
    if(txt) {
        tls_data->id=str_dup(txt);
        str_detach(tls_data->id); /* it is deallocated after str_stats() */
    } else if(c) {
        tls_data->id=log_id(c);
        str_detach(tls_data->id); /* it is deallocated after str_stats() */
    }

    return tls_data;
}

/* per-thread thread-local storage cleanup */
void tls_cleanup() {
    TLS_DATA *tls_data;

    tls_data=tls_get();
    if(!tls_data)
        return;
    str_cleanup(tls_data);
    str_free(tls_data->id); /* detached allocation */
    tls_set(NULL);
    free(tls_data);
}

#ifdef USE_UCONTEXT

static TLS_DATA *global_tls=NULL;

NOEXPORT void tls_platform_init() {
}

void tls_set(TLS_DATA *tls_data) {
    if(ready_head)
        ready_head->tls=tls_data;
    else /* ucontext threads not initialized */
        global_tls=tls;
}

TLS_DATA *tls_get() {
    if(ready_head)
        return ready_head->tls;
    else /* ucontext threads not initialized */
        return global_tls;
}

#endif /* USE_UCONTEXT */

#ifdef USE_FORK

static TLS_DATA *global_tls=NULL;

NOEXPORT void tls_platform_init() {
}

void tls_set(TLS_DATA *tls_data) {
    global_tls=tls_data;
}

TLS_DATA *tls_get() {
    return global_tls;
}

#endif /* USE_FORK */

#ifdef USE_PTHREAD

static pthread_key_t pthread_key;

NOEXPORT void tls_platform_init() {
    pthread_key_create(&pthread_key, NULL);
}

void tls_set(TLS_DATA *tls_data) {
    pthread_setspecific(pthread_key, tls_data);
}

TLS_DATA *tls_get() {
    return pthread_getspecific(pthread_key);
}

#endif /* USE_PTHREAD */

#ifdef USE_WIN32

static DWORD tls_index;

NOEXPORT void tls_platform_init() {
    tls_index=TlsAlloc();
}

void tls_set(TLS_DATA *tls_data) {
    TlsSetValue(tls_index, tls_data);
}

TLS_DATA *tls_get() {
    return TlsGetValue(tls_index);
}

#endif /* USE_WIN32 */

/**************************************** OpenSSL allocator hook */

NOEXPORT void free_function(void *ptr) {
    /* CRYPTO_set_mem_ex_functions() needs a function rather than a macro */
    str_free(ptr);
}

/* end of tls.c */
