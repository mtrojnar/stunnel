/*
 *   stunnel       Universal SSL tunnel
 *   Copyright (C) 1998-2009 Michal Trojnara <Michal.Trojnara@mirt.net>
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

    /* Global OpenSSL initalization: compression, engine, entropy */
static void init_compression(void);
static int init_prng(void);
static int prng_seeded(int);
static int add_rand_file(char *);
#ifdef HAVE_OSSL_ENGINE_H
static void init_engine(void);
#endif

int cli_index, opt_index; /* to keep structure for callbacks */

void ssl_init(void) { /* init SSL before parsing configuration file */
#ifdef HAVE_OPENSSL
    OpenSSL_add_all_algorithms();
#endif
    SSLeay_add_ssl_algorithms();
    SSL_load_error_strings();
    cli_index=SSL_get_ex_new_index(0, "cli index", NULL, NULL, NULL);
    opt_index=SSL_CTX_get_ex_new_index(0, "opt index", NULL, NULL, NULL);
#ifdef HAVE_OSSL_ENGINE_H
    ENGINE_load_builtin_engines();
#endif
}

void ssl_configure(void) { /* configure global SSL settings */
    if(options.compression!=COMP_NONE)
        init_compression();
    if(!init_prng())
        s_log(LOG_DEBUG, "PRNG seeded successfully");
}

static void init_compression(void) {
    int id=0;
    COMP_METHOD *cm=NULL;
    char *name="unknown";

    switch(options.compression) {
    case COMP_ZLIB:
        id=0xe0;
        cm=COMP_zlib();
        name="zlib";
        break;
    case COMP_RLE:
        id=0xe1;
        cm=COMP_rle();
        name="rle";
        break;
    default:
        s_log(LOG_ERR, "INTERNAL ERROR: Bad compression method");
        die(1);
    }
    if(!cm || cm->type==NID_undef) {
        s_log(LOG_ERR, "Failed to initialize %s compression method", name);
        die(1);
    }
    if(SSL_COMP_add_compression_method(id, cm)) {
        s_log(LOG_ERR, "Failed to add %s compression method", name);
        die(1);
    }
    s_log(LOG_INFO, "Compression enabled using %s method", name);
}

static int init_prng(void) {
    int totbytes=0;
    char filename[STRLEN];
    int bytes;

    bytes=0; /* avoid warning if #ifdef'd out for windows */

    filename[0]='\0';

    /* If they specify a rand file on the command line we
       assume that they really do want it, so try it first */
    if(options.rand_file) {
        totbytes+=add_rand_file(options.rand_file);
        if(prng_seeded(totbytes))
            return 0;
    }

    /* try the $RANDFILE or $HOME/.rnd files */
    RAND_file_name(filename, STRLEN);
    if(filename[0]) {
        filename[STRLEN-1]='\0';        /* just in case */
        totbytes+=add_rand_file(filename);
        if(prng_seeded(totbytes))
            return 0;
    }

#ifdef RANDOM_FILE
    totbytes+=add_rand_file(RANDOM_FILE);
    if(prng_seeded(totbytes))
        return 0;
#endif

#ifdef USE_WIN32
    RAND_screen();
    if(prng_seeded(totbytes)) {
        s_log(LOG_DEBUG, "Seeded PRNG with RAND_screen");
        return 0;
    }
    s_log(LOG_DEBUG, "RAND_screen failed to sufficiently seed PRNG");
#else

#if SSLEAY_VERSION_NUMBER>=0x0090581fL
    if(options.egd_sock) {
        if((bytes=RAND_egd(options.egd_sock))==-1) {
            s_log(LOG_WARNING, "EGD Socket %s failed", options.egd_sock);
            bytes=0;
        } else {
            totbytes+=bytes;
            s_log(LOG_DEBUG, "Snagged %d random bytes from EGD Socket %s",
                bytes, options.egd_sock);
            return 0; /* OpenSSL always gets what it needs or fails,
                         so no need to check if seeded sufficiently */
        }
    }
#ifdef EGD_SOCKET
    if((bytes=RAND_egd(EGD_SOCKET))==-1) {
        s_log(LOG_WARNING, "EGD Socket %s failed", EGD_SOCKET);
    } else {
        totbytes+=bytes;
        s_log(LOG_DEBUG, "Snagged %d random bytes from EGD Socket %s",
            bytes, EGD_SOCKET);
        return 0;
    }
#endif /* EGD_SOCKET */

#endif /* OpenSSL-0.9.5a */
#endif /* USE_WIN32 */

    /* Try the good-old default /dev/urandom, if available  */
    totbytes+=add_rand_file("/dev/urandom");
    if(prng_seeded(totbytes))
        return 0;

    /* Random file specified during configure */
    s_log(LOG_WARNING, "PRNG seeded with %d bytes total", totbytes);
    s_log(LOG_WARNING,
        "PRNG may not have been seeded with enough random bytes");
    return -1; /* FAILED */
}

/* shortcut to determine if sufficient entropy for PRNG is present */
static int prng_seeded(int bytes) {
#if SSLEAY_VERSION_NUMBER>=0x0090581fL
    if(RAND_status()){
        s_log(LOG_DEBUG, "RAND_status claims sufficient entropy for the PRNG");
        return 1;
    }
#else
    if(bytes>=options.random_bytes) {
        s_log(LOG_DEBUG, "Sufficient entropy in PRNG assumed (>= %d)",
            options.random_bytes);
        return 1;
    }
#endif
    return 0;        /* assume we don't have enough */
}

static int add_rand_file(char *filename) {
    int readbytes;
    int writebytes;
    struct stat sb;

    if(stat(filename, &sb))
        return 0;
    if((readbytes=RAND_load_file(filename, options.random_bytes)))
        s_log(LOG_DEBUG, "Snagged %d random bytes from %s",
            readbytes, filename);
    else
        s_log(LOG_INFO, "Unable to retrieve any random data from %s",
            filename);
    /* Write new random data for future seeding if it's a regular file */
    if(options.option.rand_write && (sb.st_mode & S_IFREG)){
        writebytes=RAND_write_file(filename);
        if(writebytes==-1)
            s_log(LOG_WARNING, "Failed to write strong random data to %s - "
                "may be a permissions or seeding problem", filename);
        else
            s_log(LOG_DEBUG, "Wrote %d new random bytes to %s",
                writebytes, filename);
    }
    return readbytes;
}

#ifdef HAVE_OSSL_ENGINE_H

#define MAX_ENGINES 256
static ENGINE *engines[MAX_ENGINES]; /* table of engines */
static int current_engine=0;
static int engine_initialized;

void open_engine(const char *name) {
    s_log(LOG_DEBUG, "Enabling support for engine '%s'", name);
    if(!strcasecmp(name, "auto")) {
        ENGINE_register_all_complete();
        s_log(LOG_DEBUG, "Auto engine support enabled");
        return;
    }

    close_engine(); /* close the previous one (if specified) */
    engines[current_engine]=ENGINE_by_id(name);
    engine_initialized=0;
    if(!engines[current_engine]) {
        sslerror("ENGINE_by_id");
        die(1);
    }
}

void ctrl_engine(const char *cmd, const char *arg) {
    if(!strcasecmp(cmd, "INIT")) { /* special control command */
        init_engine();
        return;
    }
    if(arg)
        s_log(LOG_DEBUG, "Executing engine control command %s:%s", cmd, arg);
    else
        s_log(LOG_DEBUG, "Executing engine control command %s", cmd);
    if(!ENGINE_ctrl_cmd_string(engines[current_engine], cmd, arg, 0)) {
        sslerror("ENGINE_ctrl_cmd_string");
        die(1);
    }
}

void close_engine() {
    if(!engines[current_engine])
        return; /* no engine was opened -> nothing to do */
    init_engine();
    ++current_engine;
#if 0
    ENGINE_finish(e);
    ENGINE_free(e);
    e=NULL;
    s_log(LOG_DEBUG, "Engine closed");
#endif
}

static void init_engine() {
    if(engine_initialized)
        return;
    engine_initialized=1;
    s_log(LOG_DEBUG, "Initializing engine %d", current_engine+1);
    if(!ENGINE_init(engines[current_engine])) {
        if(ERR_peek_last_error()) /* really an error */
            sslerror("ENGINE_init");
        else
            s_log(LOG_ERR, "Engine %d not initialized", current_engine+1);
        die(1);
    }
    if(!ENGINE_set_default(engines[current_engine], ENGINE_METHOD_ALL)) {
        sslerror("ENGINE_set_default");
        die(1);
    }
    s_log(LOG_DEBUG, "Engine %d initialized", current_engine+1);
}

ENGINE *get_engine(int i) {
    if(i<1 || i>current_engine)
        return NULL;
    return engines[i-1];
}

#endif /* HAVE_OSSL_ENGINE_H */

/* End of ssl.c */
