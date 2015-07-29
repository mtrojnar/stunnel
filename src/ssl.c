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

    /* global OpenSSL initalization: compression, engine, entropy */
static int init_compression(void);
static int init_prng(void);
static int add_rand_file(char *);
#ifdef HAVE_OSSL_ENGINE_H
static char *init_engine(void);
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

int ssl_configure(void) { /* configure global SSL settings */
#ifdef USE_FIPS
    if(FIPS_mode()!=global_options.option.fips) {
        RAND_set_rand_method(NULL); /* reset RAND methods */
        if(!FIPS_mode_set(global_options.option.fips)) {
            ERR_load_crypto_strings();
            sslerror("FIPS_mode_set");
            return 0;
        }
        s_log(LOG_NOTICE, "FIPS mode %s",
            global_options.option.fips ? "enabled" : "disabled");
    }
#endif /* USE_FIPS */
    if(global_options.compression!=COMP_NONE && !init_compression())
        return 0;
    if(!init_prng())
        return 0;
    s_log(LOG_DEBUG, "PRNG seeded successfully");
    return 1; /* SUCCESS */
}

static int init_compression(void) {
    int id=0;
    COMP_METHOD *cm=NULL;
    char *name="unknown";

    switch(global_options.compression) {
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
        return 0;
    }
    if(!cm || cm->type==NID_undef) {
        s_log(LOG_ERR, "Failed to initialize %s compression method", name);
        return 0;
    }
    if(SSL_COMP_add_compression_method(id, cm)) {
        s_log(LOG_ERR, "Failed to add %s compression method", name);
        return 0;
    }
    s_log(LOG_INFO, "Compression enabled using %s method", name);
    return 1;
}

static int init_prng(void) {
    int totbytes=0;
    char filename[STRLEN];
    int bytes;

    bytes=0; /* avoid warning if #ifdef'd out for windows */

    filename[0]='\0';

    /* if they specify a rand file on the command line we
       assume that they really do want it, so try it first */
    if(global_options.rand_file) {
        totbytes+=add_rand_file(global_options.rand_file);
        if(RAND_status())
            return 1;
    }

    /* try the $RANDFILE or $HOME/.rnd files */
    RAND_file_name(filename, STRLEN);
    if(filename[0]) {
        filename[STRLEN-1]='\0';        /* just in case */
        totbytes+=add_rand_file(filename);
        if(RAND_status())
            return 1;
    }

#ifdef RANDOM_FILE
    totbytes+=add_rand_file(RANDOM_FILE);
    if(RAND_status())
        return 1;
#endif

#ifdef USE_WIN32
    RAND_screen();
    if(RAND_status()) {
        s_log(LOG_DEBUG, "Seeded PRNG with RAND_screen");
        return 1;
    }
    s_log(LOG_DEBUG, "RAND_screen failed to sufficiently seed PRNG");
#else
    if(global_options.egd_sock) {
        if((bytes=RAND_egd(global_options.egd_sock))==-1) {
            s_log(LOG_WARNING, "EGD Socket %s failed", global_options.egd_sock);
            bytes=0;
        } else {
            totbytes+=bytes;
            s_log(LOG_DEBUG, "Snagged %d random bytes from EGD Socket %s",
                bytes, global_options.egd_sock);
            return 1; /* OpenSSL always gets what it needs or fails,
                         so no need to check if seeded sufficiently */
        }
    }
#endif /* USE_WIN32 */

    /* try the good-old default /dev/urandom, if available  */
    totbytes+=add_rand_file("/dev/urandom");
    if(RAND_status())
        return 1;

    /* random file specified during configure */
    s_log(LOG_ERR, "PRNG seeded with %d bytes total", totbytes);
    s_log(LOG_ERR, "PRNG was not seeded with enough random bytes");
    return 0; /* FAILED */
}

static int add_rand_file(char *filename) {
    int readbytes;
    int writebytes;
    struct stat sb;

    if(stat(filename, &sb))
        return 0;
    if((readbytes=RAND_load_file(filename, global_options.random_bytes)))
        s_log(LOG_DEBUG, "Snagged %d random bytes from %s",
            readbytes, filename);
    else
        s_log(LOG_INFO, "Unable to retrieve any random data from %s",
            filename);
    /* write new random data for future seeding if it's a regular file */
    if(global_options.option.rand_write && (sb.st_mode & S_IFREG)){
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

char *open_engine(const char *name) {
    s_log(LOG_DEBUG, "Enabling support for engine '%s'", name);
    if(!strcasecmp(name, "auto")) {
        ENGINE_register_all_complete();
        s_log(LOG_DEBUG, "Auto engine support enabled");
        return NULL; /* OK */
    }

    close_engine(); /* close the previous one (if specified) */
    engines[current_engine]=ENGINE_by_id(name);
    engine_initialized=0;
    if(!engines[current_engine]) {
        sslerror("ENGINE_by_id");
        return "Failed to open the engine";
    }
    return NULL; /* OK */
}

char *ctrl_engine(const char *cmd, const char *arg) {
    if(!strcasecmp(cmd, "INIT")) { /* special control command */
        return init_engine();
    }
    if(arg)
        s_log(LOG_DEBUG, "Executing engine control command %s:%s", cmd, arg);
    else
        s_log(LOG_DEBUG, "Executing engine control command %s", cmd);
    if(!ENGINE_ctrl_cmd_string(engines[current_engine], cmd, arg, 0)) {
        sslerror("ENGINE_ctrl_cmd_string");
        return "Failed to execute the engine control command";
    }
    return NULL; /* OK */
}

void close_engine(void) {
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

static char *init_engine(void) {
    if(engine_initialized)
        return NULL; /* OK */
    engine_initialized=1;
    s_log(LOG_DEBUG, "Initializing engine %d", current_engine+1);
    if(!ENGINE_init(engines[current_engine])) {
        if(ERR_peek_last_error()) /* really an error */
            sslerror("ENGINE_init");
        else
            s_log(LOG_ERR, "Engine %d not initialized", current_engine+1);
        return "Engine initialization failed";
    }
    if(!ENGINE_set_default(engines[current_engine], ENGINE_METHOD_ALL)) {
        sslerror("ENGINE_set_default");
        return "Selecting default engine failed";
    }
    s_log(LOG_DEBUG, "Engine %d initialized", current_engine+1);
    return NULL; /* OK */
}

ENGINE *get_engine(int i) {
    if(i<1 || i>current_engine)
        return NULL;
    return engines[i-1];
}

#endif /* HAVE_OSSL_ENGINE_H */

/* end of ssl.c */
