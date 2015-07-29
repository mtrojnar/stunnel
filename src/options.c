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

#if defined(_WIN32_WCE) && !defined(CONFDIR)
#define CONFDIR "\\stunnel"
#endif

#ifdef USE_WIN32
#define CONFSEPARATOR "\\"
#else
#define CONFSEPARATOR "/"
#endif

#define CONFLINELEN (16*1024)

static void section_validate(char *, int, LOCAL_OPTIONS *, int);
static void config_error(char *, int, char *);
static char *stralloc(char *);
#ifndef USE_WIN32
static char **argalloc(char *);
#endif

static int parse_debug_level(char *);
static int parse_ssl_option(char *);
static int print_socket_options(void);
static void print_option(char *, int, OPT_UNION *);
static int parse_socket_option(char *);
static char *parse_ocsp_url(LOCAL_OPTIONS *, char *);
static unsigned long parse_ocsp_flag(char *);

GLOBAL_OPTIONS options;
LOCAL_OPTIONS local_options;

typedef enum {
    CMD_INIT, /* initialize */
    CMD_EXEC,
    CMD_DEFAULT,
    CMD_HELP
} CMD;

static char *option_not_found=
    "Specified option name is not valid here";

static char *global_options(CMD cmd, char *opt, char *arg) {
    char *tmpstr;
#ifndef USE_WIN32
    struct group *gr;
    struct passwd *pw;
#endif

    if(cmd==CMD_DEFAULT || cmd==CMD_HELP) {
        s_log(LOG_RAW, "Global options");
    }

    /* chroot */
#ifdef HAVE_CHROOT
    switch(cmd) {
    case CMD_INIT:
        options.chroot_dir=NULL;
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "chroot"))
            break;
        options.chroot_dir=stralloc(arg);
        return NULL; /* OK */
    case CMD_DEFAULT:
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = directory to chroot stunnel process", "chroot");
        break;
    }
#endif /* HAVE_CHROOT */

    /* compression */
    switch(cmd) {
    case CMD_INIT:
        options.compression=COMP_NONE;
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "compression"))
            break;
        if(!strcasecmp(arg, "zlib"))
            options.compression=COMP_ZLIB;
        else if(!strcasecmp(arg, "rle"))
            options.compression=COMP_RLE;
        else
            return "Compression type should be either 'zlib' or 'rle'";
        return NULL; /* OK */
    case CMD_DEFAULT:
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = zlib|rle compression type",
            "compression");
        break;
    }

    /* debug */
    switch(cmd) {
    case CMD_INIT:
        options.debug_level=5;
#if !defined (USE_WIN32) && !defined (__vms)
        options.facility=LOG_DAEMON;
#endif
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "debug"))
            break;
        if(!parse_debug_level(arg))
            return "Illegal debug argument";
        return NULL; /* OK */
    case CMD_DEFAULT:
        s_log(LOG_RAW, "%-15s = %d", "debug", options.debug_level);
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = [facility].level (e.g. daemon.info)", "debug");
        break;
    }

    /* EGD is only supported when compiled with OpenSSL 0.9.5a or later */
#if SSLEAY_VERSION_NUMBER >= 0x0090581fL
    switch(cmd) {
    case CMD_INIT:
        options.egd_sock=NULL;
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "EGD"))
            break;
        options.egd_sock=stralloc(arg);
        return NULL; /* OK */
    case CMD_DEFAULT:
#ifdef EGD_SOCKET
        s_log(LOG_RAW, "%-15s = %s", "EGD", EGD_SOCKET);
#endif
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = path to Entropy Gathering Daemon socket", "EGD");
        break;
    }
#endif /* OpenSSL 0.9.5a */

#ifdef HAVE_OSSL_ENGINE_H
    /* engine */
    switch(cmd) {
    case CMD_INIT:
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "engine"))
            break;
        open_engine(arg);
        return NULL; /* OK */
    case CMD_DEFAULT:
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = auto|engine_id",
            "engine");
        break;
    }

    /* engineCtrl */
    switch(cmd) {
    case CMD_INIT:
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "engineCtrl"))
            break;
        tmpstr=strchr(arg, ':');
        if(tmpstr)
            *tmpstr++='\0';
        ctrl_engine(arg, tmpstr);
        return NULL; /* OK */
    case CMD_DEFAULT:
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = cmd[:arg]",
            "engineCtrl");
        break;
    }
#endif

    /* fips */
#ifdef USE_FIPS
    switch(cmd) {
    case CMD_INIT:
        options.option.fips=1;
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "fips"))
            break;
        if(!strcasecmp(arg, "yes"))
            options.option.fips=1;
        else if(!strcasecmp(arg, "no"))
            options.option.fips=0;
        else
            return "Argument should be either 'yes' or 'no'";
        return NULL; /* OK */
    case CMD_DEFAULT:
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = yes|no FIPS 140-2 mode",
            "fips");
        break;
    }
#endif /* USE_FIPS */

    /* foreground */
#ifndef USE_WIN32
    switch(cmd) {
    case CMD_INIT:
        options.option.foreground=0;
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "foreground"))
            break;
        if(!strcasecmp(arg, "yes"))
            options.option.foreground=1;
        else if(!strcasecmp(arg, "no"))
            options.option.foreground=0;
        else
            return "Argument should be either 'yes' or 'no'";
        return NULL; /* OK */
    case CMD_DEFAULT:
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = yes|no foreground mode (don't fork, log to stderr)",
            "foreground");
        break;
    }
#endif

    /* output */
    switch(cmd) {
    case CMD_INIT:
        options.output_file=NULL;
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "output"))
            break;
        options.output_file=stralloc(arg);
        return NULL; /* OK */
    case CMD_DEFAULT:
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = file to append log messages", "output");
        break;
    }

    /* pid */
#ifndef USE_WIN32
    switch(cmd) {
    case CMD_INIT:
        options.pidfile=PIDFILE;
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "pid"))
            break;
        if(arg[0]) /* is argument not empty? */
            options.pidfile=stralloc(arg);
        else
            options.pidfile=NULL; /* empty -> do not create a pid file */
        return NULL; /* OK */
    case CMD_DEFAULT:
        s_log(LOG_RAW, "%-15s = %s", "pid", PIDFILE);
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = pid file (empty to disable creating)", "pid");
        break;
    }
#endif

    /* RNDbytes */
    switch(cmd) {
    case CMD_INIT:
        options.random_bytes=RANDOM_BYTES;
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "RNDbytes"))
            break;
        options.random_bytes=atoi(arg);
        return NULL; /* OK */
    case CMD_DEFAULT:
        s_log(LOG_RAW, "%-15s = %d", "RNDbytes", RANDOM_BYTES);
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = bytes to read from random seed files", "RNDbytes");
        break;
    }

    /* RNDfile */
    switch(cmd) {
    case CMD_INIT:
        options.rand_file=NULL;
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "RNDfile"))
            break;
        options.rand_file=stralloc(arg);
        return NULL; /* OK */
    case CMD_DEFAULT:
#ifdef RANDOM_FILE
        s_log(LOG_RAW, "%-15s = %s", "RNDfile", RANDOM_FILE);
#endif
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = path to file with random seed data", "RNDfile");
        break;
    }

    /* RNDoverwrite */
    switch(cmd) {
    case CMD_INIT:
        options.option.rand_write=1;
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "RNDoverwrite"))
            break;
        if(!strcasecmp(arg, "yes"))
            options.option.rand_write=1;
        else if(!strcasecmp(arg, "no"))
            options.option.rand_write=0;
        else
            return "Argument should be either 'yes' or 'no'";
        return NULL; /* OK */
    case CMD_DEFAULT:
        s_log(LOG_RAW, "%-15s = yes", "RNDoverwrite");
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = yes|no overwrite seed datafiles with new random data",
            "RNDoverwrite");
        break;
    }

    /* service */
    switch(cmd) {
    case CMD_INIT:
        local_options.servname=stralloc("stunnel");
#if defined(USE_WIN32) && !defined(_WIN32_WCE)
        options.win32_service="stunnel";
#endif
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "service"))
            break;
        local_options.servname=stralloc(arg);
#if defined(USE_WIN32) && !defined(_WIN32_WCE)
        options.win32_service=stralloc(arg);
#endif
        return NULL; /* OK */
    case CMD_DEFAULT:
#if defined(USE_WIN32) && !defined(_WIN32_WCE)
        s_log(LOG_RAW, "%-15s = %s", "service", options.win32_service);
#endif
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = service name", "service");
        break;
    }

#ifndef USE_WIN32
    /* setgid */
    switch(cmd) {
    case CMD_INIT:
        options.gid=0;
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "setgid"))
            break;
        gr=getgrnam(arg);
        if(gr)
            options.gid=gr->gr_gid;
        else if(atoi(arg)) /* numerical? */
            options.gid=atoi(arg);
        else
            return "Illegal GID";
        return NULL; /* OK */
    case CMD_DEFAULT:
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = groupname for setgid()", "setgid");
        break;
    }
#endif

#ifndef USE_WIN32
    /* setuid */
    switch(cmd) {
    case CMD_INIT:
        options.uid=0;
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "setuid"))
            break;
        pw=getpwnam(arg);
        if(pw)
            options.uid=pw->pw_uid;
        else if(atoi(arg)) /* numerical? */
            options.uid=atoi(arg);
        else
            return "Illegal UID";
        return NULL; /* OK */
    case CMD_DEFAULT:
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = username for setuid()", "setuid");
        break;
    }
#endif

    /* socket */
    switch(cmd) {
    case CMD_INIT:
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "socket"))
            break;
        if(!parse_socket_option(arg))
            return "Illegal socket option";
        return NULL; /* OK */
    case CMD_DEFAULT:
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = a|l|r:option=value[:value]", "socket");
        s_log(LOG_RAW, "%18sset an option on accept/local/remote socket", "");
        break;
    }

    /* syslog */
#ifndef USE_WIN32
    switch(cmd) {
    case CMD_INIT:
        options.option.syslog=1;
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "syslog"))
            break;
        if(!strcasecmp(arg, "yes"))
            options.option.syslog=1;
        else if(!strcasecmp(arg, "no"))
            options.option.syslog=0;
        else
            return "Argument should be either 'yes' or 'no'";
        return NULL; /* OK */
    case CMD_DEFAULT:
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = yes|no send logging messages to syslog",
            "syslog");
        break;
    }
#endif

    /* taskbar */
#ifdef USE_WIN32
    switch(cmd) {
    case CMD_INIT:
        options.option.taskbar=1;
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "taskbar"))
            break;
        if(!strcasecmp(arg, "yes"))
            options.option.taskbar=1;
        else if(!strcasecmp(arg, "no"))
            options.option.taskbar=0;
        else
            return "Argument should be either 'yes' or 'no'";
        return NULL; /* OK */
    case CMD_DEFAULT:
        s_log(LOG_RAW, "%-15s = yes", "taskbar");
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = yes|no enable the taskbar icon", "taskbar");
        break;
    }
#endif

    if(cmd==CMD_EXEC)
        return option_not_found;
    return NULL; /* OK */
}

static char *service_options(CMD cmd, LOCAL_OPTIONS *section,
        char *opt, char *arg) {
    int tmpnum;

    if(cmd==CMD_DEFAULT || cmd==CMD_HELP) {
        s_log(LOG_RAW, " ");
        s_log(LOG_RAW, "Service-level options");
    }

    /* accept */
    switch(cmd) {
    case CMD_INIT:
        section->option.accept=0;
        memset(&section->local_addr, 0, sizeof(SOCKADDR_LIST));
        section->local_addr.addr[0].in.sin_family=AF_INET;
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "accept"))
            break;
        section->option.accept=1;
        if(!name2addrlist(&section->local_addr, arg, DEFAULT_ANY))
            return "Failed to resolve accepting address";
        return NULL; /* OK */
    case CMD_DEFAULT:
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = [host:]port accept connections on specified host:port",
            "accept");
        break;
    }

    /* CApath */
    switch(cmd) {
    case CMD_INIT:
#if 0
        section->ca_dir=(char *)X509_get_default_cert_dir();
#endif
        section->ca_dir=NULL;
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "CApath"))
            break;
        if(arg[0]) /* not empty */
            section->ca_dir=stralloc(arg);
        else
            section->ca_dir=NULL;
        return NULL; /* OK */
    case CMD_DEFAULT:
#if 0
        s_log(LOG_RAW, "%-15s = %s", "CApath",
            section->ca_dir ? section->ca_dir : "(none)");
#endif
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = CA certificate directory for 'verify' option",
            "CApath");
        break;
    }

    /* CAfile */
    switch(cmd) {
    case CMD_INIT:
#if 0
        section->ca_file=(char *)X509_get_default_certfile();
#endif
        section->ca_file=NULL;
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "CAfile"))
            break;
        if(arg[0]) /* not empty */
            section->ca_file=stralloc(arg);
        else
            section->ca_file=NULL;
        return NULL; /* OK */
    case CMD_DEFAULT:
#if 0
        s_log(LOG_RAW, "%-15s = %s", "CAfile",
            section->ca_file ? section->ca_file : "(none)");
#endif
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = CA certificate file for 'verify' option",
            "CAfile");
        break;
    }

    /* cert */
    switch(cmd) {
    case CMD_INIT:
#ifdef CONFDIR
        section->cert=CONFDIR CONFSEPARATOR "stunnel.pem";
#else
        section->cert="stunnel.pem";
#endif
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "cert"))
            break;
        section->cert=stralloc(arg);
        section->option.cert=1;
        return NULL; /* OK */
    case CMD_DEFAULT:
        s_log(LOG_RAW, "%-15s = %s", "cert", section->cert);
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = certificate chain", "cert");
        break;
    }

    /* ciphers */
#ifdef USE_FIPS
#define STUNNEL_DEFAULT_CIPHER_LIST "FIPS"
#else
#define STUNNEL_DEFAULT_CIPHER_LIST SSL_DEFAULT_CIPHER_LIST
#endif /* USE_FIPS */
    switch(cmd) {
    case CMD_INIT:
        section->cipher_list=STUNNEL_DEFAULT_CIPHER_LIST;
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "ciphers"))
            break;
        section->cipher_list=stralloc(arg);
        return NULL; /* OK */
    case CMD_DEFAULT:
        s_log(LOG_RAW, "%-15s = %s", "ciphers", STUNNEL_DEFAULT_CIPHER_LIST);
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = list of permitted SSL ciphers", "ciphers");
        break;
    }

    /* client */
    switch(cmd) {
    case CMD_INIT:
        section->option.client=0;
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "client"))
            break;
        if(!strcasecmp(arg, "yes"))
            section->option.client=1;
        else if(!strcasecmp(arg, "no"))
            section->option.client=0;
        else
            return "Argument should be either 'yes' or 'no'";
        return NULL; /* OK */
    case CMD_DEFAULT:
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = yes|no client mode (remote service uses SSL)",
            "client");
        break;
    }

    /* connect */
    switch(cmd) {
    case CMD_INIT:
        section->option.remote=0;
        section->remote_address=NULL;
        section->remote_addr.num=0;
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "connect"))
            break;
        section->option.remote=1;
        section->remote_address=stralloc(arg);
        if(!section->option.delayed_lookup &&
                !name2addrlist(&section->remote_addr, arg, DEFAULT_LOOPBACK)) {
            s_log(LOG_RAW, "Cannot resolve '%s' - delaying DNS lookup", arg);
            section->option.delayed_lookup=1;
        }
        return NULL; /* OK */
    case CMD_DEFAULT:
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = [host:]port connect remote host:port",
            "connect");
        break;
    }

    /* CRLpath */
    switch(cmd) {
    case CMD_INIT:
        section->crl_dir=NULL;
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "CRLpath"))
            break;
        if(arg[0]) /* not empty */
            section->crl_dir=stralloc(arg);
        else
            section->crl_dir=NULL;
        return NULL; /* OK */
    case CMD_DEFAULT:
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = CRL directory", "CRLpath");
        break;
    }

    /* CRLfile */
    switch(cmd) {
    case CMD_INIT:
        section->crl_file=NULL;
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "CRLfile"))
            break;
        if(arg[0]) /* not empty */
            section->crl_file=stralloc(arg);
        else
            section->crl_file=NULL;
        return NULL; /* OK */
    case CMD_DEFAULT:
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = CRL file", "CRLfile");
        break;
    }

    /* delay */
    switch(cmd) {
    case CMD_INIT:
        section->option.delayed_lookup=0;
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "delay"))
            break;
        if(!strcasecmp(arg, "yes"))
            section->option.delayed_lookup=1;
        else if(!strcasecmp(arg, "no"))
            section->option.delayed_lookup=0;
        else
            return "Argument should be either 'yes' or 'no'";
        return NULL; /* OK */
    case CMD_DEFAULT:
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = yes|no delay DNS lookup for 'connect' option",
            "delay");
        break;
    }

#ifdef HAVE_OSSL_ENGINE_H
    /* engineNum */
    switch(cmd) {
    case CMD_INIT:
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "engineNum"))
            break;
        section->engine=get_engine(atoi(arg));
        if(!section->engine)
            return "Illegal engine number";
        return NULL; /* OK */
    case CMD_DEFAULT:
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = number of engine to read the key from",
            "engineNum");
        break;
    }
#endif

    /* exec */
#ifndef USE_WIN32
    switch(cmd) {
    case CMD_INIT:
        section->option.program=0;
        section->execname=NULL;
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "exec"))
            break;
        section->option.program=1;
        section->execname=stralloc(arg);
        if(!section->execargs) {
            section->execargs=calloc(2, sizeof(char *));
            section->execargs[0]=section->execname;
            section->execargs[1]=NULL; /* to show that it's null-terminated */
        }
        return NULL; /* OK */
    case CMD_DEFAULT:
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = file execute local inetd-type program",
            "exec");
        break;
    }
#endif

    /* execargs */
#ifndef USE_WIN32
    switch(cmd) {
    case CMD_INIT:
        section->execargs=NULL;
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "execargs"))
            break;
        section->execargs=argalloc(arg);
        return NULL; /* OK */
    case CMD_DEFAULT:
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = arguments for 'exec' (including $0)",
            "execargs");
        break;
    }
#endif

    /* failover */
    switch(cmd) {
    case CMD_INIT:
        section->failover=FAILOVER_RR;
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "failover"))
            break;
        if(!strcasecmp(arg, "rr"))
            section->failover=FAILOVER_RR;
        else if(!strcasecmp(arg, "prio"))
            section->failover=FAILOVER_PRIO;
        else
            return "Argument should be either 'rr' or 'prio'";
        return NULL; /* OK */
    case CMD_DEFAULT:
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = rr|prio chose failover strategy",
            "failover");
        break;
    }

    /* ident */
    switch(cmd) {
    case CMD_INIT:
        section->username=NULL;
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "ident"))
            break;
        section->username=stralloc(arg);
        return NULL; /* OK */
    case CMD_DEFAULT:
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = username for IDENT (RFC 1413) checking", "ident");
        break;
    }

    /* key */
    switch(cmd) {
    case CMD_INIT:
        section->key=NULL;
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "key"))
            break;
        section->key=stralloc(arg);
        return NULL; /* OK */
    case CMD_DEFAULT:
        s_log(LOG_RAW, "%-15s = %s", "key", section->cert); /* set in stunnel.c */
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = certificate private key", "key");
        break;
    }

    /* local */
    switch(cmd) {
    case CMD_INIT:
        memset(&section->source_addr, 0, sizeof(SOCKADDR_LIST));
        section->source_addr.addr[0].in.sin_family=AF_INET;
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "local"))
            break;
        if(!hostport2addrlist(&section->source_addr, arg, "0"))
            return "Failed to resolve local address";
        return NULL; /* OK */
    case CMD_DEFAULT:
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = IP address to be used as source for remote"
            " connections", "local");
        break;
    }

#if SSLEAY_VERSION_NUMBER >= 0x00907000L
    /* OCSP */
    switch(cmd) {
    case CMD_INIT:
        section->option.ocsp=0;
        memset(&section->ocsp_addr, 0, sizeof(SOCKADDR_LIST));
        section->ocsp_addr.addr[0].in.sin_family=AF_INET;
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "ocsp"))
            break;
        section->option.ocsp=1;
        return parse_ocsp_url(section, arg);
    case CMD_DEFAULT:
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = OCSP server URL", "ocsp");
        break;
    }

    /* OCSPflag */
    switch(cmd) {
    case CMD_INIT:
        section->ocsp_flags=0;
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "OCSPflag"))
            break;
        tmpnum=parse_ocsp_flag(arg);
        if(!tmpnum)
            return "Illegal OCSP flag";
        section->ocsp_flags|=tmpnum;
        return NULL;
    case CMD_DEFAULT:
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = OCSP server flags", "OCSPflag");
        break;
    }
#endif /* OpenSSL-0.9.7 */

    /* options */
    switch(cmd) {
    case CMD_INIT:
        section->ssl_options=0;
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "options"))
            break;
        tmpnum=parse_ssl_option(arg);
        if(!tmpnum)
            return "Illegal SSL option";
        section->ssl_options|=tmpnum;
        return NULL; /* OK */
    case CMD_DEFAULT:
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = SSL option", "options");
        s_log(LOG_RAW, "%18sset an SSL option", "");
        break;
    }

    /* protocol */
    switch(cmd) {
    case CMD_INIT:
        section->protocol=NULL;
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "protocol"))
            break;
        section->protocol=stralloc(arg);
        return NULL; /* OK */
    case CMD_DEFAULT:
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = protocol to negotiate before SSL initialization",
            "protocol");
        s_log(LOG_RAW, "%18scurrently supported: cifs, connect, nntp, pop3, smtp", "");
        break;
    }

    /* protocolAuthentication */
    switch(cmd) {
    case CMD_INIT:
        section->protocol_authentication="basic";
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "protocolAuthentication"))
            break;
        section->protocol_authentication=stralloc(arg);
        return NULL; /* OK */
    case CMD_DEFAULT:
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = authentication type for protocol negotiations",
            "protocolAuthentication");
        break;
    }

    /* protocolHost */
    switch(cmd) {
    case CMD_INIT:
        section->protocol_host=NULL;
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "protocolHost"))
            break;
        section->protocol_host=stralloc(arg);
        return NULL; /* OK */
    case CMD_DEFAULT:
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = host:port for protocol negotiations",
            "protocolHost");
        break;
    }

    /* protocolPassword */
    switch(cmd) {
    case CMD_INIT:
        section->protocol_password=NULL;
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "protocolPassword"))
            break;
        section->protocol_password=stralloc(arg);
        return NULL; /* OK */
    case CMD_DEFAULT:
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = password for protocol negotiations",
            "protocolPassword");
        break;
    }

    /* protocolUsername */
    switch(cmd) {
    case CMD_INIT:
        section->protocol_username=NULL;
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "protocolUsername"))
            break;
        section->protocol_username=stralloc(arg);
        return NULL; /* OK */
    case CMD_DEFAULT:
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = username for protocol negotiations",
            "protocolUsername");
        break;
    }

    /* pty */
#ifndef USE_WIN32
    switch(cmd) {
    case CMD_INIT:
        section->option.pty=0;
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "pty"))
            break;
        if(!strcasecmp(arg, "yes"))
            section->option.pty=1;
        else if(!strcasecmp(arg, "no"))
            section->option.pty=0;
        else
            return "Argument should be either 'yes' or 'no'";
        return NULL; /* OK */
    case CMD_DEFAULT:
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = yes|no allocate pseudo terminal for 'exec' option",
            "pty");
        break;
    }
#endif

    /* retry */
#ifndef USE_WIN32
    switch(cmd) {
    case CMD_INIT:
        section->option.retry=0;
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "retry"))
            break;
        if(!strcasecmp(arg, "yes"))
            section->option.retry=1;
        else if(!strcasecmp(arg, "no"))
            section->option.retry=0;
        else
            return "Argument should be either 'yes' or 'no'";
        return NULL; /* OK */
    case CMD_DEFAULT:
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = yes|no retry connect+exec section",
            "retry");
        break;
    }
#endif

    /* session */
    switch(cmd) {
    case CMD_INIT:
        section->session_timeout=300;
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "session"))
            break;
        if(atoi(arg)>0)
            section->session_timeout=atoi(arg);
        else
            return "Illegal session timeout";
        return NULL; /* OK */
    case CMD_DEFAULT:
        s_log(LOG_RAW, "%-15s = %ld seconds", "session", section->session_timeout);
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = session cache timeout (in seconds)", "session");
        break;
    }

    /* sessiond */
    switch(cmd) {
    case CMD_INIT:
        section->option.sessiond=0;
        memset(&section->sessiond_addr, 0, sizeof(SOCKADDR_LIST));
        section->sessiond_addr.addr[0].in.sin_family=AF_INET;
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "sessiond"))
            break;
        section->option.sessiond=1;
#ifdef SSL_OP_NO_TICKET
        /* disable RFC4507 support introduced in OpenSSL 0.9.8f */
        /* this prevents session callbacks from beeing executed */
        section->ssl_options|=SSL_OP_NO_TICKET;
#endif
        if(!name2addrlist(&section->sessiond_addr, arg, DEFAULT_LOOPBACK))
            return "Failed to resolve sessiond server address";
        return NULL; /* OK */
    case CMD_DEFAULT:
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = [host:]port use sessiond at host:port",
            "sessiond");
        break;
    }

#ifndef USE_FORK
    /* stack */
    switch(cmd) {
    case CMD_INIT:
        section->stack_size=DEFAULT_STACK_SIZE;
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "stack"))
            break;
        if(atoi(arg)>0)
            section->stack_size=atoi(arg);
        else
            return "Illegal thread stack size";
        return NULL; /* OK */
    case CMD_DEFAULT:
        s_log(LOG_RAW, "%-15s = %d bytes", "stack", section->stack_size);
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = thread stack size (in bytes)", "stack");
        break;
    }
#endif

    /* sslVersion */
    switch(cmd) {
    case CMD_INIT:
#ifdef USE_FIPS
        section->client_method=(SSL_METHOD *)TLSv1_client_method();
        section->server_method=(SSL_METHOD *)TLSv1_server_method();
#else
        section->client_method=(SSL_METHOD *)SSLv3_client_method();
        section->server_method=(SSL_METHOD *)SSLv23_server_method();
#endif
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "sslVersion"))
            break;
        if(!strcasecmp(arg, "all")) {
            section->client_method=(SSL_METHOD *)SSLv23_client_method();
            section->server_method=(SSL_METHOD *)SSLv23_server_method();
        } else if(!strcasecmp(arg, "SSLv2")) {
            section->client_method=(SSL_METHOD *)SSLv2_client_method();
            section->server_method=(SSL_METHOD *)SSLv2_server_method();
        } else if(!strcasecmp(arg, "SSLv3")) {
            section->client_method=(SSL_METHOD *)SSLv3_client_method();
            section->server_method=(SSL_METHOD *)SSLv3_server_method();
        } else if(!strcasecmp(arg, "TLSv1")) {
            section->client_method=(SSL_METHOD *)TLSv1_client_method();
            section->server_method=(SSL_METHOD *)TLSv1_server_method();
        } else
            return "Incorrect version of SSL protocol";
        return NULL; /* OK */
    case CMD_DEFAULT:
#ifdef USE_FIPS
        s_log(LOG_RAW, "%-15s = TLSv1", "sslVersion");
#else
        s_log(LOG_RAW, "%-15s = SSLv3 for client, all for server", "sslVersion");
#endif
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = all|SSLv2|SSLv3|TLSv1 SSL method", "sslVersion");
        break;
    }

    /* TIMEOUTbusy */
    switch(cmd) {
    case CMD_INIT:
        section->timeout_busy=300; /* 5 minutes */
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "TIMEOUTbusy"))
            break;
        if(atoi(arg)>0)
            section->timeout_busy=atoi(arg);
        else
            return "Illegal busy timeout";
        return NULL; /* OK */
    case CMD_DEFAULT:
        s_log(LOG_RAW, "%-15s = %d seconds", "TIMEOUTbusy", section->timeout_busy);
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = seconds to wait for expected data", "TIMEOUTbusy");
        break;
    }

    /* TIMEOUTclose */
    switch(cmd) {
    case CMD_INIT:
        section->timeout_close=60; /* 1 minute */
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "TIMEOUTclose"))
            break;
        if(atoi(arg)>0 || !strcmp(arg, "0"))
            section->timeout_close=atoi(arg);
        else
            return "Illegal close timeout";
        return NULL; /* OK */
    case CMD_DEFAULT:
        s_log(LOG_RAW, "%-15s = %d seconds", "TIMEOUTclose", section->timeout_close);
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = seconds to wait for close_notify"
            " (set to 0 for buggy MSIE)", "TIMEOUTclose");
        break;
    }

    /* TIMEOUTconnect */
    switch(cmd) {
    case CMD_INIT:
        section->timeout_connect=10; /* 10 seconds */
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "TIMEOUTconnect"))
            break;
        if(atoi(arg)>0 || !strcmp(arg, "0"))
            section->timeout_connect=atoi(arg);
        else
            return "Illegal connect timeout";
        return NULL; /* OK */
    case CMD_DEFAULT:
        s_log(LOG_RAW, "%-15s = %d seconds", "TIMEOUTconnect",
            section->timeout_connect);
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = seconds to connect remote host", "TIMEOUTconnect");
        break;
    }

    /* TIMEOUTidle */
    switch(cmd) {
    case CMD_INIT:
        section->timeout_idle=43200; /* 12 hours */
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "TIMEOUTidle"))
            break;
        if(atoi(arg)>0)
            section->timeout_idle=atoi(arg);
        else
            return "Illegal idle timeout";
        return NULL; /* OK */
    case CMD_DEFAULT:
        s_log(LOG_RAW, "%-15s = %d seconds", "TIMEOUTidle", section->timeout_idle);
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = seconds to keep an idle connection", "TIMEOUTidle");
        break;
    }

    /* transparent */
#ifndef USE_WIN32
    switch(cmd) {
    case CMD_INIT:
        section->option.transparent=0;
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "transparent"))
            break;
        if(!strcasecmp(arg, "yes"))
            section->option.transparent=1;
        else if(!strcasecmp(arg, "no"))
            section->option.transparent=0;
        else
            return "Argument should be either 'yes' or 'no'";
        return NULL; /* OK */
    case CMD_DEFAULT:
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = yes|no transparent proxy mode",
            "transparent");
        break;
    }
#endif

    /* verify */
    switch(cmd) {
    case CMD_INIT:
        section->verify_level=-1;
        section->verify_use_only_my=0;
        break;
    case CMD_EXEC:
        if(strcasecmp(opt, "verify"))
            break;
        section->verify_level=SSL_VERIFY_NONE;
        switch(atoi(arg)) {
        case 3:
            section->verify_use_only_my=1;
        case 2:
            section->verify_level|=SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
        case 1:
            section->verify_level|=SSL_VERIFY_PEER;
        case 0:
            return NULL; /* OK */
        default:
            return "Bad verify level";
        }
    case CMD_DEFAULT:
        s_log(LOG_RAW, "%-15s = none", "verify");
        break;
    case CMD_HELP:
        s_log(LOG_RAW, "%-15s = level of peer certificate verification", "verify");
        s_log(LOG_RAW, "%18slevel 1 - verify peer certificate if present", "");
        s_log(LOG_RAW, "%18slevel 2 - require valid peer certificate always", "");
        s_log(LOG_RAW, "%18slevel 3 - verify peer with locally installed certificate",
        "");
        break;
    }

    if(cmd==CMD_EXEC)
        return option_not_found;
    return NULL; /* OK */
}

static void syntax(char *confname) {
    s_log(LOG_RAW, " ");
    s_log(LOG_RAW, "Syntax:");
    s_log(LOG_RAW, "stunnel "
#ifdef USE_WIN32
#ifndef _WIN32_WCE
        "[ [-install | -uninstall] "
#endif
        "[-quiet] "
#endif
        "[<filename>] ] "
#ifndef USE_WIN32
        "-fd <n> "
#endif
        "| -help | -version | -sockets");
    s_log(LOG_RAW, "    <filename>  - use specified config file instead of %s",
        confname);
#ifdef USE_WIN32
#ifndef _WIN32_WCE
    s_log(LOG_RAW, "    -install    - install NT service");
    s_log(LOG_RAW, "    -uninstall  - uninstall NT service");
#endif
    s_log(LOG_RAW, "    -quiet      - don't display a message box on success");
#else
    s_log(LOG_RAW, "    -fd <n>     - read the config file from a file descriptor");
#endif
    s_log(LOG_RAW, "    -help       - get config file help");
    s_log(LOG_RAW, "    -version    - display version and defaults");
    s_log(LOG_RAW, "    -sockets    - display default socket options");
    die(1);
}

void parse_config(char *name, char *parameter) {
#ifdef CONFDIR
    char *default_config_file=CONFDIR CONFSEPARATOR "stunnel.conf";
#else
    char *default_config_file="stunnel.conf";
#endif
    DISK_FILE *df;
    char confline[CONFLINELEN], *arg, *opt, *errstr, *filename;
    int line_number, i;
#ifdef MAX_FD
    int sections=0;
#endif
    LOCAL_OPTIONS *section, *new_section;

    memset(&options, 0, sizeof(GLOBAL_OPTIONS)); /* reset global options */

    memset(&local_options, 0, sizeof(LOCAL_OPTIONS)); /* reset local options */
    local_options.next=NULL;
    section=&local_options;

    global_options(CMD_INIT, NULL, NULL);
    service_options(CMD_INIT, section, NULL, NULL);
    if(!name)
        name=default_config_file;
    if(!strcasecmp(name, "-help")) {
        global_options(CMD_HELP, NULL, NULL);
        service_options(CMD_HELP, section, NULL, NULL);
        die(1);
    }
    if(!strcasecmp(name, "-version")) {
        stunnel_info(1);
        s_log(LOG_RAW, " ");
        global_options(CMD_DEFAULT, NULL, NULL);
        service_options(CMD_DEFAULT, section, NULL, NULL);
        die(1);
    }
    if(!strcasecmp(name, "-sockets")) {
        print_socket_options();
        die(1);
    }
#ifndef USE_WIN32
    if(!strcasecmp(name, "-fd")) {
        if(!parameter) {
            s_log(LOG_RAW, "No file descriptor specified");
            syntax(default_config_file);
        }
        for(arg=parameter, i=0; *arg; ++arg) {
            if(*arg<'0' || *arg>'9') {
                s_log(LOG_RAW, "Invalid file descriptor %s", parameter);
                syntax(default_config_file);
            }
            i=10*i+*arg-'0';
        }
        df=file_fdopen(i);
        if(!df) {
            s_log(LOG_RAW, "Invalid file descriptor %s", parameter);
            syntax(default_config_file);
        }
        filename="descriptor";
    } else
#endif
    {
        df=file_open(name, 0);
        if(!df)
            syntax(default_config_file);
        filename=name;
    }
    line_number=0;
    while(file_getline(df, confline, CONFLINELEN)) {
        ++line_number;
        opt=confline;
        while(isspace((unsigned char)*opt))
            ++opt; /* remove initial whitespaces */
        for(i=strlen(opt)-1; i>=0 && isspace((unsigned char)opt[i]); --i)
            opt[i]='\0'; /* remove trailing whitespaces */
        if(opt[0]=='\0' || opt[0]=='#' || opt[0]==';') /* empty or comment */
            continue;
        if(opt[0]=='[' && opt[strlen(opt)-1]==']') { /* new section */
            section_validate(filename, line_number, section, 0);
            ++opt;
            opt[strlen(opt)-1]='\0';
            new_section=calloc(1, sizeof(LOCAL_OPTIONS));
            if(!new_section) {
                s_log(LOG_RAW, "Fatal memory allocation error");
                die(2);
            }
            memcpy(new_section, &local_options, sizeof(LOCAL_OPTIONS));
            new_section->servname=stralloc(opt);
            new_section->session=NULL;
            new_section->next=NULL;
            section->next=new_section;
            section=new_section;
#ifdef MAX_FD
            if(++sections>MAX_FD)
                config_error(filename, line_number, "Too many sections");
#endif
            continue;
        }
        arg=strchr(confline, '=');
        if(!arg)
            config_error(filename, line_number, "No '=' found");
        *arg++='\0'; /* split into option name and argument value */
        for(i=strlen(opt)-1; i>=0 && isspace((unsigned char)opt[i]); --i)
            opt[i]='\0'; /* remove trailing whitespaces */
        while(isspace((unsigned char)*arg))
            ++arg; /* remove initial whitespaces */
        errstr=service_options(CMD_EXEC, section, opt, arg);
        if(section==&local_options && errstr==option_not_found)
            errstr=global_options(CMD_EXEC, opt, arg);
        config_error(filename, line_number, errstr);
    }
    section_validate(filename, line_number, section, 1);
    file_close(df);
    if(!local_options.next) { /* inetd mode */
        if (section->option.accept) {
            s_log(LOG_RAW, "accept option is not allowed in inetd mode");
            s_log(LOG_RAW, "remove accept option or define a [section]");
            die(1);
        }
        if (!section->option.remote && !section->execname) {
            s_log(LOG_RAW, "inetd mode must define a remote host or an executable");
            die(1);
        }
    }
}

static void section_validate(char *filename, int line_number,
        LOCAL_OPTIONS *section, int final) {
    if(section==&local_options) { /* global options just configured */
#ifdef HAVE_OSSL_ENGINE_H
        close_engine();
#endif
        ssl_configure(); /* configure global SSL settings */
        if(!final) /* no need to validate defaults */
            return;
    }
    if(!section->option.client)
        section->option.cert=1; /* Server always needs a certificate */
    context_init(section); /* initialize SSL context */

    if(section==&local_options) { /* inetd mode */
        if(section->option.accept)
            config_error(filename, line_number,
                "accept is not allowed in inetd mode");
        /* TODO: some additional checks could be useful
        if((unsigned int)section->option.program +
                (unsigned int)section->option.remote != 1)
            config_error(filename, line_number,
                "Single endpoint is required in inetd mode");
        */
        return;
    }

    /* standalone mode */
#ifdef USE_WIN32
    if(!section->option.accept || !section->option.remote)
#else
    if((unsigned int)section->option.accept +
            (unsigned int)section->option.program +
            (unsigned int)section->option.remote != 2)
#endif
        config_error(filename, line_number,
            "Each service section must define exactly two endpoints");
    return; /* All tests passed -- continue program execution */
}

static void config_error(char *name, int num, char *str) {
    if(!str) /* NULL -> no error */
        return;
    s_log(LOG_RAW, "file %s line %d: %s", name, num, str);
    die(1);
}

static char *stralloc(char *str) { /* Allocate static string */
    char *retval;

    retval=calloc(strlen(str)+1, 1);
    if(!retval) {
        s_log(LOG_RAW, "Fatal memory allocation error");
        die(2);
    }
    strcpy(retval, str);
    return retval;
}

#ifndef USE_WIN32
static char **argalloc(char *str) { /* Allocate 'exec' argumets */
    int max_arg, i;
    char *ptr, **retval;

    max_arg=strlen(str)/2+1;
    ptr=stralloc(str);
    retval=calloc(max_arg+1, sizeof(char *));
    if(!retval) {
        s_log(LOG_RAW, "Fatal memory allocation error");
        die(2);
    }
    i=0;
    while(*ptr && i<max_arg) {
        retval[i++]=ptr;
        while(*ptr && !isspace((unsigned char)*ptr))
            ++ptr;
        while(*ptr && isspace((unsigned char)*ptr))
            *ptr++='\0';
    }
    retval[i]=NULL; /* to show that it's null-terminated */
    return retval;
}
#endif

/* Parse out the facility/debug level stuff */

typedef struct {
    char *name;
    int value;
} facilitylevel;

static int parse_debug_level(char *arg) {
    char arg_copy[STRLEN];
    char *string;
    facilitylevel *fl;

/* Facilities only make sense on unix */
#if !defined (USE_WIN32) && !defined (__vms)
    facilitylevel facilities[] = {
        {"auth", LOG_AUTH},     {"cron", LOG_CRON},     {"daemon", LOG_DAEMON},
        {"kern", LOG_KERN},     {"lpr", LOG_LPR},       {"mail", LOG_MAIL},
        {"news", LOG_NEWS},     {"syslog", LOG_SYSLOG}, {"user", LOG_USER},
        {"uucp", LOG_UUCP},     {"local0", LOG_LOCAL0}, {"local1", LOG_LOCAL1},
        {"local2", LOG_LOCAL2}, {"local3", LOG_LOCAL3}, {"local4", LOG_LOCAL4},
        {"local5", LOG_LOCAL5}, {"local6", LOG_LOCAL6}, {"local7", LOG_LOCAL7},

        /* Some that are not on all unicies */
#ifdef LOG_AUTHPRIV
        {"authpriv", LOG_AUTHPRIV},
#endif
#ifdef LOG_FTP
        {"ftp", LOG_FTP},
#endif
#ifdef LOG_NTP
        {"ntp", LOG_NTP},
#endif
        {NULL, 0}
    };
#endif /* USE_WIN32, __vms */

    facilitylevel levels[] = {
        {"emerg", LOG_EMERG},     {"alert", LOG_ALERT},
        {"crit", LOG_CRIT},       {"err", LOG_ERR},
        {"warning", LOG_WARNING}, {"notice", LOG_NOTICE},
        {"info", LOG_INFO},       {"debug", LOG_DEBUG},
        {NULL, -1}
    };

    safecopy(arg_copy, arg);
    string = arg_copy;

/* Facilities only make sense on Unix */
#if !defined (USE_WIN32) && !defined (__vms)
    if(strchr(string, '.')) { /* We have a facility specified */
        options.facility=-1;
        string=strtok(arg_copy, "."); /* break it up */

        for(fl=facilities; fl->name; ++fl) {
            if(!strcasecmp(fl->name, string)) {
                options.facility = fl->value;
                break;
            }
        }
        if(options.facility==-1)
            return 0; /* FAILED */
        string=strtok(NULL, ".");    /* set to the remainder */
    }
#endif /* USE_WIN32, __vms */

    /* Time to check the syslog level */
    if(string && strlen(string)==1 && *string>='0' && *string<='7') {
        options.debug_level=*string-'0';
        return 1; /* OK */
    }
    options.debug_level=8;    /* illegal level */
    for(fl=levels; fl->name; ++fl) {
        if(!strcasecmp(fl->name, string)) {
            options.debug_level=fl->value;
            break;
        }
    }
    if (options.debug_level==8)
        return 0; /* FAILED */
    return 1; /* OK */
}

/* Parse out SSL options stuff */

static int parse_ssl_option(char *arg) {
    struct {
        char *name;
        long value;
    } ssl_opts[] = {
        {"MICROSOFT_SESS_ID_BUG", SSL_OP_MICROSOFT_SESS_ID_BUG},
        {"NETSCAPE_CHALLENGE_BUG", SSL_OP_NETSCAPE_CHALLENGE_BUG},
        {"NETSCAPE_REUSE_CIPHER_CHANGE_BUG",
            SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG},
        {"SSLREF2_REUSE_CERT_TYPE_BUG", SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG},
        {"MICROSOFT_BIG_SSLV3_BUFFER", SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER},
        {"MSIE_SSLV2_RSA_PADDING", SSL_OP_MSIE_SSLV2_RSA_PADDING},
        {"SSLEAY_080_CLIENT_DH_BUG", SSL_OP_SSLEAY_080_CLIENT_DH_BUG},
        {"TLS_D5_BUG", SSL_OP_TLS_D5_BUG},
        {"TLS_BLOCK_PADDING_BUG", SSL_OP_TLS_BLOCK_PADDING_BUG},
        {"DONT_INSERT_EMPTY_FRAGMENTS", SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS},
#ifdef SSL_OP_NO_QUERY_MTU
        {"NO_QUERY_MTU", SSL_OP_NO_QUERY_MTU},
#endif
#ifdef SSL_OP_COOKIE_EXCHANGE
        {"COOKIE_EXCHANGE", SSL_OP_COOKIE_EXCHANGE},
#endif
#ifdef SSL_OP_NO_TICKET
        {"NO_TICKET", SSL_OP_NO_TICKET},
#endif
        {"NO_SESSION_RESUMPTION_ON_RENEGOTIATION",
            SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION},
#ifdef SSL_OP_NO_COMPRESSION
        {"NO_COMPRESSION", SSL_OP_NO_COMPRESSION},
#endif
#ifdef SSL_OP_SINGLE_ECDH_USE
        {"SINGLE_ECDH_USE", SSL_OP_SINGLE_ECDH_USE},
#endif
        {"SINGLE_DH_USE", SSL_OP_SINGLE_DH_USE},
        {"EPHEMERAL_RSA", SSL_OP_EPHEMERAL_RSA},
        {"CIPHER_SERVER_PREFERENCE", SSL_OP_CIPHER_SERVER_PREFERENCE},
        {"TLS_ROLLBACK_BUG", SSL_OP_TLS_ROLLBACK_BUG},
        {"NO_SSLv2", SSL_OP_NO_SSLv2},
        {"NO_SSLv3", SSL_OP_NO_SSLv3},
        {"NO_TLSv1", SSL_OP_NO_TLSv1},
        {"PKCS1_CHECK_1", SSL_OP_PKCS1_CHECK_1},
        {"PKCS1_CHECK_2", SSL_OP_PKCS1_CHECK_2},
        {"NETSCAPE_CA_DN_BUG", SSL_OP_NETSCAPE_CA_DN_BUG},
        {"NETSCAPE_DEMO_CIPHER_CHANGE_BUG",
            SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG},
#ifdef SSL_OP_CRYPTOPRO_TLSEXT_BUG
        {"CRYPTOPRO_TLSEXT_BUG", SSL_OP_CRYPTOPRO_TLSEXT_BUG},
#endif
        {"ALL", SSL_OP_ALL},
        {NULL, 0}
    }, *option;

    for(option=ssl_opts; option->name; ++option)
        if(!strcasecmp(option->name, arg))
            return option->value;
    return 0; /* FAILED */
}

/* Parse out the socket options stuff */

static int on=1;

#define DEF_VALS {NULL, NULL, NULL}
#define DEF_ACCEPT {(void *)&on, NULL, NULL}

SOCK_OPT sock_opts[] = {
    {"SO_DEBUG",        SOL_SOCKET,  SO_DEBUG,        TYPE_FLAG,    DEF_VALS},
    {"SO_DONTROUTE",    SOL_SOCKET,  SO_DONTROUTE,    TYPE_FLAG,    DEF_VALS},
    {"SO_KEEPALIVE",    SOL_SOCKET,  SO_KEEPALIVE,    TYPE_FLAG,    DEF_VALS},
    {"SO_LINGER",       SOL_SOCKET,  SO_LINGER,       TYPE_LINGER,  DEF_VALS},
    {"SO_OOBINLINE",    SOL_SOCKET,  SO_OOBINLINE,    TYPE_FLAG,    DEF_VALS},
    {"SO_RCVBUF",       SOL_SOCKET,  SO_RCVBUF,       TYPE_INT,     DEF_VALS},
    {"SO_SNDBUF",       SOL_SOCKET,  SO_SNDBUF,       TYPE_INT,     DEF_VALS},
#ifdef SO_RCVLOWAT
    {"SO_RCVLOWAT",     SOL_SOCKET,  SO_RCVLOWAT,     TYPE_INT,     DEF_VALS},
#endif
#ifdef SO_SNDLOWAT
    {"SO_SNDLOWAT",     SOL_SOCKET,  SO_SNDLOWAT,     TYPE_INT,     DEF_VALS},
#endif
#ifdef SO_RCVTIMEO
    {"SO_RCVTIMEO",     SOL_SOCKET,  SO_RCVTIMEO,     TYPE_TIMEVAL, DEF_VALS},
#endif
#ifdef SO_SNDTIMEO
    {"SO_SNDTIMEO",     SOL_SOCKET,  SO_SNDTIMEO,     TYPE_TIMEVAL, DEF_VALS},
#endif
    {"SO_REUSEADDR",    SOL_SOCKET,  SO_REUSEADDR,    TYPE_FLAG,    DEF_ACCEPT},
#ifdef SO_BINDTODEVICE
    {"SO_BINDTODEVICE", SOL_SOCKET,  SO_BINDTODEVICE, TYPE_STRING,  DEF_VALS},
#endif
#ifdef TCP_KEEPCNT
    {"TCP_KEEPCNT",     SOL_TCP,     TCP_KEEPCNT,     TYPE_INT,     DEF_VALS},
#endif
#ifdef TCP_KEEPIDLE
    {"TCP_KEEPIDLE",    SOL_TCP,     TCP_KEEPIDLE,    TYPE_INT,     DEF_VALS},
#endif
#ifdef TCP_KEEPINTVL
    {"TCP_KEEPINTVL",   SOL_TCP,     TCP_KEEPINTVL,   TYPE_INT,     DEF_VALS},
#endif
#ifdef IP_TOS
    {"IP_TOS",          IPPROTO_IP,  IP_TOS,          TYPE_INT,     DEF_VALS},
#endif
#ifdef IP_TTL
    {"IP_TTL",          IPPROTO_IP,  IP_TTL,          TYPE_INT,     DEF_VALS},
#endif
#ifdef IP_MAXSEG
    {"TCP_MAXSEG",      IPPROTO_TCP, TCP_MAXSEG,      TYPE_INT,     DEF_VALS},
#endif
    {"TCP_NODELAY",     IPPROTO_TCP, TCP_NODELAY,     TYPE_FLAG,    DEF_VALS},
    {NULL,              0,           0,               TYPE_NONE,    DEF_VALS}
};

static int print_socket_options(void) {
    int fd;
    socklen_t optlen;
    SOCK_OPT *ptr;
    OPT_UNION val;
    char line[STRLEN];

    fd=socket(AF_INET, SOCK_STREAM, 0);

    s_log(LOG_RAW, "Socket option defaults:");
    s_log(LOG_RAW, "    %-16s%-10s%-10s%-10s%-10s",
        "Option", "Accept", "Local", "Remote", "OS default");
    for(ptr=sock_opts; ptr->opt_str; ++ptr) {
        /* display option name */
        sprintf(line, "    %-16s", ptr->opt_str);
        /* display stunnel default values */
        print_option(line, ptr->opt_type, ptr->opt_val[0]);
        print_option(line, ptr->opt_type, ptr->opt_val[1]);
        print_option(line, ptr->opt_type, ptr->opt_val[2]);
        /* display OS default value */
        optlen=sizeof val;
        if(getsockopt(fd, ptr->opt_level,
                ptr->opt_name, (void *)&val, &optlen)) {
            if(get_last_socket_error()!=ENOPROTOOPT) {
                s_log(LOG_RAW, "%s", line); /* dump the name and assigned values */
                sockerror("getsockopt");
                return 0; /* FAILED */
            }
            safeconcat(line, "    --    "); /* write-only value */
        } else
            print_option(line, ptr->opt_type, &val);
        s_log(LOG_RAW, "%s", line);
    }
    return 1; /* OK */
}

static void print_option(char *line, int type, OPT_UNION *val) {
    char text[STRLEN];

    if(!val) {
        safecopy(text, "    --    ");
    } else {
        switch(type) {
        case TYPE_FLAG:
        case TYPE_INT:
            sprintf(text, "%10d", val->i_val);
            break;
        case TYPE_LINGER:
            sprintf(text, "%d:%-8d",
                val->linger_val.l_onoff, val->linger_val.l_linger);
            break;
        case TYPE_TIMEVAL:
            sprintf(text, "%6d:%-3d",
                (int)val->timeval_val.tv_sec, (int)val->timeval_val.tv_usec);
            break;
        case TYPE_STRING:
            sprintf(text, "%10s", val->c_val);
            break;
        default:
            safecopy(text, "  Ooops?  "); /* Internal error? */
        }
    }
    safeconcat(line, text);
}

static int parse_socket_option(char *arg) {
    int socket_type; /* 0-accept, 1-local, 2-remote */
    char *opt_val_str, *opt_val2_str;
    SOCK_OPT *ptr;

    if(arg[1]!=':')
        return 0; /* FAILED */
    switch(arg[0]) {
    case 'a':
        socket_type=0; break;
    case 'l':
        socket_type=1; break;
    case 'r':
        socket_type=2; break;
    default:
        return 0; /* FAILED */
    }
    arg+=2;
    opt_val_str=strchr(arg, '=');
    if(!opt_val_str) /* No '='? */
        return 0; /* FAILED */
    *opt_val_str++='\0';
    ptr=sock_opts;
    for(;;) {
        if(!ptr->opt_str)
            return 0; /* FAILED */
        if(!strcmp(arg, ptr->opt_str))
            break; /* option name found */
        ++ptr;
    }
    ptr->opt_val[socket_type]=calloc(1, sizeof(OPT_UNION));
    switch(ptr->opt_type) {
    case TYPE_FLAG:
    case TYPE_INT:
        ptr->opt_val[socket_type]->i_val=atoi(opt_val_str);
        return 1; /* OK */
    case TYPE_LINGER:
        opt_val2_str=strchr(opt_val_str, ':');
        if(opt_val2_str) {
            *opt_val2_str++='\0';
            ptr->opt_val[socket_type]->linger_val.l_linger=atoi(opt_val2_str);
        } else {
            ptr->opt_val[socket_type]->linger_val.l_linger=0;
        }
        ptr->opt_val[socket_type]->linger_val.l_onoff=atoi(opt_val_str);
        return 1; /* OK */
    case TYPE_TIMEVAL:
        opt_val2_str=strchr(opt_val_str, ':');
        if(opt_val2_str) {
            *opt_val2_str++='\0';
            ptr->opt_val[socket_type]->timeval_val.tv_usec=atoi(opt_val2_str);
        } else {
            ptr->opt_val[socket_type]->timeval_val.tv_usec=0;
        }
        ptr->opt_val[socket_type]->timeval_val.tv_sec=atoi(opt_val_str);
        return 1; /* OK */
    case TYPE_STRING:
        if(strlen(opt_val_str)+1>sizeof(OPT_UNION))
            return 0; /* FAILED */
        strcpy(ptr->opt_val[socket_type]->c_val, opt_val_str);
        return 1; /* OK */
    default:
        ; /* ANSI C compiler needs it */
    }
    return 0; /* FAILED */
}

/* Parse out OCSP URL */

static char *parse_ocsp_url(LOCAL_OPTIONS *section, char *arg) {
    char *host, *port, *path;
    int ssl;

    if(!OCSP_parse_url(arg, &host, &port, &path, &ssl))
        return "Failed to parse OCSP URL";
    if(ssl)
        return "SSL not supported for OCSP"
            " - additional stunnel service needs to be defined";
    if(!hostport2addrlist(&section->ocsp_addr, host, port))
        return "Failed to resolve OCSP server address";
    section->ocsp_path=stralloc(path);
    if(host)
        OPENSSL_free(host);
    if(port)
        OPENSSL_free(port);
    if(path)
        OPENSSL_free(path);
    return NULL; /* OK! */
}

/* Parse out OCSP flags stuff */

static unsigned long parse_ocsp_flag(char *arg) {
    struct {
        char *name;
        unsigned long value;
    } ocsp_opts[] = {
        {"NOCERTS", OCSP_NOCERTS},
        {"NOINTERN", OCSP_NOINTERN},
        {"NOSIGS", OCSP_NOSIGS},
        {"NOCHAIN", OCSP_NOCHAIN},
        {"NOVERIFY", OCSP_NOVERIFY},
        {"NOEXPLICIT", OCSP_NOEXPLICIT},
        {"NOCASIGN", OCSP_NOCASIGN},
        {"NODELEGATED", OCSP_NODELEGATED},
        {"NOCHECKS", OCSP_NOCHECKS},
        {"TRUSTOTHER", OCSP_TRUSTOTHER},
        {"RESPID_KEY", OCSP_RESPID_KEY},
        {"NOTIME", OCSP_NOTIME},
        {NULL, 0}
    }, *option;

    for(option=ocsp_opts; option->name; ++option)
        if(!strcasecmp(option->name, arg))
            return option->value;
    return 0; /* FAILED */
}

/* End of options.c */
