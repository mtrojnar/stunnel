/*
 *   stunnel       Universal SSL tunnel
 *   Copyright (c) 1998-2001 Michal Trojnara <Michal.Trojnara@mirt.net>
 *                 All Rights Reserved
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 *   In addition, as a special exception, Michal Trojnara gives
 *   permission to link the code of this program with the OpenSSL
 *   library (or with modified versions of OpenSSL that use the same
 *   license as OpenSSL), and distribute linked combinations including
 *   the two.  You must obey the GNU General Public License in all
 *   respects for all of the code used other than OpenSSL.  If you modify
 *   this file, you may extend this exception to your version of the
 *   file, but you are not obligated to do so.  If you do not wish to
 *   do so, delete this exception statement from your version.
 */

#include "common.h"
#include "prototypes.h"

/* Needed so we know which version of OpenSSL we're using */
#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#else
#include <ssl.h>
#endif

extern server_options options;

static void print_version();
static void print_help();
static void print_info();
static void name2nums(char *name, u32 **names, u_short *port);
static u_short port2num(char *portname);
static void host2num(u32 **hostlist, char *hostname);
#ifndef HAVE_GETOPT
static int getopt(int argc, char **argv, char *options);
#endif
static void alloc(u32 **ptr, int len);
static int parse_debug_level(char *optarg);
static int print_socket_options();
static void print_option(int type, opt_union *val);
static int parse_socket_option(char *optarg);

void parse_options(int argc, char *argv[]) {
    /* get options and set global variables */
    int c;
    extern char *optarg;
    extern int optind, opterr, optopt;
    char *tmpstr;
    static char *default_args[2];
    char *servname_selected=NULL;

    options.option=0;
    options.verify_level=-1;
    options.verify_use_only_my=0;
    options.debug_level=5;
#ifndef USE_WIN32
    options.facility=LOG_DAEMON;
#endif
    options.session_timeout=300;
    options.cipher_list=NULL;
    options.username=NULL;
    options.protocol=NULL;
    options.setuid_user=NULL;
    options.setgid_group=NULL;
    options.pid_dir=PIDDIR;
    options.egd_sock=NULL;
    options.rand_file=NULL;
    options.rand_write=1;
    options.random_bytes=RANDOM_BYTES;
    options.output_file=NULL;
    options.local_ip=NULL;
    opterr=0;
    while ((c = getopt(argc, argv, "A:a:cp:v:d:fTl:L:r:s:g:t:u:n:N:hC:D:O:E:R:WB:VP:S:o:I:")) != EOF)
        switch (c) {
            case 'A':
                    safecopy(options.cert_file,optarg);
                break;
            case 'a':
                safecopy(options.cert_dir, optarg);
                break;
            case 'S':
                options.cert_defaults = atoi(optarg);
                if ( options.cert_defaults < 0 ||
                     options.cert_defaults > 3 ) {
                     log(LOG_ERR, "Bad -S value '%d'", options.cert_defaults);
                     print_info();
                }
                break;
            case 'c':
                options.option|=OPT_CLIENT;
                break;
            case 'p':
                options.option|=OPT_CERT;
                safecopy(options.pem, optarg);
                break;
            case 'v':
                options.verify_level=SSL_VERIFY_NONE;
                switch(atoi(optarg)) {
                case 3:
                    options.verify_use_only_my=1;
                case 2:
                    options.verify_level|=SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
                case 1:
                    options.verify_level|=SSL_VERIFY_PEER;
                case 0:
                    break;
                default:
                    log(LOG_ERR, "Bad verify level");
                    print_info();
                }
                break;
             case 'd':
                if(options.option&OPT_DAEMON) {
                    log(LOG_ERR, "Multiple -d not allowed");
                    print_info();
                }
                options.option|=OPT_DAEMON;
                options.localnames=NULL;
                name2nums(optarg, &options.localnames, &options.localport);
                if(!options.localnames) {
                    alloc(&options.localnames, 1);
                    options.localnames[0]=htonl(INADDR_ANY);
                }
                break;
            case 'f':
                options.option|=OPT_FOREGROUND;
                break;
            case 'T':
                options.option|=OPT_TRANSPARENT;
                break;
            case 'R':
                    options.rand_file=optarg;
                break;
            case 'W':
                options.rand_write=0;
                break;
            case 'B':
                    options.random_bytes=atoi(optarg);
                break;
            case 'E':
#if SSLEAY_VERSION_NUMBER >= 0x0090581fL
                    options.egd_sock=optarg;
#else
                log(LOG_ERR, "-E is only supported when compiled with OpenSSL 0.9.5a or later");
                /* exit(1) ??? */
#endif
                break;
            case 'L':
                options.option |= OPT_PTY;
            case 'l':
                if(options.option&OPT_PROGRAM) {
                    log(LOG_ERR, "Multiple -l or -L not allowed");
                    print_info();
                }
                options.option |= OPT_PROGRAM;
                options.execname = optarg;
                /* Default servname is options.execname w/o path */
                tmpstr = strrchr(options.execname, '/');
                if (tmpstr)
                    safecopy(options.servname, tmpstr+1);
                else
                    safecopy(options.servname, options.execname);
                break;
            case 'r':
                if(options.option&OPT_REMOTE) {
                    log(LOG_ERR, "Multiple -r not allowed");
                    print_info();
                }
                options.option |= OPT_REMOTE;
                if (!(options.option & OPT_PROGRAM)) {
                    /* Default servname is optarg with '.' instead of ':' */
                    safecopy(options.servname, optarg);
                    safename(options.servname);
                }
                options.remotenames=NULL;
                name2nums(optarg, &options.remotenames, &options.remoteport);
                if (!options.remotenames) {
                    alloc(&options.remotenames, 1);
                    options.remotenames[0] = htonl(INADDR_LOOPBACK);
                }
                break;
            case 's':
                options.setuid_user=optarg;
                break;
            case 'g':
                options.setgid_group=optarg;
                break;
            case 't':
                if(!(options.session_timeout=atoi(optarg))) {
                    log(LOG_ERR, "Illegal session timeout: %s", optarg);
                    print_info();
                }
                break;
            case 'u':
                options.username=optarg;
                break;
            case 'n':
                options.protocol=optarg;
                break;
            case 'N':
                    servname_selected=optarg;
                break;
            case 'C':
                options.cipher_list=optarg;
                break;
            case 'D':
                if(!parse_debug_level(optarg)) {
                    log(LOG_ERR, "Illegal debug argument: %s", optarg);
                    print_info();
                }
                break;
            case 'O':
                if(!parse_socket_option(optarg)) {
                    log(LOG_ERR, "Illegal socket option: %s", optarg);
                    print_info();
                }
                break;
            case 'V':
                print_version();
                exit(0);
            case 'P':
                    options.pid_dir=optarg;
                break;
            case 'o':
                    options.output_file=optarg;
                break;
            case 'I':
                    host2num(&options.local_ip, optarg);
                break;
            case '?':
                log(LOG_ERR, "Illegal option: '%c'", optopt);
                print_info();
            case 'h':
                print_help();
            default:
                log(LOG_ERR, "INTERNAL ERROR: Illegal option: '%c'", c);
                print_info();
        }
#ifdef USE_WIN32
    if(!(options.option&OPT_DAEMON)) {
        log(LOG_ERR, "You must use daemon mode (-d) in Windows");
        print_info();
    }
#endif
    if(!(options.option&(OPT_REMOTE|OPT_PROGRAM))) {
        log(LOG_ERR, "Either -r, -l (or -L) option must be used");
        print_info();
    }
    if((options.option&OPT_REMOTE) && (options.option&OPT_PROGRAM)
            && (options.option&OPT_DAEMON)) {
        log(LOG_ERR, "-d, -r and -l (or -L) options are not allowed together");
        print_info();
    }
    if(!(options.option&OPT_CLIENT))
        options.option|=OPT_CERT; /* Server always needs a certificate */
    if(optind==argc) { /* No arguments - use servname as execargs */
        default_args[0]=options.servname;
        default_args[1]=0;
        options.execargs=default_args;
    } else { /* There are some arguments - use execargs[0] as servname */
        options.execargs=argv + optind;
        safecopy(options.servname, options.execargs[0]);
    }
    if(servname_selected) {
        safecopy(options.servname, servname_selected);
        safename(options.servname);
    }
}

static void print_version() {
    fprintf(stderr, "\n%s\n\n", stunnel_info());
    fprintf(stderr, "Default behaviour:\n"
#ifdef USE_WIN32
        "\trun in daemon mode\n"
        "\trun in foreground\n"
#else
        "\trun in inetd mode (unless -d used)\n"
        "\trun in background (unless -f used)\n"
#endif
        "\trun in ssl server mode (unless -c used)\n\n");

    fprintf(stderr, "Compile time defaults:\n");
    fprintf(stderr, "\t-v level\tno verify\n");
    fprintf(stderr, "\t-a directory\t%s\n",
        strcmp("",CERT_DIR)? CERT_DIR : "(none)");
    fprintf(stderr, "\t-A file\t\t%s\n",
        strcmp("",CERT_FILE)? CERT_FILE : "(none)");
    fprintf(stderr, "\t-S sources\t%d\n", CERT_DEFAULTS);
    fprintf(stderr, "\t-t timeout\t%ld seconds\n", options.session_timeout);
    fprintf(stderr, "\t-B bytes\t%d\n", RANDOM_BYTES);
    fprintf(stderr, "\t-D level\t%d\n", options.debug_level);
#ifndef USE_WIN32
    fprintf(stderr, "\t-P pid dir\t%s\n", options.pid_dir);
#endif
    fprintf(stderr, "\t-p pemfile\t"
        "in server mode: %s\n"
        "\t\t\tin client mode: none\n\n", options.pem);

    print_socket_options();
}

static void print_help() {
    fprintf(stderr,
/* Server execution */
        "\nstunnel\t"
        "[-h] "
        "[-V] "
        "[-c | -T] "
        "[-D level] "
        "[-C cipherlist] "
        "[-p pemfile] "
        "\n\t"
        "[-v level] "
        "[-A certfile] "
        "[-a directory] "
        "[-S sources] "
        "[-t timeout] "
        "\n\t"
        "[-u ident_username] "
        "[-s setuid_user] "
        "[-g setgid_group] "
        "[-n protocol]"
        "\n\t"
        "[-R randfile] "
#if SSLEAY_VERSION_NUMBER >= 0x0090581fL
        "[-E egdsock] "
#endif
        "[-B bytes] "

#ifndef USE_WIN32
        "[-P { dir/ | filename | none } ] "
        "\n\t[-d [host:]port [-f] ] "
        "\n\t[-r [host:]port | { -l | -L }  program [-- args] ] "
#else
        "\n\t-d [host:]port -r [host:]port"
#endif

        /* Argument notes */

        "\n\n  -h\t\tprint this help screen"
        "\n  -V\t\tprint stunnel version and compile-time defaults"
        "\n"
        "\n  -d [host:]port   daemon mode (host defaults to INADDR_ANY)"
        "\n  -r [host:]port   connect to remote service (host defaults to INADDR_LOOPBACK)"
#ifndef USE_WIN32
        "\n  -l program\texecute local inetd-type program"
        "\n  -L program\topen local pty and execute program"
#endif
        "\n"
        "\n  -c\t\tclient mode (remote service uses SSL)"
#ifndef USE_WIN32
        "\n  -f\t\tforeground mode (don't fork, log to stderr)"
#endif
        "\n  -I host\tlocal IP address to be used as source for remote connections"
        "\n  -T\t\ttransparent proxy mode on hosts that support it"
        "\n  -p pemfile\tprivate key and certificate chain PEM filename"
        "\n  -v level\tverify peer certificate"
        "\n\t\t   level 1 - verify peer certificate if present"
        "\n\t\t   level 2 - require valid peer certificate always"
        "\n\t\t   level 3 - verify peer with locally installed certificate"
        "\n  -a directory\tclient certificate directory for -v options"
        "\n  -A certfile\tCA certificate for -v options"
        "\n  -S sources\twhich certificate source defaults to use"
        "\n\t\t   0 = ignore all defaults sources"
        "\n\t\t   1 = use ssl library defaults"
        "\n\t\t   2 = use stunnel defaults"
        "\n\t\t   3 = use both ssl library and stunnel defaults"
        "\n  -t timeout\tsession cache timeout"
        "\n  -u user\tuse IDENT (RFC 1413) username checking"
        "\n  -n proto\tnegotiate SSL with specified protocol"
        "\n\t\tcurrently supported: smtp, pop3, nntp"
        "\n  -N name\tservice name to use for tcp wrapper checking"
#ifndef USE_WIN32
        "\n  -s username\tsetuid() to username in daemon mode"
        "\n  -g groupname\tsetgid() to groupname in daemon mode"
        "\n  -P arg\tspecify pid file { dir/ | filename | none }"
#endif
        "\n  -C list\tset permitted SSL ciphers"
#if SSLEAY_VERSION_NUMBER >= 0x0090581fL
        "\n  -E socket\tpath to Entropy Gathering Daemon socket"
#ifdef EGD_SOCKET
        "\n\t\t" EGD_SOCKET " is used when this option is not specified"
#endif
        "\n  -B bytes\thow many bytes to read from random seed files"
#else
        "\n  -B bytes\tnum bytes of random data considered 'sufficient' for PRNG"
        "\n\t\tand maximum number of bytes to read from random seed files"
#endif
        "\n  -R file\tpath to file with random seed data"
#ifdef RANDOM_FILE
        "\n\t\t" RANDOM_FILE " is used when this option is not specified"
#endif
        "\n  -W\t\tdo not overwrite random seed datafiles with new random data"
        "\n  -D [fac.]lev\tdebug level (e.g. daemon.info)"
        "\n  -O a|l|r:option=value[:value]\tset an option on accept/local/remote socket"
        "\n  -o file\tappend log messages to a file"
        "\n"
        "\nSee stunnel -V output for default values\n"
        "\n");
    exit(0);
}

static void print_info() {
    fprintf(stderr, "\nTry 'stunnel -h' for more information.\n\n");
    exit(1);
}

static void name2nums(char *name, u32 **names, u_short *port) {
    char hostname[STRLEN], *portname;

    safecopy(hostname, name);
    if((portname=strrchr(hostname, ':'))) {
        *portname++='\0';
        host2num(names, hostname);
        *port=port2num(portname);
    } else {
        *port=port2num(hostname); /* no ':' - use default host IP */
    }
}

static u_short port2num(char *portname) { /* get port number */
    struct servent *p;
    u_short port;

    if((p=getservbyname(portname, "tcp")))
        port=p->s_port;
    else
        port=htons((u_short)atoi(portname));
    if(!port) {
        log(LOG_ERR, "Invalid port: %s", portname);
        exit(2);
    }
    return port;
}

static void host2num(u32 **hostlist, char *hostname) {
        /* get list of host addresses */
    struct hostent *h;
    u32 ip;
    int i;
    char **tab;

    ip=inet_addr(hostname);
    if(ip!=-1) { /* dotted decimal */
        alloc(hostlist, 1);
        (*hostlist)[0]=ip;
        return;
    }
    /* not dotted decimal - we have to call resolver */
    if(!(h=gethostbyname(hostname))) { /* get list of addresses */
        sockerror("gethostbyname");
        exit(1);
    }
    i=0;
    tab=h->h_addr_list;
    while(*tab++) /* count the addresses */
        i++;
    alloc(hostlist, i); /* allocate memory */
    while(--i>=0)
        (*hostlist)[i]=*(u32 *)(h->h_addr_list[i]);
}

#ifndef HAVE_GETOPT
char *optarg;
int optind=1, opterr=0, optopt;

static int getopt(int argc, char **argv, char *options) {
        /* simplified version for Win32 */
    char *option;

    if(optind==argc || argv[optind][0]!='-')
        return EOF;
    optopt=argv[optind][1];
    option=strrchr(options, optopt);
    if(!option)
        return '?';
    if(option[1]==':') {
        if(optind+1==argc)
            return '?'; /* Argument not found */
        else
            optarg=argv[++optind];
    }
    ++optind;
    return optopt;
}
#endif /* !defined HAVE_GETOPT */

static void alloc(u32 **ptr, int len) {
        /* Allocate len+1 words terminated with -1 */
    if (*ptr) /* Deallocate if not null */
        free(*ptr);
    *ptr=calloc((len+1), sizeof(u32));
    if (!*ptr) {
        log(LOG_ERR, "Fatal memory allocation error");
        exit(2);
    }
    (*ptr)[len]=-1;
}

/* Parse out the facility/debug level stuff */

typedef struct {
    char *name;
    int value;
} facilitylevel;

static int parse_debug_level(char *optarg) {
    char optarg_copy[STRLEN];
    char *string;
    facilitylevel *fl;

/* Facilities only make sense on unix */
#ifndef USE_WIN32
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
#endif /* USE_WIN32 */

    facilitylevel levels[] = {
        {"emerg", LOG_EMERG},     {"alert", LOG_ALERT},
        {"crit", LOG_CRIT},       {"err", LOG_ERR},
        {"warning", LOG_WARNING}, {"notice", LOG_NOTICE},
        {"info", LOG_INFO},       {"debug", LOG_DEBUG},
        {NULL, -1}
    };

    safecopy(optarg_copy, optarg);
    string = optarg_copy;

/* Facilities only make sense on unix */
#ifndef USE_WIN32
    if(strchr(string, '.')) { /* We have a facility specified */
        options.facility=-1;
        string=strtok(optarg_copy, "."); /* break it up */

        for(fl=facilities; fl->name; fl++) {
            if(!strcasecmp(fl->name, string)) {
                options.facility = fl->value;
                break;
            }
        }
        if(options.facility==-1)
            return 0; /* FAILED */
        string=strtok(NULL, ".");    /* set to the remainder */
    }
#endif /* USE_WIN32 */

    /* Time to check the syslog level */
    if(strlen(string)==1 && *string>='0' && *string<='7') {
        options.debug_level=*string-'0';
        return 1; /* OK */
    }
    options.debug_level=8;    /* illegal level */
    for(fl=levels; fl->name; fl++) {
        if(!strcasecmp(fl->name, string)) {
            options.debug_level=fl->value;
            break;
        }
    }
    if (options.debug_level==8)
        return 0; /* FAILED */
    return 1; /* OK */
}

/* Parse out the socket options stuff */

static int on=1;

#define DEF_VALS {NULL, NULL, NULL}
#define DEF_ACCEPT {(void *)&on, NULL, NULL}

sock_opt sock_opts[] = {
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

static int print_socket_options() {
    int fd, len;
    sock_opt *ptr;
    opt_union val;

    fd=socket(AF_INET, SOCK_STREAM, 0);

    fprintf(stderr, "Socket option defaults:\n");
    fprintf(stderr, "\t%-16s%-10s%-10s%-10s%-10s\n",
        "Option", "Accept", "Local", "Remote", "OS default");
    for(ptr=sock_opts; ptr->opt_str; ptr++) {
        fprintf(stderr, "\t%-16s", ptr->opt_str);
        print_option(ptr->opt_type, ptr->opt_val[0]);
        print_option(ptr->opt_type, ptr->opt_val[1]);
        print_option(ptr->opt_type, ptr->opt_val[2]);
        len = sizeof(val);
        if(getsockopt(fd, ptr->opt_level, ptr->opt_name, (void *)&val, &len)) {
            if(get_last_socket_error()!=ENOPROTOOPT) {
                fprintf(stderr, "\n");
                sockerror("getsockopt");
                return 0; /* FAILED */
            }
            fprintf(stderr, "    --    \n");
            continue;
        }
        print_option(ptr->opt_type, &val);
        fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n");
    return 1; /* OK */
}

static void print_option(int type, opt_union *val) {
    if(!val) {
        fprintf(stderr, "    --    ");
        return;
    }
    switch(type) {
    case TYPE_FLAG:
    case TYPE_INT:
        fprintf(stderr, "%10d", val->i_val);
        break;
    case TYPE_LINGER:
        fprintf(stderr, "%d:%-8d",
            val->linger_val.l_onoff, val->linger_val.l_linger);
        break;
    case TYPE_TIMEVAL:
        fprintf(stderr, "%6d:%-3d",
            (int)val->timeval_val.tv_sec, (int)val->timeval_val.tv_usec);
        break;
    case TYPE_STRING:
        fprintf(stderr, "%10s", val->c_val);
        break;
    default:
        ; /* ANSI C compiler needs it */
    }
}

static int parse_socket_option(char *optarg) {
    int socket_type; /* 0-accept, 1-local, 2-remote */
    char *opt_val_str, *opt_val2_str;
    sock_opt *ptr;

    if(optarg[1]!=':')
        return 0; /* FAILED */
    switch(optarg[0]) {
    case 'a':
        socket_type=0; break;
    case 'l':
        socket_type=1; break;
    case 'r':
        socket_type=2; break;
    default:
        return 0; /* FAILED */
    }
    optarg+=2;
    opt_val_str=strchr(optarg, '=');
    if(!opt_val_str) /* No '='? */
        return 0; /* FAILED */
    *opt_val_str++='\0';
    ptr=sock_opts;
    for(;;) {
        if(!ptr->opt_str)
            return 0; /* FAILED */
        if(!strcmp(optarg, ptr->opt_str))
            break; /* option name found */
        ptr++;
    }
    ptr->opt_val[socket_type]=calloc(1, sizeof(opt_union));
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
        if(strlen(opt_val_str)+1>sizeof(opt_union))
            return 0; /* FAILED */
        strcpy(ptr->opt_val[socket_type]->c_val, opt_val_str);
        return 1; /* OK */
    default:
        ; /* ANSI C compiler needs it */
    }
    return 0; /* FAILED */
}

/* End of options.c */
