/*
 *   stunnel       TLS offloading and load-balancing proxy
 *   Copyright (C) 1998-2026 Michal Trojnara <Michal.Trojnara@stunnel.org>
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

#include "prototypes.h"

#ifdef _MSC_VER
/*
 * Disable MSVC C4996 warning:
 * warning C4996: 'inet_addr': Use inet_pton() or InetPton() instead
 * warning C4996: 'inet_ntoa': Use inet_ntop() or InetNtop() instead
 * warning C4996: 'gethostbyname': Use getaddrinfo() or GetAddrInfoW() instead
 */
#pragma warning(disable: 4996)
#endif

/**************************************** prototypes */

#if defined(USE_WIN32) && !defined(_WIN32_WCE)

typedef int (CALLBACK * GETADDRINFO) (const char *node,
    const char *service, const struct addrinfo *hints, struct addrinfo **res);
typedef void (CALLBACK * FREEADDRINFO) (struct addrinfo *res);
typedef int (CALLBACK * GETNAMEINFO) (const struct sockaddr *sa,
    socklen_t salen, char *host, size_t hostlen, char *serv, size_t servlen,
    int flags);
NOEXPORT GETADDRINFO s_getaddrinfo;
NOEXPORT FREEADDRINFO s_freeaddrinfo;
NOEXPORT GETNAMEINFO s_getnameinfo;

NOEXPORT int get_ipv6(LPTSTR file);

#endif /* defined(USE_WIN32) && !defined(_WIN32_WCE) */

NOEXPORT void addrlist2addr(SOCKADDR_UNION *addr,
    SOCKADDR_LIST *addr_list);
NOEXPORT void addrlist_reset(SOCKADDR_LIST *addr_list);

#ifndef HAVE_GETADDRINFO

#ifndef EAI_MEMORY
#define EAI_MEMORY 1
#endif
#ifndef EAI_NONAME
#define EAI_NONAME 2
#endif
#ifndef EAI_SERVICE
#define EAI_SERVICE 8
#endif

/* rename some potentially locally shadowed declarations */
#define getaddrinfo     local_getaddrinfo
#define freeaddrinfo    local_freeaddrinfo

#ifndef HAVE_STRUCT_ADDRINFO
struct addrinfo {
    int ai_flags;
    int ai_family;
    int ai_socktype;
    int ai_protocol;
    int ai_addrlen;
    struct sockaddr *ai_addr;
    char *ai_canonname;
    struct addrinfo *ai_next;
};
#endif

#ifndef AI_PASSIVE
#define AI_PASSIVE 1
#endif

NOEXPORT int getaddrinfo(const char *node, const char *service,
    const struct addrinfo *hints, struct addrinfo **res);
NOEXPORT int alloc_addresses(struct hostent *h, const struct addrinfo *hints,
    u_short port, struct addrinfo **head, struct addrinfo **tail);
NOEXPORT void freeaddrinfo(struct addrinfo *current);

#endif /* !defined HAVE_GETADDRINFO */

/**************************************** resolver initialization */

void resolver_init(void) {
#if defined(USE_WIN32) && !defined(_WIN32_WCE)
    if(get_ipv6(TEXT("ws2_32.dll"))) /* IPv6 in Windows XP or higher */
        return;
    if(get_ipv6(TEXT("wship6.dll"))) /* experimental IPv6 for Windows 2000 */
        return;
    /* fall back to the built-in emulation */
#endif
}

#if defined(USE_WIN32) && !defined(_WIN32_WCE)
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpragmas"
#pragma GCC diagnostic ignored "-Wcast-function-type"
#endif /* __GNUC__ */
NOEXPORT int get_ipv6(LPTSTR file) {
    HINSTANCE handle;

    handle=LoadLibrary(file);
    if(!handle)
        return 0;
    /* GetProcAddress() requires converting its generic entry point. */
    /* cppcheck-suppress-begin misra-c2012-11.3 */
    s_getaddrinfo=(GETADDRINFO)GetProcAddress(handle, "getaddrinfo");
    s_freeaddrinfo=(FREEADDRINFO)GetProcAddress(handle, "freeaddrinfo");
    s_getnameinfo=(GETNAMEINFO)GetProcAddress(handle, "getnameinfo");
    /* cppcheck-suppress-end misra-c2012-11.3 */
    if(!s_getaddrinfo || !s_freeaddrinfo || !s_getnameinfo) {
        s_getaddrinfo=NULL;
        s_freeaddrinfo=NULL;
        s_getnameinfo=NULL;
        (void)FreeLibrary(handle);
        return 0;
    }
    return 1; /* IPv6 detected -> OK */
}
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif /* __GNUC__ */
#endif

int use_ipv6(void) {
#if defined(USE_WIN32) && !defined(_WIN32_WCE)
    return s_getaddrinfo != NULL;
#else /* defined(USE_WIN32) && !defined(_WIN32_WCE) */
#if defined(USE_IPV6)
    return 1;
#else /* defined(USE_IPV6) */
    return 0;
#endif /* defined(USE_IPV6) */
#endif /* defined(USE_WIN32) && !defined(_WIN32_WCE) */
}

/**************************************** stunnel resolver API */

unsigned name2addr(SOCKADDR_UNION *addr, char *name, int passive) {
    SOCKADDR_LIST *addr_list;
    unsigned retval;

    addr_list=str_alloc(sizeof(SOCKADDR_LIST));
    addrlist_clear(addr_list, passive);
    retval=name2addrlist(addr_list, name);
    if(retval)
        addrlist2addr(addr, addr_list);
    str_free(addr_list->addr);
    str_free(addr_list);
    return retval;
}

unsigned hostport2addr(SOCKADDR_UNION *addr,
        char *host_name, const char *port_name, int passive) {
    SOCKADDR_LIST *addr_list;
    unsigned num;

    addr_list=str_alloc(sizeof(SOCKADDR_LIST));
    addrlist_clear(addr_list, passive);
    num=hostport2addrlist(addr_list, host_name, port_name);
    if(num)
        addrlist2addr(addr, addr_list);
    str_free(addr_list->addr);
    str_free(addr_list);
    return num;
}

NOEXPORT void addrlist2addr(SOCKADDR_UNION *addr, SOCKADDR_LIST *addr_list) {
    unsigned i;

    for(i=0; i<addr_list->num; ++i) { /* find the first IPv4 address */
        if(addr_family_is(&addr_list->addr[i], AF_INET)) {
            (void)memcpy(addr, &addr_list->addr[i], sizeof(SOCKADDR_UNION));
            return;
        }
    }
#ifdef USE_IPV6
    for(i=0; i<addr_list->num; ++i) { /* find the first IPv6 address */
        if(addr_family_is(&addr_list->addr[i], AF_INET6)) {
            (void)memcpy(addr, &addr_list->addr[i], sizeof(SOCKADDR_UNION));
            return;
        }
    }
#endif
    /* copy the first address resolved (currently AF_UNIX) */
    (void)memcpy(addr, &addr_list->addr[0], sizeof(SOCKADDR_UNION));
}

unsigned name2addrlist(SOCKADDR_LIST *addr_list, char *name) {
    char *tmp, *host_name, *port_name;
    unsigned num;

    /* first check if this is a UNIX socket */
#ifdef HAVE_STRUCT_SOCKADDR_UN
    if(*name=='/') {
        /* offsetof() is the portable system-interface representation. */
        /* cppcheck-suppress misra-c2012-10.8 */
        if(offsetof(struct sockaddr_un, sun_path)+strlen(name)+1U>
                sizeof(struct sockaddr_un)) {
            s_log(LOG_ERR, "Unix socket path is too long");
            return 0; /* no results */
        }
        addr_list->addr=str_realloc_detached(addr_list->addr,
            (addr_list->num+1U)*sizeof(SOCKADDR_UNION));
        addr_list->addr[addr_list->num].un.sun_family=AF_UNIX;
        (void)strcpy(addr_list->addr[addr_list->num].un.sun_path, name);
        ++(addr_list->num);
        return 1; /* ok - return the number of new addresses */
    }
#endif

    /* setup host_name and port_name */
    tmp=str_dup(name);
    port_name=strrchr(tmp, ':');
    if(port_name) {
        host_name=tmp;
        *port_name++='\0';
    } else { /* no ':' - use default host IP */
        host_name=NULL;
        port_name=tmp;
    }

    /* fill addr_list structure */
    num=hostport2addrlist(addr_list, host_name, port_name);
    str_free(tmp);
    return num; /* ok - return the number of new addresses */
}

unsigned hostport2addrlist(SOCKADDR_LIST *addr_list,
        char *host_name, const char *port_name) {
    struct addrinfo hints, *res, *cur;
    int err, retry=0;
    unsigned num;

    (void)memset(&hints, 0, sizeof hints);
#if defined(USE_IPV6) || defined(USE_WIN32)
    hints.ai_family=AF_UNSPEC;
#else
    hints.ai_family=AF_INET;
#endif
    hints.ai_socktype=SOCK_STREAM;
    hints.ai_protocol=IPPROTO_TCP;
    hints.ai_flags=0;
    if(addr_list->passive)
        hints.ai_flags|=AI_PASSIVE;
#ifdef AI_ADDRCONFIG
    hints.ai_flags|=AI_ADDRCONFIG;
#endif
    for(;;) {
        res=NULL;
        err=getaddrinfo(host_name, port_name, &hints, &res);
        if(!err) /* success */
            break;
        if(err==EAI_SERVICE) {
            s_log(LOG_ERR, "Unknown TCP service \"%s\"", port_name);
            return 0; /* error */
        }
        if(err==EAI_AGAIN) {
            ++retry;
            if(retry<=3) {
                s_log(LOG_DEBUG, "getaddrinfo: EAI_AGAIN received: retrying");
                s_poll_sleep(1, 0);
                continue;
            }
        }
#ifdef AI_ADDRCONFIG
        if(hints.ai_flags&AI_ADDRCONFIG) {
            hints.ai_flags&=~AI_ADDRCONFIG;
            continue; /* retry for unconfigured network interfaces */
        }
#endif
        s_log(LOG_ERR, "Error resolving \"%s\": %s",
            host_name ? host_name :
                (addr_list->passive ? DEFAULT_ANY : DEFAULT_LOOPBACK),
            s_gai_strerror(err));
        return 0; /* error */
    }

    /* find the number of newly resolved addresses */
    num=0;
    for(cur=res; cur; cur=cur->ai_next) {
        if((size_t)cur->ai_addrlen>sizeof(SOCKADDR_UNION)) {
            s_log(LOG_ERR, "INTERNAL ERROR: ai_addrlen value too big");
            freeaddrinfo(res);
            return 0; /* no results */
        }
        ++num;
    }

    /* append the newly resolved addresses to addr_list->addr */
    addr_list->addr=str_realloc_detached(addr_list->addr,
        (addr_list->num+num)*sizeof(SOCKADDR_UNION));
    for(cur=res; cur; cur=cur->ai_next)
        (void)memcpy(&addr_list->addr[(addr_list->num)++], cur->ai_addr,
            (size_t)cur->ai_addrlen);

    freeaddrinfo(res);
    return num; /* ok - return the number of new addresses */
}

/* initialize the structure */
void addrlist_clear(SOCKADDR_LIST *addr_list, int passive) {
    addrlist_reset(addr_list);
    addr_list->names=NULL;
    addr_list->passive=passive;
}

/* prepare the structure to resolve new hosts */
NOEXPORT void addrlist_reset(SOCKADDR_LIST *addr_list) {
    addr_list->num=0;
    addr_list->addr=NULL;
    addr_list->start=0;
    addr_list->parent=addr_list; /* allow a copy to locate its parent */
}

unsigned addrlist_dup(SOCKADDR_LIST *dst, const SOCKADDR_LIST *src) {
    (void)memcpy(dst, src, sizeof(SOCKADDR_LIST));
    if(src->num) { /* already resolved */
        dst->addr=str_alloc_detached(src->num*sizeof(SOCKADDR_UNION));
        (void)memcpy(dst->addr, src->addr, src->num*sizeof(SOCKADDR_UNION));
    } else { /* delayed resolver */
        (void)addrlist_resolve(dst);
    }
    return dst->num;
}

unsigned addrlist_resolve(SOCKADDR_LIST *addr_list) {
    unsigned num=0, rnd=0;
    NAME_LIST *host;

    addrlist_reset(addr_list);
    for(host=addr_list->names; host; host=host->next)
        num+=name2addrlist(addr_list, host->name);
    if(num<2U) {
        addr_list->start=0;
    } else {
        /* randomize the initial value of round-robin counter */
        /* ignore the error value and the distribution bias */
        (void)RAND_bytes((unsigned char *)&rnd, sizeof rnd);
        addr_list->start=rnd%num;
    }
    return num;
}

char *s_ntop(SOCKADDR_UNION *addr, socklen_t addrlen) {
    int err;
    char *host, *port, *retval;

    if(addrlen==(socklen_t)sizeof(u_short)) /* see UNIX(7) manual for details */
        return str_dup("unnamed socket");
    host=str_alloc(256);
    port=str_alloc(256); /* needs to be long enough for AF_UNIX path */
    err=getnameinfo(&addr->sa, addrlen,
        host, 256, port, 256, NI_NUMERICHOST|NI_NUMERICSERV);
    if(err) {
        s_log(LOG_ERR, "getnameinfo: %s", s_gai_strerror(err));
        retval=str_dup("unresolvable address");
    } else if(!*port && !*host)
        retval=str_dup("unnamed socket");
    else
        retval=str_printf("%s%s%s", host, *host && *port ? ":" : "", port);
    str_free(host);
    str_free(port);
    return retval;
}

int addr_cmp(const SOCKADDR_UNION *addr1, socklen_t addrlen1,
        const SOCKADDR_UNION *addr2, socklen_t addrlen2) {
    if(addrlen1!=addrlen2)
        return 1;
    /* Socket addresses are fixed-length binary endpoint representations. */
    /* cppcheck-suppress misra-c2012-21.16 */
    return memcmp(addr1, addr2, (size_t)addrlen1);
}

int addr_family_is(const SOCKADDR_UNION *addr, int family) {
    /* Address-family constants and fields have platform-specific types. */
    /* cppcheck-suppress misra-c2012-10.4 */
    return addr->sa.sa_family==family ? 1 : 0;
}

socklen_t sockaddr_len(const SOCKADDR_UNION *addr) {
    switch(addr->sa.sa_family) {
    case AF_UNSPEC: /* 0 */
        return 0;
    case AF_INET: /* 2 (almost universally) */
        return sizeof(struct sockaddr_in);
#ifdef USE_IPV6
    case AF_INET6:
        return sizeof(struct sockaddr_in6);
#endif
#ifdef HAVE_STRUCT_SOCKADDR_UN
    case AF_UNIX:
        return sizeof(struct sockaddr_un);
#endif
    }
    s_log(LOG_ERR, "INTERNAL ERROR: Unknown sa_family: %d",
        addr->sa.sa_family);
    return sizeof(SOCKADDR_UNION);
}

/**************************************** my getaddrinfo() */
/* implementation is limited to functionality needed by stunnel */

#ifndef HAVE_GETADDRINFO
NOEXPORT int getaddrinfo(const char *node, const char *service,
        const struct addrinfo *hints, struct addrinfo **res) {
    struct hostent *h;
#ifndef _WIN32_WCE
    struct servent *p;
#endif
    u_short port;
    long port_num;
    struct addrinfo *ai;
    CRYPTO_RWLOCK *lock;
    int retval;
    char *tmpstr;

    if(!node)
        node=(hints->ai_flags & AI_PASSIVE) ? DEFAULT_ANY : DEFAULT_LOOPBACK;
#if defined(USE_WIN32) && !defined(_WIN32_WCE)
    if(s_getaddrinfo)
        return s_getaddrinfo(node, service, hints, res);
#endif
    /* decode service name */
    errno=0;
    /* Cppcheck does not recognize the adjacent errno protocol. */
    /* cppcheck-suppress [misra-c2012-22.8, misra-c2012-22.9] */
    port_num=strtol(service, &tmpstr, 10);
    if(tmpstr==service || *tmpstr) { /* not a number */
#ifdef _WIN32_WCE
        return EAI_NONAME;
#else /* defined(_WIN32_WCE) */
        p=getservbyname(service, "tcp");
        if(!p)
            return EAI_NONAME;
        port=(u_short)p->s_port;
#endif /* defined(_WIN32_WCE) */
    } else {
        if(errno!=0 || port_num<0L || port_num>65535L)
            return EAI_SERVICE;
        port=htons((u_short)port_num);
    }

    /* allocate addrlist structure */
    ai=str_alloc(sizeof(struct addrinfo));
    if(hints)
        (void)memcpy(ai, hints, sizeof(struct addrinfo));

    /* try to decode numerical address */
#if defined(USE_IPV6) && !defined(USE_WIN32)
    ai->ai_family=AF_INET6;
    ai->ai_addrlen=sizeof(struct sockaddr_in6);
    ai->ai_addr=str_alloc((size_t)ai->ai_addrlen);
    ai->ai_addr->sa_family=AF_INET6;
    if(inet_pton(AF_INET6, node,
            &((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr)>0) {
#else
    ai->ai_family=AF_INET;
    ai->ai_addrlen=sizeof(struct sockaddr_in);
    ai->ai_addr=str_alloc(ai->ai_addrlen);
    ai->ai_addr->sa_family=AF_INET;
    /* addrinfo stores concrete socket addresses through a generic pointer. */
    /* cppcheck-suppress misra-c2012-11.3 */
    ((struct sockaddr_in *)ai->ai_addr)->sin_addr.s_addr=inet_addr(node);
    /* cppcheck-suppress misra-c2012-11.3 */
    if(((struct sockaddr_in *)ai->ai_addr)->sin_addr.s_addr+1U) {
    /* (signed)((struct sockaddr_in *)ai->ai_addr)->sin_addr.s_addr!=-1 */
#endif
        /* cppcheck-suppress misra-c2012-11.3 */
        ((struct sockaddr_in *)ai->ai_addr)->sin_port=port;
        *res=ai;
        return 0; /* numerical address resolved */
    }
    str_free(ai->ai_addr);
    str_free(ai);

    /* not numerical: need to call resolver library */
    *res=NULL;
    ai=NULL;
    lock=s_write_lock(LOCK_INET);
#ifdef HAVE_GETHOSTBYNAME2
    h=gethostbyname2(node, AF_INET6);
    if(h) /* some IPv6 addresses found */
        alloc_addresses(h, hints, port, res, &ai); /* ignore the error */
#endif
    h=gethostbyname(node); /* get list of addresses */
    if(h) {
#ifdef HAVE_GETHOSTBYNAME2
        if(ai)
            retval=alloc_addresses(h, hints, port, &ai->ai_next, &ai);
        else
#endif /* HAVE_GETHOSTBYNAME2 */
            retval=alloc_addresses(h, hints, port, res, &ai);
    } else if(!*res)
        retval=EAI_NONAME; /* no results */
    else
        retval=0;
#ifdef HAVE_ENDHOSTENT
    endhostent();
#endif
    s_unlock(lock);
    if(retval) { /* error: free allocated memory */
        freeaddrinfo(*res);
        *res=NULL;
    }
    return retval;
}

NOEXPORT int alloc_addresses(struct hostent *h, const struct addrinfo *hints,
        u_short port, struct addrinfo **head, struct addrinfo **tail) {
    int i;
    struct addrinfo *ai;

    /* copy addresses */
    for(i=0; h->h_addr_list[i]; i++) {
        ai=str_alloc(sizeof(struct addrinfo));
        if(hints)
            (void)memcpy(ai, hints, sizeof(struct addrinfo));
        ai->ai_next=NULL; /* just in case */
        if(*tail) { /* list not empty: add a node */
            (*tail)->ai_next=ai;
            *tail=ai;
        } else { /* list empty: create it */
            *head=ai;
            *tail=ai;
        }
        ai->ai_family=h->h_addrtype;
#if defined(USE_IPV6)
        if(h->h_addrtype==AF_INET6) {
            ai->ai_addrlen=sizeof(struct sockaddr_in6);
            ai->ai_addr=str_alloc((size_t)ai->ai_addrlen);
            /* Copy raw resolver bytes into the concrete address object. */
            /* cppcheck-suppress [misra-c2012-11.3, misra-c2012-21.15] */
            (void)memcpy(&((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr,
                h->h_addr_list[i], (size_t)h->h_length);
        } else
#endif
        {
            ai->ai_addrlen=sizeof(struct sockaddr_in);
            ai->ai_addr=str_alloc((size_t)ai->ai_addrlen);
            /* Copy raw resolver bytes into the concrete address object. */
            /* cppcheck-suppress [misra-c2012-11.3, misra-c2012-21.15] */
            (void)memcpy(&((struct sockaddr_in *)ai->ai_addr)->sin_addr,
                h->h_addr_list[i], (size_t)h->h_length);
        }
        ai->ai_addr->sa_family=(u_short)h->h_addrtype;
        /* Ports have the same offset in each supported concrete address. */
        /* cppcheck-suppress misra-c2012-11.3 */
        ((struct sockaddr_in *)ai->ai_addr)->sin_port=port;
    }
    return 0; /* success */
}

NOEXPORT void freeaddrinfo(struct addrinfo *current) {
    struct addrinfo *next;

#if defined(USE_WIN32) && !defined(_WIN32_WCE)
    if(s_freeaddrinfo) {
        s_freeaddrinfo(current);
    return;
    }
#endif
    while(current) {
        str_free(current->ai_addr);
        str_free(current->ai_canonname);
        next=current->ai_next;
        str_free(current);
        current=next;
    }
}
#endif /* !defined HAVE_GETADDRINFO */

/* due to a problem with Mingw32 I decided to define my own gai_strerror() */
const char *s_gai_strerror(int err) {
    switch(err) {
#ifdef EAI_BADFLAGS
        case EAI_BADFLAGS:
            return "Invalid value for ai_flags (EAI_BADFLAGS)";
#endif
        case EAI_NONAME:
            return "Neither nodename nor servname known (EAI_NONAME)";
#ifdef EAI_AGAIN
        case EAI_AGAIN:
            return "Temporary failure in name resolution (EAI_AGAIN)";
#endif
#ifdef EAI_FAIL
        case EAI_FAIL:
            return "Non-recoverable failure in name resolution (EAI_FAIL)";
#endif
#ifdef EAI_NODATA
#if EAI_NODATA!=EAI_NONAME
        case EAI_NODATA:
            return "No address associated with nodename (EAI_NODATA)";
#endif /* EAI_NODATA!=EAI_NONAME */
#endif /* defined EAI_NODATA */
#ifdef EAI_FAMILY
        case EAI_FAMILY:
            return "ai_family not supported (EAI_FAMILY)";
#endif
#ifdef EAI_SOCKTYPE
        case EAI_SOCKTYPE:
            return "ai_socktype not supported (EAI_SOCKTYPE)";
#endif
#ifdef EAI_SERVICE
        case EAI_SERVICE:
            return "servname is not supported for ai_socktype (EAI_SERVICE)";
#endif
#ifdef EAI_ADDRFAMILY
        case EAI_ADDRFAMILY:
            return "Address family for nodename not supported (EAI_ADDRFAMILY)";
#endif /* EAI_ADDRFAMILY */
        case EAI_MEMORY:
            return "Memory allocation failure (EAI_MEMORY)";
#ifdef EAI_SYSTEM
        case EAI_SYSTEM:
            return "System error returned in errno (EAI_SYSTEM)";
#endif /* EAI_SYSTEM */
        default:
            return "Unknown error";
    }
}

/**************************************** my getnameinfo() */
/* implementation is limited to functionality needed by stunnel */

#ifndef HAVE_GETNAMEINFO
int getnameinfo(const struct sockaddr *sa, socklen_t salen,
    char *host, size_t hostlen, char *serv, size_t servlen, int flags) {

#if defined(USE_WIN32) && !defined(_WIN32_WCE)
    if(s_getnameinfo)
        return s_getnameinfo(sa, salen, host, hostlen, serv, servlen, flags);
#endif

    if(host && hostlen) {
#if defined(USE_IPV6) && !defined(USE_WIN32)
        inet_ntop(sa->sa_family, sa->sa_family==AF_INET6 ?
                (void *)&((struct sockaddr_in6 *)sa)->sin6_addr :
                (void *)&((struct sockaddr_in *)sa)->sin_addr,
            host, hostlen);
#else /* USE_IPV6 */
        CRYPTO_RWLOCK *lock;

        /* inet_ntoa is not mt-safe */
        lock=s_write_lock(LOCK_INET);
        /* Socket APIs expose concrete addresses through struct sockaddr. */
        (void)strncpy(host,
            /* cppcheck-suppress misra-c2012-11.3 */
            inet_ntoa(((const struct sockaddr_in *)sa)->sin_addr), hostlen);
        s_unlock(lock);
        host[hostlen-1U]='\0';
#endif /* USE_IPV6 */
    }

    /* sin_port is in the same place both in sockaddr_in and sockaddr_in6 */
    if(serv && servlen) {
        /* Socket APIs expose concrete addresses through struct sockaddr. */
        (void)snprintf(serv, servlen, "%u",
            /* cppcheck-suppress misra-c2012-11.3 */
            ntohs(((const struct sockaddr_in *)sa)->sin_port));
    }
    return 0;
}
#endif

/* end of resolver.c */
