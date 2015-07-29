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

/**************************************** prototypes */

NOEXPORT void addrlist2addr(SOCKADDR_UNION *, SOCKADDR_LIST *);
NOEXPORT void addrlist_init(SOCKADDR_LIST *);

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

NOEXPORT int getaddrinfo(const char *, const char *,
    const struct addrinfo *, struct addrinfo **);
NOEXPORT int alloc_addresses(struct hostent *, const struct addrinfo *,
    u_short port, struct addrinfo **, struct addrinfo **);
NOEXPORT void freeaddrinfo(struct addrinfo *);

#endif /* !defined HAVE_GETADDRINFO */

/**************************************** resolver initialization */

#if defined(USE_WIN32) && !defined(_WIN32_WCE)
GETADDRINFO s_getaddrinfo;
FREEADDRINFO s_freeaddrinfo;
GETNAMEINFO s_getnameinfo;
#endif

void resolver_init() {
#if defined(USE_WIN32) && !defined(_WIN32_WCE)
    HINSTANCE handle;

        /* IPv6 in Windows XP or higher */
    handle=LoadLibrary(TEXT("ws2_32.dll"));
    if(handle) {
        s_getaddrinfo=(GETADDRINFO)GetProcAddress(handle, "getaddrinfo");
        s_freeaddrinfo=(FREEADDRINFO)GetProcAddress(handle, "freeaddrinfo");
        s_getnameinfo=(GETNAMEINFO)GetProcAddress(handle, "getnameinfo");
        if(s_getaddrinfo && s_freeaddrinfo && s_getnameinfo)
            return; /* IPv6 detected -> OK */
        FreeLibrary(handle);
    }

        /* experimental IPv6 for Windows 2000 */
    handle=LoadLibrary(TEXT("wship6.dll"));
    if(handle) {
        s_getaddrinfo=(GETADDRINFO)GetProcAddress(handle, "getaddrinfo");
        s_freeaddrinfo=(FREEADDRINFO)GetProcAddress(handle, "freeaddrinfo");
        s_getnameinfo=(GETNAMEINFO)GetProcAddress(handle, "getnameinfo");
        if(s_getaddrinfo && s_freeaddrinfo && s_getnameinfo)
            return; /* IPv6 detected -> OK */
        FreeLibrary(handle);
    }

        /* fall back to the built-in emulation */
    s_getaddrinfo=NULL;
    s_freeaddrinfo=NULL;
    s_getnameinfo=NULL;
#endif
}

/**************************************** stunnel resolver API */

unsigned name2addr(SOCKADDR_UNION *addr, char *name,
        char *default_host) {
    SOCKADDR_LIST *addr_list;
    unsigned retval;

    addr_list=str_alloc(sizeof(SOCKADDR_LIST));
    addrlist_clear(addr_list);
    retval=name2addrlist(addr_list, name, default_host);
    if(retval)
        addrlist2addr(addr, addr_list);
    str_free(addr_list->addr);
    str_free(addr_list);
    return retval;
}

unsigned hostport2addr(SOCKADDR_UNION *addr,
        char *host_name, char *port_name) {
    SOCKADDR_LIST *addr_list;
    unsigned retval;

    addr_list=str_alloc(sizeof(SOCKADDR_LIST));
    addrlist_clear(addr_list);
    retval=hostport2addrlist(addr_list, host_name, port_name);
    if(retval)
        addrlist2addr(addr, addr_list);
    str_free(addr_list->addr);
    str_free(addr_list);
    return retval;
}

NOEXPORT void addrlist2addr(SOCKADDR_UNION *addr, SOCKADDR_LIST *addr_list) {
    unsigned i;

    for(i=0; i<addr_list->num; ++i) { /* find the first IPv4 address */
        if(addr_list->addr[i].in.sin_family==AF_INET) {
            memcpy(addr, &addr_list->addr[i], sizeof(SOCKADDR_UNION));
            return;
        }
    }
#ifdef USE_IPv6
    for(i=0; i<addr_list->num; ++i) { /* find the first IPv6 address */
        if(addr_list->addr[i].in.sin_family==AF_INET6) {
            memcpy(addr, &addr_list->addr[i], sizeof(SOCKADDR_UNION));
            return;
        }
    }
#endif
    /* copy the first address resolved (curently AF_UNIX) */
    memcpy(addr, &addr_list->addr[0], sizeof(SOCKADDR_UNION));
}

unsigned name2addrlist(SOCKADDR_LIST *addr_list,
        char *name, char *default_host) {
    char *tmp, *host_name, *port_name;
    unsigned retval;

    /* first check if this is a UNIX socket */
#ifdef HAVE_STRUCT_SOCKADDR_UN
    if(*name=='/') {
        if(offsetof(struct sockaddr_un, sun_path)+strlen(name)+1
                > sizeof(struct sockaddr_un)) {
            s_log(LOG_ERR, "Unix socket path is too long");
            return 0; /* no results */
        }
        addr_list->addr=str_realloc(addr_list->addr,
            (addr_list->num+1)*sizeof(SOCKADDR_UNION));
        addr_list->addr[addr_list->num].un.sun_family=AF_UNIX;
        strcpy(addr_list->addr[addr_list->num].un.sun_path, name);
        return ++(addr_list->num); /* ok - return the number of addresses */
    }
#endif

    /* setup host_name and port_name */
    tmp=str_dup(name);
    port_name=strrchr(tmp, ':');
    if(port_name) {
        host_name=tmp;
        *port_name++='\0';
    } else { /* no ':' - use default host IP */
        host_name=default_host;
        port_name=tmp;
    }

    /* fill addr_list structure */
    retval=hostport2addrlist(addr_list, host_name, port_name);
    str_free(tmp);
    return retval;
}

unsigned hostport2addrlist(SOCKADDR_LIST *addr_list,
        char *host_name, char *port_name) {
    struct addrinfo hints, *res=NULL, *cur;
    int err, retries=0;

    memset(&hints, 0, sizeof hints);
#if defined(USE_IPv6) || defined(USE_WIN32)
    hints.ai_family=PF_UNSPEC;
#else
    hints.ai_family=PF_INET;
#endif
    hints.ai_socktype=SOCK_STREAM;
    hints.ai_protocol=IPPROTO_TCP;
    for(;;) {
        err=getaddrinfo(host_name, port_name, &hints, &res);
        if(err && res)
            freeaddrinfo(res);
        if(err!=EAI_AGAIN || ++retries>=3)
            break;
        s_log(LOG_DEBUG, "getaddrinfo: EAI_AGAIN received: retrying");
        sleep(1);
    }
    switch(err) {
    case 0:
        break; /* success */
    case EAI_SERVICE:
        s_log(LOG_ERR, "Unknown TCP service \"%s\"", port_name);
        return 0; /* error */
    default:
        s_log(LOG_ERR, "Error resolving \"%s\": %s",
            host_name, s_gai_strerror(err));
        return 0; /* error */
    }

    /* copy the list of addresses */
    for(cur=res; cur; cur=cur->ai_next) {
        if(cur->ai_addrlen>(int)sizeof(SOCKADDR_UNION)) {
            s_log(LOG_ERR, "INTERNAL ERROR: ai_addrlen value too big");
            freeaddrinfo(res);
            return 0; /* no results */
        }
        addr_list->addr=str_realloc(addr_list->addr,
            (addr_list->num+1)*sizeof(SOCKADDR_UNION));
        memcpy(&addr_list->addr[addr_list->num], cur->ai_addr,
            (size_t)cur->ai_addrlen);
        ++(addr_list->num);
    }
    freeaddrinfo(res);
    return addr_list->num; /* ok - return the number of addresses */
}

void addrlist_clear(SOCKADDR_LIST *addr_list) {
    addrlist_init(addr_list);
    addr_list->names=NULL;
}

NOEXPORT void addrlist_init(SOCKADDR_LIST *addr_list) {
    addr_list->num=0;
    addr_list->addr=NULL;
    addr_list->rr_val=0; /* reset round-robin counter */
    /* allow structures created with sockaddr_dup() to modify
     * the original rr_val rather than its local copy */
    addr_list->rr_ptr=&addr_list->rr_val;
}

unsigned addrlist_dup(SOCKADDR_LIST *dst, const SOCKADDR_LIST *src) {
    memcpy(dst, src, sizeof(SOCKADDR_LIST));
    if(src->num) { /* already resolved */
        dst->addr=str_alloc(src->num*sizeof(SOCKADDR_UNION));
        memcpy(dst->addr, src->addr, src->num*sizeof(SOCKADDR_UNION));
    } else { /* delayed resolver */
        addrlist_resolve(dst);
    }
    return dst->num;
}

unsigned addrlist_resolve(SOCKADDR_LIST *addr_list) {
    unsigned num=0, rnd;
    NAME_LIST *host;

    addrlist_init(addr_list);
    for(host=addr_list->names; host; host=host->next)
        num+=name2addrlist(addr_list, host->name, DEFAULT_LOOPBACK);
    if(num>1) { /* randomize the initial value of round-robin counter */
        /* ignore the error value and the distribution bias */
        RAND_bytes((unsigned char *)&rnd, sizeof rnd);
        addr_list->rr_val=rnd%num;
    }
    return num;
}

char *s_ntop(SOCKADDR_UNION *addr, socklen_t addrlen) {
    int err;
    char *host, *port, *retval;

    if(addrlen==sizeof(u_short)) /* see UNIX(7) manual for details */
        return str_dup("unnamed socket");
    host=str_alloc(256);
    port=str_alloc(256); /* needs to be long enough for AF_UNIX path */
    err=getnameinfo(&addr->sa, addrlen,
        host, 256, port, 256, NI_NUMERICHOST|NI_NUMERICSERV);
    if(err) {
        s_log(LOG_ERR, "getnameinfo: %s", s_gai_strerror(err));
        retval=str_dup("unresolvable address");
    } else
        retval=str_printf("%s:%s", host, port);
    str_free(host);
    str_free(port);
    return retval;
}

socklen_t addr_len(const SOCKADDR_UNION *addr) {
    if(addr->sa.sa_family==AF_INET)
        return sizeof(struct sockaddr_in);
#ifdef USE_IPv6
    if(addr->sa.sa_family==AF_INET6)
        return sizeof(struct sockaddr_in6);
#endif
#ifdef HAVE_STRUCT_SOCKADDR_UN
    if(addr->sa.sa_family==AF_UNIX)
        return sizeof(struct sockaddr_un);
#endif
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
    struct addrinfo *ai;
    int retval;
    char *tmpstr;

#if defined(USE_WIN32) && !defined(_WIN32_WCE)
    if(s_getaddrinfo)
        return s_getaddrinfo(node, service, hints, res);
#endif
    /* decode service name */
    port=htons((u_short)strtol(service, &tmpstr, 10));
    if(tmpstr==service || *tmpstr) { /* not a number */
#ifdef _WIN32_WCE
        return EAI_NONAME;
#else /* defined(_WIN32_WCE) */
        p=getservbyname(service, "tcp");
        if(!p)
            return EAI_NONAME;
        port=(u_short)p->s_port;
#endif /* defined(_WIN32_WCE) */
    }

    /* allocate addrlist structure */
    ai=str_alloc(sizeof(struct addrinfo));
    if(hints)
        memcpy(ai, hints, sizeof(struct addrinfo));

    /* try to decode numerical address */
#if defined(USE_IPv6) && !defined(USE_WIN32)
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
    ((struct sockaddr_in *)ai->ai_addr)->sin_addr.s_addr=inet_addr(node);
    if(((struct sockaddr_in *)ai->ai_addr)->sin_addr.s_addr+1) {
    /* (signed)((struct sockaddr_in *)ai->ai_addr)->sin_addr.s_addr!=-1 */
#endif
        ((struct sockaddr_in *)ai->ai_addr)->sin_port=port;
        *res=ai;
        return 0; /* numerical address resolved */
    }
    str_free(ai->ai_addr);
    str_free(ai);

    /* not numerical: need to call resolver library */
    *res=NULL;
    ai=NULL;
    enter_critical_section(CRIT_INET);
#ifdef HAVE_GETHOSTBYNAME2
    h=gethostbyname2(node, AF_INET6);
    if(h) /* some IPv6 addresses found */
        alloc_addresses(h, hints, port, res, &ai); /* ignore the error */
#endif
    h=gethostbyname(node); /* get list of addresses */
    if(h)
        retval=ai ?
            alloc_addresses(h, hints, port, &ai->ai_next, &ai) :
            alloc_addresses(h, hints, port, res, &ai);
    else if(!*res)
        retval=EAI_NONAME; /* no results */
    else
        retval=0;
#ifdef HAVE_ENDHOSTENT
    endhostent();
#endif
    leave_critical_section(CRIT_INET);
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
            memcpy(ai, hints, sizeof(struct addrinfo));
        ai->ai_next=NULL; /* just in case */
        if(*tail) { /* list not empty: add a node */
            (*tail)->ai_next=ai;
            *tail=ai;
        } else { /* list empty: create it */
            *head=ai;
            *tail=ai;
        }
        ai->ai_family=h->h_addrtype;
#if defined(USE_IPv6)
        if(h->h_addrtype==AF_INET6) {
            ai->ai_addrlen=sizeof(struct sockaddr_in6);
            ai->ai_addr=str_alloc((size_t)ai->ai_addrlen);
            memcpy(&((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr,
                h->h_addr_list[i], (size_t)h->h_length);
        } else
#endif
        {
            ai->ai_addrlen=sizeof(struct sockaddr_in);
            ai->ai_addr=str_alloc((size_t)ai->ai_addrlen);
            memcpy(&((struct sockaddr_in *)ai->ai_addr)->sin_addr,
                h->h_addr_list[i], (size_t)h->h_length);
        }
        ai->ai_addr->sa_family=(u_short)h->h_addrtype;
        /* offsets of sin_port and sin6_port should be the same */
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
#if defined(USE_IPv6) && !defined(USE_WIN32)
        inet_ntop(sa->sa_family, sa->sa_family==AF_INET6 ?
                (void *)&((struct sockaddr_in6 *)sa)->sin6_addr :
                (void *)&((struct sockaddr_in *)sa)->sin_addr,
            host, hostlen);
#else /* USE_IPv6 */
        enter_critical_section(CRIT_INET); /* inet_ntoa is not mt-safe */
        strncpy(host, inet_ntoa(((struct sockaddr_in *)sa)->sin_addr),
            hostlen);
        leave_critical_section(CRIT_INET);
        host[hostlen-1]='\0';
#endif /* USE_IPv6 */
    }
    if(serv && servlen)
        sprintf(serv, "%u", ntohs(((struct sockaddr_in *)sa)->sin_port));
    /* sin_port is in the same place both in sockaddr_in and sockaddr_in6 */
    /* ignore servlen since it's long enough in stunnel code */
    return 0;
}
#endif

/* end of resolver.c */
