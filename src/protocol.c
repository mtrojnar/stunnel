/*
 *   stunnel       TLS offloading and load-balancing proxy
 *   Copyright (C) 1998-2021 Michal Trojnara <Michal.Trojnara@stunnel.org>
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

#define is_prefix(a, b) (strncasecmp((a), (b), strlen(b))==0)

/* protocol-specific function prototypes */
NOEXPORT char *socks_client(CLI *, SERVICE_OPTIONS *, const PHASE);
NOEXPORT void socks5_client_method(CLI *);
NOEXPORT void socks5_client_address(CLI *);
NOEXPORT char *socks_server(CLI *, SERVICE_OPTIONS *, const PHASE);
NOEXPORT void socks4_server(CLI *);
NOEXPORT void socks5_server_method(CLI *);
NOEXPORT void socks5_server(CLI *);
NOEXPORT int validate(CLI *);
NOEXPORT char *proxy_server(CLI *, SERVICE_OPTIONS *, const PHASE);
NOEXPORT char *cifs_client(CLI *, SERVICE_OPTIONS *, const PHASE);
NOEXPORT char *cifs_server(CLI *, SERVICE_OPTIONS *, const PHASE);
NOEXPORT char *pgsql_client(CLI *, SERVICE_OPTIONS *, const PHASE);
NOEXPORT char *pgsql_server(CLI *, SERVICE_OPTIONS *, const PHASE);
NOEXPORT char *smtp_client(CLI *, SERVICE_OPTIONS *, const PHASE);
NOEXPORT void smtp_client_negotiate(CLI *);
NOEXPORT void smtp_client_plain(CLI *, const char *, const char *);
NOEXPORT void smtp_client_login(CLI *, const char *, const char *);
NOEXPORT char *smtp_server(CLI *, SERVICE_OPTIONS *, const PHASE);
NOEXPORT char *pop3_client(CLI *, SERVICE_OPTIONS *, const PHASE);
NOEXPORT char *pop3_server(CLI *, SERVICE_OPTIONS *, const PHASE);
NOEXPORT char *imap_client(CLI *, SERVICE_OPTIONS *, const PHASE);
NOEXPORT char *imap_server(CLI *, SERVICE_OPTIONS *, const PHASE);
NOEXPORT char *nntp_client(CLI *, SERVICE_OPTIONS *, const PHASE);
NOEXPORT char *ldap_client(CLI *, SERVICE_OPTIONS *, const PHASE);
NOEXPORT char *connect_server(CLI *, SERVICE_OPTIONS *, const PHASE);
NOEXPORT char *connect_client(CLI *, SERVICE_OPTIONS *, const PHASE);
#ifndef OPENSSL_NO_MD4
NOEXPORT void ntlm(CLI *, SERVICE_OPTIONS *);
NOEXPORT char *ntlm1();
NOEXPORT char *ntlm3(char *, char *, char *, char *);
NOEXPORT void crypt_DES(DES_cblock, DES_cblock, DES_cblock);
#endif
NOEXPORT char *base64(int, const char *, int);

/**************************************** framework */

char *protocol(CLI *c, SERVICE_OPTIONS *opt, const PHASE phase) {
    if(phase==PROTOCOL_CHECK) /* default to be overridden by protocols */
        opt->option.connect_before_ssl=opt->option.client;
    if(!opt->protocol) /* no protocol specified */
        return NULL; /* skip further actions */
    if(!strcasecmp(opt->protocol, "socks"))
        return opt->option.client ?
            socks_client(c, opt, phase) :
            socks_server(c, opt, phase);
    if(!strcasecmp(opt->protocol, "proxy"))
        return opt->option.client ?
            "The 'proxy' protocol is not supported in the client mode" :
            proxy_server(c, opt, phase);
    if(!strcasecmp(opt->protocol, "cifs"))
        return opt->option.client ?
            cifs_client(c, opt, phase) :
            cifs_server(c, opt, phase);
    if(!strcasecmp(opt->protocol, "pgsql"))
        return opt->option.client ?
            pgsql_client(c, opt, phase) :
            pgsql_server(c, opt, phase);
    if(!strcasecmp(opt->protocol, "smtp"))
        return opt->option.client ?
            smtp_client(c, opt, phase) :
            smtp_server(c, opt, phase);
    if(!strcasecmp(opt->protocol, "pop3"))
        return opt->option.client ?
            pop3_client(c, opt, phase) :
            pop3_server(c, opt, phase);
    if(!strcasecmp(opt->protocol, "imap"))
        return opt->option.client ?
            imap_client(c, opt, phase) :
            imap_server(c, opt, phase);
    if(!strcasecmp(opt->protocol, "nntp"))
        return opt->option.client ?
            nntp_client(c, opt, phase) :
            "The 'nntp' protocol is not supported in the server mode";
    if(!strcasecmp(opt->protocol, "ldap"))
        return opt->option.client ?
            ldap_client(c, opt, phase) :
            "The 'ldap' protocol is not supported in the server mode";
    if(!strcasecmp(opt->protocol, "connect"))
        return opt->option.client ?
            connect_client(c, opt, phase) :
            connect_server(c, opt, phase);
    return "Protocol not supported";
}

/**************************************** socks */

/* SOCKS over TLS (SOCKS protocol itself is also encrypted) */

typedef union {
    struct {
        uint8_t ver, cmd, rsv, atyp;
    } req;
    struct {
        uint8_t ver, rep, rsv, atyp;
    } resp;
    struct {
        uint8_t ver, code, rsv, atyp, addr[4], port[2];
    } v4;
    struct {
        uint8_t ver, code, rsv, atyp, addr[16], port[2];
    } v6;
} SOCKS5_UNION;

NOEXPORT char *socks_client(CLI *c, SERVICE_OPTIONS *opt, const PHASE phase) {
    (void)opt; /* squash the unused parameter warning */
    if(phase!=PROTOCOL_LATE)
        return NULL;
    socks5_client_method(c);
    socks5_client_address(c);
    return NULL;
}

NOEXPORT void socks5_client_method(CLI *c) {
    const struct {
        uint8_t ver, nmethods, method;
    } req={5, 1, 0x00}; /* NO AUTHENTICATION REQUIRED */
    struct {
        uint8_t ver, method;
    } resp;

    s_ssl_write(c, &req, sizeof req);

    s_ssl_read(c, &resp, sizeof resp);
    if(resp.ver!=5) {
        s_log(LOG_ERR, "Invalid SOCKS5 message version 0x%02x", resp.ver);
        throw_exception(c, 2); /* don't reset */
    }
    /* TODO: add USERNAME/PASSWORD authentication */
    if(resp.method!=0x00) {
        s_log(LOG_ERR, "No supported SOCKS5 authentication method received");
        throw_exception(c, 2); /* don't reset */
    }
}

NOEXPORT void socks5_client_address(CLI *c) {
    SOCKADDR_UNION addr;
    SOCKS5_UNION socks;

    if(original_dst(c->local_rfd.fd, &addr))
        throw_exception(c, 2); /* don't reset */
    memset(&socks, 0, sizeof socks);
    socks.req.ver=5; /* SOCKS5 */
    socks.req.cmd=0x01; /* CONNECT */
    switch(addr.sa.sa_family) {
    case AF_INET:
        socks.req.atyp=0x01; /* IP v4 address */
        memcpy(&socks.v4.addr, &addr.in.sin_addr, 4);
        memcpy(&socks.v4.port, &addr.in.sin_port, 2);
        s_log(LOG_INFO, "Sending SOCKS5 IPv4 address");
        s_ssl_write(c, &socks, sizeof socks.v4);
        break;
#ifdef USE_IPv6
    case AF_INET6:
        socks.req.atyp=0x04; /* IP v6 address */
        memcpy(&socks.v6.addr, &addr.in6.sin6_addr, 16);
        memcpy(&socks.v6.port, &addr.in6.sin6_port, 2);
        s_log(LOG_INFO, "Sending SOCKS5 IPv6 address");
        s_ssl_write(c, &socks, sizeof socks.v6);
        break;
#endif
    default:
        s_log(LOG_ERR, "Unsupported address type 0x%02x", addr.sa.sa_family);
        throw_exception(c, 2); /* don't reset */
    }

    s_ssl_read(c, &socks, sizeof socks.resp);
    if(socks.resp.atyp==0x04) /* IP V6 address */
        s_ssl_read(c, &socks.v6.addr, 16+2);
    else
        s_ssl_read(c, &socks.v4.addr, 4+2);
    if(socks.resp.ver!=5) {
        s_log(LOG_ERR, "Invalid SOCKS5 message version 0x%02x", socks.req.ver);
        throw_exception(c, 2); /* don't reset */
    }
    switch(socks.resp.rep) {
        case 0x00:
            s_log(LOG_INFO,
                "SOCKS5 request succeeded");
            return; /* SUCCESS */
        case 0x01:
            s_log(LOG_ERR,
                "SOCKS5 request failed: General SOCKS server failure");
            break;
        case 0x02:
            s_log(LOG_ERR,
                "SOCKS5 request failed: Connection not allowed by ruleset");
            break;
        case 0x03:
            s_log(LOG_ERR,
                "SOCKS5 request failed: Network unreachable");
            break;
        case 0x04:
            s_log(LOG_ERR,
                "SOCKS5 request failed: Host unreachable");
            break;
        case 0x05:
            s_log(LOG_ERR,
                "SOCKS5 request failed: Connection refused");
            break;
        case 0x06:
            s_log(LOG_ERR,
                "SOCKS5 request failed: TTL expired");
            break;
        case 0x07:
            s_log(LOG_ERR,
                "SOCKS5 request failed: Command not supported");
            break;
        case 0x08:
            s_log(LOG_ERR,
                "SOCKS5 request failed: Address type not supported");
            break;
        default:
            s_log(LOG_ERR,
                "SOCKS5 request failed: Unknown error 0x%02x", socks.resp.rep);
    }
    throw_exception(c, 2); /* don't reset */
}

NOEXPORT char *socks_server(CLI *c, SERVICE_OPTIONS *opt, const PHASE phase) {
    uint8_t version;

    switch(phase) {
    case PROTOCOL_CHECK:
        opt->option.protocol_endpoint=1;
        break;
    case PROTOCOL_MIDDLE:
        s_log(LOG_DEBUG, "Waiting for the SOCKS request");
        s_ssl_read(c, &version, sizeof version);
        switch(version) {
        case 4:
            socks4_server(c);
            break;
        case 5:
            socks5_server_method(c);
            socks5_server(c);
            break;
        default:
            s_log(LOG_ERR, "Unsupported SOCKS version 0x%02x", version);
            throw_exception(c, 1);
        }
        break;
    case PROTOCOL_LATE:
        /* TODO: send the SOCKS reply *after* the target is connected */
        /* FIXME: the SOCKS replies do not report CONNECT failures */
        /* FIXME: the SOCKS replies do not contain the bound IP address */
        break;
    default:
        break;
    }
    return NULL;
}

/* SOCKS4 or SOCKS4a */
/* BIND command is not supported */
/* USERID parameter is ignored */

NOEXPORT void socks4_server(CLI *c) {
    struct {
        uint8_t vn, cd;
        u_short sin_port;
        struct in_addr sin_addr;
    } socks;
    char *user_name, *host_name, *port_name;
    SOCKADDR_UNION addr;
    int close_connection=1;

    s_ssl_read(c, &socks.cd, sizeof socks-sizeof socks.vn);
    socks.vn=0; /* response version 0 */
    user_name=ssl_getstring(c); /* ignore the username */
    str_free(user_name);

    if(socks.cd==0x01) { /* CONNECT */
        if(ntohl(socks.sin_addr.s_addr)>0 &&
                ntohl(socks.sin_addr.s_addr)<256) { /* 0.0.0.x */
            host_name=ssl_getstring(c);
            port_name=str_printf("%u", ntohs(socks.sin_port));
            hostport2addrlist(&c->connect_addr, host_name, port_name);
            str_free(port_name);
            if(c->connect_addr.num) {
                s_log(LOG_INFO, "SOCKS4a resolved \"%s\" to %u host(s)",
                    host_name, c->connect_addr.num);
                if(validate(c)) {
                    socks.cd=90; /* access granted */
                    close_connection=0;
                } else {
                    socks.cd=91; /* rejected */
                }
            } else {
                s_log(LOG_ERR, "SOCKS4a failed to resolve \"%s\"", host_name);
                socks.cd=91; /* failed */
            }
            str_free(host_name);
        } else {
            c->connect_addr.num=1;
            c->connect_addr.addr=str_alloc(sizeof(SOCKADDR_UNION));
            c->connect_addr.addr[0].in.sin_family=AF_INET;
            c->connect_addr.addr[0].in.sin_port=socks.sin_port;
            c->connect_addr.addr[0].in.sin_addr.s_addr=socks.sin_addr.s_addr;
            s_log(LOG_INFO, "SOCKS4 address received");
            if(validate(c)) {
                socks.cd=90; /* access granted */
                close_connection=0;
            } else {
                socks.cd=91; /* rejected */
            }
        }
    } else if(socks.cd==0xf0) { /* RESOLVE (a TOR extension) */
        host_name=ssl_getstring(c);
        if(hostport2addr(&addr, host_name, "0", 0) && addr.sa.sa_family==AF_INET) {
            memcpy(&socks.sin_addr, &addr.in.sin_addr, 4);
            s_log(LOG_INFO, "SOCKS4a/TOR resolved \"%s\"", host_name);
            socks.cd=90; /* access granted */
        } else {
            s_log(LOG_ERR, "SOCKS4a/TOR failed to resolve \"%s\"", host_name);
            socks.cd=91; /* failed */
        }
        str_free(host_name);
    } else {
        s_log(LOG_ERR, "Unsupported SOCKS4/SOCKS4a command 0x%02x", socks.cd);
        socks.cd=91; /* failed */
    }
    s_ssl_write(c, &socks, sizeof socks);
    if(close_connection)
        throw_exception(c, 2); /* don't reset */
}

NOEXPORT void socks5_server_method(CLI *c) {
    uint8_t nmethods, *methods;
    struct {
        uint8_t ver, method;
    } response;
    int i;

    response.ver=0x05;
    response.method=0xff; /* NO ACCEPTABLE METHODS */
    s_ssl_read(c, &nmethods, sizeof nmethods);
    methods=str_alloc(nmethods);
    s_ssl_read(c, methods, nmethods);
    for(i=0; i<nmethods; ++i)
        if(methods[i]==0x00) { /* NO AUTHENTICATION REQUIRED */
            response.method=0x00; /* use this method */
            break;
        }
    str_free(methods);
    s_ssl_write(c, &response, sizeof response);
    if(response.method) { /* request failed */
        s_log(LOG_ERR, "No supported SOCKS5 authentication method received");
        throw_exception(c, 2); /* don't reset */
    }
}

/* CONNECT does not return valid BND.ADDR and BND.PORT values */

NOEXPORT void socks5_server(CLI *c) {
    SOCKS5_UNION socks;
    uint8_t host_len;
    char *host_name, *port_name;
    u_short port_number;
    SOCKADDR_UNION addr;
    int close_connection=1;

    /* parse request */
    memset(&socks, 0, sizeof socks);
    s_ssl_read(c, &socks, sizeof socks.req);
    if(socks.req.ver!=0x05) {
        s_log(LOG_ERR, "Invalid SOCKS5 message version 0x%02x", socks.req.ver);
        socks.resp.ver=0x05; /* response version 5 */
        socks.resp.rep=0x01; /* general SOCKS server failure */
    } else if(socks.req.cmd==0x01) { /* CONNECT */
        if(socks.req.atyp==0x01) { /* IP v4 address */
            c->connect_addr.num=1;
            c->connect_addr.addr=str_alloc(sizeof(SOCKADDR_UNION));
            c->connect_addr.addr[0].in.sin_family=AF_INET;
            s_ssl_read(c, &socks.v4.addr, 4+2);
            memcpy(&c->connect_addr.addr[0].in.sin_addr, &socks.v4.addr, 4);
            memcpy(&c->connect_addr.addr[0].in.sin_port, &socks.v4.port, 2);
            s_log(LOG_INFO, "SOCKS5 IPv4 address received");
            if(validate(c)) {
                socks.resp.rep=0x00; /* succeeded */
                close_connection=0;
            } else {
                socks.resp.rep=0x02; /* connection not allowed by ruleset */
            }
        } else if(socks.req.atyp==0x03) { /* DOMAINNAME */
            s_ssl_read(c, &host_len, sizeof host_len);
            host_name=str_alloc((size_t)host_len+1);
            s_ssl_read(c, host_name, host_len);
            host_name[host_len]='\0';
            s_ssl_read(c, &port_number, 2);
            port_name=str_printf("%u", ntohs(port_number));
            hostport2addrlist(&c->connect_addr, host_name, port_name);
            str_free(port_name);
            if(c->connect_addr.num) {
                s_log(LOG_INFO, "SOCKS5 resolved \"%s\" to %u host(s)",
                    host_name, c->connect_addr.num);
                if(validate(c)) {
                    socks.resp.rep=0x00; /* succeeded */
                    close_connection=0;
                } else {
                    socks.resp.rep=0x02; /* connection not allowed by ruleset */
                }
            } else {
                s_log(LOG_ERR, "SOCKS5 failed to resolve \"%s\"", host_name);
                socks.resp.rep=0x04; /* Host unreachable */
            }
            str_free(host_name);
#ifdef USE_IPv6
        } else if(socks.req.atyp==0x04) { /* IP v6 address */
            c->connect_addr.num=1;
            c->connect_addr.addr=str_alloc(sizeof(SOCKADDR_UNION));
            c->connect_addr.addr[0].in6.sin6_family=AF_INET6;
            s_ssl_read(c, &socks.v6.addr, 16+2);
            memcpy(&c->connect_addr.addr[0].in6.sin6_addr, &socks.v6.addr, 16);
            memcpy(&c->connect_addr.addr[0].in6.sin6_port, &socks.v6.port, 2);
            s_log(LOG_INFO, "SOCKS5 IPv6 address received");
            if(validate(c)) {
                socks.resp.rep=0x00; /* succeeded */
                close_connection=0;
            } else {
                socks.resp.rep=0x02; /* connection not allowed by ruleset */
            }
#endif
        } else {
            s_log(LOG_ERR,
                "Unsupported SOCKS5 address type 0x%02x", socks.req.atyp);
            socks.resp.rep=0x07; /* Address type not supported */
        }
    } else if(socks.req.cmd==0xf0) { /* RESOLVE (a TOR extension) */
        s_ssl_read(c, &host_len, sizeof host_len);
        host_name=str_alloc((size_t)host_len+1);
        s_ssl_read(c, host_name, host_len);
        host_name[host_len]='\0';
        s_ssl_read(c, &port_number, 2);
        port_name=str_printf("%u", ntohs(port_number));
        if(hostport2addr(&addr, host_name, port_name, 0)) {
            if(addr.sa.sa_family==AF_INET) {
                s_log(LOG_INFO, "SOCKS5/TOR resolved \"%s\" to IPv4", host_name);
                memcpy(&socks.v4.addr, &addr.in.sin_addr, 4);
                socks.resp.atyp=0x01; /* IP v4 address */
                socks.resp.rep=0x00; /* succeeded */
#ifdef USE_IPv6
            } else if(addr.sa.sa_family==AF_INET6) {
                s_log(LOG_INFO, "SOCKS5/TOR resolved \"%s\" to IPv6", host_name);
                memcpy(&socks.v6.addr, &addr.in6.sin6_addr, 16);
                socks.resp.atyp=0x04; /* IP v6 address */
                socks.resp.rep=0x00; /* succeeded */
#endif
            } else {
                s_log(LOG_ERR, "SOCKS5/TOR unsupported address type for \"%s\"",
                    host_name);
                socks.resp.rep=0x04; /* Host unreachable */
            }
        } else {
            s_log(LOG_ERR, "SOCKS5/TOR failed to resolve \"%s\"", host_name);
            socks.resp.rep=0x04; /* Host unreachable */
        }
        str_free(host_name);
        str_free(port_name);
    } else {
        s_log(LOG_ERR, "Unsupported SOCKS5 command 0x%02x", socks.req.cmd);
        socks.resp.rep=0x07; /* Command not supported */
    }

    /* send response */
    /* broken clients tend to expect the same address family for response,
     * so stunnel tries to preserve the address family if possible */
    if(socks.resp.atyp==0x04) { /* IP V6 address */
        s_ssl_write(c, &socks, sizeof socks.v6);
    } else {
        socks.resp.atyp=0x01; /* IP v4 address */
        s_ssl_write(c, &socks, sizeof socks.v4);
    }
    if(close_connection) /* request failed */
        throw_exception(c, 2); /* don't reset */
}

/* validate the allocated address */
NOEXPORT int validate(CLI *c) {
#ifdef USE_IPv6
    const unsigned char ipv6_loopback[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
#endif
    unsigned i;

    for(i=0; i<c->connect_addr.num; ++i) {
        SOCKADDR_UNION *addr=&c->connect_addr.addr[i];
#ifdef USE_IPv6
        if(addr->sa.sa_family==AF_INET6) {
            if(!memcmp(&addr->in6.sin6_addr, ipv6_loopback, 16)) {
                s_log(LOG_ERR,
                    "SOCKS connection to the IPv6 loopback rejected");
                return 0;
            }
            /* TODO: implement more checks */
        } else
#endif
        if(addr->sa.sa_family==AF_INET) {
            if((ntohl(addr->in.sin_addr.s_addr)&0xff000000)==0x7f000000) {
                s_log(LOG_ERR,
                    "SOCKS connection to the IPv4 loopback rejected");
                return 0;
            }
            /* TODO: implement more checks */
        } else {
            s_log(LOG_ERR, "Unsupported address type 0x%02x",
                addr->sa.sa_family);
            return 0;
        }
    }
    return 1;
}

/**************************************** proxy */

/*
 * PROXY protocol: http://haproxy.1wt.eu/download/1.5/doc/proxy-protocol.txt
 * this is a protocol client support for stunnel acting as an TLS server
 * I don't think anything else is useful, but feel free to discuss on the
 * stunnel-users mailing list if you disagree
 */

/* IP address textual representation length */
/* 1234:6789:1234:6789:1234:6789:1234:6789 -> 40 chars with '\0' */
#define IP_LEN 40
#define PORT_LEN 6

NOEXPORT char *proxy_server(CLI *c, SERVICE_OPTIONS *opt, const PHASE phase) {
    SOCKADDR_UNION addr;
    socklen_t addrlen;
    char src_host[IP_LEN], dst_host[IP_LEN];
    char src_port[PORT_LEN], dst_port[PORT_LEN], *proto;
    int err;

    (void)opt; /* squash the unused parameter warning */
    if(phase!=PROTOCOL_LATE)
        return NULL;
    addrlen=sizeof addr;
    if(getpeername(c->local_rfd.fd, &addr.sa, &addrlen)) {
        sockerror("getpeername");
        throw_exception(c, 1);
    }
    err=getnameinfo(&addr.sa, addr_len(&addr), src_host, IP_LEN,
        src_port, PORT_LEN, NI_NUMERICHOST|NI_NUMERICSERV);
    if(err) {
        s_log(LOG_ERR, "getnameinfo: %s", s_gai_strerror(err));
        throw_exception(c, 1);
    }

    addrlen=sizeof addr;
    if(getsockname(c->local_rfd.fd, &addr.sa, &addrlen)) {
        sockerror("getsockname");
        throw_exception(c, 1);
    }
    err=getnameinfo(&addr.sa, addr_len(&addr), dst_host, IP_LEN,
        dst_port, PORT_LEN, NI_NUMERICHOST|NI_NUMERICSERV);
    if(err) {
        s_log(LOG_ERR, "getnameinfo: %s", s_gai_strerror(err));
        throw_exception(c, 1);
    }

    switch(addr.sa.sa_family) {
    case AF_INET:
        proto="TCP4";
        break;
#ifdef USE_IPv6
    case AF_INET6:
        proto="TCP6";
        break;
#endif
    default: /* AF_UNIX */
        proto="UNKNOWN";
    }
    fd_printf(c, c->remote_fd.fd, "PROXY %s %s %s %s %s",
        proto, src_host, dst_host, src_port, dst_port);
    return NULL;
}

/**************************************** cifs */

NOEXPORT char *cifs_client(CLI *c, SERVICE_OPTIONS *opt, const PHASE phase) {
    uint8_t buffer[5];
    uint8_t request_dummy[4] = {0x81, 0, 0, 0}; /* a zero-length request */

    (void)opt; /* squash the unused parameter warning */
    if(phase!=PROTOCOL_MIDDLE)
        return NULL;
    s_write(c, c->remote_fd.fd, request_dummy, 4);
    s_read(c, c->remote_fd.fd, buffer, 5);
    if(buffer[0]!=0x83) { /* NB_SSN_NEGRESP */
        s_log(LOG_ERR, "Negative response expected");
        throw_exception(c, 1);
    }
    if(buffer[2]!=0 || buffer[3]!=1) { /* length != 1 */
        s_log(LOG_ERR, "Unexpected NetBIOS response size");
        throw_exception(c, 1);
    }
    if(buffer[4]!=0x8e) { /* use TLS */
        s_log(LOG_ERR, "Remote server does not require TLS");
        throw_exception(c, 1);
    }
    return NULL;
}

NOEXPORT char *cifs_server(CLI *c, SERVICE_OPTIONS *opt, const PHASE phase) {
    uint8_t buffer[128];
    uint8_t response_access_denied[5] = {0x83, 0, 0, 1, 0x81};
    uint8_t response_use_ssl[5] = {0x83, 0, 0, 1, 0x8e};
    uint16_t len;

    (void)opt; /* squash the unused parameter warning */
    if(phase!=PROTOCOL_EARLY)
        return NULL;
    s_read(c, c->local_rfd.fd, buffer, 4) ;/* NetBIOS header */
    len=(uint16_t)(((uint16_t)(buffer[2])<<8)|buffer[3]);
    if(len>sizeof buffer-4) {
        s_log(LOG_ERR, "Received block too long");
        throw_exception(c, 1);
    }
    s_read(c, c->local_rfd.fd, buffer+4, len);
    if(buffer[0]!=0x81) { /* NB_SSN_REQUEST */
        s_log(LOG_ERR, "Client did not send session setup");
        s_write(c, c->local_wfd.fd, response_access_denied, 5);
        throw_exception(c, 1);
    }
    s_write(c, c->local_wfd.fd, response_use_ssl, 5);
    return NULL;
}

/**************************************** pgsql */

/* http://www.postgresql.org/docs/8.3/static/protocol-flow.html#AEN73982 */
static const uint8_t ssl_request[8]={0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f};

NOEXPORT char *pgsql_client(CLI *c, SERVICE_OPTIONS *opt, const PHASE phase) {
    uint8_t buffer[1];

    (void)opt; /* squash the unused parameter warning */
    if(phase!=PROTOCOL_MIDDLE)
        return NULL;
    s_write(c, c->remote_fd.fd, ssl_request, sizeof ssl_request);
    s_read(c, c->remote_fd.fd, buffer, 1);
    /* S - accepted, N - rejected, non-TLS preferred */
    if(buffer[0]!='S') {
        s_log(LOG_ERR, "PostgreSQL server rejected TLS");
        throw_exception(c, 1);
    }
    return NULL;
}

NOEXPORT char *pgsql_server(CLI *c, SERVICE_OPTIONS *opt, const PHASE phase) {
    uint8_t buffer[8], ssl_ok[1]={'S'};
    /* https://www.postgresql.org/docs/current/protocol-message-formats.html */
    static const uint8_t gss_request[8]={0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x30};
    static const uint8_t gss_response[62]=
        {'E', 0, 0, 0, 61, 'S', 'E', 'R', 'R', 'O', 'R', 0, 'C', 'X', 'X', '0',
        '0', '0', 0, 'M', 'S', 'S', 'L', ' ', 'e', 'x', 'p', 'e', 'c', 't', 'e', 'd',
        ' ', 'b', 'u', 't', ' ', 'n', 'o', 't', ' ', 'r', 'e', 'q', 'u', 'e', 's', 't',
        'e', 'd', ' ', 'b', 'y', ' ', 'c', 'l', 'i', 'e', 'n', 't', 0, 0};

    (void)opt; /* squash the unused parameter warning */
    if(phase!=PROTOCOL_EARLY)
        return NULL;
    s_log(LOG_DEBUG, "Started server-side psql protcol negotiation");
    memset(buffer, 0, sizeof buffer);
    s_read(c, c->local_rfd.fd, buffer, sizeof buffer);
    if(!safe_memcmp(buffer, gss_request, sizeof gss_request)) {
        s_log(LOG_INFO, "GSSAPI encryption requested, rejecting gracefully");
        s_write(c, c->local_wfd.fd, gss_response, sizeof gss_response);
        throw_exception(c, 2); /* don't reset */
    }
    if(safe_memcmp(buffer, ssl_request, sizeof ssl_request)) {
        s_log(LOG_ERR, "PostgreSQL client did not request TLS, rejecting");
        /* no way to send error on startup, so just drop the client */
        throw_exception(c, 1);
    }
    s_log(LOG_DEBUG, "SSLRequest received");
    s_write(c, c->local_wfd.fd, ssl_ok, sizeof ssl_ok);
    return NULL;
}

/**************************************** smtp */

NOEXPORT char *smtp_client(CLI *c, SERVICE_OPTIONS *opt, const PHASE phase) {
    (void)opt; /* squash the unused parameter warning */
    switch(phase) {
    case PROTOCOL_MIDDLE:
        smtp_client_negotiate(c);
        break;
    case PROTOCOL_LATE:
        if(opt->protocol_username && opt->protocol_password) {
            char *line;

            if(opt->protocol_host)
                ssl_printf(c, "HELO %s", opt->protocol_host);
            else
                ssl_putline(c, "HELO localhost");
            line=ssl_getline(c); /* ignore the reply */
            str_free(line);
            if(!strcasecmp(c->opt->protocol_authentication, "LOGIN"))
                smtp_client_login(c,
                    opt->protocol_username, opt->protocol_password);
            else /* use PLAIN by default */
                smtp_client_plain(c,
                    opt->protocol_username, opt->protocol_password);
        }
        break;
    default:
        break;
    }
    return NULL;
}

NOEXPORT void smtp_client_negotiate(CLI *c) {
    char *line;

    line=str_dup("");
    do { /* copy multiline greeting */
        str_free(line);
        line=fd_getline(c, c->remote_fd.fd);
        fd_putline(c, c->local_wfd.fd, line);
    } while(is_prefix(line, "220-"));

    if(c->opt->protocol_host)
        fd_printf(c, c->remote_fd.fd, "EHLO %s", c->opt->protocol_host);
    else
        fd_putline(c, c->remote_fd.fd, "EHLO localhost");
    do { /* skip multiline reply */
        str_free(line);
        line=fd_getline(c, c->remote_fd.fd);
    } while(is_prefix(line, "250-"));
    if(!is_prefix(line, "250 ")) { /* error */
        s_log(LOG_ERR, "Remote server is not RFC 1425 compliant");
        str_free(line);
        throw_exception(c, 1);
    }

    fd_putline(c, c->remote_fd.fd, "STARTTLS");
    do { /* skip multiline reply */
        str_free(line);
        line=fd_getline(c, c->remote_fd.fd);
    } while(is_prefix(line, "220-"));
    if(!is_prefix(line, "220 ")) { /* error */
        s_log(LOG_ERR, "Remote server is not RFC 2487 compliant");
        str_free(line);
        throw_exception(c, 1);
    }
    str_free(line);
}

/* http://www.samlogic.net/articles/smtp-commands-reference-auth.htm */

NOEXPORT void smtp_client_plain(CLI *c, const char *user, const char *pass) {
    char *line, *encoded;

    line=str_printf("%c%s%c%s", '\0', user, '\0', pass);
    encoded=base64(1, line, (int)strlen(user) + (int)strlen(pass) + 2);
    if(!encoded) {
        s_log(LOG_ERR, "Base64 encoder failed");
        str_free(line);
        throw_exception(c, 1);
    }
    str_free(line);
    line=str_printf("AUTH PLAIN %s", encoded);
    str_free(encoded);
    ssl_putline(c, line);
    str_free(line);

    line=ssl_getline(c);
    if(!is_prefix(line, "235 ")) { /* not 'Authentication successful' */
        s_log(LOG_ERR, "PLAIN Authentication Failed");
        str_free(line);
        throw_exception(c, 1);
    }
    str_free(line);
}

NOEXPORT void smtp_client_login(CLI *c, const char *user, const char *pass) {
    char *line, *encoded;

    ssl_putline(c, "AUTH LOGIN");
    line=ssl_getline(c);
    if(!is_prefix(line, "334 ")) { /* not the username challenge */
        s_log(LOG_ERR, "Remote server does not support LOGIN authentication");
        str_free(line);
        throw_exception(c, 1);
    }
    str_free(line);

    encoded=base64(1, user, (int)strlen(user));
    if(!encoded) {
        s_log(LOG_ERR, "Base64 encoder failed");
        throw_exception(c, 1);
    }
    ssl_putline(c, encoded);
    str_free(encoded);
    line=ssl_getline(c);
    if(!is_prefix(line, "334 ")) { /* not the password challenge */
        s_log(LOG_ERR, "LOGIN authentication failed");
        str_free(line);
        throw_exception(c, 1);
    }
    str_free(line);

    encoded=base64(1, pass, (int)strlen(pass));
    if(!encoded) {
        s_log(LOG_ERR, "Base64 encoder failed");
        throw_exception(c, 1);
    }
    ssl_putline(c, encoded);
    str_free(encoded);
    line=ssl_getline(c);
    if(!is_prefix(line, "235 ")) { /* not 'Authentication successful' */
        s_log(LOG_ERR, "LOGIN authentication failed");
        str_free(line);
        throw_exception(c, 1);
    }
    str_free(line);
}

NOEXPORT char *smtp_server(CLI *c, SERVICE_OPTIONS *opt, const PHASE phase) {
    char *line, *domain, *greeting;

    if(phase==PROTOCOL_CHECK)
        opt->option.connect_before_ssl=1; /* c->remote_fd needed */
    if(phase!=PROTOCOL_MIDDLE)
        return NULL;

    /* detect RFC 2487 */
    s_poll_init(c->fds, 0);
    s_poll_add(c->fds, c->local_rfd.fd, 1, 0);
    switch(s_poll_wait(c->fds, 0, 200)) { /* wait up to 200ms */
    case 0: /* fd not ready to read */
        s_log(LOG_DEBUG, "RFC 2487 detected");
        break;
    case 1: /* fd ready to read */
        s_log(LOG_DEBUG, "RFC 2487 not detected");
        return NULL; /* return if RFC 2487 is not used */
    default: /* -1 */
        sockerror("RFC2487 (s_poll_wait)");
        throw_exception(c, 1);
    }

    /* process server's greeting */
    line=fd_getline(c, c->remote_fd.fd);
    if(!(is_prefix(line, "220 ") || is_prefix(line, "220-"))) {
        s_log(LOG_ERR, "Unknown server welcome");
        str_free(line);
        throw_exception(c, 1);
    }
    domain=str_dup(line+4); /* skip "220" and the separator */
    line[4]='\0';     /* only leave "220" and the separator */
    greeting=strchr(domain, ' ');
    if(greeting) {
        *greeting++='\0'; /* truncate anything after the domain name */
        fd_printf(c, c->local_wfd.fd, "%s%s stunnel for %s",
            line, domain, greeting);
    } else {
        fd_printf(c, c->local_wfd.fd, "%s%s stunnel", line, domain);
    }
    while(is_prefix(line, "220-")) { /* copy multiline greeting */
        str_free(line);
        line=fd_getline(c, c->remote_fd.fd);
        fd_putline(c, c->local_wfd.fd, line);
    }
    str_free(line);

    /* process client's EHLO */
    line=fd_getline(c, c->local_rfd.fd);
    if(!is_prefix(line, "EHLO ")) {
        s_log(LOG_ERR, "Unknown client EHLO");
        str_free(line);
        str_free(domain);
        throw_exception(c, 1);
    }
    str_free(line);
    fd_printf(c, c->local_wfd.fd, "250-%s", domain);
    str_free(domain);
    fd_putline(c, c->local_wfd.fd, "250 STARTTLS");

    /* process client's STARTTLS */
    line=fd_getline(c, c->local_rfd.fd);
    if(!is_prefix(line, "STARTTLS")) {
        s_log(LOG_ERR, "STARTTLS expected");
        str_free(line);
        throw_exception(c, 1);
    }
    fd_putline(c, c->local_wfd.fd, "220 Go ahead");
    str_free(line);

    return NULL;
}

/**************************************** pop3 */

NOEXPORT char *pop3_client(CLI *c, SERVICE_OPTIONS *opt, const PHASE phase) {
    char *line;

    (void)opt; /* squash the unused parameter warning */
    if(phase!=PROTOCOL_MIDDLE)
        return NULL;
    line=fd_getline(c, c->remote_fd.fd);
    if(!is_prefix(line, "+OK ")) {
        s_log(LOG_ERR, "Unknown server welcome");
        str_free(line);
        throw_exception(c, 1);
    }
    fd_putline(c, c->local_wfd.fd, line);
    fd_putline(c, c->remote_fd.fd, "STLS");
    str_free(line);
    line=fd_getline(c, c->remote_fd.fd);
    if(!is_prefix(line, "+OK ")) {
        s_log(LOG_ERR, "Server does not support TLS");
        str_free(line);
        throw_exception(c, 1);
    }
    str_free(line);
    return NULL;
}

NOEXPORT char *pop3_server(CLI *c, SERVICE_OPTIONS *opt, const PHASE phase) {
    char *line;

    if(phase==PROTOCOL_CHECK)
        opt->option.connect_before_ssl=1; /* c->remote_fd needed */
    if(phase!=PROTOCOL_MIDDLE)
        return NULL;
    line=fd_getline(c, c->remote_fd.fd);
    fd_printf(c, c->local_wfd.fd, "%s + stunnel", line);
    str_free(line);
    line=fd_getline(c, c->local_rfd.fd);
    if(is_prefix(line, "CAPA")) { /* client wants RFC 2449 extensions */
        fd_putline(c, c->local_wfd.fd, "+OK Stunnel capability list follows");
        fd_putline(c, c->local_wfd.fd, "STLS");
        fd_putline(c, c->local_wfd.fd, ".");
        str_free(line);
        line=fd_getline(c, c->local_rfd.fd);
    }
    if(!is_prefix(line, "STLS")) {
        s_log(LOG_ERR, "Client does not want TLS");
        str_free(line);
        throw_exception(c, 1);
    }
    str_free(line);
    fd_putline(c, c->local_wfd.fd, "+OK Stunnel starts TLS negotiation");
    return NULL;
}

/**************************************** imap */

NOEXPORT char *imap_client(CLI *c, SERVICE_OPTIONS *opt, const PHASE phase) {
    char *line;

    (void)opt; /* squash the unused parameter warning */
    if(phase!=PROTOCOL_MIDDLE)
        return NULL;
    line=fd_getline(c, c->remote_fd.fd);
    if(!is_prefix(line, "* OK")) {
        s_log(LOG_ERR, "Unknown server welcome");
        str_free(line);
        throw_exception(c, 1);
    }
    str_free(line);
    fd_putline(c, c->local_wfd.fd, "* OK Connected.");
    fd_putline(c, c->remote_fd.fd, "stunnel STARTTLS");
    line=fd_getline(c, c->remote_fd.fd);
    if(!is_prefix(line, "stunnel OK")) {
        fd_putline(c, c->local_wfd.fd,
            "* BYE stunnel: Server does not support TLS");
        s_log(LOG_ERR, "Server does not support TLS");
        str_free(line);
        throw_exception(c, 2); /* don't reset */
    }
    str_free(line);
    return NULL;
}

NOEXPORT char *imap_server(CLI *c, SERVICE_OPTIONS *opt, const PHASE phase) {
    char *line, *id, *tail, *capa;

    if(phase==PROTOCOL_CHECK)
        opt->option.connect_before_ssl=1; /* c->remote_fd needed */
    if(phase!=PROTOCOL_MIDDLE)
        return NULL;
    s_poll_init(c->fds, 0);
    s_poll_add(c->fds, c->local_rfd.fd, 1, 0);
    switch(s_poll_wait(c->fds, 0, 200)) {
    case 0: /* fd not ready to read */
        s_log(LOG_DEBUG, "RFC 2595 detected");
        break;
    case 1: /* fd ready to read */
        s_log(LOG_DEBUG, "RFC 2595 not detected");
        return NULL; /* return if RFC 2595 is not used */
    default: /* -1 */
        sockerror("RFC2595 (s_poll_wait)");
        throw_exception(c, 1);
    }

    /* process server welcome and send it to client */
    line=fd_getline(c, c->remote_fd.fd);
    if(!is_prefix(line, "* OK")) {
        s_log(LOG_ERR, "Unknown server welcome");
        str_free(line);
        throw_exception(c, 1);
    }
    capa=strstr(line, "CAPABILITY");
    if(!capa)
        capa=strstr(line, "capability");
    if(capa)
        *capa='K'; /* disable CAPABILITY within greeting */
    fd_printf(c, c->local_wfd.fd, "%s (stunnel)", line);

    id=str_dup("");
    while(1) { /* process client commands */
        str_free(line);
        line=fd_getline(c, c->local_rfd.fd);
        /* split line into id and tail */
        str_free(id);
        id=str_dup(line);
        tail=strchr(id, ' ');
        if(!tail)
            break;
        *tail++='\0';

        if(is_prefix(tail, "STARTTLS")) {
            fd_printf(c, c->local_wfd.fd,
                "%s OK Begin TLS negotiation now", id);
            str_free(line);
            str_free(id);
            return NULL; /* success */
        } else if(is_prefix(tail, "CAPABILITY")) {
            fd_putline(c, c->remote_fd.fd, line); /* send it to server */
            str_free(line);
            line=fd_getline(c, c->remote_fd.fd); /* get the capabilities */
            if(*line=='*') {
                /*
                 * append STARTTLS
                 * should also add LOGINDISABLED, but can't because
                 * of Mozilla bug #324138/#312009
                 * LOGIN would fail as "unexpected command", anyway
                 */
                fd_printf(c, c->local_wfd.fd, "%s STARTTLS", line);
                str_free(line);
                line=fd_getline(c, c->remote_fd.fd); /* next line */
            }
            fd_putline(c, c->local_wfd.fd, line); /* forward to the client */
            tail=strchr(line, ' ');
            if(!tail || !is_prefix(tail+1, "OK")) { /* not OK? */
                fd_putline(c, c->local_wfd.fd,
                    "* BYE unexpected server response");
                s_log(LOG_ERR, "Unexpected server response: %s", line);
                break;
            }
        } else if(is_prefix(tail, "LOGOUT")) {
            fd_putline(c, c->local_wfd.fd, "* BYE server terminating");
            fd_printf(c, c->local_wfd.fd, "%s OK LOGOUT completed", id);
            break;
        } else {
            fd_putline(c, c->local_wfd.fd, "* BYE stunnel: unexpected command");
            fd_printf(c, c->local_wfd.fd, "%s BAD %s unexpected", id, tail);
            s_log(LOG_ERR, "Unexpected client command %s", tail);
            break;
        }
    }
    /* clean server shutdown */
    str_free(id);
    fd_putline(c, c->remote_fd.fd, "stunnel LOGOUT");
    str_free(line);
    line=fd_getline(c, c->remote_fd.fd);
    if(*line=='*') {
        str_free(line);
        line=fd_getline(c, c->remote_fd.fd);
    }
    str_free(line);
    throw_exception(c, 2); /* don't reset */
    return NULL; /* some C compilers require a return value */
}

/**************************************** nntp */

NOEXPORT char *nntp_client(CLI *c, SERVICE_OPTIONS *opt, const PHASE phase) {
    char *line;

    (void)opt; /* squash the unused parameter warning */
    if(phase!=PROTOCOL_MIDDLE)
        return NULL;
    line=fd_getline(c, c->remote_fd.fd);
    if(!is_prefix(line, "200 ") && !is_prefix(line, "201 ")) {
        s_log(LOG_ERR, "Unknown server welcome");
        str_free(line);
        throw_exception(c, 1);
    }
    fd_putline(c, c->local_wfd.fd, line);
    fd_putline(c, c->remote_fd.fd, "STARTTLS");
    str_free(line);
    line=fd_getline(c, c->remote_fd.fd);
    if(!is_prefix(line, "382 ")) {
        s_log(LOG_ERR, "Server does not support TLS");
        str_free(line);
        throw_exception(c, 1);
    }
    str_free(line);
    return NULL;
}

/**************************************** LDAP, RFC 2830 */

uint8_t ldap_starttls_message[0x1d + 2] = {
    0x30,   /* tag = UNIVERSAL SEQUENCE */
    0x1d,   /* len = 29 */
    0x02,   /*   tag = INTEGER (messageID) */
    0x01,   /*   len = 1 */
    0x01,   /*   val = 1 (this is messageID 1) */
    0x77,   /*   tag = APPLICATION 23 (ExtendedRequest)
             *     0b01xxxxxx =>  Class = Application
             *     0bxx1xxxxx =>    P/C = Constructed
             *     0bxxx10111 => Number = 23 */
    0x18,   /*   len = 24 */
    0x80,   /*     tag = CONTEXT-SPECIFIC 0 (requestName) */
    0x16,   /*     len = 22 */
            /*     val = LDAP_START_TLS_OID
             *       OID: 1.3.6.1.4.1.1466.20037 */
    '1', '.',
    '3', '.',
    '6', '.',
    '1', '.',
    '4', '.',
    '1', '.',
    '1', '4', '6', '6', '.',
    '2', '0', '0', '3', '7'
    /* no requestValue, as per RFC2830
     * (section 2.1: "The requestValue field is absent") */
};

#define LDAP_UNIVERSAL_SEQUENCE                 0x30
#define LDAP_WINLDAP_FOUR_BYTE_LEN_FLAG         0x84
#define LDAP_RESPONSE_MSG_ID_TAG_INTEGER        0x02
#define LDAP_RESPONSE_MSG_ID_LEN                0x01
#define LDAP_RESPONSE_MSG_ID_VAL                0x01
#define LDAP_RESPONSE_OP_APPLICATION_24         0x78
#define LDAP_RESPONSE_RESULT_TAG_ENUMERATED     0x0a
#define LDAP_RESPONSE_RESULT_LEN                0x01
#define LDAP_RESPONSE_RESULT_VAL_SUCCESS        0x00

/* also see:
 * https://ldap.com/ldapv3-wire-protocol-reference-extended/
 */

NOEXPORT char *ldap_client(CLI *c, SERVICE_OPTIONS *opt, const PHASE phase) {
    uint8_t buffer_8;
    uint32_t buffer_32;
    size_t resp_len;
    uint8_t ldap_response[128];
    uint8_t *resp_ptr;

    (void)opt; /* squash the unused parameter warning */

    if(phase!=PROTOCOL_MIDDLE)
        return NULL;

    s_log(LOG_DEBUG, "Sending LDAP Start TLS request");
    s_write(c, c->remote_fd.fd, ldap_starttls_message, sizeof(ldap_starttls_message));

    s_log(LOG_DEBUG, "Receiving LDAP response tag");
    s_read(c, c->remote_fd.fd, &buffer_8, 1);
    if(buffer_8!=LDAP_UNIVERSAL_SEQUENCE) {
        s_log(LOG_ERR, "LDAP response is not UNIVERSAL SEQUENCE");
        throw_exception(c, 1);
    }

    s_log(LOG_DEBUG, "Receiving LDAP response length");
    s_read(c, c->remote_fd.fd, &buffer_8, 1);
    if(buffer_8==LDAP_WINLDAP_FOUR_BYTE_LEN_FLAG) { /* WinLDAP */
        /* receive response length (4 bytes, network byte order) */
        s_read(c, c->remote_fd.fd, &buffer_32, 4);
        resp_len=ntohl(buffer_32);
    } else {
        resp_len=buffer_8;
    }
    if(resp_len>sizeof(ldap_response)) {
        s_log(LOG_ERR, "LDAP response too long (%lu byte(s))",
            (unsigned long)resp_len);
        throw_exception(c, 1);
    }

    s_log(LOG_DEBUG, "Receiving LDAP response value (%lu byte(s))",
        (unsigned long)resp_len);
    memset(ldap_response, 0, sizeof(ldap_response)); /* prevent data leaks */
    s_read(c, c->remote_fd.fd, ldap_response, resp_len);

    s_log(LOG_DEBUG, "Decoding LDAP response value");
    resp_ptr=ldap_response;
    if(*resp_ptr++!=LDAP_RESPONSE_MSG_ID_TAG_INTEGER) {
        s_log(LOG_ERR, "LDAP response has an incorrect message ID type");
        throw_exception(c, 1);
    }
    if(*resp_ptr++!=LDAP_RESPONSE_MSG_ID_LEN) {
        s_log(LOG_ERR, "LDAP response has an unexpected message ID length");
        throw_exception(c, 1);
    }
    if(*resp_ptr++!=LDAP_RESPONSE_MSG_ID_VAL) {
        s_log(LOG_ERR, "LDAP response has an unexpected message ID value");
        throw_exception(c, 1);
    }
    if(*resp_ptr++!=LDAP_RESPONSE_OP_APPLICATION_24) {
        s_log(LOG_ERR, "LDAP response protocol op is not ExtendedResponse");
        throw_exception(c, 1);
    }
    /* we do not validate the protocol op sequence length */
    if(*resp_ptr++==LDAP_WINLDAP_FOUR_BYTE_LEN_FLAG) { /* WinLDAP */
        resp_ptr+=4; /* skip next 4 bytes */
    }
    if(*resp_ptr++!=LDAP_RESPONSE_RESULT_TAG_ENUMERATED) {
        s_log(LOG_ERR, "LDAP response has an unexpected result code type");
        throw_exception(c, 1);
    }
    if(*resp_ptr++!=LDAP_RESPONSE_RESULT_LEN) {
        s_log(LOG_ERR, "LDAP response has an unexpected result code length");
        throw_exception(c, 1);
    }
    if(*resp_ptr!=LDAP_RESPONSE_RESULT_VAL_SUCCESS) {
        s_log(LOG_ERR, "LDAP response has indicated an error (%u)", *resp_ptr);
        throw_exception(c, 1);
    }
    /* any remaining data is ignored */

    s_log(LOG_INFO, "LDAP Start TLS successfully negotiated");
    return NULL;
}

/**************************************** connect */

NOEXPORT char *connect_server(CLI *c, SERVICE_OPTIONS *opt, const PHASE phase) {
    char *request, *proto, *header;

    (void)opt; /* squash the unused parameter warning */
    if(phase!=PROTOCOL_EARLY)
        return NULL;
    request=fd_getline(c, c->local_rfd.fd);
    if(!is_prefix(request, "CONNECT ")) {
        fd_putline(c, c->local_wfd.fd, "HTTP/1.0 400 Bad Request Method");
        fd_putline(c, c->local_wfd.fd, "Server: stunnel/" STUNNEL_VERSION);
        fd_putline(c, c->local_wfd.fd, "");
        str_free(request);
        throw_exception(c, 1);
    }
    proto=strchr(request+8, ' ');
    if(!proto || !is_prefix(proto, " HTTP/")) {
        fd_putline(c, c->local_wfd.fd, "HTTP/1.0 400 Bad Request Protocol");
        fd_putline(c, c->local_wfd.fd, "Server: stunnel/" STUNNEL_VERSION);
        fd_putline(c, c->local_wfd.fd, "");
        str_free(request);
        throw_exception(c, 1);
    }
    *proto='\0';

    header=str_dup("");
    do { /* ignore any headers */
        str_free(header);
        header=fd_getline(c, c->local_rfd.fd);
    } while(*header); /* not empty */
    str_free(header);

    if(!name2addrlist(&c->connect_addr, request+8)) {
        fd_putline(c, c->local_wfd.fd, "HTTP/1.0 404 Not Found");
        fd_putline(c, c->local_wfd.fd, "Server: stunnel/" STUNNEL_VERSION);
        fd_putline(c, c->local_wfd.fd, "");
        str_free(request);
        throw_exception(c, 1);
    }
    str_free(request);
    fd_putline(c, c->local_wfd.fd, "HTTP/1.0 200 OK");
    fd_putline(c, c->local_wfd.fd, "Server: stunnel/" STUNNEL_VERSION);
    fd_putline(c, c->local_wfd.fd, "");
    return NULL;
}

NOEXPORT char *connect_client(CLI *c, SERVICE_OPTIONS *opt, const PHASE phase) {
    char *line, *encoded;
    NAME_LIST *ptr;

    if(phase!=PROTOCOL_MIDDLE)
        return NULL;

    if(!opt->protocol_host) {
        s_log(LOG_ERR, "protocolHost not specified");
        throw_exception(c, 1);
    }
    fd_printf(c, c->remote_fd.fd, "CONNECT %s HTTP/1.1",
        opt->protocol_host);
    fd_printf(c, c->remote_fd.fd, "Host: %s", opt->protocol_host);
    if(opt->protocol_username && opt->protocol_password) {
        if(!strcasecmp(opt->protocol_authentication, "ntlm")) {
#ifndef OPENSSL_NO_MD4
            ntlm(c, opt);
#else
            s_log(LOG_ERR, "NTLM authentication is not available");
            throw_exception(c, 1);
#endif
        } else { /* basic authentication */
            line=str_printf("%s:%s",
                opt->protocol_username, opt->protocol_password);
            encoded=base64(1, line, (int)strlen(line));
            str_free(line);
            if(!encoded) {
                s_log(LOG_ERR, "Base64 encoder failed");
                throw_exception(c, 1);
            }
            fd_printf(c, c->remote_fd.fd, "Proxy-Authorization: basic %s",
                encoded);
            str_free(encoded);
        }
    }
    for(ptr=opt->protocol_header; ptr; ptr=ptr->next)
        fd_putline(c, c->remote_fd.fd, ptr->name); /* custom header */
    fd_putline(c, c->remote_fd.fd, ""); /* empty line */

    line=fd_getline(c, c->remote_fd.fd);
    if(!is_prefix(line, "HTTP/1.0 2") && !is_prefix(line, "HTTP/1.1 2")) {
        /* not "HTTP/1.x 2xx Connection established" */
        s_log(LOG_ERR, "CONNECT request rejected");
        do { /* read all headers */
            str_free(line);
            line=fd_getline(c, c->remote_fd.fd);
        } while(*line);
        str_free(line);
        throw_exception(c, 1);
    }
    s_log(LOG_INFO, "CONNECT request accepted");
    do {
        str_free(line);
        line=fd_getline(c, c->remote_fd.fd); /* read all headers */
    } while(*line);
    str_free(line);
    return NULL;
}

#ifndef OPENSSL_NO_MD4

/*
 * NTLM code is based on the following documentation:
 * http://davenport.sourceforge.net/ntlm.html
 * http://www.innovation.ch/personal/ronald/ntlm.html
 */

#define s_min(a, b) ((a)>(b)?(b):(a))

NOEXPORT void ntlm(CLI *c, SERVICE_OPTIONS *opt) {
    char *line, buf[BUFSIZ], *ntlm1_txt, *ntlm2_txt, *ntlm3_txt, *tmpstr;
    long content_length=0; /* no HTTP content */

    /* send Proxy-Authorization (phase 1) */
    fd_printf(c, c->remote_fd.fd, "Proxy-Connection: keep-alive");
    ntlm1_txt=ntlm1();
    if(!ntlm1_txt) {
        s_log(LOG_ERR, "Proxy-Authenticate: Failed to build NTLM request");
        throw_exception(c, 1);
    }
    fd_printf(c, c->remote_fd.fd, "Proxy-Authorization: NTLM %s", ntlm1_txt);
    str_free(ntlm1_txt);
    fd_putline(c, c->remote_fd.fd, ""); /* empty line */
    line=fd_getline(c, c->remote_fd.fd);

    /* receive Proxy-Authenticate (phase 2) */
    if(!is_prefix(line, "HTTP/1.0 407") && !is_prefix(line, "HTTP/1.1 407")) {
        s_log(LOG_ERR, "Proxy-Authenticate: NTLM authorization request rejected");
        do { /* read all headers */
            str_free(line);
            line=fd_getline(c, c->remote_fd.fd);
        } while(*line);
        str_free(line);
        throw_exception(c, 1);
    }
    ntlm2_txt=NULL;
    do { /* read all headers */
        str_free(line);
        line=fd_getline(c, c->remote_fd.fd);
        if(is_prefix(line, "Proxy-Authenticate: NTLM "))
            ntlm2_txt=str_dup(line+25);
        else if(is_prefix(line, "Content-Length: ")) {
            content_length=strtol(line+16, &tmpstr, 10);
            if(tmpstr>line+16) /* found some digits */
                while(*tmpstr && isspace((int)*tmpstr))
                    ++tmpstr;
            if(tmpstr==line+16 || *tmpstr || content_length<0) {
                s_log(LOG_ERR, "Proxy-Authenticate: Invalid Content-Length");
                str_free(line);
                throw_exception(c, 1);
            }
        }
    } while(*line);
    if(!ntlm2_txt) { /* no Proxy-Authenticate: NTLM header */
        s_log(LOG_ERR, "Proxy-Authenticate: NTLM header not found");
        str_free(line);
        throw_exception(c, 1);
    }

    /* read and ignore HTTP content (if any) */
    while(content_length>0) {
        size_t n=s_min((size_t)content_length, BUFSIZ);
        s_read(c, c->remote_fd.fd, buf, n);
        content_length-=(long)n;
    }

    /* send Proxy-Authorization (phase 3) */
    fd_printf(c, c->remote_fd.fd, "CONNECT %s HTTP/1.1", opt->protocol_host);
    fd_printf(c, c->remote_fd.fd, "Host: %s", opt->protocol_host);
    ntlm3_txt=ntlm3(opt->protocol_domain,
        opt->protocol_username, opt->protocol_password, ntlm2_txt);
    str_free(ntlm2_txt);
    if(!ntlm3_txt) {
        s_log(LOG_ERR, "Proxy-Authenticate: Failed to build NTLM response");
        throw_exception(c, 1);
    }
    fd_printf(c, c->remote_fd.fd, "Proxy-Authorization: NTLM %s", ntlm3_txt);
    str_free(ntlm3_txt);
}

NOEXPORT char *ntlm1() {
    char phase1[32];

    memset(phase1, 0, sizeof phase1);
    strcpy(phase1, "NTLMSSP");
    phase1[8]=1; /* type: 1 */
    phase1[12]=2; /* flag: negotiate OEM */
    phase1[13]=2; /* flag: negotiate NTLM */
    /* bytes 16-23: supplied domain security buffer */
    /* bytes 24-31: supplied workstation security buffer */
    return base64(1, phase1, sizeof phase1); /* encode */
}

NOEXPORT char *ntlm3(char *domain,
        char *user, char *password, char *phase2) {
    MD4_CTX md4;
    uint8_t *decoded; /* decoded reply from proxy */
    uint8_t phase3[146];
    uint8_t md4_hash[21];
    const size_t ntlm_len=24; /* length of the NTLM hash response */
    const size_t domain_len=strlen(domain);
    const size_t user_len=strlen(user);
    const size_t ntlm_off=64; /* start of the data block in version 2 */
    const size_t domain_off=ntlm_off+ntlm_len;
    const size_t user_off=domain_off+domain_len;
    const size_t end_off=user_off+user_len;

    /* setup the phase3 structure */
    if(end_off>sizeof phase3)
        return NULL;
    memset(phase3, 0, sizeof phase3);
    /* bytes 0-7: null-terminated NTLMSSP signature */
    strcpy((char *)phase3, "NTLMSSP");
    /* bytes 8-11: NTLM message type */
    phase3[8]=3;                    /* type: 3 */
    /* bytes 12-19: LM/LMv2 response */
    phase3[16]=(uint8_t)end_off;    /* LM response offset */
    /* bytes 20-27: NTLM/NTLMv2 response */
    phase3[20]=(uint8_t)ntlm_len;   /* NTLM response length */
    phase3[22]=(uint8_t)ntlm_len;   /* NTLM response length */
    phase3[24]=(uint8_t)ntlm_off;   /* NTLM response offset */
    /* bytes 28-35: target (domain/server) name */
    phase3[28]=(uint8_t)domain_len; /* domain length */
    phase3[30]=(uint8_t)domain_len; /* domain length */
    phase3[32]=(uint8_t)domain_off; /* domain offset */
    /* bytes 36-43: user name */
    phase3[36]=(uint8_t)user_len;   /* user length */
    phase3[38]=(uint8_t)user_len;   /* user length */
    phase3[40]=(uint8_t)user_off;   /* user offset */
    /* bytes 44-51: workstation name */
    phase3[48]=(uint8_t)end_off;    /* host offset */
    /* bytes 52-59: session key */
    phase3[56]=(uint8_t)end_off;    /* session key offset */
    /* bytes 60-63: flags */
    phase3[60]=2;                   /* flag: negotiate OEM */
    phase3[61]=2;                   /* flag: negotiate NTLM */

    /* calculate MD4 of the UTF-16 encoded password */
    MD4_Init(&md4);
    while(*password) {
        MD4_Update(&md4, password++, 1);
        MD4_Update(&md4, "", 1); /* UTF-16 */
    }
    MD4_Final(md4_hash, &md4);
    memset(md4_hash+16, 0, 5); /* pad to 21 bytes */

    /* decode the challenge and calculate the response */
    decoded=(uint8_t *)base64(0, phase2, (int)strlen(phase2)); /* decode */
    if(!decoded)
        return NULL;
    crypt_DES(phase3+ntlm_off,    decoded+24, md4_hash);
    crypt_DES(phase3+ntlm_off+8,  decoded+24, md4_hash+7);
    crypt_DES(phase3+ntlm_off+16, decoded+24, md4_hash+14);
    str_free(decoded);

    memcpy((char *)phase3+domain_off, domain, domain_len);
    memcpy((char *)phase3+user_off, user, user_len);

    return base64(1, (char *)phase3, (int)end_off); /* encode */
}

NOEXPORT void crypt_DES(DES_cblock dst, const_DES_cblock src,
        unsigned char hash[7]) {
    DES_cblock key;
    DES_key_schedule sched;

    /* convert 56-bit hash to 64-bit DES key */
    key[0]=hash[0];
    key[1]=(unsigned char)(((hash[0]&1)<<7)|(hash[1]>>1));
    key[2]=(unsigned char)(((hash[1]&3)<<6)|(hash[2]>>2));
    key[3]=(unsigned char)(((hash[2]&7)<<5)|(hash[3]>>3));
    key[4]=(unsigned char)(((hash[3]&15)<<4)|(hash[4]>>4));
    key[5]=(unsigned char)(((hash[4]&31)<<3)|(hash[5]>>5));
    key[6]=(unsigned char)(((hash[5]&63)<<2)|(hash[6]>>6));
    key[7]=(unsigned char)(((hash[6]&127)<<1));
    DES_set_odd_parity(&key);

    /* encrypt */
    DES_set_key_unchecked(&key, &sched);
    DES_ecb_encrypt((const_DES_cblock *)src,
        (DES_cblock *)dst, &sched, DES_ENCRYPT);
}

#endif

NOEXPORT char *base64(int encode, const char *in, int len) {
    BIO *bio, *b64;
    char *out;
    int n;

    b64=BIO_new(BIO_f_base64());
    if(!b64)
        return NULL;
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio=BIO_new(BIO_s_mem());
    if(!bio) {
        BIO_free(b64);
        return NULL;
    }
    if(encode)
        bio=BIO_push(b64, bio);
    BIO_write(bio, in, len);
    (void)BIO_flush(bio); /* ignore the error if any */
    if(encode) {
        bio=BIO_pop(bio);
        BIO_free(b64);
    } else {
        bio=BIO_push(b64, bio);
    }
    n=BIO_pending(bio);
    /* 32 bytes as a safety precaution for passing decoded data to crypt_DES */
    /* n+1 to get null-terminated string on encode */
    out=str_alloc(n<32?32:(size_t)n+1);
    n=BIO_read(bio, out, n);
    if(n<0) {
        BIO_free_all(bio);
        str_free(out);
        return NULL;
    }
    BIO_free_all(bio);
    return out;
}

/* end of protocol.c */
