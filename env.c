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
 */

/* getpeername can't be declarated in a normal way */
#define getpeername no_getpeername
#include <sys/types.h>
#include <sys/socket.h> /* for AF_INET */
#include <netinet/in.h>
#include <stdlib.h>     /* for getenv */
#undef getpeername

int getpeername(int s, struct sockaddr_in *name, int *len) {
    char *value;

    name->sin_family=AF_INET;
    if((value=getenv("REMOTE_HOST")))
        name->sin_addr.s_addr=inet_addr(value);
    else
        name->sin_addr.s_addr=htonl(INADDR_ANY);
    if((value=getenv("REMOTE_PORT")))
        name->sin_port=htons(atoi(value));
    else
        name->sin_port=htons(0);
    return 0;
}

