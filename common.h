/*
 *   stunnel       Universal SSL tunnel
 *   Copyright (c) 1998-1999 Michal Trojnara <Michal.Trojnara@centertel.pl>
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

#include <stdio.h>

/* SSL headers */
#define NO_BLOWFISH
#include <ssl.h>
#include <err.h>
#include <lhash.h>
#include <crypto.h>

#ifdef USE_WIN32

#define VERSION "3.0"
#define HOST "i586-pc-mingw32-gnu"

#define get_last_socket_error() WSAGetLastError()
#define get_last_error()        GetLastError()
#define readsocket(s,b,n)       recv((s),(b),(n),0)
#define writesocket(s,b,n)      send((s),(b),(n),0)
#else /* USE_WIN32 */

#include "config.h"

#define get_last_socket_error() errno
#define get_last_error()        errno
#define readsocket(s,b,n)       read((s),(b),(n))
#define writesocket(s,b,n)      write((s),(b),(n))
#define closesocket(s)          close(s)
#define ioctlsocket(a,b,c)      ioctl((a),(b),(c))

/* POSIX threads */
#if HAVE_PTHREAD_H && HAVE_LIBPTHREAD
#define USE_PTHREAD
#define THREADS
#else
#define USE_FORK
#endif

/* TCP wrapper */
#if HAVE_TCPD_H && HAVE_LIBWRAP
#define USE_LIBWRAP
#endif

#endif /* USE_WIN32 */

#ifdef USE_PTHREAD
#define STUNNEL_TMP "stunnel " VERSION " on " HOST " PTHREAD"
#endif
#ifdef USE_WIN32
#define STUNNEL_TMP "stunnel " VERSION " on " HOST " WIN32"
#endif
#ifdef USE_FORK
#define STUNNEL_TMP "stunnel " VERSION " on " HOST " FORK"
#endif
#ifdef USE_LIBWRAP
#define STUNNEL_INFO STUNNEL_TMP "+LIBWRAP"
#else
#define STUNNEL_INFO STUNNEL_TMP
#endif

/* Prototypes for log.c */

void log(int, char *, ...);

/* Prototypes for sthreads.c */

void sthreads_init(void);
unsigned long process_id(void);
unsigned long thread_id(void);
int create_client(int, int, void (*)(int));

/* End of common.h */

