/*
 *   stunnel       Universal SSL tunnel
 *   Copyright (C) 1998-2013 Michal Trojnara <Michal.Trojnara@mirt.net>
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

#ifdef HAVE_UTIL_H
#include <util.h>
#endif /* HAVE_UTIL_H */

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif /* HAVE_SYS_IOCTL_H */

/* pty allocated with _getpty gets broken if we do I_PUSH:es to it. */
#if defined(HAVE__GETPTY) || defined(HAVE_OPENPTY)
#undef HAVE_DEV_PTMX
#endif /* HAVE__GETPTY || HAVE_OPENPTY */

#ifdef HAVE_PTY_H
#include <pty.h>
#endif /* HAVE_PTY_H */

#ifdef HAVE_LIBUTIL_H
#include <libutil.h>
#endif /* HAVE_LIBUTIL_H */

#ifndef O_NOCTTY
#define O_NOCTTY 0
#endif /* O_NOCTTY */

/*
 * allocates and opens a pty
 * returns -1 if no pty could be allocated, or zero if a pty was successfully
 * allocated
 * on success, open file descriptors for the pty and tty sides and the name of
 * the tty side are returned
 * the buffer must be able to hold at least 64 characters
 */

int pty_allocate(int *ptyfd, int *ttyfd, char *namebuf) {
#if defined(HAVE_OPENPTY) || defined(BSD4_4) && !defined(__INNOTEK_LIBC__)
    /* openpty(3) exists in OSF/1 and some other os'es */
    char buf[64];
    int i;

    i=openpty(ptyfd, ttyfd, buf, NULL, NULL);
    if(i<0) {
        ioerror("openpty");
        return -1;
    }
    strcpy(namebuf, buf); /* possible truncation */
    return 0;
#else /* HAVE_OPENPTY */
#ifdef HAVE__GETPTY
    /*
     * _getpty(3) exists in SGI Irix 4.x, 5.x & 6.x -- it generates more
     * pty's automagically when needed
     */
    char *slave;

    slave=_getpty(ptyfd, O_RDWR, 0622, 0);
    if(slave==NULL) {
        ioerror("_getpty");
        return -1;
    }
    strcpy(namebuf, slave);
    /* open the slave side */
    *ttyfd=open(namebuf, O_RDWR|O_NOCTTY);
    if(*ttyfd<0) {
        ioerror(namebuf);
        close(*ptyfd);
        return -1;
    }
    return 0;
#else /* HAVE__GETPTY */
#if defined(HAVE_DEV_PTMX)
    /*
     * this code is used e.g. on Solaris 2.x
     * note that Solaris 2.3 * also has bsd-style ptys, but they simply do not
     * work
     */
    int ptm; char *pts;

    ptm=open("/dev/ptmx", O_RDWR|O_NOCTTY);
    if(ptm<0) {
        ioerror("/dev/ptmx");
        return -1;
    }
    if(grantpt(ptm)<0) {
        ioerror("grantpt");
        /* return -1; */
        /* can you tell me why it doesn't work? */
    }
    if(unlockpt(ptm)<0) {
        ioerror("unlockpt");
        return -1;
    }
    pts=ptsname(ptm);
    if(pts==NULL)
        s_log(LOG_ERR, "Slave pty side name could not be obtained");
    strcpy(namebuf, pts);
    *ptyfd=ptm;

    /* open the slave side */
    *ttyfd=open(namebuf, O_RDWR|O_NOCTTY);
    if(*ttyfd<0) {
        ioerror(namebuf);
        close(*ptyfd);
        return -1;
    }
    /* push the appropriate streams modules, as described in Solaris pts(7) */
    if(ioctl(*ttyfd, I_PUSH, "ptem")<0)
        ioerror("ioctl I_PUSH ptem");
    if(ioctl(*ttyfd, I_PUSH, "ldterm")<0)
        ioerror("ioctl I_PUSH ldterm");
    if(ioctl(*ttyfd, I_PUSH, "ttcompat")<0)
        ioerror("ioctl I_PUSH ttcompat");
    return 0;
#else /* HAVE_DEV_PTMX */
#ifdef HAVE_DEV_PTS_AND_PTC
    /* AIX-style pty code. */
    const char *name;

    *ptyfd=open("/dev/ptc", O_RDWR|O_NOCTTY);
    if(*ptyfd<0) {
        ioerror("open(/dev/ptc)");
        return -1;
    }
    name=ttyname(*ptyfd);
    if(!name) {
        s_log(LOG_ERR, "Open of /dev/ptc returns device for which ttyname fails");
        return -1;
    }
    strcpy(namebuf, name);
    *ttyfd=open(name, O_RDWR|O_NOCTTY);
    if(*ttyfd<0) {
        ioerror(name);
        close(*ptyfd);
        return -1;
    }
    return 0;
#else /* HAVE_DEV_PTS_AND_PTC */
    /* BSD-style pty code. */
    char buf[64];
    int i;
    const char *ptymajors="pqrstuvwxyzabcdefghijklmnoABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const char *ptyminors="0123456789abcdef";
    int num_minors=strlen(ptyminors);
    int num_ptys=strlen(ptymajors)*num_minors;

    for(i=0; i<num_ptys; i++) {
#ifdef HAVE_SNPRINTF
        snprintf(buf, sizeof buf,
#else
        sprintf(buf,
#endif
             "/dev/pty%c%c", ptymajors[i/num_minors],
             ptyminors[i%num_minors]);
        *ptyfd=open(buf, O_RDWR|O_NOCTTY);
        if(*ptyfd<0)
            continue;
#ifdef HAVE_SNPRINTF
        snprintf(namebuf, 64,
#else
        sprintf(namebuf,
#endif
            "/dev/tty%c%c",
            ptymajors[i/num_minors], ptyminors[i%num_minors]);

        /* open the slave side */
        *ttyfd=open(namebuf, O_RDWR | O_NOCTTY);
        if(*ttyfd<0) {
            ioerror(namebuf);
            close(*ptyfd);
            return -1;
        }
        return 0;
    }
    return -1;
#endif /* HAVE_DEV_PTS_AND_PTC */
#endif /* HAVE_DEV_PTMX */
#endif /* HAVE__GETPTY */
#endif /* HAVE_OPENPTY */
}

/* end of pty.c */
