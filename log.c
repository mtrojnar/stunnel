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

#include "common.h"
#include <stdio.h>
#include <stdarg.h>

extern server_options options;

#ifdef USE_WIN32

void log_open()
{
}

void log_close()
{
}

#else /* USE_WIN32 */

void log_open()
{
    openlog("stunnel", LOG_CONS | LOG_NDELAY | LOG_PID, LOG_DAEMON);
}

void log_close()
{
    closelog();
}

#endif /* USE_WIN32 */

void log(int level, char *format, ...)
{
    va_list arglist;
    char text[256];

    if(level>options.debug_level)
        return;
    va_start(arglist, format);
#ifdef HAVE_VSNPRINTF
    vsnprintf(text, 256, format, arglist);
#else
    vsprintf(text, format, arglist);
#endif
    va_end(arglist);
#ifndef USE_WIN32
    if(!options.foreground)
        syslog(level, text);
    else
#endif
        fprintf(stderr, "LOG%d[%lu:%lu]: %s\n",
            level, process_id(), thread_id(), text);
}

