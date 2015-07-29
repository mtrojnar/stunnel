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

#include "common.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

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
#ifdef __ultrix__
    openlog("stunnel", LOG_PID);
#else
    openlog("stunnel", LOG_CONS | LOG_NDELAY | LOG_PID, options.facility);
#endif /* __ultrix__ */
}

void log_close()
{
    closelog();
}

#endif /* USE_WIN32 */


/* Parse out the facility/debug level stuff */

typedef struct {
	char *name;
	int value;
} facilitylevel;


int parse_debug_level( char *optarg ) {
	char optarg_copy[STRLEN];
	char *string;
	facilitylevel *fl;

#ifndef USE_WIN32
	facilitylevel facilities[] = {
	  {"auth", LOG_AUTH}, {"cron", LOG_CRON},     {"daemon", LOG_DAEMON},
	  {"kern", LOG_KERN}, {"lpr", LOG_LPR},       {"mail", LOG_MAIL},
	  {"news", LOG_NEWS}, {"syslog", LOG_SYSLOG}, {"user", LOG_USER},
	  {"uucp", LOG_UUCP}, {"local0", LOG_LOCAL0}, {"local1", LOG_LOCAL1},
	  {"local2",LOG_LOCAL2}, {"local3",LOG_LOCAL3}, {"local4",LOG_LOCAL4},
	  {"local5",LOG_LOCAL5}, {"local6",LOG_LOCAL6}, {"local7",LOG_LOCAL7},

		/* Some that are not on all unicies */
#ifdef LOG_AUTHPRIV
		{ "authpriv", LOG_AUTHPRIV },
#endif
#ifdef LOG_FTP
		{ "ftp", LOG_FTP },
#endif
#ifdef LOG_NTP
		{ "ntp", LOG_NTP },
#endif
	  { NULL, 0 }
	};

#endif
	facilitylevel levels[] = {
		{ "emerg", LOG_EMERG },     { "alert", LOG_ALERT },
		{ "crit", LOG_CRIT },       { "err", LOG_ERR },
		{ "warning", LOG_WARNING }, { "notice", LOG_NOTICE },
		{ "info", LOG_INFO },       { "debug", LOG_DEBUG },
		{ NULL, -1 }
	};

	safecopy(optarg_copy, optarg);
	string = optarg_copy;

/* facilities only make sense on unix */
#ifndef USE_WIN32
	if ( strchr(string, '.') ) {	/* We have a facility specified */
		options.facility = -1;
		string = strtok(optarg_copy, ".");	/* break it up */

		for ( fl = facilities; fl->name; fl++ ) {
			if ( ! strcasecmp( fl->name, string ) ) {
				options.facility = fl->value;
				break;
			}
		}
		if ( options.facility == -1 ) {
			options.facility=LOG_DAEMON;
			return(0);
		}
		string = strtok(NULL, ".");	/* set to the remainder */
	}
#endif
	/* Time to check the syslog level */
	if ( strlen(string) == 1 && *string >= '0' && *string <= '7' ) {
		options.debug_level = *string - '0';
		return(1);
	} else {
		options.debug_level = 8;	/* illegal level */
		for ( fl = levels; fl->name; fl++ ) {
			if ( ! strcasecmp( fl->name, string ) ) {
				options.debug_level = fl->value;
				break;
			}
		}
		if ( options.debug_level == 8 ) {
			return(0);
		}
		return(1);
	}
	return(0);
}

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
        syslog(level, "%s", text);
    else
#endif
        fprintf(stderr, "LOG%d[%lu:%lu]: %s\n",
            level, process_id(), thread_id(), text);
    fflush(stderr);
}

