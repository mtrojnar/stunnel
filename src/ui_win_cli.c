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

int main(int argc, char *argv[]) {
    static struct WSAData wsa_state;
    TCHAR *c, stunnel_exe_path[MAX_PATH];

    tls_init(); /* initialize thread-local storage */

    /* set current working directory and engine path */
    GetModuleFileName(0, stunnel_exe_path, MAX_PATH);
    c=_tcsrchr(stunnel_exe_path, TEXT('\\')); /* last backslash */
    if(c) /* found */
        c[1]=TEXT('\0'); /* truncate program name */
#ifndef _WIN32_WCE
    if(!SetCurrentDirectory(stunnel_exe_path)) {
        /* log to stderr, as s_log() is not initialized */
        _ftprintf(stderr, TEXT("Cannot set directory to %s"),
            stunnel_exe_path);
        return 1;
    }
#endif
    _tputenv(str_tprintf(TEXT("OPENSSL_ENGINES=%s"), stunnel_exe_path));

    if(WSAStartup(MAKEWORD(1, 1), &wsa_state))
        return 1;
    resolver_init();
    main_init();
    if(!main_configure(argc>1 ? argv[1] : NULL, argc>2 ? argv[2] : NULL))
        daemon_loop();
    main_cleanup();
    return 0;
}

/**************************************** options callbacks */

void ui_config_reloaded(void) {
    /* no action */
}

ICON_IMAGE load_icon_default(ICON_TYPE type) {
    (void)type; /* skip warning about unused parameter */
    return NULL;
}

ICON_IMAGE load_icon_file(const char *name) {
    (void)name; /* skip warning about unused parameter */
    return NULL;
}

/**************************************** client callbacks */

void ui_new_chain(const unsigned section_number) {
    (void)section_number; /* skip warning about unused parameter */
}

void ui_clients(const long num) {
    (void)num; /* skip warning about unused parameter */
}

/**************************************** s_log callbacks */

void message_box(LPCTSTR text, const UINT type) {
    MessageBox(NULL, text, TEXT("stunnel"), type);
}

void ui_new_log(const char *line) {
    LPTSTR tstr;

    tstr=str2tstr(line);
#ifdef _WIN32_WCE
    /* log to Windows CE debug output stream */
    RETAILMSG(TRUE, (TEXT("%s\r\n"), tstr));
#else
    /* use UTF-16 or native codepage rather than UTF-8 */
    _ftprintf(stderr, TEXT("%s\r\n"), tstr);
    fflush(stderr);
#endif
    str_free(tstr);
}

/**************************************** ctx callbacks */

int passwd_cb(char *buf, int size, int rwflag, void *userdata) {
    (void)buf; /* skip warning about unused parameter */
    (void)size; /* skip warning about unused parameter */
    (void)rwflag; /* skip warning about unused parameter */
    (void)userdata; /* skip warning about unused parameter */
    return 0; /* not implemented */
}

#ifndef OPENSSL_NO_ENGINE
int pin_cb(UI *ui, UI_STRING *uis) {
    (void)ui; /* skip warning about unused parameter */
    (void)uis; /* skip warning about unused parameter */
    return 0; /* not implemented */
}
#endif

/* end of ui_win_cli.c */
