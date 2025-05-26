/*
 *   stunnel       TLS offloading and load-balancing proxy
 *   Copyright (C) 1998-2025 Michal Trojnara <Michal.Trojnara@stunnel.org>
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

int main(int argc, char *argv[]) {
    if(stunnel_init())
        return 1;
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
    (void)type; /* squash the unused parameter warning */
    return NULL;
}

ICON_IMAGE load_icon_file(const char *name) {
    (void)name; /* squash the unused parameter warning */
    return NULL;
}

/**************************************** client callbacks */

void ui_new_chain(const unsigned section_number) {
    (void)section_number; /* squash the unused parameter warning */
}

void ui_clients(const long num) {
    (void)num; /* squash the unused parameter warning */
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
    _putts(tstr);
    fflush(stdout);
#endif
    str_free(tstr);
}

/**************************************** ctx callbacks */

int ui_passwd_cb(char *buf, int size, int rwflag, void *userdata) {
    return PEM_def_callback(buf, size, rwflag, userdata);
}

#if !defined(OPENSSL_NO_ENGINE) || OPENSSL_VERSION_NUMBER>=0x10101000L

int (*ui_get_opener(void)) (UI *) {
    return UI_method_get_opener(UI_OpenSSL());
}

int (*ui_get_writer(void)) (UI *, UI_STRING *) {
    return UI_method_get_writer(UI_OpenSSL());
}

int (*ui_get_reader(void)) (UI *, UI_STRING *) {
    return UI_method_get_reader(UI_OpenSSL());
}

int (*ui_get_closer(void)) (UI *) {
    return UI_method_get_closer(UI_OpenSSL());
}

#endif /* !defined(OPENSSL_NO_ENGINE) || OPENSSL_VERSION_NUMBER>=0x10101000L */

/* end of ui_win_cli.c */
