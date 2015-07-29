/*
 *   stunnel       Universal SSL tunnel
 *   Copyright (c) 1998-2006 Michal Trojnara <Michal.Trojnara@mirt.net>
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
 *
 *   In addition, as a special exception, Michal Trojnara gives
 *   permission to link the code of this program with the OpenSSL
 *   library (or with modified versions of OpenSSL that use the same
 *   license as OpenSSL), and distribute linked combinations including
 *   the two.  You must obey the GNU General Public License in all
 *   respects for all of the code used other than OpenSSL.  If you modify
 *   this file, you may extend this exception to your version of the
 *   file, but you are not obligated to do so.  If you do not wish to
 *   do so, delete this exception statement from your version.
 */

#include "common.h"
#include "prototypes.h"
#undef exit

int main(int argc, char *argv[]) {
    static struct WSAData wsa_state;

    if(WSAStartup(MAKEWORD(1, 1), &wsa_state))
        return 1;
    main_initialize(argc>1 ? argv[1] : NULL, argc>2 ? argv[2] : NULL);
    main_execute();
    return 0;
}

void win_log(LPSTR line) { /* Also used in log.c */
    LPTSTR tstr;

    tstr=str2tstr(line);
    RETAILMSG(TRUE, (TEXT("%s\r\n"), tstr));
    free(tstr);
}

void exit_stunnel(int code) {
    exit(code);
}

int passwd_cb(char *buf, int size, int rwflag, void *userdata) {
    return 0; /* not implemented */
}

#ifdef HAVE_OSSL_ENGINE_H
int pin_cb(UI *ui, UI_STRING *uis) {
    return 0; /* not implemented */
}
#endif

/* End of nogui.c */
