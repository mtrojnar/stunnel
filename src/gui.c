/*
 *   stunnel       Universal SSL tunnel
 *   Copyright (C) 1998-2011 Michal Trojnara <Michal.Trojnara@mirt.net>
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
#include <commdlg.h>
#include <commctrl.h>
#ifndef _WIN32_WCE
#include <psapi.h>
#endif
#include "resources.h"

#define UWM_SYSTRAY (WM_USER + 1) /* sent to us by the taskbar */
#define LOG_LINES 1000

#ifdef _WIN32_WCE
#define STUNNEL_PLATFORM "WinCE"
#else
#define STUNNEL_PLATFORM "Win32"
#define SERVICE_NAME "stunnel"
#endif

/* prototypes */
static BOOL CALLBACK set_foreground(HWND, LPARAM);
static void parse_cmdline(LPSTR);
static int initialize_winsock(void);
static int start_gui();
static void daemon_thread(void *);
static LRESULT CALLBACK window_proc(HWND, UINT, WPARAM, LPARAM);
static void update_taskbar(void);
static void save_log(void);
static int save_text_file(LPTSTR, char *);
static LRESULT CALLBACK about_proc(HWND, UINT, WPARAM, LPARAM);
static LRESULT CALLBACK pass_proc(HWND, UINT, WPARAM, LPARAM);
static void update_logs(void);
static LPTSTR log_txt(void);
static void error_box(const LPSTR);
static void message_box(const LPSTR, const UINT);

/* NT Service related function */
#ifndef _WIN32_WCE
static int service_initialize(void);
static int service_install(LPTSTR);
static int service_uninstall(void);
static int service_start(void);
static int service_stop(void);
static void WINAPI service_main(DWORD, LPTSTR *);
static void WINAPI control_handler(DWORD);
#endif /* !defined(_WIN32_WCE) */

/* global variables */
static struct LIST {
  struct LIST *next;
  int len;
  TCHAR txt[1]; /* single character for trailing '\0' */
} *head=NULL, *tail=NULL;

static struct PEER_CERT_TABLE {
    LPTSTR file, help;
    char *chain;
} *peer_cert_table;
static unsigned int number_of_sections=0;

static HINSTANCE ghInst;
static HWND edit_handle=NULL;
static HMENU tray_menu_handle=NULL;
#ifndef _WIN32_WCE
static HMENU main_menu_handle=NULL;
#endif
static HWND hwnd=NULL;
#ifdef _WIN32_WCE
static HWND command_bar_handle; /* command bar handle */
#endif
static HANDLE small_icon; /* 16x16 icon */
static TCHAR *win32_name;

#ifndef _WIN32_WCE
static SERVICE_STATUS serviceStatus;
static SERVICE_STATUS_HANDLE serviceStatusHandle=0;
#endif

static volatile int visible=0, error_mode=0;
static LONG new_logs=0;
static jmp_buf jump_buf;

static UI_DATA *ui_data=NULL;

#ifndef _WIN32_WCE
GETADDRINFO s_getaddrinfo;
FREEADDRINFO s_freeaddrinfo;
GETNAMEINFO s_getnameinfo;
#endif

static struct {
    char *config_file;
    unsigned int install:1, uninstall:1, start:1, stop:1, service:1,
        quiet:1, exit:1;
} cmdline;

int WINAPI WinMain(HINSTANCE this_instance, HINSTANCE prev_instance,
#ifdef _WIN32_WCE
        LPWSTR lpCmdLine,
#else
        LPSTR lpCmdLine,
#endif
        int nCmdShow) {
    LPSTR command_line;
#ifndef _WIN32_WCE
    char *c, *errmsg;
    char stunnel_exe_path[MAX_PATH];
#endif

    (void)prev_instance; /* skip warning about unused parameter */
    (void)nCmdShow; /* skip warning about unused parameter */

    str_init(); /* initialize per-thread string management */
    ghInst=this_instance;
#ifdef _WIN32_WCE
    command_line=tstr2str(lpCmdLine);
#else
    command_line=lpCmdLine;
#endif

    /* win32_name is needed for any error_box(), message_box(),
     * and the initial main window title */
    win32_name=TEXT("stunnel ") TEXT(STUNNEL_VERSION) TEXT(" on ")
        TEXT(STUNNEL_PLATFORM) TEXT(" (not configured)");

    parse_cmdline(command_line); /* setup global cmdline structure */

#ifndef _WIN32_WCE
    GetModuleFileName(0, stunnel_exe_path, MAX_PATH);

    /* find previous instances of the same executable */
    EnumWindows(set_foreground, (LPARAM)stunnel_exe_path);

    /* change current working directory */
    c=strrchr(stunnel_exe_path, '\\'); /* last backslash */
    if(c) /* found */
        c[1]='\0'; /* truncate program name */
    if(!SetCurrentDirectory(stunnel_exe_path)) {
        errmsg=str_printf("Cannot set directory to %s", stunnel_exe_path);
        message_box(errmsg, MB_ICONERROR);
        str_free(errmsg);
        return 1;
    }

    if(cmdline.exit)
        return 0; /* in case EnumWindows didn't find a previous instance */
#endif

    if(initialize_winsock())
        return 1;

#ifndef _WIN32_WCE
    if(cmdline.service) /* it must be checked before "-install" */
        return service_initialize();
    if(cmdline.install)
        return service_install(command_line);
    if(cmdline.uninstall)
        return service_uninstall();
    if(cmdline.start)
        return service_start();
    if(cmdline.stop)
        return service_stop();
#endif
    return start_gui();
}

#ifndef _WIN32_WCE

static BOOL CALLBACK set_foreground(HWND other_window_handle, LPARAM lParam) {
    DWORD dwProcessId;
    HINSTANCE hInstance;
    char window_exe_path[MAX_PATH];
    HANDLE hProcess;
    char *stunnel_exe_path=(char *)lParam;

    if(!other_window_handle)
        return TRUE;
    hInstance=(HINSTANCE)GetWindowLong(other_window_handle, GWL_HINSTANCE);
    GetWindowThreadProcessId(other_window_handle, &dwProcessId);
    hProcess=OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
    if(!GetModuleFileNameEx(hProcess, hInstance, window_exe_path, MAX_PATH))
        return TRUE;
    CloseHandle(hProcess);
    if(strcmp(stunnel_exe_path, window_exe_path))
        return TRUE;
    if(cmdline.exit) {
        SendMessage(other_window_handle, WM_COMMAND, IDM_EXIT, 0);
        Sleep(1000); /* give the other process some time to clean up */
    } else {
        ShowWindow(other_window_handle, SW_SHOWNORMAL); /* show window */
        SetForegroundWindow(other_window_handle); /* bring on top */
    }
    exit(0);
    return FALSE; /* should never be executed */
}

#endif

static void parse_cmdline(LPSTR command_line) {
    char *line, *c, *opt;

    line=str_dup(command_line);
    memset(&cmdline, 0, sizeof cmdline);

    c=line;
    while(*c && (*c=='/' || *c=='-')) {
        opt=c;
        while(*c && !isspace(*c)) /* skip non-whitespaces */
            c++;
        while(*c && isspace(*c)) /* replace whitespaces with '\0' */
            *c++='\0';
        if(!strcasecmp(opt+1, "install"))
            cmdline.install=1;
        else if(!strcasecmp(opt+1, "uninstall"))
            cmdline.uninstall=1;
        else if(!strcasecmp(opt+1, "start"))
            cmdline.start=1;
        else if(!strcasecmp(opt+1, "stop"))
            cmdline.stop=1;
        else if(!strcasecmp(opt+1, "service"))
            cmdline.service=1;
        else if(!strcasecmp(opt+1, "quiet"))
            cmdline.quiet=1;
        else if(!strcasecmp(opt+1, "exit"))
            cmdline.exit=1;
        else { /* option to be processed in options.c */
            cmdline.config_file=str_dup(opt);
            str_free(line);
            return; /* no need to parse other options */
        }
    }
    cmdline.config_file=str_dup(c);
    str_free(line);
}

/* try to load winsock2 resolver functions from a specified dll name */
static int initialize_winsock() {
    static struct WSAData wsa_state;
#ifndef _WIN32_WCE
    HINSTANCE handle;
#endif

    if(WSAStartup(MAKEWORD( 2, 2 ), &wsa_state)) {
        message_box("Failed to initialize winsock", MB_ICONERROR);
        return 1; /* error */
    }
#ifndef _WIN32_WCE
    handle=LoadLibrary("ws2_32.dll"); /* IPv6 in Windows XP or higher */
    if(handle) {
        s_getaddrinfo=(GETADDRINFO)GetProcAddress(handle, "getaddrinfo");
        s_freeaddrinfo=(FREEADDRINFO)GetProcAddress(handle, "freeaddrinfo");
        s_getnameinfo=(GETNAMEINFO)GetProcAddress(handle, "getnameinfo");
        if(s_getaddrinfo && s_freeaddrinfo && s_getnameinfo)
            return 0; /* IPv6 detected -> OK */
        FreeLibrary(handle);
    }
    handle=LoadLibrary("wship6.dll"); /* experimental IPv6 for Windows 2000 */
    if(handle) {
        s_getaddrinfo=(GETADDRINFO)GetProcAddress(handle, "getaddrinfo");
        s_freeaddrinfo=(FREEADDRINFO)GetProcAddress(handle, "freeaddrinfo");
        s_getnameinfo=(GETNAMEINFO)GetProcAddress(handle, "getnameinfo");
        if(s_getaddrinfo && s_freeaddrinfo && s_getnameinfo)
            return 0; /* IPv6 detected -> OK */
        FreeLibrary(handle);
    }
    s_getaddrinfo=NULL;
    s_freeaddrinfo=NULL;
    s_getnameinfo=NULL;
#endif
    return 0; /* IPv4 detected -> OK */
}

static int start_gui() {
#ifdef _WIN32_WCE
    WNDCLASS wc;
#else
    WNDCLASSEX wc;
#endif
    MSG msg;
    LPTSTR classname=TEXT("stunnel_main_window_class");

    /* register the class */
#ifndef _WIN32_WCE
    wc.cbSize=sizeof wc;
#endif
    wc.style=CS_VREDRAW|CS_HREDRAW;
    wc.lpfnWndProc=window_proc;
    wc.cbClsExtra=wc.cbWndExtra=0;
    wc.hInstance=ghInst;
    wc.hIcon=LoadIcon(ghInst, MAKEINTRESOURCE(IDI_MYICON));
    wc.hCursor=LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground=(HBRUSH)(COLOR_WINDOW+1);
    wc.lpszMenuName=NULL;
    wc.lpszClassName=classname;
    small_icon=LoadImage(ghInst, MAKEINTRESOURCE(IDI_MYICON), IMAGE_ICON,
        GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), 0);
#ifdef _WIN32_WCE
    RegisterClass(&wc);
#else
    wc.hIconSm=small_icon; /* 16x16 icon */
    RegisterClassEx(&wc);
#endif

    /* create main window */
#ifdef _WIN32_WCE
    hwnd=CreateWindow(classname, win32_name, 0,
        CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
        NULL, NULL, ghInst, NULL);
#else
    main_menu_handle=LoadMenu(ghInst, MAKEINTRESOURCE(IDM_MAINMENU));
    hwnd=CreateWindow(classname, win32_name, WS_TILEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
        NULL, main_menu_handle, ghInst, NULL);

    if(cmdline.service) { /* block unsafe operations in the service mode */
        if(main_menu_handle) {
            EnableMenuItem(main_menu_handle, IDM_EDIT_CONFIG, MF_GRAYED);
            EnableMenuItem(main_menu_handle, IDM_SAVE_LOG, MF_GRAYED);
        }
        if(tray_menu_handle) {
            EnableMenuItem(tray_menu_handle, IDM_EDIT_CONFIG, MF_GRAYED);
        }
    }
#endif
    _beginthread(daemon_thread, DEFAULT_STACK_SIZE, NULL);

    while(GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return msg.wParam;
}

static void daemon_thread(void *arg) {
    (void)arg; /* skip warning about unused parameter */

    if(!setjmp(jump_buf)) { /* catch any die() calls */
        main_initialize(
            cmdline.config_file[0] ? cmdline.config_file : NULL, NULL);
    }
    if(!setjmp(jump_buf)) { /* catch any die() calls */
        win_newconfig(error_mode);
        daemon_loop();
    }
    _endthread(); /* after signal_post(SIGNAL_TERMINATE); */
}

static LRESULT CALLBACK window_proc(HWND main_window_handle,
        UINT message, WPARAM wParam, LPARAM lParam) {
    NOTIFYICONDATA nid;
    POINT pt;
    RECT rect;

#if 0
    if(message!=WM_CTLCOLORSTATIC && message!=WM_TIMER)
        s_log(LOG_DEBUG, "Window message: %d", message);
#endif
    switch(message) {
    case WM_CREATE:
#ifdef _WIN32_WCE
        /* create command bar */
        command_bar_handle=CommandBar_Create(ghInst, main_window_handle, 1);
        if(!command_bar_handle)
            error_box("CommandBar_Create");
        if(!CommandBar_InsertMenubar(command_bar_handle, ghInst, IDM_MAINMENU, 0))
            error_box("CommandBar_InsertMenubar");
        if(!CommandBar_AddAdornments(command_bar_handle, 0, 0))
            error_box("CommandBar_AddAdornments");
#endif

        /* create child edit window */
        edit_handle=CreateWindow(TEXT("EDIT"), NULL,
            WS_CHILD|WS_VISIBLE|WS_HSCROLL|WS_VSCROLL|ES_MULTILINE|ES_READONLY,
            0, 0, 0, 0, main_window_handle, (HMENU)IDE_EDIT, ghInst, NULL);
#ifndef _WIN32_WCE
        SendMessage(edit_handle, WM_SETFONT,
            (WPARAM)CreateFont(-12, 0, 0, 0, FW_DONTCARE, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_RASTER_PRECIS, CLIP_DEFAULT_PRECIS,
                PROOF_QUALITY, DEFAULT_PITCH, TEXT("Courier")),
            MAKELPARAM(FALSE, 0)); /* no need to redraw right, now */
#endif
        /* NOTE: there's no return statement here -> proceeding with resize */

    case WM_SIZE:
        GetClientRect(main_window_handle, &rect);
#ifdef _WIN32_WCE
        MoveWindow(edit_handle, 0, CommandBar_Height(command_bar_handle),
            rect.right, rect.bottom-CommandBar_Height(command_bar_handle), TRUE);
#else
        MoveWindow(edit_handle, 0, 0, rect.right, rect.bottom, TRUE);
#endif
        UpdateWindow(edit_handle);
        /* CommandBar_Show(command_bar_handle, TRUE); */
        return TRUE;

    case WM_SETFOCUS:
        SetFocus(edit_handle);
        return TRUE;

    case WM_TIMER:
        update_taskbar();
        if(visible)
            update_logs();
        return TRUE;

    case WM_CLOSE:
        ShowWindow(main_window_handle, SW_HIDE);
        return TRUE;

    case WM_SHOWWINDOW:
        visible=wParam; /* setup global variable */
        if(tray_menu_handle)
            CheckMenuItem(tray_menu_handle, IDM_SHOW_LOG,
                visible ? MF_CHECKED : MF_UNCHECKED);
        if(visible)
            update_logs();
        return TRUE;

    case WM_DESTROY:
#ifdef _WIN32_WCE
        CommandBar_Destroy(command_bar_handle);
#else
        if(main_menu_handle)
            DestroyMenu(main_menu_handle);
#endif
        if(tray_menu_handle)
            DestroyMenu(tray_menu_handle);
        ZeroMemory(&nid, sizeof nid);
        nid.cbSize=sizeof nid;
        nid.hWnd=main_window_handle;
        nid.uID=1;
        nid.uFlags=NIF_TIP; /* not really sure what to put here, but it works */
        Shell_NotifyIcon(NIM_DELETE, &nid); /* this removes the icon */
        PostQuitMessage(0);
        KillTimer(main_window_handle, 0x29a);
        return TRUE;

    case WM_COMMAND:
        if(peer_cert_table && wParam>=IDM_PEER_MENU &&
                wParam<IDM_PEER_MENU+number_of_sections) {
            if(save_text_file(peer_cert_table[wParam-IDM_PEER_MENU].file,
                    peer_cert_table[wParam-IDM_PEER_MENU].chain))
                return TRUE;
#ifndef _WIN32_WCE
            if(main_menu_handle)
                CheckMenuItem(main_menu_handle, wParam, MF_CHECKED);
#endif
            if(tray_menu_handle)
                CheckMenuItem(tray_menu_handle, wParam, MF_CHECKED);
            message_box(peer_cert_table[wParam-IDM_PEER_MENU].help,
                MB_ICONINFORMATION);
            return TRUE;
        }
        switch(wParam) {
        case IDM_ABOUT:
            DialogBox(ghInst, TEXT("AboutBox"), main_window_handle,
                (DLGPROC)about_proc);
            break;
        case IDM_SHOW_LOG:
            if(visible) {
                ShowWindow(main_window_handle, SW_HIDE); /* hide window */
            } else {
                ShowWindow(main_window_handle, SW_SHOWNORMAL); /* show window */
                SetForegroundWindow(main_window_handle); /* bring on top */
            }
            break;
        case IDM_CLOSE:
            ShowWindow(main_window_handle, SW_HIDE); /* hide window */
            break;
        case IDM_EXIT:
            signal_post(SIGNAL_TERMINATE);
            DestroyWindow(main_window_handle);
            break;
        case IDM_SAVE_LOG:
            if(!cmdline.service) /* security */
                save_log();
            break;
        case IDM_EDIT_CONFIG:
#ifndef _WIN32_WCE
            if(!cmdline.service) /* security */
                /* ShellExecute would need ".conf" extension associated */
                _spawnlp(_P_NOWAIT, "notepad.exe", "notepad.exe",
                    "stunnel.conf", NULL);
#endif
            break;
        case IDM_RELOAD_CONFIG:
            signal_post(SIGNAL_RELOAD_CONFIG);
            break;
        case IDM_REOPEN_LOG:
            signal_post(SIGNAL_REOPEN_LOG);
            break;
        case IDM_MANPAGE:
#ifndef _WIN32_WCE
            if(!cmdline.service) /* security */
                ShellExecute(main_window_handle, "open",
                    "stunnel.html", NULL, NULL, SW_SHOWNORMAL);
#endif
            break;
        case IDM_HOMEPAGE:
#ifndef _WIN32_WCE
            if(!cmdline.service) /* security */
                ShellExecute(main_window_handle, "open",
                    "http://www.stunnel.org/", NULL, NULL, SW_SHOWNORMAL);
#endif
            break;
        }
        return TRUE;

    case UWM_SYSTRAY: /* a taskbar event */
        switch(lParam) {
#ifdef _WIN32_WCE
        case WM_LBUTTONDOWN: /* no right mouse button on Windows CE */
            GetWindowRect(GetDesktopWindow(), &rect); /* no cursor position */
            pt.x=rect.right;
            pt.y=rect.bottom-25;
#else
        case WM_RBUTTONDOWN:
            GetCursorPos(&pt);
#endif
            SetForegroundWindow(main_window_handle);
            TrackPopupMenuEx(GetSubMenu(tray_menu_handle, 0), TPM_BOTTOMALIGN,
                pt.x, pt.y, main_window_handle, NULL);
            PostMessage(main_window_handle, WM_NULL, 0, 0);
            break;
#ifndef _WIN32_WCE
        case WM_LBUTTONDBLCLK: /* switch log window visibility */
            if(visible) {
                ShowWindow(main_window_handle, SW_HIDE); /* hide window */
            } else {
                ShowWindow(main_window_handle, SW_SHOWNORMAL); /* show window */
                SetForegroundWindow(main_window_handle); /* bring on top */
            }
            break;
#endif
        }
        return TRUE;
    }
    return DefWindowProc(main_window_handle, message, wParam, lParam);
}

static LRESULT CALLBACK about_proc(HWND dialog_handle, UINT message,
        WPARAM wParam, LPARAM lParam) {
    (void)lParam; /* skip warning about unused parameter */

    switch(message) {
        case WM_INITDIALOG:
            return TRUE;
        case WM_COMMAND:
            switch(wParam) {
                case IDOK:
                case IDCANCEL:
                    EndDialog(dialog_handle, TRUE);
                    return TRUE;
            }
    }
    return FALSE;
}

static LRESULT CALLBACK pass_proc(HWND dialog_handle, UINT message,
        WPARAM wParam, LPARAM lParam) {
    char *titlebar;
    LPTSTR tstr;
    union {
        TCHAR txt[PEM_BUFSIZE];
        WORD len;
    } pass_dialog;
    WORD pass_len;
    char* pass_txt;

    switch(message) {
    case WM_INITDIALOG:
        /* set the default push button to "Cancel" */
        SendMessage(dialog_handle, DM_SETDEFID, (WPARAM)IDCANCEL, (LPARAM)0);

        titlebar=str_printf("Private key: %s", ui_data->section->key);
        tstr=str2tstr(titlebar);
        str_free(titlebar);
        SetWindowText(dialog_handle, tstr);
        str_free(tstr);
        return TRUE;

    case WM_COMMAND:
        /* set the default push button to "OK" when the user enters text */
        if(HIWORD(wParam)==EN_CHANGE && LOWORD(wParam)==IDE_PASSEDIT)
            SendMessage(dialog_handle, DM_SETDEFID, (WPARAM)IDOK, (LPARAM)0);
        switch(wParam) {
        case IDOK:
            /* get number of characters */
            pass_len=(WORD)SendDlgItemMessage(dialog_handle,
                IDE_PASSEDIT, EM_LINELENGTH, (WPARAM)0, (LPARAM)0);
            if(!pass_len || pass_len>=PEM_BUFSIZE) {
                EndDialog(dialog_handle, FALSE);
                return FALSE;
            }

            /* put the number of characters into first word of buffer */
            pass_dialog.len=pass_len;

            /* get the characters */
            SendDlgItemMessage(dialog_handle, IDE_PASSEDIT, EM_GETLINE,
                (WPARAM)0 /* line 0 */, (LPARAM)pass_dialog.txt);
            pass_dialog.txt[pass_len]='\0'; /* null-terminate the string */

            /* convert input password to ANSI string (as ui_data->pass) */
            pass_txt=tstr2str(pass_dialog.txt);
            strcpy(ui_data->pass, pass_txt);
            str_free(pass_txt);

            EndDialog(dialog_handle, TRUE);
            return TRUE;

        case IDCANCEL:
            EndDialog(dialog_handle, FALSE);
            return TRUE;
        }
        return 0;
    }
    return FALSE;

    UNREFERENCED_PARAMETER(lParam);
}

int passwd_cb(char *buf, int size, int rwflag, void *userdata) {
    (void)rwflag; /* skip warning about unused parameter */

    ui_data=userdata;
    if(!DialogBox(ghInst, TEXT("PassBox"), hwnd, (DLGPROC)pass_proc))
        return 0; /* error */
    strncpy(buf, ui_data->pass, size);
    buf[size-1]='\0';
    return strlen(buf);
}

#ifdef HAVE_OSSL_ENGINE_H
int pin_cb(UI *ui, UI_STRING *uis) {
    ui_data=UI_get0_user_data(ui); /* was: ui_data=UI_get_app_data(ui); */
    if(!ui_data) {
        s_log(LOG_ERR, "INTERNAL ERROR: user data data pointer");
        return 0;
    }
    if(!DialogBox(ghInst, TEXT("PassBox"), hwnd, (DLGPROC)pass_proc))
        return 0; /* error */
    UI_set_result(ui, uis, ui_data->pass);
    return 1;
}
#endif

static void save_log() {
    TCHAR file_name[MAX_PATH];
    OPENFILENAME ofn;
    LPTSTR txt;
    LPSTR str;

    ZeroMemory(&ofn, sizeof ofn);
    file_name[0]='\0';

    ofn.lStructSize=sizeof ofn;
    ofn.hwndOwner=hwnd;
    ofn.lpstrFilter=TEXT("Log Files (*.log)\0*.log\0All Files (*.*)\0*.*\0\0");
    ofn.lpstrFile=file_name;
    ofn.nMaxFile=MAX_PATH;
    ofn.lpstrDefExt=TEXT("LOG");
    ofn.lpstrInitialDir=TEXT(".");

    ofn.lpstrTitle=TEXT("Save Log");
    ofn.Flags=OFN_EXPLORER | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY |
        OFN_OVERWRITEPROMPT;
    if(!GetSaveFileName(&ofn))
        return;

    txt=log_txt(); /* need to convert the result to plain ASCII */
    if(!txt) {
        s_log(LOG_CRIT, "Out of memory");
        return;
    }
    str=tstr2str(txt);
    str_free(txt);
    if(!str) {
        s_log(LOG_CRIT, "Out of memory");
        return;
    }
    save_text_file(file_name, str);
    str_free(str);
}

static int save_text_file(LPTSTR file_name, char *str) {
    HANDLE file_handle;
    DWORD ignore;

    file_handle=CreateFile(file_name, GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if(file_handle==INVALID_HANDLE_VALUE) {
        error_box("CreateFile");
        return 1;
    }
    if(!WriteFile(file_handle, str, strlen(str), &ignore, NULL)) {
        CloseHandle(file_handle);
        error_box("WriteFile");
        return 1;
    }
    CloseHandle(file_handle);
    return 0;
}

void win_log(LPSTR line) { /* also used in log.c */
    struct LIST *curr;
    int len;
    static int log_len=0;
    LPTSTR txt;

    txt=str2tstr(line);
    len=_tcslen(txt);
    /* this list is shared between threads */
    curr=str_alloc(sizeof(struct LIST)+len*sizeof(TCHAR));
    str_detach(curr);
    curr->len=len;
    _tcscpy(curr->txt, txt);
    str_free(txt);
    curr->next=NULL;

    enter_critical_section(CRIT_WIN_LOG);
    if(tail)
        tail->next=curr;
    tail=curr;
    if(!head)
        head=tail;
    log_len++;
    while(log_len>LOG_LINES) {
        curr=head;
        head=head->next;
        /* this list is shared between threads */
        str_free(curr);
        log_len--;
    }
    leave_critical_section(CRIT_WIN_LOG);

    new_logs=1;
}

static void update_logs(void) {
    LPTSTR txt;

    if(!InterlockedExchange(&new_logs, 0))
        return;
    txt=log_txt();
    if(!txt)
        return;
    SetWindowText(edit_handle, txt);
    str_free(txt);
    SendMessage(edit_handle, WM_VSCROLL, (WPARAM)SB_BOTTOM, (LPARAM)0);
}

static LPTSTR log_txt(void) {
    LPTSTR buff;
    int ptr=0, len=0;
    struct LIST *curr;

    enter_critical_section(CRIT_WIN_LOG);
    for(curr=head; curr; curr=curr->next)
        len+=curr->len+2; /* +2 for trailing '\r\n' */
    buff=str_alloc((len+1)*sizeof(TCHAR)); /* +1 for trailing '\0' */
    if(!buff) {
        leave_critical_section(CRIT_WIN_LOG);
        return NULL;
    }
    for(curr=head; curr; curr=curr->next) {
        memcpy(buff+ptr, curr->txt, curr->len*sizeof(TCHAR));
        ptr+=curr->len;
        if(curr->next) {
            buff[ptr++]='\r';
            buff[ptr++]='\n';
        }
    }
    buff[ptr]='\0';
    leave_critical_section(CRIT_WIN_LOG);

    return buff;
}

/* called from start_gui() on first load, and from network.c on reload */
/* NOTE: initialization has to be completed or win_newcert() will fail */
void win_newconfig(int err) { /* 0 - successs, 1 - error */
    SERVICE_OPTIONS *section;
    MENUITEMINFO mii;
#ifndef _WIN32_WCE
    HMENU main_peer_list=NULL;
#endif
    HMENU tray_peer_list=NULL;
    char *str;
    unsigned int section_number;

    error_mode=err; /* only really used on reload */

    /* update the main window title */
    if(error_mode) {
        win32_name=TEXT("stunnel ") TEXT(STUNNEL_VERSION) TEXT(" on ")
            TEXT(STUNNEL_PLATFORM) TEXT(" (invalid stunnel.conf)");
    } else {
#ifdef _WIN32_WCE
        win32_name=TEXT("stunnel ") TEXT(STUNNEL_VERSION) TEXT(" on WinCE");
#else
        win32_name=TEXT("stunnel ") TEXT(STUNNEL_VERSION) TEXT(" on ")
            TEXT(STUNNEL_PLATFORM);
#endif
    }
    if(hwnd) {
        SetWindowText(hwnd, win32_name);
        if(error_mode) { /* log window is hidden by default */
            ShowWindow(hwnd, SW_SHOWNORMAL); /* show window */
            SetForegroundWindow(hwnd); /* bring on top */
        }
    }

    /* initialize taskbar */
    if(global_options.option.taskbar) { /* save menu resources */
        if(!tray_menu_handle)
            tray_menu_handle=LoadMenu(ghInst, MAKEINTRESOURCE(IDM_TRAYMENU));
        SetTimer(hwnd, 0x29a, 1000, NULL); /* 1-second timer */
        update_taskbar();
    }

    /* purge menu peer lists */
#ifndef _WIN32_WCE
    if(main_menu_handle)
        main_peer_list=GetSubMenu(main_menu_handle, 2); /* 3rd submenu */
    if(main_peer_list)
        while(GetMenuItemCount(main_peer_list)) /* purge old menu */
            DeleteMenu(main_peer_list, 0, MF_BYPOSITION); 
#endif
    if(tray_menu_handle)
        tray_peer_list=GetSubMenu(GetSubMenu(tray_menu_handle, 0), 2);
    if(tray_peer_list)
        while(GetMenuItemCount(tray_peer_list)) /* purge old menu */
            DeleteMenu(tray_peer_list, 0, MF_BYPOSITION);
    if(peer_cert_table) {
        for(section_number=0; section_number<number_of_sections;
                ++section_number) {
            if(peer_cert_table[section_number].file)
                str_free(peer_cert_table[section_number].file);
            if(peer_cert_table[section_number].help)
                str_free(peer_cert_table[section_number].help);
            if(peer_cert_table[section_number].chain)
                str_free(peer_cert_table[section_number].chain);
        }
        str_free(peer_cert_table);
    }

    /* initialize data structures */
    number_of_sections=0;
    for(section=service_options.next; section; section=section->next)
        section->section_number=number_of_sections++;
    peer_cert_table=
        str_alloc(number_of_sections*sizeof(struct PEER_CERT_TABLE));
    str_detach(peer_cert_table);

    section_number=0;
    for(section=service_options.next; section; section=section->next) {
        /* setup peer_cert_table[section_number].file */
        str=str_printf("peer-%s.pem", section->servname);
        if(!str) {
            s_log(LOG_CRIT, "Out of memory");
            return;
        }
        peer_cert_table[section_number].file=str2tstr(str);
        if(!peer_cert_table[section_number].file) {
            s_log(LOG_CRIT, "Out of memory");
            return;
        }
        str_free(str);
        str_detach(peer_cert_table[section_number].file);
        str=str_printf("peer-%s.pem", section->servname);
        if(!str) {
            s_log(LOG_CRIT, "Out of memory");
            return;
        }

        /* setup peer_cert_table[section_number].help */
        peer_cert_table[section_number].file=str2tstr(str);
        str=str_printf(
            "Peer certificate chain has been saved.\n"
            "Add the following lines to section [%s]:\n"
            "\tCAfile = peer-%s.pem\n"
            "\tverify = 3\n"
            "to enable cryptographic authentication.\n"
            "Then reload stunnel configuration file.",
            section->servname, section->servname);
        peer_cert_table[section_number].help=str2tstr(str);
        str_free(str);
        str_detach(peer_cert_table[section_number].help);

        /* setup peer_cert_table[section_number].chain */
        /* the value is later cached value in win_newcert() */
        peer_cert_table[section_number].chain=NULL;

        /* insert new menu item */
        mii.cbSize=sizeof mii;
        mii.fMask=MIIM_STRING|MIIM_DATA|MIIM_ID|MIIM_STATE;
        mii.fType=MFT_STRING;
        mii.dwTypeData=peer_cert_table[section_number].file;
        mii.cch=_tcslen(mii.dwTypeData);
        mii.wID=IDM_PEER_MENU+section_number;
        mii.fState=MFS_GRAYED;
#ifndef _WIN32_WCE
        if(main_peer_list)
            if(!InsertMenuItem(main_peer_list, section_number, TRUE, &mii))
                ioerror("InsertMenuItem");
#endif
        if(tray_peer_list)
            if(!InsertMenuItem(tray_peer_list, section_number, TRUE, &mii))
                ioerror("InsertMenuItem");
        ++section_number;
    }
    if(hwnd)
        DrawMenuBar(hwnd);

    /* enable IDM_REOPEN_LOG menu if a log file is used, disable otherwise */
#ifndef _WIN32_WCE
    if(main_menu_handle)
        EnableMenuItem(main_menu_handle, IDM_REOPEN_LOG,
            global_options.output_file ? MF_ENABLED : MF_GRAYED);
#endif
    if(tray_menu_handle)
        EnableMenuItem(tray_menu_handle, IDM_REOPEN_LOG,
            global_options.output_file ? MF_ENABLED : MF_GRAYED);

    /* a message box indicating error mode */
    if(error_mode) {
        win_log("");
        s_log(LOG_ERR, "Server is down");
        message_box("Stunnel server is down due to an error.\n"
            "You need to exit and correct the problem.\n"
            "Click OK to see the error log window.",
            MB_ICONERROR);
    }
}

static void update_taskbar(void) { /* create the taskbar icon */
    NOTIFYICONDATA nid;

    ZeroMemory(&nid, sizeof nid);
    nid.cbSize=sizeof nid; /* size */
    nid.hWnd=hwnd; /* window to receive notifications */
    nid.uID=1;     /* application-defined ID for icon */
    if(error_mode)
        _stprintf(nid.szTip, TEXT("Server is down"));
    else
        _stprintf(nid.szTip, TEXT("%d session(s) active"), num_clients);
    nid.uFlags=NIF_TIP;
    /* only nid.szTip and nid.uID are valid, change tip */
    if(Shell_NotifyIcon(NIM_MODIFY, &nid)) /* modify tooltip */
        return; /* OK: taskbar icon exists */

    /* trying to update tooltip failed - lets try to create the icon */
    nid.uFlags=NIF_MESSAGE | NIF_ICON | NIF_TIP;
    nid.uCallbackMessage=UWM_SYSTRAY;
    nid.hIcon=small_icon; /* 16x16 icon */
    Shell_NotifyIcon(NIM_ADD, &nid); /* this adds the icon */
}

/* called from client.c when a new session is negotiated */
void win_newcert(SSL *ssl, SERVICE_OPTIONS *section) {
    BIO *bio;
    int i, len;
    X509 *peer=NULL;
    STACK_OF(X509) *sk;

    if(!peer_cert_table) {
        s_log(LOG_ERR, "INTERNAL ERROR: peer_cert_table not initialized");
        return;
    }
    if(peer_cert_table[section->section_number].chain)
        return; /* a peer certificate was already cached */

    s_log(LOG_DEBUG, "A new certificate was received");
    bio=BIO_new(BIO_s_mem());
    if(!bio)
        return;
    sk=SSL_get_peer_cert_chain(ssl);
    for(i=0; sk && i<sk_X509_num(sk); i++) {
        peer=sk_X509_value(sk, i);
        PEM_write_bio_X509(bio, peer);
    }
    if(!sk || !section->option.client) {
        peer=SSL_get_peer_certificate(ssl);
        if(peer) {
            PEM_write_bio_X509(bio, peer);
            X509_free(peer);
        }
    }
    len=BIO_pending(bio);
    peer_cert_table[section->section_number].chain=str_alloc(len+1);
    if(!peer_cert_table[section->section_number].chain) {
        BIO_free(bio);
        return;
    }
    str_detach(peer_cert_table[section->section_number].chain);
    len=BIO_read(bio, peer_cert_table[section->section_number].chain, len);
    if(len<0) {
        BIO_free(bio);
        str_free(peer_cert_table[section->section_number].chain);
        return;
    }
    peer_cert_table[section->section_number].chain[len]='\0';
    BIO_free(bio);
    s_log(LOG_DEBUG, "A new certificate was cached (%d bytes)", len);

#ifndef _WIN32_WCE
    if(main_menu_handle)
        EnableMenuItem(main_menu_handle, IDM_PEER_MENU+section->section_number,
            MF_ENABLED);
#endif
    if(tray_menu_handle)
        EnableMenuItem(tray_menu_handle, IDM_PEER_MENU+section->section_number,
            MF_ENABLED);
}

void win_exit(int exit_code) { /* used instead of exit() on Win32 */
    (void)exit_code; /* skip warning about unused parameter */

    if(cmdline.quiet) /* e.g. uninstallation with broken config */
        exit(exit_code); /* just quit */
    error_mode=1;
    unbind_ports();
    longjmp(jump_buf, 1);
}

static void error_box(const LPSTR text) {
    char *errmsg, *fullmsg;
    LPTSTR tstr;
    long dw;

    dw=GetLastError();
    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM,
        NULL, dw, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&tstr, 0, NULL);
    errmsg=tstr2str(tstr);
    LocalFree(tstr);
    fullmsg=str_printf("%s: error %ld: %s", text, dw, errmsg);
    str_free(errmsg);
    message_box(fullmsg, MB_ICONERROR);
    str_free(fullmsg);
}

static void message_box(const LPSTR text, const UINT type) {
    LPTSTR tstr;

    if(cmdline.quiet)
        return;
    tstr=str2tstr(text);
    MessageBox(hwnd, tstr, win32_name, type);
    str_free(tstr);
}

#ifndef _WIN32_WCE

static int service_initialize(void) {
    SERVICE_TABLE_ENTRY serviceTable[]={{0, 0}, {0, 0}};

    serviceTable[0].lpServiceName=SERVICE_NAME;
    serviceTable[0].lpServiceProc=service_main;
    global_options.option.taskbar=0; /* disable taskbar for security */
    if(!StartServiceCtrlDispatcher(serviceTable)) {
        error_box("StartServiceCtrlDispatcher");
        return 1;
    }
    return 0; /* NT service started */
}

static int service_install(LPSTR command_line) {
    SC_HANDLE scm, service;
    char stunnel_exe_path[MAX_PATH], *service_path;

    scm=OpenSCManager(0, 0, SC_MANAGER_CREATE_SERVICE);
    if(!scm) {
        error_box("OpenSCManager");
        return 1;
    }
    GetModuleFileName(0, stunnel_exe_path, MAX_PATH);
    service_path=str_printf("\"%s\" -service %s", stunnel_exe_path, command_line);
    service=CreateService(scm, SERVICE_NAME, SERVICE_NAME, SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS|SERVICE_INTERACTIVE_PROCESS,
        SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, service_path,
        NULL, NULL, NULL, NULL, NULL);
    str_free(service_path);
    if(!service) {
        error_box("CreateService");
        CloseServiceHandle(scm);
        return 1;
    }
    message_box("Service installed", MB_ICONINFORMATION);
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return 0;
}

static int service_uninstall(void) {
    SC_HANDLE scm, service;
    SERVICE_STATUS serviceStatus;

    scm=OpenSCManager(0, 0, SC_MANAGER_CONNECT);
    if(!scm) {
        error_box("OpenSCManager");
        return 1;
    }
    service=OpenService(scm, SERVICE_NAME, SERVICE_QUERY_STATUS|DELETE);
    if(!service) {
        error_box("OpenService");
        CloseServiceHandle(scm);
        return 1;
    }
    if(!QueryServiceStatus(service, &serviceStatus)) {
        error_box("QueryServiceStatus");
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return 1;
    }
    if(serviceStatus.dwCurrentState!=SERVICE_STOPPED) {
        message_box("The service is still running", MB_ICONERROR);
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return 1;
    }
    if(!DeleteService(service)) {
        error_box("DeleteService");
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return 1;
    }
    message_box("Service uninstalled", MB_ICONINFORMATION);
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return 0;
}

static int service_start(void) {
    SC_HANDLE scm, service;
    SERVICE_STATUS serviceStatus;

    scm=OpenSCManager(0, 0, SC_MANAGER_CONNECT);
    if(!scm) {
        error_box("OpenSCManager");
        return 1;
    }
    service=OpenService(scm, SERVICE_NAME, SERVICE_QUERY_STATUS|SERVICE_START);
    if(!service) {
        error_box("OpenService");
        CloseServiceHandle(scm);
        return 1;
    }
    if(!StartService(service, 0, NULL)) {
        error_box("StartService");
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return 1;
    }
    do {
        Sleep(1000);
        if(!QueryServiceStatus(service, &serviceStatus)) {
            error_box("QueryServiceStatus");
            CloseServiceHandle(service);
            CloseServiceHandle(scm);
            return 1;
        }
    } while(serviceStatus.dwCurrentState==SERVICE_START_PENDING);
    if(serviceStatus.dwCurrentState!=SERVICE_RUNNING) {
        message_box("Failed to start service", MB_ICONERROR);
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return 1;
    }
    message_box("Service started", MB_ICONINFORMATION);
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return 0;
}

static int service_stop(void) {
    SC_HANDLE scm, service;
    SERVICE_STATUS serviceStatus;

    scm=OpenSCManager(0, 0, SC_MANAGER_CONNECT);
    if(!scm) {
        error_box("OpenSCManager");
        return 1;
    }
    service=OpenService(scm, SERVICE_NAME, SERVICE_QUERY_STATUS|SERVICE_STOP);
    if(!service) {
        error_box("OpenService");
        CloseServiceHandle(scm);
        return 1;
    }
    if(!QueryServiceStatus(service, &serviceStatus)) {
        error_box("QueryServiceStatus");
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return 1;
    }
    if(serviceStatus.dwCurrentState==SERVICE_STOPPED) {
        message_box("The service is already stopped", MB_ICONERROR);
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return 1;
    }
    if(!ControlService(service, SERVICE_CONTROL_STOP, &serviceStatus)) {
        error_box("ControlService");
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return 1;
    }
    do {
        Sleep(1000);
        if(!QueryServiceStatus(service, &serviceStatus)) {
            error_box("QueryServiceStatus");
            CloseServiceHandle(service);
            CloseServiceHandle(scm);
            return 1;
        }
    } while(serviceStatus.dwCurrentState!=SERVICE_STOPPED);
    message_box("Service stopped", MB_ICONINFORMATION);
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return 0;
}

static void WINAPI service_main(DWORD argc, LPTSTR* argv) {
    (void)argc; /* skip warning about unused parameter */
    (void)argv; /* skip warning about unused parameter */

    /* initialise service status */
    serviceStatus.dwServiceType=SERVICE_WIN32;
    serviceStatus.dwCurrentState=SERVICE_STOPPED;
    serviceStatus.dwControlsAccepted=0;
    serviceStatus.dwWin32ExitCode=NO_ERROR;
    serviceStatus.dwServiceSpecificExitCode=NO_ERROR;
    serviceStatus.dwCheckPoint=0;
    serviceStatus.dwWaitHint=0;

    serviceStatusHandle=
        RegisterServiceCtrlHandler(SERVICE_NAME, control_handler);

    if(serviceStatusHandle) {
        /* service is starting */
        serviceStatus.dwCurrentState=SERVICE_START_PENDING;
        SetServiceStatus(serviceStatusHandle, &serviceStatus);

        /* running */
        serviceStatus.dwControlsAccepted|=
            (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN);
        serviceStatus.dwCurrentState=SERVICE_RUNNING;
        SetServiceStatus(serviceStatusHandle, &serviceStatus);

        start_gui();

        /* service was stopped */
        serviceStatus.dwCurrentState=SERVICE_STOP_PENDING;
        SetServiceStatus(serviceStatusHandle, &serviceStatus);

        /* service is now stopped */
        serviceStatus.dwControlsAccepted&=
            ~(SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN);
        serviceStatus.dwCurrentState=SERVICE_STOPPED;
        SetServiceStatus(serviceStatusHandle, &serviceStatus);
    }
}

static void WINAPI control_handler(DWORD controlCode) {
    switch(controlCode) {
    case SERVICE_CONTROL_INTERROGATE:
        break;

    case SERVICE_CONTROL_SHUTDOWN:
    case SERVICE_CONTROL_STOP:
        serviceStatus.dwCurrentState=SERVICE_STOP_PENDING;
        SetServiceStatus(serviceStatusHandle, &serviceStatus);
        PostMessage(hwnd, WM_COMMAND, IDM_EXIT, 0);
        return;

    case SERVICE_CONTROL_PAUSE:
        break;

    case SERVICE_CONTROL_CONTINUE:
        break;

    default:
        if(controlCode >= 128 && controlCode <= 255)
            break; /* user defined control code */
        else
            break; /* unrecognised control code */
    }

    SetServiceStatus(serviceStatusHandle, &serviceStatus);
}

#endif /* !defined(_WIN32_WCE) */

/* end of gui.c */
