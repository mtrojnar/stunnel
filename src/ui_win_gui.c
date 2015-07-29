/*
 *   stunnel       Universal SSL tunnel
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
#include <commdlg.h>
#include <commctrl.h>
#ifndef _WIN32_WCE
#include <psapi.h>
#endif
#include "resources.h"

#define LOG_LINES 1000

#ifdef _WIN32_WCE
#define STUNNEL_PLATFORM "WinCE"
#else
#ifdef _WIN64
#define STUNNEL_PLATFORM "Win64"
#else /* MSDN claims that _WIN32 is always defined */
#define STUNNEL_PLATFORM "Win32"
#endif
#define SERVICE_NAME TEXT("stunnel")
#define SERVICE_DISPLAY_NAME TEXT("Stunnel SSL wrapper")
#endif

/* mingw-Patches-1825044 is missing in Debian Squeeze */
WINBASEAPI BOOL WINAPI CheckTokenMembership(HANDLE, PSID, PBOOL);

/* prototypes */
NOEXPORT BOOL CALLBACK enum_windows(HWND, LPARAM);
NOEXPORT void gui_cmdline();
NOEXPORT int initialize_winsock(void);
NOEXPORT int gui_loop();

NOEXPORT void CALLBACK timer_proc(HWND, UINT, UINT_PTR, DWORD);
NOEXPORT LRESULT CALLBACK window_proc(HWND, UINT, WPARAM, LPARAM);
NOEXPORT LRESULT CALLBACK about_proc(HWND, UINT, WPARAM, LPARAM);
NOEXPORT LRESULT CALLBACK pass_proc(HWND, UINT, WPARAM, LPARAM);

NOEXPORT void save_log(void);
NOEXPORT void win_log(LPCTSTR);
NOEXPORT int save_text_file(LPTSTR, char *);
NOEXPORT void update_logs(void);
NOEXPORT LPTSTR log_txt(void);

NOEXPORT void daemon_thread(void *);

NOEXPORT void valid_config(void);
NOEXPORT void invalid_config(void);
NOEXPORT void update_peer_menu(void);
NOEXPORT void update_tray(const int);
NOEXPORT void error_box(LPCTSTR);
NOEXPORT void edit_config(HWND);
NOEXPORT BOOL is_admin(void);

/* NT Service related function */
#ifndef _WIN32_WCE
NOEXPORT int service_initialize(void);
NOEXPORT int service_install(void);
NOEXPORT int service_uninstall(void);
NOEXPORT int service_start(void);
NOEXPORT int service_stop(void);
NOEXPORT void WINAPI service_main(DWORD, LPTSTR *);
NOEXPORT void WINAPI control_handler(DWORD);
#endif /* !defined(_WIN32_WCE) */

/* other functions */
NOEXPORT LPTSTR get_params();

/* global variables */
static struct LIST {
  struct LIST *next;
  int len;
  TCHAR txt[1]; /* single character for trailing '\0' */
} *head=NULL, *tail=NULL;

static unsigned number_of_sections=0;

static HINSTANCE ghInst;
static HWND edit_handle=NULL;
static HMENU tray_menu_handle=NULL;
#ifndef _WIN32_WCE
static HMENU main_menu_handle=NULL;
#endif
static HWND hwnd=NULL; /* main window handle */
#ifdef _WIN32_WCE
static HWND command_bar_handle; /* command bar handle */
#endif
    /* win32_name is needed for any error_box(), message_box(),
     * and the initial main window title */
static TCHAR *win32_name=TEXT("stunnel ") TEXT(STUNNEL_VERSION)
    TEXT(" on ") TEXT(STUNNEL_PLATFORM) TEXT(" (not configured)");

#ifndef _WIN32_WCE
static SERVICE_STATUS serviceStatus;
static SERVICE_STATUS_HANDLE serviceStatusHandle=0;
#endif

static BOOL visible=FALSE;
static HANDLE main_initialized=NULL; /* global initialization performed */
static HANDLE config_ready=NULL; /* reload without a valid configuration */
static LONG new_logs=0;

static UI_DATA *ui_data=NULL;

static struct {
    char *config_file;
    unsigned service:1, install:1, uninstall:1, start:1, stop:1,
        quiet:1, exit:1;
} cmdline;

/**************************************** initialization */

int WINAPI WinMain(HINSTANCE this_instance, HINSTANCE prev_instance,
#ifdef _WIN32_WCE
        LPWSTR lpCmdLine,
#else
        LPSTR lpCmdLine,
#endif
        int nCmdShow) {
    TCHAR stunnel_exe_path[MAX_PATH];
    LPTSTR c;
#ifndef _WIN32_WCE
    LPTSTR errmsg;
#endif

    (void)prev_instance; /* skip warning about unused parameter */
    (void)lpCmdLine; /* skip warning about unused parameter */
    (void)nCmdShow; /* skip warning about unused parameter */

    tls_init(); /* initialize thread-local storage */
    ghInst=this_instance;
    gui_cmdline(); /* setup global cmdline structure */
    GetModuleFileName(0, stunnel_exe_path, MAX_PATH);

#ifndef _WIN32_WCE
    /* find previous instances of the same executable */
    if(!cmdline.service && !cmdline.install && !cmdline.uninstall &&
            !cmdline.start && !cmdline.stop) {
        EnumWindows(enum_windows, (LPARAM)stunnel_exe_path);
        if(cmdline.exit)
            return 0; /* in case EnumWindows didn't find a previous instance */
    }
#endif

    /* set current working directory and engine path */
    c=_tcsrchr(stunnel_exe_path, TEXT('\\')); /* last backslash */
    if(c) /* found */
        c[1]=TEXT('\0'); /* truncate program name */
#ifndef _WIN32_WCE
    if(!SetCurrentDirectory(stunnel_exe_path)) {
        errmsg=str_tprintf(TEXT("Cannot set directory to %s"),
            stunnel_exe_path);
        message_box(errmsg, MB_ICONERROR);
        str_free(errmsg);
        return 1;
    }
#endif
    _tputenv(str_tprintf(TEXT("OPENSSL_ENGINES=%s"), stunnel_exe_path));

    if(initialize_winsock())
        return 1;

#ifndef _WIN32_WCE
    if(cmdline.service) /* "-service" must be processed before "-install" */
        return service_initialize();
    if(cmdline.install)
        return service_install();
    if(cmdline.uninstall)
        return service_uninstall();
    if(cmdline.start)
        return service_start();
    if(cmdline.stop)
        return service_stop();
#endif
    return gui_loop();
}

#ifndef _WIN32_WCE

NOEXPORT BOOL CALLBACK enum_windows(HWND other_window_handle, LPARAM lParam) {
    DWORD pid;
    HINSTANCE hInstance;
    HANDLE process_handle;
    TCHAR window_exe_path[MAX_PATH];
    LPTSTR stunnel_exe_path=(LPTSTR)lParam;

    if(!other_window_handle)
        return TRUE;
    hInstance=(HINSTANCE)GetWindowLong(other_window_handle, GWL_HINSTANCE);
    GetWindowThreadProcessId(other_window_handle, &pid);
    process_handle=OpenProcess(SYNCHRONIZE        /* WaitForSingleObject() */ |
        PROCESS_TERMINATE                         /* TerminateProcess()    */ |
        PROCESS_QUERY_INFORMATION|PROCESS_VM_READ /* GetModuleFileNameEx() */,
        FALSE, pid);
    if(!process_handle)
        return TRUE;
    if(!GetModuleFileNameEx(process_handle,
            hInstance, window_exe_path, MAX_PATH)) {
        CloseHandle(process_handle);
        return TRUE;
    }
    if(_tcscmp(stunnel_exe_path, window_exe_path)) {
        CloseHandle(process_handle);
        return TRUE;
    }
    if(cmdline.exit) {
        PostMessage(other_window_handle, WM_COMMAND, IDM_EXIT, 0);
        if(WaitForSingleObject(process_handle, 3000)==WAIT_TIMEOUT) {
            TerminateProcess(process_handle, 0);
            WaitForSingleObject(process_handle, 3000);
        }
    } else {
        ShowWindow(other_window_handle, SW_SHOWNORMAL); /* show window */
        SetForegroundWindow(other_window_handle); /* bring on top */
    }
    CloseHandle(process_handle);
    exit(0);
    return FALSE; /* should never be executed */
}

#endif

NOEXPORT void gui_cmdline() {
    char *line, *c, *opt;

    line=tstr2str(get_params());
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
        else { /* an option to be processed in options.c */
            c=opt;
            break;
        }
    }
    if(*c=='\"') { /* the option is within double quotes */
        c++;
        opt=c;
        while(*c && *c!='\"') /* find the closing double quote */
            c++;
        *c='\0';
    } else /* the option is simply the rest of the line */
        opt=c;
    cmdline.config_file=*opt ? str_dup(opt) : NULL;
    str_free(line);
}

/* try to load winsock2 resolver functions from a specified dll name */
NOEXPORT int initialize_winsock() {
    static struct WSAData wsa_state;

    if(WSAStartup(MAKEWORD( 2, 2 ), &wsa_state)) {
        message_box(TEXT("Failed to initialize winsock"), MB_ICONERROR);
        return 1; /* error */
    }
    resolver_init();
    return 0; /* IPv4 detected -> OK */
}

/**************************************** GUI thread */

NOEXPORT int gui_loop() {
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
    wc.hIcon=LoadIcon(ghInst, MAKEINTRESOURCE(IDI_STUNNEL_MAIN));
    wc.hCursor=LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground=(HBRUSH)(COLOR_WINDOW+1);
    wc.lpszMenuName=NULL;
    wc.lpszClassName=classname;
#ifdef _WIN32_WCE
    RegisterClass(&wc);
#else
    /* load 16x16 icon */
    wc.hIconSm=LoadImage(ghInst, MAKEINTRESOURCE(IDI_STUNNEL_MAIN), IMAGE_ICON,
        GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), 0);
    RegisterClassEx(&wc);
#endif

    /* create main window */
#ifdef _WIN32_WCE
    hwnd=CreateWindow(classname, win32_name, 0,
        CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
        NULL, NULL, ghInst, NULL);
#else
    main_menu_handle=LoadMenu(ghInst, MAKEINTRESOURCE(IDM_MAINMENU));
    if(main_menu_handle && cmdline.service) {
        /* block unsafe operations in the service mode */
        EnableMenuItem(main_menu_handle, IDM_EDIT_CONFIG, MF_GRAYED);
        EnableMenuItem(main_menu_handle, IDM_SAVE_LOG, MF_GRAYED);
    }
    hwnd=CreateWindow(classname, win32_name, WS_TILEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
        NULL, main_menu_handle, ghInst, NULL);
#endif

    /* auto-reset, non-signaled events */
    main_initialized=CreateEvent(NULL, FALSE, FALSE, NULL);
    config_ready=CreateEvent(NULL, FALSE, FALSE, NULL);
    /* hwnd needs to be initialized before _beginthread() */
    _beginthread(daemon_thread, DEFAULT_STACK_SIZE, NULL);
    WaitForSingleObject(main_initialized, INFINITE);
    /* logging subsystem is now available */

    /* setup periodic event to trigger update_logs() */
    SetTimer(NULL, 0, 1000, timer_proc); /* run callback once per second */

    s_log(LOG_DEBUG, "GUI message loop initialized");
    for(;;)
        switch(GetMessage(&msg, NULL, 0, 0)) {
        case -1:
            ioerror("GetMessage");
            return 0;
        case 0:
            s_log(LOG_DEBUG, "GUI message loop terminated");
            return msg.wParam;
        default:
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
}

NOEXPORT void CALLBACK timer_proc(HWND hwnd, UINT msg, UINT_PTR id, DWORD t) {
    (void)hwnd; /* skip warning about unused parameter */
    (void)msg; /* skip warning about unused parameter */
    (void)id; /* skip warning about unused parameter */
    (void)t; /* skip warning about unused parameter */
    if(visible)
        update_logs();
    update_tray(num_clients); /* needed when explorer.exe (re)starts */
}

NOEXPORT LRESULT CALLBACK window_proc(HWND main_window_handle,
        UINT message, WPARAM wParam, LPARAM lParam) {
    NOTIFYICONDATA nid;
    POINT pt;
    RECT rect;
    PAINTSTRUCT ps;
    SERVICE_OPTIONS *section;
    unsigned section_number;
    LPTSTR txt;

#if 0
    switch(message) {
    case WM_CTLCOLORSTATIC:
    case WM_TIMER:
    case WM_LOG:
        break;
    default:
        s_log(LOG_DEBUG, "Window message: 0x%x(0x%hx,0x%lx)",
            message, wParam, lParam);
    }
#endif
    switch(message) {
    case WM_CREATE:
#ifdef _WIN32_WCE
        /* create command bar */
        command_bar_handle=CommandBar_Create(ghInst, main_window_handle, 1);
        if(!command_bar_handle)
            error_box(TEXT("CommandBar_Create"));
        if(!CommandBar_InsertMenubar(command_bar_handle, ghInst, IDM_MAINMENU, 0))
            error_box(TEXT("CommandBar_InsertMenubar"));
        if(!CommandBar_AddAdornments(command_bar_handle, 0, 0))
            error_box(TEXT("CommandBar_AddAdornments"));
#endif

        /* create child edit window */
        edit_handle=CreateWindowEx(WS_EX_STATICEDGE, TEXT("EDIT"), NULL,
            WS_CHILD|WS_VISIBLE|WS_HSCROLL|WS_VSCROLL|ES_MULTILINE|ES_READONLY,
            0, 0, 0, 0, main_window_handle, (HMENU)IDE_EDIT, ghInst, NULL);
#ifndef _WIN32_WCE
        SendMessage(edit_handle, WM_SETFONT,
            (WPARAM)CreateFont(-12, 0, 0, 0, FW_DONTCARE, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_RASTER_PRECIS, CLIP_DEFAULT_PRECIS,
                PROOF_QUALITY, DEFAULT_PITCH, TEXT("Courier")),
            MAKELPARAM(FALSE, 0)); /* no need to redraw right now */
#endif
        /* NOTE: there's no return statement here -> proceeding with resize */

    case WM_SIZE:
        GetClientRect(main_window_handle, &rect);
#ifdef _WIN32_WCE
        MoveWindow(edit_handle, 0, CommandBar_Height(command_bar_handle),
            rect.right, rect.bottom-CommandBar_Height(command_bar_handle),
            TRUE);
        SendMessage(command_bar_handle, TB_AUTOSIZE, 0L, 0L);
        CommandBar_AlignAdornments(command_bar_handle);
#else
        MoveWindow(edit_handle, 0, 0, rect.right, rect.bottom, TRUE);
#endif
        UpdateWindow(edit_handle);
        /* CommandBar_Show(command_bar_handle, TRUE); */
        return 0;

    case WM_SETFOCUS:
        SetFocus(edit_handle);
        return 0;

    case WM_PAINT:
        BeginPaint(hwnd, &ps);
        EndPaint(hwnd, &ps);
        break;

    case WM_CLOSE:
        ShowWindow(main_window_handle, SW_HIDE);
        return 0;

#ifdef WM_SHOWWINDOW
    case WM_SHOWWINDOW:
        visible=(BOOL)wParam;
#else /* this works for Pierre Delaage, but not for me... */
    case WM_WINDOWPOSCHANGED:
        visible=IsWindowVisible(main_window_handle);
#endif
        if(tray_menu_handle)
            CheckMenuItem(tray_menu_handle, IDM_SHOW_LOG,
                visible ? MF_CHECKED : MF_UNCHECKED);
        if(visible)
            update_logs();
#ifdef WM_SHOWWINDOW
        return 0;
#else
        break; /* proceed to DefWindowProc() */
#endif

    case WM_DESTROY:
#ifdef _WIN32_WCE
        CommandBar_Destroy(command_bar_handle);
#else
        if(main_menu_handle) {
            DestroyMenu(main_menu_handle);
            main_menu_handle=NULL;
        }
#endif
        if(tray_menu_handle) {
            DestroyMenu(tray_menu_handle);
            tray_menu_handle=NULL;
        }
        ZeroMemory(&nid, sizeof nid);
        nid.cbSize=sizeof nid;
        nid.hWnd=main_window_handle;
        nid.uID=1;
        nid.uFlags=NIF_TIP; /* not really sure what to put here, but it works */
        Shell_NotifyIcon(NIM_DELETE, &nid); /* this removes the icon */
        PostQuitMessage(0);
        return 0;

    case WM_COMMAND:
        if(wParam>=IDM_PEER_MENU && wParam<IDM_PEER_MENU+number_of_sections) {
            for(section=service_options.next, section_number=0;
                    section && wParam!=IDM_PEER_MENU+section_number;
                    section=section->next, ++section_number)
                ;
            if(!section)
                return 0;
            if(save_text_file(section->file, section->chain))
                return 0;
#ifndef _WIN32_WCE
            if(main_menu_handle)
                CheckMenuItem(main_menu_handle, wParam, MF_CHECKED);
#endif
            if(tray_menu_handle)
                CheckMenuItem(tray_menu_handle, wParam, MF_CHECKED);
            message_box(section->help, MB_ICONINFORMATION);
            return 0;
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
            if(num_clients>=0) /* signal_pipe is active */
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
                edit_config(main_window_handle);
#endif
            break;
        case IDM_RELOAD_CONFIG:
            if(num_clients>=0) /* signal_pipe is active */
                signal_post(SIGNAL_RELOAD_CONFIG);
            else
                SetEvent(config_ready); /* unlock daemon_thread() */
            break;
        case IDM_REOPEN_LOG:
            signal_post(SIGNAL_REOPEN_LOG);
            break;
        case IDM_MANPAGE:
#ifndef _WIN32_WCE
            if(!cmdline.service) /* security */
                ShellExecute(main_window_handle, TEXT("open"),
                    TEXT("stunnel.html"), NULL, NULL, SW_SHOWNORMAL);
#endif
            break;
        case IDM_HOMEPAGE:
#ifndef _WIN32_WCE
            if(!cmdline.service) /* security */
                ShellExecute(main_window_handle, TEXT("open"),
                    TEXT("http://www.stunnel.org/"), NULL, NULL, SW_SHOWNORMAL);
#endif
            break;
        }
        return 0;

    case WM_SYSTRAY: /* a taskbar event */
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
            if(tray_menu_handle)
                TrackPopupMenuEx(GetSubMenu(tray_menu_handle, 0),
                    TPM_BOTTOMALIGN, pt.x, pt.y, main_window_handle, NULL);
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
        return 0;

    case WM_VALID_CONFIG:
        valid_config();
        return 0;

    case WM_INVALID_CONFIG:
        invalid_config();
        return 0;

    case WM_LOG:
        txt=(LPTSTR)wParam;
        win_log(txt);
        str_free(txt);
        return 0;

    case WM_NEW_CHAIN:
#ifndef _WIN32_WCE
        if(main_menu_handle)
            EnableMenuItem(main_menu_handle, IDM_PEER_MENU+wParam, MF_ENABLED);
#endif
        if(tray_menu_handle)
            EnableMenuItem(tray_menu_handle, IDM_PEER_MENU+wParam, MF_ENABLED);
        return 0;

    case WM_CLIENTS:
        update_tray((int)wParam);
        return 0;
    }

    return DefWindowProc(main_window_handle, message, wParam, lParam);
}

NOEXPORT LRESULT CALLBACK about_proc(HWND dialog_handle, UINT message,
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

NOEXPORT LRESULT CALLBACK pass_proc(HWND dialog_handle, UINT message,
        WPARAM wParam, LPARAM lParam) {
    LPTSTR titlebar;
    union {
        TCHAR txt[PEM_BUFSIZE];
        WORD len;
    } pass_dialog;
    WORD pass_len;
    char* pass_txt;
    LPTSTR key_file_name;

    switch(message) {
    case WM_INITDIALOG:
        /* set the default push button to "Cancel" */
        SendMessage(dialog_handle, DM_SETDEFID, (WPARAM)IDCANCEL, (LPARAM)0);

        key_file_name=str2tstr(ui_data->section->key);
        titlebar=str_tprintf(TEXT("Private key: %s"), key_file_name);
        str_free(key_file_name);
        SetWindowText(dialog_handle, titlebar);
        str_free(titlebar);
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

            /* convert input password to UTF-8 string (as ui_data->pass) */
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

#ifndef OPENSSL_NO_ENGINE
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

/**************************************** log handling */

NOEXPORT void save_log() {
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

    txt=log_txt(); /* need to convert the result to UTF-8 */
    str=tstr2str(txt);
    str_free(txt);
    save_text_file(file_name, str);
    str_free(str);
}

NOEXPORT int save_text_file(LPTSTR file_name, char *str) {
    HANDLE file_handle;
    DWORD ignore;

    file_handle=CreateFile(file_name, GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if(file_handle==INVALID_HANDLE_VALUE) {
        error_box(TEXT("CreateFile"));
        return 1;
    }
    if(!WriteFile(file_handle, str, strlen(str), &ignore, NULL)) {
        CloseHandle(file_handle);
        error_box(TEXT("WriteFile"));
        return 1;
    }
    CloseHandle(file_handle);
    return 0;
}

NOEXPORT void win_log(LPCTSTR txt) {
    struct LIST *curr;
    int txt_len;
    static int log_len=0;

    txt_len=_tcslen(txt);
    curr=str_alloc(sizeof(struct LIST)+txt_len*sizeof(TCHAR));
    curr->len=txt_len;
    _tcscpy(curr->txt, txt);
    curr->next=NULL;
    if(tail)
        tail->next=curr;
    tail=curr;
    if(!head)
        head=tail;
    log_len++;
    while(log_len>LOG_LINES) {
        curr=head;
        head=head->next;
        str_free(curr);
        log_len--;
    }
    new_logs=1;
}

NOEXPORT void update_logs(void) {
    LPTSTR txt;

    if(!InterlockedExchange(&new_logs, 0))
        return;
    txt=log_txt();
    SetWindowText(edit_handle, txt);
    str_free(txt);
    SendMessage(edit_handle, WM_VSCROLL, (WPARAM)SB_BOTTOM, (LPARAM)0);
}

NOEXPORT LPTSTR log_txt(void) {
    LPTSTR buff;
    int ptr=0, len=0;
    struct LIST *curr;

    for(curr=head; curr; curr=curr->next)
        len+=curr->len+2; /* +2 for trailing '\r\n' */
    buff=str_alloc((len+1)*sizeof(TCHAR)); /* +1 for trailing '\0' */
    for(curr=head; curr; curr=curr->next) {
        memcpy(buff+ptr, curr->txt, curr->len*sizeof(TCHAR));
        ptr+=curr->len;
        if(curr->next) {
            buff[ptr++]=TEXT('\r');
            buff[ptr++]=TEXT('\n');
        }
    }
    buff[ptr]=TEXT('\0');
    return buff;
}

/**************************************** worker thread */

NOEXPORT void daemon_thread(void *arg) {
    (void)arg; /* skip warning about unused parameter */

    tls_alloc(NULL, NULL, "main"); /* new thread-local storage */
    main_init();
    SetEvent(main_initialized); /* unlock the GUI thread */
    /* get a valid configuration */
    while(main_configure(cmdline.config_file, NULL)) {
        cmdline.config_file=NULL; /* don't retry commandline switches */
        unbind_ports(); /* in case initialization failed after bind_ports() */
        log_flush(LOG_MODE_ERROR); /* otherwise logs are buffered */
        PostMessage(hwnd, WM_INVALID_CONFIG, 0, 0); /* display error */
        WaitForSingleObject(config_ready, INFINITE);
        log_close(); /* prevent main_configure() from logging in error mode */
    }
    PostMessage(hwnd, WM_VALID_CONFIG, 0, 0);

    /* start the main loop */
    daemon_loop();
    main_cleanup();
    _endthread(); /* SIGNAL_TERMINATE received */
}

/**************************************** helper functions */

NOEXPORT void invalid_config() {
    /* update the main window title */
    win32_name=TEXT("stunnel ") TEXT(STUNNEL_VERSION) TEXT(" on ")
        TEXT(STUNNEL_PLATFORM) TEXT(" (invalid configuration file)");
    SetWindowText(hwnd, win32_name);

    /* log window is hidden by default */
    ShowWindow(hwnd, SW_SHOWNORMAL); /* show window */
    SetForegroundWindow(hwnd); /* bring on top */

    update_tray(-1); /* error icon */
    update_peer_menu(); /* purge the list of sections */

    win_log(TEXT(""));
    s_log(LOG_ERR, "Server is down");
    message_box(TEXT("Stunnel server is down due to an error.\n")
        TEXT("You need to exit and correct the problem.\n")
        TEXT("Click OK to see the error log window."),
        MB_ICONERROR);
}

NOEXPORT void valid_config() {
    /* update the main window title */
    win32_name=TEXT("stunnel ") TEXT(STUNNEL_VERSION) TEXT(" on ")
        TEXT(STUNNEL_PLATFORM);
    SetWindowText(hwnd, win32_name);

    update_tray(num_clients); /* idle or busy icon (on reload) */
    update_peer_menu(); /* one menu item per section */

    /* enable IDM_REOPEN_LOG menu if a log file is used, disable otherwise */
#ifndef _WIN32_WCE
    EnableMenuItem(main_menu_handle, IDM_REOPEN_LOG,
        global_options.output_file ? MF_ENABLED : MF_GRAYED);
#endif
    if(tray_menu_handle)
        EnableMenuItem(tray_menu_handle, IDM_REOPEN_LOG,
            global_options.output_file ? MF_ENABLED : MF_GRAYED);
}

NOEXPORT void update_peer_menu(void) {
    SERVICE_OPTIONS *section;
#ifndef _WIN32_WCE
    HMENU main_peer_list=NULL;
#endif
    HMENU tray_peer_list=NULL;
    unsigned section_number;
    LPTSTR servname;

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

    /* initialize data structures */
    number_of_sections=0;
    for(section=service_options.next; section; section=section->next)
        section->section_number=number_of_sections++;

    section_number=0;
    for(section=service_options.next; section; section=section->next) {
        servname=str2tstr(section->servname);

        /* setup LPTSTR section->file */
        section->file=str_tprintf(TEXT("peer-%s.pem"), servname);

        /* setup section->help */
        section->help=str_tprintf(
            TEXT("Peer certificate chain has been saved.\n")
            TEXT("Add the following lines to section [%s]:\n")
            TEXT("\tCAfile = peer-%s.pem\n")
            TEXT("\tverify = 3\n")
            TEXT("to enable cryptographic authentication.\n")
            TEXT("Then reload stunnel configuration file."),
            servname, servname);

        str_free(servname);

        /* setup section->chain */
        section->chain=NULL;

        /* insert new menu item */
#ifndef _WIN32_WCE
        if(main_peer_list)
            if(!InsertMenu(main_peer_list, section_number,
                    MF_BYPOSITION|MF_STRING|MF_GRAYED,
                    IDM_PEER_MENU+section_number, section->file))
                ioerror("InsertMenu");
#endif
        if(tray_peer_list)
            if(!InsertMenu(tray_peer_list, section_number,
                    MF_BYPOSITION|MF_STRING|MF_GRAYED,
                    IDM_PEER_MENU+section_number, section->file))
                ioerror("InsertMenu");

        ++section_number;
    }
    if(hwnd)
        DrawMenuBar(hwnd);
}

ICON_IMAGE load_icon_default(ICON_TYPE type) {
    WORD idi;
    ICON_IMAGE img;

    switch(type) {
    case ICON_ACTIVE:
        idi=IDI_STUNNEL_ACTIVE;
        break;
    case ICON_ERROR:
        idi=IDI_STUNNEL_ERROR;
        break;
    case ICON_IDLE:
        idi=IDI_STUNNEL_IDLE;
        break;
    default:
        return NULL;
    }
    img=LoadImage(ghInst, MAKEINTRESOURCE(idi), IMAGE_ICON,
        GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), 0);
    return DuplicateIcon(NULL, img);
}

ICON_IMAGE load_icon_file(const char *name) {
    LPTSTR tname;
    ICON_IMAGE icon;

    tname=str2tstr((LPSTR)name);
#ifndef _WIN32_WCE
    icon=LoadImage(NULL, tname, IMAGE_ICON, GetSystemMetrics(SM_CXSMICON),
        GetSystemMetrics(SM_CYSMICON), LR_LOADFROMFILE);
#else
    /* TODO: Implement a WCE version of LoadImage() */
    /* icon=wceLoadIconFromFile(tname); */
    s_log(LOG_ERR, "Loading image from file not implemented on WCE");
    icon=NULL;
#endif
    str_free(tname);
    return icon;
}

NOEXPORT void update_tray(const int num) {
    NOTIFYICONDATA nid;
    static ICON_TYPE previous_icon=ICON_NONE;
    ICON_TYPE current_icon;
    LPTSTR tip;

    if(!global_options.option.taskbar) {
        /* release previously allocated menu resources */
        if(tray_menu_handle) { /* disabled in the new configuration */
            DestroyMenu(tray_menu_handle);
            tray_menu_handle=NULL;
        }
        return;
    }
    if(!tray_menu_handle) /* initialize taskbar */
        tray_menu_handle=LoadMenu(ghInst, MAKEINTRESOURCE(IDM_TRAYMENU));
    if(tray_menu_handle && cmdline.service)
        EnableMenuItem(tray_menu_handle, IDM_EDIT_CONFIG, MF_GRAYED);

    ZeroMemory(&nid, sizeof nid);
    nid.cbSize=sizeof nid;
    nid.uID=1; /* application-defined ID for the icon */
    nid.uFlags=NIF_MESSAGE|NIF_TIP;
    nid.uCallbackMessage=WM_SYSTRAY; /* notification message */
    nid.hWnd=hwnd; /* window to receive notifications */
    if(num<0) {
        tip=str_tprintf(TEXT("Server is down"));
        current_icon=ICON_ERROR;
    } else if(num>0) {
        tip=str_tprintf(TEXT("%d active session(s)"), num);
        current_icon=ICON_ACTIVE;
    } else {
        tip=str_tprintf(TEXT("Server is idle"));
        current_icon=ICON_IDLE;
    }
    _tcsncpy(nid.szTip, tip, 63);
    nid.szTip[63]=TEXT('\0');
    str_free(tip);
    nid.hIcon=global_options.icon[current_icon];
    if(current_icon!=previous_icon) {
        nid.uFlags|=NIF_ICON;
        previous_icon=current_icon;
    }
    if(Shell_NotifyIcon(NIM_MODIFY, &nid)) /* modify tooltip */
        return; /* OK: taskbar icon exists */
    /* tooltip update failed - try to create the icon */
    nid.uFlags|=NIF_ICON;
    Shell_NotifyIcon(NIM_ADD, &nid);
}

NOEXPORT void error_box(LPCTSTR text) {
    LPTSTR errmsg, fullmsg;
    long dw;

    dw=GetLastError();
    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM,
        NULL, dw, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&errmsg, 0, NULL);
    fullmsg=str_tprintf(TEXT("%s: error %ld: %s"), text, dw, errmsg);
    LocalFree(errmsg);
    message_box(fullmsg, MB_ICONERROR);
    str_free(fullmsg);
}

void message_box(LPCTSTR text, const UINT type) {
    if(cmdline.quiet)
        return;
    MessageBox(hwnd, text, win32_name, type);
}

void ui_new_chain(const int section_number) {
    PostMessage(hwnd, WM_NEW_CHAIN, section_number, 0);
}

void ui_new_log(const char *line) {
    LPTSTR txt;
    txt=str2tstr(line);
    str_detach(txt); /* this allocation will be freed in the GUI thread */
    PostMessage(hwnd, WM_LOG, (WPARAM)txt, 0);
}

void ui_config_reloaded(void) {
    PostMessage(hwnd, WM_VALID_CONFIG, 0, 0);
}

void ui_clients(const long num) {
    PostMessage(hwnd, WM_CLIENTS, (WPARAM)num, 0);
}

    /* TODO: port it to WCE */
NOEXPORT void edit_config(HWND main_window_handle) {
    TCHAR cwd[MAX_PATH];
    LPTSTR conf_file, conf_path;

    conf_file=str2tstr(configuration_file);
    if(*conf_file==TEXT('\"')) {
        conf_path=conf_file;
    } else if(_tcschr(conf_file, TEXT('\\'))) {
        conf_path=str_tprintf(TEXT("\"%s\""), conf_file);
        str_free(conf_file);
    } else {
        GetCurrentDirectory(MAX_PATH, cwd);
        conf_path=str_tprintf(TEXT("\"%s\\%s\""), cwd, conf_file);
        str_free(conf_file);
    }

    if(is_admin()) {
        ShellExecute(main_window_handle, TEXT("open"),
            TEXT("notepad.exe"), conf_path,
            NULL, SW_SHOWNORMAL);
    } else { /* UAC workaround */
        ShellExecute(main_window_handle, TEXT("runas"),
            TEXT("notepad.exe"), conf_path,
            NULL, SW_SHOWNORMAL);
    }
    str_free(conf_path);
}

NOEXPORT BOOL is_admin(void) {
#ifndef _WIN32_WCE
    SID_IDENTIFIER_AUTHORITY NtAuthority={SECURITY_NT_AUTHORITY};
    PSID admin_group;
    BOOL retval;

    retval=AllocateAndInitializeSid(&NtAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &admin_group);
    if(retval) {
        if(!CheckTokenMembership(NULL, admin_group, &retval))
            retval=FALSE;
        FreeSid(admin_group);
    }
    return retval;
#else
    return TRUE; /* always an admin on WCE */
#endif
}

/**************************************** windows service */

#ifndef _WIN32_WCE

NOEXPORT int service_initialize(void) {
    SERVICE_TABLE_ENTRY serviceTable[]={{0, 0}, {0, 0}};

    serviceTable[0].lpServiceName=SERVICE_NAME;
    serviceTable[0].lpServiceProc=service_main;
    /* disable taskbar for security */
    /* global_options.option.taskbar=0; */
    if(!StartServiceCtrlDispatcher(serviceTable)) {
        error_box(TEXT("StartServiceCtrlDispatcher"));
        return 1;
    }
    return 0; /* NT service started */
}

#define DESCR_LEN 256

NOEXPORT int service_install() {
    SC_HANDLE scm, service;
    TCHAR stunnel_exe_path[MAX_PATH];
    LPTSTR service_path;
    TCHAR descr_str[DESCR_LEN];
    SERVICE_DESCRIPTION descr;

    scm=OpenSCManager(0, 0, SC_MANAGER_CREATE_SERVICE);
    if(!scm) {
        error_box(TEXT("OpenSCManager"));
        return 1;
    }
    GetModuleFileName(0, stunnel_exe_path, MAX_PATH);
    service_path=str_tprintf(TEXT("\"%s\" -service %s"),
        stunnel_exe_path, get_params());
    service=CreateService(scm, SERVICE_NAME, SERVICE_DISPLAY_NAME,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS|SERVICE_INTERACTIVE_PROCESS,
        SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, service_path,
        NULL, NULL, TEXT("TCPIP\0"), NULL, NULL);
    if(!service) {
        error_box(TEXT("CreateService"));
        str_free(service_path);
        CloseServiceHandle(scm);
        return 1;
    }
    str_free(service_path);
    if(LoadString(ghInst, IDS_SERVICE_DESC, descr_str, DESCR_LEN)) {
        descr.lpDescription=descr_str;
        ChangeServiceConfig2(service, SERVICE_CONFIG_DESCRIPTION, &descr);
    }
    message_box(TEXT("Service installed"), MB_ICONINFORMATION);
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return 0;
}

NOEXPORT int service_uninstall(void) {
    SC_HANDLE scm, service;
    SERVICE_STATUS serviceStatus;

    scm=OpenSCManager(0, 0, SC_MANAGER_CONNECT);
    if(!scm) {
        error_box(TEXT("OpenSCManager"));
        return 1;
    }
    service=OpenService(scm, SERVICE_NAME, SERVICE_QUERY_STATUS|DELETE);
    if(!service) {
        error_box(TEXT("OpenService"));
        CloseServiceHandle(scm);
        return 1;
    }
    if(!QueryServiceStatus(service, &serviceStatus)) {
        error_box(TEXT("QueryServiceStatus"));
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return 1;
    }
    if(serviceStatus.dwCurrentState!=SERVICE_STOPPED) {
        message_box(TEXT("The service is still running"), MB_ICONERROR);
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return 1;
    }
    if(!DeleteService(service)) {
        error_box(TEXT("DeleteService"));
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return 1;
    }
    message_box(TEXT("Service uninstalled"), MB_ICONINFORMATION);
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return 0;
}

NOEXPORT int service_start(void) {
    SC_HANDLE scm, service;
    SERVICE_STATUS serviceStatus;

    scm=OpenSCManager(0, 0, SC_MANAGER_CONNECT);
    if(!scm) {
        error_box(TEXT("OpenSCManager"));
        return 1;
    }
    service=OpenService(scm, SERVICE_NAME, SERVICE_QUERY_STATUS|SERVICE_START);
    if(!service) {
        error_box(TEXT("OpenService"));
        CloseServiceHandle(scm);
        return 1;
    }
    if(!StartService(service, 0, NULL)) {
        error_box(TEXT("StartService"));
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return 1;
    }
    do {
        Sleep(1000);
        if(!QueryServiceStatus(service, &serviceStatus)) {
            error_box(TEXT("QueryServiceStatus"));
            CloseServiceHandle(service);
            CloseServiceHandle(scm);
            return 1;
        }
    } while(serviceStatus.dwCurrentState==SERVICE_START_PENDING);
    if(serviceStatus.dwCurrentState!=SERVICE_RUNNING) {
        message_box(TEXT("Failed to start service"), MB_ICONERROR);
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return 1;
    }
    message_box(TEXT("Service started"), MB_ICONINFORMATION);
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return 0;
}

NOEXPORT int service_stop(void) {
    SC_HANDLE scm, service;
    SERVICE_STATUS serviceStatus;

    scm=OpenSCManager(0, 0, SC_MANAGER_CONNECT);
    if(!scm) {
        error_box(TEXT("OpenSCManager"));
        return 1;
    }
    service=OpenService(scm, SERVICE_NAME, SERVICE_QUERY_STATUS|SERVICE_STOP);
    if(!service) {
        error_box(TEXT("OpenService"));
        CloseServiceHandle(scm);
        return 1;
    }
    if(!QueryServiceStatus(service, &serviceStatus)) {
        error_box(TEXT("QueryServiceStatus"));
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return 1;
    }
    if(serviceStatus.dwCurrentState==SERVICE_STOPPED) {
        message_box(TEXT("The service is already stopped"), MB_ICONERROR);
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return 1;
    }
    if(!ControlService(service, SERVICE_CONTROL_STOP, &serviceStatus)) {
        error_box(TEXT("ControlService"));
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return 1;
    }
    do {
        Sleep(1000);
        if(!QueryServiceStatus(service, &serviceStatus)) {
            error_box(TEXT("QueryServiceStatus"));
            CloseServiceHandle(service);
            CloseServiceHandle(scm);
            return 1;
        }
    } while(serviceStatus.dwCurrentState!=SERVICE_STOPPED);
    message_box(TEXT("Service stopped"), MB_ICONINFORMATION);
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return 0;
}

NOEXPORT void WINAPI service_main(DWORD argc, LPTSTR* argv) {
    (void)argc; /* skip warning about unused parameter */
    (void)argv; /* skip warning about unused parameter */

    tls_alloc(NULL, NULL, "service"); /* new thread-local storage */

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

        gui_loop();

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

NOEXPORT void WINAPI control_handler(DWORD controlCode) {
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

/**************************************** other functions */

NOEXPORT LPTSTR get_params() {
    LPTSTR c;
    TCHAR s;

    c=GetCommandLine();
    if(*c==TEXT('\"')) {
        s=TEXT('\"');
        ++c;
    } else {
        s=TEXT(' ');
    }
    for(; *c; ++c)
        if(*c==s) {
            ++c;
            break;
        }
    while(*c==TEXT(' '))
        ++c;
    return c;
}

/* end of ui_win_gui.c */
