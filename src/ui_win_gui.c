/*
 *   stunnel       TLS offloading and load-balancing proxy
 *   Copyright (C) 1998-2022 Michal Trojnara <Michal.Trojnara@stunnel.org>
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
#include <sddl.h>
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
#define SERVICE_DISPLAY_NAME TEXT("Stunnel TLS wrapper")
#endif

/* mingw-Patches-1825044 is missing in Debian Squeeze */
WINBASEAPI BOOL WINAPI CheckTokenMembership(HANDLE, PSID, PBOOL);

/* initialization */
NOEXPORT int winsock_initialize(void);
NOEXPORT unsigned __stdcall daemon_thread(void *);

/* GUI core */
NOEXPORT void gui_cmdline(void);
NOEXPORT void gui_init(void);
NOEXPORT int gui_loop(void);

/* GUI callbacks */
NOEXPORT void CALLBACK timer_proc(HWND, UINT, UINT_PTR, DWORD);
NOEXPORT LRESULT CALLBACK window_proc(HWND, UINT, WPARAM, LPARAM);
NOEXPORT LRESULT CALLBACK edit_proc(HWND, UINT, WPARAM, LPARAM);
NOEXPORT LRESULT CALLBACK about_proc(HWND, UINT, WPARAM, LPARAM);
NOEXPORT LRESULT CALLBACK pass_proc(HWND, UINT, WPARAM, LPARAM);

/* icon tray */
NOEXPORT void tray_update(const int);
NOEXPORT void tray_delete(void);

/* configuration file (re)loading */
NOEXPORT void config_valid(void);
NOEXPORT void config_invalid(void);
NOEXPORT void config_edit(HWND);

/* peer certs */
NOEXPORT void peer_menu_update(void);
NOEXPORT void peer_menu_update_unlocked(void);
NOEXPORT void peer_cert_save(WPARAM wParam);

/* UI callbacks */
NOEXPORT int pin_cb(UI *, UI_STRING *);

/* log handling */
NOEXPORT void log_save(void);
NOEXPORT void log_push(LPCTSTR);
NOEXPORT void log_update(void);
NOEXPORT LPTSTR log_txt(void);

/* control pipe support */
NOEXPORT void control_pipe_names(void);
NOEXPORT int control_pipe_client(void);
NOEXPORT int control_pipe_server(LPTSTR);
NOEXPORT unsigned __stdcall control_pipe_server_thread(void *);
NOEXPORT unsigned __stdcall control_pipe_instance_thread(void *);
NOEXPORT int control_pipe_send(HANDLE, const char *, ...);
NOEXPORT char *control_pipe_recv(HANDLE);
NOEXPORT char *control_pipe_call(LPTSTR, const char *, ...);

/* NT Service support */
#ifndef _WIN32_WCE
NOEXPORT int service_initialize(void);
NOEXPORT int service_install(void);
NOEXPORT int service_uninstall(void);
NOEXPORT int service_start(void);
NOEXPORT int service_stop(void);
NOEXPORT void WINAPI service_main(DWORD, LPTSTR *);
NOEXPORT void WINAPI control_handler(DWORD);
#endif /* !defined(_WIN32_WCE) */

/* helper functions */
NOEXPORT LPTSTR params_get(void);
NOEXPORT int text_file_create(LPTSTR, char *);
NOEXPORT void gui_signal_post(uint8_t);
NOEXPORT void error_box(LPCTSTR);

/* global variables */
static struct LIST {
  struct LIST *next;
  size_t len;
  TCHAR txt[1]; /* single character for trailing '\0' */
} *head=NULL, *tail=NULL;

static HINSTANCE ghInst;
static HWND edit_handle=NULL, pause_handle=NULL;
static HMENU tray_menu_handle=NULL;
#ifndef _WIN32_WCE
static HMENU main_menu_handle=NULL;
#endif
static HWND hwnd=NULL; /* main window handle */
#ifdef _WIN32_WCE
static HWND command_bar_handle; /* command bar handle */
#endif
static WNDPROC default_edit_proc;
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
static HANDLE main_terminated=NULL; /* daemon_loop() terminated */
static HANDLE config_ready=NULL; /* reload without a valid configuration */
static BOOL new_logs=FALSE;
static int removed_logs=0;

static struct {
    char *config_file;
    char *config_command;
    unsigned service:1, install:1, uninstall:1, start:1, stop:1,
        quiet:1, exit:1, reload:1, reopen:1;
} cmdline;

static char ui_pass[PEM_BUFSIZE];

LPTSTR pipe_name_ui, pipe_name_service;
BOOL nt_service_client=FALSE;

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
    HANDLE daemon;

    (void)prev_instance; /* squash the unused parameter warning */
    (void)lpCmdLine; /* squash the unused parameter warning */
    (void)nCmdShow; /* squash the unused parameter warning */

    tls_init(); /* initialize thread-local storage */
    ghInst=this_instance;

    /* set current working directory and engine path */
    GetModuleFileName(0, stunnel_exe_path, MAX_PATH);
    c=_tcsrchr(stunnel_exe_path, TEXT('\\')); /* last backslash */
    if(c) { /* found */
        *c=TEXT('\0'); /* truncate the program name */
        c=_tcsrchr(stunnel_exe_path, TEXT('\\')); /* previous backslash */
        if(c && !_tcscmp(c+1, TEXT("bin")))
            *c=TEXT('\0'); /* truncate "bin" */
    }
#ifndef _WIN32_WCE
    if(!SetCurrentDirectory(stunnel_exe_path)) {
        errmsg=str_tprintf(TEXT("Cannot set directory to %s"),
            stunnel_exe_path);
        message_box(errmsg, MB_ICONERROR);
        str_free(errmsg);
        return 1;
    }
    /* try to enter the "config" subdirectory, ignore the result */
    SetCurrentDirectory(TEXT("config"));
#endif
    _tputenv(str_tprintf(TEXT("OPENSSL_ENGINES=%s\\engines"),
        stunnel_exe_path));
    _tputenv(str_tprintf(TEXT("OPENSSL_MODULES=%s\\ossl-modules"),
        stunnel_exe_path));
    _tputenv(str_tprintf(TEXT("OPENSSL_CONF=%s\\config\\openssl.cnf"),
        stunnel_exe_path));

    gui_cmdline(); /* setup global cmdline structure */
    control_pipe_names();

    if(winsock_initialize())
        return 1;

#ifndef _WIN32_WCE
    if(cmdline.service) { /* "-service" must be processed before "-install" */
        cmdline.quiet=1;
        /* create a service pipe thread for accepting signals */
        if(control_pipe_server(pipe_name_service))
            return 1; /* a control pipe service already exists or failed */
        return service_initialize();
    }
    if(cmdline.install)
        return service_install();
    if(cmdline.uninstall)
        return service_uninstall();
    if(cmdline.start)
        return service_start();
    if(cmdline.stop)
        return service_stop();
#endif

    /* auto-reset, non-signaled events */
    main_initialized=CreateEvent(NULL, FALSE, FALSE, NULL);
    main_terminated=CreateEvent(NULL, FALSE, FALSE, NULL);
    config_ready=CreateEvent(NULL, FALSE, FALSE, NULL);

    if(control_pipe_client())
        return 0;
    /* create a service pipe thread for accepting signals */
    if(control_pipe_server(pipe_name_service))
        return 1; /* a control pipe service already exists or failed */
    gui_init();
    /* hwnd needs to be initialized before _beginthreadex() */
    daemon=(HANDLE)_beginthreadex(NULL, DEFAULT_STACK_SIZE,
        daemon_thread, NULL, 0, NULL);
    if(!daemon)
        fatal("Failed to create the daemon thread");
    CloseHandle(daemon);
    WaitForSingleObject(main_initialized, INFINITE);
    return gui_loop();
}

/* try to load winsock2 resolver functions from a specified dll name */
NOEXPORT int winsock_initialize() {
    static struct WSAData wsa_state;

    if(WSAStartup(MAKEWORD(2, 2), &wsa_state)) {
        message_box(TEXT("Failed to initialize winsock"), MB_ICONERROR);
        return 1; /* error */
    }
    resolver_init();
    return 0; /* IPv4 detected -> OK */
}

NOEXPORT unsigned __stdcall daemon_thread(void *arg) {
    (void)arg; /* squash the unused parameter warning */

    tls_alloc(NULL, NULL, "main"); /* new thread-local storage */
    main_init();
    SetEvent(main_initialized); /* unlock the GUI thread */
    /* get a valid configuration */
    if(cmdline.config_command) {
        main_configure(cmdline.config_command, NULL);
        ShowWindow(hwnd, SW_SHOWNORMAL); /* show window */
        SetForegroundWindow(hwnd); /* bring on top */
    }
    while(main_configure(cmdline.config_file, NULL)) {
        PostMessage(hwnd, WM_INVALID_CONFIG, 0, 0); /* display error */
        WaitForSingleObject(config_ready, INFINITE);
    }
    PostMessage(hwnd, WM_VALID_CONFIG, 0, 0);

    /* start the main loop */
    daemon_loop();
    main_cleanup();
    SetEvent(main_terminated); /* ready for WM_QUIT */
    PostMessage(hwnd, WM_TERMINATE, 0, 0); /* terminate GUI */
    tls_cleanup();
    _endthreadex(0); /* SIGNAL_TERMINATE received */
    return 0;
}

/**************************************** GUI core */

NOEXPORT void gui_cmdline() {
    char *line, *c, *config_file=NULL;

    memset(&cmdline, 0, sizeof cmdline);
    line=tstr2str(params_get());
    c=line;
    while(*c) {
        char *opt;

        if(*c=='\"') { /* the option is within double quotes */
            *c++='\0';
            opt=c;
            while(*c && *c!='\"') /* find the closing double quote */
                c++;
            if(*c=='\"') /* replace with '\0' if found */
                *c++='\0';
        } else if(*c=='-' || *c=='/') { /* advanced parameters: the option is the next word */
            opt=c;
            while(*c && !isspace(*c)) /* skip non-whitespaces */
                c++;
        } else { /* the rest of the line is our configuration file path */
            config_file=c;
            break;
        }
        while(*c && isspace(*c)) /* replace whitespaces with '\0' */
            *c++='\0';

        if(*opt=='/' || *opt=='-') {
            if(!strcasecmp(opt+1, "install")) {
                cmdline.install=1;
                continue;
            }
            if(!strcasecmp(opt+1, "uninstall")) {
                cmdline.uninstall=1;
                continue;
            }
            if(!strcasecmp(opt+1, "reload")) {
                cmdline.reload=1;
                continue;
            }
            if(!strcasecmp(opt+1, "reopen")) {
                cmdline.reopen=1;
                continue;
            }
            if(!strcasecmp(opt+1, "start")) {
                cmdline.start=1;
                continue;
            }
            if(!strcasecmp(opt+1, "stop")) {
                cmdline.stop=1;
                continue;
            }
            if(!strcasecmp(opt+1, "service")) {
                cmdline.service=1;
                continue;
            }
            if(!strcasecmp(opt+1, "quiet")) {
                cmdline.quiet=1;
                continue;
            }
            if(!strcasecmp(opt+1, "exit")) {
                cmdline.exit=1;
                continue;
            }
            if(!strcasecmp(opt+1, "help")) {
                cmdline.config_command="-help";
                continue;
            }
            if(!strcasecmp(opt+1, "version")) {
                cmdline.config_command="-version";
                continue;
            }
            if(!strcasecmp(opt+1, "sockets")) {
                cmdline.config_command="-sockets";
                continue;
            }
            if(!strcasecmp(opt+1, "options")) {
                cmdline.config_command="-options";
                continue;
            }
        }
        /* any other non-empty option must be our configuration file name */
        if(*opt && !config_file)
            config_file=opt;
    }
    if(!config_file || !*config_file)
        config_file="stunnel.conf";
    config_file=_fullpath(NULL, config_file, 0);
    if(config_file) { /* _fullpath managed to create an absolute path */
        cmdline.config_file=str_dup(config_file);
        free(config_file);
    } else {
        cmdline.config_file=str_dup("stunnel.conf");
    }
    str_free(line);
}

NOEXPORT void gui_init() {
#ifdef _WIN32_WCE
    WNDCLASS wc;
#else
    WNDCLASSEX wc;
#endif
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
    hwnd=CreateWindow(classname, win32_name, WS_TILEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
        NULL, main_menu_handle, ghInst, NULL);
#endif

    /* create initial icon tray */
    tray_update(0);
}

NOEXPORT int gui_loop() {
    MSG msg;

    /* setup periodic event to trigger log_update() and tray_update() */
    SetTimer(NULL, 0, 1000, timer_proc); /* run callback once per second */

    for(;;)
        switch(GetMessage(&msg, NULL, 0, 0)) {
        case -1:
            ioerror("GetMessage");
            return 0;
        case 0:
            /* the following error may only be logged if main_cleanup()
             * did not disable logging with log_flush(LOG_MODE_BUFFER) */
            ui_new_log("GUI message loop terminated with WM_QUIT");
            return (int)msg.wParam;
        default:
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
}

/**************************************** GUI callbacks */

NOEXPORT void CALLBACK timer_proc(HWND hwnd, UINT msg, UINT_PTR id, DWORD t) {
    (void)hwnd; /* squash the unused parameter warning */
    (void)msg; /* squash the unused parameter warning */
    (void)id; /* squash the unused parameter warning */
    (void)t; /* squash the unused parameter warning */
    log_update();
    tray_update(num_clients);
}

NOEXPORT LRESULT CALLBACK window_proc(HWND main_window_handle,
        UINT message, WPARAM wParam, LPARAM lParam) {
    POINT pt;
    RECT rect;
    HFONT monospaced_font, proportional_font;

#if 0
    switch(message) {
    case WM_CTLCOLORSTATIC:
    case WM_TIMER:
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
        edit_handle=CreateWindowEx(WS_EX_STATICEDGE, WC_EDIT, NULL,
            WS_CHILD|WS_VISIBLE|WS_HSCROLL|WS_VSCROLL|ES_MULTILINE|ES_READONLY,
            0, 0, 0, 0, main_window_handle, (HMENU)IDE_EDIT, ghInst, NULL);
        pause_handle=CreateWindowEx(0, WC_BUTTON, TEXT("Pause auto-scroll"),
            WS_CHILD|WS_VISIBLE|BS_CHECKBOX|BS_AUTOCHECKBOX|BS_TEXT,
            0, 0, 0, 0, main_window_handle, (HMENU)IDE_PAUSE, ghInst, NULL);
        default_edit_proc=(WNDPROC)SetWindowLongPtr(edit_handle, GWLP_WNDPROC,
            (LONG_PTR)edit_proc);
#ifndef _WIN32_WCE
        monospaced_font=CreateFont(-12, 0, 0, 0, FW_DONTCARE, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_RASTER_PRECIS, CLIP_DEFAULT_PRECIS,
            PROOF_QUALITY, DEFAULT_PITCH, TEXT("Courier")),
        SendMessage(edit_handle, WM_SETFONT, (WPARAM)monospaced_font,
            MAKELPARAM(FALSE, 0)); /* no need to redraw right now */
        proportional_font=CreateFont(-12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_TT_PRECIS, CLIP_DEFAULT_PRECIS,
            DEFAULT_QUALITY, DEFAULT_PITCH, TEXT("Segoe UI")),
        SendMessage(pause_handle, WM_SETFONT, (WPARAM)proportional_font,
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
        MoveWindow(edit_handle, 0, 0, rect.right, rect.bottom-17, TRUE);
        MoveWindow(pause_handle, 0, rect.bottom-17, rect.right, 17, TRUE);
#endif
        UpdateWindow(edit_handle);
        /* CommandBar_Show(command_bar_handle, TRUE); */
        return 0;

    case WM_SETFOCUS:
        SetFocus(edit_handle);
        return 0;

    case WM_PAINT:
        {
            PAINTSTRUCT ps;
            BeginPaint(hwnd, &ps);
            EndPaint(hwnd, &ps);
        }
        break;

    case WM_GETMINMAXINFO:
        {
            LPMINMAXINFO minmaxinfo=(LPMINMAXINFO)lParam;
            minmaxinfo->ptMinTrackSize.x=320;
            minmaxinfo->ptMinTrackSize.y=200;
        }
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
        log_update();
#ifdef WM_SHOWWINDOW
        return 0;
#else
        break; /* proceed to DefWindowProc() */
#endif

    case WM_DESTROY:
        tray_delete(); /* remove the taskbark icon if exists */
#ifdef _WIN32_WCE
        CommandBar_Destroy(command_bar_handle);
#else
        if(main_menu_handle) {
            if(!DestroyMenu(main_menu_handle))
                ioerror("DestroyMenu");
            main_menu_handle=NULL;
        }
#endif
        PostQuitMessage(0);
        return 0;

    case WM_TERMINATE:
        DestroyWindow(main_window_handle);
        return 0;

    case WM_COMMAND:
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
            gui_signal_post(SIGNAL_TERMINATE);
            break;
        case IDM_SAVE_LOG:
            log_save();
            break;
        case IDM_EDIT_CONFIG:
#ifndef _WIN32_WCE
            config_edit(main_window_handle);
#endif
            break;
        case IDM_RELOAD_CONFIG:
            gui_signal_post(SIGNAL_RELOAD_CONFIG);
            break;
        case IDM_REOPEN_LOG:
            gui_signal_post(SIGNAL_REOPEN_LOG);
            break;
        case IDM_CONNECTIONS:
            gui_signal_post(SIGNAL_CONNECTIONS);
            break;
        case IDM_MANPAGE:
#ifndef _WIN32_WCE
            ShellExecute(main_window_handle, TEXT("open"),
                TEXT("..\\doc\\stunnel.html"), NULL, NULL, SW_SHOWNORMAL);
#endif
            break;
        case IDM_HOMEPAGE:
#ifndef _WIN32_WCE
            ShellExecute(main_window_handle, TEXT("open"),
                TEXT("http://www.stunnel.org/"), NULL, NULL, SW_SHOWNORMAL);
#endif
            break;
        default:
            if(wParam>=IDM_PEER_MENU && wParam<IDM_PEER_MENU+number_of_sections)
                peer_cert_save(wParam);
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
        case WM_LBUTTONDOWN: /* switch log window visibility */
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
        config_valid();
        return 0;

    case WM_INVALID_CONFIG:
        config_invalid();
        return 0;

    case WM_NEW_CHAIN:
#ifndef _WIN32_WCE
        if(main_menu_handle)
            EnableMenuItem(main_menu_handle,
                (UINT)(IDM_PEER_MENU+wParam), MF_ENABLED);
#endif
        if(tray_menu_handle)
            EnableMenuItem(tray_menu_handle,
                (UINT)(IDM_PEER_MENU+wParam), MF_ENABLED);
        return 0;

    case WM_CAPWIN_DESTROY:
        DestroyWindow(main_window_handle);
        return TRUE;
    }

    return DefWindowProc(main_window_handle, message, wParam, lParam);
}

NOEXPORT LRESULT CALLBACK edit_proc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    if(uMsg==WM_CHAR && wParam==VK_SPACE) {
        Button_SetCheck(pause_handle, !Button_GetCheck(pause_handle));
        return 0;
    }
    return CallWindowProc(default_edit_proc, hWnd, uMsg, wParam, lParam);
}

NOEXPORT LRESULT CALLBACK about_proc(HWND dialog_handle, UINT message,
        WPARAM wParam, LPARAM lParam) {
    (void)lParam; /* squash the unused parameter warning */

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

        if(current_section) { /* should always be set */
            key_file_name=str2tstr(current_section->key);
            titlebar=str_tprintf(TEXT("Private key: %s"), key_file_name);
            str_free(key_file_name);
            SetWindowText(dialog_handle, titlebar);
            str_free(titlebar);
        }
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

            /* convert input passphrase to UTF-8 string (as ui_pass) */
            pass_txt=tstr2str(pass_dialog.txt);
            strcpy(ui_pass, pass_txt);
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

/**************************************** icon tray */

NOEXPORT void tray_update(const int num) {
    NOTIFYICONDATA nid;
    static ICON_TYPE previous_icon=ICON_NONE;
    ICON_TYPE current_icon;
    LPTSTR tip;

    if(!nt_service_client) {
        if(!global_options.option.taskbar) { /* currently disabled */
            tray_delete(); /* remove the taskbark icon if exists */
            return;
        }
    }
    if(!tray_menu_handle) /* initialize taskbar */
        tray_menu_handle=LoadMenu(ghInst, MAKEINTRESOURCE(IDM_TRAYMENU));
    if(!tray_menu_handle) {
        ioerror("LoadMenu");
        return;
    }

    ZeroMemory(&nid, sizeof nid);
    nid.cbSize=sizeof nid;
    nid.uID=1; /* application-defined icon ID */
    nid.uFlags=NIF_MESSAGE|NIF_TIP;
    nid.uCallbackMessage=WM_SYSTRAY; /* notification message */
    nid.hWnd=hwnd; /* window to receive notifications */
    if(num<0) {
        tip=str_tprintf(TEXT("stunnel is down"));
        current_icon=ICON_ERROR;
    } else if(num>0) {
        tip=str_tprintf(TEXT("stunnel connections: %d"), num);
        current_icon=ICON_ACTIVE;
    } else {
        tip=str_tprintf(TEXT("stunnel is idle"));
        current_icon=ICON_IDLE;
    }
    _tcsncpy(nid.szTip, tip, 63);
    nid.szTip[63]=TEXT('\0');
    str_free(tip);
    if(!nt_service_client) {
        nid.hIcon=global_options.icon[current_icon];
    } else { /* NT service client: configuration file ignored */
        static ICON_IMAGE icon[ICON_NONE]={NULL, NULL, NULL};
        if(!icon[current_icon])
            icon[current_icon]=load_icon_default(current_icon);
        nid.hIcon=icon[current_icon];
    }
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

NOEXPORT void tray_delete(void) {
    NOTIFYICONDATA nid;

    if(tray_menu_handle) {
        ZeroMemory(&nid, sizeof nid);
        nid.cbSize=sizeof nid;
        nid.uID=1; /* application-defined icon ID */
        nid.hWnd=hwnd; /* window to receive notifications */
        nid.uFlags=NIF_TIP; /* not really sure what to put here, but it works */
        Shell_NotifyIcon(NIM_DELETE, &nid); /* this removes the icon */
        if(!DestroyMenu(tray_menu_handle)) /* release menu resources */
            ioerror("DestroyMenu");
        tray_menu_handle=NULL;
    }
}

/**************************************** configuration file (re)loading */

NOEXPORT void config_invalid() {
    /* update the main window title */
    win32_name=TEXT("stunnel ") TEXT(STUNNEL_VERSION) TEXT(" on ")
        TEXT(STUNNEL_PLATFORM) TEXT(" (invalid configuration file)");
    SetWindowText(hwnd, win32_name);

    /* log window is hidden by default */
    ShowWindow(hwnd, SW_SHOWNORMAL); /* show window */
    SetForegroundWindow(hwnd); /* bring on top */

    tray_update(-1); /* error icon */
    peer_menu_update(); /* purge the list of sections */

    log_push(TEXT(""));
    ui_new_log("Server is down");
    message_box(TEXT("Stunnel server is down due to an error.\n")
        TEXT("You need to exit and correct the problem.\n")
        TEXT("Click OK to see the error log window."),
        MB_ICONERROR);
}

NOEXPORT void config_valid() {
    /* update the main window title */
    win32_name=TEXT("stunnel ") TEXT(STUNNEL_VERSION) TEXT(" on ")
        TEXT(STUNNEL_PLATFORM);
    SetWindowText(hwnd, win32_name);

    tray_update(num_clients); /* idle or busy icon (on reload) */
    peer_menu_update(); /* one menu item per section */

    /* enable IDM_REOPEN_LOG menu if a log file is used, disable otherwise */
    if(!nt_service_client) {
#ifndef _WIN32_WCE
        EnableMenuItem(main_menu_handle, IDM_REOPEN_LOG,
            (UINT)(global_options.output_file ? MF_ENABLED : MF_GRAYED));
#endif
        if(tray_menu_handle)
            EnableMenuItem(tray_menu_handle, IDM_REOPEN_LOG,
                (UINT)(global_options.output_file ? MF_ENABLED : MF_GRAYED));
    }
}

    /* TODO: port it to WCE */
NOEXPORT void config_edit(HWND main_window_handle) {
    char *quoted;
    LPTSTR conf_path;
    DISK_FILE *df;

    if(!cmdline.config_file)
        return;
    quoted=str_printf("\"%s\"", cmdline.config_file);
    conf_path=str2tstr(quoted);
    str_free(quoted);

    df=file_open(cmdline.config_file, FILE_MODE_APPEND);
    if(df) { /* the configuration file is writable */
        file_close(df);
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

/**************************************** peer certs */

NOEXPORT void peer_menu_update(void) {
    CRYPTO_THREAD_read_lock(stunnel_locks[LOCK_SECTIONS]);
    peer_menu_update_unlocked();
    CRYPTO_THREAD_unlock(stunnel_locks[LOCK_SECTIONS]);
}

NOEXPORT void peer_menu_update_unlocked(void) {
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
        main_peer_list=GetSubMenu(main_menu_handle, 2); /* 3rd sub-menu */
    if(main_peer_list)
        while(GetMenuItemCount(main_peer_list)) /* purge old menu */
            DeleteMenu(main_peer_list, 0, MF_BYPOSITION);
#endif
    if(tray_menu_handle)
        tray_peer_list=GetSubMenu(GetSubMenu(tray_menu_handle, 0), 8); /* 9th sub-menu */
    if(tray_peer_list)
        while(GetMenuItemCount(tray_peer_list)) /* purge old menu */
            DeleteMenu(tray_peer_list, 0, MF_BYPOSITION);

    /* initialize data structures */
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
            TEXT("\tverifyPeer = yes\n")
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
    if(section_number) { /* enable Save Peer Certificate */
#ifndef _WIN32_WCE
        /* 0 - File, 1 - Configuration, 2 - Save Peer Certificate */
        EnableMenuItem(main_menu_handle, 2, MF_BYPOSITION|MF_ENABLED);
#endif
        if(tray_menu_handle) /* 9th position on the tray menu */
            EnableMenuItem(GetSubMenu(tray_menu_handle, 0), 8, MF_BYPOSITION|MF_ENABLED);
    }
    if(hwnd)
        DrawMenuBar(hwnd);
}

NOEXPORT void peer_cert_save(WPARAM wParam) {
    SERVICE_OPTIONS *section;
    unsigned section_number;

    CRYPTO_THREAD_read_lock(stunnel_locks[LOCK_SECTIONS]);
    for(section=service_options.next, section_number=0;
            section && wParam!=IDM_PEER_MENU+section_number;
            section=section->next, ++section_number)
        ;
    if(section && !text_file_create(section->file, section->chain)) {
#ifndef _WIN32_WCE
        if(main_menu_handle)
            CheckMenuItem(main_menu_handle, (UINT)wParam, MF_CHECKED);
#endif
        if(tray_menu_handle)
            CheckMenuItem(tray_menu_handle, (UINT)wParam, MF_CHECKED);
        message_box(section->help, MB_ICONINFORMATION);
    }
    CRYPTO_THREAD_unlock(stunnel_locks[LOCK_SECTIONS]);
}

/**************************************** options callbacks */

void ui_config_reloaded(void) {
    if(!hwnd) /* NT service */
        return; /* not supported */
    PostMessage(hwnd, WM_VALID_CONFIG, 0, 0);
}

ICON_IMAGE load_icon_default(ICON_TYPE type) {
    WORD idi;
    ICON_IMAGE img;

    if(!hwnd) /* NT service */
        return NULL; /* not supported */
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

    if(!hwnd) /* NT service */
        return NULL; /* not supported */
    tname=str2tstr((LPSTR)name);
#ifndef _WIN32_WCE
    icon=LoadImage(NULL, tname, IMAGE_ICON, GetSystemMetrics(SM_CXSMICON),
        GetSystemMetrics(SM_CYSMICON), LR_LOADFROMFILE);
#else
    /* TODO: Implement a WCE version of LoadImage() */
    /* icon=wceLoadIconFromFile(tname); */
    ui_new_log("Loading image from file not implemented on WCE");
    icon=NULL;
#endif
    str_free(tname);
    return icon;
}

/**************************************** client callbacks */

void ui_new_chain(const unsigned section_number) {
    if(!hwnd) /* NT service */
        return; /* not supported */
    PostMessage(hwnd, WM_NEW_CHAIN, section_number, 0);
}

void ui_clients(const long num) {
    if(cmdline.service) { /* forward the number of connections to the connected client */
        char *result;

        result=control_pipe_call(pipe_name_ui, "connections %d", num);
        str_free(result);
    }
}

/**************************************** s_log callbacks */

void message_box(LPCTSTR text, const UINT type) {
    if(cmdline.quiet)
        return;
    MessageBox(hwnd, text, win32_name, type);
}

void ui_new_log(const char *line) {
    if(cmdline.service) { /* forward the log to the connected client */
        char *result;

        result=control_pipe_call(pipe_name_ui, "log %s", line);
        str_free(result);
    } else if(hwnd) { /* GUI mode */
        LPTSTR txt;

        txt=str2tstr(line);
        log_push(txt);
        str_free(txt);
    }
}

/**************************************** ctx callbacks */

int ui_passwd_cb(char *buf, int size, int rwflag, void *userdata) {
    int len;

    (void)rwflag; /* squash the unused parameter warning */
    (void)userdata; /* squash the unused parameter warning */
    if(!hwnd) /* NT service */
        return 0; /* not supported */
    if(!DialogBox(ghInst, TEXT("PassBox"), hwnd, (DLGPROC)pass_proc))
        return 0; /* dialog cancelled or failed */
    len=(int)strlen(ui_pass);
    if(len<0 || size<0) /* the API uses signed integers */
        return 0;
    if(len>size) /* truncate the returned data if needed */
        len=size;
    memcpy(buf, ui_pass, (size_t)len);
    memset(ui_pass, 0, sizeof ui_pass);
    return len;
}

#ifndef OPENSSL_NO_ENGINE

NOEXPORT int pin_cb(UI *ui, UI_STRING *uis) {
    if(!DialogBox(ghInst, TEXT("PassBox"), hwnd, (DLGPROC)pass_proc))
        return 0; /* dialog cancelled or failed */
    UI_set_result(ui, uis, ui_pass);
    memset(ui_pass, 0, sizeof ui_pass);
    return 1;
}

int (*ui_get_opener()) (UI *) {
    return NULL;
}

int (*ui_get_writer()) (UI *, UI_STRING *) {
    return NULL;
}

int (*ui_get_reader()) (UI *, UI_STRING *) {
    return hwnd ? pin_cb : NULL; /* only allow for UI in GUI mode */
}

int (*ui_get_closer()) (UI *) {
    return NULL;
}

#endif

/**************************************** log handling */

NOEXPORT void log_save() {
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
    ofn.Flags=OFN_EXPLORER|OFN_PATHMUSTEXIST|OFN_HIDEREADONLY|
        OFN_OVERWRITEPROMPT;
    if(!GetSaveFileName(&ofn))
        return;

    CRYPTO_THREAD_write_lock(stunnel_locks[LOCK_WIN_LOG]);
    txt=log_txt(); /* need to convert the result to UTF-8 */
    CRYPTO_THREAD_unlock(stunnel_locks[LOCK_WIN_LOG]);
    str=tstr2str(txt);
    str_free(txt);
    text_file_create(file_name, str);
    str_free(str);
}

NOEXPORT void log_push(LPCTSTR txt) {
    struct LIST *curr;
    size_t txt_len;
    static size_t log_len=0;

    txt_len=_tcslen(txt);
    curr=str_alloc_detached(sizeof(struct LIST)+txt_len*sizeof(TCHAR));
    curr->len=txt_len;
    _tcscpy(curr->txt, txt);
    curr->next=NULL;

    /* this critical section is performance critical */
    CRYPTO_THREAD_write_lock(stunnel_locks[LOCK_WIN_LOG]);
    if(tail)
        tail->next=curr;
    tail=curr;
    if(!head)
        head=tail;
    log_len++;
    new_logs=TRUE;
    if(log_len>LOG_LINES) {
        curr=head;
        head=head->next;
        log_len--;
        removed_logs++;
    } else {
        curr=NULL;
    }
    CRYPTO_THREAD_unlock(stunnel_locks[LOCK_WIN_LOG]);

    str_free(curr);
}

NOEXPORT void log_update(void) {
    LPTSTR txt;
    int offset;

    if(!visible || Button_GetCheck(pause_handle))
        return;

    /* retrieve the new edit control text */
    CRYPTO_THREAD_write_lock(stunnel_locks[LOCK_WIN_LOG]);
    if(new_logs) {
        txt=log_txt();
        new_logs=FALSE;
        offset=removed_logs;
        removed_logs=0;
    } else {
        txt=NULL;
    }
    CRYPTO_THREAD_unlock(stunnel_locks[LOCK_WIN_LOG]);

    if(txt) {
        int cur_pos, max_pos;
        WPARAM vscroll_param;

        /* update the text and scroll it without flickering */
        SendMessage(edit_handle, WM_SETREDRAW, (WPARAM)FALSE, (LPARAM)0);
        cur_pos=GetScrollPos(edit_handle, SB_VERT);
        SendMessage(edit_handle, WM_VSCROLL, (WPARAM)SB_BOTTOM, (LPARAM)0);
        max_pos=GetScrollPos(edit_handle, SB_VERT);
        SetWindowText(edit_handle, txt);
        str_free(txt);
        /* stick to the bottom, otherwise scroll up if lines were removed */
        vscroll_param=cur_pos==max_pos ? (WPARAM)SB_BOTTOM :
            MAKEWPARAM(SB_THUMBPOSITION, cur_pos<offset ? 0 : cur_pos-offset);
        SendMessage(edit_handle, WM_VSCROLL, vscroll_param, (LPARAM)0);
        SendMessage(edit_handle, WM_SETREDRAW, (WPARAM)TRUE, (LPARAM)0);

        /* redraw the affected areas of the edit control */
        if(cur_pos==max_pos || cur_pos<offset) /* visible text has changed */
            UpdateWindow(edit_handle);
        else /* only update the vertical scrollbar */
            SetScrollPos(edit_handle, SB_VERT, cur_pos-offset, TRUE);
    }
}

NOEXPORT LPTSTR log_txt(void) {
    LPTSTR buff;
    size_t ptr=0, len=0;
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

/**************************************** control pipe */

/* build a pipe file name from the configuration file name */
NOEXPORT void control_pipe_names() {
    char *pipe_name_txt, *text;

    if(cmdline.config_file) {
        unsigned char hash_bin[SHA256_DIGEST_LENGTH];
        char hash_txt[2*SHA256_DIGEST_LENGTH+1];

        /* SHA256 is only used here to prevent collisions, and not for security */
        SHA256((unsigned char *)cmdline.config_file, strlen(cmdline.config_file), hash_bin);
        bin2hexstring(hash_bin, sizeof hash_bin, hash_txt, sizeof hash_txt);
        pipe_name_txt=str_printf("\\\\.\\pipe\\%s", hash_txt);
    } else {
        pipe_name_txt=str_dup("\\\\.\\pipe\\stunnel-fallback");
    }
    text=str_printf("%s-ui", pipe_name_txt);
    pipe_name_ui=str2tstr(text);
    str_free(text);
    text=str_printf("%s-service", pipe_name_txt);
    pipe_name_service=str2tstr(text);
    str_free(text);
    str_free(pipe_name_txt);
}

/* attempt to send a command to an already running stunnel */
NOEXPORT int control_pipe_client() {
    char *result=NULL;

    if(cmdline.exit || cmdline.reload || cmdline.reopen) {
        if(cmdline.exit)
            result=control_pipe_call(pipe_name_service, "signal %u", SIGNAL_TERMINATE);
        else if(cmdline.reload)
            result=control_pipe_call(pipe_name_service, "signal %u", SIGNAL_RELOAD_CONFIG);
        else if(cmdline.reopen)
            result=control_pipe_call(pipe_name_service, "signal %u", SIGNAL_REOPEN_LOG);
        if(!result) {
            message_box(TEXT("The target stunnel was not found"), MB_ICONERROR);
            return 1; /* terminate this instance */
        }
        if(strcasecmp(result, "succeeded")) {
            message_box(TEXT("Request failed"), MB_ICONERROR);
            str_free(result);
            return 1; /* terminate this instance */
        }
        message_box(TEXT("Request succeeded"), MB_ICONINFORMATION);
        str_free(result);
        return 1; /* terminate this instance */
    }
    result=control_pipe_call(pipe_name_service, "connect");
    if(!result)
        return 0; /* proceed with GUI initialization */
    if(!is_prefix(result, "service ")) {
        str_free(result);
        return 1; /* terminate this instance */
    }
    num_clients=atol(result+8);
    str_free(result);

    nt_service_client=TRUE;
    sthreads_init(); /* required for locking to work */
    if(control_pipe_server(pipe_name_ui))
        return 1; /* a control pipe ui already exists or failed */
    gui_init();
    win32_name=TEXT("stunnel ") TEXT(STUNNEL_VERSION) TEXT(" on ")
        TEXT(STUNNEL_PLATFORM) TEXT(" (NT service client)");
    SetWindowText(hwnd, win32_name);
#ifndef _WIN32_WCE
    EnableMenuItem(main_menu_handle, IDM_REOPEN_LOG, MF_ENABLED);
#endif
    if(tray_menu_handle)
        EnableMenuItem(tray_menu_handle, IDM_REOPEN_LOG, MF_ENABLED);
    ShowWindow(hwnd, SW_SHOWNORMAL); /* show window */
    SetForegroundWindow(hwnd); /* bring on top */
    /* create a UI pipe thread for accepting logs */
    gui_loop();
    return 0; /* terminate this instance */
}

/* create a new control pipe server */
NOEXPORT int control_pipe_server(LPTSTR pipe_name) {
    char *result;
    HANDLE thread;

    result=control_pipe_call(pipe_name, "connect");
    if(result) { /* a control pipe server already exists */
        str_free(result);
        return 1;
    }
    thread=(HANDLE)_beginthreadex(NULL, DEFAULT_STACK_SIZE,
        control_pipe_server_thread, pipe_name, 0, NULL);
    if(!thread) {
        message_box(TEXT("Failed to create a control pipe server"), MB_ICONERROR);
        return 1;
    }
    CloseHandle(thread);
    return 0;
}

#define MSG_SIZE 256

NOEXPORT unsigned __stdcall control_pipe_server_thread(void *arg) {
    LPTSTR pipe_name=arg;
    SECURITY_ATTRIBUTES sa;

    tls_alloc(NULL, NULL, "control server");

    /* initialize security attributes */
    sa.nLength=sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle=FALSE;
    sa.lpSecurityDescriptor=NULL;
    if(ConvertStringSecurityDescriptorToSecurityDescriptor(
            TEXT("D:") /* discretionary ACL */
            TEXT("(D;OICI;GA;;;BG)") /* deny access to Built-in Guests */
            TEXT("(D;OICI;GA;;;AN)") /* deny access to Anonymous Logon */
            TEXT("(A;OICI;GRGW;;;AU)"), /* allow read/write to Authenticated Users */
            SDDL_REVISION_1, &sa.lpSecurityDescriptor, NULL)) {
        /* spawn new threads for incoming client connections */
        for(;;) {
            BOOL connected;
            HANDLE pipe=CreateNamedPipe(pipe_name, PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_MESSAGE|PIPE_READMODE_MESSAGE|PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES, MSG_SIZE, MSG_SIZE, 3000, &sa);
            if(pipe==INVALID_HANDLE_VALUE) {
                message_box(TEXT("Failed to create a control pipe"), MB_ICONERROR);
                break;
            }
            connected=ConnectNamedPipe(pipe, NULL);
            if(!connected)
                connected=(GetLastError()==ERROR_PIPE_CONNECTED);
            if(connected) {
                HANDLE thread=(HANDLE)_beginthreadex(NULL, DEFAULT_STACK_SIZE,
                    control_pipe_instance_thread, pipe, 0, NULL);
                if(thread)
                    CloseHandle(thread);
            } else {
                CloseHandle(pipe);
            }
        }
    } else {
        message_box(TEXT("Failed to create a security descriptor"), MB_ICONERROR);
    }

    if(nt_service_client && hwnd)
        PostMessage(hwnd, WM_TERMINATE, 0, 0); /* terminate GUI */
    tls_cleanup();
    _endthreadex(0);
}

NOEXPORT unsigned __stdcall control_pipe_instance_thread(void *arg) {
    HANDLE pipe=arg;
    char *message;

    tls_alloc(NULL, NULL, "control instance");

    /* process incoming data */
    message=control_pipe_recv(pipe);
    if(message) {
        if(hwnd) { /* UI is available */
            if(is_prefix(message, "log ")) {
                control_pipe_send(pipe, "succeeded");
                ui_new_log(message+4);
            } else if(is_prefix(message, "connections ")) {
                control_pipe_send(pipe, "succeeded");
                num_clients=atol(message+12);
            } else if(is_prefix(message, "signal ")) {
                control_pipe_send(pipe, "succeeded");
                signal_post((uint8_t)atoi(message+7));
            } else if(!strcasecmp(message, "connect")) {
                control_pipe_send(pipe, "succeeded");
                ShowWindow(hwnd, SW_SHOWNORMAL); /* show window */
                SetForegroundWindow(hwnd); /* bring on top */
            } else if(!strcasecmp(message, "terminate")) {
                control_pipe_send(pipe, "succeeded");
                PostMessage(hwnd, WM_TERMINATE, 0, 0); /* terminate GUI */
            } else { /* ignore unknown messages */
                control_pipe_send(pipe, "ignored");
            }
        } else if(cmdline.service) { /* NT service */
            if(is_prefix(message, "signal ")) {
                control_pipe_send(pipe, "succeeded");
                signal_post((uint8_t)atoi(message+7));
            } else if(!strcasecmp(message, "connect")) {
                control_pipe_send(pipe, "service %d", num_clients);
            } else { /* ignore unknown messages */
                control_pipe_send(pipe, "ignored");
            }
        } else {
            control_pipe_send(pipe, "failed");
        }
        str_free(message);
    }
    CloseHandle(pipe);
    tls_cleanup();
    _endthreadex(0);
}

NOEXPORT int control_pipe_send(HANDLE pipe, const char *format, ...) {
    va_list ap;
    char *send_buf;
    BOOL success;
    DWORD send_len, sent_len;

    va_start(ap, format);
    send_buf=str_vprintf(format, ap);
    va_end(ap);
    send_len=(DWORD)strlen(send_buf);
    success=WriteFile(pipe, send_buf, send_len, &sent_len, NULL);
    str_free(send_buf);
    return !success || sent_len!=send_len;
}

NOEXPORT char *control_pipe_recv(HANDLE pipe) {
    char recv_buf[MSG_SIZE+1];
    BOOL success;
    DWORD recv_len;

    success=ReadFile(pipe, recv_buf, MSG_SIZE, &recv_len, NULL);
    if(!success || !recv_len)
        return NULL;
    recv_buf[recv_len]='\0'; /* null-terminate the received message */
    return str_dup(recv_buf);
}

NOEXPORT char *control_pipe_call(LPTSTR name, const char *format, ...) {
    va_list ap;
    char recv_buf[MSG_SIZE+1], *send_buf;
    BOOL success;
    DWORD send_len, recv_len;

    va_start(ap, format);
    send_buf=str_vprintf(format, ap);
    va_end(ap);
    send_len=(DWORD)strlen(send_buf);
    success=CallNamedPipe(name,
        send_buf, send_len,
        recv_buf, MSG_SIZE,
        &recv_len, 3000);
    str_free(send_buf);
    if(!success || !recv_len)
        return NULL;
    recv_buf[recv_len]='\0'; /* null-terminate the message */
    return str_dup(recv_buf);
}

/**************************************** windows service */

#ifndef _WIN32_WCE

NOEXPORT int service_initialize(void) {
    SERVICE_TABLE_ENTRY serviceTable[]={{0, 0}, {0, 0}};

    serviceTable[0].lpServiceName=SERVICE_NAME;
    serviceTable[0].lpServiceProc=service_main;
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
        stunnel_exe_path, params_get());
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
    (void)argc; /* squash the unused parameter warning */
    (void)argv; /* squash the unused parameter warning */

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
        char *result;

        /* service is starting */
        serviceStatus.dwCurrentState=SERVICE_START_PENDING;
        SetServiceStatus(serviceStatusHandle, &serviceStatus);

        /* running */
        serviceStatus.dwControlsAccepted|=
            (SERVICE_ACCEPT_STOP|SERVICE_ACCEPT_SHUTDOWN);
        serviceStatus.dwCurrentState=SERVICE_RUNNING;
        SetServiceStatus(serviceStatusHandle, &serviceStatus);

        /* start the main loop */
        main_init();
        if(!main_configure(cmdline.config_file, NULL))
            daemon_loop();
        result=control_pipe_call(pipe_name_ui, "terminate");
        str_free(result);
        main_cleanup();

        /* service was stopped */
        serviceStatus.dwCurrentState=SERVICE_STOP_PENDING;
        SetServiceStatus(serviceStatusHandle, &serviceStatus);

        /* service is now stopped */
        serviceStatus.dwControlsAccepted&=
            (DWORD)~(SERVICE_ACCEPT_STOP|SERVICE_ACCEPT_SHUTDOWN);
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
        signal_post(SIGNAL_TERMINATE);
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

/**************************************** helper functions */

NOEXPORT LPTSTR params_get() {
    LPTSTR c;
    TCHAR s;

    c=GetCommandLine();

    /* skip executable path */
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

    /* skip spaces */
    while(*c==TEXT(' '))
        ++c;

    return c; /* return parameters */
}

NOEXPORT int text_file_create(LPTSTR file_name, char *str) {
    HANDLE file_handle;
    DWORD ignore;

    file_handle=CreateFile(file_name, GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if(file_handle==INVALID_HANDLE_VALUE) {
        error_box(TEXT("CreateFile"));
        return 1;
    }
    if(!WriteFile(file_handle, str, (DWORD)strlen(str), &ignore, NULL)) {
        CloseHandle(file_handle);
        error_box(TEXT("WriteFile"));
        return 1;
    }
    CloseHandle(file_handle);
    return 0;
}

/* a wrapper is needed for GUI (not for NT service), as signal_pipe only
 * becomes active after the first valid configuration file is loaded */
NOEXPORT void gui_signal_post(uint8_t sig) {
    if(nt_service_client) {
        char *result;

        /* forward the signal to the connected server */
        result=control_pipe_call(pipe_name_service, "signal %u", sig);
        str_free(result);
    } else if(num_clients>=0) { /* signal_pipe is active */
        signal_post(sig);
        if(hwnd && sig==SIGNAL_TERMINATE) { /* forcefully close the GUI */
            /* 3 seconds for the main and client threads to save the final logs */
            if(WaitForSingleObject(main_terminated, 3000) != WAIT_OBJECT_0)
                PostMessage(hwnd, WM_TERMINATE, 0, 0); /* terminate GUI */
        }
    } else { /* no valid configuration file is loaded */
        switch(sig) {
        case SIGNAL_TERMINATE:
            PostMessage(hwnd, WM_TERMINATE, 0, 0); /* terminate GUI */
            break;
        case SIGNAL_RELOAD_CONFIG:
            SetEvent(config_ready); /* unlock daemon_thread() */
            break;
        default: /* ignore */
            break;
        }
    }
}

NOEXPORT void error_box(LPCTSTR text) {
    LPTSTR errmsg, fullmsg;
    DWORD dw;

    dw=GetLastError();
    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM,
        NULL, dw, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&errmsg, 0, NULL);
    fullmsg=str_tprintf(TEXT("%s: error %ld: %s"), text, dw, errmsg);
    LocalFree(errmsg);
    message_box(fullmsg, MB_ICONERROR);
    str_free(fullmsg);
}

/* end of ui_win_gui.c */
