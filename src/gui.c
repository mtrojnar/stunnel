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
#define STUNNEL_PLATFORM "Win32"
#define SERVICE_NAME "stunnel"
#endif

/* mingw-Patches-1825044 is missing in Debian Squeeze */
WINBASEAPI BOOL WINAPI CheckTokenMembership(HANDLE, PSID, PBOOL);

/* prototypes */
static BOOL CALLBACK enum_windows(HWND, LPARAM);
static void parse_cmdline(LPSTR);
static int initialize_winsock(void);
static int gui_loop();

static LRESULT CALLBACK window_proc(HWND, UINT, WPARAM, LPARAM);
static LRESULT CALLBACK about_proc(HWND, UINT, WPARAM, LPARAM);
static LRESULT CALLBACK pass_proc(HWND, UINT, WPARAM, LPARAM);

static void save_log(void);
static void win_log(LPSTR);
static int save_text_file(LPTSTR, char *);
static void update_logs(void);
static LPTSTR log_txt(void);

static void daemon_thread(void *);

static void valid_config(void);
static void invalid_config(void);
static void update_peer_menu(void);
static void update_tray_icon(void);
static void error_box(const LPSTR);
static void edit_config(HWND);
static BOOL is_admin(void);

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

static unsigned int number_of_sections=0;

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
static HANDLE small_icon; /* 16x16 icon */
    /* win32_name is needed for any error_box(), message_box(),
     * and the initial main window title */
static TCHAR *win32_name=TEXT("stunnel ") TEXT(STUNNEL_VERSION)
    TEXT(" on ") TEXT(STUNNEL_PLATFORM) TEXT(" (not configured)");

#ifndef _WIN32_WCE
static SERVICE_STATUS serviceStatus;
static SERVICE_STATUS_HANDLE serviceStatusHandle=0;
#endif

static volatile int visible=0;
static volatile int error_mode=1; /* no valid configuration was ever loaded */
static HANDLE config_ready=NULL; /* reload without a valid configuration */
static LONG new_logs=0;

static UI_DATA *ui_data=NULL;

static struct {
    char *config_file;
    unsigned int service:1, install:1, uninstall:1, start:1, stop:1,
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

    parse_cmdline(command_line); /* setup global cmdline structure */

#ifndef _WIN32_WCE
    GetModuleFileName(0, stunnel_exe_path, MAX_PATH);

    /* find previous instances of the same executable */
    if(!cmdline.service && !cmdline.install && !cmdline.uninstall &&
            !cmdline.start && !cmdline.stop) {
        EnumWindows(enum_windows, (LPARAM)stunnel_exe_path);
        if(cmdline.exit)
            return 0; /* in case EnumWindows didn't find a previous instance */
    }

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
#endif

    if(initialize_winsock())
        return 1;

#ifndef _WIN32_WCE
    if(cmdline.service) /* "-service" must be processed before "-install" */
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
    return gui_loop();
}

#ifndef _WIN32_WCE

static BOOL CALLBACK enum_windows(HWND other_window_handle, LPARAM lParam) {
    DWORD pid, exit_code;
    HINSTANCE hInstance;
    char window_exe_path[MAX_PATH];
    HANDLE process_handle;
    char *stunnel_exe_path=(char *)lParam;

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
    if(strcmp(stunnel_exe_path, window_exe_path)) {
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
            c=opt;
            break;
        }
    }
    cmdline.config_file=*c ? str_dup(c) : NULL;
    str_free(line);
}

/* try to load winsock2 resolver functions from a specified dll name */
static int initialize_winsock() {
    static struct WSAData wsa_state;

    if(WSAStartup(MAKEWORD( 2, 2 ), &wsa_state)) {
        message_box("Failed to initialize winsock", MB_ICONERROR);
        return 1; /* error */
    }
    resolver_init();
    return 0; /* IPv4 detected -> OK */
}

/**************************************** GUI thread */

static int gui_loop() {
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
    /* auto-reset, non-signaled */
    config_ready=CreateEvent(NULL, FALSE, FALSE, NULL);
    _beginthread(daemon_thread, DEFAULT_STACK_SIZE, NULL);

    while(GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return msg.wParam;
}

static LRESULT CALLBACK window_proc(HWND main_window_handle,
        UINT message, WPARAM wParam, LPARAM lParam) {
    NOTIFYICONDATA nid;
    POINT pt;
    RECT rect;
    SERVICE_OPTIONS *section;
    unsigned int section_number;

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
        update_tray_icon();
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
        if(wParam>=IDM_PEER_MENU && wParam<IDM_PEER_MENU+number_of_sections) {
            for(section=service_options.next, section_number=0;
                    section && wParam!=IDM_PEER_MENU+section_number;
                    section=section->next, ++section_number)
                ;
            if(!section)
                return TRUE;
            if(save_text_file(section->file, section->chain))
                return TRUE;
#ifndef _WIN32_WCE
            if(main_menu_handle)
                CheckMenuItem(main_menu_handle, wParam, MF_CHECKED);
#endif
            if(tray_menu_handle)
                CheckMenuItem(tray_menu_handle, wParam, MF_CHECKED);
            message_box(section->help, MB_ICONINFORMATION);
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
            if(!error_mode) /* signal_pipe is active */
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
            if(error_mode) /* unlock daemon_thread */
                SetEvent(config_ready);
            else /* signal_pipe is active */
                signal_post(SIGNAL_RELOAD_CONFIG);
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
        return TRUE;

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

    case WM_VALID_CONFIG:
        valid_config();
        return TRUE;

    case WM_INVALID_CONFIG:
        invalid_config();
        return TRUE;

    case WM_LOG:
        win_log((LPSTR)wParam);
        return TRUE;

    case WM_NEW_CHAIN:
#ifndef _WIN32_WCE
        if(main_menu_handle)
            EnableMenuItem(main_menu_handle, IDM_PEER_MENU+wParam, MF_ENABLED);
#endif
        if(tray_menu_handle)
            EnableMenuItem(tray_menu_handle, IDM_PEER_MENU+wParam, MF_ENABLED);
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

/**************************************** log handling */

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
    str=tstr2str(txt);
    str_free(txt);
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

static void win_log(LPSTR line) {
    struct LIST *curr;
    int len;
    static int log_len=0;
    LPTSTR txt;

    txt=str2tstr(line);
    len=_tcslen(txt);
    /* this list is shared between threads */
    curr=str_alloc(sizeof(struct LIST)+len*sizeof(TCHAR));
    curr->len=len;
    _tcscpy(curr->txt, txt);
    str_free(txt);
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
        /* this list is shared between threads */
        str_free(curr);
        log_len--;
    }

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

    for(curr=head; curr; curr=curr->next)
        len+=curr->len+2; /* +2 for trailing '\r\n' */
    buff=str_alloc((len+1)*sizeof(TCHAR)); /* +1 for trailing '\0' */
    for(curr=head; curr; curr=curr->next) {
        memcpy(buff+ptr, curr->txt, curr->len*sizeof(TCHAR));
        ptr+=curr->len;
        if(curr->next) {
            buff[ptr++]='\r';
            buff[ptr++]='\n';
        }
    }
    buff[ptr]='\0';

    return buff;
}

/**************************************** worker thread */

static void daemon_thread(void *arg) {
    (void)arg; /* skip warning about unused parameter */

    main_initialize();
    /* get a valid configuration */
    while(main_configure(cmdline.config_file, NULL)) {
        unbind_ports(); /* in case initialization failed after bind_ports() */
        log_flush(LOG_MODE_ERROR); /* otherwise logs are buffered */
        PostMessage(hwnd, WM_INVALID_CONFIG, 0, 0); /* display error */
        WaitForSingleObject(config_ready, INFINITE);
        log_close(); /* prevent main_configure() from logging in error mode */
    }
    error_mode=0; /* a valid configuration was loaded */

    /* start the main loop */
    daemon_loop();
    _endthread(); /* SIGNAL_TERMINATE received */
}

/**************************************** helper functions */

static void invalid_config() {
    /* update the main window title */
    win32_name=TEXT("stunnel ") TEXT(STUNNEL_VERSION) TEXT(" on ")
        TEXT(STUNNEL_PLATFORM) TEXT(" (invalid stunnel.conf)");
    SetWindowText(hwnd, win32_name);

    /* log window is hidden by default */
    ShowWindow(hwnd, SW_SHOWNORMAL); /* show window */
    SetForegroundWindow(hwnd); /* bring on top */

    update_tray_icon();

    win_log("");
    s_log(LOG_ERR, "Server is down");
    message_box("Stunnel server is down due to an error.\n"
        "You need to exit and correct the problem.\n"
        "Click OK to see the error log window.",
        MB_ICONERROR);
}

static void valid_config() {
    /* update the main window title */
    win32_name=TEXT("stunnel ") TEXT(STUNNEL_VERSION) TEXT(" on ")
        TEXT(STUNNEL_PLATFORM);
    SetWindowText(hwnd, win32_name);

    if(global_options.option.taskbar) /* save menu resources */
        update_tray_icon();

    update_peer_menu();

    /* enable IDM_REOPEN_LOG menu if a log file is used, disable otherwise */
#ifndef _WIN32_WCE
    EnableMenuItem(main_menu_handle, IDM_REOPEN_LOG,
        global_options.output_file ? MF_ENABLED : MF_GRAYED);
#endif
    if(tray_menu_handle)
        EnableMenuItem(tray_menu_handle, IDM_REOPEN_LOG,
            global_options.output_file ? MF_ENABLED : MF_GRAYED);
}

static void update_peer_menu(void) {
    SERVICE_OPTIONS *section;
#ifndef _WIN32_WCE
    HMENU main_peer_list=NULL;
#endif
    HMENU tray_peer_list=NULL;
    char *str;
    unsigned int section_number;
    MENUITEMINFO mii;

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
        /* setup section->file */
        str=str_printf("peer-%s.pem", section->servname);
        section->file=str2tstr(str);
        str_free(str);

        /* setup LPTSTR section->file */
        str=str_printf("peer-%s.pem", section->servname);
        section->file=str2tstr(str);
        str_free(str);

        /* setup (char *) section->help */
        section->help=str_printf(
            "Peer certificate chain has been saved.\n"
            "Add the following lines to section [%s]:\n"
            "\tCAfile = peer-%s.pem\n"
            "\tverify = 3\n"
            "to enable cryptographic authentication.\n"
            "Then reload stunnel configuration file.",
            section->servname, section->servname);

        /* setup section->chain */
        section->chain=NULL;

        /* insert new menu item */
        mii.cbSize=sizeof mii;
        mii.fMask=MIIM_STRING|MIIM_DATA|MIIM_ID|MIIM_STATE;
        mii.fType=MFT_STRING;
        mii.dwTypeData=section->file;
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
}

static void update_tray_icon(void) {
    NOTIFYICONDATA nid;

    if(!tray_menu_handle) { /* initialize taskbar */
        tray_menu_handle=LoadMenu(ghInst, MAKEINTRESOURCE(IDM_TRAYMENU));
        SetTimer(hwnd, 0x29a, 1000, NULL); /* 1-second timer */
    }
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
    nid.uCallbackMessage=WM_SYSTRAY;
    nid.hIcon=small_icon; /* 16x16 icon */
    Shell_NotifyIcon(NIM_ADD, &nid); /* this adds the icon */
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

void message_box(const LPSTR text, const UINT type) {
    LPTSTR tstr;

    if(cmdline.quiet)
        return;
    tstr=str2tstr(text);
    MessageBox(hwnd, tstr, win32_name, type);
    str_free(tstr);
}

void win_new_chain(int section_number) {
    PostMessage(hwnd, WM_NEW_CHAIN, section_number, 0);
}

void win_new_log(char *line) {
    SendMessage(hwnd, WM_LOG, (WPARAM)line, 0);
}

void win_new_config(void) {
    PostMessage(hwnd, WM_VALID_CONFIG, 0, 0);
}

static void edit_config(HWND main_window_handle) {
    char cwd[MAX_PATH], *conf_path;

    if(is_admin()) {
        ShellExecute(main_window_handle, TEXT("open"),
            TEXT("notepad.exe"), TEXT("stunnel.conf"),
            NULL, SW_SHOWNORMAL);
    } else { /* UAC workaround */
        GetCurrentDirectory(MAX_PATH, cwd);
        conf_path=str_printf("%s\\stunnel.conf", cwd);
        ShellExecute(main_window_handle, TEXT("runas"),
            TEXT("notepad.exe"), conf_path,
            NULL, SW_SHOWNORMAL);
        str_free(conf_path);
    }
}

static BOOL is_admin(void) {
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
}

/**************************************** windows service */

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
