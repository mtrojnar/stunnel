/*
 *   stunnel       Universal SSL tunnel
 *   Copyright (C) 1998-2009 Michal Trojnara <Michal.Trojnara@mirt.net>
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
#include "resources.h"

#define UWM_SYSTRAY (WM_USER + 1) /* sent to us by the taskbar */
#define LOG_LINES 250

/* Prototypes */
static void parse_cmdline(LPSTR);
#ifndef _WIN32_WCE
static int set_cwd(void);
#endif
static int initialize_winsock(void);
static void ThreadFunc(void *);
static LRESULT CALLBACK wndProc(HWND, UINT, WPARAM, LPARAM);
static int win_main(HINSTANCE, HINSTANCE, LPSTR, int);
static void save_file(HWND);
static LRESULT CALLBACK about_proc(HWND, UINT, WPARAM, LPARAM);
static LRESULT CALLBACK pass_proc(HWND, UINT, WPARAM, LPARAM);
static LPTSTR log_txt(void);
static void set_visible(int);
static void error_box(const LPTSTR);

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

/* Global variables */
static struct LIST {
  struct LIST *next;
  int len;
  TCHAR txt[1]; /* single character for trailing '\0' */
} *head=NULL, *tail=NULL;
static HINSTANCE ghInst;
static HWND EditControl=NULL;
static HMENU htraymenu=NULL;
#ifndef _WIN32_WCE
static HMENU hmainmenu;
#endif
static HMENU hpopup;
static HWND hwnd=NULL;
#ifdef _WIN32_WCE
static HWND hwndCB; /* command bar handle */
#endif
static HANDLE small_icon; /* 16x16 icon */
TCHAR win32_name[STRLEN];

#ifndef _WIN32_WCE
static SERVICE_STATUS serviceStatus;
static SERVICE_STATUS_HANDLE serviceStatusHandle=0;
#endif

static int visible=0, error_mode=0;
static jmp_buf jump_buf;

static UI_DATA *ui_data=NULL;

#ifndef _WIN32_WCE
GETADDRINFO s_getaddrinfo;
FREEADDRINFO s_freeaddrinfo;
GETNAMEINFO s_getnameinfo;
#endif

static struct {
    char config_file[STRLEN];
    unsigned int install:1, uninstall:1, start:1, stop:1, service:1, quiet:1;
} cmdline;

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
#ifdef _WIN32_WCE
    LPWSTR lpCmdLine,
#else
    LPSTR lpCmdLine,
#endif
    int nCmdShow) {

    LPSTR command_line;

    /* system("c:\\start.bat"); */

#ifdef _WIN32_WCE
    command_line=tstr2str(lpCmdLine);
#else
    command_line=lpCmdLine;
#endif

    ghInst=hInstance;

    parse_cmdline(command_line); /* setup global cmdline structure */
#ifndef _WIN32_WCE
    if(set_cwd()) /* set current working directory */
        return 1;
#endif

    /* setup the windo caption before reading the configuration file
     * options.win32_service is not available here and may not be used */
#ifdef _WIN32_WCE
    _tcscpy(win32_name, TEXT("stunnel ") TEXT(VERSION)
        TEXT(" on Windows CE (not configured)"));
#else
    _tcscpy(win32_name, TEXT("stunnel ") TEXT(VERSION)
        TEXT(" on Win32 (not configured)"));
#endif

    if(initialize_winsock())
        return 1;

    if(!setjmp(jump_buf)) { /* TRY */
        main_initialize(
            cmdline.config_file[0] ? cmdline.config_file : NULL, NULL);
#ifdef _WIN32_WCE
        _tcscpy(win32_name, TEXT("stunnel ") TEXT(VERSION)
            TEXT(" on Windows CE"));
#else
        _snprintf(win32_name, STRLEN, "stunnel %s on Win32 (%s)",
            VERSION, options.win32_service); /* update the information */
        if(!cmdline.service) {
            if(cmdline.install)
                return service_install(command_line);
            if(cmdline.uninstall)
                return service_uninstall();
            if(cmdline.start)
                return service_start();
            if(cmdline.stop)
                return service_stop();
        }
#endif
    }

    /* CATCH */
#ifndef _WIN32_WCE
    if(cmdline.service)
        return service_initialize();
    else
#endif
        return win_main(hInstance, hPrevInstance, command_line, nCmdShow);
}

static void parse_cmdline(LPSTR command_line) {
    char line[STRLEN], *c, *opt;

    safecopy(line, command_line);
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
        else { /* option to be processed in options.c */
            safecopy(cmdline.config_file, opt);
            return; /* no need to parse other options */
        }
    }

    safecopy(cmdline.config_file, c);
}

#ifndef _WIN32_WCE
static int set_cwd(void) {
    char *c, errmsg[STRLEN], exe_file_name[STRLEN];

    GetModuleFileName(0, exe_file_name, STRLEN);
    c=strrchr(exe_file_name, '\\'); /* last backslash */
    if(c) /* found */
        c[1]='\0'; /* truncate program name */
    if(!SetCurrentDirectory(exe_file_name)) {
        safecopy(errmsg, "Cannot set directory to ");
        safeconcat(errmsg, exe_file_name);
        MessageBox(hwnd, errmsg, TEXT("stunnel"), MB_ICONERROR);
        return 1;
    }
    return 0;
}
#endif

/* try to load winsock2 resolver functions from a specified dll name */
static int initialize_winsock() {
    static struct WSAData wsa_state;
#ifndef _WIN32_WCE
    HINSTANCE handle;
#endif

    if(WSAStartup(MAKEWORD( 2, 2 ), &wsa_state)) {
        MessageBox(hwnd, TEXT("Failed to initialize winsock"),
            TEXT("stunnel"), MB_ICONERROR);
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
    handle=LoadLibrary("wship6.dll"); /* Experimental IPv6 for Windows 2000 */
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

static int win_main(HINSTANCE hInstance, HINSTANCE hPrevInstance,
        LPSTR command_line, int nCmdShow) {
#ifdef _WIN32_WCE
    WNDCLASS wc;
#else
    WNDCLASSEX wc;
#endif
    MSG msg;
    LPTSTR classname=win32_name;

    /* register the class */
#ifndef _WIN32_WCE
    wc.cbSize=sizeof wc;
#endif
    wc.style=CS_VREDRAW|CS_HREDRAW;
    wc.lpfnWndProc=wndProc;
    wc.cbClsExtra=wc.cbWndExtra=0;
    wc.hInstance=hInstance;
    wc.hIcon=LoadIcon(hInstance, MAKEINTRESOURCE(IDI_MYICON));
    wc.hCursor=LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground=(HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszMenuName=NULL;
    wc.lpszClassName=classname;
    small_icon=LoadImage(hInstance, MAKEINTRESOURCE(IDI_MYICON), IMAGE_ICON,
        GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), 0);
#ifdef _WIN32_WCE
    RegisterClass(&wc);
#else
    wc.hIconSm=small_icon; /* 16x16 icon */
    RegisterClassEx(&wc);
#endif

    /* create main window */
    if(options.option.taskbar) { /* save menu resources */
        htraymenu=LoadMenu(ghInst, MAKEINTRESOURCE(IDM_TRAYMENU));
        hpopup=GetSubMenu(htraymenu, 0);
    }

#ifdef _WIN32_WCE
    hwnd=CreateWindow(classname, win32_name, 0,
        CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
        NULL, NULL, hInstance, NULL);
#else
    hmainmenu=LoadMenu(ghInst, MAKEINTRESOURCE(IDM_MAINMENU));
    hwnd=CreateWindow(classname, win32_name, WS_TILEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
        NULL, hmainmenu, hInstance, NULL);

    if(cmdline.service) /* do not allow to save file in the service mode */
        EnableMenuItem(hmainmenu, IDM_SAVEAS, MF_GRAYED);
#endif

    if(error_mode) /* log window is hidden by default */
        set_visible(1);
    else /* create the main thread */
        _beginthread(ThreadFunc, 0, NULL);

    while(GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return msg.wParam;
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

static void ThreadFunc(void *arg) {
    if(!setjmp(jump_buf))
        main_execute();
    else
        set_visible(1); /* could be unsafe to call it from another thread */
    _endthread();
}

static LRESULT CALLBACK wndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    NOTIFYICONDATA nid;
    POINT pt;
    RECT rect;
    LPTSTR txt;

#if 0
    if(message!=WM_CTLCOLORSTATIC && message!=WM_TIMER)
        s_log(LOG_DEBUG, "Window message: %d", message);
#endif
    switch(message) {
    case WM_CREATE:
        if(options.option.taskbar) /* taskbar update enabled? */
            SetTimer(hwnd, 0x29a, 1000, NULL); /* 1-second timer */

#ifdef _WIN32_WCE
        /* create command bar */
        hwndCB=CommandBar_Create(ghInst, hwnd, 1);
        if(!hwndCB)
            error_box(TEXT("CommandBar_Create"));
        if(!CommandBar_InsertMenubar(hwndCB, ghInst, IDM_MAINMENU, 0))
            error_box(TEXT("CommandBar_InsertMenubar"));
        if(!CommandBar_AddAdornments(hwndCB, 0, 0))
            error_box(TEXT("CommandBar_AddAdornments"));
#endif

        /* create child edit window */
        EditControl=CreateWindow(TEXT("EDIT"), NULL,
            WS_CHILD|WS_VISIBLE|WS_HSCROLL|WS_VSCROLL|ES_MULTILINE|ES_READONLY,
            0, 0, 0, 0, hwnd, (HMENU)IDE_EDIT, ghInst, NULL);
#ifndef _WIN32_WCE
        SendMessage(EditControl, WM_SETFONT,
            (WPARAM)GetStockObject(OEM_FIXED_FONT),
        MAKELPARAM(FALSE, 0)); /* no need to redraw right, now */
#endif

        /* NOTE: there's no return statement here -> proceeding with resize */

    case WM_SIZE:
        GetClientRect(hwnd, &rect);
#ifdef _WIN32_WCE
        MoveWindow(EditControl, 0, CommandBar_Height(hwndCB),
            rect.right, rect.bottom-CommandBar_Height(hwndCB), TRUE);
#else
        MoveWindow(EditControl, 0, 0, rect.right, rect.bottom, TRUE);
#endif
        UpdateWindow(EditControl);
        /* CommandBar_Show(hwndCB, TRUE); */
        return TRUE;

    case WM_SETFOCUS:
        txt=log_txt();
        SetWindowText(EditControl, txt);
        free(txt);
        SetFocus(EditControl);
        return TRUE;

    case WM_TIMER:
        update_taskbar();
        return TRUE;

    case WM_CLOSE:
        set_visible(0);
        return TRUE;

    case WM_DESTROY:
#ifdef _WIN32_WCE
        CommandBar_Destroy(hwndCB);
#else
        if(hmainmenu)
            DestroyMenu(hmainmenu);
#endif
        if(htraymenu)
            DestroyMenu(htraymenu);
        ZeroMemory(&nid, sizeof nid);
        nid.cbSize=sizeof nid;
        nid.hWnd=hwnd;
        nid.uID=1;
        nid.uFlags=NIF_TIP; /* not really sure what to put here, but it works */
        Shell_NotifyIcon(NIM_DELETE, &nid); /* this removes the icon */
        PostQuitMessage(0);
        KillTimer(hwnd, 0x29a);
        return TRUE;

    case WM_COMMAND:
        switch(wParam) {
        case IDM_ABOUT:
            DialogBox(ghInst, TEXT("AboutBox"), hwnd, (DLGPROC)about_proc);
            break;
        case IDM_LOG:
            set_visible(!visible);
            break;
        case IDM_CLOSE:
            set_visible(0);
            break;
        case IDM_EXIT:
            DestroyWindow(hwnd);
            break;
        case IDM_SAVEAS:
            save_file(hwnd);
            break;
        case IDM_SETUP:
            MessageBox(hwnd, TEXT("Function not implemented"),
                win32_name, MB_ICONERROR);
            break;
        }
        return TRUE;

    case UWM_SYSTRAY: /* a taskbar event */
        switch (lParam) {
#ifdef _WIN32_WCE
        case WM_LBUTTONDOWN: /* no right mouse button on Windows CE */
            GetWindowRect(GetDesktopWindow(), &rect); /* no cursor position */
            pt.x=rect.right;
            pt.y=rect.bottom-25;
#else
        case WM_RBUTTONDOWN:
            GetCursorPos(&pt);
#endif
            SetForegroundWindow(hwnd);
            TrackPopupMenuEx(hpopup, TPM_BOTTOMALIGN, pt.x, pt.y, hwnd, NULL);
            PostMessage(hwnd, WM_NULL, 0, 0);
            break;
#ifndef _WIN32_WCE
        case WM_LBUTTONDBLCLK: /* switch log window visibility */
            set_visible(!visible);
            break;
#endif
        }
        return TRUE;
    }
    return DefWindowProc(hwnd, message, wParam, lParam);
}

static LRESULT CALLBACK about_proc(HWND hDlg, UINT message,
        WPARAM wParam, LPARAM lParam) {
    switch(message) {
        case WM_INITDIALOG:
            return TRUE;
        case WM_COMMAND:
            switch(wParam) {
                case IDOK:
                case IDCANCEL:
                    EndDialog(hDlg, TRUE);
                    return TRUE;
            }
    }
    return FALSE;
}

static LRESULT CALLBACK pass_proc(HWND hDlg, UINT message,
        WPARAM wParam, LPARAM lParam) {
    TCHAR titlebar[STRLEN];
    WORD cchPassword;
    LPTSTR keyFileName;
    TCHAR sPassword[PEM_BUFSIZE];
    char* cPassword;

    switch (message) {
    case WM_INITDIALOG:
        /* set the default push button to "Cancel." */
        SendMessage(hDlg, DM_SETDEFID, (WPARAM) IDCANCEL, (LPARAM) 0);

        keyFileName = str2tstr(ui_data->section->key);
        _sntprintf(titlebar, STRLEN, TEXT("Private key: %s"),
            keyFileName);
        free(keyFileName);    
        SetWindowText(hDlg, titlebar);
        return TRUE;

    case WM_COMMAND:
        /* set the default push button to "OK" when the user enters text */
        if(HIWORD (wParam) == EN_CHANGE && LOWORD(wParam) == IDE_PASSEDIT)
            SendMessage(hDlg, DM_SETDEFID, (WPARAM) IDOK, (LPARAM) 0);
        switch(wParam) {
        case IDOK:
            /* get number of characters */
            cchPassword=(WORD)SendDlgItemMessage(hDlg,
                IDE_PASSEDIT, EM_LINELENGTH, (WPARAM) 0, (LPARAM) 0);
            if(!cchPassword || cchPassword>=PEM_BUFSIZE) {
                EndDialog(hDlg, FALSE);
                return FALSE;
            }

            /* put the number of characters into first word of buffer */
            *((LPWORD) sPassword)=cchPassword;

            /* get the characters */
            SendDlgItemMessage(hDlg, IDE_PASSEDIT, EM_GETLINE,
                (WPARAM) 0, /* line 0 */ (LPARAM)sPassword);
            sPassword[cchPassword]='\0'; /* null-terminate the string */
            
            /* convert input password to ANSI string (as ui_data->pass) */
            cPassword = tstr2str(sPassword);
            strcpy(ui_data->pass, cPassword);
            free(cPassword);

            EndDialog(hDlg, TRUE);
            return TRUE;

        case IDCANCEL:
            EndDialog(hDlg, FALSE);
            return TRUE;
        }
        return 0;
    }
    return FALSE;

    UNREFERENCED_PARAMETER(lParam);
}

int passwd_cb(char *buf, int size, int rwflag, void *userdata) {
    ui_data=userdata;
    if(!DialogBox(ghInst, TEXT("PassBox"), hwnd, (DLGPROC)pass_proc))
        return 0; /* error */
    strncpy(buf, ui_data->pass, size);
    buf[size-1]='\0';
    return strlen(buf);
}

#ifdef HAVE_OSSL_ENGINE_H
int pin_cb(UI *ui, UI_STRING *uis) {
    ui_data=UI_get_app_data(ui);
    if(!DialogBox(ghInst, TEXT("PassBox"), hwnd, (DLGPROC)pass_proc))
        return 0; /* error */
    UI_set_result(ui, uis, ui_data->pass);
    return 1;
}
#endif

static void save_file(HWND hwnd) {
    TCHAR szFileName[MAX_PATH];
    OPENFILENAME ofn;
    HANDLE hFile;
    BOOL bResult;
    LPTSTR txt;
    LPSTR str;
    DWORD nWritten;

    if(cmdline.service) /* do not allow to save file in the service mode */
        return;

    ZeroMemory(&ofn, sizeof ofn);
    szFileName[0]='\0';

    ofn.lStructSize=sizeof ofn;
    ofn.hwndOwner=hwnd;
    ofn.lpstrFilter=TEXT("Log Files (*.log)\0*.log\0All Files (*.*)\0*.*\0\0");
    ofn.lpstrFile=szFileName;
    ofn.nMaxFile=MAX_PATH;
    ofn.lpstrDefExt=TEXT("LOG");
    ofn.lpstrInitialDir=TEXT(".");

    ofn.lpstrTitle=TEXT("Save Log");
    ofn.Flags=OFN_EXPLORER | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY |
        OFN_OVERWRITEPROMPT;
    if(!GetSaveFileName(&ofn))
        return;

    if((hFile=CreateFile(szFileName, GENERIC_WRITE,
            0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
            (HANDLE) NULL))==INVALID_HANDLE_VALUE) {
        error_box(TEXT("CreateFile"));
        return;
    }

    txt=log_txt();
    str=tstr2str(txt);
    free(txt);
    bResult=WriteFile(hFile, str, strlen(str), &nWritten, NULL);
    free(str);
    if(!bResult)
        error_box(TEXT("WriteFile"));
    CloseHandle(hFile);
}

void win_log(LPSTR line) { /* Also used in log.c */
    struct LIST *curr;
    int len;
    static int log_len=0;
    LPTSTR txt;

    txt=str2tstr(line);
    len=_tcslen(txt);
    curr=malloc(sizeof(struct LIST)+len*sizeof(TCHAR));
    curr->len=len;
    _tcscpy(curr->txt, txt);
    free(txt);
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
        free(curr);
        log_len--;
    }
    leave_critical_section(CRIT_WIN_LOG);

    if(visible) {
        txt=log_txt();
        SetWindowText(EditControl, txt);
        free(txt);
    }
}

static LPTSTR log_txt(void) {
    LPTSTR buff;
    int ptr=0, len=0;
    struct LIST *curr;

    enter_critical_section(CRIT_WIN_LOG);
    for(curr=head; curr; curr=curr->next)
        len+=curr->len+2; /* +2 for trailing '\r\n' */
    buff=malloc((len+1)*sizeof(TCHAR)); /* +1 for trailing '\0' */
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

static void set_visible(int i) {
    LPTSTR txt;

    visible=i; /* setup global variable */
    CheckMenuItem(hpopup, IDM_LOG,
        visible?MF_CHECKED:MF_UNCHECKED); /* check or uncheck menu item */
    if(visible) {
        txt=log_txt();
        SetWindowText(EditControl, txt); /* setup window content */
        free(txt);
        ShowWindow(hwnd, SW_SHOWNORMAL); /* show window */
        SetForegroundWindow(hwnd); /* bring on top */
    } else
        ShowWindow(hwnd, SW_HIDE); /* hide window */
}

void exit_win32(int code) { /* used instead of exit() on Win32 */
    win_log("");
    s_log(LOG_ERR, "Server is down");
    MessageBox(hwnd, TEXT("Stunnel server is down due to an error.\n")
        TEXT("You need to exit and correct the problem.\n")
        TEXT("Click OK to see the error log window."),
        win32_name, MB_ICONERROR);
    error_mode=1;
    longjmp(jump_buf, 1);
}

static void error_box(const LPTSTR text) {
    TCHAR to_print[STRLEN];
    LPTSTR buff;
    long dw;

    dw=GetLastError();
    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM,
        NULL, dw, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR) &buff, 0, NULL);
    _sntprintf(to_print, STRLEN, TEXT("%s: error %ld: %s"), text, dw, buff);
    MessageBox(hwnd, to_print, win32_name, MB_ICONERROR);
    LocalFree(buff);
}

#ifndef _WIN32_WCE

static int service_initialize(void) {
    SERVICE_TABLE_ENTRY serviceTable[]={
        {options.win32_service, service_main},
        {0, 0}
    };

    options.option.taskbar=0; /* disable taskbar for security */
    if(!StartServiceCtrlDispatcher(serviceTable)) {
        error_box(TEXT("StartServiceCtrlDispatcher"));
        return 1;
    }
    return 0; /* NT service started */
}

static int service_install(LPSTR command_line) {
    SC_HANDLE scm, service;
    char exe_file_name[STRLEN], service_path[STRLEN];

    scm=OpenSCManager(0, 0, SC_MANAGER_CREATE_SERVICE);
    if(!scm) {
        error_box(TEXT("OpenSCManager"));
        return 1;
    }
    GetModuleFileName(0, exe_file_name, STRLEN);
    safecopy(service_path, "\"");
    safeconcat(service_path, exe_file_name);
    safeconcat(service_path, "\" -service ");
    safeconcat(service_path, command_line);
    service=CreateService(scm,
        options.win32_service, options.win32_service, SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS,
        SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, service_path,
        NULL, NULL, NULL, NULL, NULL);
    if(!service) {
        error_box(TEXT("CreateService"));
        CloseServiceHandle(scm);
        return 1;
    }
    if(!cmdline.quiet)
        MessageBox(hwnd, TEXT("Service installed"),
            win32_name, MB_ICONINFORMATION);
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return 0;
}

static int service_uninstall(void) {
    SC_HANDLE scm, service;
    SERVICE_STATUS serviceStatus;

    scm=OpenSCManager(0, 0, SC_MANAGER_CONNECT);
    if(!scm) {
        error_box(TEXT("OpenSCManager"));
        return 1;
    }
    service=OpenService(scm, options.win32_service,
        SERVICE_QUERY_STATUS | DELETE);
    if(!service) {
        if(!cmdline.quiet)
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
        MessageBox(hwnd, TEXT("The service is still running"),
            win32_name, MB_ICONERROR);
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
    if(!cmdline.quiet)
        MessageBox(hwnd, TEXT("Service uninstalled"), win32_name,
            MB_ICONINFORMATION);
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return 0;
}

static int service_start(void) {
    SC_HANDLE scm, service;
    SERVICE_STATUS serviceStatus;

    scm=OpenSCManager(0, 0, SC_MANAGER_CONNECT);
    if(!scm) {
        error_box(TEXT("OpenSCManager"));
        return 1;
    }
    service=OpenService(scm, options.win32_service,
        SERVICE_QUERY_STATUS | SERVICE_START);
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
        MessageBox(hwnd, TEXT("Failed to start service"),
            win32_name, MB_ICONERROR);
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return 1;
    }
    if(!cmdline.quiet)
        MessageBox(hwnd, TEXT("Service started"), win32_name,
            MB_ICONINFORMATION);
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return 0;
}

static int service_stop(void) {
    SC_HANDLE scm, service;
    SERVICE_STATUS serviceStatus;

    scm=OpenSCManager(0, 0, SC_MANAGER_CONNECT);
    if(!scm) {
        error_box(TEXT("OpenSCManager"));
        return 1;
    }
    service=OpenService(scm, options.win32_service,
        SERVICE_QUERY_STATUS | SERVICE_STOP);
    if(!service) {
        if(!cmdline.quiet)
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
        if(!cmdline.quiet)
            MessageBox(hwnd, TEXT("The service is already stopped"),
                win32_name, MB_ICONERROR);
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
    if(!cmdline.quiet)
        MessageBox(hwnd, TEXT("Service stopped"), win32_name,
            MB_ICONINFORMATION);
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return 0;
}

static void WINAPI service_main(DWORD argc, LPTSTR* argv) {
    /* initialise service status */
    serviceStatus.dwServiceType=SERVICE_WIN32;
    serviceStatus.dwCurrentState=SERVICE_STOPPED;
    serviceStatus.dwControlsAccepted=0;
    serviceStatus.dwWin32ExitCode=NO_ERROR;
    serviceStatus.dwServiceSpecificExitCode=NO_ERROR;
    serviceStatus.dwCheckPoint=0;
    serviceStatus.dwWaitHint=0;

    serviceStatusHandle=
        RegisterServiceCtrlHandler(options.win32_service, control_handler);

    if(serviceStatusHandle) {
        /* service is starting */
        serviceStatus.dwCurrentState=SERVICE_START_PENDING;
        SetServiceStatus(serviceStatusHandle, &serviceStatus);

        /* running */
        serviceStatus.dwControlsAccepted|=
            (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN);
        serviceStatus.dwCurrentState=SERVICE_RUNNING;
        SetServiceStatus(serviceStatusHandle, &serviceStatus);

        win_main(ghInst, NULL, "", 0);

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
    switch (controlCode) {
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

/* End of gui.c */
