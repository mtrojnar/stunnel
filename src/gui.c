/*
 *   stunnel       Universal SSL tunnel
 *   Copyright (c) 1998-2004 Michal Trojnara <Michal.Trojnara@mirt.net>
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
#include <setjmp.h>
#include <windows.h>
#include <windowsx.h>
#include <shellapi.h>
#include "resources.h"

#define UWM_SYSTRAY (WM_USER + 1) /* sent to us by the taskbar */
#define LOG_LINES 250

/* Externals */
int unix_main(int, char *[]);

/* Prototypes */
static DWORD WINAPI ThreadFunc(LPVOID);
static LRESULT CALLBACK wndProc(HWND, UINT, WPARAM, LPARAM);

static int win_main(HINSTANCE, HINSTANCE, LPSTR, int);
static void save_file(HWND);
static LRESULT CALLBACK about_proc(HWND, UINT, WPARAM, LPARAM);
static LRESULT CALLBACK pass_proc(HWND, UINT, WPARAM, LPARAM);
static char *log_txt(void);
static void set_visible(int);

/* NT Service related function */
static int start_service(void);
static int install_service(void);
static int uninstall_service(void);
static void WINAPI service_main(DWORD, LPTSTR *);
static void WINAPI control_handler(DWORD);

/* Global variables */
static struct LIST {
  struct LIST *next;
  int len;
  char txt[1]; /* single character for trailing '\0' */
} *head=NULL, *tail=NULL;
static HINSTANCE ghInst;
static HWND EditControl=NULL;
static HMENU htraymenu, hmainmenu;
static HMENU hpopup;
static HWND hwnd=NULL;
static HANDLE small_icon; /* 16x16 icon */

static char service_path[MAX_PATH];
static SERVICE_STATUS serviceStatus;
static SERVICE_STATUS_HANDLE serviceStatusHandle=0;
static HANDLE stopServiceEvent=0;

static int visible=0, error_mode=0;
static jmp_buf jump_buf;

static char passphrase[STRLEN];

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
    LPSTR lpszCmdLine, int nCmdShow) {

    char exe_file_name[MAX_PATH], dir[MAX_PATH], *ptr;
    static struct WSAData wsa_state;

    ghInst=hInstance;

    GetModuleFileName(0, exe_file_name, MAX_PATH);

    /* set current directory */
    strcpy(dir, exe_file_name);
    ptr=strrchr(dir, '\\'); /* last backslash */
    if(ptr)
        ptr[1]='\0'; /* truncate program name */
    if(!SetCurrentDirectory(dir)) {
        MessageBox(hwnd, "Cannot set current directory",
            options.win32_name, MB_ICONERROR);
        return 1;
    }

    /* setup service_path for CreateService() */
    strcpy(service_path, "\"");
    strcat(service_path, exe_file_name);
    strcat(service_path, "\" -service");
    /* strcat(service_path, lpszCmdLine); */

    if(WSAStartup(0x0101, &wsa_state)) {
        win_log("Failed to initialize winsock");
        error_mode=1;
    }

    if(!strcmpi(lpszCmdLine, "-service")) {
        if(!setjmp(jump_buf))
            main_initialize(NULL, NULL);
        return start_service(); /* Always start service with -service option */
    }

    if(!error_mode && !setjmp(jump_buf)) { /* TRY */
        if(!strcmpi(lpszCmdLine, "-install")) {
            main_initialize(NULL, NULL);
            return install_service();
        } else if(!strcmpi(lpszCmdLine, "-uninstall")) {
            main_initialize(NULL, NULL);
            return uninstall_service();
        } else { /* not -service, -install or -uninstall */
            main_initialize(lpszCmdLine[0] ? lpszCmdLine : NULL, NULL);
        }
    }

    /* CATCH */
    return win_main(hInstance, hPrevInstance, lpszCmdLine, nCmdShow);
}

static int win_main(HINSTANCE hInstance, HINSTANCE hPrevInstance,
        LPSTR lpszCmdLine, int nCmdShow) {
    WNDCLASSEX wc;
    MSG msg;
    char *classname=options.win32_name;
    DWORD iID;
    RECT rect;

    /* register the class */
    wc.cbSize=sizeof(WNDCLASSEX);
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
    wc.hIconSm=small_icon; /* 16x16 icon */
    RegisterClassEx(&wc);

    /* create main window */
    if(options.option.taskbar) {/* save menu resources */
        htraymenu=LoadMenu(ghInst, MAKEINTRESOURCE(IDM_TRAYMENU));
        hpopup=GetSubMenu(htraymenu, 0);
    }
    hmainmenu=LoadMenu(ghInst, MAKEINTRESOURCE(IDM_MAINMENU));
    hwnd=CreateWindow(classname, options.win32_name, WS_TILEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
        NULL, hmainmenu, hInstance, NULL);

    /* create child edit window */
    EditControl=CreateWindow ("EDIT", NULL,
        WS_CHILD|WS_VISIBLE|WS_HSCROLL|WS_VSCROLL|ES_MULTILINE|ES_READONLY,
        0, 0, 0, 0, hwnd, NULL, hInstance, NULL);
    SendMessage(EditControl, WM_SETFONT, (WPARAM)GetStockObject(OEM_FIXED_FONT),
        MAKELPARAM(FALSE, 0)); /* no need to redraw right, now */
    GetClientRect(hwnd, &rect);
    MoveWindow(EditControl, 0, 0, rect.right, rect.bottom, TRUE);
    SetFocus(EditControl);

    if(error_mode) /* log window is hidden by default */
        set_visible(1);
    else /* create the main thread */
        CloseHandle(CreateThread(NULL, 0, ThreadFunc, NULL, 0, &iID));

    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return msg.wParam;
}

static void update_taskbar(void) { /* create the taskbar icon */
    NOTIFYICONDATA nid;

    ZeroMemory(&nid, sizeof(nid));
    nid.cbSize=sizeof(NOTIFYICONDATA); /* size */
    nid.hWnd=hwnd; /* window to receive notifications */
    nid.uID=1;     /* application-defined ID for icon */
    if(error_mode)
        strcpy(nid.szTip, "Server is down");
    else
        sprintf(nid.szTip, "%d session(s) active", num_clients);
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

static DWORD WINAPI ThreadFunc(LPVOID arg) {
    if(!setjmp(jump_buf))
        main_execute();
    else
        set_visible(1); /* could be unsafe to call it from another thread */
    return 0;
}

static LRESULT CALLBACK wndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    POINT pt;
    NOTIFYICONDATA nid;
    RECT rect;
    char *txt;

#if 0
    if(message!=WM_CTLCOLORSTATIC && message!=WM_TIMER)
        log(LOG_DEBUG, "Window message: %d", message);
#endif
    switch (message) {
    case WM_CREATE:
        if (options.option.taskbar) /* taskbar update enabled? */
            SetTimer(hwnd, 0x29a, 1000, NULL); /* 1-second timer */
        return TRUE;

    case WM_SIZE:
        GetClientRect(hwnd, &rect);
        MoveWindow(EditControl, 0, 0, rect.right, rect.bottom, TRUE);
        UpdateWindow(EditControl);
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
        DestroyMenu(hmainmenu);
        DestroyMenu(htraymenu);
        ZeroMemory(&nid, sizeof(nid));
        nid.cbSize=sizeof(NOTIFYICONDATA);
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
            DialogBox(ghInst, "AboutBox", hwnd, (DLGPROC)about_proc);
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
            MessageBox(hwnd, "Function not implemented",
                options.win32_name, MB_ICONERROR);
            break;
        };
        return TRUE;

    case UWM_SYSTRAY:
        switch (lParam) {
        case WM_RBUTTONUP: /* track a popup menu */
            /* http://support.microsoft.com/support/kb/articles/Q135/7/88.asp */
            GetCursorPos(&pt);
            SetForegroundWindow(hwnd);
            TrackPopupMenu(hpopup, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, NULL);
            PostMessage(hwnd, WM_NULL, 0, 0); /* see above */
            break;
        case WM_LBUTTONDBLCLK: /* switch log window visibility */
            set_visible(!visible);
            break;
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
    char titlebar[STRLEN];
    WORD cchPassword;

    switch (message) {
    case WM_INITDIALOG:
        /* Set the default push button to "Cancel." */
        SendMessage(hDlg, DM_SETDEFID, (WPARAM) IDCANCEL, (LPARAM) 0);

        safecopy(titlebar, "Private key: ");
        safeconcat(titlebar, options.key);
        SetWindowText(hDlg, titlebar);
        return TRUE;

    case WM_COMMAND:
        /* Set the default push button to "OK" when the user enters text. */
        if(HIWORD (wParam) == EN_CHANGE && LOWORD(wParam) == IDE_PASSWORDEDIT)
            SendMessage(hDlg, DM_SETDEFID, (WPARAM) IDOK, (LPARAM) 0);
        switch(wParam) {
        case IDOK:
            /* Get number of characters. */
            cchPassword = (WORD) SendDlgItemMessage(hDlg,
                IDE_PASSWORDEDIT, EM_LINELENGTH, (WPARAM) 0, (LPARAM) 0);
            if(cchPassword==0 || cchPassword>=STRLEN) {
                EndDialog(hDlg, FALSE);
                return FALSE;
            }

            /* Put the number of characters into first word of buffer. */
            *((LPWORD)passphrase) = cchPassword;

            /* Get the characters. */
            SendDlgItemMessage(hDlg, IDE_PASSWORDEDIT, EM_GETLINE,
                (WPARAM) 0, /* line 0 */ (LPARAM) passphrase);

            passphrase[cchPassword] = 0; /* Null-terminate the string. */
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

int pem_passwd_cb(char *buf, int size, int rwflag, void *userdata) {
    int result;
#if 0
    DWORD dwThreadId;
    HWINSTA hwinstaSave;
    HDESK hdeskSave;
    HWINSTA hwinstaUser;
    HDESK hdeskUser;

    buf[0]='\0'; /* empty the buffer */

    /* Save the window station and desktop */
    hwinstaSave=GetProcessWindowStation();
    if(!hwinstaSave)
        ioerror("GetProcessWindowStation");
    dwThreadId=GetCurrentThreadId();
    if(!dwThreadId)
        ioerror("GetCurrentThreadId");
    hdeskSave=GetThreadDesktop(dwThreadId);
    if(!hdeskSave)
        ioerror("GetThreadDesktop");

    /* Switch to WinSta0/Default */
    hwinstaUser=OpenWindowStation("winsta0", FALSE, MAXIMUM_ALLOWED);
    if(!hwinstaUser)
        ioerror("OpenWindowStation");
    if(!SetProcessWindowStation(hwinstaUser))
        ioerror("SetProcessWindowStation");
    hdeskUser=OpenDesktop("Default", 0, FALSE, MAXIMUM_ALLOWED); /* Winlogon */
    if(!hdeskUser)
        ioerror("OpenDesktop");
    if(!SetThreadDesktop(hdeskUser))
        ioerror("SetThreadDesktop");
#endif

    /* Display the dialog box */
    result=DialogBox(ghInst, "PassBox", hwnd, (DLGPROC)pass_proc);

#if 0
    /* Restore window station and desktop */
    if(!SetThreadDesktop(hdeskSave))
        ioerror("SetThreadDesktop");
    if(!SetProcessWindowStation(hwinstaSave))
        ioerror("SetProcessWindowStation");
    if(!CloseDesktop(hdeskUser))
        ioerror("CloseDesktop");
    if(!CloseWindowStation(hwinstaUser))
        ioerror("CloseWindowStation");
#endif

    if(!result)
        return 0;
    strncpy(buf, passphrase, size);
    buf[size - 1] = '\0';
    return strlen(buf);
}

static void save_file(HWND hwnd) {
    char szFileName[MAX_PATH];
    OPENFILENAME ofn;
    HANDLE hFile;
    BOOL bResult;
    char *txt;
    DWORD nToWrite, nWritten;

    ZeroMemory(&ofn, sizeof(ofn));
    szFileName[0]='\0';

    ofn.lStructSize=sizeof(ofn);
    ofn.hwndOwner=hwnd;
    ofn.lpstrFilter="Log Files (*.log)\0*.log\0All Files (*.*)\0*.*\0\0";
    ofn.lpstrFile=szFileName;
    ofn.nMaxFile=MAX_PATH;
    ofn.lpstrDefExt="LOG";
    ofn.lpstrInitialDir=".";

    ofn.lpstrTitle="Save Log";
    ofn.Flags=OFN_EXPLORER | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY |
        OFN_OVERWRITEPROMPT;
    if(!GetSaveFileName(&ofn))
        return;

    if((hFile=CreateFile((LPCSTR)szFileName, GENERIC_WRITE,
            0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
            (HANDLE) NULL))==INVALID_HANDLE_VALUE) {
        MessageBox(hwnd, "File open failed", options.win32_name, MB_ICONERROR);
        return;
    }

    txt=log_txt();
    nToWrite=strlen(txt);
    bResult=WriteFile(hFile, txt, nToWrite, &nWritten, NULL);
    free(txt);
    if(!bResult)
        MessageBox(hwnd, "File write failed", options.win32_name, MB_ICONERROR);
    CloseHandle(hFile);
}

void win_log(char *line) { /* Also used in log.c */
    struct LIST *curr;
    int len;
    static int log_len=0;
    char *txt;

    len=strlen(line);
    curr=malloc(sizeof(struct LIST)+len);
    curr->len=len;
    strcpy(curr->txt, line);
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

static char *log_txt(void) {
    char *buff;
    int ptr=0, len=0;
    struct LIST *curr;

    enter_critical_section(CRIT_WIN_LOG);
    for(curr=head; curr; curr=curr->next)
        len+=curr->len+2; /* +2 for trailing '\r\n' */
    buff=malloc(len+1); /* +1 for trailing '\0' */
    for(curr=head; curr; curr=curr->next) {
        memcpy(buff+ptr, curr->txt, curr->len);
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
    char *txt;

    visible=i; /* setup global variable */
    CheckMenuItem(hpopup, GetMenuItemID(hpopup, 1),
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

void exit_stunnel(int code) { /* used instead of exit() on Win32 */
    win_log("");
    log(LOG_ERR, "Server is down");
    MessageBox(hwnd, "Stunnel server is down due to an error.\n"
        "You need to exit and correct the problem.\n"
        "Click OK to see the error log window.",
        options.win32_service, MB_ICONERROR);
    error_mode=1;
    longjmp(jump_buf, 1);
}

static int start_service(void) {
    SERVICE_TABLE_ENTRY serviceTable[]={
        {options.win32_service, service_main},
        {0, 0}
    };

    if(!StartServiceCtrlDispatcher(serviceTable)) {
        MessageBox(hwnd, "Unable to start the service",
            options.win32_service, MB_ICONERROR);
        return 1;
    }
    return 0; /* NT service started */
}

static int install_service(void) {
    SC_HANDLE scm, service;

    scm=OpenSCManager(0, 0, SC_MANAGER_CREATE_SERVICE);
    if(!scm) {
        MessageBox(hwnd, "Failed to open service control manager",
            options.win32_service, MB_ICONERROR);
        return 1;
    }
    service=CreateService(scm,
        options.win32_service, options.win32_service, SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS,
        SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, service_path,
        NULL, NULL, NULL, NULL, NULL);
    if(!service) {
        MessageBox(hwnd, "Failed to create a new service",
            options.win32_service, MB_ICONERROR);
        CloseServiceHandle(scm);
        return 1;
    }
    MessageBox(hwnd, "Service installed", options.win32_service,
        MB_ICONINFORMATION);
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return 0;
}

static int uninstall_service(void) {
    SC_HANDLE scm, service;
    SERVICE_STATUS serviceStatus;

    scm=OpenSCManager(0, 0, SC_MANAGER_CONNECT);
    if(!scm) {
        MessageBox(hwnd, "Failed to open service control manager",
            options.win32_service, MB_ICONERROR);
        return 1;
    }
    service=OpenService(scm, options.win32_service,
        SERVICE_QUERY_STATUS | DELETE);
    if(!service) {
        MessageBox(hwnd, "Failed to open the service",
            options.win32_service, MB_ICONERROR);
        CloseServiceHandle(scm);
        return 1;
    }
    if(!QueryServiceStatus(service, &serviceStatus)) {
        MessageBox(hwnd, "Failed to query service status",
            options.win32_service, MB_ICONERROR);
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return 1;
    }
    if(serviceStatus.dwCurrentState!=SERVICE_STOPPED) {
        MessageBox(hwnd, "The service is still running",
            options.win32_service, MB_ICONERROR);
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return 1;
    }
    if(!DeleteService(service)) {
        MessageBox(hwnd, "Failed to delete the service",
            options.win32_service, MB_ICONERROR);
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return 1;
    }
    MessageBox(hwnd, "Service uninstalled", options.win32_service,
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

        /* do initialisation here */
        stopServiceEvent=CreateEvent(0, FALSE, FALSE, 0);

        /* running */
        serviceStatus.dwControlsAccepted|=
            (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN);
        serviceStatus.dwCurrentState=SERVICE_RUNNING;
        SetServiceStatus(serviceStatusHandle, &serviceStatus);

        win_main(ghInst, NULL, "", 0);

        /* service was stopped */
        serviceStatus.dwCurrentState=SERVICE_STOP_PENDING;
        SetServiceStatus(serviceStatusHandle, &serviceStatus);

        /* do cleanup here */
        CloseHandle(stopServiceEvent);
        stopServiceEvent=0;

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
        SetEvent(stopServiceEvent);
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

/* End of gui.c */
