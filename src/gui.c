/*
 *   stunnel       Universal SSL tunnel
 *   Copyright (c) 1998-2002 Michal Trojnara <Michal.Trojnara@mirt.net>
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

#define UWM_SYSTRAY (WM_USER + 1) /* sent to us by the systray */
#define LOG_LINES 250
#if 0
#define PROGRAM_NAME "SecureMAX 1.0"
#define VERSION_TEXT PROGRAM_NAME " x86 by Mobi-Com Polska on WIN32"
#else
#define PROGRAM_NAME "stunnel " VERSION
#define VERSION_TEXT PROGRAM_NAME " on WIN32"
#endif

HMENU hpopup;
HWND hwnd=NULL;

LRESULT CALLBACK wndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);
DWORD WINAPI ThreadFunc(LPVOID);
int unix_main(int, char *[]);

int win_main(HINSTANCE, HINSTANCE, LPSTR, int);
void save_file(HWND);
char *log_txt();
void set_visible(int);
void WINAPI service_main(DWORD, LPTSTR *);
int install_service();
int uninstall_service();

static struct LIST {
  struct LIST *next;
  int len;
  char txt[1]; /* single character for "\0" */
} *head=NULL, *tail=NULL;
static HINSTANCE ghInst;
static HWND EditControl=NULL;
static HMENU htraymenu, hmainmenu;

static char service_path[MAX_PATH];
static SERVICE_STATUS serviceStatus;
static SERVICE_STATUS_HANDLE serviceStatusHandle=0;
static HANDLE stopServiceEvent=0;

static int visible=0, error_mode=0;
static jmp_buf jump_buf;

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
    LPSTR lpszCmdLine, int nCmdShow) {

    SERVICE_TABLE_ENTRY serviceTable[]={
        {PROGRAM_NAME, service_main},
        {0, 0}
    };
    char exe_file_name[MAX_PATH], dir[MAX_PATH], *ptr;

    ghInst=hInstance;

    GetModuleFileName(0, exe_file_name, MAX_PATH);

    /* set current directory */
    strcpy(dir, exe_file_name);
    ptr=strrchr(dir, '\\'); /* last backslash */
    if(ptr)
        ptr[1]='\0'; /* truncate program name */
    if(!SetCurrentDirectory(dir)) {
        MessageBox(hwnd, "Cannot set current directory",
            PROGRAM_NAME, MB_ICONERROR);
        return 1;
    }

    if(!strcmpi(lpszCmdLine, "-service")) {
        if(!StartServiceCtrlDispatcher(serviceTable)) {
            MessageBox(hwnd, "Unable to start the service",
                PROGRAM_NAME, MB_ICONERROR);
            return 1;
        }
        return 0; /* NT service started */
    }

    /* setup service_path for CreateService() */
    strcpy(service_path, "\"");
    strcat(service_path, exe_file_name);
    strcat(service_path, "\" -service");
    /* strcat(service_path, lpszCmdLine); */

    if(!strcmpi(lpszCmdLine, "-install"))
        return install_service();
    if(!strcmpi(lpszCmdLine, "-uninstall"))
        return uninstall_service();
    return win_main(hInstance, hPrevInstance, lpszCmdLine, nCmdShow);
}


int win_main(HINSTANCE hInstance, HINSTANCE hPrevInstance,
        LPSTR lpszCmdLine, int nCmdShow) {
    WNDCLASSEX wc;
    MSG msg;
    char *classname=PROGRAM_NAME;
    DWORD iID;
    RECT rect;
    static struct WSAData wsa_state;

    if(WSAStartup(0x0101, &wsa_state)) {
        win_log("Failed to initialize winsock");
        error_mode=1;
    } else if(!setjmp(jump_buf)) {
        main_initialize(lpszCmdLine[0] ? lpszCmdLine : NULL);
    }

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
    wc.hIconSm=LoadImage(hInstance, MAKEINTRESOURCE(IDI_MYICON), IMAGE_ICON,
        GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), 0);
    RegisterClassEx(&wc);

    /* create main window */
    htraymenu=LoadMenu(ghInst, MAKEINTRESOURCE(IDM_TRAYMENU));
    hpopup=GetSubMenu(htraymenu, 0);
    hmainmenu=LoadMenu(ghInst, MAKEINTRESOURCE(IDM_MAINMENU));
    hwnd=CreateWindow(classname, VERSION_TEXT, WS_TILEDWINDOW,
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

static void update_systray() { /* create the systray icon */
    NOTIFYICONDATA nid;
    extern int num_clients; /* defined in stunnel.c */

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
        return; /* OK: systray icon exists */

    /* trying to update tooltip failed - lets try to create the icon */
    nid.uFlags=NIF_MESSAGE | NIF_ICON | NIF_TIP;
    nid.uCallbackMessage=UWM_SYSTRAY;
    nid.hIcon=LoadImage(ghInst, MAKEINTRESOURCE(IDI_MYICON), IMAGE_ICON,
        GetSystemMetrics(SM_CXSMICON),
        GetSystemMetrics(SM_CYSMICON), 0); /* 16x16 icon */
    Shell_NotifyIcon(NIM_ADD, &nid); /* this adds the icon */
}

DWORD WINAPI ThreadFunc(LPVOID arg) {
    if(!setjmp(jump_buf))
        main_execute();
    else
        set_visible(1); /* could be unsafe to call it from another thread */
    return 0;
}

LRESULT CALLBACK wndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    POINT pt;
    NOTIFYICONDATA nid;
    RECT rect;

#if 0
    if(message!=WM_CTLCOLORSTATIC && message!=WM_TIMER)
        log(LOG_DEBUG, "Window message: %d", message);
#endif
    switch (message) {
    case WM_CREATE:
        SetTimer(hwnd, 0x29a, 1000, NULL); /* 1-second timer */
        return TRUE;

    case WM_SIZE:
        GetClientRect(hwnd, &rect);
        MoveWindow(EditControl, 0, 0, rect.right, rect.bottom, TRUE);
        UpdateWindow(EditControl);
        return TRUE;

    case WM_SETFOCUS:
        SetWindowText(EditControl, log_txt());
        SetFocus(EditControl);
        return TRUE;

    case WM_TIMER:
        update_systray();
        return TRUE;

    case WM_CLOSE:
        set_visible(0);
        return TRUE;

    case WM_DESTROY:
        DestroyMenu(hmainmenu);
        DestroyMenu(htraymenu);
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
            MessageBox(hwnd, VERSION_TEXT,
                "About " PROGRAM_NAME, MB_ICONINFORMATION);
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
                PROGRAM_NAME, MB_ICONERROR);
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


void save_file(HWND hwnd) {
    char szFileName[MAX_PATH];
    OPENFILENAME ofn;
    HANDLE hFile;
    BOOL bResult;
    char *txt;
    DWORD nToWrite, nWritten;

    txt=log_txt();
    nToWrite=strlen(txt);

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
        MessageBox(hwnd, "File open failed", PROGRAM_NAME, MB_ICONERROR);
        return; 
    }

    bResult=WriteFile(hFile, txt, nToWrite, &nWritten, NULL);
    if(!bResult)
        MessageBox(hwnd, "File write failed", PROGRAM_NAME, MB_ICONERROR);
    CloseHandle(hFile);
}

void win_log(char *txt) {
    struct LIST *curr;
    int len;
    static int log_len=0;

    len=strlen(txt);
    curr=malloc(sizeof(struct LIST)+len);
    curr->len=len;
    strcpy(curr->txt, txt);
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

    if(visible)
        SetWindowText(EditControl, log_txt());
}

char *log_txt() {
    static char buff[65536];
    int len;
    struct LIST *curr;
 
    len=0;

    enter_critical_section(CRIT_WIN_LOG);
    for(curr=head; curr; curr=curr->next) {
        memcpy(buff+len, curr->txt, curr->len);
        len+=curr->len;
        if(curr->next) {
            buff[len++]='\r';
            buff[len++]='\n';
        }
    }
    leave_critical_section(CRIT_WIN_LOG);

    buff[len]='\0';
    return buff;
}

void set_visible(int i) {
    visible=i; /* setup global variable */
    CheckMenuItem(hpopup, GetMenuItemID(hpopup, 1),
        visible?MF_CHECKED:MF_UNCHECKED); /* check or uncheck menu item */
    if(visible) {
        SetWindowText(EditControl, log_txt()); /* setup window content */
        ShowWindow(hwnd, SW_SHOWNORMAL); /* show window */
        SetForegroundWindow(hwnd); /* bring on top */
    } else
        ShowWindow(hwnd, SW_HIDE); /* hide window */
}

void exit_stunnel(int code) {
    win_log("");
    win_log("Server is down");
    error_mode=1;
    longjmp(jump_buf, 1);
}

void WINAPI control_handler(DWORD controlCode) {
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

void WINAPI service_main(DWORD argc, LPTSTR* argv) {
    /* initialise service status */
    serviceStatus.dwServiceType=SERVICE_WIN32;
    serviceStatus.dwCurrentState=SERVICE_STOPPED;
    serviceStatus.dwControlsAccepted=0;
    serviceStatus.dwWin32ExitCode=NO_ERROR;
    serviceStatus.dwServiceSpecificExitCode=NO_ERROR;
    serviceStatus.dwCheckPoint=0;
    serviceStatus.dwWaitHint=0;

    serviceStatusHandle=
        RegisterServiceCtrlHandler(PROGRAM_NAME, control_handler);

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

int install_service() {
    SC_HANDLE scm, service;
    
    scm=OpenSCManager(0, 0, SC_MANAGER_CREATE_SERVICE);
    if(!scm) {
        MessageBox(hwnd, "Failed to open service control manager",
            PROGRAM_NAME, MB_ICONERROR);
        return 1;
    }
    service=CreateService(scm,
        PROGRAM_NAME, PROGRAM_NAME, SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS,
        SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, service_path,
        NULL, NULL, NULL, NULL, NULL);
    if(!service) {
        MessageBox(hwnd, "Failed to create a new service",
            PROGRAM_NAME, MB_ICONERROR);
        CloseServiceHandle(scm);
        return 1;
    }
    MessageBox(hwnd, "Service installed", PROGRAM_NAME, MB_ICONINFORMATION);
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return 0;
}

int uninstall_service() {
    SC_HANDLE scm, service;
    SERVICE_STATUS serviceStatus;
    
    scm=OpenSCManager(0, 0, SC_MANAGER_CONNECT);
    if(!scm) {
        MessageBox(hwnd, "Failed to open service control manager",
            PROGRAM_NAME, MB_ICONERROR);
        return 1;
    }
    service=OpenService(scm, PROGRAM_NAME, SERVICE_QUERY_STATUS | DELETE);
    if(!service) {
        MessageBox(hwnd, "Failed to open the service",
            PROGRAM_NAME, MB_ICONERROR);
        CloseServiceHandle(scm);
        return 1;
    }
    if(!QueryServiceStatus(service, &serviceStatus)) {
        MessageBox(hwnd, "Failed to query service status",
            PROGRAM_NAME, MB_ICONERROR);
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return 1;
    }
    if(serviceStatus.dwCurrentState!=SERVICE_STOPPED) {
        MessageBox(hwnd, "The service is still running",
            PROGRAM_NAME, MB_ICONERROR);
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return 1;
    }
    if(!DeleteService(service)) {
        MessageBox(hwnd, "Failed to delete the service",
            PROGRAM_NAME, MB_ICONERROR);
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return 1;
    }
    MessageBox(hwnd, "Service uninstalled", PROGRAM_NAME, MB_ICONINFORMATION);
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return 0;
}

/* End of gui.c */
