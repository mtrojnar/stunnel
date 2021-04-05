# NSIS stunnel installer by Michal Trojnara 1998-2021

!define /ifndef VERSION testing
!define /ifndef ARCH win32

!define REGKEY_INSTALL "Software\NSIS_stunnel"
!define REGKEY_UNINST \
  "Software\Microsoft\Windows\CurrentVersion\Uninstall\stunnel"
!define SHORTCUTS "stunnel $MultiUser.InstallMode"

SetCompressor /SOLID LZMA
Name "stunnel ${VERSION}"
OutFile "stunnel-${VERSION}-${ARCH}-installer.exe"
BrandingText "Author: Michal Trojnara"

# MultiUser
!define MULTIUSER_EXECUTIONLEVEL Highest
!define MULTIUSER_MUI
!define MULTIUSER_INSTALLMODE_COMMANDLINE
!define MULTIUSER_INSTALLMODE_INSTDIR "stunnel"
!define MULTIUSER_INSTALLMODE_INSTDIR_REGISTRY_KEY "${REGKEY_INSTALL}"
!define MULTIUSER_INSTALLMODE_INSTDIR_REGISTRY_VALUENAME "Install_Dir"
!define MULTIUSER_INSTALLMODE_DEFAULT_REGISTRY_KEY "${REGKEY_INSTALL}"
!define MULTIUSER_INSTALLMODE_DEFAULT_REGISTRY_VALUENAME "Install_Mode"
!include MultiUser.nsh
# Modern UI
!define MUI_FINISHPAGE_RUN "$INSTDIR\bin\stunnel.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Start stunnel after installation"
!define MUI_FINISHPAGE_RUN_NOTCHECKED
!include "MUI2.nsh"
# define SF_SELECTED
!include "Sections.nsh"

!define /ifndef ROOT_DIR \devel

!define /ifndef STUNNEL_DIR ${ROOT_DIR}\src\stunnel
!define /ifndef STUNNEL_TOOLS_DIR ${STUNNEL_DIR}\tools
!define /ifndef STUNNEL_SRC_DIR ${STUNNEL_DIR}\src

!define /ifndef DEST_DIR ${STUNNEL_DIR}
!define /ifndef STUNNEL_BIN_DIR ${DEST_DIR}\bin\${ARCH}
!define /ifndef STUNNEL_DOC_DIR ${DEST_DIR}\doc

!define /ifndef BIN_DIR ${ROOT_DIR}\${ARCH}
!define /ifndef OPENSSL_DIR ${BIN_DIR}\openssl
!define /ifndef OPENSSL_BIN_DIR ${OPENSSL_DIR}\bin
!define /ifndef OPENSSL_ENGINES_DIR ${OPENSSL_DIR}\lib\engines-1_1
!define /ifndef ZLIB_DIR ${BIN_DIR}\zlib
!define /ifndef REDIST_DIR ${BIN_DIR}\redist

# additional plugins
!addplugindir "${STUNNEL_TOOLS_DIR}/plugins/SimpleFC"
!addplugindir "${STUNNEL_TOOLS_DIR}/plugins/ShellLink/Plugins"

!define MUI_ICON ${STUNNEL_SRC_DIR}\stunnel.ico

!insertmacro MUI_PAGE_LICENSE "${STUNNEL_TOOLS_DIR}\stunnel.license"
!insertmacro MULTIUSER_PAGE_INSTALLMODE
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

!macro MoveFiles src dst pattern
FindFirst $0 $1 "${src}\${pattern}"
  !define MoveFilesId ${__LINE__}
loop_${MoveFilesId}:
  StrCmp $1 "" done_${MoveFilesId}
  Rename "${src}\$1" "${dst}\$1"
  FindNext $0 $1
  Goto loop_${MoveFilesId}
done_${MoveFilesId}:
  FindClose $0
  !undef MoveFilesId
!macroend

!macro DetailError message
  # pop the error and log the failure
  !define DetailErrorId ${__LINE__}
  Pop $0 # returns error(-1)/success(0)
  IntCmp $0 0 done_${DetailErrorId}
  DetailPrint "${message}"
done_${DetailErrorId}:
  !undef DetailErrorId
!macroend

!macro SetRunAsAdmin path
  # run the link as administrator if InstallMode is AllUsers
  !define SetRunAsAdminId ${__LINE__}
  StrCmp $MultiUser.InstallMode "CurrentUser" done_${SetRunAsAdminId}
  ShellLink::SetRunAsAdministrator "$SMPROGRAMS\${SHORTCUTS}\${path}.lnk"
  !insertmacro DetailError "ShellLink::SetRunAsAdministrator failed for ${path}"
done_${SetRunAsAdminId}:
  !undef SetRunAsAdminId
!macroend

Var /GLOBAL gui_restart
Var /GLOBAL service_restart
Var /GLOBAL service_reinstall
Var /GLOBAL exe

!macro TerminateStunnel
  # initialize with nonzero values: do not restart/reinstall
  StrCpy $service_restart 1
  StrCpy $service_reinstall 1
  # find the old stunnel executable
  StrCpy $exe "$INSTDIR\bin\stunnel.exe"
  IfFileExists "$exe" found
  StrCpy $exe "$INSTDIR\stunnel.exe"
  IfFileExists "$exe" found done
found:
  # exit the stunnel GUI
  ExecWait '"$exe" -exit -quiet' $gui_restart
  # stop and uninstall the stunnel service
  # setup $service_restart and $service_reinstall
  StrCmp $MultiUser.InstallMode "CurrentUser" done
  ClearErrors
  ReadRegStr $R0 HKLM \
    "Software\Microsoft\Windows NT\CurrentVersion" CurrentVersion
  IfErrors done
  ExecWait '"$exe" -stop -quiet' $service_restart
  IntCmp $service_restart 0 0 not_stopped not_stopped
  DetailPrint "Service stopped"
not_stopped:
  StrCmp "$exe" "$INSTDIR\bin\stunnel.exe" done # no need to uninstall
  ExecWait '"$exe" -uninstall -quiet' $service_reinstall
  IntCmp $service_reinstall 0 0 done done
  DetailPrint "Service uninstalled"
done:
!macroend

!macro RestartStunnel
  # install the service if $service_reinstall is 0
  IntCmp $service_reinstall 0 0 no_service_reinstall no_service_reinstall
  ExecWait '"$INSTDIR\bin\stunnel.exe" -install -quiet' $service_reinstall
  IntCmp $service_reinstall 0 0 no_service_reinstall no_service_reinstall
  DetailPrint "Service installed"
no_service_reinstall:
  # start the service if $service_restart is 0
  IntCmp $service_restart 0 0 no_service_restart no_service_restart
  ExecWait '"$INSTDIR\bin\stunnel.exe" -start -quiet' $service_restart
  IntCmp $service_restart 0 0 no_service_restart no_service_restart
  DetailPrint "Service started"
no_service_restart:
  # start the gui if $gui_restart is 0
  # it does not work against stunnel older than 5.23 due to a bug
  #   IntCmp $gui_restart 0 0 no_gui_restart no_gui_restart
  #   Exec '"$INSTDIR\bin\stunnel.exe"'
  # no_gui_restart:
!macroend

!macro CleanupStunnelFiles
  # current versions
  Delete "$INSTDIR\config\openssl.cnf"

  Delete "$INSTDIR\bin\stunnel.exe"
  Delete "$INSTDIR\bin\stunnel.pdb"
  Delete "$INSTDIR\bin\tstunnel.exe"
  Delete "$INSTDIR\bin\tstunnel.pdb"
  Delete "$INSTDIR\bin\openssl.exe"
  Delete "$INSTDIR\bin\openssl.pdb"
  Delete "$INSTDIR\bin\libeay32.dll"
  Delete "$INSTDIR\bin\libeay32.pdb"
  Delete "$INSTDIR\bin\ssleay32.dll"
  Delete "$INSTDIR\bin\ssleay32.pdb"
  Delete "$INSTDIR\bin\zlib1.dll"
  Delete "$INSTDIR\bin\zlib1.pdb"
  Delete "$INSTDIR\bin\msvcr90.dll"
  Delete "$INSTDIR\bin\Microsoft.VC90.CRT.Manifest"
  Delete "$INSTDIR\bin\libcrypto-1_1-x64.dll"
  Delete "$INSTDIR\bin\libcrypto-1_1-x64.pdb"
  Delete "$INSTDIR\bin\libssl-1_1-x64.dll"
  Delete "$INSTDIR\bin\libssl-1_1-x64.pdb"
  Delete "$INSTDIR\bin\vcruntime140.dll"
  Delete "$INSTDIR\bin\libssp-0.dll"
  RMDir "$INSTDIR\bin"

  Delete "$INSTDIR\engines\4758cca.dll"
  Delete "$INSTDIR\engines\4758cca.pdb"
  Delete "$INSTDIR\engines\aep.dll"
  Delete "$INSTDIR\engines\aep.pdb"
  Delete "$INSTDIR\engines\atalla.dll"
  Delete "$INSTDIR\engines\atalla.pdb"
  Delete "$INSTDIR\engines\capi.dll"
  Delete "$INSTDIR\engines\capi.pdb"
  Delete "$INSTDIR\engines\chil.dll"
  Delete "$INSTDIR\engines\chil.pdb"
  Delete "$INSTDIR\engines\cswift.dll"
  Delete "$INSTDIR\engines\cswift.pdb"
  Delete "$INSTDIR\engines\gmp.dll"
  Delete "$INSTDIR\engines\gmp.pdb"
  Delete "$INSTDIR\engines\gost.dll"
  Delete "$INSTDIR\engines\gost.pdb"
  Delete "$INSTDIR\engines\nuron.dll"
  Delete "$INSTDIR\engines\nuron.pdb"
  Delete "$INSTDIR\engines\padlock.dll"
  Delete "$INSTDIR\engines\padlock.pdb"
  Delete "$INSTDIR\engines\sureware.dll"
  Delete "$INSTDIR\engines\sureware.pdb"
  Delete "$INSTDIR\engines\ubsec.dll"
  Delete "$INSTDIR\engines\ubsec.pdb"
  Delete "$INSTDIR\engines\pkcs11.dll"
  Delete "$INSTDIR\engines\pkcs11.pdb"
  RMDir "$INSTDIR\engines"

  Delete "$INSTDIR\doc\*.html"
  RMDir "$INSTDIR\doc"

  # menu and desktop shortcuts
  Delete "$SMPROGRAMS\${SHORTCUTS}\*.lnk"
  Delete "$SMPROGRAMS\${SHORTCUTS}\*.url"
  RMDir "$SMPROGRAMS\${SHORTCUTS}"
  Delete "$DESKTOP\${SHORTCUTS}.lnk"

  # obsolete versions
  Delete "$INSTDIR\stunnel.exe"
  Delete "$INSTDIR\stunnel.pdb"
  Delete "$INSTDIR\tstunnel.exe"
  Delete "$INSTDIR\tstunnel.pdb"
  Delete "$INSTDIR\openssl.exe"
  Delete "$INSTDIR\openssl.pdb"
  Delete "$INSTDIR\libeay32.dll"
  Delete "$INSTDIR\libeay32.pdb"
  Delete "$INSTDIR\ssleay32.dll"
  Delete "$INSTDIR\ssleay32.pdb"
  Delete "$INSTDIR\zlib1.dll"
  Delete "$INSTDIR\zlib1.pdb"
  Delete "$INSTDIR\msvcr90.dll"

  Delete "$INSTDIR\openssl.cnf"
  Delete "$INSTDIR\stunnel.html"

  Delete "$INSTDIR\stunnel.cnf"
  Delete "$INSTDIR\stunnel.exe.manifest"
  Delete "$INSTDIR\tstunnel.exe.manifest"
  Delete "$INSTDIR\openssl.exe.manifest"
  Delete "$INSTDIR\libeay32.dll.manifest"
  Delete "$INSTDIR\ssleay32.dll.manifest"
  Delete "$INSTDIR\zlib1.dll.manifest"
  Delete "$INSTDIR\Microsoft.VC90.CRT.Manifest"

  Delete "$INSTDIR\4758cca.dll"
  Delete "$INSTDIR\4758cca.dll.manifest"
  Delete "$INSTDIR\4758cca.pdb"
  Delete "$INSTDIR\aep.dll"
  Delete "$INSTDIR\aep.dll.manifest"
  Delete "$INSTDIR\aep.pdb"
  Delete "$INSTDIR\atalla.dll"
  Delete "$INSTDIR\atalla.dll.manifest"
  Delete "$INSTDIR\atalla.pdb"
  Delete "$INSTDIR\capi.dll"
  Delete "$INSTDIR\capi.dll.manifest"
  Delete "$INSTDIR\capi.pdb"
  Delete "$INSTDIR\chil.dll"
  Delete "$INSTDIR\chil.dll.manifest"
  Delete "$INSTDIR\chil.pdb"
  Delete "$INSTDIR\cswift.dll"
  Delete "$INSTDIR\cswift.dll.manifest"
  Delete "$INSTDIR\cswift.pdb"
  Delete "$INSTDIR\gmp.dll"
  Delete "$INSTDIR\gmp.dll.manifest"
  Delete "$INSTDIR\gmp.pdb"
  Delete "$INSTDIR\gost.dll"
  Delete "$INSTDIR\gost.dll.manifest"
  Delete "$INSTDIR\gost.pdb"
  Delete "$INSTDIR\nuron.dll"
  Delete "$INSTDIR\nuron.dll.manifest"
  Delete "$INSTDIR\nuron.pdb"
  Delete "$INSTDIR\padlock.dll"
  Delete "$INSTDIR\padlock.dll.manifest"
  Delete "$INSTDIR\padlock.pdb"
  Delete "$INSTDIR\sureware.dll"
  Delete "$INSTDIR\sureware.dll.manifest"
  Delete "$INSTDIR\sureware.pdb"
  Delete "$INSTDIR\ubsec.dll"
  Delete "$INSTDIR\ubsec.dll.manifest"
  Delete "$INSTDIR\ubsec.pdb"

  # obsolete menu and desktop shortcuts
  Delete "$SMPROGRAMS\stunnel\*.lnk"
  Delete "$SMPROGRAMS\stunnel\*.url"
  RMDir "$SMPROGRAMS\stunnel"
  Delete "$DESKTOP\stunnel.lnk"

  # refresh the screen
  System::Call 'Shell32::SHChangeNotify(i 0x8000000, i 0, i 0, i 0)'
!macroend

Function .onInit
  !insertmacro MULTIUSER_INIT
FunctionEnd

Function un.onInit
  !insertmacro MULTIUSER_UNINIT
FunctionEnd

Section "Core Files" sectionCORE
  SectionIn RO

  # save the installer configuration
  WriteRegStr SHCTX "${REGKEY_INSTALL}" "Install_Dir" "$INSTDIR"
  WriteRegStr SHCTX "${REGKEY_INSTALL}" "Install_Mode" "$MultiUser.InstallMode"

  !insertmacro TerminateStunnel
  !insertmacro CleanupStunnelFiles

  # update the configuration (migrate the old one if available)
  SetOutPath "$INSTDIR\config" # this also creates the directory
  !insertmacro MoveFiles "$INSTDIR" "$INSTDIR\config" "*.conf"
  !insertmacro MoveFiles "$INSTDIR" "$INSTDIR\config" "*.pem"
  !insertmacro MoveFiles "$INSTDIR" "$INSTDIR\config" "*.crt"
  !insertmacro MoveFiles "$INSTDIR" "$INSTDIR\config" "*.key"
  SetOverwrite off
  File "${STUNNEL_TOOLS_DIR}\stunnel.conf"
  SetOverwrite on
  File "${STUNNEL_TOOLS_DIR}\ca-certs.pem"

  # write new executables/libraries files
  SetOutPath "$INSTDIR\bin"
  File "${STUNNEL_BIN_DIR}\stunnel.exe"
  !if ${ARCH} == win32
  # Visual C++ 2008
  #File "${OPENSSL_BIN_DIR}\libeay32.dll"
  #File "${OPENSSL_BIN_DIR}\ssleay32.dll"
  #File "${REDIST_DIR}\msvcr90.dll"
  #File "${REDIST_DIR}\Microsoft.VC90.CRT.Manifest"
  File "${OPENSSL_BIN_DIR}\libcrypto-1_1.dll"
  File "${OPENSSL_BIN_DIR}\libssl-1_1.dll"
  !if /FileExists "/usr/i686-w64-mingw32/bin/libssp-0.dll"
  File "/usr/i686-w64-mingw32/bin/libssp-0.dll"
  !else
  !if /FileExists "/usr/lib/gcc/i686-w64-mingw32/10-win32/libssp-0.dll"
  File "/usr/lib/gcc/i686-w64-mingw32/10-win32/libssp-0.dll"
  !else
  !if /FileExists "/usr/lib/gcc/i686-w64-mingw32/9.3-win32/libssp-0.dll"
  File "/usr/lib/gcc/i686-w64-mingw32/9.3-win32/libssp-0.dll"
  !else
  !if /FileExists "/usr/lib/gcc/i686-w64-mingw32/8.3-win32/libssp-0.dll"
  File "/usr/lib/gcc/i686-w64-mingw32/8.3-win32/libssp-0.dll"
  !endif
  !endif
  !endif
  !endif
  !else
  File "${OPENSSL_BIN_DIR}\libcrypto-1_1-x64.dll"
  File "${OPENSSL_BIN_DIR}\libssl-1_1-x64.dll"
  !if /FileExists "/usr/x86_64-w64-mingw32/bin/libssp-0.dll"
  File "/usr/x86_64-w64-mingw32/bin/libssp-0.dll"
  !else
  !if /FileExists "/usr/lib/gcc/x86_64-w64-mingw32/10-win32/libssp-0.dll"
  File "/usr/lib/gcc/x86_64-w64-mingw32/10-win32/libssp-0.dll"
  !else
  !if /FileExists "/usr/lib/gcc/x86_64-w64-mingw32/9.3-win32/libssp-0.dll"
  File "/usr/lib/gcc/x86_64-w64-mingw32/9.3-win32/libssp-0.dll"
  !else
  !if /FileExists "/usr/lib/gcc/x86_64-w64-mingw32/8.3-win32/libssp-0.dll"
  File "/usr/lib/gcc/x86_64-w64-mingw32/8.3-win32/libssp-0.dll"
  !endif
  !endif
  !endif
  !endif
  #SetOutPath "$INSTDIR"
  #ReadRegStr $0 HKLM "SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64" "Installed"
  #${If} $0 == 1
  #  DetailPrint "VC 2017 Redistributable already installed"
  #${Else}
  #  DetailPrint "Installing VC 2017 Redistributable"
  #  File "${REDIST_DIR}\VC_redist.x64.exe"
  #  ExecWait '"$INSTDIR\VC_redist.x64.exe" /quiet'
  #  Delete "$INSTDIR\VC_redist.x64.exe"
  #${EndIf}
  !endif

  # write new engine libraries
  SetOutPath "$INSTDIR\engines"
  File "${OPENSSL_ENGINES_DIR}\capi.dll"
  File "${OPENSSL_ENGINES_DIR}\padlock.dll"
  File "${OPENSSL_ENGINES_DIR}\pkcs11.dll"

  # write new documentation
  SetOutPath "$INSTDIR\doc"
  File "${STUNNEL_DOC_DIR}\stunnel.html"

  # add firewall rule
  SimpleFC::AddApplication "stunnel (GUI Version)" \
    "$INSTDIR\bin\stunnel.exe" 0 2 "" 1
  !insertmacro DetailError "SimpleFC::AddApplication failed for stunnel.exe"

  # write uninstaller and its registry entries
  WriteUninstaller "uninstall.exe"
  WriteRegStr SHCTX "${REGKEY_UNINST}" "DisplayName" \
    "stunnel installed for $MultiUser.InstallMode"
  WriteRegStr SHCTX "${REGKEY_UNINST}" "DisplayVersion" "${VERSION}"
  WriteRegStr SHCTX "${REGKEY_UNINST}" "DisplayIcon" "$INSTDIR\bin\stunnel.exe"
  WriteRegStr SHCTX "${REGKEY_UNINST}" "Publisher" "Michal Trojnara"
  WriteRegStr SHCTX "${REGKEY_UNINST}" \
    "UninstallString" '"$INSTDIR\uninstall.exe" /$MultiUser.InstallMode'
  WriteRegDWORD SHCTX "${REGKEY_UNINST}" "NoModify" 1
  WriteRegDWORD SHCTX "${REGKEY_UNINST}" "NoRepair" 1
SectionEnd

SectionGroup "Tools" groupTOOLS

Section "openssl.exe" sectionOPENSSL
  SetOutPath "$INSTDIR\bin"
  File "${OPENSSL_BIN_DIR}\openssl.exe"
  SetOutPath "$INSTDIR\config"
  File "${STUNNEL_TOOLS_DIR}\openssl.cnf"

  # create stunnel.pem
  IfSilent no_new_pem
  IfFileExists "$INSTDIR\config\stunnel.pem" no_new_pem
  # set HOME for the .rnd file
  ReadEnvStr $0 "HOME"
  StrCmp $0 "" home_defined
  System::Call 'Kernel32::SetEnvironmentVariable(t, t) i("HOME", "$INSTDIR\config").r0'
home_defined:
  ExecWait '"$INSTDIR\bin\openssl.exe" req -new -x509 -days 365 -config "$INSTDIR\config\openssl.cnf" -out "$INSTDIR\config\stunnel.pem" -keyout "$INSTDIR\config\stunnel.pem"'
no_new_pem:
SectionEnd

Section "tstunnel.exe" sectionTSTUNNEL
  SetOutPath "$INSTDIR\bin"
  File "${STUNNEL_BIN_DIR}\tstunnel.exe"
  # add firewall rule
  SimpleFC::AddApplication "stunnel (Terminal Version)" \
    "$INSTDIR\bin\tstunnel.exe" 0 2 "" 1
  !insertmacro DetailError "SimpleFC::AddApplication failed for tstunnel.exe"
SectionEnd

SectionGroupEnd

SectionGroup "Shortcuts" groupSHORTCUTS

Section "Start Menu" sectionMENU
  CreateDirectory "$SMPROGRAMS\${SHORTCUTS}"

  # the core links
  CreateShortCut "$SMPROGRAMS\${SHORTCUTS}\stunnel GUI Start.lnk" \
    "$INSTDIR\bin\stunnel.exe" "" "$INSTDIR\bin\stunnel.exe"
  CreateShortCut "$SMPROGRAMS\${SHORTCUTS}\stunnel GUI Stop.lnk" \
    "$INSTDIR\bin\stunnel.exe" "-exit" "$INSTDIR\bin\stunnel.exe"

  # tstunnel
  SectionGetFlags ${sectionTSTUNNEL} $0
  IntOp $0 $0 & ${SF_SELECTED}
  IntCmp $0 0 no_tstunnel_shortcut
  CreateShortCut "$SMPROGRAMS\${SHORTCUTS}\stunnel Terminal Start.lnk" \
    "$INSTDIR\bin\tstunnel.exe" "" "$INSTDIR\bin\tstunnel.exe"
no_tstunnel_shortcut:

  # NT service management
  ClearErrors
  ReadRegStr $R0 HKLM \
    "Software\Microsoft\Windows NT\CurrentVersion" CurrentVersion
  IfErrors no_service_shortcuts
  StrCmp $MultiUser.InstallMode "CurrentUser" no_service_shortcuts
  CreateShortCut "$SMPROGRAMS\${SHORTCUTS}\stunnel Service Install.lnk" \
    "$INSTDIR\bin\stunnel.exe" "-install" "$INSTDIR\bin\stunnel.exe"
  !insertmacro SetRunAsAdmin "stunnel Service Install"
  CreateShortCut "$SMPROGRAMS\${SHORTCUTS}\stunnel Service Uninstall.lnk" \
    "$INSTDIR\bin\stunnel.exe" "-uninstall" "$INSTDIR\bin\stunnel.exe"
  !insertmacro SetRunAsAdmin "stunnel Service Uninstall"
  CreateShortCut "$SMPROGRAMS\${SHORTCUTS}\stunnel Service Start.lnk" \
    "$INSTDIR\bin\stunnel.exe" "-start" "$INSTDIR\bin\stunnel.exe"
  !insertmacro SetRunAsAdmin "stunnel Service Start"
  CreateShortCut "$SMPROGRAMS\${SHORTCUTS}\stunnel Service Stop.lnk" \
    "$INSTDIR\bin\stunnel.exe" "-stop" "$INSTDIR\bin\stunnel.exe"
  !insertmacro SetRunAsAdmin "stunnel Service Stop"
  CreateShortCut "$SMPROGRAMS\${SHORTCUTS}\stunnel Service Configuration File Reload.lnk" \
    "$INSTDIR\bin\stunnel.exe" "-reload" "$INSTDIR\bin\stunnel.exe"
  !insertmacro SetRunAsAdmin "stunnel Service Configuration File Reload"
  CreateShortCut "$SMPROGRAMS\${SHORTCUTS}\stunnel Service Log File Reopen.lnk" \
    "$INSTDIR\bin\stunnel.exe" "-reopen" "$INSTDIR\bin\stunnel.exe"
  !insertmacro SetRunAsAdmin "stunnel Service Log File Reopen"
no_service_shortcuts:

  # edit config file
  CreateShortCut "$SMPROGRAMS\${SHORTCUTS}\Edit stunnel.conf.lnk" \
    "notepad.exe" "$INSTDIR\config\stunnel.conf" "notepad.exe"
  !insertmacro SetRunAsAdmin "Edit stunnel.conf"

  SectionGetFlags ${sectionOPENSSL} $0
  IntOp $0 $0 & ${SF_SELECTED}
  IntCmp $0 0 no_openssl_shortcuts
  # OpenSSL shell
  CreateShortCut "$SMPROGRAMS\${SHORTCUTS}\OpenSSL Shell.lnk" \
    "$INSTDIR\bin\openssl.exe" "" "$INSTDIR\bin\openssl.exe"
  # make stunnel.pem
  CreateShortCut "$SMPROGRAMS\${SHORTCUTS}\Build a Self-signed stunnel.pem.lnk" \
    "$INSTDIR\bin\openssl.exe" \
    'req -new -x509 -days 365 -config "$INSTDIR\config\openssl.cnf" -out "$INSTDIR\config\stunnel.pem" -keyout "$INSTDIR\config\stunnel.pem"'
  !insertmacro SetRunAsAdmin "Build a Self-signed stunnel.pem"
no_openssl_shortcuts:

  # the fine manual
  WriteINIStr "$SMPROGRAMS\${SHORTCUTS}\stunnel Manual Page.url" \
    "InternetShortcut" "URL" "file://$INSTDIR\doc\stunnel.html"

  # uninstall
  CreateShortCut "$SMPROGRAMS\${SHORTCUTS}\Uninstall stunnel.lnk" \
    "$INSTDIR\uninstall.exe" "/$MultiUser.InstallMode" \
    "$INSTDIR\uninstall.exe"
SectionEnd

Section "Desktop" sectionDESKTOP
  # create the link
  CreateShortCut "$DESKTOP\${SHORTCUTS}.lnk" \
    "$INSTDIR\bin\stunnel.exe" "" "$INSTDIR\bin\stunnel.exe"

  # refresh the screen
  System::Call 'Shell32::SHChangeNotify(i 0x8000000, i 0, i 0, i 0)'
SectionEnd

SectionGroupEnd

/*
Section /o "Debugging Symbols" sectionDEBUG
  SetOutPath "$INSTDIR\bin"

  # core components
  File "${STUNNEL_BIN_DIR}\stunnel.pdb"
  !if ${ARCH} == win32
  File "${OPENSSL_BIN_DIR}\libeay32.pdb"
  File "${OPENSSL_BIN_DIR}\ssleay32.pdb"
  File "${ZLIB_DIR}\zlib1.pdb"
  !else
  File "${OPENSSL_BIN_DIR}\libcrypto-1_1-x64.pdb"
  File "${OPENSSL_BIN_DIR}\libssl-1_1-x64.pdb"
  !endif

  # optional tstunnel.exe
  SectionGetFlags ${sectionTSTUNNEL} $0
  IntOp $0 $0 & ${SF_SELECTED}
  IntCmp $0 0 no_tstunnel_pdb
  File "${STUNNEL_BIN_DIR}\tstunnel.pdb"
no_tstunnel_pdb:

  # optional openssl.exe
  SectionGetFlags ${sectionOPENSSL} $0
  IntOp $0 $0 & ${SF_SELECTED}
  IntCmp $0 0 no_openssl_pdb
  File "${OPENSSL_BIN_DIR}\openssl.pdb"
no_openssl_pdb:

  # engines
  SetOutPath "$INSTDIR\engines"
  File "${OPENSSL_ENGINES_DIR}\capi.pdb"
  File "${OPENSSL_ENGINES_DIR}\padlock.pdb"
  File "${OPENSSL_ENGINES_DIR}\pkcs11.pdb"
  SetOutPath "$INSTDIR"
SectionEnd
*/

Section
  !insertmacro RestartStunnel
SectionEnd

Section "Uninstall"
  !insertmacro TerminateStunnel
  !insertmacro CleanupStunnelFiles

  # remove the stunnel directory
  RMDir /r "$INSTDIR\config"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"

  # remove firewall rules
  SimpleFC::RemoveApplication "$INSTDIR\bin\stunnel.exe"
  !insertmacro DetailError "SimpleFC::RemoveApplication failed for stunnel.exe"
  SimpleFC::RemoveApplication "$INSTDIR\bin\tstunnel.exe"
  !insertmacro DetailError "SimpleFC::RemoveApplication failed for tstunnel.exe"

  # remove the installer and uninstaller registry entires
  DeleteRegKey SHCTX "${REGKEY_INSTALL}"
  DeleteRegKey SHCTX "${REGKEY_UNINST}"
SectionEnd

LangString DESC_sectionCORE ${LANG_ENGLISH} \
  "Installs the stunnel executable and the required libraries.$\r$\nThis component also creates a sample stunnel.conf if no such file exists."
LangString DESC_sectionOPENSSL ${LANG_ENGLISH} \
  "Installs openssl.exe, the OpenSSL command-line tool.$\r$\nThis component also builds a self-signed stunnel.pem file if no such file exists."
LangString DESC_sectionTSTUNNEL ${LANG_ENGLISH} \
  "Installs tstunnel.exe, the command-line version of stunnel.$\r$\ntstunnel.exe is often used for scripting."
LangString DESC_sectionMENU ${LANG_ENGLISH} \
  "Installs the Start Menu shortcuts for managing stunnel."
LangString DESC_sectionDESKTOP ${LANG_ENGLISH} \
  "Installs the Desktop shortcut for stunnel."
/*
LangString DESC_sectionDEBUG ${LANG_ENGLISH} \
  "Installs the .PDB (program database) files for the executables and libraries."
*/
LangString DESC_groupTOOLS ${LANG_ENGLISH} \
  "Installs optional (but useful) tools."
LangString DESC_groupSHORTCUTS ${LANG_ENGLISH} \
  "Installs menu and desktop shortcuts."

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
    !insertmacro MUI_DESCRIPTION_TEXT ${sectionCORE} $(DESC_sectionCORE)
    !insertmacro MUI_DESCRIPTION_TEXT ${sectionOPENSSL} $(DESC_sectionOPENSSL)
    !insertmacro MUI_DESCRIPTION_TEXT ${sectionTSTUNNEL} $(DESC_sectionTSTUNNEL)
    !insertmacro MUI_DESCRIPTION_TEXT ${sectionMENU} $(DESC_sectionMENU)
    !insertmacro MUI_DESCRIPTION_TEXT ${sectionDESKTOP} $(DESC_sectionDESKTOP)
/*
    !insertmacro MUI_DESCRIPTION_TEXT ${sectionDEBUG} $(DESC_sectionDEBUG)
*/
    !insertmacro MUI_DESCRIPTION_TEXT ${groupTOOLS} $(DESC_groupTOOLS)
    !insertmacro MUI_DESCRIPTION_TEXT ${groupSHORTCUTS} $(DESC_groupSHORTCUTS)
!insertmacro MUI_FUNCTION_DESCRIPTION_END

# end of stunnel.nsi
