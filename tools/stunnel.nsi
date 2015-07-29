# NSIS stunnel installer by Michal Trojnara 2011

!define VERSION "4.42"
!define DLLS "/home/ftp/openssl/openssl-1.0.0d-i586/"
!include "Sections.nsh"

Name "stunnel ${VERSION}"
OutFile "stunnel-${VERSION}-installer.exe" 
InstallDir "$PROGRAMFILES\stunnel"
BrandingText "Author: Michal Trojnara" 
LicenseData "${SRCDIR}tools/stunnel.license"
SetCompressor /SOLID LZMA
InstallDirRegKey HKLM "Software\NSIS_stunnel" "Install_Dir"

RequestExecutionLevel admin

Page license
Page components
Page directory
Page instfiles

UninstPage uninstConfirm
UninstPage instfiles

Section "Stunnel Core Files (required)"
  SectionIn RO
  SetOutPath "$INSTDIR"

  # stop the service, exit stunnel
  ReadRegStr $R0 HKLM \
    "Software\Microsoft\Windows NT\CurrentVersion" CurrentVersion
  IfErrors skip_service_stop
  ExecWait '"$INSTDIR\stunnel.exe" -stop -quiet'
skip_service_stop:
  # skip if the previously installed stunnel version is older than 4.40
  GetDLLVersion "$INSTDIR\stunnel.exe" $R0 $R1
  IfErrors skip_process_exit
  ExecWait '"$INSTDIR\stunnel.exe" -exit -quiet'
skip_process_exit:

  # write files
  SetOverwrite off
  File "${SRCDIR}tools/stunnel.conf"
  SetOverwrite on
  File "${DLLS}*eay32.dll"
  File "${DLLS}zlib1.dll"
  File "src/stunnel.exe"
  File "${SRCDIR}doc/stunnel.html"
  WriteUninstaller "uninstall.exe"

  # add uninstaller registry entries
  WriteRegStr HKLM "Software\NSIS_stunnel" "Install_Dir" "$INSTDIR"
  WriteRegStr HKLM \
    "Software\Microsoft\Windows\CurrentVersion\Uninstall\stunnel" \
    "DisplayName" "stunnel"
  WriteRegStr HKLM \
    "Software\Microsoft\Windows\CurrentVersion\Uninstall\stunnel" \
    "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegDWORD HKLM \
    "Software\Microsoft\Windows\CurrentVersion\Uninstall\stunnel" \
    "NoModify" 1
  WriteRegDWORD HKLM \
    "Software\Microsoft\Windows\CurrentVersion\Uninstall\stunnel" \
    "NoRepair" 1
SectionEnd

Section "Self-signed Certificate Tools" sectionCA
  SetOutPath "$INSTDIR"

  # write files
  File "${DLLS}openssl.exe"
  File "${SRCDIR}tools/stunnel.cnf"
  IfSilent lbl_skip_new_pem
  IfFileExists "$INSTDIR\stunnel.pem" lbl_skip_new_pem
  ExecWait '"$INSTDIR\openssl.exe" req -new -x509 -days 365 -config stunnel.cnf -out stunnel.pem -keyout stunnel.pem'
lbl_skip_new_pem:
SectionEnd

Section "Start Menu Shortcuts"
  SetShellVarContext all
  CreateDirectory "$SMPROGRAMS\stunnel"

  # remove old links
  Delete "$SMPROGRAMS\stunnel\*.lnk"
  Delete "$SMPROGRAMS\stunnel\*.url"

  # main link
  CreateShortCut "$SMPROGRAMS\stunnel\Run stunnel.lnk" \
    "$INSTDIR\stunnel.exe" "" "$INSTDIR\stunnel.exe" 0
  CreateShortCut "$SMPROGRAMS\stunnel\Exit stunnel.lnk" \
    "$INSTDIR\stunnel.exe" "-exit" "$INSTDIR\stunnel.exe" 0

  # NT service
  ClearErrors
  ReadRegStr $R0 HKLM \
    "Software\Microsoft\Windows NT\CurrentVersion" CurrentVersion
  IfErrors skip_service_links
  CreateShortCut "$SMPROGRAMS\stunnel\Service install.lnk" \
    "$INSTDIR\stunnel.exe" "-install" "$INSTDIR\stunnel.exe" 0
  CreateShortCut "$SMPROGRAMS\stunnel\Service uninstall.lnk" \
    "$INSTDIR\stunnel.exe" "-uninstall" "$INSTDIR\stunnel.exe" 0
  CreateShortCut "$SMPROGRAMS\stunnel\Service start.lnk" \
    "$INSTDIR\stunnel.exe" "-start" "$INSTDIR\stunnel.exe" 0
  CreateShortCut "$SMPROGRAMS\stunnel\Service stop.lnk" \
    "$INSTDIR\stunnel.exe" "-stop" "$INSTDIR\stunnel.exe" 0
skip_service_links:

  # edit config file
  CreateShortCut "$SMPROGRAMS\stunnel\Edit stunnel.conf.lnk" \
    "notepad.exe" "stunnel.conf" "notepad.exe" 0

  # make stunnel.pem
  SectionGetFlags ${sectionCA} $0
  IntOp $0 $0 & ${SF_SELECTED}
  IntCmp $0 0 lbl_noCA
  CreateShortCut "$SMPROGRAMS\stunnel\Build Self-signed stunnel.pem.lnk" \
    "$INSTDIR\openssl.exe" \
    "req -new -x509 -days 365 -config stunnel.cnf -out stunnel.pem -keyout stunnel.pem"
lbl_noCA:

  # help/uninstall
  WriteINIStr "$SMPROGRAMS\stunnel\Manual.url" "InternetShortcut" \
    "URL" "file://$INSTDIR/stunnel.html"
  CreateShortCut "$SMPROGRAMS\stunnel\Uninstall stunnel.lnk" \
    "$INSTDIR\uninstall.exe" "" "$INSTDIR\uninstall.exe" 0
SectionEnd

Section "Desktop Shortcut"
  SetShellVarContext all
  Delete "$DESKTOP\stunnel.lnk"
  CreateShortCut "$DESKTOP\stunnel.lnk" \
    "$INSTDIR\stunnel.exe" "" "$INSTDIR\stunnel.exe" 0
SectionEnd

Section "Uninstall"
  ClearErrors

  # stop and remove the service, exit stunnel
  ReadRegStr $R0 HKLM \
    "Software\Microsoft\Windows NT\CurrentVersion" CurrentVersion
  IfErrors skip_service_uninstall
  ExecWait '"$INSTDIR\stunnel.exe" -stop -quiet'
  ExecWait '"$INSTDIR\stunnel.exe" -uninstall -quiet'
skip_service_uninstall:
  ExecWait '"$INSTDIR\stunnel.exe" -exit -quiet'

  # remove stunnel folder
  Delete "$INSTDIR\stunnel.conf"
  Delete "$INSTDIR\stunnel.pem"
  Delete "$INSTDIR\stunnel.exe"
  Delete "$INSTDIR\stunnel.cnf"
  Delete "$INSTDIR\openssl.exe"
  Delete "$INSTDIR\*eay32.dll"
  Delete "$INSTDIR\zlib1.dll"
  Delete "$INSTDIR\stunnel.html"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"

  # remove menu shortcuts
  SetShellVarContext all
  Delete "$DESKTOP\stunnel.lnk"
  Delete "$SMPROGRAMS\stunnel\*.lnk"
  Delete "$SMPROGRAMS\stunnel\*.url"
  RMDir "$SMPROGRAMS\stunnel"

  # remove uninstaller registry entires
  DeleteRegKey HKLM \
    "Software\Microsoft\Windows\CurrentVersion\Uninstall\stunnel"
  DeleteRegKey HKLM "Software\NSIS_stunnel"
SectionEnd

# end of stunnel.nsi
