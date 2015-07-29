!define VERSION "4.29"
!define DLLS "/home/ftp/openssl/binary-0.9.8l-zdll/"
# !define DLLS "../FIPS/"
# !define DLLS "/usr/src/openssl-0.9.7m-fips/"
!define WIN32 "/home/ftp/stunnel/obsolete/"

Name "stunnel ${VERSION}"
OutFile "stunnel-${VERSION}-installer.exe" 
InstallDir "$PROGRAMFILES\stunnel"
BrandingText "Author: Michal Trojnara" 
LicenseData "${SRCDIR}/COPYING"
SetCompressor LZMA

InstallDirRegKey HKLM "Software\NSIS_stunnel" "Install_Dir"

Page license
Page components
Page directory
Page instfiles

UninstPage uninstConfirm
UninstPage instfiles

Section "stunnel (required)"
  SectionIn RO
  SetOutPath $INSTDIR
  SetOverwrite off
  File "${SRCDIR}tools/stunnel.conf"
  File "${WIN32}stunnel.pem"
  SetOverwrite on
  File "src/stunnel.exe"
#  File "${DLLS}cryptoeay32.dll"
#  File "${DLLS}ssleay32.dll"
  File "${DLLS}libeay32.dll"
  File "${DLLS}libssl32.dll"
  File "${DLLS}zlib1.dll"
  File "${SRCDIR}doc/stunnel.html"
  WriteRegStr HKLM SOFTWARE\NSIS_stunnel "Install_Dir" "$INSTDIR"
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
  WriteUninstaller "uninstall.exe"
SectionEnd

Section "Start Menu Shortcuts"
  CreateDirectory "$SMPROGRAMS\stunnel"
  CreateShortCut "$SMPROGRAMS\stunnel\Run stunnel.lnk" \
    "$INSTDIR\stunnel.exe" "" "$INSTDIR\stunnel.exe" 0

  ClearErrors
  ReadRegStr $R0 HKLM \
    "SOFTWARE\Microsoft\Windows NT\CurrentVersion" CurrentVersion
  IfErrors lbl_win9x
  CreateShortCut "$SMPROGRAMS\stunnel\Service install.lnk" \
    "$INSTDIR\stunnel.exe" "-install" "$INSTDIR\stunnel.exe" 0
  CreateShortCut "$SMPROGRAMS\stunnel\Service uninstall.lnk" \
    "$INSTDIR\stunnel.exe" "-uninstall" "$INSTDIR\stunnel.exe" 0
  CreateShortCut "$SMPROGRAMS\stunnel\Service start.lnk" \
    "$INSTDIR\stunnel.exe" "-start" "$INSTDIR\stunnel.exe" 0
  CreateShortCut "$SMPROGRAMS\stunnel\Service stop.lnk" \
    "$INSTDIR\stunnel.exe" "-stop" "$INSTDIR\stunnel.exe" 0
lbl_win9x:

  CreateShortCut "$SMPROGRAMS\stunnel\Edit stunnel.conf.lnk" \
    "notepad.exe" "stunnel.conf" "notepad.exe" 0
  WriteINIStr "$SMPROGRAMS\stunnel\Manual.url" "InternetShortcut" \
    "URL" "file://$INSTDIR/stunnel.html"
  CreateShortCut "$SMPROGRAMS\stunnel\Uninstall stunnel.lnk" \
    "$INSTDIR\uninstall.exe" "" "$INSTDIR\uninstall.exe" 0
SectionEnd

Section "Uninstall"
  DeleteRegKey HKLM \
    "Software\Microsoft\Windows\CurrentVersion\Uninstall\stunnel"
  DeleteRegKey HKLM SOFTWARE\NSIS_stunnel

  ClearErrors
  ReadRegStr $R0 HKLM \
    "SOFTWARE\Microsoft\Windows NT\CurrentVersion" CurrentVersion
  IfErrors lbl_win9x
  ExecWait '"$INSTDIR\stunnel.exe" -stop -quiet'
  ExecWait '"$INSTDIR\stunnel.exe" -uninstall -quiet'
lbl_win9x:

  Delete $INSTDIR\stunnel.conf
  Delete $INSTDIR\stunnel.pem
  Delete $INSTDIR\stunnel.exe
  Delete $INSTDIR\libeay32.dll
  Delete $INSTDIR\libssl32.dll
  Delete $INSTDIR\zlib1.dll
  Delete $INSTDIR\stunnel.html
  Delete $INSTDIR\uninstall.exe
  Delete "$SMPROGRAMS\stunnel\*.*"
  RMDir "$SMPROGRAMS\stunnel"
  RMDir "$INSTDIR"
SectionEnd

