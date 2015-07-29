# NSIS stunnel installer by Michal Trojnara 1998-2015

!include "Sections.nsh"

!ifndef VERSION
!define VERSION 5.21
!endif

!ifndef ZLIBDIR
!define ZLIBDIR zlib-1.2.8-win32
!endif

!ifndef OPENSSLDIR
!define OPENSSLDIR openssl-1.0.2d-win32
!endif

!addplugindir "plugins/SimpleFC"
!addplugindir "plugins/ShellLink/Plugins"

Name "stunnel ${VERSION}"
OutFile "stunnel-${VERSION}-installer.exe" 
InstallDir "$PROGRAMFILES\stunnel"
BrandingText "Author: Michal Trojnara" 
LicenseData "stunnel.license"
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
  Var /GLOBAL service
  StrCpy $service 1
  ReadRegStr $R0 HKLM \
    "Software\Microsoft\Windows NT\CurrentVersion" CurrentVersion
  IfErrors skip_service_stop
  ExecWait '"$INSTDIR\stunnel.exe" -stop -quiet' $service
skip_service_stop:
  ExecWait '"$INSTDIR\stunnel.exe" -exit -quiet'

  # write files
  SetOverwrite off
  File "stunnel.conf"
  File "ca-certs.pem"
  SetOverwrite on
  !cd ".."
  !cd "doc"
  File "stunnel.html"
  !cd ".."
  !cd "bin"
  !cd "win32"
  File "stunnel.exe"
  File "stunnel.exe.manifest"
  !cd ".."
  !cd ".."
  !cd ".."
  !cd "${ZLIBDIR}"
  File "zlib1.dll"
  File "zlib1.dll.manifest"
  !cd ".."
  !cd "${OPENSSLDIR}"
  !cd "out32dll"
  File "libeay32.dll"
  File "libeay32.dll.manifest"
  File "ssleay32.dll"
  File "ssleay32.dll.manifest"
  File "4758cca.dll"
  File "4758cca.dll.manifest"
  File "aep.dll"
  File "aep.dll.manifest"
  File "atalla.dll"
  File "atalla.dll.manifest"
  File "capi.dll"
  File "capi.dll.manifest"
  File "chil.dll"
  File "chil.dll.manifest"
  File "cswift.dll"
  File "cswift.dll.manifest"
  File "gmp.dll"
  File "gmp.dll.manifest"
  File "gost.dll"
  File "gost.dll.manifest"
  File "nuron.dll"
  File "nuron.dll.manifest"
  File "padlock.dll"
  File "padlock.dll.manifest"
  File "sureware.dll"
  File "sureware.dll.manifest"
  File "ubsec.dll"
  File "ubsec.dll.manifest"

  !cd ".."
  !cd ".."
  !cd "redist"
  File "msvcr90.dll"
  File "Microsoft.VC90.CRT.manifest"
  !cd ".."
  !cd "stunnel"
  !cd "tools"
  # MINGW builds requires libssp-0.dll instead of msvcr90.dll

  # add firewall rule
  SimpleFC::AddApplication "stunnel (GUI Version)" \
    "$INSTDIR\stunnel.exe" 0 2 "" 1
  Pop $0 # returns error(1)/success(0)
  DetailPrint "SimpleFC::AddApplication: $0"

  # write uninstaller and its registry entries
  WriteUninstaller "uninstall.exe"
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

  # start the service
  IntCmp $service 0 lbl_start_service lbl_skip_service lbl_skip_service
lbl_start_service:
  ExecWait '"$INSTDIR\stunnel.exe" -start -quiet'
lbl_skip_service:
SectionEnd

Section "Self-signed Certificate Tools" sectionCA
  SetOutPath "$INSTDIR"
  !cd ".."
  !cd ".."
  !cd "${OPENSSLDIR}"
  !cd "out32dll"
  File "openssl.exe"
  File "openssl.exe.manifest"
  !cd ".."
  !cd ".."
  !cd "stunnel"
  !cd "tools"
  File "stunnel.cnf"
  IfSilent lbl_skip_new_pem
  IfFileExists "$INSTDIR\stunnel.pem" lbl_skip_new_pem
  ReadEnvStr $0 "HOME"
  StrCmp $0 "" lbl_home_defined 0
  System::Call 'Kernel32::SetEnvironmentVariable(t, t) i("HOME", "$INSTDIR").r0'
lbl_home_defined:
  ExecWait '"$INSTDIR\openssl.exe" req -new -x509 -days 365 -config stunnel.cnf -out stunnel.pem -keyout stunnel.pem'
lbl_skip_new_pem:
SectionEnd

Section "Terminal Version of stunnel" sectionTERM
  SetOutPath "$INSTDIR"
  !cd ".."
  !cd "bin"
  !cd "win32"
  File "tstunnel.exe"
  File "tstunnel.exe.manifest"
  !cd ".."
  !cd ".."
  !cd "tools"
  # add firewall rule
  SimpleFC::AddApplication "stunnel (Terminal Version)" \
    "$INSTDIR\tstunnel.exe" 0 2 "" 1
  Pop $0 # returns error(1)/success(0)
  DetailPrint "SimpleFC::AddApplication: $0"
SectionEnd

Section "Start Menu Shortcuts"
  SetShellVarContext all
  CreateDirectory "$SMPROGRAMS\stunnel"

  # remove old links
  Delete "$SMPROGRAMS\stunnel\*.lnk"
  Delete "$SMPROGRAMS\stunnel\*.url"

  # main link
  CreateShortCut "$SMPROGRAMS\stunnel\stunnel GUI Start.lnk" \
    "$INSTDIR\stunnel.exe" "" "$INSTDIR\stunnel.exe" 0
  CreateShortCut "$SMPROGRAMS\stunnel\stunnel GUI Stop.lnk" \
    "$INSTDIR\stunnel.exe" "-exit" "$INSTDIR\stunnel.exe" 0

  # tstunnel
  SectionGetFlags ${sectionTERM} $0
  IntOp $0 $0 & ${SF_SELECTED}
  IntCmp $0 0 lbl_noTERM
  CreateShortCut "$SMPROGRAMS\stunnel\stunnel Terminal Start.lnk" \
    "$INSTDIR\tstunnel.exe" "" "$INSTDIR\tstunnel.exe" 0
lbl_noTERM:

  # NT service
  ClearErrors
  ReadRegStr $R0 HKLM \
    "Software\Microsoft\Windows NT\CurrentVersion" CurrentVersion
  IfErrors skip_service_links

  CreateShortCut "$SMPROGRAMS\stunnel\stunnel Service Install.lnk" \
    "$INSTDIR\stunnel.exe" "-install" "$INSTDIR\stunnel.exe" 0
  ShellLink::SetRunAsAdministrator \
    "$SMPROGRAMS\stunnel\stunnel Service Install.lnk"
  Pop $0 # returns error(-1)/success(0)
  DetailPrint "ShellLink::SetRunAsAdministrator: $0"

  CreateShortCut "$SMPROGRAMS\stunnel\stunnel Service Uninstall.lnk" \
    "$INSTDIR\stunnel.exe" "-uninstall" "$INSTDIR\stunnel.exe" 0
  ShellLink::SetRunAsAdministrator \
    "$SMPROGRAMS\stunnel\stunnel Service Uninstall.lnk"
  Pop $0 # returns error(-1)/success(0)
  DetailPrint "ShellLink::SetRunAsAdministrator: $0"

  CreateShortCut "$SMPROGRAMS\stunnel\stunnel Service Start.lnk" \
    "$INSTDIR\stunnel.exe" "-start" "$INSTDIR\stunnel.exe" 0
  ShellLink::SetRunAsAdministrator \
    "$SMPROGRAMS\stunnel\stunnel Service Start.lnk"
  Pop $0 # returns error(-1)/success(0)
  DetailPrint "ShellLink::SetRunAsAdministrator: $0"

  CreateShortCut "$SMPROGRAMS\stunnel\stunnel Service Stop.lnk" \
    "$INSTDIR\stunnel.exe" "-stop" "$INSTDIR\stunnel.exe" 0
  ShellLink::SetRunAsAdministrator \
    "$SMPROGRAMS\stunnel\stunnel Service Stop.lnk"
  Pop $0 # returns error(-1)/success(0)
  DetailPrint "ShellLink::SetRunAsAdministrator: $0"

  CreateShortCut "$SMPROGRAMS\stunnel\stunnel Service Configuration File Reload.lnk" \
    "$INSTDIR\stunnel.exe" "-reload" "$INSTDIR\stunnel.exe" 0
  ShellLink::SetRunAsAdministrator \
    "$SMPROGRAMS\stunnel\stunnel Service Configuration File Reload.lnk"
  Pop $0 # returns error(-1)/success(0)
  DetailPrint "ShellLink::SetRunAsAdministrator: $0"

  CreateShortCut "$SMPROGRAMS\stunnel\stunnel Service Log File Reopen.lnk" \
    "$INSTDIR\stunnel.exe" "-reopen" "$INSTDIR\stunnel.exe" 0
  ShellLink::SetRunAsAdministrator \
    "$SMPROGRAMS\stunnel\stunnel Service Log File Reopen.lnk"
  Pop $0 # returns error(-1)/success(0)
  DetailPrint "ShellLink::SetRunAsAdministrator: $0"
skip_service_links:

  # edit config file
  CreateShortCut "$SMPROGRAMS\stunnel\Edit stunnel.conf.lnk" \
    "notepad.exe" "$INSTDIR\stunnel.conf" "notepad.exe" 0
  ShellLink::SetRunAsAdministrator \
    "$SMPROGRAMS\stunnel\Edit stunnel.conf.lnk"
  Pop $0 # returns error(-1)/success(0)
  DetailPrint "ShellLink::SetRunAsAdministrator: $0"

  SectionGetFlags ${sectionCA} $0
  IntOp $0 $0 & ${SF_SELECTED}
  IntCmp $0 0 lbl_noCA

  # OpenSSL shell
  CreateShortCut "$SMPROGRAMS\stunnel\OpenSSL Shell.lnk" \
    "$INSTDIR\openssl.exe" "" "$INSTDIR\openssl.exe" 0

  # make stunnel.pem
  CreateShortCut "$SMPROGRAMS\stunnel\Build Self-signed stunnel.pem.lnk" \
    "$INSTDIR\openssl.exe" \
    "req -new -x509 -days 365 -config stunnel.cnf -out stunnel.pem -keyout stunnel.pem"
  ShellLink::SetRunAsAdministrator \
    "$SMPROGRAMS\stunnel\\Build Self-signed stunnel.pem.lnk"
  Pop $0 # returns error(-1)/success(0)
  DetailPrint "ShellLink::SetRunAsAdministrator: $0"

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

Section /o "Debugging Symbols"
  SetOutPath "$INSTDIR"
  !cd ".."
  !cd "bin"
  !cd "win32"
  File "stunnel.pdb"
  File "tstunnel.pdb"
  !cd ".."
  !cd ".."
  !cd ".."
  !cd "${ZLIBDIR}"
  File "zlib1.pdb"
  !cd ".."
  !cd "${OPENSSLDIR}"
  !cd "out32dll"
  File "libeay32.pdb"
  File "ssleay32.pdb"
  File "openssl.pdb"
  File "4758cca.pdb"
  File "aep.pdb"
  File "atalla.pdb"
  File "capi.pdb"
  File "chil.pdb"
  File "cswift.pdb"
  File "gmp.pdb"
  File "gost.pdb"
  File "nuron.pdb"
  File "padlock.pdb"
  File "sureware.pdb"
  File "ubsec.pdb"
  !cd ".."
  !cd ".."
  !cd "stunnel"
  !cd "tools"
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
  Delete "$INSTDIR\ca-certs.pem"
  Delete "$INSTDIR\stunnel.pem"
  Delete "$INSTDIR\stunnel.exe"
  Delete "$INSTDIR\stunnel.exe.manifest"
  Delete "$INSTDIR\stunnel.pdb"
  Delete "$INSTDIR\tstunnel.exe"
  Delete "$INSTDIR\tstunnel.exe.manifest"
  Delete "$INSTDIR\stunnel.cnf"
  Delete "$INSTDIR\openssl.exe"
  Delete "$INSTDIR\openssl.exe.manifest"
  Delete "$INSTDIR\openssl.pdb"
  Delete "$INSTDIR\Microsoft.VC90.CRT.manifest"
  Delete "$INSTDIR\libeay32.dll"
  Delete "$INSTDIR\libeay32.dll.manifest"
  Delete "$INSTDIR\libeay32.pdb"
  Delete "$INSTDIR\ssleay32.dll"
  Delete "$INSTDIR\ssleay32.dll.manifest"
  Delete "$INSTDIR\ssleay32.pdb"
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
  Delete "$INSTDIR\stunnel.html"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"

  # remove menu shortcuts
  SetShellVarContext all
  Delete "$DESKTOP\stunnel.lnk"
  Delete "$SMPROGRAMS\stunnel\*.lnk"
  Delete "$SMPROGRAMS\stunnel\*.url"
  RMDir "$SMPROGRAMS\stunnel"

  # remove firewall rules
  SimpleFC::RemoveApplication "$INSTDIR\stunnel.exe"
  Pop $0 # returns error(1)/success(0)
  DetailPrint "SimpleFC::RemoveApplication: $0"
  SimpleFC::RemoveApplication "$INSTDIR\tstunnel.exe"
  Pop $0 # returns error(1)/success(0)
  DetailPrint "SimpleFC::RemoveApplication: $0"

  # remove uninstaller registry entires
  DeleteRegKey HKLM \
    "Software\Microsoft\Windows\CurrentVersion\Uninstall\stunnel"
  DeleteRegKey HKLM "Software\NSIS_stunnel"
SectionEnd

# end of stunnel.nsi
