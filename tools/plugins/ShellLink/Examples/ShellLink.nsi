; ShellLink.nsi
; demonstrates how to use the ShellLink NSIS plugin.
;
; Created 12/16/2003
; Last Update: 03/06/2010
; Copyright (c) 2004 Angelo Mandato. 
;
; 01/14/2004 - First version
; 21/09/2005 - Shengalts Aleksander aka Instructor (Shengalts@mail.ru)
; 03/06/2010 - Afrow UK


!define SHELLLINKTEST "$EXEDIR\ShellLinkTest.lnk"

Name "Shell Link Example"
OutFile "ShellLink.exe"
ShowInstDetails show

Section "Shell Link Test"

	; Create test shortcut
	SetOutPath "${NSISDIR}"
	CreateShortCut "${SHELLLINKTEST}" "${NSISDIR}\makensisw.exe" \
		"/parameter1 /parameter2" "${NSISDIR}\makensisw.exe" 2 SW_SHOWNORMAL \
		"ALT|CTRL|SHIFT|F5" "a description"
	DetailPrint ""

	; Get Shortcut Working Directory
	ShellLink::GetShortCutWorkingDirectory "${SHELLLINKTEST}"
	Pop $0
	DetailPrint "GetWorkingDirectory: $0"

	; Get Shortcut Target
	ShellLink::GetShortCutTarget "${SHELLLINKTEST}"
	Pop $0
	DetailPrint "GetTarget: $0"

	; Get Shortcut Arguments
	ShellLink::GetShortCutArgs "${SHELLLINKTEST}"
	Pop $0
	DetailPrint "GetArgs: $0"

	; Get Shortcut Icon Location
	ShellLink::GetShortCutIconLocation "${SHELLLINKTEST}"
	Pop $0
	DetailPrint "GetIconLocation: $0"

	; Get Shortcut Icon Index
	ShellLink::GetShortCutIconIndex "${SHELLLINKTEST}"
	Pop $0
	DetailPrint "GetIconIndex: $0"

	; Get Shortcut Show Mode
	ShellLink::GetShortCutShowMode "${SHELLLINKTEST}"
	Pop $0
	DetailPrint "GetShowMode: $0"

	; Get Shortcut Hotkey(s)
	ShellLink::GetShortCutHotkey "${SHELLLINKTEST}"
	Pop $0
	DetailPrint "GetHotkey: $0"

	; Get Shortcut Description
	ShellLink::GetShortCutDescription "${SHELLLINKTEST}"
	Pop $0
	DetailPrint "GetDescriptions: $0"
	DetailPrint ""


	; Set Shortcut Working Directory
	ShellLink::SetShortCutWorkingDirectory "${SHELLLINKTEST}" "$TEMP"
	Pop $0
	DetailPrint "SetWorkingDirectory: $0"

	; Set Shortcut Target
	ShellLink::SetShortCutTarget "${SHELLLINKTEST}" "${NSISDIR}\NSIS.exe"
	Pop $0
	DetailPrint "SetTarget: $0"

	; Set Shortcut Arguments
	ShellLink::SetShortCutArgs "${SHELLLINKTEST}" "-a -b -c"
	Pop $0
	DetailPrint "SetArgs: $0"

	; Set Shortcut Icon Location
	ShellLink::SetShortCutIconLocation "${SHELLLINKTEST}" "$SYSDIR\shell32.dll"
	Pop $0
	DetailPrint "SetIconLocation: $0"

	; Set Shortcut Icon Index
	ShellLink::SetShortCutIconIndex "${SHELLLINKTEST}" "41"
	Pop $0
	DetailPrint "SetIconIndex: $0"

	; Set Shortcut Show Mode
	ShellLink::SetShortCutShowMode "${SHELLLINKTEST}" "7"
	Pop $0
	DetailPrint "SetShowMode: $0"

	; Set Shortcut Hotkey(s)
	ShellLink::SetShortCutHotkey "${SHELLLINKTEST}" "634"
	Pop $0
	DetailPrint "SetHotkey: $0"

	; Set Shortcut Description
	ShellLink::SetShortCutDescription "${SHELLLINKTEST}" "Some Description"
	Pop $0
	DetailPrint "SetDescriptions: $0"
	DetailPrint ""

	; Set Shortcut to Run As Administrator
	ShellLink::SetRunAsAdministrator "${SHELLLINKTEST}"
	Pop $0
	DetailPrint "SetRunAsAdministrator: $0"
	DetailPrint ""

SectionEnd

; eof