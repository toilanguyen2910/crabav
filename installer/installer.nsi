; CrabAV Windows Installer Script (NSIS)
; Build with: makensis installer.nsi

!define PRODUCT_NAME "CrabAV"
!define PRODUCT_VERSION "0.2.0"
!define PRODUCT_PUBLISHER "Súp Cua AI"
!define PRODUCT_WEB_SITE "https://github.com/toilanguyen2910/crabav"
!define PRODUCT_DIR_REGKEY "Software\Microsoft\Windows\CurrentVersion\App Paths\CrabAV.exe"
!define PRODUCT_UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"

SetCompressor lzma

; ── Modern UI ───────────────────────────────────────────────────
!include "MUI2.nsh"
!include "FileFunc.nsh"

!define MUI_ABORTWARNING
!define MUI_ICON "..\ui\public\icon.ico"
!define MUI_UNICON "..\ui\public\icon.ico"

; Pages
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "..\LICENSE"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

; ── Installer ──────────────────────────────────────────────────
Name "${PRODUCT_NAME} ${PRODUCT_VERSION}"
OutFile "CrabAV-Setup-${PRODUCT_VERSION}.exe"
InstallDir "$PROGRAMFILES\CrabAV"
InstallDirRegKey HKLM "${PRODUCT_DIR_REGKEY}" ""
ShowInstDetails show
ShowUnInstDetails show

Section "CrabAV (required)" SecCore
  SectionIn RO

  SetOutPath "$INSTDIR"

  ; Backend files
  File /r "..\src\"
  File "..\config.yaml"
  File "..\requirements.txt"

  ; UI build
  File /r "..\ui\build\"
  File /r "..\ui\electron\"
  File "..\ui\package.json"

  ; Rules
  File /r "..\rules\"

  ; Create data directories
  CreateDirectory "$INSTDIR\data"
  CreateDirectory "$INSTDIR\data\quarantine"
  CreateDirectory "$INSTDIR\data\backups"
  CreateDirectory "$INSTDIR\data\signatures"
  CreateDirectory "$INSTDIR\logs"

  ; Create shortcuts
  CreateDirectory "$SMPROGRAMS\CrabAV"
  CreateShortCut "$SMPROGRAMS\CrabAV\CrabAV.lnk" "$INSTDIR\CrabAV.exe"
  CreateShortCut "$DESKTOP\CrabAV.lnk" "$INSTDIR\CrabAV.exe"

  ; Register uninstaller
  WriteUninstaller "$INSTDIR\uninst.exe"

  WriteRegStr HKLM "${PRODUCT_DIR_REGKEY}" "" "$INSTDIR\CrabAV.exe"
  WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "DisplayName" "$(^Name)"
  WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "UninstallString" "$INSTDIR\uninst.exe"
  WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "DisplayIcon" "$INSTDIR\CrabAV.exe"
  WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "DisplayVersion" "${PRODUCT_VERSION}"
  WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "Publisher" "${PRODUCT_PUBLISHER}"
  WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "URLInfoAbout" "${PRODUCT_WEB_SITE}"

  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  IntFmt $0 "0x%08X" $0
  WriteRegDWORD HKLM "${PRODUCT_UNINST_KEY}" "EstimatedSize" "$0"
SectionEnd

; ── Uninstaller ─────────────────────────────────────────────────
Section Uninstall
  RMDir /r "$INSTDIR\src"
  RMDir /r "$INSTDIR\ui"
  RMDir /r "$INSTDIR\rules"
  RMDir /r "$INSTDIR\data"
  RMDir /r "$INSTDIR\logs"
  Delete "$INSTDIR\config.yaml"
  Delete "$INSTDIR\requirements.txt"
  Delete "$INSTDIR\uninst.exe"
  RMDir "$INSTDIR"

  Delete "$SMPROGRAMS\CrabAV\CrabAV.lnk"
  RMDir "$SMPROGRAMS\CrabAV"
  Delete "$DESKTOP\CrabAV.lnk"

  DeleteRegKey HKLM "${PRODUCT_UNINST_KEY}"
  DeleteRegKey HKLM "${PRODUCT_DIR_REGKEY}"
SectionEnd
