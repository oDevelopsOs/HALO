; =============================================================================
; AgentGuard — Inno Setup installer for Windows
; =============================================================================
;
; Build with: iscc /Qp packaging/windows/installer.iss
;
; Requirements:
;   - Inno Setup 6+ (https://jrsoftware.org/isdl.php)
;   - Pre-built binaries: agentguard.exe, agentguard-windows.exe
;   - EV code signing certificate (for SmartScreen)
; =============================================================================

#define AppName "AgentGuard"
#define AppVersion GetFileVersion("..\..\target\release\agentguard-windows.exe")
#define AppPublisher "AgentGuard Contributors"
#define AppURL "https://agentguard.io"
#define AppExeName "agentguard.exe"
#define DaemonExeName "agentguard-windows.exe"

[Setup]
AppId={{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}/docs
AppUpdatesURL={#AppURL}/releases
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
AllowNoIcons=yes
LicenseFile=..\..\LICENSE-BSL
OutputDir=..\..\target\release\installer
OutputBaseFilename=agentguard-setup-{#AppVersion}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
ArchitecturesAllowed=x64compatible

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; CLI binary
Source: "..\..\target\release\{#AppExeName}"; DestDir: "{app}"; Flags: ignoreversion signonce
; Daemon binary
Source: "..\..\target\release\{#DaemonExeName}"; DestDir: "{app}"; Flags: ignoreversion signonce
; Config template (generated at install time, not bundled)
; Licenses and docs
Source: "..\..\LICENSE-BSL"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\README.md"; DestDir: "{app}"; Flags: ignoreversion isreadme

[Icons]
Name: "{group}\{#AppName} Status"; Filename: "{cmd}"; Parameters: "/k ""{app}\{#AppExeName} status"""
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName} Status"; Filename: "{cmd}"; Parameters: "/k ""{app}\{#AppExeName} status"""; Tasks: desktopicon

[Registry]
; Register app path for CLI convenience (agentguard.exe available in PATH)
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; \
    ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; \
    Check: NeedsAddPath(ExpandConstant('{app}'))

[Run]
; Generate default config
Filename: "{app}\{#AppExeName}"; Parameters: "init --output ""{commonappdata}\{#AppName}\config.toml"""; \
    StatusMsg: "Generating default configuration..."; Flags: runhidden
; Register and start Windows Service
Filename: "sc.exe"; Parameters: "create ""{#AppName}"" binPath= ""{app}\{#DaemonExeName} --service"" start= auto type= own obj= LocalSystem"; \
    StatusMsg: "Registering Windows Service..."; Flags: runhidden
Filename: "sc.exe"; Parameters: "start ""{#AppName}"""; \
    StatusMsg: "Starting service..."; Flags: runhidden
; Add CA root to system trust store (if exists)
Filename: "certutil.exe"; Parameters: "-addstore -f ""ROOT"" ""{commonappdata}\{#AppName}\ca\root-cert.pem"""; \
    StatusMsg: "Adding CA to trust store..."; Flags: runhidden skipifdoesntexist

[UninstallRun]
; Stop and remove Windows Service
Filename: "sc.exe"; Parameters: "stop ""{#AppName}"""; Flags: runhidden
Filename: "sc.exe"; Parameters: "delete ""{#AppName}"""; Flags: runhidden
; Remove CA from trust store
Filename: "certutil.exe"; Parameters: "-delstore ""ROOT"" ""AgentGuard DLP Local Root CA"""; Flags: runhidden

[UninstallDelete]
; Clean up app data (user prompted)
Type: filesandordirs; Name: "{commonappdata}\{#AppName}"

[Code]
function NeedsAddPath(Param: string): boolean;
var
  OrigPath: string;
begin
  if not RegQueryStringValue(HKEY_LOCAL_MACHINE,
    'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
    'Path', OrigPath)
  then begin
    Result := True;
    exit;
  end;
  { look for the path with leading and trailing semicolon }
  { Pos() returns 0 if not found }
  Result := Pos(';' + Param + ';', ';' + OrigPath + ';') = 0;
end;
