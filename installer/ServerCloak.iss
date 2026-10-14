; Inno Setup 6 script. Built by publish.ps1 when Inno Setup is installed:
;   ISCC.exe /DAppVersion=3.0.0 /DPublishDir=..\publish installer\ServerCloak.iss
; Add /DSign plus /Ssigntool=... to sign the installer and uninstaller.

#ifndef AppVersion
  #define AppVersion "3.0.0"
#endif
#ifndef PublishDir
  #define PublishDir "..\publish"
#endif

[Setup]
AppId={{6D3F2B8E-6A57-4C1B-9B7E-2E5C3B9D41A7}
AppName=ServerCloak
AppVersion={#AppVersion}
AppVerName=ServerCloak {#AppVersion}
AppPublisher=Vikas Rana
AppPublisherURL=https://github.com/vikasrulez/ServerCloak
DefaultDirName={autopf}\ServerCloak
DefaultGroupName=ServerCloak
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Windows Server 2016 / Windows 10 1607
MinVersion=10.0.14393
OutputDir=..\publish-installer
OutputBaseFilename=ServerCloak-Setup-{#AppVersion}
SetupIconFile=..\assets\ServerCloak.ico
UninstallDisplayIcon={app}\ServerCloak.exe
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
RestartApplications=no
LicenseFile=..\LICENSE
#ifdef Sign
SignTool=signtool
SignedUninstaller=yes
#endif

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked

[Files]
Source: "{#PublishDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\ServerCloak"; Filename: "{app}\ServerCloak.exe"
Name: "{autodesktop}\ServerCloak"; Filename: "{app}\ServerCloak.exe"; Tasks: desktopicon

[Run]
; Installs the service on first install, or starts it again after an upgrade.
Filename: "{app}\ServerCloakService.exe"; Parameters: "install"; Flags: runhidden waituntilterminated; StatusMsg: "Starting the ServerCloak service..."
Filename: "{app}\ServerCloak.exe"; Description: "Open ServerCloak"; Flags: postinstall nowait skipifsilent shellexec

[UninstallRun]
Filename: "{sys}\schtasks.exe"; Parameters: "/delete /f /tn ""ServerCloak Tray"""; Flags: runhidden; RunOnceId: "RemoveTrayTask"
Filename: "{app}\ServerCloakService.exe"; Parameters: "uninstall"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveService"

[Code]
// Stop the service and the app before files are replaced during an upgrade.
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  Exec(ExpandConstant('{sys}\sc.exe'), 'stop ServerCloakService', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(3000);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM ServerCloakService.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM ServerCloak.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Result := '';
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    if MsgBox('Delete the ServerCloak database and logs in ' + ExpandConstant('{commonappdata}\ServerCloak') + '?',
              mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
      DelTree(ExpandConstant('{commonappdata}\ServerCloak'), True, True, True);
end;
