; RamiBot Inno Setup Script
; Requires Inno Setup 6.1+
; Compile with: ISCC.exe installer\ramibot-setup.iss

#define AppName "RamiBot"
#define AppVersion "3.8.0"
#define AppPublisher "RamiBot Project"

[Setup]
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
AppId={{B4E3A1C2-7F9D-4E2B-A8C5-1D6F3E9B2A47}
DefaultDirName={userdocs}\RamiBot
DefaultGroupName=RamiBot
PrivilegesRequired=lowest
OutputBaseFilename=RamiBot-Setup-v{#AppVersion}
OutputDir=.
SetupIconFile=..\frontend\public\favicon.ico
WizardStyle=modern
WizardImageFile=wizard_large.bmp
WizardSmallImageFile=wizard_small.bmp
Compression=lzma2/ultra
SolidCompression=yes
DisableProgramGroupPage=no
DisableWelcomePage=no
AllowNoIcons=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Messages]
FinishedLabel=Installation complete. You can now start RamiBot from the desktop shortcut.%nNote: Make sure Docker Desktop is running before launching RamiBot.

[Files]
; Backend — exclude generated artefacts
Source: "..\backend\*"; DestDir: "{app}\backend"; \
  Excludes: ".venv,__pycache__,*.pyc,*.db,*.db-shm,*.db-wal,*.log,settings.json,skill_decisions.log"; \
  Flags: recursesubdirs createallsubdirs ignoreversion

; Frontend — exclude generated artefacts
Source: "..\frontend\*"; DestDir: "{app}\frontend"; \
  Excludes: "node_modules,dist"; \
  Flags: recursesubdirs createallsubdirs ignoreversion

; Rami-Kali container config and server
Source: "..\rami-kali\*"; DestDir: "{app}\rami-kali"; \
  Flags: recursesubdirs createallsubdirs ignoreversion

; Assets
Source: "..\assets\*"; DestDir: "{app}\assets"; \
  Flags: recursesubdirs createallsubdirs ignoreversion

; Root-level files
Source: "..\install.bat"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\start.bat";   DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md";   DestDir: "{app}"; Flags: ignoreversion isreadme
Source: "..\LICENSE";     DestDir: "{app}"; Flags: ignoreversion
Source: "..\Makefile";    DestDir: "{app}"; Flags: ignoreversion
Source: "..\.gitattributes"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\.env.example";   DestDir: "{app}"; Flags: ignoreversion

[Icons]
; Desktop shortcut
Name: "{userdesktop}\Iniciar RamiBot"; \
  Filename: "{app}\start.bat"; \
  WorkingDir: "{app}"; \
  IconFilename: "{app}\frontend\public\favicon.ico"; \
  Comment: "Launch RamiBot (backend + frontend)"

; Start Menu folder
Name: "{group}\Iniciar RamiBot"; \
  Filename: "{app}\start.bat"; \
  WorkingDir: "{app}"; \
  IconFilename: "{app}\frontend\public\favicon.ico"; \
  Comment: "Launch RamiBot (backend + frontend)"

Name: "{group}\Desinstalar RamiBot"; \
  Filename: "{uninstallexe}"; \
  Comment: "Uninstall RamiBot"

[UninstallDelete]
; Remove generated files on uninstall (but NOT settings.json or ramibot.db — user data)
Type: filesandordirs; Name: "{app}\backend\__pycache__"
Type: filesandordirs; Name: "{app}\frontend\node_modules"
Type: filesandordirs; Name: "{app}\frontend\dist"
Type: filesandordirs; Name: "{app}\backend\.venv"

[Code]

var
  PythonWasInstalled: Boolean;
  NodeWasInstalled:   Boolean;
  DepNoticeShown:     Boolean;

// ---------------------------------------------------------------------------
// Helper: extract major version from "Python 3.12.9" or "v22.15.0" strings
// ---------------------------------------------------------------------------
function ParseMajorVersion(VerStr: String): Integer;
var
  i, DotPos: Integer;
  NumStr: String;
begin
  Result := 0;
  for i := 1 to Length(VerStr) do
  begin
    if (VerStr[i] >= '0') and (VerStr[i] <= '9') then
    begin
      NumStr := '';
      DotPos := i;
      while (DotPos <= Length(VerStr)) and (VerStr[DotPos] >= '0') and (VerStr[DotPos] <= '9') do
      begin
        NumStr := NumStr + VerStr[DotPos];
        DotPos := DotPos + 1;
      end;
      if NumStr <> '' then
      begin
        Result := StrToIntDef(NumStr, 0);
        Exit;
      end;
    end;
  end;
end;

// ---------------------------------------------------------------------------
// Helper: run a command capturing stdout; return first line
// ---------------------------------------------------------------------------
function GetCommandOutput(Cmd, Params: String): String;
var
  TmpFile: String;
  ResultCode: Integer;
  Lines: TArrayOfString;
begin
  Result := '';
  TmpFile := ExpandConstant('{tmp}\cmdout.txt');
  Exec('cmd.exe', '/c ' + Cmd + ' ' + Params + ' > "' + TmpFile + '" 2>&1',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  if LoadStringsFromFile(TmpFile, Lines) and (GetArrayLength(Lines) > 0) then
    Result := Lines[0];
end;

// ---------------------------------------------------------------------------
// CheckDocker
// ---------------------------------------------------------------------------
function CheckDocker: Boolean;
var
  Output: String;
  ResultCode: Integer;
begin
  Exec('cmd.exe', '/c docker --version > nul 2>&1',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  if ResultCode <> 0 then begin Result := False; Exit; end;
  Output := GetCommandOutput('docker', '--version');
  Result := (Pos('Docker', Output) > 0) or (Pos('docker', Output) > 0);
end;

// ---------------------------------------------------------------------------
// CheckPython — returns major version (0 = not found or Store stub)
// Uses an actual execution sanity check (import sys) to avoid false positives
// from the py launcher reporting a version when no Python is truly installed.
// ---------------------------------------------------------------------------
function CheckPython: Integer;
var
  Output, WherePath: String;
  SanityCode: Integer;
begin
  Result := 0;

  // --- Try 'python' first ---
  // Sanity: actually run Python, not just --version (avoids Store stub / broken installs)
  Exec('cmd.exe', '/c python -c "import sys" >nul 2>&1',
       '', SW_HIDE, ewWaitUntilTerminated, SanityCode);
  if SanityCode = 0 then
  begin
    // Confirm it is not the Windows Store stub
    WherePath := GetCommandOutput('where', 'python');
    if Pos('WindowsApps', WherePath) = 0 then
    begin
      Output := GetCommandOutput('python', '--version');
      if Pos('Python', Output) > 0 then
      begin
        Result := ParseMajorVersion(Output);
        Exit;
      end;
    end;
  end;

  // --- Try 'py' launcher ---
  // Same sanity: if py exists but points to a broken / other-user install,
  // the import will fail and we correctly return 0.
  Exec('cmd.exe', '/c py -c "import sys" >nul 2>&1',
       '', SW_HIDE, ewWaitUntilTerminated, SanityCode);
  if SanityCode = 0 then
  begin
    Output := GetCommandOutput('py', '--version');
    if Pos('Python', Output) > 0 then
      Result := ParseMajorVersion(Output);
  end;
end;

// ---------------------------------------------------------------------------
// CheckNode — returns major version (0 = not found)
// ---------------------------------------------------------------------------
function CheckNode: Integer;
var
  Output: String;
begin
  Output := GetCommandOutput('node', '--version');
  if Length(Output) = 0 then begin Result := 0; Exit; end;
  if Output[1] = 'v' then Result := ParseMajorVersion(Copy(Output, 2, Length(Output)))
  else Result := ParseMajorVersion(Output);
end;

// ---------------------------------------------------------------------------
// InstallPython312
// ---------------------------------------------------------------------------
procedure InstallPython312;
var
  PythonExe: String;
  ResultCode: Integer;
begin
  PythonExe := ExpandConstant('{tmp}\python-3.12.9-amd64.exe');
  if not FileExists(PythonExe) then
    DownloadTemporaryFile(
      'https://www.python.org/ftp/python/3.12.9/python-3.12.9-amd64.exe',
      'python-3.12.9-amd64.exe', '', nil);

  if not FileExists(PythonExe) then
  begin
    MsgBox('Failed to download the Python installer.' + #13#10#13#10 +
           'Please check your internet connection and try again,' + #13#10 +
           'or install Python 3.9+ manually from python.org.',
           mbError, MB_OK);
    Exit;
  end;

  MsgBox('Python will now be installed using the official installer.' + #13#10 +
         'Please follow the steps in the Python setup wizard.' + #13#10#13#10 +
         'IMPORTANT: Check "Add Python to PATH" if prompted.',
         mbInformation, MB_OK);

  Exec(PythonExe, 'PrependPath=1',
       '', SW_SHOW, ewWaitUntilTerminated, ResultCode);

  if ResultCode <> 0 then
    MsgBox('Python installation returned exit code ' + IntToStr(ResultCode) + '.' + #13#10 +
           'If Python was not installed correctly, please install it manually from python.org.',
           mbError, MB_OK);
end;

// ---------------------------------------------------------------------------
// InstallNode22
// ---------------------------------------------------------------------------
procedure InstallNode22;
var
  NodeMsi: String;
  ResultCode: Integer;
begin
  NodeMsi := ExpandConstant('{tmp}\node-v22.15.0-x64.msi');
  if not FileExists(NodeMsi) then
    DownloadTemporaryFile(
      'https://nodejs.org/dist/v22.15.0/node-v22.15.0-x64.msi',
      'node-v22.15.0-x64.msi', '', nil);

  MsgBox('Node.js will now be installed using the official installer.' + #13#10 +
         'Please follow the steps in the Node.js setup wizard.',
         mbInformation, MB_OK);

  Exec('msiexec.exe', '/i "' + NodeMsi + '"',
       '', SW_SHOW, ewWaitUntilTerminated, ResultCode);

  if ResultCode <> 0 then
    MsgBox('Node.js installation returned exit code ' + IntToStr(ResultCode) + '.' + #13#10 +
           'If Node.js was not installed correctly, please install it manually from nodejs.org.',
           mbError, MB_OK);
end;

// ---------------------------------------------------------------------------
// InitializeSetup — prerequisite gate
// ---------------------------------------------------------------------------
function InitializeSetup: Boolean;
var
  PythonVer, NodeVer, ResultCode: Integer;
begin
  Result := True;
  PythonWasInstalled := False;
  NodeWasInstalled   := False;
  DepNoticeShown     := False;

  // Docker (hard requirement)
  if not CheckDocker then
  begin
    if MsgBox('Docker Desktop is required to run RamiBot.' + #13#10#13#10 +
              'Click OK to open the Docker Desktop download page in your browser.' + #13#10 +
              'Click Cancel to close this installer.',
              mbError, MB_OKCANCEL) = IDOK then
      ShellExec('open', 'https://docs.docker.com/desktop/setup/install/windows-install/',
                '', '', SW_SHOW, ewNoWait, ResultCode);
    Result := False;
    Exit;
  end;

  // Python
  PythonVer := CheckPython;
  if PythonVer < 3 then
  begin
    if not DepNoticeShown then
    begin
      MsgBox('RamiBot will install official dependencies using their official installers.' + #13#10 +
             'No files will be installed silently.',
             mbInformation, MB_OK);
      DepNoticeShown := True;
    end;
    if MsgBox('Python 3.9 or newer was not found.' + #13#10#13#10 +
              'Click OK to download and install Python 3.12.9.' + #13#10 +
              'Click Cancel to abort.',
              mbConfirmation, MB_OKCANCEL) = IDOK then
    begin
      InstallPython312;
      PythonWasInstalled := True;
    end
    else begin Result := False; Exit; end;
  end;

  // Node.js
  NodeVer := CheckNode;
  if NodeVer < 18 then
  begin
    if not DepNoticeShown then
    begin
      MsgBox('RamiBot will install official dependencies using their official installers.' + #13#10 +
             'No files will be installed silently.',
             mbInformation, MB_OK);
      DepNoticeShown := True;
    end;
    if MsgBox('Node.js 18 or newer was not found.' + #13#10#13#10 +
              'Click OK to download and install Node.js 22 LTS.' + #13#10 +
              'Click Cancel to abort.',
              mbConfirmation, MB_OKCANCEL) = IDOK then
    begin
      InstallNode22;
      NodeWasInstalled := True;
    end
    else begin Result := False; Exit; end;
  end;

  // Abort if PATH needs refresh
  if PythonWasInstalled or NodeWasInstalled then
  begin
    MsgBox('Python and/or Node.js were just installed.' + #13#10#13#10 +
           'Please restart the installer to continue.' + #13#10 +
           'A new session is required for the PATH changes to take effect.' + #13#10#13#10 +
           'TIP: If Python is still not found after restarting, go to:' + #13#10 +
           'Settings > Apps > App execution aliases' + #13#10 +
           'and disable the "python.exe" and "python3.exe" entries.',
           mbInformation, MB_OK);
    Result := False;
    Exit;
  end;
end;

// ---------------------------------------------------------------------------
// SetProgress — update wizard status label and progress bar
// ---------------------------------------------------------------------------
procedure SetProgress(const Msg: String; Step, Total: Integer);
begin
  WizardForm.StatusLabel.Caption := Msg;
  WizardForm.ProgressGauge.Position :=
    (Step * WizardForm.ProgressGauge.Max) div Total;
end;

// ---------------------------------------------------------------------------
// CurStepChanged — run install steps with progress UI after files are copied
// ---------------------------------------------------------------------------
procedure CurStepChanged(CurStep: TSetupStep);
var
  AppDir: String;
  ResultCode: Integer;
begin
  if CurStep <> ssPostInstall then Exit;

  AppDir := ExpandConstant('{app}');

  SetProgress('Installing RamiBot dependencies...', 0, 1);

  Exec('cmd.exe', '/c "' + AppDir + '\install.bat"',
       AppDir, SW_SHOW, ewWaitUntilTerminated, ResultCode);

  if ResultCode <> 0 then
  begin
    MsgBox('Installation failed (exit code ' + IntToStr(ResultCode) + ').' + #13#10#13#10 +
           'You can retry manually by running install.bat from the RamiBot folder.',
           mbError, MB_OK);
    Exit;
  end;

  SetProgress('Installation complete.', 1, 1);
end;
