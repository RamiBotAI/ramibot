@echo off
REM =============================================================================
REM RamiBot — One-shot installer (Windows)
REM Usage: Double-click or run from cmd: install.bat
REM =============================================================================
cd /d "%~dp0"

echo.
echo [install] ============================================================
echo [install]  RamiBot Installer
echo [install] ============================================================
echo.
echo [install] Checking prerequisites...

REM ── Python 3.9+ ──────────────────────────────────────────────────────────────
echo [install]   Checking Python...
set PYTHON_CMD=
py --version >nul 2>&1
if not errorlevel 1 (
    set PYTHON_CMD=py
) else (
    python --version >nul 2>&1
    if not errorlevel 1 (
        set PYTHON_CMD=python
    )
)
if "%PYTHON_CMD%"=="" (
    echo [install]   ERROR: Python not found. Install Python 3.9+ from python.org and add to PATH.
    echo [install]   Also disable Python app execution aliases in: Settings ^> Apps ^> App execution aliases
    goto :fail
)
for /f "tokens=2 delims= " %%v in ('%PYTHON_CMD% --version 2^>^&1') do echo [install]   Python %%v ... OK ^(via %PYTHON_CMD%^)

REM ── Node.js 18+ ──────────────────────────────────────────────────────────────
echo [install]   Checking Node.js...
node --version >nul 2>&1
if errorlevel 1 (
    echo [install]   ERROR: node not found - install Node.js 18+.
    goto :fail
)
for /f %%v in ('node --version') do echo [install]   Node.js %%v ... OK

REM ── npm ──────────────────────────────────────────────────────────────────────
echo [install]   Checking npm...
call npm --version >nul 2>&1
if errorlevel 1 (
    echo [install]   ERROR: npm not found - reinstall Node.js.
    goto :fail
)
for /f %%v in ('npm --version') do echo [install]   npm %%v ... OK

echo [install] All prerequisites met.
echo.

REM =============================================================================
REM 2. Python virtual environment
REM =============================================================================
if exist "backend\.venv\" (
    echo [install] backend\.venv already exists - skipping.
    goto :venv_done
)
echo [install] Creating Python virtual environment...
%PYTHON_CMD% -m venv backend\.venv
if errorlevel 1 (
    echo [install] ERROR: Failed to create virtual environment.
    goto :fail
)
echo [install] Virtual environment created.
:venv_done

REM =============================================================================
REM 3. Backend Python dependencies
REM =============================================================================
echo [install] Installing backend dependencies...
call backend\.venv\Scripts\activate.bat
pip install --quiet --upgrade pip
pip install --quiet -r backend\requirements.txt
if errorlevel 1 (
    echo [install] ERROR: Failed to install backend dependencies.
    goto :fail
)
echo [install] Backend dependencies installed.

REM =============================================================================
REM 4. Frontend npm dependencies
REM =============================================================================
echo [install] Installing frontend dependencies...
cd frontend
call npm install --silent
if errorlevel 1 (
    echo [install] ERROR: Failed to install frontend dependencies.
    cd ..
    goto :fail
)
cd ..
echo [install] Frontend dependencies installed.

REM =============================================================================
REM 5. Settings file (never overwrite existing)
REM =============================================================================
if exist "backend\settings.json" (
    echo [install] backend\settings.json already exists - skipping ^(config preserved^).
    goto :settings_done
)
copy "backend\settings.example.json" "backend\settings.json" >nul
echo [install] Created backend\settings.json from template.
echo [install] IMPORTANT: Edit backend\settings.json and add your API keys.
:settings_done

REM =============================================================================
REM Done
REM =============================================================================
echo.
echo [install] Installation complete! You can now launch RamiBot from the desktop or Start Menu.
echo.
exit /b 0

:fail
echo.
echo [install] Installation failed. Fix the error above and re-run install.bat
echo.
pause
exit /b 1
