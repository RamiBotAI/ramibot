@echo off
REM =============================================================================
REM RamiBot — Daily startup (Windows)
REM Usage: Double-click or run from cmd: start.bat
REM =============================================================================
cd /d "%~dp0"

echo.
echo [ramibot] ============================================================
echo [ramibot]  Starting RamiBot
echo [ramibot] ============================================================
echo.

REM =============================================================================
REM 1. Sanity checks
REM =============================================================================
echo [ramibot] Running sanity checks...

if not exist "backend\.venv\" (
    echo [ramibot] ERROR: backend\.venv not found - run install.bat first.
    goto :fail
)

if not exist "backend\settings.json" (
    echo [ramibot] ERROR: backend\settings.json not found - run install.bat first.
    goto :fail
)

if not exist "frontend\node_modules\" (
    echo [ramibot] ERROR: frontend\node_modules not found - run install.bat first.
    goto :fail
)

echo [ramibot] Sanity checks passed.
echo.

REM =============================================================================
REM 2. Ensure Docker Desktop is running
REM =============================================================================
echo [ramibot] Checking Docker daemon...
docker info >nul 2>&1
if not errorlevel 1 goto :docker_ready

echo [ramibot]   Docker not running - starting Docker Desktop...
start "" "C:\Program Files\Docker\Docker\Docker Desktop.exe"
echo [ramibot]   Waiting for Docker to start (up to 60s)...

:wait_docker
timeout /t 3 /nobreak >nul
docker info >nul 2>&1
if not errorlevel 1 goto :docker_ready
set /a DOCKER_WAITED+=3
if %DOCKER_WAITED% LSS 60 goto :wait_docker
echo [ramibot] ERROR: Docker did not start in time. Open Docker Desktop manually and re-run.
goto :fail

:docker_ready
echo [ramibot]   Docker daemon running ... OK
echo.

REM =============================================================================
REM 3. Ensure Docker Compose is available
REM =============================================================================
set "COMPOSE_CMD="
docker compose version >nul 2>&1
if not errorlevel 1 (
    set "COMPOSE_CMD=docker compose"
    goto :compose_ready
)
docker-compose --version >nul 2>&1
if not errorlevel 1 (
    set "COMPOSE_CMD=docker-compose"
    goto :compose_ready
)
echo [ramibot] ERROR: Docker Compose not found. Update Docker Desktop.
goto :fail

:compose_ready

REM =============================================================================
REM 4. Ensure rami-kali container is running
REM =============================================================================
echo [ramibot] Starting rami-kali container...
%COMPOSE_CMD% -f rami-kali\docker-compose.yml up -d
if errorlevel 1 (
    echo [ramibot] ERROR: Failed to start rami-kali container.
    goto :fail
)

echo [ramibot] Waiting for rami-kali to be ready (this may take several minutes on first run)...
:wait_kali
timeout /t 3 /nobreak >nul
docker ps --filter "name=rami-kali" --filter "status=running" > "%TEMP%\rami_ps.txt" 2>&1
findstr /c:"rami-kali" "%TEMP%\rami_ps.txt" >nul 2>&1
if not errorlevel 1 goto :container_ready
goto :wait_kali

:container_ready
echo [ramibot]   rami-kali is ready.
echo.

REM =============================================================================
REM 5. Start backend in a new terminal window
REM =============================================================================
echo [ramibot] Starting backend on http://localhost:8000 ...
start "RamiBot Backend" cmd /k "cd /d "%~dp0backend" && call .venv\Scripts\activate.bat && python -m uvicorn main:app --reload --port 8000"

REM =============================================================================
REM 6. Start frontend in a new terminal window
REM =============================================================================
echo [ramibot] Starting frontend on http://localhost:5173 ...
start "RamiBot Frontend" cmd /k "cd /d "%~dp0frontend" && call npm run dev"

REM =============================================================================
REM 7. Open browser after delay
REM =============================================================================
echo [ramibot] Opening browser in 4 seconds...
timeout /t 4 /nobreak >nul
start "" "http://localhost:5173"

REM =============================================================================
REM Done
REM =============================================================================
echo.
echo [ramibot] ============================================================
echo [ramibot]  RamiBot is starting up!
echo [ramibot] ============================================================
echo.
echo   Backend:   http://localhost:8000/docs
echo   Frontend:  http://localhost:5173
echo.
echo   Close the Backend / Frontend terminal windows to stop those services.
echo   rami-kali container stays running in the background.
echo.
pause
exit /b 0

:fail
echo.
echo [ramibot] Fix the error above and re-run start.bat
echo.
pause
exit /b 1
