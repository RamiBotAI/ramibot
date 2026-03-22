#!/usr/bin/env bash
# =============================================================================
# RamiBot — Daily startup (Linux / macOS)
# Usage: bash start.sh
# Ctrl+C stops backend + frontend; rami-kali container stays running.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'

info()    { echo -e "${CYAN}[ramibot]${NC} $*"; }
success() { echo -e "${GREEN}[ramibot]${NC} $*"; }
warn()    { echo -e "${YELLOW}[ramibot]${NC} $*"; }
error()   { echo -e "${RED}[ramibot]${NC} $*"; }

# ── Detect docker compose command ────────────────────────────────────────────
detect_compose() {
    if docker compose version &>/dev/null 2>&1 || sudo docker compose version &>/dev/null 2>&1; then
        echo "docker compose"
    elif command -v docker-compose &>/dev/null; then
        echo "docker-compose"
    else
        echo ""
    fi
}

# ── Run docker with sudo fallback if user not in docker group yet ─────────────
DOCKER="docker"
docker info &>/dev/null 2>&1 || DOCKER="sudo docker"

# ── PIDs for cleanup ──────────────────────────────────────────────────────────
BACKEND_PID=""
FRONTEND_PID=""

cleanup() {
    echo ""
    info "Shutting down..."
    [[ -n "$BACKEND_PID" ]]  && kill "$BACKEND_PID"  2>/dev/null && info "  Backend stopped."
    [[ -n "$FRONTEND_PID" ]] && kill "$FRONTEND_PID" 2>/dev/null && info "  Frontend stopped."
    info "rami-kali container left running (restart: unless-stopped)."
    exit 0
}
trap cleanup SIGINT SIGTERM EXIT

# =============================================================================
# 1. Sanity checks
# =============================================================================
info "Running sanity checks..."
FAILED=0

if [[ ! -d "backend/.venv" ]]; then
    error "backend/.venv not found — run: bash install.sh"
    FAILED=1
fi

if [[ ! -f "backend/settings.json" ]]; then
    error "backend/settings.json not found — run: bash install.sh"
    FAILED=1
fi

if [[ ! -d "frontend/node_modules" ]]; then
    error "frontend/node_modules not found — run: bash install.sh"
    FAILED=1
fi

COMPOSE_CMD=$(detect_compose)
if [[ -z "$COMPOSE_CMD" ]]; then
    error "Docker Compose not found — install Docker Compose v2 plugin or docker-compose v1"
    FAILED=1
fi

if [[ $FAILED -eq 1 ]]; then
    exit 1
fi
success "Sanity checks passed."

# =============================================================================
# 2. Ensure rami-kali container is running
# =============================================================================
info "Checking rami-kali container..."
if $DOCKER ps --filter "name=^rami-kali$" --filter "status=running" --format "{{.Names}}" | grep -q "rami-kali"; then
    info "  rami-kali is already running."
else
    info "  rami-kali is not running — starting..."
    sudo $COMPOSE_CMD -f rami-kali/docker-compose.yml up -d
    success "  rami-kali started."
fi

# =============================================================================
# 3. Start backend
# =============================================================================
info "Starting backend on http://localhost:8000 ..."
(
    cd backend
    source .venv/bin/activate
    python -m uvicorn main:app --reload --port 8000
) &
BACKEND_PID=$!

# =============================================================================
# 4. Start frontend
# =============================================================================
info "Starting frontend on http://localhost:5173 ..."
(
    cd frontend
    npm run dev
) &
FRONTEND_PID=$!

# =============================================================================
# 5. Open browser (best-effort, non-fatal)
# =============================================================================
(
    sleep 4
    if command -v xdg-open &>/dev/null; then
        xdg-open "http://localhost:5173" &>/dev/null || true
    elif command -v open &>/dev/null; then
        open "http://localhost:5173" || true
    fi
) &

success "RamiBot is starting up!"
echo ""
echo -e "  Backend:  ${CYAN}http://localhost:8000/docs${NC}"
echo -e "  Frontend: ${CYAN}http://localhost:5173${NC}"
echo ""
echo "  Press Ctrl+C to stop backend and frontend."
echo "  (rami-kali container will remain running)"
echo ""

# Wait for either process to exit (unexpected crash)
wait -n "$BACKEND_PID" "$FRONTEND_PID" 2>/dev/null || true
