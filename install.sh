#!/usr/bin/env bash
# =============================================================================
# RamiBot — One-shot installer (Linux / macOS)
# Usage: bash install.sh
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'

info()    { echo -e "${CYAN}[install]${NC} $*"; }
success() { echo -e "${GREEN}[install]${NC} $*"; }
warn()    { echo -e "${YELLOW}[install]${NC} $*"; }
error()   { echo -e "${RED}[install]${NC} $*"; }

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

# ── Check docker (with or without sudo) ──────────────────────────────────────
docker_ok() {
    docker info &>/dev/null 2>&1 || sudo docker info &>/dev/null 2>&1
}

# =============================================================================
# 1. Prerequisite checks (collect ALL failures before aborting)
# =============================================================================
info "Checking prerequisites..."
PREREQ_ERRORS=()

# Python 3.9+
if command -v python3 &>/dev/null; then
    PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
    PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)
    if [[ "$PY_MAJOR" -lt 3 ]] || ( [[ "$PY_MAJOR" -eq 3 ]] && [[ "$PY_MINOR" -lt 9 ]] ); then
        PREREQ_ERRORS+=("Python 3.9+ required (found $PY_VER)")
    else
        info "  Python $PY_VER ... OK"
    fi
else
    PREREQ_ERRORS+=("python3 not found — install Python 3.9+")
fi

# Node 18+
if command -v node &>/dev/null; then
    NODE_VER=$(node --version | sed 's/v//')
    NODE_MAJOR=$(echo "$NODE_VER" | cut -d. -f1)
    if [[ "$NODE_MAJOR" -lt 18 ]]; then
        PREREQ_ERRORS+=("Node.js 18+ required (found v$NODE_VER)")
    else
        info "  Node.js v$NODE_VER ... OK"
    fi
else
    PREREQ_ERRORS+=("node not found — install Node.js 18+")
fi

# npm
if command -v npm &>/dev/null; then
    info "  npm $(npm --version) ... OK"
else
    PREREQ_ERRORS+=("npm not found — install npm")
fi

# Docker — install if missing, then start
if ! command -v docker &>/dev/null; then
    warn "  Docker not found — installing..."
    if command -v apt-get &>/dev/null; then
        sudo apt-get update -qq && sudo apt-get install -y docker.io docker-compose
    elif command -v dnf &>/dev/null; then
        sudo dnf install -y docker docker-compose
    elif command -v pacman &>/dev/null; then
        sudo pacman -Sy --noconfirm docker docker-compose
    fi
fi

if ! command -v docker &>/dev/null; then
    PREREQ_ERRORS+=("Docker could not be installed — install manually: https://docs.docker.com/engine/install/")
else
    # Add current user to docker group (avoids needing sudo for docker commands)
    if ! groups | grep -q docker; then
        warn "  Adding $USER to docker group (no sudo needed after re-login)..."
        sudo usermod -aG docker "$USER" || true
    fi

    # Ensure daemon is running
    if docker_ok; then
        info "  Docker (daemon running) ... OK"
    else
        warn "  Docker daemon not running — starting..."
        if command -v systemctl &>/dev/null; then
            sudo systemctl enable docker &>/dev/null || true
            sudo systemctl start docker || true
        elif command -v service &>/dev/null; then
            sudo service docker start || true
        fi
        # Wait up to 20s for daemon to become ready
        WAITED=0
        while ! docker_ok; do
            sleep 2; WAITED=$((WAITED+2))
            [[ $WAITED -ge 20 ]] && break
        done
        if docker_ok; then
            success "  Docker daemon started."
        else
            PREREQ_ERRORS+=("Docker daemon could not be started — run: sudo systemctl start docker")
        fi
    fi
fi

# Docker Compose
COMPOSE_CMD=$(detect_compose)
if [[ -n "$COMPOSE_CMD" ]]; then
    info "  Docker Compose ($COMPOSE_CMD) ... OK"
else
    warn "  Docker Compose not found — attempting to install..."
    if command -v apt-get &>/dev/null; then
        sudo apt-get install -y docker-compose-plugin &>/dev/null || \
        sudo apt-get install -y docker-compose &>/dev/null || true
    elif command -v dnf &>/dev/null; then
        sudo dnf install -y docker-compose-plugin &>/dev/null || \
        sudo dnf install -y docker-compose &>/dev/null || true
    elif command -v pacman &>/dev/null; then
        sudo pacman -Sy --noconfirm docker-compose &>/dev/null || true
    fi
    COMPOSE_CMD=$(detect_compose)
    if [[ -n "$COMPOSE_CMD" ]]; then
        success "  Docker Compose installed ($COMPOSE_CMD)."
    else
        PREREQ_ERRORS+=("Docker Compose could not be installed — run: sudo apt-get install -y docker-compose")
    fi
fi

if [[ ${#PREREQ_ERRORS[@]} -gt 0 ]]; then
    error "Prerequisites check failed:"
    for e in "${PREREQ_ERRORS[@]}"; do
        error "  ✗ $e"
    done
    exit 1
fi
success "All prerequisites met."

# =============================================================================
# 2. Python virtual environment
# =============================================================================
if [[ ! -f "backend/.venv/bin/pip" ]]; then
    [[ -d "backend/.venv" ]] && { warn "backend/.venv exists but is invalid (wrong platform?) — recreating..."; rm -rf backend/.venv; }
    info "Creating Python virtual environment at backend/.venv ..."
    python3 -m venv backend/.venv
    success "Virtual environment created."
else
    info "backend/.venv already exists — skipping."
fi

# =============================================================================
# 3. Backend dependencies
# =============================================================================
info "Installing backend Python dependencies..."
backend/.venv/bin/pip install --quiet --upgrade pip
backend/.venv/bin/pip install --quiet -r backend/requirements.txt
success "Backend dependencies installed."

# =============================================================================
# 4. Frontend dependencies
# =============================================================================
info "Installing frontend npm dependencies..."
(cd frontend && npm install --silent)
success "Frontend dependencies installed."

# =============================================================================
# 5. Settings file (never overwrite)
# =============================================================================
if [[ ! -f "backend/settings.json" ]]; then
    info "Copying backend/settings.example.json → backend/settings.json ..."
    cp backend/settings.example.json backend/settings.json
    warn "IMPORTANT: Edit backend/settings.json and add your API keys before starting."
else
    info "backend/settings.json already exists — skipping (your config is preserved)."
fi

# =============================================================================
# 6. Docker image build
# =============================================================================
info "Building rami-kali Docker image (this may take several minutes on first run)..."
sudo docker build -t rami-kali rami-kali/
success "Docker image built."

# =============================================================================
# 7. Start container
# =============================================================================
info "Starting rami-kali container..."
sudo $COMPOSE_CMD -f rami-kali/docker-compose.yml up -d
success "rami-kali container is running."

# =============================================================================
# Done
# =============================================================================
echo ""
success "============================================================"
success " RamiBot installation complete!"
success "============================================================"
echo ""
echo -e "  ${YELLOW}Next steps:${NC}"
echo "  1. Edit backend/settings.json — add your LLM API key(s)"
echo "  2. Run:  bash start.sh"
echo "  3. Open: http://localhost:5173"
echo ""
