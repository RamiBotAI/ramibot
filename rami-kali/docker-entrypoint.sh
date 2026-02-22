#!/bin/bash
# ============================================================================
# Rami-Kali MCP Server — Docker Entrypoint
# ============================================================================
# Runs startup checks and launches the MCP server.
# ============================================================================

set -e

BOLD='\033[1m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${BOLD}${CYAN}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║       Rami-Kali MCP Server v2.1 — Docker Edition      ║"
echo "║  For AUTHORIZED penetration testing & CTFs ONLY      ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Ensure data directories exist ──────────────────────────────────────────
mkdir -p "$(dirname "${MCP_DATABASE:-/opt/rami-kali/data/scan_results.db}")"
mkdir -p "${MCP_REPORT_DIR:-/opt/rami-kali/reports}"

# ── Tool availability check ───────────────────────────────────────────────
echo -e "${BOLD}[*] Checking installed tools...${NC}"

TOOLS=(
    # ── Recon / passive ──────────────────────────────────
    "nmap" "whatweb" "whois" "dig" "searchsploit"

    # ── Web scanning ─────────────────────────────────────
    "gobuster" "nikto" "dirb" "wfuzz" "wpscan" "joomscan"
    "zap-cli" "droopescan"

    # ── Exploitation ─────────────────────────────────────
    "sqlmap"

    # ── Credential attacks ───────────────────────────────
    "hydra" "medusa" "ncrack" "patator" "hashcat" "john"

    # ── SMB / AD enumeration ─────────────────────────────
    "enum4linux" "smbclient" "smbmap" "rpcclient"
    "crackmapexec" "evil-winrm" "bloodhound"

    # ── Impacket scripts ─────────────────────────────────
    "impacket-scripts" "psexec.py" "wmiexec.py"
    "smbexec.py" "secretsdump.py"

    # ── Frameworks / C2 ──────────────────────────────────
    "msfconsole" "msfvenom" "msfdb"
    "armitage" "veil"
    "beef-xss" "setoolkit"

    # ── MITM / network interception ──────────────────────
    "bettercap" "ettercap" "responder" "mitmproxy"
    "arpspoof" "dnsspoof" "sslstrip" "yersinia"

    # ── Wireless ─────────────────────────────────────────
    "aircrack-ng" "reaver" "bully" "wifite"
    "kismet" "mdk4" "pixiewps" "cowpatty"

    # ── Wordlist generators ──────────────────────────────
    "crunch" "cewl"

    # ── Network capture / analysis ───────────────────────
    "tshark" "tcpdump" "ngrep" "hping3" "fragrouter"
    "macchanger"

    # ── Utilities ────────────────────────────────────────
    "nc"
)

available=0
missing=0

for tool in "${TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        ((available++)) || true
    else
        echo -e "  ${YELLOW}[!] Not found: ${tool}${NC}"
        ((missing++)) || true
    fi
done

total=$((available + missing))
echo -e "  ${GREEN}[+] Tools available: ${available}/${total}${NC}"

if [ "$missing" -gt 0 ]; then
    echo -e "  ${YELLOW}[!] Missing tools will be hidden from the MCP tool list.${NC}"
fi

# ── Platform/commercial tools (never available in Docker) ──────────────────
echo ""
echo -e "  ${CYAN}[i] Not available in Docker (platform/commercial):${NC}"
echo -e "  ${CYAN}    mimikatz (Windows), cobaltstrike (commercial), burpsuite (GUI),${NC}"
echo -e "  ${CYAN}    powersploit (PowerShell), empire (deprecated), shellter (Windows),${NC}"
echo -e "  ${CYAN}    xhydra (GUI), pyrit/ewsa (deprecated)${NC}"

# ── Initialize Metasploit database if available ────────────────────────────
if command -v msfconsole &>/dev/null; then
    echo ""
    echo -e "${BOLD}[*] Initializing Metasploit database...${NC}"
    if service postgresql start 2>/dev/null; then
        msfdb init 2>/dev/null && \
            echo -e "  ${GREEN}[+] Metasploit database ready${NC}" || \
            echo -e "  ${YELLOW}[!] msfdb init failed — Metasploit will work without DB${NC}"
    else
        echo -e "  ${YELLOW}[!] PostgreSQL not running — Metasploit will work without DB${NC}"
    fi
fi

# ── Configuration summary ─────────────────────────────────────────────────
echo ""
echo -e "${BOLD}[*] Configuration:${NC}"
echo -e "  Config:    ${MCP_CONFIG_PATH:-/opt/rami-kali/config.yaml}"
echo -e "  Database:  ${MCP_DATABASE:-/opt/rami-kali/data/scan_results.db}"
echo -e "  Reports:   ${MCP_REPORT_DIR:-/opt/rami-kali/reports}"
echo -e "  Log level: ${MCP_LOG_LEVEL:-INFO}"
echo ""

# ── Knowledge base check ──────────────────────────────────────────────────
KB_DIR="/opt/rami-kali/knowledge"
if [ -d "$KB_DIR" ]; then
    kb_files=$(find "$KB_DIR" -name "*.md" | wc -l)
    echo -e "  ${GREEN}[+] Knowledge base: ${kb_files} files loaded${NC}"
else
    echo -e "  ${YELLOW}[!] Knowledge base not found at ${KB_DIR}${NC}"
fi

# ── Tor check ─────────────────────────────────────────────────────────────
if command -v tor &>/dev/null; then
    tor_ver=$(tor --version 2>/dev/null | head -1)
    echo -e "  ${GREEN}[+] Tor: ${tor_ver}${NC}"
    echo -e "  ${CYAN}[i] Transparent proxy ready (TransPort 9040, DNSPort 5353)${NC}"
else
    echo -e "  ${YELLOW}[!] Tor not found — transparent proxy unavailable${NC}"
fi

echo ""
echo -e "${BOLD}${GREEN}[*] Starting MCP server (stdin/stdout JSON-RPC)...${NC}"
echo -e "${BOLD}─────────────────────────────────────────────────────${NC}"
echo ""

# ── Launch the server ─────────────────────────────────────────────────────
exec python3 mcp_server.py "$@"
