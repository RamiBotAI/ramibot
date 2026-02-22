# ============================================================================
# Red Team MCP Server — Kali-based Docker Image
# ============================================================================
# Provides all penetration testing tools required by TOOL_BINARY_MAP plus
# the Python MCP server and tactical knowledge base.
#
# Usage:
#   docker build -t rami-kali .
#   docker compose up
# ============================================================================

FROM kalilinux/kali-rolling:latest

LABEL maintainer="rami-kali"
LABEL description="MCP server with Kali Linux penetration testing tools"
LABEL version="2.1.0"

# ── Avoid interactive prompts during install ────────────────────────────────
ENV DEBIAN_FRONTEND=noninteractive

# ── 1. System update + core utilities ───────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        wget \
        git \
        python3 \
        python3-pip \
        python3-venv \
        postgresql \
        postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# ── 2. Kali tools — grouped by category ────────────────────────────────────
#
# ~60 installable tools covering recon, exploitation, MITM, wireless,
# credential attacks, AD enumeration, C2 frameworks, and more.
#
# Category C tools (NOT installable — auto-hidden by check_available_binaries):
#   mimikatz, cobaltstrike, burpsuite, powersploit, empire, shellter,
#   pth-toolkit, xhydra (GUI), pyrit, ewsa, wifiphisher, fluxion,
#   airgeddon, wifi-honey, ghost-phisher, fern-wifi-cracker
#
RUN apt-get update && apt-get install -y --no-install-recommends \
        \
        # ── Recon / passive ─────────────────────────────── \
        whois \
        dnsutils \
        whatweb \
        exploitdb \
        \
        # ── Active scanning ─────────────────────────────── \
        nmap \
        nikto \
        gobuster \
        dirb \
        wfuzz \
        enum4linux \
        \
        # ── Exploitation / brute-force ──────────────────── \
        hydra \
        sqlmap \
        hashcat \
        john \
        netcat-traditional \
        \
        # ── SMB / AD enumeration ────────────────────────── \
        smbclient \
        smbmap \
        crackmapexec \
        python3-impacket \
        bloodhound \
        evil-winrm \
        \
        # ── Extra brute-force ───────────────────────────── \
        medusa \
        ncrack \
        patator \
        \
        # ── CMS scanners ───────────────────────────────── \
        wpscan \
        joomscan \
        \
        # ── Web app testing ─────────────────────────────── \
        zaproxy \
        \
        # ── Frameworks / C2 ─────────────────────────────── \
        metasploit-framework \
        beef-xss \
        set \
        veil \
        \
        # ── MITM / network interception ─────────────────── \
        bettercap \
        ettercap-text-only \
        responder \
        mitmproxy \
        dsniff \
        sslstrip \
        yersinia \
        tor \
        \
        # ── Wireless ────────────────────────────────────── \
        aircrack-ng \
        reaver \
        bully \
        wifite \
        kismet \
        mdk4 \
        pixiewps \
        cowpatty \
        \
        # ── Wordlist generators ─────────────────────────── \
        crunch \
        cewl \
        \
        # ── Network capture / analysis ──────────────────── \
        wireshark-common \
        tcpdump \
        ngrep \
        hping3 \
        fragrouter \
        macchanger \
        \
        # ── Wordlists ──────────────────────────────────── \
        seclists \
        wordlists \
    && rm -rf /var/lib/apt/lists/*

# ── 3. pip-only tools (not in Kali repos) ───────────────────────────────────
RUN pip3 install --no-cache-dir --break-system-packages \
        droopescan \
    || echo "pip installs partially failed (non-fatal)"
# Note: drupwn is no longer available on PyPI

# ── 4. Ensure rockyou.txt is decompressed ───────────────────────────────────
RUN if [ -f /usr/share/wordlists/rockyou.txt.gz ]; then \
        gunzip /usr/share/wordlists/rockyou.txt.gz; \
    fi

# ── Pre-configure Tor transparent proxy ────────────────────────────────────
# Directives required by RamiBot's tor_start() transparent proxy feature.
# _ensure_torrc() in terminal.py will detect these are already present (no-op).
RUN printf '\n# RamiBot transparent proxy\nTransPort 9040\nDNSPort 5353\nVirtualAddrNetworkIPv4 10.192.0.0/10\nAutomapHostsOnResolve 1\n' >> /etc/tor/torrc

# ── 5. Initialize Metasploit database ──────────────────────────────────────
RUN service postgresql start \
    && msfdb init \
    && service postgresql stop \
    || echo "msfdb init skipped (will retry at runtime)"

# ── 6. Application directory ───────────────────────────────────────────────
WORKDIR /opt/rami-kali

# ── 7. Python dependencies ─────────────────────────────────────────────────
COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

# ── 8. Application code + knowledge base ───────────────────────────────────
COPY config.yaml .
COPY mcp_server.py .
COPY knowledge/ knowledge/
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# ── 9. Runtime directories for volumes ─────────────────────────────────────
RUN mkdir -p /opt/rami-kali/reports /opt/rami-kali/data

# ── 10. Environment variable defaults ──────────────────────────────────────
#    All can be overridden in docker-compose.yml or with `docker run -e`
ENV MCP_CONFIG_PATH=/opt/rami-kali/config.yaml \
    MCP_LOG_LEVEL=INFO \
    MCP_DATABASE=/opt/rami-kali/data/scan_results.db \
    MCP_AUDIT_LOG=/opt/rami-kali/data/audit.log \
    MCP_REPORT_DIR=/opt/rami-kali/reports

# ── 11. Healthcheck ────────────────────────────────────────────────────────
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python3 -c "import sys; sys.exit(0)"

# ── 12. Entrypoint + default command ───────────────────────────────────────
ENTRYPOINT ["docker-entrypoint.sh"]
CMD []
