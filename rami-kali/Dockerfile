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

# ── Force official Kali mirror — CDN mirrors (mirror.es.cdn-perfprod.com etc.)
#    have intermittent SSL failures; http.kali.org is authoritative and stable.
RUN echo "deb http://kali.download/kali kali-rolling main non-free contrib" > /etc/apt/sources.list \
    && echo 'Acquire::Retries "5";' > /etc/apt/apt.conf.d/80retries

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
        theharvester \
        \
        # ── Active scanning ─────────────────────────────── \
        nmap \
        masscan \
        nikto \
        gobuster \
        ffuf \
        dirb \
        wfuzz \
        enum4linux \
        nuclei \
        \
        # ── Proxy routing ───────────────────────────────── \
        proxychains4 \
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

# ── 3. Quality-of-life / shell comfort tools ───────────────────────────────
#
# Standard utilities present in a normal Kali install that
# --no-install-recommends strips out.
#
RUN apt-get update && apt-get install -y --no-install-recommends \
        \
        # ── Editors ─────────────────────────────────────── \
        nano \
        vim-tiny \
        \
        # ── Network utilities ───────────────────────────── \
        iputils-ping \
        net-tools \
        iproute2 \
        dnsutils \
        traceroute \
        telnet \
        socat \
        openssh-client \
        \
        # ── Shell / terminal comfort ─────────────────────── \
        zsh \
        zsh-syntax-highlighting \
        zsh-autosuggestions \
        bash-completion \
        less \
        tree \
        file \
        lsof \
        procps \
        man-db \
        \
        # ── Archive / transfer ───────────────────────────── \
        zip \
        unzip \
        p7zip-full \
        rsync \
        \
        # ── Misc dev tools ───────────────────────────────── \
        jq \
        xxd \
        binutils \
        tmux \
    && rm -rf /var/lib/apt/lists/*

# ── Shell history + readline (arrow-up navigation in terminal) ──────────────
RUN echo 'export HISTFILE=/root/.bash_history' >> /root/.bashrc \
    && echo 'export HISTSIZE=5000' >> /root/.bashrc \
    && echo 'export HISTFILESIZE=10000' >> /root/.bashrc \
    && echo 'export HISTCONTROL=ignoredups:erasedups' >> /root/.bashrc \
    && echo 'shopt -s histappend' >> /root/.bashrc \
    && echo 'PROMPT_COMMAND="history -a; history -c; history -r; $PROMPT_COMMAND"' >> /root/.bashrc \
    && echo 'source /usr/share/bash-completion/bash_completion 2>/dev/null || true' >> /root/.bashrc

# proxychains4 configs:
#   proxychains <tool>                                    → Burp en Windows (análisis, sin anonimato)
#   proxychains -f /etc/proxychains4-tor.conf <tool>     → Tor dentro del contenedor (anónimo, sin análisis Burp)
#
#   Para análisis Burp + anonimato Tor (mejor opción):
#     1. Activa Tor desde RamiBot (expone SOCKS en 127.0.0.1:9050 vía network_mode:host)
#     2. En Burp Suite (Windows): Settings → Network → Connections → SOCKS proxy → 127.0.0.1:9050
#     3. Usa proxychains normalmente → tool → Burp → Tor → internet
RUN sed -i 's/^socks4\s.*/# &/' /etc/proxychains4.conf \
    && echo 'http    host.docker.internal  8080' >> /etc/proxychains4.conf \
    && cp /etc/proxychains4.conf /etc/proxychains4-tor.conf \
    && sed -i 's/^http.*/# &/' /etc/proxychains4-tor.conf \
    && echo 'socks5  127.0.0.1  9050' >> /etc/proxychains4-tor.conf

# inputrc: arrow-up/down search history by prefix already typed (bash fallback)
RUN printf '"\e[A": history-search-backward\n"\e[B": history-search-forward\n"\eOA": history-search-backward\n"\eOB": history-search-forward\nset show-all-if-ambiguous on\nset completion-ignore-case on\n' > /root/.inputrc

# zsh config: syntax highlighting + autosuggestions + history navigation
RUN echo 'source /usr/share/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh' >> /root/.zshrc \
    && echo 'source /usr/share/zsh-autosuggestions/zsh-autosuggestions.zsh' >> /root/.zshrc \
    && echo 'export HISTFILE=/root/.zsh_history' >> /root/.zshrc \
    && echo 'export HISTSIZE=5000' >> /root/.zshrc \
    && echo 'export SAVEHIST=10000' >> /root/.zshrc \
    && echo 'setopt HIST_IGNORE_DUPS HIST_APPEND INC_APPEND_HISTORY SHARE_HISTORY' >> /root/.zshrc \
    && echo 'autoload -Uz compinit && compinit' >> /root/.zshrc \
    && echo 'bindkey "^[[A" history-search-backward' >> /root/.zshrc \
    && echo 'bindkey "^[[B" history-search-forward' >> /root/.zshrc \
    && echo 'bindkey "^[OA" history-search-backward' >> /root/.zshrc \
    && echo 'bindkey "^[OB" history-search-forward' >> /root/.zshrc \
    && echo 'ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE="fg=8"' >> /root/.zshrc \
    && chsh -s /bin/zsh root

# ── pip-only tools (not in Kali repos) ───────────────────────────────────
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
