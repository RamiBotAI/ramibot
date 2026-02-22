# Rami-Kali — Complete Architecture Document

> **Purpose**: MCP (Model Context Protocol) server that wraps Kali Linux penetration testing tools for authorized security assessments.
> **Scope**: Authorized penetration testing, CTF competitions, security research, and defensive validation only.
> **Version**: 1.0.0

---

## Table of Contents

1. [Security Architecture](#1-security-architecture)
2. [Tool Catalog](#2-tool-catalog)
3. [Output Parsing](#3-output-parsing)
4. [Red Team Workflow Patterns](#4-red-team-workflow-patterns)
5. [MCP Server Implementation Details](#5-mcp-server-implementation-details)

---

## 1. Security Architecture

### 1.1 Core Security Principles

Every tool invocation MUST pass through these security layers in order:

```
Request → Authentication → Scope Validation → Input Sanitization → Rate Limiting → Command Construction → Execution → Audit Log → Response
```

### 1.2 Authentication

The MCP server requires a valid API key passed in the MCP session initialization. Keys are stored hashed (bcrypt) in a local config file.

```json
{
  "auth": {
    "type": "api_key",
    "header": "X-MCP-Auth-Token",
    "key_hash_file": "./config/authorized_keys.json",
    "session_timeout_minutes": 120
  }
}
```

### 1.3 Target Scope Enforcement

A mandatory configuration file defines allowed targets. **No tool can execute against a target outside the allowed scope.**

```json
{
  "scope": {
    "allowed_cidrs": [
      "10.0.0.0/8",
      "172.16.0.0/12",
      "192.168.0.0/16"
    ],
    "allowed_domains": [
      "*.target-corp.local",
      "testlab.example.com"
    ],
    "blocked_cidrs": [
      "10.0.0.1/32"
    ],
    "blocked_domains": [
      "production.target-corp.local"
    ],
    "allow_external": false
  }
}
```

**Scope validation logic** (applied before every tool execution):

1. Extract all target IPs/domains from tool parameters.
2. Resolve domains to IPs via DNS.
3. Check resolved IPs against `allowed_cidrs` (must match at least one).
4. Check resolved IPs against `blocked_cidrs` (must not match any).
5. Check domain names against `allowed_domains` (glob match).
6. Check domain names against `blocked_domains` (must not match any).
7. If `allow_external` is false, reject any target not in RFC 1918 ranges unless explicitly in `allowed_domains`.

### 1.4 Input Sanitization

#### Regex Whitelist Patterns

All user-supplied values are validated against strict regex patterns before being inserted into commands:

| Parameter Type | Regex Pattern | Example Valid | Example Rejected |
|---|---|---|---|
| IPv4 Address | `^(?:(?:25[0-5]\|2[0-4]\d\|[01]?\d\d?)\.){3}(?:25[0-5]\|2[0-4]\d\|[01]?\d\d?)$` | `192.168.1.1` | `192.168.1.1; rm -rf /` |
| IPv4 CIDR | `^(?:(?:25[0-5]\|2[0-4]\d\|[01]?\d\d?)\.){3}(?:25[0-5]\|2[0-4]\d\|[01]?\d\d?)\/(?:3[0-2]\|[12]?\d)$` | `10.0.0.0/24` | `10.0.0.0/24 && cat /etc/passwd` |
| Domain | `^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$` | `example.com` | `example.com\|nc attacker 4444` |
| Port | `^(?:[1-9]\d{0,3}\|[1-5]\d{4}\|6[0-4]\d{3}\|65[0-4]\d{2}\|655[0-2]\d\|6553[0-5])$` | `8080` | `8080; whoami` |
| Port Range | `^(?:[1-9]\d{0,3}\|[1-5]\d{4}\|6553[0-5])-(?:[1-9]\d{0,3}\|[1-5]\d{4}\|6553[0-5])$` | `1-1024` | `1-65535 --script=exploit` |
| URL Path | `^\/[a-zA-Z0-9_.~!$&'()*+,;=:@%/-]*$` | `/admin/login` | `/admin; cat /etc/shadow` |
| URL | `^https?:\/\/[a-zA-Z0-9.-]+(:\d{1,5})?(\/[a-zA-Z0-9_.~!$&'()*+,;=:@%/-]*)?(\?[a-zA-Z0-9_.~!$&'()*+,;=:@%/?-]*)?$` | `http://10.0.0.5:8080/app` | `http://evil.com\`cmd\`` |
| Filename | `^[a-zA-Z0-9_.-]{1,255}$` | `wordlist.txt` | `../../etc/passwd` |
| File Path (safe) | `^(?:\/(?:usr\/share\/(?:wordlists\|seclists\|nmap)\|tmp\/rami-kali)\/)[a-zA-Z0-9_./-]{1,500}$` | `/usr/share/wordlists/dirb/common.txt` | `/etc/shadow` |
| Hash Value | `^[a-fA-F0-9]{16,128}$` | `5f4dcc3b5aa765d61d8327deb882cf99` | `hash; rm -rf /` |
| Username | `^[a-zA-Z0-9._@\\-]{1,128}$` | `admin` | `admin$(whoami)` |
| NSE Script | `^[a-zA-Z0-9_,-]+$` | `vuln,safe` | `vuln --script-args="os.execute('rm')"` |

#### Command Injection Prevention

1. **Never use shell interpolation.** All commands are constructed as argument arrays, not shell strings.
2. **Use subprocess with `shell=False`.** Pass command + args as a list.
3. **Blacklist dangerous characters** in ALL parameters: `` ; | & ` $ ( ) { } < > \n \r ! # ~ ``
4. **Blacklist dangerous substrings**: `..`, `~/`, `/etc/`, `/root/`, `rm `, `mkfs`, `dd if=`, `chmod`, `chown`, `shutdown`, `reboot`, `&&`, `||`
5. **Environment variable stripping**: Remove all `$VAR` and `${VAR}` patterns from input.

```python
# Command construction pattern (Python example)
import subprocess

def execute_tool(cmd_args: list[str], timeout: int) -> str:
    """Execute tool with NO shell interpretation."""
    # cmd_args example: ["nmap", "-sS", "-p", "1-1024", "192.168.1.1"]
    result = subprocess.run(
        cmd_args,
        capture_output=True,
        text=True,
        timeout=timeout,
        shell=False,  # CRITICAL: never True
        env=SANITIZED_ENV  # minimal environment variables
    )
    return result.stdout
```

### 1.5 Rate Limiting

Per-tool rate limits to prevent accidental DoS:

| Tool | Max Concurrent | Max Per Minute | Cooldown (sec) |
|---|---|---|---|
| nmap | 2 | 5 | 5 |
| nikto | 1 | 3 | 10 |
| gobuster | 2 | 5 | 5 |
| sqlmap | 1 | 2 | 15 |
| hydra | 1 | 2 | 15 |
| enum4linux | 1 | 5 | 5 |
| wfuzz | 1 | 3 | 10 |
| netcat | 1 | 10 | 2 |
| searchsploit | 3 | 20 | 1 |
| hashcat | 1 | 2 | 30 |
| john | 1 | 2 | 30 |
| dirb | 1 | 3 | 10 |
| whatweb | 2 | 10 | 3 |
| whois | 3 | 15 | 2 |
| dig | 3 | 20 | 1 |
| shell_command | 1 | 5 | 5 |

### 1.6 Audit Logging

Every tool invocation is logged in structured JSON (append-only log file + optional syslog):

```json
{
  "timestamp": "2026-02-13T14:30:00Z",
  "session_id": "sess_abc123",
  "user": "pentester_01",
  "tool": "nmap",
  "parameters": {
    "target": "192.168.1.0/24",
    "scan_type": "syn",
    "ports": "1-1024"
  },
  "command_executed": ["nmap", "-sS", "-p", "1-1024", "-oX", "-", "192.168.1.0/24"],
  "scope_check": "PASS",
  "sanitization_check": "PASS",
  "execution_time_ms": 45230,
  "exit_code": 0,
  "output_size_bytes": 12480,
  "risk_level": "medium",
  "result_summary": "Found 12 hosts, 47 open ports"
}
```

Log file location: `./logs/audit_YYYY-MM-DD.jsonl`

### 1.7 Risk Level Classification

Each tool and parameter combination is assigned a risk level:

| Risk Level | Description | Requirements |
|---|---|---|
| **LOW** | Passive information gathering, no target interaction | No extra confirmation |
| **MEDIUM** | Active scanning, service probing | Scope validation required |
| **HIGH** | Vulnerability testing, brute force, exploitation | Scope validation + explicit user confirmation |
| **CRITICAL** | Tools that could cause service disruption | Scope validation + confirmation + rate limit + mandatory cooldown |

---

## 2. Tool Catalog

### 2.1 nmap — Network Scanner

**Purpose**: Host discovery, port scanning, service/version detection, OS fingerprinting, and NSE script scanning.

**Risk Level**: MEDIUM (basic scans) / HIGH (aggressive/vuln scripts)

**Timeout**: 300s (quick scan) / 900s (full scan) / 1800s (large subnet)

#### Parameters

| Parameter | Type | Required | Default | Validation | Description |
|---|---|---|---|---|---|
| `target` | string | YES | — | IPv4, IPv4 CIDR, or Domain regex | Target host, IP, or CIDR range |
| `scan_type` | enum | NO | `"syn"` | One of: `syn`, `connect`, `udp`, `ack`, `fin`, `xmas`, `null`, `ping` | TCP scan technique |
| `ports` | string | NO | `"1-1024"` | Port or Port Range regex, or `"common"`, `"all"` | Port specification |
| `service_detection` | boolean | NO | `false` | — | Enable `-sV` service/version detection |
| `os_detection` | boolean | NO | `false` | — | Enable `-O` OS fingerprinting (requires root) |
| `scripts` | string | NO | `null` | NSE Script regex | NSE scripts to run (e.g., `"vuln"`, `"default,safe"`) |
| `script_args` | string | NO | `null` | `^[a-zA-Z0-9_.=,/-]+$` | Arguments for NSE scripts |
| `timing` | enum | NO | `"T3"` | One of: `T0`-`T5` | Timing template (T0=paranoid, T5=insane) |
| `top_ports` | integer | NO | `null` | 1-65535 | Scan top N most common ports |
| `aggressive` | boolean | NO | `false` | — | Enable `-A` (OS detect + version + scripts + traceroute). Risk: HIGH |
| `no_ping` | boolean | NO | `false` | — | Skip host discovery (`-Pn`) |
| `output_format` | enum | NO | `"xml"` | One of: `xml`, `normal`, `grepable` | Output format |

#### Command Construction

```python
def build_nmap_command(params: dict) -> list[str]:
    cmd = ["nmap"]

    scan_map = {
        "syn": "-sS", "connect": "-sT", "udp": "-sU",
        "ack": "-sA", "fin": "-sF", "xmas": "-sX",
        "null": "-sN", "ping": "-sn"
    }
    cmd.append(scan_map[params.get("scan_type", "syn")])

    if params.get("ports") == "all":
        cmd.extend(["-p-"])
    elif params.get("ports") == "common":
        pass  # nmap default
    elif params.get("ports"):
        cmd.extend(["-p", params["ports"]])

    if params.get("top_ports"):
        cmd.extend(["--top-ports", str(params["top_ports"])])

    if params.get("service_detection"):
        cmd.append("-sV")

    if params.get("os_detection"):
        cmd.append("-O")

    if params.get("aggressive"):
        cmd.append("-A")

    if params.get("scripts"):
        cmd.extend(["--script", params["scripts"]])
        if params.get("script_args"):
            cmd.extend(["--script-args", params["script_args"]])

    cmd.append(f"-{params.get('timing', 'T3')}")

    if params.get("no_ping"):
        cmd.append("-Pn")

    # Always output XML for structured parsing
    cmd.extend(["-oX", "-"])

    cmd.append(params["target"])
    return cmd
```

#### Output Parsing Strategy

Use nmap XML output (`-oX -`) parsed into structured JSON:

```json
{
  "scan_info": {
    "scanner": "nmap",
    "args": "nmap -sS -p 1-1024 -sV -oX - 192.168.1.1",
    "start_time": "2026-02-13T14:30:00Z",
    "elapsed_seconds": 45.23
  },
  "hosts": [
    {
      "ip": "192.168.1.1",
      "hostname": "gateway.local",
      "state": "up",
      "os_matches": [
        {"name": "Linux 5.x", "accuracy": 95}
      ],
      "ports": [
        {
          "port": 22,
          "protocol": "tcp",
          "state": "open",
          "service": "ssh",
          "version": "OpenSSH 8.9p1",
          "product": "OpenSSH",
          "scripts": []
        },
        {
          "port": 80,
          "protocol": "tcp",
          "state": "open",
          "service": "http",
          "version": "Apache httpd 2.4.52",
          "product": "Apache",
          "scripts": [
            {"id": "http-title", "output": "Apache2 Default Page"}
          ]
        }
      ]
    }
  ],
  "summary": {
    "hosts_up": 1,
    "hosts_down": 0,
    "total_open_ports": 2
  }
}
```

---

### 2.2 nikto — Web Vulnerability Scanner

**Purpose**: Scan web servers for known vulnerabilities, misconfigurations, outdated software, and dangerous files.

**Risk Level**: HIGH (active probing of web servers)

**Timeout**: 600s (default) / 1800s (thorough scan)

#### Parameters

| Parameter | Type | Required | Default | Validation | Description |
|---|---|---|---|---|---|
| `target` | string | YES | — | URL regex | Target URL (e.g., `http://192.168.1.1:8080`) |
| `port` | integer | NO | `null` | Port regex | Override port (if not in URL) |
| `ssl` | boolean | NO | `false` | — | Force SSL connection |
| `tuning` | string | NO | `null` | `^[0-9a-cx]+$` | Scan tuning (1=files, 2=misconfig, 3=info, 4=XSS, etc.) |
| `plugins` | string | NO | `null` | `^[a-zA-Z0-9_;]+$` | Specific plugins to run |
| `max_time` | integer | NO | `600` | 60-3600 | Maximum scan time in seconds |
| `no_404` | boolean | NO | `false` | — | Disable 404 guessing |
| `evasion` | string | NO | `null` | `^[1-8]+$` | IDS evasion techniques |
| `user_agent` | string | NO | `null` | `^[a-zA-Z0-9 .;()/:_-]{1,256}$` | Custom User-Agent string |
| `output_format` | enum | NO | `"json"` | One of: `json`, `csv`, `xml` | Output format |

#### Command Construction

```python
def build_nikto_command(params: dict) -> list[str]:
    cmd = ["nikto", "-h", params["target"]]

    if params.get("port"):
        cmd.extend(["-p", str(params["port"])])
    if params.get("ssl"):
        cmd.append("-ssl")
    if params.get("tuning"):
        cmd.extend(["-Tuning", params["tuning"]])
    if params.get("plugins"):
        cmd.extend(["-Plugins", params["plugins"]])
    if params.get("max_time"):
        cmd.extend(["-maxtime", f"{params['max_time']}s"])
    if params.get("no_404"):
        cmd.append("-no404")
    if params.get("evasion"):
        cmd.extend(["-evasion", params["evasion"]])
    if params.get("user_agent"):
        cmd.extend(["-useragent", params["user_agent"]])

    cmd.extend(["-Format", "json", "-o", "-"])
    return cmd
```

#### Output Parsing

```json
{
  "target": {
    "url": "http://192.168.1.1:8080",
    "ip": "192.168.1.1",
    "port": 8080,
    "hostname": "target.local"
  },
  "server_info": {
    "banner": "Apache/2.4.52 (Ubuntu)",
    "technologies": ["Apache", "PHP/8.1"]
  },
  "vulnerabilities": [
    {
      "id": "OSVDB-3233",
      "method": "GET",
      "uri": "/icons/README",
      "description": "Apache default file found",
      "severity": "info",
      "references": ["https://osvdb.org/3233"]
    },
    {
      "id": "OSVDB-3092",
      "method": "GET",
      "uri": "/admin/",
      "description": "Admin directory found with directory listing enabled",
      "severity": "high",
      "references": []
    }
  ],
  "statistics": {
    "requests_made": 6543,
    "elapsed_seconds": 120,
    "items_found": 2,
    "errors": 0
  }
}
```

---

### 2.3 gobuster — Directory/File Brute Force

**Purpose**: Brute-force directories, files, DNS subdomains, and virtual hosts on web servers.

**Risk Level**: MEDIUM

**Timeout**: 600s (default) / 1800s (large wordlist)

#### Parameters

| Parameter | Type | Required | Default | Validation | Description |
|---|---|---|---|---|---|
| `mode` | enum | NO | `"dir"` | One of: `dir`, `dns`, `vhost`, `fuzz` | Brute-force mode |
| `target` | string | YES | — | URL or Domain regex | Target URL (dir/vhost/fuzz) or domain (dns) |
| `wordlist` | string | NO | `"/usr/share/wordlists/dirb/common.txt"` | File Path (safe) regex | Path to wordlist file |
| `extensions` | string | NO | `null` | `^[a-zA-Z0-9,]{1,100}$` | File extensions to try (e.g., `"php,html,txt"`) |
| `status_codes` | string | NO | `"200,204,301,302,307,401,403"` | `^[0-9,]+$` | Status codes to report |
| `exclude_status` | string | NO | `null` | `^[0-9,]+$` | Status codes to exclude |
| `threads` | integer | NO | `10` | 1-50 | Concurrent threads |
| `timeout` | integer | NO | `10` | 1-60 | HTTP request timeout (seconds) |
| `follow_redirect` | boolean | NO | `false` | — | Follow HTTP redirects |
| `no_tls_validation` | boolean | NO | `false` | — | Skip TLS certificate validation |
| `headers` | string | NO | `null` | `^[a-zA-Z0-9-]+:\s?[a-zA-Z0-9 _.;=/-]+$` | Custom HTTP header |
| `cookies` | string | NO | `null` | `^[a-zA-Z0-9_]+=[a-zA-Z0-9_.%-]+$` | Cookie string |
| `user_agent` | string | NO | `null` | `^[a-zA-Z0-9 .;()/:_-]{1,256}$` | Custom User-Agent |
| `exclude_length` | string | NO | `null` | `^[0-9,]+$` | Exclude responses of these content lengths |

#### Command Construction

```python
def build_gobuster_command(params: dict) -> list[str]:
    cmd = ["gobuster", params.get("mode", "dir")]

    if params.get("mode", "dir") in ("dir", "vhost", "fuzz"):
        cmd.extend(["-u", params["target"]])
    else:
        cmd.extend(["-d", params["target"]])

    cmd.extend(["-w", params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")])

    if params.get("extensions"):
        cmd.extend(["-x", params["extensions"]])
    if params.get("status_codes"):
        cmd.extend(["-s", params["status_codes"]])
    if params.get("exclude_status"):
        cmd.extend(["-b", params["exclude_status"]])
    if params.get("threads"):
        cmd.extend(["-t", str(params["threads"])])
    if params.get("timeout"):
        cmd.extend(["--timeout", f"{params['timeout']}s"])
    if params.get("follow_redirect"):
        cmd.append("-r")
    if params.get("no_tls_validation"):
        cmd.append("-k")
    if params.get("headers"):
        cmd.extend(["-H", params["headers"]])
    if params.get("cookies"):
        cmd.extend(["-c", params["cookies"]])
    if params.get("user_agent"):
        cmd.extend(["-a", params["user_agent"]])
    if params.get("exclude_length"):
        cmd.extend(["--exclude-length", params["exclude_length"]])

    cmd.append("--no-color")
    cmd.extend(["-o", "-"])
    return cmd
```

#### Output Parsing

```json
{
  "target": "http://192.168.1.1:8080",
  "mode": "dir",
  "wordlist": "/usr/share/wordlists/dirb/common.txt",
  "results": [
    {
      "path": "/admin",
      "status": 301,
      "size": 314,
      "redirect_to": "http://192.168.1.1:8080/admin/"
    },
    {
      "path": "/login.php",
      "status": 200,
      "size": 4523,
      "redirect_to": null
    },
    {
      "path": "/backup",
      "status": 403,
      "size": 277,
      "redirect_to": null
    }
  ],
  "statistics": {
    "total_requests": 4614,
    "elapsed_seconds": 32,
    "items_found": 3,
    "errors": 0,
    "progress_percent": 100
  }
}
```

---

### 2.4 sqlmap — SQL Injection Automation

**Purpose**: Detect and exploit SQL injection vulnerabilities in web applications.

**Risk Level**: CRITICAL (can read/modify/delete database content)

**Timeout**: 900s (default) / 3600s (full exploitation)

#### Parameters

| Parameter | Type | Required | Default | Validation | Description |
|---|---|---|---|---|---|
| `url` | string | YES | — | URL regex | Target URL with injectable parameter |
| `method` | enum | NO | `"GET"` | One of: `GET`, `POST` | HTTP method |
| `data` | string | NO | `null` | `^[a-zA-Z0-9_=&%+.-]+$` | POST data (e.g., `"user=admin&pass=test"`) |
| `param` | string | NO | `null` | `^[a-zA-Z0-9_]+$` | Specific parameter to test |
| `cookie` | string | NO | `null` | `^[a-zA-Z0-9_]+=[a-zA-Z0-9_.%-]+[;&]?.*$` | HTTP Cookie header |
| `level` | integer | NO | `1` | 1-5 | Test level (higher = more tests) |
| `risk` | integer | NO | `1` | 1-3 | Risk of tests (higher = more dangerous) |
| `technique` | string | NO | `null` | `^[BEUSTQ]+$` | SQL injection techniques (B/E/U/S/T/Q) |
| `dbms` | enum | NO | `null` | One of: `mysql`, `postgresql`, `mssql`, `oracle`, `sqlite` | Force backend DBMS |
| `threads` | integer | NO | `1` | 1-10 | Concurrent threads |
| `dbs` | boolean | NO | `false` | — | Enumerate databases |
| `tables` | boolean | NO | `false` | — | Enumerate tables |
| `columns` | boolean | NO | `false` | — | Enumerate columns |
| `dump` | boolean | NO | `false` | — | Dump table data |
| `database` | string | NO | `null` | `^[a-zA-Z0-9_]{1,64}$` | Specific database |
| `table` | string | NO | `null` | `^[a-zA-Z0-9_]{1,64}$` | Specific table |
| `batch` | boolean | NO | `true` | — | Non-interactive mode (never prompt) |
| `tamper` | string | NO | `null` | `^[a-z0-9_,]+$` | Tamper script(s) for WAF bypass |
| `random_agent` | boolean | NO | `true` | — | Use random User-Agent |
| `timeout` | integer | NO | `30` | 5-120 | Connection timeout per request |
| `os_shell` | boolean | NO | `false` | — | **BLOCKED** — OS shell access is disabled |
| `os_cmd` | string | NO | `null` | — | **BLOCKED** — OS command execution is disabled |
| `file_read` | string | NO | `null` | — | **BLOCKED** — Server file reading is disabled |
| `file_write` | string | NO | `null` | — | **BLOCKED** — Server file writing is disabled |

**Blocked Parameters**: `os_shell`, `os_cmd`, `file_read`, `file_write`, `reg_read`, `reg_add`, `reg_del` are permanently blocked as they enable remote code execution and file system access beyond SQL injection scope.

#### Command Construction

```python
def build_sqlmap_command(params: dict) -> list[str]:
    BLOCKED = {"os_shell", "os_cmd", "file_read", "file_write", "reg_read", "reg_add", "reg_del"}
    for key in BLOCKED:
        if params.get(key):
            raise SecurityError(f"Parameter '{key}' is blocked for security reasons")

    cmd = ["sqlmap", "-u", params["url"]]

    if params.get("method") == "POST":
        cmd.append("--method=POST")
    if params.get("data"):
        cmd.extend(["--data", params["data"]])
    if params.get("param"):
        cmd.extend(["-p", params["param"]])
    if params.get("cookie"):
        cmd.extend(["--cookie", params["cookie"]])

    cmd.extend(["--level", str(params.get("level", 1))])
    cmd.extend(["--risk", str(params.get("risk", 1))])

    if params.get("technique"):
        cmd.extend(["--technique", params["technique"]])
    if params.get("dbms"):
        cmd.extend(["--dbms", params["dbms"]])
    if params.get("threads"):
        cmd.extend(["--threads", str(params["threads"])])
    if params.get("dbs"):
        cmd.append("--dbs")
    if params.get("tables"):
        cmd.append("--tables")
    if params.get("columns"):
        cmd.append("--columns")
    if params.get("dump"):
        cmd.append("--dump")
    if params.get("database"):
        cmd.extend(["-D", params["database"]])
    if params.get("table"):
        cmd.extend(["-T", params["table"]])
    if params.get("batch", True):
        cmd.append("--batch")
    if params.get("tamper"):
        cmd.extend(["--tamper", params["tamper"]])
    if params.get("random_agent", True):
        cmd.append("--random-agent")
    if params.get("timeout"):
        cmd.extend(["--timeout", str(params["timeout"])])

    cmd.extend(["--output-dir", "/tmp/rami-kali/sqlmap"])
    return cmd
```

#### Output Parsing

```json
{
  "target": {
    "url": "http://192.168.1.1/page.php?id=1",
    "parameter": "id",
    "method": "GET"
  },
  "injection_points": [
    {
      "parameter": "id",
      "type": "UNION query",
      "technique": "U",
      "dbms": "MySQL >= 5.0",
      "payload": "1 UNION ALL SELECT NULL,CONCAT(0x716b6a7171,...),NULL-- -"
    }
  ],
  "databases": ["information_schema", "webapp_db", "mysql"],
  "tables": {
    "webapp_db": ["users", "sessions", "products"]
  },
  "columns": {
    "webapp_db.users": [
      {"name": "id", "type": "int(11)"},
      {"name": "username", "type": "varchar(64)"},
      {"name": "password", "type": "varchar(256)"}
    ]
  },
  "dump": {
    "webapp_db.users": [
      {"id": 1, "username": "admin", "password": "$2b$12$...hash..."}
    ]
  },
  "dbms_info": {
    "type": "MySQL",
    "version": "8.0.31",
    "os": "Linux"
  }
}
```

---

### 2.5 hydra — Brute Force Authentication

**Purpose**: Online password brute-forcing against network services.

**Risk Level**: CRITICAL (can lock out accounts, trigger IDS)

**Timeout**: 1800s

#### Parameters

| Parameter | Type | Required | Default | Validation | Description |
|---|---|---|---|---|---|
| `target` | string | YES | — | IPv4 or Domain regex | Target host |
| `service` | enum | YES | — | One of: `ssh`, `ftp`, `http-get`, `http-post-form`, `smtp`, `pop3`, `imap`, `mysql`, `postgres`, `rdp`, `smb`, `vnc`, `telnet`, `snmp` | Target service/protocol |
| `username` | string | NO* | `null` | Username regex | Single username (*one of username/user_list required) |
| `user_list` | string | NO* | `null` | File Path (safe) regex | Path to username wordlist |
| `password` | string | NO* | `null` | `^.{1,128}$` | Single password (*one of password/pass_list required) |
| `pass_list` | string | NO* | `null` | File Path (safe) regex | Path to password wordlist |
| `port` | integer | NO | `null` (service default) | Port regex | Override service port |
| `threads` | integer | NO | `4` | 1-16 | Concurrent connections (capped at 16 for safety) |
| `timeout` | integer | NO | `30` | 5-120 | Connection timeout |
| `http_path` | string | NO | `null` | URL Path regex | Path for HTTP services |
| `http_body` | string | NO | `null` | `^[a-zA-Z0-9_=&^%:;/.-]+$` | HTTP POST form body template |
| `http_failure` | string | NO | `null` | `^[a-zA-Z0-9 _.,:;-]{1,256}$` | HTTP failure indicator string |
| `ssl` | boolean | NO | `false` | — | Use SSL |
| `vV` | boolean | NO | `false` | — | Verbose mode (show each attempt) |
| `max_attempts` | integer | NO | `1000` | 1-10000 | Maximum total login attempts (safety cap) |

#### Command Construction

```python
def build_hydra_command(params: dict) -> list[str]:
    cmd = ["hydra"]

    if params.get("username"):
        cmd.extend(["-l", params["username"]])
    elif params.get("user_list"):
        cmd.extend(["-L", params["user_list"]])

    if params.get("password"):
        cmd.extend(["-p", params["password"]])
    elif params.get("pass_list"):
        cmd.extend(["-P", params["pass_list"]])

    if params.get("port"):
        cmd.extend(["-s", str(params["port"])])
    if params.get("threads"):
        cmd.extend(["-t", str(min(params["threads"], 16))])
    if params.get("timeout"):
        cmd.extend(["-W", str(params["timeout"])])
    if params.get("ssl"):
        cmd.append("-S")
    if params.get("vV"):
        cmd.append("-vV")

    cmd.extend(["-o", "-", "-b", "json"])
    cmd.append(params["target"])

    service = params["service"]
    if service == "http-post-form":
        form_spec = f"{params.get('http_path', '/')}:{params.get('http_body', '')}:{params.get('http_failure', 'Invalid')}"
        cmd.append(f"http-post-form")
        cmd.append(form_spec)
    else:
        cmd.append(service)

    return cmd
```

#### Output Parsing

```json
{
  "target": "192.168.1.1",
  "service": "ssh",
  "port": 22,
  "valid_credentials": [
    {
      "username": "admin",
      "password": "password123",
      "host": "192.168.1.1",
      "port": 22
    }
  ],
  "statistics": {
    "total_attempts": 450,
    "successful": 1,
    "failed": 449,
    "elapsed_seconds": 125,
    "attempts_per_second": 3.6
  }
}
```

---

### 2.6 enum4linux — SMB/Windows Enumeration

**Purpose**: Enumerate information from Windows and Samba systems via SMB.

**Risk Level**: MEDIUM

**Timeout**: 300s

#### Parameters

| Parameter | Type | Required | Default | Validation | Description |
|---|---|---|---|---|---|
| `target` | string | YES | — | IPv4 or Domain regex | Target host |
| `all` | boolean | NO | `true` | — | Full enumeration (`-a`) |
| `users` | boolean | NO | `false` | — | Enumerate users (`-U`) |
| `shares` | boolean | NO | `false` | — | Enumerate shares (`-S`) |
| `groups` | boolean | NO | `false` | — | Enumerate groups (`-G`) |
| `password_policy` | boolean | NO | `false` | — | Get password policy (`-P`) |
| `os_info` | boolean | NO | `false` | — | Get OS information (`-o`) |
| `username` | string | NO | `""` | Username regex | SMB username |
| `password` | string | NO | `""` | `^.{0,128}$` | SMB password |
| `workgroup` | string | NO | `null` | `^[a-zA-Z0-9_.-]{1,64}$` | Workgroup name |

#### Command Construction

```python
def build_enum4linux_command(params: dict) -> list[str]:
    cmd = ["enum4linux"]

    if params.get("all", True):
        cmd.append("-a")
    else:
        if params.get("users"): cmd.append("-U")
        if params.get("shares"): cmd.append("-S")
        if params.get("groups"): cmd.append("-G")
        if params.get("password_policy"): cmd.append("-P")
        if params.get("os_info"): cmd.append("-o")

    if params.get("username"):
        cmd.extend(["-u", params["username"]])
    if params.get("password"):
        cmd.extend(["-p", params["password"]])
    if params.get("workgroup"):
        cmd.extend(["-w", params["workgroup"]])

    cmd.append(params["target"])
    return cmd
```

#### Output Parsing

```json
{
  "target": "192.168.1.10",
  "os_info": {
    "os": "Windows 10 Pro 19045",
    "server": "Windows 10 Pro 6.3",
    "domain": "WORKGROUP"
  },
  "users": [
    {"rid": "0x1f4", "username": "Administrator"},
    {"rid": "0x1f5", "username": "Guest"},
    {"rid": "0x3e8", "username": "jsmith"}
  ],
  "shares": [
    {"name": "IPC$", "type": "IPC", "comment": "Remote IPC", "accessible": true},
    {"name": "ADMIN$", "type": "Disk", "comment": "Remote Admin", "accessible": false},
    {"name": "SharedDocs", "type": "Disk", "comment": "Shared Documents", "accessible": true}
  ],
  "groups": [
    {"name": "Domain Admins", "rid": "0x200", "members": ["Administrator"]},
    {"name": "Domain Users", "rid": "0x201", "members": ["jsmith", "Guest"]}
  ],
  "password_policy": {
    "min_length": 7,
    "password_history": 24,
    "max_age": 42,
    "min_age": 1,
    "lockout_threshold": 5,
    "lockout_duration": 30,
    "complexity_required": true
  }
}
```

---

### 2.7 wfuzz — Web Application Fuzzer

**Purpose**: Fuzz web application parameters, headers, URLs for vulnerabilities.

**Risk Level**: HIGH

**Timeout**: 600s

#### Parameters

| Parameter | Type | Required | Default | Validation | Description |
|---|---|---|---|---|---|
| `url` | string | YES | — | URL regex (must contain `FUZZ`) | Target URL with FUZZ placeholder |
| `wordlist` | string | NO | `"/usr/share/wordlists/wfuzz/general/common.txt"` | File Path (safe) regex | Wordlist path |
| `method` | enum | NO | `"GET"` | One of: `GET`, `POST`, `PUT`, `DELETE`, `PATCH` | HTTP method |
| `post_data` | string | NO | `null` | `^[a-zA-Z0-9_=&%+.FUZZ-]+$` | POST data (can contain FUZZ) |
| `header` | string | NO | `null` | `^[a-zA-Z0-9-]+:\s?[a-zA-Z0-9 _.;=FUZZ/-]+$` | Custom header (can contain FUZZ) |
| `cookie` | string | NO | `null` | `^[a-zA-Z0-9_]+=[a-zA-Z0-9_.%FUZZ-]+$` | Cookie string |
| `hide_code` | string | NO | `null` | `^[0-9,]+$` | Hide responses with these status codes |
| `show_code` | string | NO | `null` | `^[0-9,]+$` | Show only responses with these codes |
| `hide_chars` | string | NO | `null` | `^[0-9,]+$` | Hide responses by character count |
| `hide_words` | string | NO | `null` | `^[0-9,]+$` | Hide responses by word count |
| `hide_lines` | string | NO | `null` | `^[0-9,]+$` | Hide responses by line count |
| `threads` | integer | NO | `10` | 1-40 | Concurrent connections |
| `follow_redirect` | boolean | NO | `false` | — | Follow redirects |
| `auth` | string | NO | `null` | `^[a-zA-Z0-9_]+:[a-zA-Z0-9_.!@#$%^&*-]+$` | Basic auth (`user:pass`) |

#### Command Construction

```python
def build_wfuzz_command(params: dict) -> list[str]:
    cmd = ["wfuzz"]

    cmd.extend(["-w", params.get("wordlist", "/usr/share/wordlists/wfuzz/general/common.txt")])

    if params.get("method") and params["method"] != "GET":
        cmd.extend(["-X", params["method"]])
    if params.get("post_data"):
        cmd.extend(["-d", params["post_data"]])
    if params.get("header"):
        cmd.extend(["-H", params["header"]])
    if params.get("cookie"):
        cmd.extend(["-b", params["cookie"]])
    if params.get("hide_code"):
        cmd.extend(["--hc", params["hide_code"]])
    if params.get("show_code"):
        cmd.extend(["--sc", params["show_code"]])
    if params.get("hide_chars"):
        cmd.extend(["--hh", params["hide_chars"]])
    if params.get("hide_words"):
        cmd.extend(["--hw", params["hide_words"]])
    if params.get("hide_lines"):
        cmd.extend(["--hl", params["hide_lines"]])
    if params.get("threads"):
        cmd.extend(["-t", str(params["threads"])])
    if params.get("follow_redirect"):
        cmd.append("-L")
    if params.get("auth"):
        cmd.extend(["--basic", params["auth"]])

    cmd.extend(["-f", "-,json"])  # output to stdout as JSON
    cmd.append(params["url"])
    return cmd
```

#### Output Parsing

```json
{
  "target": "http://192.168.1.1/FUZZ",
  "wordlist": "/usr/share/wordlists/wfuzz/general/common.txt",
  "results": [
    {
      "payload": "admin",
      "status": 200,
      "content_length": 4523,
      "words": 312,
      "lines": 89,
      "url": "http://192.168.1.1/admin"
    },
    {
      "payload": "backup",
      "status": 403,
      "content_length": 277,
      "words": 20,
      "lines": 10,
      "url": "http://192.168.1.1/backup"
    }
  ],
  "statistics": {
    "total_requests": 950,
    "filtered": 948,
    "shown": 2,
    "elapsed_seconds": 15
  }
}
```

---

### 2.8 netcat (nc) — Network Utility

**Purpose**: TCP/UDP connection utility for banner grabbing, port checking, simple data transfer.

**Risk Level**: MEDIUM (connect mode) / **BLOCKED** (listen mode)

**Timeout**: 30s (connect) / 60s (data transfer)

#### Parameters

| Parameter | Type | Required | Default | Validation | Description |
|---|---|---|---|---|---|
| `target` | string | YES | — | IPv4 or Domain regex | Target host |
| `port` | integer | YES | — | Port regex | Target port |
| `protocol` | enum | NO | `"tcp"` | One of: `tcp`, `udp` | Protocol |
| `data` | string | NO | `null` | `^[\x20-\x7E\r\n]{0,1024}$` | Data to send (printable ASCII only) |
| `timeout` | integer | NO | `10` | 1-60 | Connection timeout |
| `zero_io` | boolean | NO | `false` | — | Zero I/O mode - port scan only (`-z`) |
| `verbose` | boolean | NO | `true` | — | Verbose output (`-v`) |
| `listen` | boolean | NO | `false` | — | **BLOCKED** — Listen mode disabled for security |
| `execute` | string | NO | `null` | — | **BLOCKED** — Command execution disabled |

#### Command Construction

```python
def build_netcat_command(params: dict) -> list[str]:
    if params.get("listen"):
        raise SecurityError("Listen mode is disabled for security")
    if params.get("execute"):
        raise SecurityError("Execute mode is disabled for security")

    cmd = ["nc"]

    if params.get("verbose", True):
        cmd.append("-v")
    if params.get("protocol") == "udp":
        cmd.append("-u")
    if params.get("zero_io"):
        cmd.append("-z")

    cmd.extend(["-w", str(params.get("timeout", 10))])
    cmd.append(params["target"])
    cmd.append(str(params["port"]))

    return cmd
    # If data is provided, pipe it via stdin to subprocess
```

#### Output Parsing

```json
{
  "target": "192.168.1.1",
  "port": 80,
  "protocol": "tcp",
  "connection": "success",
  "banner": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.52\r\n...",
  "response_data": "...",
  "elapsed_ms": 45
}
```

---

### 2.9 searchsploit — Exploit Database Search

**Purpose**: Search the local Exploit-DB database for known exploits and vulnerabilities.

**Risk Level**: LOW (offline search, no target interaction)

**Timeout**: 30s

#### Parameters

| Parameter | Type | Required | Default | Validation | Description |
|---|---|---|---|---|---|
| `query` | string | YES | — | `^[a-zA-Z0-9 ./_-]{1,200}$` | Search terms |
| `exact` | boolean | NO | `false` | — | Exact match only |
| `cve` | string | NO | `null` | `^CVE-\d{4}-\d{4,7}$` | Search by CVE ID |
| `type` | enum | NO | `null` | One of: `exploits`, `shellcodes`, `papers` | Filter by type |
| `platform` | string | NO | `null` | `^[a-zA-Z0-9_-]{1,50}$` | Filter by platform (e.g., `linux`, `windows`) |
| `exclude` | string | NO | `null` | `^[a-zA-Z0-9 ._-]{1,100}$` | Exclude terms |
| `json_output` | boolean | NO | `true` | — | JSON output format |

#### Command Construction

```python
def build_searchsploit_command(params: dict) -> list[str]:
    cmd = ["searchsploit"]

    if params.get("exact"):
        cmd.append("-e")
    if params.get("cve"):
        cmd.extend(["--cve", params["cve"]])
    if params.get("type"):
        cmd.extend(["-t", params["type"]])
    if params.get("platform"):
        cmd.extend(["--platform", params["platform"]])
    if params.get("exclude"):
        cmd.extend(["--exclude", params["exclude"]])
    if params.get("json_output", True):
        cmd.append("-j")

    cmd.append(params["query"])
    return cmd
```

#### Output Parsing

```json
{
  "query": "Apache 2.4",
  "results": [
    {
      "title": "Apache 2.4.49 - Path Traversal & Remote Code Execution",
      "edb_id": "50383",
      "date": "2021-10-05",
      "author": "Researcher Name",
      "platform": "Multiple",
      "type": "webapps",
      "path": "/usr/share/exploitdb/exploits/multiple/webapps/50383.py",
      "codes": ["CVE-2021-41773"]
    }
  ],
  "total_results": 15,
  "search_type": "partial"
}
```

---

### 2.10 hashcat — GPU Hash Cracking

**Purpose**: GPU-accelerated password hash cracking.

**Risk Level**: LOW (local computation, no network target)

**Timeout**: 3600s (configurable, long-running)

#### Parameters

| Parameter | Type | Required | Default | Validation | Description |
|---|---|---|---|---|---|
| `hash_value` | string | YES* | — | Hash Value regex | Single hash to crack (*one of hash_value/hash_file) |
| `hash_file` | string | YES* | — | File Path (safe) regex | File containing hashes |
| `hash_type` | integer | YES | — | 0-99999 | Hash type code (e.g., 0=MD5, 100=SHA1, 1000=NTLM, 3200=bcrypt) |
| `attack_mode` | enum | NO | `0` | One of: `0` (dict), `1` (combination), `3` (brute), `6` (dict+mask), `7` (mask+dict) | Attack mode |
| `wordlist` | string | NO | `"/usr/share/wordlists/rockyou.txt"` | File Path (safe) regex | Wordlist (for dict attack) |
| `rules` | string | NO | `null` | File Path (safe) regex | Rules file path |
| `mask` | string | NO | `null` | `^[?ludsaLUDSAb0-9]{1,32}$` | Mask pattern (e.g., `?u?l?l?l?d?d?d?d`) |
| `increment` | boolean | NO | `false` | — | Enable incremental mode |
| `increment_min` | integer | NO | `1` | 1-32 | Minimum increment length |
| `increment_max` | integer | NO | `8` | 1-32 | Maximum increment length |
| `workload_profile` | integer | NO | `2` | 1-4 | Workload profile (1=low, 4=nightmare) |
| `max_runtime` | integer | NO | `3600` | 60-86400 | Maximum runtime in seconds |
| `show` | boolean | NO | `false` | — | Show already cracked hashes |
| `potfile_disable` | boolean | NO | `false` | — | Disable potfile |

#### Command Construction

```python
def build_hashcat_command(params: dict) -> list[str]:
    cmd = ["hashcat"]

    cmd.extend(["-m", str(params["hash_type"])])
    cmd.extend(["-a", str(params.get("attack_mode", 0))])

    if params.get("workload_profile"):
        cmd.extend(["-w", str(params["workload_profile"])])
    if params.get("max_runtime"):
        cmd.extend(["--runtime", str(params["max_runtime"])])
    if params.get("rules"):
        cmd.extend(["-r", params["rules"]])
    if params.get("increment"):
        cmd.append("--increment")
        if params.get("increment_min"):
            cmd.extend(["--increment-min", str(params["increment_min"])])
        if params.get("increment_max"):
            cmd.extend(["--increment-max", str(params["increment_max"])])
    if params.get("show"):
        cmd.append("--show")
    if params.get("potfile_disable"):
        cmd.append("--potfile-disable")

    cmd.append("--machine-readable")
    cmd.extend(["--outfile-format", "2"])

    if params.get("hash_file"):
        cmd.append(params["hash_file"])
    else:
        # Write hash to temp file
        cmd.append("/tmp/rami-kali/hashcat_input.txt")

    if params.get("attack_mode", 0) in (0, 1, 6, 7):
        cmd.append(params.get("wordlist", "/usr/share/wordlists/rockyou.txt"))
    if params.get("mask"):
        cmd.append(params["mask"])

    return cmd
```

#### Output Parsing

```json
{
  "hash_type": "MD5",
  "hash_type_code": 0,
  "attack_mode": "dictionary",
  "cracked": [
    {
      "hash": "5f4dcc3b5aa765d61d8327deb882cf99",
      "plaintext": "password",
      "hex_plain": "70617373776f7264"
    }
  ],
  "statistics": {
    "total_hashes": 5,
    "cracked_count": 3,
    "remaining": 2,
    "speed": "12.5 GH/s",
    "elapsed_seconds": 45,
    "progress_percent": 100
  }
}
```

---

### 2.11 john — CPU Hash Cracking (John the Ripper)

**Purpose**: CPU-based password hash cracking with auto-detection and multiple formats.

**Risk Level**: LOW (local computation)

**Timeout**: 3600s

#### Parameters

| Parameter | Type | Required | Default | Validation | Description |
|---|---|---|---|---|---|
| `hash_file` | string | YES | — | File Path (safe) regex | File containing hashes |
| `format` | string | NO | `null` | `^[a-zA-Z0-9-]{1,50}$` | Hash format (e.g., `raw-md5`, `bcrypt`, `ntlm`, `sha512crypt`) |
| `wordlist` | string | NO | `null` | File Path (safe) regex | Wordlist path |
| `rules` | string | NO | `null` | `^[a-zA-Z0-9]+$` | Rule set name (e.g., `best64`, `dive`) |
| `incremental` | boolean | NO | `false` | — | Incremental (brute force) mode |
| `incremental_mode` | string | NO | `null` | `^[a-zA-Z0-9]+$` | Incremental mode name |
| `max_length` | integer | NO | `null` | 1-32 | Maximum password length |
| `min_length` | integer | NO | `null` | 1-32 | Minimum password length |
| `show` | boolean | NO | `false` | — | Show cracked passwords |
| `max_runtime` | integer | NO | `3600` | 60-86400 | Maximum runtime in seconds |
| `fork` | integer | NO | `null` | 1-8 | Number of processes |

#### Command Construction

```python
def build_john_command(params: dict) -> list[str]:
    cmd = ["john"]

    if params.get("format"):
        cmd.extend([f"--format={params['format']}"])
    if params.get("wordlist"):
        cmd.extend([f"--wordlist={params['wordlist']}"])
    if params.get("rules"):
        cmd.extend([f"--rules={params['rules']}"])
    if params.get("incremental"):
        if params.get("incremental_mode"):
            cmd.append(f"--incremental={params['incremental_mode']}")
        else:
            cmd.append("--incremental")
    if params.get("max_length"):
        cmd.append(f"--max-length={params['max_length']}")
    if params.get("min_length"):
        cmd.append(f"--min-length={params['min_length']}")
    if params.get("show"):
        cmd.append("--show")
    if params.get("max_runtime"):
        cmd.append(f"--max-run-time={params['max_runtime']}")
    if params.get("fork"):
        cmd.append(f"--fork={params['fork']}")

    cmd.append(params["hash_file"])
    return cmd
```

#### Output Parsing

```json
{
  "hash_file": "/tmp/rami-kali/hashes.txt",
  "format": "raw-md5",
  "cracked": [
    {
      "username": "admin",
      "hash": "5f4dcc3b5aa765d61d8327deb882cf99",
      "plaintext": "password"
    }
  ],
  "statistics": {
    "total_hashes": 10,
    "cracked_count": 4,
    "remaining": 6,
    "elapsed_seconds": 120,
    "session_name": "default"
  }
}
```

---

### 2.12 dirb — URL Brute Force

**Purpose**: Web content brute-forcing tool (alternative to gobuster with different features).

**Risk Level**: MEDIUM

**Timeout**: 600s

#### Parameters

| Parameter | Type | Required | Default | Validation | Description |
|---|---|---|---|---|---|
| `url` | string | YES | — | URL regex | Target base URL |
| `wordlist` | string | NO | `"/usr/share/dirb/wordlists/common.txt"` | File Path (safe) regex | Wordlist path |
| `extensions` | string | NO | `null` | `^[a-zA-Z0-9,.]{1,100}$` | File extensions (e.g., `.php,.html`) |
| `user_agent` | string | NO | `null` | `^[a-zA-Z0-9 .;()/:_-]{1,256}$` | Custom User-Agent |
| `cookie` | string | NO | `null` | `^[a-zA-Z0-9_]+=[a-zA-Z0-9_.%-]+$` | Cookie header |
| `auth` | string | NO | `null` | `^[a-zA-Z0-9_]+:[a-zA-Z0-9_.!@#$%^&*-]+$` | HTTP Basic auth (`user:pass`) |
| `proxy` | string | NO | `null` | URL regex | Proxy URL |
| `recursive` | boolean | NO | `false` | — | Recursive search |
| `not_recursive` | boolean | NO | `false` | — | Disable recursion |
| `case_insensitive` | boolean | NO | `false` | — | Case-insensitive search |
| `show_not_found` | boolean | NO | `false` | — | Show 404 responses |
| `speed` | enum | NO | `null` | One of: `slow`, `normal`, `fast` | Request delay |

#### Command Construction

```python
def build_dirb_command(params: dict) -> list[str]:
    cmd = ["dirb", params["url"]]
    cmd.append(params.get("wordlist", "/usr/share/dirb/wordlists/common.txt"))

    if params.get("extensions"):
        cmd.extend(["-X", params["extensions"]])
    if params.get("user_agent"):
        cmd.extend(["-a", params["user_agent"]])
    if params.get("cookie"):
        cmd.extend(["-c", params["cookie"]])
    if params.get("auth"):
        cmd.extend(["-u", params["auth"]])
    if params.get("proxy"):
        cmd.extend(["-p", params["proxy"]])
    if params.get("recursive"):
        cmd.append("-r")
    if params.get("not_recursive"):
        cmd.append("-N")
    if params.get("case_insensitive"):
        cmd.append("-i")
    if params.get("show_not_found"):
        cmd.append("-v")

    speed_map = {"slow": "-z", "normal": None, "fast": None}
    if params.get("speed") == "slow":
        cmd.extend(["-z", "100"])

    cmd.append("-S")  # silent mode (no banner)
    return cmd
```

#### Output Parsing

```json
{
  "target": "http://192.168.1.1",
  "wordlist": "/usr/share/dirb/wordlists/common.txt",
  "results": [
    {
      "url": "http://192.168.1.1/admin/",
      "code": 200,
      "size": 1234
    },
    {
      "url": "http://192.168.1.1/images/",
      "code": 403,
      "size": 277
    }
  ],
  "statistics": {
    "words_tested": 4614,
    "found": 2,
    "elapsed_seconds": 45
  }
}
```

---

### 2.13 whatweb — Web Technology Fingerprinting

**Purpose**: Identify web technologies, CMS platforms, frameworks, server software.

**Risk Level**: LOW

**Timeout**: 120s

#### Parameters

| Parameter | Type | Required | Default | Validation | Description |
|---|---|---|---|---|---|
| `target` | string | YES | — | URL or Domain regex | Target URL or domain |
| `aggression` | integer | NO | `1` | 1-4 | Aggression level (1=stealthy, 4=heavy) |
| `user_agent` | string | NO | `null` | `^[a-zA-Z0-9 .;()/:_-]{1,256}$` | Custom User-Agent |
| `cookie` | string | NO | `null` | `^[a-zA-Z0-9_]+=[a-zA-Z0-9_.%-]+$` | Cookie header |
| `follow_redirect` | enum | NO | `"always"` | One of: `never`, `same-site`, `same-domain`, `always` | Redirect behavior |
| `max_redirects` | integer | NO | `10` | 1-20 | Maximum redirects to follow |
| `proxy` | string | NO | `null` | URL regex | Proxy URL |
| `verbose` | boolean | NO | `false` | — | Verbose output |
| `color` | boolean | NO | `false` | — | Color output (always false for parsing) |
| `log_json` | boolean | NO | `true` | — | JSON output |

#### Command Construction

```python
def build_whatweb_command(params: dict) -> list[str]:
    cmd = ["whatweb"]

    cmd.extend(["-a", str(params.get("aggression", 1))])

    if params.get("user_agent"):
        cmd.extend(["-U", params["user_agent"]])
    if params.get("cookie"):
        cmd.extend(["--cookie", params["cookie"]])
    if params.get("follow_redirect"):
        cmd.extend(["--follow-redirect", params["follow_redirect"]])
    if params.get("max_redirects"):
        cmd.extend(["--max-redirects", str(params["max_redirects"])])
    if params.get("proxy"):
        cmd.extend(["--proxy", params["proxy"]])

    cmd.extend(["--log-json=-"])
    cmd.append("--color=never")
    cmd.append(params["target"])
    return cmd
```

#### Output Parsing

```json
{
  "target": "http://192.168.1.1",
  "status": 200,
  "technologies": [
    {
      "name": "Apache",
      "version": "2.4.52",
      "category": "Web Server",
      "confidence": 100
    },
    {
      "name": "PHP",
      "version": "8.1.2",
      "category": "Programming Language",
      "confidence": 100
    },
    {
      "name": "WordPress",
      "version": "6.1",
      "category": "CMS",
      "confidence": 95
    },
    {
      "name": "jQuery",
      "version": "3.6.0",
      "category": "JavaScript Library",
      "confidence": 100
    }
  ],
  "headers": {
    "Server": "Apache/2.4.52 (Ubuntu)",
    "X-Powered-By": "PHP/8.1.2"
  },
  "ip": "192.168.1.1",
  "country": "RESERVED"
}
```

---

### 2.14 whois — Domain Registration Info

**Purpose**: Query domain registration, ownership, and network allocation information.

**Risk Level**: LOW (public database query)

**Timeout**: 30s

#### Parameters

| Parameter | Type | Required | Default | Validation | Description |
|---|---|---|---|---|---|
| `target` | string | YES | — | Domain or IPv4 regex | Domain name or IP address |
| `server` | string | NO | `null` | Domain regex | Specific WHOIS server |
| `port` | integer | NO | `null` | Port regex | WHOIS server port |

#### Command Construction

```python
def build_whois_command(params: dict) -> list[str]:
    cmd = ["whois"]

    if params.get("server"):
        cmd.extend(["-h", params["server"]])
    if params.get("port"):
        cmd.extend(["-p", str(params["port"])])

    cmd.append(params["target"])
    return cmd
```

#### Output Parsing

```json
{
  "domain": "example.com",
  "registrar": "Example Registrar, LLC",
  "registration_date": "1995-08-14",
  "expiration_date": "2027-08-13",
  "updated_date": "2024-08-14",
  "status": ["clientDeleteProhibited", "clientTransferProhibited"],
  "nameservers": [
    "ns1.example.com",
    "ns2.example.com"
  ],
  "registrant": {
    "organization": "Example Corp",
    "country": "US",
    "state": "California"
  },
  "raw_text": "..."
}
```

---

### 2.15 dig — DNS Enumeration

**Purpose**: DNS record lookup and zone information gathering.

**Risk Level**: LOW (public DNS queries)

**Timeout**: 30s

#### Parameters

| Parameter | Type | Required | Default | Validation | Description |
|---|---|---|---|---|---|
| `target` | string | YES | — | Domain regex | Target domain |
| `record_type` | enum | NO | `"A"` | One of: `A`, `AAAA`, `MX`, `NS`, `TXT`, `CNAME`, `SOA`, `PTR`, `SRV`, `ANY`, `AXFR` | DNS record type |
| `server` | string | NO | `null` | IPv4 or Domain regex | Specific DNS server |
| `short` | boolean | NO | `false` | — | Short answer only |
| `trace` | boolean | NO | `false` | — | Trace delegation path |
| `reverse` | boolean | NO | `false` | — | Reverse DNS lookup (`-x`) |
| `tcp` | boolean | NO | `false` | — | Use TCP instead of UDP |
| `no_recurse` | boolean | NO | `false` | — | Disable recursion |

**Blocked Record Types**: `AXFR` (zone transfer) is allowed only if the target is in scope, since it can transfer entire zone data.

#### Command Construction

```python
def build_dig_command(params: dict) -> list[str]:
    cmd = ["dig"]

    if params.get("server"):
        cmd.append(f"@{params['server']}")

    if params.get("reverse"):
        cmd.extend(["-x", params["target"]])
    else:
        cmd.append(params["target"])
        cmd.append(params.get("record_type", "A"))

    if params.get("short"):
        cmd.append("+short")
    if params.get("trace"):
        cmd.append("+trace")
    if params.get("tcp"):
        cmd.append("+tcp")
    if params.get("no_recurse"):
        cmd.append("+norecurse")

    cmd.append("+yaml")  # YAML output for easier parsing (BIND 9.18+)
    return cmd
```

#### Output Parsing

```json
{
  "query": {
    "domain": "example.com",
    "type": "A",
    "server": "8.8.8.8"
  },
  "answers": [
    {
      "name": "example.com",
      "type": "A",
      "ttl": 300,
      "value": "93.184.216.34"
    }
  ],
  "authority": [
    {
      "name": "example.com",
      "type": "NS",
      "ttl": 86400,
      "value": "ns1.example.com"
    }
  ],
  "additional": [],
  "query_time_ms": 24,
  "server_responded": "8.8.8.8#53",
  "message_size": 56
}
```

---

### 2.16 shell_command — General Purpose (Restricted)

**Purpose**: Execute arbitrary shell commands with strict restrictions for edge cases not covered by dedicated tools.

**Risk Level**: CRITICAL

**Timeout**: 60s

#### Parameters

| Parameter | Type | Required | Default | Validation | Description |
|---|---|---|---|---|---|
| `command` | string | YES | — | See whitelist below | The command to execute |
| `args` | list[string] | NO | `[]` | Per-arg validation | Command arguments |
| `working_dir` | string | NO | `"/tmp/rami-kali"` | `^/tmp/rami-kali(/[a-zA-Z0-9_.-]+)*$` | Working directory (restricted to /tmp/rami-kali) |
| `timeout` | integer | NO | `60` | 5-120 | Execution timeout |

#### Allowed Commands Whitelist

Only these base commands are permitted:

```python
ALLOWED_COMMANDS = {
    "cat", "ls", "head", "tail", "wc",
    "sort", "uniq", "cut", "tr", "awk",
    "grep", "find", "file", "xxd", "base64",
    "curl", "wget", "ping", "traceroute",
    "openssl", "ssh-keyscan", "smbclient",
    "python3", "perl", "ruby",
    "arp-scan", "nbtscan", "dnsrecon",
    "fierce", "theharvester",
    "msfconsole", "msfvenom"
}

BLOCKED_COMMANDS = {
    "rm", "rmdir", "mkfs", "dd", "shutdown", "reboot",
    "kill", "killall", "chmod", "chown", "chgrp",
    "useradd", "userdel", "passwd", "sudo", "su",
    "iptables", "systemctl", "service",
    "mv", "cp"  # only blocked outside /tmp/rami-kali
}
```

#### Command Construction

```python
def build_shell_command(params: dict) -> list[str]:
    base_cmd = params["command"]
    if base_cmd not in ALLOWED_COMMANDS:
        raise SecurityError(f"Command '{base_cmd}' is not in the allowed whitelist")
    if base_cmd in BLOCKED_COMMANDS:
        raise SecurityError(f"Command '{base_cmd}' is blocked")

    cmd = [base_cmd]
    for arg in params.get("args", []):
        # Validate each argument against dangerous patterns
        validate_argument(arg)
        cmd.append(arg)

    return cmd
```

---

## 3. Output Parsing

### 3.1 General Parsing Architecture

Each tool has a dedicated parser class that transforms raw CLI output into structured JSON:

```python
class BaseToolParser:
    """Base class for all tool output parsers."""

    def parse(self, stdout: str, stderr: str, exit_code: int) -> dict:
        """Parse tool output into structured JSON."""
        result = {
            "success": exit_code == 0,
            "exit_code": exit_code,
            "errors": self._extract_errors(stderr),
            "warnings": self._extract_warnings(stderr),
            "data": {}
        }
        if exit_code == 0:
            result["data"] = self._parse_output(stdout)
        return result

    def _parse_output(self, stdout: str) -> dict:
        raise NotImplementedError

    def _extract_errors(self, stderr: str) -> list[str]:
        return [line for line in stderr.split('\n') if line.strip()]

    def _extract_warnings(self, stderr: str) -> list[str]:
        return [line for line in stderr.split('\n') if 'warning' in line.lower()]
```

### 3.2 Parser Implementation Summary

| Tool | Input Format | Parsing Strategy | Key Library |
|---|---|---|---|
| **nmap** | XML (`-oX -`) | Parse XML tree, extract hosts/ports/services/scripts | `xml.etree.ElementTree` |
| **nikto** | JSON (`-Format json`) | Direct JSON parse | `json` |
| **gobuster** | Text (line-by-line) | Regex parse each line: `(path) (Status: code) [Size: N]` | `re` |
| **sqlmap** | Text (structured) | Multi-pattern regex for injection points, DBs, tables, dump | `re` |
| **hydra** | JSON (`-b json`) | Direct JSON parse | `json` |
| **enum4linux** | Text (sectioned) | Section-based regex (users, shares, groups, policy) | `re` |
| **wfuzz** | JSON (`-f -,json`) | Direct JSON parse | `json` |
| **netcat** | Text (raw) | Capture banner/response as-is, parse connection status | `re` |
| **searchsploit** | JSON (`-j`) | Direct JSON parse | `json` |
| **hashcat** | Text (machine-readable) | Parse `hash:plaintext` pairs and status lines | `re` |
| **john** | Text | Parse `password (username)` format and `--show` output | `re` |
| **dirb** | Text | Regex parse `+ URL (CODE:SIZE)` lines | `re` |
| **whatweb** | JSON (`--log-json=-`) | Direct JSON parse | `json` |
| **whois** | Text (key: value) | Key-value pair extraction with field normalization | `re` |
| **dig** | YAML or text | Parse ANSWER/AUTHORITY/ADDITIONAL sections | `yaml` or `re` |
| **shell_command** | Text (raw) | Return raw stdout/stderr | — |

### 3.3 Nmap XML Parser (Detailed Example)

```python
import xml.etree.ElementTree as ET

class NmapParser(BaseToolParser):
    def _parse_output(self, stdout: str) -> dict:
        root = ET.fromstring(stdout)
        result = {
            "scan_info": {
                "scanner": root.get("scanner", "nmap"),
                "args": root.get("args", ""),
                "start_time": root.get("startstr", ""),
                "elapsed_seconds": float(
                    root.find(".//finished").get("elapsed", "0")
                ) if root.find(".//finished") is not None else 0
            },
            "hosts": [],
            "summary": {"hosts_up": 0, "hosts_down": 0, "total_open_ports": 0}
        }

        for host_elem in root.findall("host"):
            host = self._parse_host(host_elem)
            result["hosts"].append(host)
            if host["state"] == "up":
                result["summary"]["hosts_up"] += 1
                result["summary"]["total_open_ports"] += len(
                    [p for p in host["ports"] if p["state"] == "open"]
                )
            else:
                result["summary"]["hosts_down"] += 1

        return result

    def _parse_host(self, host_elem) -> dict:
        host = {
            "ip": "",
            "hostname": "",
            "state": host_elem.find("status").get("state", "unknown"),
            "os_matches": [],
            "ports": []
        }

        # IP address
        for addr in host_elem.findall("address"):
            if addr.get("addrtype") == "ipv4":
                host["ip"] = addr.get("addr", "")

        # Hostname
        hostnames = host_elem.find("hostnames")
        if hostnames is not None:
            hn = hostnames.find("hostname")
            if hn is not None:
                host["hostname"] = hn.get("name", "")

        # OS detection
        os_elem = host_elem.find("os")
        if os_elem is not None:
            for osmatch in os_elem.findall("osmatch"):
                host["os_matches"].append({
                    "name": osmatch.get("name", ""),
                    "accuracy": int(osmatch.get("accuracy", "0"))
                })

        # Ports
        ports_elem = host_elem.find("ports")
        if ports_elem is not None:
            for port_elem in ports_elem.findall("port"):
                port = self._parse_port(port_elem)
                host["ports"].append(port)

        return host

    def _parse_port(self, port_elem) -> dict:
        state_elem = port_elem.find("state")
        service_elem = port_elem.find("service")

        port = {
            "port": int(port_elem.get("portid", "0")),
            "protocol": port_elem.get("protocol", "tcp"),
            "state": state_elem.get("state", "unknown") if state_elem is not None else "unknown",
            "service": "",
            "version": "",
            "product": "",
            "scripts": []
        }

        if service_elem is not None:
            port["service"] = service_elem.get("name", "")
            port["product"] = service_elem.get("product", "")
            version_parts = []
            if service_elem.get("version"):
                version_parts.append(service_elem.get("version"))
            if service_elem.get("extrainfo"):
                version_parts.append(service_elem.get("extrainfo"))
            port["version"] = " ".join(version_parts)

        for script_elem in port_elem.findall("script"):
            port["scripts"].append({
                "id": script_elem.get("id", ""),
                "output": script_elem.get("output", "")
            })

        return port
```

### 3.4 Gobuster Text Parser (Detailed Example)

```python
import re

class GobusterParser(BaseToolParser):
    # Pattern: /path                 (Status: 200) [Size: 1234]
    LINE_PATTERN = re.compile(
        r'^(\/\S+)\s+\(Status:\s+(\d+)\)\s+\[Size:\s+(\d+)\](?:\s+\[--> (.+)\])?'
    )

    def _parse_output(self, stdout: str) -> dict:
        results = []
        for line in stdout.strip().split('\n'):
            match = self.LINE_PATTERN.match(line.strip())
            if match:
                results.append({
                    "path": match.group(1),
                    "status": int(match.group(2)),
                    "size": int(match.group(3)),
                    "redirect_to": match.group(4)
                })

        return {
            "results": results,
            "statistics": {
                "items_found": len(results)
            }
        }
```

### 3.5 Enum4linux Text Parser (Detailed Example)

```python
import re

class Enum4linuxParser(BaseToolParser):
    def _parse_output(self, stdout: str) -> dict:
        return {
            "os_info": self._parse_os_info(stdout),
            "users": self._parse_users(stdout),
            "shares": self._parse_shares(stdout),
            "groups": self._parse_groups(stdout),
            "password_policy": self._parse_password_policy(stdout)
        }

    def _parse_users(self, text: str) -> list:
        users = []
        user_pattern = re.compile(r'user:\[(\S+)\]\s+rid:\[(0x[0-9a-f]+)\]', re.I)
        for match in user_pattern.finditer(text):
            users.append({
                "username": match.group(1),
                "rid": match.group(2)
            })
        return users

    def _parse_shares(self, text: str) -> list:
        shares = []
        share_pattern = re.compile(
            r'(\S+)\s+(Disk|IPC|Printer)\s+(.*?)$', re.MULTILINE
        )
        for match in share_pattern.finditer(text):
            shares.append({
                "name": match.group(1),
                "type": match.group(2),
                "comment": match.group(3).strip()
            })
        return shares

    def _parse_os_info(self, text: str) -> dict:
        os_info = {}
        os_pattern = re.compile(r'OS=\[(.*?)\]\s+Server=\[(.*?)\]')
        match = os_pattern.search(text)
        if match:
            os_info["os"] = match.group(1)
            os_info["server"] = match.group(2)

        domain_pattern = re.compile(r'Domain=\[(.*?)\]')
        match = domain_pattern.search(text)
        if match:
            os_info["domain"] = match.group(1)

        return os_info

    def _parse_groups(self, text: str) -> list:
        groups = []
        group_pattern = re.compile(
            r'group:\[(\S+)\]\s+rid:\[(0x[0-9a-f]+)\]', re.I
        )
        for match in group_pattern.finditer(text):
            groups.append({
                "name": match.group(1),
                "rid": match.group(2)
            })
        return groups

    def _parse_password_policy(self, text: str) -> dict:
        policy = {}
        patterns = {
            "min_length": r'Minimum password length:\s*(\d+)',
            "password_history": r'Password history length:\s*(\d+)',
            "max_age": r'Maximum password age.*?:\s*(\d+)',
            "min_age": r'Minimum password age.*?:\s*(\d+)',
            "lockout_threshold": r'Account lockout threshold:\s*(\d+)',
            "complexity_required": r'Password Complexity Flags:.*?(\d+)'
        }
        for key, pattern in patterns.items():
            match = re.search(pattern, text, re.I)
            if match:
                val = match.group(1)
                policy[key] = int(val) if val.isdigit() else val
        return policy
```

---

## 4. Red Team Workflow Patterns

### 4.1 Phase 1: Passive Reconnaissance

**Goal**: Gather information without directly interacting with target systems.

**Tool Chain**:

```
1. whois(target_domain)
   → Extract registrant info, nameservers, registration dates

2. dig(target_domain, record_type="ANY")
   → Get all DNS records (A, AAAA, MX, NS, TXT, SOA)

3. dig(target_domain, record_type="MX")
   → Identify mail servers

4. dig(target_domain, record_type="NS")
   → Identify authoritative nameservers

5. searchsploit(query=<identified_software>)
   → Search for known exploits based on discovered software versions

6. dig(target_domain, record_type="AXFR")  [if zone transfer allowed]
   → Attempt zone transfer for full subdomain enumeration
```

**AI Assistant Decision Logic**:
```
IF whois returns domain info:
    → Extract nameservers → dig NS records
    → Extract organization → note for social engineering context
IF dig returns MX records:
    → Note mail servers for later enumeration
IF dig returns multiple A records:
    → Queue each IP for active scanning phase
```

### 4.2 Phase 2: Active Reconnaissance

**Goal**: Identify live hosts, technologies, and attack surface.

**Tool Chain**:

```
1. nmap(target_range, scan_type="ping")
   → Discover live hosts in the target range

2. FOR EACH live_host:
     whatweb(live_host)
     → Fingerprint web technologies

3. FOR EACH live_host:
     nmap(live_host, scan_type="syn", ports="1-1024", service_detection=true)
     → Quick port scan with service detection

4. FOR interesting hosts (many open ports or key services):
     nmap(host, scan_type="syn", ports="all", service_detection=true, os_detection=true)
     → Full port scan with OS detection

5. FOR windows hosts (ports 135/139/445 open):
     enum4linux(host)
     → SMB enumeration

6. FOR web servers:
     nikto(http://host:port)
     → Vulnerability scan
```

**AI Assistant Decision Logic**:
```
IF nmap finds port 80/443:
    → Queue whatweb + nikto + gobuster
IF nmap finds port 22:
    → Note SSH version for searchsploit
IF nmap finds port 445/139:
    → Queue enum4linux
IF nmap finds port 3306/5432:
    → Note database service for potential sqlmap later
IF whatweb identifies CMS (WordPress, Joomla, Drupal):
    → searchsploit(CMS_name + version)
    → Queue specialized scanning
```

### 4.3 Phase 3: Vulnerability Scanning & Enumeration

**Goal**: Discover specific vulnerabilities and enumerate accessible resources.

**Tool Chain**:

```
1. nmap(target, scripts="vuln")
   → NSE vulnerability scripts

2. FOR EACH web server:
     gobuster(target_url, mode="dir", wordlist="common.txt")
     → Directory enumeration

     gobuster(target_url, mode="dir", wordlist="big.txt", extensions="php,asp,aspx,jsp,txt,bak")
     → Extended file enumeration

3. FOR interesting directories found:
     nikto(target_url + directory)
     → Scan discovered directories

4. FOR EACH web form / parameter found:
     wfuzz(url_with_FUZZ, ...)
     → Fuzz parameters for anomalies

5. FOR suspected SQL injection points:
     sqlmap(url, level=1, risk=1)
     → Test for SQL injection

6. searchsploit(identified_software_version)
   → Search exploits for every identified service/version
```

**AI Assistant Decision Logic**:
```
IF gobuster finds /admin, /login, /wp-admin:
    → Queue nikto on those paths
    → Queue hydra if login form found
IF gobuster finds /backup, /db, /.git:
    → Flag as HIGH priority finding
IF nikto finds outdated software:
    → searchsploit(software + version)
IF wfuzz finds parameter differences:
    → Queue sqlmap for potential SQLi
IF nmap vuln scripts find specific CVEs:
    → searchsploit(CVE-XXXX-XXXXX)
```

### 4.4 Phase 4: Exploitation

**Goal**: Validate discovered vulnerabilities through controlled exploitation.

**Tool Chain**:

```
1. sqlmap(target_url, param=<vuln_param>, level=3, risk=2, dbs=true)
   → Confirm SQLi and enumerate databases

2. sqlmap(target_url, param=<vuln_param>, database=<db>, tables=true)
   → Enumerate tables in discovered database

3. sqlmap(target_url, param=<vuln_param>, database=<db>, table=<users>, dump=true)
   → Extract credential data

4. hashcat/john(extracted_hashes, ...)
   → Crack password hashes

5. hydra(target, service=<service>, user_list=<extracted_users>, pass_list=<cracked_passwords>)
   → Test cracked credentials against other services
```

**AI Assistant Decision Logic**:
```
IF sqlmap confirms injection:
    → Enumerate databases → tables → dump users table
IF password hashes found:
    → Identify hash type → hashcat/john with appropriate mode
IF credentials cracked:
    → Test against SSH, RDP, SMB, other services via hydra
    → NEVER test against out-of-scope systems
ALWAYS:
    → Document exploitation path for report
    → Note impact level
```

### 4.5 Phase 5: Post-Exploitation (Limited)

**Goal**: Determine impact and document findings.

**Supported Actions** (via shell_command with restrictions):
```
1. Verify access level with cracked credentials
2. Document accessible resources
3. Identify lateral movement possibilities (documentation only)
4. Screenshot/evidence collection
```

**NOT Supported** (out of scope for this MCP server):
- Persistent backdoors / implants
- Privilege escalation execution
- Lateral movement execution
- Data exfiltration beyond proof-of-concept
- Modifying target system configurations

### 4.6 AI Assistant Chaining Strategy

The AI assistant should follow this decision tree when chaining tools:

```
START
├── User provides target scope
│   ├── Single IP → Skip to Active Recon
│   ├── Domain → Start with Passive Recon
│   └── CIDR range → Start with Host Discovery
│
├── Passive Recon (if domain)
│   ├── whois → dig → searchsploit
│   └── Collect: IPs, subdomains, mail servers, nameservers
│
├── Active Recon
│   ├── nmap ping sweep (CIDR) or direct scan (single IP)
│   ├── For each live host:
│   │   ├── Quick port scan (top 1024)
│   │   ├── whatweb (if web ports open)
│   │   └── enum4linux (if SMB ports open)
│   └── Collect: open ports, services, versions, technologies
│
├── Vulnerability Scanning
│   ├── nmap vuln scripts on interesting hosts
│   ├── nikto on web servers
│   ├── gobuster for directory enumeration
│   ├── searchsploit for each service:version found
│   └── Collect: vulnerabilities, interesting paths, CVEs
│
├── Targeted Testing
│   ├── sqlmap on suspected SQLi points
│   ├── wfuzz on interesting parameters
│   ├── hydra on login forms (with CAUTION)
│   └── Collect: confirmed vulnerabilities, credentials
│
├── Exploitation (with explicit user confirmation)
│   ├── sqlmap enumeration/dump
│   ├── hashcat/john for hash cracking
│   └── Credential validation
│
└── REPORT: Compile all findings with evidence
```

### 4.7 Reporting Recommendations

After each phase, the AI should present a structured summary:

```json
{
  "phase": "Active Reconnaissance",
  "target": "192.168.1.0/24",
  "timestamp": "2026-02-13T15:00:00Z",
  "findings": [
    {
      "host": "192.168.1.10",
      "severity": "HIGH",
      "finding": "Apache 2.4.49 detected - vulnerable to CVE-2021-41773 (path traversal/RCE)",
      "evidence": "nmap service detection: Apache/2.4.49, searchsploit: EDB-50383",
      "recommendation": "Upgrade Apache to 2.4.52+"
    }
  ],
  "next_steps": [
    "Run nikto against http://192.168.1.10 for web vulnerability scanning",
    "Run gobuster for directory enumeration",
    "Test CVE-2021-41773 with targeted nmap script"
  ]
}
```

---

## 5. MCP Server Implementation Details

### 5.1 MCP Server Structure

```
rami-kali/
├── src/
│   ├── index.ts                    # MCP server entry point
│   ├── config/
│   │   ├── scope.json              # Target scope configuration
│   │   ├── authorized_keys.json    # API key hashes
│   │   └── rate_limits.json        # Per-tool rate limits
│   ├── security/
│   │   ├── scope_validator.ts      # Target scope enforcement
│   │   ├── input_sanitizer.ts      # Input validation and sanitization
│   │   ├── rate_limiter.ts         # Rate limiting implementation
│   │   ├── auth.ts                 # Authentication middleware
│   │   └── audit_logger.ts         # Structured audit logging
│   ├── tools/
│   │   ├── base_tool.ts            # Base tool class with common logic
│   │   ├── nmap.ts                 # nmap tool definition
│   │   ├── nikto.ts                # nikto tool definition
│   │   ├── gobuster.ts             # gobuster tool definition
│   │   ├── sqlmap.ts               # sqlmap tool definition
│   │   ├── hydra.ts                # hydra tool definition
│   │   ├── enum4linux.ts           # enum4linux tool definition
│   │   ├── wfuzz.ts                # wfuzz tool definition
│   │   ├── netcat.ts               # netcat tool definition
│   │   ├── searchsploit.ts         # searchsploit tool definition
│   │   ├── hashcat.ts              # hashcat tool definition
│   │   ├── john.ts                 # john tool definition
│   │   ├── dirb.ts                 # dirb tool definition
│   │   ├── whatweb.ts              # whatweb tool definition
│   │   ├── whois.ts                # whois tool definition
│   │   ├── dig.ts                  # dig tool definition
│   │   └── shell_command.ts        # Restricted shell command
│   ├── parsers/
│   │   ├── base_parser.ts          # Base parser class
│   │   ├── nmap_parser.ts          # XML → JSON
│   │   ├── nikto_parser.ts         # JSON passthrough
│   │   ├── gobuster_parser.ts      # Text → JSON
│   │   ├── sqlmap_parser.ts        # Text → JSON
│   │   ├── hydra_parser.ts         # JSON passthrough
│   │   ├── enum4linux_parser.ts    # Text → JSON
│   │   ├── wfuzz_parser.ts         # JSON passthrough
│   │   ├── netcat_parser.ts        # Text → JSON
│   │   ├── searchsploit_parser.ts  # JSON passthrough
│   │   ├── hashcat_parser.ts       # Text → JSON
│   │   ├── john_parser.ts          # Text → JSON
│   │   ├── dirb_parser.ts          # Text → JSON
│   │   ├── whatweb_parser.ts       # JSON passthrough
│   │   ├── whois_parser.ts         # Text → JSON
│   │   └── dig_parser.ts           # Text/YAML → JSON
│   └── utils/
│       ├── command_builder.ts      # Safe command array construction
│       ├── process_runner.ts       # subprocess execution with timeout
│       └── temp_file_manager.ts    # Temp file creation/cleanup
├── logs/                           # Audit logs directory
├── config/                         # Runtime configuration
├── package.json
├── tsconfig.json
└── README.md
```

### 5.2 MCP Tool Registration Format

Each tool is registered with the MCP server using this schema:

```typescript
interface MCPToolDefinition {
  name: string;
  description: string;
  inputSchema: {
    type: "object";
    properties: Record<string, {
      type: string;
      description: string;
      enum?: string[];
      default?: any;
      minimum?: number;
      maximum?: number;
    }>;
    required: string[];
  };
}
```

Example for nmap:

```typescript
{
  name: "nmap",
  description: "Network scanner for host discovery, port scanning, service detection, OS fingerprinting, and vulnerability script scanning. Requires target to be within authorized scope.",
  inputSchema: {
    type: "object",
    properties: {
      target: {
        type: "string",
        description: "Target IP, CIDR range, or domain (must be in authorized scope)"
      },
      scan_type: {
        type: "string",
        enum: ["syn", "connect", "udp", "ack", "fin", "xmas", "null", "ping"],
        default: "syn",
        description: "TCP scan technique"
      },
      ports: {
        type: "string",
        default: "1-1024",
        description: "Port specification (e.g., '80,443', '1-1024', 'all', 'common')"
      },
      service_detection: {
        type: "boolean",
        default: false,
        description: "Enable service/version detection (-sV)"
      },
      os_detection: {
        type: "boolean",
        default: false,
        description: "Enable OS fingerprinting (-O, requires root)"
      },
      scripts: {
        type: "string",
        description: "NSE scripts to run (e.g., 'vuln', 'default,safe')"
      },
      timing: {
        type: "string",
        enum: ["T0", "T1", "T2", "T3", "T4", "T5"],
        default: "T3",
        description: "Timing template (T0=paranoid, T5=insane)"
      },
      aggressive: {
        type: "boolean",
        default: false,
        description: "Enable aggressive mode (-A): OS detect + version + scripts + traceroute"
      },
      no_ping: {
        type: "boolean",
        default: false,
        description: "Skip host discovery, scan all targets (-Pn)"
      },
      top_ports: {
        type: "number",
        minimum: 1,
        maximum: 65535,
        description: "Scan top N most common ports"
      }
    },
    required: ["target"]
  }
}
```

### 5.3 Execution Pipeline

```typescript
async function executeTool(
  toolName: string,
  params: Record<string, any>,
  sessionContext: SessionContext
): Promise<MCPToolResult> {
  const startTime = Date.now();

  // 1. Authentication check
  if (!sessionContext.isAuthenticated) {
    throw new AuthError("Session not authenticated");
  }

  // 2. Rate limiting
  const rateLimiter = getRateLimiter(toolName);
  if (!rateLimiter.allow(sessionContext.userId)) {
    throw new RateLimitError(`Rate limit exceeded for ${toolName}`);
  }

  // 3. Input sanitization
  const sanitizer = getSanitizer(toolName);
  const sanitizedParams = sanitizer.validate(params);
  // Throws if any parameter fails validation

  // 4. Scope validation
  const targets = extractTargets(toolName, sanitizedParams);
  for (const target of targets) {
    if (!scopeValidator.isAllowed(target)) {
      throw new ScopeError(`Target ${target} is outside authorized scope`);
    }
  }

  // 5. Risk level check
  const riskLevel = assessRisk(toolName, sanitizedParams);
  if (riskLevel === "CRITICAL") {
    // Return confirmation request to AI assistant
    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          status: "confirmation_required",
          risk_level: "CRITICAL",
          message: `Tool ${toolName} with these parameters is rated CRITICAL risk. Please confirm execution.`,
          params: sanitizedParams
        })
      }]
    };
  }

  // 6. Build command
  const builder = getCommandBuilder(toolName);
  const cmdArgs = builder.build(sanitizedParams);

  // 7. Execute with timeout
  const timeout = getTimeout(toolName, sanitizedParams);
  const result = await processRunner.execute(cmdArgs, {
    timeout,
    cwd: "/tmp/rami-kali",
    env: SANITIZED_ENV
  });

  // 8. Parse output
  const parser = getParser(toolName);
  const parsed = parser.parse(result.stdout, result.stderr, result.exitCode);

  // 9. Audit log
  auditLogger.log({
    timestamp: new Date().toISOString(),
    session_id: sessionContext.sessionId,
    user: sessionContext.userId,
    tool: toolName,
    parameters: sanitizedParams,
    command_executed: cmdArgs,
    scope_check: "PASS",
    sanitization_check: "PASS",
    execution_time_ms: Date.now() - startTime,
    exit_code: result.exitCode,
    output_size_bytes: result.stdout.length,
    risk_level: riskLevel,
    result_summary: generateSummary(toolName, parsed)
  });

  // 10. Return structured result
  return {
    content: [{
      type: "text",
      text: JSON.stringify(parsed, null, 2)
    }]
  };
}
```

### 5.4 Environment Sanitization

The subprocess environment is stripped to prevent information leakage:

```typescript
const SANITIZED_ENV: Record<string, string> = {
  PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
  HOME: "/tmp/rami-kali",
  TERM: "xterm",
  LANG: "en_US.UTF-8",
  LC_ALL: "en_US.UTF-8"
};
// All other environment variables are NOT passed to subprocesses
```

### 5.5 Error Handling

```typescript
enum ErrorType {
  AUTH_ERROR = "authentication_error",
  SCOPE_ERROR = "scope_violation",
  VALIDATION_ERROR = "input_validation_error",
  RATE_LIMIT = "rate_limit_exceeded",
  TIMEOUT = "execution_timeout",
  TOOL_ERROR = "tool_execution_error",
  PARSE_ERROR = "output_parse_error",
  SECURITY_ERROR = "security_violation"
}

// All errors are logged to audit log with full context
// Security errors (SCOPE_ERROR, SECURITY_ERROR) trigger alerts
```

### 5.6 Common Hash Type Reference (for hashcat)

| Code | Hash Type | Example |
|---|---|---|
| 0 | MD5 | `5f4dcc3b5aa765d61d8327deb882cf99` |
| 100 | SHA1 | `5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8` |
| 1400 | SHA256 | `5e884898da28047151d0e56f8dc6292773603d0d...` |
| 1000 | NTLM | `a4f49c406510bdcab6824ee7c30fd852` |
| 1800 | sha512crypt | `$6$rounds=5000$salt$hash...` |
| 3200 | bcrypt | `$2a$12$salt...hash...` |
| 500 | md5crypt | `$1$salt$hash...` |
| 7400 | sha256crypt | `$5$rounds=5000$salt$hash...` |
| 13100 | Kerberos TGS | `$krb5tgs$23$*...` |
| 5600 | NetNTLMv2 | `username::domain:challenge:hmac:blob` |
| 22000 | WPA-PBKDF2-PMKID+EAPOL | Captured WiFi handshakes |

---

## Appendix A: Wordlist Reference

Standard wordlist paths available on Kali Linux:

| Purpose | Path |
|---|---|
| Common directories | `/usr/share/wordlists/dirb/common.txt` |
| Large directories | `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt` |
| Passwords (default) | `/usr/share/wordlists/rockyou.txt` |
| Usernames | `/usr/share/seclists/Usernames/top-usernames-shortlist.txt` |
| Subdomains | `/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt` |
| Web extensions | `/usr/share/seclists/Discovery/Web-Content/web-extensions.txt` |
| Fuzzing (XSS) | `/usr/share/seclists/Fuzzing/XSS/XSS-BruteLogic.txt` |
| Fuzzing (SQLi) | `/usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt` |
| Nmap scripts | `/usr/share/nmap/scripts/` |

## Appendix B: Quick Reference — Risk Levels by Tool

| Tool | Default Risk | Escalates to HIGH/CRITICAL when... |
|---|---|---|
| whois | LOW | Never |
| dig | LOW | AXFR zone transfer attempts |
| searchsploit | LOW | Never |
| whatweb | LOW | aggression >= 3 |
| nmap | MEDIUM | vuln scripts, aggressive mode, full port scan |
| gobuster | MEDIUM | Large wordlists, high thread counts |
| dirb | MEDIUM | Recursive mode with large wordlists |
| enum4linux | MEDIUM | Never (inherently active) |
| netcat | MEDIUM | Never (listen mode blocked) |
| nikto | HIGH | Always (active vulnerability probing) |
| wfuzz | HIGH | Always (active fuzzing) |
| sqlmap | CRITICAL | Always (SQL injection testing) |
| hydra | CRITICAL | Always (brute force authentication) |
| hashcat | LOW | Never (local computation) |
| john | LOW | Never (local computation) |
| shell_command | CRITICAL | Always (arbitrary command execution) |

---

*This architecture document defines the complete design for the Red Team MCP Server. All tools are intended for authorized penetration testing and security research only. Unauthorized use against systems without explicit written permission is illegal and unethical.*
