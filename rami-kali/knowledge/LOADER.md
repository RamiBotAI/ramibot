# Knowledge Base Loader — System Prompt Integration

> Defines HOW the 7B LLM should use this knowledge base.

## Loading Strategy

A 7B model has limited context. Do NOT load everything at once.

### Always Loaded (system prompt)
- `core_principles.md` — decision axioms (small, critical)
- `engagement_rules.md` — scope/risk rules (safety-critical)

### Loaded On-Demand (RAG or conditional injection)

| Trigger | Inject |
|---|---|
| Any scan completes | `pivot_map.md` |
| Before calling a tool | `tools/<relevant>.md` (see README map) |
| After nmap results | `interpretation/ports.md` |
| Web service discovered | `interpretation/web.md` |
| Auth mechanism found | `interpretation/auth.md` |
| Engagement start | `tactics/recon_flow.md` |
| Enumeration phase | `tactics/enumeration.md` |
| Exploit considered | `tactics/exploitation.md` |

### Tool → File Routing (pseudocode)

```python
TOOL_KNOWLEDGE_MAP = {
    # Recon
    "nmap_scan": "tools/nmap.md",
    "whatweb_scan": "tools/whatweb.md",
    "whois_lookup": "tools/whois.md",
    "dig_lookup": "tools/dig.md",

    # Web
    "gobuster_dir": "tools/gobuster.md",
    "nikto_scan": "tools/nikto.md",
    "wfuzz_scan": "tools/wfuzz.md",
    "dirb_scan": "tools/dirb.md",
    "owasp_zap": "tools/web_scanners.md",
    "burpsuite": "tools/web_scanners.md",
    "wpscan": "tools/web_scanners.md",
    "joomscan": "tools/web_scanners.md",
    "drupwn": "tools/web_scanners.md",
    "droopescan": "tools/web_scanners.md",

    # Exploitation
    "sqlmap_scan": "tools/sqlmap.md",
    "searchsploit_query": "tools/searchsploit.md",
    "msf_console": "tools/metasploit.md",
    "msfvenom": "tools/metasploit.md",
    "msf_db": "tools/metasploit.md",
    "metasploit_resource": "tools/metasploit.md",
    "msf_payload_generator": "tools/metasploit.md",

    # Credential Attacks
    "hydra_attack": "tools/hydra.md",
    "medusa": "tools/brute_alt.md",
    "ncrack": "tools/brute_alt.md",
    "patator": "tools/brute_alt.md",
    "xhydra": "tools/brute_alt.md",
    "hashcat_crack": "tools/hashcat.md",
    "john_crack": "tools/john.md",
    "crunch": "tools/wordlist_gen.md",
    "cewl": "tools/wordlist_gen.md",

    # SMB/AD/Windows
    "enum4linux_scan": "tools/enum4linux.md",
    "smbclient": "tools/smbclient.md",
    "smbmap": "tools/smb_advanced.md",
    "rpcclient": "tools/smb_advanced.md",
    "bloodhound": "tools/ad_tools.md",
    "crackmapexec": "tools/ad_tools.md",
    "evil_winrm": "tools/ad_tools.md",
    "impacket": "tools/ad_tools.md",
    "psexec": "tools/ad_tools.md",
    "wmiexec": "tools/ad_tools.md",
    "smbexec": "tools/ad_tools.md",
    "secretsdump": "tools/ad_tools.md",
    "mimikatz": "tools/ad_tools.md",
    "pth_tools": "tools/ad_tools.md",

    # Network
    "netcat_connect": "tools/netcat.md",
    "bettercap": "tools/mitm.md",
    "ettercap": "tools/mitm.md",
    "responder": "tools/mitm.md",
    "mitmproxy": "tools/mitm.md",

    # Wireless
    "aircrack_ng": "tools/wireless.md",
    "reaver": "tools/wireless.md",
    "bully": "tools/wireless.md",
    "wifite": "tools/wireless.md",

    # Social Engineering & C2
    "setoolkit": "tools/social_engineering.md",
    "beef_start": "tools/social_engineering.md",
    "empire": "tools/social_engineering.md",
    "cobaltstrike": "tools/social_engineering.md",
    "veil": "tools/social_engineering.md",
    "shellter": "tools/social_engineering.md",
    "powersploit": "tools/social_engineering.md",
}

def get_context(tool_name, scan_results=""):
    context = []

    # Always inject tool-specific knowledge
    if tool_name in TOOL_KNOWLEDGE_MAP:
        context.append(load(TOOL_KNOWLEDGE_MAP[tool_name]))

    # Context-aware injection based on results
    if tool_name == "nmap_scan":
        context.append(load("interpretation/ports.md"))
        context.append(load("pivot_map.md"))

    elif tool_name in ["whatweb_scan", "gobuster_dir", "nikto_scan",
                        "wfuzz_scan", "dirb_scan"]:
        context.append(load("interpretation/web.md"))
        context.append(load("pivot_map.md"))

    elif tool_name in ["enum4linux_scan", "smbclient", "smbmap", "rpcclient"]:
        context.append(load("pivot_map.md"))

    elif tool_name in ["hydra_attack", "medusa", "ncrack", "patator"]:
        context.append(load("interpretation/auth.md"))

    elif tool_name in ["hashcat_crack", "john_crack"]:
        context.append(load("interpretation/auth.md"))  # hash ID table

    # Result-based triggers
    if "login" in scan_results or "auth" in scan_results:
        context.append(load("interpretation/auth.md"))
    if "version" in scan_results:
        context.append(load("tools/searchsploit.md"))

    return context
```

## Behavior Prompt Template

```
You are a security assessment operator with access to MCP tools for authorized penetration testing.

BEHAVIOR:
- Execute concisely. Do not explain unless asked.
- Follow methodology: RECON → ENUMERATE → IDENTIFY → EXPLOIT → PIVOT
- Consult knowledge base internally before each action.
- Never skip enumeration to jump to exploitation.
- Validate scope before every tool call.
- ALWAYS respond in the SAME LANGUAGE the user is using. If the user writes in Spanish, respond entirely in Spanish. If in English, respond in English. Only technical terms (tool names, CVEs, parameters, command syntax) remain in English.

WHEN ACTING: be brief, act, move forward.
WHEN ASKED "why?" / "explain" / "teach me": provide full reasoning.

[INJECT RELEVANT KNOWLEDGE SECTIONS HERE BASED ON CURRENT PHASE]
```

## Context Budget (7B Model Guidance)

```
System prompt base:     ~500 tokens
core_principles.md:     ~400 tokens
engagement_rules.md:    ~300 tokens
Per-tool knowledge:     ~400-600 tokens each
interpretation file:    ~500-800 tokens each
pivot_map.md:           ~1000 tokens (load relevant section only)

TARGET: Keep injected context under 2500 tokens per turn
MAX:    4096 tokens total context for 7B model
```
