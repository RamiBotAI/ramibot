# Rami-Kali — Tactical Knowledge Base

## Purpose
Internal reasoning memory for a 7B local LLM operating MCP security tools.
Optimized for **fast lookup**, not explanation.

## Design Rules
- Agent consults these files INTERNALLY to make better decisions
- Agent does NOT narrate this knowledge to the user unprompted
- Explanations activate ONLY on explicit user request ("why?", "explain", "teach me")
- Default behavior: concise action, forward momentum

## Structure

```
knowledge/
  core_principles.md    — Decision axioms, always loaded
  engagement_rules.md   — Scope, ethics, abort conditions
  pivot_map.md          — "If X found → do Y" decision tree
  LOADER.md             — How to inject knowledge into 7B context

  tactics/
    recon_flow.md       — Reconnaissance methodology
    enumeration.md      — Service/user/share enumeration
    exploitation.md     — Exploit selection logic

  tools/
    # Reconnaissance
    nmap.md             — Port/service scanner
    whatweb.md          — Web fingerprinting
    whois.md            — Domain registration lookup
    dig.md              — DNS enumeration

    # Web Scanning & Fuzzing
    gobuster.md         — Directory/DNS bruteforce
    nikto.md            — Web vuln scanner
    wfuzz.md            — Web fuzzer (params, headers, vhosts)
    dirb.md             — Directory scanner (simple)
    web_scanners.md     — ZAP, Burp, wpscan, joomscan, droopescan

    # Exploitation
    sqlmap.md           — SQL injection
    searchsploit.md     — Exploit database search
    metasploit.md       — msf_console, msfvenom, msf_db, resources

    # Credential Attacks
    hydra.md            — Credential bruteforce
    brute_alt.md        — medusa, ncrack, patator, xhydra
    hashcat.md          — GPU hash cracking
    john.md             — CPU hash cracking
    wordlist_gen.md     — crunch, cewl

    # SMB/AD/Windows
    enum4linux.md       — SMB/NetBIOS enumeration
    smbclient.md        — SMB share access
    smb_advanced.md     — smbmap, rpcclient
    ad_tools.md         — bloodhound, crackmapexec, evil-winrm,
                          impacket (psexec/wmiexec/smbexec/secretsdump),
                          mimikatz, pth_tools

    # Network
    netcat.md           — Raw TCP/UDP connections
    mitm.md             — bettercap, ettercap, mitmproxy, responder

    # Wireless
    wireless.md         — aircrack-ng, reaver, bully, wifite

    # Social Engineering & C2
    social_engineering.md — setoolkit, beef, empire, cobaltstrike,
                           veil, shellter, powersploit

    # Manual Testing
    curl.md             — HTTP request tool

  interpretation/
    ports.md            — Port → service → attack surface map
    web.md              — HTTP response interpretation
    auth.md             — Auth mechanisms, default creds, hash ID
```

## Tool → Knowledge File Map

| MCP Tool Name | Knowledge File |
|---|---|
| `nmap_scan` | tools/nmap.md |
| `nikto_scan` | tools/nikto.md |
| `gobuster_dir` | tools/gobuster.md |
| `sqlmap_scan` | tools/sqlmap.md |
| `hydra_attack` | tools/hydra.md |
| `enum4linux_scan` | tools/enum4linux.md |
| `wfuzz_scan` | tools/wfuzz.md |
| `netcat_connect` | tools/netcat.md |
| `searchsploit_query` | tools/searchsploit.md |
| `hashcat_crack` | tools/hashcat.md |
| `john_crack` | tools/john.md |
| `dirb_scan` | tools/dirb.md |
| `whatweb_scan` | tools/whatweb.md |
| `whois_lookup` | tools/whois.md |
| `dig_lookup` | tools/dig.md |
| `msf_console` | tools/metasploit.md |
| `msfvenom` | tools/metasploit.md |
| `msf_db` | tools/metasploit.md |
| `metasploit_resource` | tools/metasploit.md |
| `beef_start` | tools/social_engineering.md |
| `setoolkit` | tools/social_engineering.md |
| `bettercap` | tools/mitm.md |
| `ettercap` | tools/mitm.md |
| `responder` | tools/mitm.md |
| `mitmproxy` | tools/mitm.md |
| `aircrack_ng` | tools/wireless.md |
| `reaver` | tools/wireless.md |
| `bully` | tools/wireless.md |
| `wifite` | tools/wireless.md |
| `crunch` | tools/wordlist_gen.md |
| `cewl` | tools/wordlist_gen.md |
| `medusa` | tools/brute_alt.md |
| `ncrack` | tools/brute_alt.md |
| `patator` | tools/brute_alt.md |
| `xhydra` | tools/brute_alt.md |
| `owasp_zap` | tools/web_scanners.md |
| `burpsuite` | tools/web_scanners.md |
| `wpscan` | tools/web_scanners.md |
| `joomscan` | tools/web_scanners.md |
| `drupwn` | tools/web_scanners.md |
| `droopescan` | tools/web_scanners.md |
| `smbmap` | tools/smb_advanced.md |
| `smbclient` | tools/smbclient.md |
| `rpcclient` | tools/smb_advanced.md |
| `impacket` | tools/ad_tools.md |
| `bloodhound` | tools/ad_tools.md |
| `crackmapexec` | tools/ad_tools.md |
| `evil_winrm` | tools/ad_tools.md |
| `psexec` | tools/ad_tools.md |
| `wmiexec` | tools/ad_tools.md |
| `smbexec` | tools/ad_tools.md |
| `secretsdump` | tools/ad_tools.md |
| `mimikatz` | tools/ad_tools.md |
| `pth_tools` | tools/ad_tools.md |
| `powersploit` | tools/social_engineering.md |
| `empire` | tools/social_engineering.md |
| `cobaltstrike` | tools/social_engineering.md |
| `veil` | tools/social_engineering.md |
| `shellter` | tools/social_engineering.md |
| `msf_payload_generator` | tools/metasploit.md |
| `shell_command` | (generic — no specific file) |
| `auto_recon` | tactics/recon_flow.md |
| `get_scan_history` | (utility — no specific file) |
| `generate_report` | (utility — no specific file) |

## How the Agent Uses This

1. Receive task or scan result
2. Consult `pivot_map.md` for next action
3. Look up tool in map above → load relevant `tools/*.md`
4. Consult `interpretation/*.md` to parse results
5. Act. Be quiet. Move forward.
