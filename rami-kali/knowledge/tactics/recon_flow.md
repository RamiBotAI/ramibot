# Recon Flow — Tactical Methodology

## Phase 1: Passive Recon (Zero Noise)

```
TARGET RECEIVED
  │
  ├─ whois <domain>         → registrant, nameservers, dates
  ├─ dig <domain> ANY       → DNS records (A, MX, NS, TXT)
  ├─ dig axfr @<ns> <domain>→ zone transfer attempt (often fails, free info if works)
  └─ searchsploit prep      → note known tech if provided
```

**Outcome**: Domain structure, IP ranges, mail servers, nameservers.

## Phase 2: Active Discovery (Low Noise)

```
IPs IDENTIFIED
  │
  ├─ If single host:
  │   └─ nmap -sS -sV -sC -O -p- <target>   → full port scan
  │
  ├─ If subnet:
  │   ├─ nmap -sn <cidr>                      → host discovery first
  │   └─ Then per-host scanning on live IPs
  │
  └─ For each HTTP port found:
      └─ whatweb <url>                          → tech fingerprint
```

**Outcome**: Live hosts, open ports, service versions, web technologies.

## Phase 3: Enumeration (Medium Noise)

```
SERVICES KNOWN
  │
  ├─ Every version found    → searchsploit <service> <version>
  │
  ├─ Web services:
  │   ├─ Check /robots.txt, /sitemap.xml, /.git/
  │   ├─ gobuster dir -u <url> -w <wordlist> -x <extensions>
  │   └─ nikto -h <url>
  │
  ├─ SMB (139/445):
  │   └─ enum4linux -a <target>
  │
  ├─ SNMP (161):
  │   └─ snmpwalk -v2c -c public <target>
  │
  └─ DNS (53):
      └─ dig axfr @<target> <domain>
```

**Outcome**: Hidden content, users, shares, vulnerabilities, exploit candidates.

## Phase 4: Targeted Testing (Higher Noise)

```
ATTACK SURFACE MAPPED
  │
  ├─ SQLi candidates?    → sqlmap
  ├─ Login forms?         → default creds → SQLi → hydra
  ├─ File upload?         → test restrictions, try shell
  ├─ LFI candidates?     → test ../../../etc/passwd
  ├─ Known exploit?       → searchsploit → verify → execute
  └─ Creds found?        → reuse on all services
```

## Decision: When to Move to Next Phase

```
MOVE FORWARD WHEN:
  ✅ All open ports identified and service versions noted
  ✅ All web apps fingerprinted and directories scanned
  ✅ All service versions checked against searchsploit
  ✅ SMB/LDAP/SNMP enumerated if present
  ✅ Low-hanging fruit checked (default creds, anon access)

DO NOT MOVE FORWARD IF:
  ❌ You haven't finished reading the previous scan output
  ❌ You're guessing instead of enumerating
  ❌ You skipped a port because "it's probably nothing"
```
