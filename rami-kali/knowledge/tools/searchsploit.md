# searchsploit — Exploit Database Search

## Why
Searches local copy of Exploit-DB for known vulnerabilities. Instant, offline, zero noise. Should be used after EVERY version discovery.

## When to Use

| Signal | Action |
|---|---|
| Service version found (nmap -sV) | Search immediately |
| CMS + version (whatweb) | Search immediately |
| Software name in banner | Search immediately |
| OS version identified | Check for kernel exploits |

## Common Invocations

```bash
# Basic search
searchsploit <software> <version>

# Examples
searchsploit apache 2.4.49
searchsploit openssh 7.2
searchsploit wordpress 5.0
searchsploit vsftpd 2.3.4

# Broader search (if exact version has no results)
searchsploit apache 2.4
searchsploit openssh 7

# Read exploit details
searchsploit -x <exploit_path>

# Copy exploit to working dir
searchsploit -m <exploit_path>

# JSON output (for parsing)
searchsploit --json <query>

# Exclude DoS results (usually not useful)
searchsploit --exclude="Denial of Service" <query>
```

## Search Strategy

```
1. Exact version first:  "vsftpd 2.3.4"
2. Minor version:        "vsftpd 2.3"
3. Major version:        "vsftpd 2"
4. Software name only:   "vsftpd"
5. Check related:        "ProFTPD" if FTP but not vsftpd
```

## Parsing Priorities

1. **RCE exploits** → highest value, direct shell
2. **Auth bypass** → access without creds
3. **LFI/RFI** → file read/inclusion → potential RCE
4. **SQLi** → data extraction, possible RCE
5. **Privilege escalation** → after initial access
6. **Info disclosure** → credentials, paths
7. **DoS** → usually lowest priority (proves impact, not access)

## Exploit Quality Assessment

| Indicator | Confidence |
|---|---|
| Exact version match + Metasploit | HIGH — likely works |
| Exact version match + Python/Ruby | HIGH — review code first |
| Close version match | MEDIUM — may need modification |
| Old exploit, patched versions exist | LOW — target likely patched |
| Multiple exploits for same vuln | GOOD — well-known, reliable |

## Junior Mistakes

- Not searching at all (biggest mistake — free, fast, no noise)
- Searching too specific ("Apache httpd 2.4.49 Ubuntu" — just use "apache 2.4.49")
- Ignoring results that need minor version adjustment
- Not reading the exploit code before using it
- Skipping the "also try" related software

## Pivot After searchsploit

```
RCE found?        → review code → test (carefully, in scope)
LFI found?        → read /etc/passwd, config files
Auth bypass?      → access the service directly
Nothing found?    → target may be patched, try other attack vectors
Kernel exploit?   → save for post-exploitation privesc
```
