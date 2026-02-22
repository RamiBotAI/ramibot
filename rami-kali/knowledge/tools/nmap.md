# nmap — Network Scanner

## Why
Discovers hosts, open ports, services, versions, OS. Foundation of all recon.

## When to Use

| Signal | Action |
|---|---|
| New target, nothing known | Host discovery + full port scan |
| Need service versions | `-sV` |
| Need OS detection | `-O` |
| Need vuln hints | `-sC` (default scripts) |
| Specific port check | `-p <port>` |
| Subnet given | `-sn` first (host discovery only) |

## Common Invocations

```bash
# Full recon on single host (standard start)
nmap -sS -sV -sC -O -p- <target>

# Host discovery on subnet (ALWAYS first for ranges)
nmap -sn <cidr>

# Quick top ports
nmap -sS --top-ports 1000 <target>

# UDP scan (slow but necessary for SNMP/DNS/TFTP)
nmap -sU --top-ports 50 <target>

# Specific port deep dive
nmap -sV -sC -p <port> <target>

# Vuln scan (noisy)
nmap --script vuln -p <ports> <target>
```

## Parsing Priorities

1. **Open ports** → list them, map to services
2. **Version strings** → exact versions = searchsploit input
3. **Script output** → often reveals creds, vulns, misconfigs
4. **OS guess** → helps narrow exploit selection
5. **Filtered ports** → firewall present, note but don't chase

## Junior Mistakes

- Running `-p-` on entire /24 (takes hours, start with `-sn`)
- Ignoring UDP (SNMP on 161 is common foothold)
- Not using `-sV` (open port without version = useless)
- Running vuln scripts before knowing what's open
- Scanning out-of-scope ranges

## Pivot After Nmap

→ See `pivot_map.md` PORT FOUND section
