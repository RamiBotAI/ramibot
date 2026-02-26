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

## Tool Usage (use nmap_scan parameters — do NOT pass raw flags via extra_args)

| Goal | scan_type | ports | extra_args |
|---|---|---|---|
| Subnet host discovery | `"discovery"` | — | — |
| Full single-host recon | `"full"` | — | `"-O"` for OS |
| Quick top-1000 ports | `"quick"` | — | — |
| Vuln hints on known ports | `"vuln"` | `"80,443"` | — |
| UDP (SNMP/DNS/TFTP) | `"udp"` | — | — |
| Specific port deep dive | `"scripts"` | `"22,80,443"` | — |

**Rules:**
- Always use `scan_type="discovery"` first for CIDRs/subnets before any port scan.
- Do **not** pass `-sV`, `-sC`, `-p-`, or `--top-ports` via `extra_args` — they are already included in the scan_type profile and will conflict.
- Only use `extra_args` for flags not covered by the parameters (e.g. `-O`, `--osscan-guess`, `-6`).

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
