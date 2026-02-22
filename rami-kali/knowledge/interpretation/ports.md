# Port Interpretation — Quick Reference

> When nmap returns open ports, consult this for instant context.

## Tier 1: High-Value Targets (attack these first)

| Port | Service | Why It Matters | First Move |
|---|---|---|---|
| 21 | FTP | Anonymous access, old vulns | `ftp <target>` (try anonymous) |
| 22 | SSH | Shell access if creds found | Note version → searchsploit |
| 80 | HTTP | Largest attack surface | whatweb → gobuster → nikto |
| 443 | HTTPS | Same as 80, check cert info too | whatweb, check cert CN/SAN |
| 445 | SMB | Shares, users, EternalBlue | enum4linux immediately |
| 3306 | MySQL | Data, creds, possible RCE | Try: `mysql -h <t> -u root -p` |
| 5432 | PostgreSQL | Data, creds, possible RCE | Try: `psql -h <t> -U postgres` |

## Tier 2: Valuable Services

| Port | Service | Why It Matters | First Move |
|---|---|---|---|
| 23 | Telnet | Cleartext, often default creds | Connect, grab banner |
| 25 | SMTP | User enum (VRFY), relay | `telnet <t> 25` → VRFY |
| 53 | DNS | Zone transfer = full map | `dig axfr @<t> <domain>` |
| 110 | POP3 | Mail access with creds | Note for cred reuse |
| 111 | RPCbind | NFS shares, service map | `rpcinfo -p <t>` |
| 135 | MSRPC | Windows service enumeration | enum4linux |
| 139 | NetBIOS | SMB legacy, same as 445 | enum4linux |
| 143 | IMAP | Mail access with creds | Note for cred reuse |
| 389 | LDAP | Directory enum, user harvest | `ldapsearch -x -H ldap://<t>` |
| 636 | LDAPS | Same as LDAP, encrypted | Same approach |
| 1433 | MSSQL | Data, xp_cmdshell = RCE | Try sa:sa, searchsploit |
| 2049 | NFS | Shared files, possible write | `showmount -e <t>` |
| 3389 | RDP | GUI access with creds | Note for cred reuse |
| 5900 | VNC | GUI access, sometimes no auth | `vncviewer <t>` |
| 6379 | Redis | No auth default = RCE | `redis-cli -h <t> info` |
| 8080 | Alt-HTTP | Different web app | Treat as 80 |
| 8443 | Alt-HTTPS | Different web app | Treat as 443 |
| 27017 | MongoDB | No auth default = data dump | `mongo <t>` |

## Tier 3: Contextual

| Port | Service | Context |
|---|---|---|
| 69 | TFTP | Config file retrieval, no auth |
| 161 | SNMP | Community strings → info leak |
| 512-514 | R-services | Legacy, trust-based auth |
| 873 | Rsync | Possible anonymous access |
| 1099 | Java RMI | Deserialization attacks |
| 1521 | Oracle DB | TNS listener, cred attacks |
| 2121 | Alt-FTP | Different FTP service |
| 4443 | Alt-HTTPS | Custom app |
| 5000 | Flask/Docker | Dev server, often unprotected |
| 6667 | IRC | Backdoors sometimes use IRC |
| 8000 | Alt-HTTP | Dev server |
| 8888 | Alt-HTTP | Jupyter/dev server |
| 9090 | Alt-HTTP | Management console |
| 9200 | Elasticsearch | No auth default = data dump |
| 11211 | Memcached | Info leak, sometimes amplification |

## Port State Interpretation

| State | Meaning | Action |
|---|---|---|
| open | Service accepting connections | Investigate |
| closed | Port reachable, no service | Ignore (unless recently closed) |
| filtered | Firewall dropping packets | Note, don't chase |
| open\|filtered | UDP uncertainty | Try service-specific probe |

## Combo Patterns

```
22 + 80              → Linux web server. Standard web attack + SSH for shell.
80 + 443             → Check if same app or different. Cert may leak hostnames.
135 + 139 + 445      → Windows. enum4linux is mandatory.
135 + 445 + 3389     → Windows workstation/server. SMB + RDP.
21 + 22 + 80         → Classic CTF setup. Check FTP anon, web for vulns.
80 + 3306            → PHP + MySQL likely. SQLi probable attack vector.
80 + 8080            → Two web apps. Scan both independently.
139 + 445 + 389      → Domain controller. LDAP enum + SMB enum.
22 + 2049            → NFS shares. `showmount -e` → mount and read.
```
