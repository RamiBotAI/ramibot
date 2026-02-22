# Enumeration Tactics — Service-Specific Deep Dive

## Enumeration Principle

> "Enumerate, don't guess. The target will tell you how to break in."

## Web Enumeration Checklist

```
□ whatweb (tech stack)
□ /robots.txt
□ /sitemap.xml
□ /.git/ /.svn/ /.hg/
□ /README.md /CHANGELOG.md /LICENSE
□ Source code comments (view-source:)
□ HTTP headers (Server, X-Powered-By)
□ Cookie names (framework indicator)
□ gobuster with extensions
□ nikto
□ Check all HTTP ports independently
□ Virtual hosts (different Host header → different app?)
```

## SMB Enumeration Sequence

```
1. enum4linux -a <target>           → everything at once
2. smbclient -L //<target> -N      → list shares (null session)
3. smbclient //<target>/<share> -N  → access share
4. smbmap -H <target>               → permission map
5. crackmapexec smb <target>        → version + signing
```

## User Enumeration Sources

| Source | Method |
|---|---|
| SMB null session | enum4linux -U |
| LDAP anonymous bind | ldapsearch -x |
| SMTP VRFY | `VRFY <username>` via telnet |
| Web login error | "User not found" vs "Wrong password" |
| Web registration | "Email already taken" |
| Password reset | "User not found" responses |
| /etc/passwd (LFI) | Direct user list |
| WordPress | /wp-json/wp/v2/users |
| Git commits | Author names |

## Share/File Enumeration Priorities

```
FOUND FILES? LOOK FOR:
  ├─ *.conf, *.config, *.cfg     → credentials, connection strings
  ├─ *.bak, *.old, *.save        → backups with passwords
  ├─ *.sql                        → database dumps
  ├─ *.txt, *.log                 → notes, passwords, paths
  ├─ *.php, *.py, *.asp           → source code, hardcoded creds
  ├─ *.key, *.pem                 → SSH/SSL private keys
  ├─ .env                         → environment variables, secrets
  ├─ wp-config.php                → WordPress DB creds
  ├─ web.config                   → ASP.NET config, connection strings
  ├─ settings.py                  → Django secret key, DB creds
  └─ .htpasswd                    → password hashes
```

## DNS Enumeration

```
1. dig <domain> ANY                → all records
2. dig axfr @<ns> <domain>        → zone transfer
3. dig <domain> MX                → mail servers
4. dig <domain> NS                → name servers
5. dig <domain> TXT               → SPF, DKIM, verification tokens
6. gobuster dns -d <domain> -w <wordlist>  → subdomain brute
```

## SNMP Enumeration (port 161 UDP)

```
snmpwalk -v2c -c public <target>     → try "public" community first
snmpwalk -v2c -c private <target>    → try "private"

SNMP REVEALS:
  - Running processes
  - Installed software
  - Network interfaces
  - User accounts
  - Sometimes: passwords in process args
```
